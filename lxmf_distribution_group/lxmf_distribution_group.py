#!/usr/bin/env python3
##############################################################################################################
#
# Copyright (c) 2022 Sebastian Obele  /  obele.eu
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#
# This software uses the following software-parts:
# Reticulum, LXMF, NomadNet  /  Copyright (c) 2016-2022 Mark Qvist  /  unsigned.io  /  MIT License
#
##############################################################################################################


##############################################################################################################
# Include


#### System ####
import sys
import os
import time
import datetime
import argparse

#### Config ####
import configparser

#### Variables ####
from collections import defaultdict

#### JSON ####
import json
import pickle

#### String ####
import string

#### Regex ####
import re

#### Search ####
import fnmatch

#### Process ####
import signal
import threading

#### Reticulum, LXMF ####
# Install: pip3 install rns lxmf
# Source: https://markqvist.github.io
import RNS
import LXMF
import RNS.vendor.umsgpack as umsgpack


##############################################################################################################
# Globals


#### Global Variables - Configuration ####
NAME = "LXMF Distribution Group"
DESCRIPTION = "Server-Side group functions for LXMF based apps"
VERSION = "0.0.1 (2022-10-21)"
COPYRIGHT = "(c) 2022 Sebastian Obele  /  obele.eu"
PATH = os.path.expanduser("~") + "/." + os.path.splitext(os.path.basename(__file__))[0]
PATH_RNS = None




#### Global Variables - System (Not changeable) ####
DATA = None
CONFIG = None
STATISTIC = None
RNS_MAIN_CONNECTION = None
LXMF_CONNECTION = None
RNS_CONNECTION = None

CONV_P2P                = 0x01
CONV_GROUP              = 0x02
CONV_BROADCAST          = 0x03
CONV_DISTRIBUTION_GROUP = 0x04


##############################################################################################################
# LXMF Class


class lxmf_connection:
    message_received_callback = None
    message_notification_callback = None
    message_notification_success_callback = None
    message_notification_failed_callback = None
    config_set_callback = None


    def __init__(self, storage_path=None, identity_file="identity", identity=None, destination_name="lxmf", destination_type="delivery", display_name="", announce_data=None, announce_hidden=False, send_delay=0, desired_method="direct", propagation_node=None, propagation_node_auto=False, propagation_node_active=None, try_propagation_on_fail=False, announce_startup=False, announce_startup_delay=0, announce_periodic=False, announce_periodic_interval=360, sync_startup=False, sync_startup_delay=0, sync_limit=8, sync_periodic=False, sync_periodic_interval=360):
        self.storage_path = storage_path

        self.identity_file = identity_file

        self.identity = identity

        self.destination_name = destination_name
        self.destination_type = destination_type
        self.aspect_filter = self.destination_name + "." + self.destination_type

        self.display_name = display_name
        self.announce_data = announce_data
        self.announce_hidden = announce_hidden

        self.send_delay = int(send_delay)

        if desired_method == "propagated" or desired_method == "PROPAGATED":
            self.desired_method_direct = False
        else:
            self.desired_method_direct = True
        self.propagation_node = propagation_node
        self.propagation_node_auto = propagation_node_auto
        self.propagation_node_active = propagation_node_active
        self.try_propagation_on_fail = try_propagation_on_fail

        self.announce_startup = announce_startup
        self.announce_startup_delay = int(announce_startup_delay)

        self.announce_periodic = announce_periodic
        self.announce_periodic_interval = int(announce_periodic_interval)

        self.sync_startup = sync_startup
        self.sync_startup_delay = int(sync_startup_delay)
        self.sync_limit = int(sync_limit)
        self.sync_periodic = sync_periodic
        self.sync_periodic_interval = int(sync_periodic_interval)

        if not self.storage_path:
            log("LXMF - No storage_path parameter", LOG_ERROR)
            return

        if not os.path.isdir(self.storage_path):
            os.makedirs(self.storage_path)
            log("LXMF - Storage path was created", LOG_NOTICE)
        log("LXMF - Storage path: " + self.storage_path, LOG_INFO)

        if self.identity:
            log("LXMF - Using existing Primary Identity %s" % (str(self.identity)))
        else:
            if not self.identity_file:
                self.identity_file = "identity"
            self.identity_path = self.storage_path + "/" + self.identity_file
            if os.path.isfile(self.identity_path):
                try:
                    self.identity = RNS.Identity.from_file(self.identity_path)
                    if self.identity != None:
                        log("LXMF - Loaded Primary Identity %s from %s" % (str(self.identity), self.identity_path))
                    else:
                        log("LXMF - Could not load the Primary Identity from "+self.identity_path, LOG_ERROR)
                except Exception as e:
                    log("LXMF - Could not load the Primary Identity from "+self.identity_path, LOG_ERROR)
                    log("LXMF - The contained exception was: %s" % (str(e)), LOG_ERROR)
            else:
                try:
                    log("LXMF - No Primary Identity file found, creating new...")
                    self.identity = RNS.Identity()
                    self.identity.to_file(self.identity_path)
                    log("LXMF - Created new Primary Identity %s" % (str(self.identity)))
                except Exception as e:
                    log("LXMF - Could not create and save a new Primary Identity", LOG_ERROR)
                    log("LXMF - The contained exception was: %s" % (str(e)), LOG_ERROR)

        self.message_router = LXMF.LXMRouter(identity=self.identity, storagepath=self.storage_path)

        if self.destination_name == "lxmf" and self.destination_type == "delivery":
            self.destination = self.message_router.register_delivery_identity(self.identity, display_name=self.display_name)
            self.message_router.register_delivery_callback(self.process_lxmf_message_propagated)
        else:
            self.destination = RNS.Destination(self.identity, RNS.Destination.IN, RNS.Destination.SINGLE, self.destination_name, self.destination_type)

        if self.display_name == "":
            self.display_name = RNS.prettyhexrep(self.destination_hash())

        self.destination.set_default_app_data(self.display_name.encode("utf-8"))

        self.destination.set_proof_strategy(RNS.Destination.PROVE_ALL)

        RNS.Identity.remember(packet_hash=None, destination_hash=self.destination.hash, public_key=self.identity.get_public_key(), app_data=None)

        log("LXMF - Identity: " + str(self.identity), LOG_INFO)
        log("LXMF - Destination: " + str(self.destination), LOG_INFO)
        log("LXMF - Hash: " + RNS.prettyhexrep(self.destination_hash()), LOG_INFO)

        self.destination.set_link_established_callback(self.client_connected)

        if self.propagation_node_auto:
            self.propagation_callback = lxmf_connection_propagation(self, "lxmf.propagation")
            RNS.Transport.register_announce_handler(self.propagation_callback)
            if self.propagation_node_active:
                self.propagation_node_set(self.propagation_node_active)
            elif self.propagation_node:
                self.propagation_node_set(self.propagation_node)
        else:
            self.propagation_node_set(self.propagation_node)

        if self.announce_startup or self.announce_periodic:
            self.announce(initial=True)

        if self.sync_startup or self.sync_periodic:
            self.sync(True)


    def register_announce_callback(self, handler_function):
        self.announce_callback = handler_function(self.aspect_filter)
        RNS.Transport.register_announce_handler(self.announce_callback)


    def register_message_received_callback(self, handler_function):
        self.message_received_callback = handler_function


    def register_message_notification_callback(self, handler_function):
        self.message_notification_callback = handler_function


    def register_message_notification_success_callback(self, handler_function):
        self.message_notification_success_callback = handler_function


    def register_message_notification_failed_callback(self, handler_function):
        self.message_notification_failed_callback = handler_function


    def register_config_set_callback(self, handler_function):
        self.config_set_callback = handler_function


    def destination_hash(self):
        return self.destination.hash


    def destination_hash_str(self):
        return RNS.hexrep(self.destination.hash, False)


    def destination_check(self, destination):
        if type(destination) is not bytes:
            if len(destination) == ((RNS.Reticulum.TRUNCATED_HASHLENGTH//8)*2)+2:
                destination = destination[1:-1]

            if len(destination) != ((RNS.Reticulum.TRUNCATED_HASHLENGTH//8)*2):
                log("LXMF - Destination length is invalid", LOG_ERROR)
                return False

            try:    
                destination = bytes.fromhex(destination)
            except Exception as e:
                log("LXMF - Destination is invalid", LOG_ERROR)
                return False

        return True


    def destination_correct(self, destination):
        if type(destination) is not bytes:
            if len(destination) == ((RNS.Reticulum.TRUNCATED_HASHLENGTH//8)*2)+2:
                destination = destination[1:-1]

            if len(destination) != ((RNS.Reticulum.TRUNCATED_HASHLENGTH//8)*2):
                return ""

            try:
                destination_bytes = bytes.fromhex(destination)
                return destination
            except Exception as e:
                return ""

        return ""


    def send(self, destination, content="", title="", fields=None, timestamp=None, app_data="", destination_name=None, destination_type=None):
        if type(destination) is not bytes:
            if len(destination) == ((RNS.Reticulum.TRUNCATED_HASHLENGTH//8)*2)+2:
                destination = destination[1:-1]

            if len(destination) != ((RNS.Reticulum.TRUNCATED_HASHLENGTH//8)*2):
                log("LXMF - Destination length is invalid", LOG_ERROR)
                return None

            try:
                destination = bytes.fromhex(destination)
            except Exception as e:
                log("LXMF - Destination is invalid", LOG_ERROR)
                return None

        if destination_name == None:
            destination_name = self.destination_name
        if destination_type == None:
            destination_type = self.destination_type

        destination_identity = RNS.Identity.recall(destination)
        destination = RNS.Destination(destination_identity, RNS.Destination.OUT, RNS.Destination.SINGLE, destination_name, destination_type)
        return self.send_message(destination, self.destination, content, title, fields, timestamp, app_data)


    def send_message(self, destination, source, content="", title="", fields=None, timestamp=None, app_data=""):
        if self.desired_method_direct:
            desired_method = LXMF.LXMessage.DIRECT
        else:
            desired_method = LXMF.LXMessage.PROPAGATED

        message = LXMF.LXMessage(destination, source, content, title=title, desired_method=desired_method)

        if fields is not None:
            message.fields = fields

        if timestamp is not None:
            message.timestamp = timestamp

        message.app_data = app_data

        self.message_method(message)
        self.log_message(message, "LXMF - Message send")

        message.register_delivery_callback(self.message_notification)
        message.register_failed_callback(self.message_notification)

        if self.message_router.get_outbound_propagation_node() != None:
            message.try_propagation_on_fail = self.try_propagation_on_fail

        try:
            self.message_router.handle_outbound(message)
            time.sleep(self.send_delay)
            return message.hash
        except Exception as e:
            log("LXMF - Could not send message " + str(message), LOG_ERROR)
            log("LXMF - The contained exception was: " + str(e), LOG_ERROR)
            return None


    def message_notification(self, message):
        self.message_method(message)

        if self.message_notification_callback is not None:
            self.message_notification_callback(message)

        if message.state == LXMF.LXMessage.FAILED and hasattr(message, "try_propagation_on_fail") and message.try_propagation_on_fail:
            self.log_message(message, "LXMF - Delivery receipt (failed) Retrying as propagated message")
            message.try_propagation_on_fail = None
            message.delivery_attempts = 0
            del message.next_delivery_attempt
            message.packed = None
            message.desired_method = LXMF.LXMessage.PROPAGATED
            self.message_router.handle_outbound(message)
        elif message.state == LXMF.LXMessage.FAILED:
            self.log_message(message, "LXMF - Delivery receipt (failed)")
            if self.message_notification_failed_callback is not None:
                self.message_notification_failed_callback(message)
        else:
            self.log_message(message, "LXMF - Delivery receipt (success)")
            if self.message_notification_success_callback is not None:
                self.message_notification_success_callback(message)


    def message_method(self, message):
        if message.desired_method == LXMF.LXMessage.DIRECT:
            message.desired_method_str = "direct"
        elif message.desired_method == LXMF.LXMessage.PROPAGATED:
            message.desired_method_str = "propagated"


    def announce(self, app_data=None, attached_interface=None, initial=False):
        announce_timer = None

        if self.announce_periodic and self.announce_periodic_interval > 0:
            announce_timer = threading.Timer(self.announce_periodic_interval*60, self.announce)
            announce_timer.daemon = True
            announce_timer.start()

        if initial:
            if self.announce_startup:
                if self.announce_startup_delay > 0:
                    if announce_timer is not None:
                        announce_timer.cancel()
                    announce_timer = threading.Timer(self.announce_startup_delay, self.announce)
                    announce_timer.daemon = True
                    announce_timer.start()
                else:
                    self.announce_now(app_data=app_data, attached_interface=attached_interface)
            return

        self.announce_now(app_data=app_data, attached_interface=attached_interface)


    def announce_now(self, app_data=None, attached_interface=None):
        if self.announce_hidden:
            self.destination.announce("".encode("utf-8"), attached_interface=attached_interface)
            log("LXMF - Announced: " + RNS.prettyhexrep(self.destination_hash()) +" (Hidden)", LOG_DEBUG)
        elif app_data != None:
            if isinstance(app_data, str):
                self.destination.announce(app_data.encode("utf-8"), attached_interface=attached_interface)
                log("LXMF - Announced: " + RNS.prettyhexrep(self.destination_hash()) +":" + app_data, LOG_DEBUG)
            else:
                self.destination.announce(app_data, attached_interface=attached_interface)
                log("LMF - Announced: " + RNS.prettyhexrep(self.destination_hash()), LOG_DEBUG)
        elif self.announce_data:
            if isinstance(self.announce_data, str):
                self.destination.announce(self.announce_data.encode("utf-8"), attached_interface=attached_interface)
                log("LXMF - Announced: " + RNS.prettyhexrep(self.destination_hash()) +":" + self.announce_data, LOG_DEBUG)
            else:
                self.destination.announce(self.announce_data, attached_interface=attached_interface)
                log("LXMF - Announced: " + RNS.prettyhexrep(self.destination_hash()), LOG_DEBUG)
        else:
            self.destination.announce()
            log("LXMF - Announced: " + RNS.prettyhexrep(self.destination_hash()) + ": " + self.display_name, LOG_DEBUG)


    def sync(self, initial=False):
        sync_timer = None

        if self.sync_periodic and self.sync_periodic_interval > 0:
            sync_timer = threading.Timer(self.sync_periodic_interval*60, self.sync)
            sync_timer.daemon = True
            sync_timer.start()

        if initial:
            if self.sync_startup:
                if self.sync_startup_delay > 0:
                    if sync_timer is not None:
                        sync_timer.cancel()
                    sync_timer = threading.Timer(self.sync_startup_delay, self.sync)
                    sync_timer.daemon = True
                    sync_timer.start()
                else:
                    self.sync_now(self.sync_limit)
            return

        self.sync_now(self.sync_limit)


    def sync_now(self, limit=None):
        if self.message_router.get_outbound_propagation_node() is not None:
            if self.message_router.propagation_transfer_state == LXMF.LXMRouter.PR_IDLE or self.message_router.propagation_transfer_state == LXMF.LXMRouter.PR_COMPLETE:
                log("LXMF - Message sync requested from propagation node " + RNS.prettyhexrep(self.message_router.get_outbound_propagation_node()) + " for " + str(self.identity))
                self.message_router.request_messages_from_propagation_node(self.identity, max_messages = limit)
                return True
            else:
                return False
        else:
            return False


    def propagation_node_set(self, dest_str):
        if not dest_str:
            return False

        if len(dest_str) != ((RNS.Reticulum.TRUNCATED_HASHLENGTH//8)*2):
            log("LXMF - Propagation node length is invalid", LOG_ERROR)
            return False

        try:
            dest_hash = bytes.fromhex(dest_str)
        except Exception as e:
            log("LXMF - Propagation node is invalid", LOG_ERROR)
            return False

        node_identity = RNS.Identity.recall(dest_hash)
        if node_identity != None:
            log("LXMF - Propagation node: " + RNS.prettyhexrep(dest_hash), LOG_INFO)
            dest_hash = RNS.Destination.hash_from_name_and_identity("lxmf.propagation", node_identity)
            self.message_router.set_outbound_propagation_node(dest_hash)
            self.propagation_node_active = dest_str
            return True
        else:
            log("LXMF - Propagation node identity not known", LOG_ERROR)
            return False


    def propagation_node_update(self, dest_str):
        if self.propagation_node_hash_str() != dest_str:
            if self.propagation_node_set(dest_str) and self.config_set_callback is not None:
                 self.config_set_callback("propagation_node_active", dest_str)


    def propagation_node_hash(self):
        try:
            return bytes.fromhex(self.propagation_node_active)
        except:
            return None


    def propagation_node_hash_str(self):
        if self.propagation_node_active:
            return self.propagation_node_active
        else:
            return ""


    def client_connected(self, link):
        log("LXMF - Client connected " + str(link), LOG_EXTREME)
        link.set_resource_strategy(RNS.Link.ACCEPT_ALL)
        link.set_resource_concluded_callback(self.resource_concluded)
        link.set_packet_callback(self.packet_received)


    def packet_received(self, lxmf_bytes, packet):
        log("LXMF - Single packet delivered " + str(packet), LOG_EXTREME)
        self.process_lxmf_message_bytes(lxmf_bytes)


    def resource_concluded(self, resource):
        log("LXMF - Resource data transfer (multi packet) delivered " + str(resource.file), LOG_EXTREME)
        if resource.status == RNS.Resource.COMPLETE:
            lxmf_bytes = resource.data.read()
            self.process_lxmf_message_bytes(lxmf_bytes)
        else:
            log("LXMF - Received resource message is not complete", LOG_EXTREME)


    def process_lxmf_message_bytes(self, lxmf_bytes):
        try:
            message = LXMF.LXMessage.unpack_from_bytes(lxmf_bytes)
        except Exception as e:
            log("LXMF - Could not assemble LXMF message from received data", LOG_ERROR)
            log("LXMF - The contained exception was: " + str(e), LOG_ERROR)
            return

        message.desired_method = LXMF.LXMessage.DIRECT

        self.message_method(message)
        self.log_message(message, "LXMF - Message received")

        if self.message_received_callback is not None:
            log("LXMF - Call to registered message received callback", LOG_DEBUG)
            self.message_received_callback(message)
        else:
            log("LXMF - No message received callback registered", LOG_DEBUG)


    def process_lxmf_message_propagated(self, message):
        message.desired_method = LXMF.LXMessage.PROPAGATED

        self.message_method(message)
        self.log_message(message, "LXMF - Message received")

        if self.message_received_callback is not None:
            log("LXMF - Call to registered message received callback", LOG_DEBUG)
            self.message_received_callback(message)
        else:
            log("LXMF - No message received callback registered", LOG_DEBUG)


    def log_message(self, message, message_tag="LXMF - Message log"):
        if message.signature_validated:
            signature_string = "Validated"
        else:
            if message.unverified_reason == LXMF.LXMessage.SIGNATURE_INVALID:
                signature_string = "Invalid signature"
            elif message.unverified_reason == LXMF.LXMessage.SOURCE_UNKNOWN:
                signature_string = "Cannot verify, source is unknown"
            else:
                signature_string = "Signature is invalid, reason undetermined"
        title = message.title.decode('utf-8')
        content = message.content.decode('utf-8')
        fields = message.fields
        log(message_tag + ":", LOG_DEBUG)
        log("-   Date/Time: " + time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(message.timestamp)), LOG_DEBUG)
        log("-       Title: " + title, LOG_DEBUG)
        log("-     Content: " + content, LOG_DEBUG)
        log("-      Fields: " + str(fields), LOG_DEBUG)
        log("-        Size: " + str(len(title) + len(content) + len(title) + len(pickle.dumps(fields))) + " bytes", LOG_DEBUG)
        log("-      Source: " + RNS.prettyhexrep(message.source_hash), LOG_DEBUG)
        log("- Destination: " + RNS.prettyhexrep(message.destination_hash), LOG_DEBUG)
        log("-   Signature: " + signature_string, LOG_DEBUG)
        log("-    Attempts: " + str(message.delivery_attempts), LOG_DEBUG)
        if hasattr(message, "desired_method_str"):
            log("-      Method: " + message.desired_method_str + " (" + str(message.desired_method) + ")", LOG_DEBUG)
        else:
            log("-      Method: " + str(message.desired_method), LOG_DEBUG)
        if hasattr(message, "app_data"):
            log("-    App Data: " + message.app_data, LOG_DEBUG)




class lxmf_connection_propagation():
    def __init__(self, owner, aspect_filter=None):
        self.owner = owner
        self.aspect_filter = aspect_filter

    EMITTED_DELTA_GRACE = 300
    EMITTED_DELTA_IGNORE = 10

    def received_announce(self, destination_hash, announced_identity, app_data):
        if app_data == None:
            return

        if len(app_data) == 0:
            return

        try:
            unpacked = umsgpack.unpackb(app_data)
            node_active = unpacked[0]
            emitted = unpacked[1]
            hop_count = RNS.Transport.hops_to(destination_hash)
            age = time.time() - emitted
            if age < 0:
                if age < -1*PropDetector.EMITTED_DELTA_GRACE:
                    return
            log("LXMF - Received an propagation node announce from "+RNS.prettyhexrep(destination_hash)+": "+str(age)+" seconds ago, "+str(hop_count)+" hops away", LOG_INFO)
            if self.owner.propagation_node_active == None:
                self.owner.propagation_node_update(RNS.hexrep(destination_hash, False))
            else:
                prev_hop_count = RNS.Transport.hops_to(self.owner.propagation_node_hash())
                if hop_count <= prev_hop_count:
                    self.owner.propagation_node_update(RNS.hexrep(destination_hash, False))
        except:
            return


##############################################################################################################
# RNS Class


class rns_connection:
    def __init__(self, storage_path=None, identity_file="identity", identity=None, destination_name="rns", destination_type="connect", announce_startup=False, announce_startup_delay=0, announce_periodic=False, announce_periodic_interval=360, announce_data="", announce_hidden=False):
        self.storage_path = storage_path

        self.identity_file = identity_file

        self.identity = identity

        self.destination_name = destination_name
        self.destination_type = destination_type
        self.aspect_filter = self.destination_name + "." + self.destination_type

        self.announce_startup = announce_startup
        self.announce_startup_delay = int(announce_startup_delay)

        self.announce_periodic = announce_periodic
        self.announce_periodic_interval = int(announce_periodic_interval)

        self.announce_data = announce_data
        self.announce_hidden = announce_hidden

        if not self.storage_path:
            log("RNS - No storage_path parameter", LOG_ERROR)
            return

        if not os.path.isdir(self.storage_path):
            os.makedirs(self.storage_path)
            log("RNS - Storage path was created", LOG_NOTICE)
        log("RNS - Storage path: " + self.storage_path, LOG_INFO)

        if self.identity:
            log("RNS - Using existing Primary Identity %s" % (str(self.identity)))
        else:
            if not self.identity_file:
                self.identity_file = "identity"
            self.identity_path = self.storage_path + "/" + self.identity_file
            if os.path.isfile(self.identity_path):
                try:
                    self.identity = RNS.Identity.from_file(self.identity_path)
                    if self.identity != None:
                        log("RNS - Loaded Primary Identity %s from %s" % (str(self.identity), self.identity_path))
                    else:
                        log("RNS - Could not load the Primary Identity from "+self.identity_path, LOG_ERROR)
                except Exception as e:
                    log("RNS - Could not load the Primary Identity from "+self.identity_path, LOG_ERROR)
                    log("RNS - The contained exception was: %s" % (str(e)), LOG_ERROR)
            else:
                try:
                    log("RNS - No Primary Identity file found, creating new...")
                    self.identity = RNS.Identity()
                    self.identity.to_file(self.identity_path)
                    log("RNS - Created new Primary Identity %s" % (str(self.identity)))
                except Exception as e:
                    log("RNS - Could not create and save a new Primary Identity", LOG_ERROR)
                    log("RNS - The contained exception was: %s" % (str(e)), LOG_ERROR)

        self.destination = RNS.Destination(self.identity, RNS.Destination.IN, RNS.Destination.SINGLE, self.destination_name, self.destination_type)

        self.destination.set_proof_strategy(RNS.Destination.PROVE_ALL)

        if self.announce_startup or self.announce_periodic:
            self.announce(initial=True)


    def register_announce_callback(self, handler_function):
        self.announce_callback = handler_function(self.aspect_filter)
        RNS.Transport.register_announce_handler(self.announce_callback)


    def destination_hash(self):
        return self.destination.hash


    def destination_hash_str(self):
        return RNS.hexrep(self.destination.hash, False)


    def destination_check(self, destination):
        if type(destination) is not bytes:
            if len(destination) == ((RNS.Reticulum.TRUNCATED_HASHLENGTH//8)*2)+2:
                destination = destination[1:-1]

            if len(destination) != ((RNS.Reticulum.TRUNCATED_HASHLENGTH//8)*2):
                log("RNS - Destination length is invalid", LOG_ERROR)
                return False

            try:    
                destination = bytes.fromhex(destination)
            except Exception as e:
                log("RNS - Destination is invalid", LOG_ERROR)
                return False

        return True


    def destination_correct(self, destination):
        if type(destination) is not bytes:
            if len(destination) == ((RNS.Reticulum.TRUNCATED_HASHLENGTH//8)*2)+2:
                destination = destination[1:-1]

            if len(destination) != ((RNS.Reticulum.TRUNCATED_HASHLENGTH//8)*2):
                return ""

            try:
                destination_bytes = bytes.fromhex(destination)
                return destination
            except Exception as e:
                return ""

        return ""


    def announce(self, app_data=None, attached_interface=None, initial=False):
        announce_timer = None

        if self.announce_periodic and self.announce_periodic_interval > 0:
            announce_timer = threading.Timer(self.announce_periodic_interval*60, self.announce)
            announce_timer.daemon = True
            announce_timer.start()

        if initial:
            if self.announce_startup:
                if self.announce_startup_delay > 0:
                    if announce_timer is not None:
                        announce_timer.cancel()
                    announce_timer = threading.Timer(self.announce_startup_delay, self.announce)
                    announce_timer.daemon = True
                    announce_timer.start()
                else:
                    self.announce_now(app_data=app_data, attached_interface=attached_interface)
            return

        self.announce_now(app_data=app_data, attached_interface=attached_interface)


    def announce_now(self, app_data=None, attached_interface=None):
        if self.announce_hidden:
            self.destination.announce("".encode("utf-8"), attached_interface=attached_interface)
            log("RNS - Announced: " + RNS.prettyhexrep(self.destination_hash()) +" (Hidden)", LOG_DEBUG)
        elif app_data != None:
            if isinstance(app_data, str):
                self.destination.announce(app_data.encode("utf-8"), attached_interface=attached_interface)
                log("RNS - Announced: " + RNS.prettyhexrep(self.destination_hash()) +":" + app_data, LOG_DEBUG)
            else:
                self.destination.announce(app_data, attached_interface=attached_interface)
                log("RNS - Announced: " + RNS.prettyhexrep(self.destination_hash()), LOG_DEBUG)
        else:
            if isinstance(self.announce_data, str):
                self.destination.announce(self.announce_data.encode("utf-8"), attached_interface=attached_interface)
                log("RNS - Announced: " + RNS.prettyhexrep(self.destination_hash()) +":" + self.announce_data, LOG_DEBUG)
            else:
                self.destination.announce(self.announce_data, attached_interface=attached_interface)
                log("RNS - Announced: " + RNS.prettyhexrep(self.destination_hash()), LOG_DEBUG)


##############################################################################################################
# LXMF Functions


#### LXMF - Announce ####
class lxmf_announce_callback:
    def __init__(self, aspect_filter=None):
        self.aspect_filter = aspect_filter


    @staticmethod
    def received_announce(destination_hash, announced_identity, app_data):
        if app_data == None:
            return

        if len(app_data) == 0:
            return

        try:
            app_data_dict = umsgpack.unpackb(app_data)
            if isinstance(app_data_dict, dict) and "c" in app_data_dict:
                app_data = app_data_dict["c"]
        except:
            pass

        try:
            app_data = app_data.decode("utf-8").strip()
        except:
            return

        log("LXMF - Received an announce from " + RNS.prettyhexrep(destination_hash) + ": " + app_data, LOG_INFO)

        global DATA

        lng_key = "-" + CONFIG["main"]["lng"]

        sections = []
        for (key, val) in CONFIG.items("rights"):
            if DATA.has_section(key):
                sections.append(key)

        if CONFIG["main"].getboolean("auto_name_def") or CONFIG["main"].getboolean("auto_name_change"):
            source_hash = RNS.hexrep(destination_hash, False)
            for section in DATA.sections():
                for (key, val) in DATA.items(section):
                    if key == source_hash:
                        if (val == "" and CONFIG["main"].getboolean("auto_name_def")) or (val != "" and CONFIG["main"].getboolean("auto_name_change")):
                            value = app_data
                            if value != DATA[section][key]:
                                if DATA[section][key] == "":
                                    content_type = "name_def"
                                    content_add = " " + value
                                else:
                                    content_type = "name_change"
                                    content_add = " " + DATA[section][key] + " -> " + value

                                DATA[section][key] = value

                                content_group = config_get(CONFIG, "interface_messages", "member_"+content_type, "", lng_key)
                                if content_group != "":
                                    fields = fields_generate(lng_key, h=destination_hash ,n=value, tpl=content_type)
                                    content_group = replace(content_group, source_hash, value, "", lng_key)
                                    content_group = content_group + content_add
                                    for section in sections:
                                        if "receive_auto_"+content_type in config_get(CONFIG, "rights", section).split(","):
                                            for (key, val) in DATA.items(section):
                                                if key != source_hash:
                                                    LXMF_CONNECTION.send(key, content_group, "", fields, None, "interface_send")

                                if CONFIG["main"].getboolean("auto_save_data"):
                                    DATA.remove_option("main", "unsaved")
                                    if not data_save(PATH + "/data.cfg"):
                                        DATA["main"]["unsaved"] = "True"
                                else:
                                    DATA["main"]["unsaved"] = "True"




#### LXMF - Message ####
def lxmf_message_received_callback(message):
    if CONFIG["lxmf"].getboolean("signature_validated") and not message.signature_validated:
        log("LXMF - Source " + RNS.prettyhexrep(message.source_hash) + " have no valid signature", LOG_DEBUG)
        return

    title = message.title.decode('utf-8').strip()
    denys = config_get(CONFIG, "message", "deny_title")
    if denys != "":
        denys = denys.split(",")
        if "*" in denys:
            return
        for deny in denys:
            if deny in title:
                return

    content = message.content.decode('utf-8').strip()
    denys = config_get(CONFIG, "message", "deny_content")
    if denys != "":
        denys = denys.split(",")
        if "*" in denys:
            return
        for deny in denys:
            if deny in title:
                return

    if message.fields:
        denys = config_get(CONFIG, "message", "deny_fields")
        if denys != "":
            denys = denys.split(",")
            if "*" in denys:
                return
            for deny in denys:
                if deny in message.fields:
                    return

    if not CONFIG["message"].getboolean("title"):
        title = ""

    if CONFIG["message"].getboolean("fields") and message.fields:
        pass
    elif content == "":
        return

    fields = message.fields

    lng_key = "-" + CONFIG["main"]["lng"]

    sections = []
    for (key, val) in CONFIG.items("rights"):
        if DATA.has_section(key):
            sections.append(key)

    destination_hash = RNS.hexrep(message.destination_hash, False)
    source_hash = RNS.hexrep(message.source_hash, False)
    source_name = ""
    source_right = ""

    for section in DATA.sections():
        if section.startswith("block"):
            if DATA.has_option(section, source_hash):
                log("LXMF - Source " + RNS.prettyhexrep(message.source_hash) + " blocked", LOG_DEBUG)
                source_right = section.replace("block_", "")
                source_rights = config_get(CONFIG, "rights", source_right)
                source_rights = source_rights.split(",")
                if "reply_block" in source_rights:
                    content_user = config_get(CONFIG, "interface_messages", "reply_block", "", lng_key)
                    content_user = replace(content_user, source_hash, source_name, source_right, lng_key)
                    if content_user != "":
                        LXMF_CONNECTION.send(source_hash, content_user, "", fields_generate(lng_key), None, "interface_send")
                return

    source_rights = []
    for section in DATA.sections():
        for (key, val) in DATA.items(section):
            if key == source_hash:
                if source_name == "":
                    source_name = val
                source_right = section
                source_rights.append(section)

    if fields:
        if "c_n" in fields and "c_t" in fields and "m_t" in fields:
            if fields["c_n"] == CONFIG["cluster"]["name"] and fields["c_t"] == CONFIG["cluster"]["type"] and "cluster" in source_rights and config_getboolean(CONFIG, "cluster", "enabled"):
                title_prefix = config_get(CONFIG, "message", "cluster_receive_title_prefix", "", lng_key)
                content_prefix = config_get(CONFIG, "message", "cluster_receive_prefix", "", lng_key)
                content_suffix = config_get(CONFIG, "message", "cluster_receive_suffix", "", lng_key)

                title_prefix = replace(title_prefix, source_hash, source_name, source_right, lng_key)
                content_prefix = replace(content_prefix, source_hash, source_name, source_right, lng_key)
                content_suffix = replace(content_suffix, source_hash, source_name, source_right, lng_key)

                source = source_name.rsplit('/', 1)[-1]
                destination = config_get(CONFIG, "cluster", "display_name", "", lng_key).rsplit('/', 1)[-1]
                title_prefix = title_prefix.replace(CONFIG["interface"]["delimiter_output"]+"cluster_source"+CONFIG["interface"]["delimiter_output"], source)
                title_prefix = title_prefix.replace(CONFIG["interface"]["delimiter_output"]+"cluster_destination"+CONFIG["interface"]["delimiter_output"], destination)
                content_prefix = content_prefix.replace(CONFIG["interface"]["delimiter_output"]+"cluster_source"+CONFIG["interface"]["delimiter_output"], source)
                content_prefix = content_prefix.replace(CONFIG["interface"]["delimiter_output"]+"cluster_destination"+CONFIG["interface"]["delimiter_output"], destination)
                content_suffix = content_suffix.replace(CONFIG["interface"]["delimiter_output"]+"cluster_source"+CONFIG["interface"]["delimiter_output"], source)
                content_suffix = content_suffix.replace(CONFIG["interface"]["delimiter_output"]+"cluster_destination"+CONFIG["interface"]["delimiter_output"], destination)

                search = config_get(CONFIG, "message", "cluster_receive_search")
                if search != "":
                    content = content.replace(search, config_get(CONFIG, "message", "cluster_receive_replace"))

                search = config_get(CONFIG, "message", "cluster_receive_regex_search")
                if search != "":
                    content = re.sub(search, config_get(CONFIG, "message", "cluster_receive_regex_replace"), content)

                title = title_prefix + title
                content = content_prefix + content + content_suffix

                if config_get(CONFIG, "message", "timestamp", "", lng_key) == "client":
                    timestamp = message.timestamp
                else:
                    timestamp = time.time()

                if CONFIG["message"].getboolean("fields"):
                    if message.fields:
                        fields = fields_remove(message.fields, "fields_remove_anonymous" if "anonymous" in source_rights else "fields_remove")
                    else:
                        fields = {}
                else:
                    fields = {}
                fields = fields(fields)

                if CONFIG["statistic"].getboolean("enabled") and CONFIG["statistic"].getboolean("cluster"):
                    statistic("add", "cluster_in_" + message.desired_method_str)

                if fields["m_t"] == "message":
                    for section in sections:
                        if "receive_cluster" in config_get(CONFIG, "rights", section).split(","):
                            for (key, val) in DATA.items(section):
                                if key != source_hash:
                                    LXMF_CONNECTION.send(key, content, title, fields, timestamp, "cluster_send")
                elif fields["m_t"] == "pin":
                    delimiter = CONFIG["interface"]["delimiter_output"]

                    value_new = config_get(CONFIG, "interface_menu", "cluster_pin", "", lng_key)
                    value_new = replace(value_new, source_hash, source_name, source_right, lng_key)
                    value_new = value_new.replace(delimiter+"value"+delimiter, content)

                    key = time.strftime(config_get(CONFIG, "message", "pin_id", "%y%m%d-%H%M%S", lng_key), time.localtime(time.time()))
                    if DATA.has_option("pin", key):
                        key = key + "-"
                        key_int = 0
                        while DATA.has_option("pin", key+str(key_int)):
                            key_int += 1
                        key = key+str(key_int)

                    DATA["pin"][key] = value_new

                    content_group = config_get(CONFIG, "interface_messages", "cluster_pin_add", "", lng_key)
                    content_group = replace(content_group, source_hash, source_name, source_right, lng_key)
                    content_group = content_group.replace(delimiter+"key"+delimiter, key)
                    content_group = content_group.replace(delimiter+"value"+delimiter, value_new)
                    if content_group != "":
                        for section in sections:
                            if "receive_cluster_pin_add" in config_get(CONFIG, "rights", section).split(","):
                                for (key, val) in DATA.items(section):
                                    if key != source_hash:
                                        LXMF_CONNECTION.send(key, content_group, "", fields, None, "cluster_send")

                    if CONFIG["main"].getboolean("auto_save_data"):
                        DATA.remove_option("main", "unsaved")
                        if not data_save(PATH + "/data.cfg"):
                            DATA["main"]["unsaved"] = "True"
                    else:
                        DATA["main"]["unsaved"] = "True"

            return

    if source_right == "" and DATA["main"].getboolean("auto_add_user"):
        if CONFIG["lxmf"].getboolean("signature_validated_new") and not message.signature_validated:
            log("LXMF - Source " + RNS.prettyhexrep(message.source_hash) + " have no valid signature 'new'", LOG_DEBUG)
            return

        source_right = DATA["main"]["auto_add_user_type"]
        if DATA.has_section(source_right) and source_right != "main":
            if CONFIG["main"].getboolean("auto_name_add"):
                app_data = RNS.Identity.recall_app_data(message.source_hash)
                if app_data != None and len(app_data) > 0:
                    try:
                        app_data_dict = umsgpack.unpackb(app_data)
                        if isinstance(app_data_dict, dict) and "c" in app_data_dict:
                            app_data = app_data_dict["c"]
                    except:
                        pass
                    source_name = app_data.decode('utf-8')
            DATA[source_right][source_hash] = source_name
            DATA.remove_option("main", "unsaved")
            content = config_get(CONFIG, "interface_messages", "auto_add_"+source_right, "", lng_key)
            content_group = config_get(CONFIG, "interface_messages", "member_join", "", lng_key)
            content_group = replace(content_group, source_hash, source_name, source_right, lng_key)
            if content_group != "":
                fields = fields_generate(lng_key, h=message.source_hash ,n=source_name, m=True, tpl="join")
                for section in sections:
                    if "receive_join" in config_get(CONFIG, "rights", section).split(","):
                        for (key, val) in DATA.items(section):
                            if key != source_hash:
                                LXMF_CONNECTION.send(key, content_group, title, fields, None, "interface_send")
            if CONFIG["main"].getboolean("auto_save_data"):
                DATA.remove_option("main", "unsaved")
                if not data_save(PATH + "/data.cfg"):
                    DATA["main"]["unsaved"] = "True"
            else:
                DATA["main"]["unsaved"] = "True"
            content = replace(content, source_hash, source_name, source_right, lng_key)
            if content != "":
                LXMF_CONNECTION.send(source_hash, content, title, fields_generate(lng_key, m=True, d=True, r=True, cmd=source_right, config=source_right, tpl="info"), None, "interface_send")
        return
    elif source_right == "":
        log("LXMF - Source " + RNS.prettyhexrep(message.source_hash) + " not exist (auto add disabled)", LOG_DEBUG)
        return


    source_rights = config_get(CONFIG, "rights", source_right)
    if source_rights == "":
        log("LXMF - Source " + RNS.prettyhexrep(message.source_hash) + " have no right", LOG_DEBUG)
        return
    source_rights = source_rights.split(",")


    if CONFIG["lxmf"].getboolean("signature_validated_known") and not message.signature_validated:
        log("LXMF - Source " + RNS.prettyhexrep(message.source_hash) + " have no valid signature 'known'", LOG_DEBUG)
        if "reply_signature" in source_rights:
            content_user = config_get(CONFIG, "interface_messages", "reply_signature", "", lng_key)
            content_user = replace(content_user, source_hash, source_name, source_right, lng_key)
            if content_user != "":
                LXMF_CONNECTION.send(source_hash, content_user, "", fields_generate(lng_key), None, "interface_send")
        return


    length = config_getint(CONFIG, "message", "receive_length_min", 0, lng_key)
    if length> 0:
        if len(content) < length:
            if "reply_length_min" in source_rights:
                content_user = config_get(CONFIG, "interface_messages", "reply_length_min", "", lng_key)
                content_user = replace(content_user, source_hash, source_name, source_right, lng_key)
                if content_user != "":
                    LXMF_CONNECTION.send(source_hash, content_user, "", fields_generate(lng_key), None, "interface_send")
            return


    length = config_getint(CONFIG, "message", "receive_length_max", 0, lng_key)
    if length > 0:
        if len(content) > length:
            if "reply_length_max" in source_rights:
                content_user = config_get(CONFIG, "interface_messages", "reply_length_max", "", lng_key)
                content_user = replace(content_user, source_hash, source_name, source_right, lng_key)
                if content_user != "":
                    LXMF_CONNECTION.send(source_hash, content_user, "", fields_generate(lng_key), None, "interface_send")
            return


    title_prefix = config_get(CONFIG, "message", "receive_title_prefix", "", lng_key)
    content_prefix = config_get(CONFIG, "message", "receive_prefix", "", lng_key)
    content_suffix = config_get(CONFIG, "message", "receive_suffix", "", lng_key)

    search = config_get(CONFIG, "message", "receive_search")
    if search != "":
        content = content.replace(search, config_get(CONFIG, "message", "receive_replace"))

    search = config_get(CONFIG, "message", "receive_regex_search")
    if search != "":
        content = re.sub(search, config_get(CONFIG, "message", "receive_regex_replace"), content)

    title = title_prefix + title
    content = content_prefix + content + content_suffix


    # Interface
    if content.startswith(CONFIG["interface"]["delimiter_input"]):
        if not config_getboolean(CONFIG, "interface", "enabled"):
            log("LXMF - Source " + RNS.prettyhexrep(message.source_hash) + " 'interface' disabled", LOG_DEBUG)
            if "reply_interface_enabled" in source_rights:
                content_user = config_get(CONFIG, "interface_messages", "reply_interface_enabled", "", lng_key)
                content_user = replace(content_user, source_hash, source_name, source_right, lng_key)
                if content_user != "":
                    LXMF_CONNECTION.send(source_hash, content_user, "", fields_generate(lng_key), None, "interface_send")
            return

        if "interface" not in source_rights:
            log("LXMF - Source " + RNS.prettyhexrep(message.source_hash) + " 'interface' not allowed", LOG_DEBUG)
            if "reply_interface_right" in source_rights:
                content_user = config_get(CONFIG, "interface_messages", "reply_interface_right", "", lng_key)
                content_user = replace(content_user, source_hash, source_name, source_right, lng_key)
                if content_user != "":
                    LXMF_CONNECTION.send(source_hash, content_user, "", fields_generate(lng_key), None, "interface_send")
            return

        content = interface(content[len(CONFIG["interface"]["delimiter_input"]):], source_hash, source_name, source_right, source_rights, lng_key, message)
        if content == "":
            log("LXMF - Source " + RNS.prettyhexrep(message.source_hash) + " 'interface' not allowed (empty response)", LOG_DEBUG)
            return

        if CONFIG["statistic"].getboolean("enabled"):
            if CONFIG["statistic"].getboolean("interface"):
                statistic("add", "interface_received_" + message.desired_method_str)
            if CONFIG["statistic"].getboolean("user"):
                statistic("value_set", source_hash, "activity", time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(time.time())))
                statistic("value_set", source_hash, "activity_receive", time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(time.time())))

        LXMF_CONNECTION.send(source_hash, content, "", fields_generate(lng_key), None, "interface_send")
        return


    # Message - Cluster
    if content.startswith(CONFIG["cluster"]["delimiter_input"]):
        if not config_getboolean(CONFIG, "cluster", "enabled") or not DATA["main"].getboolean("enabled_cluster"):
           log("LXMF - Source " + RNS.prettyhexrep(message.source_hash) + " 'cluster' disabled", LOG_DEBUG)
           if "reply_cluster_enabled" in source_rights:
               content_user = config_get(CONFIG, "interface_messages", "reply_cluster_enabled", "", lng_key)
               content_user = replace(content_user, source_hash, source_name, source_right, lng_key)
               if content_user != "":
                   LXMF_CONNECTION.send(source_hash, content_user, "", fields_generate(lng_key), None, "interface_send")
           return

        if "send_cluster" not in source_rights:
            log("LXMF - Source " + RNS.prettyhexrep(message.source_hash) + " 'cluster' not allowed", LOG_DEBUG)
            if "reply_cluster_right" in source_rights:
                content_user = config_get(CONFIG, "interface_messages", "reply_cluster_right", "", lng_key)
                content_user = replace(content_user, source_hash, source_name, source_right, lng_key)
                if content_user != "":
                    LXMF_CONNECTION.send(source_hash, content_user, "", fields_generate(lng_key), None, "interface_send")
            return

        try:
            content = content[len(CONFIG["cluster"]["delimiter_input"]):]
            destination, content = content.split(" ", 1)
        except:
            LXMF_CONNECTION.send(source_hash, config_get(CONFIG, "interface_menu", "cluster_format_error", "", lng_key) , "", fields_generate(lng_key), None, "interface_send")
            return

        destinations = []
        for (key, val) in DATA.items("cluster"):
            if key != destination_hash and destination in val.split("/"):
                destinations.append(key)

        if len(destinations) == 0:
            LXMF_CONNECTION.send(source_hash, config_get(CONFIG, "interface_menu", "cluster_found_error", "", lng_key) , "", fields_generate(lng_key), None, "interface_send")
            return

        length = config_getint(CONFIG, "message", "cluster_send_length_min", 0, lng_key)
        if length> 0:
            if len(content) < length:
                if "reply_length_min" in source_rights:
                    content_user = config_get(CONFIG, "interface_messages", "reply_length_min", "", lng_key)
                    content_user = replace(content_user, source_hash, source_name, source_right, lng_key)
                    if content_user != "":
                        LXMF_CONNECTION.send(source_hash, content_user, "", fields_generate(lng_key), None, "interface_send")
                return

        length = config_getint(CONFIG, "message", "cluster_send_length_max", 0, lng_key)
        if length > 0:
            if len(content) > length:
                if "reply_length_max" in source_rights:
                    content_user = config_get(CONFIG, "interface_messages", "reply_length_max", "", lng_key)
                    content_user = replace(content_user, source_hash, source_name, source_right, lng_key)
                    if content_user != "":
                        LXMF_CONNECTION.send(source_hash, content_user, "", fields_generate(lng_key), None, "interface_send")
                return

        title_prefix = config_get(CONFIG, "message", "cluster_send_title_prefix", "", lng_key)
        content_prefix = config_get(CONFIG, "message", "cluster_send_prefix", "", lng_key)
        content_suffix = config_get(CONFIG, "message", "cluster_send_suffix", "", lng_key)

        if "anonymous" in source_rights:
            title_prefix = replace(title_prefix, "", "", source_right, lng_key)
            content_prefix = replace(content_prefix, "", "", source_right, lng_key)
            content_suffix = replace(content_suffix, "", "", source_right, lng_key)
        else:
            title_prefix = replace(title_prefix, source_hash, source_name, source_right, lng_key)
            content_prefix = replace(content_prefix, source_hash, source_name, source_right, lng_key)
            content_suffix = replace(content_suffix, source_hash, source_name, source_right, lng_key)

        source = config_get(CONFIG, "cluster", "display_name", "", lng_key).rsplit('/', 1)[-1]
        title_prefix = title_prefix.replace(CONFIG["interface"]["delimiter_output"]+"cluster_source"+CONFIG["interface"]["delimiter_output"], source)
        title_prefix = title_prefix.replace(CONFIG["interface"]["delimiter_output"]+"cluster_destination"+CONFIG["interface"]["delimiter_output"], destination)
        content_prefix = content_prefix.replace(CONFIG["interface"]["delimiter_output"]+"cluster_source"+CONFIG["interface"]["delimiter_output"], source)
        content_prefix = content_prefix.replace(CONFIG["interface"]["delimiter_output"]+"cluster_destination"+CONFIG["interface"]["delimiter_output"], destination)
        content_suffix = content_suffix.replace(CONFIG["interface"]["delimiter_output"]+"cluster_source"+CONFIG["interface"]["delimiter_output"], source)
        content_suffix = content_suffix.replace(CONFIG["interface"]["delimiter_output"]+"cluster_destination"+CONFIG["interface"]["delimiter_output"], destination)

        search = config_get(CONFIG, "message", "cluster_send_search")
        if search != "":
            content = content.replace(search, config_get(CONFIG, "message", "cluster_send_replace"))

        search = config_get(CONFIG, "message", "cluster_send_regex_search")
        if search != "":
            content = re.sub(search, config_get(CONFIG, "message", "cluster_send_regex_replace"), content)

        if CONFIG["message"].getboolean("fields"):
            if message.fields:
                fields = fields_remove(message.fields, "fields_remove_anonymous" if "anonymous" in source_rights else "fields_remove")
            else:
                fields = {}
        else:
            fields = {}
        if CONFIG["main"].getboolean("fields_message"):
            if not "hash" in fields:
                fields["hash"] = message.hash
            if not "anonymous" in source_rights and "src" not in fields:
                fields["src"] = {}
                fields["src"]["h"] = message.source_hash
                fields["src"]["n"] = source_name
        fields["c_n"] = CONFIG["cluster"]["name"]
        fields["c_t"] = CONFIG["cluster"]["type"]

        delimiter_input = CONFIG["interface"]["delimiter_input"]
        if (content.startswith(delimiter_input+"pin ") or content.startswith(delimiter_input+"pins ")) and "cluster_pin_add" in source_rights:
            content = content.lstrip(delimiter_input+"pin ")
            content = content.lstrip(delimiter_input+"pins ")
            fields["m_t"] = "pin"
        else:
            fields["m_t"] = "message"

        title = title_prefix + title
        content = content_prefix + content + content_suffix

        if config_get(CONFIG, "message", "timestamp", "", lng_key) == "client":
            timestamp = message.timestamp
        else:
            timestamp = time.time()

        if CONFIG["statistic"].getboolean("enabled"):
            if CONFIG["statistic"].getboolean("cluster"):
                statistic("add", "cluster_received_" + message.desired_method_str)
            if CONFIG["statistic"].getboolean("user"):
                statistic("add", source_hash)
                statistic("value_set", source_hash, "activity", time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(time.time())))
                statistic("value_set", source_hash, "activity_receive", time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(time.time())))

        for val in destinations:
            LXMF_CONNECTION.send(key, content, title, fields, timestamp, "cluster_out")

        cluster_loop = False
        if destination in config_get(CONFIG, "cluster", "display_name", "", lng_key).split("/"):
            cluster_loop = True

        if CONFIG["message"].getboolean("fields"):
            if message.fields:
                fields = fields_remove(message.fields, "fields_remove_anonymous" if "anonymous" in source_rights else "fields_remove")
            else:
                fields = {}
        else:
            fields = {}

        if CONFIG["main"].getboolean("fields_message"):
            if CONFIG["lxmf"]["destination_type_conv"] != "":
                fields["type"] = CONFIG["lxmf"].getint("destination_type_conv")
            if not "hash" in fields:
                fields["hash"] = message.hash
            if not "anonymous" in source_rights and "src" not in fields:
                fields["src"] = {}
                fields["src"]["h"] = message.source_hash
                fields["src"]["n"] = source_name

        for section in sections:
            if "receive_cluster_send" in config_get(CONFIG, "rights", section).split(",") or (cluster_loop and "receive_cluster_loop" in config_get(CONFIG, "rights", section).split(",")):
                for (key, val) in DATA.items(section):
                    if key != source_hash:
                        LXMF_CONNECTION.send(key, content, title, fields, timestamp, "local_send")

        return


    # Message - Local
    if DATA["main"].getboolean("enabled_local"):
        if "send_local" in source_rights:

            length = config_getint(CONFIG, "message", "send_length_min", 0, lng_key)
            if length> 0:
                if len(content) < length:
                    if "reply_length_min" in source_rights:
                        content_user = config_get(CONFIG, "interface_messages", "reply_length_min", "", lng_key)
                        content_user = replace(content_user, source_hash, source_name, source_right, lng_key)
                        if content_user != "":
                            LXMF_CONNECTION.send(source_hash, content_user, "", fields_generate(lng_key), None, "interface_send")
                    return

            length = config_getint(CONFIG, "message", "send_length_max", 0, lng_key)
            if length > 0:
                if len(content) > length:
                    if "reply_length_max" in source_rights:
                        content_user = config_get(CONFIG, "interface_messages", "reply_length_max", "", lng_key)
                        content_user = replace(content_user, source_hash, source_name, source_right, lng_key)
                        if content_user != "":
                            LXMF_CONNECTION.send(source_hash, content_user, "", fields_generate(lng_key), None, "interface_send")
                    return

            title_prefix = config_get(CONFIG, "message", "send_title_prefix", "", lng_key)
            content_prefix = config_get(CONFIG, "message", "send_prefix", "", lng_key)
            content_suffix = config_get(CONFIG, "message", "send_suffix", "", lng_key)

            if "anonymous" in source_rights:
                title_prefix = replace(title_prefix, "", "", source_right, lng_key)
                content_prefix = replace(content_prefix, "", "", source_right, lng_key)
                content_suffix = replace(content_suffix, "", "", source_right, lng_key)
            else:
                title_prefix = replace(title_prefix, source_hash, source_name, source_right, lng_key)
                content_prefix = replace(content_prefix, source_hash, source_name, source_right, lng_key)
                content_suffix = replace(content_suffix, source_hash, source_name, source_right, lng_key)

            search = config_get(CONFIG, "message", "send_search")
            if search != "":
                content = content.replace(search, config_get(CONFIG, "message", "send_replace"))

            search = config_get(CONFIG, "message", "send_regex_search")
            if search != "":
                content = re.sub(search, config_get(CONFIG, "message", "send_regex_replace"), content)

            title = title_prefix + title
            content = content_prefix + content + content_suffix

            if CONFIG["message"].getboolean("fields"):
                if message.fields:
                    fields = fields_remove(message.fields, "fields_remove_anonymous" if "anonymous" in source_rights else "fields_remove")
                else:
                    fields = {}
            else:
                fields = {}

            if CONFIG["main"].getboolean("fields_message"):
                if CONFIG["lxmf"]["destination_type_conv"] != "":
                    fields["type"] = CONFIG["lxmf"].getint("destination_type_conv")
                if not "hash" in fields:
                    fields["hash"] = message.hash
                if not "anonymous" in source_rights and "src" not in fields:
                    fields["src"] = {}
                    fields["src"]["h"] = message.source_hash
                    fields["src"]["n"] = source_name

            if config_get(CONFIG, "message", "timestamp", "", lng_key) == "client":
                timestamp = message.timestamp
            else:
                timestamp = time.time()

            if CONFIG["statistic"].getboolean("enabled"):
                if CONFIG["statistic"].getboolean("local"):
                    statistic("add", "local_received_" + message.desired_method_str)
                if CONFIG["statistic"].getboolean("user"):
                    statistic("add", source_hash)
                    statistic("value_set", source_hash, "activity", time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(time.time())))
                    statistic("value_set", source_hash, "activity_receive", time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(time.time())))

            for section in sections:
                if "receive_local" in config_get(CONFIG, "rights", section).split(","):
                    for (key, val) in DATA.items(section):
                        if key != source_hash:
                            LXMF_CONNECTION.send(key, content, title, fields, timestamp, "local_send")
            return
        else:
            log("LXMF - Source " + RNS.prettyhexrep(message.source_hash) + " 'send' not allowed", LOG_DEBUG)
            if "reply_local_right" in source_rights:
                content_user = config_get(CONFIG, "interface_messages", "reply_local_right", "", lng_key)
                content_user = replace(content_user, source_hash, source_name, source_right, lng_key)
                if content_user != "":
                    LXMF_CONNECTION.send(source_hash, content_user, "", fields_generate(lng_key), None, "interface_send")
    else:
        if "reply_local_enabled" in source_rights:
            content_user = config_get(CONFIG, "interface_messages", "reply_local_enabled", "", lng_key)
            content_user = replace(content_user, source_hash, source_name, source_right, lng_key)
            if content_user != "":
                LXMF_CONNECTION.send(source_hash, content_user, "", fields_generate(lng_key), None, "interface_send")


    return




#### LXMF - Notification ####
def lxmf_message_notification_success_callback(message):
    if CONFIG["statistic"].getboolean("enabled"):
        if message.app_data.startswith("cluster") and CONFIG["statistic"].getboolean("cluster"):
            statistic("add", message.app_data + "_" + message.desired_method_str + "_success")
        elif message.app_data.startswith("router") and CONFIG["statistic"].getboolean("router"):
            statistic("add", message.app_data + "_" + message.desired_method_str + "_success")
        elif message.app_data.startswith("local") and CONFIG["statistic"].getboolean("local"):
            statistic("add", message.app_data + "_" + message.desired_method_str + "_success")
        elif message.app_data.startswith("interface") and CONFIG["statistic"].getboolean("interface"):
            statistic("add", message.app_data + "_" + message.desired_method_str + "_success")

        if CONFIG["statistic"].getboolean("user"):
            if message.desired_method_str == "direct":
                destination_hash = RNS.hexrep(message.destination_hash, False)
                statistic("value_set", destination_hash, "activity", time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(time.time())))
                statistic("value_set", destination_hash, "activity_send", time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(time.time())))
    return




#### LXMF - Notification ####
def lxmf_message_notification_failed_callback(message):
    if CONFIG["statistic"].getboolean("enabled"):
        if message.app_data.startswith("cluster") and CONFIG["statistic"].getboolean("cluster"):
            statistic("add", message.app_data + "_" + message.desired_method_str + "_failed")
        elif message.app_data.startswith("router") and CONFIG["statistic"].getboolean("router"):
            statistic("add", message.app_data + "_" + message.desired_method_str + "_failed")
        elif message.app_data.startswith("local") and CONFIG["statistic"].getboolean("local"):
            statistic("add", message.app_data + "_" + message.desired_method_str + "_failed")
        elif message.app_data.startswith("interface") and CONFIG["statistic"].getboolean("interface"):
            statistic("add", message.app_data + "_" + message.desired_method_str + "_failed")
    return


##############################################################################################################
# RNS Functions


class rns_announce_callback:
    def __init__(self, aspect_filter=None):
        self.aspect_filter = aspect_filter

    @staticmethod
    def received_announce(destination_hash, announced_identity, app_data):
        if app_data != None:
            log("Cluster - Received an announce from " + RNS.prettyhexrep(destination_hash) + ": " + app_data.decode("utf-8"), LOG_INFO)

            global DATA

            lng_key = "-" + CONFIG["main"]["lng"]

            sections = []
            for (key, val) in CONFIG.items("rights"):
                if DATA.has_section(key):
                    sections.append(key)

            receive = app_data.decode("utf-8")
            if receive != "":
                receive = json.loads(receive)
                executed = False

                if "h" in receive and "c" in receive and "c_n" in receive and CONFIG["cluster"].getboolean("enabled") and DATA["main"].getboolean("auto_add_cluster"):
                    if receive["c"] == "1":
                        if not DATA.has_option("cluster", receive["h"]):
                            content_group = config_get(CONFIG, "interface_messages", "cluster_join", "", lng_key)
                            content_group = replace(content_group, receive["h"], receive["c_n"], "", lng_key)
                            if content_group != "":
                                for section in sections:
                                    if "receive_cluster_join" in config_get(CONFIG, "rights", section).split(","):
                                        for (key, val) in DATA.items(section):
                                                LXMF_CONNECTION.send(key, content_group, "", fields_generate(lng_key), None, "interface_send")
                        DATA["cluster"][receive["h"]] = receive["c_n"]
                        executed = True

                if "h" in receive and "r" in receive and "r_n" in receive and CONFIG["router"].getboolean("enabled") and DATA["main"].getboolean("auto_add_router"):
                    if receive["r"] == "1":
                        DATA["router"][receive["h"]] = receive["r_n"]
                        executed = True

                if executed:
                    if CONFIG["main"].getboolean("auto_save_data"):
                        DATA.remove_option("main", "unsaved")
                        if not data_save(PATH + "/data.cfg"):
                            DATA["main"]["unsaved"] = "True"
                    else:
                        DATA["main"]["unsaved"] = "True"


##############################################################################################################
# Interface


#### Interface #####
def interface(cmd, source_hash, source_name, source_right, source_rights, lng_key, message):
    cmd = cmd.strip()

    content = ""

    delimiter = CONFIG["interface"]["delimiter_output"]

    sections = []
    for (key, val) in CONFIG.items("rights"):
        if DATA.has_section(key):
            sections.append(key)

    # "/help" command.
    if (cmd == "help" or cmd == "?") and "help" in source_rights:
        content = config_get(CONFIG, "interface_menu", "help_"+source_right, "", lng_key)
        interface_help = ""
        interface_help_command = ""
        for value in source_rights:
            interface_help = interface_help + config_get(CONFIG, "interface_help", value, "", lng_key)
            interface_help_command = interface_help_command + config_get(CONFIG, "interface_help_command", value, "", lng_key)
        content = content.replace(delimiter+"interface_help"+delimiter, interface_help)
        content = content.replace(delimiter+"interface_help_command"+delimiter, interface_help_command)
        content = replace(content, source_hash, source_name, source_right, lng_key)


    # "/update" command.
    elif (cmd == "update") and "update" in source_rights:
        try:
            content = config_get(CONFIG, "interface_menu", "update_ok", "", lng_key)
            LXMF_CONNECTION.send(source_hash, content, "", fields_generate(lng_key, m=True, d=True, r=True, cmd=source_right, config=source_right, tpl="update"), None, "interface_send")
            content = ""
        except:
            content = config_get(CONFIG, "interface_menu", "update_error", "", lng_key)


    # "/update_all" command.
    elif (cmd == "update_all") and "update_all" in source_rights:
        try:
            content = config_get(CONFIG, "interface_menu", "update_all_ok", "", lng_key)
            for section in sections:
                for (key, val) in DATA.items(section):
                    LXMF_CONNECTION.send(key, content, "", fields_generate(lng_key, m=True, d=True, r=True, cmd=section, config=section, tpl="update"), None, "interface_send")
            content = ""
        except:
            content = config_get(CONFIG, "interface_menu", "update_all_error", "", lng_key)


    # "/join" command.
    elif (cmd == "join" or cmd == "subscribe") and "join" in source_rights:
        try:
            content = config_get(CONFIG, "interface_messages", "auto_add_"+source_right, "", lng_key)
            content = replace(content, source_hash, source_name, source_right, lng_key)
            if content != "":
                LXMF_CONNECTION.send(source_hash, content, "", fields_generate(lng_key, m=True, d=True, r=True, cmd=source_right, config=source_right, tpl="info"), None, "interface_send")
                content = ""
        except:
            content = config_get(CONFIG, "interface_menu", "join_error", "", lng_key)


    # "/leave" command.
    elif (cmd == "leave" or cmd == "unsubscribe" or cmd == "part") and "leave" in source_rights:
        try:
            for section in sections:
                for (key, val) in DATA.items(section):
                    if key == source_hash:
                        DATA.remove_option(section, key)

            if CONFIG["statistic"].getboolean("enabled"):
                statistic("del", key)

            content_group = config_get(CONFIG, "interface_messages", "member_leave", "", lng_key)
            content_group = replace(content_group, source_hash, source_name, source_right, lng_key)
            if content_group != "":
                fields = fields_generate(lng_key, h=message.source_hash ,n=source_name, m=True, tpl="leave")
                for section in sections:
                    if "receive_leave" in config_get(CONFIG, "rights", section).split(","):
                        for (key, val) in DATA.items(section):
                            LXMF_CONNECTION.send(key, content_group, "", fields, None, "interface_send")

            content = config_get(CONFIG, "interface_menu", "leave_ok", "", lng_key)
            content = replace(content, source_hash, source_name, source_right, lng_key)
            if content != "":
                LXMF_CONNECTION.send(source_hash, content, "", {"data": None, "tpl": "info"}, None, "interface_send")
                content = ""

            if CONFIG["main"].getboolean("auto_save_data"):
                DATA.remove_option("main", "unsaved")
                if not data_save(PATH + "/data.cfg"):
                    DATA["main"]["unsaved"] = "True"
            else:
                DATA["main"]["unsaved"] = "True"
        except:
            content = config_get(CONFIG, "interface_menu", "leave_error", "", lng_key)


    # "/name" command.
    elif (cmd == "name" or cmd == "nick") and "name" in source_rights:
        content = config_get(CONFIG, "interface_menu", "name", "", lng_key)
        content = replace(content, source_hash, source_name, source_right, lng_key)

    elif (cmd.startswith("name ") or cmd.startswith("nick ") or cmd.startswith("setname ")) and "name" in source_rights:
        try:
            cmd, value = cmd.split(" ", 1)
            for section in sections:
                for (key, val) in DATA.items(section):
                    if key == source_hash:
                        DATA[section][key] = value

            if source_name == "":
                content_type = "name_def"
                content_add = " " + value
            else:
                content_type = "name_change"
                content_add = " " + source_name + " -> " + value

            content_group = config_get(CONFIG, "interface_messages", "member_"+content_type, "", lng_key)
            if content_group != "":
                fields = fields_generate(lng_key, h=message.source_hash ,n=source_name, tpl=content_type)
                content_group = replace(content_group, source_hash, source_name, source_right, lng_key)
                content_group = content_group + content_add
                for section in sections:
                    if "receive_"+content_type in config_get(CONFIG, "rights", section).split(","):
                        for (key, val) in DATA.items(section):
                            if key != source_hash:
                                LXMF_CONNECTION.send(key, content_group, "", fields, None, "interface_send")

            content = config_get(CONFIG, "interface_menu", "name_ok", "", lng_key) + " " + value

            if CONFIG["main"].getboolean("auto_save_data"):
                DATA.remove_option("main", "unsaved")
                if not data_save(PATH + "/data.cfg"):
                    DATA["main"]["unsaved"] = "True"
            else:
                DATA["main"]["unsaved"] = "True"
        except:
            content = config_get(CONFIG, "interface_menu", "name_error", "", lng_key)


    # "/address" command.
    elif cmd == "address" and "address" in source_rights:
        content = config_get(CONFIG, "interface_menu", "address_"+source_right, "", lng_key)
        content = replace(content, source_hash, source_name, source_right, lng_key)


    # "/info" command.
    elif cmd == "info" and "info" in source_rights:
        content = config_get(CONFIG, "interface_menu", "info_"+source_right, "", lng_key)
        content = replace(content, source_hash, source_name, source_right, lng_key)


    # "/pin" command.
    elif (cmd == "pin" or cmd == "pins") and "pin" in source_rights:
        count = 0
        content = config_get(CONFIG, "interface_menu", "pin_header", "", lng_key)
        content = replace(content, source_hash, source_name, source_right, lng_key)
        for (key, val) in DATA.items("pin"):
            count += 1
            content = content + "#" + key + "\n" + val + "\n\n"
        content = content.replace(delimiter+"count"+delimiter, str(count))

    elif (cmd.startswith("pin ") or cmd.startswith("pins ")) and "pin_add" in source_rights:
        try:
            cmd, value = cmd.split(" ", 1)
            value_new = config_get(CONFIG, "interface_menu", "pin", "", lng_key)
            value_new = replace(value_new, source_hash, source_name, source_right, lng_key)
            value_new = value_new.replace(delimiter+"value"+delimiter, value)

            key = time.strftime(config_get(CONFIG, "message", "pin_id", "%y%m%d-%H%M%S", lng_key), time.localtime(time.time()))
            if DATA.has_option("pin", key):
                key = key + "-"
                key_int = 0
                while DATA.has_option("pin", key+str(key_int)):
                    key_int += 1
                key = key+str(key_int)

            DATA["pin"][key] = value_new

            content_group = config_get(CONFIG, "interface_messages", "pin_add", "", lng_key)
            content_group = replace(content_group, source_hash, source_name, source_right, lng_key)
            content_group = content_group.replace(delimiter+"key"+delimiter, key)
            content_group = content_group.replace(delimiter+"value"+delimiter, value_new)
            if content_group != "":
                for section in sections:
                    if "receive_pin_add" in config_get(CONFIG, "rights", section).split(","):
                        for (key, val) in DATA.items(section):
                            if key != source_hash:
                                LXMF_CONNECTION.send(key, content_group, "", fields_generate(lng_key, h=message.source_hash ,n=source_name), None, "interface_send")

            content = config_get(CONFIG, "interface_menu", "pin_add_ok", "", lng_key)

            if CONFIG["main"].getboolean("auto_save_data"):
                DATA.remove_option("main", "unsaved")
                if not data_save(PATH + "/data.cfg"):
                    DATA["main"]["unsaved"] = "True"
            else:
                DATA["main"]["unsaved"] = "True"
        except:
            content = config_get(CONFIG, "interface_menu", "cmd_error", "", lng_key)

    elif (cmd.startswith("unpin ") or cmd.startswith("unpins ")) and "pin_remove" in source_rights:
        try:
            cmd, key = cmd.split(" ", 1)
            if key.startswith("#"):
                key = key[1:]
            if DATA.has_option("pin", key):
                value = DATA["pin"][key]
                DATA.remove_option("pin", key)

                content_group = config_get(CONFIG, "interface_messages", "pin_remove", "", lng_key)
                content_group = replace(content_group, source_hash, source_name, source_right, lng_key)
                content_group = content_group.replace(delimiter+"key"+delimiter, key)
                content_group = content_group.replace(delimiter+"value"+delimiter, value)
                if content_group != "":
                    for section in sections:
                        if "receive_pin_add" in config_get(CONFIG, "rights", section).split(","):
                            for (key, val) in DATA.items(section):
                                if key != source_hash:
                                    LXMF_CONNECTION.send(key, content_group, "", fields_generate(lng_key, h=message.source_hash ,n=source_name), None, "interface_send")

                content = config_get(CONFIG, "interface_menu", "pin_remove_ok", "", lng_key)

                if CONFIG["main"].getboolean("auto_save_data"):
                    DATA.remove_option("main", "unsaved")
                    if not data_save(PATH + "/data.cfg"):
                        DATA["main"]["unsaved"] = "True"
                else:
                    DATA["main"]["unsaved"] = "True"
            else:
                content = config_get(CONFIG, "interface_menu", "pin_found_error", "", lng_key)
        except:
            content = config_get(CONFIG, "interface_menu", "cmd_error", "", lng_key)


    # "/version" command.
    elif cmd == "version" and "version" in source_rights:
        content = config_get(CONFIG, "interface_menu", "version_header", "", lng_key)
        content = replace(content, source_hash, source_name, source_right, lng_key)
        content = content + NAME + "\n" + DESCRIPTION + "\nV" + VERSION


    # "/groups" command.
    elif (cmd == "groups"  or cmd == "group" or cmd == "cluster") and "groups" in source_rights:
        count = 0
        content = config_get(CONFIG, "interface_menu", "groups_header", "", lng_key)
        content = replace(content, source_hash, source_name, source_right, lng_key)
        content_member = config_get(CONFIG, "interface_menu", "groups_member", "", lng_key)
        data_dict = defaultdict(dict)
        section = "cluster"
        for (key, val) in DATA.items(section):
            data_dict[val] = key
        for key in sorted(data_dict):
            count += 1
            content = content + replace(content_member, data_dict[key], key, section, lng_key)
        content = content.replace(delimiter+"count"+delimiter, str(count))

    elif (cmd.startswith("groups ") or cmd.startswith("group ") or cmd.startswith("cluster ")) and "groups" in source_rights:
        try:
            cmd, value = cmd.split(" ", 1)
            executed = False
            count = 0
            content = config_get(CONFIG, "interface_menu", "groups_search_header", "", lng_key)
            content = replace(content, source_hash, source_name, source_right, lng_key)
            content_member = config_get(CONFIG, "interface_menu", "groups_search_member", "", lng_key)
            data_dict = defaultdict(dict)
            section = "cluster"
            for (key, val) in DATA.items(section):
                if value in val:
                    executed = True
                    data_dict[val] = key
            for key in sorted(data_dict):
                count += 1
                content = content + replace(content_member, data_dict[key], key, section, lng_key)
            content = content.replace(delimiter+"count"+delimiter, str(count))
            if not executed:
                content = config_get(CONFIG, "interface_menu", "groups_search_found_error", "", lng_key)
        except:
            content = config_get(CONFIG, "interface_menu", "cmd_error", "", lng_key)


    # "/members" command.
    elif (cmd == "members"  or cmd == "member" or cmd == "names" or cmd == "who") and "members" in source_rights:
        count = 0
        content = config_get(CONFIG, "interface_menu", "members_header", "", lng_key)
        content = replace(content, source_hash, source_name, source_right, lng_key)
        content_member = config_get(CONFIG, "interface_menu", "members_member", "", lng_key)
        for section in sections:
            for (key, val) in DATA.items(section):
                count += 1
                content = content + replace(content_member, key, val, section, lng_key)
        content = content.replace(delimiter+"count"+delimiter, str(count))


    # "/search" command.
    elif (cmd.startswith("search ") or cmd.startswith("whois ") or cmd.startswith("w ")) and "search" in source_rights:
        try:
            cmd, value = cmd.split(" ", 1)
            executed = False
            count = 0
            content = config_get(CONFIG, "interface_menu", "search_header", "", lng_key)
            content = replace(content, source_hash, source_name, source_right, lng_key)
            content_member = config_get(CONFIG, "interface_menu", "search_member", "", lng_key)
            for section in sections:
                for (key, val) in DATA.items(section):
                    if fnmatch.fnmatch(key, value) or fnmatch.fnmatch(val, value):
                        executed = True
                        count += 1
                        content = content + replace(content_member, key, val, section, lng_key).replace(delimiter+"activity_receive"+delimiter, statistic_value_get(key, "activity_receive")).replace(delimiter+"activity_send"+delimiter, statistic_value_get(key, "activity_send"))
            content = content.replace(delimiter+"count"+delimiter, str(count))
            if not executed:
                content = config_get(CONFIG, "interface_menu", "search_found_error", "", lng_key)
        except:
            content = config_get(CONFIG, "interface_menu", "cmd_error", "", lng_key)


    # "/activitys" command.
    elif (cmd == "activitys" or cmd == "activity") and "activitys" in source_rights:
        count = 0
        content = config_get(CONFIG, "interface_menu", "activitys_header", "", lng_key)
        content = replace(content, source_hash, source_name, source_right, lng_key)
        content_member = config_get(CONFIG, "interface_menu", "activitys_member", "", lng_key)
        for section in sections:
            for (key, val) in DATA.items(section):
                count += 1
                content = content + replace(content_member, key, val, section, lng_key).replace(delimiter+"activity_receive"+delimiter, statistic_value_get(key, "activity_receive")).replace(delimiter+"activity_send"+delimiter, statistic_value_get(key, "activity_send"))
        content = content.replace(delimiter+"count"+delimiter, str(count))


    # "/statistic" command.
    elif (cmd == "statistic" or cmd == "stat" or cmd == "stats" or cmd.startswith("statistic ") or cmd.startswith("stat ") or cmd.startswith("stats ")) and "statistic" in source_rights:
        try:
            cmd, value = cmd.split(" ", 1)
        except:
            value = "day"
        values = ["day", "last_day", "week", "last_week", "month", "last_month", "year", "last_year", "all", "max"] 
        if value in values:
            if CONFIG["statistic"].getboolean("enabled") and CONFIG["statistic"].getboolean("cluster") and "statistic_cluster" in source_rights and ("statistic_min" in source_rights or "statistic_full" in source_rights):
                content = content + replace(config_get(CONFIG, "interface_menu", "statistic_header_cluster", "", lng_key), source_hash, source_name, source_right, lng_key).replace(delimiter+"value"+delimiter, value)
                if "statistic_min" in source_rights:
                    statistic_recalculate("cluster_received_direct")
                    statistic_recalculate("cluster_received_propagated")
                    statistic_recalculate("cluster_send_direct_success")
                    statistic_recalculate("cluster_send_propagated_success")
                    statistic_recalculate("cluster_send_direct_failed")
                    statistic_recalculate("cluster_send_propagated_failed")
                    statistic_recalculate("cluster_in_direct")
                    statistic_recalculate("cluster_in_propagated")
                    statistic_recalculate("cluster_out_direct_success")
                    statistic_recalculate("cluster_out_propagated_success")
                    statistic_recalculate("cluster_out_direct_failed")
                    statistic_recalculate("cluster_out_propagated_failed")
                    content = content + "#Received: " + statistic_value_get("cluster_received_direct", value+"_value", "0") + "d/" + statistic_value_get("cluster_received_propagated", value+"_value", "0") + "p\n"
                    content = content + "#Send OK: " + statistic_value_get("cluster_send_direct_success", value+"_value", "0") + "d/" + statistic_value_get("cluster_send_propagated_success", value+"_value", "0") + "p\n"
                    content = content + "#Send Failed: " + statistic_value_get("cluster_send_direct_failed", value+"_value", "0") + "d/" + statistic_value_get("cluster_send_propagated_failed", value+"_value", "0") + "p\n"
                    content = content + "#In: " + statistic_value_get("cluster_in_direct", value+"_value", "0") + "d/" + statistic_value_get("cluster_in_propagated", value+"_value", "0") + "p\n"
                    content = content + "#Out OK: " + statistic_value_get("cluster_out_direct_success", value+"_value", "0") + "d/" + statistic_value_get("cluster_out_propagated_success", value+"_value", "0") + "p\n"
                    content = content + "#Out Failed: " + statistic_value_get("cluster_out_direct_failed", value+"_value", "0") + "d/" + statistic_value_get("cluster_out_propagated_failed", value+"_value", "0") + "p\n\n"
                if "statistic_full" in source_rights:
                    content = content + "#Received - Direct:\n" + statistic_get("cluster_received_direct") + "\n\n"
                    content = content + "#Received - Propagated:\n" + statistic_get("cluster_received_propagated") + "\n\n"
                    content = content + "#Send - Direct - Success:\n" + statistic_get("cluster_send_direct_success") + "\n\n"
                    content = content + "#Send - Propagated - Success:\n" + statistic_get("cluster_send_propagated_success") + "\n\n"
                    content = content + "#Send - Direct - Failed:\n" + statistic_get("cluster_send_direct_failed") + "\n\n"
                    content = content + "#Send - Propagated - Failed:\n" + statistic_get("cluster_send_propagated_failed") + "\n\n"
                    content = content + "#In - Direct:\n" + statistic_get("cluster_in_direct") + "\n\n"
                    content = content + "#In - Propagated:\n" + statistic_get("cluster_in_propagated") + "\n\n"
                    content = content + "#Out - Direct - Success:\n" + statistic_get("cluster_out_direct_success") + "\n\n"
                    content = content + "#Out - Propagated - Success:\n" + statistic_get("cluster_out_propagated_success") + "\n\n"
                    content = content + "#Out - Direct - Failed:\n" + statistic_get("cluster_out_direct_failed") + "\n\n"
                    content = content + "#Out - Propagated - Failed:\n" + statistic_get("cluster_out_propagated_failed") + "\n\n"

            if CONFIG["statistic"].getboolean("enabled") and CONFIG["statistic"].getboolean("router") and "statistic_router" in source_rights and ("statistic_min" in source_rights or "statistic_full" in source_rights):
                content = content + replace(config_get(CONFIG, "interface_menu", "statistic_header_router", "", lng_key), source_hash, source_name, source_right, lng_key).replace(delimiter+"value"+delimiter, value)
                if "statistic_min" in source_rights:
                    statistic_recalculate("router_in_direct")
                    statistic_recalculate("router_in_propagated")
                    statistic_recalculate("router_out_direct_success")
                    statistic_recalculate("router_out_propagated_success")
                    statistic_recalculate("router_out_direct_failed")
                    statistic_recalculate("router_out_propagated_failed")
                    content = content + "#In: " + statistic_value_get("router_in_direct", value+"_value", "0") + "d/" + statistic_value_get("router_in_propagated", value+"_value", "0") + "p\n"
                    content = content + "#Out OK: " + statistic_value_get("router_out_direct_success", value+"_value", "0") + "d/" + statistic_value_get("router_out_propagated_success", value+"_value", "0") + "p\n"
                    content = content + "#Out Failed: " + statistic_value_get("router_out_direct_failed", value+"_value", "0") + "d/" + statistic_value_get("router_out_propagated_failed", value+"_value", "0") + "p\n\n"
                if "statistic_full" in source_rights:
                    content = content + "#In - Direct:\n" + statistic_get("router_in_direct") + "\n\n"
                    content = content + "#In - Propagated:\n" + statistic_get("router_in_propagated") + "\n\n"
                    content = content + "#Out - Direct - Success:\n" + statistic_get("router_out_direct_success") + "\n\n"
                    content = content + "#Out - Propagated - Success:\n" + statistic_get("router_out_propagated_success") + "\n\n"
                    content = content + "#Out - Direct - Failed:\n" + statistic_get("router_out_direct_failed") + "\n\n"
                    content = content + "#Out - Propagated - Failed:\n" + statistic_get("router_out_propagated_failed") + "\n\n"

            if CONFIG["statistic"].getboolean("enabled") and CONFIG["statistic"].getboolean("local") and "statistic_local" in source_rights and ("statistic_min" in source_rights or "statistic_full" in source_rights):
                content = content + replace(config_get(CONFIG, "interface_menu", "statistic_header_local", "", lng_key), source_hash, source_name, source_right, lng_key).replace(delimiter+"value"+delimiter, value)
                if "statistic_min" in source_rights:
                    statistic_recalculate("local_received_direct")
                    statistic_recalculate("local_received_propagated")
                    statistic_recalculate("local_send_direct_success")
                    statistic_recalculate("local_send_propagated_success")
                    statistic_recalculate("local_send_direct_failed")
                    statistic_recalculate("local_send_propagated_failed")
                    content = content + "#Received: " + statistic_value_get("local_received_direct", value+"_value", "0") + "d/" + statistic_value_get("local_received_propagated", value+"_value", "0") + "p\n"
                    content = content + "#Send OK: " + statistic_value_get("local_send_direct_success", value+"_value", "0") + "d/" + statistic_value_get("local_send_propagated_success", value+"_value", "0") + "p\n"
                    content = content + "#Send Failed: " + statistic_value_get("local_send_direct_failed", value+"_value", "0") + "d/" + statistic_value_get("local_send_propagated_failed", value+"_value", "0") + "p\n\n"
                if "statistic_full" in source_rights:
                    content = content + "#Received - Direct:\n" + statistic_get("local_received_direct") + "\n\n"
                    content = content + "#Received - Propagated:\n" + statistic_get("local_received_propagated") + "\n\n"
                    content = content + "#Send - Direct - Success:\n" + statistic_get("local_send_direct_success") + "\n\n"
                    content = content + "#Send - Propagated - Success:\n" + statistic_get("local_send_propagated_success") + "\n\n"
                    content = content + "#Send - Direct - Failed:\n" + statistic_get("local_send_direct_failed") + "\n\n"
                    content = content + "#Send - Propagated - Failed:\n" + statistic_get("local_send_propagated_failed") + "\n\n"

            if CONFIG["statistic"].getboolean("enabled") and CONFIG["statistic"].getboolean("interface") and "statistic_interface" in source_rights and ("statistic_min" in source_rights or "statistic_full" in source_rights):
                content = content + replace(config_get(CONFIG, "interface_menu", "statistic_header_interface", "", lng_key), source_hash, source_name, source_right, lng_key).replace(delimiter+"value"+delimiter, value)
                if "statistic_min" in source_rights:
                    statistic_recalculate("interface_received_direct")
                    statistic_recalculate("interface_received_propagated")
                    statistic_recalculate("interface_send_direct_success")
                    statistic_recalculate("interface_send_propagated_success")
                    statistic_recalculate("interface_send_direct_failed")
                    statistic_recalculate("interface_send_propagated_failed")
                    content = content + "#Received: " + statistic_value_get("local_received_direct", value+"_value", "0") + "d/" + statistic_value_get("local_received_propagated", value+"_value", "0") + "p\n"
                    content = content + "#Send OK: " + statistic_value_get("interface_send_direct_success", value+"_value", "0") + "d/" + statistic_value_get("interface_send_propagated_success", value+"_value", "0") + "p\n"
                    content = content + "#Send Failed: " + statistic_value_get("interface_send_direct_failed", value+"_value", "0") + "d/" + statistic_value_get("interface_send_propagated_failed", value+"_value", "0") + "p\n\n"
                if "statistic_full" in source_rights:
                    content = content + "#Received - Direct:\n" + statistic_get("interface_received_direct") + "\n\n"
                    content = content + "#Received - Propagated:\n" + statistic_get("interface_received_propagated") + "\n\n"
                    content = content + "#Send - Direct - Success:\n" + statistic_get("interface_send_direct_success") + "\n\n"
                    content = content + "#Send - Propagated - Success:\n" + statistic_get("interface_send_propagated_success") + "\n\n"
                    content = content + "#Send - Direct - Failed:\n" + statistic_get("interface_send_direct_failed") + "\n\n"
                    content = content + "#Send - Propagated - Failed:\n" + statistic_get("interface_send_propagated_failed") + "\n\n"

            if CONFIG["statistic"].getboolean("enabled") and CONFIG["statistic"].getboolean("user") and "statistic_self" in source_rights and ("statistic_min" in source_rights or "statistic_full" in source_rights):
                content = content + replace(config_get(CONFIG, "interface_menu", "statistic_header_self", "", lng_key), source_hash, source_name, source_right, lng_key).replace(delimiter+"value"+delimiter, value)
                if "statistic_min" in source_rights or "statistic_full" in source_rights:
                    content = content + statistic_get(source_hash) + "\n\n"

            if CONFIG["statistic"].getboolean("enabled") and CONFIG["statistic"].getboolean("user") and "statistic_user" in source_rights and ("statistic_min" in source_rights or "statistic_full" in source_rights):
                content = content + replace(config_get(CONFIG, "interface_menu", "statistic_header_user", "", lng_key), source_hash, source_name, source_right, lng_key).replace(delimiter+"value"+delimiter, value)
                for section in STATISTIC.sections():
                    if section != "main" and not section.startswith("cluster") and not section.startswith("local") and not section.startswith("interface"):
                        if "statistic_min" in source_rights:
                            statistic_recalculate(section)
                            content = "<" + section + ">: " + statistic_value_get(section, value+"_value") + "\n"
                        if "statistic_full" in source_rights:
                            content = "<" + section + ">:\n" + statistic_get(section) + "\n\n"
        else:
            content = config_get(CONFIG, "interface_menu", "statistic_found_error", "", lng_key)


    # "/status" command.
    elif cmd == "status" and "status" in source_rights:
        content = config_get(CONFIG, "interface_menu", "status_"+source_right, "", lng_key)
        content = replace(content, source_hash, source_name, source_right, lng_key)
        content = content.replace(delimiter+"enabled_local"+delimiter, DATA["main"]["enabled_local"])
        content = content.replace(delimiter+"enabled_cluster"+delimiter, DATA["main"]["enabled_cluster"])


    # "/delivery" command.
    #elif cmd == "delivery" and "delivery" in source_rights:
    # TODO


    # "/enable_local" command.
    elif cmd == "enable_local" and "enable_local" in source_rights:
        if DATA["main"].getboolean("enabled_local"):
            content = config_get(CONFIG, "interface_menu", "enable_local_true", "", lng_key)
        else:
            content = config_get(CONFIG, "interface_menu", "enable_local_false", "", lng_key)

    elif cmd.startswith("enable_local ") and "enable_local" in source_rights:
        try:
            cmd, value = cmd.split(" ", 1)
            if val_to_bool(value):
                DATA["main"]["enabled_local"] = "True"
                content = config_get(CONFIG, "interface_menu", "enable_local_true", "", lng_key)
                DATA["main"]["unsaved_local"] = "True"
            else:
                DATA["main"]["enabled_local"] = "False"
                content = config_get(CONFIG, "interface_menu", "enable_local_false", "", lng_key)
                DATA["main"]["unsaved"] = "True"
        except:
            content = config_get(CONFIG, "interface_menu", "enable_local_error", "", lng_key)


    # "/enable_cluster" command.
    elif cmd == "enable_cluster" and "enable_cluster" in source_rights:
        if DATA["main"].getboolean("enabled_cluster"):
            content = config_get(CONFIG, "interface_menu", "enable_cluster_true", "", lng_key)
        else:
            content = config_get(CONFIG, "interface_menu", "enable_cluster_false", "", lng_key)

    elif cmd.startswith("enable_cluster ") and "enable_cluster" in source_rights:
        try:
            cmd, value = cmd.split(" ", 1)
            if val_to_bool(value):
                DATA["main"]["enabled_cluster"] = "True"
                content = config_get(CONFIG, "interface_menu", "enable_cluster_true", "", lng_key)
                DATA["main"]["unsaved_cluster"] = "True"
            else:
                DATA["main"]["enabled_cluster"] = "False"
                content = config_get(CONFIG, "interface_menu", "enable_cluster_false", "", lng_key)
                DATA["main"]["unsaved"] = "True"
        except:
            content = config_get(CONFIG, "interface_menu", "enable_cluster_error", "", lng_key)


    # "/auto_add_user" command.
    elif cmd == "auto_add_user" and "auto_add_user" in source_rights:
        if DATA["main"].getboolean("auto_add_user"):
            content = config_get(CONFIG, "interface_menu", "auto_add_user_true", "", lng_key)
        else:
            content = config_get(CONFIG, "interface_menu", "auto_add_user_false", "", lng_key)

    elif cmd.startswith("auto_add_user ") and "auto_add_user" in source_rights:
        try:
            cmd, value = cmd.split(" ", 1)
            if val_to_bool(value):
                DATA["main"]["auto_add_user"] = "True"
                content = config_get(CONFIG, "interface_menu", "auto_add_user_true", "", lng_key)
                DATA["main"]["unsaved"] = "True"
            else:
                DATA["main"]["auto_add_user"] = "False"
                content = config_get(CONFIG, "interface_menu", "auto_add_user_false", "", lng_key)
                DATA["main"]["unsaved"] = "True"
        except:
            content = config_get(CONFIG, "interface_menu", "auto_add_user_error", "", lng_key)


    # "/auto_add_user_type" command.
    elif cmd == "auto_add_user_type" and "auto_add_user_type" in source_rights:
        content = config_get(DATA, "main", "auto_add_user_type", "", lng_key)

    elif cmd.startswith("auto_add_user_type ") and "auto_add_user_type" in source_rights:
        try:
            cmd, value = cmd.split(" ", 1)
            DATA["main"]["auto_add_user_type"] = value
            content = config_get(CONFIG, "interface_menu", "auto_add_user_type", "", lng_key) + " " + value
            DATA["main"]["unsaved"] = "True"
        except:
            content = config_get(CONFIG, "interface_menu", "auto_add_user_type_error", "", lng_key)


    # "/auto_add_cluster" command.
    elif cmd == "auto_add_cluster" and "auto_add_cluster" in source_rights:
        if DATA["main"].getboolean("auto_add_cluster"):
            content = config_get(CONFIG, "interface_menu", "auto_add_cluster_true", "", lng_key)
        else:
            content = config_get(CONFIG, "interface_menu", "auto_add_cluster_false", "", lng_key)

    elif cmd.startswith("auto_add_cluster ") and "auto_add_cluster" in source_rights:
        try:
            cmd, value = cmd.split(" ", 1)
            if val_to_bool(value):
                DATA["main"]["auto_add_cluster"] = "True"
                content = config_get(CONFIG, "interface_menu", "auto_add_cluster_true", "", lng_key)
                DATA["main"]["unsaved"] = "True"
            else:
                DATA["main"]["auto_add_cluster"] = "False"
                content = config_get(CONFIG, "interface_menu", "auto_add_cluster_false", "", lng_key)
                DATA["main"]["unsaved"] = "True"
        except:
            content = config_get(CONFIG, "interface_menu", "auto_add_cluster_error", "", lng_key)


    # "/auto_add_router" command.
    elif cmd == "auto_add_router" and "auto_add_router" in source_rights:
        if DATA["main"].getboolean("auto_add_router"):
            content = config_get(CONFIG, "interface_menu", "auto_add_router_true", "", lng_key)
        else:
            content = config_get(CONFIG, "interface_menu", "auto_add_router_false", "", lng_key)

    elif cmd.startswith("auto_add_router ") and "auto_add_router" in source_rights:
        try:
            cmd, value = cmd.split(" ", 1)
            if val_to_bool(value):
                DATA["main"]["auto_add_router"] = "True"
                content = config_get(CONFIG, "interface_menu", "auto_add_router_true", "", lng_key)
                DATA["main"]["unsaved"] = "True"
            else:
                DATA["main"]["auto_add_router"] = "False"
                content = config_get(CONFIG, "interface_menu", "auto_add_router_false", "", lng_key)
                DATA["main"]["unsaved"] = "True"
        except:
            content = config_get(CONFIG, "interface_menu", "auto_add_router_error", "", lng_key)


    # "/invite_user" command.
    elif cmd == "invite_user" and "invite_user" in source_rights:
        if DATA["main"].getboolean("invite_user"):
            content = config_get(CONFIG, "interface_menu", "invite_user_true", "", lng_key)
        else:
            content = config_get(CONFIG, "interface_menu", "invite_user_false", "", lng_key)

    elif cmd.startswith("invite_user ") and "invite_user" in source_rights:
        try:
            cmd, value = cmd.split(" ", 1)
            if val_to_bool(value):
                DATA["main"]["invite_user"] = "True"
                content = config_get(CONFIG, "interface_menu", "invite_user_true", "", lng_key)
                DATA["main"]["unsaved"] = "True"
            else:
                DATA["main"]["invite_user"] = "False"
                content = config_get(CONFIG, "interface_menu", "invite_user_false", "", lng_key)
                DATA["main"]["unsaved"] = "True"
        except:
            content = config_get(CONFIG, "interface_menu", "invite_user_error", "", lng_key)


    # "/invite_user_type" command.
    elif cmd == "invite_user_type" and "invite_user_type" in source_rights:
        content = config_get(DATA, "main", "invite_user_type", "", lng_key)

    elif cmd.startswith("invite_user_type ") and "invite_user_type" in source_rights:
        try:
            cmd, value = cmd.split(" ", 1)
            DATA["main"]["invite_user_type"] = value
            content = config_get(CONFIG, "interface_menu", "invite_user_type", "", lng_key) + " " + value
            DATA["main"]["unsaved"] = "True"
        except:
            content = config_get(CONFIG, "interface_menu", "invite_user_type_error", "", lng_key)


    # "/allow_user" command.
    elif cmd == "allow_user" and "allow_user" in source_rights:
        if DATA["main"].getboolean("allow_user"):
            content = config_get(CONFIG, "interface_menu", "allow_user_true", "", lng_key)
        else:
            content = config_get(CONFIG, "interface_menu", "allow_user_false", "", lng_key)

    elif cmd.startswith("allow_user ") and "allow_user" in source_rights:
        try:
            cmd, value = cmd.split(" ", 1)
            if val_to_bool(value):
                DATA["main"]["allow_user"] = "True"
                content = config_get(CONFIG, "interface_menu", "allow_user_true", "", lng_key)
                DATA["main"]["unsaved"] = "True"
            else:
                DATA["main"]["allow_user"] = "False"
                content = config_get(CONFIG, "interface_menu", "allow_user_false", "", lng_key)
                DATA["main"]["unsaved"] = "True"
        except:
            content = config_get(CONFIG, "interface_menu", "allow_user_error", "", lng_key)


    # "/allow_user_type" command.
    elif cmd == "allow_user_type" and "allow_user_type" in source_rights:
        content = config_get(DATA, "main", "allow_user_type", "", lng_key)

    elif cmd.startswith("allow_user_type ") and "allow_user_type" in source_rights:
        try:
            cmd, value = cmd.split(" ", 1)
            DATA["main"]["allow_user_type"] = value
            content = config_get(CONFIG, "interface_menu", "allow_user_type", "", lng_key) + " " + value
            DATA["main"]["unsaved"] = "True"
        except:
            content = config_get(CONFIG, "interface_menu", "allow_user_type_error", "", lng_key)


    # "/deny_user" command.
    elif cmd == "deny_user" and "deny_user" in source_rights:
        if DATA["main"].getboolean("deny_user"):
            content = config_get(CONFIG, "interface_menu", "deny_user_true", "", lng_key)
        else:
            content = config_get(CONFIG, "interface_menu", "deny_user_false", "", lng_key)

    elif cmd.startswith("deny_user ") and "deny_user" in source_rights:
        try:
            cmd, value = cmd.split(" ", 1)
            if val_to_bool(value):
                DATA["main"]["deny_user"] = "True"
                content = config_get(CONFIG, "interface_menu", "deny_user_true", "", lng_key)
                DATA["main"]["unsaved"] = "True"
            else:
                DATA["main"]["deny_user"] = "False"
                content = config_get(CONFIG, "interface_menu", "deny_user_false", "", lng_key)
                DATA["main"]["unsaved"] = "True"
        except:
            content = config_get(CONFIG, "interface_menu", "deny_user_error", "", lng_key)


    # "/deny_user_type" command.
    elif cmd == "deny_user_type" and "deny_user_type" in source_rights:
        content = config_get(DATA, "main", "deny_user_type", "", lng_key)

    elif cmd.startswith("deny_user_type ") and "deny_user_type" in source_rights:
        try:
            cmd, value = cmd.split(" ", 1)
            DATA["main"]["deny_user_type"] = value
            content = config_get(CONFIG, "interface_menu", "deny_user_type", "", lng_key) + " " + value
            DATA["main"]["unsaved"] = "True"
        except:
            content = config_get(CONFIG, "interface_menu", "deny_user_type_error", "", lng_key)


    # "/description" command.
    elif cmd == "description" and "description" in source_rights:
        content = config_get(DATA, "main", "description", "", lng_key)
        content = replace(content, source_hash, source_name, source_right, lng_key)

    elif cmd.startswith("description ") and "description_set" in source_rights:
        try:
            cmd, value = cmd.split(" ", 1)
            DATA["main"]["description"+lng_key] = value

            content_group = config_get(CONFIG, "interface_messages", "description", "", lng_key)
            content_group = replace(content_group, source_hash, source_name, source_right, lng_key)
            if content_group != "":
                for section in sections:
                    if "receive_description" in config_get(CONFIG, "rights", section).split(","):
                        for (key, val) in DATA.items(section):
                            if key != source_hash:
                                LXMF_CONNECTION.send(key, content_group, "", fields_generate(lng_key, h=message.source_hash ,n=source_name, tpl="description"), None, "interface_send")

            content = config_get(CONFIG, "interface_menu", "description", "", lng_key) + " " + value
            DATA["main"]["unsaved"] = "True"
        except:
            content = config_get(CONFIG, "interface_menu", "description_error", "", lng_key)


    # "/rules" command.
    elif cmd == "rules" and "rules" in source_rights:
        content = config_get(DATA, "main", "rules", "", lng_key)
        content = replace(content, source_hash, source_name, source_right, lng_key)

    elif cmd.startswith("rules ") and "rules_set" in source_rights:
        try:
            cmd, value = cmd.split(" ", 1)
            DATA["main"]["rules"+lng_key] = value

            content_group = config_get(CONFIG, "interface_messages", "rules", "", lng_key)
            content_group = replace(content_group, source_hash, source_name, source_right, lng_key)
            if content_group != "":
                for section in sections:
                    if "receive_rules" in config_get(CONFIG, "rights", section).split(","):
                        for (key, val) in DATA.items(section):
                            if key != source_hash:
                                LXMF_CONNECTION.send(key, content_group, "", fields_generate(lng_key, h=message.source_hash ,n=source_name, tpl="rules"), None, "interface_send")

            content = config_get(CONFIG, "interface_menu", "rules", "", lng_key) + " " + value
            DATA["main"]["unsaved"] = "True"
        except:
            content = config_get(CONFIG, "interface_menu", "rules_error", "", lng_key)


    # "/readme" command.
    elif cmd == "readme" and "readme" in source_rights:
        content = config_get(CONFIG, "interface_menu", "readme", "", lng_key)
        content = replace(content, source_hash, source_name, source_right, lng_key)


    # "/time" command.
    elif cmd == "time" and "time" in source_rights:
        content = config_get(CONFIG, "interface_menu", "time", "", lng_key)
        content = time.strftime(content, time.localtime(time.time()))
        content = replace(content, source_hash, source_name, source_right, lng_key)


    # "/announce" command.
    elif cmd == "announce" and "announce" in source_rights:
        content = config_get(CONFIG, "interface_menu", "announce", "", lng_key)
        content = replace(content, source_hash, source_name, source_right, lng_key)
        LXMF_CONNECTION.announce_now()
        if CONFIG["cluster"].getboolean("enabled"):
            RNS_CONNECTION.announce_now()


    # "/sync" command.
    elif cmd == "sync" and "sync" in source_rights:
        content = config_get(CONFIG, "interface_menu", "sync", "", lng_key)
        content = replace(content, source_hash, source_name, source_right, lng_key)
        LXMF_CONNECTION.sync_now()


    # "/show run" command.
    elif (cmd == "show run" or cmd == "sh run") and "show_run" in source_rights:
        content = config_get(CONFIG, "interface_menu", "show_run_header", "", lng_key)
        content = replace(content, source_hash, source_name, source_right, lng_key)
        for (key, val) in DATA.items("main"):
            content = content + key + " = " + val + "\n"


    # "/show" command.
    elif (cmd.startswith("show") or cmd.startswith("list") or cmd.startswith("sh")) and "show" in source_rights:
        try:
            cmd, key = cmd.split(" ", 1)
            if DATA.has_section(key) and key != "main":
                content = config_get(CONFIG, "interface_menu", "show_header", "", lng_key)
                content = replace(content, source_hash, source_name, source_right, lng_key)
                content = content + "[" + key + "]\n"
                for (section_key, section_val) in DATA.items(key):
                    content = content + section_key + " = " + section_val + "\n"
            else:
                content = config_get(CONFIG, "interface_menu", "user_type_error", "", lng_key) + " " + key
        except:
            content = config_get(CONFIG, "interface_menu", "show_header", "", lng_key)
            content = replace(content, source_hash, source_name, source_right, lng_key)
            for section in DATA.sections():
                if section in sections or section.replace("block_", "") in sections:
                    content = content + "[" + section + "]\n"
                    for (key, val) in DATA.items(section):
                        content = content + key + " = " + val + "\n"
                content = content + "\n"


    # "/user" command.
    elif cmd.startswith("add ") and "add" in source_rights:
        try:
            cmd, key, value, name = cmd.split(" ", 3)
            if DATA.has_section(key) and key != "main":
                value = LXMF_CONNECTION.destination_correct(value)
                if value != "":
                    for section in DATA.sections():
                        if section != "main":
                            for (key, val) in DATA.items(section):
                                if key == value:
                                    DATA.remove_option(section, key)
                    DATA[key][value] = name
                    content = config_get(CONFIG, "interface_menu", "user_add", "", lng_key) + " " + value + " -> " + key
                    DATA["main"]["unsaved"] = "True"
                else:
                    content = config_get(CONFIG, "interface_menu", "user_format_error", "", lng_key)
            else:
                content = config_get(CONFIG, "interface_menu", "user_type_error", "", lng_key)
        except:
            content = config_get(CONFIG, "interface_menu", "cmd_error", "", lng_key)


    # "/user" command.
    elif (cmd.startswith("del ") or cmd.startswith("rm ") or cmd.startswith("delete ")) and "del" in source_rights:
        try:
            cmd, key, value = cmd.split(" ", 2)
            if DATA.has_section(key) and key != "main":
                value = LXMF_CONNECTION.destination_correct(value)
                if value != "":
                    if DATA.has_option(key, value):
                        DATA.remove_option(key, value)
                        content = config_get(CONFIG, "interface_menu", "user_del", "", lng_key) + " " + value + " -> " + key
                        DATA["main"]["unsaved"] = "True"

                        if CONFIG["statistic"].getboolean("enabled"):
                            statistic("del", value)

                    else:
                        content = config_get(CONFIG, "interface_menu", "user_error", "", lng_key) + " " + value + " -> " + key
                else:
                    content = config_get(CONFIG, "interface_menu", "user_format_error", "", lng_key)
            else:
                content = config_get(CONFIG, "interface_menu", "user_type_error", "", lng_key)
        except:
            try:
                cmd, value = cmd.split(" ", 1)
                value = LXMF_CONNECTION.destination_correct(value)
                if value != "":
                    for section in DATA.sections():
                        if section != "main":
                            for (key, val) in DATA.items(section):
                                if key == value:
                                    DATA.remove_option(section, key)
                                    if CONFIG["statistic"].getboolean("enabled"):
                                        statistic("del", value)
                    content = "OK: Removed user '" + value + "' from all types"
                    DATA["main"]["unsaved"] = "True"
                else:
                    content = config_get(CONFIG, "interface_menu", "user_format_error", "", lng_key)
            except:
               content = config_get(CONFIG, "interface_menu", "cmd_error", "", lng_key)


    # "/user" command.
    elif (cmd.startswith("move ") or cmd.startswith("mv ")) and "move" in source_rights:
        try:
            cmd, key, value = cmd.split(" ", 2)
            if DATA.has_section(key) and key != "main":
                value = LXMF_CONNECTION.destination_correct(value)
                if value != "":
                    for section in DATA.sections():
                        if section != "main":
                            for (key_old, val_old) in DATA.items(section):
                                if key_old == value:
                                    DATA.remove_option(section, key_old)
                                    DATA[key][value] = val_old
                                    content = config_get(CONFIG, "interface_menu", "user_move", "", lng_key) + " " + value + " -> " + key
                                    DATA["main"]["unsaved"] = "True"
                    if content == "":
                        content = config_get(CONFIG, "interface_menu", "user_format_error", "", lng_key)
                else:
                    content = config_get(CONFIG, "interface_menu", "user_format_error", "", lng_key)
            else:
                content = config_get(CONFIG, "interface_menu", "user_type_error", "", lng_key)
        except:
            content = config_get(CONFIG, "interface_menu", "cmd_error", "", lng_key)


    # "/user" command.
    elif cmd.startswith("rename ") and "rename" in source_rights:
        try:
            cmd, key, value = cmd.split(" ", 2)
            key = LXMF_CONNECTION.destination_correct(key)
            if key != "":
                executed = False
                for section in sections:
                    if DATA.has_option(section, key):
                        content = config_get(CONFIG, "interface_menu", "user_rename", "", lng_key) + " " + DATA[section][key] + " -> " + value
                        DATA[section][key] = value
                        executed = True
                if executed:
                    if CONFIG["main"].getboolean("auto_save_data"):
                        DATA.remove_option("main", "unsaved")
                        if not data_save(PATH + "/data.cfg"):
                            DATA["main"]["unsaved"] = "True"
                    else:
                        DATA["main"]["unsaved"] = "True"
                else:
                    content = config_get(CONFIG, "interface_menu", "user_found_error", "", lng_key) 
            else:
                content = config_get(CONFIG, "interface_menu", "user_format_error", "", lng_key)
        except:
           content = config_get(CONFIG, "interface_menu", "cmd_error", "", lng_key)


    # "/invite" command.
    elif cmd.startswith("invite ") and "invite" in source_rights:
        if DATA["main"].getboolean("invite_user"):
            try:
                cmd, value = cmd.split(" ", 1)
                key = DATA["main"]["invite_user_type"]
                if DATA.has_section(key) and key != "main":
                    value = LXMF_CONNECTION.destination_correct(value)
                    if value != "":
                        user_name = ""
                        if CONFIG["main"].getboolean("auto_name_add"):
                            app_data = RNS.Identity.recall_app_data(bytes.fromhex(value))
                            if app_data != None:
                                user_name = app_data.decode('utf-8')
                        DATA[key][value] = user_name

                        content_user = config_get(CONFIG, "interface_messages", "invite_"+key, "", lng_key)
                        content_user = replace(content_user, source_hash, source_name, source_right, lng_key)
                        content_user = content_user.replace(delimiter+"user_name"+delimiter, user_name)
                        if content_user != "":
                            LXMF_CONNECTION.send(value, content_user, "", fields_generate(lng_key, m=True, d=True, r=True, cmd=key, config=key), None, "interface_send")

                        content_group = config_get(CONFIG, "interface_messages", "member_invite", "", lng_key)
                        content_group = replace(content_group, source_hash, source_name, source_right, lng_key)
                        content_group = content_group.replace(delimiter+"user_address"+delimiter, value)
                        content_group = content_group.replace(delimiter+"user_name"+delimiter, user_name)
                        if content_group != "":
                            fields = fields_generate(lng_key, h=bytes.fromhex(value) ,n=user_name, m=True, tpl="invite")
                            for section in sections:
                                if "receive_invite" in config_get(CONFIG, "rights", section).split(","):
                                    for (key, val) in DATA.items(section):
                                        if key != source_hash:
                                            LXMF_CONNECTION.send(key, content_group, "", fields, None, "interface_send")

                        content = config_get(CONFIG, "interface_menu", "invite_ok", "", lng_key) + " <" + value + ">"

                        if CONFIG["main"].getboolean("auto_save_data"):
                            DATA.remove_option("main", "unsaved")
                            if not data_save(PATH + "/data.cfg"):
                                DATA["main"]["unsaved"] = "True"
                        else:
                            DATA["main"]["unsaved"] = "True"
                    else:
                        content = config_get(CONFIG, "interface_menu", "invite_format_error", "", lng_key)
                else:
                    content = config_get(CONFIG, "interface_menu", "invite_type_error", "", lng_key)
            except:
                content = config_get(CONFIG, "interface_menu", "cmd_error", "", lng_key)
        else:
            content = config_get(CONFIG, "interface_menu", "cmd_error", "", lng_key)


    # "/kick" command.
    elif cmd.startswith("kick ") and "kick" in source_rights:
        try:
            cmd, value = cmd.split(" ", 1)
            value = LXMF_CONNECTION.destination_correct(value)
            if value != "":
                executed = False
                for section in sections:
                    for (key, val) in DATA.items(section):
                        if key == value:
                            user_section = section
                            user_name = val
                            executed = True
                            DATA.remove_option(section, key)
                if executed:
                    if CONFIG["statistic"].getboolean("enabled"):
                        statistic("del", value)

                    content_user = config_get(CONFIG, "interface_messages", "kick_"+user_section, "", lng_key)
                    content_user = replace(content_user, source_hash, source_name, source_right, lng_key)
                    if content_user != "":
                        LXMF_CONNECTION.send(value, content_user, "", fields_generate(lng_key), None, "interface_send")

                    content_group = config_get(CONFIG, "interface_messages", "member_kick", "", lng_key)
                    content_group = replace(content_group, source_hash, source_name, source_right, lng_key)
                    content_group = content_group.replace(delimiter+"user_address"+delimiter, value)
                    content_group = content_group.replace(delimiter+"user_name"+delimiter, user_name)
                    if content_group != "":
                        fields = fields_generate(lng_key, h=bytes.fromhex(value) ,n=user_name, m=True, tpl="kick")
                        for section in sections:
                            if "receive_kick" in config_get(CONFIG, "rights", section).split(","):
                                for (key, val) in DATA.items(section):
                                    LXMF_CONNECTION.send(key, content_group, "", fields, None, "interface_send")

                    content = config_get(CONFIG, "interface_menu", "kick_ok", "", lng_key)
                    content = content.replace(delimiter+"user_address"+delimiter, value)
                    content = content.replace(delimiter+"user_name"+delimiter, user_name)

                    if CONFIG["main"].getboolean("auto_save_data"):
                        DATA.remove_option("main", "unsaved")
                        if not data_save(PATH + "/data.cfg"):
                            DATA["main"]["unsaved"] = "True"
                    else:
                        DATA["main"]["unsaved"] = "True"
                else:
                    content = config_get(CONFIG, "interface_menu", "kick_found_error", "", lng_key) 
            else:
                content = config_get(CONFIG, "interface_menu", "kick_format_error", "", lng_key) 
        except:
           content = config_get(CONFIG, "interface_menu", "cmd_error", "", lng_key)


    # "/block" command.
    elif (cmd.startswith("block ") or cmd.startswith("ban ")) and "block" in source_rights:
        try:
            cmd, value = cmd.split(" ", 1)
            value = LXMF_CONNECTION.destination_correct(value)
            if value != "":
                executed = False
                for section in sections:
                    for (key, val) in DATA.items(section):
                        if key == value:
                            user_section = section
                            user_name = val
                            executed = True
                            if not DATA.has_section("block_"+section):
                                DATA.add_section("block_"+section)
                            DATA["block_"+section][key] = val
                            DATA.remove_option(section, key)
                if executed:
                    content_user = config_get(CONFIG, "interface_messages", "block_"+user_section, "", lng_key)
                    content_user = replace(content_user, source_hash, source_name, source_right, lng_key)
                    if content_user != "":
                        LXMF_CONNECTION.send(value, content_user, "", fields_generate(lng_key), None, "interface_send")

                    content_group = config_get(CONFIG, "interface_messages", "member_block", "", lng_key)
                    content_group = replace(content_group, source_hash, source_name, source_right, lng_key)
                    content_group = content_group.replace(delimiter+"user_address"+delimiter, value)
                    content_group = content_group.replace(delimiter+"user_name"+delimiter, user_name)
                    if content_group != "":
                        fields = fields_generate(lng_key, h=bytes.fromhex(value) ,n=user_name, m=True, tpl="block")
                        for section in sections:
                            if "receive_block" in config_get(CONFIG, "rights", section).split(","):
                                for (key, val) in DATA.items(section):
                                    LXMF_CONNECTION.send(key, content_group, "", fields, None, "interface_send")

                    content = config_get(CONFIG, "interface_menu", "block_ok", "", lng_key)
                    content = content.replace(delimiter+"user_address"+delimiter, value)
                    content = content.replace(delimiter+"user_name"+delimiter, user_name)

                    if CONFIG["main"].getboolean("auto_save_data"):
                        DATA.remove_option("main", "unsaved")
                        if not data_save(PATH + "/data.cfg"):
                            DATA["main"]["unsaved"] = "True"
                    else:
                        DATA["main"]["unsaved"] = "True"
                else:
                    content = config_get(CONFIG, "interface_menu", "block_found_error", "", lng_key)
            else:
                content = config_get(CONFIG, "interface_menu", "block_format_error", "", lng_key)
        except:
           content = config_get(CONFIG, "interface_menu", "cmd_error", "", lng_key)


    # "/unblock" command.
    elif (cmd.startswith("unblock ") or cmd.startswith("unban ")) and "unblock" in source_rights:
        try:
            cmd, value = cmd.split(" ", 1)
            value = LXMF_CONNECTION.destination_correct(value)
            if value != "":
                executed = False
                for section in DATA.sections():
                    if section.startswith("block"):
                        for (key, val) in DATA.items(section):
                            if key == value:
                                user_section = section.replace("block_", "")
                                user_name = val
                                executed = True
                                if not DATA.has_section(user_section):
                                    DATA.add_section(user_section)
                                DATA[user_section][key] = val
                                DATA.remove_option(section, key)
                if executed:
                    content_user = config_get(CONFIG, "interface_messages", "unblock_"+user_section, "", lng_key)
                    content_user = replace(content_user, source_hash, source_name, source_right, lng_key)
                    if content_user != "":
                        LXMF_CONNECTION.send(value, content_user, "", fields_generate(lng_key, m=True, d=True, r=True, cmd=user_section, config=user_section), None, "interface_send")

                    content_group = config_get(CONFIG, "interface_messages", "member_unblock", "", lng_key)
                    content_group = replace(content_group, source_hash, source_name, source_right, lng_key)
                    content_group = content_group.replace(delimiter+"user_address"+delimiter, value)
                    content_group = content_group.replace(delimiter+"user_name"+delimiter, user_name)
                    if content_group != "":
                        fields = fields_generate(lng_key, h=bytes.fromhex(value) ,n=user_name, m=True, tpl="unblock")
                        for section in sections:
                            if "receive_block" in config_get(CONFIG, "rights", section).split(","):
                                for (key, val) in DATA.items(section):
                                    LXMF_CONNECTION.send(key, content_group, "", fields, None, "interface_send")

                    content = config_get(CONFIG, "interface_menu", "unblock_ok", "", lng_key)
                    content = content.replace(delimiter+"user_address"+delimiter, value)
                    content = content.replace(delimiter+"user_name"+delimiter, user_name)

                    if CONFIG["main"].getboolean("auto_save_data"):
                        DATA.remove_option("main", "unsaved")
                        if not data_save(PATH + "/data.cfg"):
                            DATA["main"]["unsaved"] = "True"
                    else:
                        DATA["main"]["unsaved"] = "True"
                else:
                    content = config_get(CONFIG, "interface_menu", "unblock_found_error", "", lng_key)
            else:
                content = config_get(CONFIG, "interface_menu", "unblock_format_error", "", lng_key)
        except:
           content = config_get(CONFIG, "interface_menu", "cmd_error", "", lng_key)


    # "/allow" command.
    elif cmd.startswith("allow ") and "allow" in source_rights:
        try:
            cmd, value = cmd.split(" ", 1)
            user_section = DATA["main"]["allow_user_type"]
            if DATA.has_section(user_section) and user_section != "main":
                value = LXMF_CONNECTION.destination_correct(value)
                if value != "":
                    executed = False
                    section = "wait"
                    if DATA.has_section(section):
                        for (key, val) in DATA.items(section):
                            if key == value:
                                user_name = val
                                executed = True
                                DATA[user_section][key] = val
                                DATA.remove_option(section, key)
                    if executed:
                        content_user = config_get(CONFIG, "interface_messages", "allow_"+user_section, "", lng_key)
                        content_user = replace(content_user, source_hash, source_name, source_right, lng_key)
                        if content_user != "":
                            LXMF_CONNECTION.send(value, content_user, "", fields_generate(lng_key, m=True, d=True, r=True, cmd=user_section, config=user_section), None, "interface_send")

                        content_group = config_get(CONFIG, "interface_messages", "member_allow", "", lng_key)
                        content_group = replace(content_group, source_hash, source_name, source_right, lng_key)
                        content_group = content_group.replace(delimiter+"user_address"+delimiter, value)
                        content_group = content_group.replace(delimiter+"user_name"+delimiter, user_name)
                        if content_group != "":
                            fields = fields_generate(lng_key, h=bytes.fromhex(value) ,n=user_name, m=True, tpl="allow")
                            for section in sections:
                                if "receive_block" in config_get(CONFIG, "rights", section).split(","):
                                    for (key, val) in DATA.items(section):
                                        LXMF_CONNECTION.send(key, content_group, "", fields, None, "interface_send")

                        content = config_get(CONFIG, "interface_menu", "allow_ok", "", lng_key)
                        content = content.replace(delimiter+"user_address"+delimiter, value)
                        content = content.replace(delimiter+"user_name"+delimiter, user_name)

                        if CONFIG["main"].getboolean("auto_save_data"):
                            DATA.remove_option("main", "unsaved")
                            if not data_save(PATH + "/data.cfg"):
                                DATA["main"]["unsaved"] = "True"
                        else:
                            DATA["main"]["unsaved"] = "True"
                    else:
                        content = config_get(CONFIG, "interface_menu", "allow_found_error", "", lng_key)
                else:
                    content = config_get(CONFIG, "interface_menu", "allow_format_error", "", lng_key)
            else:
                content = config_get(CONFIG, "interface_menu", "allow_type_error", "", lng_key)
        except:
           content = config_get(CONFIG, "interface_menu", "cmd_error", "", lng_key)


    # "/deny" command.
    elif cmd.startswith("deny ") and "deny" in source_rights:
        try:
            cmd, value = cmd.split(" ", 1)
            user_section = DATA["main"]["deny_user_type"]
            if DATA.has_section(user_section) and user_section != "main":
                value = LXMF_CONNECTION.destination_correct(value)
                if value != "":
                    executed = False
                    for section in sections:
                        for (key, val) in DATA.items(section):
                            if key == value:
                                user_name = val
                                executed = True
                                DATA[user_section][key] = val
                                DATA.remove_option(section, key)
                    if executed:
                        content_user = config_get(CONFIG, "interface_messages", "deny_"+user_section, "", lng_key)
                        content_user = replace(content_user, source_hash, source_name, source_right, lng_key)
                        if content_user != "":
                            LXMF_CONNECTION.send(value, content_user, "", fields_generate(lng_key), None, "interface_send")

                        content_group = config_get(CONFIG, "interface_messages", "member_deny", "", lng_key)
                        content_group = replace(content_group, source_hash, source_name, source_right, lng_key)
                        content_group = content_group.replace(delimiter+"user_address"+delimiter, value)
                        content_group = content_group.replace(delimiter+"user_name"+delimiter, user_name)
                        if content_group != "":
                            fields = fields_generate(lng_key, h=bytes.fromhex(value) ,n=user_name, m=True, tpl="deny")
                            for section in sections:
                                if "receive_block" in config_get(CONFIG, "rights", section).split(","):
                                    for (key, val) in DATA.items(section):
                                        LXMF_CONNECTION.send(key, content_group, "", fields, None, "interface_send")

                        content = config_get(CONFIG, "interface_menu", "deny_ok", "", lng_key)
                        content = content.replace(delimiter+"user_address"+delimiter, value)
                        content = content.replace(delimiter+"user_name"+delimiter, user_name)

                        if CONFIG["main"].getboolean("auto_save_data"):
                            DATA.remove_option("main", "unsaved")
                            if not data_save(PATH + "/data.cfg"):
                                DATA["main"]["unsaved"] = "True"
                        else:
                            DATA["main"]["unsaved"] = "True"
                    else:
                        content = config_get(CONFIG, "interface_menu", "deny_found_error", "", lng_key)
                else:
                    content = config_get(CONFIG, "interface_menu", "deny_format_error", "", lng_key)
            else:
                content = config_get(CONFIG, "interface_menu", "deny_type_error", "", lng_key)
        except:
           content = config_get(CONFIG, "interface_menu", "cmd_error", "", lng_key)


    # "/load" command.
    elif (cmd == "load" or cmd == "read") and "load" in source_rights:
        if data_read(PATH + "/data.cfg"):
            content = config_get(CONFIG, "interface_menu", "load_ok", "", lng_key)
        else:
            content = config_get(CONFIG, "interface_menu", "load_error", "", lng_key)


    # "/save" command.
    elif (cmd == "save" or cmd == "wr") and "save" in source_rights:
        DATA.remove_option("main", "unsaved")
        if data_save(PATH + "/data.cfg"):
            content = config_get(CONFIG, "interface_menu", "save_ok", "", lng_key)
        else:
            content = config_get(CONFIG, "interface_menu", "save_error", "", lng_key)
            DATA["main"]["unsaved"] = "True"

        if CONFIG["statistic"].getboolean("enabled"):
            statistic_save(PATH + "/statistic.cfg")


    # "/reload" command.
    elif cmd == "reload" and "reload" in source_rights:
        content = config_get(CONFIG, "interface_menu", "reload_error", "", lng_key)
        DATA.remove_option("main", "unsaved")
        if data_save(PATH + "/data.cfg"):
            if data_read(PATH + "/data.cfg"):
                content = config_get(CONFIG, "interface_menu", "reload_ok", "", lng_key)
        else:
            DATA["main"]["unsaved"] = "True"


    # "/reset" command.
    elif cmd.startswith("reset statistic ") and "reset" in source_rights:
        try:
            cmd, key, value = cmd.split(" ", 2)

            if value == "all":
                for section in STATISTIC.sections():
                    statistic_reset(section)
                if CONFIG["main"].getboolean("auto_save_statistic"):
                    statistic_save(PATH + "/statistic.cfg")
                else:
                    if not STATISTIC.has_section("main"):
                        STATISTIC.add_section("main")
                    STATISTIC["main"]["unsaved"] = "True"
                content = config_get(CONFIG, "interface_menu", "reset_statistic_ok", "", lng_key)

            elif value == "cluster":
                for section in STATISTIC.sections():
                    if section.startswith("cluster"):
                        statistic_reset(section)
                if CONFIG["main"].getboolean("auto_save_statistic"):
                    statistic_save(PATH + "/statistic.cfg")
                else:
                    if not STATISTIC.has_section("main"):
                        STATISTIC.add_section("main")
                    STATISTIC["main"]["unsaved"] = "True"
                content = config_get(CONFIG, "interface_menu", "reset_statistic_ok", "", lng_key)

            elif value == "local":
                for section in STATISTIC.sections():
                    if section.startswith("local"):
                        statistic_reset(section)
                if CONFIG["main"].getboolean("auto_save_statistic"):
                    statistic_save(PATH + "/statistic.cfg")
                else:
                    if not STATISTIC.has_section("main"):
                        STATISTIC.add_section("main")
                    STATISTIC["main"]["unsaved"] = "True"
                content = config_get(CONFIG, "interface_menu", "reset_statistic_ok", "", lng_key)

            elif value == "interface":
                for section in STATISTIC.sections():
                    if section.startswith("interface"):
                        statistic_reset(section)
                if CONFIG["main"].getboolean("auto_save_statistic"):
                    statistic_save(PATH + "/statistic.cfg")
                else:
                    if not STATISTIC.has_section("main"):
                        STATISTIC.add_section("main")
                    STATISTIC["main"]["unsaved"] = "True"
                content = config_get(CONFIG, "interface_menu", "reset_statistic_ok", "", lng_key)

            elif value == "user":
                for section in STATISTIC.sections():
                    if not section.startswith("cluster") and not section.startswith("local") and not section.startswith("interface"):
                        statistic_reset(section)
                if CONFIG["main"].getboolean("auto_save_statistic"):
                    statistic_save(PATH + "/statistic.cfg")
                else:
                    if not STATISTIC.has_section("main"):
                        STATISTIC.add_section("main")
                    STATISTIC["main"]["unsaved"] = "True"
                content = config_get(CONFIG, "interface_menu", "reset_statistic_ok", "", lng_key)

            else:
                content = config_get(CONFIG, "interface_menu", "reset_statistic_error", "", lng_key)
        except:
            content = config_get(CONFIG, "interface_menu", "cmd_error", "", lng_key)


    else:
        # "/admins" command.
        # "/moderators" command.
        # "/users" command.
        # "/guests" command.
        executed = False
        for section in sections:
            if (cmd == section or cmd == section+"s") and section+"s" in source_rights:
                count = 0
                content = config_get(CONFIG, "interface_menu", section+"s_header", "", lng_key)
                content = replace(content, source_hash, source_name, source_right, lng_key)
                content_member = config_get(CONFIG, "interface_menu", section+"s_member", "", lng_key)
                for (key, val) in DATA.items(section):
                    count += 1
                    content = content + replace(content_member, key, val, section, lng_key)
                content = content.replace(delimiter+"count"+delimiter, str(count))
                executed = True
                break

        # cmd_unknown
        if not executed:
            content = config_get(CONFIG, "interface_menu", "cmd_unknown", "", lng_key)


    # unsaved
    if DATA["main"].getboolean("unsaved") and "unsaved" in source_rights:
        if CONFIG["main"].getboolean("auto_save_data"):
            DATA.remove_option("main", "unsaved")
            if data_save(PATH + "/data.cfg"):
                content = content + "\n" + config_get(CONFIG, "interface_menu", "save_ok", "", lng_key)
            else:
                content = content + "\n" + config_get(CONFIG, "interface_menu", "save_error", "", lng_key)
                DATA["main"]["unsaved"] = "True"
        else:
            content = content + "\n" + config_get(CONFIG, "interface_menu", "save_info", "", lng_key)


    return content




#### Fields #####
def fields_remove(fields=None, key="fields_remove"):
    search = config_get(CONFIG, "message", key).split(",")

    delete = []
    for field in fields:
        if field in search:
            delete.append(field)

    for field in delete:
        del fields[field]

    return fields




#### Fields #####
def fields_generate(lng_key, fields=None, h=None, n=None, m=False, d=False, r=False, cmd=None, config=None, tpl=None):
    if not CONFIG["main"].getboolean("fields_message"):
        return fields

    if not fields:
        fields = {}

    if CONFIG["lxmf"]["destination_type_conv"] != "":
        fields["type"] = CONFIG["lxmf"].getint("destination_type_conv")

    if h:
        fields["src"] = {}
        fields["src"]["h"] = h
        if n:
            fields["src"]["n"] = n
        else:
            fields["src"]["n"] = ""

    if m or d or r or cmd or config:
        fields["data"] = {}

    if m:
        fields["data"]["m"] = {}
        for (key, val) in CONFIG.items("rights"):
            if DATA.has_section(key):
                fields["data"]["m"][key] = {}
                for (section_key, section_val) in DATA.items(key):
                    try:
                        h = bytes.fromhex(LXMF_CONNECTION.destination_correct(section_key))
                        fields["data"]["m"][key][h] = section_val
                    except:
                       pass

    if d:
        fields["data"]["d"] = config_get(DATA, "main", "description", "", lng_key).replace(CONFIG["interface"]["delimiter_output"]+"n"+CONFIG["interface"]["delimiter_output"], "\n")

    if r:
        fields["data"]["r"] = config_get(DATA, "main", "rules", "", lng_key).replace(CONFIG["interface"]["delimiter_output"]+"n"+CONFIG["interface"]["delimiter_output"], "\n")

    if cmd:
        fields["data"]["cmd"] = []
        if CONFIG.has_option("cmds", cmd):
            cmds = config_get(CONFIG, "cmds", cmd).split(",")
            for cmd in cmds:
                fields["data"]["cmd"].append({"c": "/"+cmd})

    if config:
        fields["data"]["config"] = {}
        if CONFIG.has_option("configs", config):
            configs = config_get(CONFIG, "configs", config).split(",")
            for config in configs:
                if config != "":
                    key, value = config.split("=", 1)
                    fields["data"]["config"][key] = val_to_val(value)

    if tpl:
        fields["tpl"] = tpl

    return fields




#### Replace #####
def replace(text, source_hash, source_name, source_right, lng_key):
    delimiter = CONFIG["interface"]["delimiter_output"]

    text = text.replace(delimiter+"source_address"+delimiter, source_hash)
    text = text.replace(delimiter+"source_name"+delimiter, source_name)
    text = text.replace(delimiter+"source_right"+delimiter, source_right)

    text = text.replace(delimiter+"name"+delimiter, config_get(CONFIG, "main", "name", "", lng_key))
    text = text.replace(delimiter+"display_name"+delimiter, config_get(CONFIG, "lxmf", "display_name", "", lng_key))
    text = text.replace(delimiter+"description"+delimiter, config_get(DATA, "main", "description", "", lng_key))
    text = text.replace(delimiter+"rules"+delimiter, config_get(DATA, "main", "rules", "", lng_key))
    text = text.replace(delimiter+"destination_address"+delimiter, LXMF_CONNECTION.destination_hash_str())
    text = text.replace(delimiter+"propagation_node"+delimiter, config_get(CONFIG, "lxmf", "propagation_node", "", lng_key))
    text = text.replace(delimiter+"cluster_name"+delimiter, config_get(CONFIG, "cluster", "display_name", "", lng_key).rsplit('/', 1)[-1])

    text = text.replace(delimiter+"n"+delimiter, "\n")

    if delimiter+"count_members"+delimiter in text:
        count = 0
        for (section, section_val) in CONFIG.items("rights"):
            if DATA.has_section(section):
                for (key, val) in DATA.items(section):
                    count += 1
        text = text.replace(delimiter+"count_members"+delimiter, str(count))

    if delimiter+"count_pin"+delimiter in text:
        count = 0
        if DATA.has_section("pin"):
            for (key, val) in DATA.items("pin"):
                count += 1
        text = text.replace(delimiter+"count_pin"+delimiter, str(count))

    return text


##############################################################################################################
# Config


#### Config - Get #####
def config_get(config, section, key, default="", lng_key=""):
    if not config or section == "" or key == "": return default
    if not config.has_section(section): return default
    if config.has_option(section, key+lng_key):
        return config[section][key+lng_key]
    elif config.has_option(section, key):
        return config[section][key]
    return default


def config_getint(config, section, key, default=0, lng_key=""):
    if not config or section == "" or key == "": return default
    if not config.has_section(section): return default
    if config.has_option(section, key+lng_key):
        return config.getint(section, key+lng_key)
    elif config.has_option(section, key):
        return config.getint(section, key)
    return default


def config_getboolean(config, section, key, default=False, lng_key=""):
    if not config or section == "" or key == "": return default
    if not config.has_section(section): return default
    if config.has_option(section, key+lng_key):
        return config[section].getboolean(key+lng_key)
    elif config.has_option(section, key):
        return config[section].getboolean(key)
    return default


def config_getsection(config, section, default="", lng_key=""):
    if not config or section == "": return default
    if not config.has_section(section): return default
    if config.has_section(section+lng_key):
        return key+lng_key
    elif config.has_section(section):
        return key
    return default


def config_getoption(config, section, key, default=False, lng_key=""):
    if not config or section == "" or key == "": return default
    if not config.has_section(section): return default
    if config.has_option(section, key+lng_key):
        return key+lng_key
    elif config.has_option(section, key):
        return key
    return default




#### Config - Set #####
def config_set(key=None, value=""):
    global PATH

    try:
        file = PATH + "/config.cfg.owr"
        if os.path.isfile(file):
            fh = open(file,'r')
            data = fh.read()
            fh.close()
            data = re.sub(r'^#?'+key+'( +)?=( +)?(\w+)?', key+" = "+value, data, count=1, flags=re.MULTILINE)
            fh = open(file,'w')
            fh.write(data)
            fh.close()
    
        file = PATH + "/config.cfg"
        if os.path.isfile(file):
            fh = open(file,'r')
            data = fh.read()
            fh.close()
            data = re.sub(r'^#?'+key+'( +)?=( +)?(\w+)?', key+" = "+value, data, count=1, flags=re.MULTILINE)
            fh = open(file,'w')
            fh.write(data)
            fh.close()
    except:
        pass




#### Config - Read #####
def config_read(file=None, file_override=None):
    global CONFIG

    if file is None:
        return False
    else:
        CONFIG = configparser.ConfigParser(allow_no_value=True, inline_comment_prefixes="#")
        CONFIG.sections()
        if os.path.isfile(file):
            try:
                if file_override is None:
                    CONFIG.read(file, encoding='utf-8')
                elif os.path.isfile(file_override):
                    CONFIG.read([file, file_override], encoding='utf-8')
                else:
                    CONFIG.read(file, encoding='utf-8')
            except Exception as e:
                return False
        else:
            if not config_default(file=file, file_override=file_override):
                return False
    return True




#### Config - Save #####
def config_save(file=None):
    global CONFIG

    if file is None:
        return False
    else:
        if os.path.isfile(file):
            try:
                with open(file,"w") as file:
                    CONFIG.write(file)
            except Exception as e:
                return False
        else:
            return False
    return True




#### Config - Default #####
def config_default(file=None, file_override=None):
    global CONFIG

    if file is None:
        return False
    elif DEFAULT_CONFIG != "":
        if file_override and DEFAULT_CONFIG_OVERRIDE != "":
            if not os.path.isdir(os.path.dirname(file_override)):
                try:
                    os.makedirs(os.path.dirname(file_override))
                except Exception:
                    return False
            if not os.path.exists(file_override):
                try:
                    config_file = open(file_override, "w")
                    config_file.write(DEFAULT_CONFIG_OVERRIDE)
                    config_file.close()
                except:
                    return False

        if not os.path.isdir(os.path.dirname(file)):
            try:
                os.makedirs(os.path.dirname(file))
            except Exception:
                return False
        try:
            config_file = open(file, "w")
            config_file.write(DEFAULT_CONFIG)
            config_file.close()
            if not config_read(file=file, file_override=file_override):
                return False
        except:
            return False
    else:
        return False

    if not CONFIG.has_section("main"): CONFIG.add_section("main")
    CONFIG["main"]["default_config"] = "True"
    return True


##############################################################################################################
# Data


#### Data - Read #####
def data_read(file=None):
    global DATA

    if file is None:
        return False
    else:
        DATA = configparser.ConfigParser(allow_no_value=True, inline_comment_prefixes="#")
        DATA.sections()
        if os.path.isfile(file):
            try:
                DATA.read(file)
            except Exception as e:
                return False
        else:
            if not data_default(file=file):
                return False
    return True




#### Data - Save #####
def data_save(file=None):
    global DATA

    if file is None:
        return False
    else:
        if os.path.isfile(file):
            try:
                with open(file,"w") as file:
                    DATA.write(file)
            except Exception as e:
                return False
        else:
            return False
    return True




#### Data - Save #####
def data_save_periodic(initial=False):
    data_timer = threading.Timer(CONFIG.getint("main", "periodic_save_data_interval")*60, data_save_periodic)
    data_timer.daemon = True
    data_timer.start()

    if initial:
        return

    global DATA
    if DATA.has_section("main"):
        if DATA["main"].getboolean("unsaved"):
            DATA.remove_option("main", "unsaved")
            if not data_save(PATH + "/data.cfg"):
                DATA["main"]["unsaved"] = "True"




#### Data - Default #####
def data_default(file=None):
    global DATA

    if file is None:
        return False
    elif DEFAULT_DATA != "":
        if not os.path.isdir(os.path.dirname(file)):
            try:
                os.makedirs(os.path.dirname(file))
            except Exception:
                return False
        try:
            data_file = open(file, "w")
            data_file.write(DEFAULT_DATA)
            data_file.close()
            if not data_read(file=file):
                return False
        except:
            return False
    else:
        return False
    return True


##############################################################################################################
# Statistic/Counter


#### Statistic #####
def statistic(cmd="add", section="global", key="", value=1):
    global STATISTIC

    changed = False

    if cmd == "add":
        statistic_add(section, value)
        changed = True
    elif cmd == "del":
        statistic_del(section)
        changed = True
    elif cmd == "reset":
        statistic_reset(section)
        changed = True
    elif cmd == "get":
        return statistic_get(section)
    elif cmd == "value_set":
        statistic_value_set(section, key, value)
        changed = True
    elif cmd == "value_get":
        return statistic_value_get(section, key)
    elif cmd == "read":
        return statistic_read(PATH + "/statistic.cfg")
    elif cmd == "save":
        return statistic_save(PATH + "/statistic.cfg")

    if changed:
        if CONFIG["main"].getboolean("auto_save_statistic"):
            statistic_save(PATH + "/statistic.cfg")
        else:
            if not STATISTIC.has_section("main"):
                STATISTIC.add_section("main")
            STATISTIC["main"]["unsaved"] = "True"




#### Statistic - Add #####
def statistic_add(section="global", value=1):
    global STATISTIC

    if not STATISTIC.has_section(section):
        statistic_default(section)

    statistic_recalculate(section)

    date = datetime.date.today()
    day = date.timetuple().tm_yday
    month = date.timetuple().tm_mon
    year = date.timetuple().tm_year
    week = date.isocalendar()[1]

    #day
    if STATISTIC[section]["day_index"] == str(day):
        STATISTIC[section]["day_value"] = str(STATISTIC.getint(section, "day_value")+value)

    #week
    if STATISTIC[section]["week_index"] == str(week):
        STATISTIC[section]["week_value"] = str(STATISTIC.getint(section, "week_value")+value)

    #month
    if STATISTIC[section]["month_index"] == str(month):
        STATISTIC[section]["month_value"] = str(STATISTIC.getint(section, "month_value")+value)

    #year
    if STATISTIC[section]["year_index"] == str(year):
        STATISTIC[section]["year_value"] = str(STATISTIC.getint(section, "year_value")+value)

    #all
    STATISTIC[section]["all_value"] = str(STATISTIC.getint(section, "all_value")+value)

    #max
    if STATISTIC.getint(section, "day_value") > STATISTIC.getint(section, "max_value"):
        STATISTIC[section]["max_value"] = STATISTIC[section]["day_value"]
        STATISTIC[section]["max_index"] = time.strftime("%Y-%m-%d", time.localtime(time.time()))
    return




#### Statistic - Recalculate #####
def statistic_recalculate(section="global"):
    global STATISTIC

    if not STATISTIC.has_section(section):
        return

    date = datetime.date.today()
    day = date.timetuple().tm_yday
    month = date.timetuple().tm_mon
    year = date.timetuple().tm_year
    week = date.isocalendar()[1]

    #day
    if STATISTIC[section]["day_index"] != str(day):
        if STATISTIC[section]["day_index"] == str(day-1):
            STATISTIC[section]["last_day_value"] = STATISTIC[section]["day_value"]
            STATISTIC[section]["last_day_index"] = str(day-1)
        else:
            STATISTIC[section]["last_day_value"] = "0"
            STATISTIC[section]["last_day_index"] = str(day-1)
        STATISTIC[section]["day_value"] = "0"
        STATISTIC[section]["day_index"] = str(day)

    #week
    if STATISTIC[section]["week_index"] != str(week):
        if STATISTIC[section]["week_index"] == str(week-1):
            STATISTIC[section]["last_week_value"] = STATISTIC[section]["week_value"]
            STATISTIC[section]["last_week_index"] = str(week-1)
        else:
            STATISTIC[section]["last_week_value"] = "0"
            STATISTIC[section]["last_week_index"] = str(week-1)
        STATISTIC[section]["week_value"] = "0"
        STATISTIC[section]["week_index"] = str(week)

    #month
    if STATISTIC[section]["month_index"] != str(month):
        if STATISTIC[section]["month_index"] == str(month-1):
            STATISTIC[section]["last_month_value"] = STATISTIC[section]["month_value"]
            STATISTIC[section]["last_month_index"] = str(month-1)
        else:
            STATISTIC[section]["last_month_value"] = "0"
            STATISTIC[section]["last_month_index"] = str(month-1)
        STATISTIC[section]["month_value"] = "0"
        STATISTIC[section]["month_index"] = str(month)

    #year
    if STATISTIC[section]["year_index"] != str(year):
        if STATISTIC[section]["year_index"] == str(year-1):
            STATISTIC[section]["last_year_value"] = STATISTIC[section]["year_value"]
            STATISTIC[section]["last_year_index"] = str(year-1)
        else:
            STATISTIC[section]["last_year_value"] = "0"
            STATISTIC[section]["last_year_index"] = str(year-1)
        STATISTIC[section]["year_value"] = "0"
        STATISTIC[section]["year_index"] = str(year)

    return




#### Statistic - Del #####
def statistic_del(section="global"):
    global STATISTIC

    if STATISTIC.has_section(section):
        STATISTIC.remove_section(section)




#### Statistic - Reset #####
def statistic_reset(section="global"):
    statistic_del(section)
    statistic_add(section, 0)




#### Statistic - Get #####
def statistic_get(section="global"):
    global STATISTIC

    text = ""
    if STATISTIC.has_section(section):
        statistic_recalculate(section)
        for (key, val) in STATISTIC.items(section):
            if key.endswith("_value"):
                text = text + key.capitalize() + ": " + val + "\n"
    text = text.replace("_value", "")
    text = text.replace("_", " ")
    text = text.strip()

    return text




#### Statistic - Value set #####
def statistic_value_set(section, key, value):
    global STATISTIC

    if not STATISTIC.has_section(section):
        statistic_default(section)

    STATISTIC[section][key] = value




#### Statistic - Value get #####
def statistic_value_get(section, key, default=""):
    global STATISTIC

    if STATISTIC.has_section(section):
        if STATISTIC.has_option(section, key):
            return STATISTIC[section][key]
    return default




#### Statistic - Read #####
def statistic_read(file=None):
    global STATISTIC

    if file is None:
        return False
    else:
        STATISTIC = configparser.ConfigParser(allow_no_value=True, inline_comment_prefixes="#")
        STATISTIC.sections()
        if os.path.isfile(file):
            try:
                STATISTIC.read(file)
            except Exception as e:
                return False
    return True




#### Statistic - Save #####
def statistic_save(file=None):
    global STATISTIC

    if file is None:
        return False
    else:
        try:
            with open(file,"w") as file:
                if STATISTIC.has_section("main"):
                    STATISTIC.remove_section("main")
                STATISTIC.write(file)
        except Exception as e:
            return False
    return True




#### Statistic - Save #####
def statistic_save_periodic(initial=False):
    statistic_timer = threading.Timer(CONFIG.getint("main", "periodic_save_statistic_interval")*60, statistic_save_periodic)
    statistic_timer.daemon = True
    statistic_timer.start()

    if initial:
        return

    global STATISTIC
    if STATISTIC.has_section("main"):
        if STATISTIC["main"].getboolean("unsaved"):
            STATISTIC.remove_section("main")
            if not statistic_save(PATH + "/statistic.cfg"):
                if not STATISTIC.has_section("main"):
                    STATISTIC.add_section("main")
                STATISTIC["main"]["unsaved"] = "True"




#### Statistic - Default #####
def statistic_default(section="global"):
    global STATISTIC

    date = datetime.date.today()
    day = date.timetuple().tm_yday
    month = date.timetuple().tm_mon
    year = date.timetuple().tm_year
    week = date.isocalendar()[1]

    STATISTIC.add_section(section)
    STATISTIC[section]["day_value"] = "0"
    STATISTIC[section]["day_index"] = str(day)
    STATISTIC[section]["last_day_value"] = "0"
    STATISTIC[section]["last_day_index"] = str(day-1)
    STATISTIC[section]["week_value"] = "0"
    STATISTIC[section]["week_index"] = str(week)
    STATISTIC[section]["last_week_value"] = "0"
    STATISTIC[section]["last_week_index"] = str(week-1)
    STATISTIC[section]["month_value"] = "0"
    STATISTIC[section]["month_index"] = str(month)
    STATISTIC[section]["last_month_value"] = "0"
    STATISTIC[section]["last_month_index"] = str(month-1)
    STATISTIC[section]["year_value"] = "0"
    STATISTIC[section]["year_index"] = str(year)
    STATISTIC[section]["last_year_value"] = "0"
    STATISTIC[section]["last_year_index"] = str(year-1)
    STATISTIC[section]["all_value"] = "0"
    STATISTIC[section]["max_value"] = "0"
    STATISTIC[section]["max_index"] = time.strftime("%Y-%m-%d", time.localtime(time.time()))


##############################################################################################################
# Value convert


def val_to_bool(val, fallback_true=True, fallback_false=False):
    if val == "on" or val == "On" or val == "true" or val == "True" or val == "yes" or val == "Yes" or val == "1" or val == "open" or val == "opened" or val == "up":
        return True
    elif val == "off" or val == "Off" or val == "false" or val == "False" or val == "no" or val == "No" or val == "0" or val == "close" or val == "closed" or val == "down":
        return False
    elif val != "":
        return fallback_true
    else:
        return fallback_false


def val_to_val(val):
    if val.isdigit():
        return int(val)
    elif val.isnumeric():
        return float(val)
    elif val.lower() == "true":
        return True
    elif val.lower() == "false":
        return False
    else:
        return val


##############################################################################################################
# Log


LOG_FORCE    = -1
LOG_CRITICAL = 0
LOG_ERROR    = 1
LOG_WARNING  = 2
LOG_NOTICE   = 3
LOG_INFO     = 4
LOG_VERBOSE  = 5
LOG_DEBUG    = 6
LOG_EXTREME  = 7

LOG_LEVEL         = LOG_NOTICE
LOG_LEVEL_SERVICE = LOG_NOTICE
LOG_TIMEFMT       = "%Y-%m-%d %H:%M:%S"
LOG_MAXSIZE       = 5*1024*1024
LOG_PREFIX        = ""
LOG_SUFFIX        = ""
LOG_FILE          = ""




def log(text, level=3, file=None):
    if not LOG_LEVEL:
        return

    if LOG_LEVEL >= level:
        name = "Unknown"
        if (level == LOG_FORCE):
            name = ""
        if (level == LOG_CRITICAL):
            name = "Critical"
        if (level == LOG_ERROR):
            name = "Error"
        if (level == LOG_WARNING):
            name = "Warning"
        if (level == LOG_NOTICE):
            name = "Notice"
        if (level == LOG_INFO):
            name = "Info"
        if (level == LOG_VERBOSE):
            name = "Verbose"
        if (level == LOG_DEBUG):
            name = "Debug"
        if (level == LOG_EXTREME):
            name = "Extra"

        if not isinstance(text, str):
            text = str(text)

        text = "[" + time.strftime(LOG_TIMEFMT, time.localtime(time.time())) +"] [" + name + "] " + LOG_PREFIX + text + LOG_SUFFIX

        if file == None and LOG_FILE != "":
            file = LOG_FILE

        if file == None:
            print(text)
        else:
            try:
                file_handle = open(file, "a")
                file_handle.write(text + "\n")
                file_handle.close()
                
                if os.path.getsize(file) > LOG_MAXSIZE:
                    file_prev = file + ".1"
                    if os.path.isfile(file_prev):
                        os.unlink(file_prev)
                    os.rename(file, file_prev)
            except:
                return


##############################################################################################################
# System


#### Panic #####
def panic():
    sys.exit(255)


#### Exit #####
def exit():
    sys.exit(0)


##############################################################################################################
# Setup/Start


#### Setup #####
def setup(path=None, path_rns=None, path_log=None, loglevel=None, service=False):
    global PATH
    global PATH_RNS
    global LOG_LEVEL
    global LOG_FILE
    global RNS_MAIN_CONNECTION
    global LXMF_CONNECTION
    global RNS_CONNECTION

    if path is not None:
        if path.endswith("/"):
            path = path[:-1]
        PATH = path

    if path_rns is not None:
        if path_rns.endswith("/"):
            path_rns = path_rns[:-1]
        PATH_RNS = path_rns

    if loglevel is not None:
        LOG_LEVEL = loglevel
        rns_loglevel = loglevel
    else:
        rns_loglevel = None

    if service:
        LOG_LEVEL = LOG_LEVEL_SERVICE
        if path_log is not None:
            if path_log.endswith("/"):
                path_log = path_log[:-1]
            LOG_FILE = path_log
        else:
            LOG_FILE = PATH
        LOG_FILE = LOG_FILE + "/" + NAME + ".log"
        rns_loglevel = None

    if not config_read(PATH + "/config.cfg", PATH + "/config.cfg.owr"):
        print("Config - Error reading config file " + PATH + "/config.cfg")
        panic()

    if not data_read(PATH + "/data.cfg"):
        print("Data - Error reading data file " + PATH + "/data.cfg")
        panic()

    if CONFIG["main"].getboolean("default_config"):
        print("Exit!")
        print("First start with the default config!")
        print("You should probably edit the config file \"" + PATH + "/config.cfg\" to suit your needs and use-case!")
        print("You should make all your changes at the user configuration file \"" + PATH + "/config.cfg.owr\" to override the default configuration file!")
        print("Then restart this program again!")
        exit()

    if not CONFIG["main"].getboolean("enabled"):
        print("Disabled in config file. Exit!")
        exit()

    if CONFIG["statistic"].getboolean("enabled"):
        statistic_read(PATH + "/statistic.cfg")

    if CONFIG.has_section("cmds") and CONFIG.has_section("rights"):
        for (key, val) in CONFIG.items("cmds"):
            if val != "" and CONFIG.has_option("rights", key):
                CONFIG["rights"][key] += ",interface,"+val

    RNS_MAIN_CONNECTION = RNS.Reticulum(configdir=PATH_RNS, loglevel=rns_loglevel)

    log("...............................................................................", LOG_INFO)
    log("        Name: " + CONFIG["main"]["name"], LOG_INFO)
    log("Program File: " + __file__, LOG_INFO)
    log(" Config File: " + PATH + "/config", LOG_INFO)
    log(" Data File: " + PATH + "/data.cfg", LOG_INFO)
    log("     Version: " + VERSION, LOG_INFO)
    log("   Copyright: " + COPYRIGHT, LOG_INFO)
    log("...............................................................................", LOG_INFO)

    log("LXMF - Connecting ...", LOG_DEBUG)

    if CONFIG.has_option("lxmf", "propagation_node"):
        config_propagation_node = CONFIG["lxmf"]["propagation_node"]
    else:
        config_propagation_node = None

    if CONFIG.has_option("lxmf", "propagation_node_active"):
        config_propagation_node_active = CONFIG["lxmf"]["propagation_node_active"]
    else:
        config_propagation_node_active = None

    if path is None:
        path = PATH

    display_name = CONFIG["lxmf"]["display_name"]
    announce_data = None
    if CONFIG["lxmf"]["destination_type_conv"] != "":
        try:
           if CONFIG["main"].getboolean("fields_announce"):
               announce_data = umsgpack.packb({"c": CONFIG["lxmf"]["display_name"].encode("utf-8"), "t": None, "f": {"type": CONFIG["lxmf"].getint("destination_type_conv")}})
           else:
               display_name += chr(CONFIG["lxmf"].getint("destination_type_conv"))
        except:
            pass

    LXMF_CONNECTION = lxmf_connection(
        storage_path=path,
        identity_file="identity",
        identity=None,
        destination_name=CONFIG["lxmf"]["destination_name"],
        destination_type=CONFIG["lxmf"]["destination_type"],
        display_name=display_name,
        announce_data = announce_data,
        announce_hidden=CONFIG["lxmf"].getboolean("announce_hidden"),
        send_delay=CONFIG["lxmf"]["send_delay"],
        desired_method=CONFIG["lxmf"]["desired_method"],
        propagation_node=config_propagation_node,
        propagation_node_auto=CONFIG["lxmf"].getboolean("propagation_node_auto"),
        propagation_node_active=config_propagation_node_active,
        try_propagation_on_fail=CONFIG["lxmf"].getboolean("try_propagation_on_fail"),
        announce_startup=CONFIG["lxmf"].getboolean("announce_startup"),
        announce_startup_delay=CONFIG["lxmf"]["announce_startup_delay"],
        announce_periodic=CONFIG["lxmf"].getboolean("announce_periodic"),
        announce_periodic_interval=CONFIG["lxmf"]["announce_periodic_interval"],
        sync_startup=CONFIG["lxmf"].getboolean("sync_startup"),
        sync_startup_delay=CONFIG["lxmf"]["sync_startup_delay"],
        sync_limit=CONFIG["lxmf"]["sync_limit"],
        sync_periodic=CONFIG["lxmf"].getboolean("sync_periodic"),
        sync_periodic_interval=CONFIG["lxmf"]["sync_periodic_interval"])

    LXMF_CONNECTION.register_announce_callback(lxmf_announce_callback)
    LXMF_CONNECTION.register_message_received_callback(lxmf_message_received_callback)
    LXMF_CONNECTION.register_config_set_callback(config_set)

    if CONFIG["statistic"].getboolean("enabled"):
        LXMF_CONNECTION.register_message_notification_success_callback(lxmf_message_notification_success_callback)
        LXMF_CONNECTION.register_message_notification_failed_callback(lxmf_message_notification_failed_callback)

    log("LXMF - Connected", LOG_DEBUG)

    log("...............................................................................", LOG_FORCE)
    log("LXMF - Address: " + RNS.prettyhexrep(LXMF_CONNECTION.destination_hash()), LOG_FORCE)
    log("...............................................................................", LOG_FORCE)

    if CONFIG["cluster"].getboolean("enabled") or CONFIG["router"].getboolean("enabled") or CONFIG["high_availability"].getboolean("enabled"):
        announce_data = defaultdict(dict)

        announce_data["h"] = LXMF_CONNECTION.destination_hash_str()

        if CONFIG["high_availability"].getboolean("enabled"):
            announce_data["ha"] = "1"
            announce_data["ha_r"] = CONFIG["high_availability"]["role"]
        else:
            announce_data["ha"] = "0"

        if CONFIG["cluster"].getboolean("enabled"):
            announce_data["c"] = "1"
            announce_data["c_n"] = CONFIG["cluster"]["display_name"].replace(" ", "")
        else:
            announce_data["c"] = "0"

        if CONFIG["router"].getboolean("enabled"):
            announce_data["r"] = "1"
            announce_data["r_n"] = CONFIG["router"]["display_name"].replace(" ", "")
        else:
            announce_data["r"] = "0"

        log("RNS - Connecting ...", LOG_DEBUG)
        RNS_CONNECTION = rns_connection(
            storage_path=path,
            identity_file="identity",
            identity=LXMF_CONNECTION.identity,
            destination_name=CONFIG["cluster"]["name"],
            destination_type=CONFIG["cluster"]["type"],
            announce_startup=CONFIG["rns"].getboolean("announce_startup"),
            announce_startup_delay=CONFIG["rns"]["announce_startup_delay"],
            announce_periodic=CONFIG["rns"].getboolean("announce_periodic"),
            announce_periodic_interval=CONFIG["rns"]["announce_periodic_interval"],
            announce_data = json.dumps(announce_data, separators=(',', ':')),
            announce_hidden=CONFIG["rns"].getboolean("announce_hidden")
            )
        RNS_CONNECTION.register_announce_callback(rns_announce_callback)
        log("RNS - Connected", LOG_DEBUG)

    if CONFIG["main"].getboolean("periodic_save_data"):
        data_save_periodic(True)

    if CONFIG["main"].getboolean("periodic_save_statistic"):
        statistic_save_periodic(True)

    while True:
        time.sleep(1)




#### Start ####
def main():
    try:
        description = NAME + " - " + DESCRIPTION
        parser = argparse.ArgumentParser(description=description)

        parser.add_argument("-p", "--path", action="store", type=str, default=None, help="Path to alternative config directory")
        parser.add_argument("-pr", "--path_rns", action="store", type=str, default=None, help="Path to alternative Reticulum config directory")
        parser.add_argument("-pl", "--path_log", action="store", type=str, default=None, help="Path to alternative log directory")
        parser.add_argument("-l", "--loglevel", action="store", type=int, default=LOG_LEVEL)
        parser.add_argument("-s", "--service", action="store_true", default=False, help="Running as a service and should log to file")
        parser.add_argument("--exampleconfig", action="store_true", default=False, help="Print verbose configuration example to stdout and exit")
        parser.add_argument("--exampleconfigoverride", action="store_true", default=False, help="Print verbose configuration example to stdout and exit")
        parser.add_argument("--exampledata", action="store_true", default=False, help="Print verbose configuration example to stdout and exit")

        params = parser.parse_args()

        if params.exampleconfig:
            print("Config File: " + PATH + "/config.cfg")
            print("Content:")
            print(DEFAULT_CONFIG)
            exit()

        if params.exampleconfigoverride:
            print("Config Override File: " + PATH + "/config.cfg.owr")
            print("Content:")
            print(DEFAULT_CONFIG_OVERRIDE)
            exit()

        if params.exampledata:
            print("Data File: " + PATH + "/data.cfg")
            print("Content:")
            print(DEFAULT_DATA)
            exit()

        setup(path=params.path, path_rns=params.path_rns, path_log=params.path_log, loglevel=params.loglevel, service=params.service)

    except KeyboardInterrupt:
        print("Terminated by CTRL-C")
        exit()


##############################################################################################################
# Files


#### Default configuration override file ####
DEFAULT_CONFIG_OVERRIDE = '''# This is the user configuration file to override the default configuration file.
# All settings made here have precedence.
# This file can be used to clearly summarize all settings that deviate from the default.
# This also has the advantage that all changed settings can be kept when updating the program.


#### Main program settings ####
[main]

# Default language.
lng = en # en/de


#### LXMF connection settings ####
[lxmf]

# The name will be visible to other peers
# on the network, and included in announces.
# It is also used in the group description/info.
display_name = Distribution Group

# Set propagation node automatically.
propagation_node_auto = True

# Try to deliver a message via the LXMF propagation network,
# if a direct delivery to the recipient is not possible.
try_propagation_on_fail = Yes


#### Cluster settings ####
[cluster]

# Enable/Disable this functionality.
enabled = True

# To use several completely separate clusters/groups,
# an individual name and type can be assigned here.
name = grp
type = cluster

# Slash-separated list with the names of this cluster.
# This feature can be used to build multi level group structures.
# All send messages that match the name (all levels) will be received.
# The last name is the main name of this group and is used as source for send messages.
# No spaces are allowed in the name.
display_name = County/Region/City


#### Router settings ####
[router]

# Enable/Disable router functionality.
enabled = True

# Comma-separated list with the names for which the messages are to be routed/repeated.
# The names and levels must match the used display_name of the cluster accordingly.
# No spaces are allowed in the name.
display_name = Country,Country/Region


#### High availability settings ####
[high_availability]

# Enable/Disable this functionality.
enabled = False

# Role of this node (master/slave)
role = master

# Peer address
peer = 


#### Statistic/Counter settings ####
[statistic]

# Enable/Disable this functionality.
enabled = True
'''


#### Default configuration file ####
DEFAULT_CONFIG = '''# This is the default config file.
# You should probably edit it to suit your needs and use-case.




#### Main program settings ####
[main]

# Enable/Disable this functionality.
enabled = True

# Name of the program. Only for display in the log or program startup.
name = Distribution Group

# Default language.
# The following languages are available. Other languages can be defined below in the "interface" settings.
# You have to add the language key to the settings to be used. For example "-de".
# en/de
lng = en

# Auto save changes.
# If there are changes in the data or statistics, they can be saved directly in the files.
# Attention: This can lead to very high write cycles.
# If you want to prevent frequent writing, please set this to 'False' and use the peridodic save function.
auto_save_data = True
auto_save_statistic = False

# Periodic actions - Save changes periodically.
periodic_save_data = True
periodic_save_data_interval = 30 #Minutes
periodic_save_statistic = True
periodic_save_statistic_interval = 30 #Minutes

# Auto apply name from announces.
# As an alternative to defining the nickname manually, it can be used automatically from the announce.
auto_name_add = True
auto_name_def = True
auto_name_change = True

# Transport extended data in the announce and fields variable.
# This is needed for the integration of advanced client apps.
fields_announce = False
fields_message = False




#### LXMF connection settings ####
[lxmf]

# Destination name & type need to fits the LXMF protocoll
# to be compatibel with other LXMF programs.
destination_name = lxmf
destination_type = delivery
destination_type_conv = #4=Group, 6=Channel (Only for use with Communicator-Software.)

# The name will be visible to other peers
# on the network, and included in announces.
# It is also used in the group description/info.
display_name = Distribution Group

# Default send method.
desired_method = direct #direct/propagated

# Propagation node address/hash.
propagation_node = 

# Set propagation node automatically.
propagation_node_auto = True

# Current propagation node (Automatically set by the software).
propagation_node_active = 

# Try to deliver a message via the LXMF propagation network,
# if a direct delivery to the recipient is not possible.
try_propagation_on_fail = Yes

# The peer is announced at startup
# to let other peers reach it immediately.
announce_startup = Yes
announce_startup_delay = 0 #Seconds

# The peer is announced periodically
# to let other peers reach it.
announce_periodic = Yes
announce_periodic_interval = 120 #Minutes

# The announce is hidden for client applications
# but is still used for the routing tables.
announce_hidden = No

# Some waiting time after message send
# for LXMF/Reticulum processing.
send_delay = 0 #Seconds

# Sync LXMF messages at startup.
sync_startup = No
sync_startup_delay = 0 #Seconds

# Sync LXMF messages periodically.
sync_periodic = No

# The sync interval in minutes.
sync_periodic_interval = 360 #Minutes

# Automatic LXMF syncs will only
# download x messages at a time. You can change
# this number, or set the option to 0 to disable
# the limit, and download everything every time.
sync_limit = 0

# Allow only messages with valid signature.
signature_validated = No
signature_validated_new = No
signature_validated_known = No




#### RNS connection settings ####
[rns]

# Destination name & type need to fits the RNS protocoll
# to be compatibel with other RNS programs.
destination_name = grp
destination_type = cluster

# The peer is announced at startup
# to let other peers reach it immediately.
announce_startup = Yes
announce_startup_delay = 0 #Seconds

# The peer is announced periodically
# to let other peers reach it.
announce_periodic = Yes
announce_periodic_interval = 120 #Minutes

# The announce is hidden for client applications
# but is still used for the routing tables.
announce_hidden = No




#### Cluster settings ####
[cluster]

# Enable/Disable this functionality.
enabled = False

# To use several completely separate clusters/groups,
# an individual name and type can be assigned here.
name = grp
type = cluster

# Slash-separated list with the names of this cluster.
# This feature can be used to build multi level group structures.
# All send messages that match the name (all levels) will be received.
# The last name is the main name of this group and is used as source for send messages.
# No spaces are allowed in the name.
display_name = County/Region/City

# Define the delimiters for cluster input.
delimiter_input = @




#### Router settings ####
[router]

# Enable/Disable router functionality.
enabled = False

# Comma-separated list with the names for which the messages are to be routed/repeated.
# The names and levels must match the used display_name of the cluster accordingly.
# No spaces are allowed in the name.
display_name = Country,Country/Region




#### High availability settings ####
[high_availability]

# Enable/Disable this functionality.
enabled = False

# Role of this node (master/slave)
role = master

# Peer address
peer = 

# Sync
sync_periodic_interval = 30 #Minutes

# Sync at startup
sync_startup = No
sync_startup_delay = 0 #Seconds

# Heartbeat
heartbeat_interval = 1 #Minutes
heartbeat_timeout = 15 #Minutes




#### Message settings ####
[message]

## Each message received (message and command) ##

# Deny message if the title/content/fields contains the following content.
# Comma-separated list with text or field keys.
# *=any
deny_title = 
deny_content = 
deny_fields = 

# Text is added.
receive_title_prefix = 
receive_prefix = 
receive_suffix = 

# Text is replaced.
receive_search = 
receive_replace = 

# Text is replaced by regular expression.
receive_regex_search = 
receive_regex_replace = 

# Length limitation.
receive_length_min = 0 #0=any length
receive_length_max = 0 #0=any length


## Each message send (message) ##

# Text is added.
send_title_prefix = #!source_name!!n!<!source_address!>!n!
send_prefix = !source_name!!n!<!source_address!>!n!
send_suffix = 

# Text is replaced.
send_search = 
send_replace = 

# Text is replaced by regular expression.
send_regex_search = 
send_regex_replace = 

# Length limitation.
send_length_min = 0 #0=any length
send_length_max = 0 #0=any length


## Each cluster message received (message and command) ##

# Text is added.
cluster_receive_title_prefix = #@!cluster_source!->
cluster_receive_prefix = @!cluster_source!->
cluster_receive_suffix = 

# Text is replaced.
cluster_receive_search = 
cluster_receive_replace = 

# Text is replaced by regular expression.
cluster_receive_regex_search = 
cluster_receive_regex_replace = 

# Length limitation.
cluster_receive_length_min = 0 #0=any length
cluster_receive_length_max = 0 #0=any length


## Each cluster message send (message) ##

# Text is added.
cluster_send_title_prefix = #@!cluster_destination!!n!!source_name!!n!<!source_address!>!n!
cluster_send_prefix = @!cluster_destination!!n!!source_name!!n!<!source_address!>!n!
cluster_send_suffix = 

# Text is replaced.
cluster_send_search = 
cluster_send_replace = 

# Text is replaced by regular expression.
cluster_send_regex_search = 
cluster_send_regex_replace = 

# Length limitation.
cluster_send_length_min = 0 #0=any length
cluster_send_length_max = 0 #0=any length


## Each pinned message ##

pin_id = %%y%%m%%d-%%H%%M%%S


# Define which message timestamp should be used.
timestamp = client #client/server

# Use title/fields.
title = Yes
fields = Yes

# Comma-separated list with fields which will be removed.
fields_remove = 
fields_remove_anonymous = 




#### Statistic/Counter settings ####
[statistic]

# Enable/Disable this functionality.
enabled = True

# Create cluster statistics.
cluster = True

# Create router statistics.
router = True

# Create local/group statistics.
local = True

# Create interface statistics.
interface = True

# Create user statistics.
user = True




#### User rights assignment ####

# Define the individual rights for the different user types.
# Delimiter for different rights: ,
[rights]

admin = interface,receive_local,receive_cluster,receive_cluster_pin_add,receive_cluster_loop,receive_cluster_join,receive_join,receive_leave,receive_invite,receive_kick,receive_block,receive_unblock,receive_allow,receive_deny,receive_description,receive_rules,receive_pin_add,receive_pin_remove,receive_name_def,receive_name_change,receive_auto_name_def,receive_auto_name_change,reply_signature,reply_cluster_enabled,reply_cluster_right,reply_interface_enabled,reply_interface_right,reply_local_enabled,reply_local_right,reply_block,reply_length_min,reply_length_max,send_local,send_cluster,help,update,update_all,join,leave,name,address,info,pin,pin_add,pin_remove,cluster_pin_add,description,rules,readme,time,version,groups,members,admins,moderators,users,guests,search,activitys,statistic,statistic_min,statistic_full,statistic_cluster,statistic_router,statistic_local,statistic_interface,statistic_self,statistic_user,status,delivery,enable_local,enable_cluster,auto_add_user,auto_add_user_type,auto_add_cluster,auto_add_router,invite_user,invite_user_type,allow_user,allow_user_type,deny_user,deny_user_type,description_set,rules_set,announce,sync,show_run,show,add,del,move,rename,invite,kick,block,unblock,allow,deny,load,save,reload,reset,unsaved
mod = interface,receive_local,receive_cluster,receive_cluster_pin_add,receive_cluster_loop,receive_join,receive_leave,receive_invite,receive_kick,receive_block,receive_unblock,receive_allow,receive_deny,receive_description,receive_rules,receive_pin_add,reply_signature,reply_cluster_enabled,reply_cluster_right,reply_interface_enabled,reply_interface_right,reply_local_enabled,reply_local_right,reply_block,reply_length_min,reply_length_max,send_local,send_cluster,help,update,update_all,join,leave,name,address,info,pin,pin_add,pin_remove,cluster_pin_add,description,rules,readme,time,version,groups,members,admins,moderators,users,guests,search,activitys,statistic,statistic_min,statistic_cluster,statistic_router,statistic_local,statistic_self,delivery,show,add,del,move,rename,invite,kick,block,unblock,allow,deny
user = interface,receive_local,receive_cluster,receive_cluster_pin_add,receive_cluster_loop,receive_join,receive_leave,receive_invite,receive_kick,receive_block,receive_unblock,receive_allow,receive_description,receive_rules,receive_pin_add,reply_signature,reply_cluster_enabled,reply_cluster_right,reply_interface_enabled,reply_interface_right,reply_local_enabled,reply_local_right,reply_block,reply_length_min,reply_length_max,send_local,send_cluster,help,update,join,leave,name,address,info,pin,pin_add,pin_remove,cluster_pin_add,description,rules,readme,time,version,groups,members,admins,moderators,users,guests,search,activitys,statistic,statistic_min,statistic_cluster,statistic_router,statistic_local,statistic_self,delivery,invite
guest = interface,receive_local,receive_cluster,receive_cluster_loop,update,join,leave
wait = interface,update,join,leave




#### User cmd assignment ####

# Define the individual cmds for the different user types.
# Delimiter for different cmds: ,
[cmds]

admin = update,update_all,leave,invite,kick,block,unblock,allow,deny
mod = update,update_all,leave,invite,kick,block,unblock,allow,deny
user = leave,invite
guest = leave
wait = leave




#### User config assignment ####
# Define the individual configs for the different user types.
# Delimiter for different configs: ,
[configs]
admin = #file_tx_enabled=True,audio_tx_enabled=True
mod = 
user = 
guest = 
wait = 




#### User rights/cmds options ####

# The following rights/cmds can be assigned:
# anonymous = Hide source identity.
# interface = General function of the command interface.
# receive_local = Receive local (own group) messages.
# receive_cluster = Receive cluster (foreign group) messages.
# receive_cluster_pin_add = Receive cluster (foreign group) pinned messages.
# receive_cluster_send = Receive a copy of the message sent to another cluster.
# receive_cluster_loop = Receive message which is sent to a higher hierarchy in the cluster and includes the own cluster.
# receive_cluster_join = Receive an info message when a new cluster joins.
# receive_join = Receive an info message when a new user joins.
# receive_leave = Receive an info message when a user leaves.
# receive_invite = Receive an info message when a user is invited.
# receive_kick = Receive an info message when a user is kicked.
# receive_block = Receive an info message when a user is blocked.
# receive_unblock = Receive an info message when a user is unblocked.
# receive_allow = Receive an info message when a user has been allowed.
# receive_deny = Receive an info message when a user has been denied.
# receive_description = Receive an info message when the group description is changed.
# receive_pin_add = Receive an info message when a message is pinned.
# receive_pin_remove = Receive an info message when a pinned message is removed.
# receive_rules = Receive an info message when the group rules are changed.
# receive_name_def = Receive an info message when a user assigns a name.
# receive_name_change = Receive an info message when a user changes his name.
# receive_auto_name_def = Receive an info message when a user assigns a name.
# receive_auto_name_change = Receive an info message when a user changes his name.
# reply_signature = Receive an error message if the signature is invalid.
# reply_cluster_enabled = Receive an error message when the cluster is disabled.
# reply_cluster_right = Receive an error message when you do not have permission to send in the cluster.
# reply_interface_enabled = Receive an error message when the interface is disabled.
# reply_interface_right = Receive an error message if you do not have permission to use the interface.
# reply_local_enabled = Receive an error message when sending a local message is disabled.
# reply_local_right = Receive an error message when you do not have permission to send locally.
# reply_block = Receive an error message when you are blocked.
# reply_length_min = Receive an error message if the message length is too short.
# reply_length_max = Receive an error message if the message length is too long.
# send_local = Allows you to send loacally in your own group.
# send_cluster = Allows sending to another cluster/group.
# help = Use of the "/help" command allowed.
# update = Use of the "/update" command allowed.
# join = Use of the "/join" command allowed.
# leave = Use of the "/leave" command allowed.
# name = Use of the "/name" command allowed.
# address = Use of the "/address" command allowed.
# info = Use of the "/info" command allowed.
# pin = Use of the "/pin" command allowed.
# pin_add = Use of the "/pin" command allowed.
# pin_remove = Use of the "/pin" command allowed.
# cluster_pin_add = Use of the "/pin" command allowed.
# version = Use of the "/version" command allowed.
# groups = Use of the "/groups" command allowed.
# members = Use of the "/members" command allowed.
# admins = Use of the "/admins" command allowed.
# moderators = Use of the "/moderators" command allowed.
# users = Use of the "/users" command allowed.
# guests = Use of the "/guests" command allowed.
# search = Use of the "/search" command allowed.
# activitys = Use of the "/activitys" command allowed.
# statistic = Use of the "/statistic" command allowed.
# statistic_min = Minimal statistics output.
# statistic_full = Full/Maximal statistics output.
# statistic_cluster = Displays the cluster statistics on the statistics text.
# statistic_router = Displays the cluster statistics on the statistics text.
# statistic_local = Displays the local statistics on the statistics text.
# statistic_interface = Displays the interface statistics on the statistics text.
# statistic_self = Displays the own statistics on the statistics text.
# statistic_user = Displays the user statistics on the statistics text.
# status = Use of the "/status" command allowed.
# delivery = Use of the "/delivery" command allowed.
# enable_local = Use of the "/enable_local" command allowed.
# enable_cluster = Use of the "/enable_cluster" command allowed.
# auto_add_user = Use of the "/auto_add_user" command allowed.
# auto_add_user_type = Use of the "/auto_add_user_type" command allowed.
# auto_add_cluster = Use of the "/auto_add_cluster" command allowed.
# auto_add_router = Use of the "/auto_add_router" command allowed.
# invite_user = Use of the "/invite_user" command allowed.
# invite_user_type = Use of the "/invite_user_type" command allowed.
# allow_user = Use of the "/allow_user" command allowed.
# allow_user_type = Use of the "/allow_user_type" command allowed.
# deny_user = Use of the "/deny_user" command allowed.
# deny_user_type = Use of the "/deny_user_type" command allowed.
# description = Use of the "/description" command allowed.
# description_set = Use of the "/description" command allowed.
# rules = Use of the "/rules" command allowed.
# rules_set = Use of the "/rules" command allowed.
# readme = Use of the "/readme" command allowed.
# time = Use of the "/time" command allowed.
# announce = Use of the "/announce" command allowed.
# sync = Use of the "/sync" command allowed.
# show_run = Use of the "/show_run" command allowed.
# show = Use of the "/show" command allowed.
# add = Use of the "/add" command allowed.
# del = Use of the "/del" command allowed.
# move = Use of the "/move" command allowed.
# rename = Use of the "/rename" command allowed.
# invite = Use of the "/invite" command allowed.
# kick = Use of the "/kick" command allowed.
# block = Use of the "/block" command allowed.
# unblock = Use of the "/unblock" command allowed.
# allow = Use of the "/allow" command allowed.
# deny = Use of the "/deny" command allowed.
# load = Use of the "/load" command allowed.
# save = Use of the "/save" command allowed.
# reload = Use of the "/reload" command allowed.
# reset = Use of the "/reset" command allowed.
# unsaved = Displays the status of the data file when using any action/command.




#### Interface settings - General ####
[interface]

# Enable/Disable the whole interface/commands.
enabled = True

# Define the delimiters for command input/output.
delimiter_input = /
delimiter_output = !




#### Interface settings - Messages ####

# Define messages for user or automatic actions.
# These messages are sent automatically when a corresponding action is triggered.
# If a message is to be deactivated simply comment it out.
[interface_messages]

# Auto user add. (Single message to the user.)
auto_error = ERROR: Joining the group is not possible.
auto_error-de = FEHLER: Beitritt zur Gruppe ist nicht möglich.

auto_add_admin = Welcome to the group "!display_name!"!!n!!n!!description!!n!!n!The messages sent here are distributed to all group members.!n!!n!For help enter /?!n!!n!To read the group rules use the command /rules!n!!n!Pinned messages: !count_pin!!n!Use the command /pin to display them.!n!!n!Your current nickname is "!source_name!". Please change your nickname with the command /name
auto_add_admin-de = Willkommen in der Gruppe "!display_name!"!!n!!n!!description!!n!!n!Die hier gesendeten Nachrichten werden an alle Gruppenmitglieder verteilt.!n!!n!Für Hilfe geben Sie /? ein.!n!!n!Um die Gruppenregeln zu lesen verwenden Sie den Befehl /rules!n!!n!Angepinnte Nachrichten: !count_pin!!n!Verwenden Sie den Befehl /pin um sie anzuzeigen.!n!!n!Dein aktueller Nickname ist "!source_name!" Bitte ändern Sie ihren Nickname mit dem Befehl /name
auto_add_mod = Welcome to the group "!display_name!"!!n!!n!!description!!n!!n!The messages sent here are distributed to all group members.!n!!n!For help enter /?!n!!n!To read the group rules use the command /rules!n!!n!Pinned messages: !count_pin!!n!Use the command /pin to display them.!n!!n!Your current nickname is "!source_name!". Please change your nickname with the command /name
auto_add_mod-de = Willkommen in der Gruppe "!display_name!"!!n!!n!!description!!n!!n!Die hier gesendeten Nachrichten werden an alle Gruppenmitglieder verteilt.!n!!n!Für Hilfe geben Sie /? ein.!n!!n!Um die Gruppenregeln zu lesen verwenden Sie den Befehl /rules!n!!n!Angepinnte Nachrichten: !count_pin!!n!Verwenden Sie den Befehl /pin um sie anzuzeigen.!n!!n!Dein aktueller Nickname ist "!source_name!" Bitte ändern Sie ihren Nickname mit dem Befehl /name
auto_add_user = Welcome to the group "!display_name!"!!n!!n!!description!!n!!n!The messages sent here are distributed to all group members.!n!!n!For help enter /?!n!!n!To read the group rules use the command /rules!n!!n!Pinned messages: !count_pin!!n!Use the command /pin to display them.!n!!n!Your current nickname is "!source_name!". Please change your nickname with the command /name
auto_add_user-de = Willkommen in der Gruppe "!display_name!"!!n!!n!!description!!n!!n!Die hier gesendeten Nachrichten werden an alle Gruppenmitglieder verteilt.!n!!n!Für Hilfe geben Sie /? ein.!n!!n!Um die Gruppenregeln zu lesen verwenden Sie den Befehl /rules!n!!n!Angepinnte Nachrichten: !count_pin!!n!Verwenden Sie den Befehl /pin um sie anzuzeigen.!n!!n!Dein aktueller Nickname ist "!source_name!" Bitte ändern Sie ihren Nickname mit dem Befehl /name
auto_add_guest = Welcome to the group "!display_name!"!!n!!n!!description!!n!!n!You can only receive messages.!n!!n!Pinned messages: !count_pin!!n!Use the command /pin to display them.!n!!n!To leave the group use the following command: /leave
auto_add_guest-de = Willkommen in der Gruppe "!display_name!"!!n!!n!!description!!n!!n!Sie können nur Nachrichten empfangen.!n!!n!Angepinnte Nachrichten: !count_pin!!n!Verwenden Sie den Befehl /pin um sie anzuzeigen.!n!!n!Um die Gruppe zu verlassen verwenden Sie folgenden Befehl: /leave
auto_add_wait = Welcome to the group "!display_name!"!!n!!n!You still need to be allowed to join. You will be notified automatically.
auto_add_wait-de = Willkommen in der Gruppe "!display_name!"!!n!!n!Der Beitritt muss ihnen noch erlaubt werden. Sie werden darüber automatisch benachrichtigt.

# Manual/Admin user add. (Single message to the user.)
add_admin = 
add_admin-de = 
add_mod = 
add_mod-de = 
add_user = 
add_user-de = 
add_guest = 
add_guest-de = 
add_wait = 
add_wait-de = 

# Invite user. (Single message to the user.)
invite_admin = You have been invited by !source_name! <!source_address!> to the group "!display_name!"!!n!!n!!description!!n!!n!The messages sent here are distributed to all group members.!n!!n!For help enter /?!n!!n!To read the group rules use the command /rules!n!!n!Your current nickname is "!user_name!". Please change your nickname with the command /name
invite_admin-de = Sie wurden von !source_name! <!source_address!> in die Gruppe "!display_name!" eingeladen!!n!!n!!description!!n!!n!Die hier gesendeten Nachrichten werden an alle Gruppenmitglieder verteilt.!n!!n!Für Hilfe geben Sie /? ein.!n!!n!Um die Gruppenregeln zu lesen verwenden Sie den Befehl /rules!n!!n!Dein aktueller Nickname ist "!user_name!" Bitte ändern Sie ihren Nickname mit dem Befehl /name
invite_mod = You have been invited by !source_name! <!source_address!> to the group "!display_name!"!!n!!n!!description!!n!!n!The messages sent here are distributed to all group members.!n!!n!For help enter /?!n!!n!To read the group rules use the command /rules!n!!n!Your current nickname is "!user_name!". Please change your nickname with the command /name
invite_mod-de = Sie wurden von !source_name! <!source_address!> in die Gruppe "!display_name!" eingeladen!!n!!n!!description!!n!!n!Die hier gesendeten Nachrichten werden an alle Gruppenmitglieder verteilt.!n!!n!Für Hilfe geben Sie /? ein.!n!!n!Um die Gruppenregeln zu lesen verwenden Sie den Befehl /rules!n!!n!Dein aktueller Nickname ist "!user_name!" Bitte ändern Sie ihren Nickname mit dem Befehl /name
invite_user = You have been invited by !source_name! <!source_address!> to the group "!display_name!"!!n!!n!!description!!n!!n!The messages sent here are distributed to all group members.!n!!n!For help enter /?!n!!n!To read the group rules use the command /rules!n!!n!Your current nickname is "!user_name!". Please change your nickname with the command /name
invite_user-de = Sie wurden von !source_name! <!source_address!> in die Gruppe "!display_name!" eingeladen!!n!!n!!description!!n!!n!Die hier gesendeten Nachrichten werden an alle Gruppenmitglieder verteilt.!n!!n!Für Hilfe geben Sie /? ein.!n!!n!Um die Gruppenregeln zu lesen verwenden Sie den Befehl /rules!n!!n!Dein aktueller Nickname ist "!user_name!" Bitte ändern Sie ihren Nickname mit dem Befehl /name
invite_guest = You have been invited by !source_name! <!source_address!> to the group "!display_name!"!!n!!n!!description!!n!!n!You can only receive messages.!n!!n!To leave the group use the following command: /leave
invite_guest-de = Sie wurden von !source_name! <!source_address!> in die Gruppe "!display_name!" eingeladen!!n!!n!!description!!n!!n!Sie können nur Nachrichten empfangen.!n!!n!Um die Gruppe zu verlassen verwenden Sie folgenden Befehl: /leave
invite_wait = You have been invited by !source_name! <!source_address!> to the group "!display_name!"!!n!!n!You still need to be allowed to join. You will be notified automatically.
invite_wait-de = Sie wurden von !source_name! <!source_address!> in die Gruppe "!display_name!" eingeladen!!n!!n!Der Beitritt muss ihnen noch erlaubt werden. Sie werden darüber automatisch benachrichtigt.

# Kick user. (Single message to the user.)
kick_admin = You have been kicked out of the group!
kick_admin-de = Sie wurden aus der Gruppe geworfen!
kick_mod = You have been kicked out of the group!
kick_mod-de = Sie wurden aus der Gruppe geworfen!
kick_user = You have been kicked out of the group!
kick_user-de = Sie wurden aus der Gruppe geworfen!
kick_guest = You have been kicked out of the group!
kick_guest-de = Sie wurden aus der Gruppe geworfen!
kick_wait = You have been kicked out of the group!
kick_wait-de = Sie wurden aus der Gruppe geworfen!

# Block user. (Single message to the user.)
block_admin = 
block_admin-de = 
block_mod = 
block_mod-de = 
block_user = 
block_user-de = 
block_guest = 
block_guest-de = 
block_wait = 
block_wait-de = 

# Unblock user. (Single message to the user.)
unblock_admin = 
unblock_admin-de = 
unblock_mod = 
unblock_mod-de = 
unblock_user = 
unblock_user-de = 
unblock_guest = 
unblock_guest-de = 
unblock_wait = 
unblock_wait-de = 

# Allow user. (Single message to the user.)
allow_admin = You have been allowed to join the group "!display_name!"!!n!!n!!description!!n!!n!The messages sent here are distributed to all group members.!n!!n!For help enter /?!n!!n!To read the group rules use the command /rules!n!!n!Please assign a nickname with the command /name
allow_admin-de = Sie wurden erlaubt der Gruppe "!display_name!" beizutreten!!n!!n!!description!!n!!n!Die hier gesendeten Nachrichten werden an alle Gruppenmitglieder verteilt.!n!!n!Für Hilfe geben Sie /? ein.!n!!n!Um die Gruppenregeln zu lesen verwenden Sie den Befehl /rules!n!!n!Bitte vergeben Sie einen Nickname mit dem Befehl /name
allow_mod = You have been allowed to join the group "!display_name!"!!n!!n!!description!!n!!n!The messages sent here are distributed to all group members.!n!!n!For help enter /?!n!!n!To read the group rules use the command /rules!n!!n!Please assign a nickname with the command /name
allow_mod-de = Sie wurden erlaubt der Gruppe "!display_name!" beizutreten!!n!!n!!description!!n!!n!Die hier gesendeten Nachrichten werden an alle Gruppenmitglieder verteilt.!n!!n!Für Hilfe geben Sie /? ein.!n!!n!Um die Gruppenregeln zu lesen verwenden Sie den Befehl /rules!n!!n!Bitte vergeben Sie einen Nickname mit dem Befehl /name
allow_user = You have been allowed to join the group "!display_name!"!!n!!n!!description!!n!!n!The messages sent here are distributed to all group members.!n!!n!For help enter /?!n!!n!To read the group rules use the command /rules!n!!n!Please assign a nickname with the command /name
allow_user-de = Sie wurden erlaubt der Gruppe "!display_name!" beizutreten!!n!!n!!description!!n!!n!Die hier gesendeten Nachrichten werden an alle Gruppenmitglieder verteilt.!n!!n!Für Hilfe geben Sie /? ein.!n!!n!Um die Gruppenregeln zu lesen verwenden Sie den Befehl /rules!n!!n!Bitte vergeben Sie einen Nickname mit dem Befehl /name
allow_guest = You have been allowed to join the group "!display_name!"!!n!!n!!description!!n!!n!You can only receive messages.!n!!n!To leave the group use the following command: /leave
allow_guest-de = Sie wurden erlaubt der Gruppe "!display_name!" beizutreten!!n!!n!!description!!n!!n!Sie können nur Nachrichten empfangen.!n!!n!Um die Gruppe zu verlassen verwenden Sie folgenden Befehl: /leave
allow_wait = 
allow_wait-de = 

# Deny user. (Single message to the user.)
deny_admin = You have been denied to join the group "!display_name!"!
deny_admin-de = Ihnen wurde der Beitritt in die Gruppe "!display_name!" abgelehnt!
deny_mod = You have been denied to join the group "!display_name!"!
deny_mod-de = Ihnen wurde der Beitritt in die Gruppe "!display_name!" abgelehnt!
deny_user = You have been denied to join the group "!display_name!"!
deny_user-de = Ihnen wurde der Beitritt in die Gruppe "!display_name!" abgelehnt!
deny_guest = You have been denied to join the group "!display_name!"!
deny_guest-de = Ihnen wurde der Beitritt in die Gruppe "!display_name!" abgelehnt!
deny_wait = 
deny_wait-de = 

# General user/member messages. (Group message to all group members.)
member_join = !source_name! <!source_address!> joins the group.
member_join-de = !source_name! <!source_address!> tritt der Gruppe bei.
member_leave = !source_name! <!source_address!> leave the group.
member_leave-de = !source_name! <!source_address!> verlässt die Gruppe.
member_invite = !user_name! <!user_address!> was invited to the group by !source_name! <!source_address!>
member_invite-de = !user_name! <!user_address!> wurde in die Gruppe eingeladen von !source_name! <!source_address!>
member_kick = !user_name! <!user_address!> was kicked out of the group by !source_name! <!source_address!>
member_kick-de = !user_name! <!user_address!> wurde aus der Gruppe geworfen von !source_name! <!source_address!>
member_block = !user_name! <!user_address!> was blocked by !source_name! <!source_address!>
member_block-de = !user_name! <!user_address!> wurde geblockt von !source_name! <!source_address!>
member_unblock = !user_name! <!user_address!> was unblocked by !source_name! <!source_address!>
member_unblock-de = !user_name! <!user_address!> wurde entsperrt von !source_name! <!source_address!>
member_allow = !user_name! <!user_address!> was allowed by !source_name! <!source_address!>
member_allow-de = !user_name! <!user_address!> wurde erlaubt von !source_name! <!source_address!>
member_deny = !user_name! <!user_address!> was denied by !source_name! <!source_address!>
member_deny-de = !user_name! <!user_address!> wurde abgelehnt von !source_name! <!source_address!>
member_name_def = <!source_address!> defined the name:
member_name_def-de = <!source_address!> hat den Namen definiert:
member_name_change = <!source_address!> changed the name:
member_name_change-de = <!source_address!> hat den Namen geändert:
description = !source_name! <!source_address!> has changed the group description:!n!!n!!description!
description-de = !source_name! <!source_address!> hat die Gruppenbeschreibung geändert:!n!!n!!description!
rules = !source_name! <!source_address!> has changed the group rules:!n!!n!!rules!
rules-de = !source_name! <!source_address!> hat die Gruppenregeln geändert:!n!!n!!rules!
cluster_join = New cluster/group connected: !source_name! <!source_address!>
cluster_join-de = Neue Cluster/Gruppe verbunden: !source_name! <!source_address!>
pin_add = New pinned message:!n!#!key!!n!!value!
pin_add-de = Neue angeheftete Nachricht:!n!#!key!!n!!value!
pin_remove = Removed pinned message:!n!#!key!!n!!value!
pin_remove-de = Angeheftete Nachricht entfernt:!n!#!key!!n!!value!
cluster_pin_add = New pinned message:!n!#!key!!n!!value!
cluster_pin_add-de = Neue angeheftete Nachricht:!n!#!key!!n!!value!

# Reply messages. (Single message to the user.)
reply_signature = Info: Signature invalid!
reply_signature-de = Info: Signatur ungültig!
reply_cluster_enabled = Info: Cluster disabled!
reply_cluster_enabled-de = Info: Cluster deaktiviert!
reply_cluster_right = Info: No authorization for cluster messages!
reply_cluster_right-de = Keine Berechtigung für Clusternachrichten!
reply_interface_enabled = Info: Commands disabled!
reply_interface_enabled-de = Info: Befehle deaktiviert!
reply_interface_right = Info: No authorization for commands!
reply_interface_right-de = Info: Keine Berechtigung für Befehle!
reply_local_enabled = Info: Group deactivated!
reply_local_enabled-de = Info: Gruppe deaktiviert!
reply_local_right = Info: No authorization to send messages!
reply_local_right-de = Info: Keine Berechtigung zum senden von Nachrichten!
reply_block = Info: You are blocked!
reply_block-de = Info: Sie sind geblockt!
reply_length_min = Info: Minimum message length not reached!
reply_length_min-de = Info: Minimale Nachrichtenlänge unterschritten!
reply_length_max = Info: Maximum message length exceeded!
reply_length_max-de = Info: Maximale Nachrichtenlänge überschritten!




#### Interface settings - Menu/command ####

# Define menu/command texts.
# These texts are used within the menu the user has to start.
[interface_menu]

# "/help" command.
help_admin = Group:!n!!display_name!!n!!n!Description:!n!!description!!n!!n!Number of members: !count_members!!n!Nickname: !source_name!!n!User right/type: !source_right!!n!!n!!interface_help!!n!Commands:!n!!interface_help_command!
help_admin-de = Gruppe:!n!!display_name!!n!!n!Beschreibung:!n!!description!!n!!n!Anzahl Mitglieder: !count_members!!n!Nickname: !source_name!!n!Benutzer Recht/Typ: !source_right!!n!!n!!interface_help!!n!Befehle:!n!!interface_help_command!
help_mod = Group:!n!!display_name!!n!!n!Description:!n!!description!!n!!n!Number of members: !count_members!!n!Nickname: !source_name!!n!User right/type: !source_right!!n!!n!!interface_help!!n!Commands:!n!!interface_help_command!
help_mod-de = Gruppe:!n!!display_name!!n!!n!Beschreibung:!n!!description!!n!!n!Anzahl Mitglieder: !count_members!!n!Nickname: !source_name!!n!Benutzer Recht/Typ: !source_right!!n!!n!!interface_help!!n!Befehle:!n!!interface_help_command!
help_user = Group:!n!!display_name!!n!!n!Description:!n!!description!!n!!n!Number of members: !count_members!!n!Nickname: !source_name!!n!User right/type: !source_right!!n!!n!!interface_help!!n!Commands:!n!!interface_help_command!
help_user-de = Gruppe:!n!!display_name!!n!!n!Beschreibung:!n!!description!!n!!n!Anzahl Mitglieder: !count_members!!n!Nickname: !source_name!!n!Benutzer Recht/Typ: !source_right!!n!!n!!interface_help!!n!Befehle:!n!!interface_help_command!
help_guest = 
help_guest-de = 

# "/update" command.
update_ok = OK: Data updated.
update_ok-de = OK: Daten aktualisiert.
update_error = ERROR: Updating data.
update_error-de = FEHLER: Daten aktualisieren.

# "/update_all" command.
update_all_ok = OK: Data updated.
update_all_ok-de = OK: Daten aktualisiert.
update_all_error = ERROR: Updating data.
update_all_error-de = FEHLER: Daten aktualisieren.

# "/join" command.
join_error = ERROR: While joining group.
join_error-de = FEHLER: Beim Beitritt in die Gruppe.

# "/leave" command.
leave_ok = OK: You leaved the group.
leave_ok-de = OK: Sie haben die Gruppe verlassen.
leave_error = ERROR: While leaving group.
leave_error-de = FEHLER: Beim Verlassen der Gruppe.

# "/name" command.
name = Current nickname: !source_name!
name-de = Aktueller Nickname: !source_name!
name_ok = OK: Changed name: 
name_ok-de = OK: Name geändert:
name_error = ERROR: Changing name:
name_error-de = FEHLER: Name ändern:

# "/address" command.
address_admin = Group address:!n!<!destination_address!>!n!!n!Propagation node:!n!<!propagation_node!>
address_admin-de = Gruppenadresse:!n!<!destination_address!>!n!!n!Propagation Node:!n!<!propagation_node!>
address_mod = Group address:!n!<!destination_address!>!n!!n!Propagation node:!n!<!propagation_node!>
address_mod-de = Gruppenadresse:!n!<!destination_address!>!n!!n!Propagation Node:!n!<!propagation_node!>
address_user = Group address:!n!<!destination_address!>!n!!n!Propagation node:!n!<!propagation_node!>
address_user-de = Gruppenadresse:!n!<!destination_address!>!n!!n!Propagation Node:!n!<!propagation_node!>
address_guest = Group address:!n!<!destination_address!>!n!!n!Propagation node:!n!<!propagation_node!>
address_guest-de = Gruppenadresse:!n!<!destination_address!>!n!!n!Propagation Node:!n!<!propagation_node!>

# "/info" command.
info_admin = Group:!n!!display_name!!n!!n!Description:!n!!description!!n!!n!Number of members: !count_members!!n!Pinned messages: !count_pin!!n!Use the command /pin to display them.
info_admin-de = Gruppe:!n!!display_name!!n!!n!Beschreibung:!n!!description!!n!!n!Anzahl Mitglieder: !count_members!!n!Angepinnte Nachrichten: !count_pin!!n!Verwenden Sie den Befehl /pin um sie anzuzeigen.
info_mod = Group:!n!!display_name!!n!!n!Description:!n!!description!!n!!n!Number of members: !count_members!!n!Pinned messages: !count_pin!!n!Use the command /pin to display them.
info_mod-de = Gruppe:!n!!display_name!!n!!n!Beschreibung:!n!!description!!n!!n!Anzahl Mitglieder: !count_members!!n!Angepinnte Nachrichten: !count_pin!!n!Verwenden Sie den Befehl /pin um sie anzuzeigen.
info_user = Group:!n!!display_name!!n!!n!Description:!n!!description!!n!!n!Number of members: !count_members!!n!Pinned messages: !count_pin!!n!Use the command /pin to display them.
info_user-de = Gruppe:!n!!display_name!!n!!n!Beschreibung:!n!!description!!n!!n!Anzahl Mitglieder: !count_members!!n!Angepinnte Nachrichten: !count_pin!!n!Verwenden Sie den Befehl /pin um sie anzuzeigen.
info_guest = Group:!n!!display_name!!n!!n!Description:!n!!description!!n!!n!Number of members: !count_members!!n!Pinned messages: !count_pin!!n!Use the command /pin to display them.
info_guest-de = Gruppe:!n!!display_name!!n!!n!Beschreibung:!n!!description!!n!!n!Anzahl Mitglieder: !count_members!!n!Angepinnte Nachrichten: !count_pin!!n!Verwenden Sie den Befehl /pin um sie anzuzeigen.

# "/pin" command.
pin_header = Pinned messages (!count!):!n!!n!
pin_header-de = Angeheftete Nachrichten (!count!):!n!!n!
pin = !source_name!!n!<!source_address!>!n!!value!
pin-de = !source_name!!n!<!source_address!>!n!!value!
pin_add_ok = OK: Message pinned
pin_add_ok-de = OK: Nachricht angeheftet
pin_remove_ok = OK: Message removed
pin_remove_ok-de = OK: Nachricht entfernt
pin_found_error = ERROR: Message ID not found
pin_found_error-de = FEHLER: Nachrichten ID nicht gefunden
cluster_pin = !value!
cluster_pin-de = !value!

# "/version" command.
version_header = Version info:!n!!n!
version_header-de = Versionsinformationen:!n!!n!

# "/groups" command.
groups_header = Groups/Cluster (!count!):!n!!n!
groups_header-de = Gruppen/Cluster (!count!):!n!!n!
groups_member = !source_name!!n!
groups_member-de = !source_name!!n!
groups_search_header = Found groups/cluster (!count!):!n!!n!
groups_search_header-de = Gefundene Gruppen/Cluster (!count!):!n!!n!
groups_search_member = !source_name!!n!
groups_search_member-de = !source_name!!n!
groups_search_found_error = ERROR: Group/Cluster not found
groups_search_found_error-de = FEHLER: Gruppe/Cluster nicht gefunden

# "/members" command.
members_header = Group members (!count!):!n!!n!
members_header-de = Gruppenmitglieder (!count!):!n!!n!
members_member = !source_name!!n!<!source_address!>!n!!n!
members_member-de = !source_name!!n!<!source_address!>!n!!n!

# "/admins" command.
admins_header = Group admins (!count!):!n!!n!
admins_header-de = Gruppenadmins (!count!):!n!!n!
admins_member = !source_name!!n!<!source_address!>!n!!n!
admins_member-de = !source_name!!n!<!source_address!>!n!!n!

# "/moderators" command.
moderators_header = Group moderators (!count!):!n!!n!
moderators_header-de = Gruppenmoderatoren (!count!):!n!!n!
moderators_member = !source_name!!n!<!source_address!>!n!!n!
moderators_member-de = !source_name!!n!<!source_address!>!n!!n!

# "/users" command.
users_header = Group users (!count!):!n!!n!
users_header-de = Gruppenbenutzer (!count!):!n!!n!
users_member = !source_name!!n!<!source_address!>!n!!n!
users_member-de = !source_name!!n!<!source_address!>!n!!n!

# "/guests" command.
guests_header = Group guests (!count!):!n!!n!
guests_header-de = Gruppengäste (!count!):!n!!n!
guests_member = !source_name!!n!<!source_address!>!n!!n!
guests_member-de = !source_name!!n!<!source_address!>!n!!n!

# "/search" command.
search_header = Found members (!count!):!n!!n!
search_header-de = Gefundene Mitglieder (!count!):!n!!n!
search_member = !source_name!!n!<!source_address!>!n!!activity_receive! / !activity_send!!n!!n!
search_member-de = !source_name!!n!<!source_address!>!n!!activity_receive! / !activity_send!!n!!n!
search_found_error = ERROR: Nickname or address not found
search_found_error-de = FEHLER: Benutzername oder Adresse nicht gefunden

# "/activitys" command.
activitys_header = User activitys (!count!):!n!(receive / send)!n!!n!
activitys_header-de = Benutzeraktivitäten (!count!):!n!(empf. / gesendet)!n!!n!
activitys_member = !source_name!!n!<!source_address!>!n!!activity_receive! / !activity_send!!n!!n!
activitys_member-de = !source_name!!n!<!source_address!>!n!!activity_receive! / !activity_send!!n!!n!

# "/statistic" command.
statistic_header_cluster = -- Cluster statistics - !value! --!n!
statistic_header_cluster-de = -- Cluster-Statistik - !value! --!n!
statistic_header_router = -- Router statistics - !value! --!n!
statistic_header_router-de = -- Router-Statistik - !value! --!n!
statistic_header_local = -- Group statistics - !value! --!n!
statistic_header_local-de = -- Gruppen-Statistik - !value! --!n!
statistic_header_interface = -- Interface statistics - !value! --!n!
statistic_header_interface-de = -- Interface-Statistik - !value! --!n!
statistic_header_user = -- User statistics - !value! --!n!
statistic_header_user-de = -- Benutzer-Statistik - !value! --!n!
statistic_header_self = -- Own statistics --!n!
statistic_header_self-de = -- Eigene-Statistik --!n!
statistic_found_error = ERROR: Statistic type not found
statistic_found_error-de = FEHLER: Statistik typ nicht vorhanden

# "/status" command.
status_admin = Status:!n!!n!Local message routing:!enabled_local!!n!Cluster message routing:!enabled_cluster!!n!
status_admin-de = Status:!n!!n!Lokales Nachrichten Routing:!enabled_local!!n!Cluster Nachrichten Routing:!enabled_cluster!!n!
status_mod = Status:!n!!n!Local message routing:!enabled_local!!n!Cluster message routing:!enabled_cluster!!n!
status_mod-de = Status:!n!!n!Lokales Nachrichten Routing:!enabled_local!!n!Cluster Nachrichten Routing:!enabled_cluster!!n!
status_user = Status:!n!!n!Local message routing:!enabled_local!!n!Cluster message routing:!enabled_cluster!!n!
status_user-de = Status:!n!!n!Lokales Nachrichten Routing:!enabled_local!!n!Cluster Nachrichten Routing:!enabled_cluster!!n!
status_guest = Status:!n!!n!Local message routing:!enabled_local!!n!Cluster message routing:!enabled_cluster!!n!
status_guest-de = Status:!n!!n!Lokales Nachrichten Routing:!enabled_local!!n!Cluster Nachrichten Routing:!enabled_cluster!!n!

# "/delivery" command.
# todo

# "/enable_local" command.
enable_local_true = OK: Local message routing enabled.
enable_local_true-de = OK: Lokales Nachrichten Routing aktiviert.
enable_local_false = OK: Local message routing disabled.
enable_local_false-de = OK: Lokales Nachrichten Routing deaktiviert.
enable_local_error = ERROR: Local message routing change.
enable_local_error-de = FEHLER: Änderung Lokales Nachrichten Routing.

# "/enable_cluster" command.
enable_cluster_true = OK: Cluster message routing enabled.
enable_cluster_true-de = OK: Cluster Nachrichten Routing aktiviert.
enable_cluster_false = OK: Cluster message routing disabled.
enable_cluster_false-de = OK: Cluster Nachrichten Routing deaktiviert.
enable_cluster_error = ERROR: Cluster message routing change.
enable_cluster_error-de = FEHLER: Änderung Cluster Nachrichten Routing.

# "/auto_add_user" command.
auto_add_user_true = OK: Auto add user enabled.
auto_add_user_true-de = OK: Benutzer automatisch hinzufügen aktiviert.
auto_add_user_false = OK: Auto add user disabled.
auto_add_user_false-de = OK: Benutzer automatisch hinzufügen deaktiviert.
auto_add_user_error = ERROR: Auto add user change.
auto_add_user_error-de = FEHLER: Änderung Benutzer automatisch hinzufügen.

# "/auto_add_user_type" command.
auto_add_user_type = OK: User type changed to:
auto_add_user_type-de = OK: Benutzertyp geändert in:
auto_add_user_type_error = ERROR: User type change.
auto_add_user_type_error-de = FEHLER: Änderung des Benutzertyps.

# "/auto_add_cluster" command.
auto_add_cluster_true = OK: Auto add cluster enabled.
auto_add_cluster_true-de = OK: Cluster/Gruppen automatisch hinzufügen aktiviert.
auto_add_cluster_false = OK: Auto add cluster disabled.
auto_add_cluster_false-de = OK: Cluster/Gruppen automatisch hinzufügen deaktiviert.
auto_add_cluster_error = ERROR: Auto add cluster change.
auto_add_cluster_error-de = FEHLER: Änderung Cluster/Gruppen automatisch hinzufügen.

# "/auto_add_router" command.
auto_add_router_true = OK: Auto add router enabled.
auto_add_router_true-de = OK: Router automatisch hinzufügen aktiviert.
auto_add_router_false = OK: Auto add router disabled.
auto_add_router_false-de = OK: Router automatisch hinzufügen deaktiviert.
auto_add_router_error = ERROR: Auto add router change.
auto_add_router_error-de = FEHLER: Änderung Router automatisch hinzufügen.

# "/invite_user" command.
invite_user_true = OK: Invite user enabled.
invite_user_true-de = OK: Benutzer einladen aktiviert.
invite_user_false = OK: Invite user disabled.
invite_user_false-de = OK: Benutzer einladen deaktiviert.
invite_user_error = ERROR: Invite user change.
invite_user_error-de = FEHLER: Änderung Benutzer einladen.

# "/invite_user_type" command.
invite_user_type = OK: User type changed to:
invite_user_type-de = OK: Benutzertyp geändert in:
invite_user_type_error = ERROR: User type change.
invite_user_type_error-de = FEHLER: Änderung des Benutzertyps.

# "/allow_user" command.
allow_user_true = OK: Allow user enabled.
allow_user_true-de = OK: Benutzer erlauben aktiviert.
allow_user_false = OK: Allow user disabled.
allow_user_false-de = OK: Benutzer erlauben deaktiviert.
allow_user_error = ERROR: Allow user change.
allow_user_error-de = FEHLER: Änderung Benutzer erlauben.

# "/allow_user_type" command.
allow_user_type = OK: User type changed to:
allow_user_type-de = OK: Benutzertyp geändert in:
allow_user_type_error = ERROR: User type change.
allow_user_type_error-de = FEHLER: Änderung des Benutzertyps.

# "/deny_user" command.
deny_user_true = OK: Deny user enabled.
deny_user_true-de = OK: Benutzer ablehnen aktiviert.
deny_user_false = OK: Deny user disabled.
deny_user_false-de = OK: Benutzer ablehnen deaktiviert.
deny_user_error = ERROR: Deny user change.
deny_user_error-de = FEHLER: Änderung Benutzer ablehnen.

# "/deny_user_type" command.
deny_user_type = OK: User type changed to:
deny_user_type-de = OK: Benutzertyp geändert in:
deny_user_type_error = ERROR: User type change.
deny_user_type_error-de = FEHLER: Änderung des Benutzertyps.

# "/description" command.
description = OK: Description changed to:
description-de = OK: Beschreibung geändert in:
description_error = ERROR: Description change.
description_error-de = FEHLER: Beschreibung ändern.

# "/rules" command.
rules = OK: Rules changed to:
rules-de = OK: Regeln geändert in:
rules_error = ERROR: Rules change.
rules_error-de = FEHLER: Regeln ändern.

# "/readme" command.
readme = 
readme-de = 

# "/time" command.
time = Current server time: %%Y-%%m-%%d %%H:%%M:%%S
time-de = Aktuelle Server-Zeit: %%Y-%%m-%%d %%H:%%M:%%S

# "/announce" command.
announce = Announce send.
announce-de = Announce gesendet.

# "/sync" command.
sync = Synchronize messages with propagation node <!propagation_node!>.
sync-de = Synchronisiere Nachrichten mit Propagation node <!propagation_node!>.

# "/show run" command.
show_run_header = Current settings/data:!n!!n!
show_run_header-de = Aktuelle Konfiguration/Daten:!n!!n!

# "/show" command.
show_header = 
show_header-de = 

# "/user" command.
user_add = OK: Added user -> group:
user_add-de = OK: Benutzer -> Gruppe hinzugefügt:
user_del = OK: Removed user -> group:
user_del-de = OK: Entfernter Benutzer -> Gruppe:
user_move = OK: Moved user -> group:
user_move-de = OK: Benutzer -> Gruppe verschoben:
user_rename = OK: Renamed user:
user_rename-de = OK: Umbenannter Benutzer:
user_error = ERROR: Unknown user -> group:
user_error-de = FEHLER: Unbekannter Benutzer -> Gruppe:
user_found_error = ERROR: User not found
user_found_error-de = FEHLER: Benutzer nicht gefunden
user_format_error = ERROR: Wrong user format
user_format_error-de = FEHLER: Falsches Benutzerformat
user_type_error = ERROR: Unknown user type
user_type_error-de = FEHLER: Unbekannter Benutzertyp

# "/invite" command.
invite_ok = OK: Invited user: 
invite_ok-de = OK: Benutzer eingeladen:
invite_error = ERROR: Inviting user:
invite_error-de = FEHLER: Benutzer einladen:
invite_format_error = ERROR: Wrong user format
invite_format_error-de = FEHLER: Falsches Benutzerformat
invite_type_error = ERROR: Unknown user type
invite_type_error-de = FEHLER: Unbekannter Benutzertyp

# "/kick" command.
kick_ok = OK: User kicked out: !user_name! <!user_address!>
kick_ok-de = OK: Benutzer rausgeworfen: !user_name! <!user_address!>
kick_found_error = ERROR: User address not found
kick_found_error-de = FEHLER: Benutzer Adresse nicht gefunden
kick_format_error = ERROR: Wrong user format
kick_format_error-de = FEHLER: Falsches Benutzerformat

# "/block" command.
block_ok = OK: User blocked: !user_name! <!user_address!>
block_ok-de = OK: Benutzer blockiert: !user_name! <!user_address!>
block_found_error = ERROR: User address not found
block_found_error-de = FEHLER: Benutzer Adresse nicht gefunden
block_format_error = ERROR: Wrong user format
block_format_error-de = FEHLER: Falsches Benutzerformat

# "/unblock" command.
unblock_ok = OK: User unblocked: !user_name! <!user_address!>
unblock_ok-de = OK: Blockerierung des Benutzers aufgehoben: !user_name! <!user_address!>
unblock_found_error = ERROR: User address not found
unblock_found_error-de = FEHLER: Benutzer Adresse nicht gefunden
unblock_format_error = ERROR: Wrong user format
unblock_format_error-de = FEHLER: Falsches Benutzerformat

# "/allow" command.
allow_ok = OK: User allowed: !user_name! <!user_address!>
allow_ok-de = OK: Benutzer erlaubt: !user_name! <!user_address!>
allow_found_error = ERROR: User address not found
allow_found_error-de = FEHLER: Benutzer Adresse nicht gefunden
allow_format_error = ERROR: Wrong user format
allow_format_error-de = FEHLER: Falsches Benutzerformat
allow_type_error = ERROR: Unknown user type
allow_type_error-de = FEHLER: Unbekannter Benutzertyp

# "/deny" command.
deny_ok = OK: User denied: !user_name! <!user_address!>
deny_ok-de = OK: Benutzer abgelehnt: !user_name! <!user_address!>
deny_found_error = ERROR: User address not found
deny_found_error-de = FEHLER: Benutzer Adresse nicht gefunden
deny_format_error = ERROR: Wrong user format
deny_format_error-de = FEHLER: Falsches Benutzerformat
deny_type_error = ERROR: Unknown user type
deny_type_error-de = FEHLER: Unbekannter Benutzertyp

# "/load" command.
load_ok = OK: Loading configuration/data.
load_ok-de = OK: Konfiguration/Daten werden geladen.
load_error = ERROR: Loading configuration/data.
load_error-de = FEHLER: Konfiguration/Daten werden geladen.

# "/save" command.
save_ok = OK: Saved configuration/data.
save_ok-de = OK: Konfiguration/Daten gespeichert.
save_error = ERROR: Saving configuration/data.
save_error-de = FEHLER: Speichern der Konfiguration/Daten.
save_info = INFO: Unsaved changes! Please run the command '/save' to save these changes permanently!
save_info-de = INFO: Nicht gespeicherte Änderungen! Bitte führen Sie den Befehl '/save' aus, um diese Änderungen dauerhaft zu speichern!

# "/reload" command.
reload_ok = OK: Reloaded configuration/data.
reload_ok-de = OK: Konfiguration/Daten neu geladen.
reload_error = ERROR: Reload configuration/data.
reload_error-de = FEHLER: Neu laden der Konfiguration/Daten.

# "/reset" command.
reset_statistic_ok = OK: Reset statistic.
reset_statistic_ok-de = OK: Statistik zurückgesetzt.
reset_statistic_error = ERROR: Reset statistic.
reset_statistic_error-de = FEHLER: Statistik zurücksetzen.

# Cluster messages.
cluster_found_error = ERROR: Cluster name not found
cluster_found_error-de = FEHLER: Clustername nicht gefunden
cluster_format_error = ERROR: Wrong cluster format
cluster_format_error-de = FEHLER: Falsches Clusterformat

# General messages.
cmd_error = ERROR: Processing command.
cmd_error-de = FEHLER: Verarbeitung des Befehls.
cmd_unknown = ERROR: Unknown command. Type /? for help.
cmd_unknown-de = FEHLER: Unbekannter Befehl. Geben Sie /? für Hilfe ein.




#### Interface settings - Help ####

# Define help texts.
# These texts are used within the help-menu.
# Only the commands defined in the user rights are displayed.
# If a message is to be deactivated simply comment it out.
[interface_help]
send_local = To send a message simply enter any text.!n!!n!
send_local-de = Um eine Nachricht zu senden, geben Sie einfach einen beliebigen Text ein.!n!!n!
send_cluster = To send a message to another group enter the destination group with the following command followed by the message: @destination message.!n!!n!
send_cluster-de = Um eine Nachricht an eine andere Gruppe zu senden, geben Sie die Zielgruppe mit dem folgenden Befehl gefolgt von der Nachricht ein: @Zielname Nachricht.!n!!n!
interface = If the sent message is displayed as delivered and no error message is received, everything has worked fine.!n!!n!
interface-de = Wenn die gesendete Nachricht als zugestellt angezeigt wird und keine Fehlermeldung eingeht, hat alles fehlerfrei funktioniert.!n!!n!


# Define help texts.
# These texts are used within the help-menu.
# Only the commands defined in the user rights are displayed.
# If a message is to be deactivated simply comment it out.
[interface_help_command]

help = /help or /? = Shows this help!n!
help-de = /help oder /? = Zeigt diese Hilfe an!n!

leave = /leave or /part = Leave group!n!
leave-de = /leave oder /part = Gruppe verlassen!n!

name = /name = Show current nickname!n!/nick = Show current nickname!n!/name <your nickname> = Change/Define nickname!n!/nick <your nickname> = Change/Define nickname!n!
name-de = /name = Aktueller Nickname anzeigen!n!/nick = Aktueller Nickname anzeigen!n!/name <dein Nichname> = Ändern/Definieren des Nickname!n!/nick <dein Nichname> = Ändern/Definieren des Nickname!n!

address = /address = Dislay address info!n!
address-de = /address = Adressinfos anzeigen!n!

info = /info = Show group info!n!
info-de = /info = Gruppeninfos anzeigen!n!

pin = /pin = Show pinned messages!n!
pin-de = /pin = Angeheftete Nachrichten anzeigen!n!

pin_add = /pin <message> = Pin a message!n!
pin_add-de = /pin <Nachricht> = Nachricht anheften!n!

pin_remove = /unpin <#id> = Removes a pinned message!n!
pin_remove-de = /unpin <#id> = Angeheftete Nachricht entfernen!n!

version = /version = Show version info!n!
version-de = /version = Versionsinformationen anzeigen!n!

groups = /groups or /cluster = Show all groups/clusters!n!/groups <name> = Searches for a group/cluster by name!n!
groups-de = /groups oder /cluster = Alle Gruppen/Cluster anzeigen!n!/groups <name> = Sucht nach einer Gruppe/Cluster nach Namen!n!

members = /members or /names or /who = Show all group members!n!
members-de = /members oder /names oder /who = Alle Gruppenmitglieder anzeigen!n!

admins = /admins = Show group admins!n!
admins-de = /admins = Gruppenadmins anzeigen!n!

moderators = /moderators or /mods = Show group moderators!n!
moderators-de = /moderators oder /mods = Gruppenmoderatoren anzeigen!n!

users = /users = Show group users!n!
users-de = /users = Gruppenbenutzer anzeigen!n!

guests = /guests = Show group guests!n!
guests-de = /guests = Gruppengäste anzeigen!n!

search = /search <nickname/user_address> = Searches for a user by nickname or address!n!/whois <nickname/user_address> = Searches for a user by nickname or address!n!
search-de = /search <nickname/user_address> = Sucht einen Benutzer anhand des Nicknamens oder Adresse!n!/whois <nickname/user_address> = Sucht einen Benutzer anhand des Nicknamens oder Adresse!n!

activitys = /activitys = Show user activitys!n!
activitys-de = /activitys = Benutzeraktivitäten anzeigen!n!

statistic = /statistic or /stat = Show group statistic!n!/statistic <day/week/month/year/all> or /stat <day/week/month/year/all> = Show group statistic!n!
statistic-de = /statistic oder /stat = Gruppenstatistik anzeigen!n!/statistic <day/week/month/year/all> oder /stat <day/week/month/year/all> = Gruppenstatistik anzeigen!n!

status = /status = Show status!n!
status-de = /status = Status anzeigen!n!

delivery = /delivery or /message = Show delivery status of last message!n!
delivery-de = /delivery oder /message = Lieferstatus der letzten Nachricht anzeigen!n!

enable_local = /enable_local <true/false> = Local message routing!n!
enable_local-de = /enable_local <true/false> Lokales Nachrichten Routing!n!

enable_cluster = /enable_cluster <true/false> = Cluster message routing!n!
enable_cluster-de = /enable_cluster <true/false> Cluster Nachrichten Routing!n!

auto_add_user = /auto_add_user <true/false> = Add unknown user functionality!n!
auto_add_user-de = /auto_add_user <true/false> = Unbekannten Benutzer hinzufügen Funktionalität!n!

auto_add_user_type = /auto_add_user_type <admin/mod/user/guest>!n!
auto_add_user_type-de = /auto_add_user_type <admin/mod/user/guest>!n!

auto_add_cluster = /auto_add_cluster <true/false> = Add unknown cluster functionality!n!
auto_add_cluster-de = /auto_add_cluster <true/false> = Unbekannten Cluster/Gruppen hinzufügen Funktionalität!n!

auto_add_router = /auto_add_router <true/false> = Add unknown router functionality!n!
auto_add_router-de = /auto_add_router <true/false> = Unbekannten Router hinzufügen Funktionalität!n!

invite_user = /invite_user <true/false> = Invite functionality!n!
invite_user-de = /invite_user <true/false> = Einladung Funktionalität!n!

invite_user_type = /invite_user_type <admin/mod/user/guest>!n!
invite_user_type-de = /invite_user_type <admin/mod/user/guest>!n!

allow_user = /allow_user <true/false> = Allow user functionality!n!
allow_user-de = /allow_user <true/false> = Benutzer erlauben Funktionalität!n!

allow_user_type = /allow_user_type <admin/mod/user/guest>!n!
allow_user_type-de = /allow_user_type <admin/mod/user/guest>!n!

deny_user = /deny_user <true/false> = Deny user functionality!n!
deny_user-de = /deny_user <true/false> = Benutzer ablehnen Funktionalität!n!

deny_user_type = /deny_user_type <admin/mod/user/guest>!n!
deny_user_type-de = /deny_user_type <admin/mod/user/guest>!n!

description = /description = Show current description!n!
description-de = /description = Aktuelle Beschreibung anzeigen!n!

description_set = /description <description> = Change description!n!
description_set-de = /description <description>!n! = Beschreibung ändern

rules = /rules = Show current rules!n!
rules-de = /rules = Aktuelle Regeln anzeigen!n!

rules_set = /rules <description> = Change rules!n!
rules_set-de = /rules <description>!n! = Regeln ändern

readme = /readme = Show readme!n!
readme-de = /readme = Liesmich anzeigen!n!

time = /time = Show date/time!n!
time-de = /time = Datum/Uhrzeit anzeigen!n!

announce = /announce = Send announce!n!
announce-de = /announce = Announce senden!n!

sync = /sync = Synchronize messages with propagation node!n!
sync-de = /sync = Nachrichten mit Propagation Node synchronisieren!n!

show_run = /show run = Show current configuration!n!
show_run-de = /show run = Aktuelle Konfiguration anzeigen!n!

show = /show or /list!n!/show or /list <admin/mod/user/guest>!n!
show-de = /show oder /list!n!/show oder /list <admin/mod/user/guest>!n!

add = /add <admin/mod/user/guest> <user_address> <user_name>!n!
add-de = /add <admin/mod/user/guest> <user_address> <user_name>!n!

del = /del or /rm <admin/mod/user/guest> <user_address>!n!/del or /rm <user_address>!n!
del-de = /del oder /rm <admin/mod/user/guest> <user_address>!n!/del oder /rm <user_address>!n!

move = /move <admin/mod/user/guest> <user_address>!n!
move-de = /move <admin/mod/user/guest> <user_address>!n!

rename = /rename <user_address> <new nickname> = Change nickname!n!
rename-de = /rename <user_address> <new nickname> = Ändern des Nickname!n!

invite = /invite <user_address> = Invites user to group!n!
invite-de = /invite <user_address> = Lädt Benutzer zur Gruppe ein!n!

kick = /kick <user_address> = Kicks user out of group!n!
kick-de = /kick <user_address> = Wirft den Benutzer aus der Gruppe!n!

block = /block <user_address> = Block user!n!/ban <user_address> = Block user!n!
block-de = /block <user_address> = Blockiert Benutzer!n!/ban <user_address> = Blockiert Benutzer!n!

unblock = /unblock <user_address> = Unblock user!n!/unban <user_address> = Unblock user!n!
unblock-de = /unblock <user_address> = Blockierung des Benutzers aufheben!n!/unban <user_address> = Blockierung des Benutzers aufheben!n!

allow = /allow <user_address> = Allow user!n!
allow-de = /allow <user_address> = Benutzer erlauben!n!

deny = /deny <user_address> = Deny user!n!
deny-de = /deny <user_address> = Benutzer ablehnen!n!

load = /load or /read = Read the configuration/data!n!
load-de = /load oder /read = Lesen der Konfiguration/Daten!n!

save = /save or /wr = Saves the current configuration/data!n!
save-de = /save oder /wr = Speichert die aktuelle Konfiguration/Daten!n!

reload = /reload = Reload the current configuration/data!n!
reload-de = /reload = Neu laden der aktuelle Konfiguration/Daten!n!

reset = /reset statistic <all/cluster/local/interface/user> = Reset statistic!n!
reset-de = /reset statistic <all/cluster/local/interface/user> = Statisktik zurücksetzenn!n!
'''


#### Default data file ####
DEFAULT_DATA = '''# This is the data file. It is automatically created and saved/overwritten.
# It contains data managed by the software itself.
# If manual adjustments are made here, the program must be shut down first!


#### High availability settings ####
[high_availability]
role = master
last_heartbeat = 0000-00-00 00:00:00


#### Main program settings ####
[main]
enabled_local = True
enabled_cluster = True
auto_add_user = True
auto_add_user_type = user
auto_add_cluster = True
auto_add_router = True
invite_user = True
invite_user_type = user
allow_user = True
allow_user_type = user
deny_user = True
deny_user_type = block_wait
description = 
description-de = 
rules = Please follow the general rules of etiquette which should be taken for granted!!n!Prohibited are:!n!Spam, insults, violence, sex, illegal topics
rules-de = Bitte befolgen Sie die allgemeinen benimm-dich-Regeln welche als selbstverständlich gelten sollten!!n!Verboten sind:!n!Spam, Beleidigungen, Gewalt, Sex, illegale Themen


#### Admin user ####
[admin]

#### Mod/Moderator user ####
[mod]

#### User ####
[user]

#### Guest user ####
[guest]

#### Wait user ####
[wait]

#### Blocked user ####
[block_admin]

[block_mod]

[block_user]

[block_guest]

[block_wait]

#### Cluster (Automatically or manual created) ####
[cluster]

[block_cluster]

#### Router (Automatically or manual created) ####
[router]

[block_router]

#### Pinned messages (Automatically created) ####
[pin]
'''


##############################################################################################################
# Init


if __name__ == "__main__":
    main()