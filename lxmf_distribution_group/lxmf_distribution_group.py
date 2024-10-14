#!/usr/bin/env python3
##############################################################################################################
#
# Copyright (c) 2024 Sebastian Obele  /  obele.eu
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
import random

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
import RNS.vendor.umsgpack as msgpack


##############################################################################################################
# Globals


#### Global Variables - Configuration ####
NAME = "LXMF Distribution Group"
DESCRIPTION = "Server-Side group functions for LXMF based apps"
VERSION = "0.0.1 (2024-05-31)"
COPYRIGHT = "(c) 2024 Sebastian Obele  /  obele.eu"
PATH = os.path.expanduser("~")+"/.config/"+os.path.splitext(os.path.basename(__file__))[0]
PATH_RNS = None


#### Global Variables - System (Not changeable) ####
DATA = None
CONFIG = None
RNS_CONNECTION = None
LXMF_CONNECTION = None

ANNOUNCE_DATA_CONTENT = 0x00
ANNOUNCE_DATA_FIELDS  = 0x01
ANNOUNCE_DATA_TITLE   = 0x02

CONV_P2P                = 0x01
CONV_GROUP              = 0x02
CONV_BROADCAST          = 0x03
CONV_DISTRIBUTION_GROUP = 0x04

MSG_FIELD_EMBEDDED_LXMS    = 0x01
MSG_FIELD_TELEMETRY        = 0x02
MSG_FIELD_TELEMETRY_STREAM = 0x03
MSG_FIELD_ICON             = 0x04
MSG_FIELD_FILE_ATTACHMENTS = 0x05
MSG_FIELD_IMAGE            = 0x06
MSG_FIELD_AUDIO            = 0x07
MSG_FIELD_THREAD           = 0x08
MSG_FIELD_COMMANDS         = 0x09
MSG_FIELD_RESULTS          = 0x0A

MSG_FIELD_ANSWER             = 0xA0
MSG_FIELD_ATTACHMENT         = 0xA1
MSG_FIELD_COMMANDS_EXECUTE   = 0xA2
MSG_FIELD_COMMANDS_RESULT    = 0xA3
MSG_FIELD_CONTACT            = 0xA4
MSG_FIELD_DATA               = 0xA5
MSG_FIELD_DELETE             = 0xA6
MSG_FIELD_EDIT               = 0xA7
MSG_FIELD_GROUP              = 0xA8
MSG_FIELD_HASH               = 0xA9
MSG_FIELD_ICON_MENU          = 0xAA
MSG_FIELD_ICON_SRC           = 0xAB
MSG_FIELD_KEYBOARD           = 0xAC
MSG_FIELD_KEYBOARD_INLINE    = 0xAD
MSG_FIELD_LOCATION           = 0xAE
MSG_FIELD_POLL               = 0xAF
MSG_FIELD_POLL_ANSWER        = 0xB0
MSG_FIELD_REACTION           = 0xB1
MSG_FIELD_RECEIPT            = 0xB2
MSG_FIELD_SCHEDULED          = 0xB3
MSG_FIELD_SILENT             = 0xB4
MSG_FIELD_SRC                = 0xB5
MSG_FIELD_STATE              = 0xB6
MSG_FIELD_STICKER            = 0xB7
MSG_FIELD_TELEMETRY_DB       = 0xB8
MSG_FIELD_TELEMETRY_PEER     = 0xB9
MSG_FIELD_TELEMETRY_COMMANDS = 0xBA
MSG_FIELD_TEMPLATE           = 0xBB
MSG_FIELD_TOPIC              = 0xBC
MSG_FIELD_TYPE               = 0xBD
MSG_FIELD_TYPE_FIELDS        = 0xBE
MSG_FIELD_VOICE              = 0xBF


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
        if self.announce_startup_delay == 0:
            self.announce_startup_delay = random.randint(5, 30)

        self.announce_periodic = announce_periodic
        self.announce_periodic_interval = int(announce_periodic_interval)

        self.sync_startup = sync_startup
        self.sync_startup_delay = int(sync_startup_delay)
        if self.sync_startup_delay == 0:
            self.sync_startup_delay = random.randint(5, 30)
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
        if destination == self.destination:
            return None

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
                log("LXMF - Announced: " + RNS.prettyhexrep(self.destination_hash()) +": " + app_data, LOG_DEBUG)
            else:
                self.destination.announce(app_data, attached_interface=attached_interface)
                log("LMF - Announced: " + RNS.prettyhexrep(self.destination_hash()), LOG_DEBUG)
        elif self.announce_data:
            if isinstance(self.announce_data, str):
                self.destination.announce(self.announce_data.encode("utf-8"), attached_interface=attached_interface)
                log("LXMF - Announced: " + RNS.prettyhexrep(self.destination_hash()) +": " + self.announce_data, LOG_DEBUG)
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
                log("LXMF - Message sync requested from propagation node " + RNS.prettyhexrep(self.message_router.get_outbound_propagation_node()) + " for " + str(self.identity), LOG_DEBUG)
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
            unpacked = msgpack.unpackb(app_data)
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
            app_data_dict = msgpack.unpackb(app_data)
            if isinstance(app_data_dict, dict) and ANNOUNCE_DATA_CONTENT in app_data_dict:
                app_data = app_data_dict[ANNOUNCE_DATA_CONTENT]
                if ANNOUNCE_DATA_FIELDS in app_data_dict and MSG_FIELD_TYPE in app_data_dict[ANNOUNCE_DATA_FIELDS]:
                    denys = config_getarray(CONFIG, "lxmf", "announce_deny_type")
                    if len(denys) > 0:
                        if "*" in denys:
                            return
                        for deny in denys:
                            if app_data_dict[ANNOUNCE_DATA_FIELDS][MSG_FIELD_TYPE] == deny:
                                return
        except:
            pass

        try:
            app_data = app_data.decode("utf-8").strip()
        except:
            return

        log("LXMF - Received an announce from " + RNS.prettyhexrep(destination_hash) + ": " + app_data, LOG_INFO)

        global DATA

        sections = []
        for (key, val) in CONFIG.items("rights"):
            if DATA.has_section(key):
                sections.append(key)

        if DATA["main"].getboolean("auto_add_user_announce"):
            source_hash = RNS.hexrep(destination_hash, False)
            exist = False

            hop_count = RNS.Transport.hops_to(destination_hash)
            hop_min = DATA.getint("main", "auto_add_user_announce_hop_min")
            hop_max = DATA.getint("main", "auto_add_user_announce_hop_max")
            if hop_min > 0 and hop_count < hop_min:
                exist = True
            if hop_max > 0 and hop_count < hop_max:
                exist = True

            for section in DATA.sections():
                for (key, val) in DATA.items(section):
                    if key == source_hash:
                        exist = True
                        break
                if exist:
                    break

            if not exist:
                source_right = DATA["main"]["auto_add_user_type"]
                if DATA.has_section(source_right) and source_right != "main":
                    if CONFIG["main"].getboolean("auto_name_add"):
                        source_name = app_data
                    else:
                        source_name = ""
                    DATA[source_right][source_hash] = source_name
                    fields = fields_generate(src_hash=destination_hash, src_name=source_name, members=True, result_key="join", result_value=True)
                    for section in sections:
                        if "receive_join" in config_get(CONFIG, "rights", section).split(","):
                            for (key, val) in DATA.items(section):
                                if key != source_hash:
                                    LXMF_CONNECTION.send(key, "", "", fields)
                    if CONFIG["main"].getboolean("auto_save_data"):
                        DATA.remove_option("main", "unsaved")
                        if not data_save(PATH + "/data.cfg"):
                            DATA["main"]["unsaved"] = "True"
                    else:
                        DATA["main"]["unsaved"] = "True"
                    LXMF_CONNECTION.send(source_hash, DATA["main"]["welcome"].replace("!n!", "\n"), "", fields_generate(members=True, data=True, cmd=source_right, config=source_right, result_key="join", result_value=True))
                    return
                elif source_right == "":
                    log("LXMF - Source " + RNS.prettyhexrep(message.source_hash) + " not exist (auto add disabled)", LOG_DEBUG)
                    return

        if CONFIG["main"].getboolean("auto_name_def") or CONFIG["main"].getboolean("auto_name_change"):
            source_hash = RNS.hexrep(destination_hash, False)
            for section in DATA.sections():
                for (key, val) in DATA.items(section):
                    if key == source_hash:
                        if (val == "" and CONFIG["main"].getboolean("auto_name_def")) or (val != "" and CONFIG["main"].getboolean("auto_name_change")):
                            value = app_data
                            if value != DATA[section][key]:
                                DATA[section][key] = value

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
    denys = config_getarray(CONFIG, "message", "deny_title")
    if len(denys) > 0:
        if "*" in denys:
            return
        for deny in denys:
            if deny in title:
                return

    content = message.content.decode('utf-8').strip()
    denys = config_getarray(CONFIG, "message", "deny_content")
    if len(denys) > 0:
        if "*" in denys:
            return
        for deny in denys:
            if deny in title:
                return

    if message.fields:
        denys = config_getarray(CONFIG, "message", "deny_fields")
        if len(denys) > 0:
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
                return

    source_rights = []
    for section in DATA.sections():
        for (key, val) in DATA.items(section):
            if key == source_hash:
                if source_name == "":
                    source_name = val
                source_right = section
                source_rights.append(section)


    if source_right == "" and DATA["main"].getboolean("auto_add_user_message"):
        if CONFIG["lxmf"].getboolean("signature_validated_new") and not message.signature_validated:
            log("LXMF - Source " + RNS.prettyhexrep(message.source_hash) + " have no valid signature 'new'", LOG_DEBUG)
            return

        source_right = DATA["main"]["auto_add_user_type"]
        if DATA.has_section(source_right) and source_right != "main":
            if CONFIG["main"].getboolean("auto_name_add"):
                app_data = RNS.Identity.recall_app_data(message.source_hash)
                if app_data != None and len(app_data) > 0:
                    try:
                        app_data_dict = msgpack.unpackb(app_data)
                        if isinstance(app_data_dict, dict) and ANNOUNCE_DATA_CONTENT in app_data_dict:
                            app_data = app_data_dict[ANNOUNCE_DATA_CONTENT]
                    except:
                        pass
                    source_name = app_data.decode('utf-8')
            DATA[source_right][source_hash] = source_name
            fields = fields_generate(src_hash=message.source_hash, src_name=source_name, members=True, result_key="join", result_value=True)
            for section in sections:
                if "receive_join" in config_get(CONFIG, "rights", section).split(","):
                    for (key, val) in DATA.items(section):
                        if key != source_hash:
                            LXMF_CONNECTION.send(key, "", title, fields)
            if CONFIG["main"].getboolean("auto_save_data"):
                DATA.remove_option("main", "unsaved")
                if not data_save(PATH + "/data.cfg"):
                    DATA["main"]["unsaved"] = "True"
            else:
                DATA["main"]["unsaved"] = "True"
            LXMF_CONNECTION.send(source_hash, DATA["main"]["welcome"].replace("!n!", "\n"), title, fields_generate(members=True, data=True, cmd=source_right, config=source_right, result_key="join", result_value=True))
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
        return


    # Commands
    if fields and MSG_FIELD_COMMANDS_EXECUTE in fields:
        cmd = ""
        key, value = list(fields[MSG_FIELD_COMMANDS_EXECUTE][0].items())[0]
        if isinstance(key, str):
            cmd = key
        if isinstance(value, str):
            cmd += " "+value


        # allow
        if cmd.startswith("allow ") and "allow" in source_rights:
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
                            LXMF_CONNECTION.send(value, "", "", fields_generate(members=True, data=True, cmd=user_section, config=user_section, result_key="allow", result_value=True))

                            fields = fields_generate(src_hash=bytes.fromhex(value), src_name=user_name, members=True, result_key="allow", result_value=True)
                            for section in sections:
                                if "receive_allow" in config_get(CONFIG, "rights", section).split(","):
                                    for (key, val) in DATA.items(section):
                                        LXMF_CONNECTION.send(key, "", "", fields)

                            LXMF_CONNECTION.send(source_hash, "", "", fields_generate(src_hash=bytes.fromhex(value), src_name=user_name, members=True, result_key="allow", result_value=True))

                            if CONFIG["main"].getboolean("auto_save_data"):
                                DATA.remove_option("main", "unsaved")
                                if not data_save(PATH + "/data.cfg"):
                                    DATA["main"]["unsaved"] = "True"
                            else:
                                DATA["main"]["unsaved"] = "True"
                        else:
                            LXMF_CONNECTION.send(source_hash, "", "", fields_generate(result_key="allow", result_value=False))
                    else:
                        LXMF_CONNECTION.send(source_hash, "", "", fields_generate(result_key="allow", result_value=False))
                else:
                    LXMF_CONNECTION.send(source_hash, "", "", fields_generate(result_key="allow", result_value=False))
            except:
               LXMF_CONNECTION.send(source_hash, "", "", fields_generate(result_key="allow", result_value=False))


        # announce
        elif cmd == "announce" and "announce" in source_rights:
            LXMF_CONNECTION.send(source_hash, content, "", fields_generate(result_key="announce", result_value=True))
            LXMF_CONNECTION.announce_now()


        # block
        elif cmd.startswith("block ") and "block" in source_rights:
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
                        LXMF_CONNECTION.send(value, "", "", {MSG_FIELD_DATA: None, MSG_FIELD_COMMANDS_RESULT: [{"block": True}]})

                        fields = fields_generate(src_hash=bytes.fromhex(value), src_name=user_name, members=True, result_key="block", result_value=True)
                        for section in sections:
                            if "receive_block" in config_get(CONFIG, "rights", section).split(","):
                                for (key, val) in DATA.items(section):
                                    if key != source_hash and key != value:
                                        LXMF_CONNECTION.send(key, "", "", fields)

                        LXMF_CONNECTION.send(source_hash, "", "", fields_generate(src_hash=bytes.fromhex(value), src_name=user_name, members=True, result_key="block", result_value=True))

                        if CONFIG["main"].getboolean("auto_save_data"):
                            DATA.remove_option("main", "unsaved")
                            if not data_save(PATH + "/data.cfg"):
                                DATA["main"]["unsaved"] = "True"
                        else:
                            DATA["main"]["unsaved"] = "True"
                    else:
                        LXMF_CONNECTION.send(source_hash, "", "", fields_generate(result_key="block", result_value=False))
                else:
                    LXMF_CONNECTION.send(source_hash, "", "", fields_generate(result_key="block", result_value=False))
            except:
               LXMF_CONNECTION.send(source_hash, "", "", fields_generate(result_key="block", result_value=False))


        # deny
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
                            LXMF_CONNECTION.send(value, "", "", fields_generate(result_key="deny", result_value=True))

                            fields = fields_generate(src_hash=bytes.fromhex(value), src_name=user_name, members=True, result_key="deny", result_value=True)
                            for section in sections:
                                if "receive_deny" in config_get(CONFIG, "rights", section).split(","):
                                    for (key, val) in DATA.items(section):
                                        LXMF_CONNECTION.send(key, "", "", fields)

                            LXMF_CONNECTION.send(source_hash, "", "", fields_generate(src_hash=bytes.fromhex(value), src_name=user_name, members=True, result_key="deny", result_value=True))

                            if CONFIG["main"].getboolean("auto_save_data"):
                                DATA.remove_option("main", "unsaved")
                                if not data_save(PATH + "/data.cfg"):
                                    DATA["main"]["unsaved"] = "True"
                            else:
                                DATA["main"]["unsaved"] = "True"
                        else:
                            LXMF_CONNECTION.send(source_hash, "", "", fields_generate(result_key="deny", result_value=False))
                    else:
                        LXMF_CONNECTION.send(source_hash, "", "", fields_generate(result_key="deny", result_value=False))
                else:
                    LXMF_CONNECTION.send(source_hash, "", "", fields_generate(result_key="deny", result_value=False))
            except:
               LXMF_CONNECTION.send(source_hash, "", "", fields_generate(result_key="deny", result_value=False))


        # invite
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

                            LXMF_CONNECTION.send(value, DATA["main"]["welcome"].replace("!n!", "\n"), "", fields_generate(members=True, data=True, cmd=key, config=key, result_key="invite", result_value=True))

                            fields = fields_generate(src_hash=bytes.fromhex(value), src_name=user_name, members=True, result_key="invite", result_value=True)
                            for section in sections:
                                if "receive_invite" in config_get(CONFIG, "rights", section).split(","):
                                    for (key, val) in DATA.items(section):
                                        if key != source_hash and key != value:
                                            LXMF_CONNECTION.send(key, "", "", fields)

                            LXMF_CONNECTION.send(source_hash, "", "", fields_generate(src_hash=bytes.fromhex(value), src_name=user_name, members=True, result_key="invite", result_value=True))

                            if CONFIG["main"].getboolean("auto_save_data"):
                                DATA.remove_option("main", "unsaved")
                                if not data_save(PATH + "/data.cfg"):
                                    DATA["main"]["unsaved"] = "True"
                            else:
                                DATA["main"]["unsaved"] = "True"
                        else:
                            LXMF_CONNECTION.send(source_hash, "", "", fields_generate(result_key="invite", result_value=False))
                    else:
                        LXMF_CONNECTION.send(source_hash, "", "", fields_generate(result_key="invite", result_value=False))
                except:
                    LXMF_CONNECTION.send(source_hash, "", "", fields_generate(result_key="invite", result_value=False))
            else:
                LXMF_CONNECTION.send(source_hash, "", "", fields_generate(result_key="invite", result_value=False))


        # join
        elif cmd == "join" and "join" in source_rights:
            try:
                LXMF_CONNECTION.send(source_hash, DATA["main"]["welcome"].replace("!n!", "\n"), "", fields_generate(members=True, data=True, cmd=source_right, config=source_right, result_key="join", result_value=True))
            except:
                LXMF_CONNECTION.send(source_hash, "", "", fields_generate(result_key="join", result_value=False))


        # kick
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
                        LXMF_CONNECTION.send(value, "", "", {MSG_FIELD_DATA: None, MSG_FIELD_COMMANDS_RESULT: [{"kick": True}]})

                        fields = fields_generate(src_hash=bytes.fromhex(value), src_name=user_name, members=True, result_key="kick", result_value=True)
                        for section in sections:
                            if "receive_kick" in config_get(CONFIG, "rights", section).split(","):
                                for (key, val) in DATA.items(section):
                                    if key != source_hash and key != value:
                                        LXMF_CONNECTION.send(key, "", "", fields)

                        LXMF_CONNECTION.send(source_hash, "", "", fields_generate(src_hash=bytes.fromhex(value), src_name=user_name, members=True, result_key="kick", result_value=True))

                        if CONFIG["main"].getboolean("auto_save_data"):
                            DATA.remove_option("main", "unsaved")
                            if not data_save(PATH + "/data.cfg"):
                                DATA["main"]["unsaved"] = "True"
                        else:
                            DATA["main"]["unsaved"] = "True"
                    else:
                        LXMF_CONNECTION.send(source_hash, "", "", fields_generate(result_key="kick", result_value=False))
                else:
                    LXMF_CONNECTION.send(source_hash, "", "", fields_generate(result_key="kick", result_value=False))
            except:
               LXMF_CONNECTION.send(source_hash, "", "", fields_generate(result_key="kick", result_value=False))


        # leave
        elif cmd == "leave" and "leave" in source_rights:
            try:
                for section in sections:
                    for (key, val) in DATA.items(section):
                        if key == source_hash:
                            DATA.remove_option(section, key)

                fields = fields_generate(src_hash=message.source_hash, src_name=source_name, members=True, result_key="leave", result_value=True)
                for section in sections:
                    if "receive_leave" in config_get(CONFIG, "rights", section).split(","):
                        for (key, val) in DATA.items(section):
                            LXMF_CONNECTION.send(key, "", "", fields)

                LXMF_CONNECTION.send(source_hash, "", "", {MSG_FIELD_DATA: None, MSG_FIELD_COMMANDS_RESULT: [{"leave": True}]})

                if CONFIG["main"].getboolean("auto_save_data"):
                    DATA.remove_option("main", "unsaved")
                    if not data_save(PATH + "/data.cfg"):
                        DATA["main"]["unsaved"] = "True"
                else:
                    DATA["main"]["unsaved"] = "True"
            except:
                LXMF_CONNECTION.send(source_hash, "", "", {MSG_FIELD_DATA: None, MSG_FIELD_COMMANDS_RESULT: [{"leave": False}]})


        # right_admin
        elif cmd.startswith("right_admin ") and "right_admin" in source_rights:
            try:
                cmd, value = cmd.split(" ", 1)
                key = "admin"
                if DATA.has_section(key) and key != "main":
                    value = LXMF_CONNECTION.destination_correct(value)
                    if value != "":
                        for section in DATA.sections():
                            if section != "main":
                                for (key_old, val_old) in DATA.items(section):
                                    if key_old == value:
                                        DATA.remove_option(section, key_old)
                                        DATA[key][value] = val_old

                                        LXMF_CONNECTION.send(value, "", "", fields_generate(members=True, data=True, cmd=key, config=key, result_key="right_admin", result_value=True))

                                        fields = fields_generate(src_hash=bytes.fromhex(value), src_name=val_old, members=True, result_key="right_admin", result_value=True)
                                        for section in sections:
                                            if "receive_right" in config_get(CONFIG, "rights", section).split(","):
                                                for (key, val) in DATA.items(section):
                                                    if key != source_hash and key != value:
                                                        LXMF_CONNECTION.send(key, "", "", fields)

                                        LXMF_CONNECTION.send(source_hash, "", "", fields_generate(src_hash=bytes.fromhex(value), src_name=val_old, members=True, result_key="right_admin", result_value=True))

                                        if CONFIG["main"].getboolean("auto_save_data"):
                                            DATA.remove_option("main", "unsaved")
                                            if not data_save(PATH + "/data.cfg"):
                                                DATA["main"]["unsaved"] = "True"
                                        else:
                                            DATA["main"]["unsaved"] = "True"
                    else:
                        LXMF_CONNECTION.send(source_hash, "", "", fields_generate(result_key="right_admin", result_value=False))
                else:
                    LXMF_CONNECTION.send(source_hash, "", "", fields_generate(result_key="right_admin", result_value=False))
            except:
                LXMF_CONNECTION.send(source_hash, "", "", fields_generate(result_key="right_admin", result_value=False))


        # right_guest
        elif cmd.startswith("right_guest ") and "right_guest" in source_rights:
            try:
                cmd, value = cmd.split(" ", 1)
                key = "guest"
                if DATA.has_section(key) and key != "main":
                    value = LXMF_CONNECTION.destination_correct(value)
                    if value != "":
                        for section in DATA.sections():
                            if section != "main":
                                for (key_old, val_old) in DATA.items(section):
                                    if key_old == value:
                                        DATA.remove_option(section, key_old)
                                        DATA[key][value] = val_old

                                        LXMF_CONNECTION.send(value, "", "", fields_generate(members=True, data=True, cmd=key, config=key, result_key="right_guest", result_value=True))

                                        fields = fields_generate(src_hash=bytes.fromhex(value), src_name=val_old, members=True, result_key="right_guest", result_value=True)
                                        for section in sections:
                                            if "receive_right" in config_get(CONFIG, "rights", section).split(","):
                                                for (key, val) in DATA.items(section):
                                                    if key != source_hash and key != value:
                                                        LXMF_CONNECTION.send(key, "", "", fields)

                                        LXMF_CONNECTION.send(source_hash, "", "", fields_generate(src_hash=bytes.fromhex(value), src_name=val_old, members=True, result_key="right_guest", result_value=True))

                                        if CONFIG["main"].getboolean("auto_save_data"):
                                            DATA.remove_option("main", "unsaved")
                                            if not data_save(PATH + "/data.cfg"):
                                                DATA["main"]["unsaved"] = "True"
                                        else:
                                            DATA["main"]["unsaved"] = "True"
                    else:
                        LXMF_CONNECTION.send(source_hash, "", "", fields_generate(result_key="right_guest", result_value=False))
                else:
                    LXMF_CONNECTION.send(source_hash, "", "", fields_generate(result_key="right_guest", result_value=False))
            except:
                LXMF_CONNECTION.send(source_hash, "", "", fields_generate(result_key="right_guest", result_value=False))


        # right_mod
        elif cmd.startswith("right_mod ") and "right_mod" in source_rights:
            try:
                cmd, value = cmd.split(" ", 1)
                key = "mod"
                if DATA.has_section(key) and key != "main":
                    value = LXMF_CONNECTION.destination_correct(value)
                    if value != "":
                        for section in DATA.sections():
                            if section != "main":
                                for (key_old, val_old) in DATA.items(section):
                                    if key_old == value:
                                        DATA.remove_option(section, key_old)
                                        DATA[key][value] = val_old

                                        LXMF_CONNECTION.send(value, "", "", fields_generate(members=True, data=True, cmd=key, config=key, result_key="right_mod", result_value=True))

                                        fields = fields_generate(src_hash=bytes.fromhex(value), src_name=val_old, members=True, result_key="right_mod", result_value=True)
                                        for section in sections:
                                            if "receive_right" in config_get(CONFIG, "rights", section).split(","):
                                                for (key, val) in DATA.items(section):
                                                    if key != source_hash and key != value:
                                                        LXMF_CONNECTION.send(key, "", "", fields)

                                        LXMF_CONNECTION.send(source_hash, "", "", fields_generate(src_hash=bytes.fromhex(value), src_name=val_old, members=True, result_key="right_mod", result_value=True))

                                        if CONFIG["main"].getboolean("auto_save_data"):
                                            DATA.remove_option("main", "unsaved")
                                            if not data_save(PATH + "/data.cfg"):
                                                DATA["main"]["unsaved"] = "True"
                                        else:
                                            DATA["main"]["unsaved"] = "True"
                    else:
                        LXMF_CONNECTION.send(source_hash, "", "", fields_generate(result_key="right_mod", result_value=False))
                else:
                    LXMF_CONNECTION.send(source_hash, "", "", fields_generate(result_key="right_mod", result_value=False))
            except:
                LXMF_CONNECTION.send(source_hash, "", "", fields_generate(result_key="right_mod", result_value=False))


        # right_user
        elif cmd.startswith("right_user ") and "right_user" in source_rights:
            try:
                cmd, value = cmd.split(" ", 1)
                key = "user"
                if DATA.has_section(key) and key != "main":
                    value = LXMF_CONNECTION.destination_correct(value)
                    if value != "":
                        for section in DATA.sections():
                            if section != "main":
                                for (key_old, val_old) in DATA.items(section):
                                    if key_old == value:
                                        DATA.remove_option(section, key_old)
                                        DATA[key][value] = val_old

                                        LXMF_CONNECTION.send(value, "", "", fields_generate(members=True, data=True, cmd=key, config=key, result_key="right_user", result_value=True))

                                        fields = fields_generate(src_hash=bytes.fromhex(value), src_name=val_old, members=True, result_key="right_user", result_value=True)
                                        for section in sections:
                                            if "receive_right" in config_get(CONFIG, "rights", section).split(","):
                                                for (key, val) in DATA.items(section):
                                                    if key != source_hash and key != value:
                                                        LXMF_CONNECTION.send(key, "", "", fields)

                                        LXMF_CONNECTION.send(source_hash, "", "", fields_generate(src_hash=bytes.fromhex(value), src_name=val_old, members=True, result_key="right_user", result_value=True))

                                        if CONFIG["main"].getboolean("auto_save_data"):
                                            DATA.remove_option("main", "unsaved")
                                            if not data_save(PATH + "/data.cfg"):
                                                DATA["main"]["unsaved"] = "True"
                                        else:
                                            DATA["main"]["unsaved"] = "True"
                    else:
                        LXMF_CONNECTION.send(source_hash, "", "", fields_generate(result_key="right_user", result_value=False))
                else:
                    LXMF_CONNECTION.send(source_hash, "", "", fields_generate(result_key="right_user", result_value=False))
            except:
                LXMF_CONNECTION.send(source_hash, "", "", fields_generate(result_key="right_user", result_value=False))


        # sync
        elif cmd == "sync" and "sync" in source_rights:
            LXMF_CONNECTION.send(source_hash, content, "", fields_generate(result_key="sync", result_value=True))
            LXMF_CONNECTION.sync_now()


        # unblock
        elif cmd.startswith("unblock ") and "unblock" in source_rights:
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
                        LXMF_CONNECTION.send(value, "", "", fields_generate(members=True, data=True, cmd=user_section, config=user_section, result_key="unblock", result_value=True))

                        fields = fields_generate(src_hash=bytes.fromhex(value), src_name=user_name, members=True, result_key="unblock", result_value=True)
                        for section in sections:
                            if "receive_unblock" in config_get(CONFIG, "rights", section).split(","):
                                for (key, val) in DATA.items(section):
                                    if key != source_hash and key != value:
                                        LXMF_CONNECTION.send(key, "", "", fields)

                        LXMF_CONNECTION.send(source_hash, "", "", fields_generate(src_hash=bytes.fromhex(value), src_name=user_name, members=True, result_key="unblock", result_value=True))

                        if CONFIG["main"].getboolean("auto_save_data"):
                            DATA.remove_option("main", "unsaved")
                            if not data_save(PATH + "/data.cfg"):
                                DATA["main"]["unsaved"] = "True"
                        else:
                            DATA["main"]["unsaved"] = "True"
                    else:
                        LXMF_CONNECTION.send(source_hash, "", "", fields_generate(result_key="unblock", result_value=False))
                else:
                    LXMF_CONNECTION.send(source_hash, "", "", fields_generate(result_key="unblock", result_value=False))
            except:
               LXMF_CONNECTION.send(source_hash, "", "", fields_generate(result_key="unblock", result_value=False))


        # update
        elif cmd == "update" and "update" in source_rights:
            try:
                LXMF_CONNECTION.send(source_hash, "", "", fields_generate(members=True, data=True, cmd=source_right, config=source_right, result_key="update", result_value=True))
            except:
                LXMF_CONNECTION.send(source_hash, "", "", fields_generate(result_key="update", result_value=False))


        # update_all
        elif cmd == "update_all" and "update_all" in source_rights:
            try:
                for section in sections:
                    for (key, val) in DATA.items(section):
                        LXMF_CONNECTION.send(key, "", "", fields_generate(members=True, data=True, cmd=section, config=section, result_key="update", result_value=True))
            except:
                LXMF_CONNECTION.send(source_hash, "", "", fields_generate(result_key="update", result_value=False))


        # unsaved
        if DATA["main"].getboolean("unsaved") and "unsaved" in source_rights:
            if CONFIG["main"].getboolean("auto_save_data"):
                DATA.remove_option("main", "unsaved")
                if not data_save(PATH + "/data.cfg"):
                    DATA["main"]["unsaved"] = "True"


        return


    # Message
    if DATA["main"].getboolean("enabled"):
        if "send" in source_rights:
            if CONFIG["message"].getboolean("fields"):
                if message.fields:
                    fields = fields_remove(message.fields, "fields_remove_anonymous" if "anonymous" in source_rights else "fields_remove")
                else:
                    fields = {}
            else:
                fields = {}

            if CONFIG["main"].getboolean("fields_message"):
                if CONFIG["lxmf"]["destination_type_conv"] != "":
                    fields[MSG_FIELD_TYPE] = CONFIG["lxmf"].getint("destination_type_conv")
                if not MSG_FIELD_HASH in fields:
                    fields[MSG_FIELD_HASH] = message.hash
                if not "anonymous" in source_rights and MSG_FIELD_SRC not in fields:
                    fields[MSG_FIELD_SRC] = [message.source_hash, source_name]

            if config_get(CONFIG, "message", "timestamp", "") == "client":
                timestamp = message.timestamp
            else:
                timestamp = time.time()

            for section in sections:
                if "receive" in config_get(CONFIG, "rights", section).split(","):
                    for (key, val) in DATA.items(section):
                        if key != source_hash:
                            LXMF_CONNECTION.send(key, content, title, fields, timestamp)
            return
        else:
            log("LXMF - Source " + RNS.prettyhexrep(message.source_hash) + " 'send' not allowed", LOG_DEBUG)

    return


#### Fields #####
def fields_remove(fields=None, key="fields_remove"):
    search = config_getarray(CONFIG, "message", key)

    delete = []
    for field in fields:
        if field in search:
            delete.append(field)

    for field in delete:
        del fields[field]

    return fields


#### Fields #####
def fields_generate(fields=None, src_hash=None, src_name=None, members=False, data=False, cmd=None, config=None, result_key=None, result_value=True):
    if not CONFIG["main"].getboolean("fields_message"):
        return fields

    if not fields:
        fields = {}

    if CONFIG["lxmf"]["destination_type_conv"] != "":
        fields[MSG_FIELD_TYPE] = CONFIG["lxmf"].getint("destination_type_conv")

    if src_hash:
        fields[MSG_FIELD_SRC] = [src_hash, src_name]

    if members or data or cmd or config:
        fields[MSG_FIELD_DATA] = {}

    if members:
        fields[MSG_FIELD_DATA]["m"] = {}
        for (key, val) in CONFIG.items("rights"):
            if DATA.has_section(key):
                fields[MSG_FIELD_DATA]["m"][key] = {}
                for (section_key, section_val) in DATA.items(key):
                    try:
                        h = bytes.fromhex(LXMF_CONNECTION.destination_correct(section_key))
                        fields[MSG_FIELD_DATA]["m"][key][h] = section_val
                    except:
                       pass

    if data:
        fields[MSG_FIELD_DATA]["d"] = config_get(DATA, "main", "description", "").replace("!n!", "\n")

    if cmd:
        fields[MSG_FIELD_DATA]["cmd"] = []
        if CONFIG.has_option("cmd", cmd):
            keys = config_get(CONFIG, "cmd", cmd).split(",")
            for key in keys:
                fields[MSG_FIELD_DATA]["cmd"].append(key)
        fields[MSG_FIELD_DATA]["cmd_menu"] = []
        if CONFIG.has_option("cmd_menu", cmd):
            keys = config_get(CONFIG, "cmd_menu", cmd).split(",")
            for key in keys:
                fields[MSG_FIELD_DATA]["cmd_menu"].append(key)
        fields[MSG_FIELD_DATA]["cmd_src"] = []
        if CONFIG.has_option("cmd_src", cmd):
            keys = config_get(CONFIG, "cmd_src", cmd).split(",")
            for key in keys:
                fields[MSG_FIELD_DATA]["cmd_src"].append(key)

    if config:
        fields[MSG_FIELD_DATA]["config"] = {}
        if CONFIG.has_option("config", config):
            keys = config_get(CONFIG, "config", config).split(",")
            for key in keys:
                if key != "":
                    key, value = key.split("=", 1)
                    fields[MSG_FIELD_DATA]["config"][key] = val_to_val(value)

    if cmd or config:
        if DATA.has_section("topics"):
            fields[MSG_FIELD_DATA]["topics"] = {}
            for (key, val) in DATA.items("topics"):
                try:
                    fields[MSG_FIELD_DATA]["topics"][int(key)] = val
                except:
                    pass

    if result_key:
        fields[MSG_FIELD_COMMANDS_RESULT] = [{result_key: result_value}]

    return fields


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


def config_getarray(config, section, key, default=[], lng_key=""):
    if not config or section == "" or key == "": return default
    if not config.has_section(section): return default
    value = ""
    if config.has_option(section, key+lng_key):
        value = config[section][key+lng_key]
    elif config.has_option(section, key):
        value = config[section][key]
    if value != "":
        values_return = []
        values = value.split(",")
        for value in values:
            values_return.append(val_to_val(value.strip()))
        return values_return
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
    elif val.startswith("0x") or val.startswith("0X"):
        try:
            val_int = int(val, 16)
            return val_int
        except:
            pass
    return val


##############################################################################################################
# CMDs


def cmd_user(cmd, file, right="admin", sections=["admin", "mod", "user"]):
    global DATA

    if not data_read(file):
        print("Error: No data/users exists")
        panic()

    cmd = cmd.strip()
    cmd = cmd.split()

    if len(cmd) < 1:
        print("Error: Command format wrong")
        panic()

    if cmd[0] == "list" and len(cmd) == 1:
        print("User/Address\tRight\tName")
        for section in sections:
            if DATA.has_section(section):
                for (key, val) in DATA.items(section):
                    print(key+"\t"+section+"\t"+val)

    elif cmd[0] == "get" and len(cmd) == 2:
        print("User/Address\tRight\tName")
        for section in sections:
            if DATA.has_section(section) and DATA.has_option(section, cmd[1]):
                print(cmd[1]+"\t"+section+"\t"+DATA[section][cmd[1]])
                break

    elif cmd[0] == "add" and len(cmd) == 2:
        for section in sections:
            if DATA.has_option(section, cmd[1]):
                DATA.remove_option(section, cmd[1])
        if DATA.has_section(right):
            DATA[right][cmd[1]] = ""
        else:
            print("Error: Right not exist")
            panic()
        if not data_save(file):
            print("Error: Saving data/users")
            panic()

    elif cmd[0] == "add" and len(cmd) == 3:
        for section in sections:
            if DATA.has_option(section, cmd[1]):
                DATA.remove_option(section, cmd[1])
        right = cmd[2]
        if DATA.has_section(right):
            DATA[right][cmd[1]] = ""
        else:
            print("Error: Right not exist")
            panic()
        if not data_save(file):
            print("Error: Saving data/users")
            panic()

    elif cmd[0] == "del" and len(cmd) == 2:
        for section in sections:
            if DATA.has_option(section, cmd[1]):
                DATA.remove_option(section, cmd[1])
        if not data_save(file):
            print("Error: Saving data/users")
            panic()

    elif cmd[0] == "set" and len(cmd) == 3:
        for section in sections:
            if DATA.has_option(section, cmd[1]):
                DATA.remove_option(section, cmd[1])
        right = cmd[2]
        if DATA.has_section(right):
            DATA[right][cmd[1]] = ""
        else:
            print("Error: Right not exist")
            panic()
        if not data_save(file):
            print("Error: Saving data/users")
            panic()

    elif cmd[0] == "check" and len(cmd) == 3:
        if DATA.has_section(cmd[2]) and DATA.has_option(cmd[2], cmd[1]):
            print("1")
        else:
            print("0")

    else:
        print("Error: Wrong/Unknown command")
        panic()


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
    global RNS_CONNECTION
    global LXMF_CONNECTION

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


    if CONFIG.has_section("rights"):
        if CONFIG.has_section("cmd"):
            for (key, val) in CONFIG.items("cmd"):
                if val != "" and CONFIG.has_option("rights", key):
                    CONFIG["rights"][key] += ","+val
        if CONFIG.has_section("cmd_menu"):
            for (key, val) in CONFIG.items("cmd_menu"):
                if val != "" and CONFIG.has_option("rights", key):
                    CONFIG["rights"][key] += ","+val
        if CONFIG.has_section("cmd_src"):
            for (key, val) in CONFIG.items("cmd_src"):
                if val != "" and CONFIG.has_option("rights", key):
                    CONFIG["rights"][key] += ","+val

    RNS_CONNECTION = RNS.Reticulum(configdir=PATH_RNS, loglevel=rns_loglevel)

    log("...............................................................................", LOG_INFO)
    log("        Name: " + CONFIG["main"]["name"], LOG_INFO)
    log("Program File: " + __file__, LOG_INFO)
    log(" Config File: " + PATH + "/config", LOG_INFO)
    log("   Data File: " + PATH + "/data.cfg", LOG_INFO)
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
    if CONFIG["main"].getboolean("fields_announce"):
        fields = {}
        if CONFIG["lxmf"]["destination_type_conv"] != "":
            try:
               fields[MSG_FIELD_TYPE] = CONFIG["lxmf"].getint("destination_type_conv")
            except:
                pass
        if CONFIG["telemetry"].getboolean("location_enabled"):
            try:
               fields[MSG_FIELD_LOCATION] = [CONFIG["telemetry"].getfloat("location_lat"), CONFIG["telemetry"].getfloat("location_lon")]
            except:
                pass
        if CONFIG["telemetry"].getboolean("state_enabled"):
            try:
               fields[MSG_FIELD_STATE] = [CONFIG["telemetry"].getint("state_data"), int(time.time())]
            except:
                pass
        if len(fields) > 0:
            announce_data = {ANNOUNCE_DATA_CONTENT: CONFIG["lxmf"]["display_name"].encode("utf-8"), ANNOUNCE_DATA_TITLE: None, ANNOUNCE_DATA_FIELDS: fields}
            log("LXMF - Configured announce data: "+str(announce_data), LOG_DEBUG)
            announce_data = msgpack.packb(announce_data)
    elif CONFIG["lxmf"]["destination_type_conv"] != "":
        display_name += chr(CONFIG["lxmf"].getint("destination_type_conv"))

    LXMF_CONNECTION = lxmf_connection(
        storage_path=path,
        identity_file="identity",
        identity=None,
        destination_name=CONFIG["lxmf"]["destination_name"],
        destination_type=CONFIG["lxmf"]["destination_type"],
        display_name=display_name,
        announce_data=announce_data,
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

    log("LXMF - Connected", LOG_DEBUG)

    log("...............................................................................", LOG_FORCE)
    log("LXMF - Address: " + RNS.prettyhexrep(LXMF_CONNECTION.destination_hash()), LOG_FORCE)
    log("...............................................................................", LOG_FORCE)

    if CONFIG["main"].getboolean("periodic_save_data"):
        data_save_periodic(True)

    while True:
        time.sleep(1)


#### Start ####
def main():
    try:
        global PATH

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

        parser.add_argument("--cmd_user", action="store", type=str, default=None, help="Manage users")

        params = parser.parse_args()

        if params.path is not None:
            PATH = params.path
            if PATH.endswith("/"):
                PATH = PATH[:-1]

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

        if params.cmd_user:
            cmd_user(cmd=params.cmd_user, file=PATH+"/data.cfg")
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


[lxmf]
display_name = Distribution Group
propagation_node_auto = True
try_propagation_on_fail = Yes


[telemetry]
location_enabled = False
location_lat = 0
location_lon = 0

state_enabled = False
state_data = 0
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

# Auto save changes.
# If there are changes in the data, they can be saved directly in the files.
# Attention: This can lead to very high write cycles.
# If you want to prevent frequent writing, please set this to 'False' and use the peridodic save function.
auto_save_data = True

# Periodic actions - Save changes periodically.
periodic_save_data = True
periodic_save_data_interval = 30 #Minutes

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

# Reject auto add user for announcements of the following type.
announce_deny_type = 0x04,0x06

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


#### Telemetry settings ####
[telemetry]
location_enabled = False
location_lat = 0
location_lon = 0

state_enabled = False
state_data = 0


#### Message settings ####
[message]

## Each message received (message and command) ##

# Deny message if the title/content/fields contains the following content.
# Comma-separated list with text or field keys.
# *=any
deny_title = 
deny_content = 
deny_fields = 

# Define which message timestamp should be used.
timestamp = client #client/server

# Use title/fields.
title = Yes
fields = Yes

# Comma-separated list with fields which will be removed.
fields_remove = 
fields_remove_anonymous = "


#### User rights assignment ####

# Define the individual rights for the different user types.
# Delimiter for different rights: ,
[rights]
admin = receive,send,receive_join,receive_leave,receive_invite,receive_kick,receive_block,receive_unblock,join
mod = receive,send,receive_join,receive_leave,receive_invite,receive_kick,receive_block,receive_unblock,join
user = receive,send,receive_join,receive_leave,receive_invite,receive_kick,receive_block,receive_unblock,join
guest = receive,join
wait = join


#### User cmd assignment ####

# Define the individual cmds for the different user types.
# Delimiter for different cmds: ,
[cmd]
admin = update,update_all,leave,announce,sync
mod = update,update_all,leave
user = leave
guest = leave
wait = leave

[cmd_menu]
admin = invite
mod = invite
user = invite
guest = 
wait = 

[cmd_src]
admin = kick,block,unblock,right_admin,right_mod,right_user,right_guest
mod = kick,block,unblock,right_user,right_guest
user = 
guest = 
wait = 


#### User config assignment ####
# Define the individual configs for the different user types.
# Delimiter for different configs: ,
[config]
admin = #file_tx_enabled=True,audio_tx_enabled=True
mod = 
user = 
guest = 
wait = 


#### User rights/cmds options ####

# The following rights/cmds can be assigned:

# anonymous = Hide source identity.

# receive = Receive messages.
# send = Send messages.

# receive_allow = Receive an info message when a user has been allowed.
# receive_block = Receive an info message when a user is blocked.
# receive_deny = Receive an info message when a user has been denied.
# receive_invite = Receive an info message when a user is invited.
# receive_join = Receive an info message when a new user joins.
# receive_kick = Receive an info message when a user is kicked.
# receive_leave = Receive an info message when a user leaves.
# receive_right = Receive an info message when a user right is changed.
# receive_unblock = Receive an info message when a user is unblocked.

# allow = Command: allow
# announce = Command: announce
# block = Command: block
# deny = Command: deny
# invite = Command: invite
# join = Command: join
# kick = Command: kick
# leave = Command: leave
# right_admin = Command: right_admin
# right_guest = Command: right_guest
# right_mod = Command: right_mod
# right_user = Command: right_user
# sync = Command: sync
# unblock = Command: unblock
# update = Command: update
# update_all = Command: update_all
'''


#### Default data file ####
DEFAULT_DATA = '''# This is the data file. It is automatically created and saved/overwritten.
# It contains data managed by the software itself.
# If manual adjustments are made here, the program must be shut down first!


#### Main program settings ####
[main]
enabled = True
auto_add_user_announce = False
auto_add_user_announce_hop_min = 0
auto_add_user_announce_hop_max = 0
auto_add_user_message = True
auto_add_user_type = user
invite_user = True
invite_user_type = user
allow_user = True
allow_user_type = user
deny_user = True
deny_user_type = block_wait
description = # Group description
welcome = # Welcome message


#### Topics ####
[topics]


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
'''


##############################################################################################################
# Init


if __name__ == "__main__":
    main()