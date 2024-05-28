#!/usr/bin/env python3
##############################################################################################################
#
# Copyright (c) 2023 Sebastian Obele  /  obele.eu
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

#### JSON ####
import json
import pickle

#### String ####
import string

#### Regex ####
import re

#### Process ####
import signal
import threading

#### Reticulum, LXMF ####
# Install: pip3 install rns lxmf
# Source: https://markqvist.github.io
import RNS
import LXMF
import RNS.vendor.umsgpack as umsgpack

#### Matrix ####
# Install: apt-get install libolm-dev
# Install: pip3 install matrix-nio[e2e]
# Source: https://github.com/poljar/matrix-nio
import asyncio
from nio import AsyncClient, LoginResponse, UploadResponse, SyncResponse, MatrixRoom, RoomMessage, RoomMessageText


##############################################################################################################
# Globals


#### Global Variables - Configuration ####
NAME = "LXMF Bridge Matrix"
DESCRIPTION = ""
VERSION = "0.0.1 (2023-05-05)"
COPYRIGHT = "(c) 2023 Sebastian Obele  /  obele.eu"
PATH = os.path.expanduser("~")+"/.config/"+os.path.splitext(os.path.basename(__file__))[0]
PATH_RNS = None

# Number of message ids which will be saved (older will be deleted).
DATA_COUNT_SAVE = 10000 #0=No limit


#### Global Variables - System (Not changeable) ####
CONFIG = None
DATA = {}
ROUTING_TABLE = {}
RNS_CONNECTION = None
LXMF_CONNECTION = None
MATRIX_CONNECTION = None

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
# Matrix Class


class matrix_connection:
    message_received_callback = None
    message_send_callback = None


    def __init__(self, storage_path, address, username, password):
        self.storage_path = storage_path

        self.address = address
        self.username = username
        self.password = password

        if not self.storage_path:
            log("Matrix - No storage_path parameter", LOG_ERROR)
            return

        if not os.path.isdir(self.storage_path):
            os.makedirs(self.storage_path)
            log("Matrix - Storage path was created", LOG_NOTICE)
        log("Matrix - Storage path: " + self.storage_path, LOG_INFO)

        self.sync_path = self.storage_path + "/matrix_sync"

        self.client = None


    def loop_forever(self):
        self.thread = asyncio.get_event_loop()
        self.thread.run_until_complete(self.main())


    def register_message_received_callback(self, handler_function):
        self.message_received_callback = handler_function


    def register_message_send_callback(self, handler_function):
        self.message_send_callback = handler_function


    async def message_callback(self, room: MatrixRoom, event: RoomMessage) -> None:
        if event.sender == self.username:
            return

        self.log_message(source_address=event.sender, source_name= room.user_name(event.sender), destination_address=room.room_id, destination_name=room.display_name, content=event.source.get("content"), message_tag="Matrix - Message received")

        if self.message_received_callback is not None:
            log("Matrix - Call to registered message received callback", LOG_DEBUG)
            self.message_received_callback(room, event)
        else:
            log("Matrix - No message received callback registered", LOG_DEBUG)


    async def sync_cb(self, response):
        log("Matrix - Synced token: " + response.next_batch, LOG_DEBUG)
        try:
            with open(self.sync_path, "w") as fh:
                fh.write(response.next_batch)
        except:
            pass


    def send(self, room_id, content, hash):
        asyncio.run_coroutine_threadsafe(self.send_message(room_id, content, hash), self.thread)


    async def send_message(self, room_id, content, hash):
        global DATA

        self.log_message(source_address=self.address, destination_address=room_id, content=content, message_tag="Matrix - Message send")

        resp = await self.client.room_send(
            room_id=room_id,
            message_type="m.room.message",
            content=content,
        )

        if self.message_send_callback is not None:
            self.message_send_callback(resp.event_id, hash)


    def send_file(self, room_id, name, size, data):
        # TODO
        asyncio.run_coroutine_threadsafe(self.send_message_file(room_id, name, size, data), self.thread)


    async def send_message_file(self, room_id, name, size, data):
        # TODO
        print("#1")
        self.log_message(source_address=self.address, destination_address=room_id, content=name+" ("+str(size)+")", message_tag="Matrix - File send")

        mime_type = "image/jpe"

        print("#2")
        resp, maybe_keys = await self.client.upload(
            data,
            content_type=mime_type,
            filename=name,
            filesize=size)

        print("#3")
        if isinstance(resp, UploadResponse):
            log("Matrix - Upload ok: "+str(resp), LOG_DEBUG)
        else:
            log("Matrix - Upload error: "+str(resp), LOG_ERROR)

        content = {
            "body": name,
            "info": {
                "size": size,
                "mimetype": mime_type,
            },
            "msgtype": "m.file",
            "url": resp.content_uri,
        }

        print("#4")
        resp = await self.client.room_send(
            room_id=room_id,
            message_type="m.room.message",
            content=content,
        )
        print("#5")


    async def main(self) -> None:
        while True:
            try:
                self.client = AsyncClient(self.address, self.username)
                try:
                    with open(self.sync_path, "r") as fh:
                        self.client.next_batch = fh.read()
                except:
                    pass

                self.client.add_event_callback(self.message_callback, RoomMessage)
                self.client.add_response_callback(self.sync_cb, SyncResponse)

                resp = await self.client.login(self.password)
                if isinstance(resp, LoginResponse):
                    log("Matrix - Login ok: "+str(resp), LOG_DEBUG)
                else:
                    log("Matrix - Login error: "+str(resp), LOG_ERROR)

                log("Matrix - Connected", LOG_DEBUG)
                await self.client.sync_forever(timeout=30000) # Milliseconds
                log("Matrix - Connection timeout", LOG_ERROR)
                log("Matrix - Reconnect in 10 seconds", LOG_ERROR)
            except Exception as e:
                log("Matrix - Connection error: "+str(e), LOG_ERROR)
                log("Matrix - Reconnect in 10 seconds", LOG_ERROR)
            time.sleep(10)


    def log_message(self, source_address="", source_name="", destination_address="", destination_name="", content="", message_tag="Matrix - Message log"):
        log(message_tag + ":", LOG_DEBUG)
        log("-           Content: " + str(content), LOG_DEBUG)
        log("-              Size: " + str(len(content)) + " bytes", LOG_DEBUG)
        log("-      Source addr.: " + str(source_address), LOG_DEBUG)
        log("-       Source name: " + str(source_name), LOG_DEBUG)
        log("- Destination addr.: " + str(destination_address), LOG_DEBUG)
        log("- Destination name : " + str(destination_name), LOG_DEBUG)


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
            app_data = app_data.decode("utf-8").strip()
        except:
            return

        log("LXMF - Received an announce from " + RNS.prettyhexrep(destination_hash) + ": " + app_data, LOG_INFO)


#### LXMF - Message ####
def lxmf_message_received_callback(message):
    if not CONFIG["router"].getboolean("lxmf_to_matrix"):
        log("LXMF - Routing disabled", LOG_DEBUG)
        return

    if CONFIG["lxmf"].getboolean("signature_validated") and not message.signature_validated:
        log("LXMF - Source " + RNS.prettyhexrep(message.source_hash) + " have no valid signature", LOG_DEBUG)
        return

    if CONFIG.has_option("allowed", "any") or CONFIG.has_option("allowed", "all") or CONFIG.has_option("allowed", "anybody") or CONFIG.has_option("allowed", RNS.hexrep(message.source_hash, False)) or CONFIG.has_option("allowed", RNS.prettyhexrep(message.source_hash)):

        destination_address = RNS.hexrep(message.source_hash, False)

        if destination_address not in ROUTING_TABLE:
            log("LXMF - Routing table not found for '"+destination_address+"'", LOG_DEBUG)
            return

        title = message.title.decode('utf-8').strip()
        denys = config_getarray(CONFIG, "message", "lxmf_to_matrix_deny_title")
        if len(denys) > 0:
            if "*" in denys:
                return
            for deny in denys:
                if deny in title:
                    return

        content = message.content.decode('utf-8').strip()
        denys = config_getarray(CONFIG, "message", "lxmf_to_matrix_deny_content")
        if len(denys) > 0:
            if "*" in denys:
                return
            for deny in denys:
                if deny in title:
                    return

        if message.fields:
            denys = config_getarray(CONFIG, "message", "lxmf_to_matrix_deny_fields")
            if len(denys) > 0:
                if "*" in denys:
                    return
                for deny in denys:
                    if deny in message.fields:
                        return

        length = config_getint(CONFIG, "message", "lxmf_to_matrix_length_min", 0)
        if length> 0:
            if len(content) < length:
                return

        length = config_getint(CONFIG, "message", "lxmf_to_matrix_length_max", 0)
        if length > 0:
            if len(content) > length:
                return

        source_address = RNS.hexrep(message.source_hash, False)
        source_name = ""

        if message.fields:
            if MSG_FIELD_SRC in message.fields:
                source_address = RNS.hexrep(message.fields[MSG_FIELD_SRC][0], False)
                source_name = message.fields[MSG_FIELD_SRC][1]

        routing_destination = ROUTING_TABLE[destination_address][0]
        routing_table = ROUTING_TABLE[destination_address][1]

        content_prefix = config_get(CONFIG, "message", "lxmf_to_matrix_prefix")
        content_prefix = replace(content_prefix, source_address=source_address, source_name=source_name, destination_address=destination_address, destination_name="", routing_table=routing_table)
        content_suffix = config_get(CONFIG, "message", "lxmf_to_matrix_suffix")
        content_suffix = replace(content_suffix, source_address=source_address, source_name=source_name, destination_address=destination_address, destination_name="", routing_table=routing_table)

        search = config_get(CONFIG, "message", "lxmf_to_matrix_search")
        if search != "":
            content = content.replace(search, config_get(CONFIG, "message", "lxmf_to_matrix_replace"))

        search = config_get(CONFIG, "message", "lxmf_to_matrix_regex_search")
        if search != "":
            content = re.sub(search, config_get(CONFIG, "message", "lxmf_to_matrix_regex_replace"), content)

        content = content_prefix + content + content_suffix

        if message.fields and MSG_FIELD_HASH in message.fields:
            hash = message.fields[MSG_FIELD_HASH]
        else:
            hash = message.hash

        if message.fields and MSG_FIELD_EDIT in message.fields and MSG_FIELD_HASH in message.fields and message.fields[MSG_FIELD_HASH] in DATA:
            content = {"msgtype": "m.text", "body": "", "m.new_content": {"body": content, "msgtype": "m.text"}, "m.relates_to": {"event_id": DATA[message.fields[MSG_FIELD_HASH]][0], "rel_type": "m.replace"}}
        elif message.fields and MSG_FIELD_DELETE in message.fields and MSG_FIELD_HASH in message.fields and message.fields[MSG_FIELD_HASH] in DATA:
            content = {"msgtype": "m.text", "body": "", "m.new_content": {"body": config_get(CONFIG, "message", "lxmf_to_matrix_deleted", "-"), "msgtype": "m.text"}, "m.relates_to": {"event_id": DATA[message.fields[MSG_FIELD_HASH]][0], "rel_type": "m.replace"}}
        elif message.fields and MSG_FIELD_ANSWER in message.fields and message.fields[MSG_FIELD_ANSWER] in DATA:
            content = {"msgtype": "m.text", "body": content, "m.relates_to": {"m.in_reply_to": {"event_id": DATA[message.fields[MSG_FIELD_ANSWER]][0]}}}
        else:
            content = {"msgtype": "m.text", "body": content}

        MATRIX_CONNECTION.send(routing_destination, content, hash)

        # TODO
        #if message.fields and MSG_FIELD_ATTACHMENT in message.fields:
        #    for attachment in message.fields[MSG_FIELD_ATTACHMENT]:
        #        MATRIX_CONNECTION.send_file(routing_destination, attachment["name"], attachment["size"], attachment["data"])
    else:
        log("LXMF - Source " + RNS.prettyhexrep(message.source_hash) + " not allowed", LOG_DEBUG)
        return


##############################################################################################################
# Matrix Functions


#### Matrix - Message ####
def matrix_message_received_callback(room: MatrixRoom, event: RoomMessage):
    global DATA

    if not CONFIG["router"].getboolean("matrix_to_lxmf"):
        log("Matrix - Routing disabled", LOG_DEBUG)
        return

    if room.room_id not in ROUTING_TABLE:
        log("Matrix - Routing table not found for '"+room.room_id+"'", LOG_DEBUG)
        return

    fields = {}

    user_name = room.user_name(event.sender)
    if not user_name:
        user_name = re.sub(r'@(.*):.*', r'\1', event.sender)
    if user_name == event.sender:
        user_name = ""

    content_dict = event.source.get("content")

    try:
        if "m.relates_to" in content_dict and "rel_type" in content_dict["m.relates_to"] and content_dict["m.relates_to"]["rel_type"] == "m.replace":
            content = content_dict["m.new_content"]["body"]
            event_id = content_dict["m.relates_to"]["event_id"]
            if event_id in DATA:
                fields[MSG_FIELD_HASH] = DATA[event_id][0]
                if DATA[event_id][1]:
                    fields[MSG_FIELD_ANSWER] = DATA[event_id][1]
                fields[MSG_FIELD_EDIT] = time.time()
        elif "m.relates_to" in content_dict and "m.in_reply_to" in content_dict["m.relates_to"]:
            content = content_dict["formatted_body"]
            content = re.sub(r'<mx-reply>.*<\/mx-reply>', '', content)
            event_id = content_dict["m.relates_to"]["m.in_reply_to"]["event_id"]
            if event_id in DATA:
                fields[MSG_FIELD_ANSWER] = DATA[event_id][0]
        else:
            content = event.body
    except:
        content = event.body

    content = content.strip()

    length = config_getint(CONFIG, "message", "matrix_to_lxmf_length_min", 0)
    if length> 0:
        if len(content) < length:
            return

    length = config_getint(CONFIG, "message", "matrix_to_lxmf_length_max", 0)
    if length > 0:
        if len(content) > length:
            return

    routing_destination = ROUTING_TABLE[room.room_id][0]
    routing_table = ROUTING_TABLE[room.room_id][1]

    content_prefix = config_get(CONFIG, "message", "matrix_to_lxmf_prefix")
    content_prefix = replace(content_prefix, source_address=event.sender, source_name=user_name, destination_address=room.room_id, destination_name=room.display_name, routing_table=routing_table)
    content_suffix = config_get(CONFIG, "message", "matrix_to_lxmf_suffix")
    content_suffix = replace(content_suffix, source_address=event.sender, source_name=user_name, destination_address=room.room_id, destination_name=room.display_name, routing_table=routing_table)

    search = config_get(CONFIG, "message", "matrix_to_lxmf_search")
    if search != "":
        content = content.replace(search, config_get(CONFIG, "message", "matrix_to_lxmf_replace"))

    search = config_get(CONFIG, "message", "matrix_to_lxmf_regex_search")
    if search != "":
        content = re.sub(search, config_get(CONFIG, "message", "matrix_to_lxmf_regex_replace"), content)

    content = content_prefix + content + content_suffix

    fields[MSG_FIELD_SRC] = [b'', replace(config_get(CONFIG, "message", "matrix_to_lxmf"), source_address=event.sender, source_name=user_name, destination_address=room.room_id, destination_name=room.display_name, routing_table=routing_table)]

    result = LXMF_CONNECTION.send(routing_destination, content, "", fields=fields)

    if result:
        if MSG_FIELD_ANSWER in fields:
            answer = fields[MSG_FIELD_ANSWER]
        else:
            answer = None
        DATA[result] = [event.event_id, answer]
        DATA[event.event_id] = [result, answer]
        DATA["unsaved"] = True

        if CONFIG["main"].getboolean("auto_save_data"):
            del(DATA["unsaved"])
            if not data_save(PATH + "/data.data"):
                DATA["unsaved"] = True


#### Matrix - Message ####
def matrix_message_send_callback(hash_0, hash_1):
    global DATA

    DATA[hash_0] = [hash_1, None]
    DATA[hash_1] = [hash_0, None]
    DATA["unsaved"] = True

    if CONFIG["main"].getboolean("auto_save_data"):
        del(DATA["unsaved"])
        if not data_save(PATH + "/data.data"):
            DATA["unsaved"] = True


##############################################################################################################
# Functions


#### Replace #####
def replace(text, source_address="", source_name="", destination_address="", destination_name="", routing_table=""):
    text = text.replace("!source_address!", source_address)
    text = text.replace("!source_name!", source_name)
    text = text.replace("!destination_address!", destination_address)
    text = text.replace("!destination_name!", destination_name)
    text = text.replace("!routing_table!", routing_table)

    text = text.replace("!n!", "\n")

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
        DATA = {}
        return False
    else:
        if os.path.isfile(file):
            try:
                fh = open(file , "rb")
                DATA = umsgpack.unpackb(fh.read())
                fh.close()
            except Exception as e:
                DATA = {}
                return False
        else:
            DATA = {}
    return True


#### Data - Save #####
def data_save(file=None):
    global DATA

    if file is None:
        return False
    else:
        try:
            if DATA_COUNT_SAVE > 0 and len(DATA) > DATA_COUNT_SAVE:
                keys = list(DATA.keys())[:DATA_COUNT_SAVE]
                for key in keys:
                    del DATA[key]
            fh = open(file, "wb")
            fh.write(umsgpack.packb(DATA))
            fh.close()
        except Exception as e:
            return False
    return True


#### Data - Save #####
def data_save_periodic(initial=False):
    data_timer = threading.Timer(CONFIG.getint("main", "periodic_save_data_interval"), data_save_periodic)
    data_timer.daemon = True
    data_timer.start()

    if initial:
        return

    global DATA
    if "unsaved" in DATA:
        del(DATA["unsaved"])
        if not data_save(PATH + "/data.data"):
            DATA["unsaved"] = True


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
    global ROUTING_TABLE
    global RNS_CONNECTION
    global LXMF_CONNECTION
    global MATRIX_CONNECTION

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

    if not data_read(PATH + "/data.data"):
        print("Data - Error reading data file " + PATH + "/data.data")
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

    ROUTING_TABLE = {}
    if CONFIG.has_section("routing_table"):
        for (key, val) in CONFIG.items("routing_table"):
            try:
                value, name = val.split(" = ", 1)
            except:
                value = val
                name = ""
            ROUTING_TABLE[key] = [value, name]
            ROUTING_TABLE[value] = [key, name]

    RNS_CONNECTION = RNS.Reticulum(configdir=PATH_RNS, loglevel=rns_loglevel)

    log("...............................................................................", LOG_INFO)
    log("        Name: " + CONFIG["main"]["name"], LOG_INFO)
    log("Program File: " + __file__, LOG_INFO)
    log(" Config File: " + PATH + "/config", LOG_INFO)
    log("     Version: " + VERSION, LOG_INFO)
    log("   Copyright: " + COPYRIGHT, LOG_INFO)
    log("...............................................................................", LOG_INFO)

    if CONFIG["main"].getboolean("periodic_save_data"):
        data_save_periodic(True)

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

    LXMF_CONNECTION = lxmf_connection(
        storage_path=path,
        destination_name=CONFIG["lxmf"]["destination_name"],
        destination_type=CONFIG["lxmf"]["destination_type"],
        display_name=CONFIG["lxmf"]["display_name"],
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

    log("Matrix - Connecting ...", LOG_DEBUG)
    MATRIX_CONNECTION = matrix_connection(
        storage_path=path,
        address=CONFIG["matrix"]["address"],
        username=CONFIG["matrix"]["username"],
        password=CONFIG["matrix"]["password"]
    )
    MATRIX_CONNECTION.register_message_received_callback(matrix_message_received_callback)
    MATRIX_CONNECTION.register_message_send_callback(matrix_message_send_callback)
    MATRIX_CONNECTION.loop_forever()

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
'''


#### Default configuration file ####
DEFAULT_CONFIG = '''# This is the default config file.
# You should probably edit it to suit your needs and use-case.


#### Main program settings ####
[main]

enabled = True

# Name of the program. Only for display in the log or program startup.
name =


# Auto save changes.
# If there are changes in the data, they can be saved directly in the files.
# Attention: This can lead to very high write cycles.
# If you want to prevent frequent writing, please set this to 'False' and use the peridodic save function.
auto_save_data = False

# Periodic actions - Save changes periodically.
periodic_save_data = True
periodic_save_data_interval = 1 #Minutes


#### LXMF connection settings ####
[lxmf]

# Destination name & type need to fits the LXMF protocoll
# to be compatibel with other LXMF programs.
destination_name = lxmf
destination_type = delivery

# The name will be visible to other peers
# on the network, and included in announces.
display_name =

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
announce_startup = No
announce_startup_delay = 0 #Seconds

# The peer is announced periodically
# to let other peers reach it.
announce_periodic = No
announce_periodic_interval = 360 #Minutes

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
signature_validated = Yes


#### Matrix connection settings ####
[matrix]

address = <server address>

username = <username>

password = <password>


#### Message router settings ####
[router]

# Transmit LXMF messages to Matrix
lxmf_to_matrix = True

# Transmit Matrix messages to LXMF
matrix_to_lxmf = True


#### Message routing table ####
# Definition of the assignment of lxmf addresses to matrix room ids (bidirectional routing).
# Format: <LXMF address> = <Matrix room id> = <Name (for display)> 
# Example: 2858b7a096899116cd529559cc679ffe = !ADeAldKEzhgebazEzG:matrix.org = Test-Room
[routing_table]


#### Message settings ####
[message]

# Deny message if the title/content/fields contains the following content.
# Comma-separated list with text or field keys.
# *=any
lxmf_to_matrix_deny_title = 
lxmf_to_matrix_deny_content = 
lxmf_to_matrix_deny_fields = 

# Source name
lxmf_to_matrix = 

# Text is added.
lxmf_to_matrix_prefix = !source_name! <!source_address!>!n!
lxmf_to_matrix_suffix = 

# Text is replaced.
lxmf_to_matrix_search = 
lxmf_to_matrix_replace = 

# Text is replaced by regular expression.
lxmf_to_matrix_regex_search = 
lxmf_to_matrix_regex_replace = 

# Length limitation.
lxmf_to_matrix_length_min = 0 #0=any length
lxmf_to_matrix_length_max = 0 #0=any length

# Text is used.
lxmf_to_matrix_deleted = Message deleted


# Deny message if the title/content/fields contains the following content.
# Comma-separated list with text or field keys.
# *=any
matrix_to_lxmf_deny_title = 
matrix_to_lxmf_deny_content = 
matrix_to_lxmf_deny_fields = 

# Source name
matrix_to_lxmf = !source_name! (!routing_table!)

# Text is added.
matrix_to_lxmf_prefix = 
matrix_to_lxmf_suffix = 

# Text is replaced.
matrix_to_lxmf_search = 
matrix_to_lxmf_replace = 

# Text is replaced by regular expression.
matrix_to_lxmf_regex_search = 
matrix_to_lxmf_regex_replace = 

# Length limitation.
matrix_to_lxmf_length_min = 0 #0=any length
matrix_to_lxmf_length_max = 0 #0=any length

# Text is used.
matrix_to_lxmf_deleted = 


#### Right settings ####
# Allow only specific source addresses/hashs or any.
[allowed]

any
#2858b7a096899116cd529559cc679ffe
'''


##############################################################################################################
# Init


if __name__ == "__main__":
    main()