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

#### MQTT ####
# Install: pip3 install paho-mqtt
# Source: https://pypi.org/project/paho-mqtt/
import paho.mqtt.client as mqtt
import paho.mqtt.publish as publish


##############################################################################################################
# Globals


#### Global Variables - Configuration ####
NAME = "LXMF Bridge MQTT"
DESCRIPTION = ""
VERSION = "0.0.1 (2022-10-21)"
COPYRIGHT = "(c) 2022 Sebastian Obele  /  obele.eu"
PATH = os.path.expanduser("~") + "/." + os.path.splitext(os.path.basename(__file__))[0]
PATH_RNS = None


#### Global Variables - System (Not changeable) ####
CONFIG = None
RNS_CONNECTION = None
LXMF_CONNECTION = None
MQTT_CONNECTION = None


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

        if not CONFIG["main"].getboolean("power") or not CONFIG["router"].getboolean("lxmf_announce_to_mqtt"):
            log("LXMF - Routing disabled", LOG_DEBUG)
            return

        if CONFIG.has_option("allowed", "any") or CONFIG.has_option("allowed", "all") or CONFIG.has_option("allowed", "anybody") or CONFIG.has_option("allowed", RNS.hexrep(destination_hash, False)) or CONFIG.has_option("allowed", RNS.prettyhexrep(destination_hash)):
            message_out = json.dumps({
                "source": RNS.hexrep(destination_hash, False),
                "data": app_data
            })

            MQTT_CONNECTION.publish(CONFIG["mqtt"]["topic_announce"], message_out)
        else:
            log("LXMF - Source " + RNS.prettyhexrep(message.source_hash) + " not allowed", LOG_DEBUG)
            return


#### LXMF - Message ####
def lxmf_message_received_callback(message):
    if not CONFIG["main"].getboolean("power") or not CONFIG["router"].getboolean("lxmf_to_mqtt"):
        log("LXMF - Routing disabled", LOG_DEBUG)
        return

    if CONFIG["lxmf"].getboolean("signature_validated") and not message.signature_validated:
        log("LXMF - Source " + RNS.prettyhexrep(message.source_hash) + " have no valid signature", LOG_DEBUG)
        return

    if CONFIG.has_option("allowed", "any") or CONFIG.has_option("allowed", "all") or CONFIG.has_option("allowed", "anybody") or CONFIG.has_option("allowed", RNS.hexrep(message.source_hash, False)) or CONFIG.has_option("allowed", RNS.prettyhexrep(message.source_hash)):

        title = message.title.decode('utf-8').strip()
        denys = config_get(CONFIG, "message", "lxmf_to_mqtt_deny_title")
        if denys != "":
            denys = denys.split(",")
            if "*" in denys:
                return
            for deny in denys:
                if deny in title:
                    return

        content = message.content.decode('utf-8').strip()
        denys = config_get(CONFIG, "message", "lxmf_to_mqtt_deny_content")
        if denys != "":
            denys = denys.split(",")
            if "*" in denys:
                return
            for deny in denys:
                if deny in title:
                    return

        if message.fields:
            denys = config_get(CONFIG, "message", "lxmf_to_mqtt_deny_fields")
            if denys != "":
                denys = denys.split(",")
                if "*" in denys:
                    return
                for deny in denys:
                    if deny in message.fields:
                        return

        length = config_getint(CONFIG, "message", "lxmf_to_mqtt_length_min", 0)
        if length> 0:
            if len(content) < length:
                return

        length = config_getint(CONFIG, "message", "lxmf_to_mqtt_length_max", 0)
        if length > 0:
            if len(content) > length:
                return

        content_prefix = config_get(CONFIG, "message", "lxmf_to_mqtt_prefix")
        content_suffix = config_get(CONFIG, "message", "lxmf_to_mqtt_suffix")

        search = config_get(CONFIG, "message", "lxmf_to_mqtt_search")
        if search != "":
            content = content.replace(search, config_get(CONFIG, "message", "lxmf_to_mqtt_replace"))

        search = config_get(CONFIG, "message", "lxmf_to_mqtt_regex_search")
        if search != "":
            content = re.sub(search, config_get(CONFIG, "message", "lxmf_to_mqtt_regex_replace"), content)

        content = content_prefix + content + content_suffix

        if message.signature_validated:
            signature_string = "Validated"
            signature_valid = 1
        else:
            signature_valid = 0
            if message.unverified_reason == LXMF.LXMessage.SIGNATURE_INVALID:
                signature_string = "Invalid signature"
            elif message.unverified_reason == LXMF.LXMessage.SOURCE_UNKNOWN:
                signature_string = "Cannot verify, source is unknown"
            else:
                signature_string = "Signature is invalid, reason undetermined"

        message_out = json.dumps({
            "source": RNS.hexrep(message.source_hash, False),
            "destination": RNS.hexrep(message.destination_hash, False),
            "title": message.title.decode('utf-8').strip(),
            "content": content,
            "fields": str(message.fields),
            "date_time": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(message.timestamp)),
            "timestamp": message.timestamp,
            "signature_valid": signature_valid,
            "signature_string": signature_string
        })

        MQTT_CONNECTION.publish(CONFIG["mqtt"]["topic_receive"], message_out)
    else:
        log("LXMF - Source " + RNS.prettyhexrep(message.source_hash) + " not allowed", LOG_DEBUG)
        return


##############################################################################################################
# MQTT Functions


#### MQTT - Log ####
def mqtt_log_message(message, message_tag="MQTT - Message log"):
    log(message_tag + ":", LOG_DEBUG)
    log("-   Topic: " + str(message.topic), LOG_DEBUG)
    log("- Payload: " + str(message.payload.decode('utf-8')), LOG_DEBUG)
    log("-     QOS: " + str(message.qos), LOG_DEBUG)


#### MQTT - State ####
def mqtt_state():
    t = threading.Timer(int(CONFIG["mqtt"]["state_interval"])*60, mqtt_state_now)
    t.daemon = True
    t.start()


#### MQTT - State ####
def mqtt_state_now():
    if not CONFIG["router"].getboolean("state_to_mqtt"):
        log("MQTT - Routing disabled", LOG_DEBUG)
        return

    if CONFIG["main"].getboolean("power"):
        power = "on"
    else:
        power = "off"

    MQTT_CONNECTION.publish(CONFIG["mqtt"]["topic_rm_power"], power)

    interfaces = None
    try:
        interfaces = RNS_CONNECTION.get_interface_stats()
    except Exception:
        pass

    message_out = json.dumps({
        "power": power,
        "identity": str(LXMF_CONNECTION.identity),
        "destination": str(LXMF_CONNECTION.destination),
        "hash": RNS.hexrep(LXMF_CONNECTION.destination_hash(), False),
        #"interfaces": interfaces,
        "file_info": __file__,
        "path_info": PATH,
        "version_info": VERSION,
        "host_info": os.uname(),
    })

    MQTT_CONNECTION.publish(CONFIG["mqtt"]["topic_rm_state"], message_out)


#### MQTT - Connected ####
def mqtt_connected_callback(client, userdata, flags, rc):
    MQTT_CONNECTION.subscribe(CONFIG["mqtt"]["topic_power"])
    MQTT_CONNECTION.subscribe(CONFIG["mqtt"]["topic_state"])
    MQTT_CONNECTION.subscribe(CONFIG["mqtt"]["topic_send"])

    if CONFIG["mqtt"].getboolean("state_startup"):
        mqtt_state_now()

    if CONFIG["mqtt"].getboolean("state_periodic"):
        mqtt_state()

    log("MQTT - Connected", LOG_DEBUG)


#### MQTT - Message ####
def mqtt_message_received_callback_power(client, userdata, message):
    global CONFIG

    mqtt_log_message(message)

    if message.payload.decode('utf-8') == "on" or message.payload.decode('utf-8') == "1":
        CONFIG["main"]["power"] = True
        MQTT_CONNECTION.publish(CONFIG["mqtt"]["topic_rm_power"], "on")
    else:
        CONFIG["main"]["power"] = False
        MQTT_CONNECTION.publish(CONFIG["mqtt"]["topic_rm_power"], "off")


#### MQTT - Message ####
def mqtt_message_received_callback_state(client, userdata, message):
    global CONFIG

    mqtt_log_message(message)

    mqtt_state_now()


#### MQTT - Message ####
def mqtt_message_received_callback_send(client, userdata, message):
    mqtt_log_message(message)

    if not CONFIG["main"].getboolean("power") or not CONFIG["router"].getboolean("mqtt_to_lxmf"):
        log("MQTT - Routing disabled", LOG_DEBUG)
        return

    message_data = json.loads(message.payload.decode('utf-8'))

    if "destination" not in message_data or "content" not in message_data:
        return

    content = message_data["content"].strip()

    length = config_getint(CONFIG, "message", "mqtt_to_lxmf_length_min", 0)
    if length> 0:
        if len(content) < length:
            return

    length = config_getint(CONFIG, "message", "mqtt_to_lxmf_length_max", 0)
    if length > 0:
        if len(content) > length:
            return

    content_prefix = config_get(CONFIG, "message", "mqtt_to_lxmf_prefix")
    content_suffix = config_get(CONFIG, "message", "mqtt_to_lxmf_suffix")

    search = config_get(CONFIG, "message", "mqtt_to_lxmf_search")
    if search != "":
        content = content.replace(search, config_get(CONFIG, "message", "mqtt_to_lxmf_replace"))

    search = config_get(CONFIG, "message", "mqtt_to_lxmf_regex_search")
    if search != "":
        content = re.sub(search, config_get(CONFIG, "message", "mqtt_to_lxmf_regex_replace"), content)

    content = content_prefix + content + content_suffix

    if "title" not in message_data:
        message_data["title"] = ""

    if "fields" not in message_data:
        message_data["fields"] = None

    timestamp = None
    if "timestamp" in message_data and timestamp is None:
        message_data["timestamp"] = message_data["timestamp"].strip()
        if message_data["timestamp"] != "":
            timestamp = float(message_data["timestamp"])

    if "date_time" in message_data and timestamp is None:
        message_data["date_time"] = message_data["date_time"].strip()
        if message_data["date_time"] != "":
            timestamp = time.mktime(datetime.datetime.strptime(message_data["date_time"], '%Y-%m-%d %H:%M:%S').timetuple())

    LXMF_CONNECTION.send(message_data["destination"].strip(), content, message_data["title"].strip(), message_data["fields"], timestamp)


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
    global RNS_CONNECTION
    global LXMF_CONNECTION
    global MQTT_CONNECTION

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

    RNS_CONNECTION = RNS.Reticulum(configdir=PATH_RNS, loglevel=rns_loglevel)

    log("...............................................................................", LOG_INFO)
    log("        Name: " + CONFIG["main"]["name"], LOG_INFO)
    log("Program File: " + __file__, LOG_INFO)
    log(" Config File: " + PATH + "/config", LOG_INFO)
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

    log("MQTT - Connecting ...", LOG_DEBUG)
    MQTT_CONNECTION = mqtt.Client(CONFIG["mqtt"]["client_id"], False, userdata=None, transport=CONFIG["mqtt"]["transport"])
    MQTT_CONNECTION.on_connect = mqtt_connected_callback
    MQTT_CONNECTION.message_callback_add(CONFIG["mqtt"]["topic_power"], mqtt_message_received_callback_power)
    MQTT_CONNECTION.message_callback_add(CONFIG["mqtt"]["topic_state"], mqtt_message_received_callback_state)
    MQTT_CONNECTION.message_callback_add(CONFIG["mqtt"]["topic_send"], mqtt_message_received_callback_send)
    if CONFIG.has_option("mqtt", "username") and CONFIG.has_option("mqtt", "password"):
        if CONFIG["mqtt"]["username"] != "" and CONFIG["mqtt"]["password"] != "":
            MQTT_CONNECTION.username_pw_set(CONFIG["mqtt"]["username"], CONFIG["mqtt"]["password"])
    MQTT_CONNECTION.connect(CONFIG["mqtt"]["host"], int(CONFIG["mqtt"]["port"]), 60)
    MQTT_CONNECTION.loop_forever()

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

# Enable/Disable the message routing.
# This is controllable with a MQTT message.
power = Yes


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
sync_limit = 8

# Allow only messages with valid signature.
signature_validated = Yes


#### MQTT connection settings ####
[mqtt]

host = 192.168.10.201

port = 1883

transport = tcp

client_id = lxmf_mqtt_bridge

#username = 

#password = 

# Topic for power switch.
# Direction: From MQTT server.
# Data: on/off
topic_power = message/lxmf/power

# Topic for power switch state.
# Direction: To MQTT server.
# Data: on/off
topic_rm_power = message/lxmf/rm_power

# Topic for state request.
# Direction: From MQTT server.
# Data: any
topic_state = message/lxmf/state

# Topic for state (diagnose data).
# Direction: To MQTT server.
# Data: {"power": "on", "identity": "<36a82374456b9c31a37f>", "destination": "<lxmf.delivery.36a82374456b9c31a37f/36a82374456b9c31a37f>", "hash": "36a82374456b9c31a37f", "interfaces": [{"clients": 0, "name": "Shared Instance[37428]", "rxb": 0, "txb": 0, "status": true}, {"clients": null, "name": "AutoInterface[Default Interface]", "rxb": 1111, "txb": 1176, "status": true}], "file_info": "/root/./lxmf_mqtt_bridge.py", "path_info": "/root/.lxmf_mqtt_bridge", "version_info": "0.0.1", "host_info": ["Linux", "test", "5.13.19-6", "#1 5.13.19-15 (Tue, 29 Mar 2022 15:59:50 +0200)", "x86_64"]}
topic_rm_state = message/lxmf/rm_state

# Topic for announce.
# Direction: To MQTT server.
# Data: {"source": "36a82374456b9c31a37f", "data": "Sideband"}
topic_announce = message/lxmf/announce

# Topic for receive messages (LXMF->MQTT).
# Direction: To MQTT server.
# Data: {"source": "36a82374456b9c31a37f", "destination": "36a82374456b9c31a37f", "title": "", "content": "Frage", "fields": "None", "date_time": "2022-05-07 14:19:10", "timestamp": 1651933150.803059, "signature_valid": 1, "signature_string": "Validated"}
topic_receive = message/lxmf/receive

# Topic for send messages (MQTT->LXMF).
# Direction: From MQTT server.
# Data: {"destination":"36a82374456b9c31a37f", "content":"Antwort"}
# Data: {"destination":"36a82374456b9c31a37f", "content":"Antwort", "title":"Example", "date_time":"2022-10-01 11:45:00", "timestamp":""}
topic_send = message/lxmf/send

# Send state at startup.
state_startup = Yes

# Send state periodically.
state_periodic = Yes
state_interval = 30 #Minutes


#### Message router settings ####
[router]

# Transmit LXMF messages to MQTT
lxmf_to_mqtt = True

# Transmit MQTT messages to LXMF
mqtt_to_lxmf = True

# Transmit LXMF announces to MQTT
lxmf_announce_to_mqtt = False

# Transmit state to MQTT
state_to_mqtt = True


#### Message settings ####
[message]

# Deny message if the title/content/fields contains the following content.
# Comma-separated list with text or field keys.
# *=any
lxmf_to_mqtt_deny_title = 
lxmf_to_mqtt_deny_content = 
lxmf_to_mqtt_deny_fields = 

# Text is added.
lxmf_to_mqtt_prefix = 
lxmf_to_mqtt_suffix = 

# Text is replaced.
lxmf_to_mqtt_search = 
lxmf_to_mqtt_replace = 

# Text is replaced by regular expression.
lxmf_to_mqtt_regex_search = 
lxmf_to_mqtt_regex_replace = 

# Length limitation.
lxmf_to_mqtt_length_min = 0 #0=any length
lxmf_to_mqtt_length_max = 0 #0=any length


# Deny message if the title/content/fields contains the following content.
# Comma-separated list with text or field keys.
# *=any
mqtt_to_lxmf_deny_title = 
mqtt_to_lxmf_deny_content = 
mqtt_to_lxmf_deny_fields = 

# Text is added.
mqtt_to_lxmf_prefix = 
mqtt_to_lxmf_suffix = 

# Text is replaced.
mqtt_to_lxmf_search = 
mqtt_to_lxmf_replace = 

# Text is replaced by regular expression.
mqtt_to_lxmf_regex_search = 
mqtt_to_lxmf_regex_replace = 

# Length limitation.
mqtt_to_lxmf_length_min = 0 #0=any length
mqtt_to_lxmf_length_max = 0 #0=any length


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