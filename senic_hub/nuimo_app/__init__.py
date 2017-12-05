import logging

from importlib import import_module
from threading import Thread
import threading

import ctypes
import mmap
import os
import struct
import socket
import binascii

from nuimo import (Controller, ControllerListener, ControllerManager, Gesture, LedMatrix)

from . import matrices
from . import KNXNuimoServer as KNS

import time

logger = logging.getLogger(__name__)

KNX_DISPLAY_MATRIX = ""


class NuimoControllerListener(ControllerListener):

    is_app_disconnection = False
    connection_failed = False

    def started_connecting(self):
        mac = self.controller.mac_address
        logger.info("Connecting to Nuimo controller %s...", mac)

    def connect_succeeded(self):
        mac = self.controller.mac_address
        self.connection_failed = False
        logger.info("Connected to Nuimo controller %s", mac)

    def connect_failed(self, error):
        mac = self.controller.mac_address
        self.connection_failed = True
        logger.critical("Connection failed %s: %s", mac, error)
        self.controller.connect()

    def disconnect_succeeded(self):
        mac = self.controller.mac_address
        logger.warn("Disconnected from %s, reconnecting...", mac)
        if not self.is_app_disconnection:
            self.controller.connect()

    def services_resolved(self):
        mac = self.controller.mac_address
        logger.info("Received services resolved to Nuimo controller %s", mac)

    def received_gesture_event(self, event):
        mac = self.controller.mac_address
        logger.info("Received gesture event to Nuimo controller %s", mac)
        self.process_gesture_event(event)



class NuimoApp(NuimoControllerListener):
    TOUCH_GESTURES = [
        Gesture.TOUCH_LEFT,
        Gesture.TOUCH_RIGHT,
        Gesture.TOUCH_BOTTOM,
    ]

    INTERNAL_GESTURES = [
        Gesture.SWIPE_UP,
        Gesture.SWIPE_DOWN,
    ] + TOUCH_GESTURES

    GESTURES_TO_IGNORE = [
        Gesture.BUTTON_RELEASE,
    ]

    def __init__(self, ha_api_url, ble_adapter_name, mac_address, components):
        super().__init__()

        self.components = []
        self.active_component = None
        component_instances = get_component_instances(components, mac_address)
        self.set_components(component_instances)

        self.manager = None
        self.ble_adapter_name = ble_adapter_name
        self.controller = None
        self.mac_address = mac_address
        self.battery_level = None

        # memory map using mmap to store nuimo battery level
        fd = os.open('/tmp/' + self.mac_address.replace(':', '-'), os.O_CREAT | os.O_TRUNC | os.O_RDWR)
        assert os.write(fd, b'\x00' * mmap.PAGESIZE) == mmap.PAGESIZE
        buf = mmap.mmap(fd, mmap.PAGESIZE, mmap.MAP_SHARED, mmap.PROT_WRITE)
        self.bl = ctypes.c_int.from_buffer(buf)
        self.bl.value = 0
        offset = struct.calcsize(self.bl._type_)
        assert buf[offset] == 0


        ##### SOCKET SERVER UDP #######
        # self.server_address = 'localhost'
        # self.server_port = 55555
        # self.nuimoserversock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # self.nuimoserversock.bind((self.server_address, self.server_port))
        # self.nuimoserversock.listen(5)
        # logger.info('Socket Server initialized on port 55555 : Listening to Max. 5 connections')

        ###############################

        # class NuimoKNXClient(Thread):
        #     def __init__(self, socket, address):
        #         Thread.__init__(self)
        #         self.sock = socket
        #         self.addr = address
        #         self.start()
        #
        #         def run(self):
        #             while 1:
        #                 print('Client sent:', self.sock.recv(1024).decode())
        #                 self.sock.send(b'1')



        self.client_address = '127.0.0.1'
        self.client_port = 55556
        self.nuimo_client_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        # self.nuimo_client_sock.connect((self.client_address, self.client_port))


    def set_components(self, components):
        previously_active = self.active_component
        if self.active_component:
            self.active_component.stop()
            self.active_component = None

        for component in components:
            component.nuimo = self
        self.components = components

        if previously_active:
            for component in components:
                if previously_active.component_id == component.component_id:
                    self.set_active_component(component)
                    break

        if self.active_component is None:
            self.set_active_component()

    def start(self, ipc_queue):

        ipc_thread = Thread(target=self.listen_to_ipc_queue, args=(ipc_queue,), daemon=True)
        ipc_thread.start()

        connection_thread = Thread(target=self.check_nuimo_connection, daemon=True)
        connection_thread.start()

        self.manager = ControllerManager(self.ble_adapter_name)
        self.manager.is_adapter_powered = True

        self.controller = Controller(self.mac_address, self.manager)

        knx_client_address = '127.0.0.1'
        knx_client_port = 55555

        self.controller.listener = self
        self.set_active_component()
        logger.info("Connecting to Nuimo controller %s", self.controller.mac_address)
        self.controller.connect()

        get_knx_client_data = Thread(
            target=self.listen_nuimo_server,
            args=(self.controller, knx_client_address, knx_client_port,),
            daemon=True)

        get_knx_client_data.start()

        try:
            self.manager.run()
        except KeyboardInterrupt:
            logger.info("Nuimo app received SIGINT %s", self.controller.mac_address)
            self.stop()


    def stop(self):
        logger.info("Stopping nuimo app of %s ...", self.controller.mac_address)
        if self.active_component:
            self.active_component.stop()

        self.controller.disconnect()
        self.is_app_disconnection = True
        logger.info("Disconnected from Nuimo controller %s", self.controller.mac_address)
        self.manager.stop()
        logger.debug("self manager stop %s", self.controller.mac_address)

    def process_gesture_event(self, event):
        ip_addr = None
        if event.gesture in self.GESTURES_TO_IGNORE:
            logger.debug("Ignoring gesture event: %s", event)
            return

        logger.debug("Processing gesture event: %s", event)

        if event.gesture in self.INTERNAL_GESTURES:
            self.process_internal_gesture(event.gesture)
            return

        if event.gesture == Gesture.BATTERY_LEVEL:
            logger.info("gesture BATTERY LEVEL %d", event.value)
            self.battery_level = event.value
            self.update_battery_level()
            return

        if not self.active_component:
            logger.warn("Ignoring event, no active component")
            self.show_error_matrix()
            return

        if self.active_component.stopped:
            logger.warn("Ignoring event, component is not running")
            self.show_error_matrix()
            return

        if self.active_component.ip_address is not None:
            ip_addr = self.active_component.ip_address
            if self.is_device_responsive(ip_addr) is True:
                self.process_gesture(event.gesture, event.value)
                return
            else:
                self.show_error_matrix()
                return# self.nuimo_client_sock.connect((self.client_address, self.client_port))

        # Process gestures for devices having no IP address in nuimo_app.cfg
        self.process_gesture_event(event.gesture, event.value)

    def process_internal_gesture(self, gesture):
        if gesture == Gesture.SWIPE_UP:
            msg = [0x02, 0x02, 0x00, 0x00]
            msgstr = ""
            for m in msg:
                msgstr+=chr(m)
            self.nuimo_client_sock.sendto(msgstr.encode(), (self.client_address, self.client_port))
            logger.info("SENT DATA TO SERVER" + str(2000))

        elif gesture == Gesture.SWIPE_DOWN:
            msg = [0x02, 0x03, 0x00, 0x00]
            msgstr = ""
            for m in msg:
                msgstr+=chr(m)
            self.nuimo_client_sock.sendto(msgstr.encode(), (self.client_address, self.client_port))
            logger.info("SENT DATA TO SERVER : " + str(2100))

        elif gesture in self.TOUCH_GESTURES:
            # Fall-through to show active component...
            pass

        self.show_active_component()

    def process_gesture(self, gesture, delta):
        if gesture == Gesture.ROTATION:
            logger.info("DELTA VALUE: " + str(int(delta/10)))
            msg = [0x04]
            if delta > 0:
                 msg.append(0x01)
                 del_2 = int(delta/10)

            else:
                 msg.append(0x00)
                 del_2 = int(-1*delta/10)

            msg.append((del_2 >> 8) & 0xFF)
            msg.append(del_2 & 0xFF)
            msgstr = ""
            for m in msg:
                msgstr+=chr(m)

            self.nuimo_client_sock.sendto(msgstr.encode(), (self.client_address, self.client_port))
            logger.info("SENT DATA TO SERVER : ")

        if gesture == Gesture.BUTTON_PRESS:
            msg = [0x01, 0x00, 0x00, 0x00]
            msgstr = ""
            for m in msg:
                msgstr+=chr(m)
            self.nuimo_client_sock.sendto(msgstr.encode(), (self.client_address, self.client_port))
            logger.info("SENT DATA TO SERVER : " + str(1000))
            logger.info(self.controller)

        elif gesture == Gesture.SWIPE_LEFT:
            msg = [0x02, 0x00, 0x00, 0x00]
            msgstr = ""
            for m in msg:
                msgstr+=chr(m)
            # self.active_component.on_swipe_left()
            self.nuimo_client_sock.sendto(msgstr.encode(), (self.client_address, self.client_port))
            logger.info("SENT DATA TO SERVER : " + str(3000))

        elif gesture == Gesture.SWIPE_RIGHT:
            msg = [0x02, 0x01, 0x00, 0x00]
            msgstr = ""
            for m in msg:
                msgstr+=chr(m)
            # self.active_component.on_swipe_right()
            self.nuimo_client_sock.sendto(msgstr.encode(), (self.client_address, self.client_port))
            logger.info("SENT DATA TO SERVER : " + str(3100))

        elif gesture == Gesture.LONGTOUCH_LEFT:
            # self.active_component.on_longtouch_left()
            msg = [0x02, 0x08, 0x00, 0x00]
            msgstr = ""
            for m in msg:
                msgstr+=chr(m)
            self.nuimo_client_sock.sendto(msgstr.encode(), (self.client_address, self.client_port))
            logger.info("SENT DATA TO SERVER" + str(2000))

        elif gesture == Gesture.LONGTOUCH_BOTTOM:
            # self.active_component.on_longtouch_bottom()
            msg = [0x02, 0x0B, 0x00, 0x00]
            msgstr = ""
            for m in msg:
                msgstr+=chr(m)
            self.nuimo_client_sock.sendto(msgstr.encode(), (self.client_address, self.client_port))
            logger.info("SENT DATA TO SERVER" + str(2000))

        elif gesture == Gesture.LONGTOUCH_RIGHT:
            # self.active_component.on_longtouch_right()
            msg = [0x02, 0x09, 0x00, 0x00]
            msgstr = ""
            for m in msg:
                msgstr+=chr(m)
            self.nuimo_client_sock.sendto(msgstr.encode(), (self.client_address, self.client_port))
            logger.info("SENT DATA TO SERVER" + str(2000))

        else:
            # TODO handle all remaining gestures...
            pass

    def get_prev_component(self):
        if not self.components:
            return None

        if self.active_component:
            index = self.components.index(self.active_component)
            return self.components[index - 1]
        else:
            return self.components[0]

    def get_next_component(self):
        if not self.components:
            return None

        if self.active_component:
            index = self.components.index(self.active_component)
            try:
                return self.components[index + 1]
            except IndexError:
                return self.components[0]
        else:
            return self.components[0]

    def set_active_component(self, component=None):
        active_component = None

        if component:
            active_component = component
        elif self.components:
            active_component = self.components[0]

        if active_component:
            if self.active_component:
                logger.debug("Stopping component: %s", self.active_component.component_id)
                self.active_component.stop()

            logger.debug("Activating component: %s", active_component.component_id)
            self.active_component = active_component
            self.active_component.start()

    def show_active_component(self):
        if self.active_component:
            index = self.components.index(self.active_component)
            matrix = matrices.matrix_with_index(self.active_component.MATRIX, index)
        else:
            matrix = matrices.ERROR

        self.display_matrix(matrix)

    def show_error_matrix(self):
        self.display_matrix(matrices.ERROR)

    def show_custom_matrix(self, matrix_string):
        self.display_matrix(matrix_string)

    def display_matrix(self, matrix):
        self.controller.display_matrix(LedMatrix(matrix))

    def register_knx_app(self, register_data):
        nuimo_app_config_path = '/data/senic-hub/nuimo_app.cfg'

        data = {'device_ids': ['knx-light-1'],
                    'id': '123abc',
                    'is_reachable': True,
                    'name': 'KNX',
                    'type': 'knx'}

        with open(nuimo_app_config_path, 'r+') as f:
            config = yaml.load(f)

            for mac_address in config['nuimos']:
                config['nuimos'][mac_address]['components'].append(data)

            f.seek(0)
            yaml.dump(config, f, default_flow_style=False)
            logger.info('KNX is now registered')

###################################################################################
    def listen_to_ipc_queue(self, ipc_queue):
        """
        Checks an inter-process queue for new messages. The messages have a simple custom format
        containing the name of one of the defined methods to call and in some cases additional arguments.

        This is required because this NuimoApp instance is executed in its own process (because gatt-python
        doesn't handle multiple devices in a single thread correctly) and it needs to be notified of changes
        and when to quit.
        """
        while True:
            msg = ipc_queue.get()
            if msg['method'] == 'set_components':
                components = msg['components']
                logger.info("IPC set_components() received: %s mac = %s", components, self.controller.mac_address)
                component_instances = get_component_instances(components, self.controller.mac_address)
                self.set_components(component_instances)
            elif msg['method'] == 'stop':
                logger.info("IPC stop() received %s", self.controller.mac_address)
                self.stop()
                return

###################################################################################

    def listen_nuimo_server(self, controller, addr, port):
        logger.info("Reached Here! :" )
        nuimoserversock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        nuimoserversock.bind((addr, port))
        logger.info("Nuimo Server bound to receive on " + addr + ", on port " + str(port))

        while True:
            data, address = nuimoserversock.recvfrom(1024)
            description = hex(ord(data[:1]))
            self.process_knx_data(controller, description, data)



#####################################################################################


    def process_knx_data(self, controller, desc, data):
        processed_data = "".join(["{0:08b}".format(b) for b in data[1:]])[0:-7]
        logger.info("PROCESSED INCOMING DATA : " + desc + " -- " + processed_data)

        if desc == '0x30':
            controller.display_matrix(LedMatrix(processed_data))
        elif ('0x05' == desc): # Register
            logger.info("Register command")
            register_data = 'foo'
            self.register_knx_app(register_data)
        elif ('0x06' == desc): # Switch
            logger.info("Switch command")
        elif ('0x07' == desc): # Scale
            logger.info("Scale command")
        elif ('0x08' == desc): # TriggerScene
            logger.info("TriggerScene command")
        elif ('0x09' == desc): # SwitchState
            logger.info("SwitchState command")
        elif ('0x0A' == desc or '0xa' == desc): # ScalingState
            logger.info("ScalingState command")
        else:
            logger.info("Unknown command")


    def check_nuimo_connection(self):
        while True:
            time.sleep(5)
            if self.controller and self.controller.is_connected() is False and self.connection_failed is True:
                logger.info("not Connected, retry a connection every 5 seconds")
                self.controller.connect()

    def is_device_responsive(self, host_ip):
        param = "-c 1 -w 1"
        status = (os.system("ping " + param + " " + host_ip) == 0)
        return status

    def update_battery_level(self):
        self.bl.value = self.battery_level


def get_component_instances(components, mac_address):
    """
    Import component modules configured in the Nuimo app configuration
    and return instances of the contained component classes.
    """
    module_name_format = __name__ + '.components.{}'

    instances = []
    first = True
    for component in components:
        module_name = module_name_format.format(component['type'])
        # TODO: philips hue related fix for delete groups - would be better to keep separation of concerns
        component['nuimo_mac_address'] = mac_address
        if component['type'] == 'philips_hue' and first is True:
            component['first'] = True
            first = False
        else:
            component['first'] = False

        # join Sonos speakers
        join = component.get('join', None)
        if join and join['master'] is False:
            continue
        logger.info("Importing module %s", module_name)
        # FIXME: don't ignore errors, this is just a workaround!
        try:
            component_module = import_module(module_name)
            instances.append(component_module.Component(component))
        except Exception as e:
            logger.error("Error during import: %s", e)

    return instances
