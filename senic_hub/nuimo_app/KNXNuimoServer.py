import logging

import socket
import nuimo

from .import matrices

logger = logging.getLogger(__name__)

class KNXComponent:

        def __init__(self, addr, port):
            self.server_addr = addr
            self.server_port= port
            self.serving = False


            self.nuimoserversock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.nuimoserversock.bind((self.server_addr, self.server_port))
            logger.info("Nuimo Server bound to receive on " + self.server_addr + ", on port " + self.server_port)


        def run_server():
            logger.info("Nuimo Server bound to receive on " + self.server_addr + ", on port " + self.server_port)
            while True:
                data, address = self.nuimoserversock.recvfrom(1024)
                logger.info("Data received: " + data)



                # if str(data).len == 81:
                #     logger.info("LED Matrix Data Received - Applying to LED =----- > ")
                #     self.set_nuimo_led(str(data))
