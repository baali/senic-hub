import socket
import sys

from nuimo import (Controller, ControllerListener, ControllerManager, Gesture, LedMatrix)


addr = 'localhost'
port = 55556


nuimoserversock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
nuimoserversock.bind((addr, port))
# nuimoserversock.listen(5)

while True:
    data, address = nuimoserversock.recvfrom(1024)
    print("Received" + str(data))
    # if len(data) > 3:
    #     print("Looks like a Nuimo LED Message : " + data)



    # Here, import the NuimoApp
