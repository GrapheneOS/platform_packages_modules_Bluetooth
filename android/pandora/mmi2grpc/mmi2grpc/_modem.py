import os
import socket


class Modem:

    def __init__(self, port):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect(("127.0.0.1", port))
        self.socket = s

    def close(self):
        self.socket.close()

    def call(self, phone_number):
        self.socket.sendall(b'REM0\r\nAT+REMOTECALL=4,0,0,"' + str(phone_number).encode("utf-8") + b'",129\r\n')
