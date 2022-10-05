#!/usr/bin/env python3
#
#   Copyright 2022 - The Android Open Source Project
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.

import logging

from blueberry.tests.gd.cert.truth import assertThat


class L2cap:

    __l2cap_connection_timeout = 30  #seconds
    __device = None

    def __init__(self, device):
        self.__device = device

    def create_l2cap_le_coc(self, address, psm, secure):
        logging.info("creating l2cap channel with secure=%r and psm %s", secure, psm)
        self.__device.sl4a.bluetoothSocketConnBeginConnectThreadPsm(address, True, psm, secure)

    # Starts listening on the l2cap server socket, returns the psm
    def listen_using_l2cap_coc(self, secure):
        logging.info("Listening for l2cap channel with secure=%r and psm %s", secure, psm)
        self.__device.sl4a.bluetoothSocketConnBeginAcceptThreadPsm(__l2cap_connection_timeout, True, secure)
        return self.__device.sl4a.bluetoothSocketConnGetPsm()
