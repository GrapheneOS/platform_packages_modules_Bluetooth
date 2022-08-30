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

import queue
import logging

from blueberry.tests.gd.cert.closable import Closable
from blueberry.tests.gd.cert.truth import assertThat
from blueberry.tests.sl4a_sl4a.lib.oob_data import OobData


class Security:

    # Events sent from SL4A
    SL4A_EVENT_GENERATED = "GeneratedOobData"
    SL4A_EVENT_ERROR = "ErrorOobData"
    SL4A_EVENT_BONDED = "Bonded"
    SL4A_EVENT_UNBONDED = "Unbonded"

    # Matches tBT_TRANSPORT
    # Used Strings because ints were causing gRPC problems
    TRANSPORT_AUTO = "0"
    TRANSPORT_BREDR = "1"
    TRANSPORT_LE = "2"

    __default_timeout = 10  # seconds
    __default_bonding_timeout = 30  # seconds
    __device = None

    def __init__(self, device):
        self.__device = device
        self.__device.sl4a.bluetoothStartPairingHelper(True)

    def generate_oob_data(self, transport):
        self.__device.sl4a.bluetoothGenerateLocalOobData(transport)
        try:
            event_info = self.__device.ed.pop_event(self.SL4A_EVENT_GENERATED, self.__default_timeout)
        except queue.Empty as error:
            logging.error("Failed to generate OOB data!")
            return None
        return OobData(event_info["data"]["address_with_type"], event_info["data"]["confirmation"],
                       event_info["data"]["randomizer"])

    def ensure_device_bonded(self):
        bond_state = None
        try:
            bond_state = self.__device.ed.pop_event(self.SL4A_EVENT_BONDED, self.__default_bonding_timeout)
        except queue.Empty as error:
            logging.error("Failed to get bond event!")

        assertThat(bond_state).isNotNone()
        logging.info("Bonded: %s", bond_state["data"]["bonded_state"])
        assertThat(bond_state["data"]["bonded_state"]).isEqualTo(True)

    def create_bond_out_of_band(self, oob_data):
        assertThat(oob_data).isNotNone()
        address = oob_data.to_sl4a_address()
        self.__device.sl4a.bluetoothCreateBondOutOfBand(address, self.TRANSPORT_LE, oob_data.confirmation,
                                                        oob_data.randomizer)
        self.ensure_device_bonded()

    def create_bond_numeric_comparison(self, address, transport=TRANSPORT_LE):
        assertThat(address).isNotNone()
        if transport == self.TRANSPORT_LE:
            self.__device.sl4a.bluetoothLeBond(address)
        else:
            self.__device.sl4a.bluetoothBond(address)
        self.ensure_device_bonded()

    def remove_all_bonded_devices(self):
        bonded_devices = self.__device.sl4a.bluetoothGetBondedDevices()
        for device in bonded_devices:
            self.remove_bond(device["address"])

    def remove_bond(self, address):
        self.__device.sl4a.bluetoothUnbond(address)
        bond_state = None
        try:
            bond_state = self.__device.ed.pop_event(self.SL4A_EVENT_UNBONDED, self.__default_timeout)
        except queue.Empty as error:
            logging.error("Failed to get bond event!")

        assertThat(bond_state).isNotNone()
        assertThat(bond_state["data"]["bonded_state"]).isEqualTo(False)

    def close(self):
        self.remove_all_bonded_devices()
        self.__device.sl4a.bluetoothStartPairingHelper(False)
        self.__device = None
