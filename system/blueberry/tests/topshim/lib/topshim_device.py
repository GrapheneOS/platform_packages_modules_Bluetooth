#!/usr/bin/env python3
#   Copyright 2019 - The Android Open Source Project
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

import asyncio
import logging

from blueberry.tests.gd.cert.gd_device import GdHostOnlyDevice
from blueberry.tests.gd.cert.gd_device import MOBLY_CONTROLLER_CONFIG_NAME
from blueberry.tests.gd.cert.os_utils import get_gd_root
from blueberry.tests.topshim.lib.async_closable import AsyncClosable
from blueberry.tests.topshim.lib.async_closable import asyncSafeClose
from blueberry.tests.topshim.lib.oob_data import OobData
from blueberry.tests.topshim.lib.gatt_client import GattClient


def create(configs):
    return get_instances_with_configs(configs)


def destroy(devices):
    pass


def replace_vars_for_topshim(string, config):
    serial_number = config.get("serial_number")
    if serial_number is None:
        serial_number = ""
    rootcanal_port = config.get("rootcanal_port")
    if rootcanal_port is None:
        rootcanal_port = ""
    if serial_number == "DUT" or serial_number == "CERT":
        raise Exception("Did you forget to configure the serial number?")
    # We run bt_topshim_facade instead of bluetooth_stack_with_facade
    return string.replace("$GD_ROOT", get_gd_root()) \
                 .replace("bluetooth_stack_with_facade", "bt_topshim_facade") \
                 .replace("$(grpc_port)", config.get("grpc_port")) \
                 .replace("$(grpc_root_server_port)", config.get("grpc_root_server_port")) \
                 .replace("$(rootcanal_port)", rootcanal_port) \
                 .replace("$(signal_port)", config.get("signal_port")) \
                 .replace("$(serial_number)", serial_number)


def get_instances_with_configs(configs):
    logging.info(configs)
    devices = []
    for config in configs:
        resolved_cmd = []
        for arg in config["cmd"]:
            logging.debug(arg)
            resolved_cmd.append(replace_vars_for_topshim(arg, config))
        verbose_mode = bool(config.get('verbose_mode', False))
        device = GdHostOnlyDevice(config["grpc_port"], "-1", config["signal_port"], resolved_cmd, config["label"],
                                  MOBLY_CONTROLLER_CONFIG_NAME, config["name"], verbose_mode)
        device.setup()
        devices.append(device)
    return devices


TRANSPORT_CLASSIC = 1
TRANSPORT_LE = 2


class TopshimDevice(AsyncClosable):
    __adapter = None
    __gatt = None
    __security = None

    async def __le_rand_wrapper(self, async_fn):
        result = await async_fn
        await self.__adapter.le_rand()
        le_rand_future = await self.__adapter._listen_for_event(facade_pb2.EventType.LE_RAND)
        return result

    def __post(self, async_fn):
        return asyncio.get_event_loop().run_until_complete(async_fn)

    def __init__(self, adapter, gatt, security):
        self.__adapter = adapter
        self.__gatt = gatt
        self.__security = security

    async def close(self):
        """
        Implement abstract method to close out any streams or jobs.
        """
        await asyncSafeClose(self.__adapter)
        await asyncSafeClose(self.__gatt)
        await asyncSafeClose(self.__security)

    def enable_page_scan(self):
        self.__post(self.__adapter.enable_page_scan())

    def disable_page_scan(self):
        self.__post(self.__adapter.disable_page_scan())

    def start_advertising(self):
        """
        Starts BLE Advertiser for the stack.
        Assumes stack defaults.  Which in our case would be RRPA
        """
        self.__post(self.__gatt.advertising_enable())

    def stop_advertising(self):
        """
        Stop BLE Advertiser.
        """
        self.__post(self.__gatt.advertising_disable())

    def start_scanning(self):
        pass

    def stop_scanning(self):
        pass

    def clear_event_mask(self):
        self.__post(self.__adapter.clear_event_mask())

    def clear_event_filter(self):
        self.__post(self.__adapter.clear_event_filter())

    def clear_filter_accept_list(self):
        self.__post(self.__adapter.clear_filter_accept_list())

    def disconnect_all_acls(self):
        self.__post(self.__adapter.disconnect_all_acls())

    def allow_wake_by_hid(self):
        self.__post(self.__adapter.allow_wake_by_hid())

    def set_default_event_mask_except(self, mask, le_mask):
        self.__post(self.__adapter.set_default_event_mask(mask, le_mask))

    def set_event_filter_inquiry_result_all_devices(self):
        self.__post(self.__adapter.set_event_filter_inquiry_result_all_devices())

    def set_event_filter_connection_setup_all_devices(self):
        self.__post(self.__adapter.set_event_filter_connection_setup_all_devices())

    def le_rand(self):
        self.__post(self.__adapter.le_rand())

    def remove_bonded_device(self, address):
        """
        Removes a bonding entry for a given address.
        """
        self.__post(self.__security.remove_bond(address))

    def generate_local_oob_data(self, transport=TRANSPORT_LE):
        """
        Generate local Out of Band data

        @param transport TRANSPORT_CLASSIC or TRANSPORT_LE

        @return a future to await on fo the data
        """
        f = self.__post(self.__security.generate_local_oob_data(transport))

        async def waiter(f):
            data = await f
            data_list = data.split(";")
            return OobData(data_list[0], data_list[1], data_list[2], data_list[3], data_list[4])

        return asyncio.get_event_loop().run_until_complete(waiter(f))

    def set_local_io_caps(self, io_capability=0):
        f = self.__post(self.__adapter.set_local_io_caps(io_capability))

        async def waiter(f):
            data = await f
            data_list = data.split(" :: ")
            status, properties = data_list[0].strip(), data_list[1].strip()
            properties = list(properties[1:-1].strip().split(","))
            return (status, properties)

        return asyncio.get_event_loop().run_until_complete(waiter(f))
