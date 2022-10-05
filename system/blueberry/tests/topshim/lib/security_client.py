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

import grpc

from blueberry.facade.topshim import facade_pb2
from blueberry.facade.topshim import facade_pb2_grpc
from blueberry.tests.topshim.lib.async_closable import AsyncClosable
from blueberry.tests.topshim.lib.async_closable import asyncSafeClose

from google.protobuf import empty_pb2 as empty_proto


class SecurityClient(AsyncClosable):
    """
    Wrapper gRPC interface to the GATT Service
    """
    # Timeout for async wait
    DEFAULT_TIMEOUT = 2
    __task_list = []
    __channel = None
    __security_stub = None
    __adapter_event_stream = None
    __adapter_client = None

    def __init__(self, adapter_client, port=8999):
        self.__channel = grpc.aio.insecure_channel("localhost:%d" % port)
        self.__security_stub = facade_pb2_grpc.SecurityServiceStub(self.__channel)
        self.__adapter_client = adapter_client
        #self.__gatt_event_stream = self.__security_stub.FetchEvents(facade_pb2.FetchEventsRequest())

    async def close(self):
        """
        Terminate the current tasks
        """
        for task in self.__task_list:
            task.cancel()
            task = None
        self.__task_list.clear()
        await self.__channel.close()

    async def remove_bond(self, address):
        """
        Removes a bonding entry for a given address
        """
        await self.__security_stub.RemoveBond(facade_pb2.RemoveBondRequest(address=address))
        return await self.__adapter_client.le_rand()

    async def bond_using_numeric_comparison(self, address):
        """
        Bond to a given address using numeric comparison method
        """
        # Set IO Capabilities
        # Enable Page scan
        # Become discoverable
        # Discover device
        # Initiate bond
        return await self.__adapter_client.le_rand()
