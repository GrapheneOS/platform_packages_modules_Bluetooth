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
    __task_list = []
    __channel = None
    __security = None
    __adapter = None

    def __init__(self, adapter, port=8999):
        self.__channel = grpc.aio.insecure_channel("localhost:%d" % port)
        self.__security = facade_pb2_grpc.SecurityServiceStub(self.__channel)
        self.__adapter = adapter

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
        await self.__security.RemoveBond(facade_pb2.RemoveBondRequest(address=address))

    async def generate_local_oob_data(self, transport):
        await self.__security.GenerateLocalOobData(facade_pb2.GenerateOobDataRequest(transport=transport))
        future = await self.__adapter._listen_for_event(facade_pb2.EventType.GENERATE_LOCAL_OOB_DATA)
        return future
