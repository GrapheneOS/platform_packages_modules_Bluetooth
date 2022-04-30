#!/usr/bin/env python3
#
#   Copyright 2021 - The Android Open Source Project
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
import grpc

from blueberry.facade.topshim import facade_pb2
from blueberry.facade.topshim import facade_pb2_grpc

from google.protobuf import empty_pb2 as empty_proto


class AdapterClient():
    """
    Wrapper gRPC interface to the Topshim/BTIF layer
    """
    # Timeout for async wait
    DEFAULT_TIMEOUT = 2
    __task_list = []
    __channel = None
    __adapter_stub = None
    __adapter_event_stream = None

    def __init__(self, port=8999):
        self.__channel = grpc.aio.insecure_channel("localhost:%d" % port)
        self.__adapter_stub = facade_pb2_grpc.AdapterServiceStub(self.__channel)
        self.__adapter_event_stream = self.__adapter_stub.FetchEvents(facade_pb2.FetchEventsRequest())

    async def terminate(self):
        for task in self.__task_list:
            task.cancel()
            task = None
        self.__task_list.clear()
        await self.__channel.close()

    async def __get_next_event(self, event, future):
        """Get the future of next event from the stream"""
        while True:
            e = await self.__adapter_event_stream.read()

            # Match event by some condition.
            if e.event_type == event:
                future.set_result(e.data)
                break
            else:
                print("Got '%s'; expecting '%s'" % (e.event_type, event))
                print(e)

    async def _listen_for_event(self, event):
        """Start fetching events"""
        future = asyncio.get_running_loop().create_future()
        self.__task_list.append(asyncio.get_running_loop().create_task(self.__get_next_event(event, future)))
        await asyncio.wait_for(future, AdapterClient.DEFAULT_TIMEOUT)
        return future

    async def _verify_adapter_started(self):
        future = await self._listen_for_event(facade_pb2.EventType.ADAPTER_STATE)
        return future.result() == "ON"

    async def toggle_stack(self, is_start=True):
        """Enable/disable the stack"""
        await self.__adapter_stub.ToggleStack(facade_pb2.ToggleStackRequest(start_stack=is_start))
        return await self._verify_adapter_started()

    async def set_enable_page_scan(self):
        """Enable page scan (might be used for A2dp sink to be discoverable)"""
        await self.__adapter_stub.SetDiscoveryMode(facade_pb2.SetDiscoveryModeRequest(enable_page_scan=True))

    async def clear_event_filter(self):
        await self.__adapter_stub.ClearEventFilter(empty_proto.Empty())

    async def clear_event_mask(self):
        await self.__adapter_stub.ClearEventMask(empty_proto.Empty())

    async def clear_filter_accept_list(self):
        await self.__adapter_stub.ClearFilterAcceptList(empty_proto.Empty())

    async def disconnect_all_acls(self):
        await self.__adapter_stub.DisconnectAllAcls(empty_proto.Empty())

    async def le_rand(self):
        await self.__adapter_stub.LeRand(empty_proto.Empty())
        future = await self._listen_for_event(facade_pb2.EventType.LE_RAND)
        #        await asyncio.wait_for(future, AdapterClient.DEFAULT_TIMEOUT)
        return future.result()

    async def restore_filter_accept_list(self):
        await self.__adapter_stub.RestoreFilterAcceptList(empty_proto.Empty())

    async def set_default_event_mask(self):
        await self.__adapter_stub.SetDefaultEventMask(empty_proto.Empty())

    async def set_event_filter_inquiry_result_all_devices(self):
        await self.__adapter_stub.SetEventFilterInquiryResultAllDevices(empty_proto.Empty())


class A2dpAutomationHelper():
    """Invoke gRPC on topshim for A2DP testing"""

    def __init__(self, port=8999):
        self.__channel = grpc.insecure_channel("localhost:%d" % port)
        self.media_stub = facade_pb2_grpc.MediaServiceStub(self.__channel)

    """Start A2dp source profile service"""

    def start_source(self):
        self.media_stub.StartA2dp(facade_pb2.StartA2dpRequest(start_a2dp_source=True))

    """Start A2dp sink profile service"""

    def start_sink(self):
        self.media_stub.StartA2dp(facade_pb2.StartA2dpRequest(start_a2dp_sink=True))

    """Initialize an A2dp connection from source to sink"""

    def source_connect_to_remote(self, address="11:22:33:44:55:66"):
        self.media_stub.A2dpSourceConnect(facade_pb2.A2dpSourceConnectRequest(address=address))
