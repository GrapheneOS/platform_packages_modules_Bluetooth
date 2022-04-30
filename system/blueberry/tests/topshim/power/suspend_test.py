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

import asyncio

from blueberry.tests.gd.cert.truth import assertThat
from blueberry.tests.topshim.lib.topshim_base_test import TopshimBaseTest
from blueberry.tests.topshim.lib.adapter_client import AdapterClient

from mobly import test_runner


class SuspendTest(TopshimBaseTest):

    async def __verify_disconnected_suspend(self):
        # Start suspend work
        await self.dut_adapter.clear_event_filter()
        await self.dut_adapter.clear_event_mask()
        await self.dut_adapter.clear_filter_accept_list()
        # TODO(optedoblivion): Find a better way to disconnect active ACLs
        # await self.dut_adapter.disconnect_all_acls()
        random = await self.dut_adapter.le_rand()
        return random

    async def __verify_disconnected_resume(self):
        # Start resume work
        await self.dut_adapter.set_event_filter_inquiry_result_all_devices()
        await self.dut_adapter.set_default_event_mask()
        await self.dut_adapter.restore_filter_accept_list()
        random = await self.dut_adapter.le_rand()
        return random

    def test_disconnected_suspend(self):
        asyncio.get_event_loop().run_until_complete(self.__verify_disconnected_suspend())

    def test_disconnected_resume(self):
        asyncio.get_event_loop().run_until_complete(self.__verify_disconnected_resume())

    def test_disconnected_suspend_then_resume(self):
        asyncio.get_event_loop().run_until_complete(self.__verify_disconnected_suspend())
        asyncio.get_event_loop().run_until_complete(self.__verify_disconnected_resume())

    def test_disconnected_suspend_then_resume_then_suspend(self):
        asyncio.get_event_loop().run_until_complete(self.__verify_disconnected_suspend())
        asyncio.get_event_loop().run_until_complete(self.__verify_disconnected_resume())
        asyncio.get_event_loop().run_until_complete(self.__verify_disconnected_suspend())
