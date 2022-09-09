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

from blueberry.tests.gd.cert.truth import assertThat
from blueberry.tests.topshim.lib.topshim_base_test import TopshimBaseTest
from blueberry.tests.topshim.lib.adapter_client import AdapterClient

from mobly import test_runner


class SuspendTest(TopshimBaseTest):

    async def __verify_no_wake_suspend(self):
        # Start suspend work
        await self.dut_adapter.clear_event_mask()
        await self.dut_adapter.clear_event_filter()
        await self.dut_adapter.clear_filter_accept_list()
        await self.dut_gatt.advertising_disable()
        await self.dut_gatt.stop_scan()
        await self.dut_adapter.disconnect_all_acls()
        return await self.dut_adapter.le_rand()

    async def __verify_no_wake_resume(self):
        # Start resume work
        await self.dut_adapter.set_default_event_mask()
        await self.dut_adapter.set_event_filter_inquiry_result_all_devices()
        await self.dut_adapter.set_event_filter_connection_setup_all_devices()
        return await self.dut_adapter.le_rand()

    async def __verify_wakeful_suspend(self, is_a2dp_connected):
        await self.dut_adapter.clear_event_mask()
        await self.dut_adapter.clear_event_filter()
        await self.dut_adapter.clear_filter_accept_list()
        await self.dut_gatt.advertising_disable()
        await self.dut_gatt.stop_scan()
        if is_a2dp_connected:
            # await self.media_server.disconnect_a2dp()
            pass
        await self.dut_adapter.disconnect_all_acls()
        await self.dut_adapter.allow_wake_by_hid()
        return await self.dut_adapter.le_rand()

    async def __verify_wakeful_resume(self, was_a2dp_connected):
        # Start resume work
        await self.dut_adapter.set_default_event_mask()
        await self.dut_adapter.set_event_filter_inquiry_result_all_devices()
        await self.dut_adapter.set_event_filter_connection_setup_all_devices()
        if was_a2dp_connected:
            # restore filter accept list?
            await self.dut_adapter.restore_filter_accept_list()
            # reconnect a2dp
            # await self.media_server.reconnect_last_a2dp()
            # await self.gatt.restart_all_previous_advertising()
        await self.dut_gatt.advertising_enable()
        return await self.dut_adapter.le_rand()

    def test_no_wake_suspend(self):
        self.post(self.__verify_no_wake_suspend())

    def test_no_wake_resume(self):
        self.post(self.__verify_no_wake_resume())

    def test_no_wake_suspend_then_resume(self):
        self.post(self.__verify_no_wake_suspend())
        self.post(self.__verify_no_wake_resume())

    def test_no_wake_suspend_then_resume_then_suspend(self):
        self.post(self.__verify_no_wake_suspend())
        self.post(self.__verify_no_wake_resume())
        self.post(self.__verify_no_wake_suspend())

    def test_wakeful_suspend_no_a2dp(self):
        self.post(self.__verify_wakeful_suspend(False))

    def test_wakeful_resume_no_a2dp(self):
        self.post(self.__verify_wakeful_resume(False))

    def test_wakeful_suspend_then_resume_no_a2dp(self):
        self.post(self.__verify_wakeful_suspend(False))
        self.post(self.__verify_wakeful_resume(False))

    def test_wakeful_suspend_then_resume_then_suspend_no_a2dp(self):
        self.post(self.__verify_wakeful_suspend(False))
        self.post(self.__verify_wakeful_resume(False))
        self.post(self.__verify_wakeful_suspend(False))


if __name__ == "__main__":
    test_runner.main()
