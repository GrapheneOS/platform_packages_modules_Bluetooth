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
import os
import unittest


class TopshimBaseTest(unittest.IsolatedAsyncioTestCase):

    async def asyncSetUp(self):
        """
        Run aprotoc to generate python proto, and open root-canal and bt_topshim_facade
        """
        assert os.getenv(
            "ANDROID_BUILD_TOP"
        ) is not None, "Currently we only support run with Android tree, with bt_topshim_facade and root-canal built"
        # Run root-canal and DUT process.  STDERR should be saved by the process itself.
        self.root_canal = await asyncio.create_subprocess_exec("root-canal", stderr=asyncio.subprocess.DEVNULL)
        self.dut = await asyncio.create_subprocess_exec("bt_topshim_facade", stderr=asyncio.subprocess.DEVNULL)

        # Wait for gRPC channel to open
        await asyncio.sleep(2)

    async def asyncTearDown(self):
        self.dut.terminate()
        self.root_canal.terminate()
