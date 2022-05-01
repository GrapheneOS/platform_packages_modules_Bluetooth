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


class AdapterTest(TopshimBaseTest):

    def test_verify_adapter_started(self):
        print("Adapter is verified when test starts")


if __name__ == "__main__":
    test_runner.main()
