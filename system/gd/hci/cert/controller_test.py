#!/usr/bin/env python3
#
#   Copyright 2020 - The Android Open Source Project
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

from cert.gd_base_test import GdBaseTestClass
from hci.cert.controller_test_lib import ControllerTestBase


class ControllerTest(GdBaseTestClass, ControllerTestBase):

    def setup_class(self):
        GdBaseTestClass.setup_class(self, dut_module='HCI_INTERFACES', cert_module='HCI_INTERFACES')

    def test_get_addresses(self):
        ControllerTestBase.test_get_addresses(self, self.dut, self.cert)

    def test_write_local_name(self):
        ControllerTestBase.test_write_local_name(self, self.dut, self.cert)

    def test_extended_advertising_support(self):
        ControllerTestBase.test_extended_advertising_support(self, self.dut, self.cert)
