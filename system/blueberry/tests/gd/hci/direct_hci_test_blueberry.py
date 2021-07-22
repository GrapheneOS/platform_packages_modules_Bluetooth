#!/usr/bin/env python3
#
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

from blueberry.tests.gd.cert import gd_base_test
from hci.cert.direct_hci_test_lib import DirectHciTestBase
from mobly import test_runner


class DirectHciTestBb(gd_base_test.GdBaseTestClass, DirectHciTestBase):

    def setup_class(self):
        gd_base_test.GdBaseTestClass.setup_class(self, dut_module='HCI', cert_module='HAL')

    def setup_test(self):
        gd_base_test.GdBaseTestClass.setup_test(self)
        DirectHciTestBase.setup_test(self, self.dut, self.cert)

    def teardown_test(self):
        DirectHciTestBase.teardown_test(self)
        gd_base_test.GdBaseTestClass.teardown_test(self)


if __name__ == '__main__':
    test_runner.main()
