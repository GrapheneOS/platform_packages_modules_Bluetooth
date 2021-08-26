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
from security.cert.le_security_test_lib import LeSecurityTestBase

from mobly import asserts
from mobly import test_runner


class LeSecurityTestBb(gd_base_test.GdBaseTestClass, LeSecurityTestBase):

    def setup_class(self):
        gd_base_test.GdBaseTestClass.setup_class(self, dut_module='SECURITY', cert_module='SECURITY')

    def setup_test(self):
        asserts.skip("Unhandled race condition - Flaky test")
        gd_base_test.GdBaseTestClass.setup_test(self)
        LeSecurityTestBase.setup_test(self, self.dut, self.cert)

    def teardown_test(self):
        return  # test skipped
        LeSecurityTestBase.teardown_test(self)
        gd_base_test.GdBaseTestClass.teardown_test(self)


if __name__ == '__main__':
    test_runner.main()
