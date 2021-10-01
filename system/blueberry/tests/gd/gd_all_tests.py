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

from blueberry.tests.gd.cert.cert_self_test_blueberry import CertSelfTestBb
from blueberry.tests.gd.hal.simple_hal_test_blueberry import SimpleHalTestBb
from blueberry.tests.gd.hci.acl_manager_test_blueberry import AclManagerTestBb
from blueberry.tests.gd.hci.controller_test_blueberry import ControllerTestBb
from blueberry.tests.gd.hci.direct_hci_test_blueberry import DirectHciTestBb
from blueberry.tests.gd.hci.le_acl_manager_test_blueberry import LeAclManagerTestBb
from blueberry.tests.gd.hci.le_advertising_manager_test_blueberry import LeAdvertisingManagerTestBb
from blueberry.tests.gd.hci.le_scanning_manager_test_blueberry import LeScanningManagerTestBb
from blueberry.tests.gd.hci.le_scanning_with_security_test_blueberry import LeScanningWithSecurityTestBb
from blueberry.tests.gd.iso.le_iso_test_blueberry import LeIsoTestBb
from blueberry.tests.gd.l2cap.classic.l2cap_performance_test_blueberry import L2capPerformanceTestBb
from blueberry.tests.gd.l2cap.classic.l2cap_test_blueberry import L2capTestBb
from blueberry.tests.gd.l2cap.le.dual_l2cap_test_blueberry import DualL2capTestBb
from blueberry.tests.gd.l2cap.le.le_l2cap_test_blueberry import LeL2capTestBb
from blueberry.tests.gd.neighbor.neighbor_test_blueberry import NeighborTestBb
from blueberry.tests.gd.security.le_security_test_blueberry import LeSecurityTestBb
from blueberry.tests.gd.security.security_test_blueberry import SecurityTestBb
from blueberry.tests.gd.shim.shim_test_blueberry import ShimTestBb
from blueberry.tests.gd.shim.stack_test_blueberry import StackTestBb

from mobly import suite_runner

ALL_TESTS = {
    CertSelfTestBb, SimpleHalTestBb, AclManagerTestBb, ControllerTestBb, DirectHciTestBb, LeAclManagerTestBb,
    LeAdvertisingManagerTestBb, LeScanningManagerTestBb, LeScanningWithSecurityTestBb, LeIsoTestBb,
    L2capPerformanceTestBb, L2capTestBb, DualL2capTestBb, LeL2capTestBb, NeighborTestBb, LeSecurityTestBb,
    SecurityTestBb, ShimTestBb, StackTestBb
}

DISABLED_TESTS = set()

ENABLED_TESTS = list(ALL_TESTS - DISABLED_TESTS)

if __name__ == '__main__':
    suite_runner.run_suite(ENABLED_TESTS)
