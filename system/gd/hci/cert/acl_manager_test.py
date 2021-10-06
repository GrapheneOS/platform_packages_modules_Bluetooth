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
from hci.cert.acl_manager_test_lib import AclManagerTestBase


class AclManagerTest(GdBaseTestClass, AclManagerTestBase):

    def setup_class(self):
        GdBaseTestClass.setup_class(self, dut_module='HCI_INTERFACES', cert_module='HCI')

    # todo: move into GdBaseTestClass, based on modules inited
    def setup_test(self):
        GdBaseTestClass.setup_test(self)
        AclManagerTestBase.setup_test(self, self.dut, self.cert)

    def teardown_test(self):
        AclManagerTestBase.teardown_test(self)
        GdBaseTestClass.teardown_test(self)

    def test_dut_connects(self):
        AclManagerTestBase.test_dut_connects(self)

    def test_cert_connects(self):
        AclManagerTestBase.test_cert_connects(self)

    def test_reject_broadcast(self):
        dut_address = self.dut.hci_controller.GetMacAddressSimple()
        self.dut.neighbor.EnablePageScan(neighbor_facade.EnableMsg(enabled=True))

        self.dut_acl_manager.listen_for_an_incoming_connection()
        self.cert_hci.initiate_connection(dut_address)
        with self.dut_acl_manager.complete_incoming_connection() as dut_acl:
            cert_acl = self.cert_hci.complete_connection()

            cert_acl.send(hci_packets.PacketBoundaryFlag.FIRST_AUTOMATICALLY_FLUSHABLE,
                          hci_packets.BroadcastFlag.ACTIVE_PERIPHERAL_BROADCAST,
                          b'\x26\x00\x07\x00This is a Broadcast from the Cert')
            assertThat(dut_acl).emitsNone()

            cert_acl.send(hci_packets.PacketBoundaryFlag.FIRST_AUTOMATICALLY_FLUSHABLE,
                          hci_packets.BroadcastFlag.POINT_TO_POINT,
                          b'\x26\x00\x07\x00This is just SomeAclData from the Cert')
            assertThat(dut_acl).emits(lambda packet: b'SomeAclData' in packet.payload)

    def test_cert_connects_disconnects(self):
        AclManagerTestBase.test_cert_connects_disconnects(self)

    def test_recombination_l2cap_packet(self):
        AclManagerTestBase.test_recombination_l2cap_packet(self)
