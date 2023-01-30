# Copyright 2022 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import re
import sys

from mmi2grpc._helpers import assert_description
from mmi2grpc._proxy import ProfileProxy

from pandora_experimental.pan_grpc import PAN
from pandora_experimental.host_grpc import Host


class PANProxy(ProfileProxy):

    def __init__(self, channel):
        super().__init__(channel)
        self.pan = PAN(channel)
        self.host = Host(channel)
        self.connection = None

    def TSC_BNEP_mmi_iut_accept_transport(self, pts_addr: bytes, **kwargs):
        """
        Take action to accept the PAN transport from the tester.

        Note: The IUT
        must accept the Basic L2cap configuration for this test case.
        """

        # Only accepting pairing here.
        self.pan.EnableTethering()
        self.host.WaitConnection(address=pts_addr)
        #self.connection = self.pan.ConnectPan(addr=pts_addr).connection
        return "OK"

    @assert_description
    def TSC_BNEP_mmi_iut_accept_setup(self, pts_addr: bytes, **kwargs):
        """
        Take action to accept setup connection.
        """

        return "OK"

    def TSC_BNEP_mmi_iut_initiate_transport(self, pts_addr: bytes, **kwargs):
        """
        Take action to initiate an PAN transport .

        Note: The IUT must require
        Basic L2cap configuration for this test case.
        """
        self.host.Connect(address=pts_addr)
        #self.pan.ConnectPan(connection=self.connection)
        #self.connection = self.host.WaitConnection(address=pts_addr).connection

        return "OK"

    def TSC_BNEP_mmi_iut_initiate_setup(self, **kwargs):
        """
        Take action to initiate setup connection
        """

        return "OK"

    @assert_description
    def TSC_BNEP_mmi_iut_accept_unknown(self, **kwargs):
        """
        Take action to response to reserve control message
        """
        return "OK"

    @assert_description
    def TSC_BNEP_mmi_iut_accept_filter_network(self, **kwargs):
        """
        Take action to accept filter network.
        """
        return "OK"

    @assert_description
    def TSC_BNEP_mmi_iut_accept_filter_multicast(self, **kwargs):
        """
        Take action to accept filter multicast.
        """
        return "OK"

    @assert_description
    def TSC_BNEP_mmi_iut_confirm_general_ethernet(self, **kwargs):
        """
        Please confirm IUT received general ethernet request.
        """
        return "OK"

    @assert_description
    def TSC_PAN_mmi_iut_send_arp_probe_request(self, **kwargs):
        """
        Take action to send ARP probe request for the process of choosing a
        valid LINKLOCAL IP address. 

        Notes: 
        (1) It may be necessary to clear
        the assigned IP on the IUT first in order to trigger ARP request. 
        (2)
        PTS anticipates an ARP request which has the destination protocol
        address field matching the value set in TSPX_iut_ip_address.
        """

        return "OK"

    def TS_MTC_BNEPEX_iut_accept_general_ethernet(self, **kwargs):
        return "OK"

    @assert_description
    def TSC_BNEP_mmi_iut_accept_general_ethernet(self, **kwargs):
        """
        Take action to accept general ethernet.
        """

        return "OK"

    @assert_description
    def TSC_PAN_mmi_iut_dhcp_discovery_request(self, **kwargs):
        """
        Take action to send dhcp discovery request
        """

        return "OK"

    @assert_description
    def TSC_PAN_mmi_iut_icmp_echo_reply(self, **kwargs):
        """
        Take action to respond with ICMP echo reply
        """

        return "OK"
