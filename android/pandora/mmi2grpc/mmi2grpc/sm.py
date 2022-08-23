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
"""SMP proxy module."""

from mmi2grpc._helpers import assert_description
from mmi2grpc._proxy import ProfileProxy

from pandora.sm_grpc import SM
from pandora.host_grpc import Host

# The tests needs the MMI to accept pairing confirmation request.
NEEDS_PAIRING_CONFIRMATION = {
    "SM/CEN/EKS/BV-01-C",
    "SM/CEN/JW/BI-04-C",
    "SM/CEN/JW/BI-01-C",
    "SM/CEN/KDU/BV-04-C",
    "SM/CEN/KDU/BV-05-C",
    "SM/CEN/KDU/BV-06-C",
    "SM/CEN/KDU/BV-10-C",
    "SM/CEN/KDU/BV-11-C",
}

ACCEPTS_REMOTE_PAIRING_CONFIRMATION = {
    "SM/CEN/KDU/BI-01-C",
    "SM/CEN/KDU/BI-02-C",
    "SM/CEN/KDU/BI-03-C",
}


class SMProxy(ProfileProxy):

    def __init__(self, channel):
        super().__init__()
        self.sm = SM(channel)
        self.host = Host(channel)
        self.connection = None

    @assert_description
    def MMI_IUT_ENABLE_CONNECTION_SM(self, test, pts_addr: bytes, **kwargs):
        """
        Initiate an connection from the IUT to the PTS.
        """
        self.connection = self.host.ConnectLE(address=pts_addr).connection
        if self.connection and test in ACCEPTS_REMOTE_PAIRING_CONFIRMATION:
            self.sm.ProvidePairingConfirmation(connection=self.connection, pairing_confirmation_value=True)
        return "OK"

    @assert_description
    def MMI_ASK_IUT_PERFORM_PAIRING_PROCESS(self, test, **kwargs):
        """
        Please start pairing process.
        """
        if self.connection:
            self.sm.Pair(connection=self.connection)
            if test in NEEDS_PAIRING_CONFIRMATION:
                self.sm.ProvidePairingConfirmation(connection=self.connection, pairing_confirmation_value=True)

        return "OK"

    @assert_description
    def MMI_IUT_SEND_DISCONNECTION_REQUEST(self, **kwargs):
        """
        Please initiate a disconnection to the PTS.

        Description: Verify that
        the Implementation Under Test(IUT) can initiate a disconnect request to
        PTS.
        """
        if self.connection:
            self.host.DisconnectLE(connection=self.connection)
            self.connection = None
        return "OK"

    def MMI_LESC_NUMERIC_COMPARISON(self, **kwargs):
        """
        Please confirm the following number matches IUT: 385874.
        """

        return "OK"

    @assert_description
    def MMI_ASK_IUT_PERFORM_RESET(self, **kwargs):
        """
        Please reset your device.
        """
        self.host.SoftReset()
        return "OK"
