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

from mmi2grpc._helpers import assert_description
from mmi2grpc._proxy import ProfileProxy

from pandora.gatt_grpc import GATT
from pandora.host_grpc import Host


class GATTProxy(ProfileProxy):

    def __init__(self, channel):
        super().__init__()
        self.gatt = GATT(channel)
        self.host = Host(channel)
        self.connection = None

    @assert_description
    def MMI_IUT_INITIATE_CONNECTION(self, pts_addr: bytes, **kwargs):
        """
        Please initiate a GATT connection to the PTS.

        Description: Verify that
        the Implementation Under Test (IUT) can initiate GATT connect request to
        PTS.
        """

        self.connection = self.host.ConnectLE(address=pts_addr).connection
        return "OK"

    @assert_description
    def MMI_IUT_MTU_EXCHANGE(self, **kwargs):
        """
        Please send exchange MTU command to the PTS.

        Description: Verify that
        the Implementation Under Test (IUT) can send Exchange MTU command to the
        tester.
        """

        assert self.connection is not None
        self.gatt.ExchangeMTU(mtu=512, connection=self.connection)
        return "OK"

    def MMI_IUT_SEND_PREPARE_WRITE_REQUEST_VALID_SIZE(self, description: str, **kwargs):
        """
        Please send prepare write request with handle = 'FFFF'O and size = 'XXX'
        to the PTS.

        Description: Verify that the Implementation Under Test
        (IUT) can send data according to negotiate MTU size.
        """

        assert self.connection is not None
        matches = re.findall("'([a0-Z9]*)'O and size = '([a0-Z9]*)'", description)
        handle = int(matches[0][0], 16)
        data = bytes([1]) * int(matches[0][1])
        self.gatt.WriteCharacteristicFromHandle(connection=self.connection, handle=handle, value=data)
        return "OK"

    @assert_description
    def MMI_IUT_INITIATE_DISCONNECTION(self, **kwargs):
        """
        Please initiate a GATT disconnection to the PTS.

        Description: Verify
        that the Implementation Under Test (IUT) can initiate GATT disconnect
        request to PTS.
        """

        assert self.connection is not None
        self.host.DisconnectLE(connection=self.connection)
        self.connection = None
        return "OK"
