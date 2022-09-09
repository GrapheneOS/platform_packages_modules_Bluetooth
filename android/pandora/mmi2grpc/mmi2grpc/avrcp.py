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
"""AVRCP proxy module."""

import time
from typing import Optional

from grpc import RpcError

from mmi2grpc._audio import AudioSignal
from mmi2grpc._helpers import assert_description
from mmi2grpc._proxy import ProfileProxy
from pandora_experimental.a2dp_grpc import A2DP
from pandora_experimental.a2dp_pb2 import Sink, Source
from pandora_experimental.avrcp_grpc import AVRCP
from pandora_experimental.host_grpc import Host
from pandora_experimental.host_pb2 import Connection


class AVRCPProxy(ProfileProxy):
    """AVRCP proxy.

    Implements AVRCP and AVCTP PTS MMIs.
    """

    connection: Optional[Connection] = None
    sink: Optional[Sink] = None
    source: Optional[Source] = None

    def __init__(self, channel):
        super().__init__()

        self.host = Host(channel)
        self.a2dp = A2DP(channel)
        self.avrcp = AVRCP(channel)

    @assert_description
    def TSC_AVDTP_mmi_iut_accept_connect(self, test: str, pts_addr: bytes, **kwargs):
        """
        If necessary, take action to accept the AVDTP Signaling Channel
        Connection initiated by the tester.

        Description: Make sure the IUT
        (Implementation Under Test) is in a state to accept incoming Bluetooth
        connections.  Some devices may need to be on a specific screen, like a
        Bluetooth settings screen, in order to pair with PTS.  If the IUT is
        still having problems pairing with PTS, try running a test case where
        the IUT connects to PTS to establish pairing.

        """
        if "CT" in test:

            self.connection = self.host.WaitConnection(address=pts_addr).connection
            try:
                self.source = self.a2dp.WaitSource(connection=self.connection).source
            except RpcError:
                pass
        else:
            self.connection = self.host.WaitConnection(address=pts_addr).connection
            try:
                self.sink = self.a2dp.WaitSink(connection=self.connection).sink
            except RpcError:
                pass
        return "OK"

    @assert_description
    def TSC_AVCTP_mmi_iut_accept_connect_control(self, **kwargs):
        """
        Please wait while PTS creates an AVCTP control channel connection.
        Action: Make sure the IUT is in a connectable state.

        """
        #TODO: Wait for connection to be established and AVCTP control channel to be open
        return "OK"

    @assert_description
    def TSC_AVCTP_mmi_iut_accept_disconnect_control(self, **kwargs):
        """
        Please wait while PTS disconnects the AVCTP control channel connection.

        """
        return "OK"

    @assert_description
    def TSC_AVRCP_mmi_iut_accept_unit_info(self, **kwargs):
        """
        Take action to send a valid response to the [Unit Info] command sent by
        the PTS.

        """
        return "OK"

    @assert_description
    def TSC_AVRCP_mmi_iut_accept_subunit_info(self, **kwargs):
        """
        Take action to send a valid response to the [Subunit Info] command sent
        by the PTS.

        """
        return "OK"

    @assert_description
    def TSC_AVCTP_mmi_iut_accept_connect_browsing(self, **kwargs):
        """
        Please wait while PTS creates an AVCTP browsing channel connection.
        Action: Make sure the IUT is in a connectable state.

        """
        return "OK"

    @assert_description
    def TSC_AVRCP_mmi_iut_accept_get_folder_items_media_player_list(self, **kwargs):
        """
        Take action to send a valid response to the [Get Folder Items] with the
        scope <Media Player List> command sent by the PTS.

        """
        return "OK"

    @assert_description
    def TSC_AVRCP_mmi_user_confirm_media_players(self, **kwargs):
        """
        Do the following media players exist on the IUT?

        Media Player:
        Bluetooth Player


        Note: Some media players may not be listed above.

        """
        #TODO: Verify the media players available
        return "OK"

    @assert_description
    def TSC_AVP_mmi_iut_initiate_disconnect(self, **kwargs):
        """
        Take action to disconnect all A2DP and/or AVRCP connections.

        """
        if self.connection is None:
            self.connection = self.host.GetConnection(address=pts_addr).connection
        self.host.Disconnect(connection=self.connection)
        self.connection = None
        self.sink = None
        self.source = None
        return "OK"

    @assert_description
    def TSC_AVRCP_mmi_iut_accept_set_addressed_player(self, **kwargs):
        """
        Take action to send a valid response to the [Set Addressed Player]
        command sent by the PTS.

        """
        return "OK"

    @assert_description
    def _mmi_1002(self, test: str, pts_addr: bytes, **kwargs):
        """
        If necessary, take action to accept the AVDTP Signaling Channel
        Connection initiated by the tester.

        Description: Make sure the IUT
        (Implementation Under Test) is in a state to accept incoming Bluetooth
        connections.  Some devices may need to be on a specific screen, like a
        Bluetooth settings screen, in order to pair with PTS.  If the IUT is
        still having problems pairing with PTS, try running a test case where
        the IUT connects to PTS to establish pairing.
        """
        self.connection = self.host.WaitConnection(address=pts_addr).connection
        try:
            self.sink = self.a2dp.WaitSink(connection=self.connection).sink
        except RpcError:
            pass

        return "OK"

    @assert_description
    def TSC_AVCTP_mmi_send_AVCT_ConnectRsp(self, **kwargs):
        """
        Upon a call to the callback function ConnectInd_CBTest_System,  use the
        Upper Tester to send an AVCT_ConnectRsp message to the IUT with the
        following parameter values:
           * BD_ADDR = BD_ADDRLower_Tester
           *
        Connect Result = Valid value for L2CAP connect response result.
           *
        Status = Valid value for L2CAP connect response status.

        The IUT should
        then initiate an L2CAP_ConnectRsp and L2CAP_ConfigRsp.
        """
        return "OK"

    @assert_description
    def TSC_AVCTP_mmi_verify_ConnectInd_CB(self, **kwargs):
        """
        Press 'OK' if the following conditions were met :

        1. The IUT returns
        the following AVCT_EventRegistration output parameters to the Upper
        Tester:
           * Result = 0x0000 (Event successfully registered)

        2. The IUT
        calls the ConnectInd_CBTest_System function in the Upper Tester with the
        following parameter values:
           * BD_ADDR = BD_ADDRLower_Tester

        3. After
        reception of any expected AVCT_EventRegistration command from the Upper
        Tester and the L2CAP_ConnectReq from the Lower Tester, the IUT issues an
        L2CAP_ConnectRsp to the Lower Tester.
        """
        return "OK"

    @assert_description
    def TSC_AVCTP_mmi_register_ConnectInd_CB(self, **kwargs):
        """
        Using the Upper Tester register the function ConnectInd_CBTest_System
        for callback on the AVCT_Connect_Ind event by sending an
        AVCT_EventRegistration command to the IUT with the following parameter
        values:
           * Event = AVCT_Connect_Ind
           * Callback =
        ConnectInd_CBTest_System
           * PID = PIDTest_System

        Press 'OK' to
        continue once the IUT has responded.
        """
        return "OK"

    @assert_description
    def TSC_AVCTP_mmi_register_DisconnectInd_CB(self, **kwargs):
        """
        Using the Upper Tester register the DisconnectInd_CBTest_System function
        for callback on the AVCT_Disconnect_Ind event by sending an
        AVCT_EventRegistration command to the IUT with the following parameter
        values :
           * Event = AVCT_Disconnect_Ind
           * Callback =
        DisconnectInd_CBTest_System
           * PID = PIDTest_System

        Press 'OK' to
        continue once the IUT has responded.
        """
        return "OK"

    @assert_description
    def TSC_AVCTP_mmi_verify_DisconnectInd_CB(self, **kwargs):
        """
        Press 'OK' if the following conditions were met :

        1. The IUT returns
        the following AVCT_EventRegistration output parameters to the Upper
        Tester:
           * Result = 0x0000 (Event successfully registered)

        2. The IUT
        calls the DisconnectInd_CBTest_System function in the Upper Tester with
        the following parameter values:
           * BD_ADDR = BD_ADDRLower_Tester
        """
        return "OK"

    @assert_description
    def TSC_AVCTP_mmi_verify_AVCT_SendMessage_TG(self, **kwargs):
        """
        Press 'OK' if the following conditions were met :

        1. The IUT returns
        the following AVCT_EventRegistration output parameters to the Upper
        Tester:
           * Result = 0x0000 (Event successfully registered)

        2. The IUT
        calls the MessageInd_CBTest_System callback function of the test system
        with the following parameters:
           * BD_ADDR = BD_ADDRTest_System
           *
        Transaction = TRANSTest_System
           * Type = 0
           * Data =
        DATA[]Lower_Tester
           * Length = LengthOf(DATA[]Lower_Tester)
        """
        return "OK"

    @assert_description
    def TSC_AVCTP_mmi_iut_reject_invalid_profile_id(self, **kwargs):
        """
        Take action to reject the AVCTP DATA request with an invalid profile id.
        The IUT is expected to set the ipid field to invalid and return only the
        avctp header (no body data should be sent).
        """
        return "OK"

    @assert_description
    def TSC_AVCTP_mmi_verify_fragmented_AVCT_SendMessage_TG(self, **kwargs):
        """
        Press 'OK' if the following condition was met :

        The IUT receives three
        AVCTP packets from the Lower Tester, reassembles the message and calls
        the MessageInd_CBTestSystem callback function with the following
        parameters:
           * BD_ADDR = BD_ADDRTest_System
           * Transaction =
        TRANSTest_System
           * Type = 0x01 (Command Message)
           * Data =
        ADDRESSdata_buffer (Buffer holding DATA[]Lower_Tester)
           * Length =
        LengthOf(DATA[]Lower_Tester)
        """
        return "OK"

    @assert_description
    def TSC_AVCTP_mmi_iut_initiate_avctp_data_response(self, **kwargs):
        """
        Take action to send the data specified in TSPX_avctp_iut_response_data
        to the tester.

        Note: If TSPX_avctp_psm = '0017'(AVRCP control channel
        psm), a valid AVRCP response may be sent to the tester.
        """
        return "OK"

    @assert_description
    def TSC_AVCTP_mmi_register_MessageInd_CB_TG(self, **kwargs):
        """
        Using the Upper Tester register the function MessageInd_CBTest_System
        for callback on the AVCT_MessageRec_Ind event by sending an
        AVCT_EventRegistration command to the IUT with the following parameter
        values:     
           * Event = AVCT_MessageRec_Ind
           * Callback =
        MessageInd_CBTest_System
           * PID = PIDTest_System

        Press 'OK' to
        continue once the IUT has responded.
        """
        #TODO: Remove trailing space post "values:" from docstring description
        return "OK"