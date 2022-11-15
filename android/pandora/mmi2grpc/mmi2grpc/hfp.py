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
"""HFP proxy module."""

from mmi2grpc._helpers import assert_description
from mmi2grpc._proxy import ProfileProxy

from pandora_experimental.hfp_grpc import HFP
from pandora_experimental.host_grpc import Host
from pandora_experimental.security_grpc import Security
from pandora_experimental.hfp_pb2 import AudioPath

import sys
import threading
import time

# Standard time to wait before asking for waitConnection
WAIT_DELAY_BEFORE_CONNECTION = 2

# The tests needs the MMI to accept pairing confirmation request.
NEEDS_WAIT_CONNECTION_BEFORE_TEST = {'HFP/AG/WBS/BV-01-I', 'HFP/AG/SLC/BV-05-I'}

IXIT_PHONE_NUMBER = 42


class HFPProxy(ProfileProxy):

    def __init__(self, test, channel, rootcanal, modem):
        super().__init__(channel)
        self.hfp = HFP(channel)
        self.host = Host(channel)
        self.security = Security(channel)
        self.rootcanal = rootcanal
        self.modem = modem

        self.connection = None

        self._auto_confirm_requests()

    def asyncWaitConnection(self, pts_addr, delay=WAIT_DELAY_BEFORE_CONNECTION):
        """
        Send a WaitConnection in a grpc callback
        """

        def waitConnectionCallback(self, pts_addr):
            self.connection = self.host.WaitConnection(address=pts_addr).connection

        print(f'HFP placeholder mmi: asyncWaitConnection', file=sys.stderr)
        th = threading.Timer(interval=delay, function=waitConnectionCallback, args=(self, pts_addr))
        th.start()

    def test_started(self, test: str, pts_addr: bytes, **kwargs):
        if test in NEEDS_WAIT_CONNECTION_BEFORE_TEST:
            self.asyncWaitConnection(pts_addr)

        return "OK"

    @assert_description
    def TSC_delete_pairing_iut(self, pts_addr: bytes, **kwargs):
        """
        Delete the pairing with the PTS using the Implementation Under Test
        (IUT), then click Ok.
        """

        self.security.DeletePairing(address=pts_addr)
        return "OK"

    @assert_description
    def TSC_iut_enable_slc(self, pts_addr: bytes, **kwargs):
        """
        Click Ok, then initiate a service level connection from the
        Implementation Under Test (IUT) to the PTS.
        """

        if not self.connection:
            self.connection = self.host.Connect(address=pts_addr).connection
        self.hfp.EnableSlc(connection=self.connection)
        return "OK"

    @assert_description
    def TSC_iut_search(self, **kwargs):
        """
        Using the Implementation Under Test (IUT), perform a search for the PTS.
        If found, click OK.
        """

        return "OK"

    @assert_description
    def TSC_iut_connect(self, pts_addr: bytes, **kwargs):
        """
        Click Ok, then make a connection request to the PTS from the
        Implementation Under Test (IUT).
        """

        def connect():
            time.sleep(2)
            self.connection = self.host.Connect(address=pts_addr).connection

        threading.Thread(target=connect).start()

        return "OK"

    @assert_description
    def TSC_iut_connectable(self, pts_addr: str, test: str, **kwargs):
        """
        Make the Implementation Under Test (IUT) connectable, then click Ok.
        """

        if "HFP/AG/SLC/BV-03-C" in test:
            self.connection = self.host.WaitConnection(pts_addr).connection

        return "OK"

    @assert_description
    def TSC_iut_disable_slc(self, pts_addr: bytes, **kwargs):
        """
        Click Ok, then disable the service level connection using the
        Implementation Under Test (IUT).
        """

        self.connection = self.host.GetConnection(address=pts_addr).connection

        def disable_slc():
            time.sleep(2)
            self.hfp.DisableSlc(connection=self.connection)

        threading.Thread(target=disable_slc).start()

        return "OK"

    @assert_description
    def TSC_make_battery_charged(self, **kwargs):
        """
        Click Ok, then manipulate the Implementation Under Test (IUT) so that
        the battery is fully charged.
        """

        self.hfp.SetBatteryLevel(connection=self.connection, battery_percentage=100)

        return "OK"

    @assert_description
    def TSC_make_battery_discharged(self, **kwargs):
        """
        Manipulate the Implementation Under Test (IUT) so that the battery level
        is not fully charged, then click Ok.
        """

        self.hfp.SetBatteryLevel(connection=self.connection, battery_percentage=42)

        return "OK"

    @assert_description
    def TSC_ag_iut_enable_call(self, **kwargs):
        """
        Click Ok, then place a call from an external line to the Implementation
        Under Test (IUT). Do not answer the call unless prompted to do so.
        """

        def enable_call():
            time.sleep(2)
            self.modem.call(IXIT_PHONE_NUMBER)

        threading.Thread(target=enable_call).start()

        return "OK"

    @assert_description
    def TSC_verify_audio(self, **kwargs):
        """
        Verify the presence of an audio connection, then click Ok.
        """

        # TODO

        return "OK"

    @assert_description
    def TSC_ag_iut_disable_call_external(self, **kwargs):
        """
        Click Ok, then end the call using the external terminal.
        """

        def disable_call_external():
            time.sleep(2)
            self.hfp.DeclineCall()

        threading.Thread(target=disable_call_external).start()

        return "OK"

    @assert_description
    def TSC_iut_enable_audio_using_codec(self, **kwargs):
        """
        Click OK, then initiate an audio connection using the Codec Connection
        Setup procedure.
        """

        return "OK"

    @assert_description
    def TSC_iut_disable_audio(self, **kwargs):
        """
        Click Ok, then close the audio connection (SCO) between the
        Implementation Under Test (IUT) and the PTS.  Do not close the serivice
        level connection (SLC) or power-off the IUT.
        """

        def disable_audio():
            time.sleep(2)
            self.hfp.SetAudioPath(audio_path=AudioPath.AUDIO_PATH_SPEAKERS)

        threading.Thread(target=disable_audio).start()

        return "OK"

    @assert_description
    def TSC_verify_no_audio(self, **kwargs):
        """
        Verify the absence of an audio connection (SCO), then click Ok.
        """

        return "OK"

    def _auto_confirm_requests(self, times=None):

        def task():
            cnt = 0
            pairing_events = self.security.OnPairing()
            for event in pairing_events:
                if event.WhichOneof('method') in {"just_works", "numeric_comparison"}:
                    if times is None or cnt < times:
                        cnt += 1
                        pairing_events.send(event=event, confirm=True)

        threading.Thread(target=task).start()
