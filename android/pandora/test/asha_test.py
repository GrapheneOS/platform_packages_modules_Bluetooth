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

import asyncio
import logging
import time

from avatar import PandoraDevices, parameterized
from avatar.aio import asynchronous
from avatar.bumble_server.security import PairingDelegate
from avatar.pandora_client import BumblePandoraClient, PandoraClient
from bumble.gatt import GATT_ASHA_SERVICE
from mobly import base_test, test_runner
from mobly.asserts import assert_equal  # type: ignore
from mobly.asserts import assert_in  # type: ignore
from pandora._utils import Stream
from pandora.host_pb2 import PUBLIC, RANDOM, AdvertiseResponse, Connection, DataTypes, OwnAddressType, ScanningResponse
from pandora.security_pb2 import LE_LEVEL3, LESecurityLevel
from typing import List, Optional, Tuple

ASHA_UUID = GATT_ASHA_SERVICE.to_hex_str()
HISYCNID: List[int] = [0x01, 0x02, 0x03, 0x04, 0x5, 0x6, 0x7, 0x8]
CAPABILITY: int = 0x0
COMPLETE_LOCAL_NAME: str = "Bumble"


class ASHATest(base_test.BaseTestClass):  # type: ignore[misc]
    devices: Optional[PandoraDevices] = None
    dut: PandoraClient
    ref: BumblePandoraClient

    def setup_class(self) -> None:
        self.devices = PandoraDevices(self)
        dut, ref, *_ = self.devices
        assert isinstance(ref, BumblePandoraClient)
        self.dut, self.ref = dut, ref

    def teardown_class(self) -> None:
        if self.devices:
            self.devices.stop_all()

    @asynchronous
    async def setup_test(self) -> None:
        await asyncio.gather(self.dut.reset(), self.ref.reset())
        # ASHA hearing aid's IO capability is NO_OUTPUT_NO_INPUT
        setattr(self.ref.device, "io_capability", PairingDelegate.NO_OUTPUT_NO_INPUT)

    def ref_advertise_asha(self, ref_address_type: OwnAddressType) -> Stream[AdvertiseResponse]:
        """
        Ref device starts to advertise
        :return: Ref device's advertise response
        """
        # Ref starts advertising with ASHA service data
        self.ref.asha.Register(capability=CAPABILITY, hisyncid=HISYCNID)
        return self.ref.host.Advertise(
            legacy=True,
            connectable=True,
            data=DataTypes(
                complete_local_name=COMPLETE_LOCAL_NAME,
                incomplete_service_class_uuids16=[ASHA_UUID],
            ),
            own_address_type=ref_address_type,
        )

    def dut_scan_for_asha(self, dut_address_type: OwnAddressType) -> ScanningResponse:
        """
        DUT starts to scan for the Ref device.
        :return: ScanningResponse for ASHA
        """
        scan_result = self.dut.host.Scan(own_address_type=dut_address_type)
        ref = next((x for x in scan_result if ASHA_UUID in x.data.incomplete_service_class_uuids16))
        scan_result.cancel()

        assert ref
        return ref

    def dut_connect_to_ref(
        self, advertisement: Stream[AdvertiseResponse], ref: ScanningResponse, dut_address_type: OwnAddressType
    ) -> Tuple[Connection, Connection]:
        """
        Helper method for Dut connects to Ref
        :return: a Tuple (DUT to REF connection, REF to DUT connection)
        """
        # DUT connects to Ref
        dut_ref = self.dut.host.ConnectLE(own_address_type=dut_address_type, **ref.address_asdict()).connection
        ref_dut = (next(advertisement)).connection
        assert dut_ref
        assert ref_dut

        advertisement.cancel()
        return dut_ref, ref_dut

    def test_advertising_advertisement_data(self) -> None:
        """
        Ref starts ASHA advertisements with service data in advertisement data.
        DUT starts a service discovery.
        Verify Ref is correctly discovered by DUT as a hearing aid device.
        """
        protocol_version = 0x01
        truncated_hisyncid = HISYCNID[:4]

        advertisement = self.ref_advertise_asha(ref_address_type=RANDOM)

        # DUT starts a service discovery
        scan_result = self.dut_scan_for_asha(dut_address_type=RANDOM)
        advertisement.cancel()

        # Verify Ref is correctly discovered by DUT as a hearing aid device
        assert_in(ASHA_UUID, scan_result.data.service_data_uuid16)
        assert_equal(type(scan_result.data.complete_local_name), str)
        expected_advertisement_data = (
            "{:02x}".format(protocol_version)
            + "{:02x}".format(CAPABILITY)
            + "".join([("{:02x}".format(x)) for x in truncated_hisyncid])
        )
        assert_equal(
            expected_advertisement_data,
            (scan_result.data.service_data_uuid16[ASHA_UUID]).hex(),
        )

    def test_advertising_scan_response(self) -> None:
        """
        Ref starts ASHA advertisements with service data in scan response data.
        DUT starts a service discovery.
        Verify Ref is correctly discovered by DUT as a hearing aid device.
        """
        protocol_version = 0x01
        truncated_hisyncid = HISYCNID[:4]

        self.ref.asha.Register(capability=CAPABILITY, hisyncid=HISYCNID)

        # advertise with ASHA service data in scan response
        advertisement = self.ref.host.Advertise(
            legacy=True,
            scan_response_data=DataTypes(
                complete_local_name=COMPLETE_LOCAL_NAME,
                complete_service_class_uuids16=[ASHA_UUID],
            ),
        )

        scan_result = self.dut_scan_for_asha(dut_address_type=RANDOM)
        advertisement.cancel()

        # Verify Ref is correctly discovered by DUT as a hearing aid device.
        assert_in(ASHA_UUID, scan_result.data.service_data_uuid16)
        expected_advertisement_data = (
            "{:02x}".format(protocol_version)
            + "{:02x}".format(CAPABILITY)
            + "".join([("{:02x}".format(x)) for x in truncated_hisyncid])
        )
        assert_equal(
            expected_advertisement_data,
            (scan_result.data.service_data_uuid16[ASHA_UUID]).hex(),
        )

    @parameterized(
        (RANDOM, PUBLIC),
        (RANDOM, RANDOM),
    )  # type: ignore[misc]
    def test_pairing(
        self,
        dut_address_type: OwnAddressType,
        ref_address_type: OwnAddressType,
    ) -> None:
        """
        DUT discovers Ref.
        DUT initiates connection to Ref.
        Verify that DUT and Ref are bonded and connected.
        """
        advertisement = self.ref_advertise_asha(ref_address_type=ref_address_type)

        ref = self.dut_scan_for_asha(dut_address_type=dut_address_type)

        # DUT initiates connection to Ref.
        dut_ref, _ = self.dut_connect_to_ref(advertisement, ref, dut_address_type)
        assert dut_ref

        # DUT starts pairing with the Ref.
        secure = self.dut.security.Secure(connection=dut_ref, le=LE_LEVEL3)

        assert_equal(secure.WhichOneof("result"), "success")

    @parameterized(
        (RANDOM, PUBLIC),
        (RANDOM, RANDOM),
    )  # type: ignore[misc]
    def test_unbonding(
        self,
        dut_address_type: OwnAddressType,
        ref_address_type: OwnAddressType,
    ) -> None:
        """
        DUT removes bond with Ref.
        Verify that DUT and Ref are disconnected and unbonded.
        """
        from mobly.signals import TestSkip

        raise TestSkip("update rootcanal to retry")

        advertisement = self.ref_advertise_asha(ref_address_type=ref_address_type)
        ref = self.dut_scan_for_asha(dut_address_type=ref_address_type)

        dut_ref, ref_dut = self.dut_connect_to_ref(advertisement, ref, dut_address_type)

        secure = self.dut.security.Secure(connection=dut_ref, le=LESecurityLevel.LE_LEVEL3)

        assert_equal(secure.WhichOneof("result"), "success")
        self.dut.host.Disconnect(dut_ref)
        self.ref.host.WaitDisconnection(ref_dut)

        # delete the bond
        if dut_address_type == OwnAddressType.PUBLIC:
            self.dut.security_storage.DeleteBond(public=self.ref.address)
        else:
            self.dut.security_storage.DeleteBond(random=self.ref.random_address)

        # DUT connect to REF again
        dut_ref = (self.dut.host.ConnectLE(own_address_type=dut_address_type, **ref.address_asdict())).connection
        # TODO very likely there is a bug in android here
        logging.debug("result should come out")

        advertisement.cancel()
        assert dut_ref

        secure = self.dut.security.Secure(connection=dut_ref, le=LESecurityLevel.LE_LEVEL3)

        assert_equal(secure.WhichOneof("result"), "success")

    @parameterized(
        (RANDOM, RANDOM),
        (RANDOM, PUBLIC),
    )  # type: ignore[misc]
    def test_connection(self, dut_address_type: OwnAddressType, ref_address_type: OwnAddressType) -> None:
        """
        DUT discovers Ref.
        DUT initiates connection to Ref.
        Verify that DUT and Ref are connected.
        """
        advertisement = self.ref_advertise_asha(ref_address_type=ref_address_type)
        ref = self.dut_scan_for_asha(dut_address_type=dut_address_type)
        dut_ref, ref_dut = self.dut_connect_to_ref(advertisement, ref, dut_address_type)
        assert dut_ref
        assert ref_dut

    @parameterized(
        (RANDOM, RANDOM),
        (RANDOM, PUBLIC),
    )  # type: ignore[misc]
    def test_disconnect_initiator(
        self,
        dut_address_type: OwnAddressType,
        ref_address_type: OwnAddressType,
    ) -> None:
        """
        DUT initiates disconnection to Ref.
        Verify that DUT and Ref are disconnected.
        """
        advertisement = self.ref_advertise_asha(ref_address_type=ref_address_type)
        ref = self.dut_scan_for_asha(dut_address_type=dut_address_type)
        dut_ref, _ = self.dut_connect_to_ref(advertisement, ref, dut_address_type)

        self.dut.host.Disconnect(connection=dut_ref)

    @parameterized(
        (RANDOM, RANDOM),
        (RANDOM, PUBLIC),
    )  # type: ignore[misc]
    def test_disconnect_acceptor(
        self,
        dut_address_type: OwnAddressType,
        ref_address_type: OwnAddressType,
    ) -> None:
        """
        Ref initiates disconnection to DUT (typically when put back in its box).
        Verify that Ref is disconnected.
        """
        advertisement = self.ref_advertise_asha(ref_address_type=ref_address_type)
        ref = self.dut_scan_for_asha(dut_address_type=dut_address_type)
        dut_ref, ref_dut = self.dut_connect_to_ref(advertisement, ref, dut_address_type)
        assert dut_ref
        assert ref_dut
        self.ref.host.Disconnect(connection=ref_dut)

    @parameterized(
        (RANDOM, RANDOM, 0),
        (RANDOM, RANDOM, 0.5),
        (RANDOM, RANDOM, 1),
        (RANDOM, RANDOM, 5),
    )  # type: ignore[misc]
    def test_reconnection(
        self,
        dut_address_type: OwnAddressType,
        ref_address_type: OwnAddressType,
        reconnection_gap: float,
    ) -> None:
        """
        DUT initiates disconnection to the Ref.
        Verify that DUT and Ref are disconnected.
        DUT reconnects to Ref after various certain time.
        Verify that DUT and Ref are connected.
        """

        def connect_and_disconnect() -> None:
            advertisement = self.ref_advertise_asha(ref_address_type=ref_address_type)
            ref = self.dut_scan_for_asha(dut_address_type=dut_address_type)
            dut_ref, _ = self.dut_connect_to_ref(advertisement, ref, dut_address_type)
            self.dut.host.Disconnect(connection=dut_ref)

        connect_and_disconnect()
        # simulating reconnect interval
        time.sleep(reconnection_gap)
        connect_and_disconnect()

    @parameterized(
        (RANDOM, RANDOM),
        (RANDOM, PUBLIC),
    )  # type: ignore[misc]
    def test_auto_connection(
        self,
        dut_address_type: OwnAddressType,
        ref_address_type: OwnAddressType,
    ) -> None:
        """
        Ref initiates disconnection to DUT.
        Ref starts sending ASHA advertisements.
        Verify that DUT auto-connects to Ref.
        """
        advertisement = self.ref_advertise_asha(ref_address_type=ref_address_type)
        ref = self.dut_scan_for_asha(dut_address_type=dut_address_type)

        # manually connect and not cancel advertisement
        dut_ref = self.dut.host.ConnectLE(own_address_type=dut_address_type, **ref.address_asdict()).connection
        ref_dut = next(advertisement).connection
        assert dut_ref
        assert ref_dut

        # pairing
        secure = self.dut.security.Secure(connection=dut_ref, le=LE_LEVEL3)
        assert_equal(secure.WhichOneof("result"), "success")

        self.ref.host.Disconnect(connection=ref_dut)

        ref_dut = next(advertisement).connection
        advertisement.cancel()
        assert ref_dut


if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    test_runner.main()  # type: ignore
