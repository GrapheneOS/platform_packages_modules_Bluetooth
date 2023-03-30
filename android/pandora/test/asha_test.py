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
import avatar
import enum
import grpc
import logging

from avatar import BumblePandoraDevice, PandoraDevice, PandoraDevices, asynchronous, bumble_server
from bumble.gatt import GATT_ASHA_SERVICE
from bumble.smp import PairingDelegate
from bumble_experimental.asha import ASHAService
from mobly import base_test, signals, test_runner
from mobly.asserts import assert_equal  # type: ignore
from mobly.asserts import assert_in  # type: ignore
from pandora._utils import AioStream
from pandora.host_pb2 import PUBLIC, RANDOM, AdvertiseResponse, Connection, DataTypes, OwnAddressType, ScanningResponse
from pandora.security_pb2 import LE_LEVEL3, LESecurityLevel
from pandora_experimental.asha_grpc_aio import Asha as AioAsha, add_AshaServicer_to_server
from typing import List, Optional, Tuple

ASHA_UUID = GATT_ASHA_SERVICE.to_hex_str()
HISYCNID: List[int] = [0x01, 0x02, 0x03, 0x04, 0x5, 0x6, 0x7, 0x8]
CAPABILITY: int = 0x0
COMPLETE_LOCAL_NAME: str = "Bumble"


class Ear(enum.IntEnum):
    """Reference devices type"""

    LEFT = 0
    RIGHT = 1

    def __repr__(self) -> str:
        return str(self.value)


class ASHATest(base_test.BaseTestClass):  # type: ignore[misc]
    devices: Optional[PandoraDevices] = None

    # pandora devices.
    dut: PandoraDevice
    ref_left: PandoraDevice
    ref_right: PandoraDevice

    def setup_class(self) -> None:
        # Register experimental bumble servicers hook.
        bumble_server.register_servicer_hook(
            lambda bumble, server: add_AshaServicer_to_server(ASHAService(bumble.device), server)
        )

        self.devices = PandoraDevices(self)
        self.dut, self.ref_left, self.ref_right, *_ = self.devices

    def teardown_class(self) -> None:
        if self.devices:
            self.devices.stop_all()

    @avatar.asynchronous
    async def setup_test(self) -> None:
        await asyncio.gather(self.dut.reset(), self.ref_left.reset(), self.ref_right.reset())

        if isinstance(self.dut, BumblePandoraDevice):
            raise signals.TestSkip('DUT Bumble does not support Asha source')
        if not isinstance(self.ref_left, BumblePandoraDevice):
            raise signals.TestSkip('Test require Bumble as reference device(s)')
        if not isinstance(self.ref_right, BumblePandoraDevice):
            raise signals.TestSkip('Test require Bumble as reference device(s)')

        # ASHA hearing aid's IO capability is NO_OUTPUT_NO_INPUT
        setattr(self.ref_left.device, "io_capability", PairingDelegate.NO_OUTPUT_NO_INPUT)
        setattr(self.ref_right.device, "io_capability", PairingDelegate.NO_OUTPUT_NO_INPUT)

    async def ref_advertise_asha(
        self, ref_device: PandoraDevice, ref_address_type: OwnAddressType
    ) -> AioStream[AdvertiseResponse]:
        """
        Ref device starts to advertise with service data in advertisement data.
        :return: Ref device's advertise stream
        """
        # Ref starts advertising with ASHA service data
        asha = AioAsha(ref_device.aio.channel)
        await asha.Register(capability=CAPABILITY, hisyncid=HISYCNID)
        return ref_device.aio.host.Advertise(
            legacy=True,
            connectable=True,
            own_address_type=ref_address_type,
            data=DataTypes(
                complete_local_name=COMPLETE_LOCAL_NAME,
                incomplete_service_class_uuids16=[ASHA_UUID],
            ),
        )

    async def dut_scan_for_asha(self, dut_address_type: OwnAddressType) -> ScanningResponse:
        """
        DUT starts to scan for the Ref device.
        :return: ScanningResponse for ASHA
        """
        dut_scan = self.dut.aio.host.Scan(own_address_type=dut_address_type)
        ref = await anext((x async for x in dut_scan if ASHA_UUID in x.data.incomplete_service_class_uuids16))
        dut_scan.cancel()
        assert ref
        return ref

    async def dut_connect_to_ref(
        self, advertisement: AioStream[AdvertiseResponse], ref: ScanningResponse, dut_address_type: OwnAddressType
    ) -> Tuple[Connection, Connection]:
        """
        Helper method for Dut connects to Ref
        :return: a Tuple (DUT to REF connection, REF to DUT connection)
        """
        (dut_ref_res, ref_dut_res) = await asyncio.gather(
            self.dut.aio.host.ConnectLE(own_address_type=dut_address_type, **ref.address_asdict()),
            anext(aiter(advertisement)),  # pytype: disable=name-error
        )
        assert_equal(dut_ref_res.result_variant(), 'connection')
        dut_ref, ref_dut = dut_ref_res.connection, ref_dut_res.connection
        assert dut_ref and ref_dut
        advertisement.cancel()

        return dut_ref, ref_dut

    async def is_device_connected(self, device: PandoraDevice, connection: Connection, timeout: float) -> bool:
        try:
            await device.aio.host.WaitDisconnection(connection=connection, timeout=timeout)
            return False
        except grpc.RpcError as e:
            assert e.code() == grpc.StatusCode.DEADLINE_EXCEEDED  # type: ignore
            return True

    @asynchronous
    async def test_advertising_advertisement_data(self) -> None:
        """
        Ref starts ASHA advertisements with service data in advertisement data.
        DUT starts a service discovery.
        Verify Ref is correctly discovered by DUT as a hearing aid device.
        """
        protocol_version = 0x01
        truncated_hisyncid = HISYCNID[:4]

        advertisement = await self.ref_advertise_asha(self.ref_left, RANDOM)

        # DUT starts a service discovery
        scan_result = await self.dut_scan_for_asha(dut_address_type=RANDOM)
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

    @asynchronous
    async def test_advertising_scan_response(self) -> None:
        """
        Ref starts ASHA advertisements with service data in scan response data.
        DUT starts a service discovery.
        Verify Ref is correctly discovered by DUT as a hearing aid device.
        """
        protocol_version = 0x01
        truncated_hisyncid = HISYCNID[:4]

        asha = AioAsha(self.ref_left.aio.channel)
        await asha.Register(capability=CAPABILITY, hisyncid=HISYCNID)

        # advertise with ASHA service data in scan response
        advertisement = self.ref_left.aio.host.Advertise(
            legacy=True,
            scan_response_data=DataTypes(
                complete_local_name=COMPLETE_LOCAL_NAME,
                complete_service_class_uuids16=[ASHA_UUID],
            ),
        )

        scan_result = await self.dut_scan_for_asha(dut_address_type=RANDOM)
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

    @avatar.parameterized(
        (RANDOM, PUBLIC),
        (RANDOM, RANDOM),
    )  # type: ignore[misc]
    @asynchronous
    async def test_pairing(
        self,
        dut_address_type: OwnAddressType,
        ref_address_type: OwnAddressType,
    ) -> None:
        """
        DUT discovers Ref.
        DUT initiates connection to Ref.
        Verify that DUT and Ref are bonded and connected.
        """
        advertisement = await self.ref_advertise_asha(ref_device=self.ref_left, ref_address_type=ref_address_type)

        ref = await self.dut_scan_for_asha(dut_address_type=dut_address_type)

        # DUT initiates connection to Ref.
        dut_ref, ref_dut = await self.dut_connect_to_ref(advertisement, ref, dut_address_type)
        assert dut_ref, ref_dut

        # DUT starts pairing with the Ref.
        # FIXME: assert the security Level on ref side
        secure = await self.dut.aio.security.Secure(connection=dut_ref, le=LE_LEVEL3)

        assert_equal(secure.result_variant(), 'success')

    @avatar.parameterized(
        (RANDOM, PUBLIC),
        (RANDOM, RANDOM),
    )  # type: ignore[misc]
    @asynchronous
    async def test_unbonding(
        self,
        dut_address_type: OwnAddressType,
        ref_address_type: OwnAddressType,
    ) -> None:
        """
        DUT removes bond with Ref.
        Verify that DUT and Ref are disconnected and unbonded.
        """
        raise signals.TestSkip("TODO: update rootcanal to retry")

        advertisement = await self.ref_advertise_asha(ref_device=self.ref_left, ref_address_type=ref_address_type)
        ref = await self.dut_scan_for_asha(dut_address_type=dut_address_type)

        dut_ref, ref_dut = await self.dut_connect_to_ref(advertisement, ref, dut_address_type)

        secure = self.dut.security.Secure(connection=dut_ref, le=LESecurityLevel.LE_LEVEL3)

        assert_equal(secure.WhichOneof("result"), "success")
        await self.dut.aio.host.Disconnect(dut_ref)
        await self.ref_left.aio.host.WaitDisconnection(ref_dut)

        # delete the bond
        if dut_address_type == OwnAddressType.PUBLIC:
            await self.dut.aio.security_storage.DeleteBond(public=self.ref_left.address)
        else:
            await self.dut.aio.security_storage.DeleteBond(random=self.ref_left.random_address)

        # DUT connect to REF again
        dut_ref = (
            await self.dut.aio.host.ConnectLE(own_address_type=dut_address_type, **ref.address_asdict())
        ).connection
        # TODO very likely there is a bug in android here
        logging.debug("result should come out")

        advertisement.cancel()
        assert dut_ref

        secure = await self.dut.aio.security.Secure(connection=dut_ref, le=LESecurityLevel.LE_LEVEL3)

        assert_equal(secure.WhichOneof("result"), "success")

    @avatar.parameterized(
        (RANDOM, RANDOM),
        (RANDOM, PUBLIC),
    )  # type: ignore[misc]
    @asynchronous
    async def test_connection(self, dut_address_type: OwnAddressType, ref_address_type: OwnAddressType) -> None:
        """
        DUT discovers Ref.
        DUT initiates connection to Ref.
        Verify that DUT and Ref are connected.
        """
        advertisement = await self.ref_advertise_asha(ref_device=self.ref_left, ref_address_type=ref_address_type)
        ref = await self.dut_scan_for_asha(dut_address_type=dut_address_type)

        dut_ref, ref_dut = await self.dut_connect_to_ref(advertisement, ref, dut_address_type)
        assert dut_ref, ref_dut

    @avatar.parameterized(
        (RANDOM, RANDOM),
        (RANDOM, PUBLIC),
    )  # type: ignore[misc]
    @asynchronous
    async def test_disconnect_initiator(
        self,
        dut_address_type: OwnAddressType,
        ref_address_type: OwnAddressType,
    ) -> None:
        """
        DUT initiates disconnection to Ref.
        Verify that DUT and Ref are disconnected.
        """
        advertisement = await self.ref_advertise_asha(ref_device=self.ref_left, ref_address_type=ref_address_type)
        ref = await self.dut_scan_for_asha(dut_address_type=dut_address_type)

        dut_ref, ref_dut = await self.dut_connect_to_ref(advertisement, ref, dut_address_type)
        assert dut_ref, ref_dut

        await asyncio.gather(
            self.dut.aio.host.Disconnect(connection=dut_ref), self.is_device_connected(self.ref_left, ref_dut, 5)
        )

    @avatar.parameterized(
        (RANDOM, RANDOM),
        (RANDOM, PUBLIC),
    )  # type: ignore[misc]
    @asynchronous
    async def test_disconnect_acceptor(
        self,
        dut_address_type: OwnAddressType,
        ref_address_type: OwnAddressType,
    ) -> None:
        """
        Ref initiates disconnection to DUT (typically when put back in its box).
        Verify that Ref is disconnected.
        """
        advertisement = await self.ref_advertise_asha(ref_device=self.ref_left, ref_address_type=ref_address_type)
        ref = await self.dut_scan_for_asha(dut_address_type=dut_address_type)

        dut_ref, ref_dut = await self.dut_connect_to_ref(advertisement, ref, dut_address_type)
        assert dut_ref, ref_dut

        await asyncio.gather(
            self.ref_left.aio.host.Disconnect(connection=ref_dut), self.is_device_connected(self.dut, dut_ref, 5)
        )

    @avatar.parameterized(
        (RANDOM, RANDOM, 0),
        (RANDOM, RANDOM, 0.5),
        (RANDOM, RANDOM, 1),
        (RANDOM, RANDOM, 5),
    )  # type: ignore[misc]
    @asynchronous
    async def test_reconnection(
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

        async def connect_and_disconnect() -> None:
            advertisement = await self.ref_advertise_asha(ref_device=self.ref_left, ref_address_type=ref_address_type)
            ref = await self.dut_scan_for_asha(dut_address_type=dut_address_type)
            dut_ref, _ = await self.dut_connect_to_ref(advertisement, ref, dut_address_type)
            await self.dut.aio.host.Disconnect(connection=dut_ref)

        await connect_and_disconnect()
        # simulating reconnect interval
        await asyncio.sleep(reconnection_gap)
        await connect_and_disconnect()

    @avatar.parameterized(
        (RANDOM, RANDOM),
        (RANDOM, PUBLIC),
    )  # type: ignore[misc]
    @asynchronous
    async def test_auto_connection(
        self,
        dut_address_type: OwnAddressType,
        ref_address_type: OwnAddressType,
    ) -> None:
        """
        Ref initiates disconnection to DUT.
        Ref starts sending ASHA advertisements.
        Verify that DUT auto-connects to Ref.
        """
        advertisement = await self.ref_advertise_asha(ref_device=self.ref_left, ref_address_type=ref_address_type)
        ref = await self.dut_scan_for_asha(dut_address_type=dut_address_type)

        # manually connect and not cancel advertisement
        dut_ref_res, ref_dut_res = await asyncio.gather(
            self.dut.aio.host.ConnectLE(own_address_type=dut_address_type, **ref.address_asdict()),
            anext(aiter(advertisement)),  # pytype: disable=name-error
        )
        assert_equal(dut_ref_res.result_variant(), 'connection')
        dut_ref, ref_dut = dut_ref_res.connection, ref_dut_res.connection
        assert dut_ref, ref_dut

        # Pairing
        # FIXME: assert that the security Level is reached on ref side
        secure = await self.dut.aio.security.Secure(connection=dut_ref, le=LE_LEVEL3)
        assert_equal(secure.WhichOneof("result"), "success")

        await self.ref_left.aio.host.Disconnect(connection=ref_dut)

        ref_dut = (await anext(aiter(advertisement))).connection
        advertisement.cancel()
        assert ref_dut

    @avatar.parameterized(
        (RANDOM, RANDOM, Ear.LEFT),
        (RANDOM, PUBLIC, Ear.RIGHT),
    )  # type: ignore[misc]
    @asynchronous
    async def test_disconnect_acceptor_dual_device(
        self,
        dut_address_type: OwnAddressType,
        ref_address_type: OwnAddressType,
        disconnect_device: Ear,
    ) -> None:
        """
        Prerequisites: DUT and Ref are connected and bonded.
        Description:
           1. One peripheral of Ref initiates disconnection to DUT.
           2. Verify that it is disconnected and that the other peripheral is still connected.
        """

        advertisement_left = await self.ref_advertise_asha(ref_device=self.ref_left, ref_address_type=ref_address_type)
        ref_left = await self.dut_scan_for_asha(dut_address_type=dut_address_type)
        dut_ref_left, ref_left_dut = await self.dut_connect_to_ref(
            advertisement=advertisement_left, ref=ref_left, dut_address_type=dut_address_type
        )
        advertisement_left.cancel()
        assert dut_ref_left, ref_left_dut

        advertisement_right = await self.ref_advertise_asha(
            ref_device=self.ref_right, ref_address_type=ref_address_type
        )
        ref_right = await self.dut_scan_for_asha(dut_address_type=dut_address_type)
        dut_ref_right, ref_right_dut = await self.dut_connect_to_ref(
            advertisement=advertisement_right, ref=ref_right, dut_address_type=dut_address_type
        )
        advertisement_right.cancel()
        assert dut_ref_right, ref_right_dut

        if disconnect_device == Ear.LEFT:
            await self.ref_left.aio.host.Disconnect(connection=ref_left_dut)
            assert await self.is_device_connected(device=self.ref_right, connection=ref_right_dut, timeout=5.0)
            assert not await self.is_device_connected(device=self.ref_left, connection=ref_left_dut, timeout=5.0)
        else:
            await self.ref_right.aio.host.Disconnect(connection=ref_right_dut)
            assert not await self.is_device_connected(device=self.ref_right, connection=ref_right_dut, timeout=5.0)
            assert await self.is_device_connected(device=self.ref_left, connection=ref_left_dut, timeout=5.0)


if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    test_runner.main()  # type: ignore
