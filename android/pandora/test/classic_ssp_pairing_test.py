# Copyright 2023 Google LLC
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
import bumble.device
import itertools

from avatar import BumblePandoraDevice, PandoraDevice, PandoraDevices, asynchronous, parameterized
from bumble.core import BT_BR_EDR_TRANSPORT
from bumble.hci import HCI_CENTRAL_ROLE, HCI_PERIPHERAL_ROLE, Address as BumbleAddress
from bumble.smp import PairingDelegate
from concurrent import futures
from contextlib import suppress
from google.protobuf import any_pb2
from mobly import base_test
from mobly.asserts import assert_equal, assert_in, assert_is_not_none, fail
from pandora.host_pb2 import PUBLIC, RANDOM, Connection, DataTypes, OwnAddressType
from pandora.security_pb2 import LEVEL2, PairingEventAnswer
from typing import NoReturn, Optional


class BumbleAddressWrapper(BumbleAddress):
    """Wrapper of Bumble Address class."""

    def __init__(
        self,
        address: BumbleAddress.ANY,
        address_type: int = BumbleAddress.PUBLIC_DEVICE_ADDRESS,
        bytes_endian: str = 'little',
    ):
        if isinstance(address, bytes):
            if bytes_endian == 'big':
                address = bytes(reversed(address))
            elif bytes_endian != 'little':
                raise ValueError("byteorder must be either 'little' or 'big'")
        super().__init__(address, address_type)


class ClassicSspTests(base_test.BaseTestClass):  # type: ignore[misc]
    devices: Optional[PandoraDevices] = None

    # pandora devices.
    dut: PandoraDevice
    ref: BumblePandoraDevice

    def setup_class(self) -> None:
        self.devices = PandoraDevices(self)
        self.dut, self.ref, *_ = self.devices

        # Enable BR/EDR mode for Bumble devices.
        for device in self.devices:
            if isinstance(device, BumblePandoraDevice):
                device.config.setdefault('classic_enabled', True)
                device.config.setdefault('classic_enabled', True)

    def teardown_class(self) -> None:
        if self.devices:
            self.devices.stop_all()

    @asynchronous
    async def setup_test(self) -> None:
        await asyncio.gather(self.dut.reset(), self.ref.reset())

    async def connect_le(self, dut_address_type: OwnAddressType, ref_address_type: OwnAddressType) -> None:
        advertisement = self.dut.aio.host.Advertise(
            legacy=True,
            connectable=True,
            own_address_type=dut_address_type,
            data=DataTypes(manufacturer_specific_data=b'pause cafe'),
        )

        scan = self.ref.aio.host.Scan(own_address_type=ref_address_type)
        dut = await anext((x async for x in scan if b'pause cafe' in x.data.manufacturer_specific_data))  # pytype: disable=name-error
        scan.cancel()
        assert dut

        (ref_dut_res, dut_ref_res) = await asyncio.gather(
            self.ref.aio.host.ConnectLE(own_address_type=ref_address_type, **dut.address_asdict()),
            anext(aiter(advertisement)),  # pytype: disable=name-error
        )

        advertisement.cancel()
        ref_dut, dut_ref = ref_dut_res.connection, dut_ref_res.connection
        assert ref_dut and dut_ref

    async def handle_pairing_events(self) -> NoReturn:
        ref_pairing_stream = self.ref.aio.security.OnPairing()
        dut_pairing_stream = self.dut.aio.security.OnPairing()

        try:
            while True:
                ref_pairing_event, dut_pairing_event = await asyncio.gather(
                    anext(ref_pairing_stream),
                    anext(dut_pairing_stream),
                )

                if dut_pairing_event.method_variant() in (
                        'numeric_comparison',
                        'just_works',
                ):
                    assert_in(
                        ref_pairing_event.method_variant(),
                        ('numeric_comparison', 'just_works'),
                    )
                    dut_pairing_stream.send_nowait(PairingEventAnswer(
                        event=dut_pairing_event,
                        confirm=True,
                    ))
                    ref_pairing_stream.send_nowait(PairingEventAnswer(
                        event=ref_pairing_event,
                        confirm=True,
                    ))
                elif dut_pairing_event.method_variant() == 'passkey_entry_notification':
                    assert_equal(ref_pairing_event.method_variant(), 'passkey_entry_request')
                    ref_pairing_stream.send_nowait(
                        PairingEventAnswer(
                            event=ref_pairing_event,
                            passkey=dut_pairing_event.passkey_entry_notification,
                        ))
                elif dut_pairing_event.method_variant() == 'passkey_entry_request':
                    assert_equal(ref_pairing_event.method_variant(), 'passkey_entry_notification')
                    dut_pairing_stream.send_nowait(
                        PairingEventAnswer(
                            event=dut_pairing_event,
                            passkey=ref_pairing_event.passkey_entry_notification,
                        ))
                else:
                    fail('unreachable')

        finally:
            ref_pairing_stream.cancel()
            dut_pairing_stream.cancel()

    @parameterized(*itertools.product(
        (PairingDelegate.NO_OUTPUT_NO_INPUT,),
        (HCI_CENTRAL_ROLE,),
        (RANDOM,),
    ))  # type: ignore[misc]
    @asynchronous
    async def test_classic_pairing_incoming(self, ref_io_capability: int, ref_role: int,
                                            ref_le_addr_type: OwnAddressType) -> None:
        # override reference device IO capability
        setattr(self.ref.device, 'io_capability', ref_io_capability)

        pairing = asyncio.create_task(self.handle_pairing_events())

        if ref_le_addr_type is not None:
            await self.connect_le(RANDOM, ref_le_addr_type)

        (dut_ref_res, ref_dut_res) = await asyncio.gather(
            self.dut.aio.host.WaitConnection(address=self.ref.address),
            self.ref.aio.host.Connect(address=self.dut.address),
        )

        assert_equal(ref_dut_res.result_variant(), 'connection')
        assert_equal(dut_ref_res.result_variant(), 'connection')
        ref_dut = ref_dut_res.connection
        dut_ref = dut_ref_res.connection
        assert_is_not_none(ref_dut)
        assert_is_not_none(dut_ref)

        ref_dut_raw = self.ref.device.find_connection_by_bd_addr(
            BumbleAddressWrapper(self.dut.address, bytes_endian='big'), BT_BR_EDR_TRANSPORT)
        assert_is_not_none(ref_dut_raw)

        if ref_dut_raw.role != ref_role:
            await ref_dut_raw.switch_role(ref_role)

        (secure, wait_security) = await asyncio.gather(
            self.ref.aio.security.Secure(connection=ref_dut, classic=LEVEL2),
            self.dut.aio.security.WaitSecurity(connection=dut_ref, classic=LEVEL2),
        )

        pairing.cancel()
        with suppress(asyncio.CancelledError, futures.CancelledError):
            await pairing

        assert_equal(secure.result_variant(), 'success')
        assert_equal(wait_security.result_variant(), 'success')

        await asyncio.gather(
            self.dut.aio.host.WaitDisconnection(connection=dut_ref),
            self.ref.aio.host.Disconnect(connection=ref_dut),
        )


if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)
    test_runner.main()  # type: ignore
