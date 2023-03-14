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

from avatar import BumbleDevice, PandoraDevice, PandoraDevices, asynchronous
from bumble.gatt import Characteristic, Service
from bumble.smp import PairingConfig
from mobly import base_test, test_runner
from pandora.host_pb2 import RANDOM, Connection, DataTypes
from pandora.security_pb2 import LE_LEVEL3, PairingEventAnswer, SecureResponse
from pandora_experimental.gatt_grpc import GATT
from pandora_experimental.gatt_grpc_aio import GATT as AioGATT
from pandora_experimental.gatt_pb2 import SUCCESS, ReadCharacteristicsFromUuidResponse
from typing import Optional, Tuple


class GattTest(base_test.BaseTestClass):  # type: ignore[misc]
    devices: Optional[PandoraDevices] = None

    # pandora devices.
    dut: PandoraDevice
    ref: BumbleDevice

    def setup_class(self) -> None:
        self.devices = PandoraDevices(self)
        dut, ref = self.devices
        assert isinstance(ref, BumbleDevice)
        self.dut, self.ref = dut, ref

    def teardown_class(self) -> None:
        if self.devices:
            self.devices.stop_all()

    @asynchronous
    async def setup_test(self) -> None:
        await asyncio.gather(self.dut.reset(), self.ref.reset())

    def test_print_dut_gatt_services(self) -> None:
        advertise = self.ref.host.Advertise(legacy=True, connectable=True)
        dut_ref = self.dut.host.ConnectLE(public=self.ref.address, own_address_type=RANDOM).connection
        assert dut_ref
        advertise.cancel()

        gatt = GATT(self.dut.channel)
        services = gatt.DiscoverServices(dut_ref)
        self.dut.log.info(f'DUT services: {services}')

    def test_print_ref_gatt_services(self) -> None:
        advertise = self.dut.host.Advertise(
            legacy=True,
            connectable=True,
            own_address_type=RANDOM,
            data=DataTypes(manufacturer_specific_data=b'pause cafe'),
        )

        scan = self.ref.host.Scan()
        dut = next((x for x in scan if b'pause cafe' in x.data.manufacturer_specific_data))
        scan.cancel()

        ref_dut = self.ref.host.ConnectLE(own_address_type=RANDOM, **dut.address_asdict()).connection
        assert ref_dut
        advertise.cancel()

        gatt = GATT(self.ref.channel)
        services = gatt.DiscoverServices(ref_dut)
        self.ref.log.info(f'REF services: {services}')

    @asynchronous
    async def test_read_characteristic_while_pairing(self) -> None:
        async def connect_dut_to_ref() -> Tuple[Connection, Connection]:
            ref_advertisement = self.ref.aio.host.Advertise(
                legacy=True,
                connectable=True,
            )

            dut_connection_to_ref = (
                await self.dut.aio.host.ConnectLE(public=self.ref.address, own_address_type=RANDOM)
            ).connection
            assert dut_connection_to_ref

            ref_connection_to_dut = (await anext(aiter(ref_advertisement))).connection
            ref_advertisement.cancel()

            return dut_connection_to_ref, ref_connection_to_dut

        # arrange: set up GATT service on REF side with a characteristic
        # that can only be read after pairing
        SERVICE_UUID = "00005a00-0000-1000-8000-00805f9b34fb"
        CHARACTERISTIC_UUID = "00006a00-0000-1000-8000-00805f9b34fb"
        service = Service(
            SERVICE_UUID,
            [
                Characteristic(
                    CHARACTERISTIC_UUID,
                    Characteristic.READ,
                    Characteristic.READ_REQUIRES_ENCRYPTION,
                    b"Hello, world!",
                ),
            ],
        )
        self.ref.device.add_service(service)  # type:ignore
        # disable MITM requirement on REF side (since it only does just works)
        self.ref.device.pairing_config_factory = lambda _: PairingConfig(
            sc=True, mitm=False, bonding=True
        )  # type: ignore
        # manually handle pairing on the DUT side
        dut_pairing_events = self.dut.aio.security.OnPairing()
        # set up connection
        dut_connection_to_ref, ref_connection_to_dut = await connect_dut_to_ref()

        # act: initiate pairing from REF side (send a security request)
        async def ref_secure() -> SecureResponse:
            return await self.ref.aio.security.Secure(connection=ref_connection_to_dut, le=LE_LEVEL3)

        ref_secure_task = asyncio.create_task(ref_secure())

        # wait for pairing to start
        event = await anext(dut_pairing_events)

        # before acknowledging pairing, start a GATT read
        dut_gatt = AioGATT(self.dut.aio.channel)

        async def dut_read() -> ReadCharacteristicsFromUuidResponse:
            return await dut_gatt.ReadCharacteristicsFromUuid(dut_connection_to_ref, CHARACTERISTIC_UUID, 1, 0xFFFF)

        dut_read_task = asyncio.create_task(dut_read())

        await asyncio.sleep(3)

        # now continue with pairing
        dut_pairing_events.send_nowait(PairingEventAnswer(event=event, confirm=True))

        # android pops up a second pairing notification for some reason, accept it
        event = await anext(dut_pairing_events)
        dut_pairing_events.send_nowait(PairingEventAnswer(event=event, confirm=True))

        # assert: that the read succeeded (so Android re-tried the read after pairing)
        read_response = await dut_read_task
        self.ref.log.info(read_response)
        assert read_response.characteristics_read[0].status == SUCCESS
        assert read_response.characteristics_read[0].value.value == b"Hello, world!"

        # make sure pairing was successful
        ref_secure_res = await ref_secure_task
        assert ref_secure_res.result_variant() == 'success'


if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)
    test_runner.main()  # type: ignore
