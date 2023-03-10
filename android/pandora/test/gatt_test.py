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

from avatar import PandoraDevice, PandoraDevices, asynchronous
from mobly import base_test, test_runner
from pandora.host_pb2 import RANDOM, DataTypes
from pandora_experimental.gatt_grpc import GATT
from typing import Optional


class GattTest(base_test.BaseTestClass):  # type: ignore[misc]
    devices: Optional[PandoraDevices] = None

    # pandora devices.
    dut: PandoraDevice
    ref: PandoraDevice

    def setup_class(self) -> None:
        self.devices = PandoraDevices(self)
        self.dut, self.ref, *_ = self.devices

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


if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)
    test_runner.main()  # type: ignore
