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
import enum
import logging
import random

from avatar import PandoraDevice, PandoraDevices, asynchronous, parameterized
from mobly import base_test, test_runner
from mobly.asserts import assert_equal  # type: ignore
from mobly.asserts import assert_false  # type: ignore
from mobly.asserts import assert_in  # type: ignore
from mobly.asserts import assert_is_none  # type: ignore
from mobly.asserts import assert_is_not_none  # type: ignore
from mobly.asserts import assert_true  # type: ignore
from mobly.asserts import fail  # type: ignore
from pandora.host_pb2 import PUBLIC, DataTypes
from typing import Optional


class AdvertisingEventProperties(enum.IntEnum):
    ADV_IND = 0x13
    ADV_DIRECT_IND = 0x15
    ADV_SCAN_IND = 0x12
    ADV_NONCONN_IND = 0x10

    CONNECTABLE = 0x01
    SCANNABLE = 0x02
    DIRECTED = 0x04
    LEGACY = 0x10
    ANONYMOUS = 0x20

    def __repr__(self) -> str:
        return str(self.value)


class LeAdvertisingTest(base_test.BaseTestClass):  # type: ignore[misc]
    """Suite of tests designed to validate that Android correctly reports
    all kinds of advertising events to the user application."""

    devices: Optional[PandoraDevices] = None
    dut: PandoraDevice
    ref: PandoraDevice

    def setup_class(self) -> None:
        self.devices = PandoraDevices(self)
        dut, ref, *_ = self.devices
        self.dut, self.ref = dut, ref

    def teardown_class(self) -> None:
        if self.devices:
            self.devices.stop_all()

    @asynchronous
    async def setup_test(self) -> None:
        await asyncio.gather(self.dut.reset(), self.ref.reset())

    @parameterized(
        (AdvertisingEventProperties.ADV_IND, 0),
        (AdvertisingEventProperties.ADV_IND, 31),
        (AdvertisingEventProperties.ADV_DIRECT_IND, 0),
        (AdvertisingEventProperties.ADV_SCAN_IND, 0),
        (AdvertisingEventProperties.ADV_SCAN_IND, 31),
        (AdvertisingEventProperties.ADV_NONCONN_IND, 0),
        (AdvertisingEventProperties.ADV_NONCONN_IND, 31),
    )  # type: ignore[misc]
    def test_legacy_advertising_parameters(
        self, advertising_event_properties: AdvertisingEventProperties, advertising_data_length: int
    ) -> None:
        # Advertise from the Ref device with the specified legacy advertising
        # event properties. Use the manufacturer specific data to pad the advertising data to the
        # desired length. The scan response data must always be provided when
        # scannable but it is defaulted.
        connectable = (advertising_event_properties & AdvertisingEventProperties.CONNECTABLE) != 0
        scannable = (advertising_event_properties & AdvertisingEventProperties.SCANNABLE) != 0
        directed = (advertising_event_properties & AdvertisingEventProperties.DIRECTED) != 0

        manufacturer_specific_data_length = max(0, advertising_data_length - 5)  # Flags (3) + LV (2)
        manufacturer_specific_data = bytes([random.randint(1, 255) for _ in range(manufacturer_specific_data_length)])
        advertising_data = (
            DataTypes(manufacturer_specific_data=manufacturer_specific_data) if advertising_data_length > 0 else None
        )

        scan_response_data = DataTypes() if scannable else None
        target = self.dut.address if directed else None

        advertiser = self.ref.host.Advertise(
            legacy=True,
            connectable=connectable,
            data=advertising_data,  # type: ignore[arg-type]
            scan_response_data=scan_response_data,  # type: ignore[arg-type]
            public=target,
            own_address_type=PUBLIC,
        )
        scanner = self.dut.host.Scan(legacy=False, passive=False)

        report = next((x for x in scanner if x.public == self.ref.address))

        scanner.cancel()
        advertiser.cancel()

        assert_true(report.legacy, msg='expected legacy advertising report')
        assert_equal(report.connectable, connectable)
        # TODO: scannable is not set by the android server
        # assert_equal(report.scannable, scannable)
        # TODO: direct_address is not set by the android server
        assert_equal(report.data.manufacturer_specific_data, manufacturer_specific_data)
        assert_false(report.truncated, msg='expected non-truncated advertising report')


if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)
    test_runner.main()  # type: ignore
