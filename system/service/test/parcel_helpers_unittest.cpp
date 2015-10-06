//
//  Copyright (C) 2015 Google, Inc.
//
//  Licensed under the Apache License, Version 2.0 (the "License");
//  you may not use this file except in compliance with the License.
//  You may obtain a copy of the License at:
//
//  http://www.apache.org/licenses/LICENSE-2.0
//
//  Unless required by applicable law or agreed to in writing, software
//  distributed under the License is distributed on an "AS IS" BASIS,
//  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//  See the License for the specific language governing permissions and
//  limitations under the License.
//

#include <gtest/gtest.h>

#include "service/common/bluetooth/advertise_data.h"
#include "service/common/bluetooth/advertise_settings.h"
#include "service/common/bluetooth/binder/parcel_helpers.h"

using android::Parcel;

using bluetooth::AdvertiseData;
using bluetooth::AdvertiseSettings;
using bluetooth::GattIdentifier;
using bluetooth::UUID;

namespace ipc {
namespace binder {
namespace {

bool TestAdvertiseData(const AdvertiseData &adv_in) {
  Parcel parcel;

  WriteAdvertiseDataToParcel(adv_in, &parcel);
  parcel.setDataPosition(0);
  auto adv_out = CreateAdvertiseDataFromParcel(parcel);

  return adv_in == *adv_out;
}

bool TestAdvertiseSettings(const AdvertiseSettings &settings_in) {
  Parcel parcel;

  WriteAdvertiseSettingsToParcel(settings_in, &parcel);
  parcel.setDataPosition(0);
  auto settings_out = CreateAdvertiseSettingsFromParcel(parcel);

  return settings_in == *settings_out;
}

bool TestUUID(const UUID& uuid_in) {
  Parcel parcel;

  WriteUUIDToParcel(uuid_in, &parcel);
  parcel.setDataPosition(0);
  auto uuid_out = CreateUUIDFromParcel(parcel);

  return uuid_in == *uuid_out;
}

bool TestGattIdentifier(const GattIdentifier& id_in) {
  Parcel parcel;

  WriteGattIdentifierToParcel(id_in, &parcel);
  parcel.setDataPosition(0);
  auto id_out = CreateGattIdentifierFromParcel(parcel);

  return id_in == *id_out;
}

TEST(ParcelHelpersTest, EmptyAdvertiseData) {
  std::vector<uint8_t> data;
  AdvertiseData adv(data);

  EXPECT_TRUE(TestAdvertiseData(adv));
}

TEST(ParcelHelpersTest, NonEmptyAdvertiseData) {
  std::vector<uint8_t> data{ 0x02, 0x02, 0x00 };
  AdvertiseData adv0(data);
  adv0.set_include_tx_power_level(true);
  EXPECT_TRUE(TestAdvertiseData(adv0));

  AdvertiseData adv1(data);
  adv1.set_include_device_name(true);
  EXPECT_TRUE(TestAdvertiseData(adv1));

  AdvertiseData adv2(data);
  adv2.set_include_tx_power_level(true);
  adv2.set_include_device_name(true);
  EXPECT_TRUE(TestAdvertiseData(adv2));
}

TEST(ParcelHelpersTest, DefaultAdvertiseSettings) {
  AdvertiseSettings settings;
  EXPECT_TRUE(TestAdvertiseSettings(settings));
}

TEST(ParcelHelpersTest, NonEmptyAdvertiseSettings) {
  AdvertiseSettings settings(
      AdvertiseSettings::MODE_BALANCED,
      base::TimeDelta::FromMilliseconds(150),
      AdvertiseSettings::TX_POWER_LEVEL_HIGH,
      false /* connectable */);
  EXPECT_TRUE(TestAdvertiseSettings(settings));
}

TEST(ParcelHelpersTest, UUID) {
  // Try a whole bunch of UUIDs.
  for (int i = 0; i < 10; i++) {
    UUID uuid = UUID::GetRandom();
    TestUUID(uuid);
  }
}

TEST(ParcelHelpersTest, GattIdentifier) {
  UUID uuid0 = UUID::GetRandom();
  UUID uuid1 = UUID::GetRandom();
  UUID uuid2 = UUID::GetRandom();

  auto service_id = GattIdentifier::CreateServiceId(
      "01:23:45:67:89:ab", 5, uuid0, false);
  auto char_id = GattIdentifier::CreateCharacteristicId(3, uuid1, *service_id);
  auto desc_id = GattIdentifier::CreateDescriptorId(10, uuid2, *char_id);

  TestGattIdentifier(*service_id);
  TestGattIdentifier(*char_id);
  TestGattIdentifier(*desc_id);
}

}  // namespace
}  // namespace binder
}  // namespace ipc
