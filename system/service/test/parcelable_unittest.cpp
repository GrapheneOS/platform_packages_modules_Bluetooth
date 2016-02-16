//
//  Copyright (C) 2016 Google, Inc.
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

#include "service/common/android/bluetooth/advertise_data.h"
#include "service/common/android/bluetooth/advertise_settings.h"
#include "service/common/android/bluetooth/gatt_identifier.h"
#include "service/common/android/bluetooth/scan_filter.h"
#include "service/common/android/bluetooth/scan_result.h"
#include "service/common/android/bluetooth/scan_settings.h"
#include "service/common/android/bluetooth/uuid.h"

using android::Parcel;

using bluetooth::AdvertiseData;
using bluetooth::AdvertiseSettings;
using bluetooth::GattIdentifier;
using bluetooth::ScanFilter;
using bluetooth::ScanResult;
using bluetooth::ScanSettings;
using bluetooth::UUID;

namespace bluetooth {
namespace {

template <class IN, class OUT>
bool TestData(IN& in) {
  Parcel parcel;

  parcel.writeParcelable((OUT)in);
  parcel.setDataPosition(0);
  OUT out;
  parcel.readParcelable(&out);
  return in == out;
}

TEST(ParcelableTest, NonEmptyAdvertiseData) {
  std::vector<uint8_t> data{0x02, 0x02, 0x00};
  AdvertiseData adv0(data);
  adv0.set_include_tx_power_level(true);
  bool result = TestData<AdvertiseData, android::bluetooth::AdvertiseData>(adv0);
  EXPECT_TRUE(result);

  AdvertiseData adv1(data);
  adv1.set_include_device_name(true);
  result = TestData<AdvertiseData, android::bluetooth::AdvertiseData>(adv1);
  EXPECT_TRUE(result);

  AdvertiseData adv2(data);
  adv2.set_include_tx_power_level(true);
  adv2.set_include_device_name(true);
  result = TestData<AdvertiseData, android::bluetooth::AdvertiseData>(adv2);
  EXPECT_TRUE(result);
}

TEST(ParcelableTest, DefaultAdvertiseSettings) {
  AdvertiseSettings settings;
  bool result =
      TestData<AdvertiseSettings, android::bluetooth::AdvertiseSettings>(
          settings);
  EXPECT_TRUE(result);
}

TEST(ParcelableTest, NonEmptyAdvertiseSettings) {
  AdvertiseSettings settings(
      AdvertiseSettings::MODE_BALANCED, base::TimeDelta::FromMilliseconds(150),
      AdvertiseSettings::TX_POWER_LEVEL_HIGH, false /* connectable */);

  bool result =
      TestData<AdvertiseSettings, android::bluetooth::AdvertiseSettings>(
          settings);
  EXPECT_TRUE(result);
}

TEST(ParcelableTest, UUID) {
  // Try a whole bunch of UUIDs.
  for (int i = 0; i < 10; i++) {
    UUID uuid = UUID::GetRandom();
    TestData<UUID, android::bluetooth::UUID>(uuid);
  }
}

TEST(ParcelableTest, GattIdentifier) {
  UUID uuid0 = UUID::GetRandom();
  UUID uuid1 = UUID::GetRandom();
  UUID uuid2 = UUID::GetRandom();

  auto service_id =
      GattIdentifier::CreateServiceId("01:23:45:67:89:ab", 5, uuid0, false);
  auto char_id = GattIdentifier::CreateCharacteristicId(3, uuid1, *service_id);
  auto desc_id = GattIdentifier::CreateDescriptorId(10, uuid2, *char_id);

  bool result =
      TestData<GattIdentifier, android::bluetooth::GattIdentifier>(*service_id);
  EXPECT_TRUE(result);
  result =
      TestData<GattIdentifier, android::bluetooth::GattIdentifier>(*char_id);
  EXPECT_TRUE(result);
  result =
      TestData<GattIdentifier, android::bluetooth::GattIdentifier>(*desc_id);
  EXPECT_TRUE(result);
}

TEST(ParcelableTest, ScanSettings) {
  ScanSettings settings0;
  ScanSettings settings1(
      ScanSettings::MODE_BALANCED, ScanSettings::CALLBACK_TYPE_FIRST_MATCH,
      ScanSettings::RESULT_TYPE_ABBREVIATED,
      base::TimeDelta::FromMilliseconds(150), ScanSettings::MATCH_MODE_STICKY,
      ScanSettings::MATCH_COUNT_FEW_ADVERTISEMENTS);

  bool result =
      TestData<ScanSettings, android::bluetooth::ScanSettings>(settings0);
  EXPECT_TRUE(result);

  result = TestData<ScanSettings, android::bluetooth::ScanSettings>(settings0);
  EXPECT_TRUE(result);
}

TEST(ParcelableTest, ScanFilter) {
  ScanFilter filter;

  filter.set_device_name("Test Device Name");
  ASSERT_TRUE(filter.SetDeviceAddress("01:02:04:AB:CD:EF"));

  bool result = TestData<ScanFilter, android::bluetooth::ScanFilter>(filter);
  EXPECT_TRUE(result);

  UUID uuid = UUID::GetRandom();
  filter.SetServiceUuid(uuid);

  result = TestData<ScanFilter, android::bluetooth::ScanFilter>(filter);
  EXPECT_TRUE(result);

  UUID mask = UUID::GetRandom();
  filter.SetServiceUuidWithMask(uuid, mask);
  result = TestData<ScanFilter, android::bluetooth::ScanFilter>(filter);
  EXPECT_TRUE(result);
}

TEST(ParcelableTest, ScanResult) {
  const char kTestAddress[] = "01:02:03:AB:CD:EF";

  const std::vector<uint8_t> kEmptyBytes;
  const std::vector<uint8_t> kTestBytes{0x01, 0x02, 0x03};

  const int kTestRssi = 127;

  ScanResult result0(kTestAddress, kEmptyBytes, kTestRssi);
  ScanResult result1(kTestAddress, kTestBytes, kTestRssi);

  bool result = TestData<ScanResult, android::bluetooth::ScanResult>(result0);
  EXPECT_TRUE(result);

  result = TestData<ScanResult, android::bluetooth::ScanResult>(result1);
  EXPECT_TRUE(result);
}

}  // namespace
}  // namespace bluetooth
