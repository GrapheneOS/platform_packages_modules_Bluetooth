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

#include "service/advertise_data.h"
#include "service/advertise_settings.h"
#include "service/ipc/binder/parcel_helpers.h"

using android::Parcel;

using bluetooth::AdvertiseData;
using bluetooth::AdvertiseSettings;

namespace ipc {
namespace binder {
namespace {

bool TestAdvertiseData(const AdvertiseData &adv_in) {
  Parcel parcel;

  WriteAdvertiseDataToParcel(adv_in, &parcel);
  parcel.setDataPosition(0);
  std::unique_ptr<AdvertiseData> adv_out =
      CreateAdvertiseDataFromParcel(parcel);

  return adv_in == *adv_out;
}

bool TestAdvertiseSettings(const AdvertiseSettings &settings_in) {
  Parcel parcel;

  WriteAdvertiseSettingsToParcel(settings_in, &parcel);
  parcel.setDataPosition(0);
  std::unique_ptr<AdvertiseSettings> settings_out =
      CreateAdvertiseSettingsFromParcel(parcel);

  return settings_in == *settings_out;
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

}  // namespace
}  // namespace binder
}  // namespace ipc
