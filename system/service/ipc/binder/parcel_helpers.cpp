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

#include "service/ipc/binder/parcel_helpers.h"

using android::Parcel;

using bluetooth::AdvertiseData;
using bluetooth::AdvertiseSettings;

namespace ipc {
namespace binder {

// TODO(armansito): The helpers below currently don't match the Java
// definitions. We need to change the AIDL and framework code to comply with the
// new definition and Parcel format provided here.

void WriteAdvertiseDataToParcel(const AdvertiseData& data, Parcel* parcel) {
  CHECK(parcel);
  parcel->writeByteArray(data.data().size(), data.data().data());  // lol
  parcel->writeInt32(data.include_device_name());
  parcel->writeInt32(data.include_tx_power_level());
}

std::unique_ptr<AdvertiseData> CreateAdvertiseDataFromParcel(
    const Parcel& parcel) {
  std::vector<uint8_t> data;

  // For len=0 Parcel::writeByteArray writes "-1" for the length value. So, any
  // other value means that there is data to read.
  // TODO(pavlin): We shouldn't need to worry about his here. Instead, Parcel
  // should have an API for deserializing an array of bytes (e.g.
  // Parcel::readByteArray()).
  int data_len = parcel.readInt32();
  if (data_len != -1) {
    uint8_t bytes[data_len];
    parcel.read(bytes, data_len);

    data = std::vector<uint8_t>(bytes, bytes + data_len);
  }

  bool include_device_name = parcel.readInt32();
  bool include_tx_power = parcel.readInt32();

  std::unique_ptr<AdvertiseData> adv(new AdvertiseData(data));
  adv->set_include_device_name(include_device_name);
  adv->set_include_tx_power_level(include_tx_power);

  return std::move(adv);
}

void WriteAdvertiseSettingsToParcel(const AdvertiseSettings& settings,
                                    Parcel* parcel) {
  CHECK(parcel);
  parcel->writeInt32(settings.mode());
  parcel->writeInt32(settings.tx_power_level());
  parcel->writeInt32(settings.connectable());
  parcel->writeInt64(settings.timeout().InMilliseconds());
}

std::unique_ptr<AdvertiseSettings> CreateAdvertiseSettingsFromParcel(
    const Parcel& parcel) {
  AdvertiseSettings::Mode mode =
      static_cast<AdvertiseSettings::Mode>(parcel.readInt32());
  AdvertiseSettings::TxPowerLevel tx_power =
      static_cast<AdvertiseSettings::TxPowerLevel>(parcel.readInt32());
  bool connectable = parcel.readInt32();
  base::TimeDelta timeout = base::TimeDelta::FromMilliseconds(
      parcel.readInt64());

  return std::unique_ptr<AdvertiseSettings>(
      new AdvertiseSettings(mode, timeout, tx_power, connectable));
}

}  // namespace binder
}  // namespace ipc
