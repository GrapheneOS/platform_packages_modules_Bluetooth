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

  return adv;
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

void WriteUUIDToParcel(const bluetooth::UUID& uuid, android::Parcel* parcel) {
  // The scheme used by android.os.ParcelUuid is to wrote the most significant
  // bits first as one 64-bit integer, followed by the least significant bits in
  // a second 64-bit integer. This is the same as writing the raw-bytes in
  // sequence, but we don't want to assume any host-endianness here. So follow
  // the same scheme and use the same Parcel APIs.
  bluetooth::UUID::UUID128Bit bytes = uuid.GetFullBigEndian();

  uint64_t most_sig_bits =
      ((((uint64_t) bytes[0]) << 56) |
       (((uint64_t) bytes[1]) << 48) |
       (((uint64_t) bytes[2]) << 40) |
       (((uint64_t) bytes[3]) << 32) |
       (((uint64_t) bytes[4]) << 24) |
       (((uint64_t) bytes[5]) << 16) |
       (((uint64_t) bytes[6]) << 8) |
       bytes[7]);

  uint64_t least_sig_bits =
      ((((uint64_t) bytes[8]) << 56) |
       (((uint64_t) bytes[9]) << 48) |
       (((uint64_t) bytes[10]) << 40) |
       (((uint64_t) bytes[11]) << 32) |
       (((uint64_t) bytes[12]) << 24) |
       (((uint64_t) bytes[13]) << 16) |
       (((uint64_t) bytes[14]) << 8) |
       bytes[15]);

  parcel->writeUint64(most_sig_bits);
  parcel->writeUint64(least_sig_bits);
}

std::unique_ptr<bluetooth::UUID> CreateUUIDFromParcel(
    const android::Parcel& parcel) {
  bluetooth::UUID::UUID128Bit bytes;

  uint64_t most_sig_bits = parcel.readUint64();
  uint64_t least_sig_bits = parcel.readUint64();

  bytes[0] = (most_sig_bits >> 56) & 0xFF;
  bytes[1] = (most_sig_bits >> 48) & 0xFF;
  bytes[2] = (most_sig_bits >> 40) & 0xFF;
  bytes[3] = (most_sig_bits >> 32) & 0xFF;
  bytes[4] = (most_sig_bits >> 24) & 0xFF;
  bytes[5] = (most_sig_bits >> 16) & 0xFF;
  bytes[6] = (most_sig_bits >> 8) & 0xFF;
  bytes[7] = most_sig_bits & 0xFF;

  bytes[8] = (least_sig_bits >> 56) & 0xFF;
  bytes[9] = (least_sig_bits >> 48) & 0xFF;
  bytes[10] = (least_sig_bits >> 40) & 0xFF;
  bytes[11] = (least_sig_bits >> 32) & 0xFF;
  bytes[12] = (least_sig_bits >> 24) & 0xFF;
  bytes[13] = (least_sig_bits >> 16) & 0xFF;
  bytes[14] = (least_sig_bits >> 8) & 0xFF;
  bytes[15] = least_sig_bits & 0xFF;

  return std::unique_ptr<bluetooth::UUID>(new bluetooth::UUID(bytes));
}

void WriteGattIdentifierToParcel(
    const bluetooth::GattIdentifier& gatt_id,
    android::Parcel* parcel) {
  parcel->writeCString(gatt_id.device_address().c_str());
  parcel->writeInt32(gatt_id.is_primary());

  WriteUUIDToParcel(gatt_id.service_uuid(), parcel);
  WriteUUIDToParcel(gatt_id.characteristic_uuid(), parcel);
  WriteUUIDToParcel(gatt_id.descriptor_uuid(), parcel);

  parcel->writeInt32(gatt_id.service_instance_id());
  parcel->writeInt32(gatt_id.characteristic_instance_id());
  parcel->writeInt32(gatt_id.descriptor_instance_id());
}

std::unique_ptr<bluetooth::GattIdentifier> CreateGattIdentifierFromParcel(
    const android::Parcel& parcel) {
  std::string device_address = parcel.readCString();
  bool is_primary = parcel.readInt32();

  auto service_uuid = CreateUUIDFromParcel(parcel);
  auto char_uuid = CreateUUIDFromParcel(parcel);
  auto desc_uuid = CreateUUIDFromParcel(parcel);

  int service_id = parcel.readInt32();
  int char_id = parcel.readInt32();
  int desc_id = parcel.readInt32();

  return std::unique_ptr<bluetooth::GattIdentifier>(
      new bluetooth::GattIdentifier(
          device_address, is_primary,
          *service_uuid, *char_uuid, *desc_uuid,
          service_id, char_id, desc_id));
}

}  // namespace binder
}  // namespace ipc
