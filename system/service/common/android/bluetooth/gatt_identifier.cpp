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

#include "service/common/android/bluetooth/gatt_identifier.h"
#include "service/common/android/bluetooth/uuid.h"

#include <utils/String16.h>
#include <utils/String8.h>

using android::OK;
using android::String8;
using android::String16;

namespace android {
namespace bluetooth {

status_t GattIdentifier::writeToParcel(Parcel* parcel) const {
  status_t status =
      parcel->writeString16(String16(String8(device_address_.c_str())));
  if (status != OK) return status;

  status = parcel->writeBool(is_primary_);
  if (status != OK) return status;

  parcel->writeParcelable((UUID)service_uuid_);
  parcel->writeParcelable((UUID)char_uuid_);
  parcel->writeParcelable((UUID)desc_uuid_);

  status = parcel->writeInt32(service_instance_id_);
  if (status != OK) return status;

  status = parcel->writeInt32(char_instance_id_);
  if (status != OK) return status;

  status = parcel->writeInt32(desc_instance_id_);
  return status;
}

status_t GattIdentifier::readFromParcel(const Parcel* parcel) {
  String16 addr;
  status_t status = parcel->readString16(&addr);
  if (status != OK) return status;

  device_address_ = std::string(String8(addr).string());

  status = parcel->readBool(&is_primary_);
  if (status != OK) return status;

  UUID uuid;
  status = parcel->readParcelable(&uuid);
  if (status != OK) return status;
  service_uuid_ = uuid;

  status = parcel->readParcelable(&uuid);
  if (status != OK) return status;
  char_uuid_ = uuid;

  status = parcel->readParcelable(&uuid);
  if (status != OK) return status;
  desc_uuid_ = uuid;

  status = parcel->readInt32(&service_instance_id_);
  if (status != OK) return status;

  status = parcel->readInt32(&char_instance_id_);
  if (status != OK) return status;

  status = parcel->readInt32(&desc_instance_id_);
  return status;
}

}  // namespace bluetooth
}  // namespace android
