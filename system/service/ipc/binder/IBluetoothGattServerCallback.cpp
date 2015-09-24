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

#include "service/ipc/binder/IBluetoothGattServerCallback.h"

#include <base/logging.h>
#include <binder/Parcel.h>

#include "service/ipc/binder/parcel_helpers.h"

using android::IBinder;
using android::Parcel;
using android::sp;
using android::status_t;

namespace ipc {
namespace binder {

// static
const char IBluetoothGattServerCallback::kServiceName[] =
    "bluetooth-gatt-server-callback-service";

// BnBluetoothGattServerCallback (server) implementation
// ========================================================

status_t BnBluetoothGattServerCallback::onTransact(
    uint32_t code,
    const Parcel& data,
    Parcel* reply,
    uint32_t flags) {
  VLOG(2) << "IBluetoothGattServerCallback: " << code;
  if (!data.checkInterface(this))
    return android::PERMISSION_DENIED;

  switch (code) {
  case ON_SERVER_REGISTERED_TRANSACTION: {
    int status = data.readInt32();
    int server_if = data.readInt32();
    OnServerRegistered(status, server_if);
    return android::NO_ERROR;
  }
  case ON_SERVICE_ADDED_TRANSACTION: {
    int status = data.readInt32();
    auto gatt_id = CreateGattIdentifierFromParcel(data);
    CHECK(gatt_id);
    OnServiceAdded(status, *gatt_id);
    return android::NO_ERROR;
  }
  default:
    return BBinder::onTransact(code, data, reply, flags);
  }
}

// BpBluetoothGattServerCallback (client) implementation
// ========================================================

BpBluetoothGattServerCallback::BpBluetoothGattServerCallback(
    const sp<IBinder>& impl)
    : BpInterface<IBluetoothGattServerCallback>(impl) {
}

void BpBluetoothGattServerCallback::OnServerRegistered(
    int status, int server_if) {
  Parcel data, reply;

  data.writeInterfaceToken(
      IBluetoothGattServerCallback::getInterfaceDescriptor());
  data.writeInt32(status);
  data.writeInt32(server_if);

  remote()->transact(
      IBluetoothGattServerCallback::ON_SERVER_REGISTERED_TRANSACTION,
      data, &reply,
      IBinder::FLAG_ONEWAY);
}

void BpBluetoothGattServerCallback::OnServiceAdded(
    int status,
    const bluetooth::GattIdentifier& service_id) {
  Parcel data, reply;

  data.writeInterfaceToken(
      IBluetoothGattServerCallback::getInterfaceDescriptor());
  data.writeInt32(status);
  WriteGattIdentifierToParcel(service_id, &data);

  remote()->transact(IBluetoothGattServerCallback::ON_SERVICE_ADDED_TRANSACTION,
                     data, &reply,
                     IBinder::FLAG_ONEWAY);
}

IMPLEMENT_META_INTERFACE(BluetoothGattServerCallback,
                         IBluetoothGattServerCallback::kServiceName);

}  // namespace binder
}  // namespace ipc
