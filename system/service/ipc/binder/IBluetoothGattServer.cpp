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

#include "service/ipc/binder/IBluetoothGattServer.h"

#include <base/logging.h>
#include <binder/Parcel.h>

using android::IBinder;
using android::interface_cast;
using android::Parcel;
using android::sp;
using android::status_t;

namespace ipc {
namespace binder {

// statuc
const char IBluetoothGattServer::kServiceName[] =
    "bluetooth-gatt-server-service";

// BnBluetoothGattServer (server) implementation
// ========================================================

status_t BnBluetoothGattServer::onTransact(
    uint32_t code, const Parcel& data, Parcel* reply, uint32_t flags) {
  VLOG(2) << "IBluetoothGattServer: " << code;
  if (!data.checkInterface(this))
    return android::PERMISSION_DENIED;

  switch (code) {
  case REGISTER_SERVER_TRANSACTION: {
    sp<IBinder> callback = data.readStrongBinder();
    bool result = RegisterServer(
        interface_cast<IBluetoothGattServerCallback>(callback));
    reply->writeInt32(result);
    return android::NO_ERROR;
  }
  case UNREGISTER_SERVER_TRANSACTION: {
    int server_if = data.readInt32();
    UnregisterServer(server_if);
    return android::NO_ERROR;
  }
  case UNREGISTER_ALL_TRANSACTION: {
    UnregisterAll();
    return android::NO_ERROR;
  }
  default:
    return BBinder::onTransact(code, data, reply, flags);
  }
}

// BpBluetoothGattServer (client) implementation
// ========================================================

BpBluetoothGattServer::BpBluetoothGattServer(const sp<IBinder>& impl)
    : BpInterface<IBluetoothGattServer>(impl) {
}

bool BpBluetoothGattServer::RegisterServer(
    const sp<IBluetoothGattServerCallback>& callback) {
  Parcel data, reply;

  data.writeInterfaceToken(IBluetoothGattServer::getInterfaceDescriptor());
  data.writeStrongBinder(IInterface::asBinder(callback.get()));

  remote()->transact(IBluetoothGattServer::REGISTER_SERVER_TRANSACTION,
                     data, &reply);

  return reply.readInt32();
}

void BpBluetoothGattServer::UnregisterServer(int server_if) {
  Parcel data, reply;

  data.writeInterfaceToken(IBluetoothGattServer::getInterfaceDescriptor());
  data.writeInt32(server_if);

  remote()->transact(IBluetoothGattServer::UNREGISTER_SERVER_TRANSACTION,
                     data, &reply);
}

void BpBluetoothGattServer::UnregisterAll() {
  Parcel data, reply;

  data.writeInterfaceToken(IBluetoothGattServer::getInterfaceDescriptor());

  remote()->transact(IBluetoothGattServer::UNREGISTER_ALL_TRANSACTION,
                     data, &reply);
}

IMPLEMENT_META_INTERFACE(BluetoothGattServer,
                         IBluetoothGattServer::kServiceName);

}  // namespace binder
}  // namespace ipc
