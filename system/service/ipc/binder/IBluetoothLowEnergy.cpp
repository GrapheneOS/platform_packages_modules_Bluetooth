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

#include "service/ipc/binder/IBluetoothLowEnergy.h"

#include <base/logging.h>
#include <binder/Parcel.h>

using android::IBinder;
using android::interface_cast;
using android::Parcel;
using android::sp;
using android::status_t;

namespace ipc {
namespace binder {

// static
const char IBluetoothLowEnergy::kServiceName[] =
    "bluetooth-low-energy-service";

// BnBluetoothLowEnergy (server) implementation
// ========================================================

status_t BnBluetoothLowEnergy::onTransact(
    uint32_t code,
    const Parcel& data,
    Parcel* reply,
    uint32_t flags) {
  VLOG(2) << "IBluetoothLowEnergy: " << code;
  if (!data.checkInterface(this))
    return android::PERMISSION_DENIED;

  switch (code) {
  case REGISTER_CLIENT_TRANSACTION: {
    sp<IBinder> callback = data.readStrongBinder();
    RegisterClient(interface_cast<IBluetoothLowEnergyCallback>(callback));
    return android::NO_ERROR;
  }
  case UNREGISTER_CLIENT_TRANSACTION: {
    int client_if = data.readInt32();
    UnregisterClient(client_if);
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

// BpBluetoothLowEnergy (client) implementation
// ========================================================

BpBluetoothLowEnergy::BpBluetoothLowEnergy(const sp<IBinder>& impl)
    : BpInterface<IBluetoothLowEnergy>(impl) {
}

void BpBluetoothLowEnergy::RegisterClient(
      const sp<IBluetoothLowEnergyCallback>& callback) {
  Parcel data, reply;

  data.writeInterfaceToken(IBluetoothLowEnergy::getInterfaceDescriptor());
  data.writeStrongBinder(IInterface::asBinder(callback.get()));

  remote()->transact(IBluetoothLowEnergy::REGISTER_CLIENT_TRANSACTION,
                     data, &reply);
}

void BpBluetoothLowEnergy::UnregisterClient(int client_if) {
  Parcel data, reply;

  data.writeInterfaceToken(IBluetoothLowEnergy::getInterfaceDescriptor());
  data.writeInt32(client_if);

  remote()->transact(IBluetoothLowEnergy::UNREGISTER_CLIENT_TRANSACTION,
                     data, &reply);
}

void BpBluetoothLowEnergy::UnregisterAll() {
  Parcel data, reply;

  data.writeInterfaceToken(IBluetoothLowEnergy::getInterfaceDescriptor());

  remote()->transact(IBluetoothLowEnergy::UNREGISTER_ALL_TRANSACTION,
                     data, &reply);
}

IMPLEMENT_META_INTERFACE(BluetoothLowEnergy, IBluetoothLowEnergy::kServiceName);

}  // namespace binder
}  // namespace ipc
