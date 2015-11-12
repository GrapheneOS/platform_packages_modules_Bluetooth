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

#include "service/ipc/binder/bluetooth_gatt_client_binder_server.h"

#include <base/logging.h>

namespace ipc {
namespace binder {

BluetoothGattClientBinderServer::BluetoothGattClientBinderServer(
    bluetooth::Adapter* adapter) : adapter_(adapter) {
  CHECK(adapter_);
}

bool BluetoothGattClientBinderServer::RegisterClient(
    const android::sp<IBluetoothGattClientCallback>& callback) {
  VLOG(2) << __func__;
  // TODO(armansito): Implement.

  return false;
}

void BluetoothGattClientBinderServer::UnregisterClient(int client_id) {
  // TODO(armansito): Implement.
}

void BluetoothGattClientBinderServer::UnregisterAll() {
  // TODO(armansito): Implement.
}

}  // namespace binder
}  // namespace ipc
