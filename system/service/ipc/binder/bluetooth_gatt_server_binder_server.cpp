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

#include "service/ipc/binder/bluetooth_gatt_server_binder_server.h"

#include <base/logging.h>

namespace ipc {
namespace binder {

BluetoothGattServerBinderServer::BluetoothGattServerBinderServer(
    bluetooth::Adapter* adapter) : adapter_(adapter) {
  CHECK(adapter_);
}

bool BluetoothGattServerBinderServer::RegisterServer(
    const android::sp<IBluetoothGattServerCallback>& callback) {
  VLOG(2) << __func__;
  // TODO(armansito): Implement.
  LOG(WARNING) << "Not implemented";
  return false;
}

void BluetoothGattServerBinderServer::UnregisterServer(int server_if) {
  VLOG(2) << __func__;
  // TODO(armansito): Implement.
  LOG(WARNING) << "Not implemented";
}

void BluetoothGattServerBinderServer::UnregisterAll() {
  VLOG(2) << __func__;
  // TODO(armansito): Implement.
  LOG(WARNING) << "Not implemented";
}

}  // namespace binder
}  // namespace ipc
