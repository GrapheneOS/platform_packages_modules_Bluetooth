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

#include "service/ipc/binder/bluetooth_low_energy_binder_server.h"

#include <base/logging.h>

namespace ipc {
namespace binder {

BluetoothLowEnergyBinderServer::BluetoothLowEnergyBinderServer(
    bluetooth::Adapter* adapter) : adapter_(adapter) {
  CHECK(adapter_);
}

BluetoothLowEnergyBinderServer::~BluetoothLowEnergyBinderServer() {
}

void BluetoothLowEnergyBinderServer::RegisterClient(
    const android::sp<IBluetoothLowEnergyCallback>& callback) {
  VLOG(2) << __func__;
  // TODO(armansito): Implement
  LOG(WARNING) << "Not implemented";
}

void BluetoothLowEnergyBinderServer::UnregisterClient(int client_if) {
  VLOG(2) << __func__;
  // TODO(armansito): Implement
  LOG(WARNING) << "Not implemented";
}

void BluetoothLowEnergyBinderServer::UnregisterAll() {
  VLOG(2) << __func__;
  // TODO(armansito): Implement
  LOG(WARNING) << "Not implemented";
}

}  // namespace binder
}  // namespace ipc
