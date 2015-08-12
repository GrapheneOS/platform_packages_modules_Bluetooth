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

#include "service/ipc/binder/bluetooth_binder_server.h"

#include <base/logging.h>

namespace ipc {

BluetoothBinderServer::BluetoothBinderServer(bluetooth::CoreStack* core_stack)
    : core_stack_(core_stack) {
  CHECK(core_stack_);
}

BluetoothBinderServer::~BluetoothBinderServer() {
}

// binder::BnBluetooth overrides:
bool BluetoothBinderServer::IsEnabled() {
  // TODO(armansito): Implement.
  VLOG(2) << __func__;
  return false;
}

int BluetoothBinderServer::GetState() {
  // TODO(armansito): Implement.
  return -1;
}

bool BluetoothBinderServer::Enable() {
  // TODO(armansito): Implement.
  return false;
}

bool BluetoothBinderServer::EnableNoAutoConnect() {
  // TODO(armansito): Implement.
  return false;
}

bool BluetoothBinderServer::Disable() {
  // TODO(armansito): Implement.
  return false;
}

}  // namespace ipc
