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

#pragma once

#include <base/macros.h>

#include "service/ipc/binder/IBluetooth.h"

namespace bluetooth {
class Adapter;
}  // namespace bluetooth

namespace ipc {

// Implements the server side of the IBluetooth Binder interface.
class BluetoothBinderServer : public binder::BnBluetooth {
 public:
  explicit BluetoothBinderServer(bluetooth::Adapter* adapter);
  ~BluetoothBinderServer() override;

  // binder::BnBluetooth overrides:
  bool IsEnabled() override;
  int GetState() override;
  bool Enable() override;
  bool EnableNoAutoConnect() override;
  bool Disable() override;

 private:
  // Weak handle on the Adapter.
  bluetooth::Adapter* adapter_;

  DISALLOW_COPY_AND_ASSIGN(BluetoothBinderServer);
};

}  // namespace ipc
