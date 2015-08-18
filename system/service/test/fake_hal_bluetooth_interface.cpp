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

#include "service/test/fake_hal_bluetooth_interface.h"

namespace bluetooth {
namespace testing {

void FakeHALBluetoothInterface::AddObserver(Observer* observer) {
  // TODO(armansito): Do something meaningful here to simulate test behavior.
}

void FakeHALBluetoothInterface::RemoveObserver(Observer* observer) {
  // TODO(armansito): Do something meaningful here to simulate test behavior.
}

const bt_interface_t* FakeHALBluetoothInterface::GetHALInterface() const {
  // TODO(armansito): Do something meaningful here to simulate test behavior.
  return nullptr;
}

const bluetooth_device_t* FakeHALBluetoothInterface::GetHALAdapter() const {
  // TODO(armansito): Do something meaningful here to simulate test behavior.
  return nullptr;
}

}  // namespace testing
}  // namespace bluetooth
