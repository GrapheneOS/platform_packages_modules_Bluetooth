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

#include "service/hal/bluetooth_interface.h"

#include <base/macros.h>

namespace bluetooth {
namespace testing {

class FakeHALBluetoothInterface : public hal::BluetoothInterface {
 public:
  FakeHALBluetoothInterface() = default;
  ~FakeHALBluetoothInterface() override = default;

  // TODO(armansito): Add hooks here to simulate test behavior.

  // hal::BluetoothInterface overrides:
  void AddObserver(Observer* observer) override;
  void RemoveObserver(Observer* observer) override;
  const bt_interface_t* GetHALInterface() const override;
  const bluetooth_device_t* GetHALAdapter() const override;

 private:
  DISALLOW_COPY_AND_ASSIGN(FakeHALBluetoothInterface);
};

}  // namespace testing
}  // namespace bluetooth
