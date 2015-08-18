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

#include <atomic>
#include <memory>
#include <string>

#include <base/macros.h>

#include "service/hal/bluetooth_interface.h"

namespace bluetooth {

// Represents the local Bluetooth adapter.
class Adapter : hal::BluetoothInterface::Observer {
 public:
  Adapter();
  ~Adapter();

  // Returns true, if the adapter radio is current powered.
  bool IsEnabled();

  // Enables Bluetooth. This method will send a request to the Bluetooth adapter
  // to power up its radio. Returns true, if the request was successfully sent
  // to the controller, otherwise returns false. A successful call to this
  // method only means that the enable request has been sent to the Bluetooth
  // controller and does not imply that the operation itself succeeded.
  bool Enable();

  // Powers off the Bluetooth radio. Returns true, if the disable request was
  // successfully sent to the Bluetooth controller.
  bool Disable();

  // Sets the name assigned to the local Bluetooth adapter. This is the name
  // that the local controller will present to remote devices.
  bool SetName(const std::string& name);

 private:
  // hal::BluetoothInterface::Observer overrides.
  void AdapterStateChangedCallback(bt_state_t state) override;
  void AdapterPropertiesCallback(bt_status_t status,
                                 int num_properties,
                                 bt_property_t* properties) override;

  // Sends a request to set the given HAL adapter property type and value.
  bool SetAdapterProperty(bt_property_type_t type, void* value, int length);

  // True if the adapter radio is currently powered.
  std::atomic_bool enabled_;

  DISALLOW_COPY_AND_ASSIGN(Adapter);
};

}  // namespace bluetooth
