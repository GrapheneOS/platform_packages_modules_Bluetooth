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

#include <string>

#include "hardware/bluetooth.h"

namespace bluetooth {

// This represents the core Bluetooth stack,
// with high level operations that affect many profiles.
// It is also used to access profile interfaces.
class CoreStack {
 public:
  CoreStack();
  ~CoreStack();

  // Initialize the bluetooth stack and device.
  bool Initialize();

  // Set the device name.
  // This can be referenced in BLE GAP advertisements.
  bool SetAdapterName(const std::string& name);

  // Allow activated classic profiles to be discovered.
  bool SetClassicDiscoverable();

  // Get an interface for a profile (BLE GATT, A2DP, etc).
  const void *GetInterface(const char* profile);

 private:
  // Prevent copy and assignment.
  CoreStack& operator=(const CoreStack& rhs) = delete;
  CoreStack(const CoreStack& rhs) = delete;

  // Our libhardware handle.
  bluetooth_device_t *adapter_;

  // Common bluetooth interface handle.
  const bt_interface_t *hal_;
};

}  // namespace bluetooth
