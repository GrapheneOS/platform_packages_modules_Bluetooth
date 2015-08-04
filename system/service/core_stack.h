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

#include <memory>
#include <string>

#include <base/macros.h>

namespace bluetooth {

// This represents the core Bluetooth stack,
// with high level operations that affect many profiles.
// It is also used to access profile interfaces.
class CoreStack {
 public:
  virtual ~CoreStack() = default;

  // Initialize the bluetooth stack and device.
  virtual bool Initialize() = 0;

  // Set the device name.
  // This can be referenced in BLE GAP advertisements.
  virtual bool SetAdapterName(const std::string& name) = 0;

  // Allow activated classic profiles to be discovered.
  virtual bool SetClassicDiscoverable() = 0;

  // Get an interface for a profile (BLE GATT, A2DP, etc).
  virtual const void* GetInterface(const char* profile) = 0;

  // Factory method that creates a real CoreStack instance. This should be used
  // in production code.
  static std::unique_ptr<CoreStack> Create();

 protected:
  CoreStack() = default;

 private:
  DISALLOW_COPY_AND_ASSIGN(CoreStack);
};

}  // namespace bluetooth
