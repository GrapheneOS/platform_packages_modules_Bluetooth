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

#include <functional>
#include <memory>

#include <base/macros.h>

#include "service/low_energy_constants.h"
#include "service/uuid.h"

namespace bluetooth {

// A BluetoothClientInstance represents an application's handle to an instance
// that is registered with the underlying Bluetooth stack using a UUID and has a
// stack-assigned integer "client_if" ID associated with it.
class BluetoothClientInstance {
 public:
  virtual ~BluetoothClientInstance() = default;

  // Returns the app-specific unique ID used while registering this client.
  virtual const UUID& GetAppIdentifier() const = 0;

  // Returns the HAL "interface ID" assigned to this instance by the stack.
  virtual int GetClientId() const = 0;

 protected:
  // Constructor shouldn't be called directly as instances are meant to be
  // obtained from the factory.
  BluetoothClientInstance() = default;

 private:
  DISALLOW_COPY_AND_ASSIGN(BluetoothClientInstance);
};

// A BluetoothClientInstanceFactory provides a common interface for factory
// classes that handle asynchronously registering a per-application instance of
// a BluetoothClientInstance with the underlying stack.
class BluetoothClientInstanceFactory {
 public:
  BluetoothClientInstanceFactory() = default;
  virtual ~BluetoothClientInstanceFactory() = default;

  // Callback invoked as a result of a call to RegisterClient.
  using RegisterCallback = std::function<void(
      BLEStatus status, const UUID& app_uuid,
      std::unique_ptr<BluetoothClientInstance> client)>;

  // Registers a client of type T for the given unique identifier |app_uuid|.
  // On success, this asynchronously invokes |callback| with a unique pointer
  // to an instance of type T whose ownership can be taken by the caller. In
  // the case of an error, the pointer will contain nullptr.
  virtual bool RegisterClient(const UUID& app_uuid,
                              const RegisterCallback& callback) = 0;

 private:
  DISALLOW_COPY_AND_ASSIGN(BluetoothClientInstanceFactory);
};

}  // namespace bluetooth
