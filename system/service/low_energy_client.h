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
#include <map>
#include <mutex>

#include <base/macros.h>

#include "hal/bluetooth_gatt_interface.h"
#include "service/low_energy_constants.h"
#include "service/uuid.h"

namespace bluetooth {

// A LowEnergyClient represents an application's handle to perform various
// Bluetooth Low Energy GAP operations. Instances cannot be created directly and
// should be obtained through the factory.
class LowEnergyClient {
 public:
  // The destructor automatically unregisters this client instance from the
  // stack.
  ~LowEnergyClient();

  // The app-specific unique ID used while registering this client.
  const UUID& app_identifier() const { return app_identifier_; }

  // The HAL bt_gatt_client "interface ID" assigned to us by the stack. This is
  // what is used internally for BLE transactions.
  int client_if() const { return client_if_; }

 private:
  friend class LowEnergyClientFactory;

  // Constructor/destructor shouldn't be called directly as instances are meant
  // to be obtained from the factory.
  LowEnergyClient(const UUID& uuid, int client_if);

  // See getters above for documentation.
  UUID app_identifier_;
  int client_if_;

  DISALLOW_COPY_AND_ASSIGN(LowEnergyClient);
};

// LowEnergyClientFactory is used to register and obtain a per-application
// LowEnergyClient instance. Users should call RegisterClient to obtain their
// own unique LowEnergyClient instance that has been registered with the
// Bluetooth stack.
class LowEnergyClientFactory
    : private hal::BluetoothGattInterface::ClientObserver {
 public:
  // Don't construct/destruct directly except in tests. Instead, obtain a handle
  // from an Adapter instance..
  LowEnergyClientFactory();
  ~LowEnergyClientFactory();

  // Registers a LowEnergyClient for the given unique identifier |uuid|. On
  // success, this asynchronously invokes |callback| with a unique pointer to a
  // LowEnergyClient instance whose ownership can be taken by the caller. In the
  // case of an error, the pointer will contain a nullptr.
  using ClientCallback =
      std::function<
          void(BLEStatus, const UUID&, std::unique_ptr<LowEnergyClient>)>;
  bool RegisterClient(const UUID& uuid, const ClientCallback& callback);

 private:
  // BluetoothGattInterface::ClientObserver overrides:
  void RegisterClientCallback(int status, int client_if,
                              const bt_uuid_t& app_uuid) override;

  // Map of pending calls to register.
  std::mutex pending_calls_lock_;
  std::map<UUID, ClientCallback> pending_calls_;

  DISALLOW_COPY_AND_ASSIGN(LowEnergyClientFactory);
};

}  // namespace bluetooth
