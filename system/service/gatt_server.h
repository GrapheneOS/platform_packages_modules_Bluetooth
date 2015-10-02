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

#include <map>
#include <mutex>

#include <base/macros.h>

#include "service/bluetooth_client_instance.h"
#include "service/hal/bluetooth_gatt_interface.h"
#include "service/uuid.h"

namespace bluetooth {

// A GattServer instance represents an application's handle to perform GATT
// server-role operations. Instances cannot be created directly and should be
// obtained through the factory.
class GattServer : public BluetoothClientInstance {
 public:
  // The desctructor automatically unregisters this instance from the stack.
  ~GattServer() override;

  // BluetoothClientInstace overrides:
  const UUID& GetAppIdentifier() const override;
  int GetClientId() const override;

 private:
  friend class GattServerFactory;

  // Constructor shouldn't be called directly as instance are meant to be
  // obtained from the factory.
  GattServer(const UUID& uuid, int server_if);

  // See getters for documentation.
  UUID app_identifier_;
  int server_if_;

  DISALLOW_COPY_AND_ASSIGN(GattServer);
};

// GattServerFactory is used to register and obtain a per-application GattServer
// instance. Users should call RegisterServer to obtain their own unique
// GattServer instance that has been registered with the Bluetooth stack.
class GattServerFactory : public BluetoothClientInstanceFactory,
                          private hal::BluetoothGattInterface::ServerObserver {
 public:
  // Don't construct/destruct directly except in tests. Instead, obtain a handle
  // from an Adapter instance.
  GattServerFactory();
  ~GattServerFactory() override;

  // BluetoothClientInstanceFactory override:
  bool RegisterClient(const UUID& uuid,
                      const RegisterCallback& callback) override;

 private:
  // hal::BluetoothGattInterface::ServerObserver override:
  void RegisterServerCallback(
      hal::BluetoothGattInterface* gatt_iface,
      int status, int server_if,
      const bt_uuid_t& app_uuid) override;

  // Map of pending calls to register.
  std::mutex pending_calls_lock_;
  std::map<UUID, RegisterCallback> pending_calls_;

  DISALLOW_COPY_AND_ASSIGN(GattServerFactory);
};

}  // namespace bluetooth
