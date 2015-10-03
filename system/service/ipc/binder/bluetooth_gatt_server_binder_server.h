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

#include "service/gatt_server.h"
#include "service/ipc/binder/IBluetoothGattServer.h"
#include "service/ipc/binder/IBluetoothGattServerCallback.h"
#include "service/ipc/binder/interface_with_clients_base.h"

namespace bluetooth {
class Adapter;
}  // namespace bluetooth

namespace ipc {
namespace binder {

// Implements the server side of the IBluetoothGattServer interface.
class BluetoothGattServerBinderServer : public BnBluetoothGattServer,
                                        public InterfaceWithClientsBase {
 public:
  explicit BluetoothGattServerBinderServer(bluetooth::Adapter* adapter);
  ~BluetoothGattServerBinderServer() override = default;

  // IBluetoothGattServer overrides:
  bool RegisterServer(
      const android::sp<IBluetoothGattServerCallback>& callback) override;
  void UnregisterServer(int server_if) override;
  void UnregisterAll() override;
  bool BeginServiceDeclaration(
      int server_if, bool is_primary, const bluetooth::UUID& uuid,
      std::unique_ptr<bluetooth::GattIdentifier>* out_id) override;
  bool AddCharacteristic(
      int server_if, const bluetooth::UUID& uuid,
      int properties, int permissions,
      std::unique_ptr<bluetooth::GattIdentifier>* out_id) override;
  bool EndServiceDeclaration(int server_if) override;

 private:
  // Returns a pointer to the IBluetoothGattServerBinderServer instance
  // associated with |server_if|. Returns NULL if such a callback cannot be
  // found.
  android::sp<IBluetoothGattServerCallback>
      GetGattServerCallback(int server_if);

  // Returns a pointer to the GattServer instance associated with |server_if|.
  // Returns NULL if such a client cannot be found.
  std::shared_ptr<bluetooth::GattServer> GetGattServer(int server_if);

  // InterfaceWithClientsBase override:
  void OnRegisterClientImpl(
      bluetooth::BLEStatus status,
      android::sp<IInterface> callback,
      bluetooth::BluetoothClientInstance* client) override;

  bluetooth::Adapter* adapter_;  // weak

  DISALLOW_COPY_AND_ASSIGN(BluetoothGattServerBinderServer);
};

}  // namespace binder
}  // namespace ipc
