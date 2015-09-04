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
#include <unordered_map>

#include <base/macros.h>

#include "service/ipc/binder/IBluetoothLowEnergy.h"
#include "service/ipc/binder/IBluetoothLowEnergyCallback.h"
#include "service/ipc/binder/remote_callback_map.h"
#include "service/low_energy_client.h"
#include "service/low_energy_constants.h"
#include "service/uuid.h"

namespace bluetooth {
class Adapter;
}  // namespace bluetooth

namespace ipc {
namespace binder {

// Implements the server side of the IBluetoothLowEnergy interface.
class BluetoothLowEnergyBinderServer
    : public BnBluetoothLowEnergy,
      public RemoteCallbackMap<int, IBluetoothLowEnergyCallback>::Delegate {
 public:
  explicit BluetoothLowEnergyBinderServer(bluetooth::Adapter* adapter);
  ~BluetoothLowEnergyBinderServer() override;

  // IBluetoothLowEnergy overrides:
  void RegisterClient(
      const android::sp<IBluetoothLowEnergyCallback>& callback) override;
  void UnregisterClient(int client_if) override;
  void UnregisterAll() override;

 private:
  // RemoteCallbackMap<int, IBluetoothLowEnergyCallback>::Delegate override:
  void OnRemoteCallbackRemoved(const int& key) override;

  // Called as a result of bluetooth::LowEnergyClientFactory::RegisterClient
  void OnRegisterClient(bluetooth::BLEStatus status,
                        const bluetooth::UUID& uuid,
                        std::unique_ptr<bluetooth::LowEnergyClient> client);

  bluetooth::Adapter* adapter_;  // weak

  // Clients that are pending registration. Once their registration is complete,
  // the entry will be removed from this map.
  RemoteCallbackMap<bluetooth::UUID, IBluetoothLowEnergyCallback>
      pending_callbacks_;

  // We keep two maps here: one from client_if IDs to callback Binders and one
  // from client_if IDs to LowEnergyClient instances.
  std::mutex maps_lock_;  // Needed for |cif_to_client_|.
  RemoteCallbackMap<int, IBluetoothLowEnergyCallback> cif_to_cb_;
  std::unordered_map<int, std::shared_ptr<bluetooth::LowEnergyClient>>
      cif_to_client_;

  DISALLOW_COPY_AND_ASSIGN(BluetoothLowEnergyBinderServer);
};

}  // namespace binder
}  // namespace ipc
