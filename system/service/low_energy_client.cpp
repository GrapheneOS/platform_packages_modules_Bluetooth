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

#include "service/low_energy_client.h"

#include <base/logging.h>

using std::lock_guard;
using std::mutex;

namespace bluetooth {

LowEnergyClient::LowEnergyClient(const UUID& uuid, int client_if)
    : app_identifier_(uuid),
      client_if_(client_if) {
}

LowEnergyClient::~LowEnergyClient() {
  // Automatically unregister the client.
  VLOG(1) << "LowEnergyClient unregistering client: " << client_if_;
  hal::BluetoothGattInterface::Get()->
      GetClientHALInterface()->unregister_client(client_if_);
}

LowEnergyClientFactory::LowEnergyClientFactory() {
  hal::BluetoothGattInterface::Get()->AddClientObserver(this);
}

LowEnergyClientFactory::~LowEnergyClientFactory() {
  hal::BluetoothGattInterface::Get()->RemoveClientObserver(this);
}

bool LowEnergyClientFactory::RegisterClient(const UUID& uuid,
                                            const ClientCallback& callback) {
  VLOG(1) << __func__ << " - UUID: " << uuid.ToString();
  lock_guard<mutex> lock(pending_calls_lock_);

  if (pending_calls_.find(uuid) != pending_calls_.end()) {
    LOG(ERROR) << "Low-Energy client with given UUID already registered - "
               << "UUID: " << uuid.ToString();
    return false;
  }

  const btgatt_client_interface_t* hal_iface =
      hal::BluetoothGattInterface::Get()->GetClientHALInterface();
  bt_uuid_t app_uuid = uuid.GetBlueDroid();

  if (hal_iface->register_client(&app_uuid) != BT_STATUS_SUCCESS)
    return false;

  pending_calls_[uuid] = callback;

  return true;
}

void LowEnergyClientFactory::RegisterClientCallback(
    int status, int client_if,
    const bt_uuid_t& app_uuid) {
  UUID uuid(app_uuid);

  VLOG(1) << __func__ << " - UUID: " << uuid.ToString();
  lock_guard<mutex> lock(pending_calls_lock_);

  auto iter = pending_calls_.find(uuid);
  if (iter == pending_calls_.end()) {
    VLOG(1) << "Ignoring callback for unknown app_id: " << uuid.ToString();
    return;
  }

  // No need to construct a client if the call wasn't successful.
  std::unique_ptr<LowEnergyClient> client;
  BLEStatus result = BLE_STATUS_FAILURE;
  if (status == BT_STATUS_SUCCESS) {
    client.reset(new LowEnergyClient(uuid, client_if));
    result = BLE_STATUS_SUCCESS;
  }

  // Notify the result via the success callback.
  iter->second(result, uuid, std::move(client));

  pending_calls_.erase(iter);
}

}  // namespace bluetooth
