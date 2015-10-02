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

#include "service/gatt_server.h"

using std::lock_guard;
using std::mutex;

namespace bluetooth {

// GattServer implementation
// ========================================================

GattServer::GattServer(const UUID& uuid, int server_if)
    : app_identifier_(uuid),
      server_if_(server_if) {
}

GattServer::~GattServer() {
  hal::BluetoothGattInterface::Get()->
      GetServerHALInterface()->unregister_server(server_if_);
}

const UUID& GattServer::GetAppIdentifier() const {
  return app_identifier_;
}

int GattServer::GetClientId() const {
  return server_if_;
}

// GattServerFactory implementation
// ========================================================

GattServerFactory::GattServerFactory() {
  hal::BluetoothGattInterface::Get()->AddServerObserver(this);
}

GattServerFactory::~GattServerFactory() {
  hal::BluetoothGattInterface::Get()->RemoveServerObserver(this);
}

bool GattServerFactory::RegisterClient(const UUID& uuid,
                                       const RegisterCallback& callback) {
  VLOG(1) << __func__ << " - UUID: " << uuid.ToString();
  lock_guard<mutex> lock(pending_calls_lock_);

  if (pending_calls_.find(uuid) != pending_calls_.end()) {
    LOG(ERROR) << "GATT-server client with given UUID already being registered "
               << " - UUID: " << uuid.ToString();
    return false;
  }

  const btgatt_server_interface_t* hal_iface =
      hal::BluetoothGattInterface::Get()->GetServerHALInterface();
  bt_uuid_t app_uuid = uuid.GetBlueDroid();

  if (hal_iface->register_server(&app_uuid) != BT_STATUS_SUCCESS)
    return false;

  pending_calls_[uuid] = callback;

  return true;
}

void GattServerFactory::RegisterServerCallback(
    hal::BluetoothGattInterface* /* gatt_iface */,
    int status, int server_if,
    const bt_uuid_t& app_uuid) {
  UUID uuid(app_uuid);

  VLOG(1) << __func__ << " - UUID: " << uuid.ToString();
  lock_guard<mutex> lock(pending_calls_lock_);

  auto iter = pending_calls_.find(uuid);
  if (iter == pending_calls_.end()) {
    VLOG(1) << "Ignoring callback for unknown app_id: " << uuid.ToString();
    return;
  }

  // No need to construct a server if the call wasn't successful.
  std::unique_ptr<GattServer> server;
  BLEStatus result = BLE_STATUS_FAILURE;
  if (status == BT_STATUS_SUCCESS) {
    server.reset(new GattServer(uuid, server_if));
    result = BLE_STATUS_SUCCESS;
  }

  // Notify the result via the result callback.
  iter->second(result, uuid, std::move(server));

  pending_calls_.erase(iter);
}

}  // namespace bluetooth
