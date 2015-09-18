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

#include "service/ipc/binder/bluetooth_low_energy_binder_server.h"

#include <base/logging.h>

#include "service/adapter.h"

namespace ipc {
namespace binder {

BluetoothLowEnergyBinderServer::BluetoothLowEnergyBinderServer(
    bluetooth::Adapter* adapter) : adapter_(adapter) {
  CHECK(adapter_);
}

BluetoothLowEnergyBinderServer::~BluetoothLowEnergyBinderServer() {
}

void BluetoothLowEnergyBinderServer::RegisterClient(
    const android::sp<IBluetoothLowEnergyCallback>& callback) {
  VLOG(2) << __func__;
  if (!callback.get()) {
    LOG(ERROR) << "Cannot register a NULL callback";
    return;
  }

  bluetooth::LowEnergyClientFactory* ble_factory =
      adapter_->GetLowEnergyClientFactory();

  // Store the callback in the pending list. It will get removed later when the
  // stack notifies us asynchronously.
  bluetooth::UUID app_uuid = bluetooth::UUID::GetRandom();
  if (!pending_callbacks_.Register(app_uuid, callback)) {
    LOG(ERROR) << "Failed to store |callback| to map";
    return;
  }

  // Create a weak pointer and pass that to the callback to prevent an invalid
  // access later. Since this object is managed using Android's StrongPointer
  // (sp) we are using a wp here rather than std::weak_ptr.
  android::wp<BluetoothLowEnergyBinderServer> weak_ptr_to_this(this);

  bluetooth::LowEnergyClientFactory::ClientCallback client_cb =
      [weak_ptr_to_this](bluetooth::BLEStatus status,
                         const bluetooth::UUID& in_uuid,
                         std::unique_ptr<bluetooth::LowEnergyClient> client) {
        // If the weak pointer was invalidated then there's nothing we can do.
        android::sp<BluetoothLowEnergyBinderServer> strong_ptr_to_this =
            weak_ptr_to_this.promote();
        if (!strong_ptr_to_this.get()) {
          VLOG(2) << "BluetoothLowEnergyBinderServer was deleted before "
                  << "callback was registered";
          return;
        }

        strong_ptr_to_this->OnRegisterClient(
            status, in_uuid, std::move(client));
      };

  if (ble_factory->RegisterClient(app_uuid, client_cb))
    return;

  LOG(ERROR) << "Failed to register client";
  pending_callbacks_.Remove(app_uuid);
}

void BluetoothLowEnergyBinderServer::UnregisterClient(int client_if) {
  VLOG(2) << __func__;
  std::lock_guard<std::mutex> lock(maps_lock_);

  cif_to_cb_.Remove(client_if);
  cif_to_client_.erase(client_if);
}

void BluetoothLowEnergyBinderServer::UnregisterAll() {
  VLOG(2) << __func__;
  std::lock_guard<std::mutex> lock(maps_lock_);

  cif_to_cb_.Clear();
  cif_to_client_.clear();
}

void BluetoothLowEnergyBinderServer::StartMultiAdvertising(
    int client_if,
    const bluetooth::AdvertiseData& advertise_data,
    const bluetooth::AdvertiseData& scan_response,
    const bluetooth::AdvertiseSettings& settings) {
  LOG(WARNING) << "Not implemented";
  // TODO(armansito): implement
}

void BluetoothLowEnergyBinderServer::StopMultiAdvertising(int client_if) {
  LOG(WARNING) << "Not implemented";
  // TODO(armansito): implement
}

void BluetoothLowEnergyBinderServer::OnRemoteCallbackRemoved(const int& key) {
  VLOG(2) << __func__ << " client_if: " << key;
  std::lock_guard<std::mutex> lock(maps_lock_);

  // No need to remove from the callback map as the entry should be already
  // removed when this callback gets called.
  cif_to_client_.erase(key);
}

void BluetoothLowEnergyBinderServer::OnRegisterClient(
    bluetooth::BLEStatus status,
    const bluetooth::UUID& uuid,
    std::unique_ptr<bluetooth::LowEnergyClient> client) {
  VLOG(2) << __func__ << " - status: " << status;

  // Simply remove the callback from |pending_callbacks_| as it no longer
  // belongs in there.
  sp<IBluetoothLowEnergyCallback> callback = pending_callbacks_.Remove(uuid);

  // |callback| might be NULL if it was removed from the pending list, e.g.
  // because the remote process that owns the callback died.
  if (!callback.get()) {
    VLOG(1) << "Callback was removed before the call to \"RegisterClient\" "
            << "returned; unregistering client";
    // Simply return here. |client| will unregister itself when it goes out of
    // scope.
    return;
  }

  if (status != bluetooth::BLE_STATUS_SUCCESS) {
    // The call wasn't successful. Log and return.
    LOG(ERROR) << "Failed to register Low Energy client: " << status;
    return;
  }

  std::lock_guard<std::mutex> lock(maps_lock_);
  CHECK(client->client_if());
  int client_if = client->client_if();
  if (!cif_to_cb_.Register(client_if, callback, this)) {
    LOG(ERROR) << "Failed to store callback";
    return;
  }

  VLOG(1) << "Registered BluetoothLowEnergy client: " << client_if;

  cif_to_client_[client_if] =
      std::shared_ptr<bluetooth::LowEnergyClient>(client.release());

  // Notify the client.
  callback->OnClientRegistered(static_cast<int>(status), client_if);
}

}  // namespace binder
}  // namespace ipc
