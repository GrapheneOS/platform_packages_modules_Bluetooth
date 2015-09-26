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

#include "service/ipc/binder/interface_with_clients_base.h"

#include <base/logging.h>

namespace ipc {
namespace binder {

bool InterfaceWithClientsBase::RegisterClientBase(
    const android::sp<IInterface>& callback,
    bluetooth::BluetoothClientInstanceFactory* factory) {
  VLOG(2) << __func__;
  CHECK(factory);

  if (!callback.get()) {
    LOG(ERROR) << "Cannot register a NULL callback";
    return false;
  }

  // Store the callback in the pending list. It will get removed later when the
  // stack notifies us asynchronously.
  bluetooth::UUID app_uuid = bluetooth::UUID::GetRandom();
  if (!pending_callbacks_.Register(app_uuid, callback)) {
    LOG(ERROR) << "Failed to store |callback| to map";
    return false;
  }

  // Create a weak pointer and pass that to the callback to prevent an invalid
  // access later. Since this object is managed using Android's StrongPointer
  // (sp) we are using a wp here rather than std::weak_ptr.
  android::wp<InterfaceWithClientsBase> weak_ptr_to_this(this);

  bluetooth::BluetoothClientInstanceFactory::RegisterCallback cb =
      [weak_ptr_to_this](
          bluetooth::BLEStatus status,
          const bluetooth::UUID& in_uuid,
          std::unique_ptr<bluetooth::BluetoothClientInstance> client) {
        // If the weak pointer was invalidated then there is nothing we can do.
        android::sp<InterfaceWithClientsBase> strong_ptr_to_this =
            weak_ptr_to_this.promote();
        if (!strong_ptr_to_this.get()) {
          VLOG(2) << "InterfaceWithClientsBase was deleted while client was "
                  << "being registered";
          return;
        }

        strong_ptr_to_this->OnRegisterClient(
            status, in_uuid, std::move(client));
      };

  if (factory->RegisterClient(app_uuid, cb))
    return true;

  LOG(ERROR) << "Failed to register client";
  pending_callbacks_.Remove(app_uuid);

  return false;
}

void InterfaceWithClientsBase::UnregisterClientBase(int client_if) {
  VLOG(2) << __func__;
  std::lock_guard<std::mutex> lock(maps_lock_);

  cif_to_cb_.Remove(client_if);
  cif_to_client_.erase(client_if);
}

void InterfaceWithClientsBase::UnregisterAllBase() {
  VLOG(2) << __func__;
  std::lock_guard<std::mutex> lock(maps_lock_);

  cif_to_cb_.Clear();
  cif_to_client_.clear();
}

android::sp<IInterface> InterfaceWithClientsBase::GetCallback(int client_if) {
  return cif_to_cb_.Get(client_if);
}

std::shared_ptr<bluetooth::BluetoothClientInstance>
InterfaceWithClientsBase::GetClientInstance(int client_if) {
  auto iter = cif_to_client_.find(client_if);
  if (iter == cif_to_client_.end())
    return std::shared_ptr<bluetooth::BluetoothClientInstance>();
  return iter->second;
}

void InterfaceWithClientsBase::OnRegisterClient(
    bluetooth::BLEStatus status,
    const bluetooth::UUID& uuid,
    std::unique_ptr<bluetooth::BluetoothClientInstance> client) {
  VLOG(2) << __func__ << " - status: " << status;

  // Simply remove the callback from |pending_callbacks_| as it no longer
  // belongs in there.
  sp<IInterface> callback = pending_callbacks_.Remove(uuid);

  // |callback| might be NULL if it was removed from the pending list, e.g. the
  // remote process that owns the callback died.
  if (!callback.get()) {
    VLOG(1) << "Callback was removed before the call to \"RegisterClient\" "
            << "returned; unregistering client";
    return;
  }

  if (status != bluetooth::BLE_STATUS_SUCCESS) {
    // The call wasn't successful. Notify the implementation and return.
    LOG(ERROR) << "Failed to register client: " << status;
    OnRegisterClientImpl(status, callback, nullptr);
    return;
  }

  std::lock_guard<std::mutex> lock(maps_lock_);
  int client_if = client->GetClientId();
  CHECK(client_if);
  if (!cif_to_cb_.Register(client_if, callback, this)) {
    LOG(ERROR) << "Failed to store callback";
    OnRegisterClientImpl(bluetooth::BLE_STATUS_FAILURE, callback, nullptr);
    return;
  }

  VLOG(1) << "Registered BluetoothClientInstance - ID: " << client_if;

  auto shared_client =
      std::shared_ptr<bluetooth::BluetoothClientInstance>(client.release());
  cif_to_client_[client_if] = shared_client;

  OnRegisterClientImpl(status, callback, shared_client.get());
}

void InterfaceWithClientsBase::OnRemoteCallbackRemoved(const int& key) {
  VLOG(2) << __func__ << " client_if: " << key;
  std::lock_guard<std::mutex> lock(maps_lock_);

  // No need to remove from the callback map as the entry should be already
  // removed when this callback gets called.
  cif_to_client_.erase(key);
}

}  // namespace binder
}  // namespace ipc
