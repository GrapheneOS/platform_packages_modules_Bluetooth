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

#include "service/hal/gatt_helpers.h"

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
  // Automatically unregister the server.
  VLOG(1) << "GattServer unregistering: " << server_if_;

  // Unregister as observer so we no longer receive any callbacks.
  hal::BluetoothGattInterface::Get()->RemoveServerObserver(this);

  // Unregister this server, stop all services, and ignore the result.
  // TODO(armansito): stop and remove all services here? unregister_server
  // should really take care of that.
  hal::BluetoothGattInterface::Get()->
      GetServerHALInterface()->unregister_server(server_if_);
}

const UUID& GattServer::GetAppIdentifier() const {
  return app_identifier_;
}

int GattServer::GetClientId() const {
  return server_if_;
}

std::unique_ptr<GattIdentifier> GattServer::BeginServiceDeclaration(
    const UUID& uuid, bool is_primary) {
  VLOG(1) << __func__ << "server_if: " << server_if_
          << " - UUID: " << uuid.ToString()
          << ", is_primary: " << is_primary;
  lock_guard<mutex> lock(mutex_);

  if (pending_decl_) {
    LOG(ERROR) << "Already began service declaration";
    return nullptr;
  }

  CHECK(!pending_id_);
  CHECK(!pending_decl_);
  CHECK(!pending_end_decl_cb_);

  // Calculate the instance ID for this service by searching through the handle
  // map to see how many occurrences of the same service UUID we find.
  int inst_id = 0;
  for (const auto& iter : handle_map_) {
    const GattIdentifier* gatt_id = &iter.first;

    if (!gatt_id->IsService())
      continue;

    if (gatt_id->service_uuid() == uuid)
      ++inst_id;
  }

  // Pass empty string for the address as this is a local service.
  auto service_id = GattIdentifier::CreateServiceId(
      "", inst_id, uuid, is_primary);

  pending_decl_.reset(new ServiceDeclaration());
  pending_decl_->num_handles++;  // 1 handle for the service decl. attribute
  pending_decl_->service_id = *service_id;
  pending_decl_->attributes.push(*service_id);

  return service_id;
}

bool GattServer::EndServiceDeclaration(const ResultCallback& callback) {
  VLOG(1) << __func__ << "server_if: " << server_if_;
  lock_guard<mutex> lock(mutex_);

  if (!callback) {
    LOG(ERROR) << "|callback| cannot be NULL";
    return false;
  }

  if (!pending_decl_) {
    LOG(ERROR) << "Service declaration not begun";
    return false;
  }

  if (pending_end_decl_cb_) {
    LOG(ERROR) << "EndServiceDeclaration already in progress";
    return false;
  }

  CHECK(!pending_id_);

  // There has to be at least one entry here for the service declaration
  // attribute.
  CHECK(pending_decl_->num_handles > 0);
  CHECK(!pending_decl_->attributes.empty());

  std::unique_ptr<GattIdentifier> service_id = PopNextId();
  CHECK(service_id->IsService());
  CHECK(*service_id == pending_decl_->service_id);

  btgatt_srvc_id_t hal_id;
  hal::GetHALServiceId(*service_id, &hal_id);

  bt_status_t status = hal::BluetoothGattInterface::Get()->
      GetServerHALInterface()->add_service(
          server_if_, &hal_id, pending_decl_->num_handles);
  if (status != BT_STATUS_SUCCESS) {
    LOG(ERROR) << "Failed to initiate call to populate GATT service";
    CleanUpPendingData();
    return false;
  }

  pending_id_ = std::move(service_id);
  pending_end_decl_cb_ = callback;

  return true;
}

void GattServer::ServiceAddedCallback(
    hal::BluetoothGattInterface* gatt_iface,
    int status, int server_if,
    const btgatt_srvc_id_t& srvc_id,
    int srvc_handle) {
  lock_guard<mutex> lock(mutex_);

  if (server_if != server_if_)
    return;

  // Construct a GATT identifier.
  auto gatt_id = hal::GetServiceIdFromHAL(srvc_id);
  CHECK(pending_id_);
  CHECK(*gatt_id == *pending_id_);
  CHECK(*gatt_id == pending_decl_->service_id);
  CHECK(pending_id_->IsService());

  VLOG(1) << __func__ << " - server_if: " << server_if
          << " handle: " << srvc_handle
          << " UUID: " << gatt_id->service_uuid().ToString();

  if (status != BT_STATUS_SUCCESS) {
    NotifyEndCallbackAndClearData(static_cast<BLEStatus>(status), *gatt_id);
    return;
  }

  // Add this to the handle map.
  pending_handle_map_[*gatt_id] = srvc_handle;
  CHECK(-1 == pending_decl_->service_handle);
  pending_decl_->service_handle = srvc_handle;

  // More entries aren't supported yet.
  CHECK(pending_decl_->attributes.empty());

  bt_status_t start_status = gatt_iface->GetServerHALInterface()->start_service(
      server_if_, srvc_handle, TRANSPORT_BREDR | TRANSPORT_LE);
  if (start_status == BT_STATUS_SUCCESS)
    return;  // Wait for the pending call.

  // Notify failure.
  NotifyEndCallbackAndClearData(static_cast<BLEStatus>(start_status), *gatt_id);
}

void GattServer::ServiceStartedCallback(
    hal::BluetoothGattInterface* gatt_iface,
    int status, int server_if,
    int srvc_handle) {
  lock_guard<mutex> lock(mutex_);

  if (server_if != server_if_)
    return;

  CHECK(pending_id_);
  CHECK(pending_decl_);
  CHECK(pending_decl_->service_handle == srvc_handle);

  VLOG(1) << __func__ << " - server_if: " << server_if
          << " handle: " << srvc_handle;

  // If we failed to start the service, remove it from the database and ignore
  // the result.
  if (status != BT_STATUS_SUCCESS) {
    gatt_iface->GetServerHALInterface()->delete_service(
        server_if_, srvc_handle);
  }

  // Complete the operation.
  NotifyEndCallbackAndClearData(static_cast<BLEStatus>(status),
                                pending_decl_->service_id);
}

void GattServer::ServiceStoppedCallback(
    hal::BluetoothGattInterface* /* gatt_iface */,
    int /* status */,
    int /* server_if */,
    int /* srvc_handle */) {
  // TODO(armansito): Support stopping a service.
}

void GattServer::NotifyEndCallbackAndClearData(
    BLEStatus status, const GattIdentifier& id) {
  VLOG(1) << __func__ << " status: " << status;
  CHECK(pending_end_decl_cb_);

  if (status == BLE_STATUS_SUCCESS)
    handle_map_.insert(pending_handle_map_.begin(), pending_handle_map_.end());

  pending_end_decl_cb_(status, id);

  CleanUpPendingData();
}

void GattServer::CleanUpPendingData() {
  pending_id_ = nullptr;
  pending_decl_ = nullptr;
  pending_end_decl_cb_ = ResultCallback();
  pending_handle_map_.clear();
}

std::unique_ptr<GattIdentifier> GattServer::PopNextId() {
  CHECK(pending_decl_);

  if (pending_decl_->attributes.empty())
    return nullptr;

  const GattIdentifier& next = pending_decl_->attributes.front();
  std::unique_ptr<GattIdentifier> id(new GattIdentifier(next));

  pending_decl_->attributes.pop();

  return id;
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
    hal::BluetoothGattInterface* gatt_iface,
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

    // Use the unsafe variant to register this as an observer to prevent a
    // deadlock since this callback is currently holding the lock.
    gatt_iface->AddServerObserverUnsafe(server.get());

    result = BLE_STATUS_SUCCESS;
  }

  // Notify the result via the result callback.
  iter->second(result, uuid, std::move(server));

  pending_calls_.erase(iter);
}

}  // namespace bluetooth
