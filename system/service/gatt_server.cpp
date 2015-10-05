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
  VLOG(1) << __func__ << " server_if: " << server_if_
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

  auto service_id = GetIdForService(uuid, is_primary);
  CHECK(service_id);

  // Pass 0 for permissions and properties as this is a service decl.
  AttributeEntry entry(
      *service_id, kCharacteristicPropertyNone, kAttributePermissionNone);

  pending_decl_.reset(new ServiceDeclaration());
  pending_decl_->num_handles++;  // 1 handle for the service decl. attribute
  pending_decl_->service_id = *service_id;
  pending_decl_->attributes.push_back(entry);

  return service_id;
}

std::unique_ptr<GattIdentifier> GattServer::AddCharacteristic(
      const UUID& uuid, int properties, int permissions) {
  VLOG(1) << __func__ << " server_if: " << server_if_
          << " - UUID: " << uuid.ToString()
          << ", properties: " << properties
          << ", permissions: " << permissions;
  lock_guard<mutex> lock(mutex_);

  if (!pending_decl_) {
    LOG(ERROR) << "Service declaration not begun";
    return nullptr;
  }

  if (pending_end_decl_cb_) {
    LOG(ERROR) << "EndServiceDeclaration in progress, cannot modify service";
    return nullptr;
  }

  auto char_id = GetIdForCharacteristic(uuid);
  CHECK(char_id);
  AttributeEntry entry(*char_id, properties, permissions);

  // 2 handles for the characteristic declaration and the value attributes.
  pending_decl_->num_handles += 2;
  pending_decl_->attributes.push_back(entry);

  return char_id;
}

std::unique_ptr<GattIdentifier> GattServer::AddDescriptor(
    const UUID& uuid, int permissions) {
  VLOG(1) << __func__ << " server_if: " << server_if_
          << " - UUID: " << uuid.ToString()
          << ", permissions: " << permissions;
  lock_guard<mutex> lock(mutex_);

  if (!pending_decl_) {
    LOG(ERROR) << "Service declaration not begun";
    return nullptr;
  }

  if (pending_end_decl_cb_) {
    LOG(ERROR) << "EndServiceDeclaration in progress, cannot modify service";
    return nullptr;
  }

  auto desc_id = GetIdForDescriptor(uuid);
  if (!desc_id)
    return nullptr;

  AttributeEntry entry(*desc_id, kCharacteristicPropertyNone, permissions);

  // 1 handle for the descriptor attribute.
  pending_decl_->num_handles += 1;
  pending_decl_->attributes.push_back(entry);

  return desc_id;
}

bool GattServer::EndServiceDeclaration(const ResultCallback& callback) {
  VLOG(1) << __func__ << " server_if: " << server_if_;
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

std::unique_ptr<GattIdentifier> GattServer::GetIdForService(
    const UUID& uuid, bool is_primary) {
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
  return GattIdentifier::CreateServiceId("", inst_id, uuid, is_primary);
}

std::unique_ptr<GattIdentifier> GattServer::GetIdForCharacteristic(
    const UUID& uuid) {
  CHECK(pending_decl_);

  // Calculate the instance ID for this characteristic by searching through the
  // pending entries.
  int inst_id = 0;
  for (const auto& entry : pending_decl_->attributes) {
    const GattIdentifier& gatt_id = entry.id;

    if (!gatt_id.IsCharacteristic())
      continue;

    if (gatt_id.characteristic_uuid() == uuid)
      ++inst_id;
  }

  CHECK(pending_decl_->service_id.IsService());

  return GattIdentifier::CreateCharacteristicId(
      inst_id, uuid, pending_decl_->service_id);
}

std::unique_ptr<GattIdentifier> GattServer::GetIdForDescriptor(
    const UUID& uuid) {
  CHECK(pending_decl_);

  // Calculate the instance ID for this descriptor by searching through the
  // pending entries. We iterate in reverse until we find a characteristic
  // entry.
  CHECK(!pending_decl_->attributes.empty());
  int inst_id = 0;
  bool char_found = false;
  GattIdentifier char_id;
  for (auto iter = pending_decl_->attributes.end() - 1;
       iter != pending_decl_->attributes.begin();  // Begin is always a service
       --iter) {
    const GattIdentifier& gatt_id = iter->id;

    if (gatt_id.IsCharacteristic()) {
      // Found the owning characteristic.
      char_found = true;
      char_id = gatt_id;
      break;
    }

    if (!gatt_id.IsDescriptor()) {
      // A descriptor must be preceded by a descriptor or a characteristic.
      LOG(ERROR) << "Descriptors must come directly after a characteristic or "
                 << "another descriptor.";
      return nullptr;
    }

    if (gatt_id.descriptor_uuid() == uuid)
      ++inst_id;
  }

  if (!char_found) {
    LOG(ERROR) << "No characteristic found to add the descriptor to.";
    return nullptr;
  }

  return GattIdentifier::CreateDescriptorId(inst_id, uuid, char_id);
}

void GattServer::ServiceAddedCallback(
    hal::BluetoothGattInterface* gatt_iface,
    int status, int server_if,
    const btgatt_srvc_id_t& srvc_id,
    int service_handle) {
  lock_guard<mutex> lock(mutex_);

  if (server_if != server_if_)
    return;

  // Construct a GATT identifier.
  auto gatt_id = hal::GetServiceIdFromHAL(srvc_id);
  CHECK(pending_id_);
  CHECK(*gatt_id == *pending_id_);
  CHECK(*gatt_id == pending_decl_->service_id);
  CHECK(pending_id_->IsService());

  VLOG(1) << __func__ << " - status: " << status
          << " server_if: " << server_if
          << " handle: " << service_handle
          << " UUID: " << gatt_id->service_uuid().ToString();

  if (status != BT_STATUS_SUCCESS) {
    NotifyEndCallbackAndClearData(static_cast<BLEStatus>(status), *gatt_id);
    return;
  }

  // Add this to the handle map.
  pending_handle_map_[*gatt_id] = service_handle;
  CHECK(-1 == pending_decl_->service_handle);
  pending_decl_->service_handle = service_handle;

  HandleNextEntry(gatt_iface);
}

void GattServer::CharacteristicAddedCallback(
    hal::BluetoothGattInterface* gatt_iface,
    int status, int server_if,
    const bt_uuid_t& uuid,
    int service_handle,
    int char_handle) {
  lock_guard<mutex> lock(mutex_);

  if (server_if != server_if_)
    return;

  CHECK(pending_decl_);
  CHECK(pending_decl_->service_handle == service_handle);
  CHECK(pending_id_);
  CHECK(pending_id_->IsCharacteristic());
  CHECK(pending_id_->characteristic_uuid() == UUID(uuid));

  VLOG(1) << __func__ << " - status: " << status
          << " server_if: " << server_if
          << " service_handle: " << service_handle
          << " char_handle: " << char_handle;

  if (status != BT_STATUS_SUCCESS) {
    NotifyEndCallbackAndClearData(static_cast<BLEStatus>(status),
                                  pending_decl_->service_id);
    return;
  }

  // Add this to the handle map and continue.
  pending_handle_map_[*pending_id_] = char_handle;
  HandleNextEntry(gatt_iface);
}

void GattServer::DescriptorAddedCallback(
    hal::BluetoothGattInterface* gatt_iface,
    int status, int server_if,
    const bt_uuid_t& uuid,
    int service_handle,
    int desc_handle) {
  lock_guard<mutex> lock(mutex_);

  if (server_if != server_if_)
    return;

  CHECK(pending_decl_);
  CHECK(pending_decl_->service_handle == service_handle);
  CHECK(pending_id_);
  CHECK(pending_id_->IsDescriptor());
  CHECK(pending_id_->descriptor_uuid() == UUID(uuid));

  VLOG(1) << __func__ << " - status: " << status
          << " server_if: " << server_if
          << " service_handle: " << service_handle
          << " desc_handle: " << desc_handle;

  if (status != BT_STATUS_SUCCESS) {
    NotifyEndCallbackAndClearData(static_cast<BLEStatus>(status),
                                  pending_decl_->service_id);
    return;
  }

  // Add this to the handle map and contiue.
  pending_handle_map_[*pending_id_] = desc_handle;
  HandleNextEntry(gatt_iface);
}

void GattServer::ServiceStartedCallback(
    hal::BluetoothGattInterface* gatt_iface,
    int status, int server_if,
    int service_handle) {
  lock_guard<mutex> lock(mutex_);

  if (server_if != server_if_)
    return;

  CHECK(pending_id_);
  CHECK(pending_decl_);
  CHECK(pending_decl_->service_handle == service_handle);

  VLOG(1) << __func__ << " - server_if: " << server_if
          << " handle: " << service_handle;

  // If we failed to start the service, remove it from the database and ignore
  // the result.
  if (status != BT_STATUS_SUCCESS) {
    gatt_iface->GetServerHALInterface()->delete_service(
        server_if_, service_handle);
  }

  // Complete the operation.
  NotifyEndCallbackAndClearData(static_cast<BLEStatus>(status),
                                pending_decl_->service_id);
}

void GattServer::ServiceStoppedCallback(
    hal::BluetoothGattInterface* /* gatt_iface */,
    int /* status */,
    int /* server_if */,
    int /* service_handle */) {
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

void GattServer::HandleNextEntry(hal::BluetoothGattInterface* gatt_iface) {
  CHECK(pending_decl_);
  CHECK(gatt_iface);

  auto next_entry = PopNextEntry();
  if (!next_entry) {
    // No more entries. Call start_service to finish up.
    bt_status_t status = gatt_iface->GetServerHALInterface()->start_service(
        server_if_,
        pending_decl_->service_handle,
        TRANSPORT_BREDR | TRANSPORT_LE);

    // Terminate the procedure in the case of an error.
    if (status != BT_STATUS_SUCCESS) {
      NotifyEndCallbackAndClearData(static_cast<BLEStatus>(status),
                                    pending_decl_->service_id);
    }

    return;
  }

  if (next_entry->id.IsCharacteristic()) {
    bt_uuid_t char_uuid = next_entry->id.characteristic_uuid().GetBlueDroid();
    bt_status_t status = gatt_iface->GetServerHALInterface()->
        add_characteristic(
            server_if_,
            pending_decl_->service_handle,
            &char_uuid,
            next_entry->char_properties,
            next_entry->permissions);

    // Terminate the procedure in the case of an error.
    if (status != BT_STATUS_SUCCESS) {
      NotifyEndCallbackAndClearData(static_cast<BLEStatus>(status),
                                    pending_decl_->service_id);
      return;
    }

    pending_id_.reset(new GattIdentifier(next_entry->id));
    return;
  }

  if (next_entry->id.IsDescriptor()) {
    bt_uuid_t desc_uuid = next_entry->id.descriptor_uuid().GetBlueDroid();
    bt_status_t status = gatt_iface->GetServerHALInterface()->
        add_descriptor(
            server_if_,
            pending_decl_->service_handle,
            &desc_uuid,
            next_entry->permissions);

    // Terminate the procedure in the case of an error.
    if (status != BT_STATUS_SUCCESS) {
      NotifyEndCallbackAndClearData(static_cast<BLEStatus>(status),
                                    pending_decl_->service_id);
      return;
    }

    pending_id_.reset(new GattIdentifier(next_entry->id));
    return;
  }

  NOTREACHED() << "Unexpected entry type";
}

std::unique_ptr<GattServer::AttributeEntry> GattServer::PopNextEntry() {
  CHECK(pending_decl_);

  if (pending_decl_->attributes.empty())
    return nullptr;

  const auto& next = pending_decl_->attributes.front();
  std::unique_ptr<AttributeEntry> entry(new AttributeEntry(next));

  pending_decl_->attributes.pop_front();

  return entry;
}

std::unique_ptr<GattIdentifier> GattServer::PopNextId() {
  auto entry = PopNextEntry();
  if (!entry)
    return nullptr;

  return std::unique_ptr<GattIdentifier>(new GattIdentifier(entry->id));
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
