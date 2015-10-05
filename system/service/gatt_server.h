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

#include <deque>
#include <functional>
#include <mutex>
#include <unordered_map>

#include <base/macros.h>

#include "service/bluetooth_client_instance.h"
#include "service/gatt_identifier.h"
#include "service/hal/bluetooth_gatt_interface.h"
#include "service/uuid.h"

namespace bluetooth {

// A GattServer instance represents an application's handle to perform GATT
// server-role operations. Instances cannot be created directly and should be
// obtained through the factory.
class GattServer : public BluetoothClientInstance,
                   private hal::BluetoothGattInterface::ServerObserver {
 public:
  // The desctructor automatically unregisters this instance from the stack.
  ~GattServer() override;

  // BluetoothClientInstace overrides:
  const UUID& GetAppIdentifier() const override;
  int GetClientId() const override;

  // Callback type used to report the status of an asynchronous GATT server
  // operation.
  using ResultCallback =
      std::function<void(BLEStatus status, const GattIdentifier& id)>;

  // Starts a new GATT service declaration for the service with the given
  // parameters. In the case of an error, for example If a service declaration
  // is already in progress, then this method returns a NULL pointer. Otherwise,
  // this returns an identifier that uniquely identifies the added service.
  //
  // TODO(armansito): In the framework code, the "min_handles" parameter is
  // annotated to be used for "conformance testing only". I don't fully see the
  // point of this and suggest getting rid of this parameter entirely. For now
  // this code doesn't declare or use it.
  std::unique_ptr<GattIdentifier> BeginServiceDeclaration(
      const UUID& uuid, bool is_primary);

  // Inserts a new characteristic definition into a previously begun service
  // declaration. Returns the assigned identifier for the characteristic, or
  // nullptr if a service declaration wasn't begun or a call to
  // EndServiceDeclaration is still in progress.
  std::unique_ptr<GattIdentifier> AddCharacteristic(
      const UUID& uuid, int properties, int permissions);

  // Inserts a new descriptor definition into a previous begun service
  // declaration. Returns the assigned identifier for the descriptor, or
  // nullptr if a service declaration wasn't begun, a call to
  // EndServiceDeclaration is still in progress, or a characteristic definition
  // doesn't properly precede this definition.
  std::unique_ptr<GattIdentifier> AddDescriptor(
      const UUID& uuid, int permissions);

  // Ends a previously started service declaration. This method immediately
  // returns false if a service declaration hasn't been started. Otherwise,
  // |callback| will be called asynchronously with the result of the operation.
  //
  // TODO(armansito): It is unclear to me what it means for this function to
  // fail. What is the state that we're in? Is the service declaration over so
  // we can add other services to this server instance? Do we need to clean up
  // all the entries or does the upper-layer need to remove the service? Or are
  // we in a stuck-state where the service declaration hasn't ended?
  bool EndServiceDeclaration(const ResultCallback& callback);

 private:
  friend class GattServerFactory;

  // Internal representation of an attribute entry as part of a service
  // declaration.
  struct AttributeEntry {
    AttributeEntry(const GattIdentifier& id,
                   int char_properties,
                   int permissions)
        : id(id), char_properties(char_properties), permissions(permissions) {}

    GattIdentifier id;
    int char_properties;
    int permissions;
  };

  // Internal representation of a GATT service declaration before it has been
  // sent to the stack.
  struct ServiceDeclaration {
    ServiceDeclaration() : num_handles(0), service_handle(-1) {}

    size_t num_handles;
    GattIdentifier service_id;
    int service_handle;
    std::deque<AttributeEntry> attributes;
  };

  // Constructor shouldn't be called directly as instance are meant to be
  // obtained from the factory.
  GattServer(const UUID& uuid, int server_if);

  // Returns a GattIdentifier for the attribute with the given UUID within the
  // current pending service declaration.
  std::unique_ptr<GattIdentifier> GetIdForService(const UUID& uuid,
                                                  bool is_primary);
  std::unique_ptr<GattIdentifier> GetIdForCharacteristic(const UUID& uuid);
  std::unique_ptr<GattIdentifier> GetIdForDescriptor(const UUID& uuid);

  // hal::BluetoothGattInterface::ServerObserver overrides:
  void ServiceAddedCallback(
      hal::BluetoothGattInterface* gatt_iface,
      int status, int server_if,
      const btgatt_srvc_id_t& srvc_id,
      int service_handle) override;
  void CharacteristicAddedCallback(
      hal::BluetoothGattInterface* gatt_iface,
      int status, int server_if,
      const bt_uuid_t& uuid,
      int service_handle,
      int char_handle) override;
  void DescriptorAddedCallback(
      hal::BluetoothGattInterface* gatt_iface,
      int status, int server_if,
      const bt_uuid_t& uuid,
      int service_handle,
      int desc_handle) override;
  void ServiceStartedCallback(
      hal::BluetoothGattInterface* gatt_iface,
      int status, int server_if,
      int service_handle) override;
  void ServiceStoppedCallback(
      hal::BluetoothGattInterface* gatt_iface,
      int status, int server_if,
      int service_handle) override;

  // Helper function that notifies and clears the pending callback.
  void NotifyEndCallbackAndClearData(BLEStatus status,
                                     const GattIdentifier& id);
  void CleanUpPendingData();

  // Handles the next attribute entry in the pending service declaration.
  void HandleNextEntry(hal::BluetoothGattInterface* gatt_iface);

  // Pops the next GATT ID or entry from the pending service declaration's
  // attribute list.
  std::unique_ptr<AttributeEntry> PopNextEntry();
  std::unique_ptr<GattIdentifier> PopNextId();

  // See getters for documentation.
  UUID app_identifier_;
  int server_if_;

  // Mutex that synchronizes access to the entries below.
  std::mutex mutex_;
  std::unique_ptr<GattIdentifier> pending_id_;
  std::unique_ptr<ServiceDeclaration> pending_decl_;
  ResultCallback pending_end_decl_cb_;
  std::unordered_map<GattIdentifier, int> pending_handle_map_;

  // Mapping of handles and GATT identifiers for started services.
  std::unordered_map<GattIdentifier, int> handle_map_;

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
  std::unordered_map<UUID, RegisterCallback> pending_calls_;

  DISALLOW_COPY_AND_ASSIGN(GattServerFactory);
};

}  // namespace bluetooth
