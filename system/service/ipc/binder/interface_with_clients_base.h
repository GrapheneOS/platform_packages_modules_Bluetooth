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

#include "service/bluetooth_client_instance.h"
#include "service/common/bluetooth/uuid.h"
#include "service/ipc/binder/remote_callback_map.h"

namespace ipc {
namespace binder {

// InterfaceWithClientsBase provides a common base class for Binder interface
// servers that involve client callback Binders registered with an integer
// client ID over an asynchronous lower-level stack API. This class abstracts
// away the common procedures of managing pending callbacks, listening to death
// notifications, and maintaining multiple internal maps in one common base
// class.
// TODO: add code example here.
class InterfaceWithClientsBase
    : public RemoteCallbackMap<int, android::IInterface>::Delegate,
      virtual public android::RefBase {
 public:
  InterfaceWithClientsBase() = default;
  ~InterfaceWithClientsBase() override = default;

 protected:
  // The initial entry point for registering a client. Invoke this from the
  // registration API to add a client/UUID pair to the pending list and set up
  // the generic asynchronous callback handler and initiate the process with the
  // given |factory| instance. Returns false, if there were any errors that
  // could be synchronously reported.
  bool RegisterClientBase(const android::sp<IInterface>& callback,
                          bluetooth::BluetoothClientInstanceFactory* factory);

  // Unregister the client with the given ID, if it was registered before.
  void UnregisterClientBase(int client_if);

  // Unregisters all registered clients.
  void UnregisterAllBase();

  // Returns a handle to the lock used to synchronize access to the internal
  // data structures. Subclasses should acquire this before accessing the maps.
  std::mutex* maps_lock() { return &maps_lock_; }

  // Returns the callback interface binder that is assigned to the given client
  // ID |client_if|. The returned pointer will contain NULL if an entry for the
  // given ID cannot be found.
  android::sp<IInterface> GetCallback(int client_if);

  // Returns the client instance that is assigned to the given client ID
  // |client_if|. The returned pointer will contain NULL if an entry for the
  // given ID cannot be found.
  std::shared_ptr<bluetooth::BluetoothClientInstance> GetClientInstance(
      int client_if);

 private:
  // Base implementation of the register callback.
  void OnRegisterClient(
      bluetooth::BLEStatus status,
      const bluetooth::UUID& uuid,
      std::unique_ptr<bluetooth::BluetoothClientInstance> client);

  // Called when the callback registration has completed. |client| is owned by
  // the base class and should not be deleted by the implementation. If the
  // operation failed, nullptr will be passed for |client|.
  virtual void OnRegisterClientImpl(
      bluetooth::BLEStatus status,
      android::sp<IInterface> callback,
      bluetooth::BluetoothClientInstance* client) = 0;

  // RemoteCallbackMap<int, IBluetoothLowEnergyCallback>::Delegate override:
  void OnRemoteCallbackRemoved(const int& key) override;

  // Clients that are pending registration. Once their registration is complete,
  // the entry will be removed from this map.
  RemoteCallbackMap<bluetooth::UUID, android::IInterface> pending_callbacks_;

  // We keep two maps here: one from client_if IDs to callback Binders and one
  // from client_if IDs to the ultimate client instance of type T.
  std::mutex maps_lock_;  // Needed for |cif_to_client_|.
  RemoteCallbackMap<int, IInterface> cif_to_cb_;
  std::unordered_map<int, std::shared_ptr<bluetooth::BluetoothClientInstance>>
      cif_to_client_;

  DISALLOW_COPY_AND_ASSIGN(InterfaceWithClientsBase);
};

}  // namespace binder
}  // namespace ipc
