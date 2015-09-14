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
#include <hardware/bluetooth.h>
#include <hardware/bt_gatt.h>

namespace bluetooth {
namespace hal {

// This class represents the standard BT-GATT interface. This class combines
// GATT profile server and client role operations with general GAP profile
// operations of various roles (central, scanner, peripheral, advertiser),
// wrapping around the underlying bt_gatt_interface_t structure. A single
// instance of this class exists per application and it allows multiple classes
// to interface with the global HAL interface by multiplexing callbacks among
// registered clients.
//
// This is declared as an abstract interface so that a fake implementation can
// be injected for testing the upper layer.
class BluetoothGattInterface {
 public:
  // The standard BT-GATT client callback interface. The HAL interface doesn't
  // allow registering "user data" that carries context beyond the callback
  // parameters, forcing implementations to deal with global variables. The
  // Observer interface is to redirect these events to interested parties in an
  // object-oriented manner.
  class ClientObserver {
   public:
    virtual ~ClientObserver() = default;

    // All of the events below correspond to callbacks defined in
    // "bt_gatt_client_callbacks_t" in the HAL API definitions.

    virtual void RegisterClientCallback(int status, int client_if,
                                        const bt_uuid_t& app_uuid);

    // TODO(armansito): Complete the list of callbacks.
  };

  // Initialize and clean up the BluetoothInterface singleton. Returns false if
  // the underlying HAL interface failed to initialize, and true on success.
  static bool Initialize();

  // Shuts down and cleans up the interface. CleanUp must be called on the same
  // thread that called Initialize.
  static void CleanUp();

  // Returns true if the interface was initialized and a global singleton has
  // been created.
  static bool IsInitialized();

  // Initialize for testing. Use this to inject a test version of
  // BluetoothGattInterface. To be used from unit tests only.
  static void InitializeForTesting(BluetoothGattInterface* test_instance);

  // Returns the BluetoothGattInterface singleton. If the interface has
  // not been initialized, returns nullptr.
  static BluetoothGattInterface* Get();

  // Add or remove an observer that is interested in GATT client interface
  // notifications from us.
  virtual void AddClientObserver(ClientObserver* observer) = 0;
  virtual void RemoveClientObserver(ClientObserver* observer) = 0;

  // The HAL module pointer that represents the standard BT-GATT client
  // interface. This is implemented in and provided by the shared Bluetooth
  // library, so this isn't owned by us.
  //
  // Upper layers can make btgatt_client_interface_t API calls through this
  // structure.
  virtual const btgatt_client_interface_t* GetClientHALInterface() const = 0;

  // TODO(armansito): Add getter for server handle.

 protected:
  BluetoothGattInterface() = default;
  virtual ~BluetoothGattInterface() = default;

 private:
  DISALLOW_COPY_AND_ASSIGN(BluetoothGattInterface);
};

}  // namespace hal
}  // namespace bluetooth
