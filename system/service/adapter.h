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

#include <atomic>
#include <mutex>
#include <string>

#include <base/macros.h>
#include <base/observer_list.h>

#include "service/common/bluetooth/adapter_state.h"
#include "service/common/bluetooth/util/atomic_string.h"
#include "service/gatt_client.h"
#include "service/gatt_server.h"
#include "service/hal/bluetooth_interface.h"
#include "service/low_energy_client.h"

namespace bluetooth {

// Represents the local Bluetooth adapter.
class Adapter : public hal::BluetoothInterface::Observer {
 public:
  // The default values returned before the Adapter is fully initialized and
  // powered. The complete values for these fields are obtained following a
  // successful call to "Enable".
  static const char kDefaultAddress[];
  static const char kDefaultName[];

  // Observer interface allows other classes to receive notifications from us.
  // All of the methods in this interface are declared as optional to allow
  // different layers to process only those events that they are interested in.
  class Observer {
   public:
    virtual ~Observer() = default;

    virtual void OnAdapterStateChanged(Adapter* adapter,
                                       AdapterState prev_state,
                                       AdapterState new_state);
  };

  Adapter();
  ~Adapter() override;

  // Add or remove an observer.
  void AddObserver(Observer* observer);
  void RemoveObserver(Observer* observer);

  // Returns the current Adapter state.
  AdapterState GetState() const;

  // Returns true, if the adapter radio is current powered.
  bool IsEnabled() const;

  // Enables Bluetooth. This method will send a request to the Bluetooth adapter
  // to power up its radio. Returns true, if the request was successfully sent
  // to the controller, otherwise returns false. A successful call to this
  // method only means that the enable request has been sent to the Bluetooth
  // controller and does not imply that the operation itself succeeded.
  bool Enable();

  // Powers off the Bluetooth radio. Returns true, if the disable request was
  // successfully sent to the Bluetooth controller.
  bool Disable();

  // Returns the name currently assigned to the local adapter.
  std::string GetName() const;

  // Sets the name assigned to the local Bluetooth adapter. This is the name
  // that the local controller will present to remote devices.
  bool SetName(const std::string& name);

  // Returns the local adapter addess in string form (XX:XX:XX:XX:XX:XX).
  std::string GetAddress() const;

  // Returns true if the local adapter supports the Low-Energy
  // multi-advertisement feature.
  bool IsMultiAdvertisementSupported() const;

  // Returns a pointer to the LowEnergyClientFactory. This can be used to
  // register per-application LowEnergyClient instances to perform BLE GAP
  // operations.
  LowEnergyClientFactory* GetLowEnergyClientFactory() const;

  // Returns a pointer to the GattClientFactory. This can be used to register
  // per-application GATT server instances.
  GattClientFactory* GetGattClientFactory() const;

  // Returns a pointer to the GattServerFactory. This can be used to register
  // per-application GATT server instances.
  GattServerFactory* GetGattServerFactory() const;

 private:
  // hal::BluetoothInterface::Observer overrides.
  void AdapterStateChangedCallback(bt_state_t state) override;
  void AdapterPropertiesCallback(bt_status_t status,
                                 int num_properties,
                                 bt_property_t* properties) override;

  // Sends a request to set the given HAL adapter property type and value.
  bool SetAdapterProperty(bt_property_type_t type, void* value, int length);

  // Helper for invoking observer method.
  void NotifyAdapterStateChanged(AdapterState prev_state,
                                 AdapterState new_state);

  // The current adapter state.
  std::atomic<AdapterState> state_;

  // The Bluetooth device address of the local adapter in string from
  // (i.e.. XX:XX:XX:XX:XX:XX)
  util::AtomicString address_;

  // The current local adapter name.
  util::AtomicString name_;

  // The current set of supported LE features as obtained from the stack. The
  // values here are all initially set to 0 and updated when the corresponding
  // adapter property has been received from the stack.
  bt_local_le_features_t local_le_features_;

  // List of observers that are interested in notifications from us.
  std::mutex observers_lock_;
  base::ObserverList<Observer> observers_;

  // Factory used to create per-app LowEnergyClient instances.
  std::unique_ptr<LowEnergyClientFactory> ble_client_factory_;

  // Factory used to create per-app GattClient instances.
  std::unique_ptr<GattClientFactory> gatt_client_factory_;

  // Factory used to create per-app GattServer instances.
  std::unique_ptr<GattServerFactory> gatt_server_factory_;

  DISALLOW_COPY_AND_ASSIGN(Adapter);
};

}  // namespace bluetooth
