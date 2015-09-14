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
#include <base/observer_list.h>

#include "service/hal/bluetooth_gatt_interface.h"

namespace bluetooth {
namespace hal {

class FakeBluetoothGattInterface : public BluetoothGattInterface {
 public:
  // Handles HAL Bluetooth API calls for testing. Test code can provide a fake
  // or mock implementation of this and all calls will be routed to it.
  class TestHandler {
   public:
    virtual ~TestHandler() = default;

    virtual bt_status_t RegisterClient(bt_uuid_t* app_uuid) = 0;
    virtual bt_status_t UnregisterClient(int client_if) = 0;
  };

  // Constructs the fake with the given handler |handler|. Implementations can
  // provide their own handlers or simply pass "nullptr" for the default
  // behavior in which BT_STATUS_FAIL will be returned from all calls.
  FakeBluetoothGattInterface(std::shared_ptr<TestHandler> handler);
  ~FakeBluetoothGattInterface();

  // The methods below can be used to notify observers with certain events and
  // given parameters.
  void NotifyRegisterClientCallback(int status, int client_if,
                                    const bt_uuid_t& app_uuid);

  // BluetoothGattInterface overrides:
  void AddClientObserver(ClientObserver* observer) override;
  void RemoveClientObserver(ClientObserver* observer) override;
  const btgatt_client_interface_t* GetClientHALInterface() const override;

 private:
  base::ObserverList<ClientObserver> client_observers_;
  std::shared_ptr<TestHandler> handler_;

  DISALLOW_COPY_AND_ASSIGN(FakeBluetoothGattInterface);
};

}  // namespace hal
}  // namespace bluetooth
