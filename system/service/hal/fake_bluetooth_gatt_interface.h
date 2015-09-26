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
  // Handles HAL Bluetooth GATT client API calls for testing. Test code can
  // provide a fake or mock implementation of this and all calls will be routed
  // to it.
  class TestClientHandler {
   public:
    virtual ~TestClientHandler() = default;

    virtual bt_status_t RegisterClient(bt_uuid_t* app_uuid) = 0;
    virtual bt_status_t UnregisterClient(int client_if) = 0;
    virtual bt_status_t MultiAdvEnable(
        int client_if, int min_interval, int max_interval, int adv_type,
        int chnl_map, int tx_power, int timeout_s) = 0;
    virtual bt_status_t MultiAdvSetInstData(
        int client_if, bool set_scan_rsp, bool include_name,
        bool incl_txpower, int appearance,
        int manufacturer_len, char* manufacturer_data,
        int service_data_len, char* service_data,
        int service_uuid_len, char* service_uuid) = 0;
    virtual bt_status_t MultiAdvDisable(int client_if) = 0;
  };

  // Handles HAL Bluetooth GATT server API calls for testing. Test code can
  // provide a fake or mock implementation of this and all calls will be routed
  // to it.
  class TestServerHandler {
   public:
    virtual ~TestServerHandler() = default;

    virtual bt_status_t RegisterServer(bt_uuid_t* app_uuid) = 0;
    virtual bt_status_t UnregisterServer(int server_if) = 0;
  };

  // Constructs the fake with the given handlers. Implementations can
  // provide their own handlers or simply pass "nullptr" for the default
  // behavior in which BT_STATUS_FAIL will be returned from all calls.
  FakeBluetoothGattInterface(std::shared_ptr<TestClientHandler> client_handler,
                             std::shared_ptr<TestServerHandler> server_handler);
  ~FakeBluetoothGattInterface();

  // The methods below can be used to notify observers with certain events and
  // given parameters.
  void NotifyRegisterClientCallback(int status, int client_if,
                                    const bt_uuid_t& app_uuid);
  void NotifyMultiAdvEnableCallback(int client_if, int status);
  void NotifyMultiAdvDataCallback(int client_if, int status);
  void NotifyMultiAdvDisableCallback(int client_if, int status);

  void NotifyRegisterServerCallback(int status, int server_if,
                                    const bt_uuid_t& app_uuid);

  // BluetoothGattInterface overrides:
  void AddClientObserver(ClientObserver* observer) override;
  void RemoveClientObserver(ClientObserver* observer) override;
  void AddClientObserverUnsafe(ClientObserver* observer) override;
  void RemoveClientObserverUnsafe(ClientObserver* observer) override;
  void AddServerObserver(ServerObserver* observer) override;
  void RemoveServerObserver(ServerObserver* observer) override;
  void AddServerObserverUnsafe(ServerObserver* observer) override;
  void RemoveServerObserverUnsafe(ServerObserver* observer) override;
  const btgatt_client_interface_t* GetClientHALInterface() const override;
  const btgatt_server_interface_t* GetServerHALInterface() const override;

 private:
  base::ObserverList<ClientObserver> client_observers_;
  base::ObserverList<ServerObserver> server_observers_;
  std::shared_ptr<TestClientHandler> client_handler_;
  std::shared_ptr<TestServerHandler> server_handler_;

  DISALLOW_COPY_AND_ASSIGN(FakeBluetoothGattInterface);
};

}  // namespace hal
}  // namespace bluetooth
