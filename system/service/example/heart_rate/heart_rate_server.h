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

#include "service/gatt_identifier.h"
#include "service/ipc/binder/IBluetooth.h"
#include "service/ipc/binder/IBluetoothGattServerCallback.h"

namespace heart_rate {

// Implements an example GATT Heart Rate service. This class emulates the
// behavior of a heart rate service by sending fake heart-rate pulses.
class HeartRateServer : public ipc::binder::BnBluetoothGattServerCallback {
 public:
  explicit HeartRateServer(android::sp<ipc::binder::IBluetooth> bluetooth);
  ~HeartRateServer() override;

  // Set up the server and register the GATT services with the stack. This
  // initiates a set of asynchronous procedures. Invokes |callback|
  // asynchronously with the result of the operation.
  using RunCallback = std::function<void(bool success)>;
  bool Run(const RunCallback& callback);

 private:
  // ipc::binder::IBluetoothGattServerCallback override:
  void OnServerRegistered(int status, int server_if) override;
  void OnServiceAdded(
      int status,
      const bluetooth::GattIdentifier& service_id) override;
  void OnCharacteristicReadRequest(
      const std::string& device_address,
      int request_id, int offset, bool is_long,
      const bluetooth::GattIdentifier& characteristic_id) override;
  void OnDescriptorReadRequest(
      const std::string& device_address,
      int request_id, int offset, bool is_long,
      const bluetooth::GattIdentifier& descriptor_id) override;
  void OnCharacteristicWriteRequest(
      const std::string& device_address,
      int request_id, int offset, bool is_prepare_write, bool need_response,
      const std::vector<uint8_t>& value,
      const bluetooth::GattIdentifier& characteristic_id) override;
  void OnDescriptorWriteRequest(
      const std::string& device_address,
      int request_id, int offset, bool is_prepare_write, bool need_response,
      const std::vector<uint8_t>& value,
      const bluetooth::GattIdentifier& descriptor_id) override;
  void OnExecuteWriteRequest(
      const std::string& device_address,
      int request_id, bool is_execute) override;

  std::mutex mutex_;

  android::sp<ipc::binder::IBluetooth> bluetooth_;
  android::sp<ipc::binder::IBluetoothGattServer> gatt_;
  int server_if_;
  RunCallback pending_run_cb_;

  bluetooth::GattIdentifier hr_service_id_;
  bluetooth::GattIdentifier hr_measurement_id_;
  bluetooth::GattIdentifier hr_measurement_cccd_id_;
  bluetooth::GattIdentifier body_sensor_loc_id_;
  bluetooth::GattIdentifier hr_control_point_id_;

  DISALLOW_COPY_AND_ASSIGN(HeartRateServer);
};

}  // namespace heart_rate
