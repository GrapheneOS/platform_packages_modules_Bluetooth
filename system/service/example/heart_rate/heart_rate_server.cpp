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

#include "service/example/heart_rate/heart_rate_server.h"

#include <base/logging.h>

#include "service/low_energy_constants.h"

namespace heart_rate {

HeartRateServer::HeartRateServer(android::sp<ipc::binder::IBluetooth> bluetooth)
    : bluetooth_(bluetooth),
      server_if_(-1) {
  CHECK(bluetooth_.get());
}

HeartRateServer::~HeartRateServer() {
  std::lock_guard<std::mutex> lock(mutex_);
  if (!gatt_.get() || server_if_ == -1)
    return;

  if (!android::IInterface::asBinder(gatt_.get())->isBinderAlive())
    return;

  gatt_->UnregisterServer(server_if_);
}

bool HeartRateServer::Run(const RunCallback& callback) {
  std::lock_guard<std::mutex> lock(mutex_);

  if (pending_run_cb_) {
    LOG(ERROR) << "Already started";
    return false;
  }

  gatt_ = bluetooth_->GetGattServerInterface();
  if (!gatt_.get()) {
    LOG(ERROR) << "Failed to obtain handle to IBluetoothGattServer interface";
    return false;
  }

  if (!gatt_->RegisterServer(this)) {
    LOG(ERROR) << "Failed to register with the server interface";
    return false;
  }

  pending_run_cb_ = callback;

  return true;
}

void HeartRateServer::OnServerRegistered(int status, int server_if) {
  std::lock_guard<std::mutex> lock(mutex_);

  if (status != bluetooth::BLE_STATUS_SUCCESS) {
    LOG(ERROR) << "Failed to register GATT server";
    pending_run_cb_(false);
    return;
  }

  server_if_ = server_if;

  LOG(INFO) << "Heart Rate server registered - server_if: " << server_if_;
  LOG(INFO) << "Populating attributes";

  // Start service declaration.
  bluetooth::UUID hr_uuid("180D");
  std::unique_ptr<bluetooth::GattIdentifier> gatt_id;
  if (!gatt_->BeginServiceDeclaration(server_if_, true, hr_uuid, &gatt_id)) {
    LOG(ERROR) << "Failed to begin service declaration";
    pending_run_cb_(false);
    return;
  }

  hr_service_id_ = *gatt_id;

  // Add Heart Rate Measurement characteristic.
  bluetooth::UUID hr_msrmt_uuid("2A37");
  if (!gatt_->AddCharacteristic(
      server_if_, hr_msrmt_uuid,
      bluetooth::kCharacteristicPropertyNotify, 0,
      &gatt_id)) {
    LOG(ERROR) << "Failed to add heart rate measurement characteristic";
    pending_run_cb_(false);
    return;
  }

  hr_measurement_id_ = *gatt_id;

  // Add Client Characteristic Configuration descriptor for the Heart Rate
  // Measurement characteristic.
  bluetooth::UUID ccc_uuid("2902");
  if (!gatt_->AddDescriptor(
      server_if_, ccc_uuid,
      bluetooth::kAttributePermissionRead|bluetooth::kAttributePermissionWrite,
      &gatt_id)) {
    LOG(ERROR) << "Failed to add CCC descriptor";
    pending_run_cb_(false);
    return;
  }

  hr_measurement_cccd_id_ = *gatt_id;

  // Add Body Sensor Location characteristic.
  bluetooth::UUID body_sensor_loc_uuid("2A38");
  if (!gatt_->AddCharacteristic(
      server_if_, body_sensor_loc_uuid,
      bluetooth::kCharacteristicPropertyRead,
      bluetooth::kAttributePermissionRead,
      &gatt_id)) {
    LOG(ERROR) << "Failed to add body sensor location characteristic";
    pending_run_cb_(false);
    return;
  }

  body_sensor_loc_id_ = *gatt_id;

  // Add Heart Rate Control Point characteristic.
  bluetooth::UUID ctrl_pt_uuid("2A39");
  if (!gatt_->AddCharacteristic(
      server_if_, ctrl_pt_uuid,
      bluetooth::kCharacteristicPropertyWrite,
      bluetooth::kAttributePermissionWrite,
      &gatt_id)) {
    LOG(ERROR) << "Failed to add heart rate control point characteristic";
    pending_run_cb_(false);
    return;
  }

  hr_control_point_id_ = *gatt_id;

  // End service declaration.
  if (!gatt_->EndServiceDeclaration(server_if_)) {
    LOG(ERROR) << "Failed to end service declaration";
    pending_run_cb_(false);
    return;
  }

  LOG(INFO) << "Initiated EndServiceDeclaration request";
}

void HeartRateServer::OnServiceAdded(
    int status,
    const bluetooth::GattIdentifier& service_id) {
  std::lock_guard<std::mutex> lock(mutex_);

  if (status != bluetooth::BLE_STATUS_SUCCESS) {
    LOG(ERROR) << "Failed to add Heart Rate service";
    pending_run_cb_(false);
    return;
  }

  if (service_id != hr_service_id_) {
    LOG(ERROR) << "Received callback for the wrong service ID";
    pending_run_cb_(false);
    return;
  }

  LOG(INFO) << "Heart Rate service added";
  pending_run_cb_(true);
}

}  // namespace heart_rate
