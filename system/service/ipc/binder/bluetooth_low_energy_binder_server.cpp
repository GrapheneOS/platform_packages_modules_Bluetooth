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

#include "service/ipc/binder/bluetooth_low_energy_binder_server.h"

#include <base/logging.h>

#include "service/adapter.h"

using android::String8;
using android::String16;
using android::binder::Status;

namespace ipc {
namespace binder {

namespace {
const int kInvalidInstanceId = -1;
}  // namespace

BluetoothLowEnergyBinderServer::BluetoothLowEnergyBinderServer(
    bluetooth::Adapter* adapter)
    : adapter_(adapter) {
  CHECK(adapter_);
}

BluetoothLowEnergyBinderServer::~BluetoothLowEnergyBinderServer() {}

Status BluetoothLowEnergyBinderServer::RegisterClient(
    const android::sp<IBluetoothLowEnergyCallback>& callback,
    bool* _aidl_return) {
  VLOG(2) << __func__;
  bluetooth::LowEnergyClientFactory* ble_factory =
      adapter_->GetLowEnergyClientFactory();

  *_aidl_return = RegisterInstanceBase(callback, ble_factory);
  return Status::ok();
}

Status BluetoothLowEnergyBinderServer::UnregisterClient(int client_id) {
  VLOG(2) << __func__;
  UnregisterInstanceBase(client_id);
  return Status::ok();
}

Status BluetoothLowEnergyBinderServer::UnregisterAll() {
  VLOG(2) << __func__;
  UnregisterAllBase();
  return Status::ok();
}

Status BluetoothLowEnergyBinderServer::Connect(int client_id,
                                               const String16& address,
                                               bool is_direct,
                                               bool* _aidl_return) {
  VLOG(2) << __func__ << " client_id: " << client_id << " address: " << address
          << " is_direct: " << is_direct;
  std::lock_guard<std::mutex> lock(*maps_lock());

  auto client = GetLEClient(client_id);
  if (!client) {
    LOG(ERROR) << "Unknown client_id: " << client_id;
    *_aidl_return = false;
    return Status::ok();
  }

  *_aidl_return =
      client->Connect(std::string(String8(address).string()), is_direct);
  return Status::ok();
}

Status BluetoothLowEnergyBinderServer::Disconnect(int client_id,
                                                  const String16& address,
                                                  bool* _aidl_return) {
  VLOG(2) << __func__ << " client_id: " << client_id << " address: " << address;
  std::lock_guard<std::mutex> lock(*maps_lock());

  auto client = GetLEClient(client_id);
  if (!client) {
    LOG(ERROR) << "Unknown client_id: " << client_id;
    *_aidl_return = false;
    return Status::ok();
  }

  *_aidl_return = client->Disconnect(std::string(String8(address).string()));
  return Status::ok();
}

Status BluetoothLowEnergyBinderServer::SetMtu(int client_id,
                                              const String16& address, int mtu,
                                              bool* _aidl_return) {
  VLOG(2) << __func__ << " client_id: " << client_id << " address: " << address
          << " mtu: " << mtu;
  std::lock_guard<std::mutex> lock(*maps_lock());

  auto client = GetLEClient(client_id);
  if (!client) {
    LOG(ERROR) << "Unknown client_id: " << client_id;
    *_aidl_return = false;
    return Status::ok();
  }

  *_aidl_return = client->SetMtu(std::string(String8(address).string()), mtu);
  return Status::ok();
}

Status BluetoothLowEnergyBinderServer::StartScan(
    int client_id, const android::bluetooth::ScanSettings& settings,
    const std::vector<android::bluetooth::ScanFilter>& filters,
    bool* _aidl_return) {
  VLOG(2) << __func__ << " client_id: " << client_id;
  std::lock_guard<std::mutex> lock(*maps_lock());

  auto client = GetLEClient(client_id);
  if (!client) {
    LOG(ERROR) << "Unknown client_id: " << client_id;
    *_aidl_return = false;
    return Status::ok();
  }

  std::vector<bluetooth::ScanFilter> flt;
  for (auto filter : filters) {
    flt.push_back(filter);
  }

  *_aidl_return = client->StartScan(settings, flt);
  return Status::ok();
}

Status BluetoothLowEnergyBinderServer::StopScan(int client_id,
                                                bool* _aidl_return) {
  VLOG(2) << __func__ << " client_id: " << client_id;
  std::lock_guard<std::mutex> lock(*maps_lock());

  auto client = GetLEClient(client_id);
  if (!client) {
    LOG(ERROR) << "Unknown client_id: " << client_id;
    *_aidl_return = false;
    return Status::ok();
  }

  *_aidl_return = client->StopScan();
  return Status::ok();
}

Status BluetoothLowEnergyBinderServer::StartMultiAdvertising(
    int client_id, const android::bluetooth::AdvertiseData& advertise_data,
    const android::bluetooth::AdvertiseData& scan_response,
    const android::bluetooth::AdvertiseSettings& settings, bool* _aidl_return) {
  VLOG(2) << __func__ << " client_id: " << client_id;
  std::lock_guard<std::mutex> lock(*maps_lock());

  auto client = GetLEClient(client_id);
  if (!client) {
    LOG(ERROR) << "Unknown client_id: " << client_id;
    *_aidl_return = false;
    return Status::ok();
  }

  // Create a weak pointer and pass that to the callback to prevent a potential
  // use after free.
  android::wp<BluetoothLowEnergyBinderServer> weak_ptr_to_this(this);
  auto settings_copy = settings;
  auto callback = [=](bluetooth::BLEStatus status) {
    auto sp_to_this = weak_ptr_to_this.promote();
    if (!sp_to_this.get()) {
      VLOG(2) << "BluetoothLowEnergyBinderServer was deleted";
      return;
    }

    std::lock_guard<std::mutex> lock(*maps_lock());

    auto cb = GetLECallback(client_id);
    if (!cb.get()) {
      VLOG(1) << "Client was removed before callback: " << client_id;
      return;
    }

    cb->OnMultiAdvertiseCallback(status, true /* is_start */, settings_copy);
  };

  if (!client->StartAdvertising(settings, advertise_data, scan_response,
                                callback)) {
    LOG(ERROR) << "Failed to initiate call to start advertising";
    *_aidl_return = false;
    return Status::ok();
  }

  *_aidl_return = true;
  return Status::ok();
}

Status BluetoothLowEnergyBinderServer::StopMultiAdvertising(
    int client_id, bool* _aidl_return) {
  VLOG(2) << __func__;
  std::lock_guard<std::mutex> lock(*maps_lock());

  auto client = GetLEClient(client_id);
  if (!client) {
    LOG(ERROR) << "Unknown client_id: " << client_id;
    *_aidl_return = false;
    return Status::ok();
  }

  // Create a weak pointer and pass that to the callback to prevent a potential
  // use after free.
  android::wp<BluetoothLowEnergyBinderServer> weak_ptr_to_this(this);
  auto settings_copy = client->advertise_settings();
  auto callback = [=](bluetooth::BLEStatus status) {
    auto sp_to_this = weak_ptr_to_this.promote();
    if (!sp_to_this.get()) {
      VLOG(2) << "BluetoothLowEnergyBinderServer was deleted";
      return;
    }

    auto cb = GetLECallback(client_id);
    if (!cb.get()) {
      VLOG(2) << "Client was unregistered - client_id: " << client_id;
      return;
    }

    std::lock_guard<std::mutex> lock(*maps_lock());

    cb->OnMultiAdvertiseCallback(status, false /* is_start */, settings_copy);
  };

  if (!client->StopAdvertising(callback)) {
    LOG(ERROR) << "Failed to initiate call to start advertising";
    *_aidl_return = false;
    return Status::ok();
  }

  *_aidl_return = true;
  return Status::ok();
}

void BluetoothLowEnergyBinderServer::OnConnectionState(
    bluetooth::LowEnergyClient* client, int status, const char* address,
    bool connected) {
  VLOG(2) << __func__ << " address: " << address << " connected: " << connected;

  int client_id = client->GetInstanceId();
  auto cb = GetLECallback(client->GetInstanceId());
  if (!cb.get()) {
    VLOG(2) << "Client was unregistered - client_id: " << client_id;
    return;
  }

  cb->OnConnectionState(status, client_id,
                        String16(address, std::strlen(address)), connected);
}

void BluetoothLowEnergyBinderServer::OnMtuChanged(
    bluetooth::LowEnergyClient* client, int status, const char* address,
    int mtu) {
  VLOG(2) << __func__ << " address: " << address << " status: " << status
          << " mtu: " << mtu;

  int client_id = client->GetInstanceId();
  auto cb = GetLECallback(client_id);
  if (!cb.get()) {
    VLOG(2) << "Client was unregistered - client_id: " << client_id;
    return;
  }

  cb->OnMtuChanged(status, String16(address, std::strlen(address)), mtu);
}

void BluetoothLowEnergyBinderServer::OnScanResult(
    bluetooth::LowEnergyClient* client, const bluetooth::ScanResult& result) {
  VLOG(2) << __func__;
  std::lock_guard<std::mutex> lock(*maps_lock());

  int client_id = client->GetInstanceId();
  auto cb = GetLECallback(client->GetInstanceId());
  if (!cb.get()) {
    VLOG(2) << "Client was unregistered - client_id: " << client_id;
    return;
  }

  cb->OnScanResult(result);
}

android::sp<IBluetoothLowEnergyCallback>
BluetoothLowEnergyBinderServer::GetLECallback(int client_id) {
  auto cb = GetCallback(client_id);
  return android::sp<IBluetoothLowEnergyCallback>(
      static_cast<IBluetoothLowEnergyCallback*>(cb.get()));
}

std::shared_ptr<bluetooth::LowEnergyClient>
BluetoothLowEnergyBinderServer::GetLEClient(int client_id) {
  return std::static_pointer_cast<bluetooth::LowEnergyClient>(
      GetInstance(client_id));
}

void BluetoothLowEnergyBinderServer::OnRegisterInstanceImpl(
    bluetooth::BLEStatus status, android::sp<IInterface> callback,
    bluetooth::BluetoothInstance* instance) {
  VLOG(1) << __func__ << " status: " << status;
  bluetooth::LowEnergyClient* le_client =
      static_cast<bluetooth::LowEnergyClient*>(instance);
  le_client->SetDelegate(this);

  android::sp<IBluetoothLowEnergyCallback> cb(
      static_cast<IBluetoothLowEnergyCallback*>(callback.get()));
  cb->OnClientRegistered(status, (status == bluetooth::BLE_STATUS_SUCCESS)
                                     ? instance->GetInstanceId()
                                     : kInvalidInstanceId);
}

}  // namespace binder
}  // namespace ipc
