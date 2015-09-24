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

#include "service/low_energy_client.h"

#include <base/logging.h>

#include "stack/include/bt_types.h"
#include "stack/include/hcidefs.h"

using std::lock_guard;
using std::mutex;

namespace bluetooth {

namespace {

BLEStatus GetBLEStatus(int status) {
  if (status == BT_STATUS_FAIL)
    return BLE_STATUS_FAILURE;

  return static_cast<BLEStatus>(status);
}

// TODO(armansito): BTIF currently expects each advertising field in a
// specific format passed directly in arguments. We should fix BTIF to accept
// the advertising data directly instead.
struct HALAdvertiseData {
  std::vector<uint8_t> manufacturer_data;
  std::vector<uint8_t> service_data;
  std::vector<uint8_t> service_uuid;
};

bool ProcessAdvertiseData(const AdvertiseData& adv,
                          HALAdvertiseData* out_data) {
  CHECK(out_data);
  CHECK(out_data->manufacturer_data.empty());
  CHECK(out_data->service_data.empty());
  CHECK(out_data->service_uuid.empty());

  const auto& data = adv.data();
  size_t len = data.size();
  for (size_t i = 0, field_len = 0; i < len; i += (field_len + 1)) {
    // The length byte is the first byte in the adv. "TLV" format.
    field_len = data[i];

    // The type byte is the next byte in the adv. "TLV" format.
    uint8_t type = data[i + 1];
    size_t uuid_len = 0;

    switch (type) {
    case HCI_EIR_MANUFACTURER_SPECIFIC_TYPE: {
      // TODO(armansito): BTIF doesn't allow setting more than one
      // manufacturer-specific data entry. This is something we should fix. For
      // now, fail if more than one entry was set.
      if (!out_data->manufacturer_data.empty()) {
        VLOG(1) << "More than one Manufacturer Specific Data entry not allowed";
        return false;
      }

      // The value bytes start at the next byte in the "TLV" format.
      const uint8_t* mnf_data = data.data() + i + 2;
      out_data->manufacturer_data.insert(
          out_data->manufacturer_data.begin(),
          mnf_data, mnf_data + field_len - 1);
      break;
    }
    // TODO(armansito): Support other fields.
    default:
      VLOG(1) << "Unrecognized EIR field: " << type;
      return false;
    }
  }

  return true;
}

// The Bluetooth Core Specification defines time interval (e.g. Page Scan
// Interval, Advertising Interval, etc) units as 0.625 milliseconds (or 1
// Baseband slot). The HAL advertising functions expect the interval in this
// unit. This function maps an AdvertiseSettings::Mode value to the
// corresponding time unit.
int GetAdvertisingIntervalUnit(AdvertiseSettings::Mode mode) {
  int ms;

  switch (mode) {
  case AdvertiseSettings::MODE_BALANCED:
    ms = kAdvertisingIntervalMediumMs;
    break;
  case AdvertiseSettings::MODE_LOW_LATENCY:
    ms = kAdvertisingIntervalLowMs;
    break;
  case AdvertiseSettings::MODE_LOW_POWER:
    // Fall through
  default:
    ms = kAdvertisingIntervalHighMs;
    break;
  }

  // Convert milliseconds Bluetooth units.
  return (ms * 1000) / 625;
}

struct AdvertiseParams {
  int min_interval;
  int max_interval;
  int event_type;
  int tx_power_level;
  int timeout_s;
};

void GetAdvertiseParams(const AdvertiseSettings& settings, bool has_scan_rsp,
                        AdvertiseParams* out_params) {
  CHECK(out_params);

  out_params->min_interval = GetAdvertisingIntervalUnit(settings.mode());
  out_params->max_interval =
      out_params->min_interval + kAdvertisingIntervalDeltaUnit;

  if (settings.connectable())
    out_params->event_type = kAdvertisingEventTypeConnectable;
  else if (has_scan_rsp)
    out_params->event_type = kAdvertisingEventTypeScannable;
  else
    out_params->event_type = kAdvertisingEventTypeNonConnectable;

  out_params->tx_power_level = settings.tx_power_level();
  out_params->timeout_s = settings.timeout().InSeconds();
}

}  // namespace

// LowEnergyClient implementation
// ========================================================

LowEnergyClient::LowEnergyClient(const UUID& uuid, int client_if)
    : app_identifier_(uuid),
      client_if_(client_if),
      adv_data_needs_update_(false),
      scan_rsp_needs_update_(false),
      is_setting_adv_data_(false),
      adv_started_(false),
      adv_start_callback_(nullptr),
      adv_stop_callback_(nullptr) {
}

LowEnergyClient::~LowEnergyClient() {
  // Automatically unregister the client.
  VLOG(1) << "LowEnergyClient unregistering client: " << client_if_;

  // Unregister as observer so we no longer receive any callbacks.
  hal::BluetoothGattInterface::Get()->RemoveClientObserver(this);

  // Stop advertising and ignore the result.
  hal::BluetoothGattInterface::Get()->
      GetClientHALInterface()->multi_adv_disable(client_if_);
  hal::BluetoothGattInterface::Get()->
      GetClientHALInterface()->unregister_client(client_if_);
}

bool LowEnergyClient::StartAdvertising(const AdvertiseSettings& settings,
                                       const AdvertiseData& advertise_data,
                                       const AdvertiseData& scan_response,
                                       const StatusCallback& callback) {
  VLOG(2) << __func__;
  lock_guard<mutex> lock(adv_fields_lock_);

  if (IsAdvertisingStarted()) {
    LOG(WARNING) << "Already advertising";
    return false;
  }

  if (IsStartingAdvertising()) {
    LOG(WARNING) << "StartAdvertising already pending";
    return false;
  }

  if (!advertise_data.IsValid()) {
    LOG(ERROR) << "Invalid advertising data";
    return false;
  }

  if (!scan_response.IsValid()) {
    LOG(ERROR) << "Invalid scan response data";
    return false;
  }

  CHECK(!adv_data_needs_update_.load());
  CHECK(!scan_rsp_needs_update_.load());

  adv_data_ = advertise_data;
  scan_response_ = scan_response;
  settings_ = settings;

  AdvertiseParams params;
  GetAdvertiseParams(settings, !scan_response_.data().empty(), &params);

  bt_status_t status = hal::BluetoothGattInterface::Get()->
      GetClientHALInterface()->multi_adv_enable(
          client_if_,
          params.min_interval,
          params.max_interval,
          params.event_type,
          kAdvertisingChannelAll,
          params.tx_power_level,
          params.timeout_s);
  if (status != BT_STATUS_SUCCESS) {
    LOG(ERROR) << "Failed to initiate call to enable multi-advertising";
    return false;
  }

  // Always update advertising data.
  adv_data_needs_update_ = true;

  // Update scan response only if it has data, since otherwise we just won't
  // send ADV_SCAN_IND.
  if (!scan_response_.data().empty())
    scan_rsp_needs_update_ = true;

  // OK to set this at the end since we're still holding |adv_fields_lock_|.
  adv_start_callback_.reset(new StatusCallback(callback));

  return true;
}

bool LowEnergyClient::StopAdvertising(const StatusCallback& callback) {
  VLOG(2) << __func__;
  lock_guard<mutex> lock(adv_fields_lock_);

  if (!IsAdvertisingStarted()) {
    LOG(ERROR) << "Not advertising";
    return false;
  }

  if (IsStoppingAdvertising()) {
    LOG(ERROR) << "StopAdvertising already pending";
    return false;
  }

  CHECK(!adv_start_callback_);

  bt_status_t status = hal::BluetoothGattInterface::Get()->
      GetClientHALInterface()->multi_adv_disable(client_if_);
  if (status != BT_STATUS_SUCCESS) {
    LOG(ERROR) << "Failed to initiate call to disable multi-advertising";
    return false;
  }

  // OK to set this at the end since we're still holding |adv_fields_lock_|.
  adv_stop_callback_.reset(new StatusCallback(callback));

  return true;
}

bool LowEnergyClient::IsAdvertisingStarted() const {
  return adv_started_.load();
}

bool LowEnergyClient::IsStartingAdvertising() const {
  return !IsAdvertisingStarted() && adv_start_callback_;
}

bool LowEnergyClient::IsStoppingAdvertising() const {
  return IsAdvertisingStarted() && adv_stop_callback_;
}

void LowEnergyClient::MultiAdvEnableCallback(
    hal::BluetoothGattInterface* gatt_iface,
    int client_if, int status) {
  if (client_if != client_if_)
    return;

  lock_guard<mutex> lock(adv_fields_lock_);

  VLOG(1) << __func__ << "client_if: " << client_if << " status: " << status;

  CHECK(adv_start_callback_);
  CHECK(!adv_stop_callback_);

  // Terminate operation in case of error.
  if (status != BT_STATUS_SUCCESS) {
    LOG(ERROR) << "Failed to enable multi-advertising";
    InvokeAndClearStartCallback(GetBLEStatus(status));
    return;
  }

  // Now handle deferred tasks.
  HandleDeferredAdvertiseData(gatt_iface);
}

void LowEnergyClient::MultiAdvDataCallback(
    hal::BluetoothGattInterface* gatt_iface,
    int client_if, int status) {
  if (client_if != client_if_)
    return;

  lock_guard<mutex> lock(adv_fields_lock_);

  VLOG(1) << __func__ << "client_if: " << client_if << " status: " << status;

  is_setting_adv_data_ = false;

  // Terminate operation in case of error.
  if (status != BT_STATUS_SUCCESS) {
    LOG(ERROR) << "Failed to set advertising data";
    InvokeAndClearStartCallback(GetBLEStatus(status));
    return;
  }

  // Now handle deferred tasks.
  HandleDeferredAdvertiseData(gatt_iface);
}

void LowEnergyClient::MultiAdvDisableCallback(
    hal::BluetoothGattInterface* /* gatt_iface */,
    int client_if, int status) {
  if (client_if != client_if_)
    return;

  lock_guard<mutex> lock(adv_fields_lock_);

  VLOG(1) << __func__ << "client_if: " << client_if << " status: " << status;

  CHECK(!adv_start_callback_);
  CHECK(adv_stop_callback_);

  if (status == BT_STATUS_SUCCESS) {
    VLOG(1) << "Multi-advertising stopped for client_if: " << client_if;
    adv_started_ = false;
  } else {
    LOG(ERROR) << "Failed to stop multi-advertising";
  }

  InvokeAndClearStopCallback(GetBLEStatus(status));
}

bt_status_t LowEnergyClient::SetAdvertiseData(
    hal::BluetoothGattInterface* gatt_iface,
    const AdvertiseData& data,
    bool set_scan_rsp) {
  VLOG(2) << __func__;

  HALAdvertiseData hal_data;

  // TODO(armansito): The stack should check that the length is valid when other
  // fields inserted by the stack (e.g. flags, device name, tx-power) are taken
  // into account. At the moment we are skipping this check; this means that if
  // the given data is too long then the stack will truncate it.
  if (!ProcessAdvertiseData(data, &hal_data)) {
    VLOG(1) << "Malformed advertise data given";
    return BT_STATUS_FAIL;
  }

  if (is_setting_adv_data_.load()) {
    VLOG(1) << "Setting advertising data already in progress.";
    return BT_STATUS_FAIL;
  }

  // TODO(armansito): The length fields in the BTIF function below are signed
  // integers so a call to std::vector::size might get capped. This is very
  // unlikely anyway but it's safer to stop using signed-integer types for
  // length in APIs, so we should change that.
  bt_status_t status = gatt_iface->GetClientHALInterface()->
      multi_adv_set_inst_data(
          client_if_,
          set_scan_rsp,
          data.include_device_name(),
          data.include_tx_power_level(),
          0,  // This is what Bluetooth.apk current hardcodes for "appearance".
          hal_data.manufacturer_data.size(),
          reinterpret_cast<char*>(hal_data.manufacturer_data.data()),
          0, nullptr, 0, nullptr);  // TODO(armansito): Support the rest.
  if (status != BT_STATUS_SUCCESS) {
    LOG(ERROR) << "Failed to set instance advertising data.";
    return status;
  }

  if (set_scan_rsp)
    scan_rsp_needs_update_ = false;
  else
    adv_data_needs_update_ = false;

  is_setting_adv_data_ = true;

  return status;
}

void LowEnergyClient::HandleDeferredAdvertiseData(
    hal::BluetoothGattInterface* gatt_iface) {
  VLOG(2) << __func__;

  CHECK(!IsAdvertisingStarted());
  CHECK(!IsStoppingAdvertising());
  CHECK(IsStartingAdvertising());
  CHECK(!is_setting_adv_data_.load());

  if (adv_data_needs_update_.load()) {
    bt_status_t status = SetAdvertiseData(gatt_iface, adv_data_, false);
    if (status != BT_STATUS_SUCCESS) {
      LOG(ERROR) << "Failed setting advertisement data";
      InvokeAndClearStartCallback(GetBLEStatus(status));
    }
    return;
  }

  if (scan_rsp_needs_update_.load()) {
    bt_status_t status = SetAdvertiseData(gatt_iface, scan_response_, true);
    if (status != BT_STATUS_SUCCESS) {
      LOG(ERROR) << "Failed setting scan response data";
      InvokeAndClearStartCallback(GetBLEStatus(status));
    }
    return;
  }

  // All pending tasks are complete. Report success.
  adv_started_ = true;
  InvokeAndClearStartCallback(BLE_STATUS_SUCCESS);
}

void LowEnergyClient::InvokeAndClearStartCallback(BLEStatus status) {
  adv_data_needs_update_ = false;
  scan_rsp_needs_update_ = false;

  // We allow NULL callbacks.
  if (*adv_start_callback_)
    (*adv_start_callback_)(status);

  adv_start_callback_ = nullptr;
}

void LowEnergyClient::InvokeAndClearStopCallback(BLEStatus status) {
  // We allow NULL callbacks.
  if (*adv_stop_callback_)
    (*adv_stop_callback_)(status);

  adv_stop_callback_ = nullptr;
}

// LowEnergyClientFactory implementation
// ========================================================

LowEnergyClientFactory::LowEnergyClientFactory() {
  hal::BluetoothGattInterface::Get()->AddClientObserver(this);
}

LowEnergyClientFactory::~LowEnergyClientFactory() {
  hal::BluetoothGattInterface::Get()->RemoveClientObserver(this);
}

bool LowEnergyClientFactory::RegisterClient(const UUID& uuid,
                                            const ClientCallback& callback) {
  VLOG(1) << __func__ << " - UUID: " << uuid.ToString();
  lock_guard<mutex> lock(pending_calls_lock_);

  if (pending_calls_.find(uuid) != pending_calls_.end()) {
    LOG(ERROR) << "Low-Energy client with given UUID already registered - "
               << "UUID: " << uuid.ToString();
    return false;
  }

  const btgatt_client_interface_t* hal_iface =
      hal::BluetoothGattInterface::Get()->GetClientHALInterface();
  bt_uuid_t app_uuid = uuid.GetBlueDroid();

  if (hal_iface->register_client(&app_uuid) != BT_STATUS_SUCCESS)
    return false;

  pending_calls_[uuid] = callback;

  return true;
}

void LowEnergyClientFactory::RegisterClientCallback(
    hal::BluetoothGattInterface* gatt_iface,
    int status, int client_if,
    const bt_uuid_t& app_uuid) {
  UUID uuid(app_uuid);

  VLOG(1) << __func__ << " - UUID: " << uuid.ToString();
  lock_guard<mutex> lock(pending_calls_lock_);

  auto iter = pending_calls_.find(uuid);
  if (iter == pending_calls_.end()) {
    VLOG(1) << "Ignoring callback for unknown app_id: " << uuid.ToString();
    return;
  }

  // No need to construct a client if the call wasn't successful.
  std::unique_ptr<LowEnergyClient> client;
  BLEStatus result = BLE_STATUS_FAILURE;
  if (status == BT_STATUS_SUCCESS) {
    client.reset(new LowEnergyClient(uuid, client_if));

    // Use the unsafe variant to register this as an observer, since
    // LowEnergyClient instances only get created by LowEnergyClientCallback
    // from inside this GATT client observer event, which would otherwise cause
    // a deadlock.
    gatt_iface->AddClientObserverUnsafe(client.get());

    result = BLE_STATUS_SUCCESS;
  }

  // Notify the result via the success callback.
  iter->second(result, uuid, std::move(client));

  pending_calls_.erase(iter);
}

}  // namespace bluetooth
