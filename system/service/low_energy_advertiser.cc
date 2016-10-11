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

#include "service/low_energy_advertiser.h"

#include <base/bind.h>
#include <base/logging.h>

#include "service/adapter.h"
#include "service/common/bluetooth/util/address_helper.h"
#include "service/logging_helpers.h"
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

bool ProcessUUID(const uint8_t* uuid_data, size_t uuid_len, UUID* out_uuid) {
  // BTIF expects a single 128-bit UUID to be passed in little-endian form, so
  // we need to convert into that from raw data.
  // TODO(armansito): We have three repeated if bodies below only because UUID
  // accepts std::array which requires constexpr lengths. We should just have a
  // single UUID constructor that takes in an std::vector instead.
  if (uuid_len == UUID::kNumBytes16) {
    UUID::UUID16Bit uuid_bytes;
    for (size_t i = 0; i < uuid_len; ++i)
      uuid_bytes[uuid_len - i - 1] = uuid_data[i];
    *out_uuid = UUID(uuid_bytes);
  } else if (uuid_len == UUID::kNumBytes32) {
    UUID::UUID32Bit uuid_bytes;
    for (size_t i = 0; i < uuid_len; ++i)
      uuid_bytes[uuid_len - i - 1] = uuid_data[i];
    *out_uuid = UUID(uuid_bytes);
  } else if (uuid_len == UUID::kNumBytes128) {
    UUID::UUID128Bit uuid_bytes;
    for (size_t i = 0; i < uuid_len; ++i)
      uuid_bytes[uuid_len - i - 1] = uuid_data[i];
    *out_uuid = UUID(uuid_bytes);
  } else {
    LOG(ERROR) << "Invalid UUID length";
    return false;
  }

  return true;
}

bool ProcessServiceData(const uint8_t* data,
        uint8_t uuid_len,
        HALAdvertiseData* out_data) {
  size_t field_len = data[0];

  // Minimum packet size should be equal to the uuid length + 1 to include
  // the byte for the type of packet
  if (field_len < uuid_len + 1) {
    // Invalid packet size
    return false;
  }

  if (!out_data->service_data.empty()) {
    // More than one Service Data is not allowed due to the limitations
    // of the HAL API. We error in order to make sure there
    // is no ambiguity on which data to send.
    VLOG(1) << "More than one Service Data entry not allowed";
    return false;
  }

  const uint8_t* service_uuid = data + 2;
  UUID uuid;
  if (!ProcessUUID(service_uuid, uuid_len, &uuid))
    return false;

  UUID::UUID128Bit uuid_bytes = uuid.GetFullLittleEndian();
  const std::vector<uint8_t> temp_uuid(
      uuid_bytes.data(), uuid_bytes.data() + uuid_bytes.size());

  // This section is to make sure that there is no UUID conflict
  if (out_data->service_uuid.empty()) {
    out_data->service_uuid = temp_uuid;
  } else if (out_data->service_uuid != temp_uuid) {
    // Mismatch in uuid passed through service data and uuid passed
    // through uuid field
    VLOG(1) << "More than one UUID entry not allowed";
    return false;
  }  // else do nothing as UUID is already properly assigned

  // Use + uuid_len + 2 here in order to skip over a
  // uuid contained in the beggining of the field
  const uint8_t* srv_data = data + uuid_len + 2;


  out_data->service_data.insert(
      out_data->service_data.begin(),
      srv_data, srv_data + field_len - uuid_len - 1);

  return true;
}

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

    switch (type) {
    case HCI_EIR_MANUFACTURER_SPECIFIC_TYPE: {
      // TODO(armansito): BTIF doesn't allow setting more than one
      // manufacturer-specific data entry. This is something we should fix. For
      // now, fail if more than one entry was set.
      if (!out_data->manufacturer_data.empty()) {
        LOG(ERROR) << "More than one Manufacturer Specific Data entry not allowed";
        return false;
      }

      // The value bytes start at the next byte in the "TLV" format.
      const uint8_t* mnf_data = data.data() + i + 2;
      out_data->manufacturer_data.insert(
          out_data->manufacturer_data.begin(),
          mnf_data, mnf_data + field_len - 1);
      break;
    }
    case HCI_EIR_MORE_16BITS_UUID_TYPE:
    case HCI_EIR_COMPLETE_16BITS_UUID_TYPE:
    case HCI_EIR_MORE_32BITS_UUID_TYPE:
    case HCI_EIR_COMPLETE_32BITS_UUID_TYPE:
    case HCI_EIR_MORE_128BITS_UUID_TYPE:
    case HCI_EIR_COMPLETE_128BITS_UUID_TYPE: {
      const uint8_t* uuid_data = data.data() + i + 2;
      size_t uuid_len = field_len - 1;
      UUID uuid;
      if (!ProcessUUID(uuid_data, uuid_len, &uuid))
        return false;

      UUID::UUID128Bit uuid_bytes = uuid.GetFullLittleEndian();

      if (!out_data->service_uuid.empty() &&
          memcmp(out_data->service_uuid.data(),
                 uuid_bytes.data(), uuid_bytes.size()) != 0) {
        // More than one UUID is not allowed due to the limitations
        // of the HAL API. We error in order to make sure there
        // is no ambiguity on which UUID to send. Also makes sure that
        // UUID Hasn't been set by service data first
        LOG(ERROR) << "More than one UUID entry not allowed";
        return false;
      }

      out_data->service_uuid.assign(
          uuid_bytes.data(), uuid_bytes.data() + UUID::kNumBytes128);
      break;
    }
    case HCI_EIR_SERVICE_DATA_16BITS_UUID_TYPE: {
      if (!ProcessServiceData(data.data() + i, 2, out_data))
        return false;
      break;
    }
    case HCI_EIR_SERVICE_DATA_32BITS_UUID_TYPE: {
      if (!ProcessServiceData(data.data() + i, 4, out_data))
        return false;
      break;
    }
    case HCI_EIR_SERVICE_DATA_128BITS_UUID_TYPE: {
      if (!ProcessServiceData(data.data() + i, 16, out_data))
        return false;
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

  // Convert milliseconds to Bluetooth units.
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

void DoNothing(uint8_t status) {}

}  // namespace

// LowEnergyAdvertiser implementation
// ========================================================

LowEnergyAdvertiser::LowEnergyAdvertiser(const UUID& uuid, int advertiser_id) :
      app_identifier_(uuid),
      advertiser_id_(advertiser_id),
      adv_data_needs_update_(false),
      scan_rsp_needs_update_(false),
      is_setting_adv_data_(false),
      adv_started_(false),
      adv_start_callback_(nullptr),
      adv_stop_callback_(nullptr) {
}

LowEnergyAdvertiser::~LowEnergyAdvertiser() {
  // Automatically unregister the advertiser.
  VLOG(1) << "LowEnergyAdvertiser unregistering advertiser: " << advertiser_id_;

  // Stop advertising and ignore the result.
  hal::BluetoothGattInterface::Get()->
      GetAdvertiserHALInterface()->MultiAdvEnable(advertiser_id_, false, base::Bind(&DoNothing), 0, base::Bind(&DoNothing));
  hal::BluetoothGattInterface::Get()->
      GetAdvertiserHALInterface()->Unregister(advertiser_id_);
}

bool LowEnergyAdvertiser::StartAdvertising(const AdvertiseSettings& settings,
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
  advertise_settings_ = settings;

  AdvertiseParams params;
  GetAdvertiseParams(settings, !scan_response_.data().empty(), &params);

  hal::BluetoothGattInterface::Get()->
      GetAdvertiserHALInterface()->MultiAdvSetParameters(
          advertiser_id_,
          params.min_interval,
          params.max_interval,
          params.event_type,
          kAdvertisingChannelAll,
          params.tx_power_level,
          base::Bind(&LowEnergyAdvertiser::MultiAdvSetParamsCallback, base::Unretained(this), advertiser_id_));

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

bool LowEnergyAdvertiser::StopAdvertising(const StatusCallback& callback) {
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

  hal::BluetoothGattInterface::Get()
      ->GetAdvertiserHALInterface()
      ->MultiAdvEnable(
          advertiser_id_, false,
          base::Bind(&LowEnergyAdvertiser::MultiAdvEnableCallback,
                     base::Unretained(this), false, advertiser_id_),
          0, base::Bind(&LowEnergyAdvertiser::MultiAdvEnableCallback,
                        base::Unretained(this), false, advertiser_id_));

  // OK to set this at the end since we're still holding |adv_fields_lock_|.
  adv_stop_callback_.reset(new StatusCallback(callback));

  return true;
}

bool LowEnergyAdvertiser::IsAdvertisingStarted() const {
  return adv_started_.load();
}

bool LowEnergyAdvertiser::IsStartingAdvertising() const {
  return !IsAdvertisingStarted() && adv_start_callback_;
}

bool LowEnergyAdvertiser::IsStoppingAdvertising() const {
  return IsAdvertisingStarted() && adv_stop_callback_;
}

const UUID& LowEnergyAdvertiser::GetAppIdentifier() const {
  return app_identifier_;
}

int LowEnergyAdvertiser::GetInstanceId() const {
  return advertiser_id_;
}

void LowEnergyAdvertiser::HandleDeferredAdvertiseData() {
  VLOG(2) << __func__;

  CHECK(!IsAdvertisingStarted());
  CHECK(!IsStoppingAdvertising());
  CHECK(IsStartingAdvertising());
  CHECK(!is_setting_adv_data_.load());

  if (adv_data_needs_update_.load()) {
    bt_status_t status = SetAdvertiseData(adv_data_, false);
    if (status != BT_STATUS_SUCCESS) {
      LOG(ERROR) << "Failed setting advertisement data";
      InvokeAndClearStartCallback(GetBLEStatus(status));
    }
    return;
  }

  if (scan_rsp_needs_update_.load()) {
    bt_status_t status = SetAdvertiseData(scan_response_, true);
    if (status != BT_STATUS_SUCCESS) {
      LOG(ERROR) << "Failed setting scan response data";
      InvokeAndClearStartCallback(GetBLEStatus(status));
    }
    return;
  }

  AdvertiseParams params;
  GetAdvertiseParams(advertise_settings_, !scan_response_.data().empty(), &params);

  hal::BluetoothGattInterface::Get()
      ->GetAdvertiserHALInterface()
      ->MultiAdvEnable(
          advertiser_id_, true,
          base::Bind(&LowEnergyAdvertiser::MultiAdvEnableCallback,
                     base::Unretained(this), true, advertiser_id_),
          params.timeout_s,
          base::Bind(&LowEnergyAdvertiser::MultiAdvEnableCallback,
                     base::Unretained(this), false, advertiser_id_));
}

void LowEnergyAdvertiser::MultiAdvSetParamsCallback(
    uint8_t advertiser_id, uint8_t status) {
  if (advertiser_id != advertiser_id_)
    return;

  lock_guard<mutex> lock(adv_fields_lock_);

  VLOG(1) << __func__ << "advertiser_id: " << advertiser_id << " status: " << status;

  // Terminate operation in case of error.
  if (status != BT_STATUS_SUCCESS) {
    LOG(ERROR) << "Failed to set advertising parameters";
    InvokeAndClearStartCallback(GetBLEStatus(status));
    return;
  }

  // Now handle deferred tasks.
  HandleDeferredAdvertiseData();
}

void LowEnergyAdvertiser::MultiAdvDataCallback(
    uint8_t advertiser_id, uint8_t status) {
  if (advertiser_id != advertiser_id_)
    return;

  lock_guard<mutex> lock(adv_fields_lock_);

  VLOG(1) << __func__ << "advertiser_id: " << advertiser_id << " status: " << status;

  is_setting_adv_data_ = false;

  // Terminate operation in case of error.
  if (status != BT_STATUS_SUCCESS) {
    LOG(ERROR) << "Failed to set advertising data";
    InvokeAndClearStartCallback(GetBLEStatus(status));
    return;
  }

  // Now handle deferred tasks.
  HandleDeferredAdvertiseData();
}

void LowEnergyAdvertiser::MultiAdvEnableCallback(
    bool enable, uint8_t advertiser_id, uint8_t status) {
  if (advertiser_id != advertiser_id_)
    return;

  lock_guard<mutex> lock(adv_fields_lock_);

  VLOG(1) << __func__ << "advertiser_id: " << advertiser_id
          << " status: " << status
          << " enable: " << enable;

  if (enable) {
    CHECK(adv_start_callback_);
    CHECK(!adv_stop_callback_);

    // Terminate operation in case of error.
    if (status != BT_STATUS_SUCCESS) {
      LOG(ERROR) << "Failed to enable multi-advertising";
      InvokeAndClearStartCallback(GetBLEStatus(status));
      return;
    }

    // All pending tasks are complete. Report success.
    adv_started_ = true;
    InvokeAndClearStartCallback(BLE_STATUS_SUCCESS);

  } else {
    CHECK(!adv_start_callback_);
    CHECK(adv_stop_callback_);

    if (status == BT_STATUS_SUCCESS) {
      VLOG(1) << "Multi-advertising stopped for advertiser_id: " << advertiser_id;
      adv_started_ = false;
    } else {
      LOG(ERROR) << "Failed to stop multi-advertising";
    }

    InvokeAndClearStopCallback(GetBLEStatus(status));
  }
}

bt_status_t LowEnergyAdvertiser::SetAdvertiseData(
    const AdvertiseData& data,
    bool set_scan_rsp) {
  VLOG(2) << __func__;

  HALAdvertiseData hal_data;

  // TODO(armansito): The stack should check that the length is valid when other
  // fields inserted by the stack (e.g. flags, device name, tx-power) are taken
  // into account. At the moment we are skipping this check; this means that if
  // the given data is too long then the stack will truncate it.
  if (!ProcessAdvertiseData(data, &hal_data)) {
    LOG(ERROR) << "Malformed advertise data given";
    return BT_STATUS_FAIL;
  }

  if (is_setting_adv_data_.load()) {
    LOG(ERROR) << "Setting advertising data already in progress.";
    return BT_STATUS_FAIL;
  }

  // TODO(armansito): The length fields in the BTIF function below are signed
  // integers so a call to std::vector::size might get capped. This is very
  // unlikely anyway but it's safer to stop using signed-integer types for
  // length in APIs, so we should change that.
  hal::BluetoothGattInterface::Get()
      ->GetAdvertiserHALInterface()
      ->MultiAdvSetInstData(
          advertiser_id_, set_scan_rsp, data.include_device_name(),
          data.include_tx_power_level(),
          0,  // This is what Bluetooth.apk current hardcodes for "appearance".
          hal_data.manufacturer_data, hal_data.service_data,
          hal_data.service_uuid,
          base::Bind(&LowEnergyAdvertiser::MultiAdvDataCallback, base::Unretained(this), advertiser_id_));

  if (set_scan_rsp)
    scan_rsp_needs_update_ = false;
  else
    adv_data_needs_update_ = false;

  is_setting_adv_data_ = true;

  return BT_STATUS_SUCCESS;
}

void LowEnergyAdvertiser::InvokeAndClearStartCallback(BLEStatus status) {
  adv_data_needs_update_ = false;
  scan_rsp_needs_update_ = false;

  // We allow NULL callbacks.
  if (*adv_start_callback_)
    (*adv_start_callback_)(status);

  adv_start_callback_ = nullptr;
}

void LowEnergyAdvertiser::InvokeAndClearStopCallback(BLEStatus status) {
  // We allow NULL callbacks.
  if (*adv_stop_callback_)
    (*adv_stop_callback_)(status);

  adv_stop_callback_ = nullptr;
}

// LowEnergyAdvertiserFactory implementation
// ========================================================

LowEnergyAdvertiserFactory::LowEnergyAdvertiserFactory() {
}

LowEnergyAdvertiserFactory::~LowEnergyAdvertiserFactory() {
}

bool LowEnergyAdvertiserFactory::RegisterInstance(
    const UUID& app_uuid, const RegisterCallback& callback) {
  VLOG(1) << __func__;
  lock_guard<mutex> lock(pending_calls_lock_);

  if (pending_calls_.find(app_uuid) != pending_calls_.end()) {
    LOG(ERROR) << "Low-Energy advertiser with given UUID already registered - "
               << "UUID: " << app_uuid.ToString();
    return false;
  }

  BleAdvertiserInterface* hal_iface =
      hal::BluetoothGattInterface::Get()->GetAdvertiserHALInterface();

  VLOG(1) << __func__ << " calling register!";
  hal_iface->RegisterAdvertiser(
      base::Bind(&LowEnergyAdvertiserFactory::RegisterAdvertiserCallback,
                 base::Unretained(this), callback, app_uuid));
  VLOG(1) << __func__ << " call finished!";

  pending_calls_.insert(app_uuid);

  return true;
}

void LowEnergyAdvertiserFactory::RegisterAdvertiserCallback(
    const RegisterCallback& callback, const UUID& app_uuid,
    uint8_t advertiser_id, uint8_t status) {
  VLOG(1) << __func__;
  lock_guard<mutex> lock(pending_calls_lock_);

  auto iter = pending_calls_.find(app_uuid);
  if (iter == pending_calls_.end()) {
    VLOG(1) << "Ignoring callback for unknown app_id: " << app_uuid.ToString();
    return;
  }

  // No need to construct a advertiser if the call wasn't successful.
  std::unique_ptr<LowEnergyAdvertiser> advertiser;
  BLEStatus result = BLE_STATUS_FAILURE;
  if (status == BT_STATUS_SUCCESS) {
    advertiser.reset(new LowEnergyAdvertiser(app_uuid, advertiser_id));

    result = BLE_STATUS_SUCCESS;
  }

  // Notify the result via the result callback.
  callback(result, app_uuid, std::move(advertiser));

  pending_calls_.erase(iter);
}

}  // namespace bluetooth
