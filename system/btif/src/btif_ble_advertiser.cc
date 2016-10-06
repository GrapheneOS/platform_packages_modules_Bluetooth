/******************************************************************************
 *
 *  Copyright (C) 2016 Google Inc.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at:
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 ******************************************************************************/

#define LOG_TAG "bt_btif_ble_advertiser"

#include <hardware/bluetooth.h>
#include <hardware/bt_gatt.h>

#include <base/bind.h>
#include <vector>

#include "ble_advertiser.h"
#include "bta_closure_api.h"
#include "bta_gatt_api.h"
#include "btif_common.h"
#include "btif_gatt.h"

using base::Bind;
using base::Owned;
using std::vector;

extern bt_status_t do_in_jni_thread(const base::Closure& task);
extern const btgatt_callbacks_t* bt_gatt_callbacks;

#define CHECK_BTGATT_INIT()                                      \
  do {                                                           \
    if (bt_gatt_callbacks == NULL) {                             \
      LOG_WARN(LOG_TAG, "%s: BTGATT not initialized", __func__); \
      return BT_STATUS_NOT_READY;                                \
    } else {                                                     \
      LOG_VERBOSE(LOG_TAG, "%s", __func__);                      \
    }                                                            \
  } while (0)

namespace {

template <typename T>
class OwnedArrayWrapper {
 public:
  explicit OwnedArrayWrapper(T* o) : ptr_(o) {}
  ~OwnedArrayWrapper() { delete[] ptr_; }
  T* get() const { return ptr_; }
  OwnedArrayWrapper(OwnedArrayWrapper&& other) {
    ptr_ = other.ptr_;
    other.ptr_ = NULL;
  }

 private:
  mutable T* ptr_;
};

template <typename T>
T* Unwrap(const OwnedArrayWrapper<T>& o) {
  return o.get();
}

template <typename T>
static inline OwnedArrayWrapper<T> OwnedArray(T* o) {
  return OwnedArrayWrapper<T>(o);
}

/* return the actual power in dBm based on the mapping in config file */
int ble_tx_power[BTM_BLE_ADV_TX_POWER_MAX + 1] = BTM_BLE_ADV_TX_POWER;
char ble_map_adv_tx_power(int tx_power_index) {
  if (0 <= tx_power_index && tx_power_index < BTM_BLE_ADV_TX_POWER_MAX)
    return (char)ble_tx_power[tx_power_index];
  return 0;
}

#define MIN_ADV_LENGTH 2
#define BLE_AD_DATA_LEN 31
vector<uint8_t> build_adv_data(bool set_scan_rsp, bool include_name,
                               bool incl_txpower, uint16_t appearance,
                               vector<uint8_t> manufacturer_data,
                               vector<uint8_t> service_data,
                               vector<uint8_t> service_uuid) {
  vector<uint8_t> data;

  // Flags are added by lower layers of the stack, only if needed; no need to
  // add them here.

  // TODO(jpawlowski): appearance is a dead argument, never set by upper layers.
  // Remove.

  if (include_name) {
    char* bd_name;
    BTM_ReadLocalDeviceName(&bd_name);
    size_t bd_name_len = strlen(bd_name);
    uint8_t type;

    // TODO(jpawlowski) put a better limit on device name!
    if (data.size() + MIN_ADV_LENGTH + bd_name_len > BLE_AD_DATA_LEN) {
      bd_name_len = BLE_AD_DATA_LEN - data.size() - 1;
      type = BTM_BLE_AD_TYPE_NAME_SHORT;
    } else {
      type = BTM_BLE_AD_TYPE_NAME_CMPL;
    }

    data.push_back(bd_name_len + 1);
    data.push_back(type);
    data.insert(data.end(), bd_name, bd_name + bd_name_len);
  }

  if (manufacturer_data.size()) {
    data.push_back(manufacturer_data.size() + 1);
    data.push_back(HCI_EIR_MANUFACTURER_SPECIFIC_TYPE);
    data.insert(data.end(), manufacturer_data.begin(), manufacturer_data.end());
  }

  /* TX power */
  if (incl_txpower) {
    data.push_back(MIN_ADV_LENGTH);
    data.push_back(HCI_EIR_TX_POWER_LEVEL_TYPE);
    data.push_back(0);  // lower layers will fill this value.
  }

  // TODO(jpawlowski): right now we can pass only one service, and it's size
  // determine type (16/32/128bit), this must be fixed in future!
  if (service_uuid.size()) {
    data.push_back(service_uuid.size() + 1);
    if (service_uuid.size() == LEN_UUID_16)
      data.push_back(BT_EIR_COMPLETE_16BITS_UUID_TYPE);
    else if (service_uuid.size() == LEN_UUID_32)
      data.push_back(BT_EIR_COMPLETE_32BITS_UUID_TYPE);
    else if (service_uuid.size() == LEN_UUID_128)
      data.push_back(BT_EIR_COMPLETE_128BITS_UUID_TYPE);

    data.insert(data.end(), service_uuid.begin(), service_uuid.end());
  }

  if (service_data.size()) {
    data.push_back(service_data.size() + 1);
    // TODO(jpawlowski): we can accept only 16bit uuid. Remove this restriction
    // as we move this code up the stack
    data.push_back(BT_EIR_SERVICE_DATA_16BITS_UUID_TYPE);

    data.insert(data.end(), service_data.begin(), service_data.end());
  }

  return data;
}

void bta_adv_set_data_cback(tBTA_STATUS call_status) {}

void btif_adv_set_data_impl(int advertiser_id, bool set_scan_rsp,
                            vector<uint8_t> data) {
  uint8_t* data_ptr = nullptr;

  if (data.size()) {
    // base::Owned will free this ptr
    data_ptr = new uint8_t[data.size()];
    memcpy(data_ptr, data.data(), data.size());
  }

  if (!set_scan_rsp) {
    if (data_ptr) {
      do_in_bta_thread(FROM_HERE,
                       base::Bind(&BTM_BleWriteAdvData, OwnedArray(data_ptr),
                                  data.size(), bta_adv_set_data_cback));
    } else {
      do_in_bta_thread(FROM_HERE,
                       base::Bind(&BTM_BleWriteAdvData, nullptr, data.size(),
                                  bta_adv_set_data_cback));
    }
  } else {
    if (data_ptr) {
      do_in_bta_thread(FROM_HERE,
                       base::Bind(&BTM_BleWriteScanRsp, OwnedArray(data_ptr),
                                  data.size(), bta_adv_set_data_cback));
    } else {
      do_in_bta_thread(FROM_HERE,
                       base::Bind(&BTM_BleWriteScanRsp, nullptr, data.size(),
                                  bta_adv_set_data_cback));
    }
  }
}

bt_status_t btif_adv_set_data(int advertiser_id, bool set_scan_rsp,
                              bool include_name, bool include_txpower,
                              int min_interval, int max_interval,
                              int appearance, vector<uint8_t> manufacturer_data,
                              vector<uint8_t> service_data,
                              vector<uint8_t> service_uuid) {
  CHECK_BTGATT_INIT();

  vector<uint8_t> data =
      build_adv_data(set_scan_rsp, include_name, include_txpower, appearance,
                     manufacturer_data, service_data, service_uuid);

  return do_in_jni_thread(Bind(&btif_adv_set_data_impl, advertiser_id,
                               set_scan_rsp, std::move(data)));
}

void multi_adv_set_params_cb_impl(int advertiser_id, int status) {
  HAL_CBACK(bt_gatt_callbacks, advertiser->multi_adv_set_params_cb,
            advertiser_id, status);
}

void multi_adv_set_params_cb(uint8_t advertiser_id, uint8_t status) {
  do_in_jni_thread(Bind(multi_adv_set_params_cb_impl, advertiser_id, status));
}

void btif_multiadv_set_params_impl(int advertiser_id, int min_interval,
                                   int max_interval, int adv_type, int chnl_map,
                                   int tx_power) {
  tBTM_BLE_ADV_PARAMS* params = new tBTM_BLE_ADV_PARAMS;
  params->adv_int_min = min_interval;
  params->adv_int_max = max_interval;
  params->adv_type = adv_type;
  params->channel_map = chnl_map;
  params->adv_filter_policy = 0;
  params->tx_power = ble_map_adv_tx_power(tx_power);

  do_in_bta_thread(
      FROM_HERE,
      base::Bind(&BleAdvertisingManager::SetParameters,
                 base::Unretained(BleAdvertisingManager::Get()), advertiser_id,
                 base::Owned(params),
                 base::Bind(multi_adv_set_params_cb, advertiser_id)));
}

bt_status_t btif_multiadv_set_params(int advertiser_id, int min_interval,
                                     int max_interval, int adv_type,
                                     int chnl_map, int tx_power) {
  CHECK_BTGATT_INIT();
  return do_in_jni_thread(Bind(btif_multiadv_set_params_impl, advertiser_id,
                               min_interval, max_interval, adv_type, chnl_map,
                               tx_power));
}

void multi_adv_data_cb_impl(int advertiser_id, int status) {
  HAL_CBACK(bt_gatt_callbacks, advertiser->multi_adv_data_cb, advertiser_id,
            status);
}

void multi_adv_data_cb(uint8_t advertiser_id, uint8_t status) {
  do_in_jni_thread(Bind(multi_adv_data_cb_impl, advertiser_id, status));
}

void btif_multiadv_set_data_impl(int advertiser_id, bool set_scan_rsp,
                                 vector<uint8_t> data) {
  do_in_bta_thread(FROM_HERE,
                   base::Bind(&BleAdvertisingManager::SetData,
                              base::Unretained(BleAdvertisingManager::Get()),
                              advertiser_id, set_scan_rsp, std::move(data),
                              base::Bind(multi_adv_data_cb, advertiser_id)));
}

bt_status_t btif_multiadv_set_data(int advertiser_id, bool set_scan_rsp,
                                   bool include_name, bool incl_txpower,
                                   int appearance,
                                   vector<uint8_t> manufacturer_data,
                                   vector<uint8_t> service_data,
                                   vector<uint8_t> service_uuid) {
  CHECK_BTGATT_INIT();

  vector<uint8_t> data =
      build_adv_data(set_scan_rsp, include_name, incl_txpower, appearance,
                     manufacturer_data, service_data, service_uuid);

  return do_in_jni_thread(Bind(&btif_multiadv_set_data_impl, advertiser_id,
                               set_scan_rsp, std::move(data)));
}

void multi_adv_enable_cb_impl(int advertiser_id, int status, bool enable) {
  HAL_CBACK(bt_gatt_callbacks, advertiser->multi_adv_enable_cb, advertiser_id,
            status, enable);
}

void multi_adv_enable_cb(bool enable, uint8_t advertiser_id, uint8_t status) {
  do_in_jni_thread(
      Bind(multi_adv_enable_cb_impl, advertiser_id, status, enable));
}

void multi_adv_timeout_cb(uint8_t advertiser_id, uint8_t status) {
  do_in_jni_thread(
      Bind(multi_adv_enable_cb_impl, advertiser_id, status, false));
}

void btif_multiadv_enable_impl(int advertiser_id, bool enable, int timeout_s) {
  BTIF_TRACE_DEBUG("%s: advertiser_id: %d, enable: %d", __func__, advertiser_id,
                   enable);
  do_in_bta_thread(
      FROM_HERE,
      base::Bind(&BleAdvertisingManager::Enable,
                 base::Unretained(BleAdvertisingManager::Get()), advertiser_id,
                 enable, base::Bind(multi_adv_enable_cb, enable, advertiser_id),
                 timeout_s, base::Bind(multi_adv_timeout_cb, advertiser_id)));
}

bt_status_t btif_multiadv_enable(int advertiser_id, bool enable,
                                 int timeout_s) {
  CHECK_BTGATT_INIT();
  return do_in_jni_thread(
      Bind(btif_multiadv_enable_impl, advertiser_id, enable, timeout_s));
}

void multi_adv_reg_cb_impl(bt_uuid_t uuid, int advertiser_id, int status) {
  HAL_CBACK(bt_gatt_callbacks, advertiser->register_advertiser_cb, status,
            advertiser_id, &uuid);
}

void multi_adv_reg_cb(bt_uuid_t uuid, uint8_t advertiser_id, uint8_t status) {
  do_in_jni_thread(Bind(multi_adv_reg_cb_impl, uuid, advertiser_id, status));
}

bt_status_t btif_multiadv_register(bt_uuid_t* uuid) {
  do_in_bta_thread(FROM_HERE,
                   base::Bind(&BleAdvertisingManager::RegisterAdvertiser,
                              base::Unretained(BleAdvertisingManager::Get()),
                              base::Bind(multi_adv_reg_cb, *uuid)));
  return (bt_status_t)BTA_GATT_OK;
}

bt_status_t btif_multiadv_unregister(int advertiser_id) {
  do_in_bta_thread(FROM_HERE,
                   base::Bind(&BleAdvertisingManager::Unregister,
                              base::Unretained(BleAdvertisingManager::Get()),
                              advertiser_id));

  return (bt_status_t)BTA_GATT_OK;
}

}  // namespace

const ble_advertiser_interface_t btLeAdvertiserInstance = {
  btif_multiadv_register,
  btif_multiadv_unregister,
  btif_adv_set_data,
  btif_multiadv_set_params,
  btif_multiadv_set_data,
  btif_multiadv_enable
};
