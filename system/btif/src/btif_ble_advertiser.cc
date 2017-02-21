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
#include "btif_common.h"

using base::Bind;
using base::Owned;
using std::vector;

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

class BleAdvertiserInterfaceImpl : public BleAdvertiserInterface {
  ~BleAdvertiserInterfaceImpl(){};

  void RegisterAdvertiserCb(
      base::Callback<void(uint8_t /* adv_id */, uint8_t /* status */)> cb,
      uint8_t advertiser_id, uint8_t status) {
    LOG(INFO) << __func__ << " status: " << +status
              << " , adveriser_id: " << +advertiser_id;
    do_in_jni_thread(Bind(cb, advertiser_id, status));
  }

  void RegisterAdvertiser(
      base::Callback<void(uint8_t /* advertiser_id */, uint8_t /* status */)>
          cb) override {
    do_in_bta_thread(
        FROM_HERE, Bind(&BleAdvertisingManager::RegisterAdvertiser,
                        base::Unretained(BleAdvertisingManager::Get()),
                        Bind(&BleAdvertiserInterfaceImpl::RegisterAdvertiserCb,
                             base::Unretained(this), cb)));
  }

  void Unregister(uint8_t advertiser_id) override {
    do_in_bta_thread(
        FROM_HERE,
        Bind(&BleAdvertisingManager::Unregister,
             base::Unretained(BleAdvertisingManager::Get()), advertiser_id));
  }

  void SetParametersCb(Callback cb, uint8_t status) {
    LOG(INFO) << __func__ << " status: " << +status;
    do_in_jni_thread(Bind(cb, status));
  }

  void SetParameters(uint8_t advertiser_id,
                     uint16_t advertising_event_properties,
                     uint32_t min_interval, uint32_t max_interval, int chnl_map,
                     int tx_power, uint8_t primary_advertising_phy,
                     uint8_t secondary_advertising_phy,
                     uint8_t scan_request_notification_enable, Callback cb) {
    tBTM_BLE_ADV_PARAMS* params = new tBTM_BLE_ADV_PARAMS;

    params->advertising_event_properties = advertising_event_properties;
    params->adv_int_min = min_interval;
    params->adv_int_max = max_interval;
    params->channel_map = chnl_map;
    params->adv_filter_policy = 0;
    params->tx_power = tx_power;
    params->primary_advertising_phy = primary_advertising_phy;
    params->secondary_advertising_phy = secondary_advertising_phy;
    params->scan_request_notification_enable = scan_request_notification_enable;

    do_in_bta_thread(FROM_HERE,
                     Bind(&BleAdvertisingManager::SetParameters,
                          base::Unretained(BleAdvertisingManager::Get()),
                          advertiser_id, base::Owned(params),
                          Bind(&BleAdvertiserInterfaceImpl::SetParametersCb,
                               base::Unretained(this), cb)));
  }

  void SetData(int advertiser_id, bool set_scan_rsp, vector<uint8_t> data,
               Callback cb) override {
    do_in_bta_thread(
        FROM_HERE,
        Bind(&BleAdvertisingManager::SetData,
             base::Unretained(BleAdvertisingManager::Get()), advertiser_id,
             set_scan_rsp, std::move(data), jni_thread_wrapper(FROM_HERE, cb)));
  }

  void Enable(uint8_t advertiser_id, bool enable, Callback cb, int timeout_s,
              Callback timeout_cb) override {
    VLOG(1) << __func__ << " advertiser_id: " << +advertiser_id
            << " ,enable: " << enable;

    do_in_bta_thread(
        FROM_HERE,
        Bind(&BleAdvertisingManager::Enable,
             base::Unretained(BleAdvertisingManager::Get()), advertiser_id,
             enable, jni_thread_wrapper(FROM_HERE, cb), timeout_s,
             jni_thread_wrapper(FROM_HERE, timeout_cb)));
  }

  void StartAdvertising(uint8_t advertiser_id, Callback cb,
                        AdvertiseParameters params,
                        std::vector<uint8_t> advertise_data,
                        std::vector<uint8_t> scan_response_data, int timeout_s,
                        MultiAdvCb timeout_cb) override {
    VLOG(1) << __func__;

    tBTM_BLE_ADV_PARAMS* p_params = new tBTM_BLE_ADV_PARAMS;
    p_params->advertising_event_properties =
        params.advertising_event_properties;
    p_params->adv_int_min = params.min_interval;
    p_params->adv_int_max = params.max_interval;
    p_params->channel_map = params.channel_map;
    p_params->adv_filter_policy = 0;
    p_params->tx_power = params.tx_power;
    p_params->primary_advertising_phy = params.primary_advertising_phy;
    p_params->secondary_advertising_phy = params.secondary_advertising_phy;
    p_params->scan_request_notification_enable =
        params.scan_request_notification_enable;

    do_in_bta_thread(
        FROM_HERE,
        Bind(&BleAdvertisingManager::StartAdvertising,
             base::Unretained(BleAdvertisingManager::Get()), advertiser_id,
             jni_thread_wrapper(FROM_HERE, cb), base::Owned(p_params),
             std::move(advertise_data), std::move(scan_response_data),
             timeout_s, jni_thread_wrapper(FROM_HERE, timeout_cb)));
  }
};

BleAdvertiserInterface* btLeAdvertiserInstance = nullptr;

}  // namespace

BleAdvertiserInterface* get_ble_advertiser_instance() {
  if (btLeAdvertiserInstance == nullptr)
    btLeAdvertiserInstance = new BleAdvertiserInterfaceImpl();

  return btLeAdvertiserInstance;
}
