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

#include "bta_closure_api.h"
#include "ble_advertiser.h"
#include "bta_gatt_api.h"
#include "btif_common.h"
#include "btif_gatt.h"
#include "btif_gatt_multi_adv_util.h"

using base::Bind;
using base::Owned;
using std::vector;

extern bt_status_t do_in_jni_thread(const base::Closure &task);
extern const btgatt_callbacks_t *bt_gatt_callbacks;

#define CHECK_BTGATT_INIT()                                      \
  do {                                                           \
    if (bt_gatt_callbacks == NULL) {                             \
      LOG_WARN(LOG_TAG, "%s: BTGATT not initialized", __func__); \
      return BT_STATUS_NOT_READY;                                \
    } else {                                                     \
      LOG_VERBOSE(LOG_TAG, "%s", __func__);                      \
    }                                                            \
  } while(0)

namespace {

bt_status_t btif_multiadv_enable(int advertiser_id, bool enable,
                                        int timeout_s);
void btif_multi_adv_stop_cb(void *data) {
  int advertiser_id = PTR_TO_INT(data);
  btif_multiadv_enable(advertiser_id, false, 0);  // Does context switch
}

void multi_adv_enable_cb_impl(int advertiser_id, int status, bool enable) {
  HAL_CBACK(bt_gatt_callbacks, advertiser->multi_adv_enable_cb, advertiser_id,
            status, enable);
  if (enable == false) {
      btif_multi_adv_timer_ctrl(
          advertiser_id, (status == BTA_GATT_OK) ? btif_multi_adv_stop_cb : NULL);
  }
}

void multi_adv_set_params_cb_impl(int advertiser_id, int status) {
  HAL_CBACK(bt_gatt_callbacks, advertiser->multi_adv_set_params_cb, advertiser_id,
            status);
  btif_multi_adv_timer_ctrl(
      advertiser_id, (status == BTA_GATT_OK) ? btif_multi_adv_stop_cb : NULL);
}

void multi_adv_data_cb_impl(int advertiser_id, int status) {
  btif_gattc_clear_clientif(advertiser_id, false);
  HAL_CBACK(bt_gatt_callbacks, advertiser->multi_adv_data_cb, advertiser_id,
            status);
}

bt_uuid_t registering_uuid;

void multi_adv_reg_cb_impl(int advertiser_id, int status) {
  HAL_CBACK(bt_gatt_callbacks, advertiser->register_advertiser_cb, status,
            advertiser_id, &registering_uuid);
}

void bta_gattc_multi_adv_cback(tBTM_BLE_MULTI_ADV_EVT event, uint8_t advertiser_id,
                               tBTA_STATUS status) {

  BTIF_TRACE_DEBUG("%s: advertiser_id: %d, Status:%x", __func__, advertiser_id, status);

  if (event == BTM_BLE_MULTI_ADV_REG_EVT)
    do_in_jni_thread(Bind(multi_adv_reg_cb_impl, advertiser_id, status));
  else if (event == BTM_BLE_MULTI_ADV_PARAM_EVT)
    do_in_jni_thread(Bind(multi_adv_set_params_cb_impl, advertiser_id, status));
  else if (event == BTM_BLE_MULTI_ADV_ENB_EVT)
    do_in_jni_thread(
        Bind(multi_adv_enable_cb_impl, advertiser_id, status, true));
  else if (event == BTM_BLE_MULTI_ADV_DISABLE_EVT)
    do_in_jni_thread(
        Bind(multi_adv_enable_cb_impl, advertiser_id, status, false));
  else if (event == BTM_BLE_MULTI_ADV_DATA_EVT)
    do_in_jni_thread(
        Bind(multi_adv_data_cb_impl, advertiser_id, status));
}

void bta_adv_set_data_cback(tBTA_STATUS call_status) {
  do_in_jni_thread(Bind(&btif_gattc_cleanup_inst_cb, STD_ADV_INSTID, false));
}

void btif_adv_set_data_impl(btif_adv_data_t *p_adv_data) {
  const int cbindex = CLNT_IF_IDX;
  if (cbindex >= 0 && btif_gattc_copy_datacb(cbindex, p_adv_data, false)) {
    btgatt_multi_adv_common_data *p_multi_adv_data_cb =
        btif_obtain_multi_adv_data_cb();

    tBTM_BLE_ADV_DATA *adv_cfg = new tBTM_BLE_ADV_DATA;
    memcpy(adv_cfg, &p_multi_adv_data_cb->inst_cb[cbindex].data,
           sizeof(tBTM_BLE_ADV_DATA));

    if (!p_adv_data->set_scan_rsp) {
      do_in_bta_thread(FROM_HERE,
          base::Bind(&BTM_BleWriteAdvData,
                     p_multi_adv_data_cb->inst_cb[cbindex].mask,
                     base::Owned(adv_cfg),
                     bta_adv_set_data_cback));
    } else {
      do_in_bta_thread(FROM_HERE,
          base::Bind(&BTM_BleWriteScanRsp,
                     p_multi_adv_data_cb->inst_cb[cbindex].mask,
                     base::Owned(adv_cfg),
                     bta_adv_set_data_cback));
    }
  } else {
    BTIF_TRACE_ERROR("%s: failed to get instance data cbindex: %d", __func__,
                     cbindex);
  }
}

bt_status_t btif_adv_set_data(int advertiser_id, bool set_scan_rsp,
                              bool include_name, bool include_txpower,
                              int min_interval, int max_interval,
                              int appearance,
                              vector<uint8_t> manufacturer_data,
                              vector<uint8_t> service_data,
                              vector<uint8_t> service_uuid) {
  CHECK_BTGATT_INIT();

  btif_adv_data_t *adv_data = new btif_adv_data_t;

  btif_gattc_adv_data_packager(
      advertiser_id, set_scan_rsp, include_name, include_txpower, min_interval,
      max_interval, appearance, std::move(manufacturer_data),
      std::move(service_data), std::move(service_uuid), adv_data);

  return do_in_jni_thread(
      Bind(&btif_adv_set_data_impl, base::Owned(adv_data)));
}

void btif_multiadv_set_params_impl(int advertiser_id, int min_interval,
                                          int max_interval, int adv_type,
                                          int chnl_map, int tx_power) {
  tBTM_BLE_ADV_PARAMS param;
  param.adv_int_min = min_interval;
  param.adv_int_max = max_interval;
  param.adv_type = adv_type;
  param.channel_map = chnl_map;
  param.adv_filter_policy = 0;
  param.tx_power = tx_power;

  btgatt_multi_adv_common_data *p_multi_adv_data_cb =
      btif_obtain_multi_adv_data_cb();
  memcpy(&p_multi_adv_data_cb->inst_cb[advertiser_id].param, &param,
         sizeof(tBTM_BLE_ADV_PARAMS));

  tBTM_BLE_ADV_PARAMS *params = new tBTM_BLE_ADV_PARAMS;
  memcpy(params, &(p_multi_adv_data_cb->inst_cb[advertiser_id].param), sizeof(tBTM_BLE_ADV_PARAMS));
  do_in_bta_thread(FROM_HERE,
      base::Bind(&BTM_BleAdvSetParameters, advertiser_id, base::Owned(params)));
}

bt_status_t btif_multiadv_set_params(int advertiser_id, int min_interval,
                                            int max_interval, int adv_type,
                                            int chnl_map, int tx_power) {
  CHECK_BTGATT_INIT();
  return do_in_jni_thread(Bind(btif_multiadv_set_params_impl, advertiser_id,
                               min_interval, max_interval, adv_type, chnl_map,
                               tx_power));
}

void btif_multiadv_set_data_impl(btif_adv_data_t *p_adv_data) {
  uint8_t advertiser_id = p_adv_data->advertiser_id;
  if (!btif_gattc_copy_datacb(advertiser_id, p_adv_data, true)) {
    BTIF_TRACE_ERROR("%s: failed to copy instance data: advertiser_id:%d",
                     __func__, advertiser_id);
    return;
  }

  btgatt_multi_adv_common_data *p_multi_adv_data_cb =
      btif_obtain_multi_adv_data_cb();

  do_in_bta_thread(FROM_HERE,
    base::Bind(&BTM_BleAdvSetData, advertiser_id, p_adv_data->set_scan_rsp,
              p_multi_adv_data_cb->inst_cb[advertiser_id].mask,
              (tBTM_BLE_ADV_DATA*)&p_multi_adv_data_cb->inst_cb[advertiser_id].data));
}

bt_status_t btif_multiadv_set_data(int advertiser_id, bool set_scan_rsp,
                                         bool include_name, bool incl_txpower,
                                         int appearance,
                                         vector<uint8_t> manufacturer_data,
                                         vector<uint8_t> service_data,
                                         vector<uint8_t> service_uuid) {
  CHECK_BTGATT_INIT();

  btif_adv_data_t *multi_adv_data_inst = new btif_adv_data_t;

  const int min_interval = 0;
  const int max_interval = 0;

  btif_gattc_adv_data_packager(
      advertiser_id, set_scan_rsp, include_name, incl_txpower, min_interval,
      max_interval, appearance, std::move(manufacturer_data),
      std::move(service_data), std::move(service_uuid), multi_adv_data_inst);

  return do_in_jni_thread(Bind(&btif_multiadv_set_data_impl,
                               base::Owned(multi_adv_data_inst)));
}

void btif_multiadv_enable_impl(int advertiser_id, bool enable,
                                      int timeout_s) {
  BTIF_TRACE_DEBUG("%s: advertiser_id: %d, enable: %d", __func__,
                   advertiser_id, enable);

  btgatt_multi_adv_common_data *p_multi_adv_data_cb =
      btif_obtain_multi_adv_data_cb();
  if (enable)
    p_multi_adv_data_cb->inst_cb[advertiser_id].timeout_s = timeout_s;

  do_in_bta_thread(FROM_HERE,
      base::Bind(&BTM_BleAdvEnable, advertiser_id, enable));
}

bt_status_t btif_multiadv_enable(int advertiser_id, bool enable,
                                        int timeout_s) {
  CHECK_BTGATT_INIT();
  return do_in_jni_thread(Bind(btif_multiadv_enable_impl, advertiser_id,
                               enable, timeout_s));
}

bt_status_t btif_multiadv_register(bt_uuid_t *uuid) {
  btif_gattc_incr_app_count();

  registering_uuid = *uuid;

  do_in_bta_thread(FROM_HERE,
        base::Bind(&BTM_BleAdvRegister, bta_gattc_multi_adv_cback));
  return (bt_status_t)BTA_GATT_OK;
}

bt_status_t btif_multiadv_unregister(int advertiser_id) {
  btif_gattc_clear_clientif(advertiser_id, true);
  btif_gattc_decr_app_count();

  do_in_bta_thread(FROM_HERE,
        base::Bind(&BTM_BleAdvUnregister, advertiser_id));

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
