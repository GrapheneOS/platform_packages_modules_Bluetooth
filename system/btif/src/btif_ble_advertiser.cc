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

#include "bta_api.h"
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

bt_status_t btif_multiadv_disable(int advertiser_id);
void btif_multi_adv_stop_cb(void *data) {
  int advertiser_id = PTR_TO_INT(data);
  btif_multiadv_disable(advertiser_id);  // Does context switch
}

void multi_adv_enable_cb_impl(int advertiser_id, int status, int inst_id) {
  if (0xFF != inst_id) btif_multi_adv_add_instid_map(advertiser_id, inst_id, false);
  HAL_CBACK(bt_gatt_callbacks, advertiser->multi_adv_enable_cb, advertiser_id,
            status);
  btif_multi_adv_timer_ctrl(
      advertiser_id, (status == BTA_GATT_OK) ? btif_multi_adv_stop_cb : NULL);
}

void multi_adv_update_cb_impl(int advertiser_id, int status, int inst_id) {
  HAL_CBACK(bt_gatt_callbacks, advertiser->multi_adv_update_cb, advertiser_id,
            status);
  btif_multi_adv_timer_ctrl(
      advertiser_id, (status == BTA_GATT_OK) ? btif_multi_adv_stop_cb : NULL);
}

void multi_adv_data_cb_impl(int advertiser_id, int status, int inst_id) {
  btif_gattc_clear_clientif(advertiser_id, false);
  HAL_CBACK(bt_gatt_callbacks, advertiser->multi_adv_data_cb, advertiser_id,
            status);
}

void multi_adv_disable_cb_impl(int advertiser_id, int status, int inst_id) {
  btif_gattc_clear_clientif(advertiser_id, true);
  HAL_CBACK(bt_gatt_callbacks, advertiser->multi_adv_disable_cb, advertiser_id,
            status);
}

void bta_multiadv_cback(tBTA_BLE_MULTI_ADV_EVT event, uint8_t inst_id,
                               void *p_ref, tBTA_STATUS status) {
  uint8_t advertiser_id = 0;

  if (p_ref == NULL) {
    BTIF_TRACE_WARNING("%s: Invalid p_ref received", __func__);
  } else {
    advertiser_id = *(uint8_t *)p_ref;
  }

  BTIF_TRACE_DEBUG("%s: Inst ID %d, Status:%x, advertiser_id:%d", __func__, inst_id,
                   status, advertiser_id);

  if (event == BTA_BLE_MULTI_ADV_ENB_EVT)
    do_in_jni_thread(
        Bind(multi_adv_enable_cb_impl, advertiser_id, status, inst_id));
  else if (event == BTA_BLE_MULTI_ADV_DISABLE_EVT)
    do_in_jni_thread(
        Bind(multi_adv_disable_cb_impl, advertiser_id, status, inst_id));
  else if (event == BTA_BLE_MULTI_ADV_PARAM_EVT)
    do_in_jni_thread(
        Bind(multi_adv_update_cb_impl, advertiser_id, status, inst_id));
  else if (event == BTA_BLE_MULTI_ADV_DATA_EVT)
    do_in_jni_thread(Bind(multi_adv_data_cb_impl, advertiser_id, status, inst_id));
}

void bta_adv_set_data_cback(tBTA_STATUS call_status) {
  do_in_jni_thread(Bind(&btif_gattc_cleanup_inst_cb, STD_ADV_INSTID, false));
}

void btif_adv_set_data_impl(btif_adv_data_t *p_adv_data) {
  const int cbindex = CLNT_IF_IDX;
  if (cbindex >= 0 && btif_gattc_copy_datacb(cbindex, p_adv_data, false)) {
    btgatt_multi_adv_common_data *p_multi_adv_data_cb =
        btif_obtain_multi_adv_data_cb();
    if (!p_adv_data->set_scan_rsp) {
      BTA_DmBleSetAdvConfig(p_multi_adv_data_cb->inst_cb[cbindex].mask,
                            &p_multi_adv_data_cb->inst_cb[cbindex].data,
                            bta_adv_set_data_cback);
    } else {
      BTA_DmBleSetScanRsp(p_multi_adv_data_cb->inst_cb[cbindex].mask,
                          &p_multi_adv_data_cb->inst_cb[cbindex].data,
                          bta_adv_set_data_cback);
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

void btif_multiadv_enable_impl(int advertiser_id, int min_interval,
                                      int max_interval, int adv_type,
                                      int chnl_map, int tx_power,
                                      int timeout_s) {
  tBTA_BLE_ADV_PARAMS param;
  param.adv_int_min = min_interval;
  param.adv_int_max = max_interval;
  param.adv_type = adv_type;
  param.channel_map = chnl_map;
  param.adv_filter_policy = 0;
  param.tx_power = tx_power;

  int cbindex = -1;
  int arrindex =
      btif_multi_adv_add_instid_map(advertiser_id, INVALID_ADV_INST, true);
  if (arrindex >= 0)
    cbindex = btif_gattc_obtain_idx_for_datacb(advertiser_id, CLNT_IF_IDX);

  if (cbindex >= 0 && arrindex >= 0) {
    btgatt_multi_adv_common_data *p_multi_adv_data_cb =
        btif_obtain_multi_adv_data_cb();
    memcpy(&p_multi_adv_data_cb->inst_cb[cbindex].param, &param,
           sizeof(tBTA_BLE_ADV_PARAMS));
    p_multi_adv_data_cb->inst_cb[cbindex].timeout_s = timeout_s;
    BTIF_TRACE_DEBUG("%s: advertiser_id value: %d", __func__,
                     p_multi_adv_data_cb->clntif_map[arrindex + arrindex]);
    BTA_BleEnableAdvInstance(
        &(p_multi_adv_data_cb->inst_cb[cbindex].param),
        bta_multiadv_cback,
        &(p_multi_adv_data_cb->clntif_map[arrindex + arrindex]));
  } else {
    // let the error propagate up from BTA layer
    BTIF_TRACE_ERROR("%s: invalid index arrindex: %d, cbindex: %d", __func__,
                     arrindex, cbindex);
    BTA_BleEnableAdvInstance(&param, bta_multiadv_cback, NULL);
  }
}

bt_status_t btif_multiadv_enable(int advertiser_id, int min_interval,
                                        int max_interval, int adv_type,
                                        int chnl_map, int tx_power,
                                        int timeout_s) {
  CHECK_BTGATT_INIT();
  return do_in_jni_thread(Bind(btif_multiadv_enable_impl, advertiser_id,
                               min_interval, max_interval, adv_type, chnl_map,
                               tx_power, timeout_s));
}

void btif_multiadv_update_impl(int advertiser_id, int min_interval,
                                      int max_interval, int adv_type,
                                      int chnl_map, int tx_power) {
  tBTA_BLE_ADV_PARAMS param;
  param.adv_int_min = min_interval;
  param.adv_int_max = max_interval;
  param.adv_type = adv_type;
  param.channel_map = chnl_map;
  param.adv_filter_policy = 0;
  param.tx_power = tx_power;

  int inst_id = btif_multi_adv_instid_for_clientif(advertiser_id);
  int cbindex = btif_gattc_obtain_idx_for_datacb(advertiser_id, CLNT_IF_IDX);
  if (inst_id >= 0 && cbindex >= 0) {
    btgatt_multi_adv_common_data *p_multi_adv_data_cb =
        btif_obtain_multi_adv_data_cb();
    memcpy(&p_multi_adv_data_cb->inst_cb[cbindex].param, &param,
           sizeof(tBTA_BLE_ADV_PARAMS));
    BTA_BleUpdateAdvInstParam((uint8_t)inst_id,
                              &(p_multi_adv_data_cb->inst_cb[cbindex].param));
  } else {
    BTIF_TRACE_ERROR("%s: invalid index in BTIF_GATTC_UPDATE_ADV", __func__);
  }
}

bt_status_t btif_multiadv_update(int advertiser_id, int min_interval,
                                        int max_interval, int adv_type,
                                        int chnl_map, int tx_power,
                                        int timeout_s) {
  CHECK_BTGATT_INIT();
  return do_in_jni_thread(Bind(btif_multiadv_update_impl, advertiser_id,
                               min_interval, max_interval, adv_type, chnl_map,
                               tx_power));
}

void btif_multiadv_set_data_impl(btif_adv_data_t *p_adv_data) {
  int cbindex =
      btif_gattc_obtain_idx_for_datacb(p_adv_data->advertiser_id, CLNT_IF_IDX);
  int inst_id = btif_multi_adv_instid_for_clientif(p_adv_data->advertiser_id);
  if (inst_id >= 0 && cbindex >= 0 &&
      btif_gattc_copy_datacb(cbindex, p_adv_data, true)) {
    btgatt_multi_adv_common_data *p_multi_adv_data_cb =
        btif_obtain_multi_adv_data_cb();
    BTA_BleCfgAdvInstData((uint8_t)inst_id, p_adv_data->set_scan_rsp,
                          p_multi_adv_data_cb->inst_cb[cbindex].mask,
                          &p_multi_adv_data_cb->inst_cb[cbindex].data);
  } else {
    BTIF_TRACE_ERROR(
        "%s: failed to get invalid instance data: inst_id:%d cbindex:%d",
        __func__, inst_id, cbindex);
  }
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

void btif_multiadv_disable_impl(int advertiser_id) {
  int inst_id = btif_multi_adv_instid_for_clientif(advertiser_id);
  if (inst_id >= 0)
    BTA_BleDisableAdvInstance((uint8_t)inst_id);
  else
    BTIF_TRACE_ERROR("%s: invalid instance ID", __func__);
}

bt_status_t btif_multiadv_disable(int advertiser_id) {
  CHECK_BTGATT_INIT();
  return do_in_jni_thread(Bind(btif_multiadv_disable_impl, advertiser_id));
}

void btif_multiadv_register_cb_impl(int status, int advertiser_id,
                                      bt_uuid_t uuid) {
  HAL_CBACK(bt_gatt_callbacks, advertiser->register_advertiser_cb, status,
            advertiser_id, &uuid);
}

int nextAdvertiserId = 36;

bt_status_t btif_multiadv_register(bt_uuid_t *uuid) {
  btif_gattc_incr_app_count();

  // TODO: there should be code that reserve advertising inst_id and return it
  // here, so that we don't need mapping between advertiser_id and instance_id

  return do_in_jni_thread(Bind(btif_multiadv_register_cb_impl, BTA_GATT_OK,
                               nextAdvertiserId++, *uuid));
}

bt_status_t btif_multiadv_unregister(int advertiser_id) {
  btif_gattc_clear_clientif(advertiser_id, true);
  btif_gattc_decr_app_count();
  return (bt_status_t)BTA_GATT_OK;
}

}  // namespace

const ble_advertiser_interface_t btLeAdvertiserInstance = {
  btif_multiadv_register,
  btif_multiadv_unregister,
  btif_adv_set_data,
  btif_multiadv_enable,
  btif_multiadv_update,
  btif_multiadv_set_data,
  btif_multiadv_disable
};
