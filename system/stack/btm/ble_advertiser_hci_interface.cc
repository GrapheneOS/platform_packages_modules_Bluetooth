/******************************************************************************
 *
 *  Copyright (C) 2016 The Android Open Source Project
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

#include "ble_advertiser_hci_interface.h"
#include <base/callback.h>
#include <base/logging.h>
#include <queue>
#include <utility>
#include "btm_api.h"
#include "btm_ble_api.h"

#define BTM_BLE_MULTI_ADV_SET_RANDOM_ADDR_LEN 8
#define BTM_BLE_MULTI_ADV_ENB_LEN 3
#define BTM_BLE_MULTI_ADV_SET_PARAM_LEN 24
#define BTM_BLE_AD_DATA_LEN 31
#define BTM_BLE_MULTI_ADV_WRITE_DATA_LEN (BTM_BLE_AD_DATA_LEN + 3)

using status_cb = BleAdvertiserHciInterface::status_cb;

namespace {
class BleAdvertiserHciInterfaceImpl;

BleAdvertiserHciInterfaceImpl *instance = nullptr;
std::queue<std::pair<int, status_cb>> *pending_ops = nullptr;

void btm_ble_multi_adv_vsc_cmpl_cback(tBTM_VSC_CMPL *p_params) {
  uint8_t status, subcode;
  uint8_t *p = p_params->p_param_buf;
  uint16_t len = p_params->param_len;

  // All multi-adv commands respond with status and inst_id.
  LOG_ASSERT(len == 2) << "Received bad response length to multi-adv VSC";

  STREAM_TO_UINT8(status, p);
  STREAM_TO_UINT8(subcode, p);

  VLOG(1) << "subcode = " << +subcode << ", status: " << +status;

  auto pending_op = pending_ops->front();
  uint8_t opcode = pending_op.first;
  pending_ops->pop();

  if (opcode != subcode) {
    LOG(ERROR) << "unexpected VSC cmpl, expect: " << +subcode
               << " get: " << +opcode;
    return;
  }

  pending_op.second.Run(status);
}

class BleAdvertiserHciInterfaceImpl : public BleAdvertiserHciInterface {
  void SendVscMultiAdvCmd(uint8_t param_len, uint8_t *param_buf,
                          status_cb command_complete) {
    BTM_VendorSpecificCommand(HCI_BLE_MULTI_ADV_OCF, param_len, param_buf,
                              btm_ble_multi_adv_vsc_cmpl_cback);
    pending_ops->push(std::make_pair(param_buf[0], command_complete));
  }

  void ReadInstanceCount(base::Callback<void(uint8_t /* inst_cnt*/)> cb) override {
    cb.Run(BTM_BleMaxMultiAdvInstanceCount());
  }

  void SetParameters(uint8_t adv_int_min, uint8_t adv_int_max,
                     uint8_t advertising_type, uint8_t own_address_type,
                     BD_ADDR own_address, uint8_t direct_address_type,
                     BD_ADDR direct_address, uint8_t channel_map,
                     uint8_t filter_policy, uint8_t inst_id, uint8_t tx_power,
                     status_cb command_complete) override {
    VLOG(1) << __func__;
    uint8_t param[BTM_BLE_MULTI_ADV_SET_PARAM_LEN];
    memset(param, 0, BTM_BLE_MULTI_ADV_SET_PARAM_LEN);

    uint8_t *pp = param;
    UINT8_TO_STREAM(pp, BTM_BLE_MULTI_ADV_SET_PARAM);
    UINT16_TO_STREAM(pp, adv_int_min);
    UINT16_TO_STREAM(pp, adv_int_max);
    UINT8_TO_STREAM(pp, advertising_type);
    UINT8_TO_STREAM(pp, own_address_type);
    BDADDR_TO_STREAM(pp, own_address);
    UINT8_TO_STREAM(pp, direct_address_type);
    BDADDR_TO_STREAM(pp, direct_address);
    UINT8_TO_STREAM(pp, channel_map);
    UINT8_TO_STREAM(pp, filter_policy);
    UINT8_TO_STREAM(pp, inst_id);
    UINT8_TO_STREAM(pp, tx_power);

    SendVscMultiAdvCmd(BTM_BLE_MULTI_ADV_SET_PARAM_LEN, param,
                       command_complete);
  }

  void SetAdvertisingData(uint8_t data_length, uint8_t *data, uint8_t inst_id,
                          status_cb command_complete) override {
    VLOG(1) << __func__;
    uint8_t param[BTM_BLE_MULTI_ADV_WRITE_DATA_LEN];
    memset(param, 0, BTM_BLE_MULTI_ADV_WRITE_DATA_LEN);

    uint8_t *pp = param;
    UINT8_TO_STREAM(pp, BTM_BLE_MULTI_ADV_WRITE_ADV_DATA);
    UINT8_TO_STREAM(pp, data_length);
    ARRAY_TO_STREAM(pp, data, data_length);
    param[BTM_BLE_MULTI_ADV_WRITE_DATA_LEN - 1] = inst_id;

    SendVscMultiAdvCmd((uint8_t)BTM_BLE_MULTI_ADV_WRITE_DATA_LEN, param,
                       command_complete);
  }

  void SetScanResponseData(uint8_t scan_response_data_length,
                           uint8_t *scan_response_data, uint8_t inst_id,
                           status_cb command_complete) {
    VLOG(1) << __func__;
    uint8_t param[BTM_BLE_MULTI_ADV_WRITE_DATA_LEN];
    memset(param, 0, BTM_BLE_MULTI_ADV_WRITE_DATA_LEN);

    uint8_t *pp = param;
    UINT8_TO_STREAM(pp, BTM_BLE_MULTI_ADV_WRITE_SCAN_RSP_DATA);
    UINT8_TO_STREAM(pp, scan_response_data_length);
    ARRAY_TO_STREAM(pp, scan_response_data, scan_response_data_length);
    param[BTM_BLE_MULTI_ADV_WRITE_DATA_LEN - 1] = inst_id;

    SendVscMultiAdvCmd((uint8_t)BTM_BLE_MULTI_ADV_WRITE_DATA_LEN, param,
                       command_complete);
  }

  void SetRandomAddress(uint8_t random_address[6], uint8_t inst_id,
                        status_cb command_complete) {
    VLOG(1) << __func__;
    uint8_t param[BTM_BLE_MULTI_ADV_SET_RANDOM_ADDR_LEN];
    memset(param, 0, BTM_BLE_MULTI_ADV_SET_RANDOM_ADDR_LEN);

    uint8_t *pp = param;
    UINT8_TO_STREAM(pp, BTM_BLE_MULTI_ADV_SET_RANDOM_ADDR);
    BDADDR_TO_STREAM(pp, random_address);
    UINT8_TO_STREAM(pp, inst_id);

    SendVscMultiAdvCmd((uint8_t)BTM_BLE_MULTI_ADV_SET_RANDOM_ADDR_LEN, param,
                       command_complete);
  }

  void Enable(uint8_t advertising_enable, uint8_t inst_id,
              status_cb command_complete) {
    VLOG(1) << __func__;
    uint8_t param[BTM_BLE_MULTI_ADV_ENB_LEN];
    memset(param, 0, BTM_BLE_MULTI_ADV_ENB_LEN);

    uint8_t *pp = param;
    UINT8_TO_STREAM(pp, BTM_BLE_MULTI_ADV_ENB);
    UINT8_TO_STREAM(pp, advertising_enable);
    UINT8_TO_STREAM(pp, inst_id);

    SendVscMultiAdvCmd((uint8_t)BTM_BLE_MULTI_ADV_ENB_LEN, param,
                       command_complete);
  }

 public:
  static void VendorSpecificEventCback(uint8_t length, uint8_t *p) {
    VLOG(1) << __func__;

    LOG_ASSERT(p);
    uint8_t sub_event, adv_inst, change_reason;
    uint16_t conn_handle;

    STREAM_TO_UINT8(sub_event, p);
    length--;

    if (sub_event != HCI_VSE_SUBCODE_BLE_MULTI_ADV_ST_CHG || length != 4) {
      return;
    }

    STREAM_TO_UINT8(adv_inst, p);
    STREAM_TO_UINT8(change_reason, p);
    STREAM_TO_UINT16(conn_handle, p);
  }
};
}  // namespace

void BleAdvertiserHciInterface::Initialize() {
  VLOG(1) << __func__;
  LOG_ASSERT(instance == nullptr) << "Was already initialized.";
  instance = new BleAdvertiserHciInterfaceImpl();
  pending_ops = new std::queue<std::pair<int, status_cb>>();

  BTM_RegisterForVSEvents(
      BleAdvertiserHciInterfaceImpl::VendorSpecificEventCback, true);
}

BleAdvertiserHciInterface *BleAdvertiserHciInterface::Get() { return instance; }

void BleAdvertiserHciInterface::CleanUp() {
  VLOG(1) << __func__;
  BTM_RegisterForVSEvents(
      BleAdvertiserHciInterfaceImpl::VendorSpecificEventCback, false);
  delete pending_ops;
  pending_ops = nullptr;
  delete instance;
  instance = nullptr;
}
