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
#include "device/include/controller.h"

#define BTM_BLE_MULTI_ADV_SET_RANDOM_ADDR_LEN 8
#define BTM_BLE_MULTI_ADV_ENB_LEN 3
#define BTM_BLE_MULTI_ADV_SET_PARAM_LEN 24
#define BTM_BLE_AD_DATA_LEN 31
#define BTM_BLE_MULTI_ADV_WRITE_DATA_LEN (BTM_BLE_AD_DATA_LEN + 3)

#define HCIC_PARAM_SIZE_WRITE_ADV_ENABLE 1
#define HCIC_PARAM_SIZE_WRITE_RANDOM_ADDR_CMD 6
#define HCIC_PARAM_SIZE_BLE_WRITE_ADV_PARAMS 15
#define HCIC_PARAM_SIZE_BLE_WRITE_SCAN_RSP 31
#define HCIC_PARAM_SIZE_BLE_WRITE_ADV_DATA 31

using status_cb = BleAdvertiserHciInterface::status_cb;

typedef void (*hci_cmd_complete_cb)(uint16_t opcode, uint8_t* return_parameters,
                                    uint16_t return_parameters_length);
extern void btu_hcif_send_cmd_with_cb(uint16_t opcode, uint8_t* params,
                                      uint8_t params_len,
                                      hci_cmd_complete_cb cb);

namespace {
BleAdvertiserHciInterface* instance = nullptr;
std::queue<std::pair<uint8_t, status_cb>>* pending_ops = nullptr;

void btm_ble_multi_adv_vsc_cmpl_cback(tBTM_VSC_CMPL* p_params) {
  uint8_t status, subcode;
  uint8_t* p = p_params->p_param_buf;
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

class BleAdvertiserVscHciInterfaceImpl : public BleAdvertiserHciInterface {
  void SendVscMultiAdvCmd(uint8_t param_len, uint8_t* param_buf,
                          status_cb command_complete) {
    BTM_VendorSpecificCommand(HCI_BLE_MULTI_ADV_OCF, param_len, param_buf,
                              btm_ble_multi_adv_vsc_cmpl_cback);
    pending_ops->push(std::make_pair(param_buf[0], command_complete));
  }

  void ReadInstanceCount(
      base::Callback<void(uint8_t /* inst_cnt*/)> cb) override {
    cb.Run(BTM_BleMaxMultiAdvInstanceCount());
  }

  void SetAdvertisingEventObserver(
      AdvertisingEventObserver* observer) override {
    this->advertising_event_observer = observer;
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

    uint8_t* pp = param;
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

  void SetAdvertisingData(uint8_t data_length, uint8_t* data, uint8_t inst_id,
                          status_cb command_complete) override {
    VLOG(1) << __func__;
    uint8_t param[BTM_BLE_MULTI_ADV_WRITE_DATA_LEN];
    memset(param, 0, BTM_BLE_MULTI_ADV_WRITE_DATA_LEN);

    uint8_t* pp = param;
    UINT8_TO_STREAM(pp, BTM_BLE_MULTI_ADV_WRITE_ADV_DATA);
    UINT8_TO_STREAM(pp, data_length);
    ARRAY_TO_STREAM(pp, data, data_length);
    param[BTM_BLE_MULTI_ADV_WRITE_DATA_LEN - 1] = inst_id;

    SendVscMultiAdvCmd((uint8_t)BTM_BLE_MULTI_ADV_WRITE_DATA_LEN, param,
                       command_complete);
  }

  void SetScanResponseData(uint8_t scan_response_data_length,
                           uint8_t* scan_response_data, uint8_t inst_id,
                           status_cb command_complete) override {
    VLOG(1) << __func__;
    uint8_t param[BTM_BLE_MULTI_ADV_WRITE_DATA_LEN];
    memset(param, 0, BTM_BLE_MULTI_ADV_WRITE_DATA_LEN);

    uint8_t* pp = param;
    UINT8_TO_STREAM(pp, BTM_BLE_MULTI_ADV_WRITE_SCAN_RSP_DATA);
    UINT8_TO_STREAM(pp, scan_response_data_length);
    ARRAY_TO_STREAM(pp, scan_response_data, scan_response_data_length);
    param[BTM_BLE_MULTI_ADV_WRITE_DATA_LEN - 1] = inst_id;

    SendVscMultiAdvCmd((uint8_t)BTM_BLE_MULTI_ADV_WRITE_DATA_LEN, param,
                       command_complete);
  }

  void SetRandomAddress(uint8_t random_address[6], uint8_t inst_id,
                        status_cb command_complete) override {
    VLOG(1) << __func__;
    uint8_t param[BTM_BLE_MULTI_ADV_SET_RANDOM_ADDR_LEN];
    memset(param, 0, BTM_BLE_MULTI_ADV_SET_RANDOM_ADDR_LEN);

    uint8_t* pp = param;
    UINT8_TO_STREAM(pp, BTM_BLE_MULTI_ADV_SET_RANDOM_ADDR);
    BDADDR_TO_STREAM(pp, random_address);
    UINT8_TO_STREAM(pp, inst_id);

    SendVscMultiAdvCmd((uint8_t)BTM_BLE_MULTI_ADV_SET_RANDOM_ADDR_LEN, param,
                       command_complete);
  }

  void Enable(uint8_t advertising_enable, uint8_t inst_id,
              status_cb command_complete) override {
    VLOG(1) << __func__;
    uint8_t param[BTM_BLE_MULTI_ADV_ENB_LEN];
    memset(param, 0, BTM_BLE_MULTI_ADV_ENB_LEN);

    uint8_t* pp = param;
    UINT8_TO_STREAM(pp, BTM_BLE_MULTI_ADV_ENB);
    UINT8_TO_STREAM(pp, advertising_enable);
    UINT8_TO_STREAM(pp, inst_id);

    SendVscMultiAdvCmd((uint8_t)BTM_BLE_MULTI_ADV_ENB_LEN, param,
                       command_complete);
  }

 public:
  static void VendorSpecificEventCback(uint8_t length, uint8_t* p) {
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

    AdvertisingEventObserver* observer =
        ((BleAdvertiserVscHciInterfaceImpl*)BleAdvertiserHciInterface::Get())
            ->advertising_event_observer;
    if (observer)
      observer->OnAdvertisingStateChanged(adv_inst, change_reason, conn_handle);
  }

 private:
  AdvertisingEventObserver* advertising_event_observer = nullptr;
};

std::queue<std::pair<uint16_t, status_cb>>* legacy_pending_ops = nullptr;
void adv_cmd_cmpl_cback(uint16_t opcode, uint8_t* return_parameters,
                        uint16_t return_parameters_length) {
  uint8_t status = *return_parameters;

  VLOG(1) << "opcode = " << +opcode << ", status: " << +status;

  auto pending_op = legacy_pending_ops->front();
  uint16_t pending_opc_opcode = pending_op.first;
  legacy_pending_ops->pop();

  if (opcode != pending_opc_opcode) {
    LOG(ERROR) << "unexpected command complete, expect: " << +pending_opc_opcode
               << " get: " << +opcode;
    return;
  }

  pending_op.second.Run(status);
}

class BleAdvertiserLegacyHciInterfaceImpl : public BleAdvertiserHciInterface {
  void SendAdvCmd(uint16_t opcode, uint8_t* param_buf, uint8_t param_buf_len,
                  status_cb command_complete) {
    btu_hcif_send_cmd_with_cb(opcode, param_buf, param_buf_len,
                              adv_cmd_cmpl_cback);

    legacy_pending_ops->push(std::make_pair(opcode, command_complete));
  }

  void ReadInstanceCount(
      base::Callback<void(uint8_t /* inst_cnt*/)> cb) override {
    cb.Run(1);
  }

  void SetAdvertisingEventObserver(
      AdvertisingEventObserver* observer) override {}

  void SetParameters(uint8_t adv_int_min, uint8_t adv_int_max,
                     uint8_t advertising_type, uint8_t own_address_type,
                     BD_ADDR own_address, uint8_t direct_address_type,
                     BD_ADDR direct_address, uint8_t channel_map,
                     uint8_t filter_policy, uint8_t inst_id, uint8_t tx_power,
                     status_cb command_complete) override {
    VLOG(1) << __func__;

    uint8_t param[HCIC_PARAM_SIZE_BLE_WRITE_ADV_PARAMS];

    uint8_t* pp = param;
    UINT16_TO_STREAM(pp, adv_int_min);
    UINT16_TO_STREAM(pp, adv_int_max);
    UINT8_TO_STREAM(pp, advertising_type);
    UINT8_TO_STREAM(pp, own_address_type);
    UINT8_TO_STREAM(pp, direct_address_type);
    BDADDR_TO_STREAM(pp, direct_address);
    UINT8_TO_STREAM(pp, channel_map);
    UINT8_TO_STREAM(pp, filter_policy);

    SendAdvCmd(HCI_BLE_WRITE_ADV_PARAMS, param,
               HCIC_PARAM_SIZE_BLE_WRITE_ADV_PARAMS, command_complete);
  }

  void SetAdvertisingData(uint8_t data_length, uint8_t* data, uint8_t inst_id,
                          status_cb command_complete) override {
    VLOG(1) << __func__;

    uint8_t param[HCIC_PARAM_SIZE_BLE_WRITE_ADV_DATA + 1];

    uint8_t* pp = param;
    memset(pp, 0, HCIC_PARAM_SIZE_BLE_WRITE_ADV_DATA + 1);
    UINT8_TO_STREAM(pp, data_length);
    ARRAY_TO_STREAM(pp, data, data_length);

    SendAdvCmd(HCI_BLE_WRITE_ADV_DATA, param,
               HCIC_PARAM_SIZE_BLE_WRITE_ADV_DATA + 1, command_complete);
  }

  void SetScanResponseData(uint8_t scan_response_data_length,
                           uint8_t* scan_response_data, uint8_t inst_id,
                           status_cb command_complete) override {
    VLOG(1) << __func__;
    uint8_t param[HCIC_PARAM_SIZE_BLE_WRITE_ADV_DATA + 1];

    uint8_t* pp = param;
    memset(pp, 0, HCIC_PARAM_SIZE_BLE_WRITE_ADV_DATA + 1);
    UINT8_TO_STREAM(pp, scan_response_data_length);
    ARRAY_TO_STREAM(pp, scan_response_data, scan_response_data_length);

    SendAdvCmd(HCI_BLE_WRITE_SCAN_RSP_DATA, param,
               HCIC_PARAM_SIZE_BLE_WRITE_ADV_DATA + 1, command_complete);
  }

  void SetRandomAddress(uint8_t random_address[6], uint8_t inst_id,
                        status_cb command_complete) override {
    VLOG(1) << __func__;

    uint8_t param[HCIC_PARAM_SIZE_WRITE_RANDOM_ADDR_CMD];

    uint8_t* pp = param;
    BDADDR_TO_STREAM(pp, random_address);

    SendAdvCmd(HCI_BLE_WRITE_RANDOM_ADDR, param,
               HCIC_PARAM_SIZE_WRITE_RANDOM_ADDR_CMD, command_complete);
  }

  void Enable(uint8_t advertising_enable, uint8_t inst_id,
              status_cb command_complete) override {
    VLOG(1) << __func__;
    uint8_t param[HCIC_PARAM_SIZE_WRITE_ADV_ENABLE];

    uint8_t* pp = param;
    UINT8_TO_STREAM(pp, advertising_enable);

    SendAdvCmd(HCI_BLE_WRITE_ADV_ENABLE, param,
               HCIC_PARAM_SIZE_WRITE_ADV_ENABLE, command_complete);
  }
};

class BleAdvertiserHciExtendedImpl : public BleAdvertiserHciInterface {
  void SendAdvCmd(uint16_t opcode, uint8_t* param_buf, uint8_t param_buf_len,
                  status_cb command_complete) {
    btu_hcif_send_cmd_with_cb(opcode, param_buf, param_buf_len,
                              adv_cmd_cmpl_cback);

    legacy_pending_ops->push(std::make_pair(opcode, command_complete));
  }

  void ReadInstanceCount(
      base::Callback<void(uint8_t /* inst_cnt*/)> cb) override {
    cb.Run(controller_get_interface()
               ->get_ble_number_of_supported_advertising_sets());
  }

  void SetAdvertisingEventObserver(
      AdvertisingEventObserver* observer) override {}

  void SetParameters(uint8_t adv_int_min, uint8_t adv_int_max,
                     uint8_t advertising_type, uint8_t own_address_type,
                     BD_ADDR own_address, uint8_t direct_address_type,
                     BD_ADDR direct_address, uint8_t channel_map,
                     uint8_t filter_policy, uint8_t advertising_handle,
                     uint8_t tx_power, status_cb command_complete) override {
    VLOG(1) << __func__;
    const uint16_t HCI_LE_SET_EXT_ADVERTISING_PARAM_LEN = 25;
    uint8_t param[HCI_LE_SET_EXT_ADVERTISING_PARAM_LEN];
    memset(param, 0, HCI_LE_SET_EXT_ADVERTISING_PARAM_LEN);

    uint8_t* pp = param;
    UINT8_TO_STREAM(pp, advertising_handle);

    if (advertising_type == 0x00) {  // ADV_IND
      UINT16_TO_STREAM(pp, 0x13);
    } else if (advertising_type == 0x02) {  // ADV_SCAN_IND
      UINT16_TO_STREAM(pp, 0x12);
    } else if (advertising_type == 0x03) {  // ADV_NONCONN_IND
      UINT16_TO_STREAM(pp, 0x10);
    } else {
      LOG_ASSERT("Unsupported advertisement type selected!");
    }

    UINT24_TO_STREAM(pp, (uint32_t)adv_int_min);
    UINT24_TO_STREAM(pp, (uint32_t)adv_int_max);
    UINT8_TO_STREAM(pp, channel_map);

    UINT8_TO_STREAM(pp, own_address_type);
    UINT8_TO_STREAM(pp, direct_address_type);
    BDADDR_TO_STREAM(pp, direct_address);
    UINT8_TO_STREAM(pp, filter_policy);

    INT8_TO_STREAM(pp, tx_power);

    UINT8_TO_STREAM(pp, 0x01);  // primary advertising phy
    UINT8_TO_STREAM(pp, 0x01);  // secondary advertising max skip
    UINT8_TO_STREAM(pp, 0x01);  // secondary advertising phy
    UINT8_TO_STREAM(pp, 0x00);  // advertising SID
    UINT8_TO_STREAM(pp, 0x00);  // scan req notification

    SendAdvCmd(HCI_LE_SET_EXT_ADVERTISING_PARAM, param,
               HCI_LE_SET_EXT_ADVERTISING_PARAM_LEN, command_complete);
  }

  void SetAdvertisingData(uint8_t data_length, uint8_t* data, uint8_t inst_id,
                          status_cb command_complete) override {
    VLOG(1) << __func__;

    const uint16_t cmd_length = 4 + data_length;
    uint8_t param[cmd_length];
    memset(param, 0, cmd_length);

    uint8_t* pp = param;
    UINT8_TO_STREAM(pp, inst_id);
    UINT8_TO_STREAM(pp, 0x03);  // complete advertising data
    UINT8_TO_STREAM(pp, 0x01);  // don't fragment
    UINT8_TO_STREAM(pp, data_length);
    ARRAY_TO_STREAM(pp, data, data_length);

    SendAdvCmd(HCI_LE_SET_EXT_ADVERTISING_DATA, param, cmd_length,
               command_complete);
  }

  void SetScanResponseData(uint8_t scan_response_data_length,
                           uint8_t* scan_response_data, uint8_t inst_id,
                           status_cb command_complete) override {
    VLOG(1) << __func__;

    const uint16_t cmd_length = 4 + scan_response_data_length;
    uint8_t param[cmd_length];
    memset(param, 0, cmd_length);

    uint8_t* pp = param;
    UINT8_TO_STREAM(pp, inst_id);
    UINT8_TO_STREAM(pp, 0x03);  // complete advertising data
    UINT8_TO_STREAM(pp, 0x01);  // don't fragment
    UINT8_TO_STREAM(pp, scan_response_data_length);
    ARRAY_TO_STREAM(pp, scan_response_data, scan_response_data_length);

    SendAdvCmd(HCI_LE_SET_EXT_ADVERTISING_SCAN_RESP, param, cmd_length,
               command_complete);
  }

  void SetRandomAddress(uint8_t random_address[6], uint8_t advertising_handle,
                        status_cb command_complete) override {
    VLOG(1) << __func__;
    const int LE_SET_ADVERTISING_SET_RANDOM_ADDRESS_LEN = 7;

    uint8_t param[LE_SET_ADVERTISING_SET_RANDOM_ADDRESS_LEN];
    memset(param, 0, LE_SET_ADVERTISING_SET_RANDOM_ADDRESS_LEN);

    uint8_t* pp = param;
    UINT8_TO_STREAM(pp, advertising_handle);
    BDADDR_TO_STREAM(pp, random_address);

    SendAdvCmd(HCI_LE_SET_EXT_ADVERTISING_RANDOM_ADDRESS, param,
               LE_SET_ADVERTISING_SET_RANDOM_ADDRESS_LEN, command_complete);
  }

  void Enable(uint8_t advertising_enable, uint8_t inst_id,
              status_cb command_complete) override {
    VLOG(1) << __func__;

    /* cmd_length = header_size + num_of_of_advertiser * size_per_advertiser */
    const uint16_t cmd_length = 2 + 1 * 4;
    uint8_t param[cmd_length];
    memset(param, 0, cmd_length);

    uint8_t* pp = param;
    UINT8_TO_STREAM(pp, 0x01);  // enable
    UINT8_TO_STREAM(pp, 0x01);  // just one set

    UINT8_TO_STREAM(pp, inst_id);  // set_id
    UINT16_TO_STREAM(pp, 0x0000);  // duration
    UINT8_TO_STREAM(pp, 0x00);     // max extended advertising events

    SendAdvCmd(HCI_LE_SET_EXT_ADVERTISING_ENABLE, param, cmd_length,
               command_complete);
  }
};

}  // namespace

void BleAdvertiserHciInterface::Initialize() {
  VLOG(1) << __func__;
  LOG_ASSERT(instance == nullptr) << "Was already initialized.";
  pending_ops = new std::queue<std::pair<uint8_t, status_cb>>();
  legacy_pending_ops = new std::queue<std::pair<uint16_t, status_cb>>();

  if (controller_get_interface()->supports_ble_extended_advertising()) {
    instance = new BleAdvertiserHciExtendedImpl();
  } else if (BTM_BleMaxMultiAdvInstanceCount()) {
    instance = new BleAdvertiserVscHciInterfaceImpl();
    BTM_RegisterForVSEvents(
        BleAdvertiserVscHciInterfaceImpl::VendorSpecificEventCback, true);
  } else {
    instance = new BleAdvertiserLegacyHciInterfaceImpl();
  }
}

BleAdvertiserHciInterface* BleAdvertiserHciInterface::Get() { return instance; }

void BleAdvertiserHciInterface::CleanUp() {
  VLOG(1) << __func__;

  if (BTM_BleMaxMultiAdvInstanceCount()) {
    BTM_RegisterForVSEvents(
        BleAdvertiserVscHciInterfaceImpl::VendorSpecificEventCback, false);
  }

  delete pending_ops;
  pending_ops = nullptr;
  delete legacy_pending_ops;
  legacy_pending_ops = nullptr;
  delete instance;
  instance = nullptr;
}
