/******************************************************************************
 *
 *  Copyright (C) 2014  Broadcom Corporation
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

#include <base/bind.h>
#include <base/logging.h>
#include <base/strings/string_number_conversions.h>
#include <string.h>
#include <queue>
#include <vector>

#include "bt_target.h"
#include "device/include/controller.h"
#include "osi/include/alarm.h"

#if (BLE_INCLUDED == TRUE)
#include "ble_advertiser.h"
#include "ble_advertiser_hci_interface.h"
#include "btm_int_types.h"

using base::Bind;
using multiadv_cb = base::Callback<void(uint8_t /* status */)>;

struct AdvertisingInstance {
  uint8_t inst_id;
  bool in_use;
  uint8_t adv_evt;
  BD_ADDR rpa;
  alarm_t *adv_raddr_timer;
  AdvertisingInstance(int inst_id)
      : inst_id(inst_id), in_use(false), adv_evt(0), rpa{0} {
    adv_raddr_timer = alarm_new_periodic("btm_ble.adv_raddr_timer");
  }

  ~AdvertisingInstance() { alarm_free(adv_raddr_timer); }
};

/************************************************************************************
**  Externs
************************************************************************************/
extern fixed_queue_t *btu_general_alarm_queue;

void DoNothing(uint8_t) {}

/* return the actual power in dBm based on the mapping in config file */
int btm_ble_tx_power[BTM_BLE_ADV_TX_POWER_MAX + 1] = BTM_BLE_ADV_TX_POWER;
char btm_ble_map_adv_tx_power(int tx_power_index) {
  if (0 <= tx_power_index && tx_power_index < BTM_BLE_ADV_TX_POWER_MAX)
    return (char)btm_ble_tx_power[tx_power_index];
  return 0;
}

std::queue<base::Callback<void(tBTM_RAND_ENC *p)>> *rand_gen_inst_id = nullptr;

/* RPA generation completion callback for each adv instance. Will continue write
 * the new RPA into controller. */
void btm_ble_multi_adv_gen_rpa_cmpl(tBTM_RAND_ENC *p) {
  /* Retrieve the index of adv instance from stored Q */
  base::Callback<void(tBTM_RAND_ENC * p)> cb = rand_gen_inst_id->front();
  rand_gen_inst_id->pop();
  cb.Run(p);
}

void btm_ble_adv_raddr_timer_timeout(void *data);

class BleAdvertisingManagerImpl
    : public BleAdvertisingManager,
      public BleAdvertiserHciInterface::AdvertisingEventObserver {
 public:
  BleAdvertisingManagerImpl() {
    adv_inst.reserve(BTM_BleMaxMultiAdvInstanceCount());
    /* Initialize adv instance indices and IDs. */
    for (uint8_t i = 0; i < BTM_BleMaxMultiAdvInstanceCount(); i++) {
      adv_inst.emplace_back(i + 1);
    }
  }

  ~BleAdvertisingManagerImpl() { adv_inst.clear(); }

  void OnRpaGenerationComplete(uint8_t inst_id, tBTM_RAND_ENC *p) {
#if (SMP_INCLUDED == TRUE)
    AdvertisingInstance *p_inst = &adv_inst[inst_id - 1];

    LOG(INFO) << "inst_id = " << +p_inst->inst_id;

    if (!p) return;

    p->param_buf[2] &= (~BLE_RESOLVE_ADDR_MASK);
    p->param_buf[2] |= BLE_RESOLVE_ADDR_MSB;

    p_inst->rpa[2] = p->param_buf[0];
    p_inst->rpa[1] = p->param_buf[1];
    p_inst->rpa[0] = p->param_buf[2];

    BT_OCTET16 irk;
    BTM_GetDeviceIDRoot(irk);
    tSMP_ENC output;

    if (!SMP_Encrypt(irk, BT_OCTET16_LEN, p->param_buf, 3, &output))
      LOG_ASSERT(false) << "SMP_Encrypt failed";

    /* set hash to be LSB of rpAddress */
    p_inst->rpa[5] = output.param_buf[0];
    p_inst->rpa[4] = output.param_buf[1];
    p_inst->rpa[3] = output.param_buf[2];

    if (p_inst->inst_id != BTM_BLE_MULTI_ADV_DEFAULT_STD &&
        p_inst->inst_id < BTM_BleMaxMultiAdvInstanceCount()) {
      /* set it to controller */
      GetHciInterface()->SetRandomAddress(p_inst->rpa, p_inst->inst_id,
                                          Bind(DoNothing));
    }
#endif
  }

  void ConfigureRpa(uint8_t inst_id) {
    if (rand_gen_inst_id == nullptr)
      rand_gen_inst_id =
          new std::queue<base::Callback<void(tBTM_RAND_ENC * p)>>();

    rand_gen_inst_id->push(
        Bind(&BleAdvertisingManagerImpl::OnRpaGenerationComplete,
             base::Unretained(this), inst_id));
    btm_gen_resolvable_private_addr((void *)btm_ble_multi_adv_gen_rpa_cmpl);
  }

  void RegisterAdvertiser(
      base::Callback<void(uint8_t /* inst_id */, uint8_t /* status */)> cb)
      override {
    if (BTM_BleMaxMultiAdvInstanceCount() == 0) {
      LOG(ERROR) << "multi adv not supported";
      cb.Run(0xFF, BTM_BLE_MULTI_ADV_FAILURE);
      return;
    }

    AdvertisingInstance *p_inst = &adv_inst[0];
    for (uint8_t i = 0; i < BTM_BleMaxMultiAdvInstanceCount() - 1;
         i++, p_inst++) {
      if (!p_inst->in_use) {
        p_inst->in_use = TRUE;

#if (BLE_PRIVACY_SPT == TRUE)
        // configure the address, and set up periodic timer to update it.
        ConfigureRpa(p_inst->inst_id);

        if (BTM_BleLocalPrivacyEnabled()) {
          alarm_set_on_queue(
              p_inst->adv_raddr_timer, BTM_BLE_PRIVATE_ADDR_INT_MS,
              btm_ble_adv_raddr_timer_timeout, p_inst, btu_general_alarm_queue);
        }
#endif

        cb.Run(p_inst->inst_id, BTM_BLE_MULTI_ADV_SUCCESS);
        return;
      }
    }

    LOG(INFO) << "no free advertiser instance";
    cb.Run(0xFF, BTM_BLE_MULTI_ADV_FAILURE);
  }

  void Enable(uint8_t inst_id, bool enable, MultiAdvCb cb) {
    VLOG(1) << __func__ << " inst_id: " << +inst_id << ", enable: " << enable;

    if (BTM_BleMaxMultiAdvInstanceCount() == 0) {
      LOG(ERROR) << "multi adv not supported";
      return;
    }

    AdvertisingInstance *p_inst = &adv_inst[inst_id - 1];
    if (!p_inst || !p_inst->in_use) {
      LOG(ERROR) << "Invalid or no active instance";
      cb.Run(BTM_BLE_MULTI_ADV_FAILURE);
      return;
    }

    GetHciInterface()->Enable(enable, p_inst->inst_id, cb);
  }

  void SetParameters(uint8_t inst_id, tBTM_BLE_ADV_PARAMS *p_params,
                     MultiAdvCb cb) override {
    AdvertisingInstance *p_inst = &adv_inst[inst_id - 1];

    VLOG(1) << __func__ << " inst_id:" << +inst_id;

    if (BTM_BleMaxMultiAdvInstanceCount() == 0) {
      LOG(ERROR) << "multi adv not supported";
      return;
    }

    if (inst_id > BTM_BleMaxMultiAdvInstanceCount() || inst_id < 0 ||
        inst_id == BTM_BLE_MULTI_ADV_DEFAULT_STD) {
      LOG(ERROR) << "bad instance id " << +inst_id;
      return;
    }

    if (!p_inst->in_use) {
      LOG(ERROR) << "adv instance not in use" << +inst_id;
      cb.Run(BTM_BLE_MULTI_ADV_FAILURE);
      return;
    }

    // TODO: disable only if was enabled, currently no use scenario needs that,
    // we always set parameters before enabling
    // GetHciInterface()->Enable(false, inst_id, Bind(DoNothing));

    uint8_t own_address_type = BLE_ADDR_PUBLIC;
    BD_ADDR own_address;

#if (BLE_PRIVACY_SPT == TRUE)
    if (BTM_BleLocalPrivacyEnabled()) {
      own_address_type = BLE_ADDR_RANDOM;
      memcpy(own_address, p_inst->rpa, BD_ADDR_LEN);
    } else {
#else
    {
#endif
      memcpy(own_address, controller_get_interface()->get_address()->address,
             BD_ADDR_LEN);
      p_inst->adv_evt = p_params->adv_type;
    }

    BD_ADDR dummy = {0, 0, 0, 0, 0, 0};
    GetHciInterface()->SetParameters(
        p_params->adv_int_min, p_params->adv_int_max, p_params->adv_type,
        own_address_type, own_address, 0, dummy, p_params->channel_map,
        p_params->adv_filter_policy, p_inst->inst_id,
        btm_ble_map_adv_tx_power(p_params->tx_power), cb);

    // TODO: re-enable only if it was enabled, properly call
    // SetParamsCallback
    // currently no use scenario needs that
    // GetHciInterface()->Enable(true, inst_id, BTM_BleUpdateAdvInstParamCb);
  }

  void SetData(uint8_t inst_id, bool is_scan_rsp, tBTM_BLE_AD_MASK data_mask,
               tBTM_BLE_ADV_DATA *p_data, MultiAdvCb cb) override {
    VLOG(1) << "inst_id = " << +inst_id << ", is_scan_rsp = " << is_scan_rsp;

    if (BTM_BleMaxMultiAdvInstanceCount() == 0) {
      LOG(ERROR) << "multi adv not supported";
      return;
    }

    btm_ble_update_dmt_flag_bits(&p_data->flag,
                                 BTM_ReadConnectability(nullptr, nullptr),
                                 BTM_ReadDiscoverability(nullptr, nullptr));

    if (inst_id > BTM_BleMaxMultiAdvInstanceCount() || inst_id < 0 ||
        inst_id == BTM_BLE_MULTI_ADV_DEFAULT_STD) {
      LOG(ERROR) << "bad instance id " << +inst_id;
      return;
    }

    uint8_t data[BTM_BLE_AD_DATA_LEN], *pp = data;
    memset(data, 0, BTM_BLE_AD_DATA_LEN);

    btm_ble_build_adv_data(&data_mask, &pp, p_data);
    uint8_t len = (uint8_t)(pp - data);

    VLOG(1) << "data is: " << base::HexEncode(data, len);

    if (is_scan_rsp) {
      GetHciInterface()->SetScanResponseData(len, data, inst_id, cb);
    } else {
      GetHciInterface()->SetAdvertisingData(len, data, inst_id, cb);
    }
  }

  void Unregister(uint8_t inst_id) override {
    AdvertisingInstance *p_inst = &adv_inst[inst_id - 1];

    VLOG(1) << __func__ << " inst_id: " << +inst_id;

    if (BTM_BleMaxMultiAdvInstanceCount() == 0) {
      LOG(ERROR) << "multi adv not supported";
      return;
    }

    if (inst_id > BTM_BleMaxMultiAdvInstanceCount() || inst_id < 0 ||
        inst_id == BTM_BLE_MULTI_ADV_DEFAULT_STD) {
      LOG(ERROR) << "bad instance id " << +inst_id;
      return;
    }

    // TODO(jpawlowski): only disable when enabled or enabling
    GetHciInterface()->Enable(false, inst_id, Bind(DoNothing));

    alarm_cancel(p_inst->adv_raddr_timer);
    p_inst->in_use = false;
  }

  void OnAdvertisingStateChanged(uint8_t inst_id, uint8_t reason,
                                 uint16_t conn_handle) override {
    AdvertisingInstance *p_inst = &adv_inst[inst_id - 1];
    VLOG(1) << __func__ << " inst_id: 0x" << std::hex << inst_id
            << ", reason: 0x" << std::hex << reason << ", conn_handle: 0x"
            << std::hex << conn_handle;

#if (BLE_PRIVACY_SPT == TRUE)
    if (BTM_BleLocalPrivacyEnabled() && inst_id <= BTM_BLE_MULTI_ADV_MAX &&
        inst_id != BTM_BLE_MULTI_ADV_DEFAULT_STD) {
      btm_acl_update_conn_addr(conn_handle, p_inst->rpa);
    }
#endif

    if (inst_id < BTM_BleMaxMultiAdvInstanceCount() &&
        inst_id != BTM_BLE_MULTI_ADV_DEFAULT_STD) {
      VLOG(1) << "reneabling advertising";

      if (p_inst->in_use == true) {
        // TODO(jpawlowski): we don't really allow to do directed advertising
        // right now. This should probably be removed, check with Andre.
        if (p_inst->adv_evt != BTM_BLE_CONNECT_DIR_EVT) {
          GetHciInterface()->Enable(true, inst_id, Bind(DoNothing));
        } else {
          /* mark directed adv as disabled if adv has been stopped */
          p_inst->in_use = false;
        }
      }
    } else if (inst_id == BTM_BLE_MULTI_ADV_DEFAULT_STD) {
      /* re-enable connectibility */
      uint16_t conn_mode = BTM_ReadConnectability(nullptr, nullptr);
      if (conn_mode == BTM_BLE_CONNECTABLE) {
        btm_ble_set_connectability(conn_mode);
      }
    }
  }

  void SetHciInterface(BleAdvertiserHciInterface *interface) {
    hci_interface = interface;
  };

 private:
  BleAdvertiserHciInterface *GetHciInterface() { return hci_interface; }

  BleAdvertiserHciInterface *hci_interface = nullptr;
  std::vector<AdvertisingInstance> adv_inst;
};

namespace {
BleAdvertisingManager *instance;
}

void BleAdvertisingManager::Initialize() {
  instance = new BleAdvertisingManagerImpl();
}

BleAdvertisingManager *BleAdvertisingManager::Get() {
  CHECK(instance);
  return instance;
};

void BleAdvertisingManager::CleanUp() {
  delete instance;
  instance = nullptr;
};

void btm_ble_adv_raddr_timer_timeout(void *data) {
  ((BleAdvertisingManagerImpl *)BleAdvertisingManager::Get())
      ->ConfigureRpa(((AdvertisingInstance *)data)->inst_id);
}

/*******************************************************************************
**
** Function         btm_ble_multi_adv_init
**
** Description      This function initialize the multi adv control block.
**
** Parameters       None
**
** Returns          void
**
*******************************************************************************/
void btm_ble_multi_adv_init() {
  BleAdvertisingManager::Initialize();
  BleAdvertiserHciInterface::Initialize();
  BleAdvertisingManager::Get()->SetHciInterface(
      BleAdvertiserHciInterface::Get());
}

/*******************************************************************************
**
** Function         btm_ble_multi_adv_cleanup
**
** Description      This function cleans up multi adv control block.
**
** Parameters
** Returns          void
**
*******************************************************************************/
void btm_ble_multi_adv_cleanup(void) {
  BleAdvertisingManager::CleanUp();
  BleAdvertiserHciInterface::CleanUp();
}

#endif
