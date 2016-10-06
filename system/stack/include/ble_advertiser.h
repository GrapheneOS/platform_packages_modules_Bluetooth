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

#ifndef BLE_ADVERTISER_H
#define BLE_ADVERTISER_H

#include <base/bind.h>
#include <vector>
#include "btm_ble_api.h"

#define BTM_BLE_MULTI_ADV_DEFAULT_STD 0

#define BTM_BLE_MULTI_ADV_SUCCESS 0
#define BTM_BLE_MULTI_ADV_FAILURE 1

using MultiAdvCb = base::Callback<void(uint8_t /* status */)>;

extern "C" {
// methods we must have defined
tBTM_STATUS btm_ble_set_connectability(uint16_t combined_mode);
void btm_ble_update_dmt_flag_bits(uint8_t *flag_value,
                                  const uint16_t connect_mode,
                                  const uint16_t disc_mode);
void btm_gen_resolvable_private_addr(void *p_cmd_cplt_cback);
void btm_acl_update_conn_addr(uint8_t conn_handle, BD_ADDR address);

// methods we expose to c code:
void btm_ble_multi_adv_cleanup(void);
void btm_ble_multi_adv_init();
}

typedef struct {
  uint16_t adv_int_min;
  uint16_t adv_int_max;
  uint8_t adv_type;
  tBTM_BLE_ADV_CHNL_MAP channel_map;
  tBTM_BLE_AFP adv_filter_policy;
  tBTM_BLE_ADV_TX_POWER tx_power;
} tBTM_BLE_ADV_PARAMS;

class BleAdvertiserHciInterface;

class BleAdvertisingManager {
 public:
  virtual ~BleAdvertisingManager() = default;

  static void Initialize();
  static void CleanUp();
  static BleAdvertisingManager *Get();

  /* Register an advertising instance, status will be returned in |cb|
  * callback, with assigned id, if operation succeeds. Instance is freed when
  * advertising is disabled by calling |BTM_BleDisableAdvInstance|, or when any
  * of the operations fails. */
  virtual void RegisterAdvertiser(
      base::Callback<void(uint8_t /* inst_id */, uint8_t /* status */)>);

  /* This function enables/disables an advertising instance. Operation status is
   * returned in |cb| */
  virtual void Enable(uint8_t inst_id, bool enable, MultiAdvCb cb, int timeout_s,
                    MultiAdvCb timeout_cb);

  /* This function update a Multi-ADV instance with the specififed adv
   * parameters. */
  virtual void SetParameters(uint8_t inst_id, tBTM_BLE_ADV_PARAMS *p_params,
                             MultiAdvCb cb);

  /* This function configure a Multi-ADV instance with the specified adv data or
   * scan response data.*/
  virtual void SetData(uint8_t inst_id, bool is_scan_rsp,
                       std::vector<uint8_t> data, MultiAdvCb cb);

  /*  This function disable a Multi-ADV instance */
  virtual void Unregister(uint8_t inst_id);

  /* This is exposed for tests, and for initial configuration. Higher layers
   * shouldn't have need to ever call it.*/
  virtual void SetHciInterface(BleAdvertiserHciInterface *interface);
};

#endif  // BLE_ADVERTISER_H
