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

#include "btm_ble_api.h"

#define BTM_BLE_MULTI_ADV_ENB_EVT           1
#define BTM_BLE_MULTI_ADV_DISABLE_EVT       2
#define BTM_BLE_MULTI_ADV_PARAM_EVT         3
#define BTM_BLE_MULTI_ADV_DATA_EVT          4
#define BTM_BLE_MULTI_ADV_REG_EVT           5
typedef uint8_t tBTM_BLE_MULTI_ADV_EVT;

#define BTM_BLE_MULTI_ADV_DEFAULT_STD 0

#define BTM_BLE_MULTI_ADV_SUCCESS           0
#define BTM_BLE_MULTI_ADV_FAILURE           1

typedef struct
{
    uint16_t        adv_int_min;
    uint16_t        adv_int_max;
    uint8_t         adv_type;
    tBTM_BLE_ADV_CHNL_MAP channel_map;
    tBTM_BLE_AFP    adv_filter_policy;
    tBTM_BLE_ADV_TX_POWER tx_power;
}tBTM_BLE_ADV_PARAMS;

typedef void (tBTM_BLE_MULTI_ADV_CBACK)(tBTM_BLE_MULTI_ADV_EVT evt, uint8_t inst_id,
                tBTM_STATUS status);

/*******************************************************************************
**
** Register an advertising instance, status will be returned in |p_cback|
** callback, with assigned id, if operation succeeds. Instance is freed when
** advertising is disabled by calling |BTM_BleDisableAdvInstance|, or when any
** of the operations fails.
*******************************************************************************/
extern void  BTM_BleAdvRegister(tBTM_BLE_MULTI_ADV_CBACK *p_cback);

/*******************************************************************************
**
** Function         BTM_BleAdvEnable
**
** Description      This function enable a Multi-ADV instance
**
** Parameters       inst_id: adv instance ID
** Parameters       enable: true to enable, false to disable
**
** Returns          void
**
*******************************************************************************/
extern void BTM_BleAdvEnable(uint8_t inst_id, bool enable);

/*******************************************************************************
**
** Function         BTM_BleAdvSetParameters
**
** Description      This function update a Multi-ADV instance with the specififed
**                  adv parameters.
**
** Parameters       inst_id: adv instance ID
**                  p_params: pointer to the adv parameter structure.
**
** Returns          void
**
*******************************************************************************/
extern void BTM_BleAdvSetParameters(uint8_t inst_id, tBTM_BLE_ADV_PARAMS *p_params);

/*******************************************************************************
**
** Function         BTM_BleAdvSetData
**
** Description      This function configure a Multi-ADV instance with the specified
**                  adv data or scan response data.
**
** Parameters       inst_id: adv instance ID
**                  is_scan_rsp: is this scacn response, if no set as adv data.
**                  data_mask: adv data mask.
**                  p_data: pointer to the adv data structure.
**
** Returns          void
**
*******************************************************************************/
extern void BTM_BleAdvSetData (uint8_t inst_id, bool is_scan_rsp,
                               tBTM_BLE_AD_MASK data_mask,
                               tBTM_BLE_ADV_DATA *p_data);

/*******************************************************************************
**
** Function         BTM_BleAdvUnregister
**
** Description      This function disable a Multi-ADV instance.
**
** Parameters       inst_id: adv instance ID
**
** Returns          void
**
*******************************************************************************/
extern void BTM_BleAdvUnregister (uint8_t inst_id);

#endif // BLE_ADVERTISER_H
