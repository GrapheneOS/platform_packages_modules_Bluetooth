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

#pragma once

#include <hardware/bluetooth.h>
#include <vector>

#include "ble_advertiser.h"

#define CLNT_IF_IDX 0
#define INST_ID_IDX 1
#define INST_ID_IDX_MAX (INST_ID_IDX + 1)
#define INVALID_ADV_INST (-1)
#define STD_ADV_INSTID 0

/* Default ADV flags for general and limited discoverability */
#define ADV_FLAGS_LIMITED BTA_DM_LIMITED_DISC
#define ADV_FLAGS_GENERAL BTA_DM_GENERAL_DISC

typedef struct
{
    int advertiser_id;
    bool set_scan_rsp;
    bool include_name;
    bool include_txpower;
    int min_interval;
    int max_interval;
    int appearance;
    uint16_t manufacturer_len;
    uint8_t p_manufacturer_data[MAX_SIZE_MANUFACTURER_DATA];
    uint16_t service_data_len;
    uint8_t p_service_data[MAX_SIZE_SERVICE_DATA];
    uint16_t service_uuid_len;
    uint8_t p_service_uuid[MAX_SIZE_SERVICE_DATA];
} btif_adv_data_t;


typedef struct
{
    uint8_t advertiser_id;
    tBTA_BLE_AD_MASK mask;
    tBTA_BLE_ADV_DATA data;
    tBTM_BLE_ADV_PARAMS param;
    alarm_t *multi_adv_timer;
    int timeout_s;
} btgatt_multi_adv_inst_cb;

typedef struct
{
    // Includes the stored data for standard LE instance
    btgatt_multi_adv_inst_cb *inst_cb;

} btgatt_multi_adv_common_data;

extern btgatt_multi_adv_common_data *btif_obtain_multi_adv_data_cb();

extern void btif_gattc_incr_app_count(void);
extern void btif_gattc_decr_app_count(void);
extern void btif_gattc_clear_clientif(int advertiser_id, bool stop_timer);
extern void btif_gattc_cleanup_inst_cb(int inst_id, bool stop_timer);
extern void btif_gattc_cleanup_multi_inst_cb(btgatt_multi_adv_inst_cb *p_inst_cb,
                                                    bool stop_timer);
extern bool btif_gattc_copy_datacb(int arrindex, const btif_adv_data_t *p_adv_data,
                                            bool bInstData);
extern void btif_gattc_adv_data_packager(int advertiser_id, bool set_scan_rsp,
                bool include_name, bool include_txpower, int min_interval, int max_interval,
                int appearance, const std::vector<uint8_t> &manufacturer_data,
                const std::vector<uint8_t> &service_data, const std::vector<uint8_t> &service_uuid,
                btif_adv_data_t *p_multi_adv_inst);
extern void btif_gattc_adv_data_cleanup(btif_adv_data_t* adv);
void btif_multi_adv_timer_ctrl(int advertiser_id, alarm_callback_t cb);
