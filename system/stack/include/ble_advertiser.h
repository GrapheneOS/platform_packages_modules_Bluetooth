/******************************************************************************
 *
 *  Copyright 2016 The Android Open Source Project
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

#include <base/functional/bind.h>
#include <base/memory/weak_ptr.h>

#include <cstdint>
#include <vector>

#include "btm_ble_api.h"
#include "types/raw_address.h"

#define BTM_BLE_MULTI_ADV_SUCCESS 0
#define BTM_BLE_MULTI_ADV_FAILURE 1
#define ADVERTISE_FAILED_TOO_MANY_ADVERTISERS 0x02

using MultiAdvCb = base::Callback<void(uint8_t /* status */)>;
using ParametersCb =
    base::Callback<void(uint8_t /* status */, int8_t /* tx_power */)>;

// methods we must have defined
void btm_ble_update_dmt_flag_bits(uint8_t* flag_value,
                                  const uint16_t connect_mode,
                                  const uint16_t disc_mode);

typedef struct {
  uint16_t advertising_event_properties;
  uint32_t adv_int_min;
  uint32_t adv_int_max;
  tBTM_BLE_ADV_CHNL_MAP channel_map;
  tBTM_BLE_AFP adv_filter_policy;
  int8_t tx_power;
  uint8_t primary_advertising_phy;
  uint8_t secondary_advertising_phy;
  uint8_t scan_request_notification_enable;
  uint8_t own_address_type;
} tBTM_BLE_ADV_PARAMS;

typedef struct {
  bool enable;
  bool include_adi;
  uint16_t min_interval;
  uint16_t max_interval;
  uint16_t periodic_advertising_properties;
} tBLE_PERIODIC_ADV_PARAMS;

#endif  // BLE_ADVERTISER_H
