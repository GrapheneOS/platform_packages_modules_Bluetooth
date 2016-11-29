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

#ifndef BLE_ADVERTISER_HCI_INTERFACE_H
#define BLE_ADVERTISER_HCI_INTERFACE_H

#include <base/bind.h>
#include "stack/include/bt_types.h"

/* This class is an abstraction of HCI commands used for managing
 * advertisements. Please see VSC HCI SPEC at
 * https://static.googleusercontent.com/media/source.android.com/en//devices/Android-6.0-Bluetooth-HCI-Reqs.pdf
 * for more details  */
class BleAdvertiserHciInterface {
 public:
  using status_cb = base::Callback<void(uint8_t /* status */)>;

  static void Initialize();
  static BleAdvertiserHciInterface* Get();
  static void CleanUp();

  virtual ~BleAdvertiserHciInterface() = default;

  class AdvertisingEventObserver {
   public:
    virtual ~AdvertisingEventObserver() = default;
    virtual void OnAdvertisingStateChanged(uint8_t inst_id,
                                           uint8_t state_change_reason,
                                           uint16_t connection_handle) = 0;
  };

  virtual void SetAdvertisingEventObserver(
      AdvertisingEventObserver* observer) = 0;
  virtual void ReadInstanceCount(
      base::Callback<void(uint8_t /* inst_cnt*/)> cb) = 0;
  virtual void SetParameters(uint8_t adv_int_min, uint8_t adv_int_max,
                             uint8_t advertising_type, uint8_t own_address_type,
                             BD_ADDR own_address, uint8_t direct_address_type,
                             BD_ADDR direct_address, uint8_t channel_map,
                             uint8_t filter_policy, uint8_t inst_id,
                             uint8_t tx_power, status_cb command_complete) = 0;
  virtual void SetAdvertisingData(uint8_t data_length, uint8_t* data,
                                  uint8_t inst_id,
                                  status_cb command_complete) = 0;
  virtual void SetScanResponseData(uint8_t scan_response_data_length,
                                   uint8_t* scan_response_data, uint8_t inst_id,
                                   status_cb command_complete) = 0;
  virtual void SetRandomAddress(BD_ADDR random_address, uint8_t inst_id,
                                status_cb command_complete) = 0;
  virtual void Enable(uint8_t advertising_enable, uint8_t inst_id,
                      status_cb command_complete) = 0;
};

#endif  // BLE_ADVERTISER_HCI_INTERFACE_H
