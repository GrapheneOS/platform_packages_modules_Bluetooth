/******************************************************************************
 *
 *  Copyright 2016 Google Inc.
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

#include <base/logging.h>

#include "main/shim/le_advertising_manager.h"

BleAdvertiserInterface* get_ble_advertiser_instance() {
  LOG(INFO) << __func__ << " use gd le advertiser";
  return bluetooth::shim::get_ble_advertiser_instance();
}
