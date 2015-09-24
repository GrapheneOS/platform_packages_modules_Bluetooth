//
//  Copyright (C) 2015 Google, Inc.
//
//  Licensed under the Apache License, Version 2.0 (the "License");
//  you may not use this file except in compliance with the License.
//  You may obtain a copy of the License at:
//
//  http://www.apache.org/licenses/LICENSE-2.0
//
//  Unless required by applicable law or agreed to in writing, software
//  distributed under the License is distributed on an "AS IS" BASIS,
//  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//  See the License for the specific language governing permissions and
//  limitations under the License.
//

#pragma once

namespace bluetooth {

// Defined here are various status codes that can be returned from the stack for
// BLE operations.
enum BLEStatus {
  BLE_STATUS_SUCCESS = 0,
  BLE_STATUS_ADV_ERROR_DATA_TOO_LARGE = 1,
  BLE_STATUS_ADV_ERROR_TOO_MANY_ADVERTISERS = 2,
  BLE_STATUS_ADV_ERROR_ALREADY_STARTED = 3,
  BLE_STATUS_ADV_ERROR_FEATURE_UNSUPPORTED = 5,
  BLE_STATUS_FAILURE = 0x101,

  // TODO(armansito): Add ATT protocol error codes
};

enum Transport {
  TRANSPORT_AUTO = 0,
  TRANSPORT_BREDR = 1,
  TRANSPORT_LE = 2
};

// Advertising interval for different modes.
const int kAdvertisingIntervalHighMs = 1000;
const int kAdvertisingIntervalMediumMs = 250;
const int kAdvertisingIntervalLowMs = 100;

// Add some randomness to the advertising min/max interval so the controller can
// do some optimization.
// TODO(armansito): I took this directly from packages/apps/Bluetooth but based
// on code review comments this constant and the accompanying logic doesn't make
// sense. Let's remove this constant and figure out how to properly calculate
// the Max. Adv. Interval. (See http://b/24344075).
const int kAdvertisingIntervalDeltaUnit = 10;

// Advertising types (ADV_IND, ADV_SCAN_IND, etc.) that are exposed to
// applications.
const int kAdvertisingEventTypeConnectable = 0;
const int kAdvertisingEventTypeScannable = 2;
const int kAdvertisingEventTypeNonConnectable = 3;

// Advertising channels. These should be kept the same as those defined in the
// stack.
const int kAdvertisingChannel37 = (1 << 0);
const int kAdvertisingChannel38 = (1 << 1);
const int kAdvertisingChannel39 = (1 << 2);
const int kAdvertisingChannelAll =
    (kAdvertisingChannel37 | kAdvertisingChannel38 | kAdvertisingChannel39);

// Various Extended Inquiry Response fields types that are used for advertising
// data fields as defined in the Core Specification Supplement.
const uint8_t kEIRTypeFlags = 0x01;
const uint8_t kEIRTypeIncomplete16BitUUIDs = 0x02;
const uint8_t kEIRTypeComplete16BitUUIDs = 0x03;
const uint8_t kEIRTypeIncomplete32BitUUIDs = 0x04;
const uint8_t kEIRTypeComplete32BitUUIDs = 0x05;
const uint8_t kEIRTypeIncomplete128BitUUIDs = 0x06;
const uint8_t kEIRTypeComplete128BitUUIDs = 0x07;
const uint8_t kEIRTypeManufacturerSpecificData = 0xFF;

}  // namespace bluetooth
