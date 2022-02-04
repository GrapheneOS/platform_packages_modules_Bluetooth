/*
 * Copyright 2019 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#pragma once

#include <gmock/gmock.h>

#include <memory>

#include "hci/address.h"
#include "hci/le_scanning_manager.h"
#include "hci/uuid.h"

namespace bluetooth {
namespace hci {
namespace testing {

class MockScanningCallback : public ScanningCallback {
  MOCK_METHOD(void, OnScannerRegistered, (const bluetooth::hci::Uuid, ScannerId, ScanningStatus));
  MOCK_METHOD(void, OnSetScannerParameterComplete, (ScannerId scanner_id, ScanningStatus status));
  MOCK_METHOD(
      void,
      OnScanResult,
      (uint16_t, uint8_t, Address, uint8_t, uint8_t, uint8_t, int8_t, int8_t, uint16_t, std::vector<uint8_t>));
  MOCK_METHOD(void, OnTrackAdvFoundLost, (AdvertisingFilterOnFoundOnLostInfo));
  MOCK_METHOD(void, OnBatchScanReports, (int, int, int, int, std::vector<uint8_t>));
  MOCK_METHOD(void, OnBatchScanThresholdCrossed, (int));
  MOCK_METHOD(void, OnTimeout, ());
  MOCK_METHOD(void, OnFilterEnable, (Enable, uint8_t));
  MOCK_METHOD(void, OnFilterParamSetup, (uint8_t, ApcfAction, uint8_t));
  MOCK_METHOD(void, OnFilterConfigCallback, (ApcfFilterType, uint8_t, ApcfAction, uint8_t));
};

class MockLeScanningManager : public LeScanningManager {
 public:
  MOCK_METHOD(void, RegisterScanner, (const Uuid));
  MOCK_METHOD(void, Unregister, (ScannerId));
  MOCK_METHOD(void, Scan, (bool));
  MOCK_METHOD(void, SetScanParameters, (ScannerId, LeScanType, uint16_t, uint16_t));
  MOCK_METHOD(void, ScanFilterEnable, (bool));
  MOCK_METHOD(void, ScanFilterParameterSetup, (ApcfAction, uint8_t, AdvertisingFilterParameter));
  MOCK_METHOD(void, ScanFilterAdd, (uint8_t, std::vector<AdvertisingPacketContentFilterCommand>));
  MOCK_METHOD(void, BatchScanConifgStorage, (uint8_t, uint8_t, uint8_t, ScannerId));
  MOCK_METHOD(void, BatchScanEnable, (BatchScanMode, uint32_t, uint32_t, BatchScanDiscardRule));
  MOCK_METHOD(void, BatchScanDisable, ());
  MOCK_METHOD(void, BatchScanReadReport, (ScannerId, BatchScanMode));
  MOCK_METHOD(void, TrackAdvertiser, (ScannerId));
  MOCK_METHOD(void, RegisterScanningCallback, (ScanningCallback*));
};

}  // namespace testing
}  // namespace hci
}  // namespace bluetooth
