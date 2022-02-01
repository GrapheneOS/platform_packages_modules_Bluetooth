/*
 * Copyright (C) 2022 The Android Open Source Project
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
#ifndef GD_RUST_TOPSHIM_GATT_GATT_BLE_SCANNER_SHIM_H
#define GD_RUST_TOPSHIM_GATT_GATT_BLE_SCANNER_SHIM_H

#include <memory>

#include "include/hardware/ble_scanner.h"
#include "include/hardware/bt_gatt.h"
#include "rust/cxx.h"

namespace bluetooth {
namespace topshim {
namespace rust {

class BleScannerIntf : public ScanningCallbacks {
 public:
  BleScannerIntf(BleScannerInterface* scanner_intf) : scanner_intf_(scanner_intf){};
  ~BleScannerIntf() = default;

  void RegisterCallbacks();

  // ScanningCallbacks overrides
  void OnScannerRegistered(const bluetooth::Uuid app_uuid, uint8_t scannerId, uint8_t status) override;

  void OnSetScannerParameterComplete(uint8_t scannerId, uint8_t status) override;

  void OnScanResult(
      uint16_t event_type,
      uint8_t addr_type,
      RawAddress bda,
      uint8_t primary_phy,
      uint8_t secondary_phy,
      uint8_t advertising_sid,
      int8_t tx_power,
      int8_t rssi,
      uint16_t periodic_adv_int,
      std::vector<uint8_t> adv_data) override;

  void OnTrackAdvFoundLost(AdvertisingTrackInfo advertising_track_info) override;

  void OnBatchScanReports(
      int client_if, int status, int report_format, int num_records, std::vector<uint8_t> data) override;

  void OnBatchScanThresholdCrossed(int client_if) override;

 private:
  BleScannerInterface* scanner_intf_;
};

std::unique_ptr<BleScannerIntf> GetBleScannerIntf(const unsigned char* gatt_intf);

}  // namespace rust
}  // namespace topshim
}  // namespace bluetooth

#endif  // GD_RUST_TOPSHIM_GATT_GATT_BLE_SCANNER_SHIM_H
