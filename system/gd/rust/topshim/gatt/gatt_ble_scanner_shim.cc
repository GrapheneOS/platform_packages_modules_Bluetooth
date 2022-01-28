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

#include "gd/rust/topshim/gatt/gatt_ble_scanner_shim.h"

#include <algorithm>
#include <iterator>
#include <vector>

#include "gd/rust/topshim/common/utils.h"
#include "rust/cxx.h"
#include "src/profiles/gatt.rs.h"
#include "types/raw_address.h"

namespace bluetooth {
namespace topshim {
namespace rust {

namespace rusty = ::bluetooth::topshim::rust;

void BleScannerIntf::RegisterCallbacks() {
  // Register self as a callback handler. We will dispatch to Rust callbacks.
  scanner_intf_->RegisterCallbacks(this);
}

// ScanningCallbacks overrides
void BleScannerIntf::OnScannerRegistered(const bluetooth::Uuid app_uuid, uint8_t scannerId, uint8_t status) {
  rusty::gdscan_on_scanner_registered(reinterpret_cast<const signed char*>(&app_uuid), scannerId, status);
}

void BleScannerIntf::OnSetScannerParameterComplete(uint8_t scannerId, uint8_t status) {
  rusty::gdscan_on_set_scanner_parameter_complete(scannerId, status);
}

void BleScannerIntf::OnScanResult(
    uint16_t event_type,
    uint8_t addr_type,
    RawAddress bda,
    uint8_t primary_phy,
    uint8_t secondary_phy,
    uint8_t advertising_sid,
    int8_t tx_power,
    int8_t rssi,
    uint16_t periodic_adv_int,
    std::vector<uint8_t> adv_data) {
  RustRawAddress raw_address = rusty::CopyToRustAddress(bda);
  rusty::gdscan_on_scan_result(
      event_type,
      addr_type,
      reinterpret_cast<const signed char*>(&raw_address),
      primary_phy,
      secondary_phy,
      advertising_sid,
      tx_power,
      rssi,
      periodic_adv_int,
      adv_data.data(),
      adv_data.size());
}

void BleScannerIntf::OnTrackAdvFoundLost(AdvertisingTrackInfo ati) {
  rusty::RustRawAddress addr = rusty::CopyToRustAddress(ati.advertiser_address);
  rusty::RustAdvertisingTrackInfo rust_info = {
      .scanner_id = ati.scanner_id,
      .filter_index = ati.filter_index,
      .advertiser_state = ati.advertiser_state,
      .advertiser_info_present = ati.advertiser_info_present,
      .advertiser_address = addr,
      .advertiser_address_type = ati.advertiser_address_type,
      .tx_power = ati.tx_power,
      .rssi = ati.rssi,
      .timestamp = ati.time_stamp,
      .adv_packet_len = ati.adv_packet_len,
      // .adv_packet is copied below
      .scan_response_len = ati.scan_response_len,
      // .scan_response is copied below
  };

  std::copy(ati.adv_packet.begin(), ati.adv_packet.end(), std::back_inserter(rust_info.adv_packet));
  std::copy(ati.scan_response.begin(), ati.scan_response.end(), std::back_inserter(rust_info.scan_response));

  rusty::gdscan_on_track_adv_found_lost(rust_info);
}

void BleScannerIntf::OnBatchScanReports(
    int client_if, int status, int report_format, int num_records, std::vector<uint8_t> data) {
  rusty::gdscan_on_batch_scan_reports(client_if, status, report_format, num_records, data.data(), data.size());
}

void BleScannerIntf::OnBatchScanThresholdCrossed(int client_if) {
  rusty::gdscan_on_batch_scan_threshold_crossed(client_if);
}

std::unique_ptr<BleScannerIntf> GetBleScannerIntf(const unsigned char* gatt_intf) {
  return std::make_unique<BleScannerIntf>(reinterpret_cast<const btgatt_interface_t*>(gatt_intf)->scanner);
}

}  // namespace rust
}  // namespace topshim
}  // namespace bluetooth
