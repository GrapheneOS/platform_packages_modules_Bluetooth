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

#include "gd/rust/topshim/metrics/metrics_shim.h"

#include "gd/metrics/metrics.h"
#include "gd/rust/topshim/common/utils.h"
#include "src/metrics.rs.h"
#include "types/raw_address.h"

namespace rusty = ::bluetooth::topshim::rust;

namespace bluetooth {
namespace topshim {
namespace rust {

void adapter_state_changed(uint32_t state) {
  metrics::LogMetricsAdapterStateChanged(state);
}

void bond_create_attempt(RustRawAddress bt_addr, uint32_t device_type) {
  RawAddress addr = rusty::CopyFromRustAddress(bt_addr);

  metrics::LogMetricsBondCreateAttempt(&addr, device_type);
}

void bond_state_changed(
    RustRawAddress bt_addr, uint32_t device_type, uint32_t status, uint32_t bond_state, int32_t fail_reason) {
  RawAddress addr = rusty::CopyFromRustAddress(bt_addr);

  metrics::LogMetricsBondStateChanged(&addr, device_type, status, bond_state, fail_reason);
}

void device_info_report(
    RustRawAddress bt_addr,
    uint32_t device_type,
    uint32_t class_of_device,
    uint32_t appearance,
    uint32_t vendor_id,
    uint32_t vendor_id_src,
    uint32_t product_id,
    uint32_t version) {
  RawAddress addr = rusty::CopyFromRustAddress(bt_addr);

  metrics::LogMetricsDeviceInfoReport(
      &addr, device_type, class_of_device, appearance, vendor_id, vendor_id_src, product_id, version);
}

void profile_connection_attempt(RustRawAddress bt_addr, uint32_t intent, uint32_t profile) {
  RawAddress addr = rusty::CopyFromRustAddress(bt_addr);

  metrics::LogMetricsProfileConnectionAttempt(&addr, intent, profile);
}

void profile_connection_state_changed(
    RustRawAddress bt_addr, uint32_t intent, uint32_t profile, uint32_t status, uint32_t state) {
  RawAddress addr = rusty::CopyFromRustAddress(bt_addr);

  metrics::LogMetricsProfileConnectionStateChanged(&addr, intent, profile, status, state);
}

}  // namespace rust
}  // namespace topshim
}  // namespace bluetooth
