/*
 * Copyright 2022 The Android Open Source Project
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
#define LOG_TAG "BluetoothMetrics"

#include "gd/metrics/metrics.h"

#include <metrics/structured_events.h>

#include "common/time_util.h"
#include "gd/metrics/chromeos/metrics_event.h"
#include "gd/metrics/utils.h"

namespace bluetooth {
namespace metrics {

void LogMetricsAdapterStateChanged(uint32_t state) {
  std::string boot_id;

  if (!GetBootId(&boot_id)) return;

  ::metrics::structured::events::bluetooth::BluetoothAdapterStateChanged()
      .SetBootId(boot_id)
      .SetSystemTime(bluetooth::common::time_get_os_boottime_us())
      .SetIsFloss(true)
      .SetAdapterState((int64_t)ToAdapterState(state))
      .Record();
}

void LogMetricsBondCreateAttempt(RawAddress* addr) {}

void LogMetricsBondStateChanged(
    RawAddress* addr, uint32_t device_type, uint32_t status, uint32_t bond_state, int32_t fail_reason) {}
}  // namespace metrics
}  // namespace bluetooth
