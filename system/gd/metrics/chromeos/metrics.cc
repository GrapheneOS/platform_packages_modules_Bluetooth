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
#include "gd/os/log.h"

namespace bluetooth {
namespace metrics {

void LogMetricsAdapterStateChanged(uint32_t state) {
  int64_t adapter_state;
  int64_t boot_time;
  std::string boot_id;

  if (!GetBootId(&boot_id)) return;

  adapter_state = (int64_t)ToAdapterState(state);
  boot_time = bluetooth::common::time_get_os_boottime_us();

  LOG_DEBUG("AdapterStateChanged: %s, %d, %d", boot_id.c_str(), boot_time, adapter_state);

  ::metrics::structured::events::bluetooth::BluetoothAdapterStateChanged()
      .SetBootId(boot_id)
      .SetSystemTime(boot_time)
      .SetIsFloss(true)
      .SetAdapterState(adapter_state)
      .Record();
}

void LogMetricsBondCreateAttempt(RawAddress* addr, uint32_t device_type) {
  int64_t boot_time;
  std::string addr_string;
  std::string boot_id;

  if (!GetBootId(&boot_id)) return;

  addr_string = addr->ToString();
  boot_time = bluetooth::common::time_get_os_boottime_us();

  LOG_DEBUG(
      "PairingStateChanged: %s, %d, %s, %d, %d",
      boot_id.c_str(),
      boot_time,
      addr_string.c_str(),
      device_type,
      PairingState::PAIR_STARTING);

  ::metrics::structured::events::bluetooth::BluetoothPairingStateChanged()
      .SetBootId(boot_id)
      .SetSystemTime(boot_time)
      .SetDeviceId(addr_string)
      .SetDeviceType(device_type)
      .SetPairingState((int64_t)PairingState::PAIR_STARTING)
      .Record();
}

void LogMetricsBondStateChanged(
    RawAddress* addr, uint32_t device_type, uint32_t status, uint32_t bond_state, int32_t fail_reason) {
  int64_t boot_time;
  PairingState pairing_state;
  std::string addr_string;
  std::string boot_id;

  if (!GetBootId(&boot_id)) return;

  addr_string = addr->ToString();
  boot_time = bluetooth::common::time_get_os_boottime_us();
  pairing_state = ToPairingState(status, bond_state, fail_reason);

  // Ignore the start of pairing event as its logged separated above.
  if (pairing_state == PairingState::PAIR_STARTING) return;

  LOG_DEBUG(
      "PairingStateChanged: %s, %d, %s, %d, %d",
      boot_id.c_str(),
      boot_time,
      addr_string.c_str(),
      device_type,
      pairing_state);

  ::metrics::structured::events::bluetooth::BluetoothPairingStateChanged()
      .SetBootId(boot_id)
      .SetSystemTime(boot_time)
      .SetDeviceId(addr_string)
      .SetDeviceType(device_type)
      .SetPairingState((int64_t)pairing_state)
      .Record();
}

}  // namespace metrics
}  // namespace bluetooth
