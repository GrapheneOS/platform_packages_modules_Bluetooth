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
#pragma once

#include <cstdint>

namespace bluetooth {
namespace metrics {

// ENUM definitaion for adapter state that in sync with ChromeOS strcutured metrics
// BluetoothAdapterStateChanged/AdapterState.
enum class AdapterState : int64_t { OFF = 0, ON = 1 };

// Convert topshim::btif::BtState to AdapterState.
AdapterState ToAdapterState(uint32_t state);

}  // namespace metrics
}  // namespace bluetooth