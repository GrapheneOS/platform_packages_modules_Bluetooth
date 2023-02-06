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

/// This class intercepts incoming connection requests and data packets, and
/// decides whether to intercept them or pass them to the legacy stack
///
/// It allows us to easily gate changes to the datapath and roll back to legacy
/// behavior if needed.

#pragma once

#include "rust/cxx.h"
#include "stack/include/bt_hdr.h"

namespace bluetooth {
namespace shim {
namespace arbiter {

void SendPacketToPeer(uint8_t tcb_idx, ::rust::Vec<uint8_t> buffer);

}  // namespace arbiter
}  // namespace shim
}  // namespace bluetooth
