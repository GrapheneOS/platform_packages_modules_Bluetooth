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

// ENUM definitaion for pairing state that in sync with ChromeOS strcutured metrics
// BluetoothPairingStateChanged/PairingState and BlueZ metrics_pair_result.
enum class PairingState : int64_t {
  PAIR_STARTING = 0,
  PAIR_SUCCEED = 1,
  // The controller is not powered.
  PAIR_FAIL_NONPOWERED = 2,
  // The remote device has been paired with the local host.
  PAIR_FAIL_ALREADY_PAIRED = 3,
  // This can be invalid address type, invalid IO capability.
  PAIR_FAIL_INVALID_PARAMS = 4,
  // The pairing is in progress or being canceled.
  PAIR_FAIL_BUSY = 5,
  // Simple pairing or pairing is not supported on the remote device.
  PAIR_FAIL_NOT_SUPPORTED = 6,
  // Fail to set up connection with the remote device.
  PAIR_FAIL_ESTABLISH_CONN = 7,
  // The authentication failure can be caused by incorrect PIN/link key or
  // missing PIN/link key during pairing or authentication procedure.
  // This can also be a failure during message integrity check.
  PAIR_FAIL_AUTH_FAILED = 8,
  // The pairing request is rejected by the remote device.
  PAIR_FAIL_REJECTED = 9,
  // The pairing was cancelled.
  PAIR_FAIL_CANCELLED = 10,
  // The connection was timeout.
  PAIR_FAIL_TIMEOUT = 11,
  PAIR_FAIL_UNKNOWN = 12,
  // BT IO connection error
  PAIR_FAIL_BT_IO_CONNECT_ERROR = 13,
  // Unknown command.
  PAIR_FAIL_UNKNOWN_COMMAND = 14,
  // The peer was not connected.
  PAIR_FAIL_NOT_CONNECTED = 15,
  // Exceeded the limit of resource such as memory, connections.
  PAIR_FAIL_NO_RESOURCES = 16,
  // Disconnected due to power, user termination or other reasons.
  PAIR_FAIL_DISCONNECTED = 17,
  // Failed due to all the other reasons such as hardware, invalid LMP
  // PDU, transaction collision, role change, slot violation etc.
  PAIR_FAIL_FAILED = 18,
  PAIR_FAIL_END = 19,
};

// Convert topshim::btif::BtState to AdapterState.
AdapterState ToAdapterState(uint32_t state);

// Convert topshim::btif::bond_state info (status, addr, bond_state, and fail_reason) to PairingState
PairingState ToPairingState(uint32_t status, uint32_t bond_state, int32_t fail_reason);

}  // namespace metrics
}  // namespace bluetooth