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
#include <string>

namespace bluetooth {
namespace metrics {

// ENUM definition for adapter state that in sync with ChromeOS structured metrics
// BluetoothAdapterStateChanged/AdapterState.
enum class AdapterState : int64_t { OFF = 0, ON = 1 };

// ENUM definition for pairing state that in sync with ChromeOS structured metrics
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

// ENUM definition for pairing state that in sync with ChromeOS structured metrics
// BluetoothProfileConnectionStateChanged/Profile and BlueZ metrics_bluetooth_profile.
enum class Profile : int64_t {
  UNKNOWN = 0,
  HSP = 1,
  HFP = 2,
  A2DP = 3,
  AVRCP = 4,
  HID = 5,
  HOG = 6,
  GATT = 7,
  GAP = 8,
  DEVICE_INFO = 9,
  BATTERY = 10,
  NEARBY = 11,
  PHONEHUB = 12,
};

// ENUM definition for profile connection state that in sync with ChromeOS structured metrics
// MetricProfileConnectionStatus and BlueZ's metrics_profile_conn_state.
enum class MetricProfileConnectionStatus : int64_t {
  // Common states for connecting and disconnecting a profile
  PROFILE_CONN_STATE_STARTING = 0,
  PROFILE_CONN_STATE_SUCCEED = 1,
  PROFILE_CONN_STATE_ALREADY_CONNECTED = 2,
  PROFILE_CONN_STATE_BUSY_CONNECTING = 3,
  PROFILE_CONN_STATE_CONNECTION_REFUSED = 4,
  PROFILE_CONN_STATE_CONNECTION_CANCELED = 5,
  PROFILE_CONN_STATE_REMOTE_UNAVAILABLE = 6,
  PROFILE_CONN_STATE_PROFILE_NOT_SUPPORTED = 7,
  PROFILE_CONN_STATE_UNKNOWN_ERROR = 8,

};

// ENUM definition for profile disconnection state that in sync with ChromeOS structured metrics
// MetricProfileDisconnectionStatus and BlueZ's metrics_profile_disconn_state.
enum class MetricProfileDisconnectionStatus : int64_t {
  // Common states for connecting and disconnecting a profile
  PROFILE_DISCONN_STATE_STARTING = 0,
  PROFILE_DISCONN_STATE_SUCCEED = 1,
  PROFILE_DISCONN_STATE_ALREADY_DISCONNECTED = 2,
  PROFILE_DISCONN_STATE_BUSY_DISCONNECTING = 3,
  PROFILE_DISCONN_STATE_DISCONNECTION_REFUSED = 4,
  PROFILE_DISCONN_STATE_DISCONNECTION_CANCELED = 5,
  PROFILE_DISCONN_STATE_BT_IO_CONNECT_ERROR = 6,
  PROFILE_DISCONN_STATE_INVALID_PARAMS = 7,
  PROFILE_DISCONN_STATE_UNKNOWN_ERROR = 8,
};

// A binary ENUM defines the metrics event is logged for: either for an attempt to connect or to disconnect.
enum class StateChangeType : int64_t { STATE_CHANGE_TYPE_DISCONNECT = 0, STATE_CHANGE_TYPE_CONNECT = 1 };

// A struct holds the parsed profile connection event.
struct ProfileConnectionEvent {
  int64_t type;
  int64_t profile;
  int64_t state;
};

// Convert topshim::btif::BtState to AdapterState.
AdapterState ToAdapterState(uint32_t state);

// Convert topshim::btif::bond_state info (status, addr, bond_state, and fail_reason) to PairingState
PairingState ToPairingState(uint32_t status, uint32_t bond_state, int32_t fail_reason);

// Convert Floss profile connection info to ProfileConnectionEvent
ProfileConnectionEvent ToProfileConnectionEvent(std::string addr, uint32_t profile, uint32_t status, uint32_t state);

}  // namespace metrics
}  // namespace bluetooth
