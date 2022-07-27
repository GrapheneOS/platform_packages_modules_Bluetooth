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
#include "gd/metrics/chromeos/metrics_event.h"

#include "hci/hci_packets.h"

namespace bluetooth {
namespace metrics {

// ENUM definitaion for Bluetooth Bond State in sync with topshim::btif::BtBondState
enum class BtBondState {
  NotBonded = 0,
  Bonding,
  Bonded,
};

// ENUM definitaion for Bluetooth action status in sync with topshim::btif::BtStatus
enum class BtStatus {
  Success = 0,
  Fail,
  NotReady,
  NoMemory,
  Busy,
  Done,
  Unsupported,
  InvalidParam,
  Unhandled,
  AuthFailure,
  RemoteDeviceDown,
  AuthRejected,
  JniEnvironmentError,
  JniThreadAttachError,
  WakeLockError,

  // Any statuses that couldn't be cleanly converted
  Unknown = 0xff,
};

static PairingState StatusToPairingState(uint32_t status) {
  switch ((BtStatus)status) {
    case BtStatus::Success:
      return PairingState::PAIR_SUCCEED;
    case BtStatus::Fail:
      return PairingState::PAIR_FAIL_FAILED;
    case BtStatus::NoMemory:
      return PairingState::PAIR_FAIL_NO_RESOURCES;
    case BtStatus::Busy:
      return PairingState::PAIR_FAIL_BUSY;
    case BtStatus::Unsupported:
      return PairingState::PAIR_FAIL_NOT_SUPPORTED;
    case BtStatus::InvalidParam:
      return PairingState::PAIR_FAIL_INVALID_PARAMS;
    case BtStatus::AuthFailure:
      return PairingState::PAIR_FAIL_AUTH_FAILED;
    case BtStatus::RemoteDeviceDown:
      return PairingState::PAIR_FAIL_ESTABLISH_CONN;
    case BtStatus::AuthRejected:
      return PairingState::PAIR_FAIL_AUTH_FAILED;
    case BtStatus::NotReady:
    case BtStatus::Done:
    case BtStatus::Unhandled:
    default:
      return PairingState::PAIR_FAIL_UNKNOWN;
  }
}

static PairingState FailReasonToPairingState(int32_t fail_reason) {
  switch ((hci::ErrorCode)fail_reason) {
    case hci::ErrorCode::SUCCESS:
      return PairingState::PAIR_SUCCEED;
    case hci::ErrorCode::UNKNOWN_HCI_COMMAND:
      return PairingState::PAIR_FAIL_UNKNOWN_COMMAND;
    case hci::ErrorCode::UNKNOWN_CONNECTION:
      return PairingState::PAIR_FAIL_INVALID_PARAMS;
    case hci::ErrorCode::HARDWARE_FAILURE:
      return PairingState::PAIR_FAIL_FAILED;
    case hci::ErrorCode::PAGE_TIMEOUT:
      return PairingState::PAIR_FAIL_ESTABLISH_CONN;
    case hci::ErrorCode::AUTHENTICATION_FAILURE:
      return PairingState::PAIR_FAIL_AUTH_FAILED;
    case hci::ErrorCode::PIN_OR_KEY_MISSING:
      return PairingState::PAIR_FAIL_AUTH_FAILED;
    case hci::ErrorCode::MEMORY_CAPACITY_EXCEEDED:
      return PairingState::PAIR_FAIL_NO_RESOURCES;
    case hci::ErrorCode::CONNECTION_TIMEOUT:
      return PairingState::PAIR_FAIL_ESTABLISH_CONN;
    case hci::ErrorCode::CONNECTION_LIMIT_EXCEEDED:
      return PairingState::PAIR_FAIL_NO_RESOURCES;
    case hci::ErrorCode::SYNCHRONOUS_CONNECTION_LIMIT_EXCEEDED:
      return PairingState::PAIR_FAIL_NO_RESOURCES;
    case hci::ErrorCode::CONNECTION_ALREADY_EXISTS:
      return PairingState::PAIR_FAIL_ALREADY_PAIRED;
    case hci::ErrorCode::COMMAND_DISALLOWED:
      return PairingState::PAIR_FAIL_FAILED;
    case hci::ErrorCode::CONNECTION_REJECTED_LIMITED_RESOURCES:
      return PairingState::PAIR_FAIL_NO_RESOURCES;
    case hci::ErrorCode::CONNECTION_REJECTED_SECURITY_REASONS:
      return PairingState::PAIR_FAIL_AUTH_FAILED;
    case hci::ErrorCode::CONNECTION_REJECTED_UNACCEPTABLE_BD_ADDR:
      return PairingState::PAIR_FAIL_INVALID_PARAMS;
    case hci::ErrorCode::CONNECTION_ACCEPT_TIMEOUT:
      return PairingState::PAIR_FAIL_ESTABLISH_CONN;
    case hci::ErrorCode::UNSUPPORTED_FEATURE_OR_PARAMETER_VALUE:
      return PairingState::PAIR_FAIL_NOT_SUPPORTED;
    case hci::ErrorCode::INVALID_HCI_COMMAND_PARAMETERS:
      return PairingState::PAIR_FAIL_INVALID_PARAMS;
    case hci::ErrorCode::REMOTE_USER_TERMINATED_CONNECTION:
      return PairingState::PAIR_FAIL_DISCONNECTED;
    case hci::ErrorCode::REMOTE_DEVICE_TERMINATED_CONNECTION_LOW_RESOURCES:
      return PairingState::PAIR_FAIL_DISCONNECTED;
    case hci::ErrorCode::REMOTE_DEVICE_TERMINATED_CONNECTION_POWER_OFF:
      return PairingState::PAIR_FAIL_DISCONNECTED;
    case hci::ErrorCode::CONNECTION_TERMINATED_BY_LOCAL_HOST:
      return PairingState::PAIR_FAIL_DISCONNECTED;
    case hci::ErrorCode::REPEATED_ATTEMPTS:
      return PairingState::PAIR_FAIL_BUSY;
    case hci::ErrorCode::PAIRING_NOT_ALLOWED:
      return PairingState::PAIR_FAIL_FAILED;
    case hci::ErrorCode::UNKNOWN_LMP_PDU:
      return PairingState::PAIR_FAIL_FAILED;
    case hci::ErrorCode::UNSUPPORTED_REMOTE_OR_LMP_FEATURE:
      return PairingState::PAIR_FAIL_NOT_SUPPORTED;
    case hci::ErrorCode::INVALID_LMP_OR_LL_PARAMETERS:
      return PairingState::PAIR_FAIL_INVALID_PARAMS;
    case hci::ErrorCode::UNSPECIFIED_ERROR:
      return PairingState::PAIR_FAIL_UNKNOWN;
    case hci::ErrorCode::UNSUPPORTED_LMP_OR_LL_PARAMETER:
      return PairingState::PAIR_FAIL_NOT_SUPPORTED;
    case hci::ErrorCode::ROLE_CHANGE_NOT_ALLOWED:
      return PairingState::PAIR_FAIL_FAILED;
    case hci::ErrorCode::TRANSACTION_RESPONSE_TIMEOUT:
      return PairingState::PAIR_FAIL_TIMEOUT;
    case hci::ErrorCode::LINK_LAYER_COLLISION:
      return PairingState::PAIR_FAIL_FAILED;
    case hci::ErrorCode::ENCRYPTION_MODE_NOT_ACCEPTABLE:
      return PairingState::PAIR_FAIL_AUTH_FAILED;
    case hci::ErrorCode::ROLE_SWITCH_FAILED:
      return PairingState::PAIR_FAIL_FAILED;
    case hci::ErrorCode::CONTROLLER_BUSY:
      return PairingState::PAIR_FAIL_BUSY;
    case hci::ErrorCode::CONNECTION_FAILED_ESTABLISHMENT:
      return PairingState::PAIR_FAIL_ESTABLISH_CONN;
    case hci::ErrorCode::LIMIT_REACHED:
      return PairingState::PAIR_FAIL_NO_RESOURCES;
    case hci::ErrorCode::SCO_OFFSET_REJECTED:
    case hci::ErrorCode::SCO_INTERVAL_REJECTED:
    case hci::ErrorCode::SCO_AIR_MODE_REJECTED:
    case hci::ErrorCode::ADVERTISING_TIMEOUT:
    case hci::ErrorCode::STATUS_UNKNOWN:
      return PairingState::PAIR_FAIL_UNKNOWN;
  }
}

AdapterState ToAdapterState(uint32_t state) {
  return state == 1 ? AdapterState::ON : AdapterState::OFF;
}

PairingState ToPairingState(uint32_t status, uint32_t bond_state, int32_t fail_reason) {
  PairingState pairing_state = PairingState::PAIR_FAIL_UNKNOWN;

  // The Bonding is a transitional state during the pairing process. Ignore it by returning the starting again.
  if ((BtBondState)bond_state == BtBondState::Bonding) return PairingState::PAIR_STARTING;

  if ((BtStatus)status == BtStatus::Success && (hci::ErrorCode)fail_reason == hci::ErrorCode::SUCCESS) {
    if ((BtBondState)bond_state == BtBondState::Bonded) {
      return PairingState::PAIR_SUCCEED;
    } else {
      return PairingState::PAIR_FAIL_CANCELLED;
    }
  }

  // When both status and fail reason are provided and disagree with each other, overwrite status with the fail reason
  // as fail reason is generated closer to the HCI and provides a more accurate description.
  if (status) pairing_state = StatusToPairingState(status);
  if (fail_reason) pairing_state = FailReasonToPairingState(status);

  return pairing_state;
}

}  // namespace metrics
}  // namespace bluetooth