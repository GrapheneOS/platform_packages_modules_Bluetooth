/*
 *Copyright (c) 2020-2021, The Linux Foundation. All rights reserved.
 */

/*
 * Copyright 2017 The Android Open Source Project
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

#include "bluetooth_callcontrol_callbacks.h"
#include <hardware/bluetooth.h>

#define BT_PROFILE_CC_ID "cc_server"

namespace bluetooth {
namespace call_control {

/**
 * Programming interface for CCS/GTBS profiles in the Fluoride stack
 * Thread-safe
 */
class CallControllerInterface {
 public:
  virtual ~CallControllerInterface() = default;
  /**
   * Initialize the CCS/GTBS Interface
   *
   * @param callbacks callbacks for the user of the native stack
   * @param max_ccs_clients maximum number of CCS/GTBS clients
   * @param inband_ringing_enabled whether inband ringtone is enabled
   * @return BT_STATUS_SUCCESS on success
   */
  virtual bt_status_t Init(CallControllerCallbacks* callbacks, Uuid uuid, int max_ccs_clients,
                           bool inband_ringing_enabled) = 0;
  /**
   * Updates telephony bearer name
   *
   * @param operator_str bearer name of provider
   * @return BT_STATUS_SUCCESS on success
   */
  virtual bt_status_t UpdateBearerName(uint8_t* operator_str) = 0;

  /**
   * Updates the bearer Technogly type
   *
   * @param bearer_tech bearer technology type of provider
   * @return BT_STATUS_SUCCESS on success
   */
  virtual bt_status_t UpdateBearerTechnology(int bearer_tech) = 0;

  /**
   * Updates telephony network bearers supported
   *
   * @param supportedBearers supported bearers list
   * @return BT_STATUS_SUCCESS on success
   */
  virtual bt_status_t UpdateSupportedBearerList(uint8_t* supportedBearers) = 0;

  /**
   * Updates optional Call control operations supported
   *
   * @param feature bitmask value representing the optional op code supported
   * @return BT_STATUS_SUCCESS on success
   */
  virtual bt_status_t  CallControlOptionalOpSupported(int feature) = 0;

  /**
   * Update network signal strength
   *
   * @param signal level
   * @return BT_STATUS_SUCCESS on success
   */
  virtual bt_status_t UpdateSignalStatus(int signal) = 0;

  /**
   * Update status flag for GTBS
   *
   * @param bd_addr remote device address
   * @return BT_STATUS_SUCCESS on success
   */
  virtual bt_status_t UpdateStatusFlags(uint8_t status_flag) = 0;

  /**
   * Update Content control for GTBS/CCS
   *
   * @param ccid content control Id for GTBS/CCS
   * @return BT_STATUS_SUCCESS on success
   */
  virtual void ContentControlId(uint32_t ccid) = 0;

  /**
   * Update the Call State of CCS
   *
   * @param len of call state infos
   * @param call_state_list array of call state list, where each call state
   *        comprised of index, state, flags
   * @return BT_STATUS_SUCCESS on success
   */
  virtual bt_status_t CallState(int len, std::vector<uint8_t> call_state_list) = 0;

  /**
   * Update Incoming call URI for the given Call Index
   *
   * @param index index of the call
   * @param uri representing the Incoming call, will be Incoming call number for telephony
   * @return BT_STATUS_SUCCESS on success
   */

  virtual void UpdateIncomingCall(int index, uint8_t* uri) = 0;
  /**
   * Response for Call control Operation initiated
   *
   * @param op Operation for which response is sent
   * @param index index of call for operation
   * @param status status of the operation performed
   * @return BT_STATUS_SUCCESS on success
   */
  virtual bt_status_t CallControlResponse(uint8_t op, uint8_t index, uint32_t status, const RawAddress& address) = 0;

  /**
   * Set the current active device for GTBS/CCS
   *
   * @param active_device_addr remote device address
   */
  virtual void SetActiveDevice(const RawAddress& address, int set_id) = 0;

  /**
   * Disconnect GTBS/CTS profile for remote
   * @param address remote device address
   */
  virtual void Disconnect(const RawAddress& address) = 0;
   /**
   * Closes the GTBS/CCS interface.
   */
  virtual void Cleanup() = 0;
};

}  // namespace call_control
}  // namespace bluetooth
