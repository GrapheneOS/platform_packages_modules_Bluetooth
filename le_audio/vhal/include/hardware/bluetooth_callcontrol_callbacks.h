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

namespace bluetooth {
namespace call_control {

/**
 * CCS/GTBS related callbacks invoked from from the Bluetooth native stack
 * All callbacks are invoked on the JNI thread
 */
class CallControllerCallbacks {
 public:
  virtual ~CallControllerCallbacks() = default;
  /**
   * Callback for notifying the CCS initialization status.
   *
   * @param state success if zero, failure otherwise
   */
  virtual void CallControlInitializedCallback(uint8_t state
                                        ) = 0;
  /**
   * Callback for connection state change.
   *
   * @param state one of the values from btcc_connection_state_t
   * @param bd_addr remote device address
   */
  virtual void ConnectionStateCallback(uint8_t state,
                                        const RawAddress& address) = 0;
  /**
   * Callback for call control operations.
   *
   * @param op call control operation initiated from remote
   * @param indicies Indicies for the call control operations
   * @param count number of Indicies for the call control operations
   * @uri uri for the call control operation
   * @param bd_addr remote device address which initiated the call control op
   */
  virtual void CallControlCallback(uint8_t op, std::vector<int32_t> indicies, int count, std::vector<uint8_t> uri_data,
                                   const RawAddress& address) = 0;
};

}  // namespace callcontrol
}  // namespace bluetooth
