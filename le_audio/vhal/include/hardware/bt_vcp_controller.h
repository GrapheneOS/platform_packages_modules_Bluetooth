/*
 *Copyright (c) 2020, The Linux Foundation. All rights reserved.
 */

/*
 * Copyright 2018 The Android Open Source Project
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

#ifndef ANDROID_INCLUDE_BT_VCP_CONTROLLER_H
#define ANDROID_INCLUDE_BT_VCP_CONTROLLER_H

#include <hardware/bluetooth.h>

#define BT_PROFILE_VOLUME_CONTROL_ID "volume_control"

namespace bluetooth {
namespace vcp_controller {

enum class ConnectionState {
  DISCONNECTED = 0,
  CONNECTING,
  CONNECTED,
  DISCONNECTING
};

class VcpControllerCallbacks {
 public:
  virtual ~VcpControllerCallbacks() = default;

  /** Callback for profile connection state change */
  virtual void OnConnectionState(ConnectionState state,
                                  const RawAddress& address) = 0;

  virtual void OnVolumeStateChange(uint8_t volume, uint8_t mute,
                                  const RawAddress& address) = 0;

  virtual void OnVolumeFlagsChange(uint8_t flags,
                                  const RawAddress& address) = 0;
};

class VcpControllerInterface {
 public:
  virtual ~VcpControllerInterface() = default;

  /** Register the Volume Controller callbacks */
  virtual void Init(VcpControllerCallbacks* callbacks) = 0;

  /** Connect to Volume Renderer device */
  virtual void Connect(const RawAddress& address, bool isDirect) = 0;

  /** Disconnect from Volume Renderer device */
  virtual void Disconnect(const RawAddress& address) = 0;

  /** Set absolute volume */
  virtual void SetAbsVolume(uint8_t volume, const RawAddress& address) = 0;

  virtual void Mute(const RawAddress& address) = 0;

  virtual void Unmute(const RawAddress& address) = 0;

  /** Closes the interface. */
  virtual void Cleanup(void) = 0;
};

}  // namespace vcp_controller
}  // namespace bluetooth

#endif /* ANDROID_INCLUDE_BT_VCP_CONTROLLER_H */


