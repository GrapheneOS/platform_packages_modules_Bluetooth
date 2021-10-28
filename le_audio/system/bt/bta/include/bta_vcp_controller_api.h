/*
 *Copyright (c) 2020, The Linux Foundation. All rights reserved.
 */

/******************************************************************************
 *
 *  Copyright 2018 The Android Open Source Project
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at:
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 ******************************************************************************/

#pragma once

#include <base/callback_forward.h>
#include <hardware/bt_vcp_controller.h>
#include <deque>
#include <future>
#include <vector>

enum {
  BTA_VCP_DISCONNECTED = 0x0,
  BTA_VCP_CONNECTING,
  BTA_VCP_CONNECTED,
  BTA_VCP_DISCONNECTING,
};

enum {
  VCS_VOLUME_STATE_READ_CMPL_EVT = 0x0,
  VCS_VOLUME_FLAGS_READ_CMPL_EVT,
  VCS_VOLUME_STATE_CCC_WRITE_CMPL_EVT,
  VCS_VOLUME_FLAGS_CCC_WRITE_CMPL_EVT,
};

enum {
  VCS_CONTROL_POINT_OP_REL_VOLUME_DOWN = 0x0,
  VCS_CONTROL_POINT_OP_REL_VOLUME_UP,
  VCS_CONTROL_POINT_OP_UNMUTE_REL_VOLUME_DOWN,
  VCS_CONTROL_POINT_OP_UNMUTE_REL_VOLUME_UP,
  VCS_CONTROL_POINT_OP_SET_ABS_VOL,
  VCS_CONTROL_POINT_OP_UNMUTE,
  VCS_CONTROL_POINT_OP_MUTE,
};

enum {
  VCS_UNMUTE_STATE = 0x0,
  VCS_MUTE_STATE,
};

typedef struct {
  uint8_t op_id;
  uint8_t change_counter;
  uint8_t volume_setting;
} SetAbsVolumeOp;

typedef struct {
  uint8_t op_id;
  uint8_t change_counter;
} MuteOp;

typedef struct {
  uint8_t op_id;
  uint8_t change_counter;
} UnmuteOp;

struct VolumeState {
  uint8_t volume_setting;
  uint8_t mute;
  uint8_t change_counter;

  VolumeState()
      : volume_setting(0),
        mute(0),
        change_counter(0) {}
};

struct VolumeControlService {
  uint16_t volume_state_handle;
  uint16_t volume_control_point_handle;
  uint16_t volume_flags_handle;
  uint16_t volume_state_ccc_handle;
  uint16_t volume_flags_ccc_handle;

  VolumeState volume_state;
  uint8_t volume_flags;
  uint8_t pending_volume_setting;
  uint8_t pending_mute_setting;
  uint8_t retry_cmd;

  VolumeControlService()
      : volume_state_handle(0),
        volume_control_point_handle(0),
        volume_flags_handle(0),
        volume_state_ccc_handle(0),
        volume_flags_ccc_handle(0),
        volume_state(),
        volume_flags(0),
        pending_volume_setting(0),
        pending_mute_setting(0),
        retry_cmd(0) {}
};

struct RendererDevice {
  RawAddress address;
  uint16_t conn_id;
  uint8_t state;
  bool bg_conn;
  bool service_changed_rcvd;
  VolumeControlService vcs;

  RendererDevice(const RawAddress& address)
      : address(address),
        conn_id(0),
        state(BTA_VCP_DISCONNECTED),
        bg_conn(false),
        service_changed_rcvd(false),
        vcs() {}

  RendererDevice() : RendererDevice(RawAddress::kEmpty) {}
};

class VcpController {
   public:
  virtual ~VcpController() = default;

  static void Initialize(bluetooth::vcp_controller::VcpControllerCallbacks* callbacks);
  static void CleanUp();
  static VcpController* Get();
  static bool IsVcpControllerRunning();
  static int GetDeviceCount();

  virtual void Connect(const RawAddress& address, bool isDirect) = 0;
  virtual void Disconnect(const RawAddress& address) = 0;
  virtual void SetAbsVolume(const RawAddress& address, uint8_t volume) = 0;
  virtual void Mute(const RawAddress& address) = 0;
  virtual void Unmute(const RawAddress& address) = 0;
};

