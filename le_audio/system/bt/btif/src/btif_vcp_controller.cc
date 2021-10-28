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

/* Volume Control Profile Interface */

#include "bt_target.h"
#include "bta_closure_api.h"
#include "bta_vcp_controller_api.h"
#include "btif_common.h"
#include "btif_storage.h"

#include <base/bind.h>
#include <base/callback.h>
#include <base/location.h>
#include <base/logging.h>
#include <hardware/bluetooth.h>
#include <hardware/bt_vcp_controller.h>

using base::Bind;
using base::Unretained;
using bluetooth::vcp_controller::ConnectionState;
using bluetooth::vcp_controller::VcpControllerCallbacks;
using bluetooth::vcp_controller::VcpControllerInterface;

namespace {
class VcpControllerInterfaceImpl;
std::unique_ptr<VcpControllerInterface> VcpControllerInstance;

class VcpControllerInterfaceImpl
    : public VcpControllerInterface, public VcpControllerCallbacks {
  ~VcpControllerInterfaceImpl() = default;

  void Init(VcpControllerCallbacks* callbacks) override {
    LOG(INFO) << __func__ ;
    this->callbacks = callbacks;

    do_in_bta_thread(
        FROM_HERE,
        Bind(&VcpController::Initialize, this));
  }

  void OnConnectionState(ConnectionState state,
                         const RawAddress& address) override {
    LOG(INFO) << __func__ << ": device=" << address << " state=" << (int)state;
    do_in_jni_thread(FROM_HERE, Bind(&VcpControllerCallbacks::OnConnectionState,
                                     Unretained(callbacks), state, address));
  }

  void OnVolumeStateChange(uint8_t volume, uint8_t mute,
                          const RawAddress& address) override {
    LOG(INFO) << __func__ << ": device=" << address << " volume=" << loghex(volume)
                        << " mute=" << (int)mute;
    do_in_jni_thread(FROM_HERE, Bind(&VcpControllerCallbacks::OnVolumeStateChange,
                                     Unretained(callbacks), volume, mute, address));
  }

  void OnVolumeFlagsChange(uint8_t flags,
                          const RawAddress& address) override {
    LOG(INFO) << __func__ << ": device=" << address << " flags=" << loghex(flags);
    do_in_jni_thread(FROM_HERE, Bind(&VcpControllerCallbacks::OnVolumeFlagsChange,
                                     Unretained(callbacks), flags, address));
  }

  void Connect(const RawAddress& address, bool isDirect) override {
    LOG(INFO) << __func__ << ": device=" << address;
    do_in_bta_thread(FROM_HERE, Bind(&VcpController::Connect,
                                      Unretained(VcpController::Get()), address, isDirect));
  }

  void Disconnect(const RawAddress& address) override {
    LOG(INFO) << __func__ << ": device=" << address;
    do_in_bta_thread(FROM_HERE, Bind(&VcpController::Disconnect,
                                      Unretained(VcpController::Get()), address));
  }

  void SetAbsVolume(uint8_t volume, const RawAddress& address) override {
    LOG(INFO) << __func__ << ": device=" << address << " volume=" << loghex(volume);
    do_in_bta_thread(FROM_HERE, Bind(&VcpController::SetAbsVolume,
                                      Unretained(VcpController::Get()), address, volume));
  }

  void Mute(const RawAddress& address) override {
    LOG(INFO) << __func__ << ": device=" << address;
    do_in_bta_thread(FROM_HERE, Bind(&VcpController::Mute,
                                      Unretained(VcpController::Get()), address));
  }

  void Unmute(const RawAddress& address) override {
    LOG(INFO) << __func__ << ": device=" << address;
    do_in_bta_thread(FROM_HERE, Bind(&VcpController::Unmute,
                                    Unretained(VcpController::Get()), address));
  }

  void Cleanup(void) override {
    LOG(INFO) << __func__;
    do_in_bta_thread(FROM_HERE, Bind(&VcpController::CleanUp));
  }

 private:
  VcpControllerCallbacks* callbacks;
};

}  // namespace

VcpControllerInterface* btif_vcp_get_controller_interface() {
  LOG(INFO) << __func__;
  if (!VcpControllerInstance)
    VcpControllerInstance.reset(new VcpControllerInterfaceImpl());

  return VcpControllerInstance.get();
}

