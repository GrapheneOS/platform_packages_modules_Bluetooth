/*
 * Copyright (c) 2020, The Linux Foundation. All rights reserved.
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

#include "bta_closure_api.h"
#include "bta_ascs_client_api.h"
#include "btif_common.h"
#include "btif_storage.h"

#include <base/bind.h>
#include <base/callback.h>
#include <base/location.h>
#include <base/logging.h>
#include <hardware/bluetooth.h>
#include <hardware/bt_ascs_client.h>
#include "osi/include/thread.h"

using base::Bind;
using base::Unretained;
using bluetooth::bap::ascs::AscsClient;
using bluetooth::bap::ascs::GattState;
using bluetooth::bap::ascs::AscsClientCallbacks;
using bluetooth::bap::ascs::AscsClientInterface;
using bluetooth::bap::ascs::AseOpId;
using bluetooth::bap::ascs::AseOpStatus;
using bluetooth::bap::ascs::AseParams;
using bluetooth::bap::ascs::AseCodecConfigOp;
using bluetooth::bap::ascs::AseQosConfigOp;
using bluetooth::bap::ascs::AseEnableOp;
using bluetooth::bap::ascs::AseDisableOp;
using bluetooth::bap::ascs::AseStartReadyOp;
using bluetooth::bap::ascs::AseStopReadyOp;
using bluetooth::bap::ascs::AseReleaseOp;
using bluetooth::bap::ascs::AseUpdateMetadataOp;

namespace {

class AscsClientInterfaceImpl;
std::unique_ptr<AscsClientInterface> AscsClientInstance;

class AscsClientInterfaceImpl
    : public AscsClientInterface,
      public AscsClientCallbacks {
  ~AscsClientInterfaceImpl() = default;

  void Init(AscsClientCallbacks* callbacks) override {
    DVLOG(2) << __func__;
    this->callbacks = callbacks;

    do_in_bta_thread(
        FROM_HERE,
        Bind(&AscsClient::Init, this));
  }

  void OnAscsInitialized(int status, int client_id) override {
    do_in_jni_thread(FROM_HERE, Bind(&AscsClientCallbacks::OnAscsInitialized,
                                     Unretained(callbacks), status,
                                     client_id));
  }

  void OnConnectionState(const RawAddress& address,
                         GattState state) override {
    DVLOG(2) << __func__ << " address: " << address;
    do_in_jni_thread(FROM_HERE, Bind(&AscsClientCallbacks::OnConnectionState,
                                     Unretained(callbacks), address, state));
  }

  void OnAseOpFailed(const RawAddress& address, AseOpId ase_op_id,
                     std::vector<AseOpStatus> status) override {
    do_in_jni_thread(FROM_HERE,
                     Bind(&AscsClientCallbacks::OnAseOpFailed,
                          Unretained(callbacks),
                          address, ase_op_id, status));
  }

  void OnAseState(const RawAddress& address, AseParams ase) override {
    do_in_jni_thread(FROM_HERE,
                     Bind(&AscsClientCallbacks::OnAseState,
                          Unretained(callbacks), address, ase));
  }

  void OnSearchComplete(int status,
                        const RawAddress& address,
                        std::vector<AseParams> sink_ase_list,
                        std::vector<AseParams> src_ase_list) override {
    do_in_jni_thread(FROM_HERE, Bind(&AscsClientCallbacks::OnSearchComplete,
                                     Unretained(callbacks),
                                     status,
                                     address,
                                     sink_ase_list,
                                     src_ase_list));
  }

  void Connect(uint16_t client_id, const RawAddress& address) override {
    do_in_bta_thread(FROM_HERE, Bind(&AscsClient::Connect,
                                      Unretained(AscsClient::Get()),
                                      client_id, address, false));
  }

  void Disconnect(uint16_t client_id, const RawAddress& address) override {
    do_in_bta_thread(FROM_HERE, Bind(&AscsClient::Disconnect,
                                      Unretained(AscsClient::Get()),
                                      client_id, address));
  }

  void StartDiscovery(uint16_t client_id, const RawAddress& address) override {
    do_in_bta_thread(FROM_HERE, Bind(&AscsClient::StartDiscovery,
                                      Unretained(AscsClient::Get()),
                                      client_id, address));
  }

  void GetAseState(uint16_t client_id, const RawAddress& address,
                   uint8_t ase_id) override {
    do_in_bta_thread(FROM_HERE, Bind(&AscsClient::GetAseState,
                                      Unretained(AscsClient::Get()),
                                      client_id, address, ase_id));
  }

  void CodecConfig(uint16_t client_id, const RawAddress& address,
                   std::vector<AseCodecConfigOp> codec_configs) override {
    do_in_bta_thread(FROM_HERE, Bind(&AscsClient::CodecConfig,
                                      Unretained(AscsClient::Get()),
                                      client_id, address, codec_configs));
  }

  void QosConfig(uint16_t client_id, const RawAddress& address,
                 std::vector<AseQosConfigOp> qos_configs) override {
    do_in_bta_thread(FROM_HERE, Bind(&AscsClient::QosConfig,
                                      Unretained(AscsClient::Get()),
                                      client_id, address, qos_configs));
  }

  void Enable(uint16_t client_id, const RawAddress& address,
              std::vector<AseEnableOp> enable_ops) override {
    do_in_bta_thread(FROM_HERE, Bind(&AscsClient::Enable,
                                      Unretained(AscsClient::Get()),
                                      client_id, address, enable_ops));
  }

  void Disable(uint16_t client_id, const RawAddress& address,
               std::vector<AseDisableOp> disable_ops) override {
    do_in_bta_thread(FROM_HERE, Bind(&AscsClient::Disable,
                                      Unretained(AscsClient::Get()),
                                      client_id, address, disable_ops));
  }

  void StartReady(uint16_t client_id, const RawAddress& address,
                  std::vector<AseStartReadyOp> start_ready_ops) override {
    do_in_bta_thread(FROM_HERE, Bind(&AscsClient::StartReady,
                                      Unretained(AscsClient::Get()),
                                      client_id, address, start_ready_ops));
  }

  void StopReady(uint16_t client_id, const RawAddress& address,
                 std::vector<AseStopReadyOp> stop_ready_ops) override {
    do_in_bta_thread(FROM_HERE, Bind(&AscsClient::StopReady,
                                      Unretained(AscsClient::Get()),
                                      client_id, address, stop_ready_ops));
  }

  void Release(uint16_t client_id, const RawAddress& address,
               std::vector<AseReleaseOp> release_ops) override {
    do_in_bta_thread(FROM_HERE, Bind(&AscsClient::Release,
                                      Unretained(AscsClient::Get()),
                                      client_id, address, release_ops));
  }

  void UpdateStream(uint16_t client_id, const RawAddress& address,
                    std::vector<AseUpdateMetadataOp> metadata_ops) override {
    do_in_bta_thread(FROM_HERE, Bind(&AscsClient::UpdateStream,
                                      Unretained(AscsClient::Get()),
                                      client_id, address, metadata_ops));
  }

  void Cleanup(uint16_t client_id) override {
    DVLOG(2) << __func__;
    do_in_bta_thread(FROM_HERE, Bind(&AscsClient::CleanUp, client_id));
  }

 private:
  AscsClientCallbacks* callbacks;
};

}  // namespace

AscsClientInterface* btif_ascs_client_get_interface() {
  if (!AscsClientInstance)
    AscsClientInstance.reset(new AscsClientInterfaceImpl());

  return AscsClientInstance.get();
}
