/*
 * Copyright (c) 2020, The Linux Foundation. All rights reserved.
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
#pragma once

#include <string>
#include <hardware/bt_ascs_client.h>

namespace bluetooth {
namespace bap {
namespace ascs {

class AscsClient {
  public:
  virtual ~AscsClient() = default;

  static void Init(bluetooth::bap::ascs::AscsClientCallbacks* callbacks);

  static void CleanUp(uint16_t client_id);

  static AscsClient* Get();

  virtual void Connect(uint16_t client_id, const RawAddress& address,
                       bool is_direct) = 0;

  virtual void Disconnect(uint16_t client_id, const RawAddress& address) = 0;

  virtual void StartDiscovery(uint16_t client_id,
                              const RawAddress& address) = 0;

  virtual void GetAseState(uint16_t client_id, const RawAddress& address,
                           uint8_t ase_id) = 0;

  virtual void CodecConfig(uint16_t client_id, const RawAddress& address,
                           std::vector<AseCodecConfigOp> codec_configs);

  virtual void QosConfig(uint16_t client_id, const RawAddress& address,
                           std::vector<AseQosConfigOp> qos_configs);

  virtual void Enable(uint16_t client_id, const RawAddress& address,
                           std::vector<AseEnableOp> enable_ops);

  virtual void Disable(uint16_t client_id, const RawAddress& address,
                           std::vector<AseDisableOp> disable_ops);

  virtual void StartReady(uint16_t client_id, const RawAddress& address,
                           std::vector<AseStartReadyOp> start_ready_ops);

  virtual void StopReady(uint16_t client_id, const RawAddress& address,
                           std::vector<AseStopReadyOp> stop_ready_ops);

  virtual void Release(uint16_t client_id, const RawAddress& address,
                           std::vector<AseReleaseOp> release_ops);

  virtual void UpdateStream(uint16_t client_id, const RawAddress& address,
                           std::vector<AseUpdateMetadataOp> metadata_ops);
};

}  // namespace ascs
}  // namespace bap
}  // namespace bluetooth
