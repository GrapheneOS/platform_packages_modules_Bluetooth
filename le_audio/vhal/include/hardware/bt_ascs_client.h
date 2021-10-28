/*
 * Copyright (c) 2020, The Linux Foundation. All rights reserved.
 *
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

#ifndef ANDROID_INCLUDE_BT_ASCS_CLIENT_H
#define ANDROID_INCLUDE_BT_ASCS_CLIENT_H

#include <hardware/bluetooth.h>

namespace bluetooth {
namespace bap {
namespace ascs {

#define BT_PROFILE_ASCS_CLIENT_ID "bt_ascs_client"

constexpr uint8_t ASE_DIRECTION_SINK   = 0x01;
constexpr uint8_t ASE_DIRECTION_SOURCE = 0x02;

constexpr uint32_t CONTEXT_TYPE_CONVERSATIONAL  = 0x0002;
constexpr uint32_t CONTEXT_TYPE_MEDIA           = 0x0004;

constexpr uint8_t  ASE_STATE_IDLE                = 0x00;
constexpr uint8_t  ASE_STATE_CODEC_CONFIGURED    = 0x01;
constexpr uint8_t  ASE_STATE_QOS_CONFIGURED      = 0x02;
constexpr uint8_t  ASE_STATE_ENABLING            = 0x03;
constexpr uint8_t  ASE_STATE_STREAMING           = 0x04;
constexpr uint8_t  ASE_STATE_DISABLING           = 0x05;
constexpr uint8_t  ASE_STATE_RELEASING           = 0x06;
constexpr uint8_t  ASE_STATE_INVALID             = 0xFF;

typedef uint8_t sdu_interval_t[3];
typedef uint8_t presentation_delay_t[3];
typedef uint8_t codec_type_t[5];


enum class ASCSEvent {
  ASCS_DISCOVERY_CMPL_EVT = 0,
  ASCS_DEV_CONNECTED,
  ASCS_DEV_DISCONNECTED,
  ASCS_ASE_STATE,
};

struct AudioContext {
  uint8_t length;
  uint8_t type;
  uint16_t value;
};

enum class AseState {
  IDLE = 0,
  CODEC_CONFIGURED,
  QOS_CONFIGURED,
  ENABLING,
  STREAMING,
  DISABLING,
  RELEASING,
};

enum class AseOpId {
  CODEC_CONFIG = 0x01,
  QOS_CONFIG,
  ENABLE,
  START_READY,
  DISABLE,
  STOP_READY,
  UPDATE_META_DATA,
  RELEASE
};

enum class GattState {
  DISCONNECTED = 0,
  CONNECTING,
  CONNECTED,
  DISCONNECTING
};

struct AseCodecConfigOp {
  uint8_t ase_id;
  uint8_t tgt_latency;
  uint8_t tgt_phy;
  codec_type_t codec_id;
  uint8_t codec_params_len;
  std::vector<uint8_t> codec_params;
} __attribute__((packed));

struct  AseQosConfigOp {
  uint8_t ase_id;
  uint8_t cig_id;
  uint8_t cis_id;
  sdu_interval_t sdu_interval;
  uint8_t framing;
  uint8_t phy;
  uint16_t max_sdu_size;
  uint8_t retrans_number;
  uint16_t trans_latency;
  presentation_delay_t present_delay;
} __attribute__((packed));

struct AseEnableOp {
  uint8_t ase_id;
  uint8_t meta_data_len;
  std::vector<uint8_t> meta_data;
} __attribute__((packed));

struct AseDisableOp {
  uint8_t ase_id;
} __attribute__((packed));

struct AseStartReadyOp {
  uint8_t ase_id;
} __attribute__((packed));

struct AseStopReadyOp {
  uint8_t ase_id;
} __attribute__((packed));

struct AseReleaseOp {
  uint8_t ase_id;
} __attribute__((packed));

struct AseUpdateMetadataOp {
  uint8_t ase_id;
  uint8_t meta_data_len;
  std::vector<uint8_t> meta_data;
} __attribute__((packed));

struct AseCodecConfigParams {
  uint8_t framing;
  uint8_t pref_phy;
  uint8_t pref_rtn;
  uint16_t mtl;
  presentation_delay_t pd_min;
  presentation_delay_t pd_max;
  presentation_delay_t pref_pd_min;
  presentation_delay_t pref_pd_max;
  codec_type_t codec_id;
  uint8_t codec_params_len;
  std::vector<uint8_t> codec_params;
} __attribute__((packed));

struct  AseQosConfigParams {
  uint8_t cig_id;
  uint8_t cis_id;
  sdu_interval_t sdu_interval;
  uint8_t framing;
  uint8_t phy;
  uint16_t max_sdu_size;
  uint8_t rtn;
  uint16_t mtl;
  presentation_delay_t pd;
} __attribute__((packed));

struct AseGenericParams {
  uint8_t cig_id;
  uint8_t cis_id;
  uint8_t meta_data_len;
  std::vector<uint8_t> meta_data;
} __attribute__((packed));

union AseOp {
  AseCodecConfigOp codec_config_op;
  AseQosConfigOp qos_config_op;
  AseEnableOp enable_op;
  AseDisableOp disable_op;
  AseStartReadyOp start_ready_op;
  AseStopReadyOp stop_ready_op;
  AseReleaseOp release_op;
};

struct AseOpStatus {
  uint8_t ase_id;
  uint8_t resp_code;
  uint8_t reason;
};

struct AseParams {
  uint8_t ase_id;
  uint8_t ase_state;
  AseCodecConfigParams codec_config_params;
  AseQosConfigParams qos_config_params;
  AseGenericParams generic_params;
} __attribute__((packed));

struct AseCpNotification {
  uint8_t ase_opcode;
  uint8_t num_ases;
  std::vector<AseOpStatus> status;
} __attribute__((packed));

struct Ase {
  uint16_t ase_handle;
  uint16_t ase_ccc_handle;
  AseParams ase_params;
} __attribute__((packed));

struct AscsDiscoveryDb {
  std::vector<Ase> ase_list;
  uint16_t ase_cp_handle;
  uint16_t ase_cp_ccc_handle;
  bool service_changed_rcvd;
  bool active;
};

class AscsClientCallbacks {
 public:
  virtual ~AscsClientCallbacks() = default;

  /** Callback for ascs server registration status */
  virtual void OnAscsInitialized(int status, int client_id) = 0;

  /** Callback for ascs server connection state change */
  virtual void OnConnectionState(const RawAddress& address,
                                 GattState state) = 0;

  /** Callback for ascs server control op failed status */
  virtual void OnAseOpFailed(const RawAddress& address,
                             AseOpId ase_op_id,
                             std::vector<AseOpStatus> status) = 0;

  /** Callback for ascs ase state change */
  virtual void OnAseState(const RawAddress& address,
                          AseParams ase) = 0;

  /** Callback for ascs discovery results */
  virtual void OnSearchComplete(int status, const RawAddress& address,
                          std::vector<AseParams> sink_ase_list,
                          std::vector<AseParams> src_ase_list) = 0;
};

class AscsClientInterface {
 public:
  virtual ~AscsClientInterface() = default;

  /** Register the Ascs client callbacks */
  virtual void Init(AscsClientCallbacks* callbacks) = 0;

  /** Connect to ascs server */
  virtual void Connect(uint16_t client_id, const RawAddress& address) = 0;

  /** Disconnect ascs server */
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

  /** Closes the interface. */
  virtual void Cleanup(uint16_t client_id) = 0;
};

}  // namespace ascs
}  // namespace bap
}  // namespace bluetooth

#endif /* ANDROID_INCLUDE_BT_CLIENT_H */
