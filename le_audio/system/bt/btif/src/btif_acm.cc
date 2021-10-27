/******************************************************************************
 *
 *  Copyright 2021 The Android Open Source Project
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


#define LOG_TAG "btif_acm"
#include "btif_acm.h"
#include <base/bind.h>
#include <base/bind_helpers.h>
#include <base/logging.h>
#include <base/strings/stringprintf.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <map>
#include <future>
#include "bta_closure_api.h"
#include "btif_storage.h"
#include <hardware/bluetooth.h>
#include <hardware/bt_acm.h>
#include "audio_hal_interface/a2dp_encoding.h"
#include "bt_common.h"
#include "bt_utils.h"
#include "bta/include/bta_api.h"
#include "btif/include/btif_a2dp_source.h"
#include "btif_common.h"
#include <base/callback.h>
#include "audio_a2dp_hw/include/audio_a2dp_hw.h"
#include "btif_av_co.h"
#include "btif_util.h"
#include "btu.h"
#include "common/state_machine.h"
#include "osi/include/allocator.h"
#include "osi/include/osi.h"
#include "osi/include/properties.h"
#include "btif/include/btif_bap_config.h"
#include "bta_bap_uclient_api.h"
#include "btif_bap_codec_utils.h"
#include "bta/include/bta_csip_api.h"
#include <base/threading/thread.h>
#include "osi/include/thread.h"
#include <pthread.h>
#include "bta_api.h"
#include <hardware/bt_pacs_client.h>
#include <hardware/bt_bap_uclient.h>
#include "btif/include/btif_vmcp.h"
#include "btif/include/btif_acm_source.h"
#include "l2c_api.h"
#include "bt_types.h"
#include "btm_int.h"
#include <inttypes.h>

/*****************************************************************************
 *  Constants & Macros
 *****************************************************************************/
#define LE_AUDIO_MASK                      0x00000300
#define LE_AUDIO_NOT_AVAILABLE             0x00000100
#define LE_AUDIO_AVAILABLE_NOT_LICENSED    0x00000200  //LC3
#define LE_AUDIO_AVAILABLE_LICENSED        0x00000300  //LC3Q
#define LE_AUDIO_CS_3_1ST_BYTE_INDEX       0x00
#define LE_AUDIO_CS_3_2ND_BYTE_INDEX       0x01
#define LE_AUDIO_CS_3_3RD_BYTE_INDEX       0x02
#define LE_AUDIO_CS_3_4TH_BYTE_INDEX       0x03
#define LE_AUDIO_CS_3_5TH_BYTE_INDEX       0x04
#define LE_AUDIO_CS_3_7TH_BYTE_INDEX       0x06
#define LE_AUDIO_CS_3_8TH_BYTE_INDEX       0x07

static RawAddress active_bda = {};
static constexpr int kDefaultMaxConnectedAudioDevices = 5;
CodecConfig current_active_config;
static CodecConfig current_media_config;
static CodecConfig current_voice_config;
static CodecConfig current_recording_config;
uint16_t current_active_profile_type = 0;
uint16_t current_active_context_type;

using bluetooth::bap::ucast::UcastClientInterface;
using bluetooth::bap::ucast::UcastClientCallbacks;
using bluetooth::bap::ucast::UcastClient;
using bluetooth::bap::ucast::StreamState;
using bluetooth::bap::ucast::StreamConnect;
using bluetooth::bap::ucast::StreamType;

using bluetooth::bap::pacs::CodecIndex;
using bluetooth::bap::pacs::CodecPriority;
using bluetooth::bap::pacs::CodecSampleRate;
using bluetooth::bap::pacs::CodecBPS;
using bluetooth::bap::pacs::CodecChannelMode;
using bluetooth::bap::pacs::CodecFrameDuration;
using bluetooth::bap::ucast::CodecQosConfig;
using bluetooth::bap::ucast::StreamStateInfo;
using bluetooth::bap::ucast::StreamConfigInfo;
using bluetooth::bap::ucast::StreamReconfig;
using bluetooth::bap::ucast::CISConfig;
using bluetooth::bap::pacs::CodecDirection;
using bluetooth::bap::ucast::CONTENT_TYPE_MEDIA;
using bluetooth::bap::ucast::CONTENT_TYPE_CONVERSATIONAL;
using bluetooth::bap::ucast::CONTENT_TYPE_LIVE;
using bluetooth::bap::ucast::CONTENT_TYPE_UNSPECIFIED;
using bluetooth::bap::ucast::CONTENT_TYPE_INSTRUCTIONAL;
using bluetooth::bap::ucast::CONTENT_TYPE_NOTIFICATIONS;
using bluetooth::bap::ucast::CONTENT_TYPE_ALERT;
using bluetooth::bap::ucast::CONTENT_TYPE_MAN_MACHINE;
using bluetooth::bap::ucast::CONTENT_TYPE_EMERGENCY;
using bluetooth::bap::ucast::CONTENT_TYPE_RINGTONE;
using bluetooth::bap::ucast::CONTENT_TYPE_SOUND_EFFECTS;
using bluetooth::bap::ucast::CONTENT_TYPE_GAME;

using bluetooth::bap::ucast::ASE_DIRECTION_SRC;
using bluetooth::bap::ucast::ASE_DIRECTION_SINK;
using bluetooth::bap::ucast::ASCSConfig;
using bluetooth::bap::ucast::LE_2M_PHY;
using bluetooth::bap::ucast::LE_QHS_PHY;

using base::Bind;
using base::Unretained;
using base::IgnoreResult;
using bluetooth::Uuid;
extern void do_in_bta_thread(const base::Location& from_here,
                             const base::Closure& task);

bool reconfig_acm_initiator(const RawAddress& peer_address, int profileType);

static void btif_acm_initiator_dispatch_sm_event(const RawAddress& peer_address,
                                                  btif_acm_sm_event_t event);
void btif_acm_update_lc3q_params(int64_t* cs3, tBTIF_ACM* p_acm_data);

uint16_t btif_acm_bap_to_acm_context(uint16_t bap_context);

std::mutex acm_session_wait_mutex_;
std::condition_variable acm_session_wait_cv;
bool acm_session_wait;


/*****************************************************************************
 *  Local type definitions
 *****************************************************************************/

class BtifCsipEvent {
 public:
  BtifCsipEvent(uint32_t event, const void* p_data, size_t data_length);
  BtifCsipEvent(const BtifCsipEvent& other);
  BtifCsipEvent() = delete;
  ~BtifCsipEvent();
  BtifCsipEvent& operator=(const BtifCsipEvent& other);

  uint32_t Event() const { return event_; }
  void* Data() const { return data_; }
  size_t DataLength() const { return data_length_; }
  std::string ToString() const;
  static std::string EventName(uint32_t event);

 private:
  void DeepCopy(uint32_t event, const void* p_data, size_t data_length);
  void DeepFree();

  uint32_t event_;
  void* data_;
  size_t data_length_;
};

class BtifAcmEvent {
 public:
  BtifAcmEvent(uint32_t event, const void* p_data, size_t data_length);
  BtifAcmEvent(const BtifAcmEvent& other);
  BtifAcmEvent() = delete;
  ~BtifAcmEvent();
  BtifAcmEvent& operator=(const BtifAcmEvent& other);

  uint32_t Event() const { return event_; }
  void* Data() const { return data_; }
  size_t DataLength() const { return data_length_; }
  std::string ToString() const;
  static std::string EventName(uint32_t event);

 private:
  void DeepCopy(uint32_t event, const void* p_data, size_t data_length);
  void DeepFree();

  uint32_t event_;
  void* data_;
  size_t data_length_;
};

class BtifAcmPeer;

class BtifAcmStateMachine : public bluetooth::common::StateMachine {
 public:
  enum {
    kStateIdle,            // ACM state disconnected
    kStateOpening,         // ACM state connecting
    kStateOpened,          // ACM state connected
    kStateStarted,         // ACM state streaming
    kStateReconfiguring,   // ACM state reconfiguring
    kStateClosing,         // ACM state disconnecting
  };

  class StateIdle : public State {
   public:
    StateIdle(BtifAcmStateMachine& sm)
        : State(sm, kStateIdle), peer_(sm.Peer()) {}
    void OnEnter() override;
    void OnExit() override;
    bool ProcessEvent(uint32_t event, void* p_data) override;

   private:
    BtifAcmPeer& peer_;
  };

  class StateOpening : public State {
   public:
    StateOpening(BtifAcmStateMachine& sm)
        : State(sm, kStateOpening), peer_(sm.Peer()) {}
    void OnEnter() override;
    void OnExit() override;
    bool ProcessEvent(uint32_t event, void* p_data) override;

   private:
    BtifAcmPeer& peer_;
  };

  class StateOpened : public State {
   public:
    StateOpened(BtifAcmStateMachine& sm)
        : State(sm, kStateOpened), peer_(sm.Peer()) {}
    void OnEnter() override;
    void OnExit() override;
    bool ProcessEvent(uint32_t event, void* p_data) override;

   private:
    BtifAcmPeer& peer_;
  };

  class StateStarted : public State {
   public:
    StateStarted(BtifAcmStateMachine& sm)
        : State(sm, kStateStarted), peer_(sm.Peer()) {}
    void OnEnter() override;
    void OnExit() override;
    bool ProcessEvent(uint32_t event, void* p_data) override;

   private:
    BtifAcmPeer& peer_;
  };

  class StateReconfiguring : public State {
   public:
    StateReconfiguring(BtifAcmStateMachine& sm)
        : State(sm, kStateReconfiguring), peer_(sm.Peer()) {}
    void OnEnter() override;
    void OnExit() override;
    bool ProcessEvent(uint32_t event, void* p_data) override;

   private:
    BtifAcmPeer& peer_;
  };

  class StateClosing : public State {
   public:
    StateClosing(BtifAcmStateMachine& sm)
        : State(sm, kStateClosing), peer_(sm.Peer()) {}
    void OnEnter() override;
    void OnExit() override;
    bool ProcessEvent(uint32_t event, void* p_data) override;

   private:
    BtifAcmPeer& peer_;
  };

  BtifAcmStateMachine(BtifAcmPeer& btif_acm_peer) : peer_(btif_acm_peer) {
    state_idle_ = new StateIdle(*this);
    state_opening_ = new StateOpening(*this);
    state_opened_ = new StateOpened(*this);
    state_started_ = new StateStarted(*this);
    state_reconfiguring_ = new StateReconfiguring(*this);
    state_closing_ = new StateClosing(*this);

    AddState(state_idle_);
    AddState(state_opening_);
    AddState(state_opened_);
    AddState(state_started_);
    AddState(state_reconfiguring_);
    AddState(state_closing_);
    SetInitialState(state_idle_);
  }

  BtifAcmPeer& Peer() { return peer_; }

 private:
  BtifAcmPeer& peer_;
  StateIdle* state_idle_;
  StateOpening* state_opening_;
  StateOpened* state_opened_;
  StateStarted* state_started_;
  StateReconfiguring* state_reconfiguring_;
  StateClosing* state_closing_;
};

class BtifAcmPeer {
 public:
  enum {
    kFlagPendingLocalSuspend       = 0x01,
    kFlagPendingReconfigure        = 0x02,
    kFlagPendingStart              = 0x04,
    kFlagPendingStop               = 0x08,
    kFLagPendingStartAfterReconfig = 0x10,
  };

  enum {
    kFlagAggresiveMode             = 0x01,
    kFlagRelaxedMode               = 0x02,
  };

  static constexpr uint64_t  kTimeoutLockReleaseMs = 5 * 1000;

  BtifAcmPeer(const RawAddress& peer_address, uint8_t peer_sep,
              uint8_t set_id, uint8_t cig_id, uint8_t cis_id);
  ~BtifAcmPeer();

  bt_status_t Init();
  void Cleanup();

  /**
   * Check whether the peer can be deleted.
   *
   * @return true if the pair can be deleted, otherwise false
   */
  bool CanBeDeleted() const;

  bool IsPeerActiveForMusic() const {
    return (SetId() == MusicActiveSetId());
  }
  bool IsPeerActiveForVoice() const {
    return (SetId() == VoiceActiveSetId());
  }

  bool IsAcceptor() const { return (peer_sep_ == ACM_TSEP_SNK); }

  const RawAddress& MusicActivePeerAddress() const;
  const RawAddress& VoiceActivePeerAddress() const;
  uint8_t MusicActiveSetId() const;
  uint8_t VoiceActiveSetId() const;

  const RawAddress& PeerAddress() const { return peer_address_; }

  void SetContextType(uint16_t contextType) { context_type_ = context_type_ | contextType; }
  uint16_t GetContextType() { return context_type_; }
  void ResetContextType(uint16_t contextType) { context_type_ &= ~contextType; }


  void SetProfileType(uint16_t profileType) { profile_type_ = profile_type_ | profileType; }
  uint16_t GetProfileType() {return profile_type_;}
  void ResetProfileType(uint16_t profileType) { profile_type_ &= ~profileType; }


  void SetRcfgProfileType(uint16_t profileType) { rcfg_profile_type_ = profileType; }
  uint16_t GetRcfgProfileType() {return rcfg_profile_type_;}

  void SetPrefContextType(uint16_t preferredContext) {preferred_context_ = preferredContext;};
  uint16_t GetPrefContextType() {return preferred_context_;}

  void SetStreamContextType(uint16_t contextType) { stream_context_type_ = contextType; }
  uint16_t GetStreamContextType() { return stream_context_type_; }

  void SetPeerVoiceRxState(StreamState state) {voice_rx_state = state;}
  StreamState GetPeerVoiceRxState() {return voice_rx_state;}

  void SetPeerVoiceTxState(StreamState state) {voice_tx_state = state;}
  StreamState GetPeerVoiceTxState() {return voice_tx_state;}

  void SetPeerMusicTxState(StreamState state) {music_tx_state = state;}
  StreamState GetPeerMusicTxState() {return music_tx_state;}

  void SetPeerMusicRxState(StreamState state) {music_rx_state = state;}
  StreamState GetPeerMusicRxState() {return music_rx_state;}

  void SetPeerLatency(uint16_t peerLatency) { peer_latency_ = peerLatency; }
  uint16_t GetPeerLatency() {return peer_latency_;}

  void SetIsStereoHsType(bool stereoHsType) { is_stereohs_type_= stereoHsType; }
  bool IsStereoHsType() {return is_stereohs_type_;}

  void set_peer_media_codec_config(CodecConfig &codec_config) {
      peer_media_codec_config = codec_config;
  }
  CodecConfig get_peer_media_codec_config() {return peer_media_codec_config;}

  void set_peer_media_qos_config(QosConfig &qos_config) {peer_media_qos_config = qos_config;}
  QosConfig get_peer_media_qos_config() {return peer_media_qos_config;}

  void set_peer_media_codec_qos_config(CodecQosConfig &codec_qos_config) {
      peer_media_codec_qos_config = codec_qos_config;}
  CodecQosConfig get_peer_media_codec_qos_config() {return peer_media_codec_qos_config;}

  void set_peer_voice_rx_codec_config(CodecConfig &codec_config) {
      peer_voice_rx_codec_config = codec_config;
  }
  CodecConfig get_peer_voice_rx_codec_config() {return peer_voice_rx_codec_config;}

  void set_peer_voice_rx_qos_config(QosConfig &qos_config) {peer_voice_rx_qos_config = qos_config;}
  QosConfig get_peer_voice_rx_qos_config() {return peer_voice_rx_qos_config;}

  void set_peer_voice_rx_codec_qos_config(CodecQosConfig &codec_qos_config) {
      peer_voice_rx_codec_qos_config = codec_qos_config;}
  CodecQosConfig get_peer_voice_rx_codec_qos_config() {return peer_voice_rx_codec_qos_config;}

  void set_peer_voice_tx_codec_config(CodecConfig &codec_config) {
      peer_voice_tx_codec_config = codec_config;
  }
  CodecConfig get_peer_voice_tx_codec_config() {return peer_voice_tx_codec_config;}

  void set_peer_voice_tx_qos_config(QosConfig &qos_config) {peer_voice_tx_qos_config = qos_config;}
  QosConfig get_peer_voice_tx_qos_config() {return peer_voice_tx_qos_config;}

  void set_peer_voice_tx_codec_qos_config(CodecQosConfig &codec_qos_config) {
      peer_voice_tx_codec_qos_config = codec_qos_config;}
  CodecQosConfig get_peer_voice_tx_codec_qos_config() {return peer_voice_tx_codec_qos_config;}

  uint8_t SetId() const { return set_id_; }
  uint8_t CigId() const { return cig_id_; }
  uint8_t CisId() const { return cis_id_; }

  BtifAcmStateMachine& StateMachine() { return state_machine_; }
  const BtifAcmStateMachine& StateMachine() const { return state_machine_; }

  bool IsConnected() const;
  bool IsStreaming() const;

  bool CheckConnUpdateMode(uint8_t mode) const {
    return (conn_mode_ == mode);
  }

  void SetConnUpdateMode(uint8_t mode) {
    if(conn_mode_ == mode) return;
    if(mode == kFlagAggresiveMode) {
      BTIF_TRACE_DEBUG("%s: push aggressive intervals", __func__);
      L2CA_UpdateBleConnParams(peer_address_, 16, 32, 0, 1000);
    } else if(mode == kFlagRelaxedMode) {
      BTIF_TRACE_DEBUG("%s: push relaxed intervals", __func__);
      L2CA_UpdateBleConnParams(peer_address_, 40, 56, 0, 1000);
    }
    conn_mode_ = mode;
  }

  void ClearConnUpdateMode() { conn_mode_ = 0; }

  bool CheckFlags(uint8_t flags_mask) const {
    return ((flags_ & flags_mask) != 0);
  }

  /**
   * Set only the flags as specified by the flags mask.
   *
   * @param flags_mask the flags to set
   */
  void SetFlags(uint8_t flags_mask) { flags_ |= flags_mask; }

  /**
   * Clear only the flags as specified by the flags mask.
   *
   * @param flags_mask the flags to clear
   */
  void ClearFlags(uint8_t flags_mask) { flags_ &= ~flags_mask; }

  /**
   * Clear all the flags.
   */
  void ClearAllFlags() { flags_ = 0; }

  /**
   * Get string for the flags set.
   */
  std::string FlagsToString() const;

 private:
  const RawAddress peer_address_;
  const uint8_t peer_sep_;// SEP type of peer device
  uint8_t set_id_, cig_id_, cis_id_;
  BtifAcmStateMachine state_machine_;
  uint8_t flags_;
  uint8_t conn_mode_;
  bool is_stereohs_type_ = false;
  StreamState voice_rx_state, voice_tx_state, music_tx_state, music_rx_state;
  uint16_t peer_latency_;
  uint16_t context_type_ = 0;
  uint16_t profile_type_ = 0;
  uint16_t rcfg_profile_type_ = 0;
  uint16_t preferred_context_ = 0;
  uint16_t stream_context_type_ = 0;
  CodecConfig peer_media_codec_config, peer_voice_rx_codec_config, peer_voice_tx_codec_config;
  QosConfig peer_media_qos_config, peer_voice_rx_qos_config, peer_voice_tx_qos_config;
  CodecQosConfig peer_media_codec_qos_config, peer_voice_rx_codec_qos_config, peer_voice_tx_codec_qos_config;
};

static void btif_acm_check_and_cancel_lock_release_timer(uint8_t setId);
bool btif_acm_request_csip_unlock(uint8_t setId);
void btif_acm_process_request(tA2DP_CTRL_CMD cmd);

void btif_acm_source_on_stopped();
void btif_acm_source_on_suspended();
void btif_acm_on_idle(void);
bool btif_acm_check_if_requested_devices_stopped();

void btif_acm_source_cleanup(void);

bt_status_t btif_acm_source_setup_codec();
uint16_t btif_acm_get_active_device_latency();

class BtifAcmInitiator {
 public:
  static constexpr uint8_t kCigIdMin = 0;
  static constexpr uint8_t kCigIdMax = BTA_ACM_NUM_CIGS;
  static constexpr uint8_t kPeerMinSetId = BTA_ACM_MIN_NUM_SETID;
  static constexpr uint8_t kPeerMaxSetId = BTA_ACM_MAX_NUM_SETID;

  enum {
    kFlagStatusUnknown = 0x0,
    kFlagStatusUnlocked = 0x1,
    kFlagStatusPendingLock = 0x2,
    kFlagStatusSubsetLocked = 0x4,
    kFlagStatusLocked = 0x8,
    kFlagStatusPendingUnlock = 0x10,
  };

  // acm group procedure timer
  static constexpr uint64_t kTimeoutAcmGroupProcedureMs = 10 * 1000;
  static constexpr uint64_t kTimeoutConnIntervalMs = 5 * 1000;

  BtifAcmInitiator()
      : callbacks_(nullptr),
        enabled_(false),
        max_connected_peers_(kDefaultMaxConnectedAudioDevices),
        music_active_setid_(INVALID_SET_ID),
        voice_active_setid_(INVALID_SET_ID),
        csip_app_id_(0),
        is_csip_reg_(false),
        lock_flags_(0),
        music_set_lock_release_timer_(nullptr),
        voice_set_lock_release_timer_(nullptr),
        acm_group_procedure_timer_(nullptr),
        acm_conn_interval_timer_(nullptr){}
  ~BtifAcmInitiator();

  bt_status_t Init(
      btacm_initiator_callbacks_t* callbacks, int max_connected_audio_devices,
      const std::vector<CodecConfig>& codec_priorities);
  void Cleanup();
  bool IsSetIdle(uint8_t setId) const;

  btacm_initiator_callbacks_t* Callbacks() { return callbacks_; }
  bool Enabled() const { return enabled_; }

  BtifAcmPeer* FindPeer(const RawAddress& peer_address);
  uint8_t FindPeerSetId(const RawAddress& peer_address);
  uint8_t FindPeerBySetId(uint8_t set_id);
  uint8_t FindPeerCigId(uint8_t set_id);
  uint8_t FindPeerByCigId(uint8_t cig_id);
  uint8_t FindPeerByCisId(uint8_t cig_id, uint8_t cis_id);
  BtifAcmPeer* FindOrCreatePeer(const RawAddress& peer_address);
  BtifAcmPeer* FindMusicActivePeer();

  /**
   * Check whether a connection to a peer is allowed.
   * The check considers the maximum number of connected peers.
   *
   * @param peer_address the peer address to connect to
   * @return true if connection is allowed, otherwise false
   */
  bool AllowedToConnect(const RawAddress& peer_address) const;
  bool IsAcmIdle() const;

  bool IsOtherSetPeersIdle(const RawAddress& peer_address, uint8_t setId) const;

  alarm_t* MusicSetLockReleaseTimer() { return music_set_lock_release_timer_; }
  alarm_t* VoiceSetLockReleaseTimer() { return voice_set_lock_release_timer_; }
  alarm_t* AcmGroupProcedureTimer() { return acm_group_procedure_timer_; }
  alarm_t* AcmConnIntervalTimer() { return acm_conn_interval_timer_; }

  /**
   * Delete a peer.
   *
   * @param peer_address of the peer to be deleted
   * @return true on success, false on failure
   */
  bool DeletePeer(const RawAddress& peer_address);

  /**
   * Delete all peers that are in Idle state and can be deleted.
   */
  void DeleteIdlePeers();

  /**
   * Get the Music active peer.
   *
   * @return the music active peer
   */
  const RawAddress& MusicActivePeer() const { return music_active_peer_; }

  /**
   * Get the Voice active peer.
   *
   * @return the voice active peer
   */
  const RawAddress& VoiceActivePeer() const { return voice_active_peer_; }

  uint8_t MusicActiveCSetId() const { return music_active_setid_; }
  uint8_t VoiceActiveCSetId() const { return voice_active_setid_; }

  void SetCsipAppId(uint8_t csip_app_id) { csip_app_id_ = csip_app_id; }
  uint8_t GetCsipAppId() const { return csip_app_id_; }

  void SetCsipRegistration(bool is_csip_reg) { is_csip_reg_ = is_csip_reg; }
  bool IsCsipRegistered() const { return is_csip_reg_;}

  void SetMusicActiveGroupStarted(bool flag) { is_music_active_set_started_ = flag; }
  bool IsMusicActiveGroupStarted () { return is_music_active_set_started_; }

  bool IsConnUpdateEnabled() const {
    return (is_conn_update_enabled_ == true);
  }

  void SetOrUpdateGroupLockStatus(uint8_t set_id, int lock_status) {
    std::map<uint8_t, int>::iterator p = set_lock_status_.find(set_id);
    if (p == set_lock_status_.end()) {
      set_lock_status_.insert(std::make_pair(set_id, lock_status));
    } else {
      set_lock_status_.erase(set_id);
      set_lock_status_.insert(std::make_pair(set_id, lock_status));
    }
  }

  int GetGroupLockStatus(uint8_t set_id) {
    auto it = set_lock_status_.find(set_id);
    if (it != set_lock_status_.end()) return it->second;
    return kFlagStatusUnknown;
  }

  bool CheckLockFlags(uint8_t bitlockflags_mask) const {
    return ((lock_flags_ & bitlockflags_mask) != 0);
  }

    /**
     * Set only the flags as specified by the bitlockflags_mask.
     *
     * @param bitlockflags_mask the lock flags to set
     */
  void SetLockFlags(uint8_t bitlockflags_mask) { lock_flags_ |= bitlockflags_mask;}

    /**
     * Clear only the flags as specified by the bitlockflags_mask.
     *
     * @param bitlockflags_mask the lock flags to clear
     */
  void ClearLockFlags(uint8_t bitlockflags_mask) { lock_flags_ &= ~bitlockflags_mask;}

    /**
     * Clear all lock flags.
     */
  void ClearAllLockFlags() { lock_flags_ = 0;}

    /**
     * Get a string for lock flags.
     */
  std::string LockFlagsToString() const;

  bool SetAcmActivePeer(const RawAddress& peer_address, uint16_t contextType, uint16_t profileType,
                        std::promise<void> peer_ready_promise) {
    LOG(INFO) << __PRETTY_FUNCTION__ << ": peer: " << peer_address
           << " music_active_peer_: " << music_active_peer_ << " voice_active_peer_: " << voice_active_peer_;
    uint16_t sink_latency;
    active_bda = peer_address;// for stereo LEA active_bda = peer_address
    BtifAcmPeer* peer = FindPeer(peer_address);
    BTIF_TRACE_DEBUG("%s address byte BDA:%02x", __func__,active_bda.address[5]);
    if (contextType == CONTEXT_TYPE_MUSIC) {
      if (music_active_peer_ == active_bda) {
        //Same active device, profileType may have changed.
        if ((peer != nullptr) && (current_active_profile_type != 0) && (current_active_profile_type != profileType)) {
          BTIF_TRACE_DEBUG("%s current_active_profile_type %d, profileType %d peer->GetProfileType() %d",
                  __func__, current_active_profile_type, profileType, peer->GetProfileType());
          if ((peer->GetProfileType() & profileType) == 0) {
            std::unique_lock<std::mutex> guard(acm_session_wait_mutex_);
            acm_session_wait = false;
            if (reconfig_acm_initiator(peer_address, profileType)) {
              acm_session_wait_cv.wait_for(guard, std::chrono::milliseconds(3000), []{return acm_session_wait;});
              BTIF_TRACE_EVENT("%s: done with signal",__func__);
            }
          } else {
            current_active_profile_type = profileType;
            if (current_active_profile_type != WMCP)
              current_active_config = current_media_config;
            else
              current_active_config = current_recording_config;
            if (!btif_acm_source_restart_session(music_active_peer_, active_bda)) {
              // cannot set promise but need to be handled within restart_session
              return false;
            }
            if (current_active_profile_type == WMCP) {
              sink_latency = btif_acm_get_active_device_latency();
              BTIF_TRACE_EVENT("%s: sink_latency = %dms", __func__, sink_latency);
              if ((sink_latency > 0) && !btif_acm_update_sink_latency_change(sink_latency * 10)) {
                BTIF_TRACE_ERROR("%s: unable to update latency", __func__);
              }
            }
          }
          peer_ready_promise.set_value();
          return true;
        } else {
          peer_ready_promise.set_value();
          return true;
        }
      }

      if (active_bda.IsEmpty()) {
        BTIF_TRACE_EVENT("%s: set address is empty, shutdown the Acm initiator",
                         __func__);
        btif_acm_check_and_cancel_lock_release_timer(music_active_setid_);
        if ((GetGroupLockStatus(music_active_setid_) == BtifAcmInitiator::kFlagStatusLocked) ||
            (GetGroupLockStatus(music_active_setid_) == BtifAcmInitiator::kFlagStatusSubsetLocked)) {
          if (!btif_acm_request_csip_unlock(music_active_setid_)) {
            BTIF_TRACE_ERROR("%s: error unlocking", __func__);
          }
        }
        btif_acm_source_end_session(music_active_peer_);
        music_active_peer_ = active_bda;
        current_active_profile_type = 0;
        memset(&current_active_config, 0, sizeof(current_active_config));
        peer_ready_promise.set_value();
        return true;
      }

      btif_acm_check_and_cancel_lock_release_timer(music_active_setid_);
      if ((GetGroupLockStatus(music_active_setid_) == BtifAcmInitiator::kFlagStatusLocked) ||
          (GetGroupLockStatus(music_active_setid_) == BtifAcmInitiator::kFlagStatusSubsetLocked)) {
        if (!btif_acm_request_csip_unlock(music_active_setid_)) {
          BTIF_TRACE_ERROR("%s: error unlocking", __func__);
        }
      }

      /*check if previous active device is streaming, then STOP it first*/
      if (!music_active_peer_.IsEmpty()) {
        int setid = music_active_setid_;
        if (setid < INVALID_SET_ID) {
          tBTA_CSIP_CSET cset_info;
          memset(&cset_info, 0, sizeof(tBTA_CSIP_CSET));
          cset_info = BTA_CsipGetCoordinatedSet(setid);
          if (cset_info.size != 0) {
            std::vector<RawAddress>::iterator itr;
            BTIF_TRACE_DEBUG("%s: size of set members %d", __func__, (cset_info.set_members).size());
            if ((cset_info.set_members).size() > 0) {
              for (itr =(cset_info.set_members).begin(); itr != (cset_info.set_members).end(); itr++) {
                BtifAcmPeer* grp_peer = FindPeer(*itr);
                if (grp_peer != nullptr && grp_peer->IsStreaming()) {
                  BTIF_TRACE_DEBUG("%s: peer is streaming %s ", __func__, grp_peer->PeerAddress().ToString().c_str());
                  btif_acm_initiator_dispatch_sm_event(*itr, BTIF_ACM_STOP_STREAM_REQ_EVT);
                }
              }
            }
          }
        } else {
          BTIF_TRACE_DEBUG("%s: music_active_peer_ is twm device ", __func__);
          BtifAcmPeer* twm_peer = FindPeer(music_active_peer_);
          if (twm_peer != nullptr && twm_peer->IsStreaming()) {
            BTIF_TRACE_DEBUG("%s: music_active_peer_ %s is streaming, send stop ", __func__, twm_peer->PeerAddress().ToString().c_str());
            btif_acm_initiator_dispatch_sm_event(music_active_peer_, BTIF_ACM_STOP_STREAM_REQ_EVT);
          }
        }
      }

      if ((peer != nullptr) && ((peer->GetProfileType() & profileType) == 0)) {
        BTIF_TRACE_DEBUG("%s peer.GetProfileType() %d, profileType %d", __func__, peer->GetProfileType(), profileType);
        std::unique_lock<std::mutex> guard(acm_session_wait_mutex_);
        acm_session_wait = false;
        if (reconfig_acm_initiator(peer_address, profileType)) {
          acm_session_wait_cv.wait_for(guard, std::chrono::milliseconds(3000), []{return acm_session_wait;});
          BTIF_TRACE_EVENT("%s: done with signal",__func__);
        }
      } else {
        current_active_profile_type = profileType;
        if (current_active_profile_type != WMCP)
          current_active_config = current_media_config;
        else
          current_active_config = current_recording_config;
        if (!btif_acm_source_restart_session(music_active_peer_, active_bda)) {
          // cannot set promise but need to be handled within restart_session
          return false;
        }
      }
      music_active_peer_ = active_bda;
      if (active_bda.address[0] == 0x9E && active_bda.address[1] == 0x8B && active_bda.address[2] == 0x00) {
        BTIF_TRACE_DEBUG("%s: get set ID from group BD address ", __func__);
        music_active_setid_ = active_bda.address[5];
      } else {
        BTIF_TRACE_DEBUG("%s: get set ID from peer data ", __func__);
        if (peer != nullptr)
          music_active_setid_ = peer->SetId();
      }

      if (current_active_profile_type == WMCP) {
        sink_latency = btif_acm_get_active_device_latency();
        BTIF_TRACE_EVENT("%s: sink_latency = %dms", __func__, sink_latency);
        if ((sink_latency > 0) && !btif_acm_update_sink_latency_change(sink_latency * 10)) {
          BTIF_TRACE_ERROR("%s: unable to update latency", __func__);
        }
      }
      peer_ready_promise.set_value();
      return true;
    } else if (contextType == CONTEXT_TYPE_VOICE) {
      if (voice_active_peer_ == active_bda) {
        peer_ready_promise.set_value();
        return true;
      }
      if (active_bda.IsEmpty()) {
        BTIF_TRACE_EVENT("%s: peer address is empty, shutdown the acm initiator",
                         __func__);
        voice_active_peer_ = active_bda;
        peer_ready_promise.set_value();
        return true;
      }

      /*check if previous active device is streaming, then STOP it first*/
      if (!voice_active_peer_.IsEmpty()) {
        int setid = voice_active_setid_;
        if (setid < INVALID_SET_ID) {
          tBTA_CSIP_CSET cset_info;
          memset(&cset_info, 0, sizeof(tBTA_CSIP_CSET));
          cset_info = BTA_CsipGetCoordinatedSet(setid);
          if (cset_info.size != 0) {
            std::vector<RawAddress>::iterator itr;
            BTIF_TRACE_DEBUG("%s: size of set members %d", __func__, (cset_info.set_members).size());
            if ((cset_info.set_members).size() > 0) {
              for (itr =(cset_info.set_members).begin(); itr != (cset_info.set_members).end(); itr++) {
                BtifAcmPeer* grp_peer = FindPeer(*itr);
                if (grp_peer != nullptr && grp_peer->IsStreaming()) {
                  BTIF_TRACE_DEBUG("%s: voice peer is streaming %s ", __func__, grp_peer->PeerAddress().ToString().c_str());
                  btif_acm_initiator_dispatch_sm_event(*itr, BTIF_ACM_STOP_STREAM_REQ_EVT);
                }
              }
            }
          }
        } else {
          BTIF_TRACE_DEBUG("%s: voice_active_peer_ is twm device ", __func__);
          BtifAcmPeer* twm_peer = FindPeer(voice_active_peer_);
          if (twm_peer != nullptr && twm_peer->IsStreaming()) {
            BTIF_TRACE_DEBUG("%s: voice_active_peer_ %s is streaming, send stop ", __func__, twm_peer->PeerAddress().ToString().c_str());
            btif_acm_initiator_dispatch_sm_event(voice_active_peer_, BTIF_ACM_STOP_STREAM_REQ_EVT);
          }
        }
      }

      voice_active_peer_ = active_bda;
      if (active_bda.address[0] == 0x9E && active_bda.address[1] == 0x8B && active_bda.address[2] == 0x00) {
        BTIF_TRACE_DEBUG("%s: get set ID from group BD address ", __func__);
        voice_active_setid_ = active_bda.address[5];
      } else {
        BTIF_TRACE_DEBUG("%s: get set ID from peer data ", __func__);
        if (peer != nullptr)
          voice_active_setid_ = peer->SetId();
      }
      peer_ready_promise.set_value();
      return true;
    } else {
      peer_ready_promise.set_value();
      return true;
    }
  }

  void btif_acm_initiator_encoder_user_config_update_req(
      const RawAddress& peer_addr,
      const std::vector<CodecConfig>& codec_user_preferences,
      std::promise<void> peer_ready_promise);


  void UpdateCodecConfig(
      const RawAddress& peer_address,
      const std::vector<CodecConfig>& codec_preferences,
      int contextType,
      int profileType,
      std::promise<void> peer_ready_promise) {
    // Restart the session if the codec for the active peer is updated
    if (!peer_address.IsEmpty() && music_active_peer_ == peer_address) {
      btif_acm_source_end_session(music_active_peer_);
    }

    btif_acm_initiator_encoder_user_config_update_req(
        peer_address, codec_preferences, std::move(peer_ready_promise));
  }

  const std::map<RawAddress, BtifAcmPeer*>& Peers() const { return peers_; }
 // const std::map<uint8_t, BtifAcmPeer*>& SetPeers() const { return set_peers_; }

  std::vector<RawAddress> locked_devices;
 private:
  void CleanupAllPeers();

  btacm_initiator_callbacks_t* callbacks_;
  bool enabled_;
  int max_connected_peers_;

  RawAddress music_active_peer_;
  RawAddress voice_active_peer_;
  uint8_t music_active_setid_;
  uint8_t voice_active_setid_;
  uint8_t music_active_set_locked_dev_count_;
  uint8_t voice_active_set_locked_dev_count_;
  bool is_music_active_set_started_;
  bool is_voice_active_set_started_;
  bool is_conn_update_enabled_;

  uint8_t csip_app_id_;
  bool is_csip_reg_;
  uint8_t lock_flags_;

  alarm_t* music_set_lock_release_timer_;
  alarm_t* voice_set_lock_release_timer_;
  alarm_t* acm_group_procedure_timer_;
  alarm_t* acm_conn_interval_timer_;


  std::map<RawAddress, BtifAcmPeer*> peers_;
  std::map<RawAddress, uint8_t> addr_setid_pair;
  std::map<uint8_t, uint8_t> set_cig_pair;//setid and cig id pair
  std::map<RawAddress, std::map<uint8_t, uint8_t> > cig_cis_pair;//cig id and cis id pair
  std::map<uint8_t, int> set_lock_status_;
};


/*****************************************************************************
 *  Static variables
 *****************************************************************************/
static BtifAcmInitiator btif_acm_initiator;
std::vector<CodecConfig> unicast_codecs_capabilities;
static CodecConfig acm_local_capability =
                           {CodecIndex::CODEC_INDEX_SOURCE_LC3,
                            CodecPriority::CODEC_PRIORITY_DEFAULT,
                            CodecSampleRate::CODEC_SAMPLE_RATE_48000,
                            CodecBPS::CODEC_BITS_PER_SAMPLE_24,
                            CodecChannelMode::CODEC_CHANNEL_MODE_STEREO, 0, 0, 0, 0};
static CodecConfig default_config;
static bool mandatory_codec_selected = false;
static bt_status_t disconnect_acm_initiator(const RawAddress& peer_address,
                                            uint16_t contextType);

static bt_status_t start_stream_acm_initiator(const RawAddress& peer_address,
                                              uint16_t contextType);
static bt_status_t stop_stream_acm_initiator(const RawAddress& peer_address,
                                             uint16_t contextType);

static void btif_acm_handle_csip_status_locked(std::vector<RawAddress> addr, uint8_t setId);

static void btif_acm_handle_evt(uint16_t event, char* p_param);
static void btif_report_connection_state(const RawAddress& peer_address,
                                         btacm_connection_state_t state, uint16_t contextType);
static void btif_report_audio_state(const RawAddress& peer_address,
                                    btacm_audio_state_t state, uint16_t contextType);

static void btif_acm_check_and_start_lock_release_timer(uint8_t setId);

static void btif_acm_initiator_lock_release_timer_timeout(void* data);

static void btif_acm_check_and_start_group_procedure_timer(uint8_t setId);
static void btif_acm_check_and_start_conn_Interval_timer(BtifAcmPeer* peer);
static void btif_acm_initiator_conn_Interval_timer_timeout(void *data);
static void btif_acm_check_and_cancel_conn_Interval_timer();


static void btif_acm_check_and_cancel_group_procedure_timer(uint8_t setId);
static void btif_acm_initiator_group_procedure_timer_timeout(void *data);
static void SelectCodecQosConfig(const RawAddress& bd_addr, int profile_type,
                                 int context_type, int direction, int config_type);
bool compare_codec_config_(CodecConfig &first, CodecConfig &second);
void print_codec_parameters(CodecConfig config);
void print_qos_parameters(QosConfig qos_config);
void select_best_codec_config(const RawAddress& bd_addr, uint16_t context_type,
                              uint8_t profile_type, CodecConfig *codec_config, int dir, int config_type);
static UcastClientInterface* sUcastClientInterface = nullptr;

/*****************************************************************************
 * Local helper functions
 *****************************************************************************/

const char* dump_acm_sm_event_name(btif_acm_sm_event_t event) {
  switch ((int)event) {
    CASE_RETURN_STR(BTA_ACM_DISCONNECT_EVT)
    CASE_RETURN_STR(BTA_ACM_CONNECT_EVT)
    CASE_RETURN_STR(BTA_ACM_START_EVT)
    CASE_RETURN_STR(BTA_ACM_STOP_EVT)
    CASE_RETURN_STR(BTA_ACM_RECONFIG_EVT)
    CASE_RETURN_STR(BTA_ACM_CONFIG_EVT)
    CASE_RETURN_STR(BTIF_ACM_CONNECT_REQ_EVT)
    CASE_RETURN_STR(BTIF_ACM_DISCONNECT_REQ_EVT)
    CASE_RETURN_STR(BTIF_ACM_START_STREAM_REQ_EVT)
    CASE_RETURN_STR(BTIF_ACM_STOP_STREAM_REQ_EVT)
    CASE_RETURN_STR(BTIF_ACM_SUSPEND_STREAM_REQ_EVT)
    CASE_RETURN_STR(BTIF_ACM_RECONFIG_REQ_EVT)
    CASE_RETURN_STR(BTA_ACM_CONN_UPDATE_TIMEOUT_EVT)
    default:
      return "UNKNOWN_EVENT";
  }
}

const char* dump_csip_event_name(btif_csip_sm_event_t event) {
  switch ((int)event) {
    CASE_RETURN_STR(BTA_CSIP_NEW_SET_FOUND_EVT)
    CASE_RETURN_STR(BTA_CSIP_SET_MEMBER_FOUND_EVT)
    CASE_RETURN_STR(BTA_CSIP_CONN_STATE_CHG_EVT)
    CASE_RETURN_STR(BTA_CSIP_LOCK_STATUS_CHANGED_EVT)
    CASE_RETURN_STR(BTA_CSIP_LOCK_AVAILABLE_EVT)
    CASE_RETURN_STR(BTA_CSIP_SET_SIZE_CHANGED)
    CASE_RETURN_STR(BTA_CSIP_SET_SIRK_CHANGED)
    default:
      return "UNKNOWN_EVENT";
  }
}

void btif_acm_signal_session_ready() {
  std::unique_lock<std::mutex> guard(acm_session_wait_mutex_);
  if(!acm_session_wait) {
    acm_session_wait = true;
    acm_session_wait_cv.notify_all();
  } else {
    BTIF_TRACE_WARNING("%s: already signalled ",__func__);
  }
}

void fetch_media_tx_codec_qos_config(const RawAddress& bd_addr, int profile_type, StreamConnect *conn_media) {
    BTIF_TRACE_DEBUG("%s: Peer %s , profile_type: %d", __func__, bd_addr.ToString().c_str(), profile_type);
    CodecQosConfig conf;
    BtifAcmPeer* peer = btif_acm_initiator.FindPeer(bd_addr);
    if (peer == nullptr) {
      BTIF_TRACE_WARNING("%s: peer is NULL", __func__);
      return;
    }
    if (peer->IsStereoHsType()) {
      //Stereo HS config 1
      SelectCodecQosConfig(peer->PeerAddress(), profile_type, MEDIA_CONTEXT, SNK, STEREO_HS_CONFIG_1);
      conf = peer->get_peer_media_codec_qos_config();
      print_codec_parameters(conf.codec_config);
      print_qos_parameters(conf.qos_config);
      conn_media->codec_qos_config_pair.push_back(conf);
    } else {
      //EB config
      SelectCodecQosConfig(peer->PeerAddress(), profile_type, MEDIA_CONTEXT, SNK, EB_CONFIG);
      conf = peer->get_peer_media_codec_qos_config();
      print_codec_parameters(conf.codec_config);
      print_qos_parameters(conf.qos_config);
      conn_media->codec_qos_config_pair.push_back(conf);
    }
    conn_media->stream_type.type = CONTENT_TYPE_MEDIA;
    conn_media->stream_type.audio_context = CONTENT_TYPE_MEDIA;
    conn_media->stream_type.direction = ASE_DIRECTION_SINK;
}

void fetch_media_rx_codec_qos_config(const RawAddress& bd_addr, int profile_type, StreamConnect *conn_media) {
    BTIF_TRACE_DEBUG("%s: Peer %s , profile_type: %d", __func__, bd_addr.ToString().c_str(), profile_type);
    CodecQosConfig conf;
    BtifAcmPeer* peer = btif_acm_initiator.FindPeer(bd_addr);
    if (peer == nullptr) {
      BTIF_TRACE_WARNING("%s: peer is NULL", __func__);
      return;
    }
    if (peer->IsStereoHsType()) {
      //Stereo HS config 1
      SelectCodecQosConfig(peer->PeerAddress(), WMCP, MEDIA_CONTEXT, SRC, STEREO_HS_CONFIG_1);
      conf = peer->get_peer_media_codec_qos_config();
      print_codec_parameters(conf.codec_config);
      print_qos_parameters(conf.qos_config);
      conn_media->codec_qos_config_pair.push_back(conf);
    } else {
      //EB config
      SelectCodecQosConfig(peer->PeerAddress(), WMCP, MEDIA_CONTEXT, SRC, EB_CONFIG);
      conf = peer->get_peer_media_codec_qos_config();
      print_codec_parameters(conf.codec_config);
      print_qos_parameters(conf.qos_config);
      conn_media->codec_qos_config_pair.push_back(conf);
    }
    conn_media->stream_type.type = CONTENT_TYPE_MEDIA;
    conn_media->stream_type.audio_context = CONTENT_TYPE_LIVE; //Live audio context
    conn_media->stream_type.direction = ASE_DIRECTION_SRC;
}

void fetch_voice_rx_codec_qos_config(const RawAddress& bd_addr, int profile_type, StreamConnect *conn_voice) {
    BTIF_TRACE_DEBUG("%s: Peer %s , profile_type: %d", __func__, bd_addr.ToString().c_str(), profile_type);
    CodecQosConfig conf;
    BtifAcmPeer* peer = btif_acm_initiator.FindPeer(bd_addr);
    if (peer == nullptr) {
      BTIF_TRACE_WARNING("%s: peer is NULL", __func__);
      return;
    }
    if (peer->IsStereoHsType()) {
      //Stereo HS config 1
      SelectCodecQosConfig(peer->PeerAddress(), BAP, VOICE_CONTEXT, SRC, STEREO_HS_CONFIG_1);
      conf = peer->get_peer_voice_rx_codec_qos_config();
      print_codec_parameters(conf.codec_config);
      print_qos_parameters(conf.qos_config);
      conn_voice->codec_qos_config_pair.push_back(conf);
    } else {
      // EB config
      SelectCodecQosConfig(peer->PeerAddress(), BAP, VOICE_CONTEXT, SRC, EB_CONFIG);
      conf = peer->get_peer_voice_rx_codec_qos_config();
      print_codec_parameters(conf.codec_config);
      print_qos_parameters(conf.qos_config);
      conn_voice->codec_qos_config_pair.push_back(conf);
    }
    conn_voice->stream_type.type = CONTENT_TYPE_CONVERSATIONAL;
    conn_voice->stream_type.audio_context = CONTENT_TYPE_CONVERSATIONAL;
    conn_voice->stream_type.direction = ASE_DIRECTION_SRC;
}

void fetch_voice_tx_codec_qos_config(const RawAddress& bd_addr, int profile_type, StreamConnect *conn_voice) {
    BTIF_TRACE_DEBUG("%s: Peer %s , profile_type: %d", __func__, bd_addr.ToString().c_str(), profile_type);
    CodecQosConfig conf;
    BtifAcmPeer* peer = btif_acm_initiator.FindPeer(bd_addr);
    if (peer == nullptr) {
      BTIF_TRACE_WARNING("%s: peer is NULL", __func__);
      return;
    }
    if (peer->IsStereoHsType()) {
      //Stereo HS config 1
      SelectCodecQosConfig(peer->PeerAddress(), BAP, VOICE_CONTEXT, SNK, STEREO_HS_CONFIG_1);
      conf = peer->get_peer_voice_tx_codec_qos_config();
      print_codec_parameters(conf.codec_config);
      print_qos_parameters(conf.qos_config);
      conn_voice->codec_qos_config_pair.push_back(conf);
    } else {
      // EB config
      SelectCodecQosConfig(peer->PeerAddress(), BAP, VOICE_CONTEXT, SNK, EB_CONFIG);
      conf = peer->get_peer_voice_tx_codec_qos_config();
      print_codec_parameters(conf.codec_config);
      print_qos_parameters(conf.qos_config);
      conn_voice->codec_qos_config_pair.push_back(conf);
    }
    conn_voice->stream_type.type = CONTENT_TYPE_CONVERSATIONAL;
    conn_voice->stream_type.audio_context = CONTENT_TYPE_CONVERSATIONAL;
    conn_voice->stream_type.direction = ASE_DIRECTION_SINK;
}

BtifAcmEvent::BtifAcmEvent(uint32_t event, const void* p_data, size_t data_length)
    : event_(event), data_(nullptr), data_length_(0) {
  DeepCopy(event, p_data, data_length);
}

BtifAcmEvent::BtifAcmEvent(const BtifAcmEvent& other)
    : event_(0), data_(nullptr), data_length_(0) {
  *this = other;
}

BtifAcmEvent& BtifAcmEvent::operator=(const BtifAcmEvent& other) {
  DeepFree();
  DeepCopy(other.Event(), other.Data(), other.DataLength());
  return *this;
}

BtifAcmEvent::~BtifAcmEvent() { DeepFree(); }

std::string BtifAcmEvent::ToString() const {
  return BtifAcmEvent::EventName(event_);
}

std::string BtifAcmEvent::EventName(uint32_t event) {
  std::string name = dump_acm_sm_event_name((btif_acm_sm_event_t)event);
  std::stringstream ss_value;
  ss_value << "(0x" << std::hex << event << ")";
  return name + ss_value.str();
}

void BtifAcmEvent::DeepCopy(uint32_t event, const void* p_data,
                           size_t data_length) {
  event_ = event;
  data_length_ = data_length;
  if (data_length == 0) {
    data_ = nullptr;
  } else {
    data_ = osi_malloc(data_length_);
    memcpy(data_, p_data, data_length);
  }
}

void BtifAcmEvent::DeepFree() {
  osi_free_and_reset((void**)&data_);
  data_length_ = 0;
}

BtifCsipEvent::BtifCsipEvent(uint32_t event, const void* p_data, size_t data_length)
    : event_(event), data_(nullptr), data_length_(0) {
  DeepCopy(event, p_data, data_length);
}

BtifCsipEvent::BtifCsipEvent(const BtifCsipEvent& other)
    : event_(0), data_(nullptr), data_length_(0) {
  *this = other;
}

BtifCsipEvent& BtifCsipEvent::operator=(const BtifCsipEvent& other) {
  DeepFree();
  DeepCopy(other.Event(), other.Data(), other.DataLength());
  return *this;
}

BtifCsipEvent::~BtifCsipEvent() { DeepFree(); }

std::string BtifCsipEvent::ToString() const {
  return BtifCsipEvent::EventName(event_);
}

std::string BtifCsipEvent::EventName(uint32_t event) {
  std::string name = dump_csip_event_name((btif_csip_sm_event_t)event);
  std::stringstream ss_value;
  ss_value << "(0x" << std::hex << event << ")";
  return name + ss_value.str();
}

void BtifCsipEvent::DeepCopy(uint32_t event, const void* p_data,
                           size_t data_length) {
  event_ = event;
  data_length_ = data_length;
  if (data_length == 0) {
    data_ = nullptr;
  } else {
    data_ = osi_malloc(data_length_);
    memcpy(data_, p_data, data_length);
  }
}

void BtifCsipEvent::DeepFree() {
  osi_free_and_reset((void**)&data_);
  data_length_ = 0;
}

BtifAcmPeer::BtifAcmPeer(const RawAddress& peer_address, uint8_t peer_sep,
                         uint8_t set_id, uint8_t cig_id, uint8_t cis_id)
    : peer_address_(peer_address),
      peer_sep_(peer_sep),
      set_id_(set_id),
      cig_id_(cig_id),
      cis_id_(cis_id),
      state_machine_(*this),
      flags_(0) {}

BtifAcmPeer::~BtifAcmPeer() { /*alarm_free(av_open_on_rc_timer_);*/ }

std::string BtifAcmPeer::FlagsToString() const {
  std::string result;

  if (flags_ & BtifAcmPeer::kFlagPendingLocalSuspend) {
    if (!result.empty()) result += "|";
    result += "LOCAL_SUSPEND_PENDING";
  }
  if (flags_ & BtifAcmPeer::kFlagPendingReconfigure) {
    if (!result.empty()) result += "|";
    result += "PENDING_RECONFIGURE";
  }
  if (flags_ & BtifAcmPeer::kFlagPendingStart) {
    if (!result.empty()) result += "|";
    result += "PENDING_START";
  }
  if (flags_ & BtifAcmPeer::kFlagPendingStop) {
    if (!result.empty()) result += "|";
    result += "PENDING_STOP";
  }
  if (flags_ & BtifAcmPeer::kFLagPendingStartAfterReconfig) {
    if (!result.empty()) result += "|";
    result += "PENDING_START_AFTER_RECONFIG";
  }
  if (result.empty()) result = "None";

  return base::StringPrintf("0x%x(%s)", flags_, result.c_str());
}

bt_status_t BtifAcmPeer::Init() {
  state_machine_.Start();
  return BT_STATUS_SUCCESS;
}

void BtifAcmPeer::Cleanup() {
  state_machine_.Quit();
}

bool BtifAcmPeer::CanBeDeleted() const {
  return (
      (state_machine_.StateId() == BtifAcmStateMachine::kStateIdle) &&
      (state_machine_.PreviousStateId() != BtifAcmStateMachine::kStateInvalid));
}

const RawAddress& BtifAcmPeer::MusicActivePeerAddress() const {
  return btif_acm_initiator.MusicActivePeer();
}
const RawAddress& BtifAcmPeer::VoiceActivePeerAddress() const {
  return btif_acm_initiator.VoiceActivePeer();
}
uint8_t BtifAcmPeer::MusicActiveSetId() const {
  return btif_acm_initiator.MusicActiveCSetId();
}
uint8_t BtifAcmPeer::VoiceActiveSetId() const {
  return btif_acm_initiator.VoiceActiveCSetId();
}

bool BtifAcmPeer::IsConnected() const {
  int state = state_machine_.StateId();
  return ((state == BtifAcmStateMachine::kStateOpened) ||
          (state == BtifAcmStateMachine::kStateStarted));
}

bool BtifAcmPeer::IsStreaming() const {
  int state = state_machine_.StateId();
  return (state == BtifAcmStateMachine::kStateStarted);
}

BtifAcmInitiator::~BtifAcmInitiator() {
  CleanupAllPeers();
}

void init_local_capabilities() {
  unicast_codecs_capabilities.push_back(acm_local_capability);
}

void BtifAcmInitiator::Cleanup() {
  LOG_INFO(LOG_TAG, "%s", __PRETTY_FUNCTION__);
  if (!enabled_) return;
  std::promise<void> peer_ready_promise;
  btif_disable_service(BTA_ACM_INITIATOR_SERVICE_ID); // ACM deregistration required?
  CleanupAllPeers();
  alarm_free(music_set_lock_release_timer_);
  music_set_lock_release_timer_ = nullptr;
  alarm_free(music_set_lock_release_timer_);
  music_set_lock_release_timer_ = nullptr;
  alarm_free(acm_group_procedure_timer_);
  acm_group_procedure_timer_ = nullptr;
  alarm_free(acm_conn_interval_timer_);
  acm_conn_interval_timer_ = nullptr;
  callbacks_ = nullptr;
  enabled_ = false;
  if (sUcastClientInterface != nullptr) {
    sUcastClientInterface->Cleanup();
    sUcastClientInterface = nullptr;
  }
}

BtifAcmPeer* BtifAcmInitiator::FindPeer(const RawAddress& peer_address) {
  auto it = peers_.find(peer_address);
  if (it != peers_.end()) return it->second;
  return nullptr;
}

uint8_t BtifAcmInitiator:: FindPeerSetId(const RawAddress& peer_address) {
    auto it = addr_setid_pair.find(peer_address);
    if (it != addr_setid_pair.end()) return it->second;
    return 0xff;
}

uint8_t BtifAcmInitiator:: FindPeerBySetId(uint8_t setid) {
  for (auto it : addr_setid_pair) {
    if (it.second == setid) {
      return setid;
    }
  }
  return 0xff;
}

uint8_t BtifAcmInitiator:: FindPeerCigId(uint8_t setid) {
    auto it = set_cig_pair.find(setid);
    if (it != set_cig_pair.end()) return it->second;
    return 0xff;
}

uint8_t BtifAcmInitiator:: FindPeerByCigId(uint8_t cigid) {
  for (auto it : set_cig_pair) {
    if (it.second == cigid) {
      return cigid;
    }
  }
  return 0xff;
}

uint8_t BtifAcmInitiator:: FindPeerByCisId(uint8_t cigid, uint8_t cisid) {
  for (auto itr = cig_cis_pair.begin(); itr != cig_cis_pair.end(); itr++) {
    for (auto ptr = itr->second.begin(); ptr != itr->second.end(); ptr++) {
      if (ptr->first == cigid) {
        if (ptr->second == cisid) {
          return cisid;
        }
      }
    }
  }
  return 0xff;
}

BtifAcmPeer* BtifAcmInitiator::FindOrCreatePeer(const RawAddress& peer_address) {
  BTIF_TRACE_DEBUG("%s: peer_address=%s ", __PRETTY_FUNCTION__,
                   peer_address.ToString().c_str());

  BtifAcmPeer* peer = FindPeer(peer_address);
  if (peer != nullptr) return peer;

  uint8_t SetId, CigId, CisId;
  //get the set id from CSIP.
  //TODO: need UUID ?
  Uuid uuid = Uuid::kEmpty;
  LOG_INFO(LOG_TAG, "%s ACM UUID = %s", __func__, uuid.ToString().c_str());
  SetId = BTA_CsipGetDeviceSetId(peer_address, uuid);
  BTIF_TRACE_EVENT("%s: set id from csip : %d", __func__, SetId);
  if (SetId == INVALID_SET_ID) {
    SetId = FindPeerSetId(peer_address);
    // Find next available SET ID to use
    if (SetId == 0xff) {
      for (SetId = kPeerMinSetId; SetId < kPeerMaxSetId; SetId++) {
        if (FindPeerBySetId(SetId) == 0xff) break;
      }
    }
  }
  if (SetId == kPeerMaxSetId) {
    BTIF_TRACE_ERROR(
        "%s: Cannot create peer for peer_address=%s : "
        "cannot allocate unique SET ID",
        __PRETTY_FUNCTION__, peer_address.ToString().c_str());
    return nullptr;
  }
  addr_setid_pair.insert(std::make_pair(peer_address, SetId));

  //Find next available CIG ID to use
  CigId = FindPeerCigId(SetId);
  if (CigId == 0xff) {
    for (CigId = kCigIdMin; CigId < kCigIdMax; ) {
      if (FindPeerByCigId(CigId) == 0xff) break;
      CigId += 4;
    }
  }
  if (CigId == kCigIdMax) {
    BTIF_TRACE_ERROR(
        "%s: cannot allocate unique CIG ID to = %s ",
        __func__, peer_address.ToString().c_str());
    return nullptr;
  }
  set_cig_pair.insert(std::make_pair(SetId, CigId));

  //Find next available CIS ID to use
  for (CisId = kCigIdMin; CisId < kCigIdMax; CisId++) {
    if (FindPeerByCisId(CigId, CisId) == 0xff) break;
  }
  if (CisId == kCigIdMax) {
    BTIF_TRACE_ERROR(
        "%s: cannot allocate unique CIS ID to = %s ",
        __func__, peer_address.ToString().c_str());
    return nullptr;
  }
  cig_cis_pair.insert(std::make_pair(peer_address, map<uint8_t, uint8_t>()));
  cig_cis_pair[peer_address].insert(std::make_pair(CigId, CisId));

  LOG_INFO(LOG_TAG,
           "%s: Create peer: peer_address=%s, set_id=%d, cig_id=%d, cis_id=%d",
           __PRETTY_FUNCTION__, peer_address.ToString().c_str(), SetId, CigId, CisId);
  peer = new BtifAcmPeer(peer_address, ACM_TSEP_SNK, SetId, CigId, CisId);
  peer->SetPeerVoiceTxState(StreamState::DISCONNECTED);
  peer->SetPeerVoiceRxState(StreamState::DISCONNECTED);
  peer->SetPeerMusicTxState(StreamState::DISCONNECTED);
  peer->SetPeerMusicRxState(StreamState::DISCONNECTED);
  if (SetId >= kPeerMinSetId && SetId < kPeerMaxSetId) {
    LOG_INFO(LOG_TAG,
             "%s: Created peer is TWM device",__PRETTY_FUNCTION__);
    peer->SetIsStereoHsType(true);
  }
  peers_.insert(std::make_pair(peer_address, peer));
  peer->Init();
  return peer;
}

BtifAcmPeer* BtifAcmInitiator::FindMusicActivePeer() {
  for (auto it : peers_) {
    BtifAcmPeer* peer = it.second;
    if (peer->IsPeerActiveForMusic()) {
      return peer;
    }
  }
  return nullptr;
}

bool BtifAcmInitiator::AllowedToConnect(const RawAddress& peer_address) const {
  int connected = 0;

  // Count peers that are in the process of connecting or already connected
  for (auto it : peers_) {
    const BtifAcmPeer* peer = it.second;
    switch (peer->StateMachine().StateId()) {
      case BtifAcmStateMachine::kStateOpening:
      case BtifAcmStateMachine::kStateOpened:
      case BtifAcmStateMachine::kStateStarted:
      case BtifAcmStateMachine::kStateReconfiguring:
        if (peer->PeerAddress() == peer_address) {
          return true;  // Already connected or accounted for
        }
        connected++;
        break;
      default:
        break;
    }
  }
  return (connected < max_connected_peers_);
}

bool BtifAcmInitiator::IsAcmIdle() const {
  int connected = 0;

  // Count peers that are in the process of connecting or already connected
  for (auto it : peers_) {
    const BtifAcmPeer* peer = it.second;
    switch (peer->StateMachine().StateId()) {
      case BtifAcmStateMachine::kStateOpening:
      case BtifAcmStateMachine::kStateOpened:
      case BtifAcmStateMachine::kStateStarted:
      case BtifAcmStateMachine::kStateReconfiguring:
      case BtifAcmStateMachine::kStateClosing:
        connected++;
        break;
      default:
        break;
    }
  }
  return (connected == 0);
}

bool BtifAcmInitiator::IsSetIdle(uint8_t setId) const {
  int connected = 0;
  tBTA_CSIP_CSET cset_info = BTA_CsipGetCoordinatedSet(setId);
  std::vector<RawAddress>::iterator itr;
  if ((cset_info.set_members).size() > 0) {
    for (itr = (cset_info.set_members).begin(); itr != (cset_info.set_members).end(); itr++) {
      BtifAcmPeer* peer = btif_acm_initiator.FindPeer(*itr);
      switch (peer->StateMachine().StateId()) {
        case BtifAcmStateMachine::kStateOpening:
        case BtifAcmStateMachine::kStateOpened:
        case BtifAcmStateMachine::kStateStarted:
        case BtifAcmStateMachine::kStateReconfiguring:
        case BtifAcmStateMachine::kStateClosing:
          connected++;
          break;
        default:
          break;
      }
    }
  }
  return (connected == 0);
}

bool BtifAcmInitiator::IsOtherSetPeersIdle(const RawAddress& peer_address, uint8_t setId) const {
  int connected = 0;
  tBTA_CSIP_CSET cset_info = BTA_CsipGetCoordinatedSet(setId);
  std::vector<RawAddress>::iterator itr;
  if ((cset_info.set_members).size() > 0) {
    for (itr = (cset_info.set_members).begin(); itr != (cset_info.set_members).end(); itr++) {
      if (*itr  == peer_address) continue;
      BtifAcmPeer* peer = btif_acm_initiator.FindPeer(*itr);
      if (peer == nullptr) continue;
      switch (peer->StateMachine().StateId()) {
        case BtifAcmStateMachine::kStateOpening:
        case BtifAcmStateMachine::kStateOpened:
        case BtifAcmStateMachine::kStateStarted:
        case BtifAcmStateMachine::kStateReconfiguring:
        case BtifAcmStateMachine::kStateClosing:
          connected++;
          break;
        default:
          break;
      }
    }
  }
  return (connected == 0);
}

bool BtifAcmInitiator::DeletePeer(const RawAddress& peer_address) {
  auto it = peers_.find(peer_address);
  if (it == peers_.end()) return false;
  BtifAcmPeer* peer = it->second;
  for (auto itr = addr_setid_pair.begin(); itr != addr_setid_pair.end(); ++itr) {
    if (itr->second == peer->SetId()) {
      addr_setid_pair.erase(itr);
      break;
    }
  }
  for (auto itr = set_cig_pair.begin(); itr != set_cig_pair.end(); ++itr) {
    if (itr->second == peer->SetId()) {
      set_cig_pair.erase(itr);
      break;
    }
  }
  bool found = false;
  for (auto itr = cig_cis_pair.begin(); itr != cig_cis_pair.end(); itr++) {
    for (auto ptr = itr->second.begin(); ptr != itr->second.end(); ptr++) {
      if (ptr->first == peer->CigId()) {
        if (ptr->second == peer->CisId()) {
          cig_cis_pair.erase(itr);
          found = true;
          break;
        }
      }
    }
    if (found)
      break;
  }
  peer->Cleanup();
  peers_.erase(it);
  delete peer;
  return true;
}

void BtifAcmInitiator::DeleteIdlePeers() {
  for (auto it = peers_.begin(); it != peers_.end();) {
    BtifAcmPeer* peer = it->second;
    auto prev_it = it++;
    if (!peer->CanBeDeleted()) continue;
    LOG_INFO(LOG_TAG, "%s: Deleting idle peer: %s ", __func__,
             peer->PeerAddress().ToString().c_str());
    for (auto itr = addr_setid_pair.begin(); itr != addr_setid_pair.end(); ++itr) {
      if (itr->second == peer->SetId()) {
        addr_setid_pair.erase(itr);
        break;
      }
    }
    for (auto itr = set_cig_pair.begin(); itr != set_cig_pair.end(); ++itr) {
      if (itr->second == peer->SetId()) {
        set_cig_pair.erase(itr);
        break;
      }
    }
    bool found = false;
    for (auto itr = cig_cis_pair.begin(); itr != cig_cis_pair.end(); itr++) {
      for (auto ptr = itr->second.begin(); ptr != itr->second.end(); ptr++) {
        if (ptr->first == peer->CigId()) {
          if (ptr->second == peer->CisId()) {
            cig_cis_pair.erase(itr);
            found = true;
            break;
          }
        }
      }
      if (found)
        break;
    }
    peer->Cleanup();
    peers_.erase(prev_it);
    delete peer;
  }
}

void BtifAcmInitiator::CleanupAllPeers() {
  while (!peers_.empty()) {
    auto it = peers_.begin();
    BtifAcmPeer* peer = it->second;
    for (auto itr = addr_setid_pair.begin(); itr != addr_setid_pair.end(); ++itr) {
      if (itr->second == peer->SetId()) {
        addr_setid_pair.erase(itr);
        break;
      }
    }
    for (auto itr = set_cig_pair.begin(); itr != set_cig_pair.end(); ++itr) {
      if (itr->second == peer->SetId()) {
        set_cig_pair.erase(itr);
        break;
      }
    }
    bool found = false;
    for (auto itr = cig_cis_pair.begin(); itr != cig_cis_pair.end(); itr++) {
      for (auto ptr = itr->second.begin(); ptr != itr->second.end(); ptr++) {
        if (ptr->first == peer->CigId()) {
          if (ptr->second == peer->CisId()) {
            cig_cis_pair.erase(itr);
            found = true;
            break;
          }
        }
      }
      if (found)
        break;
    }
    peer->Cleanup();
    peers_.erase(it);
    delete peer;
  }
}

class UcastClientCallbacksImpl : public UcastClientCallbacks {
 public:
  ~UcastClientCallbacksImpl() = default;
  void OnStreamState(const RawAddress& address,
                     std::vector<StreamStateInfo> streams_state_info) override {
    LOG(INFO) << __func__;
    BtifAcmPeer* peer = btif_acm_initiator.FindPeer(address);
    if (peer == nullptr) {
      BTIF_TRACE_DEBUG("%s: Peer is NULL", __PRETTY_FUNCTION__);
    }
    for (auto it = streams_state_info.begin(); it != streams_state_info.end(); ++it) {
      LOG(WARNING) << __func__ << ": address: " << address;
      LOG(WARNING) << __func__ << ": stream type:    "
                   << GetStreamType(it->stream_type.type);
      LOG(WARNING) << __func__ << ": stream context: "
                   << GetStreamType(it->stream_type.audio_context);
      LOG(WARNING) << __func__ << ": stream dir:     "
                   << GetStreamDirection(it->stream_type.direction);
      LOG(WARNING) << __func__ << ": stream state:   "
                   << GetStreamState(static_cast<int> (it->stream_state));
      switch (it->stream_state) {
        case StreamState::DISCONNECTED:
        case StreamState::DISCONNECTING: {
          tBTA_ACM_STATE_INFO data = {.bd_addr = address, .stream_type = it->stream_type,
                                      .stream_state = it->stream_state, .reason = it->reason};
          btif_acm_handle_evt(BTA_ACM_DISCONNECT_EVT, (char*)&data);
        } break;

        case StreamState::CONNECTING:
        case StreamState::CONNECTED: {
          tBTA_ACM_STATE_INFO data = {.bd_addr = address, .stream_type = it->stream_type,
                                      .stream_state = it->stream_state, .reason = it->reason};
          btif_acm_handle_evt(BTA_ACM_CONNECT_EVT, (char*)&data);
        } break;

        case StreamState::STARTING:
        case StreamState::STREAMING: {
          tBTA_ACM_STATE_INFO data = {.bd_addr = address, .stream_type = it->stream_type,
                                      .stream_state = it->stream_state, .reason = it->reason};
          btif_acm_handle_evt(BTA_ACM_START_EVT, (char*)&data);
        } break;

        case StreamState::STOPPING: {
          tBTA_ACM_STATE_INFO data = {.bd_addr = address, .stream_type = it->stream_type,
                                      .stream_state = it->stream_state, .reason = it->reason};
          btif_acm_handle_evt(BTA_ACM_STOP_EVT, (char*)&data);
        } break;

        case StreamState::RECONFIGURING: {
          tBTA_ACM_STATE_INFO data = {.bd_addr = address, .stream_type = it->stream_type,
                                      .stream_state = it->stream_state, .reason = it->reason};
          btif_acm_handle_evt(BTA_ACM_RECONFIG_EVT, (char*)&data);
        } break;
        default:
          break;
      }
    }
  }

  void OnStreamConfig(const RawAddress& address,
                      std::vector<StreamConfigInfo> streams_config_info) override {
    LOG(INFO) << __func__;
    BtifAcmPeer* peer = btif_acm_initiator.FindPeer(address);
    if (peer == nullptr) {
      BTIF_TRACE_DEBUG("%s: Peer is NULL", __PRETTY_FUNCTION__);
    }
    for (auto it = streams_config_info.begin(); it != streams_config_info.end(); ++it) {
      tBTA_ACM_CONFIG_INFO data = {.bd_addr = address, .stream_type = it->stream_type,
                                   .codec_config = it->codec_config, .audio_location = it->audio_location,
                                   .qos_config = it->qos_config, .codecs_selectable = it->codecs_selectable};
      btif_acm_handle_evt(BTA_ACM_CONFIG_EVT, (char*)&data);
    }
  }

  void OnStreamAvailable(const RawAddress& bd_addr, uint16_t src_audio_contexts,
                                      uint16_t sink_audio_contexts) override {
     LOG(INFO) << __func__;
     //Need to use during START of src and sink audio context
     BTIF_TRACE_DEBUG("%s: Peer %s, src_audio_context: 0x%x, sink_audio_contexts: 0x%x",
                      __func__,
                      bd_addr.ToString().c_str(), src_audio_contexts, sink_audio_contexts);
  }

  const char* GetStreamType(uint16_t stream_type) {
    switch (stream_type) {
      CASE_RETURN_STR(CONTENT_TYPE_UNSPECIFIED)
      CASE_RETURN_STR(CONTENT_TYPE_CONVERSATIONAL)
      CASE_RETURN_STR(CONTENT_TYPE_MEDIA)
      CASE_RETURN_STR(CONTENT_TYPE_INSTRUCTIONAL)
      CASE_RETURN_STR(CONTENT_TYPE_NOTIFICATIONS)
      CASE_RETURN_STR(CONTENT_TYPE_ALERT)
      CASE_RETURN_STR(CONTENT_TYPE_MAN_MACHINE)
      CASE_RETURN_STR(CONTENT_TYPE_EMERGENCY)
      CASE_RETURN_STR(CONTENT_TYPE_RINGTONE)
      CASE_RETURN_STR(CONTENT_TYPE_SOUND_EFFECTS)
      CASE_RETURN_STR(CONTENT_TYPE_LIVE)
      CASE_RETURN_STR(CONTENT_TYPE_GAME)
      default:
       return "Unknown StreamType";
    }
  }

  const char* GetStreamDirection(uint8_t event) {
    switch (event) {
      CASE_RETURN_STR(ASE_DIRECTION_SINK)
      CASE_RETURN_STR(ASE_DIRECTION_SRC)
      default:
       return "Unknown StreamDirection";
    }
  }

  const char* GetStreamState(uint8_t event) {
    switch (event) {
      CASE_RETURN_STR(STREAM_STATE_DISCONNECTED)
      CASE_RETURN_STR(STREAM_STATE_CONNECTING)
      CASE_RETURN_STR(STREAM_STATE_CONNECTED)
      CASE_RETURN_STR(STREAM_STATE_STARTING)
      CASE_RETURN_STR(STREAM_STATE_STREAMING)
      CASE_RETURN_STR(STREAM_STATE_STOPPING)
      CASE_RETURN_STR(STREAM_STATE_DISCONNECTING)
      CASE_RETURN_STR(STREAM_STATE_RECONFIGURING)
      default:
       return "Unknown StreamState";
    }
  }
};

static UcastClientCallbacksImpl sUcastClientCallbacks;

bt_status_t BtifAcmInitiator::Init(
    btacm_initiator_callbacks_t* callbacks, int max_connected_acceptors,
    const std::vector<CodecConfig>& codec_priorities) {
  LOG_INFO(LOG_TAG, "%s: max_connected_acceptors=%d", __PRETTY_FUNCTION__,
           max_connected_acceptors);
  if (enabled_) return BT_STATUS_SUCCESS;
  CleanupAllPeers();
  max_connected_peers_ = max_connected_acceptors;
  alarm_free(music_set_lock_release_timer_);
  alarm_free(voice_set_lock_release_timer_);
  alarm_free(acm_group_procedure_timer_);
  alarm_free(acm_conn_interval_timer_);
  music_set_lock_release_timer_ = alarm_new("btif_acm_initiator.music_set_lock_release_timer");
  voice_set_lock_release_timer_ = alarm_new("btif_acm_initiator.voice_set_lock_release_timer");
  acm_group_procedure_timer_ = alarm_new("btif_acm_initiator.acm_group_procedure_timer");
  acm_conn_interval_timer_ = alarm_new("btif_acm_initiator.acm_conn_interval_timer");

  callbacks_ = callbacks;
  //init local capabilties
  init_local_capabilities();

  // register ACM with AHIM
  btif_register_cb();

  btif_vmcp_init();
  bt_status_t status1 = btif_acm_initiator_execute_service(true);
  if (status1 == BT_STATUS_SUCCESS) {
    BTIF_TRACE_EVENT("%s: status success", __func__);
  }
  if (sUcastClientInterface != nullptr) {
    LOG_INFO(LOG_TAG, "%s Cleaning up BAP client Interface before initializing...",
             __PRETTY_FUNCTION__);
    sUcastClientInterface->Cleanup();
    sUcastClientInterface = nullptr;
  }
  sUcastClientInterface = bluetooth::bap::ucast::btif_bap_uclient_get_interface();


  if (sUcastClientInterface == nullptr) {
    LOG_ERROR(LOG_TAG, "%s Failed to get BAP Interface", __PRETTY_FUNCTION__);
    return BT_STATUS_FAIL;
  }
  char value[PROPERTY_VALUE_MAX];
  if(property_get("persist.vendor.service.bt.bap.conn_update", value, "false")
                     && !strcmp(value, "true")) {
    is_conn_update_enabled_ = true;
  } else {
    is_conn_update_enabled_ = false;
  }
  sUcastClientInterface->Init(&sUcastClientCallbacks);
  enabled_ = true;
  return BT_STATUS_SUCCESS;
}

void BtifAcmStateMachine::StateIdle::OnEnter() {
  BTIF_TRACE_DEBUG("%s: Peer %s", __PRETTY_FUNCTION__,
                   peer_.PeerAddress().ToString().c_str());
  if(btif_acm_initiator.IsConnUpdateEnabled()) {
    if ((peer_.StateMachine().PreviousStateId() == BtifAcmStateMachine::kStateOpened) ||
       (peer_.StateMachine().PreviousStateId() == BtifAcmStateMachine::kStateStarted))
    {
      if (alarm_is_scheduled(btif_acm_initiator.AcmConnIntervalTimer())) {
        btif_acm_check_and_cancel_conn_Interval_timer();
        peer_.SetConnUpdateMode(BtifAcmPeer::kFlagRelaxedMode);
      } else {
          LOG_ERROR(LOG_TAG, "%s Already in relaxed intervals", __PRETTY_FUNCTION__);
      }
    } else if (peer_.StateMachine().PreviousStateId() != BtifAcmStateMachine::kStateInvalid) {
      if (alarm_is_scheduled(btif_acm_initiator.AcmConnIntervalTimer())) {
        btif_acm_check_and_cancel_conn_Interval_timer();
      }
      peer_.SetConnUpdateMode(BtifAcmPeer::kFlagRelaxedMode);
    }
  }
  peer_.ClearConnUpdateMode();
  peer_.ClearAllFlags();
  peer_.SetProfileType(0);
  peer_.SetRcfgProfileType(0);
  memset(&current_media_config, 0, sizeof(current_media_config));

  // Delete peers that are re-entering the Idle state
  if (peer_.IsAcceptor()) {
    do_in_bta_thread(FROM_HERE, base::Bind(&BtifAcmInitiator::DeleteIdlePeers,
                                            base::Unretained(&btif_acm_initiator)));
  }
}

void BtifAcmStateMachine::StateIdle::OnExit() {
  BTIF_TRACE_DEBUG("%s: Peer %s", __PRETTY_FUNCTION__,
                   peer_.PeerAddress().ToString().c_str());
}

bool BtifAcmStateMachine::StateIdle::ProcessEvent(uint32_t event, void* p_data) {
  BTIF_TRACE_DEBUG("%s: Peer %s : event=%s flags=%s music_active_peer=%s voice_active_peer=%s",
                   __PRETTY_FUNCTION__, peer_.PeerAddress().ToString().c_str(),
                   BtifAcmEvent::EventName(event).c_str(),
                   peer_.FlagsToString().c_str(),
                   logbool(peer_.IsPeerActiveForMusic()).c_str(),
                   logbool(peer_.IsPeerActiveForVoice()).c_str());

  switch (event) {
    case BTIF_ACM_STOP_STREAM_REQ_EVT:
    case BTIF_ACM_SUSPEND_STREAM_REQ_EVT:
      break;
#if 0
    case BTIF_ACM_DISCONNECT_REQ_EVT: {
      tBTIF_ACM_CONN_DISC* p_bta_data = (tBTIF_ACM_CONN_DISC*)p_data;
      std::vector<StreamType> disconnect_streams;
      if (p_bta_data->contextType == CONTEXT_TYPE_MUSIC) {
        StreamType type_1;
        if (peer_.GetProfileType() & (BAP|GCP)) {
          type_1 = {.type = CONTENT_TYPE_MEDIA,
                    .audio_context = CONTENT_TYPE_MEDIA,
                    .direction = ASE_DIRECTION_SINK
                   };
          disconnect_streams.push_back(type_1);
        }
        if (peer_.GetProfileType() & WMCP) {
          type_1 = {.type = CONTENT_TYPE_MEDIA,
                    .audio_context = CONTENT_TYPE_LIVE,
                    .direction = ASE_DIRECTION_SRC
                   };
          disconnect_streams.push_back(type_1);
        }
      } else if (p_bta_data->contextType == CONTEXT_TYPE_MUSIC_VOICE) {
        StreamType type_2 = {.type = CONTENT_TYPE_CONVERSATIONAL,
                             .audio_context = CONTENT_TYPE_CONVERSATIONAL,
                             .direction = ASE_DIRECTION_SRC
                            };
        StreamType type_3 = {.type = CONTENT_TYPE_CONVERSATIONAL,
                             .audio_context = CONTENT_TYPE_CONVERSATIONAL,
                             .direction = ASE_DIRECTION_SINK
                            };
        disconnect_streams.push_back(type_2);
        disconnect_streams.push_back(type_3);
        StreamType type_1;
        if (peer_.GetProfileType() & (BAP|GCP)) {
          type_1 = {.type = CONTENT_TYPE_MEDIA,
                    .audio_context = CONTENT_TYPE_MEDIA,
                    .direction = ASE_DIRECTION_SINK
                    };
          disconnect_streams.push_back(type_1);
        }
        if (peer_.GetProfileType() & WMCP) {
          type_1 = {.type = CONTENT_TYPE_MEDIA,
                    .audio_context = CONTENT_TYPE_LIVE,
                    .direction = ASE_DIRECTION_SRC
                    };
          disconnect_streams.push_back(type_1);
        }
      }
      LOG(WARNING) << __func__ << " size of disconnect_streams " << disconnect_streams.size();
      if (!sUcastClientInterface) break;
      sUcastClientInterface->Disconnect(peer_.PeerAddress(), disconnect_streams);

      // Re-enter Idle so the peer can be deleted
      peer_.StateMachine().TransitionTo(BtifAcmStateMachine::kStateIdle);
    }
    break;
#endif

    case BTIF_ACM_CONNECT_REQ_EVT: {
      tBTIF_ACM_CONN_DISC* p_bta_data = (tBTIF_ACM_CONN_DISC*)p_data;
      bool can_connect = true;
      // Check whether connection is allowed
      if (peer_.IsAcceptor()) {
        //There is no char in current spec. Should we check VMCP role here?
        // shall we assume VMCP role would have been checked in apps and no need to check here?
        can_connect = btif_acm_initiator.AllowedToConnect(peer_.PeerAddress());
        if (!can_connect) disconnect_acm_initiator(peer_.PeerAddress(), p_bta_data->contextType);
      }
      if (!can_connect) {
        BTIF_TRACE_ERROR(
            "%s: Cannot connect to peer %s: too many connected "
            "peers",
            __PRETTY_FUNCTION__, peer_.PeerAddress().ToString().c_str());
        break;
      }
      std::vector<StreamConnect> streams;
      if (p_bta_data->contextType == CONTEXT_TYPE_MUSIC) {
        StreamConnect conn_media;
        if (peer_.GetProfileType() & (BAP|GCP)) {
          //keeping media tx as BAP/GCP config
          memset(&conn_media, 0, sizeof(conn_media));
          fetch_media_tx_codec_qos_config(peer_.PeerAddress(), peer_.GetProfileType() & (BAP|GCP), &conn_media);
          streams.push_back(conn_media);
#if 0
          if (false) {//enable when GCP support is available
            SelectCodecQosConfig(peer_.PeerAddress(), (peer_.GetProfileType() & ~WMCP), VOICE_CONTEXT, SRC, EB_CONFIG);
            StreamConnect conn_voice;
            CodecQosConfig config;
            conn_voice.stream_type.type = CONTENT_TYPE_CONVERSATIONAL;
            conn_voice.stream_type.audio_context = CONTENT_TYPE_CONVERSATIONAL;
            config = peer_.get_peer_voice_rx_codec_qos_config();
            print_codec_parameters(config.codec_config);
            print_qos_parameters(config.qos_config);
            conn_voice.stream_type.direction = ASE_DIRECTION_SRC;
            conn_voice.codec_qos_config_pair.push_back(config);
            streams.push_back(conn_voice);
          }
#endif
        }
        if (peer_.GetProfileType() & WMCP) {
          //keeping media rx as WMCP config
          memset(&conn_media, 0, sizeof(conn_media));
          fetch_media_rx_codec_qos_config(peer_.PeerAddress(), WMCP, &conn_media);
          streams.push_back(conn_media);
        }
      } else if (p_bta_data->contextType == CONTEXT_TYPE_MUSIC_VOICE) {
        StreamConnect conn_media, conn_voice;
        //keeping voice tx as BAP config
        memset(&conn_voice, 0, sizeof(conn_voice));
        fetch_voice_tx_codec_qos_config(peer_.PeerAddress(), BAP, &conn_voice);
        streams.push_back(conn_voice);
        //keeping voice rx as BAP config
        memset(&conn_voice, 0, sizeof(conn_voice));
        fetch_voice_rx_codec_qos_config(peer_.PeerAddress(), BAP, &conn_voice);
        streams.push_back(conn_voice);
        if (peer_.GetProfileType() & (BAP|GCP)) {
          //keeping media tx as BAP/GCP config
          memset(&conn_media, 0, sizeof(conn_media));
          fetch_media_tx_codec_qos_config(peer_.PeerAddress(), peer_.GetProfileType() & (BAP|GCP), &conn_media);
          streams.push_back(conn_media);
        }
        if (peer_.GetProfileType() & WMCP) {
          //keeping media rx as WMCP config
          memset(&conn_media, 0, sizeof(conn_media));
          fetch_media_rx_codec_qos_config(peer_.PeerAddress(), WMCP, &conn_media);
          streams.push_back(conn_media);
        }
      } else if (p_bta_data->contextType == CONTEXT_TYPE_VOICE) {
        StreamConnect conn_voice;
        //keeping voice tx as BAP config
        memset(&conn_voice, 0, sizeof(conn_voice));
        fetch_voice_tx_codec_qos_config(peer_.PeerAddress(), BAP, &conn_voice);
        streams.push_back(conn_voice);
        //keeping voice rx as BAP config
        memset(&conn_voice, 0, sizeof(conn_voice));
        fetch_voice_rx_codec_qos_config(peer_.PeerAddress(), BAP, &conn_voice);
        streams.push_back(conn_voice);
      }
      LOG(WARNING) << __func__ << " size of streams " << streams.size();
      if (!sUcastClientInterface) break;
      // intiate background connection
      std::vector<RawAddress> address;
      address.push_back(peer_.PeerAddress());
      sUcastClientInterface->Connect(address, false, streams);
      peer_.StateMachine().TransitionTo(BtifAcmStateMachine::kStateOpening);
    } break;
#if 0
    case BTA_ACM_DISCONNECT_EVT: {
      tBTIF_ACM* p_acm = (tBTIF_ACM*)p_data;
      int context_type = p_acm->state_info.stream_type.type;
      if (p_acm->state_info.stream_state == StreamState::DISCONNECTED) {
        if (context_type == CONTENT_TYPE_MEDIA) {
          if (p_acm->state_info.stream_type.direction == ASE_DIRECTION_SRC) {
            BTIF_TRACE_DEBUG("%s: received Media Rx disconnected state from BAP, set state & ignore", __func__);
            peer_.SetPeerMusicRxState(p_acm->state_info.stream_state);
          }
        }
      } else if (p_acm->state_info.stream_state == StreamState::DISCONNECTING) {
        if (context_type == CONTENT_TYPE_MEDIA) {
          BTIF_TRACE_DEBUG("%s: received Media disconnecting state from BAP, ignore", __func__);
          if (p_acm->state_info.stream_type.direction == ASE_DIRECTION_SRC)
            peer_.SetPeerMusicRxState(p_acm->state_info.stream_state);
        }
      }
    } break;
#endif

    case BTA_ACM_CONN_UPDATE_TIMEOUT_EVT:
      peer_.SetConnUpdateMode(BtifAcmPeer::kFlagRelaxedMode);
      break;

    default:
      BTIF_TRACE_WARNING("%s: Peer %s : Unhandled event=%s",
                         __PRETTY_FUNCTION__,
                         peer_.PeerAddress().ToString().c_str(),
                         BtifAcmEvent::EventName(event).c_str());
      return false;
  }

  return true;
}

void BtifAcmStateMachine::StateOpening::OnEnter() {
  BTIF_TRACE_DEBUG("%s: Peer %s", __PRETTY_FUNCTION__,
                   peer_.PeerAddress().ToString().c_str());

  if(btif_acm_initiator.IsConnUpdateEnabled()) {
    //Cancel the timer if start streamng comes before
    // 5 seconds while moving the interval to relaxed mode.
    if (alarm_is_scheduled(btif_acm_initiator.AcmConnIntervalTimer())) {
       btif_acm_check_and_cancel_conn_Interval_timer();
    }
    else {
       peer_.SetConnUpdateMode(BtifAcmPeer::kFlagAggresiveMode);
    }
  }

}

void BtifAcmStateMachine::StateOpening::OnExit() {
  BTIF_TRACE_DEBUG("%s: Peer %s", __PRETTY_FUNCTION__,
                   peer_.PeerAddress().ToString().c_str());
}

bool BtifAcmStateMachine::StateOpening::ProcessEvent(uint32_t event, void* p_data) {
  BTIF_TRACE_DEBUG("%s: Peer %s : event=%s flags=%s music_active_peer=%s voice_active_peer=%s",
                   __PRETTY_FUNCTION__, peer_.PeerAddress().ToString().c_str(),
                   BtifAcmEvent::EventName(event).c_str(),
                   peer_.FlagsToString().c_str(),
                   logbool(peer_.IsPeerActiveForMusic()).c_str(),
                   logbool(peer_.IsPeerActiveForVoice()).c_str());

  switch (event) {
    case BTIF_ACM_STOP_STREAM_REQ_EVT:
    case BTIF_ACM_SUSPEND_STREAM_REQ_EVT:
      break;  // Ignore

    case BTA_ACM_CONNECT_EVT: {
      tBTIF_ACM* p_bta_data = (tBTIF_ACM*)p_data;
      btacm_connection_state_t state;
      uint8_t status = (uint8_t)p_bta_data->state_info.stream_state;
      uint16_t contextType = p_bta_data->state_info.stream_type.type;

      LOG_INFO(
          LOG_TAG, "%s: Peer %s : event=%s flags=%s status=%d contextType=%d",
          __PRETTY_FUNCTION__, peer_.PeerAddress().ToString().c_str(),
          BtifAcmEvent::EventName(event).c_str(), peer_.FlagsToString().c_str(),
          status, contextType);
      if (contextType == CONTENT_TYPE_MEDIA) {
        if (p_bta_data->state_info.stream_state == StreamState::CONNECTED) {
          state = BTACM_CONNECTION_STATE_CONNECTED;
          // Report the connection state to the application
          btif_report_connection_state(peer_.PeerAddress(), state, CONTEXT_TYPE_MUSIC);
          if (p_bta_data->state_info.stream_type.direction == ASE_DIRECTION_SINK) {
            peer_.SetPeerMusicTxState(p_bta_data->state_info.stream_state);
            BTIF_TRACE_DEBUG("%s: received connected state from BAP for mediaTx, move in opened state", __func__);
          } else if (p_bta_data->state_info.stream_type.direction == ASE_DIRECTION_SRC) {
            peer_.SetPeerMusicRxState(p_bta_data->state_info.stream_state);
            BTIF_TRACE_DEBUG("%s: received connected state from BAP for mediaRx, move in opened state", __func__);
          }
          // Change state to OPENED
          peer_.StateMachine().TransitionTo(BtifAcmStateMachine::kStateOpened);
        } else if (p_bta_data->state_info.stream_state == StreamState::CONNECTING) {
          BTIF_TRACE_DEBUG("%s: received connecting state from BAP for MEDIA Tx or Rx, ignore", __func__);
          if (p_bta_data->state_info.stream_type.direction == ASE_DIRECTION_SINK)
            peer_.SetPeerMusicTxState(p_bta_data->state_info.stream_state);
          else if (p_bta_data->state_info.stream_type.direction == ASE_DIRECTION_SRC)
            peer_.SetPeerMusicRxState(p_bta_data->state_info.stream_state);
        }
      } else if (contextType == CONTENT_TYPE_CONVERSATIONAL) {
        if (p_bta_data->state_info.stream_state == StreamState::CONNECTED) {
          state = BTACM_CONNECTION_STATE_CONNECTED;
          if (p_bta_data->state_info.stream_type.direction == ASE_DIRECTION_SINK) {
            peer_.SetPeerVoiceTxState(p_bta_data->state_info.stream_state);
            if (peer_.GetPeerVoiceRxState() == StreamState::CONNECTED) {
              btif_report_connection_state(peer_.PeerAddress(), state, CONTEXT_TYPE_VOICE);
              BTIF_TRACE_DEBUG("%s: received connected state from BAP for voice Tx, move in opened state", __func__);
              peer_.StateMachine().TransitionTo(BtifAcmStateMachine::kStateOpened);
            }
          } else if (p_bta_data->state_info.stream_type.direction == ASE_DIRECTION_SRC) {
            peer_.SetPeerVoiceRxState(p_bta_data->state_info.stream_state);
            if (peer_.GetPeerVoiceTxState() == StreamState::CONNECTED) {
              btif_report_connection_state(peer_.PeerAddress(), state, CONTEXT_TYPE_VOICE);
              BTIF_TRACE_DEBUG("%s: received connected state from BAP for voice Rx, move in opened state", __func__);
              peer_.StateMachine().TransitionTo(BtifAcmStateMachine::kStateOpened);
            }
          }
        } else if (p_bta_data->state_info.stream_state == StreamState::CONNECTING) {
          BTIF_TRACE_DEBUG("%s: received connecting state from BAP for CONVERSATIONAL Tx or Rx, ignore", __func__);
          if (p_bta_data->state_info.stream_type.direction == ASE_DIRECTION_SINK) {
            peer_.SetPeerVoiceTxState(p_bta_data->state_info.stream_state);
          } else if (p_bta_data->state_info.stream_type.direction == ASE_DIRECTION_SRC) {
            peer_.SetPeerVoiceRxState(p_bta_data->state_info.stream_state);
          }
        }
      }
    } break;

    case BTA_ACM_DISCONNECT_EVT: {
      tBTIF_ACM* p_acm = (tBTIF_ACM*)p_data;
      int context_type = p_acm->state_info.stream_type.type;
      if (p_acm->state_info.stream_state == StreamState::DISCONNECTED) {
        if (context_type == CONTENT_TYPE_MEDIA) {
          if (p_acm->state_info.stream_type.direction == ASE_DIRECTION_SINK) {
            peer_.SetPeerMusicTxState(p_acm->state_info.stream_state);
          } else if (p_acm->state_info.stream_type.direction == ASE_DIRECTION_SRC) {
            peer_.SetPeerMusicRxState(p_acm->state_info.stream_state);
          }
          if (peer_.GetPeerMusicTxState() == StreamState::DISCONNECTED &&
              peer_.GetPeerMusicRxState() == StreamState::DISCONNECTED) {
            btif_report_connection_state(peer_.PeerAddress(),
                BTACM_CONNECTION_STATE_DISCONNECTED, CONTEXT_TYPE_MUSIC);
          }
          if (peer_.GetPeerVoiceRxState() == StreamState::DISCONNECTED &&
               peer_.GetPeerVoiceTxState() == StreamState::DISCONNECTED &&
               peer_.GetPeerMusicTxState() == StreamState::DISCONNECTED &&
               peer_.GetPeerMusicRxState() == StreamState::DISCONNECTED) {
            BTIF_TRACE_DEBUG("%s: received Media Tx/Rx disconnected state from BAP"
                      " when Voice Tx+Rx & Media Rx/Tx was disconnected, move in idle state", __func__);
            peer_.StateMachine().TransitionTo(BtifAcmStateMachine::kStateIdle);
          } else {
            BTIF_TRACE_DEBUG("%s: received Media Tx/Rx disconnected state from BAP"
                      " when either Voice Tx or Rx or Media Rx/Tx is connecting, remain in opening state", __func__);
          }
        } else if (context_type == CONTENT_TYPE_CONVERSATIONAL) {
          if (p_acm->state_info.stream_type.direction == ASE_DIRECTION_SINK) {
            peer_.SetPeerVoiceTxState(p_acm->state_info.stream_state);
            if (peer_.GetPeerVoiceRxState() == StreamState::DISCONNECTED) {
              btif_report_connection_state(peer_.PeerAddress(), BTACM_CONNECTION_STATE_DISCONNECTED, CONTEXT_TYPE_VOICE);
              if (peer_.GetPeerMusicTxState() == StreamState::DISCONNECTED &&
                  peer_.GetPeerMusicRxState() == StreamState::DISCONNECTED) {
                BTIF_TRACE_DEBUG("%s: received disconnected state from BAP for voice Tx,"
                                 " voice Rx, music Tx+Rx are disconnected move in idle state", __func__);
                peer_.StateMachine().TransitionTo(BtifAcmStateMachine::kStateIdle);
              } else if (peer_.GetPeerMusicTxState() == StreamState::CONNECTING ||
                         peer_.GetPeerMusicRxState() == StreamState::CONNECTING) {
                BTIF_TRACE_DEBUG("%s: received disconnected state from BAP for voice Tx,"
                                 " voice Rx is disconnected but either music Tx or Rx still connecting,"
                                 " remain in opening state", __func__);
              }
            }
          } else if (p_acm->state_info.stream_type.direction == ASE_DIRECTION_SRC) {
            peer_.SetPeerVoiceRxState(p_acm->state_info.stream_state);
            if (peer_.GetPeerVoiceTxState() == StreamState::DISCONNECTED) {
              btif_report_connection_state(peer_.PeerAddress(), BTACM_CONNECTION_STATE_DISCONNECTED, CONTEXT_TYPE_VOICE);
              if (peer_.GetPeerMusicTxState() == StreamState::DISCONNECTED &&
                  peer_.GetPeerMusicRxState() == StreamState::DISCONNECTED) {
                BTIF_TRACE_DEBUG("%s: received disconnected state from BAP for voice Rx,"
                                 " voice Tx, music Tx+Rx are disconnected move in idle state", __func__);
                peer_.StateMachine().TransitionTo(BtifAcmStateMachine::kStateIdle);
              } else if (peer_.GetPeerMusicTxState() == StreamState::CONNECTING ||
                         peer_.GetPeerMusicRxState() == StreamState::CONNECTING) {
                BTIF_TRACE_DEBUG("%s: received disconnected state from BAP for voice Rx,"
                                 " voice Tx is disconnected but music Tx or Rx still connecting,"
                                 " remain in opening state", __func__);
              }
            }
          }
        }
      } else if (p_acm->state_info.stream_state == StreamState::DISCONNECTING) {
          if (context_type == CONTENT_TYPE_MEDIA) {
            BTIF_TRACE_DEBUG("%s: received disconnecting state from BAP for MEDIA Tx or Rx, ignore", __func__);
            if (p_acm->state_info.stream_type.direction == ASE_DIRECTION_SINK) {
              peer_.SetPeerMusicTxState(p_acm->state_info.stream_state);
            } else if (p_acm->state_info.stream_type.direction == ASE_DIRECTION_SRC) {
              peer_.SetPeerMusicRxState(p_acm->state_info.stream_state);
            }
            btif_report_connection_state(peer_.PeerAddress(), BTACM_CONNECTION_STATE_DISCONNECTING, CONTEXT_TYPE_MUSIC);
          } else if (context_type == CONTENT_TYPE_CONVERSATIONAL) {
            BTIF_TRACE_DEBUG("%s: received disconnecting state from BAP for CONVERSATIONAL Tx or Rx, ignore", __func__);
            if (p_acm->state_info.stream_type.direction == ASE_DIRECTION_SINK) {
              peer_.SetPeerVoiceTxState(p_acm->state_info.stream_state);
            } else if (p_acm->state_info.stream_type.direction == ASE_DIRECTION_SRC) {
              peer_.SetPeerVoiceRxState(p_acm->state_info.stream_state);
            }
            btif_report_connection_state(peer_.PeerAddress(), BTACM_CONNECTION_STATE_DISCONNECTING, CONTEXT_TYPE_VOICE);
          }
      }
    }
    break;

    case BTIF_ACM_DISCONNECT_REQ_EVT:{
      tBTIF_ACM_CONN_DISC* p_bta_data = (tBTIF_ACM_CONN_DISC*)p_data;
      std::vector<StreamType> disconnect_streams;
      if (p_bta_data->contextType == CONTEXT_TYPE_MUSIC) {
        StreamType type_1;
        if (p_bta_data->profileType & (BAP|GCP)) {
          type_1 = {.type = CONTENT_TYPE_MEDIA,
                    .audio_context = CONTENT_TYPE_MEDIA,
                    .direction = ASE_DIRECTION_SINK
                   };
          disconnect_streams.push_back(type_1);
        }
        if (p_bta_data->profileType & WMCP) {
          type_1 = {.type = CONTENT_TYPE_MEDIA,
                    .audio_context = CONTENT_TYPE_LIVE,
                    .direction = ASE_DIRECTION_SRC
                   };
          disconnect_streams.push_back(type_1);
        }
      } else if (p_bta_data->contextType == CONTEXT_TYPE_MUSIC_VOICE) {
        StreamType type_2 = {.type = CONTENT_TYPE_CONVERSATIONAL,
                             .audio_context = CONTENT_TYPE_CONVERSATIONAL,
                             .direction = ASE_DIRECTION_SRC
                            };
        StreamType type_3 = {.type = CONTENT_TYPE_CONVERSATIONAL,
                             .audio_context = CONTENT_TYPE_CONVERSATIONAL,
                             .direction = ASE_DIRECTION_SINK
                            };
        disconnect_streams.push_back(type_3);
        disconnect_streams.push_back(type_2);
        StreamType type_1;
        if (p_bta_data->profileType & (BAP|GCP)) {
          type_1 = {.type = CONTENT_TYPE_MEDIA,
                    .audio_context = CONTENT_TYPE_MEDIA,
                    .direction = ASE_DIRECTION_SINK
                    };
          disconnect_streams.push_back(type_1);
        }
        if (p_bta_data->profileType & WMCP) {
          type_1 = {.type = CONTENT_TYPE_MEDIA,
                    .audio_context = CONTENT_TYPE_LIVE,
                    .direction = ASE_DIRECTION_SRC
                    };
          disconnect_streams.push_back(type_1);
        }
      } else if (p_bta_data->contextType == CONTEXT_TYPE_VOICE) {
        StreamType type_2 = {.type = CONTENT_TYPE_CONVERSATIONAL,
                             .audio_context = CONTENT_TYPE_CONVERSATIONAL,
                             .direction = ASE_DIRECTION_SRC
                            };
        StreamType type_3 = {.type = CONTENT_TYPE_CONVERSATIONAL,
                             .audio_context = CONTENT_TYPE_CONVERSATIONAL,
                             .direction = ASE_DIRECTION_SINK
                            };
        disconnect_streams.push_back(type_3);
        disconnect_streams.push_back(type_2);
      }
      LOG(WARNING) << __func__ << " size of disconnect_streams " << disconnect_streams.size();
      if (!sUcastClientInterface) break;
      sUcastClientInterface->Disconnect(peer_.PeerAddress(), disconnect_streams);

      if ((p_bta_data->contextType == CONTEXT_TYPE_MUSIC) && ((peer_.GetPeerVoiceRxState() == StreamState::CONNECTING) ||
          (peer_.GetPeerVoiceTxState() == StreamState::CONNECTING))) {
        LOG(WARNING) << __func__ << " voice connecting remain in opening ";
        btif_report_connection_state(peer_.PeerAddress(), BTACM_CONNECTION_STATE_DISCONNECTED, CONTEXT_TYPE_MUSIC);
      } else if ((p_bta_data->contextType == CONTEXT_TYPE_VOICE) && (peer_.GetPeerMusicTxState() == StreamState::CONNECTING ||
          (peer_.GetPeerMusicRxState() == StreamState::CONNECTING))) {
        LOG(WARNING) << __func__ << " Music connecting remain in opening ";
        btif_report_connection_state(peer_.PeerAddress(), BTACM_CONNECTION_STATE_DISCONNECTED, CONTEXT_TYPE_VOICE);
      } else {
        LOG(WARNING) << __func__ << " Move in idle state ";
        btif_report_connection_state(peer_.PeerAddress(), BTACM_CONNECTION_STATE_DISCONNECTED, CONTEXT_TYPE_MUSIC_VOICE);
        peer_.StateMachine().TransitionTo(BtifAcmStateMachine::kStateIdle);
      }
    }
    break;

    case BTIF_ACM_CONNECT_REQ_EVT: {
      BTIF_TRACE_WARNING(
          "%s: Peer %s : event=%s : device is already connecting, "
          "ignore Connect request",
          __PRETTY_FUNCTION__, peer_.PeerAddress().ToString().c_str(),
          BtifAcmEvent::EventName(event).c_str());
    } break;

    case BTA_ACM_CONFIG_EVT: {
       tBTIF_ACM* p_acm_data = (tBTIF_ACM*)p_data;
       uint16_t contextType = p_acm_data->state_info.stream_type.type;
       uint16_t peer_latency_ms = 0;
       uint32_t presen_delay = 0;
       bool is_update_require = false;
       if (contextType == CONTENT_TYPE_MEDIA) {
         if (p_acm_data->state_info.stream_type.audio_context == CONTENT_TYPE_MEDIA) {
           BTIF_TRACE_DEBUG("%s: compare with current media config", __PRETTY_FUNCTION__);
           is_update_require = compare_codec_config_(current_media_config, p_acm_data->config_info.codec_config);
         } else if (p_acm_data->state_info.stream_type.audio_context == CONTENT_TYPE_LIVE) {
           BTIF_TRACE_DEBUG("%s: cache current_recording_config", __PRETTY_FUNCTION__);
           current_recording_config = p_acm_data->config_info.codec_config;
         }
         if (mandatory_codec_selected) {
           BTIF_TRACE_DEBUG("%s: Mandatory codec selected, do not store config", __PRETTY_FUNCTION__);
         } else {
           BTIF_TRACE_DEBUG("%s: store configuration", __PRETTY_FUNCTION__);
         }
         //Cache the peer latency in WMCP case
         if (p_acm_data->state_info.stream_type.audio_context == CONTENT_TYPE_LIVE) {
           BTIF_TRACE_DEBUG("%s: presentation delay[0] = %x", __func__,
                            p_acm_data->config_info.qos_config.ascs_configs[0].presentation_delay[0]);
           BTIF_TRACE_DEBUG("%s: presentation delay[1] = %x", __func__,
                            p_acm_data->config_info.qos_config.ascs_configs[0].presentation_delay[1]);
           BTIF_TRACE_DEBUG("%s: presentation delay[2] = %x", __func__,
                            p_acm_data->config_info.qos_config.ascs_configs[0].presentation_delay[2]);
           presen_delay = static_cast<uint32_t>(p_acm_data->config_info.qos_config.ascs_configs[0].presentation_delay[0]) |
                          static_cast<uint32_t>(p_acm_data->config_info.qos_config.ascs_configs[0].presentation_delay[1] << 8) |
                          static_cast<uint32_t>(p_acm_data->config_info.qos_config.ascs_configs[0].presentation_delay[2] << 16);
           BTIF_TRACE_DEBUG("%s: presen_delay = %dus", __func__, presen_delay);
           peer_latency_ms = presen_delay/1000;
           BTIF_TRACE_DEBUG("%s: s_to_m latency = %dms", __func__,
                           p_acm_data->config_info.qos_config.cig_config.max_tport_latency_s_to_m);
           peer_latency_ms += p_acm_data->config_info.qos_config.cig_config.max_tport_latency_s_to_m;
           peer_.SetPeerLatency(peer_latency_ms);
           BTIF_TRACE_DEBUG("%s: cached peer Latency = %dms", __func__, peer_.GetPeerLatency());
         }
         if (is_update_require) {
           current_media_config = p_acm_data->config_info.codec_config;
           BTIF_TRACE_DEBUG("%s: current_media_config.codec_specific_3: %"
                                 PRIi64, __func__, current_media_config.codec_specific_3);
           btif_acm_update_lc3q_params(&current_media_config.codec_specific_3, p_acm_data);
           btif_acm_report_source_codec_state(peer_.PeerAddress(), current_media_config,
                                              unicast_codecs_capabilities,
                                              unicast_codecs_capabilities, CONTEXT_TYPE_MUSIC);
         }
       } else if (contextType == CONTENT_TYPE_CONVERSATIONAL &&
                  p_acm_data->state_info.stream_type.direction == ASE_DIRECTION_SINK) {
         BTIF_TRACE_DEBUG("%s: cache current_voice_config", __PRETTY_FUNCTION__);
         current_voice_config = p_acm_data->config_info.codec_config;
         BTIF_TRACE_DEBUG("%s: current_voice_config.codec_specific_3: %"
                               PRIi64, __func__, current_voice_config.codec_specific_3);
         btif_acm_update_lc3q_params(&current_voice_config.codec_specific_3, p_acm_data);
         btif_acm_report_source_codec_state(peer_.PeerAddress(), current_voice_config,
                                            unicast_codecs_capabilities,
                                            unicast_codecs_capabilities, CONTEXT_TYPE_VOICE);
       }
      //Handle BAP START if reconfig comes in mid of streaming
      //peer_.SetStreamReconfigInfo(p_acm->acm_reconfig);
      //TODO: local capabilities
      //CodecConfig record = p_bta_data->acm_reconfig.codec_config;
      //saving codec config as negotiated parameter as true
      //btif_pacs_add_record(peer_.PeerAddress(), true, CodecDirection::CODEC_DIR_SRC, &record);

    } break;

    case BTA_ACM_CONN_UPDATE_TIMEOUT_EVT:
      peer_.SetConnUpdateMode(BtifAcmPeer::kFlagRelaxedMode);
      break;

    default:
      BTIF_TRACE_WARNING("%s: Peer %s : Unhandled event=%s",
                         __PRETTY_FUNCTION__,
                         peer_.PeerAddress().ToString().c_str(),
                         BtifAcmEvent::EventName(event).c_str());
      return false;
  }
  return true;
}

bool btif_peer_device_is_streaming(uint8_t Id) {
    bool is_streaming = false;
    tBTA_CSIP_CSET cset_info;
    memset(&cset_info, 0, sizeof(tBTA_CSIP_CSET));
    cset_info = BTA_CsipGetCoordinatedSet(Id);
    if (cset_info.size == 0) {
      BTIF_TRACE_ERROR("%s: CSET info size is zero, return", __func__);
      return false;
    }
    std::vector<RawAddress>::iterator itr;
    BTIF_TRACE_DEBUG("%s: size of set members %d", __func__, (cset_info.set_members).size());
    if ((cset_info.set_members).size() > 0) {
      for (itr =(cset_info.set_members).begin(); itr != (cset_info.set_members).end(); itr++) {
        BtifAcmPeer* peer = btif_acm_initiator.FindPeer(*itr);
        if (peer != nullptr && (peer->IsStreaming() || peer->CheckFlags(BtifAcmPeer::kFlagPendingStart)) &&
            !peer->CheckFlags(BtifAcmPeer::kFlagPendingLocalSuspend)) {
          BTIF_TRACE_DEBUG("%s: fellow device is streaming %s ", __func__, peer->PeerAddress().ToString().c_str());
          is_streaming = true;
          break;
        }
      }
    }
    return is_streaming;
}

bool btif_peer_device_is_reconfiguring(uint8_t Id) {
    bool is_reconfigured = false;
    if (Id < INVALID_SET_ID) {
      tBTA_CSIP_CSET cset_info;
      memset(&cset_info, 0, sizeof(tBTA_CSIP_CSET));
      cset_info = BTA_CsipGetCoordinatedSet(Id);
      if (cset_info.size == 0) {
        BTIF_TRACE_ERROR("%s: CSET info size is zero, return", __func__);
        return false;
      }
      std::vector<RawAddress>::iterator itr;
      BTIF_TRACE_DEBUG("%s: size of set members %d", __func__, (cset_info.set_members).size());
      if ((cset_info.set_members).size() > 0) {
        for (itr =(cset_info.set_members).begin(); itr != (cset_info.set_members).end(); itr++) {
          BtifAcmPeer* peer = btif_acm_initiator.FindPeer(*itr);
          if (peer != nullptr && peer->CheckFlags(BtifAcmPeer::kFlagPendingReconfigure)) {
            BTIF_TRACE_DEBUG("%s: peer is reconfiguring %s ", __func__, peer->PeerAddress().ToString().c_str());
            is_reconfigured = true;
            break;
          }
        }
      }
    } else {
      is_reconfigured = true;
      BTIF_TRACE_ERROR("%s: peer is TWM device, return is_reconfigured %d", __func__, is_reconfigured);
    }
    return is_reconfigured;
}

void BtifAcmStateMachine::StateOpened::OnEnter() {
  BTIF_TRACE_DEBUG("%s: Peer %s, Peer SetId = %d, MusicActiveSetId = %d, ContextType = %d", __PRETTY_FUNCTION__,
                   peer_.PeerAddress().ToString().c_str(), peer_.SetId(),
                   btif_acm_initiator.MusicActiveCSetId(), peer_.GetContextType());

  //Starting the timer for 5 seconds before moving to relaxed state as
  //stop event or start streaming event moght immediately come
  //which requires aggresive interval
  if(btif_acm_initiator.IsConnUpdateEnabled()) {
    btif_acm_check_and_start_conn_Interval_timer(&peer_);
  }
  peer_.ClearFlags(BtifAcmPeer::kFlagPendingLocalSuspend |
                   BtifAcmPeer::kFlagPendingStart |
                   BtifAcmPeer::kFlagPendingStop);

  BTIF_TRACE_DEBUG("%s: kFlagPendingReconfigure %d and kFLagPendingStartAfterReconfig %d",  __PRETTY_FUNCTION__,
          peer_.CheckFlags(BtifAcmPeer::kFlagPendingReconfigure),
          peer_.CheckFlags(BtifAcmPeer::kFLagPendingStartAfterReconfig));

  if (peer_.CheckFlags(BtifAcmPeer::kFlagPendingReconfigure)) {
    peer_.ClearFlags(BtifAcmPeer::kFlagPendingReconfigure);
    if ((peer_.GetRcfgProfileType() != BAP_CALL) &&
            (current_active_profile_type != peer_.GetRcfgProfileType())) {
      current_active_profile_type = peer_.GetRcfgProfileType();
      if (current_active_profile_type != WMCP)
        current_active_config = current_media_config;
      else
        current_active_config = current_recording_config;

      if (btif_peer_device_is_reconfiguring(peer_.SetId()))
        btif_acm_source_restart_session(active_bda, active_bda);

      if (current_active_profile_type == WMCP) {
        uint16_t sink_latency = btif_acm_get_active_device_latency();
        BTIF_TRACE_EVENT("%s: sink_latency = %dms", __func__, sink_latency);
        if ((sink_latency > 0) && !btif_acm_update_sink_latency_change(sink_latency * 10)) {
        BTIF_TRACE_ERROR("%s: unable to update latency", __func__);
        }
      }
      if (current_active_profile_type == BAP) {
        peer_.ResetProfileType(GCP);
        peer_.SetProfileType(BAP);
      } else if (current_active_profile_type == GCP) {
        peer_.ResetProfileType(BAP);
        peer_.SetProfileType(GCP);
      }
      BTIF_TRACE_DEBUG("%s: cummulative_profile_type %d", __func__, peer_.GetProfileType());
      BTIF_TRACE_DEBUG("%s: Reconfig + restart session completed for media, signal session ready", __func__);
      btif_acm_signal_session_ready();
    } else if (current_active_profile_type == peer_.GetRcfgProfileType()) {
      BTIF_TRACE_DEBUG("%s: Reconfig to remote is completed for media, restart session wasn't needed", __func__);
    } else {
      BTIF_TRACE_DEBUG("%s: Reconfig completed for BAP_CALL", __func__);
    }
  }
  //Start the lock release timer here.
  //check if peer device is in started state
  if (btif_peer_device_is_streaming(peer_.SetId()) ||
      peer_.CheckFlags(BtifAcmPeer::kFLagPendingStartAfterReconfig)) {
    StreamType type_1, type_2;
    std::vector<StreamType> start_streams;
    if (peer_.GetRcfgProfileType() != BAP_CALL) {
      if ((current_active_profile_type == BAP || current_active_profile_type == GCP) &&
              (peer_.GetPeerMusicTxState() == StreamState::CONNECTED)) {
        type_1 = {.type = CONTENT_TYPE_MEDIA,
                  .audio_context = CONTENT_TYPE_MEDIA,
                  .direction = ASE_DIRECTION_SINK
                 };
        start_streams.push_back(type_1);
      } else if ((current_active_profile_type == WMCP) &&
              (peer_.GetPeerMusicRxState() == StreamState::CONNECTED)) {
        type_1 = {.type = CONTENT_TYPE_MEDIA,
                  .audio_context = CONTENT_TYPE_LIVE,
                  .direction = ASE_DIRECTION_SRC
                 };
        start_streams.push_back(type_1);
      }
    } else {
      if ((peer_.GetPeerVoiceTxState() == StreamState::CONNECTED) &&
              (peer_.GetPeerVoiceRxState() == StreamState::CONNECTED)) {
        type_1 = {.type = CONTENT_TYPE_CONVERSATIONAL,
                  .audio_context = CONTENT_TYPE_CONVERSATIONAL,
                  .direction = ASE_DIRECTION_SINK
                 };
        type_2 = {.type = CONTENT_TYPE_CONVERSATIONAL,
                  .audio_context = CONTENT_TYPE_CONVERSATIONAL,
                  .direction = ASE_DIRECTION_SRC
                 };
        start_streams.push_back(type_1);
        start_streams.push_back(type_2);
      }
    }

    if(btif_acm_initiator.IsConnUpdateEnabled()) {
      //Cancel the timer if start streamng comes before
      // 5 seconds while moving the interval to relaxed mode.
      if (alarm_is_scheduled(btif_acm_initiator.AcmConnIntervalTimer())) {
        btif_acm_check_and_cancel_conn_Interval_timer();
      } else {
        peer_.SetConnUpdateMode(BtifAcmPeer::kFlagAggresiveMode);
      }
    }
    sUcastClientInterface->Start(peer_.PeerAddress(), start_streams);
    peer_.SetFlags(BtifAcmPeer::kFlagPendingStart);
    peer_.ClearFlags(BtifAcmPeer::kFLagPendingStartAfterReconfig);
  }
  peer_.SetRcfgProfileType(0);

  if (peer_.StateMachine().PreviousStateId() == BtifAcmStateMachine::kStateStarted) {
    BTIF_TRACE_DEBUG("%s: Entering Opened from Started State", __PRETTY_FUNCTION__);
    if ((btif_acm_initiator.GetGroupLockStatus(peer_.SetId()) !=
         BtifAcmInitiator::kFlagStatusUnknown) &&
         alarm_is_scheduled(btif_acm_initiator.AcmGroupProcedureTimer())) {
      BTIF_TRACE_DEBUG("%s: All locked and stop/suspend requested device have stopped, ack mm audio", __func__);
      btif_acm_check_and_cancel_group_procedure_timer(btif_acm_initiator.MusicActiveCSetId());
      tA2DP_CTRL_CMD pending_cmd = btif_ahim_get_pending_command();
      if (pending_cmd == A2DP_CTRL_CMD_STOP ||
         pending_cmd == A2DP_CTRL_CMD_SUSPEND) {
        btif_acm_source_on_suspended(A2DP_CTRL_ACK_SUCCESS);
      } else if (pending_cmd == A2DP_CTRL_CMD_START) {
        btif_acm_on_started(A2DP_CTRL_ACK_SUCCESS);
      } else {
        BTIF_TRACE_DEBUG("%s: no pending command to ack mm audio", __func__);
      }
      btif_acm_check_and_start_lock_release_timer(btif_acm_initiator.MusicActiveCSetId());
    }
  }

  if (peer_.StateMachine().PreviousStateId() == BtifAcmStateMachine::kStateStarted) {
    if ((btif_acm_initiator.MusicActiveCSetId() > 0) &&
        (btif_acm_initiator.GetGroupLockStatus(btif_acm_initiator.MusicActiveCSetId()) == BtifAcmInitiator::kFlagStatusLocked)) {
      BTIF_TRACE_DEBUG("%s: Peer %s", __PRETTY_FUNCTION__, peer_.PeerAddress().ToString().c_str());
      btif_acm_check_and_start_lock_release_timer(btif_acm_initiator.MusicActiveCSetId());
    }
  }
}

void BtifAcmStateMachine::StateOpened::OnExit() {
  BTIF_TRACE_DEBUG("%s: Peer %s", __PRETTY_FUNCTION__,
                   peer_.PeerAddress().ToString().c_str());

  peer_.ClearFlags(BtifAcmPeer::kFlagPendingStart);
}

bool BtifAcmStateMachine::StateOpened::ProcessEvent(uint32_t event,
                                                   void* p_data) {
  tBTIF_ACM* p_acm = (tBTIF_ACM*)p_data;

  BTIF_TRACE_DEBUG("%s: Peer %s : event=%s flags=%s music_active_peer=%s voice_active_peer=%s",
                   __PRETTY_FUNCTION__, peer_.PeerAddress().ToString().c_str(),
                   BtifAcmEvent::EventName(event).c_str(),
                   peer_.FlagsToString().c_str(),
                   logbool(peer_.IsPeerActiveForMusic()).c_str(),
                   logbool(peer_.IsPeerActiveForVoice()).c_str());

  switch (event) {
    case BTIF_ACM_CONNECT_REQ_EVT: {
      tBTIF_ACM_CONN_DISC* p_bta_data = (tBTIF_ACM_CONN_DISC*)p_data;
      bool can_connect = true;
      // Check whether connection is allowed
      if (peer_.IsAcceptor()) {
        //There is no char in current spec. Should we check VMCP role here?
        // shall we assume VMCP role would have been checked in apps and no need to check here?
        can_connect = btif_acm_initiator.AllowedToConnect(peer_.PeerAddress());
        if (!can_connect) disconnect_acm_initiator(peer_.PeerAddress(), p_bta_data->contextType);
      }
      if (!can_connect) {
        BTIF_TRACE_ERROR(
            "%s: Cannot connect to peer %s: too many connected "
            "peers",
            __PRETTY_FUNCTION__, peer_.PeerAddress().ToString().c_str());
        break;
      }
      std::vector<StreamConnect> streams;
      if (p_bta_data->contextType == CONTEXT_TYPE_MUSIC) {
        StreamConnect conn_media;
        if (peer_.GetProfileType() & (BAP|GCP)) {
          //keeping media tx as BAP/GCP config
          memset(&conn_media, 0, sizeof(conn_media));
          fetch_media_tx_codec_qos_config(peer_.PeerAddress(), peer_.GetProfileType() & (BAP|GCP), &conn_media);
          streams.push_back(conn_media);
#if 0
          if (false) {//enable when GCP support is available
            SelectCodecQosConfig(peer_.PeerAddress(), (peer_.GetProfileType() & ~WMCP), VOICE_CONTEXT, SRC, EB_CONFIG);
            StreamConnect conn_voice;
            CodecQosConfig config;
            conn_voice.stream_type.type = CONTENT_TYPE_CONVERSATIONAL;
            conn_voice.stream_type.audio_context = CONTENT_TYPE_CONVERSATIONAL;
            config = peer_.get_peer_voice_rx_codec_qos_config();
            print_codec_parameters(config.codec_config);
            print_qos_parameters(config.qos_config);
            conn_voice.stream_type.direction = ASE_DIRECTION_SRC;
            conn_voice.codec_qos_config_pair.push_back(config);
            streams.push_back(conn_voice);
          }
#endif
        }
        if (peer_.GetProfileType() & WMCP) {
          //keeping media rx as WMCP config
          memset(&conn_media, 0, sizeof(conn_media));
          fetch_media_rx_codec_qos_config(peer_.PeerAddress(), WMCP, &conn_media);
          streams.push_back(conn_media);
        }
      } else if (p_bta_data->contextType == CONTEXT_TYPE_MUSIC_VOICE) {
	    StreamConnect conn_media, conn_voice;
        //keeping voice tx as BAP config
        memset(&conn_voice, 0, sizeof(conn_voice));
        fetch_voice_tx_codec_qos_config(peer_.PeerAddress(), BAP, &conn_voice);
        streams.push_back(conn_voice);
        //keeping voice rx as BAP config
        memset(&conn_voice, 0, sizeof(conn_voice));
        fetch_voice_rx_codec_qos_config(peer_.PeerAddress(), BAP, &conn_voice);
        streams.push_back(conn_voice);
        if (peer_.GetProfileType() & (BAP|GCP)) {
          //keeping media tx as BAP/GCP config
          memset(&conn_media, 0, sizeof(conn_media));
          fetch_media_tx_codec_qos_config(peer_.PeerAddress(), peer_.GetProfileType() & (BAP|GCP), &conn_media);
          streams.push_back(conn_media);
        }
        if (peer_.GetProfileType() & WMCP) {
          //keeping media rx as WMCP config
          memset(&conn_media, 0, sizeof(conn_media));
          fetch_media_rx_codec_qos_config(peer_.PeerAddress(), WMCP, &conn_media);
          streams.push_back(conn_media);
        }
      } else if (p_bta_data->contextType == CONTEXT_TYPE_VOICE) {
        StreamConnect conn_voice;
        //keeping voice tx as BAP config
        memset(&conn_voice, 0, sizeof(conn_voice));
        fetch_voice_tx_codec_qos_config(peer_.PeerAddress(), BAP, &conn_voice);
        streams.push_back(conn_voice);
        //keeping voice rx as BAP config
        memset(&conn_voice, 0, sizeof(conn_voice));
        fetch_voice_rx_codec_qos_config(peer_.PeerAddress(), BAP, &conn_voice);
        streams.push_back(conn_voice);
      }
      LOG(WARNING) << __func__ << " size of streams " << streams.size();
      if (!sUcastClientInterface) break;
      std::vector<RawAddress> address;
      address.push_back(peer_.PeerAddress());
      sUcastClientInterface->Connect(address, false, streams);
      //peer_.StateMachine().TransitionTo(BtifAcmStateMachine::kStateOpening);
    } break;

    case BTIF_ACM_STOP_STREAM_REQ_EVT:
    case BTIF_ACM_SUSPEND_STREAM_REQ_EVT: {
      BTIF_TRACE_DEBUG("%s: Already in OPENED state, ACK success", __PRETTY_FUNCTION__);
      tA2DP_CTRL_CMD pending_cmd = btif_ahim_get_pending_command();
      if (pending_cmd == A2DP_CTRL_CMD_STOP ||
         pending_cmd == A2DP_CTRL_CMD_SUSPEND) {
        btif_acm_source_on_suspended(A2DP_CTRL_ACK_SUCCESS);
      } else if (pending_cmd == A2DP_CTRL_CMD_START) {
        btif_acm_on_started(A2DP_CTRL_ACK_SUCCESS);
      } else {
        BTIF_TRACE_DEBUG("%s: no pending command to ack mm audio", __func__);
      }
    } break;

    case BTIF_ACM_START_STREAM_REQ_EVT: {
      LOG_INFO(LOG_TAG, "%s: Peer %s : event=%s flags=%s", __PRETTY_FUNCTION__,
              peer_.PeerAddress().ToString().c_str(),
              BtifAcmEvent::EventName(event).c_str(),
              peer_.FlagsToString().c_str());
      if (peer_.CheckFlags(BtifAcmPeer::kFlagPendingStart)) {
        BTIF_TRACE_DEBUG("%s: Ignore Start req", __PRETTY_FUNCTION__);
        break;
      }
#if 0
      //Can be either music or voice, prior to coming here,
      //this must have been evaluated for locking logic + grp logic
      StreamType type_1;
      std::vector<StreamType> start_streams;
      if (current_active_profile_type != WMCP) {
        if (peer_.GetStreamContextType() == CONTEXT_TYPE_MUSIC) {
          StreamType type_1 = {.type = CONTENT_TYPE_MEDIA,
                               .audio_context = CONTENT_TYPE_MEDIA,
                               .direction = ASE_DIRECTION_SINK
                              };
          start_streams.push_back(type_1);
        } else if (peer_.GetStreamContextType() == CONTEXT_TYPE_VOICE) {
          StreamType type_1 = {.type = CONTENT_TYPE_CONVERSATIONAL,
                               .audio_context = CONTENT_TYPE_CONVERSATIONAL,
                               .direction = ASE_DIRECTION_SINK
                              };
          StreamType type_2 = {.type = CONTENT_TYPE_CONVERSATIONAL,
                               .audio_context = CONTENT_TYPE_CONVERSATIONAL,
                               .direction = ASE_DIRECTION_SRC
                              };
          start_streams.push_back(type_1);
          start_streams.push_back(type_2);
          LOG_INFO(LOG_TAG, "%s: sending start for voice###", __PRETTY_FUNCTION__);
        }
      } else {
        type_1 = {.type = CONTENT_TYPE_MEDIA,
                  .audio_context = CONTENT_TYPE_LIVE,
                  .direction = ASE_DIRECTION_SRC
                 };
        start_streams.push_back(type_1);
      }

      if(btif_acm_initiator.IsConnUpdateEnabled()) {
        //Cancel the timer if start streamng comes before
        // 5 seconds while moving the interval to relaxed mode.
        if (alarm_is_scheduled(btif_acm_initiator.AcmConnIntervalTimer())) {
          btif_acm_check_and_cancel_conn_Interval_timer();
        } else {
          peer_.SetConnUpdateMode(BtifAcmPeer::kFlagAggresiveMode);
        }
      }
      if (!sUcastClientInterface) break;
        sUcastClientInterface->Start(peer_.PeerAddress(), start_streams);
#endif
#if 1
      if (peer_.GetStreamContextType() == CONTEXT_TYPE_MUSIC) {
        reconfig_acm_initiator(peer_.PeerAddress(), current_active_profile_type);
      } else if (peer_.GetStreamContextType() == CONTEXT_TYPE_VOICE) {
        reconfig_acm_initiator(peer_.PeerAddress(), BAP_CALL);
      }
      peer_.SetFlags(BtifAcmPeer::kFLagPendingStartAfterReconfig);
#endif
    }
    break;

    case BTA_ACM_START_EVT: {
      tBTIF_ACM_STATUS status = (uint8_t)p_acm->state_info.stream_state;
      //int contextType = p_acm->state_info.stream_type.type;
      LOG_INFO(LOG_TAG,
               "%s: Peer %s : event=%s status=%d ",
               __PRETTY_FUNCTION__, peer_.PeerAddress().ToString().c_str(),
               BtifAcmEvent::EventName(event).c_str(),status);

      if (p_acm->state_info.stream_state == StreamState::STARTING) {
        //Check what to do in this case
        BTIF_TRACE_DEBUG("%s: BAP returned as starting, ignore", __PRETTY_FUNCTION__);
        break;
      } else if (p_acm->state_info.stream_state == StreamState::STREAMING){
        peer_.ClearFlags(BtifAcmPeer::kFlagPendingStart);
        peer_.StateMachine().TransitionTo(BtifAcmStateMachine::kStateStarted);
      }
    } break;

    case BTIF_ACM_DISCONNECT_REQ_EVT:{
      tBTIF_ACM_CONN_DISC* p_bta_data = (tBTIF_ACM_CONN_DISC*)p_data;
      std::vector<StreamType> disconnect_streams;
      if (peer_.CheckFlags(BtifAcmPeer::kFlagPendingStart)) {
        peer_.ClearFlags(BtifAcmPeer::kFlagPendingStart);
        tA2DP_CTRL_CMD pending_cmd = btif_ahim_get_pending_command();
        if (pending_cmd == A2DP_CTRL_CMD_START) {
          btif_acm_on_started(A2DP_CTRL_ACK_DISCONNECT_IN_PROGRESS);
        }
      }
      if (p_bta_data->contextType == CONTEXT_TYPE_MUSIC) {
        StreamType type_1;
        if (p_bta_data->profileType & (BAP|GCP)) {
          type_1 = {.type = CONTENT_TYPE_MEDIA,
                    .audio_context = CONTENT_TYPE_MEDIA,
                    .direction = ASE_DIRECTION_SINK
                   };
          disconnect_streams.push_back(type_1);
        }
        if (p_bta_data->profileType & WMCP) {
          type_1 = {.type = CONTENT_TYPE_MEDIA,
                    .audio_context = CONTENT_TYPE_LIVE,
                    .direction = ASE_DIRECTION_SRC
                   };
          disconnect_streams.push_back(type_1);
        }
      } else if (p_bta_data->contextType == CONTEXT_TYPE_MUSIC_VOICE) {
        StreamType type_2 = {.type = CONTENT_TYPE_CONVERSATIONAL,
                             .audio_context = CONTENT_TYPE_CONVERSATIONAL,
                             .direction = ASE_DIRECTION_SRC
                            };
        StreamType type_3 = {.type = CONTENT_TYPE_CONVERSATIONAL,
                             .audio_context = CONTENT_TYPE_CONVERSATIONAL,
                             .direction = ASE_DIRECTION_SINK
                            };
        disconnect_streams.push_back(type_3);
        disconnect_streams.push_back(type_2);
        StreamType type_1;
        if (p_bta_data->profileType & (BAP|GCP)) {
          type_1 = {.type = CONTENT_TYPE_MEDIA,
                    .audio_context = CONTENT_TYPE_MEDIA,
                    .direction = ASE_DIRECTION_SINK
                    };
          disconnect_streams.push_back(type_1);
        }
        if (p_bta_data->profileType & WMCP) {
          type_1 = {.type = CONTENT_TYPE_MEDIA,
                    .audio_context = CONTENT_TYPE_LIVE,
                    .direction = ASE_DIRECTION_SRC
                    };
          disconnect_streams.push_back(type_1);
        }
      } else if (p_bta_data->contextType == CONTEXT_TYPE_VOICE) {
        StreamType type_2 = {.type = CONTENT_TYPE_CONVERSATIONAL,
                             .audio_context = CONTENT_TYPE_CONVERSATIONAL,
                             .direction = ASE_DIRECTION_SRC
                            };
        StreamType type_3 = {.type = CONTENT_TYPE_CONVERSATIONAL,
                             .audio_context = CONTENT_TYPE_CONVERSATIONAL,
                             .direction = ASE_DIRECTION_SINK
                            };
        disconnect_streams.push_back(type_3);
        disconnect_streams.push_back(type_2);
      }
      LOG(WARNING) << __func__ << " size of disconnect_streams " << disconnect_streams.size();
      if (!sUcastClientInterface) break;
      sUcastClientInterface->Disconnect(peer_.PeerAddress(), disconnect_streams);

      if ((p_bta_data->contextType == CONTEXT_TYPE_MUSIC) && ((peer_.GetPeerVoiceRxState() == StreamState::CONNECTED) ||
          (peer_.GetPeerVoiceTxState() == StreamState::CONNECTED))) {
        LOG(WARNING) << __func__ << " voice connected remain in opened ";
      } else if ((p_bta_data->contextType == CONTEXT_TYPE_VOICE) && ((peer_.GetPeerMusicTxState() == StreamState::CONNECTED) ||
          (peer_.GetPeerMusicRxState() == StreamState::CONNECTED))) {
        LOG(WARNING) << __func__ << " Music connected remain in opened ";
      } else {
        LOG(WARNING) << __func__ << " Move in closing state ";
        peer_.StateMachine().TransitionTo(BtifAcmStateMachine::kStateClosing);
      }
    } break;

    case BTA_ACM_STOP_EVT: { //Sumit: what is this case?
      int contextType = p_acm->acm_connect.streams_info.stream_type.type;
      btif_report_audio_state(peer_.PeerAddress(), BTACM_AUDIO_STATE_STOPPED, peer_.GetStreamContextType());
      if (contextType == CONTENT_TYPE_MEDIA)
        peer_.StateMachine().TransitionTo(BtifAcmStateMachine::kStateIdle);
    } break;

    case BTA_ACM_CONNECT_EVT: {// above evnt can come and handle for voice/media case
      tBTIF_ACM_STATUS status = (uint8_t)p_acm->state_info.stream_state;
      int contextType = p_acm->state_info.stream_type.type;

      LOG_INFO(
          LOG_TAG, "%s: Peer %s : event=%s status=%d",
          __PRETTY_FUNCTION__, peer_.PeerAddress().ToString().c_str(),
          BtifAcmEvent::EventName(event).c_str(),status);
      if (peer_.CheckFlags(BtifAcmPeer::kFlagPendingLocalSuspend)) {
        peer_.ClearFlags(BtifAcmPeer::kFlagPendingLocalSuspend);
        BTIF_TRACE_DEBUG("%s: peer device is suspended, send MM any pending ACK", __func__);
        tA2DP_CTRL_CMD pending_cmd = btif_ahim_get_pending_command();
        if (pending_cmd == A2DP_CTRL_CMD_STOP ||
         pending_cmd == A2DP_CTRL_CMD_SUSPEND) {
         btif_acm_source_on_suspended(A2DP_CTRL_ACK_SUCCESS);
        } else if (pending_cmd == A2DP_CTRL_CMD_START) {
          btif_acm_on_started(A2DP_CTRL_ACK_SUCCESS);
        } else {
         BTIF_TRACE_DEBUG("%s: no pending command to ack mm audio", __func__);
        }
        break;
      }
      if (p_acm->state_info.stream_state == StreamState::CONNECTED) {
        if (contextType == CONTENT_TYPE_MEDIA) {
          if ((btif_acm_initiator.MusicActivePeer() == peer_.PeerAddress()) &&
                  peer_.CheckFlags(BtifAcmPeer::kFlagPendingReconfigure)) { //recheck
            LOG(INFO) << __PRETTY_FUNCTION__ << " : Peer " << peer_.PeerAddress()
                  << " : Reconfig done - calling startSession() to audio HAL";
            std::promise<void> peer_ready_promise;
            std::future<void> peer_ready_future = peer_ready_promise.get_future();
            //TODO: cannot use peer addr here, must need group address.
            btif_acm_source_start_session(peer_.PeerAddress());
            //Perform group operation here
          } else if (((peer_.GetPeerVoiceRxState() == StreamState::CONNECTED) ||
                     (peer_.GetPeerVoiceTxState() == StreamState::CONNECTED) ||
                     (peer_.GetPeerMusicRxState() == StreamState::CONNECTED)) &&
                     (peer_.GetPeerMusicTxState() == StreamState::CONNECTING) &&
                     (p_acm->state_info.stream_type.direction == ASE_DIRECTION_SINK)) {
            BTIF_TRACE_DEBUG("%s: music Tx connected when either Voice Tx/Rx or Music Rx was connected,"
                             "remain in opened state", __func__);
            peer_.SetPeerMusicTxState(p_acm->state_info.stream_state);
            BTIF_TRACE_DEBUG("%s: received connected state from BAP for Music TX, update state", __func__);
            btif_report_connection_state(peer_.PeerAddress(),
                                         BTACM_CONNECTION_STATE_CONNECTED, CONTEXT_TYPE_MUSIC);
          } else if ((peer_.GetPeerMusicRxState() == StreamState::CONNECTING) &&
              (p_acm->state_info.stream_type.direction == ASE_DIRECTION_SRC)) {
            BTIF_TRACE_DEBUG("%s: received connected state from BAP for Music RX(recording), update state", __func__);
            peer_.SetPeerMusicRxState(p_acm->state_info.stream_state);
            btif_report_connection_state(peer_.PeerAddress(),
                                         BTACM_CONNECTION_STATE_CONNECTED, CONTEXT_TYPE_MUSIC);
          }
#if 0
          if (peer_.CheckFlags(BtifAcmPeer::kFlagPendingStart)) {
            LOG(INFO) << __PRETTY_FUNCTION__ << " : Peer " << peer_.PeerAddress()
                      << " : Reconfig done - calling BTA_AvStart()";
            StreamType type_1;
            if (current_active_profile_type != WMCP) {
              type_1 = {.type = CONTENT_TYPE_MEDIA,
                        .audio_context = CONTENT_TYPE_MEDIA,
                        .direction = ASE_DIRECTION_SINK
                       };
            } else {
              type_1 = {.type = CONTENT_TYPE_MEDIA,
                        .audio_context = CONTENT_TYPE_LIVE,
                        .direction = ASE_DIRECTION_SRC
                       };
            }
            std::vector<StreamType> start_streams;
            start_streams.push_back(type_1);
            if (!sUcastClientInterface) break;
            sUcastClientInterface->Start(peer_.PeerAddress(), start_streams);
          }
#endif
        } else if (contextType == CONTENT_TYPE_CONVERSATIONAL) {
          BTIF_TRACE_DEBUG("%s: voice context connected, remain in opened state"
                  " peer_.GetPeerVoiceTxState() %d peer_.GetPeerVoiceRxState() %d",
                  __func__, peer_.GetPeerVoiceTxState(), peer_.GetPeerVoiceRxState());
          if (p_acm->state_info.stream_type.direction == ASE_DIRECTION_SINK &&
                  (peer_.GetPeerVoiceTxState() != StreamState::CONNECTED)) {
            peer_.SetPeerVoiceTxState(p_acm->state_info.stream_state);
            if (peer_.GetPeerVoiceRxState() == StreamState::CONNECTED) {
              BTIF_TRACE_DEBUG("%s: received connected state from BAP for voice TX, update state", __func__);
              btif_report_connection_state(peer_.PeerAddress(),
                                           BTACM_CONNECTION_STATE_CONNECTED, CONTEXT_TYPE_VOICE);
            }
          } else if (p_acm->state_info.stream_type.direction == ASE_DIRECTION_SRC &&
                  (peer_.GetPeerVoiceRxState() != StreamState::CONNECTED)) {
            peer_.SetPeerVoiceRxState(p_acm->state_info.stream_state);
            if (peer_.GetPeerVoiceTxState() == StreamState::CONNECTED) {
              BTIF_TRACE_DEBUG("%s: received connected state from BAP for voice RX, update state", __func__);
              btif_report_connection_state(peer_.PeerAddress(),
                                           BTACM_CONNECTION_STATE_CONNECTED, CONTEXT_TYPE_VOICE);
            }
          }
        }
      } else if (p_acm->state_info.stream_state == StreamState::CONNECTING){
          if (contextType == CONTENT_TYPE_MEDIA) {
            BTIF_TRACE_DEBUG("%s: received connecting state from BAP for MEDIA Tx or Rx, ignore", __func__);
            if (p_acm->state_info.stream_type.direction == ASE_DIRECTION_SINK)
              peer_.SetPeerMusicTxState(p_acm->state_info.stream_state);
            else if (p_acm->state_info.stream_type.direction == ASE_DIRECTION_SRC)
              peer_.SetPeerMusicRxState(p_acm->state_info.stream_state);
          } else if (contextType == CONTENT_TYPE_CONVERSATIONAL) {
            BTIF_TRACE_DEBUG("%s: received connecting state from BAP for CONVERSATIONAL Tx or Rx, ignore", __func__);
            if (p_acm->state_info.stream_type.direction == ASE_DIRECTION_SINK) {
              peer_.SetPeerVoiceTxState(p_acm->state_info.stream_state);
            } else if (p_acm->state_info.stream_type.direction == ASE_DIRECTION_SRC) {
              peer_.SetPeerVoiceRxState(p_acm->state_info.stream_state);
            }
          }
      }
    } break;

    case BTA_ACM_DISCONNECT_EVT: {
      int context_type = p_acm->state_info.stream_type.type;
      if (p_acm->state_info.stream_state == StreamState::DISCONNECTED) {
        if (context_type == CONTENT_TYPE_MEDIA) {
          if (p_acm->state_info.stream_type.direction == ASE_DIRECTION_SINK) {
            peer_.SetPeerMusicTxState(p_acm->state_info.stream_state);
          } else if (p_acm->state_info.stream_type.direction == ASE_DIRECTION_SRC) {
            peer_.SetPeerMusicRxState(p_acm->state_info.stream_state);
          }
          if (peer_.GetPeerMusicTxState() == StreamState::DISCONNECTED &&
              peer_.GetPeerMusicRxState() == StreamState::DISCONNECTED) {
            btif_report_connection_state(peer_.PeerAddress(),
                BTACM_CONNECTION_STATE_DISCONNECTED, CONTEXT_TYPE_MUSIC);
          }
          if (peer_.GetPeerVoiceRxState() == StreamState::DISCONNECTED &&
               peer_.GetPeerVoiceTxState() == StreamState::DISCONNECTED &&
               peer_.GetPeerMusicTxState() == StreamState::DISCONNECTED &&
               peer_.GetPeerMusicRxState() == StreamState::DISCONNECTED) {
            BTIF_TRACE_DEBUG("%s: received Media Tx/Rx disconnected state from BAP"
                      " when Voice Tx+Rx & Media Rx/Tx was disconnected, move in idle state", __func__);
            peer_.StateMachine().TransitionTo(BtifAcmStateMachine::kStateIdle);
          } else {
            BTIF_TRACE_DEBUG("%s: received Media Tx/Rx disconnected state from BAP"
                      " when either Voice Tx or Rx or Media Rx/Tx is connected, remain in opened state", __func__);
          }
        } else if (context_type == CONTENT_TYPE_CONVERSATIONAL) {
          if (p_acm->state_info.stream_type.direction == ASE_DIRECTION_SINK) {
            peer_.SetPeerVoiceTxState(p_acm->state_info.stream_state);
            if (peer_.GetPeerVoiceRxState() == StreamState::DISCONNECTED) {
              btif_report_connection_state(peer_.PeerAddress(), BTACM_CONNECTION_STATE_DISCONNECTED, CONTEXT_TYPE_VOICE);
              if (peer_.GetPeerMusicTxState() == StreamState::DISCONNECTED &&
                  peer_.GetPeerMusicRxState() == StreamState::DISCONNECTED) {
                BTIF_TRACE_DEBUG("%s: received disconnected state from BAP for voice Tx,"
                                 " voice Rx, Music Tx & Rx are disconnected move in idle state", __func__);
                peer_.StateMachine().TransitionTo(BtifAcmStateMachine::kStateIdle);
              } else {
                BTIF_TRACE_DEBUG("%s: received disconnected state from BAP for voice Tx,"
                                 " voice Rx is disconnected but music Tx or Rx still not disconnected,"
                                 " remain in opened state", __func__);
              }
            }
          } else if (p_acm->state_info.stream_type.direction == ASE_DIRECTION_SRC) {
            peer_.SetPeerVoiceRxState(p_acm->state_info.stream_state);
            if (peer_.GetPeerVoiceTxState() == StreamState::DISCONNECTED) {
              btif_report_connection_state(peer_.PeerAddress(), BTACM_CONNECTION_STATE_DISCONNECTED, CONTEXT_TYPE_VOICE);
              if (peer_.GetPeerMusicTxState() == StreamState::DISCONNECTED &&
                  peer_.GetPeerMusicRxState() == StreamState::DISCONNECTED) {
                BTIF_TRACE_DEBUG("%s: received disconnected state from BAP for voice Rx,"
                                 " voice Tx, Music Tx & Rx are disconnected move in idle state", __func__);
                peer_.StateMachine().TransitionTo(BtifAcmStateMachine::kStateIdle);
              } else {
                BTIF_TRACE_DEBUG("%s: received disconnected state from BAP for voice Rx,"
                                 " voice Rx is disconnected but music Tx or Rx still not disconnected,"
                                 " remain in opened state", __func__);
              }
            }
          }
        }
      } else if (p_acm->state_info.stream_state == StreamState::DISCONNECTING) {
        if (context_type == CONTENT_TYPE_MEDIA) {
          if (p_acm->state_info.stream_type.direction == ASE_DIRECTION_SINK) {
            peer_.SetPeerMusicTxState(p_acm->state_info.stream_state);
          } else if (p_acm->state_info.stream_type.direction == ASE_DIRECTION_SRC) {
            peer_.SetPeerMusicRxState(p_acm->state_info.stream_state);
          }
          btif_report_connection_state(peer_.PeerAddress(),
                                  BTACM_CONNECTION_STATE_DISCONNECTING, CONTEXT_TYPE_MUSIC);
          if ((peer_.GetPeerVoiceRxState() == StreamState::DISCONNECTED ||
                peer_.GetPeerVoiceRxState() == StreamState::DISCONNECTING) &&
               (peer_.GetPeerVoiceTxState() == StreamState::DISCONNECTED ||
                peer_.GetPeerVoiceTxState() == StreamState::DISCONNECTING) &&
               (peer_.GetPeerMusicTxState() == StreamState::DISCONNECTED ||
                peer_.GetPeerMusicTxState() == StreamState::DISCONNECTING) &&
               (peer_.GetPeerMusicRxState() == StreamState::DISCONNECTED ||
                peer_.GetPeerMusicRxState() == StreamState::DISCONNECTING)) {
              BTIF_TRACE_DEBUG("%s: received Media Tx/Rx disconnecting state from BAP"
                               " when Voice Tx+Rx and Media Rx/Tx disconnected/ing, move in closing state", __func__);
              peer_.StateMachine().TransitionTo(BtifAcmStateMachine::kStateClosing);
          } else {
              BTIF_TRACE_DEBUG("%s: received Media Tx/Rx disconnecting state from BAP"
                               " when either Voice Tx or Rx or Media Rx/Tx is connected, remain in opened state", __func__);
          }
        } else if (context_type == CONTENT_TYPE_CONVERSATIONAL) {
          if (p_acm->state_info.stream_type.direction == ASE_DIRECTION_SINK) {
            peer_.SetPeerVoiceTxState(p_acm->state_info.stream_state);
            if (peer_.GetPeerVoiceRxState() == StreamState::DISCONNECTING ||
                peer_.GetPeerVoiceRxState() == StreamState::DISCONNECTED) {
              btif_report_connection_state(peer_.PeerAddress(), BTACM_CONNECTION_STATE_DISCONNECTING, CONTEXT_TYPE_VOICE);
              if (((peer_.GetPeerMusicTxState() == StreamState::DISCONNECTED) ||
                  (peer_.GetPeerMusicTxState() == StreamState::DISCONNECTING)) &&
                  ((peer_.GetPeerMusicRxState() == StreamState::DISCONNECTED) ||
                  (peer_.GetPeerMusicRxState() == StreamState::DISCONNECTING))) {
                BTIF_TRACE_DEBUG("%s: received disconnecting state from BAP for voice Tx,"
                                 " voice Rx, music Tx+Rx are disconnected/ing move in closing state", __func__);
                peer_.StateMachine().TransitionTo(BtifAcmStateMachine::kStateClosing);
              } else {
                BTIF_TRACE_DEBUG("%s: received disconnecting state from BAP for voice Tx,"
                                 " voice Rx is disconncted/ing but music Tx or Rx still not disconnected/ing,"
                                 " remain in opened state", __func__);
              }
            }
          } else if (p_acm->state_info.stream_type.direction == ASE_DIRECTION_SRC) {
            peer_.SetPeerVoiceRxState(p_acm->state_info.stream_state);
            if (peer_.GetPeerVoiceTxState() == StreamState::DISCONNECTING ||
                peer_.GetPeerVoiceTxState() == StreamState::DISCONNECTED) {
              btif_report_connection_state(peer_.PeerAddress(), BTACM_CONNECTION_STATE_DISCONNECTING, CONTEXT_TYPE_VOICE);
              if (((peer_.GetPeerMusicTxState() == StreamState::DISCONNECTED) ||
                  (peer_.GetPeerMusicTxState() == StreamState::DISCONNECTING)) &&
                  ((peer_.GetPeerMusicRxState() == StreamState::DISCONNECTED) ||
                  (peer_.GetPeerMusicRxState() == StreamState::DISCONNECTING))) {
                BTIF_TRACE_DEBUG("%s: received disconnecting state from BAP for voice Rx,"
                                 " voice Tx, music Tx+Rx are disconnected/ing move in closing state", __func__);
                peer_.StateMachine().TransitionTo(BtifAcmStateMachine::kStateClosing);
              } else {
                BTIF_TRACE_DEBUG("%s: received disconnected state from BAP for voice Rx,"
                                 " voice Tx is disconncted/ing but music Tx or Rx still not disconnected/ing,"
                                 " remain in opened state", __func__);
              }
            }
          }
        }
      }
    }
    break;

    case BTIF_ACM_RECONFIG_REQ_EVT: {
        std::vector<StreamReconfig> reconf_streams;
        StreamReconfig reconf_info;
        CodecQosConfig cfg;
        if (p_acm->acm_reconfig.streams_info.stream_type.type != CONTENT_TYPE_CONVERSATIONAL) {
          reconf_info.stream_type.type = p_acm->acm_reconfig.streams_info.stream_type.type;
          reconf_info.stream_type.audio_context =
                           p_acm->acm_reconfig.streams_info.stream_type.audio_context;
          reconf_info.stream_type.direction = p_acm->acm_reconfig.streams_info.stream_type.direction;
          reconf_info.reconf_type = p_acm->acm_reconfig.streams_info.reconf_type;
          cfg = peer_.get_peer_media_codec_qos_config();
          reconf_info.codec_qos_config_pair.push_back(cfg);
          reconf_streams.push_back(reconf_info);
        } else {
          reconf_info.stream_type.type = CONTENT_TYPE_CONVERSATIONAL;
          reconf_info.stream_type.audio_context = CONTENT_TYPE_CONVERSATIONAL;
          reconf_info.stream_type.direction = ASE_DIRECTION_SRC;
          reconf_info.reconf_type = bluetooth::bap::ucast::StreamReconfigType::CODEC_CONFIG;
          if (peer_.IsStereoHsType()) {
            SelectCodecQosConfig(peer_.PeerAddress(), BAP, VOICE_CONTEXT, SRC, STEREO_HS_CONFIG_1);
          } else {
            SelectCodecQosConfig(peer_.PeerAddress(), BAP, VOICE_CONTEXT, SRC, EB_CONFIG);
          }
          cfg = peer_.get_peer_voice_rx_codec_qos_config();
          print_codec_parameters(cfg.codec_config);
          print_qos_parameters(cfg.qos_config);
          reconf_info.codec_qos_config_pair.push_back(cfg);
          reconf_streams.push_back(reconf_info);

          reconf_info.stream_type.type = CONTENT_TYPE_CONVERSATIONAL;
          reconf_info.stream_type.audio_context = CONTENT_TYPE_CONVERSATIONAL;
          reconf_info.stream_type.direction = ASE_DIRECTION_SINK;
          reconf_info.reconf_type = bluetooth::bap::ucast::StreamReconfigType::CODEC_CONFIG;
          if (peer_.IsStereoHsType()) {
            SelectCodecQosConfig(peer_.PeerAddress(), BAP, VOICE_CONTEXT, SRC, STEREO_HS_CONFIG_1);
          } else {
            SelectCodecQosConfig(peer_.PeerAddress(), BAP, VOICE_CONTEXT, SRC, EB_CONFIG);
          }
          cfg = peer_.get_peer_voice_tx_codec_qos_config();
          print_codec_parameters(cfg.codec_config);
          print_qos_parameters(cfg.qos_config);
          reconf_info.codec_qos_config_pair.push_back(cfg);
          reconf_streams.push_back(reconf_info);

          peer_.SetPeerVoiceRxState(StreamState::RECONFIGURING);
          peer_.SetPeerVoiceTxState(StreamState::RECONFIGURING);
        }
        if (!sUcastClientInterface) break;
          sUcastClientInterface->Reconfigure(peer_.PeerAddress(), reconf_streams);
        peer_.SetFlags(BtifAcmPeer::kFlagPendingReconfigure);
        peer_.StateMachine().TransitionTo(BtifAcmStateMachine::kStateReconfiguring);
    }
    break;
    case BTA_ACM_CONFIG_EVT: {
       tBTIF_ACM* p_acm_data = (tBTIF_ACM*)p_data;
       uint16_t contextType = p_acm_data->state_info.stream_type.type;
       uint16_t peer_latency_ms = 0;
       uint32_t presen_delay = 0;
       bool is_update_require = false;
       if (contextType == CONTENT_TYPE_MEDIA) {
         if (p_acm_data->state_info.stream_type.audio_context == CONTENT_TYPE_MEDIA) {
           BTIF_TRACE_DEBUG("%s: compare with current media config", __PRETTY_FUNCTION__);
           is_update_require = compare_codec_config_(current_media_config, p_acm_data->config_info.codec_config);
         } else if (p_acm_data->state_info.stream_type.audio_context == CONTENT_TYPE_LIVE) {
           BTIF_TRACE_DEBUG("%s: cache current_recording_config", __PRETTY_FUNCTION__);
           current_recording_config = p_acm_data->config_info.codec_config;
         }
         if (mandatory_codec_selected) {
           BTIF_TRACE_DEBUG("%s: Mandatory codec selected, do not store config", __PRETTY_FUNCTION__);
         } else {
           BTIF_TRACE_DEBUG("%s: store configuration", __PRETTY_FUNCTION__);
         }
         //Cache the peer latency in WMCP case
         if (p_acm_data->state_info.stream_type.audio_context == CONTENT_TYPE_LIVE) {
           BTIF_TRACE_DEBUG("%s: presentation delay[0] = %x", __func__,
                            p_acm_data->config_info.qos_config.ascs_configs[0].presentation_delay[0]);
           BTIF_TRACE_DEBUG("%s: presentation delay[1] = %x", __func__,
                            p_acm_data->config_info.qos_config.ascs_configs[0].presentation_delay[1]);
           BTIF_TRACE_DEBUG("%s: presentation delay[2] = %x", __func__,
                            p_acm_data->config_info.qos_config.ascs_configs[0].presentation_delay[2]);
           presen_delay = static_cast<uint32_t>(p_acm_data->config_info.qos_config.ascs_configs[0].presentation_delay[0]) |
                          static_cast<uint32_t>(p_acm_data->config_info.qos_config.ascs_configs[0].presentation_delay[1] << 8) |
                          static_cast<uint32_t>(p_acm_data->config_info.qos_config.ascs_configs[0].presentation_delay[2] << 16);
           BTIF_TRACE_DEBUG("%s: presen_delay = %dus", __func__, presen_delay);
           peer_latency_ms = presen_delay/1000;
           BTIF_TRACE_DEBUG("%s: s_to_m latency = %dms", __func__,
                           p_acm_data->config_info.qos_config.cig_config.max_tport_latency_s_to_m);
           peer_latency_ms += p_acm_data->config_info.qos_config.cig_config.max_tport_latency_s_to_m;
           peer_.SetPeerLatency(peer_latency_ms);
           BTIF_TRACE_DEBUG("%s: cached peer Latency = %dms", __func__, peer_.GetPeerLatency());
         }
         if (is_update_require) {
           current_media_config = p_acm_data->config_info.codec_config;
           BTIF_TRACE_DEBUG("%s: current_media_config.codec_specific_3: %"
                                 PRIi64, __func__, current_media_config.codec_specific_3);
           btif_acm_update_lc3q_params(&current_media_config.codec_specific_3, p_acm_data);
           btif_acm_report_source_codec_state(peer_.PeerAddress(), current_media_config,
                                              unicast_codecs_capabilities,
                                              unicast_codecs_capabilities, CONTEXT_TYPE_MUSIC);
         }
       } else if (contextType == CONTENT_TYPE_CONVERSATIONAL &&
                  p_acm_data->state_info.stream_type.direction == ASE_DIRECTION_SINK) {
         BTIF_TRACE_DEBUG("%s: cache current_voice_config", __PRETTY_FUNCTION__);
         current_voice_config = p_acm_data->config_info.codec_config;
         BTIF_TRACE_DEBUG("%s: current_voice_config.codec_specific_3: %"
                               PRIi64, __func__, current_voice_config.codec_specific_3);
         btif_acm_update_lc3q_params(&current_voice_config.codec_specific_3, p_acm_data);
         btif_acm_report_source_codec_state(peer_.PeerAddress(), current_voice_config,
                                            unicast_codecs_capabilities,
                                            unicast_codecs_capabilities, CONTEXT_TYPE_VOICE);
       }
      //Handle BAP START if reconfig comes in mid of streaming
      //peer_.SetStreamReconfigInfo(p_acm->acm_reconfig);
      //TODO: local capabilities
      //CodecConfig record = p_bta_data->acm_reconfig.codec_config;
      //saving codec config as negotiated parameter as true
      //btif_pacs_add_record(peer_.PeerAddress(), true, CodecDirection::CODEC_DIR_SRC, &record);

    } break;

    case BTA_ACM_CONN_UPDATE_TIMEOUT_EVT:
      peer_.SetConnUpdateMode(BtifAcmPeer::kFlagRelaxedMode);
      break;

    default:
      BTIF_TRACE_WARNING("%s: Peer %s : Unhandled event=%s",
                         __PRETTY_FUNCTION__,
                         peer_.PeerAddress().ToString().c_str(),
                         BtifAcmEvent::EventName(event).c_str());
      return false;
  }
  return true;
}

bool btif_acm_check_if_requested_devices_started() {
  std::vector<RawAddress>::iterator itr;
  if ((btif_acm_initiator.locked_devices).size() > 0) {
    for (itr = (btif_acm_initiator.locked_devices).begin(); itr != (btif_acm_initiator.locked_devices).end(); itr++) {
      BTIF_TRACE_DEBUG("%s: address =%s", __func__, *itr->ToString().c_str());
      BtifAcmPeer* peer = btif_acm_initiator.FindPeer(*itr);
      if ((peer == nullptr) || (peer != nullptr && !peer->IsStreaming())) {
        break;
      }
    }
    if (itr == (btif_acm_initiator.locked_devices).end()) {
      return true;
    }
  }
  return false;
}

bool btif_acm_check_if_requested_devices_stopped() {
  std::vector<RawAddress>::iterator itr;
  if ((btif_acm_initiator.locked_devices).size() > 0) {
    for (itr = (btif_acm_initiator.locked_devices).begin(); itr != (btif_acm_initiator.locked_devices).end(); itr++) {
      BTIF_TRACE_DEBUG("%s: address =%s", __func__, *itr->ToString().c_str());
      BtifAcmPeer* peer = btif_acm_initiator.FindPeer(*itr);
      if ((peer == nullptr) || (peer != nullptr /*&& !peer->IsSuspended()*/)) {
        break;
      }
    }
    if (itr == (btif_acm_initiator.locked_devices).end()) {
      return true;
    }
  }
  return false;
}

void BtifAcmStateMachine::StateStarted::OnEnter() {
  BTIF_TRACE_DEBUG("%s: Peer %s, Peer SetId = %d, MusicActiveSetId = %d, ContextType = %d", __PRETTY_FUNCTION__,
                   peer_.PeerAddress().ToString().c_str(),
                   peer_.SetId(), btif_acm_initiator.MusicActiveCSetId(), peer_.GetContextType());

  if(btif_acm_initiator.IsConnUpdateEnabled()) {
    //Starting the timer for 5 seconds before moving to relaxed state as
    //stop event or start streaming event moght immediately come
    //which requires aggresive interval
    btif_acm_check_and_start_conn_Interval_timer(&peer_);
  }

  // Report that we have entered the Streaming stage. Usually, this should
  // be followed by focus grant. See update_audio_focus_state()
  btif_report_audio_state(peer_.PeerAddress(), BTACM_AUDIO_STATE_STARTED, peer_.GetStreamContextType());
  if (alarm_is_scheduled(btif_acm_initiator.AcmGroupProcedureTimer())) {
    btif_acm_check_and_cancel_group_procedure_timer(btif_acm_initiator.MusicActiveCSetId());
    tA2DP_CTRL_CMD pending_cmd = btif_ahim_get_pending_command();
    if (pending_cmd == A2DP_CTRL_CMD_STOP ||
       pending_cmd == A2DP_CTRL_CMD_SUSPEND) {
      btif_acm_source_on_suspended(A2DP_CTRL_ACK_SUCCESS);
    } else if (pending_cmd == A2DP_CTRL_CMD_START) {
      btif_acm_on_started(A2DP_CTRL_ACK_SUCCESS);
    } else {
      BTIF_TRACE_DEBUG("%s: no pending command to ack mm audio", __func__);
    }
  } else {
    BTIF_TRACE_DEBUG("%s:no group procedure timer running ACK pending cmd", __func__);
    tA2DP_CTRL_CMD pending_cmd = btif_ahim_get_pending_command();
    if (pending_cmd == A2DP_CTRL_CMD_STOP ||
       pending_cmd == A2DP_CTRL_CMD_SUSPEND) {
      btif_acm_source_on_suspended(A2DP_CTRL_ACK_SUCCESS);
    } else if (pending_cmd == A2DP_CTRL_CMD_START) {
      btif_acm_on_started(A2DP_CTRL_ACK_SUCCESS);
    } else {
      BTIF_TRACE_DEBUG("%s: no pending command to ack mm audio", __func__);
    }
  }
#if 0
  if ((btif_acm_initiator.GetGroupLockStatus(peer_.SetId()) != BtifAcmInitiator::kFlagStatusUnknown) &&
       alarm_is_scheduled(btif_acm_initiator.AcmGroupProcedureTimer())) {
    BTIF_TRACE_DEBUG("%s: All locked and start requested device have started, ack mm audio", __func__);
    //in this case, we need to change channel mode to stereo
    btif_acm_check_and_cancel_group_procedure_timer(btif_acm_initiator.MusicActiveCSetId());
    tA2DP_CTRL_CMD pending_cmd = btif_ahim_get_pending_command();
    if (pending_cmd == A2DP_CTRL_CMD_STOP ||
       pending_cmd == A2DP_CTRL_CMD_SUSPEND) {
      btif_acm_source_on_suspended(A2DP_CTRL_ACK_SUCCESS);
    } else if (pending_cmd == A2DP_CTRL_CMD_START) {
      btif_acm_on_started(A2DP_CTRL_ACK_SUCCESS);
    } else {
      BTIF_TRACE_DEBUG("%s: no pending command to ack mm audio", __func__);
    }
    btif_acm_check_and_start_lock_release_timer(btif_acm_initiator.MusicActiveCSetId());
  }

  //Start the lock release timer here.
  if ((btif_acm_initiator.MusicActiveCSetId() != INVALID_SET_ID) &&
      (btif_acm_initiator.GetGroupLockStatus(btif_acm_initiator.MusicActiveCSetId()) == BtifAcmInitiator::kFlagStatusLocked)) {
    BTIF_TRACE_DEBUG("%s: ", __PRETTY_FUNCTION__, peer_.PeerAddress().ToString().c_str());
    btif_acm_check_and_start_lock_release_timer(btif_acm_initiator.MusicActiveCSetId());
  }
  if (!btif_acm_initiator.IsMusicActiveGroupStarted()) {
    if (peer_.SetId() == btif_acm_initiator.MusicActiveCSetId())
      btif_acm_initiator.SetMusicActiveGroupStarted(true);
  }
#endif

}

void BtifAcmStateMachine::StateStarted::OnExit() {
  BTIF_TRACE_DEBUG("%s: Peer %s", __PRETTY_FUNCTION__,
                   peer_.PeerAddress().ToString().c_str());
}

bool BtifAcmStateMachine::StateStarted::ProcessEvent(uint32_t event, void* p_data) {
  tBTIF_ACM* p_acm = (tBTIF_ACM*)p_data;

  BTIF_TRACE_DEBUG("%s: Peer %s : event=%s flags=%s music_active_peer=%s voice_active_peer=%s",
                   __PRETTY_FUNCTION__, peer_.PeerAddress().ToString().c_str(),
                   BtifAcmEvent::EventName(event).c_str(),
                   peer_.FlagsToString().c_str(),
                   logbool(peer_.IsPeerActiveForMusic()).c_str(),
                   logbool(peer_.IsPeerActiveForVoice()).c_str());

  switch (event) {
    case BTIF_ACM_STOP_STREAM_REQ_EVT:
    case BTIF_ACM_SUSPEND_STREAM_REQ_EVT: {
      LOG_INFO(LOG_TAG, "%s: Peer %s : event=%s flags=%s", __PRETTY_FUNCTION__,
               peer_.PeerAddress().ToString().c_str(),
               BtifAcmEvent::EventName(event).c_str(),
               peer_.FlagsToString().c_str());
      peer_.SetFlags(BtifAcmPeer::kFlagPendingLocalSuspend);

      StreamType type_1;
      std::vector<StreamType> stop_streams;
      if (peer_.GetStreamContextType() == CONTEXT_TYPE_MUSIC) {
        if (current_active_profile_type != WMCP) {
          type_1 = {.type = CONTENT_TYPE_MEDIA,
                    .audio_context = CONTENT_TYPE_MEDIA,
                    .direction = ASE_DIRECTION_SINK
                   };
          stop_streams.push_back(type_1);
        } else {
          type_1 = {.type = CONTENT_TYPE_MEDIA,
                    .audio_context = CONTENT_TYPE_LIVE,
                    .direction = ASE_DIRECTION_SRC
                   };
          stop_streams.push_back(type_1);
        }
      } else if (peer_.GetStreamContextType() == CONTEXT_TYPE_VOICE) {
        StreamType type_2;
        type_1 = {.type = CONTENT_TYPE_CONVERSATIONAL,
                  .audio_context = CONTENT_TYPE_CONVERSATIONAL,
                  .direction = ASE_DIRECTION_SINK
                 };
        type_2 = {.type = CONTENT_TYPE_CONVERSATIONAL,
                  .audio_context = CONTENT_TYPE_CONVERSATIONAL,
                  .direction = ASE_DIRECTION_SRC
                 };
        stop_streams.push_back(type_2);
        stop_streams.push_back(type_1);
      }
      if(btif_acm_initiator.IsConnUpdateEnabled()) {
        //Cancel the timer if start streamng comes before
        // 5 seconds while moving the interval to relaxed mode.
        if (alarm_is_scheduled(btif_acm_initiator.AcmConnIntervalTimer())) {
           btif_acm_check_and_cancel_conn_Interval_timer();
        }
        else {
          peer_.SetConnUpdateMode(BtifAcmPeer::kFlagAggresiveMode);
        }
      }

      if (!sUcastClientInterface) break;
        sUcastClientInterface->Stop(peer_.PeerAddress(), stop_streams);
    }
    break;

    case BTIF_ACM_DISCONNECT_REQ_EVT: {
      int contextType = p_acm->state_info.stream_type.type;
      LOG_INFO(LOG_TAG, "%s: Peer %s : event=%s flags=%s contextType=%d", __PRETTY_FUNCTION__,
               peer_.PeerAddress().ToString().c_str(),
               BtifAcmEvent::EventName(event).c_str(),
               peer_.FlagsToString().c_str(), contextType);

      tBTIF_ACM_CONN_DISC* p_bta_data = (tBTIF_ACM_CONN_DISC*)p_data;
      std::vector<StreamType> disconnect_streams;
      if (p_bta_data->contextType == CONTEXT_TYPE_MUSIC) {
        StreamType type_1;
        if (p_bta_data->profileType & (BAP|GCP)) {
          type_1 = {.type = CONTENT_TYPE_MEDIA,
                    .audio_context = CONTENT_TYPE_MEDIA,
                    .direction = ASE_DIRECTION_SINK
                   };
          disconnect_streams.push_back(type_1);
        }
        if (p_bta_data->profileType & WMCP) {
          type_1 = {.type = CONTENT_TYPE_MEDIA,
                    .audio_context = CONTENT_TYPE_LIVE,
                    .direction = ASE_DIRECTION_SRC
                   };
          disconnect_streams.push_back(type_1);
        }
      } else if (p_bta_data->contextType == CONTEXT_TYPE_MUSIC_VOICE) {
        StreamType type_2 = {.type = CONTENT_TYPE_CONVERSATIONAL,
                             .audio_context = CONTENT_TYPE_CONVERSATIONAL,
                             .direction = ASE_DIRECTION_SRC
                            };
        StreamType type_3 = {.type = CONTENT_TYPE_CONVERSATIONAL,
                             .audio_context = CONTENT_TYPE_CONVERSATIONAL,
                             .direction = ASE_DIRECTION_SINK
                            };
        disconnect_streams.push_back(type_3);
        disconnect_streams.push_back(type_2);
        StreamType type_1;
        if (p_bta_data->profileType & (BAP|GCP)) {
          type_1 = {.type = CONTENT_TYPE_MEDIA,
                    .audio_context = CONTENT_TYPE_MEDIA,
                    .direction = ASE_DIRECTION_SINK
                    };
          disconnect_streams.push_back(type_1);
        }
        if (p_bta_data->profileType & WMCP) {
          type_1 = {.type = CONTENT_TYPE_MEDIA,
                    .audio_context = CONTENT_TYPE_LIVE,
                    .direction = ASE_DIRECTION_SRC
                    };
          disconnect_streams.push_back(type_1);
        }
      } else if (p_bta_data->contextType == CONTEXT_TYPE_VOICE) {
        StreamType type_2 = {.type = CONTENT_TYPE_CONVERSATIONAL,
                             .audio_context = CONTENT_TYPE_CONVERSATIONAL,
                             .direction = ASE_DIRECTION_SRC
                            };
        StreamType type_3 = {.type = CONTENT_TYPE_CONVERSATIONAL,
                             .audio_context = CONTENT_TYPE_CONVERSATIONAL,
                             .direction = ASE_DIRECTION_SINK
                            };
        disconnect_streams.push_back(type_3);
        disconnect_streams.push_back(type_2);
      }
      LOG(WARNING) << __func__ << " size of disconnect_streams " << disconnect_streams.size();
      if (!sUcastClientInterface) break;
      sUcastClientInterface->Disconnect(peer_.PeerAddress(), disconnect_streams);

      // Inform the application that we are disconnecting
      if ((p_bta_data->contextType == CONTEXT_TYPE_MUSIC) && ((peer_.GetPeerVoiceRxState() == StreamState::CONNECTED) ||
          (peer_.GetPeerVoiceTxState() == StreamState::CONNECTED))) {
        LOG(WARNING) << __func__ << " voice connected move in opened state ";
        peer_.StateMachine().TransitionTo(BtifAcmStateMachine::kStateOpened);
      } else if ((p_bta_data->contextType == CONTEXT_TYPE_VOICE) && ((peer_.GetPeerMusicTxState() == StreamState::CONNECTED) ||
          (peer_.GetPeerMusicRxState() == StreamState::CONNECTED))) {
        LOG(WARNING) << __func__ << " Music connected remain in started state ";
      } else {
        LOG(WARNING) << __func__ << " Move in closing state ";
        peer_.StateMachine().TransitionTo(BtifAcmStateMachine::kStateClosing);
      }
    }
    break;

    case BTA_ACM_STOP_EVT: {
      int contextType = p_acm->state_info.stream_type.type;
      LOG_INFO(LOG_TAG, "%s: Peer %s : event=%s flags=%s", __PRETTY_FUNCTION__,
               peer_.PeerAddress().ToString().c_str(),
               BtifAcmEvent::EventName(event).c_str(),
               peer_.FlagsToString().c_str());
      if (contextType == CONTENT_TYPE_MEDIA) {
        BTIF_TRACE_DEBUG("%s: STOPPING event came from BAP for Media, ignore", __func__);
      } else if (contextType == CONTENT_TYPE_CONVERSATIONAL) {
        BTIF_TRACE_DEBUG("%s: STOPPING event came from BAP for Voice, ignore", __func__);
      }
    }
    break;

    case BTA_ACM_DISCONNECT_EVT: {
      int context_type = p_acm->state_info.stream_type.type;
      if (p_acm->state_info.stream_state == StreamState::DISCONNECTED) {
        if (context_type == CONTENT_TYPE_MEDIA) {
          if (p_acm->state_info.stream_type.direction == ASE_DIRECTION_SINK) {
            peer_.SetPeerMusicTxState(p_acm->state_info.stream_state);
          } else if (p_acm->state_info.stream_type.direction == ASE_DIRECTION_SRC) {
            peer_.SetPeerMusicRxState(p_acm->state_info.stream_state);
          }
          if (peer_.GetPeerMusicTxState() == StreamState::DISCONNECTED &&
              peer_.GetPeerMusicRxState() == StreamState::DISCONNECTED) {
            btif_report_connection_state(peer_.PeerAddress(),
                BTACM_CONNECTION_STATE_DISCONNECTED, CONTEXT_TYPE_MUSIC);
          }
          if (peer_.GetPeerVoiceRxState() == StreamState::DISCONNECTED &&
               peer_.GetPeerVoiceTxState() == StreamState::DISCONNECTED &&
               peer_.GetPeerMusicTxState() == StreamState::DISCONNECTED &&
               peer_.GetPeerMusicRxState() == StreamState::DISCONNECTED) {
            BTIF_TRACE_DEBUG("%s: received Media Tx/Rx disconnected state from BAP"
                      " when Voice Tx+Rx & Media Rx/Tx was disconnected, move in idle state", __func__);
            peer_.StateMachine().TransitionTo(BtifAcmStateMachine::kStateIdle);
          } else {
            BTIF_TRACE_DEBUG("%s: received Media Tx/Rx disconnected state from BAP"
                      " when either Voice Tx or Rx or Media Rx/Tx is connected, remain in started state", __func__);
          }
        } else if (context_type == CONTENT_TYPE_CONVERSATIONAL) {
          if (p_acm->state_info.stream_type.direction == ASE_DIRECTION_SINK) {
            peer_.SetPeerVoiceTxState(p_acm->state_info.stream_state);
            if (peer_.GetPeerVoiceRxState() == StreamState::DISCONNECTED) {
              btif_report_connection_state(peer_.PeerAddress(), BTACM_CONNECTION_STATE_DISCONNECTED, CONTEXT_TYPE_VOICE);
              if (peer_.GetPeerMusicTxState() == StreamState::DISCONNECTED &&
                  peer_.GetPeerMusicRxState() == StreamState::DISCONNECTED) {
                BTIF_TRACE_DEBUG("%s: received disconnected state from BAP for voice Tx,"
                                 " voice Rx, Music Tx & Rx are disconnected move in idle state", __func__);
                peer_.StateMachine().TransitionTo(BtifAcmStateMachine::kStateIdle);
              } else {
                BTIF_TRACE_DEBUG("%s: received disconnected state from BAP for voice Tx,"
                                 " voice Rx is disconnected but music Tx or Rx still not disconnected,"
                                 " remain in started state", __func__);
              }
            }
          } else if (p_acm->state_info.stream_type.direction == ASE_DIRECTION_SRC) {
            peer_.SetPeerVoiceRxState(p_acm->state_info.stream_state);
            if (peer_.GetPeerVoiceTxState() == StreamState::DISCONNECTED) {
              btif_report_connection_state(peer_.PeerAddress(), BTACM_CONNECTION_STATE_DISCONNECTED, CONTEXT_TYPE_VOICE);
              if (peer_.GetPeerMusicTxState() == StreamState::DISCONNECTED &&
                  peer_.GetPeerMusicRxState() == StreamState::DISCONNECTED) {
                BTIF_TRACE_DEBUG("%s: received disconnected state from BAP for voice Rx,"
                                 " voice Tx, Music Tx & Rx are disconnected move in idle state", __func__);
                peer_.StateMachine().TransitionTo(BtifAcmStateMachine::kStateIdle);
              } else {
                BTIF_TRACE_DEBUG("%s: received disconnected state from BAP for voice Rx,"
                                 " voice Rx is disconnected but music Tx or Rx still not disconnected,"
                                 " remain in started state", __func__);
              }
            }
          }
        }
      } else if (p_acm->state_info.stream_state == StreamState::DISCONNECTING) {
        if (context_type == CONTENT_TYPE_MEDIA) {
          if (p_acm->state_info.stream_type.direction == ASE_DIRECTION_SINK) {
            peer_.SetPeerMusicTxState(p_acm->state_info.stream_state);
          } else if (p_acm->state_info.stream_type.direction == ASE_DIRECTION_SRC) {
            peer_.SetPeerMusicRxState(p_acm->state_info.stream_state);
          }
          if ((peer_.GetPeerVoiceRxState() == StreamState::DISCONNECTED ||
                peer_.GetPeerVoiceRxState() == StreamState::DISCONNECTING) &&
               (peer_.GetPeerVoiceTxState() == StreamState::DISCONNECTED ||
                peer_.GetPeerVoiceTxState() == StreamState::DISCONNECTING) &&
               (peer_.GetPeerMusicTxState() == StreamState::DISCONNECTED ||
                peer_.GetPeerMusicTxState() == StreamState::DISCONNECTING) &&
               (peer_.GetPeerMusicRxState() == StreamState::DISCONNECTED ||
                peer_.GetPeerMusicRxState() == StreamState::DISCONNECTING)) {
              BTIF_TRACE_DEBUG("%s: received Media Tx/Rx disconnecting state from BAP"
                               " when Voice Tx+Rx and Media Rx/Tx disconnected/ing, move in closing state", __func__);
              peer_.StateMachine().TransitionTo(BtifAcmStateMachine::kStateClosing);
          } else {
              if (peer_.GetStreamContextType() == CONTEXT_TYPE_MUSIC) {
                std::vector<StreamType> disconnect_streams;
                btif_report_audio_state(peer_.PeerAddress(), BTACM_AUDIO_STATE_STOPPED, CONTEXT_TYPE_MUSIC);
                BTIF_TRACE_DEBUG("%s: received Media Tx/Rx disconnecting state from BAP while streaming"
                    " when either Voice Tx or Rx or Media Rx/Tx is connected, move to opened state", __func__);
                if (peer_.GetPeerMusicTxState() == StreamState::DISCONNECTING) {
                    BTIF_TRACE_DEBUG("%s: Received disconnecting for Music-Tx, initiate for Rx also", __func__);
                    StreamType type_1;
                    type_1 = {.type = CONTENT_TYPE_MEDIA,
                              .audio_context = CONTENT_TYPE_LIVE,
                              .direction = ASE_DIRECTION_SRC
                             };
                    disconnect_streams.push_back(type_1);
                    if (!sUcastClientInterface) break;
                    sUcastClientInterface->Disconnect(peer_.PeerAddress(), disconnect_streams);
                }
                if (peer_.GetPeerMusicRxState() == StreamState::DISCONNECTING) {
                    BTIF_TRACE_DEBUG("%s: Received disconnecting for Music-Rx, initiate for Tx also", __func__);
                    StreamType type_1;
                    type_1 = {.type = CONTENT_TYPE_MEDIA,
                              .audio_context = CONTENT_TYPE_MEDIA,
                              .direction = ASE_DIRECTION_SINK
                             };
                    disconnect_streams.push_back(type_1);
                    if (!sUcastClientInterface) break;
                    sUcastClientInterface->Disconnect(peer_.PeerAddress(), disconnect_streams);
                }
                peer_.StateMachine().TransitionTo(BtifAcmStateMachine::kStateOpened);
              } else {
                BTIF_TRACE_DEBUG("%s: received Media Tx/Rx disconnecting state from BAP"
                    " when either Voice Tx or Rx or Media Rx/Tx is connected, remain in started state", __func__);
              }
          }
          btif_report_connection_state(peer_.PeerAddress(),
                                  BTACM_CONNECTION_STATE_DISCONNECTING, CONTEXT_TYPE_MUSIC);
        } else if (context_type == CONTENT_TYPE_CONVERSATIONAL) {
          if (p_acm->state_info.stream_type.direction == ASE_DIRECTION_SINK) {
            peer_.SetPeerVoiceTxState(p_acm->state_info.stream_state);
            if (peer_.GetPeerVoiceRxState() == StreamState::DISCONNECTING ||
                peer_.GetPeerVoiceRxState() == StreamState::DISCONNECTED) {
              if (((peer_.GetPeerMusicTxState() == StreamState::DISCONNECTED) ||
                  (peer_.GetPeerMusicTxState() == StreamState::DISCONNECTING)) &&
                  ((peer_.GetPeerMusicRxState() == StreamState::DISCONNECTED) ||
                  (peer_.GetPeerMusicRxState() == StreamState::DISCONNECTING))) {
                BTIF_TRACE_DEBUG("%s: received disconnecting state from BAP for voice Tx,"
                                 " voice Rx, music Tx+Rx are disconnected/ing move in closing state", __func__);
                peer_.StateMachine().TransitionTo(BtifAcmStateMachine::kStateClosing);
              } else {
                if (peer_.GetStreamContextType() == CONTEXT_TYPE_VOICE) {
                  btif_report_audio_state(peer_.PeerAddress(), BTACM_AUDIO_STATE_STOPPED, CONTEXT_TYPE_VOICE);
                  BTIF_TRACE_DEBUG("%s: received disconnecting state from BAP for voice Tx while streaming,"
                                   " voice Rx is disconncted/ing but music Tx or Rx still not disconnected/ing,"
                                   " move to opened state", __func__);
                  peer_.StateMachine().TransitionTo(BtifAcmStateMachine::kStateOpened);
                } else {
                  BTIF_TRACE_DEBUG("%s: received disconnecting state from BAP for voice Tx,"
                                   " voice Rx is disconncted/ing but music Tx or Rx still not disconnected/ing,"
                                   " remain in started state", __func__);
                }
              }
              btif_report_connection_state(peer_.PeerAddress(), BTACM_CONNECTION_STATE_DISCONNECTING, CONTEXT_TYPE_VOICE);
            }
          } else if (p_acm->state_info.stream_type.direction == ASE_DIRECTION_SRC) {
            peer_.SetPeerVoiceRxState(p_acm->state_info.stream_state);
            if (peer_.GetPeerVoiceTxState() == StreamState::DISCONNECTING ||
                peer_.GetPeerVoiceTxState() == StreamState::DISCONNECTED) {
              if (((peer_.GetPeerMusicTxState() == StreamState::DISCONNECTED) ||
                  (peer_.GetPeerMusicTxState() == StreamState::DISCONNECTING)) &&
                  ((peer_.GetPeerMusicRxState() == StreamState::DISCONNECTED) ||
                  (peer_.GetPeerMusicRxState() == StreamState::DISCONNECTING))) {
                BTIF_TRACE_DEBUG("%s: received disconnecting state from BAP for voice Rx,"
                                 " voice Tx, music Tx+Rx are disconnected/ing move in closing state", __func__);
                peer_.StateMachine().TransitionTo(BtifAcmStateMachine::kStateClosing);
              } else {
                if (peer_.GetStreamContextType() == CONTEXT_TYPE_VOICE) {
                  btif_report_audio_state(peer_.PeerAddress(), BTACM_AUDIO_STATE_STOPPED, CONTEXT_TYPE_VOICE);
                  BTIF_TRACE_DEBUG("%s: received disconnected state from BAP for voice Rx while streaming,"
                                   " voice Tx is disconncted/ing but music Tx or Rx still not disconnected/ing,"
                                   " move to Opened state", __func__);
                  peer_.StateMachine().TransitionTo(BtifAcmStateMachine::kStateOpened);
                } else {
                  BTIF_TRACE_DEBUG("%s: received disconnected state from BAP for voice Rx,"
                                   " voice Tx is disconncted/ing but music Tx or Rx still not disconnected/ing,"
                                   " remain in started state", __func__);
                }
              }
              btif_report_connection_state(peer_.PeerAddress(), BTACM_CONNECTION_STATE_DISCONNECTING, CONTEXT_TYPE_VOICE);
            }
          }
        }
      }
    }
    break;

    case BTA_ACM_CONNECT_EVT: {// above evnt can come and handle for voice/media case
      int contextType = p_acm->state_info.stream_type.type;
      LOG_INFO(
          LOG_TAG, "%s: Peer %s : event=%s context=%d",
          __PRETTY_FUNCTION__, peer_.PeerAddress().ToString().c_str(),
          BtifAcmEvent::EventName(event).c_str(), contextType);
      LOG_INFO(
          LOG_TAG, "%s: context=%d, converted=%d, Streaming context=%d",
          __PRETTY_FUNCTION__, contextType, btif_acm_bap_to_acm_context(contextType), peer_.GetStreamContextType());
      if (btif_acm_bap_to_acm_context(contextType) != peer_.GetStreamContextType()) {
        if (contextType == CONTENT_TYPE_MEDIA) {
          if (p_acm->state_info.stream_type.direction == ASE_DIRECTION_SRC) {
            if (p_acm->state_info.stream_state == StreamState::CONNECTED) {
              BTIF_TRACE_DEBUG("%s: received connected state from BAP for Music Rx, update state", __func__);
              peer_.SetPeerMusicRxState(p_acm->state_info.stream_state);
            } else if (p_acm->state_info.stream_state == StreamState::CONNECTING){
              BTIF_TRACE_DEBUG("%s: received connecting state from BAP for Music Rx, ignore", __func__);
              peer_.SetPeerMusicRxState(p_acm->state_info.stream_state);
            }
          } else if (p_acm->state_info.stream_type.direction == ASE_DIRECTION_SINK) {
            if (p_acm->state_info.stream_state == StreamState::CONNECTED) {
              BTIF_TRACE_DEBUG("%s: received connected state from BAP for Music Tx, update state", __func__);
              peer_.SetPeerMusicTxState(p_acm->state_info.stream_state);
            } else if (p_acm->state_info.stream_state == StreamState::CONNECTING){
              BTIF_TRACE_DEBUG("%s: received connecting state from BAP for Music Tx, ignore", __func__);
              peer_.SetPeerMusicTxState(p_acm->state_info.stream_state);
            }
          }
          if (p_acm->state_info.stream_state == StreamState::CONNECTED)
            btif_report_connection_state(peer_.PeerAddress(),
                    BTACM_CONNECTION_STATE_CONNECTED, CONTEXT_TYPE_MUSIC);
        } else if (contextType == CONTENT_TYPE_CONVERSATIONAL) {
          if (p_acm->state_info.stream_state == StreamState::CONNECTED) {
            BTIF_TRACE_DEBUG("%s: voice context connected, remain in started state", __func__);
            if (p_acm->state_info.stream_type.direction == ASE_DIRECTION_SINK) {
              peer_.SetPeerVoiceTxState(p_acm->state_info.stream_state);
              if (peer_.GetPeerVoiceRxState() == StreamState::CONNECTED) {
                BTIF_TRACE_DEBUG("%s: received connected state from BAP for voice Tx, update state", __func__);
                btif_report_connection_state(peer_.PeerAddress(),
                                             BTACM_CONNECTION_STATE_CONNECTED, CONTEXT_TYPE_VOICE);
              }
            } else if (p_acm->state_info.stream_type.direction == ASE_DIRECTION_SRC) {
              peer_.SetPeerVoiceRxState(p_acm->state_info.stream_state);
              if (peer_.GetPeerVoiceTxState() == StreamState::CONNECTED) {
                BTIF_TRACE_DEBUG("%s: received connected state from BAP for voice Rx, update state", __func__);
                btif_report_connection_state(peer_.PeerAddress(),
                                             BTACM_CONNECTION_STATE_CONNECTED, CONTEXT_TYPE_VOICE);
              }
            }
          } else if (p_acm->state_info.stream_state == StreamState::CONNECTING) {
            BTIF_TRACE_DEBUG("%s: received connecting state from BAP for voice Tx or Rx, ignore", __func__);
            if (p_acm->state_info.stream_type.direction == ASE_DIRECTION_SINK) {
              peer_.SetPeerVoiceTxState(p_acm->state_info.stream_state);
            } else if (p_acm->state_info.stream_type.direction == ASE_DIRECTION_SRC) {
              peer_.SetPeerVoiceRxState(p_acm->state_info.stream_state);
            }
          }
        }
      } else {
        if (peer_.CheckFlags(BtifAcmPeer::kFlagPendingLocalSuspend)) {
          peer_.ClearFlags(BtifAcmPeer::kFlagPendingLocalSuspend);
          BTIF_TRACE_DEBUG("%s: peer device is suspended, send MM any pending ACK", __func__);
          tA2DP_CTRL_CMD pending_cmd = btif_ahim_get_pending_command();
          if (pending_cmd == A2DP_CTRL_CMD_STOP ||
            pending_cmd == A2DP_CTRL_CMD_SUSPEND) {
            btif_acm_source_on_suspended(A2DP_CTRL_ACK_SUCCESS);
          } else if (pending_cmd == A2DP_CTRL_CMD_START) {
            btif_acm_on_started(A2DP_CTRL_ACK_SUCCESS);
          } else {
            BTIF_TRACE_DEBUG("%s: no pending command to ack mm audio", __func__);
          }
          BTIF_TRACE_DEBUG("%s: report STOP to apps and move to Opened", __func__);
          btif_report_audio_state(peer_.PeerAddress(), BTACM_AUDIO_STATE_STOPPED, peer_.GetStreamContextType());
          peer_.StateMachine().TransitionTo(BtifAcmStateMachine::kStateOpened);
        }
      }
      if (alarm_is_scheduled(btif_acm_initiator.AcmGroupProcedureTimer()))
        btif_acm_check_and_cancel_group_procedure_timer(btif_acm_initiator.MusicActiveCSetId());

    } break;

    case BTIF_ACM_RECONFIG_REQ_EVT: {
        BTIF_TRACE_DEBUG("%s: sending stop to BAP before reconfigure", __func__);
        btif_a2dp_source_end_session(active_bda);
        peer_.SetFlags(BtifAcmPeer::kFlagPendingLocalSuspend);
        StreamType type_1;
        std::vector<StreamType> stop_streams;
        if (peer_.GetStreamContextType() == CONTEXT_TYPE_MUSIC) {
          if (current_active_profile_type != WMCP) {
            type_1 = {.type = CONTENT_TYPE_MEDIA,
                      .audio_context = CONTENT_TYPE_MEDIA,
                      .direction = ASE_DIRECTION_SINK
                     };
            stop_streams.push_back(type_1);
          } else {
            type_1 = {.type = CONTENT_TYPE_MEDIA,
                      .audio_context = CONTENT_TYPE_LIVE,
                      .direction = ASE_DIRECTION_SRC
                     };
            stop_streams.push_back(type_1);
          }
        } else if (peer_.GetStreamContextType() == CONTEXT_TYPE_VOICE) {
          StreamType type_2;
          type_1 = {.type = CONTENT_TYPE_CONVERSATIONAL,
                    .audio_context = CONTENT_TYPE_CONVERSATIONAL,
                    .direction = ASE_DIRECTION_SINK
                   };
          type_2 = {.type = CONTENT_TYPE_CONVERSATIONAL,
                    .audio_context = CONTENT_TYPE_CONVERSATIONAL,
                    .direction = ASE_DIRECTION_SRC
                   };
          stop_streams.push_back(type_2);
          stop_streams.push_back(type_1);
        }
        if (!sUcastClientInterface) break;
          sUcastClientInterface->Stop(peer_.PeerAddress(), stop_streams);
        peer_.StateMachine().TransitionTo(BtifAcmStateMachine::kStateReconfiguring);
    }
    break;

    case BTA_ACM_CONFIG_EVT: {
       tBTIF_ACM* p_acm_data = (tBTIF_ACM*)p_data;
       uint16_t contextType = p_acm_data->state_info.stream_type.type;
       uint16_t peer_latency_ms = 0;
       uint32_t presen_delay = 0;
       bool is_update_require = false;
       if (contextType == CONTENT_TYPE_MEDIA) {
         if (p_acm_data->state_info.stream_type.audio_context == CONTENT_TYPE_MEDIA) {
           BTIF_TRACE_DEBUG("%s: compare current_media_config", __PRETTY_FUNCTION__);
           is_update_require = compare_codec_config_(current_media_config, p_acm_data->config_info.codec_config);
         } else if (p_acm_data->state_info.stream_type.audio_context == CONTENT_TYPE_LIVE) {
           BTIF_TRACE_DEBUG("%s: cache current_recording_config", __PRETTY_FUNCTION__);
           current_recording_config = p_acm_data->config_info.codec_config;
         }
         if (mandatory_codec_selected) {
           BTIF_TRACE_DEBUG("%s: Mandatory codec selected, do not store config", __PRETTY_FUNCTION__);
         } else {
           BTIF_TRACE_DEBUG("%s: store configuration", __PRETTY_FUNCTION__);
         }
         //Cache the peer latency in WMCP case
         if (p_acm_data->state_info.stream_type.audio_context == CONTENT_TYPE_LIVE) {
           BTIF_TRACE_DEBUG("%s: presentation delay[0] = %x", __func__,
                            p_acm_data->config_info.qos_config.ascs_configs[0].presentation_delay[0]);
           BTIF_TRACE_DEBUG("%s: presentation delay[1] = %x", __func__,
                            p_acm_data->config_info.qos_config.ascs_configs[0].presentation_delay[1]);
           BTIF_TRACE_DEBUG("%s: presentation delay[2] = %x", __func__,
                            p_acm_data->config_info.qos_config.ascs_configs[0].presentation_delay[2]);
           presen_delay = static_cast<uint32_t>(p_acm_data->config_info.qos_config.ascs_configs[0].presentation_delay[0]) |
                          static_cast<uint32_t>(p_acm_data->config_info.qos_config.ascs_configs[0].presentation_delay[1] << 8) |
                          static_cast<uint32_t>(p_acm_data->config_info.qos_config.ascs_configs[0].presentation_delay[2] << 16);
           BTIF_TRACE_DEBUG("%s: presen_delay = %dus", __func__, presen_delay);
           peer_latency_ms = presen_delay/1000;
           BTIF_TRACE_DEBUG("%s: s_to_m latency = %dms", __func__,
                           p_acm_data->config_info.qos_config.cig_config.max_tport_latency_s_to_m);
           peer_latency_ms += p_acm_data->config_info.qos_config.cig_config.max_tport_latency_s_to_m;
           peer_.SetPeerLatency(peer_latency_ms);
           BTIF_TRACE_DEBUG("%s: cached peer Latency = %dms", __func__, peer_.GetPeerLatency());
         }
         if (is_update_require) {
           current_media_config = p_acm_data->config_info.codec_config;
           BTIF_TRACE_DEBUG("%s: current_media_config.codec_specific_3: %"
                                 PRIi64, __func__, current_media_config.codec_specific_3);
           btif_acm_update_lc3q_params(&current_media_config.codec_specific_3, p_acm_data);
           btif_acm_report_source_codec_state(peer_.PeerAddress(), current_media_config,
                                              unicast_codecs_capabilities,
                                              unicast_codecs_capabilities, CONTEXT_TYPE_MUSIC);
         }
       } else if (contextType == CONTENT_TYPE_CONVERSATIONAL &&
                  p_acm_data->state_info.stream_type.direction == ASE_DIRECTION_SINK) {
         BTIF_TRACE_DEBUG("%s: cache current_voice_config", __PRETTY_FUNCTION__);
         current_voice_config = p_acm_data->config_info.codec_config;
         BTIF_TRACE_DEBUG("%s: current_voice_config.codec_specific_3: %"
                               PRIi64, __func__, current_voice_config.codec_specific_3);
         btif_acm_update_lc3q_params(&current_voice_config.codec_specific_3, p_acm_data);
         btif_acm_report_source_codec_state(peer_.PeerAddress(), current_voice_config,
                                            unicast_codecs_capabilities,
                                            unicast_codecs_capabilities, CONTEXT_TYPE_VOICE);
       }
      //Handle BAP START if reconfig comes in mid of streaming
      //peer_.SetStreamReconfigInfo(p_acm->acm_reconfig);
      //TODO: local capabilities
      //CodecConfig record = p_bta_data->acm_reconfig.codec_config;
      //saving codec config as negotiated parameter as true
      //btif_pacs_add_record(peer_.PeerAddress(), true, CodecDirection::CODEC_DIR_SRC, &record);

    } break;

    case BTA_ACM_CONN_UPDATE_TIMEOUT_EVT:
      peer_.SetConnUpdateMode(BtifAcmPeer::kFlagRelaxedMode);
      break;

    default:
      BTIF_TRACE_WARNING("%s: Peer %s : Unhandled event=%s",
                         __PRETTY_FUNCTION__,
                         peer_.PeerAddress().ToString().c_str(),
                         BtifAcmEvent::EventName(event).c_str());
      return false;
  }

  return true;
}

void BtifAcmStateMachine::StateReconfiguring::OnEnter() {
  BTIF_TRACE_DEBUG("%s: Peer %s", __PRETTY_FUNCTION__,
                   peer_.PeerAddress().ToString().c_str());
  if(btif_acm_initiator.IsConnUpdateEnabled()) {
    //Cancel the timer if running if  not, move to aggressive mode
    if (alarm_is_scheduled(btif_acm_initiator.AcmConnIntervalTimer())) {
       btif_acm_check_and_cancel_conn_Interval_timer();
    } else {
       BTIF_TRACE_DEBUG("%s: conn timer not running, push aggressive intervals", __func__);
       peer_.SetConnUpdateMode(BtifAcmPeer::kFlagAggresiveMode);
    }
  }
}

void BtifAcmStateMachine::StateReconfiguring::OnExit() {
  BTIF_TRACE_DEBUG("%s: Peer %s", __PRETTY_FUNCTION__,
                   peer_.PeerAddress().ToString().c_str());
}

bool BtifAcmStateMachine::StateReconfiguring::ProcessEvent(uint32_t event, void* p_data) {
  tBTIF_ACM* p_acm = (tBTIF_ACM*)p_data;
  BTIF_TRACE_DEBUG("%s: Peer %s : event=%s flags=%s music_active_peer=%s voice_active_peer=%s",
                   __PRETTY_FUNCTION__, peer_.PeerAddress().ToString().c_str(),
                   BtifAcmEvent::EventName(event).c_str(),
                   peer_.FlagsToString().c_str(),
                   logbool(peer_.IsPeerActiveForMusic()).c_str(),
                   logbool(peer_.IsPeerActiveForVoice()).c_str());

  switch (event) {
    case BTIF_ACM_SUSPEND_STREAM_REQ_EVT:

    case BTA_ACM_STOP_EVT: {
        BTIF_TRACE_DEBUG("%s: STOPPING event from BAP, ignore", __func__);
    } break;

    case BTA_ACM_RECONFIG_EVT: {
        BTIF_TRACE_DEBUG("%s: received reconfiguring state from BAP, ignore", __func__);
    } break;

    case BTA_ACM_CONFIG_EVT: {
       uint16_t contextType = p_acm->state_info.stream_type.type;
       uint16_t peer_latency_ms = 0;
       uint32_t presen_delay = 0;
       bool is_update_require = false;
       if (contextType == CONTENT_TYPE_MEDIA) {
         if (p_acm->state_info.stream_type.audio_context == CONTENT_TYPE_MEDIA) {
           BTIF_TRACE_DEBUG("%s: compare current_media_config", __PRETTY_FUNCTION__);
           is_update_require = compare_codec_config_(current_media_config, p_acm->config_info.codec_config);
         } else if (p_acm->state_info.stream_type.audio_context == CONTENT_TYPE_LIVE) {
           BTIF_TRACE_DEBUG("%s: cache current_recording_config", __PRETTY_FUNCTION__);
           current_recording_config = p_acm->config_info.codec_config;
         }
         //Cache the peer latency in WMCP case
         if (peer_.GetRcfgProfileType() == WMCP) {
           BTIF_TRACE_DEBUG("%s: presentation delay[0] = %x", __func__,
                            p_acm->config_info.qos_config.ascs_configs[0].presentation_delay[0]);
           BTIF_TRACE_DEBUG("%s: presentation delay[1] = %x", __func__,
                            p_acm->config_info.qos_config.ascs_configs[0].presentation_delay[1]);
           BTIF_TRACE_DEBUG("%s: presentation delay[2] = %x", __func__,
                            p_acm->config_info.qos_config.ascs_configs[0].presentation_delay[2]);
           presen_delay = static_cast<uint32_t>(p_acm->config_info.qos_config.ascs_configs[0].presentation_delay[0]) |
                          static_cast<uint32_t>(p_acm->config_info.qos_config.ascs_configs[0].presentation_delay[1] << 8) |
                          static_cast<uint32_t>(p_acm->config_info.qos_config.ascs_configs[0].presentation_delay[2] << 16);
           BTIF_TRACE_DEBUG("%s: presen_delay = %dus", __func__, presen_delay);
           peer_latency_ms = presen_delay/1000;
           BTIF_TRACE_DEBUG("%s: s_to_m latency = %dms", __func__,
                           p_acm->config_info.qos_config.cig_config.max_tport_latency_s_to_m);
           peer_latency_ms += p_acm->config_info.qos_config.cig_config.max_tport_latency_s_to_m;
           peer_.SetPeerLatency(peer_latency_ms);
           BTIF_TRACE_DEBUG("%s: cached peer Latency = %dms", __func__, peer_.GetPeerLatency());
         }
         if (is_update_require) {
           current_media_config = p_acm->config_info.codec_config;
           BTIF_TRACE_DEBUG("%s: current_media_config.codec_specific_3: %"
                                 PRIi64, __func__, current_media_config.codec_specific_3);
           btif_acm_update_lc3q_params(&current_media_config.codec_specific_3, p_acm);
           btif_acm_report_source_codec_state(peer_.PeerAddress(), current_media_config,
                                              unicast_codecs_capabilities,
                                              unicast_codecs_capabilities, CONTEXT_TYPE_MUSIC);
         }
       } else if (contextType == CONTENT_TYPE_CONVERSATIONAL) {
         BTIF_TRACE_DEBUG("%s: cache current_voice_config");
         current_voice_config = p_acm->config_info.codec_config;
         BTIF_TRACE_DEBUG("%s: current_voice_config.codec_specific_3: %"
                               PRIi64, __func__, current_voice_config.codec_specific_3);
         btif_acm_update_lc3q_params(&current_voice_config.codec_specific_3, p_acm);
       }
    } break;

    case BTA_ACM_CONNECT_EVT: {
        uint8_t status = (uint8_t)p_acm->state_info.stream_state;
        LOG_INFO(
            LOG_TAG, "%s: Peer %s : event=%s flags=%s status=%d",
            __PRETTY_FUNCTION__, peer_.PeerAddress().ToString().c_str(),
            BtifAcmEvent::EventName(event).c_str(), peer_.FlagsToString().c_str(),
            status);
        if (peer_.CheckFlags(BtifAcmPeer::kFlagPendingReconfigure)) {
          if (p_acm->state_info.stream_state == StreamState::CONNECTED) {
            if (p_acm->state_info.stream_type.type == CONTENT_TYPE_MEDIA) {
              BTIF_TRACE_DEBUG("%s: Reconfig complete, move in opened state", __func__);
              peer_.StateMachine().TransitionTo(BtifAcmStateMachine::kStateOpened);
            } else {
              if (p_acm->state_info.stream_type.direction == ASE_DIRECTION_SINK) {
                peer_.SetPeerVoiceTxState(p_acm->state_info.stream_state);
                if (peer_.GetPeerVoiceRxState() == StreamState::CONNECTED) {
                  BTIF_TRACE_DEBUG("%s: Report Call audio config to apps? move to opened when both Voice Tx and Rx done", __func__);
                  BTIF_TRACE_DEBUG("%s: received connected state from BAP for voice Tx, move in opened state", __func__);
                  peer_.StateMachine().TransitionTo(BtifAcmStateMachine::kStateOpened);
                }
              } else if (p_acm->state_info.stream_type.direction == ASE_DIRECTION_SRC) {
                peer_.SetPeerVoiceRxState(p_acm->state_info.stream_state);
                if (peer_.GetPeerVoiceTxState() == StreamState::CONNECTED) {
                  BTIF_TRACE_DEBUG("%s: Report Call audio config to apps? move to opened when both Voice Tx and Rx done", __func__);
                  BTIF_TRACE_DEBUG("%s: received connected state from BAP for voice Rx, move in opened state", __func__);
                  peer_.StateMachine().TransitionTo(BtifAcmStateMachine::kStateOpened);
                }
              }
            }
          }
          break;
        }
        if (peer_.CheckFlags(BtifAcmPeer::kFlagPendingLocalSuspend)) {
          peer_.ClearFlags(BtifAcmPeer::kFlagPendingLocalSuspend);
          BTIF_TRACE_DEBUG("%s: peer device is suspended, send MM any pending ACK", __func__);
          tA2DP_CTRL_CMD pending_cmd = btif_ahim_get_pending_command();
          if (pending_cmd == A2DP_CTRL_CMD_STOP || pending_cmd == A2DP_CTRL_CMD_SUSPEND) {
            btif_acm_source_on_suspended(A2DP_CTRL_ACK_SUCCESS);
          } else if (pending_cmd == A2DP_CTRL_CMD_START) {
            btif_acm_on_started(A2DP_CTRL_ACK_SUCCESS);
          } else {
           BTIF_TRACE_DEBUG("%s: no pending command to ack mm audio", __func__);
          }
          if (alarm_is_scheduled(btif_acm_initiator.AcmGroupProcedureTimer()))
            btif_acm_check_and_cancel_group_procedure_timer(btif_acm_initiator.MusicActiveCSetId());
          btif_report_audio_state(peer_.PeerAddress(), BTACM_AUDIO_STATE_STOPPED, peer_.GetStreamContextType());
          std::vector<StreamReconfig> reconf_streams;
          StreamReconfig reconf_info;
          CodecQosConfig cfg;
          reconf_info.stream_type.type = CONTENT_TYPE_MEDIA;
          // TODO to change audio context based on use case ( media or gaming or Live audio)
          if (peer_.GetRcfgProfileType() != WMCP) {
            reconf_info.stream_type.audio_context = CONTENT_TYPE_MEDIA;
            reconf_info.stream_type.direction = ASE_DIRECTION_SINK;
          } else {
            reconf_info.stream_type.audio_context = CONTENT_TYPE_LIVE;
            reconf_info.stream_type.direction = ASE_DIRECTION_SRC;
          }
          reconf_info.reconf_type = bluetooth::bap::ucast::StreamReconfigType::CODEC_CONFIG;
          cfg = peer_.get_peer_media_codec_qos_config();
          reconf_info.codec_qos_config_pair.push_back(cfg);
          reconf_streams.push_back(reconf_info);
          peer_.SetFlags(BtifAcmPeer::kFlagPendingReconfigure);
          if (!sUcastClientInterface) break;
            sUcastClientInterface->Reconfigure(peer_.PeerAddress(), reconf_streams);
        }
    } break;

    case BTA_ACM_DISCONNECT_EVT: {
      int context_type = p_acm->state_info.stream_type.type;
      if (p_acm->state_info.stream_state == StreamState::DISCONNECTED) {
        if (context_type == CONTENT_TYPE_MEDIA) {
          if (p_acm->state_info.stream_type.direction == ASE_DIRECTION_SINK) {
            peer_.SetPeerMusicTxState(p_acm->state_info.stream_state);
          } else if (p_acm->state_info.stream_type.direction == ASE_DIRECTION_SRC) {
            peer_.SetPeerMusicRxState(p_acm->state_info.stream_state);
          }
          if (peer_.GetPeerMusicTxState() == StreamState::DISCONNECTED &&
              peer_.GetPeerMusicRxState() == StreamState::DISCONNECTED) {
            btif_report_connection_state(peer_.PeerAddress(),
                BTACM_CONNECTION_STATE_DISCONNECTED, CONTEXT_TYPE_MUSIC);
          }
          if (peer_.GetPeerVoiceRxState() == StreamState::DISCONNECTED &&
               peer_.GetPeerVoiceTxState() == StreamState::DISCONNECTED &&
               peer_.GetPeerMusicTxState() == StreamState::DISCONNECTED &&
               peer_.GetPeerMusicRxState() == StreamState::DISCONNECTED) {
            BTIF_TRACE_DEBUG("%s: received Media Tx/Rx disconnected state from BAP"
                      " when Voice Tx+Rx & Media Rx/Tx was disconnected, move in idle state", __func__);
            peer_.StateMachine().TransitionTo(BtifAcmStateMachine::kStateIdle);
          } else {
            BTIF_TRACE_DEBUG("%s: received Media Tx/Rx disconnected state from BAP"
                      " when either Voice Tx or Rx or Media Rx/Tx is connected, remain in reconfiguring state", __func__);
          }
        } else if (context_type == CONTENT_TYPE_CONVERSATIONAL) {
          if (p_acm->state_info.stream_type.direction == ASE_DIRECTION_SINK) {
            peer_.SetPeerVoiceTxState(p_acm->state_info.stream_state);
            if (peer_.GetPeerVoiceRxState() == StreamState::DISCONNECTED) {
              btif_report_connection_state(peer_.PeerAddress(), BTACM_CONNECTION_STATE_DISCONNECTED, CONTEXT_TYPE_VOICE);
              if (peer_.GetPeerMusicTxState() == StreamState::DISCONNECTED &&
                  peer_.GetPeerMusicRxState() == StreamState::DISCONNECTED) {
                BTIF_TRACE_DEBUG("%s: received disconnected state from BAP for voice Tx,"
                                 " voice Rx, Music Tx & Rx are disconnected move in idle state", __func__);
                peer_.StateMachine().TransitionTo(BtifAcmStateMachine::kStateIdle);
              } else {
                BTIF_TRACE_DEBUG("%s: received disconnected state from BAP for voice Tx,"
                                 " voice Rx is disconnected but music Tx or Rx still not disconnected,"
                                 " remain in reconfiguring state", __func__);
              }
            }
          } else if (p_acm->state_info.stream_type.direction == ASE_DIRECTION_SRC) {
            peer_.SetPeerVoiceRxState(p_acm->state_info.stream_state);
            if (peer_.GetPeerVoiceTxState() == StreamState::DISCONNECTED) {
              btif_report_connection_state(peer_.PeerAddress(), BTACM_CONNECTION_STATE_DISCONNECTED, CONTEXT_TYPE_VOICE);
              if (peer_.GetPeerMusicTxState() == StreamState::DISCONNECTED &&
                  peer_.GetPeerMusicRxState() == StreamState::DISCONNECTED) {
                BTIF_TRACE_DEBUG("%s: received disconnected state from BAP for voice Rx,"
                                 " voice Tx, Music Tx & Rx are disconnected move in idle state", __func__);
                peer_.StateMachine().TransitionTo(BtifAcmStateMachine::kStateIdle);
              } else {
                BTIF_TRACE_DEBUG("%s: received disconnected state from BAP for voice Rx,"
                                 " voice Rx is disconnected but music Tx or Rx still not disconnected,"
                                 " remain in reconfiguring state", __func__);
              }
            }
          }
        }
      } else if (p_acm->state_info.stream_state == StreamState::DISCONNECTING) {
        if (context_type == CONTENT_TYPE_MEDIA) {
          if (p_acm->state_info.stream_type.direction == ASE_DIRECTION_SINK) {
            peer_.SetPeerMusicTxState(p_acm->state_info.stream_state);
          } else if (p_acm->state_info.stream_type.direction == ASE_DIRECTION_SRC) {
            peer_.SetPeerMusicRxState(p_acm->state_info.stream_state);
          }
          btif_report_connection_state(peer_.PeerAddress(),
                                  BTACM_CONNECTION_STATE_DISCONNECTING, CONTEXT_TYPE_MUSIC);
          if ((peer_.GetPeerVoiceRxState() == StreamState::DISCONNECTED ||
                peer_.GetPeerVoiceRxState() == StreamState::DISCONNECTING) &&
               (peer_.GetPeerVoiceTxState() == StreamState::DISCONNECTED ||
                peer_.GetPeerVoiceTxState() == StreamState::DISCONNECTING) &&
               (peer_.GetPeerMusicTxState() == StreamState::DISCONNECTED ||
                peer_.GetPeerMusicTxState() == StreamState::DISCONNECTING) &&
               (peer_.GetPeerMusicRxState() == StreamState::DISCONNECTED ||
                peer_.GetPeerMusicRxState() == StreamState::DISCONNECTING)) {
              BTIF_TRACE_DEBUG("%s: received Media Tx/Rx disconnecting state from BAP"
                               " when Voice Tx+Rx and Media Rx/Tx disconnected/ing, move in closing state", __func__);
              peer_.StateMachine().TransitionTo(BtifAcmStateMachine::kStateClosing);
          } else {
              BTIF_TRACE_DEBUG("%s: received Media Tx/Rx disconnecting state from BAP"
                               " when either Voice Tx or Rx or Media Rx/Tx is connected, remain in reconfiguring state", __func__);
          }
        } else if (context_type == CONTENT_TYPE_CONVERSATIONAL) {
          if (p_acm->state_info.stream_type.direction == ASE_DIRECTION_SINK) {
            peer_.SetPeerVoiceTxState(p_acm->state_info.stream_state);
            if (peer_.GetPeerVoiceRxState() == StreamState::DISCONNECTING ||
                peer_.GetPeerVoiceRxState() == StreamState::DISCONNECTED) {
              btif_report_connection_state(peer_.PeerAddress(), BTACM_CONNECTION_STATE_DISCONNECTING, CONTEXT_TYPE_VOICE);
              if (((peer_.GetPeerMusicTxState() == StreamState::DISCONNECTED) ||
                  (peer_.GetPeerMusicTxState() == StreamState::DISCONNECTING)) &&
                  ((peer_.GetPeerMusicRxState() == StreamState::DISCONNECTED) ||
                  (peer_.GetPeerMusicRxState() == StreamState::DISCONNECTING))) {
                BTIF_TRACE_DEBUG("%s: received disconnecting state from BAP for voice Tx,"
                                 " voice Rx, music Tx+Rx are disconnected/ing move in closing state", __func__);
                peer_.StateMachine().TransitionTo(BtifAcmStateMachine::kStateClosing);
              } else {
                BTIF_TRACE_DEBUG("%s: received disconnecting state from BAP for voice Tx,"
                                 " voice Rx is disconncted/ing but music Tx or Rx still not disconnected/ing,"
                                 " remain in reconfiguring state", __func__);
              }
            }
          } else if (p_acm->state_info.stream_type.direction == ASE_DIRECTION_SRC) {
            peer_.SetPeerVoiceRxState(p_acm->state_info.stream_state);
            if (peer_.GetPeerVoiceTxState() == StreamState::DISCONNECTING ||
                peer_.GetPeerVoiceTxState() == StreamState::DISCONNECTED) {
              btif_report_connection_state(peer_.PeerAddress(), BTACM_CONNECTION_STATE_DISCONNECTING, CONTEXT_TYPE_VOICE);
              if (((peer_.GetPeerMusicTxState() == StreamState::DISCONNECTED) ||
                  (peer_.GetPeerMusicTxState() == StreamState::DISCONNECTING)) &&
                  ((peer_.GetPeerMusicRxState() == StreamState::DISCONNECTED) ||
                  (peer_.GetPeerMusicRxState() == StreamState::DISCONNECTING))) {
                BTIF_TRACE_DEBUG("%s: received disconnecting state from BAP for voice Rx,"
                                 " voice Tx, music Tx+Rx are disconnected/ing move in closing state", __func__);
                peer_.StateMachine().TransitionTo(BtifAcmStateMachine::kStateClosing);
              } else {
                BTIF_TRACE_DEBUG("%s: received disconnected state from BAP for voice Rx,"
                                 " voice Tx is disconncted/ing but music Tx or Rx still not disconnected/ing,"
                                 " remain in reconfiguring state", __func__);
              }
            }
          }
        }
      }
    } break;

    case BTA_ACM_CONN_UPDATE_TIMEOUT_EVT:
      peer_.SetConnUpdateMode(BtifAcmPeer::kFlagRelaxedMode);
      break;

    default:
      BTIF_TRACE_WARNING("%s: Peer %s : Unhandled event=%s",
                         __PRETTY_FUNCTION__,
                         peer_.PeerAddress().ToString().c_str(),
                         BtifAcmEvent::EventName(event).c_str());
      return false;
  }
  return true;
}

void BtifAcmStateMachine::StateClosing::OnEnter() {
  BTIF_TRACE_DEBUG("%s: Peer %s", __PRETTY_FUNCTION__,
                   peer_.PeerAddress().ToString().c_str());
  if(btif_acm_initiator.IsConnUpdateEnabled()) {
    //Cancel the timer if running if  not, move to aggressive mode
    if (alarm_is_scheduled(btif_acm_initiator.AcmConnIntervalTimer())) {
      btif_acm_check_and_cancel_conn_Interval_timer();
    }
    else {
      BTIF_TRACE_DEBUG("%s: conn timer not running, push aggressive intervals", __func__);
      peer_.SetConnUpdateMode(BtifAcmPeer::kFlagAggresiveMode);
    }
  }

}

void BtifAcmStateMachine::StateClosing::OnExit() {
  BTIF_TRACE_DEBUG("%s: Peer %s", __PRETTY_FUNCTION__,
                   peer_.PeerAddress().ToString().c_str());
}

bool BtifAcmStateMachine::StateClosing::ProcessEvent(uint32_t event, void* p_data) {
  tBTIF_ACM* p_acm = (tBTIF_ACM*)p_data;
  BTIF_TRACE_DEBUG("%s: Peer %s : event=%s flags=%s music_active_peer=%s voice_active_peer=%s",
                   __PRETTY_FUNCTION__, peer_.PeerAddress().ToString().c_str(),
                   BtifAcmEvent::EventName(event).c_str(),
                   peer_.FlagsToString().c_str(),
                   logbool(peer_.IsPeerActiveForMusic()).c_str(),
                   logbool(peer_.IsPeerActiveForVoice()).c_str());

  switch (event) {
    case BTIF_ACM_SUSPEND_STREAM_REQ_EVT:
    case BTIF_ACM_START_STREAM_REQ_EVT:
    case BTA_ACM_STOP_EVT:
    case BTIF_ACM_STOP_STREAM_REQ_EVT:
      break;

    case BTA_ACM_DISCONNECT_EVT: {
      int context_type = p_acm->state_info.stream_type.type;
      if (p_acm->state_info.stream_state == StreamState::DISCONNECTED) {
        if (context_type == CONTENT_TYPE_MEDIA) {
          if (p_acm->state_info.stream_type.direction == ASE_DIRECTION_SINK) {
            peer_.SetPeerMusicTxState(p_acm->state_info.stream_state);
          } else if (p_acm->state_info.stream_type.direction == ASE_DIRECTION_SRC) {
            peer_.SetPeerMusicRxState(p_acm->state_info.stream_state);
          }
          if (peer_.GetPeerMusicTxState() == StreamState::DISCONNECTED &&
              peer_.GetPeerMusicRxState() == StreamState::DISCONNECTED) {
            btif_report_connection_state(peer_.PeerAddress(),
                BTACM_CONNECTION_STATE_DISCONNECTED, CONTEXT_TYPE_MUSIC);
          }
          if (peer_.GetPeerVoiceRxState() == StreamState::DISCONNECTED &&
               peer_.GetPeerVoiceTxState() == StreamState::DISCONNECTED &&
               peer_.GetPeerMusicTxState() == StreamState::DISCONNECTED &&
               peer_.GetPeerMusicRxState() == StreamState::DISCONNECTED) {
            BTIF_TRACE_DEBUG("%s: received Media Tx/Rx disconnected state from BAP"
                      " when Voice Tx+Rx & Media Rx/Tx was disconnected, move in idle state", __func__);
            peer_.StateMachine().TransitionTo(BtifAcmStateMachine::kStateIdle);
          } else {
            BTIF_TRACE_DEBUG("%s: received Media Tx/Rx disconnected state from BAP"
                      " when either Voice Tx or Rx or Media Rx/Tx is connected, remain in closing state", __func__);
          }
        } else if (context_type == CONTENT_TYPE_CONVERSATIONAL) {
          if (p_acm->state_info.stream_type.direction == ASE_DIRECTION_SINK) {
            peer_.SetPeerVoiceTxState(p_acm->state_info.stream_state);
            if (peer_.GetPeerVoiceRxState() == StreamState::DISCONNECTED) {
              btif_report_connection_state(peer_.PeerAddress(), BTACM_CONNECTION_STATE_DISCONNECTED, CONTEXT_TYPE_VOICE);
              if (peer_.GetPeerMusicTxState() == StreamState::DISCONNECTED &&
                  peer_.GetPeerMusicRxState() == StreamState::DISCONNECTED) {
                BTIF_TRACE_DEBUG("%s: received disconnected state from BAP for voice Tx,"
                                 " voice Rx, Music Tx & Rx are disconnected move in idle state", __func__);
                peer_.StateMachine().TransitionTo(BtifAcmStateMachine::kStateIdle);
              } else {
                BTIF_TRACE_DEBUG("%s: received disconnected state from BAP for voice Tx,"
                                 " voice Rx is disconnected but music Tx or Rx still not disconnected,"
                                 " remain in closing state", __func__);
              }
            }
          } else if (p_acm->state_info.stream_type.direction == ASE_DIRECTION_SRC) {
            peer_.SetPeerVoiceRxState(p_acm->state_info.stream_state);
            if (peer_.GetPeerVoiceTxState() == StreamState::DISCONNECTED) {
              btif_report_connection_state(peer_.PeerAddress(), BTACM_CONNECTION_STATE_DISCONNECTED, CONTEXT_TYPE_VOICE);
              if (peer_.GetPeerMusicTxState() == StreamState::DISCONNECTED &&
                  peer_.GetPeerMusicRxState() == StreamState::DISCONNECTED) {
                BTIF_TRACE_DEBUG("%s: received disconnected state from BAP for voice Rx,"
                                 " voice Tx, Music Tx & Rx are disconnected move in idle state", __func__);
                peer_.StateMachine().TransitionTo(BtifAcmStateMachine::kStateIdle);
              } else {
                BTIF_TRACE_DEBUG("%s: received disconnected state from BAP for voice Rx,"
                                 " voice Rx is disconnected but music Tx or Rx still not disconnected,"
                                 " remain in closing state", __func__);
              }
            }
          }
        }
      } else if (p_acm->state_info.stream_state == StreamState::DISCONNECTING) {
        if (context_type == CONTENT_TYPE_MEDIA) {
          BTIF_TRACE_DEBUG("%s: received Music Tx or Rx disconnecting state from BAP, ignore", __func__);
          if (p_acm->state_info.stream_type.direction == ASE_DIRECTION_SINK)
            peer_.SetPeerMusicTxState(p_acm->state_info.stream_state);
          else if (p_acm->state_info.stream_type.direction == ASE_DIRECTION_SRC)
            peer_.SetPeerMusicRxState(p_acm->state_info.stream_state);
        } else if (context_type == CONTENT_TYPE_CONVERSATIONAL) {
          BTIF_TRACE_DEBUG("%s: received voice Tx or Rx disconnecting state from BAP, ignore", __func__);
          if (p_acm->state_info.stream_type.direction == ASE_DIRECTION_SINK) {
            peer_.SetPeerVoiceTxState(p_acm->state_info.stream_state);
          } else if (p_acm->state_info.stream_type.direction == ASE_DIRECTION_SRC) {
            peer_.SetPeerVoiceRxState(p_acm->state_info.stream_state);
          }
        }
      }
    }
    break;

    case BTA_ACM_CONN_UPDATE_TIMEOUT_EVT:
      peer_.SetConnUpdateMode(BtifAcmPeer::kFlagRelaxedMode);
      break;

    default:
      BTIF_TRACE_WARNING("%s: Peer %s : Unhandled event=%s",
                         __PRETTY_FUNCTION__,
                         peer_.PeerAddress().ToString().c_str(),
                         BtifAcmEvent::EventName(event).c_str());
      peer_.StateMachine().TransitionTo(BtifAcmStateMachine::kStateIdle);
      return false;
  }
  return true;
}

void btif_acm_update_lc3q_params(int64_t* cs3, tBTIF_ACM* p_data) {

  /* ==================================================================
   * CS3: Res  |LC3Q-len| QTI  | VMT | VML | ver/For_Als |LC3Q-support
   * ==================================================================
   *      0x00 |0B      | 000A | FF  | 0F  | 01/03       | 10
   * ==================================================================
   * CS4:    Res
   * ==============================
   *     0x00,00,00,00,00,00,00,00
   * ============================== */

  if (GetVendorMetaDataLc3QPref(
                         &p_data->config_info.codec_config)) {
    *cs3 &= ~((int64_t)0xFF << (LE_AUDIO_CS_3_1ST_BYTE_INDEX * 8));
    *cs3 |=  ((int64_t)0x10 << (LE_AUDIO_CS_3_1ST_BYTE_INDEX * 8));

    uint8_t lc3q_ver = GetVendorMetaDataLc3QVer(&p_data->config_info.codec_config);
    BTIF_TRACE_DEBUG("%s: lc3q_ver: %d", __func__, lc3q_ver);
    *cs3 &= ~((int64_t)0xFF << (LE_AUDIO_CS_3_2ND_BYTE_INDEX * 8));
    *cs3 |=  ((int64_t)lc3q_ver << (LE_AUDIO_CS_3_2ND_BYTE_INDEX * 8));

    //*cs3 &= ~((int64_t)LE_AUDIO_MASK);
    *cs3 |=  (int64_t)LE_AUDIO_AVAILABLE_LICENSED;

    *cs3 &= ~((int64_t)0xFF << (LE_AUDIO_CS_3_3RD_BYTE_INDEX * 8));
    *cs3 |=  ((int64_t)0x0F << (LE_AUDIO_CS_3_3RD_BYTE_INDEX * 8));

    *cs3 &= ~((int64_t)0xFF << (LE_AUDIO_CS_3_4TH_BYTE_INDEX * 8));
    *cs3 |=  ((int64_t)0xFF << (LE_AUDIO_CS_3_4TH_BYTE_INDEX * 8));

    *cs3 &= ~((int64_t)0xFFFF << (LE_AUDIO_CS_3_5TH_BYTE_INDEX * 8));
    *cs3 |=  ((int64_t)0x000A << (LE_AUDIO_CS_3_5TH_BYTE_INDEX * 8));

    *cs3 &= ~((int64_t)0xFF << (LE_AUDIO_CS_3_7TH_BYTE_INDEX * 8));
    *cs3 |=  ((int64_t)0x0B << (LE_AUDIO_CS_3_7TH_BYTE_INDEX * 8));

    CodecConfig temp = unicast_codecs_capabilities.back();
    unicast_codecs_capabilities.pop_back();
    temp.codec_specific_3 = *cs3;
    unicast_codecs_capabilities.push_back(temp);
  }
  BTIF_TRACE_DEBUG("%s: cs3: %" PRIi64, __func__, *cs3);
  BTIF_TRACE_DEBUG("%s: cs3= 0x%" PRIx64, __func__, *cs3);
}

static void btif_report_connection_state(const RawAddress& peer_address,
                                         btacm_connection_state_t state, uint16_t contextType) {
  LOG_INFO(LOG_TAG, "%s: peer_address=%s state=%d contextType=%d", __func__,
           peer_address.ToString().c_str(), state, contextType);
  if (btif_acm_initiator.Enabled()) {
    do_in_jni_thread(FROM_HERE,
                     Bind(btif_acm_initiator.Callbacks()->connection_state_cb,
                          peer_address, state, contextType));
  }
}

static void btif_report_audio_state(const RawAddress& peer_address,
                                    btacm_audio_state_t state, uint16_t contextType) {
  LOG_INFO(LOG_TAG, "%s: peer_address=%s state=%d contextType=%d", __func__,
           peer_address.ToString().c_str(), state, contextType);
  if (btif_acm_initiator.Enabled()) {
    do_in_jni_thread(FROM_HERE,
                     Bind(btif_acm_initiator.Callbacks()->audio_state_cb,
                          peer_address, state, contextType));
  }
}

void btif_acm_report_source_codec_state(
    const RawAddress& peer_address,
    const CodecConfig& codec_config,
    const std::vector<CodecConfig>& codecs_local_capabilities,
    const std::vector<CodecConfig>&
        codecs_selectable_capabilities, int contextType) {
  BTIF_TRACE_EVENT("%s: peer_address=%s contextType=%d", __func__,
                   peer_address.ToString().c_str(), contextType);
  if (btif_acm_initiator.Enabled()) {
    do_in_jni_thread(FROM_HERE,
                     Bind(btif_acm_initiator.Callbacks()->audio_config_cb, peer_address,
                          codec_config, codecs_local_capabilities,
                          codecs_selectable_capabilities, contextType));
  }
}

static void btif_acm_handle_evt(uint16_t event, char* p_param) {
  BtifAcmPeer* peer = nullptr;
  BTIF_TRACE_DEBUG("Handle the ACM event = %d ", event);
  switch (event) {
    case BTIF_ACM_DISCONNECT_REQ_EVT: {
        if (p_param == NULL) {
          BTIF_TRACE_ERROR("%s: Invalid p_param, dropping event: %d", __func__, event);
          return;
        }
        tBTIF_ACM_CONN_DISC* p_acm = (tBTIF_ACM_CONN_DISC*)p_param;
        peer = btif_acm_initiator.FindOrCreatePeer(p_acm->bd_addr);
        if (peer == nullptr) {
          BTIF_TRACE_ERROR(
              "%s: Cannot find peer for peer_address=%s"
              ": event dropped: %d",
              __func__, p_acm->bd_addr.ToString().c_str(),
              event);
          return;
        } else {
          BTIF_TRACE_EVENT(
              "%s: BTIF_ACM_DISCONNECT_REQ_EVT peer_address=%s"
              ": contextType=%d",
              __func__, p_acm->bd_addr.ToString().c_str(),
              p_acm->contextType);
        }
        break;
    }
    case BTIF_ACM_START_STREAM_REQ_EVT:
    case BTIF_ACM_SUSPEND_STREAM_REQ_EVT:
    case BTIF_ACM_STOP_STREAM_REQ_EVT: {
        if (p_param == NULL) {
          BTIF_TRACE_ERROR("%s: Invalid p_param, dropping event: %d", __func__, event);
          return;
        }
        tBTIF_ACM_CONN_DISC* p_acm = (tBTIF_ACM_CONN_DISC*)p_param;
        peer = btif_acm_initiator.FindOrCreatePeer(p_acm->bd_addr);
        if (peer == nullptr) {
          BTIF_TRACE_ERROR("%s: Cannot find peer for peer_address=%s"
                           ": event dropped: %d",
                           __func__, p_acm->bd_addr.ToString().c_str(), event);
          return;
        }
    } break;
    case BTA_ACM_DISCONNECT_EVT:
    case BTA_ACM_CONNECT_EVT:
    case BTA_ACM_START_EVT:
    case BTA_ACM_STOP_EVT:
    case BTA_ACM_RECONFIG_EVT: {
        if (p_param == NULL) {
          BTIF_TRACE_ERROR("%s: Invalid p_param, dropping event: %d", __func__, event);
          return;
        }
        tBTA_ACM_STATE_INFO* p_acm = (tBTA_ACM_STATE_INFO*)p_param;
        peer = btif_acm_initiator.FindOrCreatePeer(p_acm->bd_addr);
        if (peer == nullptr) {
          BTIF_TRACE_ERROR("%s: Cannot find or create peer for peer_address=%s"
                           ": event dropped: %d",
                           __func__, p_acm->bd_addr.ToString().c_str(), event);
          return;
        }
    } break;
    case BTA_ACM_CONFIG_EVT: {
        if (p_param == NULL) {
          BTIF_TRACE_ERROR("%s: Invalid p_param, dropping event: %d", __func__, event);
          return;
        }
        tBTA_ACM_CONFIG_INFO* p_acm = (tBTA_ACM_CONFIG_INFO*)p_param;
        peer = btif_acm_initiator.FindPeer(p_acm->bd_addr);
        if (peer == nullptr) {
          BTIF_TRACE_ERROR("%s: Cannot find or create peer for peer_address=%s"
                           ": event dropped: %d",
                           __func__, p_acm->bd_addr.ToString().c_str(), event);
          return;
        }
    } break;
    case BTIF_ACM_RECONFIG_REQ_EVT: {
        if (p_param == NULL) {
          BTIF_TRACE_ERROR("%s: Invalid p_param, dropping event: %d", __func__, event);
          return;
        }
        tBTIF_ACM_RECONFIG* p_acm = (tBTIF_ACM_RECONFIG*)p_param;
        peer = btif_acm_initiator.FindPeer(p_acm->bd_addr);
        if (peer == nullptr) {
          BTIF_TRACE_ERROR("%s: Cannot find or create peer for peer_address=%s"
                           ": event dropped: %d",
                           __func__, p_acm->bd_addr.ToString().c_str(), event);
          return;
        }
    } break;

    case BTA_ACM_CONN_UPDATE_TIMEOUT_EVT: {
        if (p_param == NULL) {
          BTIF_TRACE_ERROR("%s: Invalid p_param, dropping event: %d", __func__, event);
          return;
        }
        tBTA_ACM_CONN_UPDATE_TIMEOUT_INFO * p_acm =
                                  (tBTA_ACM_CONN_UPDATE_TIMEOUT_INFO *)p_param;
        peer = btif_acm_initiator.FindPeer(p_acm->bd_addr);
        if (peer == nullptr) {
          BTIF_TRACE_ERROR("%s: Cannot find or create peer for peer_address=%s"
                           ": event dropped: %d",
                           __func__, p_acm->bd_addr.ToString().c_str(), event);
          return;
        }
    } break;

    default :
        BTIF_TRACE_DEBUG("UNHandled ACM event = %d ", event);
        break;
  }
  peer->StateMachine().ProcessEvent(event, (void*)p_param);
}

/**
 * Process BTA CSIP events. The processing is done on the JNI
 * thread.
 */
static void btif_acm_handle_bta_csip_event(uint16_t evt, char* p_param) {
  BtifCsipEvent btif_csip_event(evt, p_param, sizeof(tBTA_CSIP_DATA));
  tBTA_CSIP_EVT event = btif_csip_event.Event();
  tBTA_CSIP_DATA* p_data = (tBTA_CSIP_DATA*)btif_csip_event.Data();
  BTIF_TRACE_DEBUG("%s: event=%s", __func__, btif_csip_event.ToString().c_str());

  switch (event) {
    case BTA_CSIP_LOCK_STATUS_CHANGED_EVT: {
      const tBTA_LOCK_STATUS_CHANGED& lock_status_param = p_data->lock_status_param;
      BTIF_TRACE_DEBUG("%s: app_id=%d, set_id=%d, status=%d ", __func__,
                       lock_status_param.app_id, lock_status_param.set_id,
                       lock_status_param.status);

      std::vector<RawAddress> set_members =lock_status_param.addr;

      for (int j = 0; j < (int)set_members.size(); j++) {
        BTIF_TRACE_DEBUG("%s: address =%s", __func__, set_members[j].ToString().c_str());
      }

      BTIF_TRACE_DEBUG("%s: Get current lock status: %d ", __func__,
                        btif_acm_initiator.GetGroupLockStatus(lock_status_param.set_id));
      if (btif_acm_initiator.GetGroupLockStatus(lock_status_param.set_id) == BtifAcmInitiator::kFlagStatusPendingLock) {
        BTIF_TRACE_DEBUG("%s: lock was awaited for this set ", __func__);
      }

      if (btif_acm_initiator.GetGroupLockStatus(lock_status_param.set_id) == BtifAcmInitiator::kFlagStatusPendingUnlock) {
        BTIF_TRACE_DEBUG("%s: Unlock was awaited for this set ", __func__);
      }

      BTIF_TRACE_DEBUG("%s: Get CSIP app id: %d ", __func__,
                        btif_acm_initiator.GetCsipAppId());
      if (btif_acm_initiator.GetCsipAppId() != lock_status_param.app_id) {
        BTIF_TRACE_DEBUG("%s: app id mismatch ERROR!!! ", __func__);
        tA2DP_CTRL_CMD pending_cmd = btif_ahim_get_pending_command();
        if (pending_cmd == A2DP_CTRL_CMD_STOP ||
           pending_cmd == A2DP_CTRL_CMD_SUSPEND) {
          btif_acm_source_on_suspended(A2DP_CTRL_ACK_FAILURE);
        } else if (pending_cmd == A2DP_CTRL_CMD_START) {
          btif_acm_on_started(A2DP_CTRL_ACK_FAILURE);
        } else {
          BTIF_TRACE_DEBUG("%s: no pending command to ack mm audio", __func__);
        }
        return;
      }

      switch (lock_status_param.status) {
        case LOCK_RELEASED:
            BTIF_TRACE_DEBUG("%s: unlocked attempt succeeded ", __func__);
            btif_acm_initiator.SetOrUpdateGroupLockStatus(lock_status_param.set_id, BtifAcmInitiator::kFlagStatusUnlocked);
            break;
        case LOCK_RELEASED_TIMEOUT:
            BTIF_TRACE_DEBUG("%s: peer unlocked due to timeout ", __func__);
            //in this case evaluate which device has sent TO and how to use it ?
            btif_acm_initiator.SetOrUpdateGroupLockStatus(lock_status_param.set_id, BtifAcmInitiator::kFlagStatusUnlocked);
            break;
        case ALL_LOCKS_ACQUIRED:
            btif_acm_initiator.SetOrUpdateGroupLockStatus(lock_status_param.set_id, BtifAcmInitiator::kFlagStatusLocked);
            btif_acm_handle_csip_status_locked(lock_status_param.addr, lock_status_param.set_id);
            BTIF_TRACE_DEBUG("%s: All locks acquired ", __func__);
            break;
        case SOME_LOCKS_ACQUIRED_REASON_TIMEOUT:
            //proceed to continue use case;
        /*case SOME_LOCKS_ACQUIRED_REASON_DISC:
            //proceed to continue use case;
            BTIF_TRACE_DEBUG("%s: locked attempt succeeded with status = %d", __func__, lock_status_param.status);
            BTIF_TRACE_DEBUG("%s: locked set member count = %d, setsize = %d",
                                      __func__, (lock_status_param.addr).size(), setSize);
            btif_acm_initiator.music_active_set_locked_dev_count_ += (lock_status_param.addr).size();
            btif_acm_initiator.locked_devices.insert(btif_acm_initiator.locked_devices.end(),
                                 lock_status_param.addr.begin(), lock_status_param.addr.end());
            btif_acm_handle_csip_status_locked(lock_status_param.addr, lock_status_param.set_id);
            if (btif_acm_initiator.music_active_set_locked_dev_count_ < setSize) {
              btif_acm_initiator.SetOrUpdateGroupLockStatus(lock_status_param.set_id, BtifAcmInitiator::kFlagStatusSubsetLocked);
            } else {
              btif_acm_initiator.SetOrUpdateGroupLockStatus(lock_status_param.set_id, BtifAcmInitiator::kFlagStatusLocked);
            }
            break;*/
        case LOCK_DENIED: {
            //proceed to discontinue use case;
            tA2DP_CTRL_CMD pending_cmd = btif_ahim_get_pending_command();
            if (pending_cmd == A2DP_CTRL_CMD_STOP ||
               pending_cmd == A2DP_CTRL_CMD_SUSPEND) {
              btif_acm_source_on_suspended(A2DP_CTRL_ACK_FAILURE);
            } else if (pending_cmd == A2DP_CTRL_CMD_START) {
              btif_acm_on_started(A2DP_CTRL_ACK_FAILURE);
            } else {
              BTIF_TRACE_DEBUG("%s: no pending command to ack mm audio", __func__);
            }
            btif_acm_check_and_cancel_group_procedure_timer(lock_status_param.set_id);
            btif_acm_initiator.SetOrUpdateGroupLockStatus(lock_status_param.set_id, BtifAcmInitiator::kFlagStatusUnlocked);
        } break;
        case INVALID_REQUEST_PARAMS: {
            BTIF_TRACE_DEBUG("%s: invalid lock request ", __func__);
            tA2DP_CTRL_CMD pending_cmd = btif_ahim_get_pending_command();
            if (pending_cmd == A2DP_CTRL_CMD_STOP ||
               pending_cmd == A2DP_CTRL_CMD_SUSPEND) {
              btif_acm_source_on_suspended(A2DP_CTRL_ACK_FAILURE);
            } else if (pending_cmd == A2DP_CTRL_CMD_START) {
              btif_acm_on_started(A2DP_CTRL_ACK_FAILURE);
            } else {
              BTIF_TRACE_DEBUG("%s: no pending command to ack mm audio", __func__);
            }
            btif_acm_check_and_cancel_group_procedure_timer(lock_status_param.set_id);
            if (btif_acm_initiator.GetGroupLockStatus(lock_status_param.set_id) == BtifAcmInitiator::kFlagStatusPendingLock)
              btif_acm_initiator.SetOrUpdateGroupLockStatus(lock_status_param.set_id, BtifAcmInitiator::kFlagStatusUnlocked);
            else
              btif_acm_initiator.SetOrUpdateGroupLockStatus(lock_status_param.set_id, BtifAcmInitiator::kFlagStatusLocked);
        } break;
        default:
        break;
      }
    } break;
    case BTA_CSIP_SET_MEMBER_FOUND_EVT: {
      const tBTA_SET_MEMBER_FOUND& set_member_param = p_data->set_member_param;
      BTIF_TRACE_DEBUG("%s: set_id=%d, uuid=%d ", __func__,
                     set_member_param.set_id,
                     set_member_param.uuid);
    } break;

    case BTA_CSIP_LOCK_AVAILABLE_EVT: {
      const tBTA_LOCK_AVAILABLE& lock_available_param = p_data->lock_available_param;
      BTIF_TRACE_DEBUG("%s: app_id=%d, set_id=%d ", __func__,
                   lock_available_param.app_id, lock_available_param.set_id);
    } break;
  }
}

static void btif_acm_handle_csip_status_locked(std::vector<RawAddress> addr, uint8_t setId) {
  if (addr.empty()) {
    BTIF_TRACE_ERROR("%s: vector size is empty", __func__);
    return;
  }
  tA2DP_CTRL_CMD pending_cmd;// = A2DP_CTRL_CMD_START;//TODO: change to None
  pending_cmd =  btif_ahim_get_pending_command();
  std::vector<RawAddress>::iterator itr;
  int req = 0;
  if (pending_cmd == A2DP_CTRL_CMD_START) {
    req = BTIF_ACM_START_STREAM_REQ_EVT;
  } else if (pending_cmd == A2DP_CTRL_CMD_SUSPEND) {
    req = BTIF_ACM_SUSPEND_STREAM_REQ_EVT;
  } else if (pending_cmd == A2DP_CTRL_CMD_STOP) {
    req = BTIF_ACM_STOP_STREAM_REQ_EVT;
  } else {
    BTIF_TRACE_EVENT("%s: No pending command, check if this list of peers belong to MusicActive streaming started group", __func__);
//if (btif_acm_initiator.IsMusicActiveGroupStarted() && (setId == btif_acm_initiator.MusicActiveCSetId()))
//req = BTIF_ACM_START_STREAM_REQ_EVT;
  }
  if (req) {
    for (itr = addr.begin(); itr != addr.end(); itr++) {
      btif_acm_initiator_dispatch_sm_event(*itr, static_cast<btif_acm_sm_event_t>(req));
    }
  }
//  BtifAcmPeer* peer_ = btif_acm_initiator.FindPeer(peer_address);
  /*if ((peer_.IsPeerActiveForMusic() || !btif_acm_stream_started_ready())) {
    // Immediately stop transmission of frames while suspend is pending
    if (req == BTIF_ACM_STOP_STREAM_REQ_EVT) {
      //btif_acm_on_stopped(nullptr);
    } else if (req == BTIF_ACM_SUSPEND_STREAM_REQ_EVT) {
      // ensure tx frames are immediately suspended
      //btif_acm_source_set_tx_flush(true);
    }
  }*/
}

static void btif_acm_check_and_start_conn_Interval_timer(BtifAcmPeer* peer) {

  btif_acm_check_and_cancel_conn_Interval_timer();
  BTIF_TRACE_DEBUG("%s: ", __func__);

  alarm_set_on_mloop(btif_acm_initiator.AcmConnIntervalTimer(),
                     BtifAcmInitiator::kTimeoutConnIntervalMs,
                     btif_acm_initiator_conn_Interval_timer_timeout,
                     (void *)peer);
}

static void btif_acm_check_and_cancel_conn_Interval_timer() {

  BTIF_TRACE_DEBUG("%s: ", __func__);
  if (alarm_is_scheduled(btif_acm_initiator.AcmConnIntervalTimer())) {
    alarm_cancel(btif_acm_initiator.AcmConnIntervalTimer());
  }
}


static void btif_acm_initiator_conn_Interval_timer_timeout(void *data) {

  BTIF_TRACE_DEBUG("%s: ", __func__);
  BtifAcmPeer *peer = (BtifAcmPeer *)data;
  tBTA_ACM_CONN_UPDATE_TIMEOUT_INFO p_data;
  p_data.bd_addr = peer->PeerAddress();
  btif_transfer_context(btif_acm_handle_evt, BTA_ACM_CONN_UPDATE_TIMEOUT_EVT,
                        (char*)&p_data,
                        sizeof(tBTA_ACM_CONN_UPDATE_TIMEOUT_INFO), NULL);
}

static void btif_acm_check_and_start_group_procedure_timer(uint8_t setId) {
  uint8_t *arg = NULL;
  arg = (uint8_t *) osi_malloc(sizeof(uint8_t));
  BTIF_TRACE_DEBUG("%s: ", __func__);
  btif_acm_check_and_cancel_group_procedure_timer(setId);

  *arg = setId;
  alarm_set_on_mloop(btif_acm_initiator.AcmGroupProcedureTimer(),
                     BtifAcmInitiator::kTimeoutAcmGroupProcedureMs,
                     btif_acm_initiator_group_procedure_timer_timeout,
                     (void*) arg);

}

static void btif_acm_check_and_cancel_group_procedure_timer(uint8_t setId) {
  if (alarm_is_scheduled(btif_acm_initiator.AcmGroupProcedureTimer())) {
    BTIF_TRACE_ERROR("%s: acm group procedure already running for setId = %d, cancel", __func__, setId);
    alarm_cancel(btif_acm_initiator.AcmGroupProcedureTimer());
  }
}

static void btif_acm_initiator_group_procedure_timer_timeout(void *data) {
  BTIF_TRACE_DEBUG("%s: ", __func__);
  tBTA_CSIP_CSET cset_info; // need to do memset ?
  memset(&cset_info, 0, sizeof(tBTA_CSIP_CSET));
  std::vector<RawAddress> streaming_devices;
  std::vector<RawAddress> non_streaming_devices;
  uint8_t *arg = (uint8_t*) data;
  if (!arg) {
    BTIF_TRACE_ERROR("%s: coordinate arg is null, return", __func__);
    return;
  }
  uint8_t setId = *arg;
  if (setId == INVALID_SET_ID) {
    BTIF_TRACE_ERROR("%s: coordinate SetId is invalid, return", __func__);
    if (arg) osi_free(arg);
    return;
  }

  cset_info = BTA_CsipGetCoordinatedSet(setId);
  if (cset_info.size == 0) {
    BTIF_TRACE_ERROR("%s: CSET info size is zero, return", __func__);
    if (arg) osi_free(arg);
    return;
  }
  std::vector<RawAddress>::iterator itr;
  BTIF_TRACE_DEBUG("%s: size of set members %d", __func__, (cset_info.set_members).size());
  if ((cset_info.set_members).size() > 0) {
    for (itr =(cset_info.set_members).begin(); itr != (cset_info.set_members).end(); itr++) {
      //BTIF_TRACE_DEBUG("%s: address = %s", __func__, itr->ToString().c_str());
      BtifAcmPeer* peer = btif_acm_initiator.FindPeer(*itr);
      if ((peer == nullptr) || (peer != nullptr && !peer->IsStreaming())) {
        non_streaming_devices.push_back(*itr);
      } else {
        streaming_devices.push_back(*itr);
      }
    }
  }

  if (streaming_devices.size() > 0) {
    tA2DP_CTRL_CMD pending_cmd = btif_ahim_get_pending_command();
    if (pending_cmd == A2DP_CTRL_CMD_STOP ||
       pending_cmd == A2DP_CTRL_CMD_SUSPEND) {
      btif_acm_source_on_suspended(A2DP_CTRL_ACK_SUCCESS);
    } else if (pending_cmd == A2DP_CTRL_CMD_START) {
      btif_acm_on_started(A2DP_CTRL_ACK_SUCCESS);
    } else {
      BTIF_TRACE_DEBUG("%s: no pending command to ack mm audio", __func__);
    }
    BTIF_TRACE_DEBUG("%s: Get music active setid: %d", __func__,
                        btif_acm_initiator.MusicActiveCSetId());
    btif_acm_check_and_start_lock_release_timer(btif_acm_initiator.MusicActiveCSetId());
    if (streaming_devices.size() < (cset_info.set_members).size()) {
      // this case should continue with mono mode since all set members are not streaming
    }
  } else {
    tA2DP_CTRL_CMD pending_cmd = btif_ahim_get_pending_command();
    if (pending_cmd == A2DP_CTRL_CMD_STOP ||
       pending_cmd == A2DP_CTRL_CMD_SUSPEND) {
      btif_acm_source_on_suspended(A2DP_CTRL_ACK_FAILURE);
    } else if (pending_cmd == A2DP_CTRL_CMD_START) {
      btif_acm_on_started(A2DP_CTRL_ACK_FAILURE);
    } else {
      BTIF_TRACE_DEBUG("%s: no pending command to ack mm audio", __func__);
    }
  }

  if (non_streaming_devices.size() > 0) //do we need to unlock and then disconnect ??
   // le_Acl_disconnect (non_streaming_devices);

  if (arg) osi_free(arg);
}

static void btif_acm_check_and_start_lock_release_timer(uint8_t setId) {
  uint8_t *arg = NULL;
  arg = (uint8_t *) osi_malloc(sizeof(uint8_t));

  btif_acm_check_and_cancel_lock_release_timer(setId);

  *arg = setId;
  alarm_set_on_mloop(btif_acm_initiator.MusicSetLockReleaseTimer(),
                           BtifAcmPeer::kTimeoutLockReleaseMs,
                           btif_acm_initiator_lock_release_timer_timeout,
                           (void*) arg);
}

static void btif_acm_check_and_cancel_lock_release_timer(uint8_t setId) {
  if (alarm_is_scheduled(btif_acm_initiator.MusicSetLockReleaseTimer())) {
    BTIF_TRACE_ERROR("%s: lock release already running for setId = %d, cancel ", __func__, setId);
    alarm_cancel(btif_acm_initiator.MusicSetLockReleaseTimer());
  }
}

static void btif_acm_initiator_lock_release_timer_timeout(void *data) {
  uint8_t *arg = (uint8_t*) data;
  if (!arg) {
    BTIF_TRACE_ERROR("%s: coordinate arg is null, return", __func__);
    return;
  }
  uint8_t setId = *arg;
  if (setId == INVALID_SET_ID) {
    BTIF_TRACE_ERROR("%s: coordinate SetId is invalid, return", __func__);
    if (arg) osi_free(arg);
    return;
  }
  if ((btif_acm_initiator.GetGroupLockStatus(setId) != BtifAcmInitiator::kFlagStatusLocked) ||
      (btif_acm_initiator.GetGroupLockStatus(setId) != BtifAcmInitiator::kFlagStatusSubsetLocked)) {
    BTIF_TRACE_ERROR("%s: SetId = %d Lock Status = %d returning",
                      __func__, setId, btif_acm_initiator.GetGroupLockStatus(setId));
    if (arg) osi_free(arg);
    return;
  }
  if (!btif_acm_request_csip_unlock(setId)) {
    BTIF_TRACE_ERROR("%s: error unlocking", __func__);
  }
  if (arg) osi_free(arg);
}

static void bta_csip_callback(tBTA_CSIP_EVT event, tBTA_CSIP_DATA* p_data) {
  BTIF_TRACE_DEBUG("%s: event: %d", __func__, event);
  btif_transfer_context(btif_acm_handle_bta_csip_event, event, (char*)p_data,
                        sizeof(tBTA_CSIP_DATA), NULL);
}

// Initializes the ACM interface for initiator mode
static bt_status_t init_acm_initiator(
    btacm_initiator_callbacks_t* callbacks, int max_connected_acceptors,
    const std::vector<CodecConfig>& codec_priorities) {
  BTIF_TRACE_EVENT("%s", __func__);
  return btif_acm_initiator.Init(callbacks, max_connected_acceptors,
                                 codec_priorities);
}

// Establishes the BAP connection with the remote acceptor device
static void connect_int(uint16_t uuid, char* p_param) {
    tBTIF_ACM_CONN_DISC connection;
    memset(&connection, 0, sizeof(tBTIF_ACM_CONN_DISC));
    memcpy(&connection, p_param, sizeof(connection));
    RawAddress peer_address = RawAddress::kEmpty;
    BtifAcmPeer* peer = nullptr;
    peer_address = connection.bd_addr;
    if (uuid == ACM_UUID) {
      peer = btif_acm_initiator.FindOrCreatePeer(peer_address);
    }
    if (peer == nullptr) {
      BTIF_TRACE_ERROR("%s: peer is NULL", __func__);
      return;
    }
    peer->SetContextType(connection.contextType);
    peer->SetProfileType(connection.profileType);
    BTIF_TRACE_DEBUG("%s: cummulative_profile_type %d", __func__, peer->GetProfileType());
    //peer->SetPrefContextType(preferredContext);
    peer->StateMachine().ProcessEvent(BTIF_ACM_CONNECT_REQ_EVT, &connection);
}

// Set the active peer for contexttype
static void set_acm_active_peer_int(const RawAddress& peer_address,
                                    uint16_t contextType, uint16_t profileType,
                                    std::promise<void> peer_ready_promise) {
  BTIF_TRACE_EVENT("%s: peer_address=%s", __func__, peer_address.ToString().c_str());
  if (peer_address.IsEmpty()) {
    int setid = INVALID_SET_ID;
    if (contextType == CONTEXT_TYPE_MUSIC)
      setid = btif_acm_initiator.MusicActiveCSetId();
    else if (contextType == CONTEXT_TYPE_VOICE)
      setid = btif_acm_initiator.VoiceActiveCSetId();

    if (setid < INVALID_SET_ID) {
      tBTA_CSIP_CSET cset_info;
      memset(&cset_info, 0, sizeof(tBTA_CSIP_CSET));
      cset_info = BTA_CsipGetCoordinatedSet(setid);
      if (cset_info.size != 0) {
        std::vector<RawAddress>::iterator itr;
        BTIF_TRACE_DEBUG("%s: size of set members %d", __func__, (cset_info.set_members).size());
        if ((cset_info.set_members).size() > 0) {
          for (itr =(cset_info.set_members).begin(); itr != (cset_info.set_members).end(); itr++) {
            BtifAcmPeer* peer = btif_acm_initiator.FindPeer(*itr);
            if (peer != nullptr && peer->IsStreaming() &&
                    (contextType == peer->GetStreamContextType())) {
              BTIF_TRACE_DEBUG("%s: peer is streaming %s ", __func__, peer->PeerAddress().ToString().c_str());
              btif_acm_initiator_dispatch_sm_event(*itr, BTIF_ACM_STOP_STREAM_REQ_EVT);
            }
          }
        }
      }
    } else {
      BTIF_TRACE_DEBUG("%s: set active for twm device ", __func__);
      BtifAcmPeer* peer = nullptr;
      if (contextType == CONTEXT_TYPE_MUSIC)
        peer = btif_acm_initiator.FindPeer(btif_acm_initiator.MusicActivePeer());
      else if (contextType == CONTEXT_TYPE_VOICE)
        peer = btif_acm_initiator.FindPeer(btif_acm_initiator.VoiceActivePeer());
      if (peer != nullptr && peer->IsStreaming() &&
              (contextType == peer->GetStreamContextType())) {
        BTIF_TRACE_DEBUG("%s: peer is streaming %s ", __func__, peer->PeerAddress().ToString().c_str());
        if (contextType == CONTEXT_TYPE_MUSIC)
          btif_acm_initiator_dispatch_sm_event(btif_acm_initiator.MusicActivePeer(), BTIF_ACM_STOP_STREAM_REQ_EVT);
        else if (contextType == CONTEXT_TYPE_VOICE)
          btif_acm_initiator_dispatch_sm_event(btif_acm_initiator.VoiceActivePeer(), BTIF_ACM_STOP_STREAM_REQ_EVT);
      }
    }
  }
  if (!btif_acm_initiator.SetAcmActivePeer(peer_address, contextType, profileType,
                                           std::move(peer_ready_promise))) {
    BTIF_TRACE_ERROR("%s: Error setting %s as active peer", __func__,
                     peer_address.ToString().c_str());
  }
}

static bt_status_t connect_acm_initiator(const RawAddress& peer_address,
                                         uint16_t contextType, uint16_t profileType,
                                         uint16_t preferredContext) {
  BTIF_TRACE_EVENT("%s: Peer %s contextType=%d profileType=%d preferredContext=%d", __func__,
    peer_address.ToString().c_str(), contextType, profileType, preferredContext);

  if (!btif_acm_initiator.Enabled()) {
    BTIF_TRACE_WARNING("%s: BTIF ACM Initiator is not enabled", __func__);
    return BT_STATUS_NOT_READY;
  }

  tBTIF_ACM_CONN_DISC conn;
  conn.contextType = contextType;
  conn.profileType = profileType;
  conn.bd_addr = peer_address;
  return btif_transfer_context(connect_int, ACM_UUID, (char*)&conn,
                               sizeof(tBTIF_ACM_CONN_DISC), NULL);
}

static bt_status_t disconnect_acm_initiator(const RawAddress& peer_address,
                                                        uint16_t contextType) {
  BTIF_TRACE_EVENT("%s: Peer %s contextType=%d", __func__,
                     peer_address.ToString().c_str(), contextType);

  if (!btif_acm_initiator.Enabled()) {
    BTIF_TRACE_WARNING("%s: BTIF ACM Initiator is not enabled", __func__);
    return BT_STATUS_NOT_READY;
  }

  BtifAcmPeer* peer = btif_acm_initiator.FindOrCreatePeer(peer_address);
  if (peer == nullptr) {
    BTIF_TRACE_ERROR("%s: peer is NULL", __func__);
    return BT_STATUS_FAIL;
  }

  tBTIF_ACM_CONN_DISC disc;
  peer->ResetContextType(contextType);
  if (contextType == CONTEXT_TYPE_MUSIC) {
    peer->ResetProfileType(BAP|GCP|WMCP);
    disc.profileType = BAP|GCP|WMCP;
  } else if (contextType == CONTEXT_TYPE_VOICE) {
    peer->ResetProfileType(BAP_CALL);
    disc.profileType = BAP_CALL;
  } else if (contextType == CONTEXT_TYPE_MUSIC_VOICE) {
    peer->ResetProfileType(BAP|GCP|WMCP|BAP_CALL);
    disc.profileType = BAP|GCP|WMCP|BAP_CALL;
  }
  BTIF_TRACE_DEBUG("%s: cummulative_profile_type %d", __func__, peer->GetProfileType());

  disc.bd_addr = peer_address;
  disc.contextType = contextType;
  btif_transfer_context(btif_acm_handle_evt, BTIF_ACM_DISCONNECT_REQ_EVT, (char*)&disc,
                        sizeof(tBTIF_ACM_CONN_DISC), NULL);
  return BT_STATUS_SUCCESS;
}

static bt_status_t set_active_acm_initiator(const RawAddress& peer_address,
                                            uint16_t profileType) {
  uint16_t contextType = CONTEXT_TYPE_MUSIC;
  if (profileType == BAP || profileType == GCP || profileType == WMCP)
    contextType = CONTEXT_TYPE_MUSIC;
  else if (profileType == BAP_CALL)
    contextType = CONTEXT_TYPE_VOICE;

  BTIF_TRACE_EVENT("%s: Peer %s contextType=%d profileType=%d", __func__,
                    peer_address.ToString().c_str(), contextType, profileType);
  if (!btif_acm_initiator.Enabled()) {
    LOG(WARNING) << __func__ << ": BTIF ACM Initiator is not enabled";
    return BT_STATUS_NOT_READY;
  }

  BtifAcmPeer* peer = nullptr;
  if (contextType == CONTEXT_TYPE_MUSIC) {
    peer = btif_acm_initiator.FindPeer(btif_acm_initiator.MusicActivePeer());
    if ((peer != nullptr) && (peer->GetStreamContextType() == CONTEXT_TYPE_MUSIC) &&
        (peer->CheckFlags(BtifAcmPeer::kFlagPendingStart | BtifAcmPeer::kFlagPendingLocalSuspend |
                          BtifAcmPeer::kFlagPendingReconfigure))) {
      LOG(WARNING) << __func__ << ": Active music device is pending start or suspend or reconfig";
      return BT_STATUS_NOT_READY;
    }
  } else if (contextType == CONTEXT_TYPE_VOICE) {
    peer = btif_acm_initiator.FindPeer(btif_acm_initiator.VoiceActivePeer());
    if ((peer != nullptr) && (peer->GetStreamContextType() == CONTEXT_TYPE_VOICE) &&
        (peer->CheckFlags(BtifAcmPeer::kFlagPendingStart |
                          BtifAcmPeer::kFlagPendingLocalSuspend))) {
      LOG(WARNING) << __func__ << ": Active voice device is pending start or suspend";
      return BT_STATUS_NOT_READY;
    }
  }
  std::promise<void> peer_ready_promise;
  std::future<void> peer_ready_future = peer_ready_promise.get_future();
  set_acm_active_peer_int(peer_address, contextType, profileType,
                          std::move(peer_ready_promise));
  return BT_STATUS_SUCCESS;
}

static bt_status_t start_stream_acm_initiator(const RawAddress& peer_address,
                                              uint16_t contextType) {
  LOG_INFO(LOG_TAG, "%s: Peer %s", __func__, peer_address.ToString().c_str());

  if (!btif_acm_initiator.Enabled()) {
    BTIF_TRACE_WARNING("%s: BTIF ACM Initiator is not enabled", __func__);
    return BT_STATUS_NOT_READY;
  }
  int id = btif_acm_initiator.VoiceActiveCSetId();
  if (id < INVALID_SET_ID) {
    tBTA_CSIP_CSET cset_info;
    memset(&cset_info, 0, sizeof(tBTA_CSIP_CSET));
    cset_info = BTA_CsipGetCoordinatedSet(id);
    std::vector<RawAddress>::iterator itr;
    BTIF_TRACE_DEBUG("%s: size of set members %d", __func__, (cset_info.set_members).size());
    if ((cset_info.set_members).size() > 0) {
      for (itr =(cset_info.set_members).begin(); itr != (cset_info.set_members).end(); itr++) {
         BTIF_TRACE_DEBUG("%s: Sending start request ", __func__);
         BtifAcmPeer* p = btif_acm_initiator.FindPeer(*itr);
         if (p && p->IsConnected()) {
           p->SetStreamContextType(contextType);
           btif_acm_initiator_dispatch_sm_event(*itr, BTIF_ACM_START_STREAM_REQ_EVT);
         }
      }
    }
    btif_acm_check_and_start_group_procedure_timer(btif_acm_initiator.VoiceActiveCSetId());
  } else {
    BTIF_TRACE_DEBUG("%s: Sending start to twm device ", __func__);
    BtifAcmPeer* p = btif_acm_initiator.FindPeer(btif_acm_initiator.VoiceActivePeer());
    if (p != nullptr && p->IsConnected()) {
      p->SetStreamContextType(CONTEXT_TYPE_VOICE);
      btif_acm_initiator_dispatch_sm_event(btif_acm_initiator.VoiceActivePeer(), BTIF_ACM_START_STREAM_REQ_EVT);
    } else {
      BTIF_TRACE_DEBUG("%s: Unable to send start to twm device ", __func__);
    }
  }
  return BT_STATUS_SUCCESS;
}

static bt_status_t stop_stream_acm_initiator(const RawAddress& peer_address,
                                             uint16_t contextType) {
  LOG_INFO(LOG_TAG, "%s: Peer %s", __func__, peer_address.ToString().c_str());

  if (!btif_acm_initiator.Enabled()) {
    BTIF_TRACE_WARNING("%s: BTIF ACM Initiator is not enabled", __func__);
    return BT_STATUS_NOT_READY;
  }

  int id = btif_acm_initiator.VoiceActiveCSetId();
  if (id < INVALID_SET_ID) {
    tBTA_CSIP_CSET cset_info;
    memset(&cset_info, 0, sizeof(tBTA_CSIP_CSET));
    cset_info = BTA_CsipGetCoordinatedSet(id);
    std::vector<RawAddress>::iterator itr;
    BTIF_TRACE_DEBUG("%s: size of set members %d", __func__, (cset_info.set_members).size());
    if ((cset_info.set_members).size() > 0) {
      for (itr =(cset_info.set_members).begin(); itr != (cset_info.set_members).end(); itr++) {
         BTIF_TRACE_DEBUG("%s: Sending stop request ", __func__);
         BtifAcmPeer* p = btif_acm_initiator.FindPeer(*itr);
         if (p && p->IsConnected()) {
           p->SetStreamContextType(contextType);
           btif_acm_initiator_dispatch_sm_event(*itr, BTIF_ACM_STOP_STREAM_REQ_EVT);
         }
      }
    }
    btif_acm_check_and_start_group_procedure_timer(btif_acm_initiator.VoiceActiveCSetId());
  } else {
    BTIF_TRACE_DEBUG("%s: Sending stop to twm device ", __func__);
    BtifAcmPeer* p = btif_acm_initiator.FindPeer(btif_acm_initiator.VoiceActivePeer());
    if (p != nullptr && p->IsConnected()) {
      p->SetStreamContextType(CONTEXT_TYPE_VOICE);
      btif_acm_initiator_dispatch_sm_event(btif_acm_initiator.VoiceActivePeer(), BTIF_ACM_STOP_STREAM_REQ_EVT);
    } else {
      BTIF_TRACE_DEBUG("%s: Unable to send stop to twm device ", __func__);
    }
  }
  return BT_STATUS_SUCCESS;
}

static bt_status_t codec_config_acm_initiator(const RawAddress& peer_address,
                                std::vector<CodecConfig> codec_preferences,
                                uint16_t contextType, uint16_t profileType) {
  BTIF_TRACE_EVENT("%s", __func__);

  if (!btif_acm_initiator.Enabled()) {
    LOG(WARNING) << __func__ << ": BTIF ACM Initiator is not enabled";
    return BT_STATUS_NOT_READY;
  }

  if (peer_address.IsEmpty()) {
    LOG(WARNING) << __func__ << ": BTIF ACM Initiator, peer empty";
    return BT_STATUS_PARM_INVALID;
  }

  std::promise<void> peer_ready_promise;
  std::future<void> peer_ready_future = peer_ready_promise.get_future();
  bt_status_t status = BT_STATUS_SUCCESS;
  if (status == BT_STATUS_SUCCESS) {
    peer_ready_future.wait();
  } else {
    LOG(WARNING) << __func__ << ": BTIF ACM Initiator fails to config codec";
  }
  return status;
}

static bt_status_t change_codec_config_acm_initiator(const RawAddress& peer_address,
                                                     char* msg) {
  BTIF_TRACE_DEBUG("%s: codec change string: %s", __func__, msg);
  tBTIF_ACM_RECONFIG data;
  if (!btif_acm_initiator.Enabled()) {
    LOG(WARNING) << __func__ << ": BTIF ACM Initiator is not enabled";
    return BT_STATUS_NOT_READY;
  }

  if (peer_address.IsEmpty()) {
    LOG(WARNING) << __func__ << ": BTIF ACM Initiator, peer empty";
    return BT_STATUS_PARM_INVALID;
  }
  BtifAcmPeer* peer = btif_acm_initiator.FindPeer(peer_address);
  if (peer == nullptr)
    LOG(ERROR) << __func__ << ": BTIF ACM Initiator, peer is null";
    return BT_STATUS_FAIL;

  CodecQosConfig codec_qos_cfg;
  memset(&codec_qos_cfg, 0, sizeof(codec_qos_cfg));
  if (!strcmp(msg, "GCP_TX") && peer->GetContextType() == CONTEXT_TYPE_MUSIC) {
    data.bd_addr = peer_address;
    data.streams_info.stream_type.type = CONTENT_TYPE_MEDIA;
    data.streams_info.stream_type.audio_context = CONTENT_TYPE_MEDIA;
    data.streams_info.stream_type.direction = ASE_DIRECTION_SINK;
    data.streams_info.reconf_type = bluetooth::bap::ucast::StreamReconfigType::CODEC_CONFIG;
    if (peer->IsStereoHsType()) {
      SelectCodecQosConfig(peer_address, GCP, MEDIA_CONTEXT, SNK, STEREO_HS_CONFIG_1);
    } else {
      SelectCodecQosConfig(peer_address, GCP, MEDIA_CONTEXT, SNK, EB_CONFIG);
    }
    codec_qos_cfg = peer->get_peer_media_codec_qos_config();
    data.streams_info.codec_qos_config_pair.push_back(codec_qos_cfg);
  } else if (!strcmp(msg, "GCP_TX_RX") && peer->GetContextType() == CONTEXT_TYPE_MUSIC) {
    data.bd_addr = peer_address;
    data.streams_info.stream_type.type = CONTENT_TYPE_MEDIA;
    data.streams_info.stream_type.direction = ASE_DIRECTION_SINK;
    data.streams_info.reconf_type = bluetooth::bap::ucast::StreamReconfigType::CODEC_CONFIG;
    SelectCodecQosConfig(peer_address, GCP, MEDIA_CONTEXT, SNK, EB_CONFIG);
    codec_qos_cfg = peer->get_peer_media_codec_qos_config();
    codec_qos_cfg.qos_config.cig_config.cig_id++;
    codec_qos_cfg.qos_config.ascs_configs[0].cig_id++;
    peer->set_peer_media_qos_config(codec_qos_cfg.qos_config);
    peer->set_peer_media_codec_qos_config(codec_qos_cfg);
    data.streams_info.codec_qos_config_pair.push_back(codec_qos_cfg);
  } else if (!strcmp(msg, "MEDIA_TX")) {
    data.bd_addr = peer_address;
    data.streams_info.stream_type.type = CONTENT_TYPE_MEDIA;
    data.streams_info.reconf_type = bluetooth::bap::ucast::StreamReconfigType::CODEC_CONFIG;
    data.streams_info.stream_type.direction = ASE_DIRECTION_SINK;
    if (peer->IsStereoHsType()) {
      SelectCodecQosConfig(peer_address, BAP, MEDIA_CONTEXT, SNK, STEREO_HS_CONFIG_1);
    } else {
      SelectCodecQosConfig(peer_address, BAP, MEDIA_CONTEXT, SNK, EB_CONFIG);
    }
    codec_qos_cfg = peer->get_peer_media_codec_qos_config();
    data.streams_info.codec_qos_config_pair.push_back(codec_qos_cfg);
  } else if (!strcmp(msg, "MEDIA_RX")) {
    data.bd_addr = peer_address;
    data.streams_info.stream_type.type = CONTENT_TYPE_MEDIA;
    data.streams_info.stream_type.audio_context = CONTENT_TYPE_LIVE; //Live Audio Context
    data.streams_info.reconf_type = bluetooth::bap::ucast::StreamReconfigType::CODEC_CONFIG;
    data.streams_info.stream_type.direction = ASE_DIRECTION_SRC;
    SelectCodecQosConfig(peer_address, WMCP, MEDIA_CONTEXT, SRC, EB_CONFIG);
    codec_qos_cfg = peer->get_peer_media_codec_qos_config();
    data.streams_info.codec_qos_config_pair.push_back(codec_qos_cfg);
  }
  print_codec_parameters(codec_qos_cfg.codec_config);
  print_qos_parameters(codec_qos_cfg.qos_config);
  btif_transfer_context(btif_acm_handle_evt, BTIF_ACM_RECONFIG_REQ_EVT, (char*)&data,
                        sizeof(tBTIF_ACM_RECONFIG), NULL);
  return BT_STATUS_SUCCESS;
}

bool reconfig_acm_initiator(const RawAddress& peer_address, int profileType) {
  BTIF_TRACE_DEBUG("%s: profileType: %d", __func__, profileType);
  tBTIF_ACM_RECONFIG data;
  if (!btif_acm_initiator.Enabled()) {
    LOG(WARNING) << __func__ << ": BTIF ACM Initiator is not enabled";
    return false;
  }

  if (peer_address.IsEmpty()) {
    LOG(WARNING) << __func__ << ": BTIF ACM Initiator, peer empty";
    return false;
  }
  BtifAcmPeer* peer = btif_acm_initiator.FindPeer(peer_address);
  if (peer == nullptr) {
    LOG(ERROR) << __func__ << ": BTIF ACM Initiator, peer is null";
    return false;
  }

  CodecQosConfig codec_qos_cfg;
  memset(&codec_qos_cfg, 0, sizeof(codec_qos_cfg));
  if ((profileType == GCP) && (peer->GetContextType() & CONTEXT_TYPE_MUSIC)) {
    data.bd_addr = peer_address;
    data.streams_info.stream_type.type = CONTENT_TYPE_MEDIA;
    data.streams_info.stream_type.audio_context = CONTENT_TYPE_MEDIA;
    data.streams_info.stream_type.direction = ASE_DIRECTION_SINK;
    data.streams_info.reconf_type = bluetooth::bap::ucast::StreamReconfigType::CODEC_CONFIG;
    if (peer->IsStereoHsType()) {
      SelectCodecQosConfig(peer_address, GCP, MEDIA_CONTEXT, SNK, STEREO_HS_CONFIG_1);
    } else {
      SelectCodecQosConfig(peer_address, GCP, MEDIA_CONTEXT, SNK, EB_CONFIG);
    }
    codec_qos_cfg = peer->get_peer_media_codec_qos_config();
    data.streams_info.codec_qos_config_pair.push_back(codec_qos_cfg);
  } else if ((profileType == GCP_TX_RX) && (peer->GetContextType() & CONTEXT_TYPE_MUSIC)) {
    data.bd_addr = peer_address;
    data.streams_info.stream_type.type = CONTENT_TYPE_MEDIA;
    data.streams_info.stream_type.direction = ASE_DIRECTION_SINK;
    data.streams_info.reconf_type = bluetooth::bap::ucast::StreamReconfigType::CODEC_CONFIG;
    SelectCodecQosConfig(peer_address, GCP, MEDIA_CONTEXT, SNK, EB_CONFIG);
    codec_qos_cfg = peer->get_peer_media_codec_qos_config();
    codec_qos_cfg.qos_config.cig_config.cig_id++;
    codec_qos_cfg.qos_config.ascs_configs[0].cig_id++;
    peer->set_peer_media_qos_config(codec_qos_cfg.qos_config);
    peer->set_peer_media_codec_qos_config(codec_qos_cfg);
    data.streams_info.codec_qos_config_pair.push_back(codec_qos_cfg);
  } else if ((profileType == BAP) && (peer->GetContextType() & CONTEXT_TYPE_MUSIC)) {
    data.bd_addr = peer_address;
    data.streams_info.stream_type.type = CONTENT_TYPE_MEDIA;
    data.streams_info.stream_type.audio_context = CONTENT_TYPE_MEDIA;
    data.streams_info.stream_type.direction = ASE_DIRECTION_SINK;
    data.streams_info.reconf_type = bluetooth::bap::ucast::StreamReconfigType::CODEC_CONFIG;
    if (peer->IsStereoHsType()) {
      SelectCodecQosConfig(peer_address, BAP, MEDIA_CONTEXT, SNK, STEREO_HS_CONFIG_1);
    } else {
      SelectCodecQosConfig(peer_address, BAP, MEDIA_CONTEXT, SNK, EB_CONFIG);
    }
    codec_qos_cfg = peer->get_peer_media_codec_qos_config();
    data.streams_info.codec_qos_config_pair.push_back(codec_qos_cfg);
  } else if ((profileType == WMCP) && (peer->GetContextType() & CONTEXT_TYPE_MUSIC)) {
    data.bd_addr = peer_address;
    data.streams_info.stream_type.type = CONTENT_TYPE_MEDIA;
    data.streams_info.stream_type.audio_context = CONTENT_TYPE_LIVE; //Live Audio Context
    data.streams_info.stream_type.direction = ASE_DIRECTION_SRC;
    data.streams_info.reconf_type = bluetooth::bap::ucast::StreamReconfigType::CODEC_CONFIG;
    if (peer->IsStereoHsType()) {
      SelectCodecQosConfig(peer_address, WMCP, MEDIA_CONTEXT, SRC, STEREO_HS_CONFIG_1);
    } else {
      SelectCodecQosConfig(peer_address, WMCP, MEDIA_CONTEXT, SRC, EB_CONFIG);
    }
    codec_qos_cfg = peer->get_peer_media_codec_qos_config();
    data.streams_info.codec_qos_config_pair.push_back(codec_qos_cfg);
  } else if ((profileType == BAP_CALL) && (peer->GetContextType() & CONTEXT_TYPE_VOICE)) {
    data.bd_addr = peer_address;
    data.streams_info.stream_type.type = CONTENT_TYPE_CONVERSATIONAL;
  }

  peer->SetRcfgProfileType(profileType);
  if (profileType != BAP_CALL) {
    print_codec_parameters(codec_qos_cfg.codec_config);
    print_qos_parameters(codec_qos_cfg.qos_config);
  }
  btif_transfer_context(btif_acm_handle_evt, BTIF_ACM_RECONFIG_REQ_EVT, (char*)&data,
                        sizeof(tBTIF_ACM_RECONFIG), NULL);
  return true;
}

static void cleanup_acm_initiator(void) {
  BTIF_TRACE_EVENT("%s", __func__);
  do_in_bta_thread(FROM_HERE, Bind(&BtifAcmInitiator::Cleanup,
                                   base::Unretained(&btif_acm_initiator)));
}

static const btacm_initiator_interface_t bt_acm_initiator_interface = {
    sizeof(btacm_initiator_interface_t),
    init_acm_initiator,
    connect_acm_initiator,
    disconnect_acm_initiator,
    set_active_acm_initiator,
    start_stream_acm_initiator,
    stop_stream_acm_initiator,
    codec_config_acm_initiator,
    change_codec_config_acm_initiator,
    cleanup_acm_initiator,
};

RawAddress btif_acm_initiator_music_active_peer(void) {
  return btif_acm_initiator.MusicActivePeer();
}

RawAddress btif_acm_initiator_voice_active_peer(void) {
  return btif_acm_initiator.VoiceActivePeer();
}

bool btif_acm_request_csip_lock(uint8_t setId) {
  LOG_INFO(LOG_TAG, "%s", __func__);
  tBTA_CSIP_CSET cset_info; // need to do memset ?
  memset(&cset_info, 0, sizeof(tBTA_CSIP_CSET));
  cset_info = BTA_CsipGetCoordinatedSet(setId);
  /*if (cset_info.p_srvc_uuid != ACM_UUID) {
    return false;
  }*/
  if (cset_info.size > cset_info.total_discovered) {
    LOG_INFO(LOG_TAG, "%s not complete set discovered yet. size = %d discovered = %d",
                    __func__, cset_info.size, cset_info.total_discovered);
  }
  if (setId == cset_info.set_id) {
    LOG_INFO(LOG_TAG, "%s correct set id", __func__);
  } else {
    return false;
  }

  btif_acm_check_and_cancel_lock_release_timer(setId);

  //Aquire lock for entire group.
  tBTA_SET_LOCK_PARAMS lock_params; //need to do memset ?
  lock_params.app_id = btif_acm_initiator.GetCsipAppId();
  lock_params.set_id = cset_info.set_id;
  lock_params.lock_value = LOCK_VALUE;//For lock
  lock_params.members_addr = cset_info.set_members;
  BTA_CsipSetLockValue (lock_params);
  btif_acm_initiator.SetLockFlags(BtifAcmInitiator::kFlagStatusPendingLock);
  btif_acm_initiator.SetOrUpdateGroupLockStatus(cset_info.set_id,
                     btif_acm_initiator.CheckLockFlags(BtifAcmInitiator::kFlagStatusPendingLock));
  return true;
}

bool btif_acm_request_csip_unlock(uint8_t setId) {
  tBTA_CSIP_CSET cset_info; // need to do memset ?
  memset(&cset_info, 0, sizeof(tBTA_CSIP_CSET));
  cset_info = BTA_CsipGetCoordinatedSet(setId);
  /*if (cset_info.p_srvc_uuid != Uuid::FromString("2B86")) {
    return false;
  }*/
  if (cset_info.size > cset_info.total_discovered) {
    LOG_INFO(LOG_TAG, "%s not complete set discovered yet. size = %d discovered = %d",
                    __func__, cset_info.size, cset_info.total_discovered);
  }
  if (setId == cset_info.set_id) {
    LOG_INFO(LOG_TAG, "%s correct app id", __func__);
  } else {
    return false;
  }
  //Aquire lock for entire group.
  tBTA_SET_LOCK_PARAMS lock_params; //need to do memset ?
  lock_params.app_id = btif_acm_initiator.GetCsipAppId();
  lock_params.set_id = cset_info.set_id;
  lock_params.lock_value = UNLOCK_VALUE;//For Unlock
  lock_params.members_addr = cset_info.set_members;
  BTA_CsipSetLockValue (lock_params);
  btif_acm_initiator.SetLockFlags(BtifAcmInitiator::kFlagStatusPendingUnlock);
  btif_acm_initiator.SetOrUpdateGroupLockStatus(cset_info.set_id,
                btif_acm_initiator.CheckLockFlags(BtifAcmInitiator::kFlagStatusPendingUnlock));
  return true;
}

bool btif_acm_is_call_active(void) {
  BtifAcmPeer* peer = nullptr;
  peer = btif_acm_initiator.FindPeer(btif_acm_initiator.VoiceActivePeer());
  if (peer != nullptr && (peer->IsStreaming() || peer->CheckFlags(BtifAcmPeer::kFlagPendingStart)) &&
          (peer->GetStreamContextType() == CONTEXT_TYPE_VOICE))
    return true;

  return false;
}

void btif_acm_stream_start(void) {
  LOG_INFO(LOG_TAG, "%s", __func__);
  if (!btif_acm_initiator.Enabled())
    return;
  bool ret = false;
  if (false/*btif_acm_initiator.IsCsipRegistered() && (btif_acm_initiator.MusicActiveCSetId() != INVALID_SET_ID)*/) {
    ret = btif_acm_request_csip_lock(btif_acm_initiator.MusicActiveCSetId());
    if (ret == false) {
      tA2DP_CTRL_CMD pending_cmd = btif_ahim_get_pending_command();
      if (pending_cmd == A2DP_CTRL_CMD_STOP ||
          pending_cmd == A2DP_CTRL_CMD_SUSPEND) {
        btif_acm_source_on_suspended(A2DP_CTRL_ACK_FAILURE);
      } else if (pending_cmd == A2DP_CTRL_CMD_START) {
        btif_acm_on_started(A2DP_CTRL_ACK_FAILURE);
      } else {
        BTIF_TRACE_DEBUG("%s: no pending command to ack mm audio", __func__);
      }
      return;
    }
    //call below in lock changed success CB
    //should be dispatched to list of peers in active music group.
    btif_acm_check_and_start_group_procedure_timer(btif_acm_initiator.MusicActiveCSetId());
  } else {
    int id = btif_acm_initiator.MusicActiveCSetId();
    if (id < INVALID_SET_ID) {
      bool send_neg_ack = true;
      tBTA_CSIP_CSET cset_info;
      memset(&cset_info, 0, sizeof(tBTA_CSIP_CSET));
      cset_info = BTA_CsipGetCoordinatedSet(id);
      std::vector<RawAddress>::iterator itr;
      BTIF_TRACE_DEBUG("%s: size of set members %d", __func__, (cset_info.set_members).size());
      if ((cset_info.set_members).size() > 0) {
        for (itr =(cset_info.set_members).begin(); itr != (cset_info.set_members).end(); itr++) {
           BTIF_TRACE_DEBUG("%s: Sending start request ", __func__);
           BtifAcmPeer* p = btif_acm_initiator.FindPeer(*itr);
           if (p != nullptr && p->IsConnected()) {
             send_neg_ack = false;
             p->SetStreamContextType(CONTEXT_TYPE_MUSIC);
             btif_acm_initiator_dispatch_sm_event(*itr, BTIF_ACM_START_STREAM_REQ_EVT);
           }
        }
      }
      if (send_neg_ack) {
        tA2DP_CTRL_CMD pending_cmd = btif_ahim_get_pending_command();
        if (pending_cmd == A2DP_CTRL_CMD_STOP ||
            pending_cmd == A2DP_CTRL_CMD_SUSPEND) {
          btif_acm_source_on_suspended(A2DP_CTRL_ACK_DISCONNECT_IN_PROGRESS);
        } else if (pending_cmd == A2DP_CTRL_CMD_START) {
          btif_acm_on_started(A2DP_CTRL_ACK_DISCONNECT_IN_PROGRESS);
        } else {
          BTIF_TRACE_DEBUG("%s: no pending command to ack mm audio", __func__);
        }
        return;
      }
      btif_acm_check_and_start_group_procedure_timer(btif_acm_initiator.MusicActiveCSetId());
    } else {
      BTIF_TRACE_DEBUG("%s: Sending start to twm device ", __func__);
      BtifAcmPeer* p = btif_acm_initiator.FindPeer(btif_acm_initiator_music_active_peer());

      if (p != nullptr && p->IsStreaming()) {
        BTIF_TRACE_DEBUG("%s: Already streaming ongoing", __func__);
        btif_acm_on_started(A2DP_CTRL_ACK_SUCCESS);
        return;
      }

      if (p != nullptr && p->IsConnected()) {
        p->SetStreamContextType(CONTEXT_TYPE_MUSIC);
        btif_acm_initiator_dispatch_sm_event(btif_acm_initiator_music_active_peer(), BTIF_ACM_START_STREAM_REQ_EVT);
      } else {
        tA2DP_CTRL_CMD pending_cmd = btif_ahim_get_pending_command();
        if (pending_cmd == A2DP_CTRL_CMD_STOP ||
            pending_cmd == A2DP_CTRL_CMD_SUSPEND) {
          btif_acm_source_on_suspended(A2DP_CTRL_ACK_DISCONNECT_IN_PROGRESS);
        } else if (pending_cmd == A2DP_CTRL_CMD_START) {
          btif_acm_on_started(A2DP_CTRL_ACK_DISCONNECT_IN_PROGRESS);
        } else {
          BTIF_TRACE_DEBUG("%s: no pending command to ack mm audio", __func__);
        }
      }
    }
  }
}

void btif_acm_stream_stop(void) {
  LOG_INFO(LOG_TAG, "%s ", __func__);
  bool ret = false;
  if (false /*btif_acm_initiator.IsCsipRegistered() && (btif_acm_initiator.MusicActiveCSetId() != INVALID_SET_ID)*/) {
    ret = btif_acm_request_csip_lock(btif_acm_initiator.MusicActiveCSetId());
    if (ret == false) {
      tA2DP_CTRL_CMD pending_cmd = btif_ahim_get_pending_command();
      if (pending_cmd == A2DP_CTRL_CMD_STOP ||
          pending_cmd == A2DP_CTRL_CMD_SUSPEND) {
        btif_acm_source_on_suspended(A2DP_CTRL_ACK_FAILURE);
      } else if (pending_cmd == A2DP_CTRL_CMD_START) {
        btif_acm_on_started(A2DP_CTRL_ACK_FAILURE);
      } else {
        BTIF_TRACE_DEBUG("%s: no pending command to ack mm audio", __func__);
      }
      return;
    }
    btif_acm_check_and_start_group_procedure_timer(btif_acm_initiator.MusicActiveCSetId());
  } else {
    BTIF_TRACE_DEBUG("%s: Sending stop to twm device ", __func__);
    BtifAcmPeer* p = btif_acm_initiator.FindPeer(btif_acm_initiator_music_active_peer());
    if (p != nullptr && p->IsConnected()) {
      p->SetStreamContextType(CONTEXT_TYPE_MUSIC);
      btif_acm_initiator_dispatch_sm_event(btif_acm_initiator_music_active_peer(), BTIF_ACM_STOP_STREAM_REQ_EVT);
    } else {
      tA2DP_CTRL_CMD pending_cmd = btif_ahim_get_pending_command();
      if (pending_cmd == A2DP_CTRL_CMD_STOP ||
          pending_cmd == A2DP_CTRL_CMD_SUSPEND) {
        btif_acm_source_on_suspended(A2DP_CTRL_ACK_DISCONNECT_IN_PROGRESS);
      } else if (pending_cmd == A2DP_CTRL_CMD_START) {
        btif_acm_on_started(A2DP_CTRL_ACK_DISCONNECT_IN_PROGRESS);
      } else {
        BTIF_TRACE_DEBUG("%s: no pending command to ack mm audio", __func__);
      }
    }
  }
}

void btif_acm_stream_suspend(void) {
  LOG_INFO(LOG_TAG, "%s", __func__);
  if (!btif_acm_initiator.Enabled())
    return;
  bool ret = false;
  if (false /*btif_acm_initiator.IsCsipRegistered() && (btif_acm_initiator.MusicActiveCSetId() != INVALID_SET_ID)*/) {
    ret = btif_acm_request_csip_lock(btif_acm_initiator.MusicActiveCSetId());
    //call below in lock changed success CB.
    //should be dispatched to list of peers in active music group.
    if (ret == false) {
      tA2DP_CTRL_CMD pending_cmd = btif_ahim_get_pending_command();
      if (pending_cmd == A2DP_CTRL_CMD_STOP ||
          pending_cmd == A2DP_CTRL_CMD_SUSPEND) {
        btif_acm_source_on_suspended(A2DP_CTRL_ACK_FAILURE);
      } else if (pending_cmd == A2DP_CTRL_CMD_START) {
        btif_acm_on_started(A2DP_CTRL_ACK_FAILURE);
      } else {
        BTIF_TRACE_DEBUG("%s: no pending command to ack mm audio", __func__);
      }
      return;
    }
    btif_acm_check_and_start_group_procedure_timer(btif_acm_initiator.MusicActiveCSetId());
  } else {
    int id = btif_acm_initiator.MusicActiveCSetId();
    if (id < INVALID_SET_ID) {
      bool send_neg_ack = true;
      tBTA_CSIP_CSET cset_info; // need to do memset ?
      memset(&cset_info, 0, sizeof(tBTA_CSIP_CSET));
      cset_info = BTA_CsipGetCoordinatedSet(id);
      std::vector<RawAddress>::iterator itr;
      BTIF_TRACE_DEBUG("%s: size of set members %d", __func__, (cset_info.set_members).size());
      if ((cset_info.set_members).size() > 0) {
        for (itr =(cset_info.set_members).begin(); itr != (cset_info.set_members).end(); itr++) {
           BTIF_TRACE_DEBUG("%s: Sending suspend request ", __func__);
           BtifAcmPeer* p = btif_acm_initiator.FindPeer(*itr);
           if (p != nullptr && p->IsConnected()) {
             send_neg_ack = false;
             p->SetStreamContextType(CONTEXT_TYPE_MUSIC);
             btif_acm_initiator_dispatch_sm_event(*itr, BTIF_ACM_SUSPEND_STREAM_REQ_EVT);
           }
        }
      }
      if (send_neg_ack) {
        tA2DP_CTRL_CMD pending_cmd = btif_ahim_get_pending_command();
        if (pending_cmd == A2DP_CTRL_CMD_STOP ||
            pending_cmd == A2DP_CTRL_CMD_SUSPEND) {
          btif_acm_source_on_suspended(A2DP_CTRL_ACK_DISCONNECT_IN_PROGRESS);
        } else if (pending_cmd == A2DP_CTRL_CMD_START) {
          btif_acm_on_started(A2DP_CTRL_ACK_DISCONNECT_IN_PROGRESS);
        } else {
          BTIF_TRACE_DEBUG("%s: no pending command to ack mm audio", __func__);
        }
        return;
      }
      btif_acm_check_and_start_group_procedure_timer(btif_acm_initiator.MusicActiveCSetId());
    } else {
      BTIF_TRACE_DEBUG("%s: Sending suspend to twm device ", __func__);
      BtifAcmPeer* p = btif_acm_initiator.FindPeer(btif_acm_initiator_music_active_peer());
      if (p != nullptr && p->IsConnected()) {
        p->SetStreamContextType(CONTEXT_TYPE_MUSIC);
        btif_acm_initiator_dispatch_sm_event(btif_acm_initiator_music_active_peer(), BTIF_ACM_SUSPEND_STREAM_REQ_EVT);
      } else {
        tA2DP_CTRL_CMD pending_cmd = btif_ahim_get_pending_command();
        if (pending_cmd == A2DP_CTRL_CMD_STOP ||
            pending_cmd == A2DP_CTRL_CMD_SUSPEND) {
          btif_acm_source_on_suspended(A2DP_CTRL_ACK_DISCONNECT_IN_PROGRESS);
        } else if (pending_cmd == A2DP_CTRL_CMD_START) {
          btif_acm_on_started(A2DP_CTRL_ACK_DISCONNECT_IN_PROGRESS);
        } else {
          BTIF_TRACE_DEBUG("%s: no pending command to ack mm audio", __func__);
        }
      }
    }
  }
}

void btif_acm_disconnect(const RawAddress& peer_address, int context_type) {
  LOG_INFO(LOG_TAG, "%s: peer %s", __func__, peer_address.ToString().c_str());
  disconnect_acm_initiator(peer_address, context_type);
}

static void btif_acm_initiator_dispatch_sm_event(const RawAddress& peer_address,
                                                 btif_acm_sm_event_t event) {
  BtifAcmEvent btif_acm_event(event, nullptr, 0);
  BTIF_TRACE_EVENT("%s: peer_address=%s event=%s", __func__,
                   peer_address.ToString().c_str(),
                   btif_acm_event.ToString().c_str());

  btif_transfer_context(btif_acm_handle_evt, event, (char *)&peer_address,
                        sizeof(RawAddress), NULL);
}

bt_status_t btif_acm_initiator_execute_service(bool enable) {
  BTIF_TRACE_EVENT("%s: service: %s", __func__,
                   (enable) ? "enable" : "disable");

  if (enable) {
    BTA_RegisterCsipApp(bta_csip_callback, base::Bind([](uint8_t status, uint8_t app_id) {
                                             if (status != BTA_CSIP_SUCCESS) {
                                                LOG(ERROR) << "Can't register CSIP module ";
                                                return;
                                             }
                                             BTIF_TRACE_DEBUG("App ID: %d", app_id);
                                             btif_acm_initiator.SetCsipAppId(app_id);
                                             btif_acm_initiator.SetCsipRegistration(true);} ));
    return BT_STATUS_SUCCESS;
  }

  // Disable the service
  //BTA_UnregisterCsipApp();
  return BT_STATUS_FAIL;
}

// Get the ACM callback interface for ACM Initiator profile
const btacm_initiator_interface_t* btif_acm_initiator_get_interface(void) {
  BTIF_TRACE_EVENT("%s", __func__);
  return &bt_acm_initiator_interface;
}

uint16_t btif_acm_get_active_device_latency() {
  BtifAcmPeer* peer = btif_acm_initiator.FindMusicActivePeer();
  if (peer == nullptr) {
    BTIF_TRACE_WARNING("%s: peer is NULL", __func__);
    return 0;
  } else {
    return peer->GetPeerLatency();
  }
}

static void SelectCodecQosConfig(const RawAddress& bd_addr,
                                 int profile_type, int context_type,
                                 int direction, int config_type) {

  BTIF_TRACE_DEBUG("%s: Peer %s , context type: %d, profile_type: %d,"
                   " direction: %d config_type %d", __func__,
                   bd_addr.ToString().c_str(), context_type,
                   profile_type, direction, config_type);

  BtifAcmPeer* peer = btif_acm_initiator.FindPeer(bd_addr);
  if (peer == nullptr) {
    BTIF_TRACE_WARNING("%s: peer is NULL", __func__);
    return;
  }

  uint8_t CigId = peer->CigId();
  uint8_t set_size = 0;
  tBTA_CSIP_CSET cset_info;
  memset(&cset_info, 0, sizeof(cset_info));
  cset_info = BTA_CsipGetCoordinatedSet(peer->SetId());
  BTIF_TRACE_DEBUG("%s: cset members size: %d",
                    __func__, (uint8_t)(cset_info.size));

  if (cset_info.size == 0) {
    BTIF_TRACE_WARNING("%s: this shud be case for stereo-HS, config_type %d",
                                             __func__, config_type);
    set_size = (config_type == STEREO_HS_CONFIG_1) ? 2 : 1;
  } else {
    set_size = cset_info.size;
  }

  CodecConfig codec_config_;
  CodecQosConfig codec_qos_config;
  QosConfig qos_configs;
  CISConfig cis_config;
  std::vector<QoSConfig> vmcp_qos_config;
  BTIF_TRACE_WARNING("%s: going for best config", __func__);
  memset(&codec_config_, 0, sizeof(codec_config_));
  select_best_codec_config(bd_addr, context_type, profile_type,
                            &codec_config_, direction, config_type);
  codec_qos_config.codec_config = codec_config_;
  BTIF_TRACE_DEBUG("%s: sample rate : %d, frame_duration: %d, octets: %d, ",
                   __func__, static_cast<uint16_t>(codec_config_.sample_rate),
                   GetFrameDuration(&codec_config_),
                   GetOctsPerFrame(&codec_config_));

  if (context_type == MEDIA_CONTEXT) {
    if (profile_type != WMCP) {
      vmcp_qos_config = get_qos_params_for_codec(profile_type,
                                      MEDIA_LL_CONTEXT,
                                      codec_config_.sample_rate,
                                      GetFrameDuration(&codec_config_),
                                      GetOctsPerFrame(&codec_config_));
    } else {
      vmcp_qos_config = get_qos_params_for_codec(profile_type,
                                      MEDIA_HR_CONTEXT,
                                      codec_config_.sample_rate,
                                      GetFrameDuration(&codec_config_),
                                      GetOctsPerFrame(&codec_config_));
    }
  } else if (context_type == VOICE_CONTEXT) {
    vmcp_qos_config = get_qos_params_for_codec(profile_type,
                                      VOICE_CONTEXT,
                                      codec_config_.sample_rate,
                                      GetFrameDuration(&codec_config_),
                                      GetOctsPerFrame(&codec_config_));
  }
  BTIF_TRACE_DEBUG("%s: vmcp qos size: %d",
                           __func__, (uint8_t)vmcp_qos_config.size());

  bool qhs_enable = false;
  char qhs_value[PROPERTY_VALUE_MAX] = "false";
  property_get("persist.vendor.btstack.qhs_enable", qhs_value, "false");
  if (!strncmp("true", qhs_value, 4)) {
    if (btm_acl_qhs_phy_supported(bd_addr, BT_TRANSPORT_LE)) {
      qhs_enable = true;
    }
  } else {
    qhs_enable = false;
  }

  //TODO: fill cig id and cis count from
  //Currently it is a single size vector
  for (uint8_t j = 0; j < (uint8_t)vmcp_qos_config.size(); j++) {
    if (vmcp_qos_config[j].mandatory == 0) {
      uint32_t sdu_interval = vmcp_qos_config[j].sdu_int_micro_secs;
      codec_qos_config.qos_config.cig_config = {
                  .cig_id = CigId,
                  .cis_count = set_size,
                  .packing = 0x01, // interleaved
                  .framing =  vmcp_qos_config[j].framing, // unframed
                  .max_tport_latency_m_to_s = vmcp_qos_config[j].max_trans_lat,
                  .max_tport_latency_s_to_m = vmcp_qos_config[j].max_trans_lat,
                  .sdu_interval_m_to_s = {
                             static_cast<uint8_t>(sdu_interval & 0xFF),
                             static_cast<uint8_t>((sdu_interval >> 8)& 0xFF),
                             static_cast<uint8_t>((sdu_interval >> 16)& 0xFF)
                           },
                  .sdu_interval_s_to_m = {
                             static_cast<uint8_t>(sdu_interval & 0xFF),
                             static_cast<uint8_t>((sdu_interval >> 8)& 0xFF),
                             static_cast<uint8_t>((sdu_interval >> 16)& 0xFF)
                           }
                  };
      BTIF_TRACE_DEBUG("%s: framing: %d, transport latency: %d"
                       " sdu_interval: %d", __func__,
                        vmcp_qos_config[j].framing,
                        vmcp_qos_config[j].max_trans_lat,
                        vmcp_qos_config[j].sdu_int_micro_secs);
      BTIF_TRACE_DEBUG("%s: CIG: packing: %d, transport latency m to s: %d,"
              " transport latency s to m: %d", __func__,
              codec_qos_config.qos_config.cig_config.packing,
              codec_qos_config.qos_config.cig_config.max_tport_latency_m_to_s,
              codec_qos_config.qos_config.cig_config.max_tport_latency_s_to_m);
      BTIF_TRACE_DEBUG("%s: Filled CIG config ", __func__);
    }
  }

  for (uint8_t i = 0; i < set_size; i++) {
    //Currently it is a single size vector
    uint8_t check_memset = 0;
    for (uint8_t j = 0; j < (uint8_t)vmcp_qos_config.size(); j++) {
      if (vmcp_qos_config[j].mandatory == 0) {
        memset(&cis_config, 0, sizeof(cis_config));
        if (!check_memset)
          check_memset = 1;
        cis_config.cis_id = i;
        if (profile_type != WMCP)
          cis_config.max_sdu_m_to_s = vmcp_qos_config[j].max_sdu_size;
        else
          cis_config.max_sdu_m_to_s = 0;
        if ((context_type == VOICE_CONTEXT) || (profile_type == WMCP))
          cis_config.max_sdu_s_to_m = vmcp_qos_config[j].max_sdu_size;
        else
          cis_config.max_sdu_s_to_m = 0;

        BTIF_TRACE_DEBUG("%s: qhs_enable: %d", __func__, qhs_enable);

        if (qhs_enable) {
          cis_config.phy_m_to_s = LE_QHS_PHY;
          cis_config.phy_s_to_m = LE_QHS_PHY;
        } else {
          cis_config.phy_m_to_s = LE_2M_PHY;//2mbps
          cis_config.phy_s_to_m = LE_2M_PHY;
        }
        cis_config.rtn_m_to_s = vmcp_qos_config[j].retrans_num;
        cis_config.rtn_s_to_m = vmcp_qos_config[j].retrans_num;
      }
    }
    if (!check_memset)
      memset(&cis_config, 0, sizeof(cis_config));
    codec_qos_config.qos_config.cis_configs.push_back(cis_config);
    BTIF_TRACE_DEBUG("%s: Filled CIS config for %d", __func__, i);
  }

  for (uint8_t j = 0; j < (uint8_t)vmcp_qos_config.size(); j++) {
    if (vmcp_qos_config[j].mandatory == 0) {
      uint32_t presen_delay = vmcp_qos_config[j].presentation_delay;
      ASCSConfig ascs_config_1 = {
                      .cig_id = CigId,
                      .cis_id = peer->CisId(),
                      .target_latency = 0x03,//Target higher reliability
                      .bi_directional = false,
                      .presentation_delay = {static_cast<uint8_t>(presen_delay & 0xFF),
                                             static_cast<uint8_t>((presen_delay >> 8)& 0xFF),
                                             static_cast<uint8_t>((presen_delay >> 16)& 0xFF)}
                      };
      codec_qos_config.qos_config.ascs_configs.push_back(ascs_config_1);
      BTIF_TRACE_DEBUG("%s: presentation delay = %d", __func__, presen_delay);
      BTIF_TRACE_DEBUG("%s: Filled ASCS config for %d", __func__, ascs_config_1.cis_id);
      if (config_type == STEREO_HS_CONFIG_1) {
        ASCSConfig ascs_config_2 = ascs_config_1;
        ascs_config_2.cis_id = peer->CisId()+1;
        codec_qos_config.qos_config.ascs_configs.push_back(ascs_config_2);
        BTIF_TRACE_DEBUG("%s: Filled ASCS config for %d", __func__, ascs_config_2.cis_id);
      }
    }
  }

  if (profile_type == BAP) {
    if (context_type == VOICE_CONTEXT) {
      if (direction == SNK) {
        codec_qos_config.qos_config.cig_config.cig_id = CigId + 2;
        codec_qos_config.qos_config.ascs_configs[0].cig_id = CigId + 2;
        codec_qos_config.qos_config.ascs_configs[0].target_latency = 0x01;
        codec_qos_config.qos_config.ascs_configs[0].bi_directional = true;
        if (config_type == STEREO_HS_CONFIG_1) {
          codec_qos_config.qos_config.ascs_configs[1].cig_id = CigId + 2;
          codec_qos_config.qos_config.ascs_configs[1].target_latency = 0x01;
          codec_qos_config.qos_config.ascs_configs[1].bi_directional = true;
        }
        peer->set_peer_voice_tx_codec_config(codec_config_);
        peer->set_peer_voice_tx_qos_config(codec_qos_config.qos_config);
        peer->set_peer_voice_tx_codec_qos_config(codec_qos_config);
      } else if (direction == SRC) {
        codec_qos_config.qos_config.cig_config.cig_id = CigId + 2;
        codec_qos_config.qos_config.ascs_configs[0].cig_id = CigId + 2;
        codec_qos_config.qos_config.ascs_configs[0].target_latency = 0x01;
        codec_qos_config.qos_config.ascs_configs[0].bi_directional = true;
        if (config_type == STEREO_HS_CONFIG_1) {
          codec_qos_config.qos_config.ascs_configs[1].cig_id = CigId + 2;
          codec_qos_config.qos_config.ascs_configs[1].target_latency = 0x01;
          codec_qos_config.qos_config.ascs_configs[1].bi_directional = true;
        }
        peer->set_peer_voice_rx_codec_config(codec_config_);
        peer->set_peer_voice_rx_qos_config(codec_qos_config.qos_config);
        peer->set_peer_voice_rx_codec_qos_config(codec_qos_config);
      }
    } else {
      peer->set_peer_media_codec_config(codec_config_);
      peer->set_peer_media_qos_config(codec_qos_config.qos_config);
      peer->set_peer_media_codec_qos_config(codec_qos_config);
    }
  } else if (profile_type == GCP) {
    if (context_type == VOICE_CONTEXT) {
      codec_qos_config.qos_config.cig_config.cig_id = CigId + 1;
      codec_qos_config.qos_config.ascs_configs[0].cig_id = CigId + 1;
      codec_qos_config.qos_config.ascs_configs[0].target_latency = 0x01;
      codec_qos_config.qos_config.ascs_configs[0].bi_directional = true;
      peer->set_peer_voice_rx_codec_config(codec_config_);
      peer->set_peer_voice_rx_qos_config(codec_qos_config.qos_config);
      peer->set_peer_voice_rx_codec_qos_config(codec_qos_config);
    } else {
      peer->set_peer_media_codec_config(codec_config_);
      peer->set_peer_media_qos_config(codec_qos_config.qos_config);
      peer->set_peer_media_codec_qos_config(codec_qos_config);
    }
  } else if (profile_type == WMCP) {
    if (context_type == MEDIA_CONTEXT) {
      codec_qos_config.qos_config.cig_config.cig_id = CigId + 3;
      codec_qos_config.qos_config.ascs_configs[0].cig_id = CigId + 3;
      if (config_type == STEREO_HS_CONFIG_1)
        codec_qos_config.qos_config.ascs_configs[1].cig_id = CigId + 3;
      peer->set_peer_media_codec_config(codec_config_);
      peer->set_peer_media_qos_config(codec_qos_config.qos_config);
      peer->set_peer_media_codec_qos_config(codec_qos_config);
    }
  }
  //print_codec_parameters(codec_config_);
  //print_qos_parameters(codec_qos_config.qos_config);
}

static bool select_best_sample_rate(uint16_t samp_freq, CodecConfig *result_config) {
  BTIF_TRACE_DEBUG("%s: samp_freq: %d", __func__, samp_freq);
  if (samp_freq & static_cast<uint16_t>(CodecSampleRate::CODEC_SAMPLE_RATE_48000)) {
    result_config->sample_rate = CodecSampleRate::CODEC_SAMPLE_RATE_48000;
    return true;
  }
  if (samp_freq & static_cast<uint16_t>(CodecSampleRate::CODEC_SAMPLE_RATE_44100)) {
    result_config->sample_rate = CodecSampleRate::CODEC_SAMPLE_RATE_44100;
    return true;
  }
  if (samp_freq & static_cast<uint16_t>(CodecSampleRate::CODEC_SAMPLE_RATE_32000)) {
    result_config->sample_rate = CodecSampleRate::CODEC_SAMPLE_RATE_32000;
    return true;
  }
  if (samp_freq & static_cast<uint16_t>(CodecSampleRate::CODEC_SAMPLE_RATE_24000)) {
    result_config->sample_rate = CodecSampleRate::CODEC_SAMPLE_RATE_24000;
    return true;
  }
  if (samp_freq & static_cast<uint16_t>(CodecSampleRate::CODEC_SAMPLE_RATE_16000)) {
    result_config->sample_rate = CodecSampleRate::CODEC_SAMPLE_RATE_16000;
    return true;
  }
  if (samp_freq & static_cast<uint16_t>(CodecSampleRate::CODEC_SAMPLE_RATE_8000)) {
    result_config->sample_rate = CodecSampleRate::CODEC_SAMPLE_RATE_8000;
    return true;
  }
  return false;
}

static bool select_best_frame_dura(uint8_t frame_dura,
                                   CodecConfig *result_config) {
  BTIF_TRACE_DEBUG("%s: frame_duration: %d", __func__, frame_dura);
  if (frame_dura & static_cast<uint8_t>(CodecFrameDuration::FRAME_DUR_10)) {
    BTIF_TRACE_DEBUG("%s: selecting 10ms as best frame duration", __func__);
    UpdateFrameDuration(result_config,
                   static_cast<uint8_t>(CodecFrameDuration::FRAME_DUR_10));
    return true;
  }

  if ((frame_dura &
       static_cast<uint8_t>(CodecFrameDuration::FRAME_DUR_7_5)) == 0) {
    BTIF_TRACE_DEBUG("%s: selecting 7.5ms as best frame duration", __func__);
    UpdateFrameDuration(result_config,
               static_cast<uint8_t>(CodecFrameDuration::FRAME_DUR_7_5));
    return true;
  }
  return true;
}

void select_best_codec_config(const RawAddress& bd_addr,
                              uint16_t context_type,
                              uint8_t profile_type,
                              CodecConfig *codec_config,
                              int dir, int config_type) {

    BTIF_TRACE_DEBUG("%s: select best codec config for context type: %d,"
                     " profile type %d config_type %d", __func__,
                     context_type, profile_type, config_type);

    CodecConfig result_codec_config;
    uint16_t vmcp_samp_freq = 0;
    uint8_t vmcp_fram_dur = 0;
    uint32_t vmcp_octets_per_frame = 0;
    std::vector<CodecConfig> pac_record;
    std::vector<CodecConfig> local_codec_config;
    memset(&result_codec_config, 0, sizeof(result_codec_config));
    bool pac_found = false;
    uint16_t audio_context_type = CONTENT_TYPE_UNSPECIFIED;

    bool is_lc3q_supported = false;
    char lc3q_value[PROPERTY_VALUE_MAX] = "false";
    property_get("persist.vendor.service.bt.is_lc3q_supported", lc3q_value, "false");
    if (!strncmp("true", lc3q_value, 4)) {
      is_lc3q_supported = true;
    } else {
      is_lc3q_supported = false;
    }
    BTIF_TRACE_IMP("%s: is_lc3q_supported: %d", __func__, is_lc3q_supported);

    if (context_type == MEDIA_CONTEXT) {
      audio_context_type |=
        (profile_type == WMCP) ? CONTENT_TYPE_LIVE : CONTENT_TYPE_MEDIA;
    } else if (context_type == VOICE_CONTEXT) {
      audio_context_type |= CONTENT_TYPE_CONVERSATIONAL;
    }
    BTIF_TRACE_IMP("%s: audio_context_type: %d", __func__, audio_context_type);

    pac_found = btif_bap_get_records(bd_addr, REC_TYPE_CAPABILITY, audio_context_type,
        ((dir == SRC) ? CodecDirection::CODEC_DIR_SRC : CodecDirection::CODEC_DIR_SINK),
        &pac_record);

    if (pac_found) {
      BTIF_TRACE_DEBUG("%s: PAC record found, select best codec config", __func__);
      uint16_t peer_samp_freq = 0;
      uint8_t peer_channel_mode = 0;
      uint8_t peer_fram_dur = 0;
      uint16_t peer_min_octets_per_frame = 0;
      uint16_t peer_max_octets_per_frame = 0;
      uint8_t peer_max_sup_lc3_frames = 0;
      uint16_t peer_preferred_context = 0;
      bool peer_lc3q_pref = 0;
      uint8_t peer_lc3q_ver = 0;

      //currently differentiating based on frequency later we will do on context type
      for (auto it = pac_record.begin(); it != pac_record.end(); ++it) {
        if (it->codec_type == CodecIndex::CODEC_INDEX_SOURCE_LC3) {
          //performing only for MUSIC context type based on 44.1KHz and 48KHz
          BTIF_TRACE_DEBUG("%s: pac_record sample_rate: %d", __func__, it->sample_rate);
          if (it->sample_rate == CodecSampleRate::CODEC_SAMPLE_RATE_48000) {
            peer_samp_freq |= static_cast<uint16_t>(it->sample_rate);
          } else if (it->sample_rate == CodecSampleRate::CODEC_SAMPLE_RATE_44100) {
            peer_samp_freq |= static_cast<uint16_t>(it->sample_rate);
          } else if (it->sample_rate == CodecSampleRate::CODEC_SAMPLE_RATE_32000) {
            peer_samp_freq |= static_cast<uint16_t>(it->sample_rate);
          } else if (it->sample_rate == CodecSampleRate::CODEC_SAMPLE_RATE_24000) {
            peer_samp_freq |= static_cast<uint16_t>(it->sample_rate);
          } else if (it->sample_rate == CodecSampleRate::CODEC_SAMPLE_RATE_16000) {
            peer_samp_freq |= static_cast<uint16_t>(it->sample_rate);
          } else if (it->sample_rate == CodecSampleRate::CODEC_SAMPLE_RATE_8000) {
            peer_samp_freq |= static_cast<uint16_t>(it->sample_rate);
          }
        }
      }

      local_codec_config = get_all_codec_configs(profile_type, context_type);
      BTIF_TRACE_DEBUG("%s: vmcp codec size: %d",
                           __func__, (uint8_t)local_codec_config.size());
      for (auto it = local_codec_config.begin();
                             it != local_codec_config.end(); ++it) {
        if (it->codec_type == CodecIndex::CODEC_INDEX_SOURCE_LC3) {
          BTIF_TRACE_DEBUG("%s: local_codec_config sample_rate: %d",
                                           __func__, it->sample_rate);
          if (it->sample_rate == CodecSampleRate::CODEC_SAMPLE_RATE_48000) {
            vmcp_samp_freq |= static_cast<uint16_t>(it->sample_rate);
          } else if (it->sample_rate == CodecSampleRate::CODEC_SAMPLE_RATE_44100) {
            vmcp_samp_freq |= static_cast<uint16_t>(it->sample_rate);
          } else if (it->sample_rate == CodecSampleRate::CODEC_SAMPLE_RATE_32000) {
            vmcp_samp_freq |= static_cast<uint16_t>(it->sample_rate);
          } else if (it->sample_rate == CodecSampleRate::CODEC_SAMPLE_RATE_24000) {
            vmcp_samp_freq |= static_cast<uint16_t>(it->sample_rate);
          } else if (it->sample_rate == CodecSampleRate::CODEC_SAMPLE_RATE_16000) {
            vmcp_samp_freq |= static_cast<uint16_t>(it->sample_rate);
          } else if (it->sample_rate == CodecSampleRate::CODEC_SAMPLE_RATE_8000) {
            vmcp_samp_freq |= static_cast<uint16_t>(it->sample_rate);
          }
        }
      }

      select_best_sample_rate(peer_samp_freq & vmcp_samp_freq,
                                                   &result_codec_config);
      for (auto it = pac_record.begin(); it != pac_record.end(); ++it) {
        if (it->codec_type == CodecIndex::CODEC_INDEX_SOURCE_LC3) {
           BTIF_TRACE_DEBUG("%s: pac_record sample_rate: %d,"
                            " result_codec_config.sample_rate: %d",
                            __func__, it->sample_rate,
                            result_codec_config.sample_rate);
            if (it->sample_rate == CodecSampleRate::CODEC_SAMPLE_RATE_48000 &&
                result_codec_config.sample_rate == CodecSampleRate::CODEC_SAMPLE_RATE_48000) {
              BTIF_TRACE_DEBUG("%s: selecting 48KHz for config", __func__);
              peer_channel_mode = static_cast<uint8_t>(it->channel_mode);
              peer_fram_dur = GetCapaSupFrameDurations(&(*it));
              peer_min_octets_per_frame = GetCapaSupOctsPerFrame(&(*it)) & 0xFFFF;
              peer_max_octets_per_frame = (GetCapaSupOctsPerFrame(&(*it)) & 0xFFFF0000) >> 16;
              peer_max_sup_lc3_frames = GetCapaMaxSupLc3Frames(&(*it));
              peer_lc3q_pref = GetCapaVendorMetaDataLc3QPref(&(*it));
              peer_lc3q_ver = GetCapaVendorMetaDataLc3QVer(&(*it));
              peer_preferred_context = GetCapaPreferredContexts(&(*it));
              break;
            } else if (it->sample_rate == CodecSampleRate::CODEC_SAMPLE_RATE_44100 &&
                result_codec_config.sample_rate == CodecSampleRate::CODEC_SAMPLE_RATE_44100) {
              BTIF_TRACE_DEBUG("%s: selecting 44.1KHz for config", __func__);
              peer_channel_mode = static_cast<uint8_t>(it->channel_mode);
              peer_fram_dur = GetCapaSupFrameDurations(&(*it));
              peer_min_octets_per_frame = GetCapaSupOctsPerFrame(&(*it)) & 0xFFFF;
              peer_max_octets_per_frame = (GetCapaSupOctsPerFrame(&(*it)) & 0xFFFF0000) >> 16;
              peer_max_sup_lc3_frames = GetCapaMaxSupLc3Frames(&(*it));
              peer_lc3q_pref = GetCapaVendorMetaDataLc3QPref(&(*it));
              peer_lc3q_ver = GetCapaVendorMetaDataLc3QVer(&(*it));
              peer_preferred_context = GetCapaPreferredContexts(&(*it));
              break;
            } else if (it->sample_rate == CodecSampleRate::CODEC_SAMPLE_RATE_32000 &&
                result_codec_config.sample_rate == CodecSampleRate::CODEC_SAMPLE_RATE_32000) {
              BTIF_TRACE_DEBUG("%s: selecting 32KHz for config", __func__);
              peer_channel_mode = static_cast<uint8_t>(it->channel_mode);
              peer_fram_dur = GetCapaSupFrameDurations(&(*it));
              peer_min_octets_per_frame = GetCapaSupOctsPerFrame(&(*it)) & 0xFFFF;
              peer_max_octets_per_frame = (GetCapaSupOctsPerFrame(&(*it)) & 0xFFFF0000) >> 16;
              peer_max_sup_lc3_frames = GetCapaMaxSupLc3Frames(&(*it));
              peer_lc3q_pref = GetCapaVendorMetaDataLc3QPref(&(*it));
              peer_lc3q_ver = GetCapaVendorMetaDataLc3QVer(&(*it));
              peer_preferred_context = GetCapaPreferredContexts(&(*it));
              break;
            } else if (it->sample_rate == CodecSampleRate::CODEC_SAMPLE_RATE_24000 &&
                result_codec_config.sample_rate == CodecSampleRate::CODEC_SAMPLE_RATE_24000) {
              BTIF_TRACE_DEBUG("%s: selecting 24KHz for config", __func__);
              peer_channel_mode = static_cast<uint8_t>(it->channel_mode);
              peer_fram_dur = GetCapaSupFrameDurations(&(*it));
              peer_min_octets_per_frame = GetCapaSupOctsPerFrame(&(*it)) & 0xFFFF;
              peer_max_octets_per_frame = (GetCapaSupOctsPerFrame(&(*it)) & 0xFFFF0000) >> 16;
              peer_max_sup_lc3_frames = GetCapaMaxSupLc3Frames(&(*it));
              peer_lc3q_pref = GetCapaVendorMetaDataLc3QPref(&(*it));
              peer_lc3q_ver = GetCapaVendorMetaDataLc3QVer(&(*it));
              peer_preferred_context = GetCapaPreferredContexts(&(*it));
              break;
            } else if (it->sample_rate == CodecSampleRate::CODEC_SAMPLE_RATE_16000 &&
                result_codec_config.sample_rate == CodecSampleRate::CODEC_SAMPLE_RATE_16000) {
              BTIF_TRACE_DEBUG("%s: selecting 16KHz for config", __func__);
              peer_channel_mode = static_cast<uint8_t>(it->channel_mode);
              peer_fram_dur = GetCapaSupFrameDurations(&(*it));
              peer_min_octets_per_frame = GetCapaSupOctsPerFrame(&(*it)) & 0xFFFF;
              peer_max_octets_per_frame = (GetCapaSupOctsPerFrame(&(*it)) & 0xFFFF0000) >> 16;
              peer_max_sup_lc3_frames = GetCapaMaxSupLc3Frames(&(*it));
              peer_lc3q_pref = GetCapaVendorMetaDataLc3QPref(&(*it));
              peer_lc3q_ver = GetCapaVendorMetaDataLc3QVer(&(*it));
              peer_preferred_context = GetCapaPreferredContexts(&(*it));
              break;
            } else if (it->sample_rate == CodecSampleRate::CODEC_SAMPLE_RATE_8000 &&
                result_codec_config.sample_rate == CodecSampleRate::CODEC_SAMPLE_RATE_8000) {
              BTIF_TRACE_DEBUG("%s: selecting 8KHz for config", __func__);
              peer_channel_mode = static_cast<uint8_t>(it->channel_mode);
              peer_fram_dur = GetCapaSupFrameDurations(&(*it));
              peer_min_octets_per_frame = GetCapaSupOctsPerFrame(&(*it)) & 0xFFFF;
              peer_max_octets_per_frame = (GetCapaSupOctsPerFrame(&(*it)) & 0xFFFF0000) >> 16;
              peer_max_sup_lc3_frames = GetCapaMaxSupLc3Frames(&(*it));
              peer_lc3q_pref = GetCapaVendorMetaDataLc3QPref(&(*it));
              peer_lc3q_ver = GetCapaVendorMetaDataLc3QVer(&(*it));
              peer_preferred_context = GetCapaPreferredContexts(&(*it));
              break;
            }
          }
        }

      BTIF_TRACE_DEBUG("%s: PAC parameters, peer supported sample_freqncies=%d,"
                       " channel_mode=%d, frame_dura=%d", __func__,
                        peer_samp_freq, peer_channel_mode, peer_fram_dur);
      BTIF_TRACE_DEBUG("%s: PAC parameters, min_octets_per_frame=%d,"
                       " max_octets_per_frame=%d, peer_max_sup_lc3_frames=%d",
                       __func__, peer_min_octets_per_frame, peer_max_octets_per_frame,
                       peer_max_sup_lc3_frames);
      BTIF_TRACE_DEBUG("%s: PAC parameters, peer_preferred_context=%d",
                       __func__, peer_preferred_context);
      BTIF_TRACE_DEBUG("%s: PAC parameters, peer_lc3q_pref=%d, peer_lc3q_ver=%d",
                                        __func__, peer_lc3q_pref, peer_lc3q_ver);

      local_codec_config = get_all_codec_configs(profile_type, context_type);
      BTIF_TRACE_DEBUG("%s: vmcp codec size: %d",
                        __func__, (uint8_t)local_codec_config.size());
      for (auto it = local_codec_config.begin();
                             it != local_codec_config.end(); ++it) {
        if (it->codec_type == CodecIndex::CODEC_INDEX_SOURCE_LC3) {
          BTIF_TRACE_DEBUG("%s: local_codec_config sample_rate: %d,"
                           " result_codec_config.sample_rate: %d",
                           __func__, it->sample_rate, result_codec_config.sample_rate);
          if (it->sample_rate == CodecSampleRate::CODEC_SAMPLE_RATE_48000 &&
              result_codec_config.sample_rate == CodecSampleRate::CODEC_SAMPLE_RATE_48000) {
            vmcp_fram_dur |= GetFrameDuration(&(*it));
            if (vmcp_octets_per_frame < GetOctsPerFrame(&(*it)))
              vmcp_octets_per_frame = GetOctsPerFrame(&(*it));
          } else if (it->sample_rate == CodecSampleRate::CODEC_SAMPLE_RATE_44100 &&
              result_codec_config.sample_rate == CodecSampleRate::CODEC_SAMPLE_RATE_44100) {
            vmcp_fram_dur |= GetFrameDuration(&(*it));
            if (vmcp_octets_per_frame < GetOctsPerFrame(&(*it)))
              vmcp_octets_per_frame = GetOctsPerFrame(&(*it));
          } else if (it->sample_rate == CodecSampleRate::CODEC_SAMPLE_RATE_32000 &&
              result_codec_config.sample_rate == CodecSampleRate::CODEC_SAMPLE_RATE_32000) {
            vmcp_fram_dur |= GetFrameDuration(&(*it));
            if (vmcp_octets_per_frame < GetOctsPerFrame(&(*it)))
              vmcp_octets_per_frame = GetOctsPerFrame(&(*it));
          } else if (it->sample_rate == CodecSampleRate::CODEC_SAMPLE_RATE_24000 &&
              result_codec_config.sample_rate == CodecSampleRate::CODEC_SAMPLE_RATE_24000) {
            vmcp_fram_dur |= GetFrameDuration(&(*it));
            if (vmcp_octets_per_frame < GetOctsPerFrame(&(*it)))
              vmcp_octets_per_frame = GetOctsPerFrame(&(*it));
          } else if (it->sample_rate == CodecSampleRate::CODEC_SAMPLE_RATE_16000 &&
              result_codec_config.sample_rate == CodecSampleRate::CODEC_SAMPLE_RATE_16000) {
            vmcp_fram_dur |= GetFrameDuration(&(*it));
            if (vmcp_octets_per_frame < GetOctsPerFrame(&(*it)))
              vmcp_octets_per_frame = GetOctsPerFrame(&(*it));
          } else if (it->sample_rate == CodecSampleRate::CODEC_SAMPLE_RATE_8000 &&
              result_codec_config.sample_rate == CodecSampleRate::CODEC_SAMPLE_RATE_8000) {
            vmcp_fram_dur |= GetFrameDuration(&(*it));
            if (vmcp_octets_per_frame < GetOctsPerFrame(&(*it)))
              vmcp_octets_per_frame = GetOctsPerFrame(&(*it));
          }
        }
      }

      if (config_type == STEREO_HS_CONFIG_2)
        vmcp_octets_per_frame = vmcp_octets_per_frame * 2;

      BTIF_TRACE_DEBUG("%s: VMCP parameters, sample_freq=%d,"
                       " frame_duration=%d, octets=%d", __func__,
                        vmcp_samp_freq, vmcp_fram_dur, vmcp_octets_per_frame);

      result_codec_config.codec_type = CodecIndex::CODEC_INDEX_SOURCE_LC3;
      result_codec_config.codec_priority = CodecPriority::CODEC_PRIORITY_DEFAULT;

      if (config_type == STEREO_HS_CONFIG_2) {
        result_codec_config.channel_mode = CodecChannelMode::CODEC_CHANNEL_MODE_STEREO;
      } else {
        result_codec_config.channel_mode = CodecChannelMode::CODEC_CHANNEL_MODE_MONO;
      }

      select_best_frame_dura((peer_fram_dur >> 1) & vmcp_fram_dur, &result_codec_config);

      if (vmcp_octets_per_frame < peer_min_octets_per_frame ||
          vmcp_octets_per_frame > peer_max_octets_per_frame) {
        BTIF_TRACE_DEBUG("%s: octets per frame is out of bound: %d ",
                             __func__, vmcp_octets_per_frame);
        UpdateOctsPerFrame(&result_codec_config, vmcp_octets_per_frame);
      } else {
        BTIF_TRACE_DEBUG("%s: octets per frame is in limit update 100 octets: %d ",
                              __func__, vmcp_octets_per_frame);
        UpdateOctsPerFrame(&result_codec_config, vmcp_octets_per_frame);//TODO: make this as peer octets
      }

      if (is_lc3q_supported) {
        UpdateLc3QPreference(&result_codec_config, true);
      }
      UpdateCapaMaxSupLc3Frames(&result_codec_config, peer_max_sup_lc3_frames);
      UpdateLc3BlocksPerSdu(&result_codec_config, 1);
      UpdatePreferredAudioContext(&result_codec_config, audio_context_type);
      *codec_config = result_codec_config;
    } else {
      BTIF_TRACE_DEBUG("%s: PAC record not found, select mandatory config", __func__);
      mandatory_codec_selected = true;
      std::vector<CodecConfig> codec_pref_config;
      codec_pref_config = get_all_codec_configs(profile_type, context_type);
      BTIF_TRACE_DEBUG("%s: vmcp codec size %d", __func__, (uint8_t)codec_pref_config.size());
      for (auto it = codec_pref_config.begin(); it != codec_pref_config.end(); ++it) {
        if (it->codec_type == CodecIndex::CODEC_INDEX_SOURCE_LC3) {
          if (it->sample_rate == CodecSampleRate::CODEC_SAMPLE_RATE_48000) {
            BTIF_TRACE_DEBUG("%s: selecting 48KHz from VMCP", __func__);
            result_codec_config.sample_rate = CodecSampleRate::CODEC_SAMPLE_RATE_48000;
            vmcp_fram_dur |= GetFrameDuration(&(*it));
            if (vmcp_octets_per_frame < GetOctsPerFrame(&(*it)))
              vmcp_octets_per_frame = GetOctsPerFrame(&(*it));
          } else if (it->sample_rate == CodecSampleRate::CODEC_SAMPLE_RATE_44100) {
            BTIF_TRACE_DEBUG("%s: selecting 44.1KHz from VMCP", __func__);
            result_codec_config.sample_rate = CodecSampleRate::CODEC_SAMPLE_RATE_44100;
            vmcp_fram_dur |= GetFrameDuration(&(*it));
            if (vmcp_octets_per_frame < GetOctsPerFrame(&(*it)))
              vmcp_octets_per_frame = GetOctsPerFrame(&(*it));
          } else if (it->sample_rate == CodecSampleRate::CODEC_SAMPLE_RATE_32000) {
            BTIF_TRACE_DEBUG("%s: selecting 32KHz from VMCP", __func__);
            result_codec_config.sample_rate = CodecSampleRate::CODEC_SAMPLE_RATE_32000;
            vmcp_fram_dur |= GetFrameDuration(&(*it));
            if (vmcp_octets_per_frame < GetOctsPerFrame(&(*it)))
              vmcp_octets_per_frame = GetOctsPerFrame(&(*it));
          } else if (it->sample_rate == CodecSampleRate::CODEC_SAMPLE_RATE_24000) {
            BTIF_TRACE_DEBUG("%s: selecting 24KHz from VMCP", __func__);
            result_codec_config.sample_rate = CodecSampleRate::CODEC_SAMPLE_RATE_24000;
            vmcp_fram_dur |= GetFrameDuration(&(*it));
            if (vmcp_octets_per_frame < GetOctsPerFrame(&(*it)))
              vmcp_octets_per_frame = GetOctsPerFrame(&(*it));
          } else if (it->sample_rate == CodecSampleRate::CODEC_SAMPLE_RATE_16000) {
            BTIF_TRACE_DEBUG("%s: selecting 16KHz from VMCP", __func__);
            result_codec_config.sample_rate = CodecSampleRate::CODEC_SAMPLE_RATE_16000;
            vmcp_fram_dur |= GetFrameDuration(&(*it));
            if (vmcp_octets_per_frame < GetOctsPerFrame(&(*it)))
              vmcp_octets_per_frame = GetOctsPerFrame(&(*it));
          } else if (it->sample_rate == CodecSampleRate::CODEC_SAMPLE_RATE_8000) {
            BTIF_TRACE_DEBUG("%s: selecting 8KHz from VMCP", __func__);
            result_codec_config.sample_rate = CodecSampleRate::CODEC_SAMPLE_RATE_8000;
            vmcp_fram_dur |= GetFrameDuration(&(*it));
            if (vmcp_octets_per_frame < GetOctsPerFrame(&(*it)))
              vmcp_octets_per_frame = GetOctsPerFrame(&(*it));
          }
        }
      }

      if (config_type == STEREO_HS_CONFIG_2)
        vmcp_octets_per_frame = vmcp_octets_per_frame * 2;

      BTIF_TRACE_DEBUG("%s: VMCP parameters, frame_duration=%d, octets=%d",
                         __func__, vmcp_fram_dur, vmcp_octets_per_frame);

      result_codec_config.codec_type = CodecIndex::CODEC_INDEX_SOURCE_LC3;
      result_codec_config.codec_priority = CodecPriority::CODEC_PRIORITY_DEFAULT;
      if (config_type == STEREO_HS_CONFIG_2)
        result_codec_config.channel_mode = CodecChannelMode::CODEC_CHANNEL_MODE_STEREO;
      else
        result_codec_config.channel_mode = CodecChannelMode::CODEC_CHANNEL_MODE_MONO;
      //select_best_sample_rate(peer_samp_freq & vmcp_samp_freq, &result_codec_config, context_type);
      select_best_frame_dura(vmcp_fram_dur, &result_codec_config);
      UpdateOctsPerFrame(&result_codec_config, vmcp_octets_per_frame);
      if (is_lc3q_supported) {
        UpdateLc3QPreference(&result_codec_config, true);
      }
      UpdateLc3BlocksPerSdu(&result_codec_config, 1);//currently making it for media case
      UpdatePreferredAudioContext(&result_codec_config, audio_context_type);
      BTIF_TRACE_DEBUG("%s: saved codec config", __func__);
      *codec_config = result_codec_config;
    }
}

uint16_t btif_acm_get_sample_rate() {
  if (current_active_config.sample_rate !=
                CodecSampleRate::CODEC_SAMPLE_RATE_NONE) {
    BTIF_TRACE_DEBUG("[ACM]:%s: sample_rate = %d",
                     __func__, current_active_config.sample_rate);
    return static_cast<uint16_t>(current_active_config.sample_rate);
  } else {
    BTIF_TRACE_DEBUG("[ACM]:%s: default sample_rate = %d",
                     __func__, default_config.sample_rate);
    return static_cast<uint16_t>(default_config.sample_rate);
  }
}

uint8_t btif_acm_get_ch_mode() {
  if (current_active_config.channel_mode !=
         CodecChannelMode::CODEC_CHANNEL_MODE_NONE) {
    BTIF_TRACE_DEBUG("[ACM]:%s: channel mode = %d",
                 __func__, current_active_config.channel_mode);
    return static_cast<uint8_t>(current_active_config.channel_mode);
  } else {
    BTIF_TRACE_DEBUG("[ACM]:%s: channel mode = %d",
                      __func__, default_config.channel_mode);
    return static_cast<uint8_t>(default_config.channel_mode);
  }
}

uint32_t btif_acm_get_bitrate() {
    //based on bitrate set (100(80kbps), 120 (96kbps), 155 (128kbps))
    uint32_t bitrate = 0;
    uint16_t octets = static_cast<int>(GetOctsPerFrame(&current_active_config));
    BTIF_TRACE_DEBUG("[ACM]:%s: octets = %d",__func__, octets);

    switch (octets) {
        case 26:
          bitrate = 27800;
          break;

        case 30:
          if (btif_acm_get_sample_rate() ==
              (static_cast<uint16_t>(CodecSampleRate::CODEC_SAMPLE_RATE_8000))) {
            bitrate = 24000;
          } else {
            bitrate = 32000;
          }
          break;

        case 40:
          bitrate = 32000;
          break;

        case 45:
          bitrate = 48000;
          break;

        case 60:
          if (btif_acm_get_sample_rate() ==
              (static_cast<uint16_t>(CodecSampleRate::CODEC_SAMPLE_RATE_24000))) {
            bitrate = 48000;
          } else {
            bitrate = 64000;
          }
          break;

        case 80:
          bitrate = 64000;
          break;

        case 98:
        case 130:
          bitrate = 95550;
          break;

        case 75:
        case 100:
          bitrate = 80000;
          break;

        case 90:
        case 120:
          bitrate = 96000;
          break;

        case 117:
        case 155:
          bitrate = 124000;
          break;

        default:
          bitrate = 124000;
          break;
    }
    BTIF_TRACE_DEBUG("[ACM]%s: bitrate = %d",__func__,bitrate);
    return bitrate;
}

uint32_t btif_acm_get_octets(uint32_t bit_rate) {
    uint32_t octets = 0;
    octets = GetOctsPerFrame(&current_active_config);
    BTIF_TRACE_DEBUG("[ACM]%s: octets = %d",__func__,octets);
    return octets;
}

uint16_t btif_acm_get_framelength() {
  uint16_t frame_duration;
  switch (GetFrameDuration(&current_active_config)) {
      case 0:
        frame_duration = 7500; //7.5msec
        break;

      case 1:
        frame_duration = 10000; //10msec
        break;

      default:
        frame_duration = 10000;
  }
  BTIF_TRACE_DEBUG("[ACM]%s: frame duration = %d",
                                 __func__,frame_duration);
  return frame_duration;
}

uint16_t btif_acm_get_current_active_profile() {
    return current_active_profile_type;
}
uint8_t btif_acm_get_ch_count() {//update channel mode based on device connection
    uint8_t ch_mode = 0;
    if (current_active_config.channel_mode ==
        CodecChannelMode::CODEC_CHANNEL_MODE_STEREO) {
      ch_mode = 0x02;
    } else if (current_active_config.channel_mode ==
               CodecChannelMode::CODEC_CHANNEL_MODE_MONO) {
      ch_mode = 0x01;
    }
    BTIF_TRACE_DEBUG("[ACM]%s: channel count = %d",__func__,ch_mode);
    return ch_mode;
}

bool btif_acm_is_codec_type_lc3q() {
  BTIF_TRACE_DEBUG("[ACM]%s",__func__);
  return GetVendorMetaDataLc3QPref(&current_active_config);
}

uint8_t btif_acm_lc3q_ver() {
  BTIF_TRACE_DEBUG("[ACM]%s",__func__);
  return GetVendorMetaDataLc3QVer(&current_active_config);
}

uint16_t btif_acm_bap_to_acm_context(uint16_t bap_context) {
  switch (bap_context) {
    case CONTENT_TYPE_MEDIA:
    case CONTENT_TYPE_LIVE:
      return CONTEXT_TYPE_MUSIC;

    case CONTENT_TYPE_CONVERSATIONAL:
      return CONTEXT_TYPE_VOICE;

    default:
      BTIF_TRACE_DEBUG("%s: Unknown bap context",__func__);
      return CONTEXT_TYPE_UNKNOWN;
  }
}

static void btif_debug_acm_peer_dump(int fd, const BtifAcmPeer& peer) {
  std::string state_str;
  int state = peer.StateMachine().StateId();
  switch (state) {
    case BtifAcmStateMachine::kStateIdle:
      state_str = "Idle";
      break;

    case BtifAcmStateMachine::kStateOpening:
      state_str = "Opening";
      break;

    case BtifAcmStateMachine::kStateOpened:
      state_str = "Opened";
      break;

    case BtifAcmStateMachine::kStateStarted:
      state_str = "Started";
      break;

    case BtifAcmStateMachine::kStateReconfiguring:
      state_str = "Reconfiguring";
      break;

    case BtifAcmStateMachine::kStateClosing:
      state_str = "Closing";
      break;

    default:
      state_str = "Unknown(" + std::to_string(state) + ")";
      break;
  }

  dprintf(fd, "  Peer: %s\n", peer.PeerAddress().ToString().c_str());
  dprintf(fd, "    Connected: %s\n", peer.IsConnected() ? "true" : "false");
  dprintf(fd, "    Streaming: %s\n", peer.IsStreaming() ? "true" : "false");
  dprintf(fd, "    State Machine: %s\n", state_str.c_str());
  dprintf(fd, "    Flags: %s\n", peer.FlagsToString().c_str());

}

bool compare_codec_config_(CodecConfig &first, CodecConfig &second) {
    if (first.codec_type != second.codec_type) {
      BTIF_TRACE_DEBUG("[ACM] Codec type mismatch %s",__func__);
      return true;
    } else if (first.sample_rate != second.sample_rate) {
      BTIF_TRACE_DEBUG("[ACM] Sample rate mismatch %s",__func__);
      return true;
    } else if (first.bits_per_sample != second.bits_per_sample) {
      BTIF_TRACE_DEBUG("[ACM] Bits per sample mismatch %s",__func__);
      return true;
    } else if (first.channel_mode != second.channel_mode) {
      BTIF_TRACE_DEBUG("[ACM] Channel mode mismatch %s",__func__);
      return true;
    } else {
      uint8_t frame_first = GetFrameDuration(&first);
      uint8_t frame_second = GetFrameDuration(&second);
      if (frame_first != frame_second) {
        BTIF_TRACE_DEBUG("[ACM] frame duration mismatch %s",__func__);
        return true;
      }
      uint8_t lc3blockspersdu_first = GetLc3BlocksPerSdu(&first);
      uint8_t lc3blockspersdu_second = GetLc3BlocksPerSdu(&second);
      if (lc3blockspersdu_first != lc3blockspersdu_second) {
        BTIF_TRACE_DEBUG("[ACM] LC3blocks per SDU mismatch %s",__func__);
        return true;
      }
      uint16_t octets_first = GetOctsPerFrame(&first);
      uint16_t octets_second = GetOctsPerFrame(&second);
      if (octets_first != octets_second) {
        BTIF_TRACE_DEBUG("[ACM] LC3 octets mismatch %s",__func__);
        return true;
      }
      return false;
    }
}

void print_codec_parameters(CodecConfig config) {
  uint8_t frame = GetFrameDuration(&config);
  uint8_t lc3blockspersdu = GetLc3BlocksPerSdu(&config);
  uint16_t octets = GetOctsPerFrame(&config);
  bool vendormetadatalc3qpref = GetCapaVendorMetaDataLc3QPref(&config);
  uint8_t vendormetadatalc3qver = GetCapaVendorMetaDataLc3QVer(&config);
  LOG_DEBUG(
    LOG_TAG,
    "codec_type=%d codec_priority=%d "
    "sample_rate=0x%x bits_per_sample=0x%x "
    "channel_mode=0x%x",
    config.codec_type, config.codec_priority,
    config.sample_rate, config.bits_per_sample,
    config.channel_mode);
  LOG_DEBUG(
    LOG_TAG,
    "frame_duration=%d, lc3_blocks_per_SDU=%d,"
    " octets_per_frame=%d, vendormetadatalc3qpref=%d,"
    " vendormetadatalc3qver=%d ",
    frame, lc3blockspersdu, octets,
    vendormetadatalc3qpref, vendormetadatalc3qver);
}

void print_qos_parameters(QosConfig qos) {
    LOG_DEBUG(
    LOG_TAG,
    "CIG --> cig_id=%d cis_count=%d "
    "packing=%d framing=%d "
    "max_tport_latency_m_to_s=%d "
    "max_tport_latency_s_to_m=%d "
    "sdu_interval_m_to_s[0] = %x "
    "sdu_interval_m_to_s[1] = %x "
    "sdu_interval_m_to_s[2] = %x ",
    qos.cig_config.cig_id, qos.cig_config.cis_count,
    qos.cig_config.packing, qos.cig_config.framing,
    qos.cig_config.max_tport_latency_m_to_s,
    qos.cig_config.max_tport_latency_s_to_m,
    qos.cig_config.sdu_interval_m_to_s[0],
    qos.cig_config.sdu_interval_m_to_s[1],
    qos.cig_config.sdu_interval_m_to_s[2]);
    for (auto it = qos.cis_configs.begin(); it != qos.cis_configs.end(); ++it) {
      LOG_DEBUG(
      LOG_TAG,
      "CIS --> cis_id = %d max_sdu_m_to_s = %d "
      "max_sdu_s_to_m=%d "
      "phy_m_to_s = %d "
      "phy_s_to_m = %d "
      "rtn_m_to_s = %d "
      "rtn_s_to_m = %d",
      it->cis_id, it->max_sdu_m_to_s,
      it->max_sdu_s_to_m,
      it->phy_m_to_s, it->phy_s_to_m,
      it->rtn_m_to_s, it->rtn_s_to_m);
    }
    for (auto it = qos.ascs_configs.begin(); it != qos.ascs_configs.end(); ++it) {
      LOG_DEBUG(
        LOG_TAG,
        "ASCS --> cig_id = %d cis_id = %d "
        "target_latency=%d "
        "bi_directional = %d "
        "presentation_delay[0] = %x "
        "presentation_delay[1] = %x "
        "presentation_delay[2] = %x ",
        it->cig_id,
        it->cis_id,
        it->target_latency,
        it->bi_directional,
        it->presentation_delay[0],
        it->presentation_delay[1],
        it->presentation_delay[2]);
    }
}

static void btif_debug_acm_initiator_dump(int fd) {
  bool enabled = btif_acm_initiator.Enabled();

  dprintf(fd, "\nA2DP Source State: %s\n", (enabled) ? "Enabled" : "Disabled");
  if (!enabled) return;
  //dprintf(fd, "  Active peer: %s\n",
    //      btif_acm_initiator.ActivePeer().ToString().c_str());
  for (auto it : btif_acm_initiator.Peers()) {
    const BtifAcmPeer* peer = it.second;
    btif_debug_acm_peer_dump(fd, *peer);
  }
}

void btif_debug_acm_dump(int fd) {
  btif_debug_acm_initiator_dump(fd);
}
