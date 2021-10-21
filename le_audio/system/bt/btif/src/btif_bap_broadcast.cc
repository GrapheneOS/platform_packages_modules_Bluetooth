/*
 * Copyright (c) 2020, The Linux Foundation. All rights reserved.
 */

#define LOG_TAG "btif_bap_broadcast"

#include "btif_bap_broadcast.h"

#include <base/logging.h>
#include <string.h>
#include <base/bind.h>
#include <hardware/bluetooth.h>
#include <hardware/bt_av.h>
#include <hardware/bt_bap_ba.h>

#include "bt_common.h"
#include "bt_utils.h"
#include "btif_storage.h"
#include "btif_a2dp.h"
#include "btif_hf.h"
#include "btif_a2dp_control.h"
#include "btif_util.h"
#include "btu.h"
#include "osi/include/allocator.h"
#include "osi/include/osi.h"
#include "osi/include/properties.h"
#include "btif/include/btif_a2dp_source.h"
#include "device/include/interop.h"
#include "device/include/controller.h"
#include "btif_bat.h"
#include "btif_av.h"
#include "hcimsgs.h"
#include "btif_config.h"
#include "audio_a2dp_hw/include/audio_a2dp_hw.h"
#include <time.h>
#include <hardware/ble_advertiser.h>
#include <hardware/bt_gatt.h>
#include "btm_ble_api.h"
#include "btm_ble_api_types.h"
#include "ble_advertiser.h"
#if (OFF_TARGET_TEST_ENABLED == FALSE)
#include "audio_hal_interface/a2dp_encoding.h"
#endif
#include "controller.h"
#if (OFF_TARGET_TEST_ENABLED == TRUE)
#include "log/log.h"
#include "service/a2dp_hal_sim/audio_a2dp_hal_stub.h"
#endif
#include "state_machine.h"

#define BIG_COMPILE 1

#define BTIF_BAP_BA_NUM_CB       1
#define kDefaultMaxBroadcastSupported 1
#define BTIF_BAP_BA_NUM_BMS 1

#define INPUT_DATAPATH 0x01
#define OUTPUT_DATAPATH 0x02
#define BROADCAST_SPLIT_STEREO 2
#define BROADCAST_MONO_JOINT 1
#define BROADCAST_MODE_HR 0x1000
#define BROADCAST_MODE_LL 0x2000
/*****************************************************************************
 *  Local type definitions
 *****************************************************************************/
 typedef enum {
   BIG_TERMINATED = 0,
   BIG_CREATING,
   BIG_CREATED,
   BIG_RECONFIG,
   BIG_TERMINATING,
   BIG_DISABLING,
 } btif_big_state_t;

std::vector<btav_a2dp_codec_config_t> broadcast_codecs_capabilities;
btav_a2dp_codec_index_t lc3_codec_id = (btav_a2dp_codec_index_t)9;
static const btav_a2dp_codec_config_t broadcast_local_capability =
                           {lc3_codec_id, BTAV_A2DP_CODEC_PRIORITY_DEFAULT,
                           (BTAV_A2DP_CODEC_SAMPLE_RATE_48000 |
                            BTAV_A2DP_CODEC_SAMPLE_RATE_24000 |
                            BTAV_A2DP_CODEC_SAMPLE_RATE_16000),
                           BTAV_A2DP_CODEC_BITS_PER_SAMPLE_24,
                           ((btav_a2dp_codec_channel_mode_t)(BTAV_A2DP_CODEC_CHANNEL_MODE_MONO |
                           BTAV_A2DP_CODEC_CHANNEL_MODE_STEREO |
                           BTBAP_CODEC_CHANNEL_MODE_JOINT_STEREO)), 0, 0, 0, 0};

static btav_a2dp_codec_config_t default_config;
static btav_a2dp_codec_config_t current_config;
static int mBisMultiplier = 0;
//static bool isSplitEnabled = false;
static bool notify_key_generated = false;
Octet16 encryption_key;
std::vector<uint8_t> mBroadcastID(3,0);
struct keyCalculator {
  Octet16 rand;
};
uint8_t enc_keylength = 16;
char local_param[3];
RawAddress mBapBADevice = RawAddress({0xFA, 0xCE, 0xFA, 0xCE, 0xFA, 0xCE});
std::mutex session_wait_;
std::condition_variable session_wait_cv_;
bool mSession_wait;
bool mEncryptionEnabled = true;
bool restart_session = false;
extern int btif_max_av_clients;
extern const btgatt_interface_t* btif_gatt_get_interface();
extern int btif_av_get_latest_device_idx_to_start();
extern thread_t* get_worker_thread();
int total_bises = 0;
typedef enum {
  iso_unknown = 0,
  setup_iso = 1,
  remove_iso = 2,
}tBAP_BA_ISO_CMD;

typedef struct {
  uint32_t sdu_int;
  uint16_t max_sdu;
  uint16_t max_transport_latency;
  uint8_t rtn;
  uint8_t phy;
  uint8_t packing;
  uint8_t framing;
} tBAP_BA_BIG_PARAMS;

tBAP_BA_BIG_PARAMS mBigParams = {10000, 100, 10, 2, 2/*LE 2M*/, 1/*Interleaved*/, 0/*unframed*/};
#define PATH_ID 1
tBAP_BA_ISO_CMD pending_cmd = iso_unknown;
int current_handle = -1;
int current_iso_index = 0;

int config_req_handle = -1;
/**
 * Local functions
 */
static void btif_bap_ba_generate_enc_key_local(int length);
static void btif_bap_ba_create_big(int adv_id);
static void btif_bap_ba_terminate_big(int adv_id, int big_handle);
static bool btif_bap_ba_setup_iso_datapath(int big_handle);
static bool btif_bap_ba_remove_iso_datapath(int big_handle);
static void btif_bap_ba_process_iso_setup(uint8_t status, uint16_t bis_handle);
static void btif_bap_ba_update_big_params();
static void btif_bap_ba_handle_event(uint32_t event, char* p_param);
static void init_local_capabilities();
static void btif_report_broadcast_state(int adv_id,
                                btbap_broadcast_state_t state);
static void btif_report_broadcast_audio_state(int adv_id,
                                btbap_broadcast_audio_state_t state);
static void btif_report_audio_config(int adv_id,
                                 btav_a2dp_codec_config_t codec_config);
static void btif_report_setup_big(int setup, int adv_id, int big_handle, int num_bises);
static void btif_report_broadcast_id();
static void btif_bap_process_request(tA2DP_CTRL_CMD cmd);
static void btif_broadcast_process_hidl_event(tA2DP_CTRL_CMD cmd);
static uint16_t btif_bap_get_transport_latency();
static void btif_bap_ba_copy_broadcast_id();
static void btif_bap_ba_generate_broadcast_id();
static void btif_bap_ba_signal_session_ready() {
  std::unique_lock<std::mutex> guard(session_wait_);
  if(!mSession_wait) {
    mSession_wait = true;
    session_wait_cv_.notify_all();
  } else {
   BTIF_TRACE_WARNING("%s: already signalled ",__func__);
  }
}

const char* dump_bap_ba_sm_event_name(btif_bap_broadcast_sm_event_t event) {
  switch ((int)event) {
    CASE_RETURN_STR(BTIF_BAP_BROADCAST_ENABLE_EVT)
    CASE_RETURN_STR(BTIF_BAP_BROADCAST_DISABLE_EVT)
    CASE_RETURN_STR(BTIF_BAP_BROADCAST_START_STREAM_REQ_EVT)
    CASE_RETURN_STR(BTIF_BAP_BROADCAST_STOP_STREAM_REQ_EVT)
    CASE_RETURN_STR(BTIF_BAP_BROADCAST_SUSPEND_STREAM_REQ_EVT)
    CASE_RETURN_STR(BTIF_BAP_BROADCAST_SOURCE_CONFIG_REQ_EVT)
    CASE_RETURN_STR(BTIF_BAP_BROADCAST_CLEANUP_REQ_EVT)
    CASE_RETURN_STR(BTIF_BAP_BROADCAST_SET_ACTIVE_REQ_EVT)
    CASE_RETURN_STR(BTIF_BAP_BROADCAST_REMOVE_ACTIVE_REQ_EVT)
    CASE_RETURN_STR(BTIF_BAP_BROADCAST_SETUP_ISO_DATAPATH_EVT)
    CASE_RETURN_STR(BTIF_BAP_BROADCAST_REMOVE_ISO_DATAPATH_EVT)
    CASE_RETURN_STR(BTIF_BAP_BROADCAST_GENERATE_ENC_KEY_EVT)
    CASE_RETURN_STR(BTIF_BAP_BROADCAST_BISES_SETUP_EVT)
    CASE_RETURN_STR(BTIF_BAP_BROADCAST_BISES_REMOVE_EVT)
    CASE_RETURN_STR(BTIF_BAP_BROADCAST_BIG_SETUP_EVT)
    CASE_RETURN_STR(BTIF_BAP_BROADCAST_BIG_REMOVED_EVT)
    CASE_RETURN_STR(BTIF_BAP_BROADCAST_PROCESS_HIDL_REQ_EVT)
    CASE_RETURN_STR(BTIF_BAP_BROADCAST_SETUP_NEXT_BIS_EVENT)
    CASE_RETURN_STR(BTIF_SM_ENTER_EVT)
    CASE_RETURN_STR(BTIF_SM_EXIT_EVT)
    default:
      return "UNKNOWN_EVENT";
  }
}

void btif_bap_broadcast_update_source_codec(void *p_data) {
  btav_a2dp_codec_config_t * codec_req = (btav_a2dp_codec_config_t*)p_data;
  if (codec_req->sample_rate != current_config.sample_rate ||
    codec_req->channel_mode != current_config.channel_mode ||
    codec_req->codec_specific_1 != current_config.codec_specific_1 ||
    codec_req->codec_specific_2 != current_config.codec_specific_2) {
    restart_session = true;
  }

  if (codec_req->codec_specific_4 > 0) {
    if (current_config.codec_specific_4 == BROADCAST_MODE_HR) {
      mBigParams.max_transport_latency = 60;
    } else if (codec_req->codec_specific_4 == BROADCAST_MODE_LL) {
      mBigParams.max_transport_latency = 20;
    }
  }
  memcpy(&current_config, codec_req, sizeof(btav_a2dp_codec_config_t));
  BTIF_TRACE_DEBUG("[BapBroadcast]%s:sample rate: %d",__func__, current_config.sample_rate);
  BTIF_TRACE_DEBUG("[BapBroadcast]%s:channel mode: %d",__func__, current_config.channel_mode);
  BTIF_TRACE_DEBUG("[BapBroadcast]%s:cs1: %d",__func__, current_config.codec_specific_1);
  btif_bap_ba_update_big_params();
}

void reverseCode(uint8_t *array) {
  uint8_t *p_array = array;
  for (int i = 0; i < 8; i++) {
    uint8_t temp = p_array[i];
    p_array[i] = p_array[15-i];
    p_array[15-i] = temp;
  }
}

bool isUnencrypted(uint8_t *array) {
  uint8_t *p_array = array;
  for (int i = 0; i < 16; i++) {
    if (p_array[i] != 0x00) {
      return false;
    }
  }
  BTIF_TRACE_DEBUG("[BapBroadcast]: isUnencrypted is true");
  return true;
}
class BtifBapBroadcaster;

class BtifBapBroadcastStateMachine : public bluetooth::common::StateMachine{
 public:
  enum {
    kStateIdle,     // Broadcast idle
    kStateConfigured,  // Broadcast configured
    kStateStreaming,   // Broadcast streaming
  };

  class StateIdle : public State {
   public:
    StateIdle(BtifBapBroadcastStateMachine& sm)
        : State(sm, kStateIdle), bms_(sm.Bms()) {}
    void OnEnter() override;
    void OnExit() override;
    bool ProcessEvent(uint32_t event, void* p_data) override;

   private:
    BtifBapBroadcaster& bms_;
  };

  class StateConfigured : public State {
   public:
    StateConfigured(BtifBapBroadcastStateMachine& sm)
        : State(sm, kStateConfigured), bms_(sm.Bms()) {}
    void OnEnter() override;
    void OnExit() override;
    bool ProcessEvent(uint32_t event, void* p_data) override;

   private:
    BtifBapBroadcaster& bms_;
  };

  class StateStreaming : public State {
   public:
    StateStreaming(BtifBapBroadcastStateMachine& sm)
        : State(sm, kStateStreaming), bms_(sm.Bms()) {}
    void OnEnter() override;
    void OnExit() override;
    bool ProcessEvent(uint32_t event, void* p_data) override;

   private:
    BtifBapBroadcaster& bms_;
  };

  BtifBapBroadcastStateMachine(BtifBapBroadcaster& bms) : bms_(bms) {
    state_idle_ = new StateIdle(*this);
    state_configured_ = new StateConfigured(*this);
    state_streaming_ = new StateStreaming(*this);

    AddState(state_idle_);
    AddState(state_configured_);
    AddState(state_streaming_);
    SetInitialState(state_idle_);
  }
  BtifBapBroadcaster& Bms() { return bms_; }
  private:
  BtifBapBroadcaster& bms_;
  StateIdle* state_idle_;
  StateConfigured* state_configured_;
  StateStreaming* state_streaming_;
};

class BtifBapBroadcaster{
 public:
  enum {
    kFlagBIGPending = 0x1,
    kFlagISOPending = 0x2,
    kFlagISOError = 0x4,
    KFlagISOSetup = 0x8,
  };

  BtifBapBroadcaster(int adv_handle, int big_handle)
  :adv_handle_(adv_handle),
   big_handle_(big_handle),
   state_machine_(*this),
   flags_(0),
   big_state_(BIG_TERMINATED){}

  ~BtifBapBroadcaster();

  bt_status_t Init();
  void Cleanup();

  bool CanBeDeleted() {return (
                             (state_machine_.StateId() == BtifBapBroadcastStateMachine::kStateIdle) &&
                             (state_machine_.PreviousStateId() != BtifBapBroadcastStateMachine::kStateInvalid)); };

  int AdvHandle() const { return adv_handle_; }
  int BIGHandle() const { return big_handle_; }
  void SetBIGHandle(int handle) { big_handle_ = handle; }
  void SetAdvHandle(int handle) { adv_handle_ = handle; }
  BtifBapBroadcastStateMachine& StateMachine() { return state_machine_; }
  const BtifBapBroadcastStateMachine& StateMachine() const { return state_machine_; }
  bool CheckFlags(uint8_t bitflags_mask) const {
    return ((flags_ & bitflags_mask) != 0);
  }

  void ClearFlag(uint8_t bitflags_mask) { flags_ &= ~bitflags_mask;}

  void ClearAllFlags() { flags_ = 0; }
  /**
   * Set only the flags as specified by the bitflags mask.
   *
   * @param bitflags_mask the bitflags to set
   */
  void SetFlags(uint8_t bitflags_mask) { flags_ |= bitflags_mask; }

  void SetNumBises(uint8_t num_bises) {num_bises_ = num_bises; }

  uint8_t NumBises() const { return num_bises_; }

  void SetBIGState(btif_big_state_t state) { big_state_ = state; }

  btif_big_state_t BIGState() const { return big_state_; }

  /*void SetMandatoryCodecPreferred(bool preferred) {
    mandatory_codec_preferred_ = preferred;
  }
  bool IsMandatoryCodecPreferred() const { return mandatory_codec_preferred_; }*/

  std::vector<uint16_t> GetBISHandles() const { return bis_handle_list_;}
  void SetBISHandles(std::vector<uint16_t> handle_list) { bis_handle_list_ = handle_list; }

 private:
  int adv_handle_;
  int big_handle_;  // SEP type of peer device
  uint8_t num_bises_;
  BtifBapBroadcastStateMachine state_machine_;
  uint8_t flags_;
  btif_big_state_t big_state_;
  //bool mandatory_codec_preferred_ = false;
  std::vector<uint16_t> bis_handle_list_;
};
//BtifBapBroadcaster::BtifBapBroadcaster(int adv_handle, int big_handle)
//  :adv_handle_(adv_handle), big_handle_(big_handle){}

class BtifBapBroadcastSource{
 public:
  // The PeerId is used as AppId for BTA_AvRegister() purpose
  static constexpr uint8_t kPeerIdMin = 0;
  static constexpr uint8_t kPeerIdMax = BTIF_BAP_BA_NUM_BMS;
  public:
   enum {
     kFlagIdle = 0x1,
     kFlagConfigured = 0x2,
     kFlagStreaming = 0x4,
     KFlagDisabling = 0x8,
   };
  BtifBapBroadcastSource()
      : callbacks_(nullptr),
        enabled_(false),
        offload_enabled_(false),
        max_broadcast_(kDefaultMaxBroadcastSupported) {}
  ~BtifBapBroadcastSource();

  bt_status_t Init(
      btbap_broadcast_callbacks_t* callbacks, int max_broadcast,
      btav_a2dp_codec_config_t codec_config,int mode);

  bt_status_t EnableBroadcast(btav_a2dp_codec_config_t codec_config);
  bt_status_t DisableBroadcast(int adv_handle);
  void Cleanup();
  void CleanupIdleBms();
  btbap_broadcast_callbacks_t* Callbacks() { return callbacks_; }
  void SetEnabled(bool state) { enabled_ = state; }
  bool Enabled() const { return enabled_; }
  bool BapBroadcastOffloadEnabled() const { return offload_enabled_; }

  BtifBapBroadcaster* FindBmsFromAdvHandle(uint8_t adv_handle);
//  BtifBapBroadcaster* FindEmptyBms();
  BtifBapBroadcaster* FindBmsFromBIGHandle(uint8_t big_handle);
  BtifBapBroadcaster* FindStreamingBms();
  BtifBapBroadcaster* FindConfiguredBms();
  BtifBapBroadcaster* CreateBMS(int adv_handle);
  //void SetDefaultConfig(btav_a2dp_codec_config_t config) { default_config_ = config; }
  btav_a2dp_codec_config_t GetDefaultConfig () const { return default_config_; }
  //void SetCurrentConfig (btav_a2dp_codec_config_t config) { current_config_ = config; }
  btav_a2dp_codec_config_t GetCurrentConfig() const { return current_config_; }
  bt_status_t SetEncryption(int length);
  bt_status_t SetBroadcastActive(bool setup, uint8_t adv_id);
  bool BroadcastActive() const { return ((broadcast_state_ == kFlagConfigured)
                                           ||(broadcast_state_ == kFlagStreaming)); }
  void SetBroadcastState(uint8_t flag) { broadcast_state_ = flag; }
  uint8_t GetBroadcastState() { return broadcast_state_; }
  bt_status_t SetUserConfig(uint8_t adv_hdl, btav_a2dp_codec_config_t codec_config);

  const std::map<uint8_t/*adv_handle*/, BtifBapBroadcaster*>& Bms() const { return bms_; }

 private:
  void CleanupAllBms();

  btbap_broadcast_callbacks_t* callbacks_;
  bool enabled_;
  bool offload_enabled_;
  int max_broadcast_;
  std::map<uint8_t, BtifBapBroadcaster*> bms_;
  btav_a2dp_codec_config_t default_config_;
  btav_a2dp_codec_config_t current_config_;
  uint8_t broadcast_state_;
};

static BtifBapBroadcastSource btif_bap_bms;

bt_status_t BtifBapBroadcaster::Init() {
  state_machine_.Start();
  return BT_STATUS_SUCCESS;
}

void BtifBapBroadcaster::Cleanup() {
  state_machine_.Quit();
}

void BtifBapBroadcastStateMachine::StateIdle::OnEnter() {
  BTIF_TRACE_IMP("%s", __PRETTY_FUNCTION__);

  bms_.ClearAllFlags();
  bms_.SetAdvHandle(-1);
  bms_.SetBIGHandle(-1);
  bms_.SetBIGState(BIG_TERMINATED);
  btif_bap_bms.SetBroadcastState(BtifBapBroadcastSource::kFlagIdle);
  btif_bap_bms.SetEnabled(false);
  btif_bap_bms.CleanupIdleBms();
}

void BtifBapBroadcastStateMachine::StateIdle::OnExit() {
  BTIF_TRACE_IMP("%s", __PRETTY_FUNCTION__);
}

bool BtifBapBroadcastStateMachine::StateIdle::ProcessEvent(uint32_t event, void* p_data) {
  BTIF_TRACE_IMP("[BapBroadcast]:%s: event = %s",__func__,
                   dump_bap_ba_sm_event_name((btif_bap_broadcast_sm_event_t)event));
  switch (event) {
    case BTIF_BAP_BROADCAST_SET_ACTIVE_REQ_EVT:
     bms_.StateMachine().TransitionTo(BtifBapBroadcastStateMachine::kStateConfigured);
     break;
    case BTIF_BAP_BROADCAST_SOURCE_CONFIG_REQ_EVT:
      //copy config
      break;
    default:
      BTIF_TRACE_WARNING("%s: unhandled event=%s", __func__,
                             dump_bap_ba_sm_event_name((btif_bap_broadcast_sm_event_t)event));
      return false;
  }
 return true;
}

void BtifBapBroadcastStateMachine::StateConfigured::OnEnter() {
  BTIF_TRACE_IMP("%s", __PRETTY_FUNCTION__);

  // Inform the application that we are entering connecting state
  btif_bap_bms.SetBroadcastState(BtifBapBroadcastSource::kFlagConfigured);
  btif_bap_bms.SetEnabled(true);
  if (bms_.BIGState() == BIG_TERMINATED) {
#if AHIM_ENABLED
    btif_ahim_init_hal(get_worker_thread(), BROADCAST);
    btif_ahim_start_session();
#else
    btif_a2dp_source_restart_session(RawAddress::kEmpty, mBapBADevice);
#endif
    btif_bap_ba_signal_session_ready();
    btif_bap_ba_update_big_params();
  } else if (bms_.BIGState() == BIG_DISABLING) {
    ProcessEvent(BTIF_BAP_BROADCAST_DISABLE_EVT, nullptr);
    return;
  }
  bms_.SetBIGState(BIG_TERMINATED);
  bms_.ClearAllFlags();
  btif_report_broadcast_state(bms_.AdvHandle(), BTBAP_BROADCAST_STATE_CONFIGURED);
}

void BtifBapBroadcastStateMachine::StateConfigured::OnExit() {
  BTIF_TRACE_IMP("%s", __PRETTY_FUNCTION__);
}

bool BtifBapBroadcastStateMachine::StateConfigured::ProcessEvent(uint32_t event,
                                                    void* p_data) {
 BTIF_TRACE_IMP("[BapBroadcast]:%s: event = %s",__func__,
                            dump_bap_ba_sm_event_name((btif_bap_broadcast_sm_event_t)event));
 switch (event) {

   case BTIF_BAP_BROADCAST_DISABLE_EVT:
     BTIF_TRACE_DEBUG("[BapBroadcast]:BTIF_BAP_BROADCAST_DISABLE_EVT, moving to idle");
     if (bms_.CheckFlags(BtifBapBroadcaster::kFlagBIGPending) ||
       bms_.CheckFlags(BtifBapBroadcaster::kFlagISOPending)) {
#if AHIM_ENABLED
       btif_ahim_ack_stream_started(A2DP_CTRL_ACK_DISCONNECT_IN_PROGRESS, BROADCAST);
       btif_ahim_reset_pending_command(BROADCAST);
#else
       bluetooth::audio::a2dp::ack_stream_started(A2DP_CTRL_ACK_DISCONNECT_IN_PROGRESS);
       bluetooth::audio::a2dp::reset_pending_command();
#endif
     }
     bms_.SetBIGState(BIG_DISABLING);
     bms_.ClearFlag(BtifBapBroadcaster::kFlagISOPending);
     btif_report_broadcast_state(bms_.AdvHandle(), BTBAP_BROADCAST_STATE_IDLE);
     bms_.StateMachine().TransitionTo(BtifBapBroadcastStateMachine::kStateIdle);
     break;
   case BTIF_BAP_BROADCAST_SET_ACTIVE_REQ_EVT:
     BTIF_TRACE_DEBUG("Not handled in configured state");
     break;
   case BTIF_BAP_BROADCAST_START_STREAM_REQ_EVT:
     if (bms_.CheckFlags(BtifBapBroadcaster::kFlagBIGPending) ||
       bms_.CheckFlags(BtifBapBroadcaster::kFlagISOPending)) {
       BTIF_TRACE_DEBUG("[BapBroadcast]%s: BIG/ISO setup pending, dup req",__func__);
#if AHIM_ENABLED
       btif_ahim_ack_stream_started(A2DP_CTRL_ACK_PENDING, BROADCAST);
#else
       btif_ahim_ack_stream_started(A2DP_CTRL_ACK_PENDING, BROADCAST);
#endif
       break;
     }
     bms_.SetFlags(BtifBapBroadcaster::kFlagBIGPending);
     bms_.SetNumBises(btif_bap_broadcast_get_ch_count());
     bms_.SetBIGState(BIG_CREATING);
     btif_bap_ba_create_big(bms_.AdvHandle());
     break;
   case BTIF_BAP_BROADCAST_SETUP_ISO_DATAPATH_EVT:
     {
       if (bms_.CheckFlags(BtifBapBroadcaster::kFlagBIGPending))
         bms_.ClearFlag(BtifBapBroadcaster::kFlagBIGPending);
       bms_.SetFlags(BtifBapBroadcaster::kFlagISOPending);
       total_bises = bms_.NumBises();
       current_iso_index = 0;
       current_handle = bms_.BIGHandle();
       btif_bap_ba_setup_iso_datapath(current_handle);
     }
     break;
   case BTIF_BAP_BROADCAST_REMOVE_ISO_DATAPATH_EVT:
     total_bises = bms_.NumBises();
     current_iso_index = 0;
     current_handle = bms_.BIGHandle();
     btif_bap_ba_remove_iso_datapath(current_handle);
     break;
   case BTIF_BAP_BROADCAST_BISES_SETUP_EVT:
     {
       char *p_p = (char *) p_data;
       p_p++;
       uint8_t status = *p_p;
       if (status != BT_STATUS_SUCCESS &&
         bms_.CheckFlags(BtifBapBroadcaster::kFlagISOPending)) {
         BTIF_TRACE_ERROR("[BapBroadcast]%s: setup iso failed",__func__);
         bms_.ClearAllFlags();
         bms_.SetFlags(BtifBapBroadcaster::kFlagISOError);
#if AHIM_ENABLED
         btif_ahim_ack_stream_started(A2DP_CTRL_ACK_DISCONNECT_IN_PROGRESS, BROADCAST);
         btif_ahim_reset_pending_command(BROADCAST);
#else
         bluetooth::audio::a2dp::ack_stream_started(A2DP_CTRL_ACK_DISCONNECT_IN_PROGRESS);
         bluetooth::audio::a2dp::reset_pending_command();
#endif

         btif_bap_ba_terminate_big(bms_.AdvHandle(), bms_.BIGHandle());
         break;
       }
       bms_.ClearFlag(BtifBapBroadcaster::kFlagISOPending);
       bms_.SetFlags(BtifBapBroadcaster::KFlagISOSetup);
#if AHIM_ENABLED
       btif_ahim_ack_stream_started(A2DP_CTRL_ACK_SUCCESS, BROADCAST);
       btif_ahim_reset_pending_command(BROADCAST);
#else
       bluetooth::audio::a2dp::ack_stream_started(A2DP_CTRL_ACK_SUCCESS);
       bluetooth::audio::a2dp::reset_pending_command();
#endif
       btif_report_setup_big(1, bms_.AdvHandle(), bms_.BIGHandle(), bms_.NumBises());
       btif_report_broadcast_state(bms_.AdvHandle(), BTBAP_BROADCAST_STATE_STREAMING);
       bms_.StateMachine().TransitionTo(BtifBapBroadcastStateMachine::kStateStreaming);
     }
     break;
   case BTIF_BAP_BROADCAST_BISES_REMOVE_EVT:
#if AHIM_ENABLED
     btif_ahim_ack_stream_started(A2DP_CTRL_ACK_SUCCESS, BROADCAST);
     btif_ahim_reset_pending_command(BROADCAST);
#else
     bluetooth::audio::a2dp::ack_stream_started(A2DP_CTRL_ACK_SUCCESS);
     bluetooth::audio::a2dp::reset_pending_command();
#endif
     break;
   case BTIF_BAP_BROADCAST_BIG_SETUP_EVT:
     break;
   case BTIF_BAP_BROADCAST_BIG_REMOVED_EVT:
     btif_report_setup_big(0, bms_.AdvHandle(), -1, 0);
     if (bms_.CheckFlags(BtifBapBroadcaster::kFlagISOError)) {
       bms_.StateMachine().TransitionTo(BtifBapBroadcastStateMachine::kStateIdle);
       btif_report_broadcast_state(bms_.AdvHandle(),BTBAP_BROADCAST_STATE_IDLE);
     }
     break;
     case BTIF_BAP_BROADCAST_SOURCE_CONFIG_REQ_EVT:
       btif_bap_broadcast_update_source_codec(p_data);
       if (restart_session) {
#if AHIM_ENABLED
         btif_ahim_end_session();
         btif_ahim_init_hal(get_worker_thread(), BROADCAST);
         btif_ahim_start_session();
#else
         btif_a2dp_source_restart_session(RawAddress::kEmpty, mBapBADevice);
#endif
         btif_report_audio_config(bms_.AdvHandle(), current_config);
       }
       break;
     case BTIF_BAP_BROADCAST_SUSPEND_STREAM_REQ_EVT:
#if AHIM_ENABLED
       btif_ahim_ack_stream_suspended(A2DP_CTRL_ACK_SUCCESS, BROADCAST);
       btif_ahim_reset_pending_command(BROADCAST);
#else
       bluetooth::audio::a2dp::ack_stream_suspended(A2DP_CTRL_ACK_SUCCESS);
       bluetooth::audio::a2dp::reset_pending_command();
#endif
       BTIF_TRACE_WARNING("%s: SUSPEND_STEAM_REQ unhandled in Configured state", __func__);
       break;
   default:
     BTIF_TRACE_WARNING("%s: unhandled event=%s", __func__,
                              dump_bap_ba_sm_event_name((btif_bap_broadcast_sm_event_t)event));
     return false;
 }
 return true;

}

void BtifBapBroadcastStateMachine::StateStreaming::OnEnter() {
  BTIF_TRACE_IMP("%s", __PRETTY_FUNCTION__);
  btif_bap_bms.SetBroadcastState(BtifBapBroadcastSource::kFlagStreaming);
  btif_report_broadcast_audio_state(bms_.AdvHandle(), BTBAP_BROADCAST__AUDIO_STATE_STARTED);
}

void BtifBapBroadcastStateMachine::StateStreaming::OnExit() {
  BTIF_TRACE_IMP("%s", __PRETTY_FUNCTION__);
}

bool BtifBapBroadcastStateMachine::StateStreaming::ProcessEvent(uint32_t event,
                                                   void* p_data) {
  BTIF_TRACE_IMP("[BapBroadcast]:%s: event = %s",__func__,
                            dump_bap_ba_sm_event_name((btif_bap_broadcast_sm_event_t)event));
  switch (event) {
    case BTIF_BAP_BROADCAST_DISABLE_EVT:
      if (bms_.BIGState() == BIG_CREATED) {
        bms_.SetBIGState(BIG_DISABLING);
        btif_bap_bms.SetBroadcastState(BtifBapBroadcastSource::KFlagDisabling);
        if (bms_.CheckFlags(BtifBapBroadcaster::KFlagISOSetup)) {
          btif_bap_ba_terminate_big(bms_.AdvHandle(), bms_.BIGHandle());
        }
      } else {
        bms_.SetBIGState(BIG_DISABLING);
        BTIF_TRACE_DEBUG("[BapBroadcast]: BIG Terminate under process");
      }
      break;
    case BTIF_BAP_BROADCAST_SUSPEND_STREAM_REQ_EVT:
      if (bms_.BIGState() != BIG_CREATED) {
        BTIF_TRACE_WARNING("[BapBroadcast]:%s: BIG is getting terminated already",__func__);
#if AHIM_ENABLED
        btif_ahim_ack_stream_suspended(A2DP_CTRL_ACK_SUCCESS, BROADCAST);
        btif_ahim_reset_pending_command(BROADCAST);
#else
        bluetooth::audio::a2dp::ack_stream_suspended(A2DP_CTRL_ACK_SUCCESS);
        bluetooth::audio::a2dp::reset_pending_command();
#endif
        break;
      }
      bms_.SetFlags(BtifBapBroadcaster::kFlagISOPending);
      total_bises = bms_.NumBises();
      current_iso_index = 0;
      current_handle = bms_.BIGHandle();
      btif_bap_ba_remove_iso_datapath(current_handle);

      break;
    case BTIF_BAP_BROADCAST_SETUP_ISO_DATAPATH_EVT:
      {
        char *p_p = (char *)p_data;
        if (*p_p) {
          BTIF_TRACE_WARNING("[BapBroadcast]:%s: We shouldn't be in streaming state if ISO datapath is not setup yet",__func__);
        } else {
          if (bms_.CheckFlags(BtifBapBroadcaster::KFlagISOSetup)) {
            BTIF_TRACE_WARNING("[BapBroadcast] We shouldn't be here, ISO Datapath is removed first before BIG");
            btif_bap_ba_remove_iso_datapath(bms_.BIGHandle());
          } else {
            BTIF_TRACE_WARNING("[BapBroadcast]:%s:IsoDatapah is already removed",__func__);
            bms_.StateMachine().TransitionTo(BtifBapBroadcastStateMachine::kStateConfigured);
          }
        }
      }
      break;
    case BTIF_BAP_BROADCAST_REMOVE_ISO_DATAPATH_EVT:
      btif_bap_ba_terminate_big(bms_.AdvHandle(), bms_.BIGHandle());
      break;
    case BTIF_BAP_BROADCAST_BISES_REMOVE_EVT:
      bms_.ClearFlag(BtifBapBroadcaster::kFlagISOPending);
      if (bms_.BIGState() == BIG_CREATED)
        bms_.SetBIGState(BIG_TERMINATING);
      btif_bap_ba_terminate_big(bms_.AdvHandle(), bms_.BIGHandle());
      break;
    case BTIF_BAP_BROADCAST_BIG_REMOVED_EVT:
      if (bms_.BIGState() == BIG_DISABLING) {
        btif_report_broadcast_state(bms_.AdvHandle(), BTBAP_BROADCAST_STATE_IDLE);
        bms_.StateMachine().TransitionTo(BtifBapBroadcastStateMachine::kStateIdle);
      } else if (bms_.BIGState() == BIG_TERMINATING) {
        bms_.StateMachine().TransitionTo(BtifBapBroadcastStateMachine::kStateConfigured);
      } else if (bms_.BIGState() == BIG_RECONFIG) {
#if AHIM_ENABLED
        btif_ahim_end_session();
        btif_ahim_init_hal(get_worker_thread(), BROADCAST);
        btif_ahim_start_session();
#else
        btif_a2dp_source_restart_session(RawAddress::kEmpty, mBapBADevice);
#endif
        btif_report_audio_config(bms_.AdvHandle(), current_config);
        bms_.StateMachine().TransitionTo(BtifBapBroadcastStateMachine::kStateConfigured);
        break;
      }
#if AHIM_ENABLED
      btif_ahim_ack_stream_suspended(A2DP_CTRL_ACK_SUCCESS, BROADCAST);
      btif_ahim_reset_pending_command(BROADCAST);
#else
      bluetooth::audio::a2dp::ack_stream_suspended(A2DP_CTRL_ACK_SUCCESS);
      bluetooth::audio::a2dp::reset_pending_command();
#endif

      break;
    case BTIF_BAP_BROADCAST_SOURCE_CONFIG_REQ_EVT:
      btif_bap_broadcast_update_source_codec(p_data);
      if (restart_session) {
        bms_.SetBIGState(BIG_RECONFIG);
        btif_bap_ba_terminate_big(bms_.AdvHandle(), bms_.BIGHandle());
      }
      break;
    default:
      BTIF_TRACE_WARNING("%s: unhandled event=%s", __func__,
                              dump_bap_ba_sm_event_name((btif_bap_broadcast_sm_event_t)event));
      return false;
  }
  return true;
}

static btif_ahim_client_callbacks_t sAhimBroadcastCallbacks = {
  2, // mode
  btif_broadcast_process_hidl_event,
  btif_bap_broadcast_get_sample_rate,
  btif_bap_broadcast_get_ch_mode,
  btif_bap_broadcast_get_bitrate,
  btif_bap_broadcast_get_mtu,
  btif_bap_broadcast_get_framelength,
  btif_bap_broadcast_get_ch_count,
  btif_bap_broadcast_is_simulcast_enabled,
  nullptr,
  nullptr,
  nullptr
};

bt_status_t BtifBapBroadcastSource::Init(btbap_broadcast_callbacks_t* callbacks,
                              int max_broadcast,
                              btav_a2dp_codec_config_t codec_config,int mode) {
  BTIF_TRACE_DEBUG("[BapBroadcast]:%s", __func__);
  char value[PROPERTY_VALUE_MAX] = {'\0'};
  if (mode == 1) offload_enabled_ = true;
  callbacks_ = callbacks;
  default_config_ = codec_config;
  memset(encryption_key.data(), 0, OCTET16_LEN);
  init_local_capabilities();
  osi_property_get("persist.vendor.btstack.partial_simulcast",value,"false");
  if (strcmp(value, "true") == 0) {
      BTIF_TRACE_IMP("[BapBroadcast]%s:Partial simulcast enabled",__func__);
      mBisMultiplier = 2;
  } else  {
      mBisMultiplier = 1;
  }
  osi_property_get("persist.vendor.btstack.transport_latency",value,"0");
  mBigParams.max_transport_latency = atoi(value);
  osi_property_get("persist.vendor.btstack.bis_rtn",value,"2");
  mBigParams.rtn = atoi(value);
  BTIF_TRACE_IMP("%s: transport_latency: %d, rtn: %d",
                  __func__, mBigParams.max_transport_latency, mBigParams.rtn);
  BTIF_TRACE_IMP("%s: Fetch broadcast encryption key", __func__);

  size_t length = OCTET16_LEN;
  bool ret = btif_config_get_bin("Adapter", "BAP_BA_ENC_KEY", encryption_key.data(), &length);

  if (!ret) {
    btif_bap_ba_generate_enc_key_local(OCTET16_LEN);
  } else {
    reverseCode(encryption_key.data());
    if (isUnencrypted(encryption_key.data())) {
      mEncryptionEnabled = false;
    }
    for (int i = 0; i < OCTET16_LEN; i++) {
      BTIF_TRACE_IMP("[bapbroadcast]%s: encryption_key[%d] = %d",__func__,i,encryption_key[i]);
    }
  }
#if AHIM_ENABLED
  reg_cb_with_ahim(BROADCAST, &sAhimBroadcastCallbacks);
#endif
  return BT_STATUS_SUCCESS;
}

bt_status_t BtifBapBroadcastSource::EnableBroadcast(btav_a2dp_codec_config_t codec_config) {
  BTIF_TRACE_DEBUG("[BapBroadcast]:%s", __func__);
  current_config_ = codec_config;
  btif_bap_ba_generate_broadcast_id();
  return BT_STATUS_SUCCESS;
}

bt_status_t BtifBapBroadcastSource::DisableBroadcast(int adv_handle) {
  BTIF_TRACE_DEBUG("[BapBroadcast]:%s", __func__);
  local_param[0] = adv_handle;
  do_in_bta_thread(
      FROM_HERE, base::Bind(&btif_bap_ba_handle_event,
                            BTIF_BAP_BROADCAST_DISABLE_EVT, local_param));
  return BT_STATUS_SUCCESS;
}

bt_status_t BtifBapBroadcastSource::SetEncryption(int length) {
  BTIF_TRACE_DEBUG("[BapBroadcast]:%s", __func__);
  local_param[0] = length;
  do_in_bta_thread(
    FROM_HERE, base::Bind(&btif_bap_ba_handle_event,
                          BTIF_BAP_BROADCAST_GENERATE_ENC_KEY_EVT, local_param));
  return BT_STATUS_SUCCESS;
}

bt_status_t BtifBapBroadcastSource::SetBroadcastActive(bool setup, uint8_t adv_id) {
  if (btif_a2dp_source_is_hal_v2_supported()) {
    std::unique_lock<std::mutex> guard(session_wait_);
    mSession_wait = false;
    if (setup) {
      do_in_bta_thread(
       FROM_HERE, base::Bind(&btif_bap_ba_handle_event,
                             BTIF_BAP_BROADCAST_SET_ACTIVE_REQ_EVT, (char *)&adv_id));
    } else {
     do_in_bta_thread(
      FROM_HERE, base::Bind(&btif_bap_ba_handle_event,
                            BTIF_BAP_BROADCAST_REMOVE_ACTIVE_REQ_EVT,(char *)&adv_id));
    }
    BTIF_TRACE_EVENT("%s: wating for signal",__func__);
    session_wait_cv_.wait_for(guard, std::chrono::milliseconds(1000),
                     []{return mSession_wait;});
    BTIF_TRACE_EVENT("%s: done with signal",__func__);
    return BT_STATUS_SUCCESS;
  }
  return BT_STATUS_SUCCESS;
}
void BtifBapBroadcastSource::Cleanup() {
  BTIF_TRACE_DEBUG("[BapBroadcast]:%s", __func__);
  //while(!bms_.empty()) {
  for (auto it = bms_.begin();it != bms_.end();){
    BtifBapBroadcaster *bms = it->second;
    auto prev_it = it++;
    bms->Cleanup();
    bms_.erase(prev_it);
    //delete bms;
  }
}

void BtifBapBroadcastSource::CleanupIdleBms() {
  BTIF_TRACE_DEBUG("[BapBroadcast]:%s", __func__);
  for (auto it = bms_.begin();it != bms_.end();){
    BtifBapBroadcaster *bms = it->second;
    auto prev_it = it++;
    if (bms->CanBeDeleted()) {
      BTIF_TRACE_DEBUG("[BapBroadcast]%s: Cleaning up idle bms", __func__);
      bms->Cleanup();
      bms_.erase(prev_it);
      //delete bms;
    }
    //delete bms;
  }
  BTIF_TRACE_DEBUG("[BapBroadcast]%s:Exit",__func__);
}

bt_status_t BtifBapBroadcastSource::SetUserConfig(uint8_t adv_handle,
                                           btav_a2dp_codec_config_t codec_config) {
  BTIF_TRACE_DEBUG("[BapBroadcast]:%s", __func__);
  config_req_handle = (int) adv_handle;
  do_in_bta_thread(
    FROM_HERE, base::Bind(&btif_bap_ba_handle_event,
                          BTIF_BAP_BROADCAST_SOURCE_CONFIG_REQ_EVT, (char *)&codec_config));
  return BT_STATUS_SUCCESS;
}
BtifBapBroadcaster * BtifBapBroadcastSource::CreateBMS(int adv_handle) {
  BtifBapBroadcaster *bms = new BtifBapBroadcaster(adv_handle, -1);
//  bms_.insert(bms);
  bms_.insert(std::make_pair(adv_handle, bms));
  bms->Init();
  return bms;
}

BtifBapBroadcaster * BtifBapBroadcastSource::FindBmsFromAdvHandle(uint8_t adv_handle) {
  BTIF_TRACE_DEBUG("[BapBroadcast]:%s: adv_handle = %d", __func__, adv_handle);
  for(auto it : bms_) {
    BtifBapBroadcaster *bms = it.second;
    if (bms->AdvHandle() == adv_handle)
      return bms;
  }
  return nullptr;
}

BtifBapBroadcaster * BtifBapBroadcastSource::FindBmsFromBIGHandle(uint8_t big_handle) {
  for(auto it : bms_) {
    BtifBapBroadcaster *bms = it.second;
    if (bms->BIGHandle() == big_handle)
      return bms;
  }
  return nullptr;
}

BtifBapBroadcaster * BtifBapBroadcastSource::FindStreamingBms() {
 for(auto it : bms_) {
   BtifBapBroadcaster *bms = it.second;
   if (bms->StateMachine().StateId() == BtifBapBroadcastStateMachine::kStateStreaming)
     return bms;
 }
 return nullptr;
}

BtifBapBroadcaster * BtifBapBroadcastSource::FindConfiguredBms() {
 for(auto it : bms_) {
   BtifBapBroadcaster *bms = it.second;
   if (bms->StateMachine().StateId() == BtifBapBroadcastStateMachine::kStateConfigured)
     return bms;
 }
 return nullptr;
}
BtifBapBroadcastSource::~BtifBapBroadcastSource(){}
/*****************************************************************************
 *  Local event handlers
 *****************************************************************************/
void print_config(btav_a2dp_codec_config_t config) {
  BTIF_TRACE_WARNING("[BapBroadcast]%d: Sampling rate = %d", __func__,config.sample_rate);
  BTIF_TRACE_WARNING("[BapBroadcast]%d: channel mode = %d", __func__, config.channel_mode);
  BTIF_TRACE_WARNING("[BapBroadcast]%d: codec_specific_1 = %d", __func__, config.codec_specific_1);
  BTIF_TRACE_WARNING("[BapBroadcast]%d: codec_specific_2 = %d", __func__, config.codec_specific_2);
}

static void btif_report_encyption_key() {
    do_in_jni_thread(FROM_HERE,
                     base::Bind(btif_bap_bms.Callbacks()->enc_key_cb,
      std::string(reinterpret_cast<const char*>(encryption_key.data()), OCTET16_LEN)));
}

static void btif_report_broadcast_state(int adv_id,
                                btbap_broadcast_state_t state) {
  if (btif_bap_bms.Enabled()) {
    do_in_jni_thread(FROM_HERE,
                     base::Bind(btif_bap_bms.Callbacks()->broadcast_state_cb,
                               adv_id, state));
  }
}

static void btif_report_broadcast_audio_state(int adv_id,
                                    btbap_broadcast_audio_state_t state) {
  if (btif_bap_bms.Enabled()) {
    do_in_jni_thread(FROM_HERE,
                     base::Bind(btif_bap_bms.Callbacks()->audio_state_cb,
                               adv_id, state));
  }
}

static void btif_report_audio_config(int adv_id,
                                 btav_a2dp_codec_config_t codec_config) {
  if (btif_bap_bms.Enabled()) {
    do_in_jni_thread(FROM_HERE,
                     base::Bind(btif_bap_bms.Callbacks()->audio_config_cb,
                               adv_id, codec_config, broadcast_codecs_capabilities));
  }
}

static void btif_report_setup_big(int setup, int adv_id, int big_handle, int num_bises) {

  BtifBapBroadcaster *bms = btif_bap_bms.FindBmsFromAdvHandle(adv_id);
  if (bms == nullptr) return;
  if (btif_bap_bms.Enabled()) {
    do_in_jni_thread(FROM_HERE,
                     base::Bind(btif_bap_bms.Callbacks()->create_big_cb, setup,
                               adv_id, big_handle, num_bises, bms->GetBISHandles()));
  }

}

static void btif_report_broadcast_id() {
  do_in_jni_thread(FROM_HERE,
                   base::Bind(btif_bap_bms.Callbacks()->broadcast_id_cb, mBroadcastID));
}

static void btif_bap_ba_handle_event(uint32_t event, char* p_param) {
    int big_handle, adv_id;
    big_handle = adv_id = 0;
    BtifBapBroadcaster *broadcaster;
    BTIF_TRACE_DEBUG("[BapBroadcast]:%s: event %s",
           __func__, dump_bap_ba_sm_event_name((btif_bap_broadcast_sm_event_t)event));
    switch(event) {
      case BTIF_BAP_BROADCAST_DISABLE_EVT:
        adv_id = (int)*p_param;
        broadcaster = btif_bap_bms.FindBmsFromAdvHandle(adv_id);
        if (broadcaster == nullptr) {
          BTIF_TRACE_ERROR("[BapBroadcast]:%s:invalid index, Broadcast is already disabled",__func__);
          return;
        }
        break;
      case BTIF_BAP_BROADCAST_START_STREAM_REQ_EVT:
        broadcaster = btif_bap_bms.FindConfiguredBms();
        if (broadcaster == nullptr) {
          BTIF_TRACE_ERROR("[BapBroadcast]:%s:cannot find empty index",__func__);
          return;
        }
        break;
      case BTIF_BAP_BROADCAST_STOP_STREAM_REQ_EVT:
      case BTIF_BAP_BROADCAST_SUSPEND_STREAM_REQ_EVT:
        broadcaster = btif_bap_bms.FindStreamingBms();
        if (broadcaster == nullptr) {
          BTIF_TRACE_ERROR("[BapBroadcast]:%s:cannot find empty index",__func__);
          return;
        }
        break;
      case BTIF_BAP_BROADCAST_SOURCE_CONFIG_REQ_EVT:
        broadcaster = btif_bap_bms.FindBmsFromAdvHandle(config_req_handle);
        if (broadcaster == nullptr) {
          BTIF_TRACE_ERROR("[BapBroadcast]:%s:cannot find empty index",__func__);
          return;
        }
        break;
      case BTIF_BAP_BROADCAST_CLEANUP_REQ_EVT:
        broadcaster = btif_bap_bms.FindStreamingBms(); //TODO:add proper check
        if (broadcaster == nullptr) {
          BTIF_TRACE_ERROR("[BapBroadcast]:%s:cannot find empty index",__func__);
          return;
        }
        break;
      case BTIF_BAP_BROADCAST_SET_ACTIVE_REQ_EVT:
        {
          char *p_p = p_param;
          int adv_handle = (int)*p_p;
          BTIF_TRACE_ERROR("[BapBroadcast]:%s:adv_handle %d",__func__,adv_handle);
          broadcaster = btif_bap_bms.CreateBMS((int)adv_handle);
          if (broadcaster == nullptr) {
            BTIF_TRACE_ERROR("[BapBroadcast]:%s: cannot find empty index",__func__);
            return;
          }
          broadcaster->SetAdvHandle(adv_handle);
          BTIF_TRACE_ERROR("[BapBroadcast]:%s:adv_id = %d, big_handle = %d",__func__, adv_handle);
        }
        break;
      case BTIF_BAP_BROADCAST_REMOVE_ACTIVE_REQ_EVT:
        BTIF_TRACE_DEBUG("[BapBroadcast]:%s:End session", __func__);
#if AHIM_ENABLED
        btif_ahim_end_session();
#else
        bluetooth::audio::a2dp::end_session();
#endif
        btif_bap_ba_signal_session_ready();
        return;
      case BTIF_BAP_BROADCAST_SETUP_ISO_DATAPATH_EVT:
        {
          char *p_p = p_param;
          int adv_handle = (int)*p_p;
          BTIF_TRACE_DEBUG("[BapBroadcast]:%s:adv_handle = %d",__func__,adv_handle);
          broadcaster = btif_bap_bms.FindBmsFromAdvHandle(adv_handle);
          if (broadcaster == nullptr) {
            BTIF_TRACE_ERROR("[BapBroadcast]:%s: cannot find empty index",__func__);
            return;
          }
        }
        break;
      case BTIF_BAP_BROADCAST_REMOVE_ISO_DATAPATH_EVT:
        {
          char *p_p = p_param;
          adv_id = *p_p++;
          big_handle = *p_p;
          broadcaster = btif_bap_bms.FindBmsFromBIGHandle(big_handle);
          if (broadcaster == nullptr) {
            BTIF_TRACE_ERROR("[BapBroadcast]:%s: cannot find empty index",__func__);
            return;
          }
        }
        break;
      case BTIF_BAP_BROADCAST_GENERATE_ENC_KEY_EVT:
        enc_keylength = (uint8_t)(*p_param);
        notify_key_generated = true;
        btif_bap_ba_generate_enc_key_local(enc_keylength);
        return;
      case BTIF_BAP_BROADCAST_BISES_SETUP_EVT:
      case BTIF_BAP_BROADCAST_BISES_REMOVE_EVT:
        big_handle = *p_param;
        broadcaster = btif_bap_bms.FindBmsFromBIGHandle(big_handle);
        if (broadcaster == nullptr) {
          BTIF_TRACE_ERROR("[BapBroadcast]:%s: cannot find empty index",__func__);
          return;
        }
        break;
      case BTIF_BAP_BROADCAST_BIG_REMOVED_EVT:
        adv_id = (int)*p_param;
        btif_report_setup_big(0, adv_id,-1, 0);
        broadcaster = btif_bap_bms.FindBmsFromAdvHandle(adv_id);
        if (broadcaster == nullptr) {
          BTIF_TRACE_ERROR("[BapBroadcast]:%s: cannot find empty index",__func__);
          return;
        }
        break;
      case BTIF_BAP_BROADCAST_PROCESS_HIDL_REQ_EVT:
        btif_bap_process_request((tA2DP_CTRL_CMD ) *p_param);
        return;
      case BTIF_BAP_BROADCAST_SETUP_NEXT_BIS_EVENT:
        {
          char *p = p_param;
          uint8_t status = *p++;
          uint16_t bis_handle = *p++;
          bis_handle = (bis_handle | (*p <<8));
          btif_bap_ba_process_iso_setup(status, bis_handle);
        return;
        }
      default:
        BTIF_TRACE_ERROR("[BapBroadcast]:%s: invalid event = %d",__func__, event);
        return;
    }
    if (broadcaster == nullptr) {
      BTIF_TRACE_ERROR("[BapBroadcast]:%s:Invalid broadcaster",__func__);
    }
    broadcaster->StateMachine().ProcessEvent(event, (void*)p_param);
}

static void btif_bap_process_request(tA2DP_CTRL_CMD cmd) {
  BTIF_TRACE_DEBUG("[BapBroadcast]:%s",__func__);
  tA2DP_CTRL_ACK status = A2DP_CTRL_ACK_FAILURE;
  //BtifBapBroadcaster *broadcaster;
  uint32_t event = 0;
#if AHIM_ENABLED
  btif_ahim_update_pending_command(cmd, BROADCAST);
#else
  bluetooth::audio::a2dp::update_pending_command(cmd);
#endif

  switch(cmd) {
    case A2DP_CTRL_CMD_START:
      if (!bluetooth::headset::btif_hf_is_call_vr_idle()) {
        status = A2DP_CTRL_ACK_INCALL_FAILURE;
        break;
      }
      if (btif_bap_bms.FindStreamingBms() != nullptr) {
        BTIF_TRACE_DEBUG("%s: Broadcast already streaming, crash recover(?)",__func__);
        status = A2DP_CTRL_ACK_SUCCESS;
        break;
      }
      if (btif_bap_bms.FindConfiguredBms() == nullptr) {
        BTIF_TRACE_DEBUG("%s: Broadcast is disabled",__func__);
        status = A2DP_CTRL_ACK_DISCONNECT_IN_PROGRESS;
        break;
      }
      btif_bap_ba_dispatch_sm_event(BTIF_BAP_BROADCAST_START_STREAM_REQ_EVT, NULL, 0);
      event = BTIF_BAP_BROADCAST_START_STREAM_REQ_EVT;
      //broadcaster = btif_bap_bms.FindConfiguredBms();
      status = A2DP_CTRL_ACK_PENDING;
      break;
    case A2DP_CTRL_CMD_STOP:
      btif_bap_ba_dispatch_sm_event(BTIF_BAP_BROADCAST_STOP_STREAM_REQ_EVT, NULL, 0);
      //broadcaster = btif_bap_bms.FindStreamingBms();
      status = A2DP_CTRL_ACK_SUCCESS;
      break;
    case A2DP_CTRL_CMD_SUSPEND:
      if (btif_bap_bms.FindStreamingBms() != nullptr) {
        btif_bap_ba_dispatch_sm_event(BTIF_BAP_BROADCAST_SUSPEND_STREAM_REQ_EVT, NULL, 0);
        //broadcaster = btif_bap_bms.FindStreamingBms();
        status = A2DP_CTRL_ACK_PENDING;
      } else {
        status = A2DP_CTRL_ACK_SUCCESS;
      }
      break;
    default:
      APPL_TRACE_ERROR("UNSUPPORTED CMD (%d)", cmd);
      status = A2DP_CTRL_ACK_FAILURE;
      break;
  }
    // send the response now based on status
  switch (cmd) {
    case A2DP_CTRL_CMD_START:
#if AHIM_ENABLED
      btif_ahim_ack_stream_started(status, BROADCAST);
#else
      bluetooth::audio::a2dp::ack_stream_started(status);
#endif
      break;
    case A2DP_CTRL_CMD_SUSPEND:
    case A2DP_CTRL_CMD_STOP:
#if AHIM_ENABLED
      btif_ahim_ack_stream_suspended(status, BROADCAST);
#else
      bluetooth::audio::a2dp::ack_stream_suspended(status);
#endif
      break;
    default:
      break;
  }
  if (status != A2DP_CTRL_ACK_PENDING) {
#if AHIM_ENABLED
    btif_ahim_reset_pending_command(BROADCAST);
#else
    bluetooth::audio::a2dp::reset_pending_command();
#endif
  }
}

static bool btif_bap_is_broadcaster_valid(uint8_t big_handle) {
  BTIF_TRACE_DEBUG("[BapBroadcat]%s: handle = %d",__func__, big_handle);
  BtifBapBroadcaster *bms = btif_bap_bms.FindBmsFromBIGHandle(big_handle);
  if (bms == nullptr) return false;
  if (pending_cmd == setup_iso) {
    if (!bms->CheckFlags(BtifBapBroadcaster::kFlagISOPending) ||
      bms->StateMachine().StateId() != BtifBapBroadcastStateMachine::kStateConfigured) {
      BTIF_TRACE_WARNING("[BapBroadcast]:%s Broadcast disabled",__func__);
      return false;
    }
  } else {
    if (bms->BIGState() != BIG_CREATED) {
      BTIF_TRACE_WARNING("[BapBroadcast]:%s Broadcast disabled",__func__);
      return false;
    }
  }
  return true;
}

static void btif_bap_ba_process_iso_setup(uint8_t status, uint16_t bis_handle) {
  BTIF_TRACE_WARNING("[BapBroadcast]:%s",__func__);
  if (!btif_bap_is_broadcaster_valid(current_handle)) return;
  if (pending_cmd == setup_iso) {
    local_param[0] = current_handle;
    local_param[1] = status;
    if (!btif_bap_ba_setup_iso_datapath(current_handle)) {
       BTIF_TRACE_WARNING("[BapBroadcast]:%s: notify bis setup",__func__);
       pending_cmd = iso_unknown;
       btif_bap_ba_handle_event(BTIF_BAP_BROADCAST_BISES_SETUP_EVT, (char *)local_param);
     }
  } else if (pending_cmd == remove_iso) {
    if (!btif_bap_ba_remove_iso_datapath(current_handle)) {
      local_param[0] = current_handle;
      local_param[1] = status;
      pending_cmd = iso_unknown;
      BTIF_TRACE_WARNING("[BapBroadcast]:%s: notify bis removed",__func__);
      btif_bap_ba_handle_event(BTIF_BAP_BROADCAST_BISES_REMOVE_EVT, (char *)local_param);
    }
  }
}
static void btif_bap_ba_isodatapath_setup_cb(uint8_t status, uint16_t bis_handle) {
  BTIF_TRACE_WARNING("[BapBroadcast]:%s, status = %d for handle = %d",__func__, status, bis_handle);
  if (!btif_bap_is_broadcaster_valid(current_handle)) return;
  if (pending_cmd == setup_iso) {
    memset(local_param, 0, 3);
    local_param[0] = status;
    local_param[1] = bis_handle & 0x00FF;
    local_param[2] = (bis_handle & 0xFF00) >> 8;
    if (status == 0) {
      total_bises--;
      btif_bap_ba_handle_event(BTIF_BAP_BROADCAST_SETUP_NEXT_BIS_EVENT, (char *)local_param);
    } else {
      local_param[0] = current_handle;
      local_param[1] = status;
      btif_bap_ba_handle_event(BTIF_BAP_BROADCAST_BISES_SETUP_EVT, (char *)local_param);
    }
  } else if (pending_cmd == remove_iso) {
    memset(local_param, 0, 3);
    local_param[0] = status;
    local_param[1] = bis_handle & 0x00FF;
    local_param[2] = (bis_handle & 0xFF00) >> 8;
    btif_bap_ba_handle_event(BTIF_BAP_BROADCAST_SETUP_NEXT_BIS_EVENT, (char*)local_param);
  }
}

static bool btif_bap_ba_setup_iso_datapath(int big_handle) {
  BTIF_TRACE_WARNING("[BapBroadcast]:%s",__func__);
  BtifBapBroadcaster *bms = btif_bap_bms.FindBmsFromBIGHandle(big_handle);
  if (bms == nullptr) {
    BTIF_TRACE_WARNING("[BapBroadcast]:%s bms is null",__func__);
    return false;
  }
  if (!btif_bap_is_broadcaster_valid(big_handle)) return false;
  if (current_iso_index == bms->NumBises()) {
    BTIF_TRACE_WARNING("[BapBroadcast]:%s completed",__func__);
    return false;
  }
  pending_cmd = setup_iso;
  std::vector<uint16_t> BisHandles = bms->GetBISHandles();
  tBTM_BLE_SET_ISO_DATA_PATH_PARAM *p_param = new tBTM_BLE_SET_ISO_DATA_PATH_PARAM;
  p_param->conn_handle = BisHandles[current_iso_index++];
  p_param->data_path_dir = 0;
  p_param->data_path_id = PATH_ID;//6;
  p_param->codec_id[0] = 6;
  p_param->cont_delay[0] = 0;
  p_param->cont_delay[1] = 0;
  p_param->cont_delay[2] = 0;
  p_param->codec_config_length = 0;
  //param.codec_config = NULL;
  p_param->p_cb = (tBTM_BLE_SETUP_ISO_DATA_PATH_CMPL_CB*)&btif_bap_ba_isodatapath_setup_cb;

  BTIF_TRACE_WARNING("[BapBroadcast]:%s for handle = %d",__func__, p_param->conn_handle);
  do_in_bta_thread(FROM_HERE,base::Bind(base::IgnoreResult(&BTM_BleSetIsoDataPath), std::move(p_param)));
  return true;
}

static bool btif_bap_ba_remove_iso_datapath(int big_handle) {
  BTIF_TRACE_WARNING("[BapBroadcast]:%s",__func__);
  BtifBapBroadcaster *bms = btif_bap_bms.FindBmsFromBIGHandle(big_handle);
  if (bms == nullptr) {
    BTIF_TRACE_WARNING("[BapBroadcast]%s: broadcaster not found",__func__);
    return false;
  }
  if (current_iso_index == bms->NumBises()) {
    return false;
  }
  pending_cmd = remove_iso;
  std::vector<uint16_t> BisHandles = bms->GetBISHandles();
  uint16_t bis_handle = BisHandles[current_iso_index++];
  do_in_bta_thread(FROM_HERE, base::Bind(base::IgnoreResult(&BTM_BleRemoveIsoDataPath), bis_handle,
                          INPUT_DATAPATH,&btif_bap_ba_isodatapath_setup_cb));
   return true;
}

void btif_bap_ba_creat_big_cb(uint8_t adv_id, uint8_t status, uint8_t big_handle,
        uint32_t sync_delay, uint32_t transport_latency, uint8_t phy, uint8_t nse, uint8_t bn, uint8_t pto,
        uint8_t irc, uint16_t max_pdu, uint16_t iso_int, uint8_t num_bis, std::vector<uint16_t> conn_handle_list) {
  BTIF_TRACE_IMP("[BapBroadcast]%s: callback: status = %d, adv_id = %d",__func__, status, adv_id);
  if (status == BT_STATUS_SUCCESS) {
    BtifBapBroadcaster *bms = btif_bap_bms.FindBmsFromAdvHandle(adv_id);
    if (bms == nullptr) {
      BTIF_TRACE_ERROR("%s: broadcaster not found",__func__);
      return;
    }
    if (bms->StateMachine().StateId() != BtifBapBroadcastStateMachine::kStateConfigured ||
      bms->BIGState() != BIG_CREATING) {
      BTIF_TRACE_WARNING("[BapBroadcast]%s: Broadcast is disabling",__func__);
      return;
    }
    bms->SetBIGHandle(big_handle);
    BTIF_TRACE_DEBUG("[BapBroadcast]%s: callback: big_handle = %d",__func__, bms->BIGHandle());
    bms->SetNumBises(num_bis);
    BTIF_TRACE_DEBUG("[BapBroadcast]%s: callback: num_bis = %d",__func__, bms->NumBises());
    bms->SetBISHandles(conn_handle_list);
    bms->SetBIGState(BIG_CREATED);
    local_param[0] = adv_id;
    do_in_bta_thread(FROM_HERE,
                     base::Bind(&btif_bap_ba_handle_event,
                     BTIF_BAP_BROADCAST_SETUP_ISO_DATAPATH_EVT, local_param));
  } else {
    local_param[0] = adv_id;
    do_in_bta_thread(FROM_HERE,
                     base::Bind(&btif_bap_ba_handle_event,
                     BTIF_BAP_BROADCAST_DISABLE_EVT, local_param));
  }
}

static void btif_bap_ba_create_big(int adv_handle) {
  BTIF_TRACE_IMP("[BapBroadcast]:%s",__func__);
  //char ba_enc[PROPERTY_VALUE_MAX] = {0};
#if BIG_COMPILE
  BtifBapBroadcaster *bms = btif_bap_bms.FindBmsFromAdvHandle(adv_handle);
  if (bms == nullptr) {
    BTIF_TRACE_ERROR("%s: broadcaster not found",__func__);
    return;
  }
  CreateBIGParameters param;
  param.adv_handle = adv_handle;
  param.num_bis = bms->NumBises();
  param.sdu_int = mBigParams.sdu_int;
  param.max_sdu = mBigParams.max_sdu;
  param.max_transport_latency = btif_bap_get_transport_latency();
  param.rtn = mBigParams.rtn;
  param.phy = mBigParams.phy;
  param.packing = mBigParams.packing;;//0 : sequential, 1: interleaved
  param.framing = mBigParams.framing;
  //osi_property_get("persist.bluetooth.ba_encryption", ba_enc, "true");
  //if (!(strncmp(ba_enc,"true",4))) {
  if (mEncryptionEnabled) {
    //mEncryptionEnabled = true;
    param.encryption = 0x01;
  } else {
    mEncryptionEnabled = false;
    param.encryption = 0x00;
  }
  uint8_t code[16] = {0};
  if (mEncryptionEnabled) {
      memcpy(&code[0], encryption_key.data(),encryption_key.size());
  }
  for(int i =0; i < 16; i++) {
    param.broadcast_code.push_back(code[15-i]);
    BTIF_TRACE_VERBOSE("[BapBroadcast]%s: code[%d] = %x, bc[%d] = %d",__func__,i,code[i],i,param.broadcast_code[i]);
  }

  btif_gatt_get_interface()->advertiser->CreateBIG(adv_handle, param,
                      base::Bind(&btif_bap_ba_creat_big_cb));
#endif /* BIG_COMPILE */
}

#if BIG_COMPILE
static void btif_bap_ba_terminate_big_cb(uint8_t status, uint8_t adv_id,
                                        uint8_t big_handle, uint8_t reason) {
  BTIF_TRACE_IMP("[BapBroadcast]:%s",__func__);
  local_param[0] = adv_id;
  do_in_bta_thread(FROM_HERE,
                   base::Bind(&btif_bap_ba_handle_event,
                   BTIF_BAP_BROADCAST_BIG_REMOVED_EVT, /*(char*)&adv_id)*/local_param));

}
#endif /* BIG_COMPILE */

static void btif_bap_ba_terminate_big(int adv_handle, int big_handle) {
  BTIF_TRACE_IMP("[BapBroadcast]:%s",__func__);
#if BIG_COMPILE
  int reason = 0x16; //user terminated
  btif_gatt_get_interface()->advertiser->TerminateBIG(adv_handle, big_handle, reason,
                     base::Bind(&btif_bap_ba_terminate_big_cb));
#endif /* BIG_COMPILE */
}

void btif_bap_ba_dispatch_sm_event(btif_bap_broadcast_sm_event_t event, void* p_data, int len) {
  BTIF_TRACE_DEBUG("%s: event: %d, len: %d", __FUNCTION__, event, len);
  do_in_bta_thread(FROM_HERE,
                   base::Bind(&btif_bap_ba_handle_event, event, (char*)p_data));
  BTIF_TRACE_DEBUG("%s: event %d sent", __FUNCTION__, event);
}

void btif_broadcast_process_hidl_event(tA2DP_CTRL_CMD cmd) {
  btif_bap_ba_dispatch_sm_event(BTIF_BAP_BROADCAST_PROCESS_HIDL_REQ_EVT,
                                                (char*)&cmd, sizeof(cmd));
}
bool btif_bap_broadcast_is_active() {
  BTIF_TRACE_DEBUG("[BapBroadcast]:%s",__func__);
  if (btif_bap_bms.BroadcastActive()) {
    return true;
  }
  return false;
}

void btif_bap_ba_update_big_params() {
  uint32_t bitrate = btif_bap_broadcast_get_bitrate();
  mBigParams.max_sdu = btif_bap_broadcast_get_mtu(bitrate);
  mBigParams.sdu_int = btif_bap_broadcast_get_framelength();
  BTIF_TRACE_DEBUG("[BapBroadcast]:%s: max_sdu = %d, sdu_int = %d",__func__,
                       mBigParams.max_sdu, mBigParams.sdu_int);
}
uint16_t btif_bap_broadcast_get_sample_rate() {
  if (current_config.sample_rate != BTAV_A2DP_CODEC_SAMPLE_RATE_NONE) {
    BTIF_TRACE_DEBUG("[BapBroadcast]:%s: sample_rate = %d",__func__, current_config.sample_rate);
    return current_config.sample_rate;
  } else {
    BTIF_TRACE_DEBUG("[BapBroadcast]:%s: default sample_rate = %d",__func__, default_config.sample_rate);
    return default_config.sample_rate;
  }
}
uint8_t btif_bap_broadcast_get_ch_mode() {
  if (current_config.channel_mode != BTAV_A2DP_CODEC_CHANNEL_MODE_NONE) {
    return current_config.channel_mode;
  } else {
    return default_config.channel_mode;
  }
}
uint32_t btif_bap_broadcast_get_mtu(uint32_t bitrate) {
  //based on bitrate set (100(80kbps), 120 (96kbps), 155 (128kbps))
  uint32_t mtu;
  switch (bitrate) {
      case 24000:
        mtu = 30;
        break;
      case 27734:
        mtu = 26;
        break;
      case 48000: {//HAP HQ
        if (current_config.codec_specific_2 == 0)
          mtu = 45;
        else
          mtu = 60;
        break;
      }
      case 32000: {
        if (current_config.codec_specific_2 == 0)
          mtu = 30;
        else
          mtu = 40;
        break;
      }
      case 64000: {
        if (current_config.codec_specific_2 == 0)
          mtu = 60;
        else
          mtu = 80;
        break;
      }
      case 80000: {
        if (current_config.codec_specific_2 == 0)
          mtu = 75;
        else
          mtu = 100;
        break;
      }
      case 95060:
        mtu = 97;
        break;
      case 95550:
        mtu = 130;
        break;
      case 96000: {
        if (current_config.codec_specific_2 == 0)
          mtu = 90;
        else
          mtu = 120;
        break;
      }
      case 124800:
        mtu = 117;
        break;
      case 124000:
        mtu = 155;
        break;
      default:
          mtu = 100;
  }
  BTIF_TRACE_DEBUG("[BapBroadcast]%s: mtu = %d",__func__,mtu);
  return mtu;
}

uint16_t btif_bap_broadcast_get_framelength() {
  uint16_t frame_duration;
  switch (current_config.codec_specific_2) {
      case 0:
        frame_duration = 7500; //7.5msec
        break;
      case 1:
        frame_duration = 10000; //10msec
        break;
      default:
        frame_duration = 10000;
  }
  BTIF_TRACE_DEBUG("[BapBroadcast]%s: bitrate = %d",__func__,frame_duration);
  return frame_duration;
}

uint32_t btif_bap_broadcast_get_bitrate() {
  //based on bitrate set (100(80kbps), 120 (96kbps), 155 (128kbps))
  uint32_t bitrate = 0;
  switch (current_config.codec_specific_1) {
      case 1000: //32kbps
        if (current_config.codec_specific_2 == 0) {
          bitrate = 27734;
        } else {
          bitrate = 24000;
        }
        break;
      case 1001: //32kbps
        bitrate = 32000;
        break;
      case 1002: //48kbps
        bitrate = 48000;
        break;
      case 1003: //64kbps
        bitrate = 64000;
        break;
      case 1004: //80kbps
        bitrate = 80000;
        break;
      case 1005: //955.55kbps
        if (current_config.codec_specific_2 == 0) {
          bitrate = 95060;
        } else {
          bitrate = 95550;
        }
        break;
      case 1006: //96kbps
        bitrate = 96000;
        break;
      case 1007: //96kbps
        if (current_config.codec_specific_2 == 0) {
          bitrate = 124800;
        } else {
          bitrate = 124000;
        }
        break;
      default:
        bitrate = 80000;
  }
  BTIF_TRACE_DEBUG("[BapBroadcast]%s: bitrate = %d",__func__,bitrate);
  return bitrate;
}

uint8_t btif_bap_broadcast_get_ch_count() {
  if (current_config.channel_mode == BTAV_A2DP_CODEC_CHANNEL_MODE_STEREO) {
    return BROADCAST_SPLIT_STEREO * mBisMultiplier;
  } else if (current_config.channel_mode == BTAV_A2DP_CODEC_CHANNEL_MODE_MONO ||
    current_config.channel_mode == BTBAP_CODEC_CHANNEL_MODE_JOINT_STEREO) {
    return BROADCAST_MONO_JOINT * mBisMultiplier;
  }
  return BROADCAST_SPLIT_STEREO;//default split stereo
}

static uint16_t btif_bap_get_transport_latency() {
  uint16_t latency;
  if (mBigParams.max_transport_latency != 0) {
    BTIF_TRACE_DEBUG("[BapBroadcast]%s: latency set by property: %d",
                      __func__, mBigParams.max_transport_latency);
    return mBigParams.max_transport_latency;
  }
  switch (current_config.codec_specific_2) {
    case 0:
      latency = 45;//45msec for 7.5msec frame duration
      break;
    case 1:
    default:
      latency = 61;//61msec for 10msec frame duration
      break;
  }
  BTIF_TRACE_DEBUG("[BapBroadcast]%s: transport latency = %d",
                        __func__, latency);
  return latency;
}

bool btif_bap_broadcast_is_simulcast_enabled() {
  char value[PROPERTY_VALUE_MAX] = {'\0'};
  osi_property_get("persist.vendor.btstack.partial_simulcast",value,"false");
  if (strcmp(value, "true") == 0) {
    BTIF_TRACE_IMP("[BapBroadcast]%s:Partial simulcast enabled",__func__);
    return true;
  }
  return false;
}

static void btif_bap_ba_copy_broadcast_id() {
  BTIF_TRACE_DEBUG("[BapBroadcast]:%s",__func__);
  for(int j = 0; j < 3; j++) {
    BTIF_TRACE_DEBUG("Broadcast_ID[%d] = %d",j, mBroadcastID[j]);
  }
  btif_report_broadcast_id();
}

static void btif_bap_ba_generate_broadcast_id() {
  BTIF_TRACE_DEBUG("[BapBroadcast]:%s",__func__);
  btsnd_hcic_ble_rand(base::Bind([](BT_OCTET8 rand) {
   for(int a = 0; a < 3; a++) {
     uint8_t val = rand[a];
     BTIF_TRACE_DEBUG("val = %d", val);
     mBroadcastID[a] = val;
   }
   btif_bap_ba_copy_broadcast_id();
  }));
}

static void btif_bap_ba_generate_enc_key_local(int length) {
  BTIF_TRACE_DEBUG("[BapBroadcast]:%s length = %d",__func__, length);
  srand(time(NULL));
  int i = 0;
  uint8_t random_key[OCTET16_LEN] = {0};
  while (i < length) {
    uint8_t gen = (uint8_t)(rand() % 256);
    uint8_t range = (gen % 75) + 48;//Alphanumeric range
    if ((range > 57 && range < 65) ||
      (range > 90 && range < 97)) {
      //Ascii range 58 to 64
      //:,;, <, =, >, ?, @]
      //range 91 to 96
      //[, \, ], ^, _, `
      BTIF_TRACE_DEBUG("Generate key: Invalid character");
      continue;
    }
    random_key[i] = range;
    i++;
  }

  memset(encryption_key.data(), 0, OCTET16_LEN);
  memcpy(encryption_key.data(),random_key, OCTET16_LEN);
  reverseCode(random_key);
  BTIF_TRACE_DEBUG("[BapBroadcast]:%s storing new excryption key of length %d",__func__, OCTET16_LEN);
  if (btif_config_set_bin("Adapter", "BAP_BA_ENC_KEY", /*encryption_key.data()*/random_key, OCTET16_LEN)) {
     BTIF_TRACE_DEBUG("%s: stored new key", __func__);
     btif_config_flush();
  } else {
    BTIF_TRACE_DEBUG("%s: failed to store new key", __func__);;
  }
  if (notify_key_generated) {
    notify_key_generated = false;
    btif_report_encyption_key();
  }
}
void init_local_capabilities() {
  broadcast_codecs_capabilities.push_back(broadcast_local_capability);
}

static bt_status_t init_broadcast(
    btbap_broadcast_callbacks_t* callbacks,
    int max_broadcast, btav_a2dp_codec_config_t codec_config, int mode) {
  if(max_broadcast > BTIF_BAP_BA_NUM_CB) {
    BTIF_TRACE_WARNING("%s: App setting maximum allowable broadcast(%d) \
              to more than limit(%d)",
            __func__, max_broadcast, BTIF_BAP_BA_NUM_CB);
    max_broadcast = BTIF_BAP_BA_NUM_CB;
  }
  return btif_bap_bms.Init(callbacks, max_broadcast, codec_config, mode);
}
static bt_status_t enable_broadcast(btav_a2dp_codec_config_t codec_config) {
  BTIF_TRACE_IMP("[BapBroadcast]:%s", __func__);
  current_config = codec_config;
  print_config(current_config);
  return btif_bap_bms.EnableBroadcast(codec_config);
}
static bt_status_t disable_broadcast(int adv_id) {
  BTIF_TRACE_IMP("[BapBroadcast]:%s", __func__);
  return btif_bap_bms.DisableBroadcast(adv_id);
}
static bt_status_t set_broadcast_active(bool setup, uint8_t adv_id) {
  BTIF_TRACE_EVENT("[BapBroadcast]:%s", __func__);
  return btif_bap_bms.SetBroadcastActive(setup, adv_id);
}
static bt_status_t config_codec(uint8_t adv_handle, btav_a2dp_codec_config_t codec_config) {
  BTIF_TRACE_IMP("[BapBroadcast]:%s", __func__);
  bool config_changed = false;
  print_config(codec_config);
  if (codec_config.sample_rate != current_config.sample_rate ||
    codec_config.channel_mode != current_config.channel_mode ||
    codec_config.codec_specific_1 != current_config.codec_specific_1 ||
    codec_config.codec_specific_2 != current_config.codec_specific_2 ||
    codec_config.codec_specific_4 > 0) {
    config_changed = true;
  }

  if (config_changed) {
    return btif_bap_bms.SetUserConfig(adv_handle, codec_config);
  }
  return BT_STATUS_SUCCESS;
}
static bt_status_t set_encryption(bool enabled, uint8_t enc_length) {
  BTIF_TRACE_DEBUG("[BapBroadcast]:%s: length %d", __func__, enc_length);
  mEncryptionEnabled = enabled;
  /*if (!mEncryptionEnabled) {
    btif_config_remove("Adapter", "BAP_BA_ENC_KEY");
    return BT_STATUS_SUCCESS;
  }*/
  return btif_bap_bms.SetEncryption(enc_length);
}

static std::string get_encryption_key() {
  BTIF_TRACE_DEBUG("[BapBroadcast]:%s", __func__);
  return std::string(reinterpret_cast<const char*>(encryption_key.data()), OCTET16_LEN);
}

static bt_status_t setup_audio_data_path(bool enable, uint8_t adv_id,
                                         uint8_t big_handle, int num_bises, int *bis_handles) {
  BTIF_TRACE_DEBUG("[BapBroadcast]:%s", __func__);
  return BT_STATUS_SUCCESS;
}
static void cleanup_broadcast() {
  BTIF_TRACE_ERROR("[BapBroadcast]:%s", __func__);
  btif_bap_bms.Cleanup();
}

static const btbap_broadcast_interface_t bt_bap_broadcast_src_interface = {
    sizeof(btbap_broadcast_interface_t),
    init_broadcast,
    enable_broadcast,
    disable_broadcast,
    set_broadcast_active,
    config_codec,
    setup_audio_data_path,
    get_encryption_key,
    set_encryption,
    cleanup_broadcast,
};

/*******************************************************************************
 *
 * Function         btif_bap_broadcast_get_interface
 *
 * Description      Get the Bap broadcast callback interface
 *
 * Returns          btbap_broadcast_interface_t
 *
 ******************************************************************************/
const btbap_broadcast_interface_t* btif_bap_broadcast_get_interface(void) {
  BTIF_TRACE_EVENT("%s", __func__);
  return &bt_bap_broadcast_src_interface;
}


