/******************************************************************************
 *  Copyright (c) 2020, The Linux Foundation. All rights reserved.
 *
 *****************************************************************************/

#pragma once

#include <string>
#include "state_machine.h"
#include <list>
#include "bta_bap_uclient_api.h"
#include "bta_pacs_client_api.h"
#include "bta_ascs_client_api.h"
#include "bt_trace.h"
#include "uclient_alarm.h"
#include "btif_util.h"

namespace bluetooth {
namespace bap {
namespace ucast {

using bluetooth::bap::pacs::ConnectionState;
using bluetooth::bap::pacs::PacsClient;
using bluetooth::bap::ascs::GattState;
using bluetooth::bap::ascs::AscsClient;
using bluetooth::bap::ascs::AseParams;
using bluetooth::bap::ascs::AseCodecConfigParams;
using bluetooth::bap::ascs::AseCodecConfigOp;
using bluetooth::bap::cis::CisInterface;

using bluetooth::bap::cis::CigState;
using bluetooth::bap::cis::CisState;

using bluetooth::bap::alarm::BapAlarm;
using bluetooth::bap::alarm::BapAlarmCallbacks;

class UstreamManager;
class UstreamManagers;
struct UcastAudioStream;
class UcastAudioStreams;
class StreamContexts;
struct StreamContext;
class StreamTracker;

enum class StreamAttachedState {
  IDLE        = 0x1 << 0,
  IDLE_TO_PHY = 0x1 << 1,
  VIRTUAL     = 0x1 << 2,
  VIR_TO_PHY  = 0x1 << 3,
  PHYSICAL    = 0x1 << 4
};

enum class StreamControlType {
  None         = 0x00,
  Connect      = 0X01,
  Disconnect   = 0x02,
  Start        = 0x04,
  Stop         = 0x08,
  Reconfig     = 0x10,
  UpdateStream = 0x20
};

enum class DeviceType {
  NONE                  = 0x00,
  EARBUD                = 0X01,  // group member
  HEADSET_STEREO        = 0x02,  // headset with 1 CIS
  HEADSET_SPLIT_STEREO  = 0x03   // headset with 2 CIS
};

enum class IntConnectState {
  IDLE             = 0x00,
  PACS_CONNECTING  = 0x01,
  PACS_DISCOVERING = 0X02,
  ASCS_CONNECTING  = 0x03,
  ASCS_DISCOVERING = 0x04,
  ASCS_DISCOVERED  = 0x05,
};

enum class AscsPendingCmd {
  NONE                      = 0x00,
  CODEC_CONFIG_ISSUED       = 0x01,
  QOS_CONFIG_ISSUED         = 0x02,
  ENABLE_ISSUED             = 0x03,
  START_READY_ISSUED        = 0x04,
  DISABLE_ISSUED            = 0x05,
  STOP_READY_ISSUED         = 0x06,
  RELEASE_ISSUED            = 0x07,
  UPDATE_METADATA_ISSUED    = 0x08
};

enum class CisPendingCmd {
  NONE                      = 0x00,
  CIG_CREATE_ISSUED         = 0x08,
  CIS_CREATE_ISSUED         = 0x09,
  CIS_SETUP_DATAPATH_ISSUED = 0x10,
  CIS_RMV_DATAPATH_ISSUED   = 0x11,
  CIS_DESTROY_ISSUED        = 0x12,
  CIG_REMOVE_ISSUED         = 0x13
};

enum class GattPendingCmd {
  NONE                      = 0x00,
  GATT_CONN_PENDING         = 0x01,
  GATT_DISC_PENDING         = 0x02
};

typedef enum {
  BAP_CONNECT_REQ_EVT = 0X00,
  BAP_DISCONNECT_REQ_EVT,
  BAP_START_REQ_EVT,
  BAP_STOP_REQ_EVT,
  BAP_RECONFIG_REQ_EVT,
  BAP_STREAM_UPDATE_REQ_EVT,
  PACS_CONNECTION_STATE_EVT,
  PACS_DISCOVERY_RES_EVT,
  PACS_AUDIO_CONTEXT_RES_EVT,
  ASCS_CONNECTION_STATE_EVT,
  ASCS_DISCOVERY_RES_EVT,
  ASCS_ASE_STATE_EVT,
  ASCS_ASE_OP_FAILED_EVT,
  CIS_GROUP_STATE_EVT,
  CIS_STATE_EVT,
  BAP_TIME_OUT_EVT,
} BapEvent;

struct BapConnect {
  std::vector<RawAddress> bd_addr;
  bool is_direct;
  std::vector<StreamConnect> streams;
};

struct BapDisconnect {
  RawAddress bd_addr;
  std::vector<StreamType> streams;
};

struct BapStart {
  RawAddress bd_addr;
  std::vector<StreamType> streams;
};

struct BapStop {
  RawAddress bd_addr;
  std::vector<StreamType> streams;
};

struct BapReconfig {
  RawAddress bd_addr;
  std::vector<StreamReconfig> streams;
};

struct BapStreamUpdate {
  RawAddress bd_addr;
  std::vector<StreamUpdate> update_streams;
};

struct PacsConnectionState {
  RawAddress bd_addr;
  ConnectionState state;
};

struct AscsConnectionState {
  RawAddress bd_addr;
  GattState state;
};

struct AscsDiscovery {
  int status;
  RawAddress bd_addr;
  std::vector<AseParams> sink_ases_list;
  std::vector<AseParams> src_ases_list;
};

struct AscsState {
  RawAddress bd_addr;
  AseParams ase_params;
};

struct AscsOpFailed {
  RawAddress bd_addr;
  ascs::AseOpId ase_op_id;
  std::vector<ascs::AseOpStatus> ase_list;
};

struct CisGroupState {
  uint8_t cig_id;
  CigState state;
};

struct CisStreamState {
  uint8_t cig_id;
  uint8_t cis_id;
  uint8_t direction;
  CisState state;
};

struct PacsDiscovery {
  int status;
  RawAddress bd_addr;
  std::vector<CodecConfig> sink_pac_records;
  std::vector<CodecConfig> src_pac_records;
  uint32_t sink_locations;
  uint32_t src_locations;
  uint32_t available_contexts;
  uint32_t supported_contexts;
};

struct PacsAvailableContexts {
  RawAddress bd_addr;
  uint32_t available_contexts;
};

struct IntStrmTracker {
 IntStrmTracker(StreamType strm_type, uint8_t ase_id, uint8_t cig_id,
                uint8_t cis_id, CodecConfig &codec_config,
                QosConfig &qos_config)
     : strm_type(strm_type), ase_id(ase_id) , cig_id(cig_id) ,
       cis_id(cis_id), codec_config(codec_config),
       qos_config(qos_config) {
        attached_state = StreamAttachedState::IDLE;
       }
  StreamType strm_type;
  uint8_t ase_id;
  uint8_t cig_id;
  uint8_t cis_id;
  CodecConfig codec_config;
  QosConfig qos_config;
  StreamAttachedState attached_state;
};

class IntStrmTrackers {
 public:
  std::vector<IntStrmTracker *> FindByCigId(uint8_t cig_id) {
    std::vector<IntStrmTracker *> trackers;
    for (auto i = int_strm_trackers.begin();
                         i != int_strm_trackers.end();i++) {
      if((*i)->cig_id  == cig_id) {
        LOG(WARNING) << __func__ << " tracker found";
        trackers.push_back(*i);
      }
    }
    return trackers;
  }

  std::vector<IntStrmTracker *> FindByCigIdAndDir(uint8_t cig_id,
                                                  uint8_t direction) {
    std::vector<IntStrmTracker *> trackers;
    for (auto i = int_strm_trackers.begin();
              i != int_strm_trackers.end();i++) {
      if((*i)->cig_id  == cig_id &&
         (*i)->strm_type.direction  == direction) {
        trackers.push_back(*i);
      }
    }
    return trackers;
  }

  std::vector<IntStrmTracker *> FindByCisId(uint8_t cig_id, uint8_t cis_id) {
    std::vector<IntStrmTracker *> trackers;
    for (auto i = int_strm_trackers.begin();
              i != int_strm_trackers.end();i++) {
      if((*i)->cig_id  == cig_id && (*i)->cis_id  == cis_id) {
        trackers.push_back(*i);
      }
    }
    return trackers;
  }

  IntStrmTracker *FindByIndex(uint8_t i) {
    IntStrmTracker *tracker = int_strm_trackers.at(i);
    return tracker;
  }

  IntStrmTracker *FindByAseId(uint8_t ase_id) {
    auto iter = std::find_if(int_strm_trackers.begin(), int_strm_trackers.end(),
                         [&ase_id](IntStrmTracker *tracker) {
                            return tracker->ase_id == ase_id;
                         });

    return (iter == int_strm_trackers.end()) ? nullptr : (*iter);
  }

  IntStrmTracker *FindOrAddBytrackerType(StreamType strm_type,
                        uint8_t ase_id, uint8_t cig_id,  uint8_t cis_id,
                        CodecConfig &codec_config, QosConfig &qos_config) {

    auto iter = std::find_if(int_strm_trackers.begin(), int_strm_trackers.end(),
                  [&strm_type, &cig_id, &cis_id](IntStrmTracker *tracker) {
                     return ((tracker->strm_type.type == strm_type.type) &&
                             (tracker->strm_type.direction ==
                              strm_type.direction) &&
                             (tracker->cig_id == cig_id) &&
                             (tracker->cis_id == cis_id));
                });

    if (iter == int_strm_trackers.end()) {
      IntStrmTracker *tracker = new IntStrmTracker(strm_type,
                        ase_id, cig_id, cis_id, codec_config, qos_config);
      int_strm_trackers.push_back(tracker);
      return tracker;
    } else {
      return (*iter);
    }
  }

  void Remove(StreamType strm_type, uint8_t cig_id,  uint8_t cis_id) {
    for (auto it = int_strm_trackers.begin(); it != int_strm_trackers.end();) {
      if (((*it)->strm_type.type = strm_type.type) &&
          ((*it)->strm_type.direction = strm_type.direction) &&
          ((*it)->cig_id = cig_id) && ((*it)->cis_id = cis_id)) {
        delete(*it);
        it = int_strm_trackers.erase(it);
      } else {
        it++;
      }
    }
  }

  void RemoveVirtualAttachedTrackers() {
    LOG(WARNING) << __func__;
    for (auto it = int_strm_trackers.begin(); it != int_strm_trackers.end();) {
      if ((*it)->attached_state == StreamAttachedState::VIRTUAL) {
        delete(*it);
        it = int_strm_trackers.erase(it);
        LOG(WARNING) << __func__
                     << ": Removed virtual attached tracker";
      } else {
        it++;
      }
    }
  }

  size_t size() { return (int_strm_trackers.size()); }

  std::vector<IntStrmTracker *> *GetTrackerList() {
    return &int_strm_trackers;
  }

  std::vector<IntStrmTracker *> GetTrackerListByDir(uint8_t direction) {
    std::vector<IntStrmTracker *> trackers;
    for (auto i = int_strm_trackers.begin();
              i != int_strm_trackers.end();i++) {
      if((*i)->strm_type.direction == direction) {
        trackers.push_back(*i);
      }
    }
    return trackers;
  }

 private:
  std::vector<IntStrmTracker *> int_strm_trackers;
};

union BapEventData {
  BapConnect connect_req;
  BapDisconnect disc_req;
  BapStart start_req;
  BapStop stop_req;
  BapReconfig reconfig_req;
  PacsConnectionState connection_state_rsp;
  PacsDiscovery pacs_discovery_rsp;
  PacsAvailableContexts pacs_audio_context_rsp;
};

enum class TimeoutVal { //in milli seconds(1sec = 1000ms)
  ConnectingTimeout = 10000,
  StartingTimeout = 2000,
  StoppingTimeout = 2000,
  DisconnectingTimeout = 1000,
  ReconfiguringTimeout = 2000,
  UpdatingTimeout = 1000
};

enum class MaxTimeoutVal { //in milli seconds(1sec = 1000ms)
  ConnectingTimeout = 10000,
  StartingTimeout = 4000,
  StoppingTimeout = 4000,
  DisconnectingTimeout = 4000,
  ReconfiguringTimeout = 8000,
  UpdatingTimeout = 4000
};

enum class TimeoutReason {
  STATE_TRANSITION = 1,
};

struct BapTimeout {
  RawAddress bd_addr;
  StreamTracker* tracker;
  TimeoutReason reason;
  int transition_state;
};

class StreamTracker : public bluetooth::common::StateMachine {
 public:
  enum {
    kStateIdle,     //
    kStateConnecting,  //
    kStateConnected,   //
    kStateStarting,  //
    kStateStreaming,  //
    kStateStopping, //
    kStateDisconnecting, //
    kStateReconfiguring, //
    kStateUpdating
  };

  class StateIdle : public State {
   public:
    StateIdle(StreamTracker& sm)
        : State(sm, kStateIdle), tracker_(sm),
          strm_mgr_(sm.GetStreamManager()) {}
    void OnEnter() override;
    void OnExit() override;
    const char* GetState() { return "Idle"; }
    bool ProcessEvent(uint32_t event, void* p_data) override;

   private:
    StreamTracker &tracker_;
    UstreamManager *strm_mgr_;
  };

  class StateConnecting : public State {
   public:
    StateConnecting(StreamTracker& sm)
        : State(sm, kStateConnecting), tracker_(sm),
         strm_mgr_(sm.GetStreamManager()) {}
    void OnEnter() override;
    void OnExit() override;
    const char* GetState() { return "Connecting"; }
    bool ProcessEvent(uint32_t event, void* p_data) override;
    void DeriveDeviceType(PacsDiscovery *pacs_discovery);
    bool AttachStreamsToContext(std::vector<IntStrmTracker *> *all_trackers,
                                std::vector<UcastAudioStream *> *streams,
                                uint8_t cis_count,
                                std::vector<AseCodecConfigOp> *ase_ops);
    alarm_t* state_transition_timer;
    BapTimeout timeout;

   private:
    StreamTracker &tracker_;
    UstreamManager *strm_mgr_;
    PacsDiscovery pacs_discovery_;
    AscsDiscovery ascs_discovery_;
    IntStrmTrackers int_strm_trackers_;
   };

  class StateConnected : public State {
   public:
    StateConnected(StreamTracker& sm)
        : State(sm, kStateConnected), tracker_(sm),
          strm_mgr_(sm.GetStreamManager()){}
    void OnEnter() override;
    void OnExit() override;
    const char* GetState() { return "Connected"; }
    bool ProcessEvent(uint32_t event, void* p_data) override;

   private:
    StreamTracker &tracker_;
    UstreamManager *strm_mgr_;
  };

  class StateStarting : public State {
   public:
    StateStarting(StreamTracker& sm)
        : State(sm, kStateStarting), tracker_(sm),
          strm_mgr_(sm.GetStreamManager()){}
    void OnEnter() override;
    void OnExit() override;
    const char* GetState() { return "Starting"; }
    bool ProcessEvent(uint32_t event, void* p_data) override;
    bool CheckAndUpdateStreamingState();
    alarm_t* state_transition_timer;
    PacsAvailableContexts pacs_contexts;
    BapTimeout timeout;

   private:
    StreamTracker &tracker_;
    UstreamManager *strm_mgr_;
    IntStrmTrackers int_strm_trackers_;
  };

  class StateStreaming : public State {
   public:
    StateStreaming(StreamTracker& sm)
        : State(sm, kStateStreaming), tracker_(sm),
          strm_mgr_(sm.GetStreamManager()){}
    void OnEnter() override;
    void OnExit() override;
    const char* GetState() { return "Streaming"; }
    bool ProcessEvent(uint32_t event, void* p_data) override;

   private:
    StreamTracker &tracker_;
    UstreamManager *strm_mgr_;
  };

  class StateStopping : public State {
   public:
    StateStopping(StreamTracker& sm)
        : State(sm, kStateStopping), tracker_(sm),
          strm_mgr_(sm.GetStreamManager()) {}
    void OnEnter() override;
    void OnExit() override;
    const char* GetState() { return "Stopping"; }
    bool ProcessEvent(uint32_t event, void* p_data) override;
    bool TerminateCisAndCig(UcastAudioStream *stream);
    bool CheckAndUpdateStoppedState();
    alarm_t* state_transition_timer;
    BapTimeout timeout;

   private:
    StreamTracker &tracker_;
    UstreamManager *strm_mgr_;
    IntStrmTrackers int_strm_trackers_;
  };

  class StateDisconnecting : public State {
   public:
    StateDisconnecting(StreamTracker& sm)
        : State(sm, kStateDisconnecting), tracker_(sm),
          strm_mgr_(sm.GetStreamManager()) {}
    void OnEnter() override;
    void OnExit() override;
    const char* GetState() { return "Disconnecting"; }
    bool ProcessEvent(uint32_t event, void* p_data) override;
    bool TerminateGattConnection();
    void ContinueDisconnection(UcastAudioStream *stream);
    bool CheckAndUpdateDisconnectedState();
    alarm_t* state_transition_timer;
    BapTimeout timeout;

   private:
    StreamTracker &tracker_;
    UstreamManager *strm_mgr_;
    IntStrmTrackers int_strm_trackers_;
  };

  class StateReconfiguring: public State {
   public:
    StateReconfiguring(StreamTracker& sm)
        : State(sm, kStateReconfiguring), tracker_(sm),
          strm_mgr_(sm.GetStreamManager()) {}
    void OnEnter() override;
    void OnExit() override;
    const char* GetState() { return "Reconfiguring"; }
    bool ProcessEvent(uint32_t event, void* p_data) override;
    alarm_t* state_transition_timer;
    BapTimeout timeout;

   private:
    StreamTracker &tracker_;
    UstreamManager *strm_mgr_;
    IntStrmTrackers int_strm_trackers_;
  };

  class StateUpdating: public State {
   public:
    StateUpdating(StreamTracker& sm)
        : State(sm, kStateUpdating), tracker_(sm),
          strm_mgr_(sm.GetStreamManager()) {}
    void OnEnter() override;
    void OnExit() override;
    const char* GetState() { return "Updating"; }
    bool ProcessEvent(uint32_t event, void* p_data) override;
    alarm_t* state_transition_timer;
    BapTimeout timeout;

   private:
    StreamTracker &tracker_;
    UstreamManager *strm_mgr_;
    IntStrmTrackers int_strm_trackers_;
  };

  StreamTracker(int init_state_id, UstreamManager *strm_mgr,
                std::vector<StreamConnect> *connect_streams,
                std::vector<StreamReconfig> *reconfig_streams,
                std::vector<StreamType> *streams,
                StreamControlType ops_type):
                    init_state_id_(init_state_id),
                    strm_mgr_(strm_mgr) {

    state_idle_ = new StateIdle(*this);
    state_connecting_ = new StateConnecting(*this);
    state_connected_ = new StateConnected(*this);
    state_starting_ = new StateStarting(*this);
    state_streaming_ = new StateStreaming(*this);
    state_stopping_ = new StateStopping(*this);
    state_disconnecting_ = new StateDisconnecting(*this);
    state_reconfiguring_ = new StateReconfiguring(*this);
    state_updating_ = new StateUpdating(*this);
    pacs_disc_succeded_ = false;

    AddState(state_idle_);
    AddState(state_connecting_);
    AddState(state_connected_);
    AddState(state_starting_);
    AddState(state_streaming_);
    AddState(state_stopping_);
    AddState(state_disconnecting_);
    AddState(state_reconfiguring_);
    AddState(state_updating_);

    switch(init_state_id) {
      case kStateIdle:
        SetInitialState(state_idle_);
        break;
      case kStateConnected:
        SetInitialState(state_connected_);
        break;
      case kStateStreaming:
        SetInitialState(state_streaming_);
        break;
      case kStateDisconnecting:
        SetInitialState(state_disconnecting_);
        break;
      default:
        SetInitialState(state_idle_);
    }

    str_ops_type = ops_type;

    if(ops_type == StreamControlType::Connect) {
      conn_streams = *connect_streams;
    } else if(ops_type == StreamControlType::Reconfig) {
      reconf_streams = *reconfig_streams;
    } else if(ops_type != StreamControlType::UpdateStream) {
      other_streams = *streams;
    }
  }

  void PauseRemoteDevInteraction(bool pause);
  bool decoupleStream(StreamType *stream_info);

  uint8_t ChooseBestCodec(StreamType stream_type,
                              std::vector<CodecQosConfig> *codec_qos_configs,
                              PacsDiscovery *pacs_discovery);

  bool ChooseBestQos(QosConfig *src_config,
                     ascs::AseCodecConfigParams *rem_qos_prefs,
                     QosConfig *dst_config,
                     int stream_state, uint8_t stream_direction);

  bool HandlePacsConnectionEvent(void *p_data);

  bool HandlePacsAudioContextEvent(PacsAvailableContexts *pacs_contexts);

  bool HandleCisEventsInStreaming(void* p_data);

  bool HandleStreamUpdate (int cur_state);

  bool CheckAndUpdateStreamingState(IntStrmTrackers *int_strm_trackers);

  bool HandleAscsConnectionEvent(void *p_data);

  void HandleCigStateEvent(uint32_t event, void *p_data,
                           IntStrmTrackers *int_strm_trackers);

  void HandleAseStateEvent(void *p_data, StreamControlType control_type,
                           IntStrmTrackers *int_strm_trackers);

  void HandleAseOpFailedEvent(void *p_data);

  bool ValidateAseUpdate(void* p_data, IntStrmTrackers *int_strm_trackers,
                         int exp_strm_state);

  bool HandleDisconnect(void* p_data, int cur_state);

  bool HandleRemoteDisconnect(uint32_t event, void* p_data, int cur_state);

  bool StreamCanbeDisconnected(StreamContext *cur_context, uint8_t ase_id);

  bool HandleInternalDisconnect(bool release);

  bool HandleStop(void* p_data, int cur_state);

  bool HandleRemoteStop(uint32_t event, void* p_data, int cur_state);

  bool HandleRemoteReconfig(uint32_t event, void* p_data, int cur_state);

  bool PrepareCodecConfigPayload(std::vector<AseCodecConfigOp> *ase_ops,
                                 UcastAudioStream *stream);

  void CheckAndSendQosConfig(IntStrmTrackers *int_strm_trackers);

  void CheckAndSendEnable(IntStrmTrackers *int_strm_trackers);

  bool HandleAbruptStop(uint32_t event, void* p_data);

  alarm_t* SetTimer(const char* alarmname, BapTimeout* timeout,
                                           TimeoutReason reason, uint64_t ms);

  void ClearTimer(alarm_t* timer, const char* alarmname);

  void OnTimeout(void* data);

  StreamControlType GetControlType() {
    return str_ops_type;
  }

  UstreamManager *GetStreamManager() {
    return strm_mgr_;
  }

  bool UpdatePacsDiscovery(PacsDiscovery disc_res) {
    pacs_disc_succeded_ = true;
    pacs_discovery_ = disc_res;
    return true;
  }

  PacsDiscovery *GetPacsDiscovery() {
    if(pacs_disc_succeded_) {
      return &pacs_discovery_;
    } else {
      return nullptr;
    }
  }

  bool UpdateControlType(StreamControlType ops_type) {
    str_ops_type = ops_type;
    return true;
  }

  bool UpdateStreams(std::vector<StreamType> *streams) {
    other_streams = *streams;
    return true;
  }

  bool UpdateConnStreams(
          std::vector<StreamConnect> *connect_streams) {
    conn_streams = *connect_streams;
    return true;
  }

  bool UpdateReconfStreams(
         std::vector<StreamReconfig> *reconfig_streams) {
    reconf_streams = *reconfig_streams;
    return true;
  }

  bool UpdateMetaUpdateStreams(
         std::vector<StreamUpdate> *meta_streams) {
    meta_update_streams = *meta_streams;
    return true;
  }

  std::vector<StreamType> *GetStreams() {
    return &other_streams;
  }
  std::vector<StreamConnect> *GetConnStreams() {
    return &conn_streams;
  }
  std::vector<StreamReconfig> *GetReconfStreams() {
    return &reconf_streams;
  }

  std::vector<StreamUpdate> *GetMetaUpdateStreams() {
    return &meta_update_streams;
  }

  const char* GetEventName(uint32_t event) {
    switch (event) {
      CASE_RETURN_STR(BAP_CONNECT_REQ_EVT)
      CASE_RETURN_STR(BAP_DISCONNECT_REQ_EVT)
      CASE_RETURN_STR(BAP_START_REQ_EVT)
      CASE_RETURN_STR(BAP_STOP_REQ_EVT)
      CASE_RETURN_STR(BAP_RECONFIG_REQ_EVT)
      CASE_RETURN_STR(BAP_STREAM_UPDATE_REQ_EVT)
      CASE_RETURN_STR(PACS_CONNECTION_STATE_EVT)
      CASE_RETURN_STR(PACS_DISCOVERY_RES_EVT)
      CASE_RETURN_STR(PACS_AUDIO_CONTEXT_RES_EVT)
      CASE_RETURN_STR(ASCS_CONNECTION_STATE_EVT)
      CASE_RETURN_STR(ASCS_DISCOVERY_RES_EVT)
      CASE_RETURN_STR(ASCS_ASE_STATE_EVT)
      CASE_RETURN_STR(ASCS_ASE_OP_FAILED_EVT)
      CASE_RETURN_STR(CIS_GROUP_STATE_EVT)
      CASE_RETURN_STR(CIS_STATE_EVT)
      CASE_RETURN_STR(BAP_TIME_OUT_EVT)
      default:
       return "Unknown Event";
    }
  }

 private:
  int init_state_id_;
  UstreamManager *strm_mgr_;
  std::vector<StreamConnect> conn_streams;
  std::vector<StreamType> other_streams;
  std::vector<StreamReconfig> reconf_streams;
  std::vector<StreamUpdate> meta_update_streams;
  StreamControlType str_ops_type;
  bool pacs_disc_succeded_;
  PacsDiscovery pacs_discovery_;
  StateIdle *state_idle_;
  StateConnecting *state_connecting_;
  StateConnected *state_connected_;
  StateStarting *state_starting_;
  StateStreaming *state_streaming_;
  StateStopping *state_stopping_;
  StateDisconnecting *state_disconnecting_;
  StateReconfiguring *state_reconfiguring_;
  StateUpdating *state_updating_;
};

struct StreamOpConnect {
  StreamType stream_type;
  //std::vector<CodecConfig> codec_configs;
  //std::vector<QosConfig> qos_configs;
};

struct StreamOpReconfig {
  StreamType stream_type;
  //std::vector<CodecConfig> codec_configs;
  //std::vector<QosConfig> qos_configs;
};

union StreamOpData {
  StreamOpConnect connect_op;
  StreamType stream_type;
  StreamOpReconfig reconfig_op;
};

struct StreamOpNode {
  bool busy;
  bool is_client_originated;
  StreamControlType ops_type;
  StreamOpData ops_data;
};

struct StreamIdType {
  uint8_t ase_id;
  uint8_t ase_direction;
  bool virtual_attach;
  uint8_t cig_id;
  uint8_t cis_id;
};

struct StreamContext {
 StreamContext(StreamType strm_type)
     : stream_type(strm_type) {
       stream_state = StreamState::DISCONNECTED;
       attached_state = StreamAttachedState::IDLE;
     }
  StreamType stream_type;
  StreamAttachedState attached_state;
  std::vector<StreamIdType> stream_ids;
  StreamState stream_state;
  IntConnectState connection_state;
  CodecConfig codec_config;
  QosConfig qos_config;
  QosConfig req_qos_config;
};

class StreamContexts {
 public:

  StreamContext *FindByType(StreamType stream_type);

  StreamContext *FindOrAddByType(StreamType stream_type);

  void Remove(StreamType stream_type);

  bool IsAseAttached(StreamType stream_type);

  std::vector<StreamContext *> FindByAseAttachedState(uint16_t ase_id,
                           StreamAttachedState state);


  StreamContext* FindByAseId(uint16_t ase_id);

  std::vector<StreamContext *> *GetAllContexts() {
    return &strm_contexts;
  }

  size_t size() { return (strm_contexts.size()); }

 private:
  std::vector<StreamContext *> strm_contexts;
};


class StreamOpsQueue {
 public:
  bool Add(StreamOpNode op_node);

  bool AddFirst(StreamOpNode op_node);

  StreamOpNode *GetNextNode();

  bool Remove(StreamType stream_type);

  StreamOpNode* FindByContext(StreamType stream_type);

  bool ChangeOpType(StreamType stream_type, StreamControlType new_ops_type);

  size_t size() { return (queue.size()); }

  std::vector<StreamOpNode> queue;
};

class StreamTrackers {
 public:
  StreamTracker *FindOrAddByType(int init_state_id, UstreamManager *strm_mgr,
                                 std::vector<StreamConnect> *connect_streams,
                                 std::vector<StreamReconfig> *reconfig_streams,
                                 std::vector<StreamType> *streams,
                                 StreamControlType ops_type);

  bool Remove(std::vector<StreamType> streams,
              StreamControlType ops_type);

  void RemoveByStates(std::vector<int> state_ids);

  std::map<StreamTracker * , std::vector<StreamType> > GetTrackersByType(
                                        std::vector<StreamType> *streams);

  StreamTracker *FindByStreamsType(std::vector<StreamType> *streams);

  std::vector<StreamTracker *> GetTrackersByStates(
                                         std::vector<int> *state_ids);

  bool ChangeOpType( StreamType stream_type,
                     StreamControlType new_ops_type);

  bool IsStreamTrackerValid(StreamTracker* Tracker,
                                     std::vector<int> *state_ids);

  size_t size() { return (stream_trackers.size()); }

  std::vector<StreamTracker *> stream_trackers;
};

struct UcastAudioStream {
  UcastAudioStream(uint8_t ase_id, uint8_t ase_state, uint8_t ase_direction)
     : ase_id(ase_id) , ase_state(ase_state) {
    ase_state = ascs::ASE_STATE_INVALID;
    cig_state = CigState::INVALID;
    cis_state = CisState::INVALID;
    direction = ase_direction;
    cig_id = 0XFF;
    cis_id = 0xFF;
    cis_retry_count = 0;
    overall_state = StreamTracker::kStateIdle;
    ase_pending_cmd = AscsPendingCmd::NONE;
    cis_pending_cmd = CisPendingCmd::NONE;
  }
  bool is_active;
  uint8_t ase_id;
  uint8_t ase_state;
  AseParams ase_params;
  AseCodecConfigParams pref_qos_params;
  uint8_t cig_id;
  CigState cig_state;
  uint8_t cis_id;
  CisState cis_state;
  uint8_t cis_retry_count;
  int overall_state; // stream tracker state
  StreamControlType control_type;
  AscsPendingCmd  ase_pending_cmd;
  CisPendingCmd cis_pending_cmd;
  uint16_t audio_context;
  uint8_t direction;
  uint32_t audio_location;
  CodecConfig codec_config;
  QosConfig qos_config;
  QosConfig req_qos_config;
};

class UcastAudioStreams {
 public:

  std::vector<UcastAudioStream *> FindByCigId(uint8_t cig_id, int state) {
    std::vector<UcastAudioStream *> streams;
    for (auto i = audio_streams.begin(); i != audio_streams.end();i++) {
      if((*i)->cig_id  == cig_id &&
         (*i)->overall_state  == state) {
        streams.push_back(*i);
      }
    }
    return streams;
  }

  std::vector<UcastAudioStream *> FindByCisId(uint8_t cig_id, uint8_t cis_id) {
    std::vector<UcastAudioStream *> streams;
    for (auto i = audio_streams.begin(); i != audio_streams.end();i++) {
      if((*i)->cig_id  == cig_id && (*i)->cis_id  == cis_id) {
        streams.push_back(*i);
      }
    }
    return streams;
  }

  UcastAudioStream *FindByStreamType(uint16_t audio_context,
                                     uint8_t direction) {
    auto it = audio_streams.begin();
    while (it != audio_streams.end()) {
      if((*it)->audio_context  == audio_context &&
         (*it)->direction & direction) {
        break;
      }
      it++;
    }
    return (it == audio_streams.end()) ? nullptr : (*it);
  }

  UcastAudioStream *FindByCisIdAndDir(uint8_t cig_id, uint8_t cis_id,
                                      uint8_t dir) {
    auto it = audio_streams.begin();
    while (it != audio_streams.end()) {
      if((*it)->cig_id  == cig_id && (*it)->cis_id  == cis_id &&
         (*it)->direction & dir) {
        break;
      }
      it++;
    }
    return (it == audio_streams.end()) ? nullptr : (*it);
  }

  UcastAudioStream *FindByAseId(uint8_t ase_id) {
    auto it = audio_streams.begin();
    while (it != audio_streams.end()) {
      if((*it)->ase_id  == ase_id) {
        break;
      }
      it++;
    }
    return (it == audio_streams.end()) ? nullptr : (*it);
  }

  UcastAudioStream *FindOrAddByAseId(uint8_t ase_id, uint8_t ase_state,
                                     uint8_t ase_direction) {
    auto iter = std::find_if(audio_streams.begin(), audio_streams.end(),
                         [&ase_id, &ase_direction](UcastAudioStream *stream) {
                            return (stream->ase_id == ase_id &&
                                    stream->direction == ase_direction);
                         });

    if (iter == audio_streams.end()) {
      UcastAudioStream *stream = new UcastAudioStream(ase_id, ase_state,
                                                      ase_direction);
      stream->overall_state = StreamTracker::kStateIdle;
      audio_streams.push_back(stream);
      auto it = std::find_if(audio_streams.begin(), audio_streams.end(),
                         [&ase_id, &ase_direction](UcastAudioStream* stream) {
                            return (stream->ase_id == ase_id &&
                                    stream->direction == ase_direction);
                         });
      return (it == audio_streams.end()) ? nullptr : (*it);
    } else {
      return (*iter);
    }
  }

  std::vector<UcastAudioStream *> GetStreamsByStates(
                                  std::vector<int> state_ids,
                                  uint8_t directions) {
    std::vector<UcastAudioStream *> streams;
    for (auto i = audio_streams.begin(); i != audio_streams.end();i++) {
      for (auto j = state_ids.begin(); j != state_ids.end();j++) {
        if(((*i)->overall_state == *j) && ((*i)->direction & directions)) {
          streams.push_back(*i);
        }
      }
    }
    return streams;
  }

  void Remove(uint8_t ase_id) {
    for (auto it = audio_streams.begin(); it != audio_streams.end();) {
      if ((*it)->ase_id == ase_id)  {
        delete(*it);
        it = audio_streams.erase(it);
      } else {
        it++;
      }
    }
  }

  std::vector<UcastAudioStream *> *GetAllStreams() {
    return &audio_streams;
  }

  size_t size() { return (audio_streams.size()); }
  // UcastAudioStream
 private:
  std::vector<UcastAudioStream *> audio_streams;
};

struct GattPendingData {
  GattPendingData() {
        ascs_pending_cmd = GattPendingCmd::NONE;
        pacs_pending_cmd = GattPendingCmd::NONE;
  }
  GattPendingCmd ascs_pending_cmd;
  GattPendingCmd pacs_pending_cmd;
};

class UstreamManager {
 public:
   UstreamManager(const RawAddress& address, PacsClient *pacs_client,
                  uint16_t pacs_client_id,
                  AscsClient *ascs_client, CisInterface *cis_intf,
                  UcastClientCallbacks* callbacks,
                  BapAlarm *bap_alarm)
       : address(address) , pacs_client(pacs_client),
         pacs_client_id(pacs_client_id),
         ascs_client(ascs_client), cis_intf(cis_intf),
         ucl_callbacks(callbacks), bap_alarm(bap_alarm) {
     pacs_state = ConnectionState::DISCONNECTED;
     gatt_pending_data.pacs_pending_cmd = GattPendingCmd::NONE;
     gatt_pending_data.ascs_pending_cmd = GattPendingCmd::NONE;
     ascs_state = GattState::DISCONNECTED;
     dev_type = DeviceType::NONE;
   }

   bool PushEventToTracker(uint32_t event, void *p_data,
                           std::vector<int> *state_ids);

   std::map<int , std::vector<StreamType> > SplitContextOnState(
                             std::vector<StreamType> *streams);

   void ProcessEvent(uint32_t event, void* p_data);

   uint16_t GetConnId();

   std::list<uint16_t> GetCigId();

   std::list<uint16_t> GetCisId();

   void ReportStreamState (std::vector<StreamStateInfo> stream_info);

   RawAddress &GetAddress() { return address; };

   PacsClient *GetPacsClient() {
     return pacs_client;
   }

   uint16_t GetPacsClientId() {
     return pacs_client_id;
   }

   GattPendingData *GetGattPendingData() {
     return &gatt_pending_data;
   }

   bool UpdatePacsState(ConnectionState state) {
     pacs_state = state;
     return true;
   }

   bool UpdateAscsState(GattState state) {
     ascs_state = state;
     return true;
   }

   ConnectionState GetPacsState() {
     return pacs_state;
   }

   GattState GetAscsState() {
     return ascs_state;
   }

   AscsClient *GetAscsClient() {
     return ascs_client;
   }

   CisInterface *GetCisInterface() {
     return cis_intf;
   }

   BapAlarm *GetBapAlarm() {
     return bap_alarm;
   }

   UcastAudioStreams *GetAudioStreams() {
     return  &audio_streams;
   }

   StreamTrackers *GetStreamTrackers() {
     return &stream_trackers;
   }

   StreamContexts *GetStreamContexts() {
     return &stream_contexts;
   }

   UcastClientCallbacks *GetUclientCbacks() {
     return ucl_callbacks;
   }

   void UpdateDevType(DeviceType device_type) {
     dev_type = device_type;
   }

   DeviceType GetDevType() {
     return dev_type;
   }

  const char* GetEventName(uint32_t event) {
    switch (event) {
      CASE_RETURN_STR(BAP_CONNECT_REQ_EVT)
      CASE_RETURN_STR(BAP_DISCONNECT_REQ_EVT)
      CASE_RETURN_STR(BAP_START_REQ_EVT)
      CASE_RETURN_STR(BAP_STOP_REQ_EVT)
      CASE_RETURN_STR(BAP_RECONFIG_REQ_EVT)
      CASE_RETURN_STR(BAP_STREAM_UPDATE_REQ_EVT)
      CASE_RETURN_STR(PACS_CONNECTION_STATE_EVT)
      CASE_RETURN_STR(PACS_DISCOVERY_RES_EVT)
      CASE_RETURN_STR(PACS_AUDIO_CONTEXT_RES_EVT)
      CASE_RETURN_STR(ASCS_CONNECTION_STATE_EVT)
      CASE_RETURN_STR(ASCS_DISCOVERY_RES_EVT)
      CASE_RETURN_STR(ASCS_ASE_STATE_EVT)
      CASE_RETURN_STR(ASCS_ASE_OP_FAILED_EVT)
      CASE_RETURN_STR(CIS_GROUP_STATE_EVT)
      CASE_RETURN_STR(CIS_STATE_EVT)
      CASE_RETURN_STR(BAP_TIME_OUT_EVT)
      default:
       return "Unknown Event";
    }
  }

 private:
   RawAddress address;
   PacsClient *pacs_client;
   uint16_t pacs_client_id;
   AscsClient *ascs_client;
   ConnectionState pacs_state;
   CisInterface *cis_intf;
   GattState ascs_state;
   StreamOpsQueue ops_queue;
   UcastAudioStreams audio_streams;
   StreamTrackers stream_trackers;
   StreamContexts stream_contexts;
   GattPendingData gatt_pending_data;
   UcastClientCallbacks* ucl_callbacks;
   BapAlarm *bap_alarm;
   DeviceType dev_type;
};

class UstreamManagers {
 public:
  UstreamManager* FindByAddress(const RawAddress& address);

  UstreamManager* FindorAddByAddress(const RawAddress& address,
                  PacsClient *pacs_client, uint16_t pacs_client_id,
                  AscsClient *ascs_client, CisInterface *cis_intf,
                  UcastClientCallbacks* callbacks, BapAlarm* bap_alarm);


  std::vector<UstreamManager *> *GetAllManagers();

  void Remove(const RawAddress& address);

  size_t size() { return (strm_mgrs.size()); }

  std::vector<UstreamManager *> strm_mgrs;
};

}  // namespace ucast
}  // namespace bap
}  // namespace bluetooth
