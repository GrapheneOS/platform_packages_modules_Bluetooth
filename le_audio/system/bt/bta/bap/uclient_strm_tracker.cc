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


#include "bta_bap_uclient_api.h"
#include "ucast_client_int.h"
#include "bt_trace.h"
#include "btif/include/btif_bap_codec_utils.h"
#include "osi/include/properties.h"
#include "uclient_alarm.h"

namespace bluetooth {
namespace bap {
namespace ucast {

using bluetooth::bap::pacs::CodecIndex;
using bluetooth::bap::pacs::CodecBPS;
using bluetooth::bap::pacs::CodecConfig;
using bluetooth::bap::pacs::ConnectionState;
using bluetooth::bap::pacs::CodecSampleRate;
using bluetooth::bap::pacs::CodecChannelMode;
using bluetooth::bap::pacs::PacsClient;
using bluetooth::bap::cis::CisInterface;
using bluetooth::bap::ascs::AseCodecConfigOp;
using bluetooth::bap::ascs::AseQosConfigOp;
using bluetooth::bap::ascs::AseEnableOp;
using bluetooth::bap::ascs::AseStartReadyOp;
using bluetooth::bap::ascs::AseStopReadyOp;
using bluetooth::bap::ascs::AseDisableOp;
using bluetooth::bap::ascs::AseReleaseOp;
using bluetooth::bap::ascs::AseUpdateMetadataOp;

using cis::IsoHciStatus;
using bluetooth::bap::alarm::BapAlarm;

using bluetooth::bap::ucast::CONTENT_TYPE_MEDIA;
using bluetooth::bap::ucast::CONTENT_TYPE_CONVERSATIONAL;
using bluetooth::bap::ucast::CONTENT_TYPE_UNSPECIFIED;
using bluetooth::bap::ucast::CONTENT_TYPE_GAME;

constexpr uint8_t  LTV_TYPE_SAMP_FREQ           = 0X01;
constexpr uint8_t  LTV_TYPE_FRAME_DUR           = 0x02;
constexpr uint8_t  LTV_TYPE_CHNL_ALLOC          = 0x03;
constexpr uint8_t  LTV_TYPE_OCTS_PER_FRAME      = 0X04;
constexpr uint8_t  LTV_TYPE_FRAMES_PER_SDU      = 0X05;
constexpr uint8_t  LTV_TYPE_STRM_AUDIO_CONTEXTS = 0x02;

constexpr uint8_t  LTV_LEN_SAMP_FREQ            = 0X02;
constexpr uint8_t  LTV_LEN_FRAME_DUR            = 0x02;
constexpr uint8_t  LTV_LEN_CHNL_ALLOC           = 0x05;
constexpr uint8_t  LTV_LEN_OCTS_PER_FRAME       = 0X03;
constexpr uint8_t  LTV_LEN_FRAMES_PER_SDU       = 0X02;
constexpr uint8_t  LTV_LEN_STRM_AUDIO_CONTEXTS  = 0x03;

constexpr uint8_t  LTV_VAL_SAMP_FREQ_8K         = 0X01;
//constexpr uint8_t  LTV_VAL_SAMP_FREQ_11K        = 0X02;
constexpr uint8_t  LTV_VAL_SAMP_FREQ_16K        = 0X03;
//constexpr uint8_t  LTV_VAL_SAMP_FREQ_22K        = 0X04;
constexpr uint8_t  LTV_VAL_SAMP_FREQ_24K        = 0X05;
constexpr uint8_t  LTV_VAL_SAMP_FREQ_32K        = 0X06;
constexpr uint8_t  LTV_VAL_SAMP_FREQ_441K       = 0X07;
constexpr uint8_t  LTV_VAL_SAMP_FREQ_48K        = 0X08;
constexpr uint8_t  LTV_VAL_SAMP_FREQ_882K       = 0X09;
constexpr uint8_t  LTV_VAL_SAMP_FREQ_96K        = 0X0A;
constexpr uint8_t  LTV_VAL_SAMP_FREQ_176K       = 0X0B;
constexpr uint8_t  LTV_VAL_SAMP_FREQ_192K       = 0X0C;
//constexpr uint8_t  LTV_VAL_SAMP_FREQ_384K       = 0X0D;

constexpr uint8_t  LC3_CODEC_ID          = 0x06;
constexpr uint8_t  ASCS_CLIENT_ID        = 0x01;

constexpr uint8_t  TGT_LOW_LATENCY       = 0x01;
constexpr uint8_t  TGT_BAL_LATENCY       = 0x02;
constexpr uint8_t  TGT_HIGH_RELIABLE     = 0x03;

std::map<CodecSampleRate, uint8_t> freq_to_ltv_map = {
  {CodecSampleRate::CODEC_SAMPLE_RATE_8000,   LTV_VAL_SAMP_FREQ_8K   },
  {CodecSampleRate::CODEC_SAMPLE_RATE_16000,  LTV_VAL_SAMP_FREQ_16K  },
  {CodecSampleRate::CODEC_SAMPLE_RATE_24000,  LTV_VAL_SAMP_FREQ_24K  },
  {CodecSampleRate::CODEC_SAMPLE_RATE_32000,  LTV_VAL_SAMP_FREQ_32K  },
  {CodecSampleRate::CODEC_SAMPLE_RATE_44100,  LTV_VAL_SAMP_FREQ_441K },
  {CodecSampleRate::CODEC_SAMPLE_RATE_48000,  LTV_VAL_SAMP_FREQ_48K  },
  {CodecSampleRate::CODEC_SAMPLE_RATE_88200,  LTV_VAL_SAMP_FREQ_882K },
  {CodecSampleRate::CODEC_SAMPLE_RATE_96000,  LTV_VAL_SAMP_FREQ_96K  },
  {CodecSampleRate::CODEC_SAMPLE_RATE_176400, LTV_VAL_SAMP_FREQ_176K },
  {CodecSampleRate::CODEC_SAMPLE_RATE_192000, LTV_VAL_SAMP_FREQ_192K }
};

std::list<uint8_t> directions = {
  cis::DIR_FROM_AIR,
  cis::DIR_TO_AIR
};

std::vector<uint32_t> locations = {
  AUDIO_LOC_LEFT,
  AUDIO_LOC_RIGHT
};

// common functions used from Stream tracker state Handlers
uint8_t StreamTracker::ChooseBestCodec(StreamType stream_type,
                              std::vector<CodecQosConfig> *codec_qos_configs,
                              PacsDiscovery *pacs_discovery) {
  bool codec_found = false;
  uint8_t index = 0;
  // check the stream direction, based on direction look for
  // matching record from preferred list of upper layer and
  // remote device sink or src pac records
  std::vector<CodecConfig> *pac_records = nullptr;
  if(stream_type.direction == ASE_DIRECTION_SINK) {
    pac_records = &pacs_discovery->sink_pac_records;
  } else if(stream_type.direction == ASE_DIRECTION_SRC) {
    pac_records = &pacs_discovery->src_pac_records;
  }

  if (!pac_records) {
     LOG(ERROR) << __func__ << "pac_records is null";
     return 0xFF;
  }
  DeviceType dev_type = strm_mgr_->GetDevType();
  for (auto i = codec_qos_configs->begin(); i != codec_qos_configs->end()
                                          ; i++, index++) {
    if(dev_type == DeviceType::EARBUD ||
       dev_type == DeviceType::HEADSET_STEREO) {
      if((*i).qos_config.ascs_configs.size() != 1) continue;
    } else if(dev_type == DeviceType::HEADSET_SPLIT_STEREO) {
      if((*i).qos_config.ascs_configs.size() != 2) continue;
    }
    for (auto j = pac_records->begin();
                    j != pac_records->end();j++) {
      CodecConfig *src = &((*i).codec_config);
      CodecConfig *dst = &(*j);
      if (IsCodecConfigEqual(src,dst)) {
        LOG(WARNING) << __func__ << ": Checking for matching Codec";
        if (GetLc3QPreference(src) &&
            GetCapaVendorMetaDataLc3QPref(dst)) {
          LOG(INFO) << __func__ << ": Matching Codec LC3Q Found "
                   << ", for direction: " << loghex(stream_type.direction);
          uint8_t lc3qVer = GetCapaVendorMetaDataLc3QVer(dst);
          UpdateVendorMetaDataLc3QPref(src, true);
          UpdateVendorMetaDataLc3QVer(src, lc3qVer);
        } else {
          LOG(INFO) << __func__ << ": LC3Q not prefered, going with LC3 "
                   << "for direction: " << loghex(stream_type.direction);
        }
        codec_found = true;
        break;
      }
    }
    if(codec_found) break;
  }
  if(codec_found) return index;
  else return 0xFF;
}

// fine tuning the QOS params (RTN, MTL, PD) based on
// remote device preferences
bool StreamTracker::ChooseBestQos(QosConfig *src_config,
                                  ascs::AseCodecConfigParams *rem_qos_prefs,
                                  QosConfig *dst_config,
                                  int stream_state,
                                  uint8_t stream_direction) {
  uint8_t final_rtn = 0xFF;
  uint16_t final_mtl = 0xFFFF;
  uint32_t req_pd = (src_config->ascs_configs[0].presentation_delay[0] |
                     src_config->ascs_configs[0].presentation_delay[1] << 8 |
                     src_config->ascs_configs[0].presentation_delay[2] << 16);

  uint32_t rem_pd_min = (rem_qos_prefs->pd_min[0] |
                         rem_qos_prefs->pd_min[1] << 8 |
                         rem_qos_prefs->pd_min[2] << 16);

  uint32_t rem_pd_max = (rem_qos_prefs->pd_max[0] |
                         rem_qos_prefs->pd_max[1] << 8 |
                         rem_qos_prefs->pd_max[2] << 16);

  uint32_t rem_pref_pd_min = (rem_qos_prefs->pref_pd_min[0] |
                              rem_qos_prefs->pref_pd_min[1] << 8 |
                              rem_qos_prefs->pref_pd_min[2] << 16);

  uint32_t rem_pref_pd_max = (rem_qos_prefs->pref_pd_max[0] |
                              rem_qos_prefs->pref_pd_max[1] << 8 |
                              rem_qos_prefs->pref_pd_max[2] << 16);

  UcastAudioStreams *audio_strms = strm_mgr_->GetAudioStreams();
  std::vector<UcastAudioStream *> streams = audio_strms->FindByCigId(
                                 src_config->ascs_configs[0].cig_id,
                                 stream_state);

  // check if the RTN and MTL is with in the limits
  if(stream_direction == ASE_DIRECTION_SINK) {
    if(src_config->cis_configs[0].rtn_m_to_s > rem_qos_prefs->pref_rtn) {
      final_rtn = rem_qos_prefs->pref_rtn;
    }
    if(src_config->cig_config.max_tport_latency_m_to_s > rem_qos_prefs->mtl) {
      final_mtl = rem_qos_prefs->mtl;
    }
  } else if(stream_direction == ASE_DIRECTION_SRC) {
    if(src_config->cis_configs[0].rtn_s_to_m > rem_qos_prefs->pref_rtn) {
      final_rtn = rem_qos_prefs->pref_rtn;
    }
    if(src_config->cig_config.max_tport_latency_s_to_m > rem_qos_prefs->mtl) {
      final_mtl = rem_qos_prefs->mtl;
    }
  }

  LOG(INFO) << __func__  << " req_pd: " << loghex(req_pd)
               << " rem_pd_min: " << loghex(rem_pd_min)
               << " rem_pd_max: " << loghex(rem_pd_max)
               << " rem_pref_pd_min: " << loghex(rem_pref_pd_min)
               << " rem_pref_pd_max: " << loghex(rem_pref_pd_max);

  // check if PD is within the limits
  if(rem_pref_pd_min && rem_pref_pd_max) {
    if(req_pd < rem_pref_pd_min) {
      memcpy(&dst_config->ascs_configs[0].presentation_delay,
             &rem_qos_prefs->pref_pd_min,
             sizeof(dst_config->ascs_configs[0].presentation_delay));
    } else if(req_pd > rem_pref_pd_max) {
      memcpy(&dst_config->ascs_configs[0].presentation_delay,
             &rem_qos_prefs->pref_pd_max,
             sizeof(dst_config->ascs_configs[0].presentation_delay));
    }
  } else {
    if(req_pd != rem_pd_min) {
      memcpy(&dst_config->ascs_configs[0].presentation_delay,
             &rem_qos_prefs->pd_min,
             sizeof(dst_config->ascs_configs[0].presentation_delay));
    }
  }

  // check if anything to be updated for all streams
  if(final_rtn == 0xFF && final_mtl == 0XFFFF) {
    LOG(WARNING) << __func__  << " No fine tuning for QOS params";
    return true;
  } else if(final_rtn != 0xFF) {
    LOG(WARNING) << __func__  << " Updated RTN to " << loghex(final_rtn);
  } else if(final_mtl != 0XFFFF) {
    LOG(WARNING) << __func__  << " Updated MTL to " << loghex(final_mtl);
  }

  for (auto i = streams.begin(); i != streams.end();i++) {
    UcastAudioStream *stream = (*i);
    if(stream_direction == ASE_DIRECTION_SINK) {
      if(final_mtl != 0xFFFF) {
        stream->qos_config.cig_config.max_tport_latency_m_to_s = final_mtl;
      }
      if(final_rtn != 0xFF) {
        for (auto it = stream->qos_config.cis_configs.begin();
                          it != stream->qos_config.cis_configs.end(); it++) {
          (*it).rtn_m_to_s = final_rtn;
        }
      }
    } else if(stream_direction == ASE_DIRECTION_SRC) {
      if(final_mtl != 0xFFFF) {
        stream->qos_config.cig_config.max_tport_latency_s_to_m = final_mtl;
      }
      if(final_rtn != 0xFF) {
        for (auto it = stream->qos_config.cis_configs.begin();
                          it != stream->qos_config.cis_configs.end(); it++) {
          (*it).rtn_s_to_m = final_rtn;
        }
      }
    }
  }
  return true;
}

bool StreamTracker::HandlePacsConnectionEvent(void *p_data) {
  PacsConnectionState *pacs_state =  (PacsConnectionState *) p_data;
  if(pacs_state->state == ConnectionState::CONNECTED) {
    LOG(INFO) << __func__ << " PACS server connected";
  } else if(pacs_state->state == ConnectionState::DISCONNECTED) {
    HandleInternalDisconnect(false);
  }
  return true;
}

bool StreamTracker::HandlePacsAudioContextEvent(
                               PacsAvailableContexts *pacs_contexts) {
  std::vector<StreamUpdate> *update_streams = GetMetaUpdateStreams();
  uint8_t contexts_supported = 0;

  // check if supported audio contexts has required contexts
  for(auto it = update_streams->begin(); it != update_streams->end(); it++) {
    if(it->update_type == StreamUpdateType::STREAMING_CONTEXT) {
      if(it->stream_type.direction == ASE_DIRECTION_SINK) {
        if(it->update_value & pacs_contexts->available_contexts) {
          contexts_supported++;
        }
      } else if(it->stream_type.direction == ASE_DIRECTION_SRC) {
        if((static_cast<uint64_t>(it->update_value) << 16) &
             pacs_contexts->available_contexts) {
          contexts_supported++;
        }
      }
    }
  }

  if(contexts_supported != update_streams->size()) {
    LOG(ERROR) << __func__  << ": No Matching available Contexts found";
    return false;
  } else {
    return true;
  }
}

bool StreamTracker::HandleCisEventsInStreaming(void* p_data) {
  CisStreamState *data = (CisStreamState *) p_data;
  UcastAudioStreams *audio_strms = strm_mgr_->GetAudioStreams();
  if(data->state == CisState::READY) {
    for(auto it = directions.begin(); it != directions.end(); ++it) {
      if(data->direction & *it) {
        // find out the stream here
        UcastAudioStream *stream = audio_strms->FindByCisIdAndDir
                                   (data->cig_id, data->cis_id, *it);
        if(stream) {
          stream->cis_state = data->state;
          stream->cis_pending_cmd = CisPendingCmd::NONE;
        }
      }
    }
    TransitionTo(StreamTracker::kStateStopping);
  }
  return true;
}

bool StreamTracker::HandleAscsConnectionEvent(void *p_data) {
  AscsConnectionState *ascs_state =  (AscsConnectionState *) p_data;
  if(ascs_state->state == GattState::CONNECTED) {
    LOG(INFO) << __func__ << "ASCS server connected";
  } else if(ascs_state->state == GattState::DISCONNECTED) {
    // make all streams ASE state ot idle so that further processing
    // can happen
    UcastAudioStreams *audio_strms = strm_mgr_->GetAudioStreams();
    std::vector<UcastAudioStream *> *strms_list = audio_strms->GetAllStreams();

    for (auto it = strms_list->begin(); it != strms_list->end(); it++) {
      (*it)->ase_state = ascs::ASE_STATE_IDLE;
      (*it)->ase_pending_cmd = AscsPendingCmd::NONE;
      (*it)->overall_state = StreamTracker::kStateIdle;
    }
    HandleInternalDisconnect(false);
  }
  return true;
}

bool StreamTracker::ValidateAseUpdate(void* p_data,
                                      IntStrmTrackers *int_strm_trackers,
                                      int exp_strm_state) {
  AscsState *ascs =  ((AscsState *) p_data);

  uint8_t ase_id = ascs->ase_params.ase_id;

  // check if current stream tracker is interested in this ASE update
  if(int_strm_trackers->FindByAseId(ase_id)
                             == nullptr) {
    LOG(INFO) << __func__  << "Not intended for this tracker";
    return false;
  }

  // find out the stream for the given ase id
  UcastAudioStreams *audio_strms = strm_mgr_->GetAudioStreams();

  UcastAudioStream *stream = audio_strms->FindByAseId(ase_id);

  LOG(INFO) << __func__  << ": Streams Size = " << audio_strms->size()
                         << ": ASE Id = " << loghex(ase_id);

  if (stream == nullptr || stream->overall_state != exp_strm_state) {
    LOG(WARNING) << __func__  << "No Audio Stream found";
    return false;
  }

  stream->ase_state = ascs->ase_params.ase_state;
  stream->ase_params = ascs->ase_params;
  stream->ase_pending_cmd = AscsPendingCmd::NONE;
  return true;
}

bool StreamTracker::HandleRemoteDisconnect(uint32_t event,
                                           void* p_data, int cur_state) {
  UpdateControlType(StreamControlType::Disconnect);
  std::vector<StreamType> streams;

  switch(cur_state) {
    case StreamTracker::kStateConnecting: {
      std::vector<StreamConnect> *conn_streams = GetConnStreams();

      for (auto it = conn_streams->begin(); it != conn_streams->end(); it++) {
        StreamType type = it->stream_type;
        streams.push_back(type);
      }
      UpdateStreams(&streams);
    } break;
    case StreamTracker::kStateReconfiguring: {
      std::vector<StreamReconfig> *reconf_streams = GetReconfStreams();

      for (auto it = reconf_streams->begin();
                           it != reconf_streams->end(); it++) {
        StreamType type = it->stream_type;
        streams.push_back(type);
      }
      UpdateStreams(&streams);
    } break;
  }

  // update the state to disconnecting
  TransitionTo(StreamTracker::kStateDisconnecting);
  ProcessEvent(event, p_data);
  return true;
}

bool StreamTracker::StreamCanbeDisconnected(StreamContext *cur_context,
                                            uint8_t ase_id) {
  bool can_be_disconnected = false;
  StreamContexts *contexts = strm_mgr_->GetStreamContexts();
  StreamAttachedState state = (StreamAttachedState)
               (static_cast<uint8_t> (StreamAttachedState::PHYSICAL) |
                static_cast<uint8_t> (StreamAttachedState::IDLE_TO_PHY) |
                static_cast<uint8_t> (StreamAttachedState::VIR_TO_PHY));

  std::vector<StreamContext *> attached_contexts =
                 contexts->FindByAseAttachedState(ase_id, state);

  LOG(INFO) << __func__ <<": attached_contexts: size : "
                        << attached_contexts.size();
  if(cur_context->attached_state == StreamAttachedState::PHYSICAL ||
     cur_context->attached_state == StreamAttachedState::IDLE_TO_PHY ||
     cur_context->attached_state == StreamAttachedState::VIR_TO_PHY ) {
    can_be_disconnected = true;
  }
  return can_be_disconnected;
}

bool StreamTracker::HandleInternalDisconnect(bool release) {

  UpdateControlType(StreamControlType::Disconnect);

  std::vector<StreamType> streams;

  int cur_state = StateId();
  LOG(WARNING) << __func__ <<": cur_state: " << cur_state
                           <<", release: " << release;
  switch(cur_state) {
    case StreamTracker::kStateConnecting: {
      std::vector<StreamConnect> *conn_streams = GetConnStreams();

      for (auto it = conn_streams->begin(); it != conn_streams->end(); it++) {
        StreamType type = it->stream_type;
        streams.push_back(type);
      }
      UpdateStreams(&streams);
    } break;
    case StreamTracker::kStateReconfiguring: {
      std::vector<StreamReconfig> *reconf_streams = GetReconfStreams();

      for (auto it = reconf_streams->begin();
                           it != reconf_streams->end(); it++) {
        StreamType type = it->stream_type;
        streams.push_back(type);
      }
      UpdateStreams(&streams);
    } break;
  }

  if (release) {
    StreamContexts *contexts = strm_mgr_->GetStreamContexts();
    AscsClient *ascs_client = strm_mgr_->GetAscsClient();
    UcastAudioStreams *audio_strms = strm_mgr_->GetAudioStreams();
    std::vector<AseReleaseOp> ase_ops;
    std::vector<StreamType> *disc_streams = GetStreams();

    for (auto it = disc_streams->begin(); it != disc_streams->end(); it++) {
      StreamContext *context = contexts->FindOrAddByType(*it);

      for (auto id = context->stream_ids.begin();
                         id != context->stream_ids.end(); id++) {

        UcastAudioStream *stream = audio_strms->FindByAseId(id->ase_id);
        bool can_be_disconnected = StreamCanbeDisconnected(context, id->ase_id);
        if (can_be_disconnected &&
            stream && stream->overall_state == cur_state &&
            stream->ase_state != ascs::ASE_STATE_IDLE &&
            stream->ase_state != ascs::ASE_STATE_RELEASING &&
            stream->ase_pending_cmd != AscsPendingCmd::RELEASE_ISSUED) {
          LOG(WARNING) << __func__
                     <<": ASE State : " << loghex(stream->ase_state);
          AseReleaseOp release_op = {
                                      .ase_id = stream->ase_id
                                    };
          ase_ops.push_back(release_op);
          stream->ase_pending_cmd = AscsPendingCmd::RELEASE_ISSUED;
          // change the overall state to Disconnecting
          stream->overall_state = StreamTracker::kStateDisconnecting;
        }
      }
    }

    // send consolidated release command to ASCS client
    if(ase_ops.size()) {
      LOG(WARNING) << __func__  << ": Going For ASCS Release op";
      ascs_client->Release(ASCS_CLIENT_ID, strm_mgr_->GetAddress(), ase_ops);
    }
  }
  // update the state to disconnecting
  TransitionTo(StreamTracker::kStateDisconnecting);
  return true;
}

bool StreamTracker::HandleRemoteStop(uint32_t event,
                                           void* p_data, int cur_state) {
  AscsState *ascs =  ((AscsState *) p_data);
  uint8_t ase_id = ascs->ase_params.ase_id;
  UcastAudioStreams *audio_strms = strm_mgr_->GetAudioStreams();
  UcastAudioStream *stream = audio_strms->FindByAseId(ase_id);

  if(!stream) return false;

  if(stream->direction & cis::DIR_TO_AIR) {
    LOG(ERROR) << __func__  << ": Invalid State transition to Disabling"
               << ": ASE Id = " << loghex(ase_id);
    return false;
  }

  UpdateControlType(StreamControlType::Stop);

  if(cur_state != StreamTracker::kStateStarting ||
     cur_state != StreamTracker::kStateStreaming) {
    return false;
  }
  // update the state to stopping
  TransitionTo(StreamTracker::kStateStopping);
  ProcessEvent(event, p_data);
  return true;
}

bool StreamTracker::HandleAbruptStop(uint32_t event, void* p_data) {
  AscsState *ascs =  ((AscsState *) p_data);
  uint8_t ase_id = ascs->ase_params.ase_id;
  UcastAudioStreams *audio_strms = strm_mgr_->GetAudioStreams();
  UcastAudioStream *stream = audio_strms->FindByAseId(ase_id);

  if(!stream) return false;
  stream->ase_pending_cmd = AscsPendingCmd::NONE;

  UpdateControlType(StreamControlType::Stop);

  // update the state to stopping
  TransitionTo(StreamTracker::kStateStopping);
  return true;
}

bool StreamTracker::HandleRemoteReconfig(uint32_t event,
                                           void* p_data, int cur_state) {
  UpdateControlType(StreamControlType::Reconfig);
  std::vector<StreamType> streams;

  if(cur_state != StreamTracker::kStateConnected) {
    return false;
  }
  // update the state to Reconfiguring
  TransitionTo(StreamTracker::kStateReconfiguring);
  ProcessEvent(event, p_data);
  return true;
}

void StreamTracker::HandleAseOpFailedEvent(void *p_data) {
  AscsOpFailed *ascs_op =  ((AscsOpFailed *) p_data);
  std::vector<ascs::AseOpStatus> *ase_list = &ascs_op->ase_list;
  UcastAudioStreams *audio_strms = strm_mgr_->GetAudioStreams();

  if(ascs_op->ase_op_id == ascs::AseOpId::CODEC_CONFIG) {
    // treat it like internal failure
    for (auto i = ase_list->begin(); i != ase_list->end();i++) {
      UcastAudioStream *stream = audio_strms->FindByAseId((i)->ase_id);
      if(stream) {
        stream->ase_pending_cmd = AscsPendingCmd::NONE;
        stream->overall_state = StreamTracker::kStateIdle;
      }
    }
    HandleInternalDisconnect(false);
  } else {
    HandleInternalDisconnect(true);
  }
}

void StreamTracker::HandleAseStateEvent(void *p_data,
                                        StreamControlType control_type,
                                        IntStrmTrackers *int_strm_trackers) {
  // check the state and if the state is codec configured for all ASEs
  // then proceed with group creation
  AscsState *ascs =  reinterpret_cast<AscsState *> (p_data);

  uint8_t ase_id = ascs->ase_params.ase_id;

  // check if current stream tracker is interested in this ASE update
  if(int_strm_trackers->FindByAseId(ase_id) == nullptr) {
    LOG(INFO) << __func__ << ": Not intended for this tracker";
    return;
  }

  UcastAudioStreams *audio_strms = strm_mgr_->GetAudioStreams();

  UcastAudioStream *stream = audio_strms->FindByAseId(ase_id);

  if(stream == nullptr) {
    return;
  } else {
    stream->ase_state = ascs->ase_params.ase_state;
    stream->ase_params = ascs->ase_params;
    stream->ase_pending_cmd = AscsPendingCmd::NONE;
  }

  if(ascs->ase_params.ase_state == ascs::ASE_STATE_CODEC_CONFIGURED) {
    stream->pref_qos_params = ascs->ase_params.codec_config_params;
    // find out the stream for the given ase id
    LOG(INFO) << __func__  << ": Total Num Streams = " << audio_strms->size()
                           << ": ASE Id = " << loghex(ase_id);

    // decide on best QOS params by comparing the upper layer prefs
    // and remote dev's preferences
    int state = StreamTracker::kStateIdle;

    if(control_type == StreamControlType::Connect) {
      state = StreamTracker::kStateConnecting;
    } else if(control_type == StreamControlType::Reconfig) {
      state = StreamTracker::kStateReconfiguring;
    }

    // check for all trackers codec is configured or not
    std::vector<IntStrmTracker *> *all_trackers =
                        int_strm_trackers->GetTrackerList();
    uint8_t num_codec_configured = 0;
    for (auto i = all_trackers->begin(); i != all_trackers->end();i++) {
      UcastAudioStream *stream = audio_strms->FindByAseId((*i)->ase_id);
      if (!stream) {
        LOG(ERROR) << __func__  << "stream is null";
        continue;
      }
      if(stream->ase_pending_cmd == AscsPendingCmd::NONE &&
         (stream->ase_state == ascs::ASE_STATE_CODEC_CONFIGURED ||
         (control_type == StreamControlType::Reconfig &&
          stream->ase_state == ascs::ASE_STATE_QOS_CONFIGURED))) {
        num_codec_configured++;
      }
    }

    if(int_strm_trackers->size() != num_codec_configured) {
      LOG(WARNING) << __func__  << " Codec Not Configured For All Streams";
      return;
    }

    // check for all streams together so that final group params
    // will be decided
    for (auto i = all_trackers->begin(); i != all_trackers->end();i++) {
      UcastAudioStream *stream = audio_strms->FindByAseId((*i)->ase_id);
      if (stream) {
        ChooseBestQos(&stream->req_qos_config, &stream->pref_qos_params,
                    &stream->qos_config, state, stream->direction);
      }
    }
    CheckAndSendQosConfig(int_strm_trackers);

  } else if(ascs->ase_params.ase_state == ascs::ASE_STATE_QOS_CONFIGURED) {
    // TODO update the state as connected using callbacks
    // make the state transition to connected

    // check for all trackers QOS is configured or not
    // if so update it as streams are connected
    std::vector<IntStrmTracker *> *all_trackers =
                        int_strm_trackers->GetTrackerList();
    uint8_t num_qos_configured = 0;
    for (auto i = all_trackers->begin(); i != all_trackers->end();i++) {
      UcastAudioStream *stream = audio_strms->FindByAseId((*i)->ase_id);
      if(stream && stream->ase_state == ascs::ASE_STATE_QOS_CONFIGURED &&
         stream->ase_pending_cmd == AscsPendingCmd::NONE) {
        num_qos_configured++;
      }
    }

    if(int_strm_trackers->size() != num_qos_configured) {
      LOG(WARNING) << __func__  << " QOS Not Configured For All Streams";
      return;
    }

    for (auto i = all_trackers->begin(); i != all_trackers->end();i++) {
      UcastAudioStream *stream = audio_strms->FindByAseId((*i)->ase_id);
      if (!stream) {
        LOG(ERROR) << __func__  << "stream is null";
        continue;
      }
      StreamContexts *contexts = strm_mgr_->GetStreamContexts();
      StreamContext *context = contexts->FindOrAddByType(
                                         (*i)->strm_type);
      if(context->attached_state == StreamAttachedState::IDLE_TO_PHY ||
         context->attached_state == StreamAttachedState::VIR_TO_PHY) {
        context->attached_state = StreamAttachedState::PHYSICAL;
        LOG(INFO) << __func__  << " Attached state made physical";
      }
      stream->overall_state = kStateConnected;
    }

    // update the state to connected
    TransitionTo(StreamTracker::kStateConnected);

  } else if(ascs->ase_params.ase_state == ascs::ASE_STATE_RELEASING) {
    HandleRemoteDisconnect(ASCS_ASE_STATE_EVT, p_data, StateId());
  }
}

bool StreamTracker::HandleStreamUpdate (int cur_state) {
  StreamContexts *contexts = strm_mgr_->GetStreamContexts();
  AscsClient *ascs_client = strm_mgr_->GetAscsClient();
  UcastAudioStreams *audio_strms = strm_mgr_->GetAudioStreams();

  std::vector<AseUpdateMetadataOp> ase_meta_ops;
  std::vector<StreamUpdate> *update_streams = GetMetaUpdateStreams();

  for (auto it = update_streams->begin();
                       it != update_streams->end(); it++) {
    StreamContext *context = contexts->FindOrAddByType(it->stream_type);

    for (auto id = context->stream_ids.begin();
              id != context->stream_ids.end(); id++) {
      std::vector<uint8_t> meta_data;
      UcastAudioStream *stream = audio_strms->FindByAseId(id->ase_id);
      if(stream && stream->ase_state != ascs::ASE_STATE_ENABLING &&
         stream->ase_state != ascs::ASE_STATE_STREAMING) {
        continue;
      }
      if(it->update_type == StreamUpdateType::STREAMING_CONTEXT) {
        uint8_t len = LTV_LEN_STRM_AUDIO_CONTEXTS;
        uint8_t type = LTV_TYPE_STRM_AUDIO_CONTEXTS;
        uint16_t value = it->update_value;
        if(stream) stream->audio_context = value;
        meta_data.insert(meta_data.end(), &len, &len + 1);
        meta_data.insert(meta_data.end(), &type, &type + 1);
        meta_data.insert(meta_data.end(), ((uint8_t *)&value),
                              ((uint8_t *)&value) + sizeof(uint16_t));
      }

      AseUpdateMetadataOp meta_op = {
                            .ase_id = id->ase_id,
                            .meta_data_len =
                             static_cast <uint8_t> (meta_data.size()),
                            .meta_data = meta_data // media or voice
                          };
      ase_meta_ops.push_back(meta_op);
    }
  }

  // send consolidated update meta command to ASCS client
  if(ase_meta_ops.size()) {
    LOG(WARNING) << __func__  << ": Going For ASCS Update MetaData op";
    ascs_client->UpdateStream(ASCS_CLIENT_ID, strm_mgr_->GetAddress(),
                              ase_meta_ops);
  } else {
    return false;
  }

  if(cur_state == StreamTracker::kStateUpdating) {
    for (auto it = update_streams->begin();
                         it != update_streams->end(); it++) {
      StreamContext *context = contexts->FindOrAddByType(it->stream_type);
      for (auto id = context->stream_ids.begin();
                    id != context->stream_ids.end(); id++) {
        UcastAudioStream *stream = audio_strms->FindByAseId(id->ase_id);
        if (stream != nullptr) {
          // change the connection state to disable issued
          stream->ase_pending_cmd = AscsPendingCmd::UPDATE_METADATA_ISSUED;
          // change the overall state to Updating
          stream->overall_state = StreamTracker::kStateUpdating;
        }
      }
    }
  }
  return true;
}

bool StreamTracker::HandleStop(void* p_data, int cur_state) {
  if(p_data != nullptr) {
    BapStop *evt_data = (BapStop *) p_data;
    UpdateStreams(&evt_data->streams);
  }
  UpdateControlType(StreamControlType::Stop);

  StreamContexts *contexts = strm_mgr_->GetStreamContexts();
  AscsClient *ascs_client = strm_mgr_->GetAscsClient();
  UcastAudioStreams *audio_strms = strm_mgr_->GetAudioStreams();

  std::vector<AseDisableOp> ase_ops;
  std::vector<StreamType> *stop_streams = GetStreams();

  for (auto it = stop_streams->begin();
                       it != stop_streams->end(); it++) {
    StreamContext *context = contexts->FindOrAddByType(*it);

    for (auto id = context->stream_ids.begin();
                         id != context->stream_ids.end(); id++) {
      AseDisableOp disable_op = {
                          .ase_id = id->ase_id
      };
      ase_ops.push_back(disable_op);
    }
  }

  // send consolidated disable command to ASCS client
  if(ase_ops.size()) {
    LOG(WARNING) << __func__  << ": Going For ASCS Disable op";
    ascs_client->Disable(ASCS_CLIENT_ID, strm_mgr_->GetAddress(), ase_ops);
  }

  for (auto it = stop_streams->begin();
                       it != stop_streams->end(); it++) {
    StreamContext *context = contexts->FindOrAddByType(*it);
    for (auto id = context->stream_ids.begin();
                  id != context->stream_ids.end(); id++) {
      UcastAudioStream *stream = audio_strms->FindByAseId(id->ase_id);
      if (stream != nullptr && stream->overall_state == cur_state) {
        // change the connection state to disable issued
        stream->ase_pending_cmd = AscsPendingCmd::DISABLE_ISSUED;
        // change the overall state to stopping
        stream->overall_state = StreamTracker::kStateStopping;
      }
    }
  }
  TransitionTo(StreamTracker::kStateStopping);
  return true;
}

bool StreamTracker::HandleDisconnect(void* p_data, int cur_state) {
  // expect the disconnection for same set of streams connection
  // has initiated ex: if connect is issued for media (tx), voice(tx & rx)
  // then disconnect is expected for media (tx), voice(tx & rx).
  UcastAudioStreams *audio_strms = strm_mgr_->GetAudioStreams();

  BapDisconnect *evt_data = (BapDisconnect *) p_data;

  UpdateControlType(StreamControlType::Disconnect);

  UpdateStreams(&evt_data->streams);

  StreamContexts *contexts = strm_mgr_->GetStreamContexts();
  AscsClient *ascs_client = strm_mgr_->GetAscsClient();

  std::vector<AseReleaseOp> ase_ops;
  std::vector<StreamType> *disc_streams = GetStreams();

  for (auto it = disc_streams->begin(); it != disc_streams->end(); it++) {
    StreamContext *context = contexts->FindOrAddByType(*it);

    for (auto id = context->stream_ids.begin();
                  id != context->stream_ids.end(); id++) {
      UcastAudioStream *stream = audio_strms->FindByAseId(id->ase_id);
      bool can_be_disconnected = StreamCanbeDisconnected(context, id->ase_id);
      if(can_be_disconnected &&
         stream && stream->overall_state != StreamTracker::kStateIdle &&
         stream->overall_state != StreamTracker::kStateDisconnecting &&
         stream->ase_pending_cmd != AscsPendingCmd::RELEASE_ISSUED) {
        AseReleaseOp release_op = {
                                    .ase_id = id->ase_id
                                  };
        ase_ops.push_back(release_op);
        stream->ase_pending_cmd = AscsPendingCmd::RELEASE_ISSUED;
        // change the overall state to starting
        stream->overall_state = StreamTracker::kStateDisconnecting;
      }
    }
  }

  // send consolidated release command to ASCS client
  if(ase_ops.size()) {
    LOG(WARNING) << __func__  << ": Going For ASCS Release op";
    ascs_client->Release(ASCS_CLIENT_ID, strm_mgr_->GetAddress(), ase_ops);
  }

  TransitionTo(StreamTracker::kStateDisconnecting);
  return true;
}

void StreamTracker::CheckAndSendQosConfig(IntStrmTrackers *int_strm_trackers) {

  UcastAudioStreams *audio_strms = strm_mgr_->GetAudioStreams();
  AscsClient *ascs_client = strm_mgr_->GetAscsClient();
  // check for all trackers CIG is created or not
  // if so proceed with QOS config operaiton
  std::vector<IntStrmTracker *> *all_trackers =
                      int_strm_trackers->GetTrackerList();

  std::vector<AseQosConfigOp> ase_ops;
  for (auto i = all_trackers->begin(); i != all_trackers->end();i++) {
    UcastAudioStream *stream = audio_strms->FindByAseId((*i)->ase_id);
    QosConfig *qos_config = &stream->qos_config;
    if(!stream || stream->ase_pending_cmd != AscsPendingCmd::NONE) {
      continue;
    }
    if(stream->direction & cis::DIR_TO_AIR) {

      AseQosConfigOp qos_config_op = {
       .ase_id = (*i)->ase_id,
       .cig_id = stream->cig_id,
       .cis_id = stream->cis_id,
       .sdu_interval = { qos_config->cig_config.sdu_interval_m_to_s[0],
                         qos_config->cig_config.sdu_interval_m_to_s[1],
                         qos_config->cig_config.sdu_interval_m_to_s[2] },
       .framing = qos_config->cig_config.framing,
       .phy = LE_2M_PHY,
       .max_sdu_size = qos_config->cis_configs[(*i)->cis_id].max_sdu_m_to_s,
       .retrans_number = qos_config->cis_configs[(*i)->cis_id].rtn_m_to_s,
       .trans_latency = qos_config->cig_config.max_tport_latency_m_to_s,
       .present_delay = {qos_config->ascs_configs[0].presentation_delay[0],
                         qos_config->ascs_configs[0].presentation_delay[1],
                         qos_config->ascs_configs[0].presentation_delay[2]}
      };
      ase_ops.push_back(qos_config_op);

    } else if(stream->direction & cis::DIR_FROM_AIR) {
      AseQosConfigOp qos_config_op = {
       .ase_id = (*i)->ase_id,
       .cig_id = stream->cig_id,
       .cis_id = stream->cis_id,
       .sdu_interval = { qos_config->cig_config.sdu_interval_s_to_m[0],
                         qos_config->cig_config.sdu_interval_s_to_m[1],
                         qos_config->cig_config.sdu_interval_s_to_m[2] },
       .framing = qos_config->cig_config.framing,
       .phy = LE_2M_PHY,
       .max_sdu_size = qos_config->cis_configs[(*i)->cis_id].max_sdu_s_to_m,
       .retrans_number = qos_config->cis_configs[(*i)->cis_id].rtn_s_to_m,
       .trans_latency = qos_config->cig_config.max_tport_latency_s_to_m,
       .present_delay = {qos_config->ascs_configs[0].presentation_delay[0],
                         qos_config->ascs_configs[0].presentation_delay[1],
                         qos_config->ascs_configs[0].presentation_delay[2]}
      };
      ase_ops.push_back(qos_config_op);
    }
  }

  if(ase_ops.size()) {
    LOG(WARNING) << __func__  << ": Going For ASCS QosConfig op";
    ascs_client->QosConfig(ASCS_CLIENT_ID, strm_mgr_->GetAddress(), ase_ops);

    for (auto i = all_trackers->begin(); i != all_trackers->end();i++) {
      UcastAudioStream *stream = audio_strms->FindByAseId((*i)->ase_id);
      if(stream && stream->ase_pending_cmd == AscsPendingCmd::NONE)
        stream->ase_pending_cmd = AscsPendingCmd::QOS_CONFIG_ISSUED;
    }
  }
}


void StreamTracker::CheckAndSendEnable(IntStrmTrackers *int_strm_trackers) {

  UcastAudioStreams *audio_strms = strm_mgr_->GetAudioStreams();
  AscsClient *ascs_client = strm_mgr_->GetAscsClient();
  std::vector<StreamType> *start_streams = GetStreams();
  StreamContexts *contexts = strm_mgr_->GetStreamContexts();
  std::vector<AseEnableOp> ase_ops;
  // check for all trackers CIG is created or not
  // if so proceed with QOS config operaiton
  std::vector<IntStrmTracker *> *all_trackers =
                      int_strm_trackers->GetTrackerList();

  uint8_t num_cig_created = 0;

  for (auto i = all_trackers->begin(); i != all_trackers->end();i++) {
    UcastAudioStream *stream = audio_strms->FindByAseId((*i)->ase_id);
    if(stream && stream->cig_state == CigState::CREATED) {
      num_cig_created++;
    }
  }

  if(int_strm_trackers->size() != num_cig_created) {
    LOG(WARNING) << __func__  << " All CIGs are not created";
    return;
  }

  for(auto it = start_streams->begin(); it != start_streams->end(); it++) {
    StreamContext *context = contexts->FindOrAddByType(*it);
    for (auto id = context->stream_ids.begin();
              id != context->stream_ids.end(); id++) {
      std::vector<uint8_t> meta_data;
      UcastAudioStream *stream = audio_strms->FindByAseId(id->ase_id);
      uint8_t len = LTV_LEN_STRM_AUDIO_CONTEXTS;
      uint8_t type = LTV_TYPE_STRM_AUDIO_CONTEXTS;
      uint16_t value = (*it).audio_context;
      if(stream) stream->audio_context = value;
      meta_data.insert(meta_data.end(), &len, &len + 1);
      meta_data.insert(meta_data.end(), &type, &type + 1);
      meta_data.insert(meta_data.end(), ((uint8_t *)&value),
                              ((uint8_t *)&value) + sizeof(uint16_t));

      AseEnableOp enable_op = {
                            .ase_id = id->ase_id,
                            .meta_data_len =
                             static_cast <uint8_t> (meta_data.size()),
                            .meta_data = meta_data // media or voice
                          };
      ase_ops.push_back(enable_op);
    }
  }

  // send consolidated enable command to ASCS client
  if(ase_ops.size()) {
    LOG(WARNING) << __func__  << ": Going For ASCS Enable op";
    ascs_client->Enable(ASCS_CLIENT_ID, strm_mgr_->GetAddress(), ase_ops);

    for (auto it = start_streams->begin(); it != start_streams->end(); it++) {
      StreamContext *context = contexts->FindOrAddByType(*it);
      for (auto id = context->stream_ids.begin();
                id != context->stream_ids.end(); id++) {
        UcastAudioStream *stream = audio_strms->FindByAseId(id->ase_id);
        if (stream != nullptr && stream->overall_state ==
                               StreamTracker::kStateConnected) {
          // change the connection state to enable issued
          stream->ase_pending_cmd = AscsPendingCmd::ENABLE_ISSUED;
          // change the overall state to starting
          stream->overall_state = StreamTracker::kStateStarting;
        }
      }
    }
  }
}

void StreamTracker::HandleCigStateEvent(uint32_t event, void *p_data,
                                        IntStrmTrackers *int_strm_trackers) {
  // check if the associated CIG state is created
  // if so go for Enable Operation
  CisGroupState *data = ((CisGroupState *) p_data);

  // check if current stream tracker is interested in this CIG update
  std::vector<IntStrmTracker *> int_trackers =
                        int_strm_trackers->FindByCigId(data->cig_id);
  if(int_trackers.empty()) {
    LOG(INFO) << __func__  << " Not intended for this tracker";
    return;
  }

  UcastAudioStreams *audio_strms = strm_mgr_->GetAudioStreams();
  if(data->state == CigState::CREATED) {
    for (auto i = int_trackers.begin(); i != int_trackers.end();i++) {
      UcastAudioStream *stream = audio_strms->FindByAseId((*i)->ase_id);
      if(stream) {
        stream->cis_pending_cmd = CisPendingCmd::NONE;
        stream->cig_state = data->state;
        stream->cis_state = CisState::READY;
      }
    }
    CheckAndSendEnable(int_strm_trackers);
  } else if(data->state == CigState::IDLE) {
    // CIG state is idle means there is some failure
    LOG(ERROR) << __func__ << ": CIG Creation Failed";
    for (auto i = int_trackers.begin(); i != int_trackers.end();i++) {
      UcastAudioStream *stream = audio_strms->FindByAseId((*i)->ase_id);
      if(stream) {
        stream->cig_state = CigState::INVALID;
        stream->cis_state = CisState::INVALID;
        stream->cis_pending_cmd = CisPendingCmd::NONE;;
      }
    }
    HandleInternalDisconnect(false);
    return;
  }
}

bool StreamTracker::PrepareCodecConfigPayload(
                                 std::vector<AseCodecConfigOp> *ase_ops,
                                 UcastAudioStream *stream) {
  std::vector<uint8_t> codec_params;
  uint8_t tgt_latency = TGT_HIGH_RELIABLE;
  // check for sampling freq
  for (auto it : freq_to_ltv_map) {
    if(stream->codec_config.sample_rate == it.first) {
      uint8_t len = LTV_LEN_SAMP_FREQ;
      uint8_t type = LTV_TYPE_SAMP_FREQ;
      uint8_t rate = it.second;
      codec_params.insert(codec_params.end(), &len, &len + 1);
      codec_params.insert(codec_params.end(), &type, &type + 1);
      codec_params.insert(codec_params.end(), &rate, &rate + 1);
      break;
    }
  }

  // check for frame duration and fetch 5th byte
  uint8_t frame_duration = GetFrameDuration(&stream->codec_config);
  uint8_t len = LTV_LEN_FRAME_DUR;
  uint8_t type = LTV_TYPE_FRAME_DUR;
  codec_params.insert(codec_params.end(), &len, &len + 1);
  codec_params.insert(codec_params.end(), &type, &type + 1);
  codec_params.insert(codec_params.end(), &frame_duration,
                                          &frame_duration + 1);

  // audio chnl allcation
  if(stream->audio_location) {
    uint8_t len = LTV_LEN_CHNL_ALLOC;
    uint8_t type = LTV_TYPE_CHNL_ALLOC;
    uint32_t value = stream->audio_location;
    codec_params.insert(codec_params.end(), &len, &len + 1);
    codec_params.insert(codec_params.end(), &type, &type + 1);
    codec_params.insert(codec_params.end(), ((uint8_t *)&value),
                           ((uint8_t *)&value) + sizeof(uint32_t));
  }

  // octets per frame
  len = LTV_LEN_OCTS_PER_FRAME;
  type = LTV_TYPE_OCTS_PER_FRAME;
  uint16_t octs_per_frame = GetOctsPerFrame(&stream->codec_config);
  codec_params.insert(codec_params.end(), &len, &len + 1);
  codec_params.insert(codec_params.end(), &type, &type + 1);
  codec_params.insert(codec_params.end(), ((uint8_t *)&octs_per_frame),
                        ((uint8_t *)&octs_per_frame) + sizeof(uint16_t));

  // blocks per SDU
  len = LTV_LEN_FRAMES_PER_SDU;
  type = LTV_TYPE_FRAMES_PER_SDU;
  uint8_t blocks_per_sdu = GetLc3BlocksPerSdu(&stream->codec_config);
  // initialize it to 1 if it doesn't exists
  if(!blocks_per_sdu) {
    blocks_per_sdu = 1;
  }
  codec_params.insert(codec_params.end(), &len, &len + 1);
  codec_params.insert(codec_params.end(), &type, &type + 1);
  codec_params.insert(codec_params.end(), &blocks_per_sdu,
                                          &blocks_per_sdu + 1);

  if(stream->audio_context == CONTENT_TYPE_MEDIA) {
    tgt_latency = TGT_HIGH_RELIABLE;
  } else if(stream->audio_context == CONTENT_TYPE_CONVERSATIONAL) {
    tgt_latency = TGT_BAL_LATENCY;
  } else if(stream->audio_context == CONTENT_TYPE_GAME) {
    tgt_latency = TGT_LOW_LATENCY;
  }

  AseCodecConfigOp codec_config_op = {
                            .ase_id = stream->ase_id,
                            .tgt_latency =  tgt_latency,
                            .tgt_phy = LE_2M_PHY,
                            .codec_id = {LC3_CODEC_ID, 0, 0, 0, 0},
                            .codec_params_len =
                                static_cast <uint8_t> (codec_params.size()),
                            .codec_params = codec_params
  };
  ase_ops->push_back(codec_config_op);
  return true;
}

alarm_t* StreamTracker::SetTimer(const char* alarmname,
                  BapTimeout* timeout, TimeoutReason reason, uint64_t ms) {
  alarm_t* timer = nullptr;

  timeout->bd_addr = strm_mgr_->GetAddress();
  timeout->tracker = this;
  timeout->reason = reason;
  timeout->transition_state = StateId();

  BapAlarm* bap_alarm = strm_mgr_->GetBapAlarm();
  if (bap_alarm != nullptr) {
    timer = bap_alarm->Create(alarmname);
    if (timer == nullptr) {
      LOG(ERROR) << __func__ << ": Not able to create alarm";
      return nullptr;
    }
    LOG(INFO) << __func__ << ": starting " << alarmname;
    bap_alarm->Start(timer, ms, timeout);
  }
  return timer;
}

void StreamTracker::ClearTimer(alarm_t* timer, const char* alarmname) {
  BapAlarm* bap_alarm = strm_mgr_->GetBapAlarm();

  if (bap_alarm != nullptr && bap_alarm->IsScheduled(timer)) {
    LOG(INFO) << __func__ << ": clear " << alarmname;
    bap_alarm->Stop(timer);
  }
}

void StreamTracker::OnTimeout(void* data) {
  BapTimeout* timeout = (BapTimeout *)data;
  if (timeout == nullptr) {
    LOG(INFO) << __func__ << ": timeout data null, return ";
    return;
  }

  bool isReleaseNeeded = false;
  int stream_tracker_id = timeout->transition_state;
  LOG(INFO) << __func__ << ": stream_tracker_ID: " << stream_tracker_id
            << ", timeout reason: " << static_cast<int>(timeout->reason);

  if (timeout->reason == TimeoutReason::STATE_TRANSITION) {
    if (stream_tracker_id == StreamTracker::kStateConnecting) {
      StreamContexts *contexts = strm_mgr_->GetStreamContexts();
      std::vector<StreamConnect> *conn_streams = GetConnStreams();
      UcastAudioStreams *audio_strms = strm_mgr_->GetAudioStreams();

      LOG(WARNING) << __func__ << ": audio_strms: " << audio_strms->size()
                               << ", conn_streams: " << conn_streams->size();

      for (auto it = conn_streams->begin(); it != conn_streams->end(); it++) {
        StreamContext *context = contexts->FindOrAddByType(it->stream_type);
        LOG(INFO) << __func__ << ": connection_state: "
                              << static_cast<int>(context->connection_state);

        if(context->connection_state == IntConnectState::ASCS_DISCOVERED) {
          for (auto id = context->stream_ids.begin();
                    id != context->stream_ids.end(); id++) {
            UcastAudioStream *stream = audio_strms->FindByAseId(id->ase_id);
            if (!stream) {
              LOG(ERROR) << __func__  << "stream is null";
              continue;
            }

            LOG(INFO) << __func__ << ": ase_state: " << stream->ase_state;
            if (stream->ase_state != ascs::ASE_STATE_IDLE &&
               stream->ase_state != ascs::ASE_STATE_RELEASING) {
              LOG(WARNING) << __func__
                           << ": ascs state is neither idle nor releasing";
              isReleaseNeeded = true;
              break;
            }
          }
        }
      }
      LOG(INFO) << __func__ << ": isReleaseNeeded: " << isReleaseNeeded;
      HandleInternalDisconnect(isReleaseNeeded);
    } else if (stream_tracker_id != StreamTracker::kStateDisconnecting) {
      //All other transient states
      HandleInternalDisconnect(true);
    }
  }
  LOG(INFO) << __func__ << ": Exit";
}

void StreamTracker::StateIdle::OnEnter() {
  LOG(INFO) << __func__ << ": StreamTracker State: " << GetState();

  UcastClientCallbacks* callbacks = strm_mgr_->GetUclientCbacks();
  StreamContexts *contexts = strm_mgr_->GetStreamContexts();
  std::vector<StreamStateInfo> strms;
  StreamControlType control_type = tracker_.GetControlType();

  if(control_type != StreamControlType::Disconnect &&
     control_type != StreamControlType::Connect) {
    return;
  }

  if(control_type == StreamControlType::Disconnect) {
    std::vector<StreamType> *disc_streams = tracker_.GetStreams();
    LOG(WARNING) << __func__ << ": Disc Streams Size: "
                             << disc_streams->size();
    for (auto it = disc_streams->begin(); it != disc_streams->end(); it++) {
      StreamStateInfo state;
      memset(&state, 0, sizeof(state));
      state.stream_type = *it;
      state.stream_state = StreamState::DISCONNECTED;
      strms.push_back(state);
      StreamContext *context = contexts->FindOrAddByType(*it);
      context->stream_state = StreamState::DISCONNECTED;
      context->attached_state = StreamAttachedState::IDLE;
      LOG(INFO) << __func__  << " Attached state made idle";
      context->stream_ids.clear();
    }
  } else if(control_type == StreamControlType::Connect) {
    std::vector<StreamConnect> *conn_streams = tracker_.GetConnStreams();
    uint32_t prev_state = tracker_.PreviousStateId();
    for (auto it = conn_streams->begin(); it != conn_streams->end(); it++) {
      StreamStateInfo state;
      memset(&state, 0, sizeof(state));
      StreamContext *context = contexts->FindOrAddByType(it->stream_type);
      context->stream_state = StreamState::DISCONNECTED;
      context->attached_state = StreamAttachedState::IDLE;
      LOG(INFO) << __func__  << " Attached state made idle";
      context->stream_ids.clear();
      if(prev_state == StreamTracker::kStateConnecting) {
        state.stream_type = it->stream_type;
        state.stream_state = StreamState::DISCONNECTED;
        strms.push_back(state);
      }
    }
  }
  callbacks->OnStreamState(strm_mgr_->GetAddress(), strms);
}

void StreamTracker::StateIdle::OnExit() {

}

bool StreamTracker::StateIdle::ProcessEvent(uint32_t event, void* p_data) {
  LOG(INFO) <<__func__  <<": BD Addr = " << strm_mgr_->GetAddress()
                        <<": State = " << GetState()
                        <<": Event = " << tracker_.GetEventName(event);

  GattPendingData *gatt_pending_data = strm_mgr_->GetGattPendingData();

  switch (event) {
    case BAP_CONNECT_REQ_EVT: {
       BapConnect *evt_data = (BapConnect *) p_data;
      // check if the PACS client is connected to remote device
      PacsClient *pacs_client = strm_mgr_->GetPacsClient();
      uint16_t pacs_client_id = strm_mgr_->GetPacsClientId();
      ConnectionState pacs_state = strm_mgr_->GetPacsState();
      if(pacs_state == ConnectionState::DISCONNECTED ||
            pacs_state == ConnectionState::DISCONNECTING ||
            pacs_state == ConnectionState::CONNECTING) {
        // move the state to connecting and initiate pacs connection
        pacs_client->Connect(pacs_client_id, strm_mgr_->GetAddress(),
                             evt_data->is_direct);
        if(gatt_pending_data->pacs_pending_cmd == GattPendingCmd::NONE) {
          gatt_pending_data->pacs_pending_cmd =
                              GattPendingCmd::GATT_CONN_PENDING;
        }
        tracker_.TransitionTo(StreamTracker::kStateConnecting);
      } else if(pacs_state == ConnectionState::CONNECTED) {
        // pacs is already connected so initiate
        // pacs service discovry now and move the state to connecting
        pacs_client->StartDiscovery(pacs_client_id, strm_mgr_->GetAddress());
        tracker_.TransitionTo(StreamTracker::kStateConnecting);
      }
    } break;
    default:
      LOG(WARNING) << __func__ << "Unhandled Event" << loghex(event);
      break;
  }
  return true;
}

void StreamTracker::StateConnecting::OnEnter() {
  LOG(INFO) << __func__ << ": StreamTracker State: " << GetState();

  UcastClientCallbacks* callbacks = strm_mgr_->GetUclientCbacks();
  StreamContexts *contexts = strm_mgr_->GetStreamContexts();
  std::vector<StreamStateInfo> strms;
  std::vector<StreamConnect> *conn_streams = tracker_.GetConnStreams();

  StreamControlType control_type = tracker_.GetControlType();

  if(control_type != StreamControlType::Connect) return;

  ConnectionState pacs_state = strm_mgr_->GetPacsState();

  LOG(INFO) << __func__  << ": Conn Streams Size: " << conn_streams->size();

  for (auto it = conn_streams->begin(); it != conn_streams->end(); it++) {
    StreamStateInfo state;
    memset(&state, 0, sizeof(state));
    StreamContext *context = contexts->FindOrAddByType(it->stream_type);
    context->stream_state = StreamState::CONNECTING;
    if(pacs_state == ConnectionState::DISCONNECTED ||
       pacs_state == ConnectionState::CONNECTING) {
      context->connection_state = IntConnectState::PACS_CONNECTING;
    } else if(pacs_state == ConnectionState::CONNECTED) {
      context->connection_state = IntConnectState::PACS_DISCOVERING;
    }
    state.stream_type = it->stream_type;
    state.stream_state = StreamState::CONNECTING;
    strms.push_back(state);
  }
  callbacks->OnStreamState(strm_mgr_->GetAddress(), strms);

  TimeoutReason reason = TimeoutReason::STATE_TRANSITION;
  state_transition_timer = tracker_.SetTimer("StateConnectingTimer",
                       &timeout, reason, ((conn_streams->size()) *
                       (static_cast<uint64_t>(TimeoutVal::ConnectingTimeout))));
  if (state_transition_timer == nullptr) {
    LOG(ERROR) << __func__ << ": StateConnecting: Alarm not allocated.";
    return;
  }
}

void StreamTracker::StateConnecting::OnExit() {
  tracker_.ClearTimer(state_transition_timer, "StateConnectingTimer");
}

void StreamTracker::StateConnecting::DeriveDeviceType(
                                     PacsDiscovery *pacs_discovery) {
  // derive the device type based on sink pac records
  std::vector<CodecConfig> *pac_records = &pacs_discovery->sink_pac_records;
  uint8_t max_chnl_count = 0;

  // chnl count Audio location  Type of device           No of ASEs
  // 1          Left or Right   Earbud                   1 ASE per Earbud
  // 1          Left and Right  Stereo Headset ( 2 CIS)  2 ASEs
  // 2          Left and Right  Stereo Headset ( 1 CIS)  1 ASE
  // 2          Left or Right   Earbud                   1 ASE per Earbud

  for (auto j = pac_records->begin(); j != pac_records->end();j++) {
    CodecConfig *dst = &(*j);
    if(static_cast<uint16_t> (dst->channel_mode) &
       static_cast<uint16_t> (CodecChannelMode::CODEC_CHANNEL_MODE_STEREO)) {
      max_chnl_count = 2;
    } else if(!max_chnl_count &&
           static_cast<uint16_t> (dst->channel_mode) &
           static_cast<uint16_t> (CodecChannelMode::CODEC_CHANNEL_MODE_MONO)) {
      max_chnl_count = 1;
    }
  }

  if(pacs_discovery->sink_locations & ucast::AUDIO_LOC_LEFT &&
     pacs_discovery->sink_locations & ucast::AUDIO_LOC_RIGHT) {
    if(max_chnl_count == 2) {
      strm_mgr_->UpdateDevType(DeviceType::HEADSET_STEREO);
    } else if (max_chnl_count == 1) {
      strm_mgr_->UpdateDevType(DeviceType::HEADSET_SPLIT_STEREO);
    }
  } else if(pacs_discovery->sink_locations & ucast::AUDIO_LOC_LEFT ||
            pacs_discovery->sink_locations & ucast::AUDIO_LOC_RIGHT) {
    strm_mgr_->UpdateDevType(DeviceType::EARBUD);
  }
}


bool StreamTracker::StateConnecting::AttachStreamsToContext(
                                 std::vector<IntStrmTracker *> *all_trackers,
                                 std::vector<UcastAudioStream *> *streams,
                                 uint8_t cis_count,
                                 std::vector<AseCodecConfigOp> *ase_ops) {
  PacsDiscovery *pacs_discovery_ = tracker_.GetPacsDiscovery();
  if (!pacs_discovery_) {
    return false;
  }
  StreamContexts *contexts = strm_mgr_->GetStreamContexts();
  for(uint8_t i = 0; i < all_trackers->size()/cis_count ; i++) {
    for(uint8_t j = 0; j < cis_count ; j++) {
      IntStrmTracker *tracker = all_trackers->at(i*cis_count + j);
      UcastAudioStream *stream = streams->at((i*cis_count + j)% streams->size());
      StreamContext *context = contexts->FindOrAddByType(
                                         tracker->strm_type);
      if(stream->overall_state == StreamTracker::kStateIdle) {
        stream->audio_context = tracker->strm_type.audio_context;
        stream->control_type = StreamControlType::Connect;
        stream->ase_pending_cmd = AscsPendingCmd::NONE;
        stream->cis_pending_cmd = CisPendingCmd::NONE;
        stream->codec_config = tracker->codec_config;
        stream->req_qos_config = tracker->qos_config;
        stream->qos_config = tracker->qos_config;
        stream->cig_id = tracker->cig_id;
        stream->cis_id = tracker->cis_id;

        stream->cig_state = CigState::INVALID;
        stream->cis_state = CisState::INVALID;
        stream->overall_state = StreamTracker::kStateConnecting;

        if (stream->direction == ASE_DIRECTION_SINK) {
          if(cis_count > 1) {
            stream->audio_location =
                    pacs_discovery_->sink_locations & locations.at(j);
          } else {
            if(pacs_discovery_->sink_locations & ucast::AUDIO_LOC_LEFT &&
               pacs_discovery_->sink_locations & ucast::AUDIO_LOC_RIGHT) {
              stream->audio_location = 0;
            } else if(pacs_discovery_->sink_locations & ucast::AUDIO_LOC_LEFT ||
                      pacs_discovery_->sink_locations & ucast::AUDIO_LOC_RIGHT) {
              stream->audio_location = pacs_discovery_->sink_locations;
            }
          }
        } else if (stream->direction == ASE_DIRECTION_SRC) {
          if(cis_count > 1) {
            stream->audio_location =
                    pacs_discovery_->src_locations & locations.at(j);
          } else {
            if(pacs_discovery_->src_locations & ucast::AUDIO_LOC_LEFT &&
               pacs_discovery_->src_locations & ucast::AUDIO_LOC_RIGHT) {
              stream->audio_location = 0;
            } else if(pacs_discovery_->src_locations & ucast::AUDIO_LOC_LEFT ||
                      pacs_discovery_->src_locations & ucast::AUDIO_LOC_RIGHT) {
              stream->audio_location = pacs_discovery_->src_locations;
            }
          }
        }
        tracker_.PrepareCodecConfigPayload(ase_ops, stream);
        tracker->attached_state = context->attached_state =
                                  StreamAttachedState::IDLE_TO_PHY;
        LOG(INFO) << __func__
                     << ": Physically  attached";
      } else {
        LOG(INFO) << __func__
                     << ": Virtually attached";
        tracker->attached_state = context->attached_state =
                                  StreamAttachedState::VIRTUAL;
      }
      tracker->ase_id = stream->ase_id;

      StreamIdType id = {
                  .ase_id = stream->ase_id,
                  .ase_direction = stream->direction,
                  .virtual_attach = false,
                  .cig_id = tracker->cig_id,
                  .cis_id = tracker->cis_id
      };
      context->stream_ids.push_back(id);
    }
  }
  return true;
}

bool StreamTracker::StateConnecting::ProcessEvent(uint32_t event, void* p_data) {
  LOG(INFO) <<__func__  <<": BD Addr = " << strm_mgr_->GetAddress()
                        <<": State = " << GetState()
                        <<": Event = " << tracker_.GetEventName(event);

  std::vector<StreamConnect> *conn_streams = tracker_.GetConnStreams();
  StreamContexts *contexts = strm_mgr_->GetStreamContexts();
  GattPendingData *gatt_pending_data = strm_mgr_->GetGattPendingData();

  uint8_t num_conn_streams = 0;
  if(conn_streams) {
     num_conn_streams = conn_streams->size();
  }
  UcastAudioStreams *audio_strms = strm_mgr_->GetAudioStreams();
  AscsClient *ascs_client = strm_mgr_->GetAscsClient();

  switch (event) {
    case BAP_DISCONNECT_REQ_EVT: {

      // expect the disconnection for same set of streams connection
      // has initiated ex: if connect is issued for media (tx), voice(tx & rx)
      // then disconnect is expected for media (tx), voice(tx & rx).

      // based on connection state, issue the relevant commands and move
      // the state to disconnecting
      // issue the release opertion if for any stream ASE operation is
      // initiated

      // upate the control type and streams also
      BapDisconnect *evt_data = (BapDisconnect *) p_data;

      tracker_.UpdateControlType(StreamControlType::Disconnect);

      tracker_.UpdateStreams(&evt_data->streams);

      StreamContexts *contexts = strm_mgr_->GetStreamContexts();
      AscsClient *ascs_client = strm_mgr_->GetAscsClient();

      std::vector<AseReleaseOp> ase_ops;
      std::vector<StreamType> *disc_streams = tracker_.GetStreams();

      LOG(WARNING) << __func__  << ": disc_streams: " << disc_streams->size();

      for (auto it = disc_streams->begin(); it != disc_streams->end(); it++) {
        StreamContext *context = contexts->FindOrAddByType(*it);
        if(context->connection_state == IntConnectState::ASCS_DISCOVERED) {
          for (auto id = context->stream_ids.begin();
                  id != context->stream_ids.end(); id++) {
            UcastAudioStream *stream = audio_strms->FindByAseId(id->ase_id);
            if (!stream) {
              LOG(ERROR) << __func__  << "stream is null";
              continue;
            }
            bool can_be_disconnected =
                       tracker_.StreamCanbeDisconnected(context, id->ase_id);
            if(can_be_disconnected &&
               stream->ase_state == ascs::ASE_STATE_CODEC_CONFIGURED &&
               stream->ase_pending_cmd != AscsPendingCmd::RELEASE_ISSUED) {
              AseReleaseOp release_op = {
                                         .ase_id = stream->ase_id
                                        };
              ase_ops.push_back(release_op);
              stream->ase_pending_cmd = AscsPendingCmd::RELEASE_ISSUED;
              // change the overall state to starting
              stream->overall_state = StreamTracker::kStateDisconnecting;
            }
          }
        }
      }

      LOG(INFO) << __func__  << ": ase_ops size: " << ase_ops.size();

      // send consolidated release command to ASCS client
      if(ase_ops.size()) {
        LOG(WARNING) << __func__  << ": Going For ASCS Release op";
        ascs_client->Release(ASCS_CLIENT_ID, strm_mgr_->GetAddress(), ase_ops);
      }

      tracker_.TransitionTo(StreamTracker::kStateDisconnecting);

    } break;
    case PACS_CONNECTION_STATE_EVT: {
      PacsConnectionState *pacs_state =  (PacsConnectionState *) p_data;

      PacsClient *pacs_client = strm_mgr_->GetPacsClient();
      uint16_t pacs_client_id = strm_mgr_->GetPacsClientId();

      LOG(WARNING) << __func__
                   <<": pacs_state: " << static_cast<int>(pacs_state->state);
      if(pacs_state->state == ConnectionState::CONNECTED) {
        // now send the PACS discovery
        gatt_pending_data->pacs_pending_cmd = GattPendingCmd::NONE;
        pacs_client->StartDiscovery(pacs_client_id, strm_mgr_->GetAddress());
      } else if(pacs_state->state == ConnectionState::DISCONNECTED) {
        gatt_pending_data->pacs_pending_cmd = GattPendingCmd::NONE;
        tracker_.HandleInternalDisconnect(false);
        return false;
      }

      for (uint8_t i = 0; i < num_conn_streams ; i++) {
        StreamConnect conn_stream = conn_streams->at(i);
        StreamContext *context = contexts->FindOrAddByType(
                                           conn_stream.stream_type);
        if(pacs_state->state == ConnectionState::CONNECTED) {
          context->connection_state = IntConnectState::PACS_DISCOVERING;
        }
      }
    } break;

    case PACS_DISCOVERY_RES_EVT: {
      PacsDiscovery pacs_discovery_ =  *((PacsDiscovery *) p_data);
      GattState ascs_state = strm_mgr_->GetAscsState();
      GattPendingData *gatt_pending_data = strm_mgr_->GetGattPendingData();
      bool process_pacs_results = false;

      // check if this tracker already passed the pacs discovery stage
      for (uint8_t i = 0; i < num_conn_streams ; i++) {
        StreamConnect conn_stream = conn_streams->at(i);
        StreamContext *context = contexts->FindOrAddByType(
                                           conn_stream.stream_type);
        if(context->connection_state == IntConnectState::PACS_DISCOVERING) {
          process_pacs_results = true;
          break;
        }
      }

      if(!process_pacs_results) break;

      bool context_supported = false;
      // check the status
      if(pacs_discovery_.status) {
        tracker_.HandleInternalDisconnect(false);
        LOG(ERROR) << __func__  << " PACS discovery failed";
        return false;
      }

      tracker_.UpdatePacsDiscovery(pacs_discovery_);

      // Derive the device type based on pacs discovery results
      DeriveDeviceType((PacsDiscovery *) p_data);

      // check if supported audio contexts has required contexts
      for (auto it = conn_streams->begin(); it != conn_streams->end(); it++) {
        StreamType stream = it->stream_type;
        if(stream.direction == ASE_DIRECTION_SINK) {
          if(stream.audio_context & pacs_discovery_.supported_contexts) {
            context_supported = true;
          }
        } else if(stream.direction == ASE_DIRECTION_SRC) {
          if((static_cast<uint64_t>(stream.audio_context) << 16) &
               pacs_discovery_.supported_contexts) {
            context_supported = true;
          }
        }
      }

      if(!context_supported) {
        LOG(ERROR) << __func__  << " No Matching Supported Contexts found";
        tracker_.HandleInternalDisconnect(false);
        break;
      }

      // if not present send the BAP callback as disconnected
      // compare the codec configs from upper layer to remote dev
      // sink or src PACS records/capabilities.

      // go for ASCS discovery only when codec configs are decided

      for (uint8_t i = 0; i < num_conn_streams ; i++) {
        StreamConnect conn_stream = conn_streams->at(i);
        // TODO for now will pick directly first set of Codec and QOS configs

        uint8_t index = tracker_.ChooseBestCodec(conn_stream.stream_type,
                                             &conn_stream.codec_qos_config_pair,
                                             &pacs_discovery_);
        if(index != 0XFF) {
          CodecQosConfig entry = conn_stream.codec_qos_config_pair.at(index);
          CodecConfig codec_config = entry.codec_config;
          QosConfig qos_config = entry.qos_config;

          StreamContext *context = contexts->FindOrAddByType(
                                             conn_stream.stream_type);
          for (auto ascs_config = qos_config.ascs_configs.begin();
                ascs_config != qos_config.ascs_configs.end(); ascs_config++) {
            int_strm_trackers_.FindOrAddBytrackerType(conn_stream.stream_type,
                               0x00, ascs_config->cig_id,
                               ascs_config->cis_id,
                               codec_config, qos_config);
          }
          context->codec_config = codec_config;
          context->req_qos_config = qos_config;
        } else {
          LOG(ERROR) << __func__  << " No Matching Codec Found For Stream";
        }
      }

      // check if any match between upper layer codec and remote dev's
      // pacs records
      if(!int_strm_trackers_.size()) {
        LOG(WARNING) << __func__ << "No Matching codec found for all streams";
        tracker_.HandleInternalDisconnect(false);
        return false;
      }

      if(ascs_state == GattState::CONNECTED) {
        LOG(WARNING) << __func__  << ": Going For ASCS Service Discovery";
        // now send the ASCS discovery
        ascs_client->StartDiscovery(ASCS_CLIENT_ID, strm_mgr_->GetAddress());
      } else if(ascs_state == GattState::DISCONNECTED) {
        LOG(WARNING) << __func__  << ": Going For ASCS Conneciton";
        ascs_client->Connect(ASCS_CLIENT_ID, strm_mgr_->GetAddress(), false);
        if(gatt_pending_data->ascs_pending_cmd == GattPendingCmd::NONE) {
          gatt_pending_data->ascs_pending_cmd =
                              GattPendingCmd::GATT_CONN_PENDING;
        }
      }

      for (uint8_t i = 0; i < num_conn_streams ; i++) {
        StreamConnect conn_stream = conn_streams->at(i);
        StreamContext *context = contexts->FindOrAddByType(
                                             conn_stream.stream_type);
        if(ascs_state == GattState::CONNECTED) {
          context->connection_state = IntConnectState::ASCS_DISCOVERING;
        } else if(ascs_state == GattState::DISCONNECTED) {
          context->connection_state = IntConnectState::ASCS_CONNECTING;
        }
      }
    } break;

    case ASCS_CONNECTION_STATE_EVT: {
      AscsConnectionState *ascs_state =  (AscsConnectionState *) p_data;
      AscsClient *ascs_client = strm_mgr_->GetAscsClient();

      if(ascs_state->state == GattState::CONNECTED) {
        LOG(INFO) << __func__ << " ASCS server connected";
        // now send the ASCS discovery
        gatt_pending_data->ascs_pending_cmd = GattPendingCmd::NONE;
        ascs_client->StartDiscovery(ASCS_CLIENT_ID, strm_mgr_->GetAddress());
      } else if(ascs_state->state == GattState::DISCONNECTED) {
        LOG(INFO) << __func__ << " ASCS server Disconnected";
        gatt_pending_data->ascs_pending_cmd = GattPendingCmd::NONE;
        tracker_.HandleInternalDisconnect(false);
        return false;
      }

      for (uint8_t i = 0; i < num_conn_streams ; i++) {
        StreamConnect conn_stream = conn_streams->at(i);
        StreamContext *context = contexts->FindOrAddByType(
                                             conn_stream.stream_type);
        if(ascs_state->state == GattState::CONNECTED) {
          context->connection_state = IntConnectState::ASCS_DISCOVERING;
        }
      }
    } break;
    case ASCS_DISCOVERY_RES_EVT: {
      AscsDiscovery ascs_discovery_ =  *((AscsDiscovery *) p_data);
      std::vector<AseCodecConfigOp> ase_ops;
      AscsClient *ascs_client = strm_mgr_->GetAscsClient();
      std::vector<AseParams> sink_ase_list = ascs_discovery_.sink_ases_list;
      std::vector<AseParams> src_ase_list = ascs_discovery_.src_ases_list;
      // check the status
      if(ascs_discovery_.status) {
        tracker_.HandleInternalDisconnect(false);
        return false;
      }

      for (uint8_t i = 0; i < num_conn_streams ; i++) {
        StreamConnect conn_stream = conn_streams->at(i);
        StreamContext *context = contexts->FindOrAddByType(
                                             conn_stream.stream_type);
        context->connection_state = IntConnectState::ASCS_DISCOVERED;
      }

      UcastAudioStreams *audio_strms = strm_mgr_->GetAudioStreams();
      // create the UcastAudioStream for each ASEs (ase id)
      // check if the entry is present, if not create and add it to list
      // find out number of ASEs which are in IDLE state
      for (auto & ase : sink_ase_list) {
        audio_strms->FindOrAddByAseId(ase.ase_id,
                                      ase.ase_state, ASE_DIRECTION_SINK);
      }

      for (auto & ase : src_ase_list) {
        audio_strms->FindOrAddByAseId(ase.ase_id,
                                      ase.ase_state, ASE_DIRECTION_SRC);
      }

      LOG(INFO) << __func__ << ": total num of audio strms: "
                            << audio_strms->size();

      std::vector<IntStrmTracker *> sink_int_trackers =
                   int_strm_trackers_.GetTrackerListByDir(ASE_DIRECTION_SINK);

      std::vector<IntStrmTracker *> src_int_trackers =
                   int_strm_trackers_.GetTrackerListByDir(ASE_DIRECTION_SRC);

      std::vector<int> state_ids = { StreamTracker::kStateIdle };

      std::vector<UcastAudioStream *> idle_sink_streams =
                                   audio_strms->GetStreamsByStates(state_ids,
                                   ASE_DIRECTION_SINK);
      std::vector<UcastAudioStream *> idle_src_streams =
                                   audio_strms->GetStreamsByStates(state_ids,
                                   ASE_DIRECTION_SRC);
      LOG(INFO) << __func__  << ": Num of Sink Idle Streams = "
                                <<  idle_sink_streams.size()
                                << ": Num of Src Idle Streams = "
                                <<  idle_src_streams.size();

      LOG(INFO) << __func__  << ": Num of Sink Internal Trackers = "
                                <<  sink_int_trackers.size()
                                << ": Num of Src Internal Trackers = "
                                <<  src_int_trackers.size();

      LOG(INFO) << __func__  << ": Num of Conn Streams "
                                <<  loghex(num_conn_streams);

      // check how many stream connections are requested and
      // how many streams(ASEs) are available for processing
      // check if we have sufficient number of streams(ASEs) for
      // the given set of connection requirement
      DeviceType dev_type = strm_mgr_->GetDevType();
      uint8_t cis_count = 0;
      if(dev_type == DeviceType::EARBUD ||
         dev_type == DeviceType::HEADSET_STEREO) {
        cis_count = 1;
      } else if(dev_type == DeviceType::HEADSET_SPLIT_STEREO) {
        cis_count = 2;
      }

      std::vector<int> valid_state_ids = {
                                       StreamTracker::kStateConnecting,
                                       StreamTracker::kStateConnected,
                                       StreamTracker::kStateStreaming,
                                       StreamTracker::kStateReconfiguring,
                                       StreamTracker::kStateDisconnecting,
                                       StreamTracker::kStateStarting,
                                       StreamTracker::kStateStopping
                                    };

      if(sink_int_trackers.size()) {
        if(idle_sink_streams.size() >= sink_int_trackers.size()) {
          AttachStreamsToContext(&sink_int_trackers, &idle_sink_streams,
                                 cis_count, &ase_ops);
        } else {
          std::vector<IntStrmTracker *> sink_int_trackers_1,
                                        sink_int_trackers_2;
            // split the sink_int_trackers into 2 lists now, one list
            // is equal to idle_sink_streams as physical and other
            // list as virtually attached
          if(idle_sink_streams.size()) { // less num of free ASEs
            for (uint8_t i = 0; i < idle_sink_streams.size() ; i++) {
              IntStrmTracker *tracker = sink_int_trackers.at(i);
              sink_int_trackers_1.push_back(tracker);
            }
            AttachStreamsToContext(&sink_int_trackers_1, &idle_sink_streams,
                                   cis_count, &ase_ops);
            for (uint8_t i = idle_sink_streams.size();
                         i < sink_int_trackers.size() ; i++) {
              IntStrmTracker *tracker = sink_int_trackers.at(i);
              sink_int_trackers_2.push_back(tracker);
            }
          }

          std::vector<UcastAudioStream *> all_active_sink_streams =
                                audio_strms->GetStreamsByStates(valid_state_ids,
                                ASE_DIRECTION_SINK);

          if(sink_int_trackers_2.size()) {
            AttachStreamsToContext(&sink_int_trackers_2, &all_active_sink_streams,
                                 cis_count, &ase_ops);
          } else if(sink_int_trackers.size()) {
            AttachStreamsToContext(&sink_int_trackers, &all_active_sink_streams,
                                 cis_count, &ase_ops);
          }
        }
      }

      // do the same procedure for src trackers as well
      if(src_int_trackers.size()) {
        if(idle_src_streams.size() >= src_int_trackers.size()) {
          AttachStreamsToContext(&src_int_trackers, &idle_src_streams,
                                 cis_count, &ase_ops);
        } else {
          std::vector<IntStrmTracker *> src_int_trackers_1,
                                        src_int_trackers_2;
            // split the src_int_trackers into 2 lists now, one list
            // is equal to idle_src_streams as physical and other
            // list as virtually attached
          if(idle_src_streams.size()) { // less num of free ASEs
            for (uint8_t i = 0; i < idle_src_streams.size() ; i++) {
              IntStrmTracker *tracker = src_int_trackers.at(i);
              src_int_trackers_1.push_back(tracker);
            }
            AttachStreamsToContext(&src_int_trackers_1, &idle_src_streams,
                                 cis_count, &ase_ops);
            for (uint8_t i = idle_src_streams.size();
                         i < src_int_trackers.size() ; i++) {
              IntStrmTracker *tracker = src_int_trackers.at(i);
              src_int_trackers_2.push_back(tracker);
            }
          }

          std::vector<UcastAudioStream *> all_active_src_streams =
                              audio_strms->GetStreamsByStates(valid_state_ids,
                              ASE_DIRECTION_SRC);

          if(src_int_trackers_2.size()) {
            AttachStreamsToContext(&src_int_trackers_2, &all_active_src_streams,
                                 cis_count, &ase_ops);
          } else if(src_int_trackers.size()) {
            AttachStreamsToContext(&src_int_trackers, &all_active_src_streams,
                                 cis_count, &ase_ops);
          }
        }
      }

      // remove all duplicate internal stream trackers
      int_strm_trackers_.RemoveVirtualAttachedTrackers();

      // if the int strm trackers size is 0 then return as
      // connected immediately
      if(!int_strm_trackers_.size()) {
        // update the state to connected
        TransitionTo(StreamTracker::kStateConnected);
        break;
      }

      if(!ase_ops.empty()) {
        LOG(WARNING) << __func__  << ": Going For ASCS CodecConfig op";
        ascs_client->CodecConfig(ASCS_CLIENT_ID, strm_mgr_->GetAddress(),
                                 ase_ops);
      } else {
        tracker_.HandleInternalDisconnect(false);
        break;
      }

      // refresh the sink and src trackers
      sink_int_trackers =
                   int_strm_trackers_.GetTrackerListByDir(ASE_DIRECTION_SINK);

      src_int_trackers =
                   int_strm_trackers_.GetTrackerListByDir(ASE_DIRECTION_SRC);

      LOG(INFO) << __func__  << ": Num of new Sink Internal Trackers = "
                             <<  sink_int_trackers.size()
                             << ": Num of new Src Internal Trackers = "
                             <<  src_int_trackers.size();

      LOG(INFO) << __func__  << ": Num of new Sink Idle Streams = "
                             <<  idle_sink_streams.size()
                             << ": Num of new Src Idle Streams = "
                             <<  idle_src_streams.size();

      // update the states to connecting or other internal states
      if(sink_int_trackers.size()) {
        for (uint8_t i = 0; i < sink_int_trackers.size() ; i++) {
          UcastAudioStream *stream = idle_sink_streams.at(i);
          stream->ase_pending_cmd = AscsPendingCmd::CODEC_CONFIG_ISSUED;
        }
      }
      if(src_int_trackers.size()) {
        for (uint8_t i = 0; i < src_int_trackers.size() ; i++) {
          UcastAudioStream *stream = idle_src_streams.at(i);
          stream->ase_pending_cmd = AscsPendingCmd::CODEC_CONFIG_ISSUED;
        }
      }
    } break;

    case ASCS_ASE_STATE_EVT: {
      tracker_.HandleAseStateEvent(p_data, StreamControlType::Connect,
                                   &int_strm_trackers_);
    } break;

    case ASCS_ASE_OP_FAILED_EVT: {
      tracker_.HandleAseOpFailedEvent(p_data);
    } break;

    case BAP_TIME_OUT_EVT: {
      tracker_.OnTimeout(p_data);
    } break;

    default:
      LOG(WARNING) << __func__ << ": Un-handled event: "
                               << tracker_.GetEventName(event);
      break;
  }
  return true;
}


void StreamTracker::StateConnected::OnEnter() {
  LOG(INFO) << __func__ << ": StreamTracker State: " << GetState();

  UcastClientCallbacks* callbacks = strm_mgr_->GetUclientCbacks();
  StreamContexts *contexts = strm_mgr_->GetStreamContexts();
  std::vector<StreamStateInfo> strms;
  std::vector<StreamConfigInfo> stream_configs;
  UcastAudioStreams *audio_strms = strm_mgr_->GetAudioStreams();
  PacsDiscovery *pacs_discovery_ = tracker_.GetPacsDiscovery();
  StreamControlType control_type = tracker_.GetControlType();
  std::vector<StreamType> conv_streams;

  if(control_type != StreamControlType::Connect &&
     control_type != StreamControlType::Stop &&
     control_type != StreamControlType::Reconfig) {
    return;
  }

  if(control_type == StreamControlType::Connect) {
    std::vector<StreamConnect> *conn_streams = tracker_.GetConnStreams();
    for (auto it = conn_streams->begin(); it != conn_streams->end(); it++) {
      StreamType type = it->stream_type;
      conv_streams.push_back(type);
    }
    LOG(WARNING) << __func__  << ": Conn Streams Size " << conn_streams->size();
  } else if(control_type == StreamControlType::Reconfig) {
    std::vector<StreamReconfig> *reconf_streams = tracker_.GetReconfStreams();
    for (auto it = reconf_streams->begin(); it != reconf_streams->end();it++) {
      StreamType type = it->stream_type;
      conv_streams.push_back(type);
    }
    LOG(WARNING) << __func__  << ": Reconfig Streams size "
                              << reconf_streams->size();
  } else {
    conv_streams =  *tracker_.GetStreams();
  }

  if(control_type == StreamControlType::Connect ||
     control_type == StreamControlType::Reconfig) {
    for (auto it = conv_streams.begin(); it != conv_streams.end(); it++) {
      StreamContext *context = contexts->FindOrAddByType(*it);
      UcastAudioStream *stream = audio_strms->FindByStreamType(
                (*it).type, (*it).direction);
      // avoid duplicate updates
      if(context && pacs_discovery_ &&
         context->stream_state != StreamState::CONNECTED) {
        StreamConfigInfo config;
        memset(&config, 0, sizeof(config));
        config.stream_type = *it;
        if(stream) {
          config.codec_config = stream->codec_config;
          config.qos_config = stream->qos_config;
          context->qos_config = stream->qos_config;
        } else {
          config.codec_config = context->codec_config;
          config.qos_config = context->req_qos_config;
          context->qos_config = context->req_qos_config;
        }

        //Keeping bits_per_sample as 24 always for LC3
        if (config.codec_config.codec_type ==
                                CodecIndex::CODEC_INDEX_SOURCE_LC3) {
          config.codec_config.bits_per_sample =
                                CodecBPS::CODEC_BITS_PER_SAMPLE_24;
        }

        if(config.stream_type.direction == ASE_DIRECTION_SINK) {
          config.audio_location = pacs_discovery_->sink_locations;
          config.codecs_selectable = pacs_discovery_->sink_pac_records;
        } else if(config.stream_type.direction == ASE_DIRECTION_SRC) {
          config.audio_location = pacs_discovery_->src_locations;
          config.codecs_selectable = pacs_discovery_->src_pac_records;
        }
        stream_configs.push_back(config);
      }
    }

    if(stream_configs.size()) {
      callbacks->OnStreamConfig(strm_mgr_->GetAddress(), stream_configs);
    }
  }

  for (auto it = conv_streams.begin(); it != conv_streams.end(); it++) {
    StreamContext *context = contexts->FindOrAddByType(*it);
    // avoid duplicate updates
    if( context->stream_state != StreamState::CONNECTED) {
      StreamStateInfo state;
      memset(&state, 0, sizeof(state));
      state.stream_type = *it;
      state.stream_state = StreamState::CONNECTED;
      context->stream_state = StreamState::CONNECTED;
      strms.push_back(state);
    }
  }

  if(strms.size()) {
    callbacks->OnStreamState(strm_mgr_->GetAddress(), strms);
  }
}

void StreamTracker::StateConnected::OnExit() {

}

bool StreamTracker::StateConnected::ProcessEvent(uint32_t event, void* p_data) {
  LOG(INFO) <<__func__  <<": BD Addr = " << strm_mgr_->GetAddress()
                        <<": State = " << GetState()
                        <<": Event = " << tracker_.GetEventName(event);

  switch (event) {
    case BAP_DISCONNECT_REQ_EVT: {
      tracker_.HandleDisconnect(p_data, StreamTracker::kStateConnected);
    } break;

    case BAP_START_REQ_EVT: {
      PacsClient *pacs_client = strm_mgr_->GetPacsClient();
      uint16_t pacs_client_id = strm_mgr_->GetPacsClientId();

      BapStart *evt_data = (BapStart *) p_data;

      tracker_.UpdateControlType(StreamControlType::Start);

      tracker_.UpdateStreams(&evt_data->streams);

      pacs_client->GetAudioAvailability(pacs_client_id,
                                        strm_mgr_->GetAddress());

      tracker_.TransitionTo(StreamTracker::kStateStarting);
    } break;

    case BAP_RECONFIG_REQ_EVT: {
      BapReconfig *evt_data = (BapReconfig *) p_data;

      tracker_.UpdateControlType(StreamControlType::Reconfig);
      tracker_.UpdateReconfStreams(&evt_data->streams);

      // check if codec reconfiguration or qos reconfiguration
      PacsClient *pacs_client = strm_mgr_->GetPacsClient();
      uint16_t pacs_client_id = strm_mgr_->GetPacsClientId();

      // pacs is already connected so initiate
      // pacs service discovry now and move the state to reconfiguring
      pacs_client->StartDiscovery(pacs_client_id, strm_mgr_->GetAddress());

      tracker_.TransitionTo(StreamTracker::kStateReconfiguring);

    } break;
    case PACS_CONNECTION_STATE_EVT: {
      tracker_.HandlePacsConnectionEvent(p_data);
    } break;
    case ASCS_CONNECTION_STATE_EVT: {
      tracker_.HandleAscsConnectionEvent(p_data);
    } break;
    case ASCS_ASE_STATE_EVT: {
      AscsState *ascs =  ((AscsState *) p_data);
      if(ascs->ase_params.ase_state == ascs::ASE_STATE_RELEASING) {
        tracker_.HandleRemoteDisconnect(ASCS_ASE_STATE_EVT, p_data, StateId());
      } else if(ascs->ase_params.ase_state ==
                              ascs::ASE_STATE_CODEC_CONFIGURED) {
        tracker_.HandleRemoteReconfig(ASCS_ASE_STATE_EVT, p_data, StateId());
      }
    } break;
    default:
      LOG(WARNING) << __func__ << ": Un-handled event: "
                               << tracker_.GetEventName(event);
      break;
  }
  return true;
}


void StreamTracker::StateStarting::OnEnter() {
  LOG(INFO) << __func__ << ": StreamTracker State: " << GetState();

  UcastClientCallbacks* callbacks = strm_mgr_->GetUclientCbacks();
  StreamContexts *contexts = strm_mgr_->GetStreamContexts();
  std::vector<StreamStateInfo> strms;
  std::vector<StreamType> *start_streams = tracker_.GetStreams();
  uint8_t num_ases = 0;

  LOG(WARNING) << __func__  << ": Start Streams Size: "
                            << start_streams->size();

  StreamControlType control_type = tracker_.GetControlType();

  if(control_type != StreamControlType::Start) return;

  for (auto it = start_streams->begin(); it != start_streams->end(); it++) {
    StreamStateInfo state;
    memset(&state, 0, sizeof(state));
    state.stream_type = *it;
    state.stream_state = StreamState::STARTING;
    strms.push_back(state);
    StreamContext *context = contexts->FindOrAddByType(*it);
    context->stream_state = StreamState::STARTING;

    for (auto id = context->stream_ids.begin();
              id != context->stream_ids.end(); id++) {
      int_strm_trackers_.FindOrAddBytrackerType(*it,
                                id->ase_id, id->cig_id,
                                id->cis_id,
                                context->codec_config, context->qos_config);
    }
    num_ases += context->stream_ids.size();
  }
  callbacks->OnStreamState(strm_mgr_->GetAddress(), strms);
  uint64_t tout = num_ases *
                    (static_cast<uint64_t>(TimeoutVal::StartingTimeout));
  if(!tout) {
    tout = static_cast<uint64_t>(MaxTimeoutVal::StartingTimeout);
  }
  TimeoutReason reason = TimeoutReason::STATE_TRANSITION;
  state_transition_timer = tracker_.SetTimer("StateStartingTimer",
        &timeout, reason, tout);
  if (state_transition_timer == nullptr) {
    LOG(ERROR) << __func__  << ": StateStarting: Alarm not allocated.";
    return;
  }
}

void StreamTracker::StateStarting::OnExit() {
  tracker_.ClearTimer(state_transition_timer, "StateStartingTimer");
}

bool StreamTracker::CheckAndUpdateStreamingState(
                          IntStrmTrackers *int_strm_trackers) {
  //  to check for all internal trackers are moved to
  // streaming state then update it upper layers
  std::vector<IntStrmTracker *> *all_trackers =
                      int_strm_trackers->GetTrackerList();
  UcastAudioStreams *audio_strms = strm_mgr_->GetAudioStreams();
  uint8_t num_strms_in_streaming = 0;

  bool pending_cmds = false;

  // check if any pending commands are present
  for (auto i = all_trackers->begin(); i != all_trackers->end();i++) {
    UcastAudioStream *stream = audio_strms->FindByAseId((*i)->ase_id);
    if(stream && (stream->cis_pending_cmd != CisPendingCmd::NONE ||
                  stream->ase_pending_cmd != AscsPendingCmd::NONE)) {
      LOG(WARNING) << __func__  << ": cis_pending_cmd "
                   << loghex(static_cast <uint8_t>(stream->cis_pending_cmd));
      LOG(WARNING) << __func__  << ": ase_pending_cmd "
                   << loghex(static_cast <uint8_t>(stream->ase_pending_cmd));
      pending_cmds = true;
      break;
    }
  }

  if(pending_cmds) {
    LOG(WARNING) << __func__  << ": ASCS/CIS Pending commands left";
    return false;
  }

  for (auto i = all_trackers->begin(); i != all_trackers->end();i++) {
    UcastAudioStream *stream = audio_strms->FindByAseId((*i)->ase_id);
    if (!stream) {
      LOG(ERROR) << __func__  << "stream is null";
      continue;
    }
    if(stream->ase_state == ascs::ASE_STATE_STREAMING &&
       stream->cis_state == CisState::ESTABLISHED) {
      num_strms_in_streaming++;
    }
  }

  if(int_strm_trackers->size() != num_strms_in_streaming) {
    LOG(WARNING) << __func__  << ": Not all streams moved to streaming";
    return false;
  }

  for (auto i = all_trackers->begin(); i != all_trackers->end();i++) {
    UcastAudioStream *stream = audio_strms->FindByAseId((*i)->ase_id);
    if (!stream) {
      LOG(ERROR) << __func__  << "stream is null";
      continue;
    }
    stream->overall_state = StreamTracker::kStateStreaming;
  }

  // all streams are moved to streaming state
  TransitionTo(StreamTracker::kStateStreaming);
  return true;
}

bool StreamTracker::StateStarting::ProcessEvent(uint32_t event, void* p_data) {
  LOG(INFO) <<__func__  <<": BD Addr = " << strm_mgr_->GetAddress()
                        <<": State = " << GetState()
                        <<": Event = " << tracker_.GetEventName(event);

  switch (event) {
    case BAP_DISCONNECT_REQ_EVT: {
      tracker_.HandleDisconnect(p_data, StreamTracker::kStateStarting);
    } break;
    case BAP_STOP_REQ_EVT: {
      tracker_.HandleStop(p_data, StreamTracker::kStateStarting);
    } break;
    case BAP_STREAM_UPDATE_REQ_EVT: {
      BapStreamUpdate *evt_data = (BapStreamUpdate *) p_data;
      tracker_.UpdateMetaUpdateStreams(&evt_data->update_streams);
      if(tracker_.HandlePacsAudioContextEvent(&pacs_contexts)) {
        tracker_.HandleStreamUpdate(StreamTracker::kStateStarting);
      }
    } break;
    case PACS_CONNECTION_STATE_EVT: {
      tracker_.HandlePacsConnectionEvent(p_data);
    } break;
    case PACS_AUDIO_CONTEXT_RES_EVT: {
      // check for all stream start requests, stream contexts are
      // part of available contexts
      pacs_contexts = *((PacsAvailableContexts *) p_data);
      StreamContexts *contexts = strm_mgr_->GetStreamContexts();
      UcastAudioStreams *audio_strms = strm_mgr_->GetAudioStreams();
      std::vector<IntStrmTracker *> *all_trackers =
                            int_strm_trackers_.GetTrackerList();
      bool ignore_event = false;

      std::vector<StreamType> *start_streams = tracker_.GetStreams();
      uint8_t contexts_supported = 0;

      // check if supported audio contexts has required contexts
      for(auto it = start_streams->begin(); it != start_streams->end(); it++) {
        if(it->direction == ASE_DIRECTION_SINK) {
          if(it->audio_context & pacs_contexts.available_contexts) {
            contexts_supported++;
          }
        } else if(it->direction == ASE_DIRECTION_SRC) {
          if((static_cast<uint64_t>(it->audio_context) << 16) &
               pacs_contexts.available_contexts) {
            contexts_supported++;
          }
        }
      }

      if(contexts_supported != start_streams->size()) {
        LOG(ERROR) << __func__  << ": No Matching available Contexts found";
        tracker_.TransitionTo(StreamTracker::kStateConnected);
        break;
      }

      for (auto it = start_streams->begin(); it != start_streams->end(); it++) {
        StreamContext *context = contexts->FindOrAddByType(*it);
        for (auto id = context->stream_ids.begin();
                  id != context->stream_ids.end(); id++) {
          UcastAudioStream *stream = audio_strms->FindByAseId(id->ase_id);
          if (stream != nullptr && stream->overall_state ==
                                 StreamTracker::kStateStarting) {
            ignore_event = true;
            break;
          }
        }
      }

      if(ignore_event) break;

      // Now create the groups
      for (auto i = all_trackers->begin(); i != all_trackers->end();i++) {
        UcastAudioStream *stream = audio_strms->FindByAseId((*i)->ase_id);
        if (!stream) {
          LOG(ERROR) << __func__  << "stream is null";
          continue;
        }
        QosConfig *qos_config = &stream->qos_config;
        CisInterface *cis_intf = strm_mgr_->GetCisInterface();
        IsoHciStatus status =  cis_intf->CreateCig(strm_mgr_->GetAddress(),
                                                   false,
                                                   qos_config->cig_config,
                                                   qos_config->cis_configs);

        LOG(WARNING) << __func__  << ": status: "
                     << loghex(static_cast<uint8_t>(status));
        if( status == IsoHciStatus::ISO_HCI_SUCCESS) {
          stream->cig_state = CigState::CREATED;
          stream->cis_state = CisState::READY;
        } else if (status == IsoHciStatus::ISO_HCI_IN_PROGRESS) {
          stream->cis_pending_cmd = CisPendingCmd::CIG_CREATE_ISSUED;
        } else {
          LOG(ERROR) << __func__  << " CIG Creation Failed";
        }
      }
      tracker_.CheckAndSendEnable(&int_strm_trackers_);
    } break;

    case CIS_GROUP_STATE_EVT: {
      tracker_.HandleCigStateEvent(event, p_data, &int_strm_trackers_);
    } break;

    case ASCS_CONNECTION_STATE_EVT: {
      tracker_.HandleAscsConnectionEvent(p_data);
    } break;
    case ASCS_ASE_STATE_EVT: {
      // to handle remote driven operations
      // check the state and if the state is Enabling
      // proceed with cis creation
      AscsState *ascs =  ((AscsState *) p_data);

      if(!tracker_.ValidateAseUpdate(p_data, &int_strm_trackers_,
                                     StreamTracker::kStateStarting)) {
        break;
      }

      UcastAudioStreams *audio_strms = strm_mgr_->GetAudioStreams();

      if (ascs->ase_params.ase_state == ascs::ASE_STATE_ENABLING) {
        // change the connection state to ENABLING
        CisInterface *cis_intf = strm_mgr_->GetCisInterface();

        // check for Enabling notification is received for all ASEs
        std::vector<IntStrmTracker *> *all_trackers =
                            int_strm_trackers_.GetTrackerList();

        uint8_t num_enabling_notify = 0;

        for (auto i = all_trackers->begin(); i != all_trackers->end();i++) {
          UcastAudioStream *stream = audio_strms->FindByAseId((*i)->ase_id);
          if (!stream) {
            LOG(ERROR) << __func__  << "stream is null";
            continue;
          }
          if(stream->ase_state == ascs::ASE_STATE_ENABLING) {
            num_enabling_notify++;
          }
        }

        if(int_strm_trackers_.size() != num_enabling_notify) {
          LOG(WARNING) << __func__
                       << "Enabling notification is not received for all strms";
          break;
        }

        // As it single group use cases, always single group start request
        // will come to BAP layer
        IsoHciStatus status;
        std::vector<uint8_t> cis_ids;
        uint8_t cigId;
        for (auto i = all_trackers->begin(); i != all_trackers->end();i++) {
          UcastAudioStream *stream = audio_strms->FindByAseId((*i)->ase_id);
          if (std::find(cis_ids.begin(), cis_ids.end(),
                        stream->cis_id) == cis_ids.end()) {
            cis_ids.push_back(stream->cis_id);
            cigId = stream->cig_id;
          }
        }
        if(cis_ids.size()) {
          LOG(WARNING) << __func__ << ": Going For CIS Creation ";
          status = cis_intf->CreateCis(cigId,
                                       cis_ids,
                                       strm_mgr_->GetAddress());
        }
        for (auto i = all_trackers->begin(); i != all_trackers->end();i++) {
          UcastAudioStream *stream = audio_strms->FindByAseId((*i)->ase_id);
          if (!stream) {
            LOG(ERROR) << __func__ << "stream is null";
            continue;
          }
          stream->cis_retry_count = 0;
          if( status == IsoHciStatus::ISO_HCI_SUCCESS) {
            stream->cis_state = CisState::ESTABLISHED;
          } else if (status == IsoHciStatus::ISO_HCI_IN_PROGRESS) {
            // change the connection state to CIS create issued
            stream->cis_pending_cmd = CisPendingCmd::CIS_CREATE_ISSUED;
          } else {
            LOG(WARNING) << __func__ << "CIS create Failed";
          }
        }
      } else if (ascs->ase_params.ase_state == ascs::ASE_STATE_STREAMING) {
        tracker_.CheckAndUpdateStreamingState(&int_strm_trackers_);

      } else if(ascs->ase_params.ase_state == ascs::ASE_STATE_RELEASING) {
        tracker_.HandleRemoteDisconnect(ASCS_ASE_STATE_EVT, p_data, StateId());

      } else if(ascs->ase_params.ase_state == ascs::ASE_STATE_DISABLING) {
        tracker_.HandleRemoteStop(ASCS_ASE_STATE_EVT, p_data, StateId());
      }
    } break;

    case ASCS_ASE_OP_FAILED_EVT: {
      tracker_.HandleAseOpFailedEvent(p_data);
    } break;

    case CIS_STATE_EVT: {
      CisStreamState *data = (CisStreamState *) p_data;
      UcastAudioStreams *audio_strms = strm_mgr_->GetAudioStreams();
      // check if current stream tracker is interested in this CIG update
      std::vector<IntStrmTracker *> int_trackers =
                   int_strm_trackers_.FindByCisId(data->cig_id, data->cis_id);
      if(int_trackers.empty()) {
        LOG(INFO) << __func__  << ": Not intended for this tracker";
        break;
      }

      if(data->state == CisState::ESTABLISHED) {
        // find out the CIS is bidirectional or from air direction
        // cis, send Receiver start ready as set up data path
        // is already completed during CIG creation
        if(data->direction & cis::DIR_FROM_AIR) {
          // setup the datapath for RX
          // find out the stream here
          UcastAudioStream *stream = audio_strms->FindByCisIdAndDir
                                     (data->cig_id, data->cis_id,
                                      cis::DIR_FROM_AIR);
          LOG(WARNING) << __func__  << " DIR_FROM_AIR "
                       << loghex(static_cast <uint8_t> (cis::DIR_FROM_AIR));

          if(stream && int_strm_trackers_.FindByAseId(stream->ase_id)) {
            LOG(INFO) << __func__  << ": Stream Direction "
                      << loghex(static_cast <uint8_t> (stream->direction));

            LOG(INFO) << __func__  << ": Stream ASE Id "
                      << loghex(static_cast <uint8_t> (stream->ase_id));

            AscsClient *ascs_client = strm_mgr_->GetAscsClient();
            AseStartReadyOp start_ready_op = {
                                              .ase_id = stream->ase_id
                                             };
            std::vector<AseStartReadyOp> ase_ops;
            ase_ops.push_back(start_ready_op);
            ascs_client->StartReady(ASCS_CLIENT_ID,
                         strm_mgr_->GetAddress(), ase_ops);
            stream->cis_state = data->state;
            stream->cis_pending_cmd = CisPendingCmd::NONE;
            stream->ase_pending_cmd = AscsPendingCmd::START_READY_ISSUED;
          }
        }

        if(data->direction & cis::DIR_TO_AIR) {
          UcastAudioStream *stream = audio_strms->FindByCisIdAndDir
                                     (data->cig_id, data->cis_id,
                                      cis::DIR_TO_AIR);
          if(stream) {
            stream->cis_state = data->state;
            stream->cis_pending_cmd = CisPendingCmd::NONE;
          }
        }

        tracker_.CheckAndUpdateStreamingState(&int_strm_trackers_);

      } else if (data->state == CisState::READY) { // CIS creation failed
        CisInterface *cis_intf = strm_mgr_->GetCisInterface();
        UcastAudioStream *stream = audio_strms->FindByCisIdAndDir
                                   (data->cig_id, data->cis_id,
                                    data->direction);
        if(stream && stream->cis_retry_count < 2) {
          std::vector<uint8_t> cisIds = {stream->cis_id};
          LOG(WARNING) << __func__  << ": Going For Retrial of CIS Creation ";
          IsoHciStatus status =  cis_intf->CreateCis(
                                           stream->cig_id,
                                           cisIds,
                                           strm_mgr_->GetAddress());

          if( status == IsoHciStatus::ISO_HCI_SUCCESS) {
            stream->cis_state = CisState::ESTABLISHED;
            tracker_.CheckAndUpdateStreamingState(&int_strm_trackers_);
          } else if (status == IsoHciStatus::ISO_HCI_IN_PROGRESS) {
            // change the connection state to CIS create issued
            stream->cis_retry_count++;
            stream->cis_pending_cmd = CisPendingCmd::CIS_CREATE_ISSUED;
          } else {
            stream->cis_retry_count = 0;
            LOG(WARNING) << __func__  << "CIS create Failed";
          }
        } else {
          if(stream) {
            stream->cis_retry_count = 0;
            stream->cis_state = data->state;
            stream->cis_pending_cmd = CisPendingCmd::NONE;
          }
        }
      } else {  // transient states
        UcastAudioStream *stream = audio_strms->FindByCisIdAndDir
                                   (data->cig_id, data->cis_id,
                                    data->direction);
        if(stream) stream->cis_state = data->state;
      }
    } break;

    case BAP_TIME_OUT_EVT: {
      tracker_.OnTimeout(p_data);
    } break;

    default:
      LOG(WARNING) << __func__ << ": Un-handled event: "
                               << tracker_.GetEventName(event);
      break;
  }
  return true;
}

void StreamTracker::StateUpdating::OnEnter() {
  LOG(INFO) << __func__ << ": StreamTracker State: " << GetState();

  UcastClientCallbacks* callbacks = strm_mgr_->GetUclientCbacks();
  StreamContexts *contexts = strm_mgr_->GetStreamContexts();
  std::vector<StreamStateInfo> strms;
  std::vector<StreamUpdate> *update_streams = tracker_.GetMetaUpdateStreams();
  uint8_t num_ases = 0;

  LOG(WARNING) << __func__  << ": Start Streams Size "
                            << update_streams->size();

  StreamControlType control_type = tracker_.GetControlType();

  if(control_type != StreamControlType::UpdateStream) return;

  for (auto it = update_streams->begin(); it != update_streams->end(); it++) {
    StreamStateInfo state;
    memset(&state, 0, sizeof(state));
    state.stream_type = it->stream_type;
    state.stream_state = StreamState::UPDATING;
    strms.push_back(state);
    StreamContext *context = contexts->FindOrAddByType(it->stream_type);
    context->stream_state = StreamState::UPDATING;
    for (auto id = context->stream_ids.begin();
              id != context->stream_ids.end(); id++) {
      int_strm_trackers_.FindOrAddBytrackerType(it->stream_type,
                                id->ase_id, id->cig_id,
                                id->cis_id,
                                context->codec_config, context->qos_config);
    }
    num_ases += context->stream_ids.size();
  }
  callbacks->OnStreamState(strm_mgr_->GetAddress(), strms);

  uint64_t tout = num_ases *
                    (static_cast<uint64_t>(TimeoutVal::UpdatingTimeout));
  if(!tout) {
    tout = static_cast<uint64_t>(MaxTimeoutVal::UpdatingTimeout);
  }
  TimeoutReason reason = TimeoutReason::STATE_TRANSITION;
  state_transition_timer = tracker_.SetTimer("StateUpdatingTimer",
                                             &timeout, reason, tout);
  if (state_transition_timer == nullptr) {
    LOG(ERROR) << __func__  << ": StateUpdating: Alarm not allocated.";
    return;
  }
}

void StreamTracker::StateUpdating::OnExit() {
  tracker_.ClearTimer(state_transition_timer, "StateUpdatingTimer");
}

bool StreamTracker::StateUpdating::ProcessEvent(uint32_t event, void* p_data) {
  LOG(INFO) <<__func__  <<": BD Addr = " << strm_mgr_->GetAddress()
                        <<": State = " << GetState()
                        <<": Event = " << tracker_.GetEventName(event);

  switch (event) {
    case BAP_DISCONNECT_REQ_EVT: {
      tracker_.HandleDisconnect(p_data, StreamTracker::kStateUpdating);
    } break;
    case BAP_STOP_REQ_EVT: {
      tracker_.HandleStop(p_data, StreamTracker::kStateUpdating);
    } break;
    case PACS_CONNECTION_STATE_EVT: {
      tracker_.HandlePacsConnectionEvent(p_data);
    } break;
    case ASCS_CONNECTION_STATE_EVT: {
      tracker_.HandleAscsConnectionEvent(p_data);
    } break;
    case PACS_AUDIO_CONTEXT_RES_EVT: {
      // check for all stream start requests, stream contexts are
      // part of available contexts
      PacsAvailableContexts *pacs_contexts = (PacsAvailableContexts *) p_data;
      if(!tracker_.HandlePacsAudioContextEvent(pacs_contexts) ||
         !tracker_.HandleStreamUpdate(StreamTracker::kStateUpdating)) {
        tracker_.TransitionTo(StreamTracker::kStateStreaming);
      }
    } break;
    case ASCS_ASE_STATE_EVT: {
      AscsState *ascs =  ((AscsState *) p_data);
      if(!tracker_.ValidateAseUpdate(p_data, &int_strm_trackers_,
                                     StreamTracker::kStateUpdating)) {
        break;
      }
      if(ascs->ase_params.ase_state == ascs::ASE_STATE_STREAMING) {
        tracker_.CheckAndUpdateStreamingState(&int_strm_trackers_);
      } else if(ascs->ase_params.ase_state == ascs::ASE_STATE_RELEASING) {
        tracker_.HandleRemoteDisconnect(ASCS_ASE_STATE_EVT, p_data, StateId());
      } else if(ascs->ase_params.ase_state == ascs::ASE_STATE_DISABLING) {
        tracker_.HandleRemoteStop(ASCS_ASE_STATE_EVT, p_data, StateId());
      } else if(ascs->ase_params.ase_state == ascs::ASE_STATE_QOS_CONFIGURED) {
        // this can happen when CIS is lost and detected on remote side
        // first so it will immediately transition to QOS configured.
        tracker_.HandleAbruptStop(ASCS_ASE_STATE_EVT, p_data);
      }
    } break;
    case CIS_STATE_EVT: {
      // handle sudden CIS Disconnection
      tracker_.HandleCisEventsInStreaming(p_data);
    } break;
    default:
      LOG(WARNING) << __func__ << ": Un-handled event: "
                               << tracker_.GetEventName(event);
      break;
  }
  return true;
}

void StreamTracker::StateStreaming::OnEnter() {
  LOG(INFO) << __func__ << ": StreamTracker State: " << GetState();

  UcastClientCallbacks* callbacks = strm_mgr_->GetUclientCbacks();
  StreamContexts *contexts = strm_mgr_->GetStreamContexts();
  std::vector<StreamStateInfo> strms;
  std::vector<StreamType> *start_streams = tracker_.GetStreams();
  std::vector<StreamUpdate> *update_streams = tracker_.GetMetaUpdateStreams();
  LOG(WARNING) << __func__  << ": Start Streams Size "
                            << start_streams->size();

  LOG(WARNING) << __func__  << ": Update Streams Size "
                            << update_streams->size();

  StreamControlType control_type = tracker_.GetControlType();

  if(control_type == StreamControlType::Start) {
    for (auto it = start_streams->begin(); it != start_streams->end(); it++) {
      StreamStateInfo state;
      memset(&state, 0, sizeof(state));
      state.stream_type = *it;
      state.stream_state = StreamState::STREAMING;
      strms.push_back(state);
      StreamContext *context = contexts->FindOrAddByType(*it);
      context->stream_state = StreamState::STREAMING;
    }
  } else if(control_type == StreamControlType::UpdateStream) {
    for (auto it = update_streams->begin(); it != update_streams->end(); it++) {
      StreamStateInfo state;
      memset(&state, 0, sizeof(state));
      state.stream_type = it->stream_type;
      state.stream_state = StreamState::STREAMING;
      strms.push_back(state);
      StreamContext *context = contexts->FindOrAddByType(it->stream_type);
      context->stream_state = StreamState::STREAMING;
    }
  }
  if(strms.size()) {
    callbacks->OnStreamState(strm_mgr_->GetAddress(), strms);
  }
}

void StreamTracker::StateStreaming::OnExit() {

}

bool StreamTracker::StateStreaming::ProcessEvent(uint32_t event, void* p_data) {
  LOG(INFO) <<__func__  <<": BD Addr = " << strm_mgr_->GetAddress()
                        <<": State = " << GetState()
                        <<": Event = " << tracker_.GetEventName(event);

  switch (event) {
    case BAP_DISCONNECT_REQ_EVT: {
      tracker_.HandleDisconnect(p_data, StreamTracker::kStateStreaming);
    } break;
    case BAP_STOP_REQ_EVT: {
      tracker_.HandleStop(p_data, StreamTracker::kStateStreaming);
    } break;
    case BAP_STREAM_UPDATE_REQ_EVT: {
      PacsClient *pacs_client = strm_mgr_->GetPacsClient();
      uint16_t pacs_client_id = strm_mgr_->GetPacsClientId();
      BapStreamUpdate *evt_data = (BapStreamUpdate *) p_data;
      tracker_.UpdateControlType(StreamControlType::UpdateStream);
      tracker_.UpdateMetaUpdateStreams(&evt_data->update_streams);
      pacs_client->GetAudioAvailability(pacs_client_id,
                                        strm_mgr_->GetAddress());
      tracker_.TransitionTo(StreamTracker::kStateUpdating);
    } break;
    case PACS_CONNECTION_STATE_EVT: {
      tracker_.HandlePacsConnectionEvent(p_data);
    } break;
    case ASCS_CONNECTION_STATE_EVT: {
      tracker_.HandleAscsConnectionEvent(p_data);
    } break;
    case ASCS_ASE_STATE_EVT: {
      AscsState *ascs =  ((AscsState *) p_data);
      uint8_t ase_id = ascs->ase_params.ase_id;
      // find out the stream for the given ase id
      UcastAudioStreams *audio_strms = strm_mgr_->GetAudioStreams();
      UcastAudioStream *stream = audio_strms->FindByAseId(ase_id);
      if (stream) {
        stream->ase_state = ascs->ase_params.ase_state;
        stream->ase_params = ascs->ase_params;
        stream->ase_pending_cmd = AscsPendingCmd::NONE;
        if(ascs->ase_params.ase_state == ascs::ASE_STATE_RELEASING) {
          tracker_.HandleRemoteDisconnect(ASCS_ASE_STATE_EVT, p_data, StateId());
        } else if(ascs->ase_params.ase_state == ascs::ASE_STATE_DISABLING) {
          tracker_.HandleRemoteStop(ASCS_ASE_STATE_EVT, p_data, StateId());
        } else if(ascs->ase_params.ase_state == ascs::ASE_STATE_QOS_CONFIGURED){
          // this can happen when CIS is lost and detected on remote side
          // first so it will immediately transition to QOS configured.
          tracker_.HandleAbruptStop(ASCS_ASE_STATE_EVT, p_data);
        }
      }
    } break;
    case CIS_STATE_EVT: {
      // handle sudden CIS Disconnection
      tracker_.HandleCisEventsInStreaming(p_data);
    } break;
    default:
      LOG(WARNING) << __func__ << ": Un-handled event: "
                               << tracker_.GetEventName(event);
      break;
  }
  return true;
}

void StreamTracker::StateStopping::OnEnter() {
  LOG(INFO) << __func__ << ": StreamTracker State: " << GetState();

  UcastClientCallbacks* callbacks = strm_mgr_->GetUclientCbacks();
  StreamContexts *contexts = strm_mgr_->GetStreamContexts();
  std::vector<StreamStateInfo> strms;
  std::vector<StreamType> *stop_streams = tracker_.GetStreams();
  uint8_t num_ases = 0;

  LOG(WARNING) << __func__  << ": Stop Streams Size : "
                            << stop_streams->size();
  StreamControlType control_type = tracker_.GetControlType();

  if(control_type != StreamControlType::Stop) return;

  for (auto it = stop_streams->begin();
                       it != stop_streams->end(); it++) {
    StreamStateInfo state;
    memset(&state, 0, sizeof(state));
    state.stream_type = *it;
    state.stream_state = StreamState::STOPPING;
    strms.push_back(state);
    StreamContext *context = contexts->FindOrAddByType(*it);
    context->stream_state = StreamState::STOPPING;

    for (auto id = context->stream_ids.begin();
              id != context->stream_ids.end(); id++) {
      int_strm_trackers_.FindOrAddBytrackerType(*it,
                                id->ase_id, id->cig_id,
                                id->cis_id,
                                context->codec_config, context->qos_config);
    }
    num_ases += context->stream_ids.size();
  }
  callbacks->OnStreamState(strm_mgr_->GetAddress(), strms);

  uint64_t tout = num_ases *
                    (static_cast<uint64_t>(TimeoutVal::StoppingTimeout));
  if(!tout) {
    tout = static_cast<uint64_t>(MaxTimeoutVal::StoppingTimeout);
  }

  TimeoutReason reason = TimeoutReason::STATE_TRANSITION;
  state_transition_timer = tracker_.SetTimer("StateStoppingTimer",
                &timeout, reason, tout);
  if (state_transition_timer == nullptr) {
    LOG(ERROR) << __func__  << ": StateStopping: Alarm not allocated.";
    return;
  }
}

void StreamTracker::StateStopping::OnExit() {
  tracker_.ClearTimer(state_transition_timer, "StateStoppingTimer");
}

bool StreamTracker::StateStopping::TerminateCisAndCig(UcastAudioStream *stream) {

  CisInterface *cis_intf = strm_mgr_->GetCisInterface();
  uint8_t num_strms_in_qos_configured = 0;
  UcastAudioStreams *audio_strms = strm_mgr_->GetAudioStreams();

  std::vector<IntStrmTracker *> all_trackers =
                      int_strm_trackers_.FindByCigIdAndDir(stream->cig_id,
                                                           stream->direction);

  for(auto i = all_trackers.begin(); i != all_trackers.end();i++) {
    UcastAudioStream *stream = audio_strms->FindByAseId((*i)->ase_id);
    if (!stream) {
      LOG(ERROR) << __func__  << "stream is null";
      continue;
    }
    if(stream->ase_state == ascs::ASE_STATE_QOS_CONFIGURED) {
      num_strms_in_qos_configured++;
    }
  }

  if(all_trackers.size() != num_strms_in_qos_configured) {
    LOG(WARNING) << __func__  << "Not All Streams Moved to QOS Configured";
    return false;
  }

  for (auto i = all_trackers.begin(); i != all_trackers.end();i++) {
    UcastAudioStream *stream = audio_strms->FindByAseId((*i)->ase_id);
    if (!stream) {
      LOG(ERROR) << __func__  << "stream is null";
      continue;
    }
    if(stream->cis_pending_cmd == CisPendingCmd::NONE &&
       stream->cis_state == CisState::ESTABLISHED &&
       stream->ase_state == ascs::ASE_STATE_QOS_CONFIGURED) {
      LOG(WARNING) << __func__  << ": Going For CIS Disconnect ";
      IsoHciStatus status = cis_intf->DisconnectCis(stream->cig_id,
                                                    stream->cis_id,
                                                    stream->direction);
      if(status == IsoHciStatus::ISO_HCI_SUCCESS) {
        stream->cis_pending_cmd = CisPendingCmd::NONE;
        stream->cis_state = CisState::READY;
      } else if(status == IsoHciStatus::ISO_HCI_IN_PROGRESS) {
        stream->cis_pending_cmd = CisPendingCmd::CIS_DESTROY_ISSUED;
      } else {
        LOG(WARNING) << __func__  << ": CIS Disconnect Failed";
      }
    }

    if(stream->cis_state == CisState::READY) {
      if(stream->cig_state == CigState::CREATED &&
         stream->cis_pending_cmd == CisPendingCmd::NONE) {
        LOG(WARNING) << __func__  << ": Going For CIG Removal";
        IsoHciStatus status = cis_intf->RemoveCig(strm_mgr_->GetAddress(),
                                stream->cig_id);
        if( status == IsoHciStatus::ISO_HCI_SUCCESS) {
          stream->cig_state = CigState::INVALID;
          stream->cis_state = CisState::INVALID;
        } else if (status == IsoHciStatus::ISO_HCI_IN_PROGRESS) {
          stream->cis_pending_cmd = CisPendingCmd::CIG_REMOVE_ISSUED;
        } else {
          LOG(WARNING) << __func__  << ": CIG removal Failed";
        }
      }
    }
  }
  return true;
}

bool StreamTracker::StateStopping::CheckAndUpdateStoppedState() {
  //  to check for all internal trackers are moved to
  // cis destroyed state then update the callback
  uint8_t num_strms_in_stopping = 0;
  bool pending_cmds = false;

  std::vector<IntStrmTracker *> *all_trackers =
                      int_strm_trackers_.GetTrackerList();
  UcastAudioStreams *audio_strms = strm_mgr_->GetAudioStreams();

  // check if any pending commands are present
  for (auto i = all_trackers->begin(); i != all_trackers->end();i++) {
    UcastAudioStream *stream = audio_strms->FindByAseId((*i)->ase_id);
    if(stream && (stream->cis_pending_cmd != CisPendingCmd::NONE ||
                  stream->ase_pending_cmd != AscsPendingCmd::NONE)) {
      pending_cmds = true;
      break;
    }
  }

  if(pending_cmds) return false;

  for(auto i = all_trackers->begin(); i != all_trackers->end();i++) {
    UcastAudioStream *stream = audio_strms->FindByAseId((*i)->ase_id);
    if(stream && (stream->cig_state == CigState::IDLE ||
       stream->cig_state == CigState::INVALID) &&
       (stream->cis_state == CisState::READY ||
        stream->cis_state == CisState::INVALID) &&
       stream->ase_state == ascs::ASE_STATE_QOS_CONFIGURED) {
      num_strms_in_stopping++;
    }
  }

  if(int_strm_trackers_.size() != num_strms_in_stopping) {
    LOG(WARNING) << __func__  << "Not All Streams Moved to Stopped State";
    return false;
  }

  for (auto i = all_trackers->begin(); i != all_trackers->end();i++) {
    UcastAudioStream *stream = audio_strms->FindByAseId((*i)->ase_id);
    if (!stream) {
      LOG(ERROR) << __func__  << "stream is null";
      continue;
    }
    stream->overall_state = StreamTracker::kStateConnected;
  }

  tracker_.TransitionTo(StreamTracker::kStateConnected);
  return true;
}

bool StreamTracker::StateStopping::ProcessEvent(uint32_t event, void* p_data) {
  LOG(INFO) <<__func__  <<": BD Addr = " << strm_mgr_->GetAddress()
                        <<": State = " << GetState()
                        <<": Event = " << tracker_.GetEventName(event);

  switch (event) {
    case BAP_DISCONNECT_REQ_EVT:{
      tracker_.HandleDisconnect(p_data, StreamTracker::kStateStopping);
    } break;
    case PACS_CONNECTION_STATE_EVT: {
      tracker_.HandlePacsConnectionEvent(p_data);
    } break;
    case ASCS_CONNECTION_STATE_EVT: {
      tracker_.HandleAscsConnectionEvent(p_data);
    } break;
    case ASCS_ASE_STATE_EVT: {
      // to handle remote driven operations
      AscsState *ascs =  ((AscsState *) p_data);

      if(!tracker_.ValidateAseUpdate(p_data, &int_strm_trackers_,
                                     StreamTracker::kStateStopping)) {
        break;
      }

      // find out the stream for the given ase id
      uint8_t ase_id = ascs->ase_params.ase_id;
      UcastAudioStreams *audio_strms = strm_mgr_->GetAudioStreams();

      UcastAudioStream *stream = audio_strms->FindByAseId(ase_id);
      if (!stream) {
        LOG(ERROR) << __func__  << "stream is null";
        break;
      }

      if(ascs->ase_params.ase_state == ascs::ASE_STATE_DISABLING) {
        if(stream->direction & cis::DIR_FROM_AIR) {
          LOG(INFO) << __func__  << " Sending Stop Ready ";
          AscsClient *ascs_client = strm_mgr_->GetAscsClient();
          AseStopReadyOp stop_ready_op = {
                                .ase_id = stream->ase_id
          };
          std::vector<AseStopReadyOp> ase_ops;
          ase_ops.push_back(stop_ready_op);
          ascs_client->StopReady(ASCS_CLIENT_ID,
                       strm_mgr_->GetAddress(), ase_ops);
          stream->ase_pending_cmd = AscsPendingCmd::STOP_READY_ISSUED;
        } else {
          LOG(ERROR) << __func__  << ": Invalid State transition to Disabling"
                     << ": ASE Id = " << loghex(ase_id);
        }

      } else if(ascs->ase_params.ase_state == ascs::ASE_STATE_QOS_CONFIGURED) {

        stream->ase_pending_cmd = AscsPendingCmd::NONE;
        // stopped state then issue CIS disconnect
        TerminateCisAndCig(stream);
        CheckAndUpdateStoppedState();

      } else if(ascs->ase_params.ase_state == ascs::ASE_STATE_RELEASING) {
        tracker_.HandleRemoteDisconnect(ASCS_ASE_STATE_EVT, p_data, StateId());
      }
    } break;

    case ASCS_ASE_OP_FAILED_EVT: {
      tracker_.HandleAseOpFailedEvent(p_data);
    } break;

    case CIS_STATE_EVT: {
      CisStreamState *data = (CisStreamState *) p_data;
      CisInterface *cis_intf = strm_mgr_->GetCisInterface();
      UcastAudioStreams *audio_strms = strm_mgr_->GetAudioStreams();
      // check if current stream tracker is interested in this CIG update
      std::vector<IntStrmTracker *> int_trackers =
                   int_strm_trackers_.FindByCisId(data->cig_id, data->cis_id);
      if(int_trackers.empty()) {
        LOG(INFO) << __func__  << "Not intended for this tracker";
        break;
      }
      if(data->state == CisState::ESTABLISHED) {
        for(auto it = directions.begin(); it != directions.end(); ++it) {
          if(data->direction & *it) {
            // find out the stream here
            UcastAudioStream *stream = audio_strms->FindByCisIdAndDir
                                       (data->cig_id, data->cis_id, *it);
            if(stream) {
              stream->cis_state = data->state;
              stream->cis_pending_cmd = CisPendingCmd::NONE;
              if(int_strm_trackers_.FindByAseId(stream->ase_id)) {
                TerminateCisAndCig(stream);
              }
            }
          }
        }
        CheckAndUpdateStoppedState();

      } else if(data->state == CisState::READY) {
        for(auto it = directions.begin(); it != directions.end(); ++it) {
          if(data->direction & *it) {
            // find out the stream here
            UcastAudioStream *stream = audio_strms->FindByCisIdAndDir
                                       (data->cig_id, data->cis_id, *it);
            if(stream) {
              stream->cis_state = data->state;
              stream->cis_pending_cmd = CisPendingCmd::NONE;
              if(stream->cig_state == CigState::CREATED &&
                 stream->cis_pending_cmd == CisPendingCmd::NONE) {
                IsoHciStatus status = cis_intf->RemoveCig(
                                        strm_mgr_->GetAddress(),
                                        stream->cig_id);
                if( status == IsoHciStatus::ISO_HCI_SUCCESS) {
                  stream->cig_state = CigState::INVALID;
                  stream->cis_state = CisState::INVALID;
                } else if (status == IsoHciStatus::ISO_HCI_IN_PROGRESS) {
                  stream->cis_pending_cmd = CisPendingCmd::CIG_REMOVE_ISSUED;
                } else {
                  LOG(WARNING) << __func__  << ": CIG removal Failed";
                }
              }
            }
          }
        }
        CheckAndUpdateStoppedState();
      } else {  // transient states
        for(auto it = directions.begin(); it != directions.end(); ++it) {
          if(data->direction & *it) {
            // find out the stream here
            UcastAudioStream *stream = audio_strms->FindByCisIdAndDir
                                       (data->cig_id, data->cis_id, *it);
            if(stream) stream->cis_state = data->state;
          }
        }
      }
    } break;

    case CIS_GROUP_STATE_EVT: {
      CisGroupState *data = ((CisGroupState *) p_data);
      // check if current stream tracker is interested in this CIG update
      std::vector<IntStrmTracker *> int_trackers =
                            int_strm_trackers_.FindByCigId(data->cig_id);
      if(int_trackers.empty()) {
        LOG(INFO) << __func__  << "Not intended for this tracker";
        break;
      }

      UcastAudioStreams *audio_strms = strm_mgr_->GetAudioStreams();
      if(data->state == CigState::CREATED) {
        for (auto i = int_trackers.begin(); i != int_trackers.end();i++) {
          UcastAudioStream *stream = audio_strms->FindByAseId((*i)->ase_id);
          if (stream) {
            // check if this is a CIG created event due to CIG create
            // issued during starting state
            stream->cis_pending_cmd = CisPendingCmd::NONE;
            stream->cig_state = data->state;
            stream->cis_state = CisState::READY;
            TerminateCisAndCig(stream);
          }
        }
        CheckAndUpdateStoppedState();

      } else if(data->state == CigState::IDLE) {
        for (auto i = int_trackers.begin(); i != int_trackers.end();i++) {
          UcastAudioStream *stream = audio_strms->FindByAseId((*i)->ase_id);
          if (stream) {
            stream->cig_state = CigState::INVALID;
            stream->cis_state = CisState::INVALID;
            stream->cis_pending_cmd = CisPendingCmd::NONE;
          }
        }
        CheckAndUpdateStoppedState();
      }
    } break;
    case BAP_TIME_OUT_EVT: {
      tracker_.OnTimeout(p_data);
    } break;

    default:
      LOG(WARNING) << __func__ << ": Un-handled event: "
                               << tracker_.GetEventName(event);
      break;
  }
  return true;
}

bool StreamTracker::StateDisconnecting::TerminateGattConnection() {
  UcastAudioStreams *audio_strms = strm_mgr_->GetAudioStreams();
  GattPendingData *gatt_pending_data = strm_mgr_->GetGattPendingData();
  StreamContexts *contexts = strm_mgr_->GetStreamContexts();
  std::vector<StreamContext *> *all_contexts = contexts->GetAllContexts();
  bool any_context_active = false;
  bool disc_issued = false;
  std::vector<int> ids = { StreamTracker::kStateIdle };
  std::vector<UcastAudioStream *> idle_streams =
                               audio_strms->GetStreamsByStates(
                               ids, ASE_DIRECTION_SINK | ASE_DIRECTION_SRC);

  LOG(WARNING) << __func__ <<": Total Streams size: " << audio_strms->size()
                           <<": Idle Streams size: " << idle_streams.size();

  // check if any of the contexts stream state is connected
  for (auto it = all_contexts->begin(); it != all_contexts->end(); it++) {
    if((*it)->stream_state != StreamState::DISCONNECTING &&
       (*it)->stream_state != StreamState::DISCONNECTED) {
      LOG(INFO) << __func__ <<": Other contexts are active,not to disc Gatt";
      any_context_active = true;
      break;
    }
  }
  if(!any_context_active &&
     (!audio_strms->size() || audio_strms->size() == idle_streams.size())) {

    // check if gatt connection can be tear down for ascs & pacs clients
    // all streams are in idle state
    AscsClient *ascs_client = strm_mgr_->GetAscsClient();
    PacsClient *pacs_client = strm_mgr_->GetPacsClient();
    uint16_t pacs_client_id = strm_mgr_->GetPacsClientId();

    ConnectionState pacs_state = strm_mgr_->GetPacsState();
    if((pacs_state == ConnectionState::CONNECTED &&
        gatt_pending_data->pacs_pending_cmd == GattPendingCmd::NONE) ||
       (gatt_pending_data->pacs_pending_cmd ==
                                GattPendingCmd::GATT_CONN_PENDING)) {
      LOG(WARNING) << __func__  << " Issue PACS server disconnect ";
      pacs_client->Disconnect(pacs_client_id, strm_mgr_->GetAddress());
      gatt_pending_data->pacs_pending_cmd = GattPendingCmd::GATT_DISC_PENDING;
      disc_issued = true;
    }

    GattState ascs_state = strm_mgr_->GetAscsState();
    if((ascs_state == GattState::CONNECTED &&
        gatt_pending_data->ascs_pending_cmd == GattPendingCmd::NONE) ||
       (gatt_pending_data->ascs_pending_cmd ==
                                GattPendingCmd::GATT_CONN_PENDING)) {
      LOG(WARNING) << __func__  << " Issue ASCS server disconnect ";
      ascs_client->Disconnect(ASCS_CLIENT_ID, strm_mgr_->GetAddress());
      gatt_pending_data->ascs_pending_cmd = GattPendingCmd::GATT_DISC_PENDING;
      disc_issued = true;
    }
  }
  return disc_issued;
}

void StreamTracker::StateDisconnecting::OnEnter() {
  LOG(INFO) << __func__ << ": StreamTracker State: " << GetState();

  // check the previous state i.e connecting, starting, stopping
  // or reconfiguring

  UcastClientCallbacks* callbacks = strm_mgr_->GetUclientCbacks();
  StreamContexts *contexts = strm_mgr_->GetStreamContexts();
  std::vector<StreamStateInfo> strms;
  uint8_t num_ases = 0;

  std::vector<StreamType> *disc_streams = tracker_.GetStreams();
  LOG(WARNING) << __func__  << ": Disconection Streams Size: "
                            << disc_streams->size();

  StreamControlType control_type = tracker_.GetControlType();

  if(control_type != StreamControlType::Disconnect) {
    return;
  }

  for (auto it = disc_streams->begin(); it != disc_streams->end(); it++) {
    StreamStateInfo state;
    memset(&state, 0, sizeof(state));
    state.stream_type = *it;
    state.stream_state = StreamState::DISCONNECTING;
    strms.push_back(state);
    StreamContext *context = contexts->FindOrAddByType(*it);
    context->stream_state = StreamState::DISCONNECTING;
    if(context->connection_state == IntConnectState::ASCS_DISCOVERED) {
      for (auto id = context->stream_ids.begin();
              id != context->stream_ids.end(); id++) {
        bool can_be_disconnected = tracker_.
                       StreamCanbeDisconnected(context, id->ase_id);
        if(can_be_disconnected) {
          int_strm_trackers_.FindOrAddBytrackerType(*it,
                             id->ase_id, id->cig_id,
                             id->cis_id,
                             context->codec_config, context->qos_config);
        }
      }
    }
    num_ases += context->stream_ids.size();
  }
  callbacks->OnStreamState(strm_mgr_->GetAddress(), strms);

  uint64_t tout = num_ases *
                    (static_cast<uint64_t>(TimeoutVal::DisconnectingTimeout));
  if(!tout ||tout > static_cast<uint64_t>(MaxTimeoutVal::DisconnectingTimeout)) {
    tout = static_cast<uint64_t>(MaxTimeoutVal::DisconnectingTimeout);
  }

  TimeoutReason reason = TimeoutReason::STATE_TRANSITION;
  state_transition_timer = tracker_.SetTimer("StateDisconnectingTimer",
                &timeout, reason, tout);
  if (state_transition_timer == nullptr) {
    LOG(ERROR) << __func__  << ": StateDisconnecting: Alarm not allocated.";
    return;
  }

  bool gatt_disc_pending = TerminateGattConnection();
  // check if there are no internal stream trackers, then update to
  // upper layer as completely disconnected
  if(!int_strm_trackers_.size() && !gatt_disc_pending) {
    tracker_.TransitionTo(StreamTracker::kStateIdle);
  }
}

void StreamTracker::StateDisconnecting::ContinueDisconnection
                                (UcastAudioStream *stream) {

  // check ase state, return if state is not releasing or
  if(stream->ase_state != ascs::ASE_STATE_IDLE &&
     stream->ase_state != ascs::ASE_STATE_CODEC_CONFIGURED &&
     stream->ase_state != ascs::ASE_STATE_RELEASING) {
    LOG(WARNING) << __func__  << " Return as ASE is not moved to Right state";
    return;
  }

  CisInterface *cis_intf = strm_mgr_->GetCisInterface();

  // check if there is no pending CIS command then issue relevant
  // CIS command based on CIS state
  if(stream->cis_pending_cmd != CisPendingCmd::NONE) {
    LOG(INFO) << __func__  << ": cis_pending_cmd is not NONE ";
    return;
  }

  if(stream->cis_state == CisState::ESTABLISHED) {
    LOG(WARNING) << __func__  << ": Going For CIS disconnect ";
    IsoHciStatus status = cis_intf->DisconnectCis(stream->cig_id,
                                                  stream->cis_id,
                                                  stream->direction);
    if(status == IsoHciStatus::ISO_HCI_SUCCESS) {
      stream->cis_pending_cmd = CisPendingCmd::NONE;
      stream->cis_state = CisState::READY;
    } else if(status == IsoHciStatus::ISO_HCI_IN_PROGRESS) {
      stream->cis_pending_cmd = CisPendingCmd::CIS_DESTROY_ISSUED;
    } else {
      LOG(WARNING) << __func__  << ": CIS Disconnect Failed";
    }
  }

  if(stream->cis_state == CisState::READY) {
    if(stream->cig_state == CigState::CREATED &&
       stream->cis_pending_cmd == CisPendingCmd::NONE) {
      LOG(WARNING) << __func__  << ": Going For CIG Removal";
      IsoHciStatus status = cis_intf->RemoveCig(strm_mgr_->GetAddress(),
                              stream->cig_id);
      if( status == IsoHciStatus::ISO_HCI_SUCCESS) {
        stream->cig_state = CigState::INVALID;
        stream->cis_state = CisState::INVALID;
      } else if (status == IsoHciStatus::ISO_HCI_IN_PROGRESS) {
        stream->cis_pending_cmd = CisPendingCmd::CIG_REMOVE_ISSUED;
      } else {
        LOG(WARNING) << __func__  << ": CIG removal Failed";
      }
    }
  }
}

bool StreamTracker::StateDisconnecting::CheckAndUpdateDisconnectedState() {
  UcastAudioStreams *audio_strms = strm_mgr_->GetAudioStreams();
  bool pending_cmds = false;

  std::vector<IntStrmTracker *> *all_trackers =
                      int_strm_trackers_.GetTrackerList();

  // check if any pending commands are present
  for (auto i = all_trackers->begin(); i != all_trackers->end();i++) {
    UcastAudioStream *stream = audio_strms->FindByAseId((*i)->ase_id);
    if(stream && (stream->cis_pending_cmd != CisPendingCmd::NONE ||
                  stream->ase_pending_cmd != AscsPendingCmd::NONE)) {
      pending_cmds = true;
      break;
    }
  }

  if(pending_cmds) {
    LOG(WARNING) << __func__  << " Pending ASCS/CIS cmds present ";
    return false;
  }

  TerminateGattConnection();

  // check it needs to wait for ASCS & PACS disconnection also
  GattPendingData *gatt_pending_data = strm_mgr_->GetGattPendingData();
  if(gatt_pending_data->ascs_pending_cmd != GattPendingCmd::NONE ||
     gatt_pending_data->pacs_pending_cmd != GattPendingCmd::NONE) {
    LOG(WARNING) << __func__  << " Pending Gatt disc present ";
    return false;
  }

  // check for all trackers moved to idle and
  // CIG state is idle if so update it as streams are disconnected
  uint8_t num_strms_disconnected = 0;
  for (auto i = all_trackers->begin(); i != all_trackers->end();i++) {
    UcastAudioStream *stream = audio_strms->FindByAseId((*i)->ase_id);
    if (!stream) {
      LOG(ERROR) << __func__  << "stream is null";
      continue;
    }
    if((stream->ase_state == ascs::ASE_STATE_IDLE ||
       stream->ase_state == ascs::ASE_STATE_CODEC_CONFIGURED) &&
       (stream->cig_state == CigState::IDLE ||
       stream->cig_state == CigState::INVALID) &&
       (stream->cis_state == CisState::READY ||
        stream->cis_state == CisState::INVALID)) {
      num_strms_disconnected++;
    }
  }

  if(int_strm_trackers_.size() != num_strms_disconnected) {
    LOG(WARNING) << __func__  << "Not disconnected for all streams";
    return false;
  } else {
    LOG(ERROR) << __func__  << "Disconnected for all streams";
  }

  for (auto i = all_trackers->begin(); i != all_trackers->end();i++) {
    UcastAudioStream *stream = audio_strms->FindByAseId((*i)->ase_id);
    if (stream) {
      stream->overall_state = StreamTracker::kStateIdle;
    }
  }

  // update the state to idle
  tracker_.TransitionTo(StreamTracker::kStateIdle);
  return true;
}

void StreamTracker::StateDisconnecting::OnExit() {
  tracker_.ClearTimer(state_transition_timer, "StateDisconnectingTimer");
}

bool StreamTracker::StateDisconnecting::ProcessEvent(uint32_t event,
                                                     void* p_data) {
  LOG(INFO) <<__func__  <<": BD Addr = " << strm_mgr_->GetAddress()
                        <<": State = " << GetState()
                        <<": Event = " << tracker_.GetEventName(event);

  switch (event) {
    case PACS_CONNECTION_STATE_EVT: {
      PacsConnectionState *pacs_state =  (PacsConnectionState *) p_data;
      GattPendingData *gatt_pending_data = strm_mgr_->GetGattPendingData();
      if(pacs_state->state == ConnectionState::DISCONNECTED) {
        gatt_pending_data->pacs_pending_cmd = GattPendingCmd::NONE;
      }
      CheckAndUpdateDisconnectedState();
    } break;
    case ASCS_CONNECTION_STATE_EVT: {
      AscsConnectionState *ascs_state =  (AscsConnectionState *) p_data;
      GattPendingData *gatt_pending_data = strm_mgr_->GetGattPendingData();
      if(ascs_state->state == GattState::DISCONNECTED) {
        // make all streams ASE state to idle so that further processing
        // can happen
        gatt_pending_data->ascs_pending_cmd = GattPendingCmd::NONE;
        UcastAudioStreams *audio_strms = strm_mgr_->GetAudioStreams();
        std::vector<UcastAudioStream *> *strms_list =
                                             audio_strms->GetAllStreams();

        for (auto it = strms_list->begin(); it != strms_list->end(); it++) {

          (*it)->ase_state = ascs::ASE_STATE_IDLE;
          (*it)->ase_pending_cmd = AscsPendingCmd::NONE;
          (*it)->overall_state = StreamTracker::kStateIdle;
          ContinueDisconnection(*it);
        }
      }
      CheckAndUpdateDisconnectedState();
    } break;
    case ASCS_ASE_STATE_EVT: {  // to handle remote driven operations

      // check for state releasing
      // based on prev state do accordingly
      AscsState *ascs =  ((AscsState *) p_data);

      uint8_t ase_id = ascs->ase_params.ase_id;

      // check if current stream tracker is interested in this ASE update
      if(int_strm_trackers_.FindByAseId(ase_id)
                                 == nullptr) {
        LOG(INFO) << __func__  << "Not intended for this tracker";
        break;
      }

      UcastAudioStreams *audio_strms = strm_mgr_->GetAudioStreams();
      UcastAudioStream *stream = audio_strms->FindByAseId(ase_id);

      if(stream == nullptr) {
        break;
      } else {
        stream->ase_state = ascs->ase_params.ase_state;
        stream->ase_params = ascs->ase_params;
      }

      if(ascs->ase_params.ase_state == ascs::ASE_STATE_RELEASING) {
        // find out the stream for the given ase id
        LOG(WARNING) << __func__  << " ASE Id " << loghex(ase_id);
        stream->ase_pending_cmd = AscsPendingCmd::NONE;
        ContinueDisconnection(stream);

      } else if( ascs->ase_params.ase_state ==
                                    ascs::ASE_STATE_CODEC_CONFIGURED) {
        // check if this is a codec config notification due to codec config
        // issued during connecting state
        if((tracker_.PreviousStateId() == StreamTracker::kStateConnecting ||
            tracker_.PreviousStateId() == StreamTracker::kStateReconfiguring) &&
           stream->ase_pending_cmd == AscsPendingCmd::CODEC_CONFIG_ISSUED &&
           stream->ase_state == ascs::ASE_STATE_CODEC_CONFIGURED) {
          // mark int conn state as codec configured and issue release command
          std::vector<AseReleaseOp> ase_ops;
          AscsClient *ascs_client = strm_mgr_->GetAscsClient();
          AseReleaseOp release_op = {
                              .ase_id = stream->ase_id
          };
          ase_ops.push_back(release_op);
          stream->ase_pending_cmd = AscsPendingCmd::RELEASE_ISSUED;
          ascs_client->Release(ASCS_CLIENT_ID,
                       strm_mgr_->GetAddress(), ase_ops);
          break; // break the switch case
        } else {
          stream->ase_pending_cmd = AscsPendingCmd::NONE;
          stream->overall_state = StreamTracker::kStateIdle;
          ContinueDisconnection(stream);
          CheckAndUpdateDisconnectedState();
        }
      } else if(ascs->ase_params.ase_state == ascs::ASE_STATE_IDLE) {
        // check for all trackers moved to idle and
        // CIG state is idle if so update it as streams are disconnected
        stream->ase_pending_cmd = AscsPendingCmd::NONE;
        stream->overall_state = StreamTracker::kStateIdle;
        ContinueDisconnection(stream);
        CheckAndUpdateDisconnectedState();
      }
    } break;

    case ASCS_ASE_OP_FAILED_EVT: {
      AscsOpFailed *ascs_op =  ((AscsOpFailed *) p_data);
      std::vector<ascs::AseOpStatus> *ase_list = &ascs_op->ase_list;
      UcastAudioStreams *audio_strms = strm_mgr_->GetAudioStreams();

      if(ascs_op->ase_op_id == ascs::AseOpId::RELEASE) {
        // treat it like internal failure
        for (auto i = ase_list->begin(); i != ase_list->end();i++) {
          UcastAudioStream *stream = audio_strms->FindByAseId((i)->ase_id);
          if(stream) {
            stream->ase_state = ascs::ASE_STATE_IDLE;
            stream->ase_pending_cmd = AscsPendingCmd::NONE;
            stream->overall_state = StreamTracker::kStateIdle;
            ContinueDisconnection(stream);
          }
        }
        CheckAndUpdateDisconnectedState();
      }
    } break;

    case CIS_GROUP_STATE_EVT: {
      // check if the associated CIG state is created
      // if so go for QOS config operation
      CisGroupState *data = ((CisGroupState *) p_data);

      // check if current stream tracker is interested in this CIG update
      std::vector<IntStrmTracker *> int_trackers =
                            int_strm_trackers_.FindByCigId(data->cig_id);
      if(int_trackers.empty()) {
        LOG(INFO) << __func__  << "Not intended for this tracker";
        break;
      }

      UcastAudioStreams *audio_strms = strm_mgr_->GetAudioStreams();
      if(data->state == CigState::CREATED) {
        for (auto i = int_trackers.begin(); i != int_trackers.end();i++) {
          UcastAudioStream *stream = audio_strms->FindByAseId((*i)->ase_id);
          if (stream) {
            stream->cis_pending_cmd = CisPendingCmd::NONE;
            stream->cig_state = data->state;
            stream->cis_state = CisState::READY;
            // check if this is a CIG created event due to CIG create
            // issued during starting state
            ContinueDisconnection(stream);
          }
        }
        CheckAndUpdateDisconnectedState();

      } else if(data->state == CigState::IDLE) {
        for (auto i = int_trackers.begin(); i != int_trackers.end();i++) {
          UcastAudioStream *stream = audio_strms->FindByAseId((*i)->ase_id);
          if (!stream) {
            LOG(ERROR) << __func__  << "stream is null";
            continue;
          }
          stream->cig_state = CigState::INVALID;
          stream->cis_state = CisState::INVALID;
          stream->cis_pending_cmd = CisPendingCmd::NONE;
        }
        CheckAndUpdateDisconnectedState();
      }
    } break;
    case CIS_STATE_EVT: {
      CisStreamState *data = (CisStreamState *) p_data;
      UcastAudioStreams *audio_strms = strm_mgr_->GetAudioStreams();
      // check if current stream tracker is interested in this CIG update
      std::vector<IntStrmTracker *> int_trackers =
                   int_strm_trackers_.FindByCisId(data->cig_id, data->cis_id);
      if(int_trackers.empty()) {
        LOG(INFO) << __func__  << "Not intended for this tracker";
        break;
      }

      // go for CIS destroy or CIG removal based on CIS state
      if(data->state == CisState::ESTABLISHED) {
        for(auto it = directions.begin(); it != directions.end(); ++it) {
          if(data->direction & *it) {
            UcastAudioStream *stream = audio_strms->FindByCisIdAndDir
                                       (data->cig_id, data->cis_id, *it);
            if(stream) {
              stream->cis_state = data->state;
              stream->cis_pending_cmd = CisPendingCmd::NONE;
              ContinueDisconnection(stream);
            }
          }
        }
      } else if(data->state == CisState::READY) {
        for(auto it = directions.begin(); it != directions.end(); ++it) {
          if(data->direction & *it) {
            UcastAudioStream *stream = audio_strms->FindByCisIdAndDir
                                       (data->cig_id, data->cis_id, *it);
            if(stream) {
              stream->cis_state = data->state;
              stream->cis_pending_cmd = CisPendingCmd::NONE;
              ContinueDisconnection(stream);
            }
          }
        }
        CheckAndUpdateDisconnectedState();
      }
    } break;

    case BAP_TIME_OUT_EVT: {
      BapTimeout* timeout = static_cast <BapTimeout *> (p_data);
      if (timeout == nullptr) {
        LOG(INFO) << __func__ << ": timeout data null, return ";
        break;
      }

      int stream_tracker_id = timeout->transition_state;
      LOG(INFO) << __func__ << ": stream_tracker_ID: " << stream_tracker_id
                << ", timeout reason: " << static_cast<int>(timeout->reason);

      std::vector<IntStrmTracker *> *int_trackers =
                            int_strm_trackers_.GetTrackerList();
      if (timeout->reason == TimeoutReason::STATE_TRANSITION) {
        UcastAudioStreams *audio_strms = strm_mgr_->GetAudioStreams();
        for (auto i = int_trackers->begin(); i != int_trackers->end();i++) {
          UcastAudioStream *stream = audio_strms->FindByAseId((*i)->ase_id);
          if(stream) {
            stream->ase_state = ascs::ASE_STATE_IDLE;
            stream->ase_pending_cmd = AscsPendingCmd::NONE;
            stream->overall_state = StreamTracker::kStateIdle;
            ContinueDisconnection(stream);
          }
        }
        CheckAndUpdateDisconnectedState();
      }
    } break;
    default:
      LOG(WARNING) << __func__ << ": Un-handled event: "
                               << tracker_.GetEventName(event);
      break;
  }
  return true;
}

void StreamTracker::StateReconfiguring::OnEnter() {
  LOG(INFO) << __func__ << ": StreamTracker State: " << GetState();
  UcastClientCallbacks* callbacks = strm_mgr_->GetUclientCbacks();
  StreamContexts *contexts = strm_mgr_->GetStreamContexts();
  std::vector<StreamStateInfo> strms;
  std::vector<StreamReconfig> *reconfig_streams = tracker_.GetReconfStreams();
  uint8_t num_ases = 0;

  LOG(WARNING) << __func__  << ": Reconfig Streams Size: "
                            << reconfig_streams->size();

  StreamControlType control_type = tracker_.GetControlType();

  if(control_type != StreamControlType::Reconfig) return;

  for (auto it = reconfig_streams->begin();
                       it != reconfig_streams->end(); it++) {
    StreamStateInfo state;
    memset(&state, 0, sizeof(state));
    state.stream_type = it->stream_type;
    state.stream_state = StreamState::RECONFIGURING;
    strms.push_back(state);
    StreamContext *context = contexts->FindOrAddByType(it->stream_type);
    context->connection_state = IntConnectState::PACS_DISCOVERING;
    context->stream_state = StreamState::RECONFIGURING;
    num_ases += context->stream_ids.size();
  }
  callbacks->OnStreamState(strm_mgr_->GetAddress(), strms);

  uint64_t tout = num_ases *
                    (static_cast<uint64_t>(TimeoutVal::ReconfiguringTimeout));
  if(!tout ||tout > static_cast<uint64_t>(MaxTimeoutVal::ReconfiguringTimeout)){
    tout = static_cast<uint64_t>(MaxTimeoutVal::ReconfiguringTimeout);
  }

  TimeoutReason reason = TimeoutReason::STATE_TRANSITION;
  state_transition_timer = tracker_.SetTimer("StateReconfiguringTimer",
            &timeout, reason, tout);
  if (state_transition_timer == nullptr) {
    LOG(ERROR) << __func__  << ": state_transition_timer: Alarm not allocated.";
    return;
  }
}

void StreamTracker::StateReconfiguring::OnExit() {
  tracker_.ClearTimer(state_transition_timer, "StateReconfiguringTimer");
}

bool StreamTracker::StateReconfiguring::ProcessEvent(uint32_t event,
                                                     void* p_data) {
  LOG(INFO) <<__func__  <<": BD Addr = " << strm_mgr_->GetAddress()
                        <<": State = " << GetState()
                        <<": Event = " << tracker_.GetEventName(event);

  std::vector<StreamReconfig> *reconf_streams = tracker_.GetReconfStreams();
  StreamContexts *contexts = strm_mgr_->GetStreamContexts();
  uint8_t num_reconf_streams = 0;
  if(reconf_streams) {
     num_reconf_streams = reconf_streams->size();
  }
  UcastAudioStreams *audio_strms = strm_mgr_->GetAudioStreams();
  AscsClient *ascs_client = strm_mgr_->GetAscsClient();

  switch (event) {
    case BAP_DISCONNECT_REQ_EVT: {
      tracker_.HandleDisconnect(p_data, StreamTracker::kStateReconfiguring);
    } break;
    case PACS_DISCOVERY_RES_EVT: {
      PacsDiscovery pacs_discovery_ =  *((PacsDiscovery *) p_data);
      GattState ascs_state = strm_mgr_->GetAscsState();
      uint8_t qos_reconfigs = 0;

      bool process_pacs_results = false;

      // check if this tracker already passed the pacs discovery stage
      for (auto it = reconf_streams->begin();
                        it != reconf_streams->end(); it++) {
        StreamContext *context = contexts->FindOrAddByType(it->stream_type);
        if (context->connection_state == IntConnectState::PACS_DISCOVERING) {
          context->connection_state = IntConnectState::ASCS_DISCOVERED;
          process_pacs_results = true;
        }
      }

      if(!process_pacs_results) break;

      // check the status
      if(pacs_discovery_.status) {
        // send the BAP callback as connected as discovery failed
        // during reconfiguring
        tracker_.TransitionTo(StreamTracker::kStateConnected);
        return false;
      }

      tracker_.UpdatePacsDiscovery(pacs_discovery_);

      // check if supported audio contexts has required contexts
      for (auto it = reconf_streams->begin();
                           it != reconf_streams->end();) {
        bool context_supported = false;
        StreamType stream = it->stream_type;
        if(stream.direction == ASE_DIRECTION_SINK) {
          if(stream.audio_context & pacs_discovery_.supported_contexts) {
            context_supported = true;
          }
        } else if(stream.direction == ASE_DIRECTION_SRC) {
          if((static_cast<uint64_t>(stream.audio_context) << 16) &
               pacs_discovery_.supported_contexts) {
            context_supported = true;
          }
        }
        if(context_supported) {
          it++;
        } else {
          it = reconf_streams->erase(it);
          // TODO to update the disconnected callback
        }
      }

      if(reconf_streams->empty()) {
        LOG(ERROR) << __func__  << " No Matching Sup Contexts found";
        LOG(ERROR) << __func__  << " Moving back to Connected state";
        tracker_.TransitionTo(StreamTracker::kStateConnected);
        break;
      }

      // check physical allocation for all reconfig requests
      uint8_t num_phy_attached = 0;
      uint8_t num_same_config_applied = 0;
      // if not present send the BAP callback as disconnected
      // compare the codec configs from upper layer to remote dev
      // sink or src PACS records/capabilities.
      for (auto it = reconf_streams->begin();
                           it != reconf_streams->end(); it++) {
        uint8_t index = tracker_.ChooseBestCodec(it->stream_type,
                                 &it->codec_qos_config_pair,
                                 &pacs_discovery_);
        if(index != 0XFF) {
          CodecQosConfig entry = it->codec_qos_config_pair.at(index);
          StreamContext *context = contexts->FindOrAddByType(
                                             it->stream_type);
          if(context->attached_state == StreamAttachedState::PHYSICAL) {
            num_phy_attached++;
            // check if same config is already applied
            if(IsCodecConfigEqual(&context->codec_config,&entry.codec_config)) {
              num_same_config_applied++;
            }
          }
        } else {
          LOG(ERROR) << __func__  << " Matching Codec not found";
        }
      }

      if(reconf_streams->size() == num_phy_attached &&
         num_phy_attached == num_same_config_applied) {
        // update the state to connected
        LOG(INFO) << __func__  << " Making state to Connected as Nothing to do";
        TransitionTo(StreamTracker::kStateConnected);
        break;
      }

      if(ascs_state != GattState::CONNECTED) {
        break;
      }

      for (auto it = reconf_streams->begin();
                           it != reconf_streams->end(); it++) {
        uint8_t index = tracker_.ChooseBestCodec(it->stream_type,
                                 &it->codec_qos_config_pair,
                                 &pacs_discovery_);
        if(index != 0XFF) {
          CodecQosConfig entry = it->codec_qos_config_pair.at(index);
          StreamContext *context = contexts->FindOrAddByType(
                                             it->stream_type);
          CodecConfig codec_config = entry.codec_config;
          QosConfig qos_config = entry.qos_config;

          if(context->attached_state == StreamAttachedState::VIRTUAL) {
            std::vector<StreamContext *> phy_attached_contexts;
            for (auto id = context->stream_ids.begin();
                      id != context->stream_ids.end(); id++) {
              std::vector<StreamContext *> phy_attached_contexts;
              phy_attached_contexts = contexts->FindByAseAttachedState(
                                    id->ase_id, StreamAttachedState::PHYSICAL);
              for (auto context_id = phy_attached_contexts.begin();
                        context_id != phy_attached_contexts.end();
                        context_id++) {
                LOG(INFO) << __func__ << ":Attached state made virtual";
                (*context_id)->attached_state = StreamAttachedState::VIRTUAL;
              }
            }
            LOG(INFO) << __func__ << ":Attached state made virtual to phy";
            context->attached_state = StreamAttachedState::VIR_TO_PHY;
            context->codec_config = codec_config;
            context->req_qos_config = qos_config;
          } else if (context->attached_state == StreamAttachedState::PHYSICAL) {
            LOG(INFO) << __func__ << ":Attached state is physical";
            // check if same config is already applied
            if(IsCodecConfigEqual(&context->codec_config,&entry.codec_config)) {
              if(it->reconf_type == StreamReconfigType::CODEC_CONFIG) {
                it->reconf_type = StreamReconfigType::QOS_CONFIG;
              }
            } else {
              context->codec_config = codec_config;
            }
            context->req_qos_config = qos_config;
          }

          uint8_t ascs_config_index = 0;
          for (auto id = context->stream_ids.begin();
                    id != context->stream_ids.end(); id++) {
            int_strm_trackers_.FindOrAddBytrackerType(it->stream_type,
                        id->ase_id,
                        qos_config.ascs_configs[ascs_config_index].cig_id,
                        qos_config.ascs_configs[ascs_config_index].cis_id,
                        codec_config,
                        qos_config);
            UcastAudioStream *stream = audio_strms->FindByAseId(id->ase_id);
            if (!stream) {
              LOG(ERROR) << __func__  << "stream is null";
              continue;
            }
            stream->cig_id = id->cig_id =
                            qos_config.ascs_configs[ascs_config_index].cig_id;
            stream->cis_id = id->cis_id =
                            qos_config.ascs_configs[ascs_config_index].cis_id;
            stream->cig_state = CigState::INVALID;
            stream->cis_state = CisState::INVALID;
            stream->codec_config = codec_config;
            stream->req_qos_config = qos_config;
            stream->qos_config = qos_config;
            stream->audio_context = it->stream_type.audio_context;
            ascs_config_index++;
          }
        } else {
          LOG(ERROR) << __func__  << " Matching Codec not found";
        }
      }
      for (auto it = reconf_streams->begin();
                it != reconf_streams->end(); it++) {
        if (it->reconf_type == StreamReconfigType::QOS_CONFIG) {
          qos_reconfigs++;
        }
      }

      if(qos_reconfigs == num_reconf_streams) {
        // now create the group
        std::vector<IntStrmTracker *> *all_trackers =
                            int_strm_trackers_.GetTrackerList();
        // check for all streams together so that final group params
        // will be decided.
        for (auto i = all_trackers->begin(); i != all_trackers->end();i++) {
          UcastAudioStream *stream = audio_strms->FindByAseId((*i)->ase_id);
          if (!stream) {
            LOG(ERROR) << __func__  << "stream is null";
            continue;
          }
          tracker_.ChooseBestQos(&stream->req_qos_config,
                                 &stream->pref_qos_params,
                                 &stream->qos_config,
                                 StreamTracker::kStateReconfiguring,
                                 stream->direction);
        }
        tracker_.CheckAndSendQosConfig(&int_strm_trackers_);
      } else {
        // now send the ASCS codec config
        std::vector<AseCodecConfigOp> ase_ops;
        for (auto it = reconf_streams->begin();
                             it != reconf_streams->end(); it++) {
          if(it->reconf_type == StreamReconfigType::CODEC_CONFIG) {
            StreamContext *context = contexts->FindOrAddByType(it->stream_type);
            for (auto id = context->stream_ids.begin();
                      id != context->stream_ids.end(); id++) {
              UcastAudioStream *stream = audio_strms->FindByAseId(id->ase_id);
              if (stream) {
                tracker_.PrepareCodecConfigPayload(&ase_ops, stream);
              }
            }
          }
        }

        if(!ase_ops.empty()) {
          LOG(WARNING) << __func__  << ": Going For ASCS CodecConfig op";
          ascs_client->CodecConfig(ASCS_CLIENT_ID,
                       strm_mgr_->GetAddress(), ase_ops);
        }

        // update the states to connecting or other internal states
        for (auto it = reconf_streams->begin();
                             it != reconf_streams->end(); it++) {
          if(it->reconf_type == StreamReconfigType::CODEC_CONFIG) {
            StreamContext *context = contexts->FindOrAddByType(it->stream_type);
            for (auto id = context->stream_ids.begin();
                      id != context->stream_ids.end(); id++) {
              UcastAudioStream *stream = audio_strms->FindByAseId(id->ase_id);
              if (stream) {
                stream->ase_pending_cmd = AscsPendingCmd::CODEC_CONFIG_ISSUED;
                stream->overall_state = StreamTracker::kStateReconfiguring;
              }
            }
          } else {
            StreamContext *context = contexts->FindOrAddByType(it->stream_type);
            for (auto id = context->stream_ids.begin();
                      id != context->stream_ids.end(); id++) {
              UcastAudioStream *stream = audio_strms->FindByAseId(id->ase_id);
              if (stream) {
                stream->overall_state = StreamTracker::kStateReconfiguring;
              }
            }
          }
        }
      }
    } break;

    case ASCS_ASE_STATE_EVT: {
      tracker_.HandleAseStateEvent(p_data, StreamControlType::Reconfig,
                                   &int_strm_trackers_);
    } break;

    case ASCS_ASE_OP_FAILED_EVT: {
      tracker_.HandleAseOpFailedEvent(p_data);
    } break;

    case PACS_CONNECTION_STATE_EVT: {
      tracker_.HandlePacsConnectionEvent(p_data);
    } break;

    case ASCS_CONNECTION_STATE_EVT: {
      tracker_.HandleAscsConnectionEvent(p_data);
    } break;

    case BAP_TIME_OUT_EVT: {
      tracker_.OnTimeout(p_data);
    } break;

    default:
      LOG(WARNING) << __func__ << ": Un-handled event: "
                               << tracker_.GetEventName(event);
      break;
  }
  return true;
}

}  // namespace ucast
}  // namespace bap
}  // namespace bluetooth
