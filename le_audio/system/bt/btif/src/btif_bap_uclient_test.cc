/******************************************************************************
 *  Copyright (c) 2020, The Linux Foundation. All rights reserved.
 *****************************************************************************/

#include "bta_closure_api.h"
#include "bta_bap_uclient_api.h"
#include "btif_common.h"
#include "btif_storage.h"
#include "osi/include/thread.h"
#include "btif_bap_codec_utils.h"

#include "osi/include/properties.h"

extern void do_in_bta_thread(const base::Location& from_here,
                             const base::Closure& task);
#include <base/bind.h>
#include <base/callback.h>
#include <base/location.h>
#include <base/logging.h>
#include <hardware/bluetooth.h>
#include <hardware/bt_pacs_client.h>
#include <hardware/bt_bap_uclient.h>
#include "btif_bap_config.h"

using base::Bind;
using base::Unretained;
using bluetooth::bap::ucast::UcastClient;
using bluetooth::bap::pacs::CodecConfig;
using bluetooth::bap::pacs::ConnectionState;
using bluetooth::bap::ucast::UcastClientCallbacks;
using bluetooth::bap::ucast::UcastClientInterface;
using bluetooth::bap::ucast::StreamConnect;
using bluetooth::bap::ucast::StreamType;
using bluetooth::bap::ucast::StreamStateInfo;
using bluetooth::bap::ucast::StreamConfigInfo;
using bluetooth::bap::ucast::StreamReconfig;

using bluetooth::bap::pacs::CodecIndex;
using bluetooth::bap::pacs::CodecPriority;
using bluetooth::bap::pacs::CodecSampleRate;
using bluetooth::bap::pacs::CodecFrameDuration;
using bluetooth::bap::pacs::CodecChannelMode;
using bluetooth::bap::ucast::CodecQosConfig;
using bluetooth::bap::ucast::CISConfig;
using bluetooth::bap::ucast::CONTENT_TYPE_MEDIA;
using bluetooth::bap::ucast::CONTENT_TYPE_CONVERSATIONAL;
using bluetooth::bap::ucast::CONTENT_TYPE_GAME;
using bluetooth::bap::ucast::CONTENT_TYPE_LIVE;
using bluetooth::bap::ucast::CONTENT_TYPE_UNSPECIFIED;
using bluetooth::bap::ucast::ASE_DIRECTION_SRC;
using bluetooth::bap::ucast::ASE_DIRECTION_SINK;
using bluetooth::bap::ucast::StreamReconfigType;
using bluetooth::bap::ucast::ASCSConfig;

static thread_t *test_thread;
static UcastClientInterface* sUcastClientInterface = nullptr;
static RawAddress bap_bd_addr;

extern bluetooth::bap::pacs::PacsClientInterface* btif_pacs_client_get_interface();

class UcastClientCallbacksImpl : public UcastClientCallbacks {
 public:
  ~UcastClientCallbacksImpl() = default;
  void OnStreamState(const RawAddress &address,
                 std::vector<StreamStateInfo> streams_state_info) override {
    for (auto it = streams_state_info.begin();
                         it != streams_state_info.end(); it++) {
      LOG(WARNING) << __func__ << " stream type " << (it->stream_type.type);
      LOG(WARNING) << __func__ << " stream dir " << loghex(it->stream_type.direction);
      LOG(WARNING) << __func__ << " stream state " << static_cast<int> (it->stream_state);
    }
  }
  void OnStreamConfig(const RawAddress &address,
               std::vector<StreamConfigInfo> streams_config_info) override {
    LOG(WARNING) << __func__;
    for (auto it = streams_config_info.begin();
                         it != streams_config_info.end(); it++) {
      LOG(WARNING) << __func__ << " stream type " << (it->stream_type.type);
      LOG(WARNING) << __func__ << " stream dir " << loghex(it->stream_type.direction);
      LOG(WARNING) << __func__ << " location " << static_cast<int> (it->audio_location);
      btif_bap_add_record(address, REC_TYPE_CONFIGURATION,
                          it->stream_type.type,
                          static_cast<CodecDirection> (it->stream_type.direction),
                          &it->codec_config);

      std::vector<CodecConfig> acm_pac_records;

      btif_bap_get_records(address,
                                REC_TYPE_CAPABILITY,
                                CONTENT_TYPE_MEDIA |
                                CONTENT_TYPE_UNSPECIFIED,
                                static_cast<CodecDirection>
                                (it->stream_type.direction),
                                &acm_pac_records);

      LOG(WARNING) << __func__ << " acm len  to be 3" << (acm_pac_records.size());

      std::vector<CodecConfig> config_pac_records;
      btif_bap_get_records(address,
                                REC_TYPE_CONFIGURATION,
                                CONTENT_TYPE_MEDIA,
                                static_cast<CodecDirection>
                                (it->stream_type.direction),
                                &config_pac_records);

      LOG(WARNING) << __func__ << " configs len to be 1" << (config_pac_records.size());

      btif_bap_remove_record_by_context (address, REC_TYPE_CONFIGURATION,
                          it->stream_type.type,
                          static_cast<CodecDirection>
                           (it->stream_type.direction));

      config_pac_records.clear();
      btif_bap_get_records(address,
                                REC_TYPE_CONFIGURATION,
                                CONTENT_TYPE_MEDIA,
                                static_cast<CodecDirection>
                                (it->stream_type.direction),
                                &config_pac_records);

      LOG(WARNING) << __func__ << " configs len to be 0" << (config_pac_records.size());

#if 0
      btif_bap_remove_record_by_context (address, REC_TYPE_CAPABILITY,
                                CONTENT_TYPE_MEDIA |
                                CONTENT_TYPE_UNSPECIFIED,
                          static_cast<CodecDirection>
                           (it->stream_type.direction));

      acm_pac_records.clear();
      btif_bap_get_records(address,
                                REC_TYPE_CAPABILITY,
                                CONTENT_TYPE_MEDIA |
                                CONTENT_TYPE_UNSPECIFIED,
                                static_cast<CodecDirection>
                                (it->stream_type.direction),
                                &acm_pac_records);

      LOG(WARNING) << __func__ << " acm len to be 0" << (acm_pac_records.size());
#endif
    }
  }
  void OnStreamAvailable(const RawAddress &address,
                      uint16_t src_audio_contexts,
                      uint16_t sink_audio_contexts)  override {
    LOG(WARNING) << __func__;
  }
};

static UcastClientCallbacksImpl sUcastClientCallbacks;

static void event_test_bap_uclient(UNUSED_ATTR void* context) {
  LOG(INFO) << __func__ << " start " ;
  sUcastClientInterface = bluetooth::bap::ucast::btif_bap_uclient_get_interface();
  sUcastClientInterface->Init(&sUcastClientCallbacks);
  sleep(1);

  StreamConnect conn_info;
  CodecQosConfig codec_qos_config;
  codec_qos_config.codec_config.codec_type = CodecIndex::CODEC_INDEX_SOURCE_LC3;
  codec_qos_config.codec_config.codec_priority =
                                  CodecPriority::CODEC_PRIORITY_DEFAULT;
  codec_qos_config.codec_config.sample_rate =
                                  CodecSampleRate::CODEC_SAMPLE_RATE_48000;
  codec_qos_config.codec_config.channel_mode =
                                  CodecChannelMode::CODEC_CHANNEL_MODE_MONO;
  //Frame_Duration
  UpdateFrameDuration(&codec_qos_config.codec_config,
                     static_cast<uint8_t>(CodecFrameDuration::FRAME_DUR_10));
  // LC3_Blocks_Per_SDU
  UpdateLc3BlocksPerSdu(&codec_qos_config.codec_config, 1);
  UpdateOctsPerFrame(&codec_qos_config.codec_config, 100);
  codec_qos_config.qos_config.cig_config = {
                                     .cig_id = 1,
                                     .cis_count = 2,
                                     .packing = 0x01, // interleaved
                                     .framing =  0x00, // unframed
                                     .max_tport_latency_m_to_s =  0x000a,
                                     .max_tport_latency_s_to_m = 0x000a,
                                     .sdu_interval_m_to_s = {0x10, 0x27, 0x00},
                                     .sdu_interval_s_to_m = {0x10, 0x27, 0x00}
                                    };
  CISConfig cis_config_1 = {
                                     .cis_id = 0,
                                     .max_sdu_m_to_s = 100,
                                     .max_sdu_s_to_m = 0,
                                     .phy_m_to_s = 0x02,
                                     .phy_s_to_m = 0x02,
                                     .rtn_m_to_s = 0x02,
                                     .rtn_s_to_m = 0x02
                           };
  CISConfig cis_config_2 = {
                                     .cis_id = 1,
                                     .max_sdu_m_to_s = 100,
                                     .max_sdu_s_to_m = 0,
                                     .phy_m_to_s = 0x02,
                                     .phy_s_to_m = 0x02,
                                     .rtn_m_to_s = 0x02,
                                     .rtn_s_to_m = 0x02
                           };
  codec_qos_config.qos_config.cis_configs.push_back(cis_config_1);
  codec_qos_config.qos_config.cis_configs.push_back(cis_config_2);

  ASCSConfig ascs_config =  {
    .cig_id = 1,
    .cis_id = 0,
    .bi_directional = false,
    .presentation_delay = {0x20, 0x4E, 0x00}
  };
  codec_qos_config.qos_config.ascs_configs.push_back(ascs_config);
  conn_info.stream_type.type = 0x0004; // media
  conn_info.stream_type.direction = ASE_DIRECTION_SINK;
  conn_info.stream_type.audio_context =
                            CONTENT_TYPE_MEDIA;
  conn_info.codec_qos_config_pair.push_back(codec_qos_config);
  std::vector<StreamConnect> streams;
  streams.push_back(conn_info);

  ASCSConfig ascs_config_2 =  {
    .cig_id = 1,
    .cis_id = 1,
    .bi_directional = false,
    .presentation_delay = {0x20, 0x4E, 0x00}
  };

  codec_qos_config.qos_config.ascs_configs.clear();
  codec_qos_config.qos_config.ascs_configs.push_back(ascs_config_2);
  StreamConnect conn_info_2;
  conn_info_2.stream_type.type = 0x0004; // media
  conn_info_2.stream_type.direction = ASE_DIRECTION_SINK;
  conn_info_2.stream_type.audio_context =
                            CONTENT_TYPE_MEDIA;
  conn_info_2.codec_qos_config_pair.push_back(codec_qos_config);
  std::vector<StreamConnect> streams_2;
  streams_2.push_back(conn_info_2);

  // reconfig information
  std::vector<StreamReconfig> reconf_streams;
  codec_qos_config.qos_config.ascs_configs[0].cis_id = 1;
  UpdateFrameDuration(&codec_qos_config.codec_config,
                    static_cast<uint8_t>(CodecFrameDuration::FRAME_DUR_7_5));

  codec_qos_config.qos_config.cig_config = {
                                     .cig_id = 1,
                                     .cis_count = 2,
                                     .packing = 0x01, // interleaved
                                     .framing =  0x00, // unframed
                                     .max_tport_latency_m_to_s =  0x000a,
                                     .max_tport_latency_s_to_m = 0x000a,
                                     .sdu_interval_m_to_s = {0x4C, 0x1D, 0x00},
                                     .sdu_interval_s_to_m = {0x4C, 0x1D, 0x00}
                                    };

  StreamReconfig reconf_info;
  reconf_info.stream_type.type = 0x0004; // media
  reconf_info.reconf_type = StreamReconfigType::CODEC_CONFIG;
  reconf_info.stream_type.direction = ASE_DIRECTION_SINK;
  reconf_info.codec_qos_config_pair.push_back(codec_qos_config);
  reconf_streams.push_back(reconf_info);

  std::vector<StreamReconfig> reconf_qos_streams;
  StreamReconfig reconf_qos_info;
  reconf_qos_info.stream_type.type = 0x0004; // media
  reconf_qos_info.reconf_type = StreamReconfigType::QOS_CONFIG;
  reconf_qos_info.stream_type.direction = ASE_DIRECTION_SINK;
  codec_qos_config.qos_config.cis_configs.clear();

  cis_config_1.rtn_m_to_s = 1;
  cis_config_1.rtn_s_to_m = 1;
  cis_config_2.rtn_m_to_s = 1;
  cis_config_2.rtn_s_to_m = 1;
  codec_qos_config.qos_config.cis_configs.push_back(cis_config_1);
  codec_qos_config.qos_config.cis_configs.push_back(cis_config_2);
  reconf_qos_info.codec_qos_config_pair.push_back(codec_qos_config);
  reconf_qos_streams.push_back(reconf_qos_info);

  StreamType type_1 = { .type = 0x0004,
                        .direction = ASE_DIRECTION_SINK
                      };

  RawAddress bap_bd_addr_2;
  RawAddress::FromString("00:02:5B:00:FF:01", bap_bd_addr_2);

  std::vector<StreamType> start_streams;
  start_streams.push_back(type_1);

  char bap_test[150] = "generic";

  property_get("persist.vendor.service.bt.bap.test", bap_test, "generic");

      LOG(INFO) << __func__ << " property" << bap_test;

  if(!strcmp(bap_test, "generic")) {
    LOG(INFO) << __func__ << " going for generic test case";
    LOG(INFO) << __func__ << " going for connect";
    sUcastClientInterface->Connect( bap_bd_addr, true, streams);

    sUcastClientInterface->Connect( bap_bd_addr_2, true, streams_2);

    sleep(10);

    LOG(INFO) << __func__ << " going for stream start 1 ";
    //sUcastClientInterface->Start( bap_bd_addr, start_streams);

    LOG(INFO) << __func__ << " going for stream start 2";
    //sUcastClientInterface->Start( bap_bd_addr_2, start_streams);

    sleep(10);

    LOG(INFO) << __func__ << "going for stream disconnect 1 ";
    sUcastClientInterface->Disconnect( bap_bd_addr, start_streams);
    LOG(INFO) << __func__ << "going for stream disconnect 2 ";
    sUcastClientInterface->Disconnect( bap_bd_addr_2, start_streams);

  } else if(!strcmp(bap_test, "stereo_recording_stereo_dual_cis")) {
    LOG(INFO) << __func__ << " going for rxonly test case";
    LOG(INFO) << __func__ << " going for connect";
    StreamConnect conn_info_media_recording;

    CodecQosConfig codec_qos_config_media_rx_1;
    CodecQosConfig codec_qos_config_media_rx_2;

    CISConfig cis_config_1_media_rx = {
                                       .cis_id = 0,
                                       .max_sdu_m_to_s = 0,
                                       .max_sdu_s_to_m = 100,
                                       .phy_m_to_s = 0x02,
                                       .phy_s_to_m = 0x02,
                                       .rtn_m_to_s = 0x05,
                                       .rtn_s_to_m = 0x05
                                    };

    CISConfig cis_config_2_media_rx = {
                                       .cis_id = 1,
                                       .max_sdu_m_to_s = 0,
                                       .max_sdu_s_to_m = 100,
                                       .phy_m_to_s = 0x02,
                                       .phy_s_to_m = 0x02,
                                       .rtn_m_to_s = 0x05,
                                       .rtn_s_to_m = 0x05
                                    };

    CISConfig cis_config_1_media_rx_2 = {
                                       .cis_id = 0,
                                       .max_sdu_m_to_s = 0,
                                       .max_sdu_s_to_m = 200,
                                       .phy_m_to_s = 0x02,
                                       .phy_s_to_m = 0x02,
                                       .rtn_m_to_s = 0x05,
                                       .rtn_s_to_m = 0x05
                                    };

    ASCSConfig ascs_config_1 =  {
                                   .cig_id = 1,
                                   .cis_id = 0,
                                   .bi_directional = false,
                                   .presentation_delay = {0x20, 0x4E, 0x00}
                              };

    ASCSConfig ascs_config_2 =  {
                                   .cig_id = 1,
                                   .cis_id = 1,
                                   .bi_directional = false,
                                   .presentation_delay = {0x20, 0x4E, 0x00}
                              };

    codec_qos_config_media_rx_1.codec_config.codec_type =
                                    CodecIndex::CODEC_INDEX_SOURCE_LC3;
    codec_qos_config_media_rx_1.codec_config.codec_priority =
                                    CodecPriority::CODEC_PRIORITY_DEFAULT;
    codec_qos_config_media_rx_1.codec_config.sample_rate =
                                    CodecSampleRate::CODEC_SAMPLE_RATE_48000;
    codec_qos_config_media_rx_1.codec_config.channel_mode =
                                    CodecChannelMode::CODEC_CHANNEL_MODE_MONO;
    //Frame_Duration
    UpdateFrameDuration(&codec_qos_config_media_rx_1.codec_config,
                       static_cast<uint8_t>(CodecFrameDuration::FRAME_DUR_10));
    // LC3_Blocks_Per_SDU
    UpdateLc3BlocksPerSdu(&codec_qos_config_media_rx_1.codec_config, 1);
    UpdateOctsPerFrame(&codec_qos_config_media_rx_1.codec_config, 100);


    codec_qos_config_media_rx_2 = codec_qos_config_media_rx_1;
    UpdateOctsPerFrame(&codec_qos_config_media_rx_2.codec_config, 200);

    codec_qos_config_media_rx_1.qos_config.cig_config = {
                                       .cig_id = 1,
                                       .cis_count = 2,
                                       .packing = 0x01, // interleaved
                                       .framing =  0x00, // unframed
                                       .max_tport_latency_m_to_s = 0x000a,
                                       .max_tport_latency_s_to_m = 0x000a,
                                       .sdu_interval_m_to_s = {0x10, 0x27, 0x00},
                                       .sdu_interval_s_to_m = {0x10, 0x27, 0x00}
                                      };

    codec_qos_config_media_rx_1.qos_config.cis_configs.push_back(cis_config_1_media_rx);
    codec_qos_config_media_rx_1.qos_config.cis_configs.push_back(cis_config_2_media_rx);

    codec_qos_config_media_rx_1.qos_config.ascs_configs.push_back(ascs_config_1);
    codec_qos_config_media_rx_1.qos_config.ascs_configs.push_back(ascs_config_2);

    codec_qos_config_media_rx_2.qos_config.cig_config = {
                                       .cig_id = 1,
                                       .cis_count = 1,
                                       .packing = 0x01, // interleaved
                                       .framing =  0x00, // unframed
                                       .max_tport_latency_m_to_s = 0x000a,
                                       .max_tport_latency_s_to_m = 0x000a,
                                       .sdu_interval_m_to_s = {0x10, 0x27, 0x00},
                                       .sdu_interval_s_to_m = {0x10, 0x27, 0x00}
                                      };

    codec_qos_config_media_rx_2.qos_config.cis_configs.push_back(cis_config_1_media_rx_2);

    codec_qos_config_media_rx_2.qos_config.ascs_configs.push_back(ascs_config_1);

    StreamType type_media_rx = { .type = CONTENT_TYPE_MEDIA,
                                 .audio_context = CONTENT_TYPE_LIVE,
                                 .direction = ASE_DIRECTION_SRC
                               };

    conn_info_media_recording.stream_type.type = CONTENT_TYPE_MEDIA;
    conn_info_media_recording.stream_type.audio_context = CONTENT_TYPE_LIVE;
    conn_info_media_recording.stream_type.direction = ASE_DIRECTION_SRC;
    conn_info_media_recording.codec_qos_config_pair.push_back(codec_qos_config_media_rx_1);
    conn_info_media_recording.codec_qos_config_pair.push_back(codec_qos_config_media_rx_2);

    std::vector<StreamConnect> media_rx_streams;
    media_rx_streams.push_back(conn_info_media_recording);

    std::vector<StreamType> streams;
    streams.push_back(type_media_rx);


    sUcastClientInterface->Connect( bap_bd_addr, true, media_rx_streams);

    sleep(15);

    LOG(INFO) << __func__ << " going for stream start 1 ";
    sUcastClientInterface->Start( bap_bd_addr, streams);

    sleep(10);

    sUcastClientInterface->Stop( bap_bd_addr, streams);

    sleep(10);

    LOG(INFO) << __func__ << "going for stream disconnect 1 ";
    sUcastClientInterface->Disconnect( bap_bd_addr, streams);

  } else if(!strcmp(bap_test, "dual_streams_media_tx_voice_rx")) {
    StreamConnect conn_info_media;
    StreamConnect conn_info_gaming;

    // reconfig information
    CodecQosConfig codec_qos_config_media_tx_1;
    CodecQosConfig codec_qos_config_gaming_tx;
    CodecQosConfig codec_qos_config_gaming_tx_rx;

    CISConfig cis_config_1_media_tx = {
                                       .cis_id = 0,
                                       .max_sdu_m_to_s = 155,
                                       .max_sdu_s_to_m = 0,
                                       .phy_m_to_s = 0x02,
                                       .phy_s_to_m = 0x02,
                                       .rtn_m_to_s = 0x02,
                                       .rtn_s_to_m = 0x02
                                    };

    CISConfig cis_config_2_media_tx = {
                                       .cis_id = 1,
                                       .max_sdu_m_to_s = 155,
                                       .max_sdu_s_to_m = 0,
                                       .phy_m_to_s = 0x02,
                                       .phy_s_to_m = 0x02,
                                       .rtn_m_to_s = 0x02,
                                       .rtn_s_to_m = 0x02
                                    };

    CISConfig cis_config_1_gaming_tx = {
                                       .cis_id = 0,
                                       .max_sdu_m_to_s = 100,
                                       .max_sdu_s_to_m = 0,
                                       .phy_m_to_s = 0x02,
                                       .phy_s_to_m = 0x02,
                                       .rtn_m_to_s = 0x02,
                                       .rtn_s_to_m = 0x02
                                    };

    CISConfig cis_config_2_gaming_tx = {
                                       .cis_id = 1,
                                       .max_sdu_m_to_s = 100,
                                       .max_sdu_s_to_m = 0,
                                       .phy_m_to_s = 0x02,
                                       .phy_s_to_m = 0x02,
                                       .rtn_m_to_s = 0x02,
                                       .rtn_s_to_m = 0x02
                                    };

    CISConfig cis_config_1_gaming_tx_rx = {
                                       .cis_id = 0,
                                       .max_sdu_m_to_s = 100,
                                       .max_sdu_s_to_m = 40,
                                       .phy_m_to_s = 0x02,
                                       .phy_s_to_m = 0x02,
                                       .rtn_m_to_s = 0x02,
                                       .rtn_s_to_m = 0x02
                             };
    CISConfig cis_config_2_gaming_tx_rx = {
                                       .cis_id = 1,
                                       .max_sdu_m_to_s = 100,
                                       .max_sdu_s_to_m = 40,
                                       .phy_m_to_s = 0x02,
                                       .phy_s_to_m = 0x02,
                                       .rtn_m_to_s = 0x02,
                                       .rtn_s_to_m = 0x02
                             };

    ASCSConfig ascs_config =  {
                                       .cig_id = 1,
                                       .cis_id = 0,
                                       .bi_directional = false,
                                       .presentation_delay = {0x20, 0x4E, 0x00}
                              };

    codec_qos_config_media_tx_1.codec_config.codec_type =
                                    CodecIndex::CODEC_INDEX_SOURCE_LC3;
    codec_qos_config_media_tx_1.codec_config.codec_priority =
                                    CodecPriority::CODEC_PRIORITY_DEFAULT;
    codec_qos_config_media_tx_1.codec_config.sample_rate =
                                    CodecSampleRate::CODEC_SAMPLE_RATE_48000;
    codec_qos_config_media_tx_1.codec_config.channel_mode =
                                    CodecChannelMode::CODEC_CHANNEL_MODE_MONO;
    //Frame_Duration
    UpdateFrameDuration(&codec_qos_config_media_tx_1.codec_config,
                       static_cast<uint8_t>(CodecFrameDuration::FRAME_DUR_10));
    // LC3_Blocks_Per_SDU
    UpdateLc3BlocksPerSdu(&codec_qos_config_media_tx_1.codec_config, 1);
    UpdateOctsPerFrame(&codec_qos_config_media_tx_1.codec_config, 155);
    codec_qos_config_media_tx_1.qos_config.cig_config = {
                                       .cig_id = 1,
                                       .cis_count = 2,
                                       .packing = 0x01, // interleaved
                                       .framing =  0x00, // unframed
                                       .max_tport_latency_m_to_s =  0x000a,
                                       .max_tport_latency_s_to_m = 0x000a,
                                       .sdu_interval_m_to_s = {0x10, 0x27, 0x00},
                                       .sdu_interval_s_to_m = {0x10, 0x27, 0x00}
                                      };

    codec_qos_config_media_tx_1.qos_config.cis_configs.push_back(cis_config_1_media_tx);
    codec_qos_config_media_tx_1.qos_config.cis_configs.push_back(cis_config_2_media_tx);

    codec_qos_config_media_tx_1.qos_config.ascs_configs.push_back(ascs_config);
    codec_qos_config_gaming_tx.codec_config.codec_type =
                                    CodecIndex::CODEC_INDEX_SOURCE_LC3;
    codec_qos_config_gaming_tx.codec_config.codec_priority =
                                    CodecPriority::CODEC_PRIORITY_DEFAULT;
    codec_qos_config_gaming_tx.codec_config.sample_rate =
                                    CodecSampleRate::CODEC_SAMPLE_RATE_48000;
    codec_qos_config_gaming_tx.codec_config.channel_mode =
                                    CodecChannelMode::CODEC_CHANNEL_MODE_MONO;
    //Frame_Duration
    UpdateFrameDuration(&codec_qos_config_gaming_tx.codec_config,
                       static_cast<uint8_t>(CodecFrameDuration::FRAME_DUR_10));
    // LC3_Blocks_Per_SDU
    UpdateLc3BlocksPerSdu(&codec_qos_config_gaming_tx.codec_config, 1);
    UpdateOctsPerFrame(&codec_qos_config_gaming_tx.codec_config, 100);
    codec_qos_config_gaming_tx.qos_config.cig_config = {
                                       .cig_id = 1,
                                       .cis_count = 2,
                                       .packing = 0x01, // interleaved
                                       .framing =  0x00, // unframed
                                       .max_tport_latency_m_to_s =  0x000a,
                                       .max_tport_latency_s_to_m = 0x000a,
                                       .sdu_interval_m_to_s = {0x10, 0x27, 0x00},
                                       .sdu_interval_s_to_m = {0x10, 0x27, 0x00}
                                      };

    codec_qos_config_gaming_tx.qos_config.cis_configs.push_back(cis_config_1_gaming_tx);
    codec_qos_config_gaming_tx.qos_config.cis_configs.push_back(cis_config_2_gaming_tx);

    codec_qos_config_gaming_tx.qos_config.ascs_configs.push_back(ascs_config);
    codec_qos_config_gaming_tx_rx.codec_config.codec_type =
                                    CodecIndex::CODEC_INDEX_SOURCE_LC3;
    codec_qos_config_gaming_tx_rx.codec_config.codec_priority =
                                    CodecPriority::CODEC_PRIORITY_DEFAULT;
    codec_qos_config_gaming_tx_rx.codec_config.sample_rate =
                                    CodecSampleRate::CODEC_SAMPLE_RATE_16000;
    codec_qos_config_gaming_tx_rx.codec_config.channel_mode =
                                    CodecChannelMode::CODEC_CHANNEL_MODE_MONO;
    //Frame_Duration
    UpdateFrameDuration(&codec_qos_config_gaming_tx_rx.codec_config,
                       static_cast<uint8_t>(CodecFrameDuration::FRAME_DUR_10));
    // LC3_Blocks_Per_SDU
    UpdateLc3BlocksPerSdu(&codec_qos_config_gaming_tx_rx.codec_config, 1);
    UpdateOctsPerFrame(&codec_qos_config_gaming_tx_rx.codec_config, 40);
    codec_qos_config_gaming_tx_rx.qos_config.cig_config = {
                                       .cig_id = 2,
                                       .cis_count = 2,
                                       .packing = 0x01, // interleaved
                                       .framing =  0x00, // unframed
                                       .max_tport_latency_m_to_s =  0x000a,
                                       .max_tport_latency_s_to_m = 0x000a,
                                       .sdu_interval_m_to_s = {0x10, 0x27, 0x00},
                                       .sdu_interval_s_to_m = {0x10, 0x27, 0x00}
                                      };

    codec_qos_config_gaming_tx_rx.qos_config.cis_configs.push_back(cis_config_1_gaming_tx_rx);
    codec_qos_config_gaming_tx_rx.qos_config.cis_configs.push_back(cis_config_2_gaming_tx_rx);
    ASCSConfig ascs_config_gaming =  {
                                       .cig_id = 2,
                                       .cis_id = 0,
                                       .bi_directional = true,
                                       .presentation_delay = {0x20, 0x4E, 0x00}
                              };
    codec_qos_config_gaming_tx_rx.qos_config.ascs_configs.push_back(ascs_config_gaming);
    conn_info_media.stream_type.type = CONTENT_TYPE_MEDIA;
    conn_info_media.stream_type.audio_context = CONTENT_TYPE_MEDIA;
    conn_info_media.stream_type.direction = ASE_DIRECTION_SINK;
    conn_info_media.codec_qos_config_pair.push_back(codec_qos_config_media_tx_1);

    conn_info_gaming.stream_type.type = CONTENT_TYPE_CONVERSATIONAL;
    conn_info_gaming.stream_type.audio_context =
                            CONTENT_TYPE_CONVERSATIONAL;
    conn_info_gaming.stream_type.direction = ASE_DIRECTION_SRC;
    conn_info_gaming.codec_qos_config_pair.push_back(codec_qos_config_gaming_tx_rx);

    std::vector<StreamConnect> dual_streams;
    dual_streams.push_back(conn_info_media);
    dual_streams.push_back(conn_info_gaming);

    StreamType type_media = { .type = CONTENT_TYPE_MEDIA,
                              .audio_context = CONTENT_TYPE_MEDIA,
                              .direction = ASE_DIRECTION_SINK
                            };

    StreamType type_voice = { .type = CONTENT_TYPE_CONVERSATIONAL,
                              .audio_context = CONTENT_TYPE_CONVERSATIONAL,
                              .direction = ASE_DIRECTION_SRC
                            };

    std::vector<StreamType> media_streams;
    media_streams.push_back(type_media);
    std::vector<StreamType> voice_streams;
    voice_streams.push_back(type_voice);

    LOG(INFO) << __func__ << " going for generic test case";
    LOG(INFO) << __func__ << " going for connect with media tx and gaming rx";
    sUcastClientInterface->Connect( bap_bd_addr, true, dual_streams);

    //sUcastClientInterface->Connect( bap_bd_addr_2, true, streams_2);

    sleep(10);

    std::vector<StreamReconfig> reconf_streams;

    StreamReconfig reconf_gaming_tx_info;
    reconf_gaming_tx_info.stream_type.type = CONTENT_TYPE_MEDIA; // media
    reconf_gaming_tx_info.stream_type.audio_context = CONTENT_TYPE_MEDIA; // media
    reconf_gaming_tx_info.reconf_type = StreamReconfigType::CODEC_CONFIG;
    reconf_gaming_tx_info.stream_type.direction = ASE_DIRECTION_SINK;
    reconf_gaming_tx_info.codec_qos_config_pair.push_back(codec_qos_config_gaming_tx);

    StreamReconfig reconf_gaming_tx_rx_info;
    reconf_gaming_tx_rx_info.stream_type.type = CONTENT_TYPE_MEDIA; // media
    reconf_gaming_tx_rx_info.stream_type.audio_context = CONTENT_TYPE_MEDIA; // media
    reconf_gaming_tx_rx_info.reconf_type = StreamReconfigType::CODEC_CONFIG;
    reconf_gaming_tx_rx_info.stream_type.direction = ASE_DIRECTION_SINK;
    reconf_gaming_tx_rx_info.codec_qos_config_pair.push_back(codec_qos_config_gaming_tx_rx);

    StreamReconfig reconf_media_info;
    reconf_media_info.stream_type.type = CONTENT_TYPE_MEDIA; // media
    reconf_media_info.stream_type.audio_context = CONTENT_TYPE_MEDIA; // media
    reconf_media_info.reconf_type = StreamReconfigType::CODEC_CONFIG;
    reconf_media_info.stream_type.direction = ASE_DIRECTION_SINK;
    reconf_media_info.codec_qos_config_pair.push_back(codec_qos_config_media_tx_1);

    sleep(5);
    LOG(INFO) << __func__ << " going for stream start 1 ";
    sUcastClientInterface->Start( bap_bd_addr, media_streams);

    // switch to Gaming tx
    sleep(5);
    LOG(INFO) << __func__ << " going for stream stop 1 ";
    sUcastClientInterface->Stop( bap_bd_addr, media_streams);

    sleep(5);
    // reconfig the first stream
    LOG(INFO) << __func__ << " going for stream codec reconfig";
    reconf_streams.clear();
    reconf_streams.push_back(reconf_gaming_tx_info);
    sUcastClientInterface->Reconfigure( bap_bd_addr, reconf_streams);

    sleep(5);
    LOG(INFO) << __func__ << " going for stream reconfgured .start  ";
    sUcastClientInterface->Start( bap_bd_addr, media_streams);

    // switch to media tx
    sleep(5);
    LOG(INFO) << __func__ << " going for stream stop 1 ";
    sUcastClientInterface->Stop( bap_bd_addr, media_streams);

    sleep(5);
    // reconfig the first stream
    reconf_streams.clear();
    reconf_streams.push_back(reconf_media_info);
    LOG(INFO) << __func__ << " going for stream codec reconfig";
    sUcastClientInterface->Reconfigure( bap_bd_addr, reconf_streams);

    sleep(5);
    LOG(INFO) << __func__ << " going for stream reconfgured .start  ";
    sUcastClientInterface->Start( bap_bd_addr, media_streams);

    // switch to Gaming tx & rx
    sleep(5);
    LOG(INFO) << __func__ << " going for stream stop 1 ";
    sUcastClientInterface->Stop( bap_bd_addr, media_streams);

    sleep(5);
    // reconfig the first stream
    reconf_streams.clear();
    reconf_streams.push_back(reconf_gaming_tx_rx_info);
    LOG(INFO) << __func__ << " going for stream codec reconfig";
    sUcastClientInterface->Reconfigure( bap_bd_addr, reconf_streams);

    sleep(5);
    LOG(INFO) << __func__ << " going for stream reconfgured .start  ";
    sUcastClientInterface->Start( bap_bd_addr, media_streams);
    sUcastClientInterface->Start( bap_bd_addr, voice_streams);

    // switch to Gaming tx (2nd time) (4th)
    sleep(5);
    LOG(INFO) << __func__ << " going for stream stop 1 ";
    sUcastClientInterface->Stop( bap_bd_addr, media_streams);
    sUcastClientInterface->Stop( bap_bd_addr, voice_streams);

    sleep(5);
    // reconfig the first stream
    LOG(INFO) << __func__ << " going for stream codec reconfig";
    reconf_streams.clear();
    reconf_gaming_tx_info.reconf_type = StreamReconfigType::QOS_CONFIG;
    reconf_streams.push_back(reconf_gaming_tx_info);
    sUcastClientInterface->Reconfigure( bap_bd_addr, reconf_streams);

    sleep(5);
    LOG(INFO) << __func__ << " going for stream reconfgured .start  ";
    sUcastClientInterface->Start( bap_bd_addr, media_streams);


    // switch to Gaming tx & rx (2nd time) (5th)
    sleep(5);
    LOG(INFO) << __func__ << " going for stream stop 1 ";
    sUcastClientInterface->Stop( bap_bd_addr, media_streams);

    sleep(5);
    // reconfig the first stream
    reconf_streams.clear();
    reconf_gaming_tx_rx_info.reconf_type = StreamReconfigType::QOS_CONFIG;
    reconf_streams.push_back(reconf_gaming_tx_rx_info);
    LOG(INFO) << __func__ << " going for stream codec reconfig";
    sUcastClientInterface->Reconfigure( bap_bd_addr, reconf_streams);

    sleep(5);
    LOG(INFO) << __func__ << " going for stream reconfgured .start  ";
    sUcastClientInterface->Start( bap_bd_addr, media_streams);
    sUcastClientInterface->Start( bap_bd_addr, voice_streams);

    // switch to media tx (6th)
    sleep(5);
    LOG(INFO) << __func__ << " going for stream stop 1 ";
    sUcastClientInterface->Stop( bap_bd_addr, media_streams);
    sUcastClientInterface->Stop( bap_bd_addr, voice_streams);

    sleep(5);
    // reconfig the first stream
    reconf_streams.clear();
    reconf_streams.push_back(reconf_media_info);
    LOG(INFO) << __func__ << " going for stream codec reconfig";
    sUcastClientInterface->Reconfigure( bap_bd_addr, reconf_streams);

    sleep(5);
    LOG(INFO) << __func__ << " going for stream reconfgured .start  ";
    sUcastClientInterface->Start( bap_bd_addr, media_streams);

    sleep(5);
    LOG(INFO) << __func__ << "going for stream disconnect 1 ";
    sUcastClientInterface->Disconnect( bap_bd_addr, media_streams);
    sUcastClientInterface->Disconnect( bap_bd_addr, voice_streams);
    //LOG(INFO) << __func__ << "going for stream disconnect 2 ";
    //sUcastClientInterface->Disconnect( bap_bd_addr_2, start_streams);

  } else if(!strcmp(bap_test, "tri_streams_media_tx_voice_tx_voice_rx")) {
    StreamConnect conn_info_media;
    StreamConnect conn_info_gaming;
    StreamConnect conn_info_voice_tx;
    StreamConnect conn_info_voice_rx;

    // reconfig information
    CodecQosConfig codec_qos_config_media_tx_1;
    CodecQosConfig codec_qos_config_gaming_tx;
    CodecQosConfig codec_qos_config_gaming_tx_rx;
    CodecQosConfig codec_qos_config_gaming_rx;
    CodecQosConfig codec_qos_config_voice_tx_rx;

    CodecQosConfig codec_qos_config_media_tx_2;
    CodecQosConfig codec_qos_config_gaming_tx_2;
    CodecQosConfig codec_qos_config_gaming_tx_rx_2;
    CodecQosConfig codec_qos_config_gaming_rx_2;
    CodecQosConfig codec_qos_config_voice_tx_rx_2;

    CISConfig cis_config_1_media_tx = {
                                       .cis_id = 0,
                                       .max_sdu_m_to_s = 155,
                                       .max_sdu_s_to_m = 0,
                                       .phy_m_to_s = 0x02,
                                       .phy_s_to_m = 0x02,
                                       .rtn_m_to_s = 0x05,
                                       .rtn_s_to_m = 0x05
                                    };

    CISConfig cis_config_2_media_tx = {
                                       .cis_id = 1,
                                       .max_sdu_m_to_s = 155,
                                       .max_sdu_s_to_m = 0,
                                       .phy_m_to_s = 0x02,
                                       .phy_s_to_m = 0x02,
                                       .rtn_m_to_s = 0x05,
                                       .rtn_s_to_m = 0x05
                                    };

    CISConfig cis_config_1_gaming_tx = {
                                       .cis_id = 0,
                                       .max_sdu_m_to_s = 100,
                                       .max_sdu_s_to_m = 0,
                                       .phy_m_to_s = 0x02,
                                       .phy_s_to_m = 0x02,
                                       .rtn_m_to_s = 0x05,
                                       .rtn_s_to_m = 0x05
                                    };

    CISConfig cis_config_2_gaming_tx = {
                                       .cis_id = 1,
                                       .max_sdu_m_to_s = 100,
                                       .max_sdu_s_to_m = 0,
                                       .phy_m_to_s = 0x02,
                                       .phy_s_to_m = 0x02,
                                       .rtn_m_to_s = 0x05,
                                       .rtn_s_to_m = 0x05
                                    };

    CISConfig cis_config_1_gaming_tx_rx = {
                                       .cis_id = 0,
                                       .max_sdu_m_to_s = 100,
                                       .max_sdu_s_to_m = 40,
                                       .phy_m_to_s = 0x02,
                                       .phy_s_to_m = 0x02,
                                       .rtn_m_to_s = 0x05,
                                       .rtn_s_to_m = 0x05
                             };
    CISConfig cis_config_2_gaming_tx_rx = {
                                       .cis_id = 1,
                                       .max_sdu_m_to_s = 100,
                                       .max_sdu_s_to_m = 40,
                                       .phy_m_to_s = 0x02,
                                       .phy_s_to_m = 0x02,
                                       .rtn_m_to_s = 0x05,
                                       .rtn_s_to_m = 0x05
                             };

    CISConfig cis_config_1_voice_tx_rx = {
                                       .cis_id = 0,
                                       .max_sdu_m_to_s = 40,
                                       .max_sdu_s_to_m = 40,
                                       .phy_m_to_s = 0x02,
                                       .phy_s_to_m = 0x02,
                                       .rtn_m_to_s = 0x05,
                                       .rtn_s_to_m = 0x05
                             };
    CISConfig cis_config_2_voice_tx_rx = {
                                       .cis_id = 1,
                                       .max_sdu_m_to_s = 40,
                                       .max_sdu_s_to_m = 40,
                                       .phy_m_to_s = 0x02,
                                       .phy_s_to_m = 0x02,
                                       .rtn_m_to_s = 0x05,
                                       .rtn_s_to_m = 0x05
                             };

    ASCSConfig ascs_config =  {
                                       .cig_id = 1,
                                       .cis_id = 0,
                                       .bi_directional = false,
                                       .presentation_delay = {0x20, 0x4E, 0x00}
                              };

    ASCSConfig ascs_config_gaming =  {
                                       .cig_id = 2,
                                       .cis_id = 0,
                                       .bi_directional = true,
                                       .presentation_delay = {0x20, 0x4E, 0x00}
                                  };

    ASCSConfig ascs_config_voice =  {
                                       .cig_id = 3,
                                       .cis_id = 0,
                                       .bi_directional = true,
                                       .presentation_delay = {0x20, 0x4E, 0x00}
                                  };

    ASCSConfig ascs_config_2 =  {
                                       .cig_id = 1,
                                       .cis_id = 1,
                                       .bi_directional = false,
                                       .presentation_delay = {0x20, 0x4E, 0x00}
                              };

    ASCSConfig ascs_config_gaming_2 =  {
                                       .cig_id = 2,
                                       .cis_id = 1,
                                       .bi_directional = true,
                                       .presentation_delay = {0x20, 0x4E, 0x00}
                                  };

    ASCSConfig ascs_config_voice_2 =  {
                                       .cig_id = 3,
                                       .cis_id = 1,
                                       .bi_directional = true,
                                       .presentation_delay = {0x20, 0x4E, 0x00}
                                  };

    codec_qos_config_media_tx_1.codec_config.codec_type =
                                    CodecIndex::CODEC_INDEX_SOURCE_LC3;
    codec_qos_config_media_tx_1.codec_config.codec_priority =
                                    CodecPriority::CODEC_PRIORITY_DEFAULT;
    codec_qos_config_media_tx_1.codec_config.sample_rate =
                                    CodecSampleRate::CODEC_SAMPLE_RATE_48000;
    codec_qos_config_media_tx_1.codec_config.channel_mode =
                                    CodecChannelMode::CODEC_CHANNEL_MODE_MONO;
    //Frame_Duration
    UpdateFrameDuration(&codec_qos_config_media_tx_1.codec_config,
                       static_cast<uint8_t>(CodecFrameDuration::FRAME_DUR_10));
    // LC3_Blocks_Per_SDU
    UpdateLc3BlocksPerSdu(&codec_qos_config_media_tx_1.codec_config, 1);
    UpdateOctsPerFrame(&codec_qos_config_media_tx_1.codec_config, 155);
    codec_qos_config_media_tx_1.qos_config.cig_config = {
                                       .cig_id = 1,
                                       .cis_count = 2,
                                       .packing = 0x01, // interleaved
                                       .framing =  0x00, // unframed
                                       .max_tport_latency_m_to_s =  0x000a,
                                       .max_tport_latency_s_to_m = 0x000a,
                                       .sdu_interval_m_to_s = {0x10, 0x27, 0x00},
                                       .sdu_interval_s_to_m = {0x10, 0x27, 0x00}
                                      };

    codec_qos_config_media_tx_1.qos_config.cis_configs.push_back(cis_config_1_media_tx);
    codec_qos_config_media_tx_1.qos_config.cis_configs.push_back(cis_config_2_media_tx);

    codec_qos_config_media_tx_1.qos_config.ascs_configs.push_back(ascs_config);

    codec_qos_config_media_tx_2 = codec_qos_config_media_tx_1;
    codec_qos_config_media_tx_2.qos_config.ascs_configs.clear();
    codec_qos_config_media_tx_2.qos_config.ascs_configs.push_back(ascs_config_2);

    codec_qos_config_gaming_tx.codec_config.codec_type =
                                    CodecIndex::CODEC_INDEX_SOURCE_LC3;
    codec_qos_config_gaming_tx.codec_config.codec_priority =
                                    CodecPriority::CODEC_PRIORITY_DEFAULT;
    codec_qos_config_gaming_tx.codec_config.sample_rate =
                                    CodecSampleRate::CODEC_SAMPLE_RATE_48000;
    codec_qos_config_gaming_tx.codec_config.channel_mode =
                                    CodecChannelMode::CODEC_CHANNEL_MODE_MONO;
    //Frame_Duration
    UpdateFrameDuration(&codec_qos_config_gaming_tx.codec_config,
                       static_cast<uint8_t>(CodecFrameDuration::FRAME_DUR_10));
    // LC3_Blocks_Per_SDU
    UpdateLc3BlocksPerSdu(&codec_qos_config_gaming_tx.codec_config, 1);
    UpdateOctsPerFrame(&codec_qos_config_gaming_tx.codec_config, 100);
    codec_qos_config_gaming_tx.qos_config.cig_config = {
                                       .cig_id = 1,
                                       .cis_count = 2,
                                       .packing = 0x01, // interleaved
                                       .framing =  0x00, // unframed
                                       .max_tport_latency_m_to_s =  0x000a,
                                       .max_tport_latency_s_to_m = 0x000a,
                                       .sdu_interval_m_to_s = {0x10, 0x27, 0x00},
                                       .sdu_interval_s_to_m = {0x10, 0x27, 0x00}
                                      };

    codec_qos_config_gaming_tx.qos_config.cis_configs.push_back(cis_config_1_gaming_tx);
    codec_qos_config_gaming_tx.qos_config.cis_configs.push_back(cis_config_2_gaming_tx);

    codec_qos_config_gaming_tx.qos_config.ascs_configs.push_back(ascs_config);


    codec_qos_config_gaming_tx_2 = codec_qos_config_gaming_tx;
    codec_qos_config_gaming_tx_2.qos_config.ascs_configs.clear();
    codec_qos_config_gaming_tx_2.qos_config.ascs_configs.push_back(ascs_config_2);

    codec_qos_config_gaming_tx_rx.codec_config.codec_type =
                                    CodecIndex::CODEC_INDEX_SOURCE_LC3;
    codec_qos_config_gaming_tx_rx.codec_config.codec_priority =
                                    CodecPriority::CODEC_PRIORITY_DEFAULT;
    codec_qos_config_gaming_tx_rx.codec_config.sample_rate =
                                    CodecSampleRate::CODEC_SAMPLE_RATE_48000;
    codec_qos_config_gaming_tx_rx.codec_config.channel_mode =
                                    CodecChannelMode::CODEC_CHANNEL_MODE_MONO;
    //Frame_Duration
    UpdateFrameDuration(&codec_qos_config_gaming_tx_rx.codec_config,
                       static_cast<uint8_t>(CodecFrameDuration::FRAME_DUR_10));
    // LC3_Blocks_Per_SDU
    UpdateLc3BlocksPerSdu(&codec_qos_config_gaming_tx_rx.codec_config, 1);
    UpdateOctsPerFrame(&codec_qos_config_gaming_tx_rx.codec_config, 100);
    codec_qos_config_gaming_tx_rx.qos_config.cig_config = {
                                       .cig_id = 2,
                                       .cis_count = 2,
                                       .packing = 0x01, // interleaved
                                       .framing =  0x00, // unframed
                                       .max_tport_latency_m_to_s =  0x000a,
                                       .max_tport_latency_s_to_m = 0x000a,
                                       .sdu_interval_m_to_s = {0x10, 0x27, 0x00},
                                       .sdu_interval_s_to_m = {0x10, 0x27, 0x00}
                                      };

    codec_qos_config_gaming_tx_rx.qos_config.cis_configs.push_back(cis_config_1_gaming_tx_rx);
    codec_qos_config_gaming_tx_rx.qos_config.cis_configs.push_back(cis_config_2_gaming_tx_rx);

    codec_qos_config_gaming_tx_rx.qos_config.ascs_configs.push_back(ascs_config_gaming);

    codec_qos_config_gaming_tx_rx_2 = codec_qos_config_gaming_tx_rx;
    codec_qos_config_gaming_tx_rx_2.qos_config.ascs_configs.clear();
    codec_qos_config_gaming_tx_rx_2.qos_config.ascs_configs.push_back(ascs_config_gaming_2);


    codec_qos_config_gaming_rx.codec_config.codec_type =
                                    CodecIndex::CODEC_INDEX_SOURCE_LC3;
    codec_qos_config_gaming_rx.codec_config.codec_priority =
                                    CodecPriority::CODEC_PRIORITY_DEFAULT;
    codec_qos_config_gaming_rx.codec_config.sample_rate =
                                    CodecSampleRate::CODEC_SAMPLE_RATE_16000;
    codec_qos_config_gaming_rx.codec_config.channel_mode =
                                    CodecChannelMode::CODEC_CHANNEL_MODE_MONO;
    //Frame_Duration
    UpdateFrameDuration(&codec_qos_config_gaming_rx.codec_config,
                       static_cast<uint8_t>(CodecFrameDuration::FRAME_DUR_10));
    // LC3_Blocks_Per_SDU
    UpdateLc3BlocksPerSdu(&codec_qos_config_gaming_rx.codec_config, 1);
    UpdateOctsPerFrame(&codec_qos_config_gaming_rx.codec_config, 40);
    codec_qos_config_gaming_rx.qos_config.cig_config = {
                                       .cig_id = 2,
                                       .cis_count = 2,
                                       .packing = 0x01, // interleaved
                                       .framing =  0x00, // unframed
                                       .max_tport_latency_m_to_s =  0x000a,
                                       .max_tport_latency_s_to_m = 0x000a,
                                       .sdu_interval_m_to_s = {0x10, 0x27, 0x00},
                                       .sdu_interval_s_to_m = {0x10, 0x27, 0x00}
                                      };

    codec_qos_config_gaming_rx.qos_config.cis_configs.push_back(cis_config_1_gaming_tx_rx);
    codec_qos_config_gaming_rx.qos_config.cis_configs.push_back(cis_config_2_gaming_tx_rx);

    codec_qos_config_gaming_rx.qos_config.ascs_configs.push_back(ascs_config_gaming);

    codec_qos_config_gaming_rx_2 = codec_qos_config_gaming_rx;
    codec_qos_config_gaming_rx_2.qos_config.ascs_configs.clear();
    codec_qos_config_gaming_rx_2.qos_config.ascs_configs.push_back(ascs_config_gaming_2);


    // voice tx rx
    codec_qos_config_voice_tx_rx.codec_config.codec_type =
                                    CodecIndex::CODEC_INDEX_SOURCE_LC3;
    codec_qos_config_voice_tx_rx.codec_config.codec_priority =
                                    CodecPriority::CODEC_PRIORITY_DEFAULT;
    codec_qos_config_voice_tx_rx.codec_config.sample_rate =
                                    CodecSampleRate::CODEC_SAMPLE_RATE_16000;
    codec_qos_config_voice_tx_rx.codec_config.channel_mode =
                                    CodecChannelMode::CODEC_CHANNEL_MODE_MONO;
    //Frame_Duration
    UpdateFrameDuration(&codec_qos_config_voice_tx_rx.codec_config,
                       static_cast<uint8_t>(CodecFrameDuration::FRAME_DUR_10));
    // LC3_Blocks_Per_SDU
    UpdateLc3BlocksPerSdu(&codec_qos_config_voice_tx_rx.codec_config, 1);
    UpdateOctsPerFrame(&codec_qos_config_voice_tx_rx.codec_config, 40);
    codec_qos_config_voice_tx_rx.qos_config.cig_config = {
                                       .cig_id = 3,
                                       .cis_count = 2,
                                       .packing = 0x01, // interleaved
                                       .framing =  0x00, // unframed
                                       .max_tport_latency_m_to_s =  0x000a,
                                       .max_tport_latency_s_to_m = 0x000a,
                                       .sdu_interval_m_to_s = {0x10, 0x27, 0x00},
                                       .sdu_interval_s_to_m = {0x10, 0x27, 0x00}
                                      };

    codec_qos_config_voice_tx_rx.qos_config.cis_configs.push_back(cis_config_1_voice_tx_rx);
    codec_qos_config_voice_tx_rx.qos_config.cis_configs.push_back(cis_config_2_voice_tx_rx);

    codec_qos_config_voice_tx_rx.qos_config.ascs_configs.push_back(ascs_config_voice);

    codec_qos_config_voice_tx_rx_2 = codec_qos_config_voice_tx_rx;
    codec_qos_config_voice_tx_rx_2.qos_config.ascs_configs.clear();
    codec_qos_config_voice_tx_rx_2.qos_config.ascs_configs.push_back(ascs_config_voice_2);

    conn_info_media.stream_type.type = CONTENT_TYPE_MEDIA;
    conn_info_media.stream_type.audio_context = CONTENT_TYPE_MEDIA;
    conn_info_media.stream_type.direction = ASE_DIRECTION_SINK;
    conn_info_media.codec_qos_config_pair.push_back(codec_qos_config_media_tx_1);

    conn_info_gaming.stream_type.type = CONTENT_TYPE_CONVERSATIONAL;
    conn_info_gaming.stream_type.audio_context =
                            CONTENT_TYPE_CONVERSATIONAL;
    conn_info_gaming.stream_type.direction = ASE_DIRECTION_SRC;
    conn_info_gaming.codec_qos_config_pair.push_back(codec_qos_config_gaming_tx_rx);

    conn_info_voice_tx.stream_type.type = CONTENT_TYPE_CONVERSATIONAL;
    conn_info_voice_tx.stream_type.audio_context =
                            CONTENT_TYPE_CONVERSATIONAL;
    conn_info_voice_tx.stream_type.direction = ASE_DIRECTION_SINK;
    conn_info_voice_tx.codec_qos_config_pair.push_back(codec_qos_config_voice_tx_rx);

    conn_info_voice_rx.stream_type.type = CONTENT_TYPE_CONVERSATIONAL;
    conn_info_voice_rx.stream_type.audio_context =
                            CONTENT_TYPE_CONVERSATIONAL;
    conn_info_voice_rx.stream_type.direction = ASE_DIRECTION_SRC;
    conn_info_voice_rx.codec_qos_config_pair.push_back(codec_qos_config_voice_tx_rx);

    std::vector<StreamConnect> tri_streams;
    tri_streams.push_back(conn_info_media);
    tri_streams.push_back(conn_info_voice_tx);
    tri_streams.push_back(conn_info_voice_rx);

    conn_info_media.codec_qos_config_pair.clear();
    conn_info_media.codec_qos_config_pair.push_back(codec_qos_config_media_tx_2);

    conn_info_voice_tx.codec_qos_config_pair.clear();
    conn_info_voice_tx.codec_qos_config_pair.push_back(codec_qos_config_voice_tx_rx_2);

    conn_info_voice_rx.codec_qos_config_pair.clear();
    conn_info_voice_rx.codec_qos_config_pair.push_back(codec_qos_config_voice_tx_rx_2);

    std::vector<StreamConnect> tri_streams_2;
    tri_streams_2.push_back(conn_info_media);
    tri_streams_2.push_back(conn_info_voice_tx);
    tri_streams_2.push_back(conn_info_voice_rx);

    StreamType type_media = { .type = CONTENT_TYPE_MEDIA,
                              .audio_context = CONTENT_TYPE_MEDIA,
                              .direction = ASE_DIRECTION_SINK
                            };

    StreamType type_voice_tx = { .type = CONTENT_TYPE_CONVERSATIONAL,
                              .audio_context = CONTENT_TYPE_CONVERSATIONAL,
                              .direction = ASE_DIRECTION_SINK
                            };

    StreamType type_voice_rx = { .type = CONTENT_TYPE_CONVERSATIONAL,
                              .audio_context = CONTENT_TYPE_CONVERSATIONAL,
                              .direction = ASE_DIRECTION_SRC
                            };


    std::vector<StreamType> media_streams;
    media_streams.push_back(type_media);

    std::vector<StreamType> gaming_tx_streams;
    gaming_tx_streams.push_back(type_media);

    std::vector<StreamType> gaming_rx_streams;
    gaming_rx_streams.push_back(type_voice_rx);

    std::vector<StreamType> voice_streams;
    voice_streams.push_back(type_voice_tx);
    voice_streams.push_back(type_voice_rx);

    std::vector<StreamType> all_three_streams;
    all_three_streams.push_back(type_media);
    all_three_streams.push_back(type_voice_tx);
    all_three_streams.push_back(type_voice_rx);

#if 0
    LOG(INFO) << __func__ << " going for generic test case";
    LOG(INFO) << __func__ << " going for connect with media tx and voice tx& rx";
    sUcastClientInterface->Connect( bap_bd_addr, true, tri_streams);
    sUcastClientInterface->Connect( bap_bd_addr_2, true, tri_streams_2);
    sleep(15);

    LOG(INFO) << __func__ << "going for stream disconnect all 3 streams ";
    sUcastClientInterface->Disconnect( bap_bd_addr, all_three_streams);
    sUcastClientInterface->Disconnect( bap_bd_addr_2, all_three_streams);

    sleep(5);

    LOG(INFO) << __func__ << " going for connect all 3 streams";
    sUcastClientInterface->Connect( bap_bd_addr, true, tri_streams);
    sUcastClientInterface->Connect( bap_bd_addr_2, true, tri_streams_2);

    sleep(15);

    LOG(INFO) << __func__ << "going for stream disconnect all 3 streams ";
    sUcastClientInterface->Disconnect( bap_bd_addr, all_three_streams);
    sUcastClientInterface->Disconnect( bap_bd_addr_2, all_three_streams);

    sleep(5);
#endif

    LOG(INFO) << __func__ << " going for connect all 3 streams";
    sUcastClientInterface->Connect( bap_bd_addr, true, tri_streams);
    sUcastClientInterface->Connect( bap_bd_addr_2, true, tri_streams_2);

    std::vector<StreamReconfig> reconf_streams;
    std::vector<StreamReconfig> reconf_streams_2;

    StreamReconfig reconf_gaming_tx_info;
    reconf_gaming_tx_info.stream_type.type = CONTENT_TYPE_MEDIA;
    reconf_gaming_tx_info.stream_type.audio_context = CONTENT_TYPE_MEDIA;
    reconf_gaming_tx_info.reconf_type = StreamReconfigType::CODEC_CONFIG;
    reconf_gaming_tx_info.stream_type.direction = ASE_DIRECTION_SINK;
    reconf_gaming_tx_info.codec_qos_config_pair.
                          push_back(codec_qos_config_gaming_tx);

    StreamReconfig reconf_gaming_tx_info_2;
    reconf_gaming_tx_info_2.stream_type.type = CONTENT_TYPE_MEDIA;
    reconf_gaming_tx_info_2.stream_type.audio_context = CONTENT_TYPE_MEDIA;
    reconf_gaming_tx_info_2.reconf_type = StreamReconfigType::CODEC_CONFIG;
    reconf_gaming_tx_info_2.stream_type.direction = ASE_DIRECTION_SINK;
    reconf_gaming_tx_info_2.codec_qos_config_pair.
                          push_back(codec_qos_config_gaming_tx_2);

    StreamReconfig reconf_gaming_tx_rx_info;
    reconf_gaming_tx_rx_info.stream_type.type = CONTENT_TYPE_MEDIA;
    reconf_gaming_tx_rx_info.stream_type.audio_context = CONTENT_TYPE_MEDIA;
    reconf_gaming_tx_rx_info.reconf_type = StreamReconfigType::CODEC_CONFIG;
    reconf_gaming_tx_rx_info.stream_type.direction = ASE_DIRECTION_SINK;
    reconf_gaming_tx_rx_info.codec_qos_config_pair.
                         push_back(codec_qos_config_gaming_tx_rx);

    StreamReconfig reconf_gaming_tx_rx_info_2;
    reconf_gaming_tx_rx_info_2.stream_type.type = CONTENT_TYPE_MEDIA;
    reconf_gaming_tx_rx_info_2.stream_type.audio_context = CONTENT_TYPE_MEDIA;
    reconf_gaming_tx_rx_info_2.reconf_type = StreamReconfigType::CODEC_CONFIG;
    reconf_gaming_tx_rx_info_2.stream_type.direction = ASE_DIRECTION_SINK;
    reconf_gaming_tx_rx_info_2.codec_qos_config_pair.
                         push_back(codec_qos_config_gaming_tx_rx_2);

    StreamReconfig reconf_gaming_rx_info;
    reconf_gaming_rx_info.stream_type.type = CONTENT_TYPE_CONVERSATIONAL;
    reconf_gaming_rx_info.stream_type.audio_context =
                                      CONTENT_TYPE_CONVERSATIONAL;
    reconf_gaming_rx_info.reconf_type = StreamReconfigType::CODEC_CONFIG;
    reconf_gaming_rx_info.stream_type.direction = ASE_DIRECTION_SRC;
    reconf_gaming_rx_info.codec_qos_config_pair.
                           push_back(codec_qos_config_gaming_rx);

    StreamReconfig reconf_gaming_rx_info_2;
    reconf_gaming_rx_info_2.stream_type.type = CONTENT_TYPE_CONVERSATIONAL;
    reconf_gaming_rx_info_2.stream_type.audio_context =
                                     CONTENT_TYPE_CONVERSATIONAL;
    reconf_gaming_rx_info_2.reconf_type = StreamReconfigType::CODEC_CONFIG;
    reconf_gaming_rx_info_2.stream_type.direction = ASE_DIRECTION_SRC;
    reconf_gaming_rx_info_2.codec_qos_config_pair.
                           push_back(codec_qos_config_gaming_rx_2);

    StreamReconfig reconf_media_info;
    reconf_media_info.stream_type.type = CONTENT_TYPE_MEDIA;
    reconf_media_info.stream_type.audio_context = CONTENT_TYPE_MEDIA;
    reconf_media_info.reconf_type = StreamReconfigType::CODEC_CONFIG;
    reconf_media_info.stream_type.direction = ASE_DIRECTION_SINK;
    reconf_media_info.codec_qos_config_pair.push_back(codec_qos_config_media_tx_1);

    StreamReconfig reconf_media_info_2;
    reconf_media_info_2.stream_type.type = CONTENT_TYPE_MEDIA;
    reconf_media_info_2.stream_type.audio_context = CONTENT_TYPE_MEDIA;
    reconf_media_info_2.reconf_type = StreamReconfigType::CODEC_CONFIG;
    reconf_media_info_2.stream_type.direction = ASE_DIRECTION_SINK;
    reconf_media_info_2.codec_qos_config_pair.push_back(codec_qos_config_media_tx_2);


    StreamReconfig reconf_voice_tx_info;
    reconf_voice_tx_info.stream_type.type = CONTENT_TYPE_CONVERSATIONAL;
    reconf_voice_tx_info.stream_type.audio_context = CONTENT_TYPE_CONVERSATIONAL;
    reconf_voice_tx_info.reconf_type = StreamReconfigType::CODEC_CONFIG;
    reconf_voice_tx_info.stream_type.direction = ASE_DIRECTION_SINK;
    reconf_voice_tx_info.codec_qos_config_pair.
                                 push_back(codec_qos_config_voice_tx_rx);

    StreamReconfig reconf_voice_tx_info_2;
    reconf_voice_tx_info_2.stream_type.type = CONTENT_TYPE_CONVERSATIONAL;
    reconf_voice_tx_info_2.stream_type.audio_context = CONTENT_TYPE_CONVERSATIONAL;
    reconf_voice_tx_info_2.reconf_type = StreamReconfigType::CODEC_CONFIG;
    reconf_voice_tx_info_2.stream_type.direction = ASE_DIRECTION_SINK;
    reconf_voice_tx_info_2.codec_qos_config_pair.
                                 push_back(codec_qos_config_voice_tx_rx_2);

    StreamReconfig reconf_voice_rx_info;
    reconf_voice_rx_info.stream_type.type = CONTENT_TYPE_CONVERSATIONAL;
    reconf_voice_rx_info.stream_type.audio_context = CONTENT_TYPE_CONVERSATIONAL;
    reconf_voice_rx_info.reconf_type = StreamReconfigType::CODEC_CONFIG;
    reconf_voice_rx_info.stream_type.direction = ASE_DIRECTION_SRC;
    reconf_voice_rx_info.codec_qos_config_pair.
                       push_back(codec_qos_config_voice_tx_rx);

    StreamReconfig reconf_voice_rx_info_2;
    reconf_voice_rx_info_2.stream_type.type = CONTENT_TYPE_CONVERSATIONAL;
    reconf_voice_rx_info_2.stream_type.audio_context = CONTENT_TYPE_CONVERSATIONAL;
    reconf_voice_rx_info_2.reconf_type = StreamReconfigType::CODEC_CONFIG;
    reconf_voice_rx_info_2.stream_type.direction = ASE_DIRECTION_SRC;
    reconf_voice_rx_info_2.codec_qos_config_pair.
                       push_back(codec_qos_config_voice_tx_rx_2);

    sleep(15);
    LOG(INFO) << __func__ << " going for stream start 1 ";
    sUcastClientInterface->Start( bap_bd_addr, media_streams);
    sUcastClientInterface->Start( bap_bd_addr_2, media_streams);

    // switch to Gaming tx
    sleep(5);
    LOG(INFO) << __func__ << " going for stream stop 1 ";
    sUcastClientInterface->Stop( bap_bd_addr, media_streams);
    sUcastClientInterface->Stop( bap_bd_addr_2, media_streams);

    sleep(5);
    // reconfig the first stream
    LOG(INFO) << __func__ << " going for stream codec reconfig";
    reconf_streams.clear();
    reconf_streams.push_back(reconf_gaming_tx_info);
    sUcastClientInterface->Reconfigure( bap_bd_addr, reconf_streams);
    reconf_streams_2.clear();
    reconf_streams_2.push_back(reconf_gaming_tx_info_2);
    sUcastClientInterface->Reconfigure( bap_bd_addr_2, reconf_streams_2);

    sleep(5);
    LOG(INFO) << __func__ << " going for stream reconfgured .start  ";
    sUcastClientInterface->Start( bap_bd_addr, media_streams);
    sUcastClientInterface->Start( bap_bd_addr_2, media_streams);

    // switch to media tx
    sleep(5);
    LOG(INFO) << __func__ << " going for stream stop 1 ";
    sUcastClientInterface->Stop( bap_bd_addr, media_streams);
    sUcastClientInterface->Stop( bap_bd_addr_2, media_streams);

    sleep(5);
    // reconfig the first stream
    reconf_streams.clear();
    reconf_streams.push_back(reconf_media_info);
    LOG(INFO) << __func__ << " going for stream codec reconfig";
    sUcastClientInterface->Reconfigure( bap_bd_addr, reconf_streams);

    reconf_streams_2.clear();
    reconf_streams_2.push_back(reconf_media_info_2);
    LOG(INFO) << __func__ << " going for stream codec reconfig";
    sUcastClientInterface->Reconfigure( bap_bd_addr_2, reconf_streams_2);


    sleep(5);
    LOG(INFO) << __func__ << " going for stream reconfgured .start  ";
    sUcastClientInterface->Start( bap_bd_addr, media_streams);
    sUcastClientInterface->Start( bap_bd_addr_2, media_streams);

    // switch to Gaming tx & rx
    sleep(5);
    LOG(INFO) << __func__ << " going for stream stop 1 ";
    sUcastClientInterface->Stop( bap_bd_addr, media_streams);
    sUcastClientInterface->Stop( bap_bd_addr_2, media_streams);

    sleep(5);
    // reconfig the first stream
    reconf_streams.clear();
    reconf_streams.push_back(reconf_gaming_tx_rx_info);
    reconf_streams.push_back(reconf_gaming_rx_info);
    LOG(INFO) << __func__ << " going for stream codec reconfig";
    sUcastClientInterface->Reconfigure( bap_bd_addr, reconf_streams);

    reconf_streams_2.clear();
    reconf_streams_2.push_back(reconf_gaming_tx_rx_info_2);
    reconf_streams_2.push_back(reconf_gaming_rx_info_2);
    LOG(INFO) << __func__ << " going for stream codec reconfig";
    sUcastClientInterface->Reconfigure( bap_bd_addr_2, reconf_streams_2);

    sleep(5);
    LOG(INFO) << __func__ << " going for stream reconfgured .start  ";
    sUcastClientInterface->Start( bap_bd_addr, gaming_tx_streams);
    sUcastClientInterface->Start( bap_bd_addr, gaming_rx_streams);
    sUcastClientInterface->Start( bap_bd_addr_2, gaming_tx_streams);
    sUcastClientInterface->Start( bap_bd_addr_2, gaming_rx_streams);

    // switch to Gaming tx (2nd time) (4th)
    sleep(5);
    LOG(INFO) << __func__ << " going for stream stop 1 ";
    sUcastClientInterface->Stop( bap_bd_addr, gaming_tx_streams);
    sUcastClientInterface->Stop( bap_bd_addr, gaming_rx_streams);
    sUcastClientInterface->Stop( bap_bd_addr_2, gaming_tx_streams);
    sUcastClientInterface->Stop( bap_bd_addr_2, gaming_rx_streams);

    sleep(5);
    // reconfig the first stream
    LOG(INFO) << __func__ << " going for stream codec reconfig";
    reconf_streams.clear();
    reconf_gaming_tx_info.reconf_type = StreamReconfigType::QOS_CONFIG;
    reconf_streams.push_back(reconf_gaming_tx_info);
    sUcastClientInterface->Reconfigure( bap_bd_addr, reconf_streams);

    reconf_streams_2.clear();
    reconf_gaming_tx_info_2.reconf_type = StreamReconfigType::QOS_CONFIG;
    reconf_streams_2.push_back(reconf_gaming_tx_info_2);
    sUcastClientInterface->Reconfigure( bap_bd_addr_2, reconf_streams_2);

    sleep(5);
    LOG(INFO) << __func__ << " going for stream reconfgured .start  ";
    sUcastClientInterface->Start( bap_bd_addr, media_streams);
    sUcastClientInterface->Start( bap_bd_addr_2, media_streams);

    // switch to Gaming tx & rx (2nd time) (5th)
    sleep(5);
    LOG(INFO) << __func__ << " going for stream stop 1 ";
    sUcastClientInterface->Stop( bap_bd_addr, media_streams);
    sUcastClientInterface->Stop( bap_bd_addr_2, media_streams);

    sleep(5);
    // reconfig the first stream
    reconf_streams.clear();
    reconf_gaming_tx_rx_info.reconf_type = StreamReconfigType::QOS_CONFIG;
    reconf_streams.push_back(reconf_gaming_tx_rx_info);
    reconf_streams.push_back(reconf_gaming_rx_info);
    LOG(INFO) << __func__ << " going for stream codec reconfig";
    sUcastClientInterface->Reconfigure( bap_bd_addr, reconf_streams);

    reconf_streams_2.clear();
    reconf_gaming_tx_rx_info_2.reconf_type = StreamReconfigType::QOS_CONFIG;
    reconf_streams_2.push_back(reconf_gaming_tx_rx_info_2);
    reconf_streams_2.push_back(reconf_gaming_rx_info_2);
    LOG(INFO) << __func__ << " going for stream codec reconfig";
    sUcastClientInterface->Reconfigure( bap_bd_addr_2, reconf_streams_2);

    sleep(5);
    LOG(INFO) << __func__ << " going for stream reconfgured .start  ";
    sUcastClientInterface->Start( bap_bd_addr, gaming_tx_streams);
    sUcastClientInterface->Start( bap_bd_addr, gaming_rx_streams);
    sUcastClientInterface->Start( bap_bd_addr_2, gaming_tx_streams);
    sUcastClientInterface->Start( bap_bd_addr_2, gaming_rx_streams);

    // switch to media tx (6th)
    sleep(5);
    LOG(INFO) << __func__ << " going for stream stop 1 ";
    sUcastClientInterface->Stop( bap_bd_addr, gaming_tx_streams);
    sUcastClientInterface->Stop( bap_bd_addr, gaming_rx_streams);
    sUcastClientInterface->Stop( bap_bd_addr_2, gaming_tx_streams);
    sUcastClientInterface->Stop( bap_bd_addr_2, gaming_rx_streams);

    sleep(5);
    // reconfig the first stream
    reconf_streams.clear();
    reconf_streams.push_back(reconf_media_info);
    LOG(INFO) << __func__ << " going for stream codec reconfig";
    sUcastClientInterface->Reconfigure( bap_bd_addr, reconf_streams);

    reconf_streams_2.clear();
    reconf_streams_2.push_back(reconf_media_info_2);
    LOG(INFO) << __func__ << " going for stream codec reconfig";
    sUcastClientInterface->Reconfigure( bap_bd_addr_2, reconf_streams_2);

    sleep(5);
    LOG(INFO) << __func__ << " going for stream reconfgured .start  ";
    sUcastClientInterface->Start( bap_bd_addr, media_streams);
    sUcastClientInterface->Start( bap_bd_addr_2, media_streams);

    // switch to voice tx & Rx (7th)
    sleep(5);
    LOG(INFO) << __func__ << " going for stream stop 1 ";
    sUcastClientInterface->Stop( bap_bd_addr, media_streams);
    sUcastClientInterface->Stop( bap_bd_addr_2, media_streams);

    sleep(5);
    // reconfig the first stream
    reconf_streams.clear();
    reconf_streams.push_back(reconf_voice_rx_info);
    LOG(INFO) << __func__ << " going for stream codec reconfig";
    sUcastClientInterface->Reconfigure( bap_bd_addr, reconf_streams);

    reconf_streams_2.clear();
    reconf_streams_2.push_back(reconf_voice_rx_info_2);
    LOG(INFO) << __func__ << " going for stream codec reconfig";
    sUcastClientInterface->Reconfigure( bap_bd_addr_2, reconf_streams_2);

    sleep(5);
    LOG(INFO) << __func__ << " going for stream reconfgured .start  ";
    sUcastClientInterface->Start( bap_bd_addr, voice_streams);
    sUcastClientInterface->Start( bap_bd_addr_2, voice_streams);

    // switch to gaming tx (8th)
    sleep(5);
    LOG(INFO) << __func__ << " going for stream stop 1 ";
    sUcastClientInterface->Stop( bap_bd_addr, voice_streams);
    sUcastClientInterface->Stop( bap_bd_addr_2, voice_streams);

    sleep(5);
    LOG(INFO) << __func__ << " going for stream codec reconfig";
    reconf_streams.clear();
    reconf_gaming_tx_info.reconf_type = StreamReconfigType::CODEC_CONFIG;
    reconf_streams.push_back(reconf_gaming_tx_info);
    sUcastClientInterface->Reconfigure( bap_bd_addr, reconf_streams);

    reconf_streams_2.clear();
    reconf_gaming_tx_info_2.reconf_type = StreamReconfigType::CODEC_CONFIG;
    reconf_streams_2.push_back(reconf_gaming_tx_info_2);
    sUcastClientInterface->Reconfigure( bap_bd_addr_2, reconf_streams_2);

    sleep(5);
    LOG(INFO) << __func__ << " going for stream reconfgured .start  ";
    sUcastClientInterface->Start( bap_bd_addr, media_streams);
    sUcastClientInterface->Start( bap_bd_addr_2, media_streams);


    // switch to voice tx & Rx (9th)
    sleep(5);
    LOG(INFO) << __func__ << " going for stream stop 1 ";
    sUcastClientInterface->Stop( bap_bd_addr, media_streams);
    sUcastClientInterface->Stop( bap_bd_addr_2, media_streams);

    sleep(5);
    // reconfig the first stream
    reconf_streams.clear();
    reconf_streams.push_back(reconf_voice_rx_info);
    LOG(INFO) << __func__ << " going for stream codec reconfig";
    sUcastClientInterface->Reconfigure( bap_bd_addr, reconf_streams);

    reconf_streams_2.clear();
    reconf_streams_2.push_back(reconf_voice_rx_info_2);
    LOG(INFO) << __func__ << " going for stream codec reconfig";
    sUcastClientInterface->Reconfigure( bap_bd_addr_2, reconf_streams_2);

    sleep(5);
    LOG(INFO) << __func__ << " going for stream reconfgured .start  ";
    sUcastClientInterface->Start( bap_bd_addr, voice_streams);
    sUcastClientInterface->Start( bap_bd_addr_2, voice_streams);

     // switch to Gaming tx & rx (10th)
    sleep(5);
    LOG(INFO) << __func__ << " going for stream stop 1 ";
    sUcastClientInterface->Stop( bap_bd_addr, voice_streams);
    sUcastClientInterface->Stop( bap_bd_addr_2, voice_streams);

    sleep(5);
    // reconfig the first stream
    reconf_streams.clear();
    reconf_gaming_tx_rx_info.reconf_type = StreamReconfigType::CODEC_CONFIG;
    reconf_streams.push_back(reconf_gaming_tx_rx_info);
    reconf_streams.push_back(reconf_gaming_rx_info);
    LOG(INFO) << __func__ << " going for stream codec reconfig";
    sUcastClientInterface->Reconfigure( bap_bd_addr, reconf_streams);

    reconf_streams_2.clear();
    reconf_gaming_tx_rx_info_2.reconf_type = StreamReconfigType::CODEC_CONFIG;
    reconf_streams_2.push_back(reconf_gaming_tx_rx_info_2);
    reconf_streams_2.push_back(reconf_gaming_rx_info_2);
    LOG(INFO) << __func__ << " going for stream codec reconfig";
    sUcastClientInterface->Reconfigure( bap_bd_addr_2, reconf_streams_2);

    sleep(5);
    LOG(INFO) << __func__ << " going for stream reconfgured .start  ";
    sUcastClientInterface->Start( bap_bd_addr, gaming_tx_streams);
    sUcastClientInterface->Start( bap_bd_addr, gaming_rx_streams);
    sUcastClientInterface->Start( bap_bd_addr_2, gaming_tx_streams);
    sUcastClientInterface->Start( bap_bd_addr_2, gaming_rx_streams);


    // switch to voice tx & Rx (11th)
    sleep(5);
    LOG(INFO) << __func__ << " going for stream stop 1 ";
    sUcastClientInterface->Stop( bap_bd_addr, gaming_tx_streams);
    sUcastClientInterface->Stop( bap_bd_addr, gaming_rx_streams);
    sUcastClientInterface->Stop( bap_bd_addr_2, gaming_tx_streams);
    sUcastClientInterface->Stop( bap_bd_addr_2, gaming_rx_streams);

    sleep(5);
    // reconfig the first stream
    reconf_streams.clear();
    reconf_streams.push_back(reconf_voice_rx_info);
    LOG(INFO) << __func__ << " going for stream codec reconfig";
    sUcastClientInterface->Reconfigure( bap_bd_addr, reconf_streams);

    reconf_streams_2.clear();
    reconf_streams_2.push_back(reconf_voice_rx_info_2);
    LOG(INFO) << __func__ << " going for stream codec reconfig";
    sUcastClientInterface->Reconfigure( bap_bd_addr_2, reconf_streams_2);

    sleep(5);
    LOG(INFO) << __func__ << " going for stream reconfgured .start  ";
    sUcastClientInterface->Start( bap_bd_addr, voice_streams);
    sUcastClientInterface->Start( bap_bd_addr_2, voice_streams);

    // switch to media tx (12th)
    sleep(5);
    LOG(INFO) << __func__ << " going for stream stop 1 ";
    sUcastClientInterface->Stop( bap_bd_addr, voice_streams);
    sUcastClientInterface->Stop( bap_bd_addr_2, voice_streams);

    sleep(5);
    // reconfig the first stream
    reconf_streams.clear();
    reconf_streams.push_back(reconf_media_info);
    LOG(INFO) << __func__ << " going for stream codec reconfig";
    sUcastClientInterface->Reconfigure( bap_bd_addr, reconf_streams);

    reconf_streams_2.clear();
    reconf_streams_2.push_back(reconf_media_info_2);
    LOG(INFO) << __func__ << " going for stream codec reconfig";
    sUcastClientInterface->Reconfigure( bap_bd_addr_2, reconf_streams_2);

    sleep(5);
    LOG(INFO) << __func__ << " going for stream reconfgured .start  ";
    sUcastClientInterface->Start( bap_bd_addr, media_streams);
    sUcastClientInterface->Start( bap_bd_addr_2, media_streams);

    // switch to voice tx & Rx (13th)
    sleep(5);
    LOG(INFO) << __func__ << " going for stream stop 1 ";
    sUcastClientInterface->Stop( bap_bd_addr, media_streams);
    sUcastClientInterface->Stop( bap_bd_addr_2, media_streams);

    sleep(5);
    // reconfig the first stream
    reconf_streams.clear();
    reconf_streams.push_back(reconf_voice_rx_info);
    LOG(INFO) << __func__ << " going for stream codec reconfig";
    sUcastClientInterface->Reconfigure( bap_bd_addr, reconf_streams);

    reconf_streams_2.clear();
    reconf_streams_2.push_back(reconf_voice_rx_info_2);
    LOG(INFO) << __func__ << " going for stream codec reconfig";
    sUcastClientInterface->Reconfigure( bap_bd_addr_2, reconf_streams_2);

    sleep(5);
    LOG(INFO) << __func__ << " going for stream reconfgured .start  ";
    sUcastClientInterface->Start( bap_bd_addr, voice_streams);
    sUcastClientInterface->Start( bap_bd_addr_2, voice_streams);

    sleep(5);
    LOG(INFO) << __func__ << "going for stream disconnect 1 ";
    sUcastClientInterface->Disconnect( bap_bd_addr, all_three_streams);
    sUcastClientInterface->Disconnect( bap_bd_addr_2, all_three_streams);

    sleep(5);

    LOG(INFO) << __func__ << " going for connect all 3 streams";
    sUcastClientInterface->Connect( bap_bd_addr, true, tri_streams);
    sUcastClientInterface->Connect( bap_bd_addr_2, true, tri_streams_2);

    sleep(15);
    LOG(INFO) << __func__ << "going for stream disconnect all 3 streams ";
    sUcastClientInterface->Disconnect( bap_bd_addr, all_three_streams);

    sUcastClientInterface->Disconnect( bap_bd_addr_2, all_three_streams);

    sleep(5);

  } else if(!strcmp(bap_test, "stereo_headset_dual_cis")) {
    StreamConnect conn_info_media;
    StreamConnect conn_info_gaming;
    StreamConnect conn_info_voice_tx;
    StreamConnect conn_info_voice_rx;
    StreamConnect conn_info_media_recording;

    // reconfig information
    CodecQosConfig codec_qos_config_media_tx_1;
    CodecQosConfig codec_qos_config_media_tx_2;
    CodecQosConfig codec_qos_config_gaming_tx_1;
    CodecQosConfig codec_qos_config_gaming_tx_2;
    CodecQosConfig codec_qos_config_gaming_tx_rx;
    CodecQosConfig codec_qos_config_voice_tx_rx;
    CodecQosConfig codec_qos_config_voice_tx_rx_2;
    CodecQosConfig codec_qos_config_media_rx_1;
    CodecQosConfig codec_qos_config_media_rx_2;

    CISConfig cis_config_1_media_tx = {
                                       .cis_id = 0,
                                       .max_sdu_m_to_s = 155,
                                       .max_sdu_s_to_m = 0,
                                       .phy_m_to_s = 0x02,
                                       .phy_s_to_m = 0x02,
                                       .rtn_m_to_s = 0x02,
                                       .rtn_s_to_m = 0x02
                                    };

    CISConfig cis_config_2_media_tx = {
                                       .cis_id = 1,
                                       .max_sdu_m_to_s = 155,
                                       .max_sdu_s_to_m = 0,
                                       .phy_m_to_s = 0x02,
                                       .phy_s_to_m = 0x02,
                                       .rtn_m_to_s = 0x02,
                                       .rtn_s_to_m = 0x02
                                    };

    CISConfig cis_config_1_media_tx_2 = {
                                       .cis_id = 0,
                                       .max_sdu_m_to_s = 310,
                                       .max_sdu_s_to_m = 0,
                                       .phy_m_to_s = 0x02,
                                       .phy_s_to_m = 0x02,
                                       .rtn_m_to_s = 0x02,
                                       .rtn_s_to_m = 0x02
                                    };


    CISConfig cis_config_1_gaming_tx = {
                                       .cis_id = 0,
                                       .max_sdu_m_to_s = 100,
                                       .max_sdu_s_to_m = 0,
                                       .phy_m_to_s = 0x02,
                                       .phy_s_to_m = 0x02,
                                       .rtn_m_to_s = 0x02,
                                       .rtn_s_to_m = 0x02
                                    };

    CISConfig cis_config_2_gaming_tx = {
                                       .cis_id = 1,
                                       .max_sdu_m_to_s = 100,
                                       .max_sdu_s_to_m = 0,
                                       .phy_m_to_s = 0x02,
                                       .phy_s_to_m = 0x02,
                                       .rtn_m_to_s = 0x02,
                                       .rtn_s_to_m = 0x02
                                    };

    CISConfig cis_config_1_gaming_tx_2 = {
                                       .cis_id = 0,
                                       .max_sdu_m_to_s = 200,
                                       .max_sdu_s_to_m = 0,
                                       .phy_m_to_s = 0x02,
                                       .phy_s_to_m = 0x02,
                                       .rtn_m_to_s = 0x02,
                                       .rtn_s_to_m = 0x02
                                    };


    CISConfig cis_config_1_gaming_tx_rx = {
                                       .cis_id = 0,
                                       .max_sdu_m_to_s = 100,
                                       .max_sdu_s_to_m = 40,
                                       .phy_m_to_s = 0x02,
                                       .phy_s_to_m = 0x02,
                                       .rtn_m_to_s = 0x02,
                                       .rtn_s_to_m = 0x02
                             };
    CISConfig cis_config_2_gaming_tx_rx = {
                                       .cis_id = 1,
                                       .max_sdu_m_to_s = 100,
                                       .max_sdu_s_to_m = 40,
                                       .phy_m_to_s = 0x02,
                                       .phy_s_to_m = 0x02,
                                       .rtn_m_to_s = 0x02,
                                       .rtn_s_to_m = 0x02
                             };

    CISConfig cis_config_1_voice_tx_rx = {
                                       .cis_id = 0,
                                       .max_sdu_m_to_s = 80,
                                       .max_sdu_s_to_m = 80,
                                       .phy_m_to_s = 0x02,
                                       .phy_s_to_m = 0x02,
                                       .rtn_m_to_s = 0x02,
                                       .rtn_s_to_m = 0x02
                             };
    CISConfig cis_config_2_voice_tx_rx = {
                                       .cis_id = 1,
                                       .max_sdu_m_to_s = 80,
                                       .max_sdu_s_to_m = 80,
                                       .phy_m_to_s = 0x02,
                                       .phy_s_to_m = 0x02,
                                       .rtn_m_to_s = 0x02,
                                       .rtn_s_to_m = 0x02
                             };

    CISConfig cis_config_1_media_rx = {
                                       .cis_id = 0,
                                       .max_sdu_m_to_s = 0,
                                       .max_sdu_s_to_m = 100,
                                       .phy_m_to_s = 0x02,
                                       .phy_s_to_m = 0x02,
                                       .rtn_m_to_s = 0x05,
                                       .rtn_s_to_m = 0x05
                                    };

    CISConfig cis_config_2_media_rx = {
                                       .cis_id = 1,
                                       .max_sdu_m_to_s = 0,
                                       .max_sdu_s_to_m = 100,
                                       .phy_m_to_s = 0x02,
                                       .phy_s_to_m = 0x02,
                                       .rtn_m_to_s = 0x05,
                                       .rtn_s_to_m = 0x05
                                    };
    ASCSConfig ascs_config_1 =  {
                                       .cig_id = 1,
                                       .cis_id = 0,
                                       .bi_directional = false,
                                       .presentation_delay = {0x20, 0x4E, 0x00}
                              };

    ASCSConfig ascs_config_2 =  {
                                       .cig_id = 1,
                                       .cis_id = 1,
                                       .bi_directional = false,
                                       .presentation_delay = {0x20, 0x4E, 0x00}
                              };

    ASCSConfig ascs_config_gaming_1 =  {
                                       .cig_id = 1,
                                       .cis_id = 0,
                                       .bi_directional = true,
                                       .presentation_delay = {0x20, 0x4E, 0x00}
                                  };

    ASCSConfig ascs_config_gaming_2 =  {
                                       .cig_id = 1,
                                       .cis_id = 1,
                                       .bi_directional = true,
                                       .presentation_delay = {0x20, 0x4E, 0x00}
                                  };

    ASCSConfig ascs_config_voice_1 =  {
                                       .cig_id = 3,
                                       .cis_id = 0,
                                       .bi_directional = true,
                                       .presentation_delay = {0x40, 0x9C, 0x00}
                                  };

    ASCSConfig ascs_config_voice_2 =  {
                                       .cig_id = 3,
                                       .cis_id = 1,
                                       .bi_directional = true,
                                       .presentation_delay = {0x40, 0x9C, 0x00}
                                  };

    ASCSConfig ascs_config_media_rx_1 =  {
                                   .cig_id = 4,
                                   .cis_id = 0,
                                   .bi_directional = false,
                                   .presentation_delay = {0x20, 0x4E, 0x00}
                              };

    ASCSConfig ascs_config_media_rx_2 =  {
                                   .cig_id = 4,
                                   .cis_id = 1,
                                   .bi_directional = false,
                                   .presentation_delay = {0x20, 0x4E, 0x00}
                              };

    codec_qos_config_media_tx_1.codec_config.codec_type =
                                    CodecIndex::CODEC_INDEX_SOURCE_LC3;
    codec_qos_config_media_tx_1.codec_config.codec_priority =
                                    CodecPriority::CODEC_PRIORITY_DEFAULT;
    codec_qos_config_media_tx_1.codec_config.sample_rate =
                                    CodecSampleRate::CODEC_SAMPLE_RATE_48000;
    codec_qos_config_media_tx_1.codec_config.channel_mode =
                                    CodecChannelMode::CODEC_CHANNEL_MODE_MONO;
    //Frame_Duration
    UpdateFrameDuration(&codec_qos_config_media_tx_1.codec_config,
                       static_cast<uint8_t>(CodecFrameDuration::FRAME_DUR_10));
    // LC3_Blocks_Per_SDU
    UpdateLc3BlocksPerSdu(&codec_qos_config_media_tx_1.codec_config, 1);
    UpdateOctsPerFrame(&codec_qos_config_media_tx_1.codec_config, 155);

    codec_qos_config_media_tx_2 = codec_qos_config_media_tx_1;
    UpdateOctsPerFrame(&codec_qos_config_media_tx_2.codec_config, 310);

    codec_qos_config_media_tx_1.qos_config.cig_config = {
                                       .cig_id = 1,
                                       .cis_count = 2,
                                       .packing = 0x01, // interleaved
                                       .framing =  0x00, // unframed
                                       .max_tport_latency_m_to_s =  0x000a,
                                       .max_tport_latency_s_to_m = 0x000a,
                                       .sdu_interval_m_to_s = {0x10, 0x27, 0x00},
                                       .sdu_interval_s_to_m = {0x10, 0x27, 0x00}
                                      };

    codec_qos_config_media_tx_1.qos_config.cis_configs.push_back(cis_config_1_media_tx);
    codec_qos_config_media_tx_1.qos_config.cis_configs.push_back(cis_config_2_media_tx);

    codec_qos_config_media_tx_1.qos_config.ascs_configs.push_back(ascs_config_1);
    codec_qos_config_media_tx_1.qos_config.ascs_configs.push_back(ascs_config_2);

    codec_qos_config_media_tx_2.qos_config.cig_config = {
                                       .cig_id = 1,
                                       .cis_count = 1,
                                       .packing = 0x01, // interleaved
                                       .framing =  0x00, // unframed
                                       .max_tport_latency_m_to_s =  0x000a,
                                       .max_tport_latency_s_to_m = 0x000a,
                                       .sdu_interval_m_to_s = {0x10, 0x27, 0x00},
                                       .sdu_interval_s_to_m = {0x10, 0x27, 0x00}
                                      };

    codec_qos_config_media_tx_2.qos_config.cis_configs.push_back(cis_config_1_media_tx_2);

    codec_qos_config_media_tx_2.qos_config.ascs_configs.push_back(ascs_config_1);

    codec_qos_config_gaming_tx_1.codec_config.codec_type =
                                    CodecIndex::CODEC_INDEX_SOURCE_LC3;
    codec_qos_config_gaming_tx_1.codec_config.codec_priority =
                                    CodecPriority::CODEC_PRIORITY_DEFAULT;
    codec_qos_config_gaming_tx_1.codec_config.sample_rate =
                                    CodecSampleRate::CODEC_SAMPLE_RATE_48000;
    codec_qos_config_gaming_tx_1.codec_config.channel_mode =
                                    CodecChannelMode::CODEC_CHANNEL_MODE_MONO;
    //Frame_Duration
    UpdateFrameDuration(&codec_qos_config_gaming_tx_1.codec_config,
                       static_cast<uint8_t>(CodecFrameDuration::FRAME_DUR_10));
    // LC3_Blocks_Per_SDU
    UpdateLc3BlocksPerSdu(&codec_qos_config_gaming_tx_1.codec_config, 1);
    UpdateOctsPerFrame(&codec_qos_config_gaming_tx_1.codec_config, 100);

    codec_qos_config_gaming_tx_2 = codec_qos_config_gaming_tx_1;
    UpdateOctsPerFrame(&codec_qos_config_gaming_tx_2.codec_config, 200);

    codec_qos_config_gaming_tx_1.qos_config.cig_config = {
                                       .cig_id = 1,
                                       .cis_count = 2,
                                       .packing = 0x01, // interleaved
                                       .framing =  0x00, // unframed
                                       .max_tport_latency_m_to_s =  0x000a,
                                       .max_tport_latency_s_to_m = 0x000a,
                                       .sdu_interval_m_to_s = {0x10, 0x27, 0x00},
                                       .sdu_interval_s_to_m = {0x10, 0x27, 0x00}
                                      };

    codec_qos_config_gaming_tx_1.qos_config.cis_configs.push_back(cis_config_1_gaming_tx);
    codec_qos_config_gaming_tx_1.qos_config.cis_configs.push_back(cis_config_2_gaming_tx);

    codec_qos_config_gaming_tx_1.qos_config.ascs_configs.push_back(ascs_config_gaming_1);
    codec_qos_config_gaming_tx_1.qos_config.ascs_configs.push_back(ascs_config_gaming_2);

    codec_qos_config_gaming_tx_2.qos_config.cig_config = {
                                       .cig_id = 1,
                                       .cis_count = 1,
                                       .packing = 0x01, // interleaved
                                       .framing =  0x00, // unframed
                                       .max_tport_latency_m_to_s =  0x000a,
                                       .max_tport_latency_s_to_m = 0x000a,
                                       .sdu_interval_m_to_s = {0x10, 0x27, 0x00},
                                       .sdu_interval_s_to_m = {0x10, 0x27, 0x00}
                                      };

    codec_qos_config_gaming_tx_2.qos_config.cis_configs.push_back(cis_config_1_gaming_tx_2);

    codec_qos_config_gaming_tx_2.qos_config.ascs_configs.push_back(ascs_config_gaming_1);

    codec_qos_config_gaming_tx_rx.codec_config.codec_type =
                                    CodecIndex::CODEC_INDEX_SOURCE_LC3;
    codec_qos_config_gaming_tx_rx.codec_config.codec_priority =
                                    CodecPriority::CODEC_PRIORITY_DEFAULT;
    codec_qos_config_gaming_tx_rx.codec_config.sample_rate =
                                    CodecSampleRate::CODEC_SAMPLE_RATE_16000;
    codec_qos_config_gaming_tx_rx.codec_config.channel_mode =
                                    CodecChannelMode::CODEC_CHANNEL_MODE_MONO;
    //Frame_Duration
    UpdateFrameDuration(&codec_qos_config_gaming_tx_rx.codec_config,
                       static_cast<uint8_t>(CodecFrameDuration::FRAME_DUR_10));
    // LC3_Blocks_Per_SDU
    UpdateLc3BlocksPerSdu(&codec_qos_config_gaming_tx_rx.codec_config, 1);
    UpdateOctsPerFrame(&codec_qos_config_gaming_tx_rx.codec_config, 40);
    codec_qos_config_gaming_tx_rx.qos_config.cig_config = {
                                       .cig_id = 2,
                                       .cis_count = 2,
                                       .packing = 0x01, // interleaved
                                       .framing =  0x00, // unframed
                                       .max_tport_latency_m_to_s =  0x000a,
                                       .max_tport_latency_s_to_m = 0x000a,
                                       .sdu_interval_m_to_s = {0x10, 0x27, 0x00},
                                       .sdu_interval_s_to_m = {0x10, 0x27, 0x00}
                                      };

    codec_qos_config_gaming_tx_rx.qos_config.cis_configs.push_back(cis_config_1_gaming_tx_rx);
    codec_qos_config_gaming_tx_rx.qos_config.cis_configs.push_back(cis_config_2_gaming_tx_rx);

    codec_qos_config_gaming_tx_rx.qos_config.ascs_configs.push_back(ascs_config_gaming_1);

    // voice tx rx
    codec_qos_config_voice_tx_rx.codec_config.codec_type =
                                    CodecIndex::CODEC_INDEX_SOURCE_LC3;
    codec_qos_config_voice_tx_rx.codec_config.codec_priority =
                                    CodecPriority::CODEC_PRIORITY_DEFAULT;
    codec_qos_config_voice_tx_rx.codec_config.sample_rate =
                                    CodecSampleRate::CODEC_SAMPLE_RATE_32000;
    codec_qos_config_voice_tx_rx.codec_config.channel_mode =
                                    CodecChannelMode::CODEC_CHANNEL_MODE_MONO;
    //Frame_Duration
    UpdateFrameDuration(&codec_qos_config_voice_tx_rx.codec_config,
                       static_cast<uint8_t>(CodecFrameDuration::FRAME_DUR_10));
    // LC3_Blocks_Per_SDU
    UpdateLc3BlocksPerSdu(&codec_qos_config_voice_tx_rx.codec_config, 1);
    UpdateOctsPerFrame(&codec_qos_config_voice_tx_rx.codec_config, 80);
    codec_qos_config_voice_tx_rx.qos_config.cig_config = {
                                       .cig_id = 3,
                                       .cis_count = 2,
                                       .packing = 0x01, // interleaved
                                       .framing =  0x00, // unframed
                                       .max_tport_latency_m_to_s =  0x000a,
                                       .max_tport_latency_s_to_m = 0x000a,
                                       .sdu_interval_m_to_s = {0x10, 0x27, 0x00},
                                       .sdu_interval_s_to_m = {0x10, 0x27, 0x00}
                                      };

    codec_qos_config_voice_tx_rx.qos_config.cis_configs.push_back(cis_config_1_voice_tx_rx);
    codec_qos_config_voice_tx_rx.qos_config.cis_configs.push_back(cis_config_2_voice_tx_rx);

    codec_qos_config_voice_tx_rx.qos_config.ascs_configs.push_back(ascs_config_voice_1);
    codec_qos_config_voice_tx_rx.qos_config.ascs_configs.push_back(ascs_config_voice_2);


    codec_qos_config_media_rx_1.codec_config.codec_type =
                                    CodecIndex::CODEC_INDEX_SOURCE_LC3;
    codec_qos_config_media_rx_1.codec_config.codec_priority =
                                    CodecPriority::CODEC_PRIORITY_DEFAULT;
    codec_qos_config_media_rx_1.codec_config.sample_rate =
                                    CodecSampleRate::CODEC_SAMPLE_RATE_48000;
    codec_qos_config_media_rx_1.codec_config.channel_mode =
                                    CodecChannelMode::CODEC_CHANNEL_MODE_MONO;
    //Frame_Duration
    UpdateFrameDuration(&codec_qos_config_media_rx_1.codec_config,
                       static_cast<uint8_t>(CodecFrameDuration::FRAME_DUR_10));
    // LC3_Blocks_Per_SDU
    UpdateLc3BlocksPerSdu(&codec_qos_config_media_rx_1.codec_config, 1);
    UpdateOctsPerFrame(&codec_qos_config_media_rx_1.codec_config, 100);

    codec_qos_config_media_rx_1.qos_config.cig_config = {
                                       .cig_id = 4,
                                       .cis_count = 2,
                                       .packing = 0x01, // interleaved
                                       .framing =  0x00, // unframed
                                       .max_tport_latency_m_to_s = 0x000a,
                                       .max_tport_latency_s_to_m = 0x000a,
                                       .sdu_interval_m_to_s = {0x10, 0x27, 0x00},
                                       .sdu_interval_s_to_m = {0x10, 0x27, 0x00}
                                      };

    codec_qos_config_media_rx_1.qos_config.cis_configs.push_back(cis_config_1_media_rx);
    codec_qos_config_media_rx_1.qos_config.cis_configs.push_back(cis_config_2_media_rx);

    codec_qos_config_media_rx_1.qos_config.ascs_configs.push_back(ascs_config_media_rx_1);
    codec_qos_config_media_rx_1.qos_config.ascs_configs.push_back(ascs_config_media_rx_2);

    conn_info_media.stream_type.type = CONTENT_TYPE_MEDIA;
    conn_info_media.stream_type.audio_context = CONTENT_TYPE_MEDIA;
    conn_info_media.stream_type.direction = ASE_DIRECTION_SINK;
    conn_info_media.codec_qos_config_pair.push_back(codec_qos_config_media_tx_1);
    conn_info_media.codec_qos_config_pair.push_back(codec_qos_config_media_tx_2);

    conn_info_gaming.stream_type.type = CONTENT_TYPE_CONVERSATIONAL;
    conn_info_gaming.stream_type.audio_context = CONTENT_TYPE_GAME;
    conn_info_gaming.stream_type.direction = ASE_DIRECTION_SRC;
    conn_info_gaming.codec_qos_config_pair.push_back(codec_qos_config_gaming_tx_1);

    conn_info_voice_tx.stream_type.type = CONTENT_TYPE_CONVERSATIONAL;
    conn_info_voice_tx.stream_type.audio_context = CONTENT_TYPE_CONVERSATIONAL;
    conn_info_voice_tx.stream_type.direction = ASE_DIRECTION_SINK;
    conn_info_voice_tx.codec_qos_config_pair.push_back(codec_qos_config_voice_tx_rx);

    conn_info_voice_rx.stream_type.type = CONTENT_TYPE_CONVERSATIONAL;
    conn_info_voice_rx.stream_type.audio_context = CONTENT_TYPE_CONVERSATIONAL;
    conn_info_voice_rx.stream_type.direction = ASE_DIRECTION_SRC;
    conn_info_voice_rx.codec_qos_config_pair.push_back(codec_qos_config_voice_tx_rx);

    conn_info_media_recording.stream_type.type = CONTENT_TYPE_MEDIA;
    conn_info_media_recording.stream_type.audio_context = CONTENT_TYPE_LIVE;
    conn_info_media_recording.stream_type.direction = ASE_DIRECTION_SRC;
    conn_info_media_recording.codec_qos_config_pair.push_back(codec_qos_config_media_rx_1);

    std::vector<StreamConnect> four_streams;
    four_streams.push_back(conn_info_media);
    four_streams.push_back(conn_info_media_recording);
    four_streams.push_back(conn_info_voice_tx);
    four_streams.push_back(conn_info_voice_rx);

    std::vector<StreamConnect> voice_conn_streams;
    voice_conn_streams.push_back(conn_info_voice_tx);
    voice_conn_streams.push_back(conn_info_voice_rx);

    std::vector<StreamConnect> media_conn_streams;
    media_conn_streams.push_back(conn_info_media);

    StreamType type_media = { .type = CONTENT_TYPE_MEDIA,
                              .audio_context = CONTENT_TYPE_MEDIA,
                              .direction = ASE_DIRECTION_SINK
                            };

    StreamType type_gaming_tx = { .type = CONTENT_TYPE_MEDIA,
                                  .audio_context = CONTENT_TYPE_GAME,
                                  .direction = ASE_DIRECTION_SINK
                            };

    StreamType type_voice_tx = { .type = CONTENT_TYPE_CONVERSATIONAL,
                                 .audio_context = CONTENT_TYPE_CONVERSATIONAL,
                                 .direction = ASE_DIRECTION_SINK
                            };

    StreamType type_voice_rx = { .type = CONTENT_TYPE_CONVERSATIONAL,
                                 .audio_context = CONTENT_TYPE_CONVERSATIONAL,
                                 .direction = ASE_DIRECTION_SRC
                            };

    StreamType type_media_rx = { .type = CONTENT_TYPE_MEDIA,
                                 .audio_context = CONTENT_TYPE_LIVE,
                                 .direction = ASE_DIRECTION_SRC
                               };

    std::vector<StreamType> media_streams;
    media_streams.push_back(type_media);

    std::vector<StreamType> gaming_tx_streams;
    gaming_tx_streams.push_back(type_gaming_tx);

    std::vector<StreamType> media_rx_streams;
    media_rx_streams.push_back(type_media_rx);

    std::vector<StreamType> voice_streams;
    voice_streams.push_back(type_voice_tx);
    voice_streams.push_back(type_voice_rx);

    std::vector<StreamType> all_four_streams;
    all_four_streams.push_back(type_media);
    all_four_streams.push_back(type_voice_tx);
    all_four_streams.push_back(type_voice_rx);
    all_four_streams.push_back(type_media_rx);

    std::vector<StreamReconfig> reconf_streams;

    StreamReconfig reconf_media_info;
    reconf_media_info.stream_type.type = CONTENT_TYPE_MEDIA;
    reconf_media_info.stream_type.audio_context = CONTENT_TYPE_MEDIA;
    reconf_media_info.reconf_type = StreamReconfigType::CODEC_CONFIG;
    reconf_media_info.stream_type.direction = ASE_DIRECTION_SINK;
    reconf_media_info.codec_qos_config_pair.push_back(codec_qos_config_media_tx_1);
    reconf_media_info.codec_qos_config_pair.push_back(codec_qos_config_media_tx_2);

    StreamReconfig reconf_gaming_tx_info;
    reconf_gaming_tx_info.stream_type.type = CONTENT_TYPE_MEDIA;
    reconf_gaming_tx_info.stream_type.audio_context = CONTENT_TYPE_MEDIA;
    reconf_gaming_tx_info.reconf_type = StreamReconfigType::CODEC_CONFIG;
    reconf_gaming_tx_info.stream_type.direction = ASE_DIRECTION_SINK;
    reconf_gaming_tx_info.codec_qos_config_pair.push_back(codec_qos_config_gaming_tx_1);
    reconf_gaming_tx_info.codec_qos_config_pair.push_back(codec_qos_config_gaming_tx_2);

    StreamReconfig reconf_voice_tx_info;
    reconf_voice_tx_info.stream_type.type = CONTENT_TYPE_CONVERSATIONAL;
    reconf_voice_tx_info.stream_type.audio_context = CONTENT_TYPE_CONVERSATIONAL;
    reconf_voice_tx_info.reconf_type = StreamReconfigType::CODEC_CONFIG;
    reconf_voice_tx_info.stream_type.direction = ASE_DIRECTION_SINK;
    reconf_voice_tx_info.codec_qos_config_pair.
                                 push_back(codec_qos_config_voice_tx_rx);

    StreamReconfig reconf_voice_rx_info;
    reconf_voice_rx_info.stream_type.type = CONTENT_TYPE_CONVERSATIONAL;
    reconf_voice_rx_info.stream_type.audio_context = CONTENT_TYPE_CONVERSATIONAL;
    reconf_voice_rx_info.reconf_type = StreamReconfigType::CODEC_CONFIG;
    reconf_voice_rx_info.stream_type.direction = ASE_DIRECTION_SRC;
    reconf_voice_rx_info.codec_qos_config_pair.
                       push_back(codec_qos_config_voice_tx_rx);

    StreamReconfig reconf_media_rx_info;
    reconf_media_rx_info.stream_type.type = CONTENT_TYPE_MEDIA;
    reconf_media_rx_info.stream_type.audio_context = CONTENT_TYPE_LIVE;
    reconf_media_rx_info.reconf_type = StreamReconfigType::CODEC_CONFIG;
    reconf_media_rx_info.stream_type.direction = ASE_DIRECTION_SRC;
    reconf_media_rx_info.codec_qos_config_pair.push_back(codec_qos_config_media_rx_1);

    LOG(INFO) << __func__ << " going for generic test case";
    LOG(INFO) << __func__ << " going for connect with voice tx and rx";
    sUcastClientInterface->Connect( bap_bd_addr_2, true, four_streams);

    sleep(15);

#if 0
    //  Recording to music switch (12)
    LOG(INFO) << __func__ << " going for stream codec reconfig";
    reconf_streams.clear();
    reconf_streams.push_back(reconf_media_info);
    sUcastClientInterface->Reconfigure( bap_bd_addr_2, reconf_streams);

    sleep(5);
    LOG(INFO) << __func__ << "going for music  stream start ";
    sUcastClientInterface->Start( bap_bd_addr_2, media_streams);

    sleep(5);
    LOG(INFO) << __func__ << "going for media stream stop ";
    sUcastClientInterface->Stop( bap_bd_addr_2, media_streams);

    sleep(5);

    sUcastClientInterface->Reconfigure( bap_bd_addr_2, reconf_streams);

    sleep(5);

    LOG(INFO) << __func__ << "going for music  stream start ";
    sUcastClientInterface->Start( bap_bd_addr_2, media_streams);

    sleep(5);
    LOG(INFO) << __func__ << "going for media stream stop ";
    sUcastClientInterface->Stop( bap_bd_addr_2, media_streams);

    //sleep(5);
    LOG(INFO) << __func__ << "going for stream disconnect voice streams ";
    sUcastClientInterface->Disconnect( bap_bd_addr_2, all_four_streams);

    sleep(10);

    LOG(INFO) << __func__ << " going for connect with voice tx and rx";
    sUcastClientInterface->Connect( bap_bd_addr_2, true, four_streams);

    sleep(15);

    LOG(INFO) << __func__ << " going for stream codec reconfig";
    reconf_streams.clear();
    reconf_streams.push_back(reconf_media_info);
    sUcastClientInterface->Reconfigure( bap_bd_addr_2, reconf_streams);

    sleep(5);
    LOG(INFO) << __func__ << "going for music  stream start ";
    sUcastClientInterface->Start( bap_bd_addr_2, media_streams);

    //sleep(5);
    LOG(INFO) << __func__ << "going for stream disconnect voice streams ";
    sUcastClientInterface->Disconnect( bap_bd_addr_2, all_four_streams);

    sleep(10);


    LOG(INFO) << __func__ << " going for connect with voice tx and rx";
    sUcastClientInterface->Connect( bap_bd_addr_2, true, four_streams);

    sleep(15);
    reconf_streams.clear();
    reconf_streams.push_back(reconf_voice_tx_info);
    reconf_streams.push_back(reconf_voice_rx_info);
    LOG(INFO) << __func__ << " going for voice stream codec reconfig";
    sUcastClientInterface->Reconfigure( bap_bd_addr_2, reconf_streams);

    sleep(5);
    LOG(INFO) << __func__ << "going for voice stream start ";
    sUcastClientInterface->Start( bap_bd_addr_2, voice_streams);


     // Call Tx Rx to Gaming switch (4)
    sleep(5);
    LOG(INFO) << __func__ << "going for media stream stop ";
    sUcastClientInterface->Stop( bap_bd_addr_2, voice_streams);
    sleep(5);

    LOG(INFO) << __func__ << " going for voice stream codec reconfig";
    sUcastClientInterface->Reconfigure( bap_bd_addr_2, reconf_streams);
    sleep(5);

    LOG(INFO) << __func__ << "going for voice stream start ";
    sUcastClientInterface->Start( bap_bd_addr_2, voice_streams);


     // Call Tx Rx to Gaming switch (4)
    sleep(5);
    LOG(INFO) << __func__ << "going for media stream stop ";
    sUcastClientInterface->Stop( bap_bd_addr_2, voice_streams);

    //sleep(5);
    LOG(INFO) << __func__ << "going for stream disconnect voice streams ";
    sUcastClientInterface->Disconnect( bap_bd_addr_2, all_four_streams);

    sleep(10);


    LOG(INFO) << __func__ << " going for connect with voice tx and rx";
    sUcastClientInterface->Connect( bap_bd_addr_2, true, four_streams);
    sleep(15);

    reconf_streams.clear();
    reconf_streams.push_back(reconf_voice_tx_info);
    reconf_streams.push_back(reconf_voice_rx_info);
    LOG(INFO) << __func__ << " going for voice stream codec reconfig";
    sUcastClientInterface->Reconfigure( bap_bd_addr_2, reconf_streams);

    sleep(5);
    LOG(INFO) << __func__ << "going for voice stream start ";
    sUcastClientInterface->Start( bap_bd_addr_2, voice_streams);

    //sleep(5);
    LOG(INFO) << __func__ << "going for stream disconnect voice streams ";
    sUcastClientInterface->Disconnect( bap_bd_addr_2, all_four_streams);

    sleep(10);

    sUcastClientInterface->Connect( bap_bd_addr_2, true, four_streams);

    sleep(1);

    LOG(INFO) << __func__ << "going for stream disconnect voice streams ";
    sUcastClientInterface->Disconnect( bap_bd_addr_2, all_four_streams);

    sleep(10);

    sUcastClientInterface->Connect( bap_bd_addr_2, true, four_streams);

    sleep(15);

#endif
#if 1
    reconf_streams.clear();
    reconf_streams.push_back(reconf_voice_tx_info);
    reconf_streams.push_back(reconf_voice_rx_info);
    LOG(INFO) << __func__ << " going for voice stream codec reconfig";
    sUcastClientInterface->Reconfigure( bap_bd_addr_2, reconf_streams);

    //usleep(200000);

    sleep(5);

    LOG(INFO) << __func__ << "going for voice stream start ";
    sUcastClientInterface->Start( bap_bd_addr_2, voice_streams);


     // Call Tx Rx to Gaming switch (4)
    sleep(5);
    LOG(INFO) << __func__ << "going for media stream stop ";
    sUcastClientInterface->Stop( bap_bd_addr_2, voice_streams);

    sleep(5);

    LOG(INFO) << __func__ << " going for voice stream codec reconfig";
    sUcastClientInterface->Reconfigure( bap_bd_addr_2, reconf_streams);

    sleep(5);

    LOG(INFO) << __func__ << "going for voice stream start ";
    sUcastClientInterface->Start( bap_bd_addr_2, voice_streams);


     // Call Tx Rx to Gaming switch (4)
    sleep(5);
    LOG(INFO) << __func__ << "going for media stream stop ";
    sUcastClientInterface->Stop( bap_bd_addr_2, voice_streams);

    sleep(5);

    LOG(INFO) << __func__ << "going for voice stream start ";
    sUcastClientInterface->Start( bap_bd_addr_2, voice_streams);

    sleep(5);
    //usleep(200000);
    LOG(INFO) << __func__ << "going for stream disconnect voice streams ";
    sUcastClientInterface->Disconnect( bap_bd_addr_2, all_four_streams);

    sleep(10);

    sUcastClientInterface->Connect( bap_bd_addr_2, true, four_streams);
#endif

    sleep(15);
    LOG(INFO) << __func__ << " going for stream codec reconfig";
    reconf_streams.clear();
    reconf_streams.push_back(reconf_media_info);
    sUcastClientInterface->Reconfigure( bap_bd_addr_2, reconf_streams);

    sleep(5);

    // Music streaming
    LOG(INFO) << __func__ << "going for media stream start ";
    sUcastClientInterface->Start( bap_bd_addr_2, media_streams);

    // music to gaming Tx switch  (1)
    sleep(5);
    LOG(INFO) << __func__ << "going for media stream stop ";
    sUcastClientInterface->Stop( bap_bd_addr_2, media_streams);

    sleep(5);
    LOG(INFO) << __func__ << " going for stream codec reconfig";
    reconf_streams.clear();
    reconf_streams.push_back(reconf_gaming_tx_info);
    sUcastClientInterface->Reconfigure( bap_bd_addr_2, reconf_streams);

    sleep(5);
    LOG(INFO) << __func__ << "going for gaming stream start ";
    sUcastClientInterface->Start( bap_bd_addr_2, gaming_tx_streams);

    // Gaming Tx to music switch  (2)
    sleep(5);
    LOG(INFO) << __func__ << "going for media stream stop ";
    sUcastClientInterface->Stop( bap_bd_addr_2, gaming_tx_streams);

    sleep(5);
    LOG(INFO) << __func__ << " going for stream codec reconfig";
    reconf_streams.clear();
    reconf_streams.push_back(reconf_media_info);
    sUcastClientInterface->Reconfigure( bap_bd_addr_2, reconf_streams);

    sleep(5);
    LOG(INFO) << __func__ << "going for gaming stream start ";
    sUcastClientInterface->Start( bap_bd_addr_2, media_streams);

     // music to Call Tx Rx switch (3)
    sleep(5);
    LOG(INFO) << __func__ << "going for media stream stop ";
    sUcastClientInterface->Stop( bap_bd_addr_2, media_streams);

    sleep(5);
    reconf_streams.clear();
    reconf_streams.push_back(reconf_voice_tx_info);
    reconf_streams.push_back(reconf_voice_rx_info);
    LOG(INFO) << __func__ << " going for voice stream codec reconfig";
    sUcastClientInterface->Reconfigure( bap_bd_addr_2, reconf_streams);

    sleep(5);
    LOG(INFO) << __func__ << "going for voice stream start ";
    sUcastClientInterface->Start( bap_bd_addr_2, voice_streams);


     // Call Tx Rx to Gaming switch (4)
    sleep(5);
    LOG(INFO) << __func__ << "going for media stream stop ";
    sUcastClientInterface->Stop( bap_bd_addr_2, voice_streams);

    sleep(5);
    LOG(INFO) << __func__ << " going for stream codec reconfig";
    reconf_streams.clear();
    reconf_streams.push_back(reconf_gaming_tx_info);
    sUcastClientInterface->Reconfigure( bap_bd_addr_2, reconf_streams);

    sleep(5);
    LOG(INFO) << __func__ << "going for gaming stream start ";
    sUcastClientInterface->Start( bap_bd_addr_2, gaming_tx_streams);


     // Gaming to Cal Audio switch (5)
    sleep(5);
    LOG(INFO) << __func__ << "going for media stream stop ";
    sUcastClientInterface->Stop( bap_bd_addr_2, gaming_tx_streams);

    sleep(5);
    reconf_streams.clear();
    reconf_streams.push_back(reconf_voice_tx_info);
    reconf_streams.push_back(reconf_voice_rx_info);
    LOG(INFO) << __func__ << " going for voice stream codec reconfig";
    sUcastClientInterface->Reconfigure( bap_bd_addr_2, reconf_streams);

    sleep(5);
    LOG(INFO) << __func__ << "going for voice stream start ";
    sUcastClientInterface->Start( bap_bd_addr_2, voice_streams);



     // Cal Audio to music switch (6)
    sleep(5);
    LOG(INFO) << __func__ << "going for media stream stop ";
    sUcastClientInterface->Stop( bap_bd_addr_2, voice_streams);

    sleep(5);
    LOG(INFO) << __func__ << " going for stream codec reconfig";
    reconf_streams.clear();
    reconf_streams.push_back(reconf_media_info);
    sUcastClientInterface->Reconfigure( bap_bd_addr_2, reconf_streams);

    sleep(5);
    LOG(INFO) << __func__ << "going for music  stream start ";
    sUcastClientInterface->Start( bap_bd_addr_2, media_streams);


     //  music to Recording switch (7)
    sleep(5);
    LOG(INFO) << __func__ << "going for media stream stop ";
    sUcastClientInterface->Stop( bap_bd_addr_2, media_streams);

    sleep(5);
    LOG(INFO) << __func__ << " going for stream codec reconfig";
    reconf_streams.clear();
    reconf_streams.push_back(reconf_media_rx_info);
    sUcastClientInterface->Reconfigure( bap_bd_addr_2, reconf_streams);

    sleep(5);
    LOG(INFO) << __func__ << "going for recording stream start ";
    sUcastClientInterface->Start( bap_bd_addr_2, media_rx_streams);


     //  Recording to Gaming switch (8)
    sleep(5);
    LOG(INFO) << __func__ << "going for media stream stop ";
    sUcastClientInterface->Stop( bap_bd_addr_2, media_rx_streams);

    sleep(5);
    LOG(INFO) << __func__ << " going for stream codec reconfig";
    reconf_streams.clear();
    reconf_streams.push_back(reconf_gaming_tx_info);
    sUcastClientInterface->Reconfigure( bap_bd_addr_2, reconf_streams);

    sleep(5);
    LOG(INFO) << __func__ << "going for gaming stream start ";
    sUcastClientInterface->Start( bap_bd_addr_2, gaming_tx_streams);


     //  Gaming to Recording switch (9)
    sleep(5);
    LOG(INFO) << __func__ << "going for media stream stop ";
    sUcastClientInterface->Stop( bap_bd_addr_2, gaming_tx_streams);

    sleep(5);
    LOG(INFO) << __func__ << " going for stream codec reconfig";
    reconf_streams.clear();
    reconf_streams.push_back(reconf_media_rx_info);
    sUcastClientInterface->Reconfigure( bap_bd_addr_2, reconf_streams);

    sleep(5);
    LOG(INFO) << __func__ << "going for recording stream start ";
    sUcastClientInterface->Start( bap_bd_addr_2, media_rx_streams);


     //  Recording to Call Audio switch (10)
    sleep(5);
    LOG(INFO) << __func__ << "going for media stream stop ";
    sUcastClientInterface->Stop( bap_bd_addr_2, media_rx_streams);

    sleep(5);
    reconf_streams.clear();
    reconf_streams.push_back(reconf_voice_tx_info);
    reconf_streams.push_back(reconf_voice_rx_info);
    LOG(INFO) << __func__ << " going for voice stream codec reconfig";
    sUcastClientInterface->Reconfigure( bap_bd_addr_2, reconf_streams);

    sleep(5);
    LOG(INFO) << __func__ << "going for voice stream start ";
    sUcastClientInterface->Start( bap_bd_addr_2, voice_streams);


     //  Call Audio to Recording switch (11)
    sleep(5);
    LOG(INFO) << __func__ << "going for media stream stop ";
    sUcastClientInterface->Stop( bap_bd_addr_2, voice_streams);

    sleep(5);
    LOG(INFO) << __func__ << " going for stream codec reconfig";
    reconf_streams.clear();
    reconf_streams.push_back(reconf_media_rx_info);
    sUcastClientInterface->Reconfigure( bap_bd_addr_2, reconf_streams);

    sleep(5);
    LOG(INFO) << __func__ << "going for recording stream start ";
    sUcastClientInterface->Start( bap_bd_addr_2, media_rx_streams);


     //  Recording to music switch (12)
    sleep(5);
    LOG(INFO) << __func__ << "going for media stream stop ";
    sUcastClientInterface->Stop( bap_bd_addr_2, media_rx_streams);

    sleep(5);
    LOG(INFO) << __func__ << " going for stream codec reconfig";
    reconf_streams.clear();
    reconf_streams.push_back(reconf_media_info);
    sUcastClientInterface->Reconfigure( bap_bd_addr_2, reconf_streams);

    sleep(5);
    LOG(INFO) << __func__ << "going for music  stream start ";
    sUcastClientInterface->Start( bap_bd_addr_2, media_streams);

    sleep(5);
    LOG(INFO) << __func__ << "going for media stream stop ";
    sUcastClientInterface->Stop( bap_bd_addr_2, media_streams);

    //sleep(5);
    LOG(INFO) << __func__ << "going for stream disconnect voice streams ";
    sUcastClientInterface->Disconnect( bap_bd_addr_2, all_four_streams);

    sleep(10);

  } else if(!strcmp(bap_test, "connect")) {
    LOG(INFO) << __func__ << " going for connect test case";

    for ( uint8_t i = 0; i < 5; i++) {
      LOG(INFO) << __func__ << " iteration " << loghex(i);
      LOG(INFO) << __func__ << " going for connect";
      sUcastClientInterface->Connect( bap_bd_addr, true, streams);
      usleep( i* 1000 * 1000);
      LOG(INFO) << __func__ << " going for stream disconnect";
      sUcastClientInterface->Disconnect( bap_bd_addr, start_streams);
    }
  } else if(!strcmp(bap_test, "release_in_streaming")) {
    LOG(INFO) << __func__ << " going for release_in_streaming test case";

    LOG(INFO) << __func__ << " going for connect";
    sUcastClientInterface->Connect( bap_bd_addr, true, streams);

    sleep(10);

    LOG(INFO) << __func__ << " going for stream start";
    sUcastClientInterface->Start( bap_bd_addr, start_streams);

    sleep(10);

    LOG(INFO) << __func__ << "going for stream disconnect";
    sUcastClientInterface->Disconnect( bap_bd_addr, start_streams);


  } else if(!strcmp(bap_test, "release_in_enabling")) {
    LOG(INFO) << __func__ << " going for release_in_enabling test case";

    LOG(INFO) << __func__ << " going for connect";
    sUcastClientInterface->Connect( bap_bd_addr, true, streams);

    sleep(10);

    LOG(INFO) << __func__ << " going for stream start";
    sUcastClientInterface->Start( bap_bd_addr, start_streams);

    usleep(150 *1000);

    LOG(INFO) << __func__ << "going for stream disconnect";
    sUcastClientInterface->Disconnect( bap_bd_addr, start_streams);


  } else if(!strcmp(bap_test, "release_in_disabling")) {
    LOG(INFO) << __func__ << " going for release_in_disabling test case";

    LOG(INFO) << __func__ << " going for connect";
    sUcastClientInterface->Connect( bap_bd_addr, true, streams);

    sleep(10);

    LOG(INFO) << __func__ << " going for stream start";
    sUcastClientInterface->Start( bap_bd_addr, start_streams);

    sleep(10);

    LOG(INFO) << __func__ << " going for stream stop";
    sUcastClientInterface->Stop( bap_bd_addr, start_streams);

    usleep(100 * 1000);
    LOG(INFO) << __func__ << "going for stream disconnect";
    sUcastClientInterface->Disconnect( bap_bd_addr, start_streams);

  } else if(!strcmp(bap_test, "disable_in_enabling")) {
    LOG(INFO) << __func__ << " going for disable_in_enabling test case";

    LOG(INFO) << __func__ << " going for connect";
    sUcastClientInterface->Connect( bap_bd_addr, true, streams);

    sleep(10);

    LOG(INFO) << __func__ << " going for stream start";
    sUcastClientInterface->Start( bap_bd_addr, start_streams);

    usleep(200 * 1000);
    LOG(INFO) << __func__ << "going for stream stop";
    sUcastClientInterface->Stop( bap_bd_addr, start_streams);

  } else if(!strcmp(bap_test, "disable_in_streaming")) {
    LOG(INFO) << __func__ << " going for disable_in_streaming test case";

    LOG(INFO) << __func__ << " going for connect";
    sUcastClientInterface->Connect( bap_bd_addr, true, streams);

    sleep(10);

    LOG(INFO) << __func__ << " going for stream start";
    sUcastClientInterface->Start( bap_bd_addr, start_streams);

    sleep(5);

    LOG(INFO) << __func__ << "going for stream stop";
    sUcastClientInterface->Stop( bap_bd_addr, start_streams);

  } else if(!strcmp(bap_test, "release_in_codec_configured")) {
    LOG(INFO) << __func__ << " going for release_in_codec_configured test case";

    LOG(INFO) << __func__ << " going for connect";
    sUcastClientInterface->Connect( bap_bd_addr, true, streams);

    usleep(2600 * 1000);
    LOG(INFO) << __func__ << "going for stream disconnect";
    sUcastClientInterface->Disconnect( bap_bd_addr, start_streams);

  } else if(!strcmp(bap_test, "release_in_qos_configured")) {
    LOG(INFO) << __func__ << " going for release_in_qos_configured test case";

    LOG(INFO) << __func__ << " going for connect";
    sUcastClientInterface->Connect( bap_bd_addr, true, streams);

    sleep(10);

    LOG(INFO) << __func__ << "going for stream disconnect";
    sUcastClientInterface->Disconnect( bap_bd_addr, start_streams);

  } else if(!strcmp(bap_test, "enable_in_qos_configured")) {
    LOG(INFO) << __func__ << " going for enable_in_qos_configured test case";

    LOG(INFO) << __func__ << " going for connect";
    sUcastClientInterface->Connect( bap_bd_addr, true, streams);

    sleep(10);

    LOG(INFO) << __func__ << "going for stream start";
    sUcastClientInterface->Start( bap_bd_addr, start_streams);

  } else if(!strcmp(bap_test, "start")) {
    LOG(INFO) << __func__ << " going for start test case";

    LOG(INFO) << __func__ << " going for stop while starting test case";


    for ( uint8_t i = 0; i < 5; i++) {
      LOG(INFO) << __func__ << " iteration " << loghex(i);
      LOG(INFO) << __func__ << " going for connect";
      sUcastClientInterface->Connect( bap_bd_addr, true, streams);

      sleep(5);
      LOG(INFO) << __func__ << " going for stream start";
      sUcastClientInterface->Start( bap_bd_addr, start_streams);
      usleep( i* 200 * 1000);
      LOG(INFO) << __func__ << " going for stream stop";
      sUcastClientInterface->Stop( bap_bd_addr, start_streams);
      sleep(5);

      LOG(INFO) << __func__ << " going for stream disconnect";
      sUcastClientInterface->Disconnect( bap_bd_addr, start_streams);
    }

    LOG(INFO) << __func__ << " going for disconnect while starting test case";

    for ( uint8_t i = 0; i < 5; i++) {
      LOG(INFO) << __func__ << " iteration " << loghex(i);
      LOG(INFO) << __func__ << " going for connect";
      sUcastClientInterface->Connect( bap_bd_addr, true, streams);

      sleep(5);

      LOG(INFO) << __func__ << " going for stream start";
      sUcastClientInterface->Start( bap_bd_addr, start_streams);
      usleep( i* 200 * 1000);
      LOG(INFO) << __func__ << " going for stream disconnect";
      sUcastClientInterface->Disconnect( bap_bd_addr, start_streams);
      sleep(5);
    }

  } else if(!strcmp(bap_test, "stop")) {
    LOG(INFO) << __func__ << " going for stop test case";
    LOG(INFO) << __func__ << " going for connect";

    for ( uint8_t i = 0; i < 5; i++) {
      LOG(INFO) << __func__ << " iteration " << loghex(i);
      LOG(INFO) << __func__ << " going for disconnect while stopping";
      sUcastClientInterface->Connect( bap_bd_addr, true, streams);

      sleep(5);

      LOG(INFO) << __func__ << " going for stream start";
      sUcastClientInterface->Start( bap_bd_addr, start_streams);

      sleep(5);

      LOG(INFO) << __func__ << " going for stream stop";
      sUcastClientInterface->Stop( bap_bd_addr, start_streams);
      usleep( i* 200 * 1000);

      LOG(INFO) << __func__ << " going for stream disconnect";
      sUcastClientInterface->Disconnect( bap_bd_addr, start_streams);
    }

  } else if(!strcmp(bap_test, "stop")) {
    LOG(INFO) << __func__ << " going for stop test case";
    LOG(INFO) << __func__ << " going for connect";

    for ( uint8_t i = 0; i < 5; i++) {
      LOG(INFO) << __func__ << " iteration " << loghex(i);
      LOG(INFO) << __func__ << " going for disconnect while stopping";
      sUcastClientInterface->Connect( bap_bd_addr, true, streams);

      sleep(5);

      LOG(INFO) << __func__ << " going for stream start";
      sUcastClientInterface->Start( bap_bd_addr, start_streams);

      sleep(5);

      LOG(INFO) << __func__ << " going for stream stop";
      sUcastClientInterface->Stop( bap_bd_addr, start_streams);
      usleep( i* 200 * 1000);

      LOG(INFO) << __func__ << " going for stream disconnect";
      sUcastClientInterface->Disconnect( bap_bd_addr, start_streams);
    }
  } else if(!strcmp(bap_test, "reconfigure")) {
    LOG(INFO) << __func__ << " going for reconfigure test case";
    LOG(INFO) << __func__ << " going for connect";

    sUcastClientInterface->Connect( bap_bd_addr, true, streams);

    sleep(5);

    LOG(INFO) << __func__ << " going for stream codec reconfig";
    sUcastClientInterface->Reconfigure( bap_bd_addr, reconf_streams);

    sleep(5);

    LOG(INFO) << __func__ << " going for stream qos reconfig";
    sUcastClientInterface->Reconfigure( bap_bd_addr, reconf_qos_streams);

    sleep(5);

    LOG(INFO) << __func__ << " going for stream disconnect";
    sUcastClientInterface->Disconnect( bap_bd_addr, start_streams);

  }

  LOG(INFO) << __func__ << " Test completed";
#if 0
  sleep(2);
  LOG(INFO) << __func__ << "going for connect";
  sUcastClientInterface->Connect( bap_bd_addr);
  sleep(7);
  LOG(INFO) << __func__ << "going for discovery";
  sUcastClientInterface->StartDiscovery( bap_bd_addr);
  sleep(2);
  LOG(INFO) << __func__ << "going for getAudiocontexts";
  sUcastClientInterface->GetAvailableAudioContexts( bap_bd_addr);
  sleep(2);
  LOG(INFO) << __func__ << "going for disconnect";
  sUcastClientInterface->Disconnect( bap_bd_addr);
  sleep(1);
  sUcastClientInterface->Cleanup();
  sleep(1);
  sUcastClientInterface->Init(&sUcastClientCallbacks);
  sleep(1);
  LOG(INFO) << __func__ << "going for connect 2 ";
  sUcastClientInterface->Connect( bap_bd_addr);
  sleep(7);
  LOG(INFO) << __func__ << "going for discovery 2";
  sUcastClientInterface->StartDiscovery( bap_bd_addr);
  sleep(2);
  LOG(INFO) << __func__ << "going for getAudiocontexts 2";
  sUcastClientInterface->GetAvailableAudioContexts( bap_bd_addr);
  sleep(2);
    LOG(INFO) << __func__ << "going for disconnect 2";
  sUcastClientInterface->Disconnect( bap_bd_addr);
  sleep(1);
  sUcastClientInterface->Cleanup();
#endif
}

bool test_bap_uclient () {
  RawAddress::FromString("00:02:5b:00:ff:00", bap_bd_addr);
  test_thread = thread_new("test_bap_uclient");
  LOG(INFO) << __func__ << "going for test setup";
  thread_post(test_thread, event_test_bap_uclient, NULL);
  return true;
}

// PACS related test code
using bluetooth::bap::pacs::PacsClientInterface;
using bluetooth::bap::pacs::PacsClientCallbacks;

static PacsClientInterface* sPacsClientInterface = nullptr;
static uint16_t pacs_client_id = 0;
static RawAddress pac_bd_addr;

class PacsClientCallbacksImpl : public PacsClientCallbacks {
 public:
  ~PacsClientCallbacksImpl() = default;
  void OnInitialized(int status,
                     int client_id) override {
    LOG(WARNING) << __func__ << client_id;
    pacs_client_id = client_id;
  }
  void OnConnectionState(const RawAddress& bd_addr,
                         ConnectionState state) override {
    LOG(WARNING) << __func__;
    if(state == ConnectionState::CONNECTED)  {
      LOG(WARNING) << __func__ << "connected";
    } else if(state == ConnectionState::DISCONNECTED)  {
      LOG(WARNING) << __func__ << "Disconnected";
    }

  }
  void OnAudioContextAvailable(const RawAddress& bd_addr,
                        uint32_t available_contexts) override {
    LOG(INFO) << __func__;
  }
   void OnSearchComplete(int status, const RawAddress& address,
            std::vector<bluetooth::bap::pacs::CodecConfig> sink_pac_records,
            std::vector<bluetooth::bap::pacs::CodecConfig> src_pac_records,
            uint32_t sink_locations,
            uint32_t src_locations,
            uint32_t available_contexts,
            uint32_t supported_contexts) override {
    LOG(WARNING) << __func__;
  }
};

static PacsClientCallbacksImpl sPacsClientCallbacks;

static void event_test_pacs(UNUSED_ATTR void* context) {
  sPacsClientInterface = btif_pacs_client_get_interface();
  sPacsClientInterface->Init(&sPacsClientCallbacks);
  sleep(1);
  LOG(INFO) << __func__ << "going for connect";
  sPacsClientInterface->Connect(pacs_client_id, pac_bd_addr);
  sleep(7);
  LOG(INFO) << __func__ << "going for discovery";
  sPacsClientInterface->StartDiscovery(pacs_client_id, pac_bd_addr);
  sleep(2);
  LOG(INFO) << __func__ << "going for getAudiocontexts";
  sPacsClientInterface->GetAvailableAudioContexts(pacs_client_id, pac_bd_addr);
  sleep(2);
    LOG(INFO) << __func__ << "going for disconnect";
  sPacsClientInterface->Disconnect(pacs_client_id, pac_bd_addr);

  sleep(2);
  LOG(INFO) << __func__ << "going for connect";
  sPacsClientInterface->Connect(pacs_client_id, pac_bd_addr);
  sleep(7);
  LOG(INFO) << __func__ << "going for discovery";
  sPacsClientInterface->StartDiscovery(pacs_client_id, pac_bd_addr);
  sleep(2);
  LOG(INFO) << __func__ << "going for getAudiocontexts";
  sPacsClientInterface->GetAvailableAudioContexts(pacs_client_id, pac_bd_addr);
  sleep(2);
  LOG(INFO) << __func__ << "going for disconnect";
  sPacsClientInterface->Disconnect(pacs_client_id, pac_bd_addr);

  sleep(1);
  sPacsClientInterface->Cleanup(pacs_client_id);

  sleep(1);

  sPacsClientInterface->Init(&sPacsClientCallbacks);
  sleep(1);
  LOG(INFO) << __func__ << "going for connect 2 ";
  sPacsClientInterface->Connect(pacs_client_id, pac_bd_addr);
  sleep(7);
  LOG(INFO) << __func__ << "going for discovery 2";
  sPacsClientInterface->StartDiscovery(pacs_client_id, pac_bd_addr);
  sleep(2);
  LOG(INFO) << __func__ << "going for getAudiocontexts 2";
  sPacsClientInterface->GetAvailableAudioContexts(pacs_client_id, pac_bd_addr);
  sleep(2);
    LOG(INFO) << __func__ << "going for disconnect 2";
  sPacsClientInterface->Disconnect(pacs_client_id, pac_bd_addr);

  sleep(1);
  sPacsClientInterface->Cleanup(pacs_client_id);

}

bool test_pacs (RawAddress& bd_addr) {

  test_thread = thread_new("test_pacs");
  pac_bd_addr = bd_addr;
  thread_post(test_thread, event_test_pacs, NULL);
  return true;
}
