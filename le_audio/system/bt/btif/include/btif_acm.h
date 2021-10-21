/******************************************************************************
 *  Copyright (c) 2020, The Linux Foundation. All rights reserved.
 *
 *****************************************************************************/

#ifndef BTIF_ACM_H
#define BTIF_ACM_H

#include <vector>

//#include "bta_acm_api.h"
#include "btif_common.h"
#include "bta_bap_uclient_api.h"
#include "bta_pacs_client_api.h"
#include "bta_ascs_client_api.h"

typedef uint8_t tBTA_ACM_HNDL;
typedef uint8_t tBTIF_ACM_STATUS;

#define BTA_ACM_MAX_EVT 26
#define BTA_ACM_NUM_STRS 6
#define BTA_ACM_NUM_CIGS 239
//starting setid from 16 onwards as 16 is inavlid
#define BTA_ACM_MIN_NUM_SETID 17
#define BTA_ACM_MAX_NUM_SETID 255
#define CONTEXT_TYPE_UNKNOWN 0
#define CONTEXT_TYPE_MUSIC 1
#define CONTEXT_TYPE_VOICE 2
#define CONTEXT_TYPE_MUSIC_VOICE 3

#define BTA_ACM_DISCONNECT_EVT 0
#define BTA_ACM_CONNECT_EVT 1
#define BTA_ACM_START_EVT 2
#define BTA_ACM_STOP_EVT 3
#define BTA_ACM_RECONFIG_EVT 4
#define BTA_ACM_CONFIG_EVT 5
#define BTA_ACM_CONN_UPDATE_TIMEOUT_EVT 6

#define BTA_ACM_INITIATOR_SERVICE_ID 0xFF
#define ACM_UUID 0xFFFF
#define ACM_TSEP_SNK 1

#define SRC 0
#define SNK 1

constexpr uint8_t  STREAM_STATE_DISCONNECTED     = 0x00;
constexpr uint8_t  STREAM_STATE_CONNECTING       = 0x01;
constexpr uint8_t  STREAM_STATE_CONNECTED        = 0x02;
constexpr uint8_t  STREAM_STATE_STARTING         = 0x03;
constexpr uint8_t  STREAM_STATE_STREAMING        = 0x04;
constexpr uint8_t  STREAM_STATE_STOPPING         = 0x05;
constexpr uint8_t  STREAM_STATE_DISCONNECTING    = 0x06;
constexpr uint8_t  STREAM_STATE_RECONFIGURING    = 0x07;

using bluetooth::bap::ucast::StreamStateInfo;
using bluetooth::bap::ucast::StreamConfigInfo;

using bluetooth::bap::ucast::StreamConnect;
using bluetooth::bap::ucast::StreamType;
using bluetooth::bap::ucast::StreamReconfig;
using bluetooth::bap::ucast::StreamDiscReason;
using bluetooth::bap::ucast::StreamState;
using bluetooth::bap::ucast::QosConfig;

using bluetooth::bap::pacs::CodecConfig;

typedef struct {
  RawAddress bd_addr;
  int contextType;
  int profileType;
}tBTIF_ACM_CONN_DISC;

typedef struct {
  RawAddress bd_addr;
}tBTA_ACM_CONN_UPDATE_TIMEOUT_INFO;

typedef struct {
  RawAddress bd_addr;
  StreamType stream_type;
  CodecConfig codec_config;
  uint32_t audio_location;
  QosConfig qos_config;
  std::vector<CodecConfig> codecs_selectable;
}tBTA_ACM_CONFIG_INFO;

typedef struct {
  RawAddress bd_addr;
  StreamType stream_type;
  StreamState stream_state;
  StreamDiscReason reason;
}tBTA_ACM_STATE_INFO;

typedef struct {
  RawAddress bd_addr;
  bool is_direct;
  StreamStateInfo streams_info;
}tBTIF_ACM_CONNECT;

typedef struct {
  RawAddress bd_addr;
  StreamStateInfo streams_info;
}tBTIF_ACM_DISCONNECT;

typedef struct {
  RawAddress bd_addr;
  StreamStateInfo streams_info;
}tBTIF_ACM_START;

typedef struct {
  RawAddress bd_addr;
  StreamStateInfo streams_info;
}tBTIF_ACM_STOP;

typedef struct {
  RawAddress bd_addr;
  StreamReconfig streams_info;
}tBTIF_ACM_RECONFIG;

typedef union {
  tBTIF_ACM_CONN_DISC acm_conn_disc;
  tBTA_ACM_STATE_INFO state_info;
  tBTA_ACM_CONFIG_INFO config_info;
  tBTIF_ACM_CONNECT acm_connect;
  tBTIF_ACM_DISCONNECT acm_disconnect;
  tBTIF_ACM_START acm_start;
  tBTIF_ACM_STOP acm_stop;
  tBTIF_ACM_RECONFIG acm_reconfig;
}tBTIF_ACM;

typedef enum {
  /* Reuse BTA_ACM_XXX_EVT - No need to redefine them here */
  BTIF_ACM_CONNECT_REQ_EVT = BTA_ACM_MAX_EVT,
  BTIF_ACM_DISCONNECT_REQ_EVT,
  BTIF_ACM_START_STREAM_REQ_EVT,
  BTIF_ACM_STOP_STREAM_REQ_EVT,
  BTIF_ACM_SUSPEND_STREAM_REQ_EVT,
  BTIF_ACM_RECONFIG_REQ_EVT,
} btif_acm_sm_event_t;

typedef enum {
  BTA_CSIP_NEW_SET_FOUND_EVT = 1,
  BTA_CSIP_SET_MEMBER_FOUND_EVT,
  BTA_CSIP_CONN_STATE_CHG_EVT,
  BTA_CSIP_LOCK_STATUS_CHANGED_EVT,
  BTA_CSIP_LOCK_AVAILABLE_EVT,
  BTA_CSIP_SET_SIZE_CHANGED,
  BTA_CSIP_SET_SIRK_CHANGED,
} btif_csip_sm_event_t;

/**
 * When the local device is ACM source, get the address of the active peer.
 */
RawAddress btif_acm_source_active_peer(void);

/**
 * When the local device is ACM sink, get the address of the active peer.
 */
RawAddress btif_acm_sink_active_peer(void);

/**
 * Start streaming.
 */
void btif_acm_stream_start(void);

/**
 * Stop streaming.
 *
 * @param peer_address the peer address or RawAddress::kEmpty to stop all peers
 */
void btif_acm_stream_stop(void);

/**
 * Suspend streaming.
 */
void btif_acm_stream_suspend(void);

/**
 * Start offload streaming.
 */
void btif_acm_stream_start_offload(void);

bool btif_acm_check_if_requested_devices_stopped(void);

/**
 * Get the Stream Endpoint Type of the Active peer.
 *
 * @return the stream endpoint type: either AVDT_TSEP_SRC or AVDT_TSEP_SNK
 */
uint8_t btif_acm_get_peer_sep(void);

/**

 * Report ACM Source Codec State for a peer.
 *
 * @param peer_address the address of the peer to report
 * @param codec_config the codec config to report
 * @param codecs_local_capabilities the codecs local capabilities to report
 * @param codecs_selectable_capabilities the codecs selectable capabilities
 * to report
 */
void btif_acm_report_source_codec_state(
    const RawAddress& peer_address,
    const CodecConfig& codec_config,
    const std::vector<CodecConfig>& codecs_local_capabilities,
    const std::vector<CodecConfig>&
        codecs_selectable_capabilities, int contextType);

/**
 * Initialize / shut down the ACM Initiator service.
 *
 * @param enable true to enable the ACM Source service, false to disable it
 * @return BT_STATUS_SUCCESS on success, BT_STATUS_FAIL otherwise
 */
bt_status_t btif_acm_initiator_execute_service(bool enable);

/**
 * Dump debug-related information for the BTIF ACM module.
 *
 * @param fd the file descriptor to use for writing the ASCII formatted
 * information
 */
void btif_debug_acm_dump(int fd);

bool btif_acm_is_active();
uint16_t btif_acm_get_sample_rate();
uint8_t btif_acm_get_ch_mode();
uint32_t btif_acm_get_bitrate();
uint32_t btif_acm_get_octets(uint32_t bit_rate);
uint16_t btif_acm_get_framelength();
uint8_t btif_acm_get_ch_count();
uint16_t btif_acm_get_current_active_profile();
bool btif_acm_is_codec_type_lc3q();
uint8_t btif_acm_lc3q_ver();
bool btif_acm_is_call_active(void);

#endif /* BTIF_ACM_H */
