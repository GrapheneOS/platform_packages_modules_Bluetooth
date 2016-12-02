/******************************************************************************
 *
 *  Copyright (C) 2000-2012 Broadcom Corporation
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

/******************************************************************************
 *
 *  Interface to A2DP Application Programming Interface
 *
 ******************************************************************************/
#ifndef A2DP_API_H
#define A2DP_API_H

#include <stddef.h>

#include "avdt_api.h"
#include "osi/include/time.h"
#include "sdp_api.h"

#ifdef __cplusplus
extern "C" {
#endif

/*****************************************************************************
 *  constants
 ****************************************************************************/

//
// |MAX_PCM_FRAME_NUM_PER_TICK| controls how many buffers we can hold in
// the A2DP buffer queues during temporary link congestion.
//
#ifndef MAX_PCM_FRAME_NUM_PER_TICK
#define MAX_PCM_FRAME_NUM_PER_TICK 14
#endif

/* Profile supported features */
#define A2DP_SUPF_PLAYER 0x0001
#define A2DP_SUPF_MIC 0x0002
#define A2DP_SUPF_TUNER 0x0004
#define A2DP_SUPF_MIXER 0x0008

#define A2DP_SUPF_HEADPHONE 0x0001
#define A2DP_SUPF_SPEAKER 0x0002
#define A2DP_SUPF_RECORDER 0x0004
#define A2DP_SUPF_AMP 0x0008

/* AV Media Codec Type (Audio Codec ID) */
#define A2DP_MEDIA_CT_SBC 0x00 /* SBC media codec type */
#define A2DP_MEDIA_CT_NON_A2DP \
  0xFF /* Non-A2DP media codec type (vendor-specific codec) */

typedef uint8_t tA2DP_CODEC_TYPE; /* A2DP Codec type: A2DP_MEDIA_CT_* */

#define A2DP_SUCCESS 0           /* Success */
#define A2DP_FAIL 0x0A           /* Failed */
#define A2DP_BUSY 0x0B           /* A2DP_FindService is already in progress */
#define A2DP_INVALID_PARAMS 0x0C /* bad parameters */
#define A2DP_WRONG_CODEC 0x0D    /* wrong codec info */
#define A2DP_BAD_CODEC_TYPE 0xC1 /* Media Codec Type is not valid  */
#define A2DP_NS_CODEC_TYPE 0xC2  /* Media Codec Type is not supported */
#define A2DP_BAD_SAMP_FREQ                                             \
  0xC3 /* Sampling Frequency is not valid or multiple values have been \
          selected  */
#define A2DP_NS_SAMP_FREQ 0xC4 /* Sampling Frequency is not supported  */
#define A2DP_BAD_CH_MODE \
  0xC5 /* Channel Mode is not valid or multiple values have been selected  */
#define A2DP_NS_CH_MODE 0xC6 /* Channel Mode is not supported */
#define A2DP_BAD_SUBBANDS \
  0xC7 /* None or multiple values have been selected for Number of Subbands */
#define A2DP_NS_SUBBANDS 0xC8 /* Number of Subbands is not supported */
#define A2DP_BAD_ALLOC_METHOD \
  0xC9 /* None or multiple values have been selected for Allocation Method */
#define A2DP_NS_ALLOC_METHOD 0xCA /* Allocation Method is not supported */
#define A2DP_BAD_MIN_BITPOOL 0xCB /* Minimum Bitpool Value is not valid */
#define A2DP_NS_MIN_BITPOOL 0xCC  /* Minimum Bitpool Value is not supported */
#define A2DP_BAD_MAX_BITPOOL 0xCD /* Maximum Bitpool Value is not valid */
#define A2DP_NS_MAX_BITPOOL 0xCE  /* Maximum Bitpool Value is not supported */
#define A2DP_BAD_LAYER \
  0xCF /* None or multiple values have been selected for Layer */
#define A2DP_NS_LAYER 0xD0 /* Layer is not supported */
#define A2DP_NS_CRC 0xD1   /* CRC is not supported */
#define A2DP_NS_MPF 0xD2   /* MPF-2 is not supported */
#define A2DP_NS_VBR 0xD3   /* VBR is not supported */
#define A2DP_BAD_BIT_RATE \
  0xD4 /* None or multiple values have been selected for Bit Rate */
#define A2DP_NS_BIT_RATE 0xD5 /* Bit Rate is not supported */
#define A2DP_BAD_OBJ_TYPE                                                   \
  0xD6 /* Either 1) Object type is not valid (b3-b0) or 2) None or multiple \
          values have been selected for Object Type */
#define A2DP_NS_OBJ_TYPE 0xD7 /* Object type is not supported */
#define A2DP_BAD_CHANNEL \
  0xD8 /* None or multiple values have been selected for Channels */
#define A2DP_NS_CHANNEL 0xD9 /* Channels is not supported */
#define A2DP_BAD_BLOCK_LEN \
  0xDD /* None or multiple values have been selected for Block Length */
#define A2DP_BAD_CP_TYPE 0xE0 /* The requested CP Type is not supported. */
#define A2DP_BAD_CP_FORMAT                                            \
  0xE1 /* The format of Content Protection Service Capability/Content \
          Protection Scheme Dependent Data is not correct. */

typedef uint8_t tA2DP_STATUS;

/* the return values from A2DP_BitsSet() */
#define A2DP_SET_ONE_BIT 1   /* one and only one bit is set */
#define A2DP_SET_ZERO_BIT 0  /* all bits clear */
#define A2DP_SET_MULTL_BIT 2 /* multiple bits are set */

/*****************************************************************************
 *  type definitions
 ****************************************************************************/

/* This data type is used in A2DP_FindService() to initialize the SDP database
 * to hold the result service search. */
typedef struct {
  uint32_t db_len;   /* Length, in bytes, of the discovery database */
  uint16_t num_attr; /* The number of attributes in p_attrs */
  uint16_t* p_attrs; /* The attributes filter. If NULL, A2DP API sets the
                      * attribute filter
                      * to be ATTR_ID_SERVICE_CLASS_ID_LIST,
                      * ATTR_ID_BT_PROFILE_DESC_LIST,
                      * ATTR_ID_SUPPORTED_FEATURES, ATTR_ID_SERVICE_NAME and
                      * ATTR_ID_PROVIDER_NAME.
                      * If not NULL, the input is taken as the filter. */
} tA2DP_SDP_DB_PARAMS;

/* This data type is used in tA2DP_FIND_CBACK to report the result of the SDP
 * discovery process. */
typedef struct {
  uint16_t service_len;  /* Length, in bytes, of the service name */
  uint16_t provider_len; /* Length, in bytes, of the provider name */
  char* p_service_name;  /* Pointer the service name.  This character string may
                          * not be null terminated.
                          * Use the service_len parameter to safely copy this
                          * string */
  char* p_provider_name; /* Pointer the provider name.  This character string
                          * may not be null terminated.
                          * Use the provider_len parameter to safely copy this
                          * string */
  uint16_t features;     /* Profile supported features */
  uint16_t avdt_version; /* AVDTP protocol version */
} tA2DP_Service;

/* This is the callback to notify the result of the SDP discovery process. */
typedef void(tA2DP_FIND_CBACK)(bool found, tA2DP_Service* p_service);

/*
 * Enum values for each supported codec per SEP.
 * There should be a separate entry for each codec that is supported
 * for encoding (SRC), and for decoding purpose (SINK).
 */
typedef enum {
  A2DP_CODEC_SEP_INDEX_SOURCE_MIN = 0,
  A2DP_CODEC_SEP_INDEX_SOURCE_SBC = 0,
  /* Add an entry for each new source codec here */
  A2DP_CODEC_SEP_INDEX_SOURCE_MAX,

  A2DP_CODEC_SEP_INDEX_SINK_MIN = A2DP_CODEC_SEP_INDEX_SOURCE_MAX,
  A2DP_CODEC_SEP_INDEX_SINK_SBC = A2DP_CODEC_SEP_INDEX_SINK_MIN,
  /* Add an entry for each new sink codec here */
  A2DP_CODEC_SEP_INDEX_SINK_MAX,

  A2DP_CODEC_SEP_INDEX_MIN = A2DP_CODEC_SEP_INDEX_SOURCE_MIN,
  A2DP_CODEC_SEP_INDEX_MAX = A2DP_CODEC_SEP_INDEX_SINK_MAX
} tA2DP_CODEC_SEP_INDEX;

/**
 * Structure used to configure the A2DP feeding.
 */
typedef struct {
  uint32_t sample_rate;     // 44100, 48000, etc
  uint8_t channel_count;    // 1 for mono or 2 for stereo
  uint8_t bits_per_sample;  // 8, 16, 24, 32
} tA2DP_FEEDING_PARAMS;

/**
 * Structure used to initialize the A2DP encoder.
 */
typedef struct {
  uint8_t codec_config[AVDT_CODEC_SIZE];  // Current codec config
  uint16_t peer_mtu;                      // MTU of the A2DP peer
} tA2DP_ENCODER_INIT_PARAMS;

// Prototype for a callback to read audio data for encoding.
// |p_buf| is the buffer to store the data. |len| is the number of octets to
// read.
// Returns the number of octets read.
typedef uint32_t (*a2dp_source_read_callback_t)(uint8_t* p_buf, uint32_t len);

// Prototype for a callback to enqueue A2DP Source packets for transmission.
// |p_buf| is the buffer with the audio data to enqueue. The callback is
// responsible for freeing |p_buf|.
// |frames_n| is the number of audio frames in |p_buf| - it is used for
// statistics purpose.
// Returns true if the packet was enqueued, otherwise false.
typedef bool (*a2dp_source_enqueue_callback_t)(BT_HDR* p_buf, size_t frames_n);

//
// A2DP encoder callbacks interface.
//
typedef struct {
  // Initialize the A2DP encoder.
  // If |is_peer_edr| is true, the A2DP peer device supports EDR.
  // If |peer_supports_3mbps| is true, the A2DP peer device supports 3Mbps
  // EDR.
  // The encoder initialization parameters are in |p_init_params|.
  // |enqueue_callback} is the callback for enqueueing the encoded audio
  // data.
  void (*encoder_init)(bool is_peer_edr, bool peer_supports_3mbps,
                       const tA2DP_ENCODER_INIT_PARAMS* p_init_params,
                       a2dp_source_read_callback_t read_callback,
                       a2dp_source_enqueue_callback_t enqueue_callback);

  // Cleanup the A2DP encoder.
  void (*encoder_cleanup)(void);

  // Initialize the feeding for the A2DP encoder.
  // The feeding initialization parameters are in |p_feeding_params|.
  void (*feeding_init)(const tA2DP_FEEDING_PARAMS* p_feeding_params);

  // Reset the feeding for the A2DP encoder.
  void (*feeding_reset)(void);

  // Flush the feeding for the A2DP encoder.
  void (*feeding_flush)(void);

  // Get the A2DP encoder interval (in milliseconds).
  period_ms_t (*get_encoder_interval_ms)(void);

  // Prepare and send A2DP encoded frames.
  // |timestamp_us| is the current timestamp (in microseconds).
  void (*send_frames)(uint64_t timestamp_us);

  // Dump codec-related statistics.
  // |fd| is the file descriptor to use to dump the statistics information
  // in user-friendly test format.
  void (*debug_codec_dump)(int fd);
} tA2DP_ENCODER_INTERFACE;

/*****************************************************************************
 *  external function declarations
 ****************************************************************************/
/******************************************************************************
 *
 * Function         A2DP_AddRecord
 *
 * Description      This function is called by a server application to add
 *                  SRC or SNK information to an SDP record.  Prior to
 *                  calling this function the application must call
 *                  SDP_CreateRecord() to create an SDP record.
 *
 *                  Input Parameters:
 *                      service_uuid:  Indicates SRC or SNK.
 *
 *                      p_service_name:  Pointer to a null-terminated character
 *                      string containing the service name.
 *
 *                      p_provider_name:  Pointer to a null-terminated character
 *                      string containing the provider name.
 *
 *                      features:  Profile supported features.
 *
 *                      sdp_handle:  SDP handle returned by SDP_CreateRecord().
 *
 *                  Output Parameters:
 *                      None.
 *
 * Returns          A2DP_SUCCESS if function execution succeeded,
 *                  A2DP_INVALID_PARAMS if bad parameters are given.
 *                  A2DP_FAIL if function execution failed.
 *
 *****************************************************************************/
extern tA2DP_STATUS A2DP_AddRecord(uint16_t service_uuid, char* p_service_name,
                                   char* p_provider_name, uint16_t features,
                                   uint32_t sdp_handle);

/******************************************************************************
 *
 * Function         A2DP_FindService
 *
 * Description      This function is called by a client application to
 *                  perform service discovery and retrieve SRC or SNK SDP
 *                  record information from a server.  Information is
 *                  returned for the first service record found on the
 *                  server that matches the service UUID.  The callback
 *                  function will be executed when service discovery is
 *                  complete.  There can only be one outstanding call to
 *                  A2DP_FindService() at a time; the application must wait
 *                  for the callback before it makes another call to
 *                  the function.
 *
 *                  Input Parameters:
 *                      service_uuid:  Indicates SRC or SNK.
 *
 *                      bd_addr:  BD address of the peer device.
 *
 *                      p_db:  Pointer to the information to initialize
 *                             the discovery database.
 *
 *                      p_cback:  Pointer to the A2DP_FindService()
 *                      callback function.
 *
 *                  Output Parameters:
 *                      None.
 *
 * Returns          A2DP_SUCCESS if function execution succeeded,
 *                  A2DP_INVALID_PARAMS if bad parameters are given.
 *                  A2DP_BUSY if discovery is already in progress.
 *                  A2DP_FAIL if function execution failed.
 *
 *****************************************************************************/
extern tA2DP_STATUS A2DP_FindService(uint16_t service_uuid, BD_ADDR bd_addr,
                                     tA2DP_SDP_DB_PARAMS* p_db,
                                     tA2DP_FIND_CBACK* p_cback);

/******************************************************************************
 *
 * Function         A2DP_SetTraceLevel
 *
 * Description      Sets the trace level for A2D. If 0xff is passed, the
 *                  current trace level is returned.
 *
 *                  Input Parameters:
 *                      new_level:  The level to set the A2DP tracing to:
 *                      0xff-returns the current setting.
 *                      0-turns off tracing.
 *                      >= 1-Errors.
 *                      >= 2-Warnings.
 *                      >= 3-APIs.
 *                      >= 4-Events.
 *                      >= 5-Debug.
 *
 * Returns          The new trace level or current trace level if
 *                  the input parameter is 0xff.
 *
 *****************************************************************************/
extern uint8_t A2DP_SetTraceLevel(uint8_t new_level);

/******************************************************************************
 * Function         A2DP_BitsSet
 *
 * Description      Check the given num for the number of bits set
 * Returns          A2DP_SET_ONE_BIT, if one and only one bit is set
 *                  A2DP_SET_ZERO_BIT, if all bits clear
 *                  A2DP_SET_MULTL_BIT, if multiple bits are set
 *****************************************************************************/
extern uint8_t A2DP_BitsSet(uint8_t num);

// Initializes the A2DP control block.
void A2DP_Init(void);

// Gets the A2DP codec type.
// |p_codec_info| contains information about the codec capabilities.
tA2DP_CODEC_TYPE A2DP_GetCodecType(const uint8_t* p_codec_info);

// Checks whether the codec capabilities contain a valid A2DP Source codec.
// NOTE: only codecs that are implemented are considered valid.
// Returns true if |p_codec_info| contains information about a valid codec,
// otherwise false.
bool A2DP_IsSourceCodecValid(const uint8_t* p_codec_info);

// Checks whether the codec capabilities contain a valid A2DP Sink codec.
// NOTE: only codecs that are implemented are considered valid.
// Returns true if |p_codec_info| contains information about a valid codec,
// otherwise false.
bool A2DP_IsSinkCodecValid(const uint8_t* p_codec_info);

// Checks whether the codec capabilities contain a valid peer A2DP Source
// codec.
// NOTE: only codecs that are implemented are considered valid.
// Returns true if |p_codec_info| contains information about a valid codec,
// otherwise false.
bool A2DP_IsPeerSourceCodecValid(const uint8_t* p_codec_info);

// Checks whether the codec capabilities contain a valid peer A2DP Sink codec.
// NOTE: only codecs that are implemented are considered valid.
// Returns true if |p_codec_info| contains information about a valid codec,
// otherwise false.
bool A2DP_IsPeerSinkCodecValid(const uint8_t* p_codec_info);

// Checks whether an A2DP Sink codec is supported.
// |p_codec_info| contains information about the codec capabilities.
// Returns true if the A2DP Sink codec is supported, otherwise false.
bool A2DP_IsSinkCodecSupported(const uint8_t* p_codec_info);

// Checks whether an A2DP Source codec for a peer Source device is supported.
// |p_codec_info| contains information about the codec capabilities of the
// peer device.
// Returns true if the A2DP Source codec for a peer Source device is supported,
// otherwise false.
bool A2DP_IsPeerSourceCodecSupported(const uint8_t* p_codec_info);

// Initialize state with the default A2DP codec.
// The initialized state with the codec capabilities is stored in
// |p_codec_info|.
void A2DP_InitDefaultCodec(uint8_t* p_codec_info);

// Initializes A2DP Source-to-Sink codec config from Sink codec capability.
// |p_sink_caps| is the A2DP Sink codec capabilities to use.
// The selected codec configuration is stored in |p_result_codec_config|.
// Returns |A2DP_SUCCESS| on success, otherwise the corresponding A2DP error
// status code.
tA2DP_STATUS A2DP_InitSource2SinkCodec(const uint8_t* p_sink_caps,
                                       uint8_t* p_result_codec_config);

// Builds A2DP preferred Sink capability from Source capability.
// |p_src_cap| is the Source capability to use.
// |p_pref_cfg| is the result Sink capability to store.
// Returns |A2DP_SUCCESS| on success, otherwise the corresponding A2DP error
// status code.
tA2DP_STATUS A2DP_BuildSrc2SinkConfig(const uint8_t* p_src_cap,
                                      uint8_t* p_pref_cfg);

// Checks whether the A2DP data packets should contain RTP header.
// |content_protection_enabled| is true if Content Protection is
// enabled. |p_codec_info| contains information about the codec capabilities.
// Returns true if the A2DP data packets should contain RTP header, otherwise
// false.
bool A2DP_UsesRtpHeader(bool content_protection_enabled,
                        const uint8_t* p_codec_info);

// Gets the A2DP Source codec SEP index for a given |p_codec_info|.
// Returns the corresponding |tA2DP_CODEC_SEP_INDEX| on success,
// otherwise |A2DP_CODEC_SEP_INDEX_MAX|.
tA2DP_CODEC_SEP_INDEX A2DP_SourceCodecSepIndex(const uint8_t* p_codec_info);

// Gets the A2DP codec name for a given |codec_sep_index|.
const char* A2DP_CodecSepIndexStr(tA2DP_CODEC_SEP_INDEX codec_sep_index);

// Initializes A2DP codec-specific information into |tAVDT_CFG| configuration
// entry pointed by |p_cfg|. The selected codec is defined by
// |codec_sep_index|.
// Returns true on success, otherwise false.
bool A2DP_InitCodecConfig(tA2DP_CODEC_SEP_INDEX codec_sep_index,
                          tAVDT_CFG* p_cfg);

// Gets the |AVDT_MEDIA_TYPE_*| media type from the codec capability
// in |p_codec_info|.
uint8_t A2DP_GetMediaType(const uint8_t* p_codec_info);

// Gets the A2DP codec name for a given |p_codec_info|.
const char* A2DP_CodecName(const uint8_t* p_codec_info);

// Checks whether two A2DP codecs |p_codec_info_a| and |p_codec_info_b| have
// the same type.
// Returns true if the two codecs have the same type, otherwise false.
// If the codec type is not recognized, the return value is false.
bool A2DP_CodecTypeEquals(const uint8_t* p_codec_info_a,
                          const uint8_t* p_codec_info_b);

// Checks whether two A2DP codecs p_codec_info_a| and |p_codec_info_b| are
// exactly the same.
// Returns true if the two codecs are exactly the same, otherwise false.
// If the codec type is not recognized, the return value is false.
bool A2DP_CodecEquals(const uint8_t* p_codec_info_a,
                      const uint8_t* p_codec_info_b);

// Gets the track sample rate value for the A2DP codec.
// |p_codec_info| is a pointer to the codec_info to decode.
// Returns the track sample rate on success, or -1 if |p_codec_info|
// contains invalid codec information.
int A2DP_GetTrackSampleRate(const uint8_t* p_codec_info);

// Gets the channel count for the A2DP codec.
// |p_codec_info| is a pointer to the codec_info to decode.
// Returns the channel count on success, or -1 if |p_codec_info|
// contains invalid codec information.
int A2DP_GetTrackChannelCount(const uint8_t* p_codec_info);

// Gets the bits per audio sample for the A2DP codec.
// |p_codec_info| is a pointer to the codec_info to decode.
// Returns the bits per audio sample on success, or -1 if |p_codec_info|
// contains invalid codec information.
int A2DP_GetTrackBitsPerSample(const uint8_t* p_codec_info);

// Gets the channel type for the A2DP Sink codec:
// 1 for mono, or 3 for dual/stereo/joint.
// |p_codec_info| is a pointer to the codec_info to decode.
// Returns the channel type on success, or -1 if |p_codec_info|
// contains invalid codec information.
int A2DP_GetSinkTrackChannelType(const uint8_t* p_codec_info);

// Computes the number of frames to process in a time window for the A2DP
// Sink codec. |time_interval_ms| is the time interval (in milliseconds).
// |p_codec_info| is a pointer to the codec_info to decode.
// Returns the number of frames to process on success, or -1 if |p_codec_info|
// contains invalid codec information.
int A2DP_GetSinkFramesCountToProcess(uint64_t time_interval_ms,
                                     const uint8_t* p_codec_info);

// Gets the A2DP audio data timestamp from an audio packet.
// |p_codec_info| contains the codec information.
// |p_data| contains the audio data.
// The timestamp is stored in |p_timestamp|.
// Returns true on success, otherwise false.
bool A2DP_GetPacketTimestamp(const uint8_t* p_codec_info, const uint8_t* p_data,
                             uint32_t* p_timestamp);

// Builds A2DP codec header for audio data.
// |p_codec_info| contains the codec information.
// |p_buf| contains the audio data.
// |frames_per_packet| is the number of frames in this packet.
// Returns true on success, otherwise false.
bool A2DP_BuildCodecHeader(const uint8_t* p_codec_info, BT_HDR* p_buf,
                           uint16_t frames_per_packet);

// Gets the A2DP encoder interface that can be used to encode and prepare
// A2DP packets for transmission - see |tA2DP_ENCODER_INTERFACE|.
// |p_codec_info| contains the codec information.
// Returns the A2DP encoder interface if the |p_codec_info| is valid and
// supported, otherwise NULL.
const tA2DP_ENCODER_INTERFACE* A2DP_GetEncoderInterface(
    const uint8_t* p_codec_info);

// Adjusts the A2DP codec, based on local support and Bluetooth specification.
// |p_codec_info| contains the codec information to adjust.
// Returns true if |p_codec_info| is valid and supported, otherwise false.
bool A2DP_AdjustCodec(uint8_t* p_codec_info);

#ifdef __cplusplus
}
#endif

#endif /* A2DP_API_H */
