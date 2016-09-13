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
 *  nterface to A2DP Application Programming Interface
 *
 ******************************************************************************/
#ifndef A2D_API_H
#define A2D_API_H

#include "avdt_api.h"
#include "sdp_api.h"

#ifdef __cplusplus
extern "C" {
#endif

/*****************************************************************************
**  constants
*****************************************************************************/

/* Profile supported features */
#define A2D_SUPF_PLAYER     0x0001
#define A2D_SUPF_MIC        0x0002
#define A2D_SUPF_TUNER      0x0004
#define A2D_SUPF_MIXER      0x0008

#define A2D_SUPF_HEADPHONE  0x0001
#define A2D_SUPF_SPEAKER    0x0002
#define A2D_SUPF_RECORDER   0x0004
#define A2D_SUPF_AMP        0x0008

/* AV Media Codec Type (Audio Codec ID) */
#define A2D_MEDIA_CT_SBC        0x00    /* SBC media codec type */
#define A2D_MEDIA_CT_NON_A2DP   0xFF    /* Non-A2DP media codec type (vendor-specific codec) */

typedef uint8_t tA2D_CODEC_TYPE;    /* A2DP Codec type: A2D_MEDIA_CT_* */

#define A2D_SUCCESS           0     /* Success */
#define A2D_FAIL              0x0A  /* Failed */
#define A2D_BUSY              0x0B  /* A2D_FindService is already in progress */
#define A2D_INVALID_PARAMS    0x0C  /* bad parameters */
#define A2D_WRONG_CODEC       0x0D  /* wrong codec info */
#define A2D_BAD_CODEC_TYPE    0xC1  /* Media Codec Type is not valid  */
#define A2D_NS_CODEC_TYPE     0xC2  /* Media Codec Type is not supported */
#define A2D_BAD_SAMP_FREQ     0xC3  /* Sampling Frequency is not valid or multiple values have been selected  */
#define A2D_NS_SAMP_FREQ      0xC4  /* Sampling Frequency is not supported  */
#define A2D_BAD_CH_MODE       0xC5  /* Channel Mode is not valid or multiple values have been selected  */
#define A2D_NS_CH_MODE        0xC6  /* Channel Mode is not supported */
#define A2D_BAD_SUBBANDS      0xC7  /* None or multiple values have been selected for Number of Subbands */
#define A2D_NS_SUBBANDS       0xC8  /* Number of Subbands is not supported */
#define A2D_BAD_ALLOC_METHOD  0xC9  /* None or multiple values have been selected for Allocation Method */
#define A2D_NS_ALLOC_METHOD   0xCA  /* Allocation Method is not supported */
#define A2D_BAD_MIN_BITPOOL   0xCB  /* Minimum Bitpool Value is not valid */
#define A2D_NS_MIN_BITPOOL    0xCC  /* Minimum Bitpool Value is not supported */
#define A2D_BAD_MAX_BITPOOL   0xCD  /* Maximum Bitpool Value is not valid */
#define A2D_NS_MAX_BITPOOL    0xCE  /* Maximum Bitpool Value is not supported */
#define A2D_BAD_LAYER         0xCF  /* None or multiple values have been selected for Layer */
#define A2D_NS_LAYER          0xD0  /* Layer is not supported */
#define A2D_NS_CRC            0xD1  /* CRC is not supported */
#define A2D_NS_MPF            0xD2  /* MPF-2 is not supported */
#define A2D_NS_VBR            0xD3  /* VBR is not supported */
#define A2D_BAD_BIT_RATE      0xD4  /* None or multiple values have been selected for Bit Rate */
#define A2D_NS_BIT_RATE       0xD5  /* Bit Rate is not supported */
#define A2D_BAD_OBJ_TYPE      0xD6  /* Either 1) Object type is not valid (b3-b0) or 2) None or multiple values have been selected for Object Type */
#define A2D_NS_OBJ_TYPE       0xD7  /* Object type is not supported */
#define A2D_BAD_CHANNEL       0xD8  /* None or multiple values have been selected for Channels */
#define A2D_NS_CHANNEL        0xD9  /* Channels is not supported */
#define A2D_BAD_BLOCK_LEN     0xDD  /* None or multiple values have been selected for Block Length */
#define A2D_BAD_CP_TYPE       0xE0  /* The requested CP Type is not supported. */
#define A2D_BAD_CP_FORMAT     0xE1  /* The format of Content Protection Service Capability/Content Protection Scheme Dependent Data is not correct. */

typedef uint8_t tA2D_STATUS;

/* the return values from A2D_BitsSet() */
#define A2D_SET_ONE_BIT         1   /* one and only one bit is set */
#define A2D_SET_ZERO_BIT        0   /* all bits clear */
#define A2D_SET_MULTL_BIT       2   /* multiple bits are set */

/*****************************************************************************
**  type definitions
*****************************************************************************/

/* This data type is used in A2D_FindService() to initialize the SDP database
 * to hold the result service search. */
typedef struct
{
    uint32_t            db_len;  /* Length, in bytes, of the discovery database */
    uint16_t            num_attr;/* The number of attributes in p_attrs */
    uint16_t           *p_attrs; /* The attributes filter. If NULL, A2DP API sets the attribute filter
                                  * to be ATTR_ID_SERVICE_CLASS_ID_LIST, ATTR_ID_BT_PROFILE_DESC_LIST,
                                  * ATTR_ID_SUPPORTED_FEATURES, ATTR_ID_SERVICE_NAME and ATTR_ID_PROVIDER_NAME.
                                  * If not NULL, the input is taken as the filter. */
} tA2D_SDP_DB_PARAMS;

/* This data type is used in tA2D_FIND_CBACK to report the result of the SDP discovery process. */
typedef struct
{
    uint16_t service_len;    /* Length, in bytes, of the service name */
    uint16_t provider_len;   /* Length, in bytes, of the provider name */
    char *   p_service_name; /* Pointer the service name.  This character string may not be null terminated.
                              * Use the service_len parameter to safely copy this string */
    char *   p_provider_name;/* Pointer the provider name.  This character string may not be null terminated.
                              * Use the provider_len parameter to safely copy this string */
    uint16_t features;       /* Profile supported features */
    uint16_t avdt_version;   /* AVDTP protocol version */
} tA2D_Service;

/* This is the callback to notify the result of the SDP discovery process. */
typedef void (tA2D_FIND_CBACK)(bool    found, tA2D_Service * p_service);

/*
 * Enum values for each supported codec per SEP.
 * There should be a separate entry for each codec that is supported
 * for encoding (SRC), and for decoding purpose (SINK).
 */
typedef enum {
    A2D_CODEC_SEP_INDEX_SBC = 0,
    A2D_CODEC_SEP_INDEX_SBC_SINK,
    /* Add an entry for each new codec here */
    A2D_CODEC_SEP_INDEX_MAX
} tA2D_CODEC_SEP_INDEX;

/**
 * Structure used to configure the AV media feeding
 */

/* Codec type */
/* TODO: Those should be removed */
#define tA2D_AV_CODEC_NONE       0xFF
#define tA2D_AV_CODEC_PCM        0x5                     /* Raw PCM */
typedef uint8_t tA2D_AV_CODEC_ID;

typedef struct
{
    uint16_t sampling_freq;   /* 44100, 48000 etc */
    uint16_t num_channel;     /* 1 for mono or 2 stereo */
    uint8_t  bit_per_sample;  /* Number of bits per sample (8, 16) */
} tA2D_AV_MEDIA_FEED_CFG_PCM;

typedef union
{
    tA2D_AV_MEDIA_FEED_CFG_PCM pcm;     /* Raw PCM feeding format */
} tA2D_AV_MEDIA_FEED_CFG;

typedef struct
{
    tA2D_AV_CODEC_ID format;        /* Media codec identifier */
    tA2D_AV_MEDIA_FEED_CFG cfg;     /* Media codec configuration */
} tA2D_AV_MEDIA_FEEDINGS;

/*****************************************************************************
**  external function declarations
*****************************************************************************/
/******************************************************************************
**
** Function         A2D_AddRecord
**
** Description      This function is called by a server application to add
**                  SRC or SNK information to an SDP record.  Prior to
**                  calling this function the application must call
**                  SDP_CreateRecord() to create an SDP record.
**
**                  Input Parameters:
**                      service_uuid:  Indicates SRC or SNK.
**
**                      p_service_name:  Pointer to a null-terminated character
**                      string containing the service name.
**
**                      p_provider_name:  Pointer to a null-terminated character
**                      string containing the provider name.
**
**                      features:  Profile supported features.
**
**                      sdp_handle:  SDP handle returned by SDP_CreateRecord().
**
**                  Output Parameters:
**                      None.
**
** Returns          A2D_SUCCESS if function execution succeeded,
**                  A2D_INVALID_PARAMS if bad parameters are given.
**                  A2D_FAIL if function execution failed.
**
******************************************************************************/
extern tA2D_STATUS A2D_AddRecord(uint16_t service_uuid, char *p_service_name, char *p_provider_name,
        uint16_t features, uint32_t sdp_handle);

/******************************************************************************
**
** Function         A2D_FindService
**
** Description      This function is called by a client application to
**                  perform service discovery and retrieve SRC or SNK SDP
**                  record information from a server.  Information is
**                  returned for the first service record found on the
**                  server that matches the service UUID.  The callback
**                  function will be executed when service discovery is
**                  complete.  There can only be one outstanding call to
**                  A2D_FindService() at a time; the application must wait
**                  for the callback before it makes another call to
**                  the function.
**
**                  Input Parameters:
**                      service_uuid:  Indicates SRC or SNK.
**
**                      bd_addr:  BD address of the peer device.
**
**                      p_db:  Pointer to the information to initialize
**                             the discovery database.
**
**                      p_cback:  Pointer to the A2D_FindService()
**                      callback function.
**
**                  Output Parameters:
**                      None.
**
** Returns          A2D_SUCCESS if function execution succeeded,
**                  A2D_INVALID_PARAMS if bad parameters are given.
**                  A2D_BUSY if discovery is already in progress.
**                  A2D_FAIL if function execution failed.
**
******************************************************************************/
extern tA2D_STATUS A2D_FindService(uint16_t service_uuid, BD_ADDR bd_addr,
                                   tA2D_SDP_DB_PARAMS *p_db, tA2D_FIND_CBACK *p_cback);

/******************************************************************************
**
** Function         A2D_SetTraceLevel
**
** Description      Sets the trace level for A2D. If 0xff is passed, the
**                  current trace level is returned.
**
**                  Input Parameters:
**                      new_level:  The level to set the A2D tracing to:
**                      0xff-returns the current setting.
**                      0-turns off tracing.
**                      >= 1-Errors.
**                      >= 2-Warnings.
**                      >= 3-APIs.
**                      >= 4-Events.
**                      >= 5-Debug.
**
** Returns          The new trace level or current trace level if
**                  the input parameter is 0xff.
**
******************************************************************************/
extern uint8_t A2D_SetTraceLevel (uint8_t new_level);

/******************************************************************************
** Function         A2D_BitsSet
**
** Description      Check the given num for the number of bits set
** Returns          A2D_SET_ONE_BIT, if one and only one bit is set
**                  A2D_SET_ZERO_BIT, if all bits clear
**                  A2D_SET_MULTL_BIT, if multiple bits are set
******************************************************************************/
extern uint8_t A2D_BitsSet(uint8_t num);

/*******************************************************************************
**
** Function         A2D_Init
**
** Description      This function is called at stack startup to allocate the
**                  control block (if using dynamic memory), and initializes the
**                  control block and tracing level.
**
** Returns          void
**
*******************************************************************************/
extern void A2D_Init(void);

// Checks whether the codec capabilities contain a valid A2DP codec.
// NOTE: only codecs that are implemented are considered valid.
// Returns true if |p_codec_info| contains information about a valid codec,
// otherwise false.
bool A2D_IsValidCodec(const uint8_t *p_codec_info);

// Gets the A2DP codec type.
// |p_codec_info| contains information about the codec capabilities.
tA2D_CODEC_TYPE A2D_GetCodecType(const uint8_t *p_codec_info);

// Checks whether an A2DP source codec is supported.
// |p_codec_info| contains information about the codec capabilities.
// Returns true if the A2DP source codec is supported, otherwise false.
bool A2D_IsSourceCodecSupported(const uint8_t *p_codec_info);

// Checks whether an A2DP sink codec is supported.
// |p_codec_info| contains information about the codec capabilities.
// Returns true if the A2DP sink codec is supported, otherwise false.
bool A2D_IsSinkCodecSupported(const uint8_t *p_codec_info);

// Checks whether an A2DP source codec for a peer source device is supported.
// |p_codec_info| contains information about the codec capabilities of the
// peer device.
// Returns true if the A2DP source codec for a peer source device is supported,
// otherwise false.
bool A2D_IsPeerSourceCodecSupported(const uint8_t *p_codec_info);

// Initialize state with the default A2DP codec.
// The initialized state with the codec capabilities is stored in
// |p_codec_info|.
void A2D_InitDefaultCodec(uint8_t *p_codec_info);

// Sets A2DB codec state based on the feeding information from |p_feeding|.
// The state with the codec capabilities is stored in |p_codec_info|.
// Returns true on success, otherwise false.
bool A2D_SetCodec(const tA2D_AV_MEDIA_FEEDINGS *p_feeding,
                  uint8_t *p_codec_info);

// Builds A2DP preferred Sink capability from Source capability.
// |p_pref_cfg| is the result Sink capability to store. |p_src_cap| is
// the Source capability to use.
// Returns |A2D_SUCCESS| on success, otherwise the corresponding A2DP error
// status code.
tA2D_STATUS A2D_BuildSrc2SinkConfig(uint8_t *p_pref_cfg,
                                    const uint8_t *p_src_cap);

// Checks whether the A2DP data packets should contain RTP header.
// |content_protection_enabled| is true if Content Protection is
// enabled. |p_codec_info| contains information about the codec capabilities.
// Returns true if the A2DP data packets should contain RTP header, otherwise
// false.
bool A2D_UsesRtpHeader(bool content_protection_enabled,
                       const uint8_t *p_codec_info);

// Gets the codec name for a given |codec_sep_index|.
const char *A2D_CodecSepIndexStr(tA2D_CODEC_SEP_INDEX codec_sep_index);

// Initializes codec-specific information into |tAVDT_CFG| configuration
// entry pointed by |p_cfg|. The selected codec is defined by
// |codec_sep_index|.
// Returns true on success, otherwise false.
bool A2D_InitCodecConfig(tA2D_CODEC_SEP_INDEX codec_sep_index,
                         tAVDT_CFG *p_cfg);

// Gets the |AVDT_MEDIA_TYPE_*| media type from the codec capability
// in |p_codec_info|.
uint8_t A2D_GetMediaType(const uint8_t *p_codec_info);

// Checks whether two A2DP codecs have same type.
// Returns true if the two codecs have same type, otherwise false.
bool A2D_CodecTypeEquals(const uint8_t *p_codec_info_a,
                         const uint8_t *p_codec_info_b);

// Gets the track sampling frequency value for the A2DP codec.
// |p_codec_info| is a pointer to the codec_info to decode.
// Returns the track sampling frequency on success, or -1 if |p_codec_info|
// contains invalid codec information.
int A2D_GetTrackFrequency(const uint8_t *p_codec_info);

// Gets the channel count for the A2DP codec.
// |p_codec_info| is a pointer to the codec_info to decode.
// Returns the channel count on success, or -1 if |p_codec_info|
// contains invalid codec information.
int A2D_GetTrackChannelCount(const uint8_t *p_codec_info);

// Gets the number of subbands for the A2DP codec.
// |p_codec_info| is a pointer to the codec_info to decode.
// Returns the number of subbands on success, or -1 if |p_codec_info|
// contains invalid codec information.
int A2D_GetNumberOfSubbands(const uint8_t *p_codec_info);

// Gets the number of blocks for the A2DP codec.
// |p_codec_info| is a pointer to the codec_info to decode.
// Returns the number of blocks on success, or -1 if |p_codec_info|
// contains invalid codec information.
int A2D_GetNumberOfBlocks(const uint8_t *p_codec_info);

// Gets the allocation method code for the A2DP codec.
// The actual value is codec-specific.
// |p_codec_info| is a pointer to the codec_info to decode.
// Returns the allocation method code on success, or -1 if |p_codec_info|
// contains invalid codec information.
int A2D_GetAllocationMethodCode(const uint8_t *p_codec_info);

// Gets the channel mode code for the A2DP codec.
// The actual value is codec-specific.
// |p_codec_info| is a pointer to the codec_info to decode.
// Returns the channel mode code on success, or -1 if |p_codec_info|
// contains invalid codec information.
int A2D_GetChannelModeCode(const uint8_t *p_codec_info);

// Gets the sampling frequency code for the A2DP codec.
// The actual value is codec-specific.
// |p_codec_info| is a pointer to the codec_info to decode.
// Returns the sampling frequency code on success, or -1 if |p_codec_info|
// contains invalid codec information.
int A2D_GetSamplingFrequencyCode(const uint8_t *p_codec_info);

// Gets the minimum bitpool for the A2DP codec.
// The actual value is codec-specific.
// |p_codec_info| is a pointer to the codec_info to decode.
// Returns the minimum bitpool on success, or -1 if |p_codec_info|
// contains invalid codec information.
int A2D_GetMinBitpool(const uint8_t *p_codec_info);

// Gets the maximum bitpool for the A2DP codec.
// The actual value is codec-specific.
// |p_codec_info| is a pointer to the codec_info to decode.
// Returns the maximum bitpool on success, or -1 if |p_codec_info|
// contains invalid codec information.
int A2D_GetMaxBitpool(const uint8_t *p_codec_info);

// Gets the channel type for the A2DP sink codec:
// 1 for mono, or 3 for dual/stereo/joint.
// |p_codec_info| is a pointer to the codec_info to decode.
// Returns the channel type on success, or -1 if |p_codec_info|
// contains invalid codec information.
int A2D_GetSinkTrackChannelType(const uint8_t *p_codec_info);

// Computes the number of frames to process in a time window for the A2DP
// sink codec. |time_interval_ms| is the time interval (in milliseconds).
// |p_codec_info| is a pointer to the codec_info to decode.
// Returns the number of frames to process on success, or -1 if |p_codec_info|
// contains invalid codec information.
int A2D_GetSinkFramesCountToProcess(uint64_t time_interval_ms,
                                    const uint8_t *p_codec_info);

#ifdef __cplusplus
}
#endif

#endif /* A2D_API_H */
