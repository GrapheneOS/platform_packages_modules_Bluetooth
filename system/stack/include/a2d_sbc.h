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
 *  nterface to low complexity subband codec (SBC)
 *
 ******************************************************************************/
#ifndef A2D_SBC_H
#define A2D_SBC_H

#ifdef __cplusplus
extern "C" {
#endif

/*****************************************************************************
**  Constants
*****************************************************************************/
/* the length of the SBC Media Payload header. */
#define A2D_SBC_MPL_HDR_LEN         1

/* the LOSC of SBC media codec capabilitiy */
#define A2D_SBC_INFO_LEN            6

/* for Codec Specific Information Element */
#define A2D_SBC_IE_SAMP_FREQ_MSK    0xF0    /* b7-b4 sampling frequency */
#define A2D_SBC_IE_SAMP_FREQ_16     0x80    /* b7:16  kHz */
#define A2D_SBC_IE_SAMP_FREQ_32     0x40    /* b6:32  kHz */
#define A2D_SBC_IE_SAMP_FREQ_44     0x20    /* b5:44.1kHz */
#define A2D_SBC_IE_SAMP_FREQ_48     0x10    /* b4:48  kHz */

#define A2D_SBC_IE_CH_MD_MSK        0x0F    /* b3-b0 channel mode */
#define A2D_SBC_IE_CH_MD_MONO       0x08    /* b3: mono */
#define A2D_SBC_IE_CH_MD_DUAL       0x04    /* b2: dual */
#define A2D_SBC_IE_CH_MD_STEREO     0x02    /* b1: stereo */
#define A2D_SBC_IE_CH_MD_JOINT      0x01    /* b0: joint stereo */

#define A2D_SBC_IE_BLOCKS_MSK       0xF0    /* b7-b4 number of blocks */
#define A2D_SBC_IE_BLOCKS_4         0x80    /* 4 blocks */
#define A2D_SBC_IE_BLOCKS_8         0x40    /* 8 blocks */
#define A2D_SBC_IE_BLOCKS_12        0x20    /* 12blocks */
#define A2D_SBC_IE_BLOCKS_16        0x10    /* 16blocks */

#define A2D_SBC_IE_SUBBAND_MSK      0x0C    /* b3-b2 number of subbands */
#define A2D_SBC_IE_SUBBAND_4        0x08    /* b3: 4 */
#define A2D_SBC_IE_SUBBAND_8        0x04    /* b2: 8 */

#define A2D_SBC_IE_ALLOC_MD_MSK     0x03    /* b1-b0 allocation mode */
#define A2D_SBC_IE_ALLOC_MD_S       0x02    /* b1: SNR */
#define A2D_SBC_IE_ALLOC_MD_L       0x01    /* b0: loundess */

#define A2D_SBC_IE_MIN_BITPOOL      2
#define A2D_SBC_IE_MAX_BITPOOL      250

/* for media payload header */
#define A2D_SBC_HDR_F_MSK           0x80
#define A2D_SBC_HDR_S_MSK           0x40
#define A2D_SBC_HDR_L_MSK           0x20
#define A2D_SBC_HDR_NUM_MSK         0x0F

/*****************************************************************************
**  Type Definitions
*****************************************************************************/


/*****************************************************************************
**  External Function Declarations
*****************************************************************************/

/******************************************************************************
**
** Function         A2D_ParsSbcMplHdr
**
** Description      This function is called by an application to parse
**                  the SBC Media Payload header.
**                  Input Parameters:
**                      p_src:  the byte sequence to parse..
**
**                  Output Parameters:
**                      frag:  1, if fragmented. 0, otherwise.
**
**                      start:  1, if the starting packet of a fragmented frame.
**
**                      last:  1, if the last packet of a fragmented frame.
**
**                      num:  If frag is 1, this is the number of remaining fragments
**                            (including this fragment) of this frame.
**                            If frag is 0, this is the number of frames in this packet.
**
** Returns          void.
******************************************************************************/
extern void A2D_ParsSbcMplHdr(uint8_t *p_src, bool    *p_frag,
                              bool    *p_start, bool    *p_last,
                              uint8_t *p_num);

// Initializes SBC Source codec information into |tAVDT_CFG| configuration
// entry pointed by |p_cfg|.
bool A2D_InitCodecConfigSbc(tAVDT_CFG *p_cfg);

// Initializes SBC Sink codec information into |tAVDT_CFG| configuration
// entry pointed by |p_cfg|.
bool A2D_InitCodecConfigSbcSink(tAVDT_CFG *p_cfg);

// Checks whether the codec capabilities contain a valid A2DP SBC codec.
// NOTE: only codecs that are implemented are considered valid.
// Returns true if |p_codec_info| contains information about a valid SBC codec,
// otherwise false.
bool A2D_IsValidCodecSbc(const uint8_t *p_codec_info);

// Checks whether A2DP SBC source codec is supported.
// |p_codec_info| contains information about the codec capabilities.
// Returns true if the A2DP SBC source codec is supported, otherwise false.
bool A2D_IsSourceCodecSupportedSbc(const uint8_t *p_codec_info);

// Checks whether A2DP SBC sink codec is supported.
// |p_codec_info| contains information about the codec capabilities.
// Returns true if the A2DP SBC sink codec is supported, otherwise false.
bool A2D_IsSinkCodecSupportedSbc(const uint8_t *p_codec_info);

// Checks whether an A2DP SBC source codec for a peer source device is
// supported.
// |p_codec_info| contains information about the codec capabilities of the
// peer device.
// Returns true if the A2DP SBC source codec for a peer source device is
// supported, otherwise false.
bool A2D_IsPeerSourceCodecSupportedSbc(const uint8_t *p_codec_info);

// Initialize state with the default A2DP SBC codec.
// The initialized state with the codec capabilities is stored in
// |p_codec_info|.
void A2D_InitDefaultCodecSbc(uint8_t *p_codec_info);

// Sets A2DB SBC codec state based on the feeding information from |p_feeding|.
// The state with the codec capabilities is stored in |p_codec_info|.
// Returns true on success, otherwise false.
bool A2D_SetCodecSbc(const tA2D_AV_MEDIA_FEEDINGS *p_feeding,
                     uint8_t *p_codec_info);

// Builds A2DP preferred SBC Sink capability from SBC Source capability.
// |p_src_cap| is the Source capability to use.
// |p_pref_cfg| is the result Sink capability to store.
// Returns |A2D_SUCCESS| on success, otherwise the corresponding A2DP error
// status code.
tA2D_STATUS A2D_BuildSrc2SinkConfigSbc(const uint8_t *p_src_cap,
                                       uint8_t *p_pref_cfg);

// Builds A2DP SBC Sink codec config from SBC Source codec config and SBC Sink
// codec capability.
// |p_src_config| is the A2DP SBC Source codec config to use.
// |p_sink_cap| is the A2DP SBC Sink codec capability to use.
// The result is stored in |p_result_sink_config|.
// Returns |A2D_SUCCESS| on success, otherwise the corresponding A2DP error
// status code.
tA2D_STATUS A2D_BuildSinkConfigSbc(const uint8_t *p_src_config,
                                   const uint8_t *p_sink_cap,
                                   uint8_t *p_result_sink_config);

// Gets the A2DP SBC codec name for a given |p_codec_info|.
const char *A2D_CodecNameSbc(const uint8_t *p_codec_info);

// Checks whether two A2DP SBC codecs |p_codec_info_a| and |p_codec_info_b|
// have the same type.
// Returns true if the two codecs have the same type, otherwise false.
bool A2D_CodecTypeEqualsSbc(const uint8_t *p_codec_info_a,
                            const uint8_t *p_codec_info_b);

// Checks whether two A2DP SBC codecs |p_codec_info_a| and |p_codec_info_b|
// are exactly the same.
// Returns true if the two codecs are exactly the same, otherwise false.
// If the codec type is not SBC, the return value is false.
bool A2D_CodecEqualsSbc(const uint8_t *p_codec_info_a,
                        const uint8_t *p_codec_info_b);

// Checks whether two A2DP SBC codecs |p_codec_info_a| and |p_codec_info_b|
// are different, and A2DP requires reconfiguration.
// Returns true if the two codecs are different and A2DP requires
// reconfiguration, otherwise false.
// If the codec type is not SBC, the return value is true.
bool A2D_CodecRequiresReconfigSbc(const uint8_t *p_codec_info_a,
                                  const uint8_t *p_codec_info_b);

// Checks if an A2DP SBC codec config |p_codec_config| matches an A2DP SBC
// codec capabilities |p_codec_caps|.
// Returns true if the codec config is supported, otherwise false.
bool A2D_CodecConfigMatchesCapabilitiesSbc(const uint8_t *p_codec_config,
                                           const uint8_t *p_codec_caps);

// Gets the track sampling frequency value for the A2DP SBC codec.
// |p_codec_info| is a pointer to the SBC codec_info to decode.
// Returns the track sampling frequency on success, or -1 if |p_codec_info|
// contains invalid codec information.
int A2D_GetTrackFrequencySbc(const uint8_t *p_codec_info);

// Gets the channel count for the A2DP SBC codec.
// |p_codec_info| is a pointer to the SBC codec_info to decode.
// Returns the channel count on success, or -1 if |p_codec_info|
// contains invalid codec information.
int A2D_GetTrackChannelCountSbc(const uint8_t *p_codec_info);

// Gets the number of subbands for the A2DP SBC codec.
// |p_codec_info| is a pointer to the SBC codec_info to decode.
// Returns the number of subbands on success, or -1 if |p_codec_info|
// contains invalid codec information.
int A2D_GetNumberOfSubbandsSbc(const uint8_t *p_codec_info);

// Gets the number of blocks for the A2DP SBC codec.
// |p_codec_info| is a pointer to the SBC codec_info to decode.
// Returns the number of blocks on success, or -1 if |p_codec_info|
// contains invalid codec information.
int A2D_GetNumberOfBlocksSbc(const uint8_t *p_codec_info);

// Gets the allocation method code for the A2DP SBC codec.
// The actual value is codec-specific.
// |p_codec_info| is a pointer to the SBC codec_info to decode.
// Returns the allocation method code on success, or -1 if |p_codec_info|
// contains invalid codec information.
int A2D_GetAllocationMethodCodeSbc(const uint8_t *p_codec_info);

// Gets the channel mode code for the A2DP SBC codec.
// The actual value is codec-specific.
// |p_codec_info| is a pointer to the SBC codec_info to decode.
// Returns the channel mode code on success, or -1 if |p_codec_info|
// contains invalid codec information.
int A2D_GetChannelModeCodeSbc(const uint8_t *p_codec_info);

// Gets the sampling frequency code for the A2DP SBC codec.
// The actual value is codec-specific.
// |p_codec_info| is a pointer to the SBC codec_info to decode.
// Returns the sampling frequency code on success, or -1 if |p_codec_info|
// contains invalid codec information.
int A2D_GetSamplingFrequencyCodeSbc(const uint8_t *p_codec_info);

// Gets the minimum bitpool for the A2DP SBC codec.
// The actual value is codec-specific.
// |p_codec_info| is a pointer to the SBC codec_info to decode.
// Returns the minimum bitpool on success, or -1 if |p_codec_info|
// contains invalid codec information.
int A2D_GetMinBitpoolSbc(const uint8_t *p_codec_info);

// Gets the maximum bitpool for the A2DP SBC codec.
// The actual value is codec-specific.
// |p_codec_info| is a pointer to the SBC codec_info to decode.
// Returns the maximum bitpool on success, or -1 if |p_codec_info|
// contains invalid codec information.
int A2D_GetMaxBitpoolSbc(const uint8_t *p_codec_info);

// Gets the channel type for the A2DP SBC sink codec:
// 1 for mono, or 3 for dual/stereo/joint.
// |p_codec_info| is a pointer to the SBC codec_info to decode.
// Returns the channel type on success, or -1 if |p_codec_info|
// contains invalid codec information.
int A2D_GetSinkTrackChannelTypeSbc(const uint8_t *p_codec_info);

// Computes the number of frames to process in a time window for the A2DP
// SBC sink codec. |time_interval_ms| is the time interval (in milliseconds).
// |p_codec_info| is a pointer to the codec_info to decode.
// Returns the number of frames to process on success, or -1 if |p_codec_info|
// contains invalid codec information.
int A2D_GetSinkFramesCountToProcessSbc(uint64_t time_interval_ms,
                                       const uint8_t *p_codec_info);

// Gets the A2DP SBC audio data timestamp from an audio packet.
// |p_codec_info| contains the codec information.
// |p_data| contains the audio data.
// The timestamp is stored in |p_timestamp|.
// Returns true on success, otherwise false.
bool A2D_GetPacketTimestampSbc(const uint8_t *p_codec_info,
                               const uint8_t *p_data, uint32_t *p_timestamp);

// Builds A2DP SBC codec header for audio data.
// |p_codec_info| contains the codec information.
// |p_buf| contains the audio data.
// |frames_per_packet| is the number of frames in this packet.
// Returns true on success, otherwise false.
bool A2D_BuildCodecHeaderSbc(const uint8_t *p_codec_info, BT_HDR *p_buf,
                             uint16_t frames_per_packet);

// Decodes and displays SBC codec info (for debugging).
// |p_codec_info| is a pointer to the SBC codec_info to decode and display.
void A2D_DumpCodecInfoSbc(const uint8_t *p_codec_info);

#ifdef __cplusplus
}
#endif

#endif /* A2D_SBC_H */
