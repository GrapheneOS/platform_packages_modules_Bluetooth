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

/* data type for the SBC Codec Information Element*/
typedef struct
{
    uint8_t samp_freq;      /* Sampling frequency */
    uint8_t ch_mode;        /* Channel mode */
    uint8_t block_len;      /* Block length */
    uint8_t num_subbands;   /* Number of subbands */
    uint8_t alloc_mthd;     /* Allocation method */
    uint8_t max_bitpool;    /* Maximum bitpool */
    uint8_t min_bitpool;    /* Minimum bitpool */
} tA2D_SBC_CIE;


/*****************************************************************************
**  External Function Declarations
*****************************************************************************/
/******************************************************************************
**
** Function         A2D_BldSbcInfo
**
** Description      This function is called by an application to build
**                  the SBC Media Codec Capabilities byte sequence
**                  beginning from the LOSC octet.
**                  Input Parameters:
**                      media_type:  Indicates Audio, or Multimedia.
**
**                      p_ie:  The SBC Codec Information Element information.
**
**                  Output Parameters:
**                      p_result:  the resulting codec info byte sequence.
**
** Returns          A2D_SUCCESS if function execution succeeded.
**                  Error status code, otherwise.
******************************************************************************/
extern tA2D_STATUS A2D_BldSbcInfo(uint8_t media_type, const tA2D_SBC_CIE *p_ie,
                                  uint8_t *p_result);

/******************************************************************************
**
** Function         A2D_ParsSbcInfo
**
** Description      This function is called by an application to parse
**                  the SBC Media Codec Capabilities byte sequence
**                  beginning from the LOSC octet.
**                  Input Parameters:
**                      p_codec_info:  the codec info byte sequence to parse.
**
**                      for_caps:  true, if the byte sequence is for get capabilities response.
**
**                  Output Parameters:
**                      p_ie:  The SBC Codec Information Element information.
**
** Returns          A2D_SUCCESS if function execution succeeded.
**                  Error status code, otherwise.
******************************************************************************/
extern tA2D_STATUS A2D_ParsSbcInfo(tA2D_SBC_CIE *p_ie,
                                   const uint8_t *p_codec_info, bool for_caps);

/******************************************************************************
**
** Function         A2D_BldSbcMplHdr
**
** Description      This function is called by an application to parse
**                  the SBC Media Payload header.
**                  Input Parameters:
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
**                  Output Parameters:
**                      p_dst:  the resulting media payload header byte sequence.
**
** Returns          void.
******************************************************************************/
extern void A2D_BldSbcMplHdr(uint8_t *p_dst, bool    frag, bool    start,
                             bool    last, uint8_t num);

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

// Set A2DB SBC codec state based on the feeding information from |p_feeding|.
// The state with the codec capabilities is stored in |p_codec_info|.
bool A2D_SetCodecSbc(const tA2D_AV_MEDIA_FEEDINGS *p_feeding,
                     uint8_t *p_codec_info);

// Builds A2DP preferred SBC Sink capability from SBC Source capability.
// |p_pref_cfg| is the result Sink capability to store. |p_src_cap| is
// the Source capability to use.
// Returns |A2D_SUCCESS| on success, otherwise the corresponding A2DP error
// status code.
tA2D_STATUS A2D_BuildSrc2SinkConfigSbc(uint8_t *p_pref_cfg,
                                       const uint8_t *p_src_cap);

// Get the default A2DP SBC config.
// TODO: This is a temporary function that should be removed.
const tA2D_SBC_CIE *A2D_GetDefaultConfigSbc();

// Get the A2DP SBC track sampling frequency value.
// |frequency_type| is the frequency type - see |A2D_SBC_IE_SAMP_FREQ_*|.
int A2D_sbc_get_track_frequency(uint8_t frequency_type);

// Get the A2DP SBC channel count.
// |channel_type| is the channel type - see |A2D_SBC_IE_CH_MD_*|.
int A2D_sbc_get_track_channel_count(uint8_t channel_type);

// Decode and display SBC codec_info (for debugging).
// |p_codec| is a pointer to the SBC codec_info to decode and display.
void A2D_sbc_dump_codec_info(uint8_t *p_codec);

#ifdef __cplusplus
}
#endif

#endif /* A2D_SBC_H */
