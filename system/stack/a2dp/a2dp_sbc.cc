/******************************************************************************
 *
 *  Copyright (C) 2002-2012 Broadcom Corporation
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
 *  Utility functions to help build and parse SBC Codec Information Element
 *  and Media Payload.
 *
 ******************************************************************************/

#define LOG_TAG "a2dp_sbc"

#include "bt_target.h"

#include <string.h>
#include "a2dp_api.h"
#include "a2dp_int.h"
#include "a2dp_sbc.h"
#include "a2dp_sbc_encoder.h"
#include "bt_utils.h"
#include "embdrv/sbc/encoder/include/sbc_encoder.h"
#include "osi/include/log.h"
#include "osi/include/osi.h"

#define A2DP_SBC_MAX_BITPOOL 53

/* data type for the SBC Codec Information Element */
typedef struct {
  uint8_t samp_freq;    /* Sampling frequency */
  uint8_t ch_mode;      /* Channel mode */
  uint8_t block_len;    /* Block length */
  uint8_t num_subbands; /* Number of subbands */
  uint8_t alloc_method; /* Allocation method */
  uint8_t min_bitpool;  /* Minimum bitpool */
  uint8_t max_bitpool;  /* Maximum bitpool */
} tA2DP_SBC_CIE;

/* SBC SRC codec capabilities */
static const tA2DP_SBC_CIE a2dp_sbc_caps = {
    A2DP_SBC_IE_SAMP_FREQ_44, /* samp_freq */
    A2DP_SBC_IE_CH_MD_JOINT,  /* ch_mode */
    A2DP_SBC_IE_BLOCKS_16,    /* block_len */
    A2DP_SBC_IE_SUBBAND_8,    /* num_subbands */
    A2DP_SBC_IE_ALLOC_MD_L,   /* alloc_method */
    A2DP_SBC_IE_MIN_BITPOOL,  /* min_bitpool */
    A2DP_SBC_MAX_BITPOOL      /* max_bitpool */
};

/* SBC SINK codec capabilities */
static const tA2DP_SBC_CIE a2dp_sbc_sink_caps = {
    (A2DP_SBC_IE_SAMP_FREQ_48 | A2DP_SBC_IE_SAMP_FREQ_44), /* samp_freq */
    (A2DP_SBC_IE_CH_MD_MONO | A2DP_SBC_IE_CH_MD_STEREO |
     A2DP_SBC_IE_CH_MD_JOINT | A2DP_SBC_IE_CH_MD_DUAL), /* ch_mode */
    (A2DP_SBC_IE_BLOCKS_16 | A2DP_SBC_IE_BLOCKS_12 | A2DP_SBC_IE_BLOCKS_8 |
     A2DP_SBC_IE_BLOCKS_4),                            /* block_len */
    (A2DP_SBC_IE_SUBBAND_4 | A2DP_SBC_IE_SUBBAND_8),   /* num_subbands */
    (A2DP_SBC_IE_ALLOC_MD_L | A2DP_SBC_IE_ALLOC_MD_S), /* alloc_method */
    A2DP_SBC_IE_MIN_BITPOOL,                           /* min_bitpool */
    A2DP_SBC_MAX_BITPOOL                               /* max_bitpool */
};

/* Default SBC codec configuration */
const tA2DP_SBC_CIE a2dp_sbc_default_config = {
    A2DP_SBC_IE_SAMP_FREQ_44, /* samp_freq */
    A2DP_SBC_IE_CH_MD_JOINT,  /* ch_mode */
    A2DP_SBC_IE_BLOCKS_16,    /* block_len */
    A2DP_SBC_IE_SUBBAND_8,    /* num_subbands */
    A2DP_SBC_IE_ALLOC_MD_L,   /* alloc_method */
    A2DP_SBC_IE_MIN_BITPOOL,  /* min_bitpool */
    A2DP_SBC_MAX_BITPOOL      /* max_bitpool */
};

static const tA2DP_ENCODER_INTERFACE a2dp_encoder_interface_sbc = {
    a2dp_sbc_encoder_init,  a2dp_sbc_encoder_cleanup,
    a2dp_sbc_feeding_init,  a2dp_sbc_feeding_reset,
    a2dp_sbc_feeding_flush, a2dp_sbc_get_encoder_interval_ms,
    a2dp_sbc_send_frames,   a2dp_sbc_debug_codec_dump};

static tA2DP_STATUS A2DP_CodecInfoMatchesCapabilitySbc(
    const tA2DP_SBC_CIE* p_cap, const uint8_t* p_codec_info,
    bool is_peer_codec_info);
static void A2DP_ParseMplHeaderSbc(uint8_t* p_src, bool* p_frag, bool* p_start,
                                   bool* p_last, uint8_t* p_num);

// Builds the SBC Media Codec Capabilities byte sequence beginning from the
// LOSC octet. |media_type| is the media type |AVDT_MEDIA_TYPE_*|.
// |p_ie| is a pointer to the SBC Codec Information Element information.
// The result is stored in |p_result|. Returns A2DP_SUCCESS on success,
// otherwise the corresponding A2DP error status code.
static tA2DP_STATUS A2DP_BuildInfoSbc(uint8_t media_type,
                                      const tA2DP_SBC_CIE* p_ie,
                                      uint8_t* p_result) {
  tA2DP_STATUS status;

  if (p_ie == NULL || p_result == NULL ||
      (p_ie->samp_freq & ~A2DP_SBC_IE_SAMP_FREQ_MSK) ||
      (p_ie->ch_mode & ~A2DP_SBC_IE_CH_MD_MSK) ||
      (p_ie->block_len & ~A2DP_SBC_IE_BLOCKS_MSK) ||
      (p_ie->num_subbands & ~A2DP_SBC_IE_SUBBAND_MSK) ||
      (p_ie->alloc_method & ~A2DP_SBC_IE_ALLOC_MD_MSK) ||
      (p_ie->min_bitpool > p_ie->max_bitpool) ||
      (p_ie->min_bitpool < A2DP_SBC_IE_MIN_BITPOOL) ||
      (p_ie->min_bitpool > A2DP_SBC_IE_MAX_BITPOOL) ||
      (p_ie->max_bitpool < A2DP_SBC_IE_MIN_BITPOOL) ||
      (p_ie->max_bitpool > A2DP_SBC_IE_MAX_BITPOOL)) {
    /* if any unused bit is set */
    status = A2DP_INVALID_PARAMS;
  } else {
    status = A2DP_SUCCESS;
    *p_result++ = A2DP_SBC_INFO_LEN;
    *p_result++ = (media_type << 4);
    *p_result++ = A2DP_MEDIA_CT_SBC;

    /* Media Codec Specific Information Element */
    *p_result++ = p_ie->samp_freq | p_ie->ch_mode;

    *p_result++ = p_ie->block_len | p_ie->num_subbands | p_ie->alloc_method;

    *p_result++ = p_ie->min_bitpool;
    *p_result = p_ie->max_bitpool;
  }
  return status;
}

// Parses the SBC Media Codec Capabilities byte sequence beginning from the
// LOSC octet. The result is stored in |p_ie|. The byte sequence to parse is
// |p_codec_info|. If |is_peer_src_codec_info| is true, the byte sequence is
// for get capabilities response from a peer Source.
// Returns A2DP_SUCCESS on success, otherwise the corresponding A2DP error
// status code.
static tA2DP_STATUS A2DP_ParseInfoSbc(tA2DP_SBC_CIE* p_ie,
                                      const uint8_t* p_codec_info,
                                      bool is_peer_src_codec_info) {
  tA2DP_STATUS status = A2DP_SUCCESS;
  uint8_t losc;
  uint8_t media_type;
  tA2DP_CODEC_TYPE codec_type;

  if (p_ie == NULL || p_codec_info == NULL) return A2DP_INVALID_PARAMS;

  // Check the codec capability length
  losc = *p_codec_info++;
  if (losc != A2DP_SBC_INFO_LEN) return A2DP_WRONG_CODEC;

  media_type = (*p_codec_info++) >> 4;
  codec_type = *p_codec_info++;
  /* Check the Media Type and Media Codec Type */
  if (media_type != AVDT_MEDIA_TYPE_AUDIO || codec_type != A2DP_MEDIA_CT_SBC) {
    return A2DP_WRONG_CODEC;
  }

  p_ie->samp_freq = *p_codec_info & A2DP_SBC_IE_SAMP_FREQ_MSK;
  p_ie->ch_mode = *p_codec_info & A2DP_SBC_IE_CH_MD_MSK;
  p_codec_info++;
  p_ie->block_len = *p_codec_info & A2DP_SBC_IE_BLOCKS_MSK;
  p_ie->num_subbands = *p_codec_info & A2DP_SBC_IE_SUBBAND_MSK;
  p_ie->alloc_method = *p_codec_info & A2DP_SBC_IE_ALLOC_MD_MSK;
  p_codec_info++;
  p_ie->min_bitpool = *p_codec_info++;
  p_ie->max_bitpool = *p_codec_info;
  if (p_ie->min_bitpool < A2DP_SBC_IE_MIN_BITPOOL ||
      p_ie->min_bitpool > A2DP_SBC_IE_MAX_BITPOOL) {
    status = A2DP_BAD_MIN_BITPOOL;
  }

  if (p_ie->max_bitpool < A2DP_SBC_IE_MIN_BITPOOL ||
      p_ie->max_bitpool > A2DP_SBC_IE_MAX_BITPOOL ||
      p_ie->max_bitpool < p_ie->min_bitpool) {
    status = A2DP_BAD_MAX_BITPOOL;
  }

  if (is_peer_src_codec_info) return status;

  if (A2DP_BitsSet(p_ie->samp_freq) != A2DP_SET_ONE_BIT)
    status = A2DP_BAD_SAMP_FREQ;
  if (A2DP_BitsSet(p_ie->ch_mode) != A2DP_SET_ONE_BIT)
    status = A2DP_BAD_CH_MODE;
  if (A2DP_BitsSet(p_ie->block_len) != A2DP_SET_ONE_BIT)
    status = A2DP_BAD_BLOCK_LEN;
  if (A2DP_BitsSet(p_ie->num_subbands) != A2DP_SET_ONE_BIT)
    status = A2DP_BAD_SUBBANDS;
  if (A2DP_BitsSet(p_ie->alloc_method) != A2DP_SET_ONE_BIT)
    status = A2DP_BAD_ALLOC_METHOD;

  return status;
}

// Build the SBC Media Payload Header.
// |p_dst| points to the location where the header should be written to.
// If |frag| is true, the media payload frame is fragmented.
// |start| is true for the first packet of a fragmented frame.
// |last| is true for the last packet of a fragmented frame.
// If |frag| is false, |num| is the number of number of frames in the packet,
// otherwise is the number of remaining fragments (including this one).
static void A2DP_BuildMediaPayloadHeaderSbc(uint8_t* p_dst, bool frag,
                                            bool start, bool last,
                                            uint8_t num) {
  if (p_dst == NULL) return;

  *p_dst = 0;
  if (frag) *p_dst |= A2DP_SBC_HDR_F_MSK;
  if (start) *p_dst |= A2DP_SBC_HDR_S_MSK;
  if (last) *p_dst |= A2DP_SBC_HDR_L_MSK;
  *p_dst |= (A2DP_SBC_HDR_NUM_MSK & num);
}

/******************************************************************************
 *
 * Function         A2DP_ParseMplHeaderSbc
 *
 * Description      This function is called by an application to parse
 *                  the SBC Media Payload header.
 *                  Input Parameters:
 *                      p_src:  the byte sequence to parse..
 *
 *                  Output Parameters:
 *                      frag:  1, if fragmented. 0, otherwise.
 *
 *                      start:  1, if the starting packet of a fragmented frame.
 *
 *                      last:  1, if the last packet of a fragmented frame.
 *
 *                      num:  If frag is 1, this is the number of remaining
 *                            fragments
 *                            (including this fragment) of this frame.
 *                            If frag is 0, this is the number of frames in
 *                            this packet.
 *
 * Returns          void.
 *****************************************************************************/
UNUSED_ATTR static void A2DP_ParseMplHeaderSbc(uint8_t* p_src, bool* p_frag,
                                               bool* p_start, bool* p_last,
                                               uint8_t* p_num) {
  if (p_src && p_frag && p_start && p_last && p_num) {
    *p_frag = (*p_src & A2DP_SBC_HDR_F_MSK) ? true : false;
    *p_start = (*p_src & A2DP_SBC_HDR_S_MSK) ? true : false;
    *p_last = (*p_src & A2DP_SBC_HDR_L_MSK) ? true : false;
    *p_num = (*p_src & A2DP_SBC_HDR_NUM_MSK);
  }
}

tA2DP_CODEC_SEP_INDEX A2DP_SourceCodecSepIndexSbc(const uint8_t* p_codec_info) {
  return A2DP_CODEC_SEP_INDEX_SOURCE_SBC;
}

const char* A2DP_CodecSepIndexStrSbc(void) { return "SBC"; }

const char* A2DP_CodecSepIndexStrSbcSink(void) { return "SBC SINK"; }

bool A2DP_InitCodecConfigSbc(tAVDT_CFG* p_cfg) {
  if (A2DP_BuildInfoSbc(AVDT_MEDIA_TYPE_AUDIO, &a2dp_sbc_caps,
                        p_cfg->codec_info) != A2DP_SUCCESS) {
    return false;
  }

#if (BTA_AV_CO_CP_SCMS_T == TRUE)
  /* Content protection info - support SCMS-T */
  uint8_t* p = p_cfg->protect_info;
  *p++ = AVDT_CP_LOSC;
  UINT16_TO_STREAM(p, AVDT_CP_SCMS_T_ID);
  p_cfg->num_protect = 1;
#endif

  return true;
}

const char* A2DP_CodecNameSbc(UNUSED_ATTR const uint8_t* p_codec_info) {
  return "SBC";
}

bool A2DP_InitCodecConfigSbcSink(tAVDT_CFG* p_cfg) {
  if (A2DP_BuildInfoSbc(AVDT_MEDIA_TYPE_AUDIO, &a2dp_sbc_sink_caps,
                        p_cfg->codec_info) != A2DP_SUCCESS) {
    return false;
  }

  return true;
}

bool A2DP_IsSourceCodecValidSbc(const uint8_t* p_codec_info) {
  tA2DP_SBC_CIE cfg_cie;

  /* Use a liberal check when parsing the codec info */
  return (A2DP_ParseInfoSbc(&cfg_cie, p_codec_info, false) == A2DP_SUCCESS) ||
         (A2DP_ParseInfoSbc(&cfg_cie, p_codec_info, true) == A2DP_SUCCESS);
}

bool A2DP_IsSinkCodecValidSbc(const uint8_t* p_codec_info) {
  tA2DP_SBC_CIE cfg_cie;

  /* Use a liberal check when parsing the codec info */
  return (A2DP_ParseInfoSbc(&cfg_cie, p_codec_info, false) == A2DP_SUCCESS) ||
         (A2DP_ParseInfoSbc(&cfg_cie, p_codec_info, true) == A2DP_SUCCESS);
}

bool A2DP_IsPeerSourceCodecValidSbc(const uint8_t* p_codec_info) {
  tA2DP_SBC_CIE cfg_cie;

  /* Use a liberal check when parsing the codec info */
  return (A2DP_ParseInfoSbc(&cfg_cie, p_codec_info, false) == A2DP_SUCCESS) ||
         (A2DP_ParseInfoSbc(&cfg_cie, p_codec_info, true) == A2DP_SUCCESS);
}

bool A2DP_IsPeerSinkCodecValidSbc(const uint8_t* p_codec_info) {
  tA2DP_SBC_CIE cfg_cie;

  /* Use a liberal check when parsing the codec info */
  return (A2DP_ParseInfoSbc(&cfg_cie, p_codec_info, false) == A2DP_SUCCESS) ||
         (A2DP_ParseInfoSbc(&cfg_cie, p_codec_info, true) == A2DP_SUCCESS);
}

bool A2DP_IsSinkCodecSupportedSbc(const uint8_t* p_codec_info) {
  return (A2DP_CodecInfoMatchesCapabilitySbc(&a2dp_sbc_sink_caps, p_codec_info,
                                             false) == A2DP_SUCCESS);
}

bool A2DP_IsPeerSourceCodecSupportedSbc(const uint8_t* p_codec_info) {
  return (A2DP_CodecInfoMatchesCapabilitySbc(&a2dp_sbc_sink_caps, p_codec_info,
                                             true) == A2DP_SUCCESS);
}

void A2DP_InitDefaultCodecSbc(uint8_t* p_codec_info) {
  if (A2DP_BuildInfoSbc(AVDT_MEDIA_TYPE_AUDIO, &a2dp_sbc_default_config,
                        p_codec_info) != A2DP_SUCCESS) {
    LOG_ERROR(LOG_TAG, "%s: A2DP_BuildInfoSbc failed", __func__);
  }
}

tA2DP_STATUS A2DP_InitSource2SinkCodecSbc(const uint8_t* p_sink_caps,
                                          uint8_t* p_result_codec_config) {
  tA2DP_SBC_CIE sink_caps_cie;
  tA2DP_SBC_CIE result_config_cie;

  tA2DP_STATUS status = A2DP_ParseInfoSbc(&sink_caps_cie, p_sink_caps, false);
  if (status != A2DP_SUCCESS) {
    LOG_ERROR(LOG_TAG, "%s: can't parse peer's Sink capabilities: error = %d",
              __func__, status);
    return A2DP_FAIL;
  }

  /* Load the encoder */
  if (!A2DP_LoadEncoderSbc()) {
    LOG_ERROR(LOG_TAG, "%s: cannot load the encoder", __func__);
    return A2DP_FAIL;
  }

  //
  // Build the preferred configuration
  //
  memset(&result_config_cie, 0, sizeof(result_config_cie));
  // Select the sample frequency
  if (a2dp_sbc_caps.samp_freq & sink_caps_cie.samp_freq &
      A2DP_SBC_IE_SAMP_FREQ_48) {
    result_config_cie.samp_freq = A2DP_SBC_IE_SAMP_FREQ_48;
  } else if (a2dp_sbc_caps.samp_freq & sink_caps_cie.samp_freq &
             A2DP_SBC_IE_SAMP_FREQ_44) {
    result_config_cie.samp_freq = A2DP_SBC_IE_SAMP_FREQ_44;
  } else {
    LOG_ERROR(LOG_TAG,
              "%s: cannot match sample frequency: source caps = 0x%x "
              "sink caps = 0x%x",
              __func__, a2dp_sbc_caps.samp_freq, sink_caps_cie.samp_freq);
    return A2DP_BAD_SAMP_FREQ;
  }
  // Select the channel mode
  if (a2dp_sbc_caps.ch_mode & sink_caps_cie.ch_mode & A2DP_SBC_IE_CH_MD_JOINT) {
    result_config_cie.ch_mode = A2DP_SBC_IE_CH_MD_JOINT;
  } else if (a2dp_sbc_caps.ch_mode & sink_caps_cie.ch_mode &
             A2DP_SBC_IE_CH_MD_STEREO) {
    result_config_cie.ch_mode = A2DP_SBC_IE_CH_MD_STEREO;
  } else if (a2dp_sbc_caps.ch_mode & sink_caps_cie.ch_mode &
             A2DP_SBC_IE_CH_MD_DUAL) {
    result_config_cie.ch_mode = A2DP_SBC_IE_CH_MD_DUAL;
  } else if (a2dp_sbc_caps.ch_mode & sink_caps_cie.ch_mode &
             A2DP_SBC_IE_CH_MD_MONO) {
    result_config_cie.ch_mode = A2DP_SBC_IE_CH_MD_MONO;
  } else {
    LOG_ERROR(LOG_TAG,
              "%s: cannot match channel mode: source caps = 0x%x "
              "sink caps = 0x%x",
              __func__, a2dp_sbc_caps.ch_mode, sink_caps_cie.ch_mode);
    return A2DP_BAD_CH_MODE;
  }
  // Select the block length
  if (a2dp_sbc_caps.block_len & sink_caps_cie.block_len &
      A2DP_SBC_IE_BLOCKS_16) {
    result_config_cie.block_len = A2DP_SBC_IE_BLOCKS_16;
  } else if (a2dp_sbc_caps.block_len & sink_caps_cie.block_len &
             A2DP_SBC_IE_BLOCKS_12) {
    result_config_cie.block_len = A2DP_SBC_IE_BLOCKS_12;
  } else if (a2dp_sbc_caps.block_len & sink_caps_cie.block_len &
             A2DP_SBC_IE_BLOCKS_8) {
    result_config_cie.block_len = A2DP_SBC_IE_BLOCKS_8;
  } else if (a2dp_sbc_caps.block_len & sink_caps_cie.block_len &
             A2DP_SBC_IE_BLOCKS_4) {
    result_config_cie.block_len = A2DP_SBC_IE_BLOCKS_4;
  } else {
    LOG_ERROR(LOG_TAG,
              "%s: cannot match block length: source caps = 0x%x "
              "sink caps = 0x%x",
              __func__, a2dp_sbc_caps.block_len, sink_caps_cie.block_len);
    return A2DP_BAD_BLOCK_LEN;
  }
  // Select the number of sub-bands
  if (a2dp_sbc_caps.num_subbands & sink_caps_cie.num_subbands &
      A2DP_SBC_IE_SUBBAND_8) {
    result_config_cie.num_subbands = A2DP_SBC_IE_SUBBAND_8;
  } else if (a2dp_sbc_caps.num_subbands & sink_caps_cie.num_subbands &
             A2DP_SBC_IE_SUBBAND_4) {
    result_config_cie.num_subbands = A2DP_SBC_IE_SUBBAND_4;
  } else {
    LOG_ERROR(LOG_TAG,
              "%s: cannot match number of sub-bands: source caps = 0x%x "
              "sink caps = 0x%x",
              __func__, a2dp_sbc_caps.num_subbands, sink_caps_cie.num_subbands);
    return A2DP_BAD_SUBBANDS;
  }
  // Select the allocation method
  if (a2dp_sbc_caps.alloc_method & sink_caps_cie.alloc_method &
      A2DP_SBC_IE_ALLOC_MD_L) {
    result_config_cie.alloc_method = A2DP_SBC_IE_ALLOC_MD_L;
  } else if (a2dp_sbc_caps.alloc_method & sink_caps_cie.alloc_method &
             A2DP_SBC_IE_ALLOC_MD_S) {
    result_config_cie.alloc_method = A2DP_SBC_IE_ALLOC_MD_S;
  } else {
    LOG_ERROR(LOG_TAG,
              "%s: cannot match allocation method: source caps = 0x%x "
              "sink caps = 0x%x",
              __func__, a2dp_sbc_caps.alloc_method, sink_caps_cie.alloc_method);
    return A2DP_BAD_ALLOC_METHOD;
  }
  // Select the min/max bitpool
  result_config_cie.min_bitpool = a2dp_sbc_caps.min_bitpool;
  if (result_config_cie.min_bitpool < sink_caps_cie.min_bitpool)
    result_config_cie.min_bitpool = sink_caps_cie.min_bitpool;
  result_config_cie.max_bitpool = a2dp_sbc_caps.max_bitpool;
  if (result_config_cie.max_bitpool > sink_caps_cie.max_bitpool)
    result_config_cie.max_bitpool = sink_caps_cie.max_bitpool;
  if (result_config_cie.min_bitpool > result_config_cie.max_bitpool) {
    LOG_ERROR(LOG_TAG,
              "%s: cannot match min/max bitpool: "
              "source caps min/max = 0x%x/0x%x sink caps min/max = 0x%x/0x%x",
              __func__, a2dp_sbc_caps.min_bitpool, a2dp_sbc_caps.max_bitpool,
              sink_caps_cie.min_bitpool, sink_caps_cie.max_bitpool);
    return A2DP_BAD_ALLOC_METHOD;
  }

  return A2DP_BuildInfoSbc(AVDT_MEDIA_TYPE_AUDIO, &result_config_cie,
                           p_result_codec_config);
}

// Checks whether A2DP SBC codec configuration matches with a device's codec
// capabilities. |p_cap| is the SBC codec configuration. |p_codec_info| is
// the device's codec capabilities. |is_peer_src_codec_info| is true if
// |p_codec_info| contains the codec capabilities for a peer device that
// is acting as an A2DP source.
// Returns A2DP_SUCCESS if the codec configuration matches with capabilities,
// otherwise the corresponding A2DP error status code.
static tA2DP_STATUS A2DP_CodecInfoMatchesCapabilitySbc(
    const tA2DP_SBC_CIE* p_cap, const uint8_t* p_codec_info,
    bool is_peer_src_codec_info) {
  tA2DP_STATUS status;
  tA2DP_SBC_CIE cfg_cie;

  /* parse configuration */
  status = A2DP_ParseInfoSbc(&cfg_cie, p_codec_info, is_peer_src_codec_info);
  if (status != A2DP_SUCCESS) {
    LOG_ERROR(LOG_TAG, "%s: parsing failed %d", __func__, status);
    return status;
  }

  /* verify that each parameter is in range */

  LOG_DEBUG(LOG_TAG, "FREQ peer: 0x%x, capability 0x%x", cfg_cie.samp_freq,
            p_cap->samp_freq);
  LOG_DEBUG(LOG_TAG, "CH_MODE peer: 0x%x, capability 0x%x", cfg_cie.ch_mode,
            p_cap->ch_mode);
  LOG_DEBUG(LOG_TAG, "BLOCK_LEN peer: 0x%x, capability 0x%x", cfg_cie.block_len,
            p_cap->block_len);
  LOG_DEBUG(LOG_TAG, "SUB_BAND peer: 0x%x, capability 0x%x",
            cfg_cie.num_subbands, p_cap->num_subbands);
  LOG_DEBUG(LOG_TAG, "ALLOC_METHOD peer: 0x%x, capability 0x%x",
            cfg_cie.alloc_method, p_cap->alloc_method);
  LOG_DEBUG(LOG_TAG, "MIN_BitPool peer: 0x%x, capability 0x%x",
            cfg_cie.min_bitpool, p_cap->min_bitpool);
  LOG_DEBUG(LOG_TAG, "MAX_BitPool peer: 0x%x, capability 0x%x",
            cfg_cie.max_bitpool, p_cap->max_bitpool);

  /* sampling frequency */
  if ((cfg_cie.samp_freq & p_cap->samp_freq) == 0) return A2DP_NS_SAMP_FREQ;

  /* channel mode */
  if ((cfg_cie.ch_mode & p_cap->ch_mode) == 0) return A2DP_NS_CH_MODE;

  /* block length */
  if ((cfg_cie.block_len & p_cap->block_len) == 0) return A2DP_BAD_BLOCK_LEN;

  /* subbands */
  if ((cfg_cie.num_subbands & p_cap->num_subbands) == 0)
    return A2DP_NS_SUBBANDS;

  /* allocation method */
  if ((cfg_cie.alloc_method & p_cap->alloc_method) == 0)
    return A2DP_NS_ALLOC_METHOD;

  /* min bitpool */
  if (cfg_cie.min_bitpool > p_cap->max_bitpool) return A2DP_NS_MIN_BITPOOL;

  /* max bitpool */
  if (cfg_cie.max_bitpool < p_cap->min_bitpool) return A2DP_NS_MAX_BITPOOL;

  return A2DP_SUCCESS;
}

tA2DP_STATUS A2DP_BuildSrc2SinkConfigSbc(const uint8_t* p_src_cap,
                                         uint8_t* p_pref_cfg) {
  tA2DP_SBC_CIE src_cap;
  tA2DP_SBC_CIE pref_cap;

  /* initialize it to default SBC configuration */
  A2DP_BuildInfoSbc(AVDT_MEDIA_TYPE_AUDIO, &a2dp_sbc_default_config,
                    p_pref_cfg);

  /* now try to build a preferred one */
  /* parse configuration */
  tA2DP_STATUS status = A2DP_ParseInfoSbc(&src_cap, p_src_cap, true);
  if (status != A2DP_SUCCESS) {
    LOG_ERROR(LOG_TAG, "%s: can't parse src cap ret = %d", __func__, status);
    return A2DP_FAIL;
  }

  if (src_cap.samp_freq & A2DP_SBC_IE_SAMP_FREQ_48)
    pref_cap.samp_freq = A2DP_SBC_IE_SAMP_FREQ_48;
  else if (src_cap.samp_freq & A2DP_SBC_IE_SAMP_FREQ_44)
    pref_cap.samp_freq = A2DP_SBC_IE_SAMP_FREQ_44;

  if (src_cap.ch_mode & A2DP_SBC_IE_CH_MD_JOINT)
    pref_cap.ch_mode = A2DP_SBC_IE_CH_MD_JOINT;
  else if (src_cap.ch_mode & A2DP_SBC_IE_CH_MD_STEREO)
    pref_cap.ch_mode = A2DP_SBC_IE_CH_MD_STEREO;
  else if (src_cap.ch_mode & A2DP_SBC_IE_CH_MD_DUAL)
    pref_cap.ch_mode = A2DP_SBC_IE_CH_MD_DUAL;
  else if (src_cap.ch_mode & A2DP_SBC_IE_CH_MD_MONO)
    pref_cap.ch_mode = A2DP_SBC_IE_CH_MD_MONO;

  if (src_cap.block_len & A2DP_SBC_IE_BLOCKS_16)
    pref_cap.block_len = A2DP_SBC_IE_BLOCKS_16;
  else if (src_cap.block_len & A2DP_SBC_IE_BLOCKS_12)
    pref_cap.block_len = A2DP_SBC_IE_BLOCKS_12;
  else if (src_cap.block_len & A2DP_SBC_IE_BLOCKS_8)
    pref_cap.block_len = A2DP_SBC_IE_BLOCKS_8;
  else if (src_cap.block_len & A2DP_SBC_IE_BLOCKS_4)
    pref_cap.block_len = A2DP_SBC_IE_BLOCKS_4;

  if (src_cap.num_subbands & A2DP_SBC_IE_SUBBAND_8)
    pref_cap.num_subbands = A2DP_SBC_IE_SUBBAND_8;
  else if (src_cap.num_subbands & A2DP_SBC_IE_SUBBAND_4)
    pref_cap.num_subbands = A2DP_SBC_IE_SUBBAND_4;

  if (src_cap.alloc_method & A2DP_SBC_IE_ALLOC_MD_L)
    pref_cap.alloc_method = A2DP_SBC_IE_ALLOC_MD_L;
  else if (src_cap.alloc_method & A2DP_SBC_IE_ALLOC_MD_S)
    pref_cap.alloc_method = A2DP_SBC_IE_ALLOC_MD_S;

  pref_cap.min_bitpool = src_cap.min_bitpool;
  pref_cap.max_bitpool = src_cap.max_bitpool;

  A2DP_BuildInfoSbc(AVDT_MEDIA_TYPE_AUDIO, &pref_cap, p_pref_cfg);

  return A2DP_SUCCESS;
}

bool A2DP_CodecTypeEqualsSbc(const uint8_t* p_codec_info_a,
                             const uint8_t* p_codec_info_b) {
  tA2DP_SBC_CIE sbc_cie_a;
  tA2DP_SBC_CIE sbc_cie_b;

  // Check whether the codec info contains valid data
  tA2DP_STATUS a2dp_status =
      A2DP_ParseInfoSbc(&sbc_cie_a, p_codec_info_a, false);
  if (a2dp_status != A2DP_SUCCESS) {
    LOG_ERROR(LOG_TAG, "%s: cannot decode codec information: %d", __func__,
              a2dp_status);
    return false;
  }
  a2dp_status = A2DP_ParseInfoSbc(&sbc_cie_b, p_codec_info_b, false);
  if (a2dp_status != A2DP_SUCCESS) {
    LOG_ERROR(LOG_TAG, "%s: cannot decode codec information: %d", __func__,
              a2dp_status);
    return false;
  }

  tA2DP_CODEC_TYPE codec_type_a = A2DP_GetCodecType(p_codec_info_a);
  tA2DP_CODEC_TYPE codec_type_b = A2DP_GetCodecType(p_codec_info_b);

  return (codec_type_a == codec_type_b) && (codec_type_a == A2DP_MEDIA_CT_SBC);
}

bool A2DP_CodecEqualsSbc(const uint8_t* p_codec_info_a,
                         const uint8_t* p_codec_info_b) {
  tA2DP_SBC_CIE sbc_cie_a;
  tA2DP_SBC_CIE sbc_cie_b;

  // Check whether the codec info contains valid data
  tA2DP_STATUS a2dp_status =
      A2DP_ParseInfoSbc(&sbc_cie_a, p_codec_info_a, false);
  if (a2dp_status != A2DP_SUCCESS) {
    LOG_ERROR(LOG_TAG, "%s: cannot decode codec information: %d", __func__,
              a2dp_status);
    return false;
  }
  a2dp_status = A2DP_ParseInfoSbc(&sbc_cie_b, p_codec_info_b, false);
  if (a2dp_status != A2DP_SUCCESS) {
    LOG_ERROR(LOG_TAG, "%s: cannot decode codec information: %d", __func__,
              a2dp_status);
    return false;
  }

  tA2DP_CODEC_TYPE codec_type_a = A2DP_GetCodecType(p_codec_info_a);
  tA2DP_CODEC_TYPE codec_type_b = A2DP_GetCodecType(p_codec_info_b);

  if ((codec_type_a != codec_type_b) || (codec_type_a != A2DP_MEDIA_CT_SBC))
    return false;

  return (sbc_cie_a.samp_freq == sbc_cie_b.samp_freq) &&
         (sbc_cie_a.ch_mode == sbc_cie_b.ch_mode) &&
         (sbc_cie_a.block_len == sbc_cie_b.block_len) &&
         (sbc_cie_a.num_subbands == sbc_cie_b.num_subbands) &&
         (sbc_cie_a.alloc_method == sbc_cie_b.alloc_method) &&
         (sbc_cie_a.min_bitpool == sbc_cie_b.min_bitpool) &&
         (sbc_cie_a.max_bitpool == sbc_cie_b.max_bitpool);
}

int A2DP_GetTrackSampleRateSbc(const uint8_t* p_codec_info) {
  tA2DP_SBC_CIE sbc_cie;

  tA2DP_STATUS a2dp_status = A2DP_ParseInfoSbc(&sbc_cie, p_codec_info, false);
  if (a2dp_status != A2DP_SUCCESS) {
    LOG_ERROR(LOG_TAG, "%s: cannot decode codec information: %d", __func__,
              a2dp_status);
    return -1;
  }

  switch (sbc_cie.samp_freq) {
    case A2DP_SBC_IE_SAMP_FREQ_16:
      return 16000;
    case A2DP_SBC_IE_SAMP_FREQ_32:
      return 32000;
    case A2DP_SBC_IE_SAMP_FREQ_44:
      return 44100;
    case A2DP_SBC_IE_SAMP_FREQ_48:
      return 48000;
    default:
      break;
  }

  return -1;
}

int A2DP_GetTrackChannelCountSbc(const uint8_t* p_codec_info) {
  tA2DP_SBC_CIE sbc_cie;

  tA2DP_STATUS a2dp_status = A2DP_ParseInfoSbc(&sbc_cie, p_codec_info, false);
  if (a2dp_status != A2DP_SUCCESS) {
    LOG_ERROR(LOG_TAG, "%s: cannot decode codec information: %d", __func__,
              a2dp_status);
    return -1;
  }

  switch (sbc_cie.ch_mode) {
    case A2DP_SBC_IE_CH_MD_MONO:
      return 1;
    case A2DP_SBC_IE_CH_MD_DUAL:
    case A2DP_SBC_IE_CH_MD_STEREO:
    case A2DP_SBC_IE_CH_MD_JOINT:
      return 2;
    default:
      break;
  }

  return -1;
}

int A2DP_GetTrackBitsPerSampleSbc(const uint8_t* p_codec_info) {
  tA2DP_SBC_CIE sbc_cie;

  tA2DP_STATUS a2dp_status = A2DP_ParseInfoSbc(&sbc_cie, p_codec_info, false);
  if (a2dp_status != A2DP_SUCCESS) {
    LOG_ERROR(LOG_TAG, "%s: cannot decode codec information: %d", __func__,
              a2dp_status);
    return -1;
  }

  return 16;  // For SBC we always use 16 bits per audio sample
}

int A2DP_GetNumberOfSubbandsSbc(const uint8_t* p_codec_info) {
  tA2DP_SBC_CIE sbc_cie;

  tA2DP_STATUS a2dp_status = A2DP_ParseInfoSbc(&sbc_cie, p_codec_info, false);
  if (a2dp_status != A2DP_SUCCESS) {
    LOG_ERROR(LOG_TAG, "%s: cannot decode codec information: %d", __func__,
              a2dp_status);
    return -1;
  }

  switch (sbc_cie.num_subbands) {
    case A2DP_SBC_IE_SUBBAND_4:
      return 4;
    case A2DP_SBC_IE_SUBBAND_8:
      return 8;
    default:
      break;
  }

  return -1;
}

int A2DP_GetNumberOfBlocksSbc(const uint8_t* p_codec_info) {
  tA2DP_SBC_CIE sbc_cie;

  tA2DP_STATUS a2dp_status = A2DP_ParseInfoSbc(&sbc_cie, p_codec_info, false);
  if (a2dp_status != A2DP_SUCCESS) {
    LOG_ERROR(LOG_TAG, "%s: cannot decode codec information: %d", __func__,
              a2dp_status);
    return -1;
  }

  switch (sbc_cie.block_len) {
    case A2DP_SBC_IE_BLOCKS_4:
      return 4;
    case A2DP_SBC_IE_BLOCKS_8:
      return 8;
    case A2DP_SBC_IE_BLOCKS_12:
      return 12;
    case A2DP_SBC_IE_BLOCKS_16:
      return 16;
    default:
      break;
  }

  return -1;
}

int A2DP_GetAllocationMethodCodeSbc(const uint8_t* p_codec_info) {
  tA2DP_SBC_CIE sbc_cie;

  tA2DP_STATUS a2dp_status = A2DP_ParseInfoSbc(&sbc_cie, p_codec_info, false);
  if (a2dp_status != A2DP_SUCCESS) {
    LOG_ERROR(LOG_TAG, "%s: cannot decode codec information: %d", __func__,
              a2dp_status);
    return -1;
  }

  switch (sbc_cie.alloc_method) {
    case A2DP_SBC_IE_ALLOC_MD_S:
      return SBC_SNR;
    case A2DP_SBC_IE_ALLOC_MD_L:
      return SBC_LOUDNESS;
    default:
      break;
  }

  return -1;
}

int A2DP_GetChannelModeCodeSbc(const uint8_t* p_codec_info) {
  tA2DP_SBC_CIE sbc_cie;

  tA2DP_STATUS a2dp_status = A2DP_ParseInfoSbc(&sbc_cie, p_codec_info, false);
  if (a2dp_status != A2DP_SUCCESS) {
    LOG_ERROR(LOG_TAG, "%s: cannot decode codec information: %d", __func__,
              a2dp_status);
    return -1;
  }

  switch (sbc_cie.ch_mode) {
    case A2DP_SBC_IE_CH_MD_MONO:
      return SBC_MONO;
    case A2DP_SBC_IE_CH_MD_DUAL:
      return SBC_DUAL;
    case A2DP_SBC_IE_CH_MD_STEREO:
      return SBC_STEREO;
    case A2DP_SBC_IE_CH_MD_JOINT:
      return SBC_JOINT_STEREO;
    default:
      break;
  }

  return -1;
}

int A2DP_GetSamplingFrequencyCodeSbc(const uint8_t* p_codec_info) {
  tA2DP_SBC_CIE sbc_cie;

  tA2DP_STATUS a2dp_status = A2DP_ParseInfoSbc(&sbc_cie, p_codec_info, false);
  if (a2dp_status != A2DP_SUCCESS) {
    LOG_ERROR(LOG_TAG, "%s: cannot decode codec information: %d", __func__,
              a2dp_status);
    return -1;
  }

  switch (sbc_cie.samp_freq) {
    case A2DP_SBC_IE_SAMP_FREQ_16:
      return SBC_sf16000;
    case A2DP_SBC_IE_SAMP_FREQ_32:
      return SBC_sf32000;
    case A2DP_SBC_IE_SAMP_FREQ_44:
      return SBC_sf44100;
    case A2DP_SBC_IE_SAMP_FREQ_48:
      return SBC_sf48000;
    default:
      break;
  }

  return -1;
}

int A2DP_GetMinBitpoolSbc(const uint8_t* p_codec_info) {
  tA2DP_SBC_CIE sbc_cie;

  tA2DP_STATUS a2dp_status = A2DP_ParseInfoSbc(&sbc_cie, p_codec_info, false);
  if (a2dp_status != A2DP_SUCCESS) {
    LOG_ERROR(LOG_TAG, "%s: cannot decode codec information: %d", __func__,
              a2dp_status);
    return -1;
  }

  return sbc_cie.min_bitpool;
}

int A2DP_GetMaxBitpoolSbc(const uint8_t* p_codec_info) {
  tA2DP_SBC_CIE sbc_cie;

  tA2DP_STATUS a2dp_status = A2DP_ParseInfoSbc(&sbc_cie, p_codec_info, false);
  if (a2dp_status != A2DP_SUCCESS) {
    LOG_ERROR(LOG_TAG, "%s: cannot decode codec information: %d", __func__,
              a2dp_status);
    return -1;
  }

  return sbc_cie.max_bitpool;
}

int A2DP_GetSinkTrackChannelTypeSbc(const uint8_t* p_codec_info) {
  tA2DP_SBC_CIE sbc_cie;

  tA2DP_STATUS a2dp_status = A2DP_ParseInfoSbc(&sbc_cie, p_codec_info, false);
  if (a2dp_status != A2DP_SUCCESS) {
    LOG_ERROR(LOG_TAG, "%s: cannot decode codec information: %d", __func__,
              a2dp_status);
    return -1;
  }

  switch (sbc_cie.ch_mode) {
    case A2DP_SBC_IE_CH_MD_MONO:
      return 1;
    case A2DP_SBC_IE_CH_MD_DUAL:
    case A2DP_SBC_IE_CH_MD_STEREO:
    case A2DP_SBC_IE_CH_MD_JOINT:
      return 3;
    default:
      break;
  }

  return -1;
}

int A2DP_GetSinkFramesCountToProcessSbc(uint64_t time_interval_ms,
                                        const uint8_t* p_codec_info) {
  tA2DP_SBC_CIE sbc_cie;
  uint32_t freq_multiple;
  uint32_t num_blocks;
  uint32_t num_subbands;
  int frames_to_process;

  tA2DP_STATUS a2dp_status = A2DP_ParseInfoSbc(&sbc_cie, p_codec_info, false);
  if (a2dp_status != A2DP_SUCCESS) {
    LOG_ERROR(LOG_TAG, "%s: cannot decode codec information: %d", __func__,
              a2dp_status);
    return -1;
  }

  // Check the sample frequency
  switch (sbc_cie.samp_freq) {
    case A2DP_SBC_IE_SAMP_FREQ_16:
      LOG_VERBOSE(LOG_TAG, "%s: samp_freq:%d (16000)", __func__,
                  sbc_cie.samp_freq);
      freq_multiple = 16 * time_interval_ms;
      break;
    case A2DP_SBC_IE_SAMP_FREQ_32:
      LOG_VERBOSE(LOG_TAG, "%s: samp_freq:%d (32000)", __func__,
                  sbc_cie.samp_freq);
      freq_multiple = 32 * time_interval_ms;
      break;
    case A2DP_SBC_IE_SAMP_FREQ_44:
      LOG_VERBOSE(LOG_TAG, "%s: samp_freq:%d (44100)", __func__,
                  sbc_cie.samp_freq);
      freq_multiple = (441 * time_interval_ms) / 10;
      break;
    case A2DP_SBC_IE_SAMP_FREQ_48:
      LOG_VERBOSE(LOG_TAG, "%s: samp_freq:%d (48000)", __func__,
                  sbc_cie.samp_freq);
      freq_multiple = 48 * time_interval_ms;
      break;
    default:
      LOG_ERROR(LOG_TAG, "%s: unknown frequency: %d", __func__,
                sbc_cie.samp_freq);
      return -1;
  }

  // Check the channel mode
  switch (sbc_cie.ch_mode) {
    case A2DP_SBC_IE_CH_MD_MONO:
      LOG_VERBOSE(LOG_TAG, "%s: ch_mode:%d (Mono)", __func__, sbc_cie.ch_mode);
      break;
    case A2DP_SBC_IE_CH_MD_DUAL:
      LOG_VERBOSE(LOG_TAG, "%s: ch_mode:%d (DUAL)", __func__, sbc_cie.ch_mode);
      break;
    case A2DP_SBC_IE_CH_MD_STEREO:
      LOG_VERBOSE(LOG_TAG, "%s: ch_mode:%d (STEREO)", __func__,
                  sbc_cie.ch_mode);
      break;
    case A2DP_SBC_IE_CH_MD_JOINT:
      LOG_VERBOSE(LOG_TAG, "%s: ch_mode:%d (JOINT)", __func__, sbc_cie.ch_mode);
      break;
    default:
      LOG_ERROR(LOG_TAG, "%s: unknown channel mode: %d", __func__,
                sbc_cie.ch_mode);
      return -1;
  }

  // Check the block length
  switch (sbc_cie.block_len) {
    case A2DP_SBC_IE_BLOCKS_4:
      LOG_VERBOSE(LOG_TAG, "%s: block_len:%d (4)", __func__, sbc_cie.block_len);
      num_blocks = 4;
      break;
    case A2DP_SBC_IE_BLOCKS_8:
      LOG_VERBOSE(LOG_TAG, "%s: block_len:%d (8)", __func__, sbc_cie.block_len);
      num_blocks = 8;
      break;
    case A2DP_SBC_IE_BLOCKS_12:
      LOG_VERBOSE(LOG_TAG, "%s: block_len:%d (12)", __func__,
                  sbc_cie.block_len);
      num_blocks = 12;
      break;
    case A2DP_SBC_IE_BLOCKS_16:
      LOG_VERBOSE(LOG_TAG, "%s: block_len:%d (16)", __func__,
                  sbc_cie.block_len);
      num_blocks = 16;
      break;
    default:
      LOG_ERROR(LOG_TAG, "%s: unknown block length: %d", __func__,
                sbc_cie.block_len);
      return -1;
  }

  // Check the number of sub-bands
  switch (sbc_cie.num_subbands) {
    case A2DP_SBC_IE_SUBBAND_4:
      LOG_VERBOSE(LOG_TAG, "%s: num_subbands:%d (4)", __func__,
                  sbc_cie.num_subbands);
      num_subbands = 4;
      break;
    case A2DP_SBC_IE_SUBBAND_8:
      LOG_VERBOSE(LOG_TAG, "%s: num_subbands:%d (8)", __func__,
                  sbc_cie.num_subbands);
      num_subbands = 8;
      break;
    default:
      LOG_ERROR(LOG_TAG, "%s: unknown number of subbands: %d", __func__,
                sbc_cie.num_subbands);
      return -1;
  }

  // Check the allocation method
  switch (sbc_cie.alloc_method) {
    case A2DP_SBC_IE_ALLOC_MD_S:
      LOG_VERBOSE(LOG_TAG, "%s: alloc_method:%d (SNR)", __func__,
                  sbc_cie.alloc_method);
      break;
    case A2DP_SBC_IE_ALLOC_MD_L:
      LOG_VERBOSE(LOG_TAG, "%s: alloc_method:%d (Loudness)", __func__,
                  sbc_cie.alloc_method);
      break;
    default:
      LOG_ERROR(LOG_TAG, "%s: unknown allocation method: %d", __func__,
                sbc_cie.alloc_method);
      return -1;
  }

  LOG_VERBOSE(LOG_TAG, "%s: Bit pool Min:%d Max:%d", __func__,
              sbc_cie.min_bitpool, sbc_cie.max_bitpool);

  frames_to_process = ((freq_multiple) / (num_blocks * num_subbands)) + 1;

  return frames_to_process;
}

bool A2DP_GetPacketTimestampSbc(UNUSED_ATTR const uint8_t* p_codec_info,
                                const uint8_t* p_data, uint32_t* p_timestamp) {
  *p_timestamp = *(const uint32_t*)p_data;
  return true;
}

bool A2DP_BuildCodecHeaderSbc(UNUSED_ATTR const uint8_t* p_codec_info,
                              BT_HDR* p_buf, uint16_t frames_per_packet) {
  uint8_t* p;

  p_buf->offset -= A2DP_SBC_MPL_HDR_LEN;
  p = (uint8_t*)(p_buf + 1) + p_buf->offset;
  p_buf->len += A2DP_SBC_MPL_HDR_LEN;
  A2DP_BuildMediaPayloadHeaderSbc(p, false, false, false,
                                  (uint8_t)frames_per_packet);

  return true;
}

void A2DP_DumpCodecInfoSbc(const uint8_t* p_codec_info) {
  tA2DP_STATUS a2dp_status;
  tA2DP_SBC_CIE sbc_cie;

  LOG_DEBUG(LOG_TAG, "%s", __func__);

  a2dp_status = A2DP_ParseInfoSbc(&sbc_cie, p_codec_info, false);
  if (a2dp_status != A2DP_SUCCESS) {
    LOG_ERROR(LOG_TAG, "%s: A2DP_ParseInfoSbc fail:%d", __func__, a2dp_status);
    return;
  }

  if (sbc_cie.samp_freq == A2DP_SBC_IE_SAMP_FREQ_16) {
    LOG_DEBUG(LOG_TAG, "\tsamp_freq:%d (16000)", sbc_cie.samp_freq);
  } else if (sbc_cie.samp_freq == A2DP_SBC_IE_SAMP_FREQ_32) {
    LOG_DEBUG(LOG_TAG, "\tsamp_freq:%d (32000)", sbc_cie.samp_freq);
  } else if (sbc_cie.samp_freq == A2DP_SBC_IE_SAMP_FREQ_44) {
    LOG_DEBUG(LOG_TAG, "\tsamp_freq:%d (44.100)", sbc_cie.samp_freq);
  } else if (sbc_cie.samp_freq == A2DP_SBC_IE_SAMP_FREQ_48) {
    LOG_DEBUG(LOG_TAG, "\tsamp_freq:%d (48000)", sbc_cie.samp_freq);
  } else {
    LOG_DEBUG(LOG_TAG, "\tBAD samp_freq:%d", sbc_cie.samp_freq);
  }

  if (sbc_cie.ch_mode == A2DP_SBC_IE_CH_MD_MONO) {
    LOG_DEBUG(LOG_TAG, "\tch_mode:%d (Mono)", sbc_cie.ch_mode);
  } else if (sbc_cie.ch_mode == A2DP_SBC_IE_CH_MD_DUAL) {
    LOG_DEBUG(LOG_TAG, "\tch_mode:%d (Dual)", sbc_cie.ch_mode);
  } else if (sbc_cie.ch_mode == A2DP_SBC_IE_CH_MD_STEREO) {
    LOG_DEBUG(LOG_TAG, "\tch_mode:%d (Stereo)", sbc_cie.ch_mode);
  } else if (sbc_cie.ch_mode == A2DP_SBC_IE_CH_MD_JOINT) {
    LOG_DEBUG(LOG_TAG, "\tch_mode:%d (Joint)", sbc_cie.ch_mode);
  } else {
    LOG_DEBUG(LOG_TAG, "\tBAD ch_mode:%d", sbc_cie.ch_mode);
  }

  if (sbc_cie.block_len == A2DP_SBC_IE_BLOCKS_4) {
    LOG_DEBUG(LOG_TAG, "\tblock_len:%d (4)", sbc_cie.block_len);
  } else if (sbc_cie.block_len == A2DP_SBC_IE_BLOCKS_8) {
    LOG_DEBUG(LOG_TAG, "\tblock_len:%d (8)", sbc_cie.block_len);
  } else if (sbc_cie.block_len == A2DP_SBC_IE_BLOCKS_12) {
    LOG_DEBUG(LOG_TAG, "\tblock_len:%d (12)", sbc_cie.block_len);
  } else if (sbc_cie.block_len == A2DP_SBC_IE_BLOCKS_16) {
    LOG_DEBUG(LOG_TAG, "\tblock_len:%d (16)", sbc_cie.block_len);
  } else {
    LOG_DEBUG(LOG_TAG, "\tBAD block_len:%d", sbc_cie.block_len);
  }

  if (sbc_cie.num_subbands == A2DP_SBC_IE_SUBBAND_4) {
    LOG_DEBUG(LOG_TAG, "\tnum_subbands:%d (4)", sbc_cie.num_subbands);
  } else if (sbc_cie.num_subbands == A2DP_SBC_IE_SUBBAND_8) {
    LOG_DEBUG(LOG_TAG, "\tnum_subbands:%d (8)", sbc_cie.num_subbands);
  } else {
    LOG_DEBUG(LOG_TAG, "\tBAD num_subbands:%d", sbc_cie.num_subbands);
  }

  if (sbc_cie.alloc_method == A2DP_SBC_IE_ALLOC_MD_S) {
    LOG_DEBUG(LOG_TAG, "\talloc_method:%d (SNR)", sbc_cie.alloc_method);
  } else if (sbc_cie.alloc_method == A2DP_SBC_IE_ALLOC_MD_L) {
    LOG_DEBUG(LOG_TAG, "\talloc_method:%d (Loundess)", sbc_cie.alloc_method);
  } else {
    LOG_DEBUG(LOG_TAG, "\tBAD alloc_method:%d", sbc_cie.alloc_method);
  }

  LOG_DEBUG(LOG_TAG, "\tBit pool Min:%d Max:%d", sbc_cie.min_bitpool,
            sbc_cie.max_bitpool);
}

const tA2DP_ENCODER_INTERFACE* A2DP_GetEncoderInterfaceSbc(
    const uint8_t* p_codec_info) {
  if (!A2DP_IsSourceCodecValidSbc(p_codec_info)) return NULL;

  return &a2dp_encoder_interface_sbc;
}

bool A2DP_AdjustCodecSbc(uint8_t* p_codec_info) {
  tA2DP_SBC_CIE cfg_cie;

  if (A2DP_ParseInfoSbc(&cfg_cie, p_codec_info, false) != A2DP_SUCCESS)
    return false;

  // Updated the max bitpool
  if (cfg_cie.max_bitpool > A2DP_SBC_MAX_BITPOOL) {
    LOG_WARN(LOG_TAG, "Updated the SBC codec max bitpool from %d to %d",
             cfg_cie.max_bitpool, A2DP_SBC_MAX_BITPOOL);
    cfg_cie.max_bitpool = A2DP_SBC_MAX_BITPOOL;
  }

  return (A2DP_BuildInfoSbc(AVDT_MEDIA_TYPE_AUDIO, &cfg_cie, p_codec_info) ==
          A2DP_SUCCESS);
}
