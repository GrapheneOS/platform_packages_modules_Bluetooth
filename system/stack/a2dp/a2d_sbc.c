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

#define LOG_TAG "a2d_sbc"

#include "bt_target.h"

#include <string.h>
#include "a2d_api.h"
#include "a2d_int.h"
#include "a2d_sbc.h"
#include "bt_utils.h"
#include "embdrv/sbc/encoder/include/sbc_encoder.h"
#include "osi/include/log.h"


#define A2D_SBC_MAX_BITPOOL  53

/* data type for the SBC Codec Information Element*/
typedef struct
{
    uint8_t samp_freq;      /* Sampling frequency */
    uint8_t ch_mode;        /* Channel mode */
    uint8_t block_len;      /* Block length */
    uint8_t num_subbands;   /* Number of subbands */
    uint8_t alloc_method;   /* Allocation method */
    uint8_t min_bitpool;    /* Minimum bitpool */
    uint8_t max_bitpool;    /* Maximum bitpool */
} tA2D_SBC_CIE;

/* SBC SRC codec capabilities */
static const tA2D_SBC_CIE a2d_sbc_caps =
{
    A2D_SBC_IE_SAMP_FREQ_44,            /* samp_freq */
    A2D_SBC_IE_CH_MD_JOINT,             /* ch_mode */
    A2D_SBC_IE_BLOCKS_16,               /* block_len */
    A2D_SBC_IE_SUBBAND_8,               /* num_subbands */
    A2D_SBC_IE_ALLOC_MD_L,              /* alloc_method */
    A2D_SBC_IE_MIN_BITPOOL,             /* min_bitpool */
    A2D_SBC_MAX_BITPOOL                 /* max_bitpool */
};

/* SBC SINK codec capabilities */
static const tA2D_SBC_CIE a2d_sbc_sink_caps =
{
    (A2D_SBC_IE_SAMP_FREQ_48 | A2D_SBC_IE_SAMP_FREQ_44),        /* samp_freq */
    (A2D_SBC_IE_CH_MD_MONO | A2D_SBC_IE_CH_MD_STEREO |
     A2D_SBC_IE_CH_MD_JOINT | A2D_SBC_IE_CH_MD_DUAL),           /* ch_mode */
    (A2D_SBC_IE_BLOCKS_16 | A2D_SBC_IE_BLOCKS_12 |
     A2D_SBC_IE_BLOCKS_8 | A2D_SBC_IE_BLOCKS_4),                /* block_len */
    (A2D_SBC_IE_SUBBAND_4 | A2D_SBC_IE_SUBBAND_8),      /* num_subbands */
    (A2D_SBC_IE_ALLOC_MD_L | A2D_SBC_IE_ALLOC_MD_S),    /* alloc_method */
    A2D_SBC_IE_MIN_BITPOOL,                             /* min_bitpool */
    A2D_SBC_IE_MAX_BITPOOL                              /* max_bitpool */
};

/* Default SBC codec configuration */
const tA2D_SBC_CIE a2d_sbc_default_config =
{
    A2D_SBC_IE_SAMP_FREQ_44,            /* samp_freq */
    A2D_SBC_IE_CH_MD_JOINT,             /* ch_mode */
    A2D_SBC_IE_BLOCKS_16,               /* block_len */
    A2D_SBC_IE_SUBBAND_8,               /* num_subbands */
    A2D_SBC_IE_ALLOC_MD_L,              /* alloc_method */
    A2D_SBC_IE_MIN_BITPOOL,             /* min_bitpool */
    A2D_SBC_MAX_BITPOOL                 /* max_bitpool */
};

static tA2D_STATUS A2D_CodecInfoMatchesCapabilitySbc(
        const tA2D_SBC_CIE *p_cap,
        const uint8_t *p_codec_info,
        bool is_peer_codec_info);

// Builds the SBC Media Codec Capabilities byte sequence beginning from the
// LOSC octet. |media_type| is the media type |AVDT_MEDIA_TYPE_*|.
// |p_ie| is a pointer to the SBC Codec Information Element information.
// The result is stored in |p_result|. Returns A2D_SUCCESS on success,
// otherwise the corresponding A2DP error status code.
static tA2D_STATUS A2D_BldSbcInfo(uint8_t media_type, const tA2D_SBC_CIE *p_ie,
                                  uint8_t *p_result)
{
    tA2D_STATUS status;

    if( p_ie == NULL || p_result == NULL ||
        (p_ie->samp_freq & ~A2D_SBC_IE_SAMP_FREQ_MSK) ||
        (p_ie->ch_mode & ~A2D_SBC_IE_CH_MD_MSK) ||
        (p_ie->block_len & ~A2D_SBC_IE_BLOCKS_MSK) ||
        (p_ie->num_subbands & ~A2D_SBC_IE_SUBBAND_MSK) ||
        (p_ie->alloc_method & ~A2D_SBC_IE_ALLOC_MD_MSK) ||
        (p_ie->min_bitpool > p_ie->max_bitpool) ||
        (p_ie->min_bitpool < A2D_SBC_IE_MIN_BITPOOL) ||
        (p_ie->min_bitpool > A2D_SBC_IE_MAX_BITPOOL) ||
        (p_ie->max_bitpool < A2D_SBC_IE_MIN_BITPOOL) ||
        (p_ie->max_bitpool > A2D_SBC_IE_MAX_BITPOOL))
    {
        /* if any unused bit is set */
        status = A2D_INVALID_PARAMS;
    }
    else
    {
        status = A2D_SUCCESS;
        *p_result++ = A2D_SBC_INFO_LEN;
        *p_result++ = (media_type << 4);
        *p_result++ = A2D_MEDIA_CT_SBC;

        /* Media Codec Specific Information Element */
        *p_result++ = p_ie->samp_freq | p_ie->ch_mode;

        *p_result++ = p_ie->block_len | p_ie->num_subbands | p_ie->alloc_method;

        *p_result++ = p_ie->min_bitpool;
        *p_result   = p_ie->max_bitpool;
    }
    return status;
}

// Parses the SBC Media Codec Capabilities byte sequence beginning from the
// LOSC octet. The result is stored in |p_ie|. The byte sequence to parse is
// |p_codec_info|. If |for_caps| is true, the byte sequence is for get
// capabilities response. Returns A2D_SUCCESS on success, otherwise the
// corresponding A2DP error status code.
static tA2D_STATUS A2D_ParsSbcInfo(tA2D_SBC_CIE *p_ie,
                                   const uint8_t *p_codec_info,
                                   bool is_peer_src_codec_info)
{
    tA2D_STATUS status = A2D_SUCCESS;
    uint8_t losc;
    uint8_t media_type;
    tA2D_CODEC_TYPE codec_type;

    if (p_ie == NULL || p_codec_info == NULL)
        return A2D_INVALID_PARAMS;

    // Check the codec capability length
    losc = *p_codec_info++;
    if (losc != A2D_SBC_INFO_LEN)
        return A2D_WRONG_CODEC;

    media_type = (*p_codec_info++) >> 4;
    codec_type = *p_codec_info++;
    /* Check the Media Type and Media Codec Type */
    if (media_type != AVDT_MEDIA_TYPE_AUDIO ||
        codec_type != A2D_MEDIA_CT_SBC) {
        return A2D_WRONG_CODEC;
    }

    p_ie->samp_freq = *p_codec_info & A2D_SBC_IE_SAMP_FREQ_MSK;
    p_ie->ch_mode   = *p_codec_info & A2D_SBC_IE_CH_MD_MSK;
    p_codec_info++;
    p_ie->block_len     = *p_codec_info & A2D_SBC_IE_BLOCKS_MSK;
    p_ie->num_subbands  = *p_codec_info & A2D_SBC_IE_SUBBAND_MSK;
    p_ie->alloc_method  = *p_codec_info & A2D_SBC_IE_ALLOC_MD_MSK;
    p_codec_info++;
    p_ie->min_bitpool = *p_codec_info++;
    p_ie->max_bitpool = *p_codec_info;
    if (p_ie->min_bitpool < A2D_SBC_IE_MIN_BITPOOL ||
        p_ie->min_bitpool > A2D_SBC_IE_MAX_BITPOOL) {
        status = A2D_BAD_MIN_BITPOOL;
    }

    if (p_ie->max_bitpool < A2D_SBC_IE_MIN_BITPOOL ||
        p_ie->max_bitpool > A2D_SBC_IE_MAX_BITPOOL ||
        p_ie->max_bitpool < p_ie->min_bitpool) {
        status = A2D_BAD_MAX_BITPOOL;
    }

    if (is_peer_src_codec_info)
        return status;

    if (A2D_BitsSet(p_ie->samp_freq) != A2D_SET_ONE_BIT)
        status = A2D_BAD_SAMP_FREQ;
    if (A2D_BitsSet(p_ie->ch_mode) != A2D_SET_ONE_BIT)
        status = A2D_BAD_CH_MODE;
    if (A2D_BitsSet(p_ie->block_len) != A2D_SET_ONE_BIT)
        status = A2D_BAD_BLOCK_LEN;
    if (A2D_BitsSet(p_ie->num_subbands) != A2D_SET_ONE_BIT)
        status = A2D_BAD_SUBBANDS;
    if (A2D_BitsSet(p_ie->alloc_method) != A2D_SET_ONE_BIT)
        status = A2D_BAD_ALLOC_METHOD;

    return status;
}

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
void A2D_BldSbcMplHdr(uint8_t *p_dst, bool frag, bool start, bool last, uint8_t num)
{
    if(p_dst)
    {
        *p_dst  = 0;
        if(frag)
            *p_dst  |= A2D_SBC_HDR_F_MSK;
        if(start)
            *p_dst  |= A2D_SBC_HDR_S_MSK;
        if(last)
            *p_dst  |= A2D_SBC_HDR_L_MSK;
        *p_dst  |= (A2D_SBC_HDR_NUM_MSK & num);
    }
}

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
void A2D_ParsSbcMplHdr(uint8_t *p_src, bool *p_frag, bool *p_start, bool *p_last, uint8_t *p_num)
{
    if(p_src && p_frag && p_start && p_last && p_num)
    {
        *p_frag = (*p_src & A2D_SBC_HDR_F_MSK) ? true: false;
        *p_start= (*p_src & A2D_SBC_HDR_S_MSK) ? true: false;
        *p_last = (*p_src & A2D_SBC_HDR_L_MSK) ? true: false;
        *p_num  = (*p_src & A2D_SBC_HDR_NUM_MSK);
    }
}

bool A2D_InitCodecConfigSbc(tAVDT_CFG *p_cfg)
{
    if (A2D_BldSbcInfo(AVDT_MEDIA_TYPE_AUDIO, &a2d_sbc_caps,
                       p_cfg->codec_info) != A2D_SUCCESS) {
        return false;
    }

#if (BTA_AV_CO_CP_SCMS_T == TRUE)
    /* Content protection info - support SCMS-T */
    uint8_t *p = p_cfg->protect_info;
    *p++ = BTA_AV_CP_LOSC;
    UINT16_TO_STREAM(p, BTA_AV_CP_SCMS_T_ID);
    p_cfg->num_protect = 1;
#endif

    return true;
}

bool A2D_InitCodecConfigSbcSink(tAVDT_CFG *p_cfg)
{
    if (A2D_BldSbcInfo(AVDT_MEDIA_TYPE_AUDIO, &a2d_sbc_sink_caps,
                       p_cfg->codec_info) != A2D_SUCCESS) {
        return false;
    }

    return true;
}

bool A2D_IsValidCodecSbc(const uint8_t *p_codec_info)
{
    tA2D_SBC_CIE cfg_cie;

    /* Use a liberal check when parsing the codec info */
    return (A2D_ParsSbcInfo(&cfg_cie, p_codec_info, false) == A2D_SUCCESS) ||
      (A2D_ParsSbcInfo(&cfg_cie, p_codec_info, true) == A2D_SUCCESS);
}

bool A2D_IsSourceCodecSupportedSbc(const uint8_t *p_codec_info)
{
    return (A2D_CodecInfoMatchesCapabilitySbc(&a2d_sbc_caps, p_codec_info,
                                              false) == A2D_SUCCESS);
}

bool A2D_IsSinkCodecSupportedSbc(const uint8_t *p_codec_info)
{
    return (A2D_CodecInfoMatchesCapabilitySbc(&a2d_sbc_sink_caps, p_codec_info,
                                              false) == A2D_SUCCESS);
}

bool A2D_IsPeerSourceCodecSupportedSbc(const uint8_t *p_codec_info)
{
    return (A2D_CodecInfoMatchesCapabilitySbc(&a2d_sbc_sink_caps, p_codec_info,
                                              true) == A2D_SUCCESS);
}

void A2D_InitDefaultCodecSbc(uint8_t *p_codec_info)
{
    if (A2D_BldSbcInfo(AVDT_MEDIA_TYPE_AUDIO, &a2d_sbc_default_config,
                       p_codec_info) != A2D_SUCCESS) {
        LOG_ERROR(LOG_TAG, "%s: A2D_BldSbcInfo failed", __func__);
    }
}

bool A2D_SetCodecSbc(const tA2D_AV_MEDIA_FEEDINGS *p_feeding,
                     uint8_t *p_codec_info)
{
    tA2D_SBC_CIE sbc_config;

    LOG_DEBUG(LOG_TAG, "%s: feeding_format = 0x%x",
              __func__, p_feeding->format);

    /* Supported feeding formats */
    switch (p_feeding->format) {
    case tA2D_AV_CODEC_PCM:
        sbc_config = a2d_sbc_default_config;
        if ((p_feeding->cfg.pcm.num_channel != 1) &&
            (p_feeding->cfg.pcm.num_channel != 2)) {
            LOG_ERROR(LOG_TAG, "%s: Unsupported PCM channel number %d",
                      __func__, p_feeding->cfg.pcm.num_channel);
            return false;
        }
        if ((p_feeding->cfg.pcm.bit_per_sample != 8) &&
            (p_feeding->cfg.pcm.bit_per_sample != 16)) {
            LOG_ERROR(LOG_TAG, "%s: Unsupported PCM sample size %d",
                      __func__, p_feeding->cfg.pcm.bit_per_sample);
            return false;
        }
        switch (p_feeding->cfg.pcm.sampling_freq) {
        case 8000:
        case 12000:
        case 16000:
        case 24000:
        case 32000:
        case 48000:
            sbc_config.samp_freq = A2D_SBC_IE_SAMP_FREQ_48;
            break;
        case 11025:
        case 22050:
        case 44100:
            sbc_config.samp_freq = A2D_SBC_IE_SAMP_FREQ_44;
            break;
        default:
            LOG_ERROR(LOG_TAG, "%s: Unsupported PCM sampling frequency %d",
                      __func__, p_feeding->cfg.pcm.sampling_freq);
            return false;
        }

        /* Build the codec config */
        if (A2D_BldSbcInfo(AVDT_MEDIA_TYPE_AUDIO, &sbc_config, p_codec_info)
            != A2D_SUCCESS) {
            LOG_ERROR(LOG_TAG, "%s: A2D_BldSbcInfo failed", __func__);
            return false;
        }
        break;

    default:
        LOG_ERROR(LOG_TAG, "%s: Unsupported feeding format 0x%x",
                  __func__, p_feeding->format);
        return false;
    }

    return true;
}

// Checks whether A2DP SBC codec configuration matches with a device's codec
// capabilities. |p_cap| is the SBC codec configuration. |p_codec_info| is
// the device's codec capabilities. |is_peer_src_codec_info| is true if
// |p_codec_info| contains the codec capabilities for a peer device that
// is acting as an A2DP source.
// Returns A2D_SUCCESS if the codec configuration matches with capabilities,
// otherwise the corresponding A2DP error status code.
static tA2D_STATUS A2D_CodecInfoMatchesCapabilitySbc(
        const tA2D_SBC_CIE *p_cap,
        const uint8_t *p_codec_info,
        bool is_peer_src_codec_info)
{
    tA2D_STATUS status;
    tA2D_SBC_CIE cfg_cie;

    /* parse configuration */
    status = A2D_ParsSbcInfo(&cfg_cie, p_codec_info, is_peer_src_codec_info);
    if (status != A2D_SUCCESS) {
        LOG_ERROR(LOG_TAG, "%s: parsing failed %d", __func__, status);
        return status;
    }

    /* verify that each parameter is in range */

    LOG_DEBUG(LOG_TAG, "FREQ peer: 0x%x, capability 0x%x",
              cfg_cie.samp_freq, p_cap->samp_freq);
    LOG_DEBUG(LOG_TAG, "CH_MODE peer: 0x%x, capability 0x%x",
              cfg_cie.ch_mode, p_cap->ch_mode);
    LOG_DEBUG(LOG_TAG, "BLOCK_LEN peer: 0x%x, capability 0x%x",
              cfg_cie.block_len, p_cap->block_len);
    LOG_DEBUG(LOG_TAG, "SUB_BAND peer: 0x%x, capability 0x%x",
              cfg_cie.num_subbands, p_cap->num_subbands);
    LOG_DEBUG(LOG_TAG, "ALLOC_METHOD peer: 0x%x, capability 0x%x",
              cfg_cie.alloc_method, p_cap->alloc_method);
    LOG_DEBUG(LOG_TAG, "MIN_BitPool peer: 0x%x, capability 0x%x",
              cfg_cie.min_bitpool, p_cap->min_bitpool);
    LOG_DEBUG(LOG_TAG, "MAX_BitPool peer: 0x%x, capability 0x%x",
              cfg_cie.max_bitpool, p_cap->max_bitpool);

    /* sampling frequency */
    if ((cfg_cie.samp_freq & p_cap->samp_freq) == 0)
        return A2D_NS_SAMP_FREQ;

    /* channel mode */
    if ((cfg_cie.ch_mode & p_cap->ch_mode) == 0)
        return A2D_NS_CH_MODE;

    /* block length */
    if ((cfg_cie.block_len & p_cap->block_len) == 0)
        return A2D_BAD_BLOCK_LEN;

    /* subbands */
    if ((cfg_cie.num_subbands & p_cap->num_subbands) == 0)
        return A2D_NS_SUBBANDS;

    /* allocation method */
    if ((cfg_cie.alloc_method & p_cap->alloc_method) == 0)
        return A2D_NS_ALLOC_METHOD;

    /* min bitpool */
    if (cfg_cie.min_bitpool < p_cap->min_bitpool)
        return A2D_NS_MIN_BITPOOL;

    /* max bitpool */
    if (cfg_cie.max_bitpool > p_cap->max_bitpool)
        return A2D_NS_MAX_BITPOOL;

    return A2D_SUCCESS;
}

// Builds A2DP preferred Sink capability from Source capability.
// |p_pref_cfg| is the result Sink capability to store. |p_src_cap| is
// the Source capability to use.
// Returns |A2D_SUCCESS| on success, otherwise the corresponding A2DP error
// status code.
tA2D_STATUS A2D_BuildSrc2SinkConfigSbc(uint8_t *p_pref_cfg,
                                       const uint8_t *p_src_cap)
{
    tA2D_SBC_CIE    src_cap;
    tA2D_SBC_CIE    pref_cap;

    /* initialize it to default SBC configuration */
    A2D_BldSbcInfo(AVDT_MEDIA_TYPE_AUDIO, &a2d_sbc_default_config, p_pref_cfg);

    /* now try to build a preferred one */
    /* parse configuration */
    tA2D_STATUS status = A2D_ParsSbcInfo(&src_cap, p_src_cap, true);
    if (status != A2D_SUCCESS) {
        LOG_ERROR(LOG_TAG, "%s: can't parse src cap ret = %d",
                  __func__, status);
        return A2D_FAIL;
    }

    if (src_cap.samp_freq & A2D_SBC_IE_SAMP_FREQ_48)
        pref_cap.samp_freq = A2D_SBC_IE_SAMP_FREQ_48;
    else if (src_cap.samp_freq & A2D_SBC_IE_SAMP_FREQ_44)
        pref_cap.samp_freq = A2D_SBC_IE_SAMP_FREQ_44;

    if (src_cap.ch_mode & A2D_SBC_IE_CH_MD_JOINT)
        pref_cap.ch_mode = A2D_SBC_IE_CH_MD_JOINT;
    else if (src_cap.ch_mode & A2D_SBC_IE_CH_MD_STEREO)
        pref_cap.ch_mode = A2D_SBC_IE_CH_MD_STEREO;
    else if (src_cap.ch_mode & A2D_SBC_IE_CH_MD_DUAL)
        pref_cap.ch_mode = A2D_SBC_IE_CH_MD_DUAL;
    else if (src_cap.ch_mode & A2D_SBC_IE_CH_MD_MONO)
        pref_cap.ch_mode = A2D_SBC_IE_CH_MD_MONO;

    if (src_cap.block_len & A2D_SBC_IE_BLOCKS_16)
        pref_cap.block_len = A2D_SBC_IE_BLOCKS_16;
    else if (src_cap.block_len & A2D_SBC_IE_BLOCKS_12)
        pref_cap.block_len = A2D_SBC_IE_BLOCKS_12;
    else if (src_cap.block_len & A2D_SBC_IE_BLOCKS_8)
        pref_cap.block_len = A2D_SBC_IE_BLOCKS_8;
    else if (src_cap.block_len & A2D_SBC_IE_BLOCKS_4)
        pref_cap.block_len = A2D_SBC_IE_BLOCKS_4;

    if (src_cap.num_subbands & A2D_SBC_IE_SUBBAND_8)
        pref_cap.num_subbands = A2D_SBC_IE_SUBBAND_8;
    else if(src_cap.num_subbands & A2D_SBC_IE_SUBBAND_4)
        pref_cap.num_subbands = A2D_SBC_IE_SUBBAND_4;

    if (src_cap.alloc_method & A2D_SBC_IE_ALLOC_MD_L)
        pref_cap.alloc_method = A2D_SBC_IE_ALLOC_MD_L;
    else if(src_cap.alloc_method & A2D_SBC_IE_ALLOC_MD_S)
        pref_cap.alloc_method = A2D_SBC_IE_ALLOC_MD_S;

    pref_cap.min_bitpool = src_cap.min_bitpool;
    pref_cap.max_bitpool = src_cap.max_bitpool;

    A2D_BldSbcInfo(AVDT_MEDIA_TYPE_AUDIO, &pref_cap, p_pref_cfg);

    return A2D_SUCCESS;
}

bool A2D_CodecTypeEqualsSbc(const uint8_t *p_codec_info_a,
                            const uint8_t *p_codec_info_b)
{
    tA2D_SBC_CIE sbc_cie_a;
    tA2D_SBC_CIE sbc_cie_b;

    // Check whether the codec info contains valid data
    tA2D_STATUS a2d_status = A2D_ParsSbcInfo(&sbc_cie_a, p_codec_info_a, false);
    if (a2d_status != A2D_SUCCESS) {
        LOG_ERROR(LOG_TAG, "%s: cannot decode codec information: %d",
                  __func__, a2d_status);
        return false;
    }
    a2d_status = A2D_ParsSbcInfo(&sbc_cie_b, p_codec_info_b, false);
    if (a2d_status != A2D_SUCCESS) {
        LOG_ERROR(LOG_TAG, "%s: cannot decode codec information: %d",
                  __func__, a2d_status);
        return false;
    }

    tA2D_CODEC_TYPE codec_type_a = A2D_GetCodecType(p_codec_info_a);
    tA2D_CODEC_TYPE codec_type_b = A2D_GetCodecType(p_codec_info_b);

    return (codec_type_a == codec_type_b) && (codec_type_a == A2D_MEDIA_CT_SBC);
}

int A2D_GetTrackFrequencySbc(const uint8_t *p_codec_info)
{
    tA2D_SBC_CIE sbc_cie;

    tA2D_STATUS a2d_status = A2D_ParsSbcInfo(&sbc_cie, p_codec_info, false);
    if (a2d_status != A2D_SUCCESS) {
        LOG_ERROR(LOG_TAG, "%s: cannot decode codec information: %d",
                  __func__, a2d_status);
        return -1;
    }

    switch (sbc_cie.samp_freq) {
    case A2D_SBC_IE_SAMP_FREQ_16:
        return 16000;
    case A2D_SBC_IE_SAMP_FREQ_32:
        return 32000;
    case A2D_SBC_IE_SAMP_FREQ_44:
        return 44100;
    case A2D_SBC_IE_SAMP_FREQ_48:
        return 48000;
    default:
        break;
    }

    return -1;
}

int A2D_GetTrackChannelCountSbc(const uint8_t *p_codec_info)
{
    tA2D_SBC_CIE sbc_cie;

    tA2D_STATUS a2d_status = A2D_ParsSbcInfo(&sbc_cie, p_codec_info, false);
    if (a2d_status != A2D_SUCCESS) {
        LOG_ERROR(LOG_TAG, "%s: cannot decode codec information: %d",
                  __func__, a2d_status);
        return -1;
    }

    switch (sbc_cie.ch_mode) {
    case A2D_SBC_IE_CH_MD_MONO:
        return 1;
    case A2D_SBC_IE_CH_MD_DUAL:
    case A2D_SBC_IE_CH_MD_STEREO:
    case A2D_SBC_IE_CH_MD_JOINT:
        return 2;
    default:
        break;
    }

    return -1;
}

int A2D_GetNumberOfSubbandsSbc(const uint8_t *p_codec_info)
{
    tA2D_SBC_CIE sbc_cie;

    tA2D_STATUS a2d_status = A2D_ParsSbcInfo(&sbc_cie, p_codec_info, false);
    if (a2d_status != A2D_SUCCESS) {
        LOG_ERROR(LOG_TAG, "%s: cannot decode codec information: %d",
                  __func__, a2d_status);
        return -1;
    }

    switch (sbc_cie.num_subbands) {
    case A2D_SBC_IE_SUBBAND_4:
        return 4;
    case A2D_SBC_IE_SUBBAND_8:
        return 8;
    default:
        break;
    }

    return -1;
}

int A2D_GetNumberOfBlocksSbc(const uint8_t *p_codec_info)
{
    tA2D_SBC_CIE sbc_cie;

    tA2D_STATUS a2d_status = A2D_ParsSbcInfo(&sbc_cie, p_codec_info, false);
    if (a2d_status != A2D_SUCCESS) {
        LOG_ERROR(LOG_TAG, "%s: cannot decode codec information: %d",
                  __func__, a2d_status);
        return -1;
    }

    switch (sbc_cie.block_len) {
    case A2D_SBC_IE_BLOCKS_4:
        return 4;
    case A2D_SBC_IE_BLOCKS_8:
        return 8;
    case A2D_SBC_IE_BLOCKS_12:
        return 12;
    case A2D_SBC_IE_BLOCKS_16:
        return 16;
    default:
        break;
    }

    return -1;
}

int A2D_GetAllocationMethodCodeSbc(const uint8_t *p_codec_info)
{
    tA2D_SBC_CIE sbc_cie;

    tA2D_STATUS a2d_status = A2D_ParsSbcInfo(&sbc_cie, p_codec_info, false);
    if (a2d_status != A2D_SUCCESS) {
        LOG_ERROR(LOG_TAG, "%s: cannot decode codec information: %d",
                  __func__, a2d_status);
        return -1;
    }

    switch (sbc_cie.alloc_method) {
    case A2D_SBC_IE_ALLOC_MD_S:
        return SBC_SNR;
    case A2D_SBC_IE_ALLOC_MD_L:
        return SBC_LOUDNESS;
    default:
        break;
    }

    return -1;
}

int A2D_GetChannelModeCodeSbc(const uint8_t *p_codec_info)
{
    tA2D_SBC_CIE sbc_cie;

    tA2D_STATUS a2d_status = A2D_ParsSbcInfo(&sbc_cie, p_codec_info, false);
    if (a2d_status != A2D_SUCCESS) {
        LOG_ERROR(LOG_TAG, "%s: cannot decode codec information: %d",
                  __func__, a2d_status);
        return -1;
    }

    switch (sbc_cie.ch_mode) {
    case A2D_SBC_IE_CH_MD_MONO:
        return SBC_MONO;
    case A2D_SBC_IE_CH_MD_DUAL:
        return SBC_DUAL;
    case A2D_SBC_IE_CH_MD_STEREO:
        return SBC_STEREO;
    case A2D_SBC_IE_CH_MD_JOINT:
        return SBC_JOINT_STEREO;
    default:
        break;
    }

    return -1;
}

int A2D_GetSamplingFrequencyCodeSbc(const uint8_t *p_codec_info)
{
    tA2D_SBC_CIE sbc_cie;

    tA2D_STATUS a2d_status = A2D_ParsSbcInfo(&sbc_cie, p_codec_info, false);
    if (a2d_status != A2D_SUCCESS) {
        LOG_ERROR(LOG_TAG, "%s: cannot decode codec information: %d",
                  __func__, a2d_status);
        return -1;
    }

    switch (sbc_cie.samp_freq) {
    case A2D_SBC_IE_SAMP_FREQ_16:
        return SBC_sf16000;
    case A2D_SBC_IE_SAMP_FREQ_32:
        return SBC_sf32000;
    case A2D_SBC_IE_SAMP_FREQ_44:
        return SBC_sf44100;
    case A2D_SBC_IE_SAMP_FREQ_48:
        return SBC_sf48000;
    default:
        break;
    }

    return -1;
}

int A2D_GetMinBitpoolSbc(const uint8_t *p_codec_info)
{
    tA2D_SBC_CIE sbc_cie;

    tA2D_STATUS a2d_status = A2D_ParsSbcInfo(&sbc_cie, p_codec_info, false);
    if (a2d_status != A2D_SUCCESS) {
        LOG_ERROR(LOG_TAG, "%s: cannot decode codec information: %d",
                  __func__, a2d_status);
        return -1;
    }

    return sbc_cie.min_bitpool;
}

int A2D_GetMaxBitpoolSbc(const uint8_t *p_codec_info)
{
    tA2D_SBC_CIE sbc_cie;

    tA2D_STATUS a2d_status = A2D_ParsSbcInfo(&sbc_cie, p_codec_info, false);
    if (a2d_status != A2D_SUCCESS) {
        LOG_ERROR(LOG_TAG, "%s: cannot decode codec information: %d",
                  __func__, a2d_status);
        return -1;
    }

    return sbc_cie.max_bitpool;
}

int A2D_GetSinkTrackChannelTypeSbc(const uint8_t *p_codec_info)
{
    tA2D_SBC_CIE sbc_cie;

    tA2D_STATUS a2d_status = A2D_ParsSbcInfo(&sbc_cie, p_codec_info, false);
    if (a2d_status != A2D_SUCCESS) {
        LOG_ERROR(LOG_TAG, "%s: cannot decode codec information: %d",
                  __func__, a2d_status);
        return -1;
    }

    switch (sbc_cie.ch_mode) {
    case A2D_SBC_IE_CH_MD_MONO:
        return 1;
    case A2D_SBC_IE_CH_MD_DUAL:
    case A2D_SBC_IE_CH_MD_STEREO:
    case A2D_SBC_IE_CH_MD_JOINT:
        return 3;
    default:
        break;
    }

    return -1;
}

int A2D_GetSinkFramesCountToProcessSbc(uint64_t time_interval_ms,
                                       const uint8_t *p_codec_info)
{
    tA2D_SBC_CIE sbc_cie;
    uint32_t freq_multiple;
    uint32_t num_blocks;
    uint32_t num_subbands;
    int frames_to_process;

    tA2D_STATUS a2d_status = A2D_ParsSbcInfo(&sbc_cie, p_codec_info, false);
    if (a2d_status != A2D_SUCCESS) {
        LOG_ERROR(LOG_TAG, "%s: cannot decode codec information: %d",
                  __func__, a2d_status);
        return -1;
    }

    // Check the sample frequency
    switch (sbc_cie.samp_freq) {
    case A2D_SBC_IE_SAMP_FREQ_16:
        LOG_DEBUG(LOG_TAG, "%s: samp_freq:%d (16000)", __func__,
                  sbc_cie.samp_freq);
        freq_multiple = 16 * time_interval_ms;
        break;
    case A2D_SBC_IE_SAMP_FREQ_32:
        LOG_DEBUG(LOG_TAG, "%s: samp_freq:%d (32000)", __func__,
                  sbc_cie.samp_freq);
        freq_multiple = 32 * time_interval_ms;
        break;
    case A2D_SBC_IE_SAMP_FREQ_44:
        LOG_DEBUG(LOG_TAG, "%s: samp_freq:%d (44100)", __func__,
                  sbc_cie.samp_freq);
        freq_multiple = (441 * time_interval_ms) / 10;
        break;
    case A2D_SBC_IE_SAMP_FREQ_48:
        LOG_DEBUG(LOG_TAG, "%s: samp_freq:%d (48000)", __func__,
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
    case A2D_SBC_IE_CH_MD_MONO:
        LOG_DEBUG(LOG_TAG, "%s: ch_mode:%d (Mono)", __func__,
                  sbc_cie.ch_mode);
        break;
    case A2D_SBC_IE_CH_MD_DUAL:
        LOG_DEBUG(LOG_TAG, "%s: ch_mode:%d (DUAL)", __func__,
                  sbc_cie.ch_mode);
        break;
    case A2D_SBC_IE_CH_MD_STEREO:
        LOG_DEBUG(LOG_TAG, "%s: ch_mode:%d (STEREO)", __func__,
                  sbc_cie.ch_mode);
        break;
    case A2D_SBC_IE_CH_MD_JOINT:
        LOG_DEBUG(LOG_TAG, "%s: ch_mode:%d (JOINT)", __func__,
                  sbc_cie.ch_mode);
        break;
    default:
        LOG_ERROR(LOG_TAG, "%s: unknown channel mode: %d", __func__,
                  sbc_cie.ch_mode);
        return -1;
    }

    // Check the block length
    switch (sbc_cie.block_len) {
    case A2D_SBC_IE_BLOCKS_4:
        LOG_DEBUG(LOG_TAG, "%s: block_len:%d (4)", __func__,
                  sbc_cie.block_len);
        num_blocks = 4;
        break;
    case A2D_SBC_IE_BLOCKS_8:
        LOG_DEBUG(LOG_TAG, "%s: block_len:%d (8)", __func__,
                  sbc_cie.block_len);
        num_blocks = 8;
        break;
    case A2D_SBC_IE_BLOCKS_12:
        LOG_DEBUG(LOG_TAG, "%s: block_len:%d (12)", __func__,
                  sbc_cie.block_len);
        num_blocks = 12;
        break;
    case A2D_SBC_IE_BLOCKS_16:
        LOG_DEBUG(LOG_TAG, "%s: block_len:%d (16)", __func__,
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
    case A2D_SBC_IE_SUBBAND_4:
        LOG_DEBUG(LOG_TAG, "%s: num_subbands:%d (4)", __func__,
                  sbc_cie.num_subbands);
        num_subbands = 4;
        break;
    case A2D_SBC_IE_SUBBAND_8:
        LOG_DEBUG(LOG_TAG, "%s: num_subbands:%d (8)", __func__,
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
    case A2D_SBC_IE_ALLOC_MD_S:
        LOG_DEBUG(LOG_TAG, "%s: alloc_method:%d (SNR)", __func__,
                  sbc_cie.alloc_method);
        break;
    case A2D_SBC_IE_ALLOC_MD_L:
        LOG_DEBUG(LOG_TAG, "%s: alloc_method:%d (Loudness)", __func__,
                  sbc_cie.alloc_method);
        break;
    default:
        LOG_ERROR(LOG_TAG, "%s: unknown allocation method: %d", __func__,
                  sbc_cie.alloc_method);
        return -1;
    }

    LOG_DEBUG(LOG_TAG, "%s: Bit pool Min:%d Max:%d", __func__,
              sbc_cie.min_bitpool, sbc_cie.max_bitpool);

    frames_to_process = ((freq_multiple) / (num_blocks * num_subbands)) + 1;

    return frames_to_process;
}

void A2D_DumpCodecInfoSbc(const uint8_t *p_codec_info)
{
    tA2D_STATUS a2d_status;
    tA2D_SBC_CIE sbc_cie;

    LOG_DEBUG(LOG_TAG, "%s", __func__);

    a2d_status = A2D_ParsSbcInfo(&sbc_cie, p_codec_info, false);
    if (a2d_status != A2D_SUCCESS) {
        LOG_ERROR(LOG_TAG, "%s: A2D_ParsSbcInfo fail:%d",
                  __func__, a2d_status);
        return;
    }

    if (sbc_cie.samp_freq == A2D_SBC_IE_SAMP_FREQ_16) {
        LOG_DEBUG(LOG_TAG, "\tsamp_freq:%d (16000)", sbc_cie.samp_freq);
    } else if (sbc_cie.samp_freq == A2D_SBC_IE_SAMP_FREQ_32) {
        LOG_DEBUG(LOG_TAG, "\tsamp_freq:%d (32000)", sbc_cie.samp_freq);
    } else if (sbc_cie.samp_freq == A2D_SBC_IE_SAMP_FREQ_44) {
        LOG_DEBUG(LOG_TAG, "\tsamp_freq:%d (44.100)", sbc_cie.samp_freq);
    } else if (sbc_cie.samp_freq == A2D_SBC_IE_SAMP_FREQ_48) {
        LOG_DEBUG(LOG_TAG, "\tsamp_freq:%d (48000)", sbc_cie.samp_freq);
    } else {
        LOG_DEBUG(LOG_TAG, "\tBAD samp_freq:%d", sbc_cie.samp_freq);
    }

    if (sbc_cie.ch_mode == A2D_SBC_IE_CH_MD_MONO) {
        LOG_DEBUG(LOG_TAG, "\tch_mode:%d (Mono)", sbc_cie.ch_mode);
    } else if (sbc_cie.ch_mode == A2D_SBC_IE_CH_MD_DUAL) {
        LOG_DEBUG(LOG_TAG, "\tch_mode:%d (Dual)", sbc_cie.ch_mode);
    } else if (sbc_cie.ch_mode == A2D_SBC_IE_CH_MD_STEREO) {
        LOG_DEBUG(LOG_TAG, "\tch_mode:%d (Stereo)", sbc_cie.ch_mode);
    } else if (sbc_cie.ch_mode == A2D_SBC_IE_CH_MD_JOINT) {
        LOG_DEBUG(LOG_TAG, "\tch_mode:%d (Joint)", sbc_cie.ch_mode);
    } else {
        LOG_DEBUG(LOG_TAG, "\tBAD ch_mode:%d", sbc_cie.ch_mode);
    }

    if (sbc_cie.block_len == A2D_SBC_IE_BLOCKS_4) {
        LOG_DEBUG(LOG_TAG, "\tblock_len:%d (4)", sbc_cie.block_len);
    } else if (sbc_cie.block_len == A2D_SBC_IE_BLOCKS_8) {
        LOG_DEBUG(LOG_TAG, "\tblock_len:%d (8)", sbc_cie.block_len);
    } else if (sbc_cie.block_len == A2D_SBC_IE_BLOCKS_12) {
        LOG_DEBUG(LOG_TAG, "\tblock_len:%d (12)", sbc_cie.block_len);
    } else if (sbc_cie.block_len == A2D_SBC_IE_BLOCKS_16) {
        LOG_DEBUG(LOG_TAG, "\tblock_len:%d (16)", sbc_cie.block_len);
    } else {
        LOG_DEBUG(LOG_TAG, "\tBAD block_len:%d", sbc_cie.block_len);
    }

    if (sbc_cie.num_subbands == A2D_SBC_IE_SUBBAND_4) {
        LOG_DEBUG(LOG_TAG, "\tnum_subbands:%d (4)", sbc_cie.num_subbands);
    } else if (sbc_cie.num_subbands == A2D_SBC_IE_SUBBAND_8) {
        LOG_DEBUG(LOG_TAG, "\tnum_subbands:%d (8)", sbc_cie.num_subbands);
    } else {
        LOG_DEBUG(LOG_TAG, "\tBAD num_subbands:%d", sbc_cie.num_subbands);
    }

    if (sbc_cie.alloc_method == A2D_SBC_IE_ALLOC_MD_S) {
        LOG_DEBUG(LOG_TAG, "\talloc_method:%d (SNR)", sbc_cie.alloc_method);
    } else if (sbc_cie.alloc_method == A2D_SBC_IE_ALLOC_MD_L) {
        LOG_DEBUG(LOG_TAG, "\talloc_method:%d (Loundess)", sbc_cie.alloc_method);
    } else {
        LOG_DEBUG(LOG_TAG, "\tBAD alloc_method:%d", sbc_cie.alloc_method);
    }

    LOG_DEBUG(LOG_TAG, "\tBit pool Min:%d Max:%d", sbc_cie.min_bitpool,
              sbc_cie.max_bitpool);
}
