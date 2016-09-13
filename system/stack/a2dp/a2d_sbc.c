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
#include "osi/include/log.h"

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
        bool is_peer_codec_info);


#define A2D_SBC_MAX_BITPOOL  53

/* SBC SRC codec capabilities */
static const tA2D_SBC_CIE a2d_sbc_caps =
{
    A2D_SBC_IE_SAMP_FREQ_44,            /* samp_freq */
    A2D_SBC_IE_CH_MD_JOINT,             /* ch_mode */
    A2D_SBC_IE_BLOCKS_16,               /* block_len */
    A2D_SBC_IE_SUBBAND_8,               /* num_subbands */
    A2D_SBC_IE_ALLOC_MD_L,              /* alloc_mthd */
    A2D_SBC_MAX_BITPOOL,                /* max_bitpool */
    A2D_SBC_IE_MIN_BITPOOL              /* min_bitpool */
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
    (A2D_SBC_IE_ALLOC_MD_L | A2D_SBC_IE_ALLOC_MD_S),    /* alloc_mthd */
    A2D_SBC_IE_MAX_BITPOOL,                             /* max_bitpool */
    A2D_SBC_IE_MIN_BITPOOL                              /* min_bitpool */
};

/* Default SBC codec configuration */
const tA2D_SBC_CIE a2d_sbc_default_config =
{
    A2D_SBC_IE_SAMP_FREQ_44,            /* samp_freq */
    A2D_SBC_IE_CH_MD_JOINT,             /* ch_mode */
    A2D_SBC_IE_BLOCKS_16,               /* block_len */
    A2D_SBC_IE_SUBBAND_8,               /* num_subbands */
    A2D_SBC_IE_ALLOC_MD_L,              /* alloc_mthd */
    A2D_SBC_MAX_BITPOOL,                /* max_bitpool */
    A2D_SBC_IE_MIN_BITPOOL              /* min_bitpool */
};

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
tA2D_STATUS A2D_BldSbcInfo(uint8_t media_type, const tA2D_SBC_CIE *p_ie,
                           uint8_t *p_result)
{
    tA2D_STATUS status;

    if( p_ie == NULL || p_result == NULL ||
        (p_ie->samp_freq & ~A2D_SBC_IE_SAMP_FREQ_MSK) ||
        (p_ie->ch_mode & ~A2D_SBC_IE_CH_MD_MSK) ||
        (p_ie->block_len & ~A2D_SBC_IE_BLOCKS_MSK) ||
        (p_ie->num_subbands & ~A2D_SBC_IE_SUBBAND_MSK) ||
        (p_ie->alloc_mthd & ~A2D_SBC_IE_ALLOC_MD_MSK) ||
        (p_ie->max_bitpool < p_ie->min_bitpool) ||
        (p_ie->max_bitpool < A2D_SBC_IE_MIN_BITPOOL) ||
        (p_ie->max_bitpool > A2D_SBC_IE_MAX_BITPOOL) ||
        (p_ie->min_bitpool < A2D_SBC_IE_MIN_BITPOOL) ||
        (p_ie->min_bitpool > A2D_SBC_IE_MAX_BITPOOL) )
    {
        /* if any unused bit is set */
        status = A2D_INVALID_PARAMS;
    }
    else
    {
        status = A2D_SUCCESS;
        *p_result++ = A2D_SBC_INFO_LEN;
        *p_result++ = media_type;
        *p_result++ = A2D_MEDIA_CT_SBC;

        /* Media Codec Specific Information Element */
        *p_result++ = p_ie->samp_freq | p_ie->ch_mode;

        *p_result++ = p_ie->block_len | p_ie->num_subbands | p_ie->alloc_mthd;

        *p_result++ = p_ie->min_bitpool;
        *p_result   = p_ie->max_bitpool;
    }
    return status;
}

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
tA2D_STATUS A2D_ParsSbcInfo(tA2D_SBC_CIE *p_ie, const uint8_t *p_codec_info,
                            bool is_peer_src_codec_info)
{
    tA2D_STATUS status = A2D_SUCCESS;
    uint8_t losc;

    if (p_ie == NULL || p_codec_info == NULL)
        return A2D_INVALID_PARAMS;

    losc = *p_codec_info;
    p_codec_info += 2;

    /* If the function is called for the wrong Media Type or Media Codec Type */
    if (losc != A2D_SBC_INFO_LEN || *p_codec_info != A2D_MEDIA_CT_SBC)
        return A2D_WRONG_CODEC;

    p_codec_info++;
    p_ie->samp_freq = *p_codec_info & A2D_SBC_IE_SAMP_FREQ_MSK;
    p_ie->ch_mode   = *p_codec_info & A2D_SBC_IE_CH_MD_MSK;
    p_codec_info++;
    p_ie->block_len     = *p_codec_info & A2D_SBC_IE_BLOCKS_MSK;
    p_ie->num_subbands  = *p_codec_info & A2D_SBC_IE_SUBBAND_MSK;
    p_ie->alloc_mthd    = *p_codec_info & A2D_SBC_IE_ALLOC_MD_MSK;
    p_codec_info++;
    p_ie->min_bitpool = *p_codec_info++;
    p_ie->max_bitpool = *p_codec_info;
    if (p_ie->min_bitpool < A2D_SBC_IE_MIN_BITPOOL || p_ie->min_bitpool > A2D_SBC_IE_MAX_BITPOOL )
        status = A2D_BAD_MIN_BITPOOL;

    if (p_ie->max_bitpool < A2D_SBC_IE_MIN_BITPOOL || p_ie->max_bitpool > A2D_SBC_IE_MAX_BITPOOL ||
         p_ie->max_bitpool < p_ie->min_bitpool)
        status = A2D_BAD_MAX_BITPOOL;

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
    if (A2D_BitsSet(p_ie->alloc_mthd) != A2D_SET_ONE_BIT)
        status = A2D_BAD_ALLOC_MTHD;

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

int A2D_sbc_get_track_frequency(uint8_t frequency) {
    int freq = 48000;
    switch (frequency) {
        case A2D_SBC_IE_SAMP_FREQ_16:
            freq = 16000;
            break;
        case A2D_SBC_IE_SAMP_FREQ_32:
            freq = 32000;
            break;
        case A2D_SBC_IE_SAMP_FREQ_44:
            freq = 44100;
            break;
        case A2D_SBC_IE_SAMP_FREQ_48:
            freq = 48000;
            break;
    }
    return freq;
}


bool A2D_InitCodecConfigSbc(tAVDT_CFG *p_cfg)
{
    if (A2D_BldSbcInfo(AVDT_MEDIA_AUDIO, &a2d_sbc_caps,
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
    if (A2D_BldSbcInfo(AVDT_MEDIA_AUDIO, &a2d_sbc_sink_caps,
                       p_cfg->codec_info) != A2D_SUCCESS) {
        return false;
    }

    return true;
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
    if (A2D_BldSbcInfo(A2D_MEDIA_TYPE_AUDIO, &a2d_sbc_default_config,
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
        if (A2D_BldSbcInfo(A2D_MEDIA_TYPE_AUDIO, &sbc_config, p_codec_info)
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
    LOG_DEBUG(LOG_TAG, "ALLOC_MTHD peer: 0x%x, capability 0x%x",
              cfg_cie.alloc_mthd, p_cap->alloc_mthd);
    LOG_DEBUG(LOG_TAG, "MAX_BitPool peer: 0x%x, capability 0x%x",
              cfg_cie.max_bitpool, p_cap->max_bitpool);
    LOG_DEBUG(LOG_TAG, "MIN_BitPool peer: 0x%x, capability 0x%x",
              cfg_cie.min_bitpool, p_cap->min_bitpool);

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
    if ((cfg_cie.alloc_mthd & p_cap->alloc_mthd) == 0)
        return A2D_NS_ALLOC_MTHD;

    /* max bitpool */
    if (cfg_cie.max_bitpool > p_cap->max_bitpool)
        return A2D_NS_MAX_BITPOOL;

    /* min bitpool */
    if (cfg_cie.min_bitpool < p_cap->min_bitpool)
        return A2D_NS_MIN_BITPOOL;

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
    A2D_BldSbcInfo(AVDT_MEDIA_AUDIO, &a2d_sbc_default_config, p_pref_cfg);

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

    if (src_cap.alloc_mthd & A2D_SBC_IE_ALLOC_MD_L)
        pref_cap.alloc_mthd = A2D_SBC_IE_ALLOC_MD_L;
    else if(src_cap.alloc_mthd & A2D_SBC_IE_ALLOC_MD_S)
        pref_cap.alloc_mthd = A2D_SBC_IE_ALLOC_MD_S;

    pref_cap.max_bitpool = src_cap.max_bitpool;
    pref_cap.min_bitpool = src_cap.min_bitpool;

    A2D_BldSbcInfo(AVDT_MEDIA_AUDIO, &pref_cap, p_pref_cfg);

    return A2D_SUCCESS;
}

const tA2D_SBC_CIE *A2D_GetDefaultConfigSbc()
{
    return &a2d_sbc_default_config;
}

int A2D_sbc_get_track_channel_count(uint8_t channeltype)
{
    int count = 1;
    switch (channeltype) {
        case A2D_SBC_IE_CH_MD_MONO:
            count = 1;
            break;
        case A2D_SBC_IE_CH_MD_DUAL:
        case A2D_SBC_IE_CH_MD_STEREO:
        case A2D_SBC_IE_CH_MD_JOINT:
            count = 2;
            break;
    }
    return count;
}

void A2D_sbc_dump_codec_info(unsigned char *p_codec)
{
    tA2D_STATUS a2d_status;
    tA2D_SBC_CIE sbc_cie;

    LOG_DEBUG(LOG_TAG, "%s", __func__);

    a2d_status = A2D_ParsSbcInfo(&sbc_cie, p_codec, false);
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

    if (sbc_cie.alloc_mthd == A2D_SBC_IE_ALLOC_MD_S) {
        LOG_DEBUG(LOG_TAG, "\talloc_mthd:%d (SNR)", sbc_cie.alloc_mthd);
    } else if (sbc_cie.alloc_mthd == A2D_SBC_IE_ALLOC_MD_L) {
        LOG_DEBUG(LOG_TAG, "\talloc_mthd:%d (Loundess)", sbc_cie.alloc_mthd);
    } else {
        LOG_DEBUG(LOG_TAG, "\tBAD alloc_mthd:%d", sbc_cie.alloc_mthd);
    }

    LOG_DEBUG(LOG_TAG, "\tBit pool Min:%d Max:%d", sbc_cie.min_bitpool,
              sbc_cie.max_bitpool);
}
