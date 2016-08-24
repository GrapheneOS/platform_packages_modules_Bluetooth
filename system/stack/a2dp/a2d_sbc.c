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

#include "bt_target.h"

#include <string.h>
#include "a2d_api.h"
#include "a2d_int.h"
#include "a2d_sbc.h"
#include "bt_utils.h"

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
tA2D_STATUS A2D_BldSbcInfo(uint8_t media_type, tA2D_SBC_CIE *p_ie, uint8_t *p_result)
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
**                      p_info:  the byte sequence to parse.
**
**                      for_caps:  true, if the byte sequence is for get capabilities response.
**
**                  Output Parameters:
**                      p_ie:  The SBC Codec Information Element information.
**
** Returns          A2D_SUCCESS if function execution succeeded.
**                  Error status code, otherwise.
******************************************************************************/
tA2D_STATUS A2D_ParsSbcInfo(tA2D_SBC_CIE *p_ie, const uint8_t *p_info,
                            bool for_caps)
{
    tA2D_STATUS status = A2D_SUCCESS;
    uint8_t losc;

    if (p_ie == NULL || p_info == NULL)
        return A2D_INVALID_PARAMS;

    losc = *p_info;
    p_info += 2;

    /* If the function is called for the wrong Media Type or Media Codec Type */
    if (losc != A2D_SBC_INFO_LEN || *p_info != A2D_MEDIA_CT_SBC)
        return A2D_WRONG_CODEC;

    p_info++;
    p_ie->samp_freq = *p_info & A2D_SBC_IE_SAMP_FREQ_MSK;
    p_ie->ch_mode   = *p_info & A2D_SBC_IE_CH_MD_MSK;
    p_info++;
    p_ie->block_len     = *p_info & A2D_SBC_IE_BLOCKS_MSK;
    p_ie->num_subbands  = *p_info & A2D_SBC_IE_SUBBAND_MSK;
    p_ie->alloc_mthd    = *p_info & A2D_SBC_IE_ALLOC_MD_MSK;
    p_info++;
    p_ie->min_bitpool = *p_info++;
    p_ie->max_bitpool = *p_info;
    if (p_ie->min_bitpool < A2D_SBC_IE_MIN_BITPOOL || p_ie->min_bitpool > A2D_SBC_IE_MAX_BITPOOL )
        status = A2D_BAD_MIN_BITPOOL;

    if (p_ie->max_bitpool < A2D_SBC_IE_MIN_BITPOOL || p_ie->max_bitpool > A2D_SBC_IE_MAX_BITPOOL ||
         p_ie->max_bitpool < p_ie->min_bitpool)
        status = A2D_BAD_MAX_BITPOOL;

    if (for_caps != false)
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

int A2D_sbc_get_track_channel_count(uint8_t channeltype) {
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

    APPL_TRACE_DEBUG("%s", __func__);

    a2d_status = A2D_ParsSbcInfo(&sbc_cie, p_codec, false);
    if (a2d_status != A2D_SUCCESS) {
        APPL_TRACE_ERROR("%s: A2D_ParsSbcInfo fail:%d", __func__, a2d_status);
        return;
    }

    if (sbc_cie.samp_freq == A2D_SBC_IE_SAMP_FREQ_16)
    {    APPL_TRACE_DEBUG("\tsamp_freq:%d (16000)", sbc_cie.samp_freq);}
    else  if (sbc_cie.samp_freq == A2D_SBC_IE_SAMP_FREQ_32)
    {    APPL_TRACE_DEBUG("\tsamp_freq:%d (32000)", sbc_cie.samp_freq);}
    else  if (sbc_cie.samp_freq == A2D_SBC_IE_SAMP_FREQ_44)
    {    APPL_TRACE_DEBUG("\tsamp_freq:%d (44.100)", sbc_cie.samp_freq);}
    else  if (sbc_cie.samp_freq == A2D_SBC_IE_SAMP_FREQ_48)
    {    APPL_TRACE_DEBUG("\tsamp_freq:%d (48000)", sbc_cie.samp_freq);}
    else
    {    APPL_TRACE_DEBUG("\tBAD samp_freq:%d", sbc_cie.samp_freq);}

    if (sbc_cie.ch_mode == A2D_SBC_IE_CH_MD_MONO)
    {    APPL_TRACE_DEBUG("\tch_mode:%d (Mono)", sbc_cie.ch_mode);}
    else  if (sbc_cie.ch_mode == A2D_SBC_IE_CH_MD_DUAL)
    {    APPL_TRACE_DEBUG("\tch_mode:%d (Dual)", sbc_cie.ch_mode);}
    else  if (sbc_cie.ch_mode == A2D_SBC_IE_CH_MD_STEREO)
    {    APPL_TRACE_DEBUG("\tch_mode:%d (Stereo)", sbc_cie.ch_mode);}
    else  if (sbc_cie.ch_mode == A2D_SBC_IE_CH_MD_JOINT)
    {    APPL_TRACE_DEBUG("\tch_mode:%d (Joint)", sbc_cie.ch_mode);}
    else
    {    APPL_TRACE_DEBUG("\tBAD ch_mode:%d", sbc_cie.ch_mode);}

    if (sbc_cie.block_len == A2D_SBC_IE_BLOCKS_4)
    {    APPL_TRACE_DEBUG("\tblock_len:%d (4)", sbc_cie.block_len);}
    else  if (sbc_cie.block_len == A2D_SBC_IE_BLOCKS_8)
    {    APPL_TRACE_DEBUG("\tblock_len:%d (8)", sbc_cie.block_len);}
    else  if (sbc_cie.block_len == A2D_SBC_IE_BLOCKS_12)
    {    APPL_TRACE_DEBUG("\tblock_len:%d (12)", sbc_cie.block_len);}
    else  if (sbc_cie.block_len == A2D_SBC_IE_BLOCKS_16)
    {    APPL_TRACE_DEBUG("\tblock_len:%d (16)", sbc_cie.block_len);}
    else
    {    APPL_TRACE_DEBUG("\tBAD block_len:%d", sbc_cie.block_len);}

    if (sbc_cie.num_subbands == A2D_SBC_IE_SUBBAND_4)
    {    APPL_TRACE_DEBUG("\tnum_subbands:%d (4)", sbc_cie.num_subbands);}
    else  if (sbc_cie.num_subbands == A2D_SBC_IE_SUBBAND_8)
    {    APPL_TRACE_DEBUG("\tnum_subbands:%d (8)", sbc_cie.num_subbands);}
    else
    {    APPL_TRACE_DEBUG("\tBAD num_subbands:%d", sbc_cie.num_subbands);}

    if (sbc_cie.alloc_mthd == A2D_SBC_IE_ALLOC_MD_S)
    {    APPL_TRACE_DEBUG("\talloc_mthd:%d (SNR)", sbc_cie.alloc_mthd);}
    else  if (sbc_cie.alloc_mthd == A2D_SBC_IE_ALLOC_MD_L)
    {    APPL_TRACE_DEBUG("\talloc_mthd:%d (Loundess)", sbc_cie.alloc_mthd);}
    else
    {    APPL_TRACE_DEBUG("\tBAD alloc_mthd:%d", sbc_cie.alloc_mthd);}

    APPL_TRACE_DEBUG("\tBit pool Min:%d Max:%d", sbc_cie.min_bitpool,
                     sbc_cie.max_bitpool);
}
