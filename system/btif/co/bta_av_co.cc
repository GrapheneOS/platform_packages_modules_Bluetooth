/******************************************************************************
 *
 *  Copyright (C) 2004-2012 Broadcom Corporation
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
 *  This is the advanced audio/video call-out function implementation for
 *  BTIF.
 *
 ******************************************************************************/

#include <string.h>
#include "a2d_api.h"
#include "bt_target.h"
#include "bta_sys.h"
#include "bta_av_api.h"
#include "bta_av_co.h"
#include "bta_av_ci.h"
#include "bta_av_sbc.h"

#include "btif_media.h"
#include "sbc_encoder.h"
#include "btif_av_co.h"
#include "btif_util.h"
#include "osi/include/mutex.h"


/*****************************************************************************
 **  Constants
 *****************************************************************************/

/* Macro to retrieve the number of elements in a statically allocated array */
#define BTA_AV_CO_NUM_ELEMENTS(__a) (sizeof(__a)/sizeof((__a)[0]))

/* MIN and MAX macros */
#define BTA_AV_CO_MIN(X,Y) ((X) < (Y) ? (X) : (Y))
#define BTA_AV_CO_MAX(X,Y) ((X) > (Y) ? (X) : (Y))

/* Macro to convert audio handle to index and vice versa */
#define BTA_AV_CO_AUDIO_HNDL_TO_INDX(hndl) (((hndl) & (~BTA_AV_CHNL_MSK)) - 1)
#define BTA_AV_CO_AUDIO_INDX_TO_HNDL(indx) (((indx) + 1) | BTA_AV_CHNL_AUDIO)


/* Offsets to access codec information in SBC codec */
#define BTA_AV_CO_SBC_FREQ_CHAN_OFF    3
#define BTA_AV_CO_SBC_BLOCK_BAND_OFF   4
#define BTA_AV_CO_SBC_MIN_BITPOOL_OFF  5
#define BTA_AV_CO_SBC_MAX_BITPOOL_OFF  6

/* SCMS-T protect info */
const uint8_t bta_av_co_cp_scmst[BTA_AV_CP_INFO_LEN] = {0x02, 0x02, 0x00};


/*****************************************************************************
**  Local data
*****************************************************************************/
typedef struct
{
    uint8_t sep_info_idx;                 /* local SEP index (in BTA tables) */
    uint8_t seid;                         /* peer SEP index (in peer tables) */
    uint8_t codec_type;                   /* peer SEP codec type */
    uint8_t codec_caps[AVDT_CODEC_SIZE];  /* peer SEP codec capabilities */
    uint8_t num_protect;                  /* peer SEP number of CP elements */
    uint8_t protect_info[BTA_AV_CP_INFO_LEN];  /* peer SEP content protection info */
} tBTA_AV_CO_SINK;

typedef struct
{
    BD_ADDR         addr;                 /* address of audio/video peer */
    tBTA_AV_CO_SINK snks[A2D_CODEC_SEP_INDEX_MAX]; /* array of supported sinks */
    tBTA_AV_CO_SINK srcs[A2D_CODEC_SEP_INDEX_MAX]; /* array of supported srcs */
    uint8_t           num_snks;           /* total number of sinks at peer */
    uint8_t           num_srcs;           /* total number of srcs at peer */
    uint8_t           num_seps;           /* total number of seids at peer */
    uint8_t           num_rx_snks;        /* number of received sinks */
    uint8_t           num_rx_srcs;        /* number of received srcs */
    uint8_t           num_sup_snks;       /* number of supported sinks in the snks array */
    uint8_t           num_sup_srcs;       /* number of supported srcs in the srcs array */
    tBTA_AV_CO_SINK *p_snk;             /* currently selected sink */
    tBTA_AV_CO_SINK *p_src;             /* currently selected src */
    uint8_t           codec_cfg[AVDT_CODEC_SIZE]; /* current codec configuration */
    bool         cp_active;          /* current CP configuration */
    bool         acp;                /* acceptor */
    bool         recfg_needed;       /* reconfiguration is needed */
    bool         opened;             /* opened */
    uint16_t          mtu;                /* maximum transmit unit size */
    uint16_t          uuid_to_connect;    /* uuid of peer device */
} tBTA_AV_CO_PEER;

typedef struct
{
    bool active;
    uint8_t flag;
} tBTA_AV_CO_CP;

typedef struct
{
    /* Connected peer information */
    tBTA_AV_CO_PEER peers[BTA_AV_NUM_STRS];
    /* Current codec configuration - access to this variable must be protected */
    tBTIF_AV_CODEC_INFO codec_cfg;
    tBTIF_AV_CODEC_INFO codec_cfg_setconfig; /* remote peer setconfig preference */

    tBTA_AV_CO_CP cp;
} tBTA_AV_CO_CB;

/* Control block instance */
static tBTA_AV_CO_CB bta_av_co_cb;

static bool bta_av_co_audio_codec_build_config(const uint8_t *p_codec_caps, uint8_t *p_codec_cfg);
static void bta_av_co_audio_peer_reset_config(tBTA_AV_CO_PEER *p_peer);
static bool bta_av_co_cp_is_scmst(const uint8_t *p_protectinfo);
static bool bta_av_co_audio_sink_has_scmst(const tBTA_AV_CO_SINK *p_sink);
static bool bta_av_co_audio_peer_supports_codec(tBTA_AV_CO_PEER *p_peer, uint8_t *p_snk_index);
static bool bta_av_co_audio_peer_src_supports_codec(tBTA_AV_CO_PEER *p_peer, uint8_t *p_src_index);


const uint8_t *bta_av_co_get_codec_info(void)
{
    return bta_av_co_cb.codec_cfg.info;
}

/*******************************************************************************
 **
 ** Function         bta_av_co_cp_is_active
 **
 ** Description      Get the current configuration of content protection
 **
 ** Returns          true if the current streaming has CP, false otherwise
 **
 *******************************************************************************/
bool bta_av_co_cp_is_active(void)
{
    return bta_av_co_cb.cp.active;
}

/*******************************************************************************
 **
 ** Function         bta_av_co_cp_get_flag
 **
 ** Description      Get content protection flag
 **                  BTA_AV_CP_SCMS_COPY_NEVER
 **                  BTA_AV_CP_SCMS_COPY_ONCE
 **                  BTA_AV_CP_SCMS_COPY_FREE
 **
 ** Returns          The current flag value
 **
 *******************************************************************************/
uint8_t bta_av_co_cp_get_flag(void)
{
    return bta_av_co_cb.cp.flag;
}

/*******************************************************************************
 **
 ** Function         bta_av_co_cp_set_flag
 **
 ** Description      Set content protection flag
 **                  BTA_AV_CP_SCMS_COPY_NEVER
 **                  BTA_AV_CP_SCMS_COPY_ONCE
 **                  BTA_AV_CP_SCMS_COPY_FREE
 **
 ** Returns          true if setting the SCMS flag is supported else false
 **
 *******************************************************************************/
bool bta_av_co_cp_set_flag(uint8_t cp_flag)
{
    APPL_TRACE_DEBUG("%s: cp_flag = %d", __func__, cp_flag);

#if (BTA_AV_CO_CP_SCMS_T == TRUE)
#else
    if (cp_flag != BTA_AV_CP_SCMS_COPY_FREE)
    {
        return false;
    }
#endif
    bta_av_co_cb.cp.flag = cp_flag;
    return true;
}

/*******************************************************************************
 **
 ** Function         bta_av_co_get_peer
 **
 ** Description      find the peer entry for a given handle
 **
 ** Returns          the control block
 **
 *******************************************************************************/
static tBTA_AV_CO_PEER *bta_av_co_get_peer(tBTA_AV_HNDL hndl)
{
    uint8_t index;

    index = BTA_AV_CO_AUDIO_HNDL_TO_INDX(hndl);

    APPL_TRACE_DEBUG("%s: handle = %d index = %d", __func__, hndl, index);

    /* Sanity check */
    if (index >= BTA_AV_CO_NUM_ELEMENTS(bta_av_co_cb.peers))
    {
        APPL_TRACE_ERROR("%s: peer index out of bounds: %d", __func__, index);
        return NULL;
    }

    return &bta_av_co_cb.peers[index];
}

/*******************************************************************************
 **
 ** Function         bta_av_co_audio_init
 **
 ** Description      This callout function is executed by AV when it is
 **                  started by calling BTA_AvRegister().  This function can be
 **                  used by the phone to initialize audio paths or for other
 **                  initialization purposes.
 **
 **
 ** Returns          Stream codec and content protection capabilities info.
 **
 *******************************************************************************/
bool bta_av_co_audio_init(tA2D_CODEC_SEP_INDEX codec_sep_index,
                          tAVDT_CFG *p_cfg)
{
    /* reset remote preference through setconfig */
    memset(bta_av_co_cb.codec_cfg_setconfig.info, 0,
           sizeof(bta_av_co_cb.codec_cfg_setconfig.info));
    bta_av_co_cb.codec_cfg_setconfig.id = tA2D_AV_CODEC_NONE;

    return A2D_InitCodecConfig(codec_sep_index, p_cfg);
}

/*******************************************************************************
 **
 ** Function         bta_av_co_audio_disc_res
 **
 ** Description      This callout function is executed by AV to report the
 **                  number of stream end points (SEP) were found during the
 **                  AVDT stream discovery process.
 **
 **
 ** Returns          void.
 **
 *******************************************************************************/
void bta_av_co_audio_disc_res(tBTA_AV_HNDL hndl, uint8_t num_seps, uint8_t num_snk,
        uint8_t num_src, BD_ADDR addr, uint16_t uuid_local)
{
    tBTA_AV_CO_PEER *p_peer;

    APPL_TRACE_DEBUG("%s: h:x%x num_seps:%d num_snk:%d num_src:%d",
                     __func__, hndl, num_seps, num_snk, num_src);

    /* Find the peer info */
    p_peer = bta_av_co_get_peer(hndl);
    if (p_peer == NULL)
    {
        APPL_TRACE_ERROR("%s: could not find peer entry", __func__);
        return;
    }

    /* Sanity check : this should never happen */
    if (p_peer->opened)
    {
        APPL_TRACE_ERROR("%s: peer already opened", __func__);
    }

    /* Copy the discovery results */
    bdcpy(p_peer->addr, addr);
    p_peer->num_snks = num_snk;
    p_peer->num_srcs = num_src;
    p_peer->num_seps = num_seps;
    p_peer->num_rx_snks = 0;
    p_peer->num_rx_srcs = 0;
    p_peer->num_sup_snks = 0;
    if (uuid_local == UUID_SERVCLASS_AUDIO_SINK)
        p_peer->uuid_to_connect = UUID_SERVCLASS_AUDIO_SOURCE;
    else if (uuid_local == UUID_SERVCLASS_AUDIO_SOURCE)
        p_peer->uuid_to_connect = UUID_SERVCLASS_AUDIO_SINK;
}

/*******************************************************************************
 **
 ** Function         bta_av_audio_sink_getconfig
 **
 ** Description      This callout function is executed by AV to retrieve the
 **                  desired codec and content protection configuration for the
 **                  A2DP Sink audio stream in Initiator.
 **
 **
 ** Returns          Pass or Fail for current getconfig.
 **
 *******************************************************************************/
tA2D_STATUS bta_av_audio_sink_getconfig(tBTA_AV_HNDL hndl,
                                        tA2D_CODEC_TYPE codec_type,
                                        uint8_t *p_codec_info,
                                        uint8_t *p_sep_info_idx, uint8_t seid,
                                        uint8_t *p_num_protect,
                                        uint8_t *p_protect_info)
{

    tA2D_STATUS result = A2D_FAIL;
    bool supported;
    tBTA_AV_CO_PEER *p_peer;
    tBTA_AV_CO_SINK *p_src;
    uint8_t pref_cfg[AVDT_CODEC_SIZE];
    uint8_t index;

    APPL_TRACE_DEBUG("%s: handle:0x%x codec_type:%d seid:%d",
                     __func__, hndl, codec_type, seid);
    APPL_TRACE_DEBUG("%s: num_protect:0x%02x protect_info:0x%02x%02x%02x",
                     __func__, *p_num_protect, p_protect_info[0],
                     p_protect_info[1], p_protect_info[2]);

    /* Retrieve the peer info */
    p_peer = bta_av_co_get_peer(hndl);
    if (p_peer == NULL)
    {
        APPL_TRACE_ERROR("%s: could not find peer entry", __func__);
        return A2D_FAIL;
    }

    APPL_TRACE_DEBUG("%s: peer(o=%d,n_snks=%d,n_rx_snks=%d,n_sup_snks=%d)",
                     __func__, p_peer->opened, p_peer->num_srcs,
                     p_peer->num_rx_srcs, p_peer->num_sup_srcs);

    p_peer->num_rx_srcs++;

    /* Check if this is a supported configuration */
    supported = false;
    switch (codec_type)
    {
        case A2D_MEDIA_CT_SBC:
            supported = true;
            break;

        default:
            break;
    }

    if (supported)
    {
        /* If there is room for a new one */
        if (p_peer->num_sup_srcs < BTA_AV_CO_NUM_ELEMENTS(p_peer->srcs))
        {
            p_src = &p_peer->srcs[p_peer->num_sup_srcs++];

            APPL_TRACE_DEBUG("%s: saved caps[%x:%x:%x:%x:%x:%x]",
                             __func__, p_codec_info[1], p_codec_info[2],
                             p_codec_info[3], p_codec_info[4], p_codec_info[5],
                             p_codec_info[6]);

            memcpy(p_src->codec_caps, p_codec_info, AVDT_CODEC_SIZE);
            p_src->codec_type = codec_type;
            p_src->sep_info_idx = *p_sep_info_idx;
            p_src->seid = seid;
            p_src->num_protect = *p_num_protect;
            memcpy(p_src->protect_info, p_protect_info, BTA_AV_CP_INFO_LEN);
        }
        else
        {
            APPL_TRACE_ERROR("%s: no more room for SRC info", __func__);
        }
    }

    /* If last SNK get capabilities or all supported codec caps retrieved */
    if ((p_peer->num_rx_srcs == p_peer->num_srcs) ||
        (p_peer->num_sup_srcs == BTA_AV_CO_NUM_ELEMENTS(p_peer->srcs)))
    {
        APPL_TRACE_DEBUG("%s: last SRC reached", __func__);

        /* Protect access to bta_av_co_cb.codec_cfg */
        mutex_global_lock();

        /* Find a src that matches the codec config */
        if (bta_av_co_audio_peer_src_supports_codec(p_peer, &index))
        {
            APPL_TRACE_DEBUG("%s: codec supported", __func__);
            p_src = &p_peer->srcs[index];

            /* Build the codec configuration for this sink */
            {
                /* Save the new configuration */
                p_peer->p_src = p_src;
                /* get preferred config from src_caps */
                if (A2D_BuildSrc2SinkConfig(pref_cfg, p_src->codec_caps) !=
                    A2D_SUCCESS) {
                    mutex_global_unlock();
                    return A2D_FAIL;
                }
                memcpy(p_peer->codec_cfg, pref_cfg, AVDT_CODEC_SIZE);

                APPL_TRACE_DEBUG("%s: p_codec_info[%x:%x:%x:%x:%x:%x]",
                                 __func__, p_peer->codec_cfg[1],
                                 p_peer->codec_cfg[2], p_peer->codec_cfg[3],
                                 p_peer->codec_cfg[4], p_peer->codec_cfg[5],
                                 p_peer->codec_cfg[6]);
                /* By default, no content protection */
                *p_num_protect = 0;

#if (BTA_AV_CO_CP_SCMS_T == TRUE)
                    p_peer->cp_active = false;
                    bta_av_co_cb.cp.active = false;
#endif

                    *p_sep_info_idx = p_src->sep_info_idx;
                    memcpy(p_codec_info, p_peer->codec_cfg, AVDT_CODEC_SIZE);
                result =  A2D_SUCCESS;
            }
        }
        /* Protect access to bta_av_co_cb.codec_cfg */
        mutex_global_unlock();
    }
    return result;
}
/*******************************************************************************
 **
 ** Function         bta_av_co_audio_getconfig
 **
 ** Description      This callout function is executed by AV to retrieve the
 **                  desired codec and content protection configuration for the
 **                  audio stream.
 **
 **
 ** Returns          Stream codec and content protection configuration info.
 **
 *******************************************************************************/
tA2D_STATUS bta_av_co_audio_getconfig(tBTA_AV_HNDL hndl,
                                      tA2D_CODEC_TYPE codec_type,
                                      uint8_t *p_codec_info,
                                      uint8_t *p_sep_info_idx, uint8_t seid,
                                      uint8_t *p_num_protect,
                                      uint8_t *p_protect_info)
{
    tA2D_STATUS result = A2D_FAIL;
    bool supported;
    tBTA_AV_CO_PEER *p_peer;
    tBTA_AV_CO_SINK *p_sink;
    uint8_t codec_cfg[AVDT_CODEC_SIZE];
    uint8_t index;

    APPL_TRACE_DEBUG("%s: codec_type = %d", __func__, codec_type);

    /* Retrieve the peer info */
    p_peer = bta_av_co_get_peer(hndl);
    if (p_peer == NULL)
    {
        APPL_TRACE_ERROR("%s: could not find peer entry", __func__);
        return A2D_FAIL;
    }

    if (p_peer->uuid_to_connect == UUID_SERVCLASS_AUDIO_SOURCE)
    {
        result = bta_av_audio_sink_getconfig(hndl, codec_type, p_codec_info,
                                             p_sep_info_idx, seid,
                                             p_num_protect, p_protect_info);
        return result;
    }
    APPL_TRACE_DEBUG("%s: handle:0x%x codec_type:%d seid:%d",
                     __func__, hndl, codec_type, seid);
    APPL_TRACE_DEBUG("%s: num_protect:0x%02x protect_info:0x%02x%02x%02x",
                     __func__, *p_num_protect, p_protect_info[0],
                     p_protect_info[1], p_protect_info[2]);
    APPL_TRACE_DEBUG("%s: peer(o=%d, n_snks=%d, n_rx_snks=%d, n_sup_snks=%d)",
                     __func__, p_peer->opened, p_peer->num_snks,
                     p_peer->num_rx_snks, p_peer->num_sup_snks);

    p_peer->num_rx_snks++;

    /* Check if this is a supported configuration */
    supported = false;
    switch (codec_type)
    {
    case A2D_MEDIA_CT_SBC:
        supported = true;
        break;

    default:
        break;
    }

    if (supported)
    {
        /* If there is room for a new one */
        if (p_peer->num_sup_snks < BTA_AV_CO_NUM_ELEMENTS(p_peer->snks))
        {
            p_sink = &p_peer->snks[p_peer->num_sup_snks++];

            APPL_TRACE_DEBUG("%s: saved caps[%x:%x:%x:%x:%x:%x]", __func__,
                    p_codec_info[1], p_codec_info[2], p_codec_info[3],
                    p_codec_info[4], p_codec_info[5], p_codec_info[6]);

            memcpy(p_sink->codec_caps, p_codec_info, AVDT_CODEC_SIZE);
            p_sink->codec_type = codec_type;
            p_sink->sep_info_idx = *p_sep_info_idx;
            p_sink->seid = seid;
            p_sink->num_protect = *p_num_protect;
            memcpy(p_sink->protect_info, p_protect_info, BTA_AV_CP_INFO_LEN);
        } else {
            APPL_TRACE_ERROR("%s: no more room for SNK info", __func__);
        }
    }

    /* If last SNK get capabilities or all supported codec capa retrieved */
    if ((p_peer->num_rx_snks == p_peer->num_snks) ||
        (p_peer->num_sup_snks == BTA_AV_CO_NUM_ELEMENTS(p_peer->snks)))
    {
        APPL_TRACE_DEBUG("%s: last sink reached", __func__);

        /* Protect access to bta_av_co_cb.codec_cfg */
        mutex_global_lock();

        /* Find a sink that matches the codec config */
        if (bta_av_co_audio_peer_supports_codec(p_peer, &index))
        {
            /* stop fetching caps once we retrieved a supported codec */
            if (p_peer->acp)
            {
                *p_sep_info_idx = p_peer->num_seps;
                APPL_TRACE_EVENT("%s: no need to fetch more SEPs", __func__);
            }

            p_sink = &p_peer->snks[index];

            /* Build the codec configuration for this sink */
            if (bta_av_co_audio_codec_build_config(p_sink->codec_caps, codec_cfg))
            {
                APPL_TRACE_DEBUG("%s: reconfig codec_cfg[%x:%x:%x:%x:%x:%x]",
                        __func__,
                        codec_cfg[1], codec_cfg[2], codec_cfg[3],
                        codec_cfg[4], codec_cfg[5], codec_cfg[6]);
                for (int i = 0; i < AVDT_CODEC_SIZE; i++) {
                    APPL_TRACE_DEBUG("%s: p_codec_info[%d]: %x",
                                     __func__, i,  p_codec_info[i]);
                }

                /* Save the new configuration */
                p_peer->p_snk = p_sink;
                memcpy(p_peer->codec_cfg, codec_cfg, AVDT_CODEC_SIZE);

                /* By default, no content protection */
                *p_num_protect = 0;

#if (BTA_AV_CO_CP_SCMS_T == TRUE)
                /* Check if this sink supports SCMS */
                if (bta_av_co_audio_sink_has_scmst(p_sink))
                {
                    p_peer->cp_active = true;
                    bta_av_co_cb.cp.active = true;
                    *p_num_protect = BTA_AV_CP_INFO_LEN;
                    memcpy(p_protect_info, bta_av_co_cp_scmst, BTA_AV_CP_INFO_LEN);
                }
                else
                {
                    p_peer->cp_active = false;
                    bta_av_co_cb.cp.active = false;
                }
#endif

                /* If acceptor -> reconfig otherwise reply for configuration */
                if (p_peer->acp)
                {
                    if (p_peer->recfg_needed)
                    {
                        APPL_TRACE_DEBUG("%s: call BTA_AvReconfig(x%x)",
                                         __func__, hndl);
                        BTA_AvReconfig(hndl, true, p_sink->sep_info_idx, p_peer->codec_cfg, *p_num_protect, (uint8_t *)bta_av_co_cp_scmst);
                    }
                }
                else
                {
                    *p_sep_info_idx = p_sink->sep_info_idx;
                    memcpy(p_codec_info, p_peer->codec_cfg, AVDT_CODEC_SIZE);
                }
                result =  A2D_SUCCESS;
            }
        }
        /* Protect access to bta_av_co_cb.codec_cfg */
        mutex_global_unlock();
    }
    return result;
}

/*******************************************************************************
 **
 ** Function         bta_av_co_audio_setconfig
 **
 ** Description      This callout function is executed by AV to set the codec and
 **                  content protection configuration of the audio stream.
 **
 **
 ** Returns          void
 **
 *******************************************************************************/
void bta_av_co_audio_setconfig(tBTA_AV_HNDL hndl, tA2D_CODEC_TYPE codec_type,
                               uint8_t *p_codec_info, uint8_t seid,
                               BD_ADDR addr, uint8_t num_protect,
                               uint8_t *p_protect_info, uint8_t t_local_sep,
                               uint8_t avdt_handle)
{
    tBTA_AV_CO_PEER *p_peer;
    tA2D_STATUS status = A2D_SUCCESS;
    uint8_t category = A2D_SUCCESS;
    bool recfg_needed = false;
    bool codec_cfg_supported = false;
    UNUSED(seid);
    UNUSED(addr);

    APPL_TRACE_DEBUG("%s: p_codec_info[%x:%x:%x:%x:%x:%x]",
            __func__,
            p_codec_info[1], p_codec_info[2], p_codec_info[3],
            p_codec_info[4], p_codec_info[5], p_codec_info[6]);
    APPL_TRACE_DEBUG("num_protect:0x%02x protect_info:0x%02x%02x%02x",
        num_protect, p_protect_info[0], p_protect_info[1], p_protect_info[2]);

    /* Retrieve the peer info */
    p_peer = bta_av_co_get_peer(hndl);
    if (p_peer == NULL)
    {
        APPL_TRACE_ERROR("%s: could not find peer entry", __func__);

        /* Call call-in rejecting the configuration */
        bta_av_ci_setconfig(hndl, A2D_BUSY, AVDT_ASC_CODEC, 0, NULL, false, avdt_handle);
        return;
    }
    APPL_TRACE_DEBUG("%s: peer(o=%d, n_snks=%d, n_rx_snks=%d, n_sup_snks=%d)",
                     __func__, p_peer->opened, p_peer->num_snks,
                     p_peer->num_rx_snks, p_peer->num_sup_snks);

    /* Sanity check: should not be opened at this point */
    if (p_peer->opened)
    {
        APPL_TRACE_ERROR("%s: peer already in use", __func__);
    }

#if (BTA_AV_CO_CP_SCMS_T == TRUE)
    if (num_protect != 0)
    {
        /* If CP is supported */
        if ((num_protect != 1) ||
            (bta_av_co_cp_is_scmst(p_protect_info) == false))
        {
            APPL_TRACE_ERROR("%s: wrong CP configuration", __func__);
            status = A2D_BAD_CP_TYPE;
            category = AVDT_ASC_PROTECT;
        }
    }
#else
    /* Do not support content protection for the time being */
    if (num_protect != 0)
    {
        APPL_TRACE_ERROR("%s: wrong CP configuration", __func__);
        status = A2D_BAD_CP_TYPE;
        category = AVDT_ASC_PROTECT;
    }
#endif
    if (status == A2D_SUCCESS)
    {
        if(AVDT_TSEP_SNK == t_local_sep)
        {
            codec_cfg_supported = A2D_IsSinkCodecSupported(p_codec_info);
            APPL_TRACE_DEBUG("%s: peer is A2DP SRC", __func__);
        }
        if(AVDT_TSEP_SRC == t_local_sep)
        {
            codec_cfg_supported = A2D_IsSourceCodecSupported(p_codec_info);
            APPL_TRACE_DEBUG("%s: peer is A2DP SINK", __func__);
        }
        /* Check if codec configuration is supported */
        if (codec_cfg_supported)
        {

            /* Protect access to bta_av_co_cb.codec_cfg */
            mutex_global_lock();

            /* Check if the configuration matches the current codec config */
            switch (bta_av_co_cb.codec_cfg.id)
            {
            case A2D_MEDIA_CT_SBC:
                if ((codec_type != A2D_MEDIA_CT_SBC) ||
                    memcmp(p_codec_info, bta_av_co_cb.codec_cfg.info, 5)) {
                    recfg_needed = true;
                } else if ((num_protect == 1) && (!bta_av_co_cb.cp.active)) {
                    recfg_needed = true;
                }

                /* if remote side requests a restricted notify sinks preferred bitpool range as all other params are
                   already checked for validify */
                APPL_TRACE_DEBUG("%s: SBC", __func__);
                APPL_TRACE_EVENT("%s: remote peer setconfig bitpool range [%d:%d]",
                                 __func__,
                                 p_codec_info[BTA_AV_CO_SBC_MIN_BITPOOL_OFF],
                                 p_codec_info[BTA_AV_CO_SBC_MAX_BITPOOL_OFF]);

                bta_av_co_cb.codec_cfg_setconfig.id = A2D_MEDIA_CT_SBC;
                memcpy(bta_av_co_cb.codec_cfg_setconfig.info, p_codec_info, AVDT_CODEC_SIZE);
                if(AVDT_TSEP_SNK == t_local_sep)
                {
                    /* If Peer is SRC, and our cfg subset matches with what is requested by peer, then
                                         just accept what peer wants */
                    memcpy(bta_av_co_cb.codec_cfg.info, p_codec_info, AVDT_CODEC_SIZE);
                    recfg_needed = false;
                }
                break;


            default:
                APPL_TRACE_ERROR("%s: unsupported cid %d", __func__,
                                 bta_av_co_cb.codec_cfg.id);
                recfg_needed = true;
                break;
            }
            /* Protect access to bta_av_co_cb.codec_cfg */
            mutex_global_unlock();
        }
        else
        {
            category = AVDT_ASC_CODEC;
            status = A2D_WRONG_CODEC;
        }
    }

    if (status != A2D_SUCCESS)
    {
        APPL_TRACE_DEBUG("%s: reject s=%d c=%d", __func__, status, category);

        /* Call call-in rejecting the configuration */
        bta_av_ci_setconfig(hndl, status, category, 0, NULL, false, avdt_handle);
    }
    else
    {
        /* Mark that this is an acceptor peer */
        p_peer->acp = true;
        p_peer->recfg_needed = recfg_needed;

        APPL_TRACE_DEBUG("%s: accept reconf=%d", __func__, recfg_needed);

        /* Call call-in accepting the configuration */
        bta_av_ci_setconfig(hndl, A2D_SUCCESS, A2D_SUCCESS, 0, NULL, recfg_needed, avdt_handle);
    }
}

/*******************************************************************************
 **
 ** Function         bta_av_co_audio_open
 **
 ** Description      This function is called by AV when the audio stream connection
 **                  is opened.
 **
 **
 ** Returns          void
 **
 *******************************************************************************/
void bta_av_co_audio_open(tBTA_AV_HNDL hndl, tA2D_CODEC_TYPE codec_type,
                          uint8_t *p_codec_info, uint16_t mtu)
{
    tBTA_AV_CO_PEER *p_peer;
    UNUSED(p_codec_info);

    APPL_TRACE_DEBUG("%s: mtu:%d codec_type:%d", __func__, mtu, codec_type);

    /* Retrieve the peer info */
    p_peer = bta_av_co_get_peer(hndl);
    if (p_peer == NULL)
    {
        APPL_TRACE_ERROR("%s: could not find peer entry", __func__);
    }
    else
    {
        p_peer->opened = true;
        p_peer->mtu = mtu;
    }
}

/*******************************************************************************
 **
 ** Function         bta_av_co_audio_close
 **
 ** Description      This function is called by AV when the audio stream connection
 **                  is closed.
 **
 **
 ** Returns          void
 **
 *******************************************************************************/
void bta_av_co_audio_close(tBTA_AV_HNDL hndl, tA2D_CODEC_TYPE codec_type,
                           uint16_t mtu)

{
    tBTA_AV_CO_PEER *p_peer;
    UNUSED(codec_type);
    UNUSED(mtu);

    APPL_TRACE_DEBUG("%s", __func__);

    /* Retrieve the peer info */
    p_peer = bta_av_co_get_peer(hndl);
    if (p_peer)
    {
        /* Mark the peer closed and clean the peer info */
        memset(p_peer, 0, sizeof(*p_peer));
    }
    else
    {
        APPL_TRACE_ERROR("%s: could not find peer entry", __func__);
    }

    /* reset remote preference through setconfig */
    memset(bta_av_co_cb.codec_cfg_setconfig.info, 0,
           sizeof(bta_av_co_cb.codec_cfg_setconfig.info));
    bta_av_co_cb.codec_cfg_setconfig.id = tA2D_AV_CODEC_NONE;
}

/*******************************************************************************
 **
 ** Function         bta_av_co_audio_start
 **
 ** Description      This function is called by AV when the audio streaming data
 **                  transfer is started.
 **
 **
 ** Returns          void
 **
 *******************************************************************************/
void bta_av_co_audio_start(tBTA_AV_HNDL hndl, tA2D_CODEC_TYPE codec_type,
                           uint8_t *p_codec_info, bool *p_no_rtp_hdr)
{
    UNUSED(hndl);
    UNUSED(codec_type);
    UNUSED(p_codec_info);
    UNUSED(p_no_rtp_hdr);

    APPL_TRACE_DEBUG("%s", __func__);
}

/*******************************************************************************
 **
 ** Function         bta_av_co_audio_stop
 **
 ** Description      This function is called by AV when the audio streaming data
 **                  transfer is stopped.
 **
 **
 ** Returns          void
 **
 *******************************************************************************/
void bta_av_co_audio_stop(tBTA_AV_HNDL hndl, tA2D_CODEC_TYPE codec_type)
{
    UNUSED(hndl);
    UNUSED(codec_type);

    APPL_TRACE_DEBUG("%s", __func__);
}

/*******************************************************************************
 **
 ** Function         bta_av_co_audio_src_data_path
 **
 ** Description      This function is called to manage data transfer from
 **                  the audio codec to AVDTP.
 **
 ** Returns          Pointer to the GKI buffer to send, NULL if no buffer to send
 **
 *******************************************************************************/
void * bta_av_co_audio_src_data_path(tA2D_CODEC_TYPE codec_type,
                                     uint32_t *p_len, uint32_t *p_timestamp)
{
    BT_HDR *p_buf;
    UNUSED(p_len);

    APPL_TRACE_DEBUG("%s: codec_type = %d", __func__, codec_type);

    p_buf = btif_media_aa_readbuf();
    if (p_buf != NULL)
    {
        switch (codec_type)
        {
        case A2D_MEDIA_CT_SBC:
            /* In media packet SBC, the following information is available:
             * p_buf->layer_specific : number of SBC frames in the packet
             * p_buf->word[0] : timestamp
             */
            /* Retrieve the timestamp information from the media packet */
            *p_timestamp = *((uint32_t *) (p_buf + 1));

            /* Set up packet header */
            bta_av_sbc_bld_hdr(p_buf, p_buf->layer_specific);
            break;


        default:
            APPL_TRACE_ERROR("%s: unsupported codec type (%d)", __func__,
                             codec_type);
            break;
        }
#if (BTA_AV_CO_CP_SCMS_T == TRUE)
        {
            uint8_t *p;
            if (bta_av_co_cp_is_active())
            {
                p_buf->len++;
                p_buf->offset--;
                p = (uint8_t *)(p_buf + 1) + p_buf->offset;
                *p = bta_av_co_cp_get_flag();
            }
        }
#endif
    }
    return p_buf;
}

/*******************************************************************************
 **
 ** Function         bta_av_co_audio_drop
 **
 ** Description      An Audio packet is dropped. .
 **                  It's very likely that the connected headset with this handle
 **                  is moved far away. The implementation may want to reduce
 **                  the encoder bit rate setting to reduce the packet size.
 **
 ** Returns          void
 **
 *******************************************************************************/
void bta_av_co_audio_drop(tBTA_AV_HNDL hndl)
{
    APPL_TRACE_ERROR("%s: dropped audio packet on handle 0x%x",
                     __func__, hndl);
}

/*******************************************************************************
 **
 ** Function         bta_av_co_audio_delay
 **
 ** Description      This function is called by AV when the audio stream connection
 **                  needs to send the initial delay report to the connected SRC.
 **
 **
 ** Returns          void
 **
 *******************************************************************************/
void bta_av_co_audio_delay(tBTA_AV_HNDL hndl, uint16_t delay)
{
    APPL_TRACE_ERROR("%s: handle: x%x, delay:0x%x", __func__, hndl, delay);
}



/*******************************************************************************
 **
 ** Function         bta_av_co_audio_codec_build_config
 **
 ** Description      Build the codec configuration
 **
 ** Returns          true if the codec was built successfully, false otherwise
 **
 *******************************************************************************/
static bool bta_av_co_audio_codec_build_config(const uint8_t *p_codec_caps, uint8_t *p_codec_cfg)
{
    APPL_TRACE_DEBUG("%s", __func__);

    memset(p_codec_cfg, 0, AVDT_CODEC_SIZE);

    switch (bta_av_co_cb.codec_cfg.id) {
    case A2D_MEDIA_CT_SBC:
        /*  only copy the relevant portions for this codec to avoid issues when
            comparing codec configs covering larger codec sets than SBC (7 bytes) */
        memcpy(p_codec_cfg, bta_av_co_cb.codec_cfg.info, BTA_AV_CO_SBC_MAX_BITPOOL_OFF+1);

        /* Update the bit pool boundaries with the codec capabilities */
        p_codec_cfg[BTA_AV_CO_SBC_MIN_BITPOOL_OFF] = p_codec_caps[BTA_AV_CO_SBC_MIN_BITPOOL_OFF];
        p_codec_cfg[BTA_AV_CO_SBC_MAX_BITPOOL_OFF] = p_codec_caps[BTA_AV_CO_SBC_MAX_BITPOOL_OFF];

        APPL_TRACE_DEBUG("%s: SBC", __func__);
        APPL_TRACE_EVENT("%s: bitpool min %d, max %d", __func__,
                         p_codec_cfg[BTA_AV_CO_SBC_MIN_BITPOOL_OFF],
                         p_codec_caps[BTA_AV_CO_SBC_MAX_BITPOOL_OFF]);
        break;
    default:
        APPL_TRACE_ERROR("%s: unsupported codec id %d",
                         __func__, bta_av_co_cb.codec_cfg.id);
        return false;
    }
    return true;
}

/*******************************************************************************
 **
 ** Function         bta_av_co_audio_codec_cfg_matches_caps
 **
 ** Description      Check if a codec config matches a codec capabilities
 **
 ** Returns          true if it codec config is supported, false otherwise
 **
 *******************************************************************************/
static bool bta_av_co_audio_codec_cfg_matches_caps(uint8_t codec_id, const uint8_t *p_codec_caps, const uint8_t *p_codec_cfg)
{
    APPL_TRACE_DEBUG("%s", __func__);

    switch(codec_id) {
    case A2D_MEDIA_CT_SBC:

        APPL_TRACE_EVENT("%s: min %d/%d max %d/%d",
           __func__,
           p_codec_caps[BTA_AV_CO_SBC_MIN_BITPOOL_OFF],
           p_codec_cfg[BTA_AV_CO_SBC_MIN_BITPOOL_OFF],
           p_codec_caps[BTA_AV_CO_SBC_MAX_BITPOOL_OFF],
           p_codec_cfg[BTA_AV_CO_SBC_MAX_BITPOOL_OFF]);

        /* Must match all items exactly except bitpool boundaries which can be adjusted */
        if (!((p_codec_caps[BTA_AV_CO_SBC_FREQ_CHAN_OFF] & p_codec_cfg[BTA_AV_CO_SBC_FREQ_CHAN_OFF]) &&
              (p_codec_caps[BTA_AV_CO_SBC_BLOCK_BAND_OFF] & p_codec_cfg[BTA_AV_CO_SBC_BLOCK_BAND_OFF])))
        {
            APPL_TRACE_EVENT("%s: false %x %x %x %x", __func__,
                    p_codec_caps[BTA_AV_CO_SBC_FREQ_CHAN_OFF],
                    p_codec_cfg[BTA_AV_CO_SBC_FREQ_CHAN_OFF],
                    p_codec_caps[BTA_AV_CO_SBC_BLOCK_BAND_OFF],
                    p_codec_cfg[BTA_AV_CO_SBC_BLOCK_BAND_OFF]);
            return false;
        }
        break;

    default:
        APPL_TRACE_ERROR("%s: unsupported codec id %d", __func__, codec_id);
        return false;
    }
    APPL_TRACE_EVENT("%s: true", __func__);

    return true;
}

/*******************************************************************************
 **
 ** Function         bta_av_co_audio_codec_match
 **
 ** Description      Check if a codec capabilities supports the codec config
 **
 ** Returns          true if the connection supports this codec, false otherwise
 **
 *******************************************************************************/
static bool bta_av_co_audio_codec_match(const uint8_t *p_codec_caps)
{
    APPL_TRACE_DEBUG("%s", __func__);

    return bta_av_co_audio_codec_cfg_matches_caps(bta_av_co_cb.codec_cfg.id, p_codec_caps, bta_av_co_cb.codec_cfg.info);
}

/*******************************************************************************
 **
 ** Function         bta_av_co_audio_peer_reset_config
 **
 ** Description      Reset the peer codec configuration
 **
 ** Returns          Nothing
 **
 *******************************************************************************/
static void bta_av_co_audio_peer_reset_config(tBTA_AV_CO_PEER *p_peer)
{
    APPL_TRACE_DEBUG("%s", __func__);

    /* Indicate that there is no currently selected sink */
    p_peer->p_snk = NULL;
}

/*******************************************************************************
 **
 ** Function         bta_av_co_cp_is_scmst
 **
 ** Description      Check if a content protection service is SCMS-T
 **
 ** Returns          true if this CP is SCMS-T, false otherwise
 **
 *******************************************************************************/
static bool bta_av_co_cp_is_scmst(const uint8_t *p_protectinfo)
{
    APPL_TRACE_DEBUG("%s", __func__);

    if (*p_protectinfo >= BTA_AV_CP_LOSC) {
        uint16_t cp_id;

        p_protectinfo++;
        STREAM_TO_UINT16(cp_id, p_protectinfo);
        if (cp_id == BTA_AV_CP_SCMS_T_ID)
        {
            APPL_TRACE_DEBUG("%s: SCMS-T found", __func__);
            return true;
        }
    }

    return false;
}

/*******************************************************************************
 **
 ** Function         bta_av_co_audio_sink_has_scmst
 **
 ** Description      Check if a sink supports SCMS-T
 **
 ** Returns          true if the sink supports this CP, false otherwise
 **
 *******************************************************************************/
static bool bta_av_co_audio_sink_has_scmst(const tBTA_AV_CO_SINK *p_sink)
{
    uint8_t index;
    const uint8_t *p;

    APPL_TRACE_DEBUG("%s", __func__);

    /* Check if sink supports SCMS-T */
    index = p_sink->num_protect;
    p = &p_sink->protect_info[0];

    while (index)
    {
        if (bta_av_co_cp_is_scmst(p))
        {
            return true;
        }
        /* Move to the next SC */
        p += *p + 1;
        /* Decrement the SC counter */
        index--;
    }
    APPL_TRACE_DEBUG("%s: SCMS-T not found", __func__);
    return false;
}

/*******************************************************************************
 **
 ** Function         bta_av_co_audio_sink_supports_cp
 **
 ** Description      Check if a sink supports the current content protection
 **
 ** Returns          true if the sink supports this CP, false otherwise
 **
 *******************************************************************************/
static bool bta_av_co_audio_sink_supports_cp(const tBTA_AV_CO_SINK *p_sink)
{
    APPL_TRACE_DEBUG("%s", __func__);

    /* Check if content protection is enabled for this stream */
    if (bta_av_co_cp_get_flag() != BTA_AV_CP_SCMS_COPY_FREE)
    {
        return bta_av_co_audio_sink_has_scmst(p_sink);
    }
    else
    {
        APPL_TRACE_DEBUG("%s: not required", __func__);
        return true;
    }
}

/*******************************************************************************
 **
 ** Function         bta_av_co_audio_peer_supports_codec
 **
 ** Description      Check if a connection supports the codec config
 **
 ** Returns          true if the connection supports this codec, false otherwise
 **
 *******************************************************************************/
static bool bta_av_co_audio_peer_supports_codec(tBTA_AV_CO_PEER *p_peer, uint8_t *p_snk_index)
{
    int index;
    uint8_t codec_type;

    APPL_TRACE_DEBUG("%s", __func__);

    /* Configure the codec type to look for */
    codec_type = bta_av_co_cb.codec_cfg.id;


    for (index = 0; index < p_peer->num_sup_snks; index++)
    {
        if (p_peer->snks[index].codec_type == codec_type)
        {
            switch (bta_av_co_cb.codec_cfg.id)
            {
            case A2D_MEDIA_CT_SBC:
                if (p_snk_index) *p_snk_index = index;
                return bta_av_co_audio_codec_match(p_peer->snks[index].codec_caps);
                break;


            default:
                APPL_TRACE_ERROR("%s: unsupported codec id %d",
                                 __func__, bta_av_co_cb.codec_cfg.id);
                return false;
            }
        }
    }
    return false;
}

/*******************************************************************************
 **
 ** Function         bta_av_co_audio_peer_src_supports_codec
 **
 ** Description      Check if a peer acting as src supports codec config
 **
 ** Returns          true if the connection supports this codec, false otherwise
 **
 *******************************************************************************/
static bool bta_av_co_audio_peer_src_supports_codec(tBTA_AV_CO_PEER *p_peer, uint8_t *p_src_index)
{
    int index;
    tA2D_CODEC_TYPE codec_type;

    APPL_TRACE_DEBUG("%s", __func__);

    /* Configure the codec type to look for */
    codec_type = bta_av_co_cb.codec_cfg.id;

    for (index = 0; index < p_peer->num_sup_srcs; index++) {
        if (p_peer->srcs[index].codec_type != codec_type)
            continue;
        if (A2D_IsPeerSourceCodecSupported(p_peer->srcs[index].codec_caps)) {
            if (p_src_index != NULL) {
                *p_src_index = index;
            }
            return true;
        }
        break;
    }
    return false;
}

/*******************************************************************************
 **
 ** Function         bta_av_co_audio_codec_supported
 **
 ** Description      Check if all opened connections are compatible with a codec
 **                  configuration and content protection
 **
 ** Returns          true if all opened devices support this codec, false otherwise
 **
 *******************************************************************************/
bool bta_av_co_audio_codec_supported(void)
{
    uint8_t index;
    uint8_t snk_index;
    tBTA_AV_CO_PEER *p_peer;
    tBTA_AV_CO_SINK *p_sink;
    uint8_t codec_cfg[AVDT_CODEC_SIZE];
    uint8_t num_protect = 0;
#if (BTA_AV_CO_CP_SCMS_T == TRUE)
    bool cp_active;
#endif

    APPL_TRACE_DEBUG("%s", __func__);

    /* Check AV feeding is supported */
    for (index = 0; index < BTA_AV_CO_NUM_ELEMENTS(bta_av_co_cb.peers); index++)
    {
        p_peer = &bta_av_co_cb.peers[index];
        if (p_peer->opened)
        {
            if (bta_av_co_audio_peer_supports_codec(p_peer, &snk_index))
            {
                p_sink = &p_peer->snks[snk_index];

                /* Check that this sink is compatible with the CP */
                if (!bta_av_co_audio_sink_supports_cp(p_sink))
                {
                    APPL_TRACE_DEBUG("%s: sink %d of peer %d doesn't support cp",
                                     __func__, snk_index, index);
                    return false;
                }

                /* Build the codec configuration for this sink */
                if (bta_av_co_audio_codec_build_config(p_sink->codec_caps, codec_cfg))
                {
#if (BTA_AV_CO_CP_SCMS_T == TRUE)
                    /* Check if this sink supports SCMS */
                    cp_active = bta_av_co_audio_sink_has_scmst(p_sink);
#endif
                    /* Check if this is a new configuration (new sink or new config) */
                    if ((p_sink != p_peer->p_snk) ||
                        (memcmp(codec_cfg, p_peer->codec_cfg, AVDT_CODEC_SIZE))
#if (BTA_AV_CO_CP_SCMS_T == TRUE)
                        || (p_peer->cp_active != cp_active)
#endif
                        )
                    {
                        /* Save the new configuration */
                        p_peer->p_snk = p_sink;
                        memcpy(p_peer->codec_cfg, codec_cfg, AVDT_CODEC_SIZE);
#if (BTA_AV_CO_CP_SCMS_T == TRUE)
                        p_peer->cp_active = cp_active;
                        if (p_peer->cp_active)
                        {
                            bta_av_co_cb.cp.active = true;
                            num_protect = BTA_AV_CP_INFO_LEN;
                        }
                        else
                        {
                            bta_av_co_cb.cp.active = false;
                        }
#endif
                        APPL_TRACE_DEBUG("%s: call BTA_AvReconfig(x%x)",
                                         __func__,
                                         BTA_AV_CO_AUDIO_INDX_TO_HNDL(index));
                        BTA_AvReconfig(BTA_AV_CO_AUDIO_INDX_TO_HNDL(index), true, p_sink->sep_info_idx,
                                p_peer->codec_cfg, num_protect, (uint8_t *)bta_av_co_cp_scmst);
                    }
                }
            }
            else
            {
                APPL_TRACE_DEBUG("%s: index %d doesn't support codec",
                                 __func__, index);
                return false;
            }
        }
    }

    return true;
}

/*******************************************************************************
 **
 ** Function         bta_av_co_audio_codec_reset
 **
 ** Description      Reset the current codec configuration
 **
 ** Returns          void
 **
 *******************************************************************************/
void bta_av_co_audio_codec_reset(void)
{
    APPL_TRACE_DEBUG("%s", __func__);

    mutex_global_lock();

    /* Reset the current configuration to SBC */
    bta_av_co_cb.codec_cfg.id = A2D_MEDIA_CT_SBC;
    A2D_InitDefaultCodec(bta_av_co_cb.codec_cfg.info);

    mutex_global_unlock();
}

/*******************************************************************************
 **
 ** Function         bta_av_co_audio_set_codec
 **
 ** Description      Set the current codec configuration from the feeding type.
 **                  This function is starting to modify the configuration, it
 **                  should be protected.
 **
 ** Returns          true if successful, false otherwise
 **
 *******************************************************************************/
bool bta_av_co_audio_set_codec(const tA2D_AV_MEDIA_FEEDINGS *p_feeding)
{
    tBTIF_AV_CODEC_INFO new_cfg;

    if (!A2D_SetCodec(p_feeding, new_cfg.info))
        return false;
    new_cfg.id = A2D_GetCodecType(new_cfg.info);

    /* The new config was correctly built */
    bta_av_co_cb.codec_cfg = new_cfg;

    /* Check all devices support it */
    return bta_av_co_audio_codec_supported();
}

void bta_av_co_audio_encoder_init(tBTIF_MEDIA_INIT_AUDIO *msg)
{
    uint16_t min_mtu = 0xFFFF;

    APPL_TRACE_DEBUG("%s", __func__);

    /* Protect access to bta_av_co_cb.codec_cfg */
    mutex_global_lock();

    /* Compute the MTU */
    for (size_t i = 0; i < BTA_AV_CO_NUM_ELEMENTS(bta_av_co_cb.peers); i++) {
        const tBTA_AV_CO_PEER *p_peer = &bta_av_co_cb.peers[i];
        if (!p_peer->opened)
            continue;
        if (p_peer->mtu < min_mtu)
            min_mtu = p_peer->mtu;
    }

    const uint8_t *p_codec_info = bta_av_co_cb.codec_cfg.info;
    msg->NumOfSubBands = A2D_GetNumberOfSubbands(p_codec_info);
    msg->NumOfBlocks = A2D_GetNumberOfBlocks(p_codec_info);
    msg->AllocationMethod = A2D_GetAllocationMethodCode(p_codec_info);
    msg->ChannelMode = A2D_GetChannelModeCode(p_codec_info);
    msg->SamplingFreq = A2D_GetSamplingFrequencyCode(p_codec_info);
    msg->MtuSize = min_mtu;

    /* Protect access to bta_av_co_cb.codec_cfg */
    mutex_global_unlock();
}

void bta_av_co_audio_encoder_update(tBTIF_MEDIA_UPDATE_AUDIO *msg)
{
    uint16_t min_mtu = 0xFFFF;

    APPL_TRACE_DEBUG("%s", __func__);

    /* Protect access to bta_av_co_cb.codec_cfg */
    mutex_global_lock();

    const uint8_t *p_codec_info = bta_av_co_cb.codec_cfg.info;
    int min_bitpool = A2D_GetMinBitpool(p_codec_info);
    int max_bitpool = A2D_GetMaxBitpool(p_codec_info);

    if ((min_bitpool < 0) || (max_bitpool < 0)) {
        APPL_TRACE_ERROR("%s: Invalid min/max bitpool: [%d, %d]",
                         __func__, min_bitpool, max_bitpool);
        mutex_global_unlock();
        return;
    }

    for (size_t i = 0; i < BTA_AV_CO_NUM_ELEMENTS(bta_av_co_cb.peers); i++) {
        const tBTA_AV_CO_PEER *p_peer = &bta_av_co_cb.peers[i];
        if (!p_peer->opened)
            continue;

        if (p_peer->mtu < min_mtu)
            min_mtu = p_peer->mtu;

        for (int j = 0; j < p_peer->num_sup_snks; j++) {
            const tBTA_AV_CO_SINK *p_sink = &p_peer->snks[j];
            if (!A2D_CodecTypeEquals(p_codec_info, p_sink->codec_caps))
                continue;
            /* Update the bitpool boundaries of the current config */
            int peer_min_bitpool = A2D_GetMinBitpool(p_sink->codec_caps);
            int peer_max_bitpool = A2D_GetMaxBitpool(p_sink->codec_caps);
            if (peer_min_bitpool >= 0)
                min_bitpool = BTA_AV_CO_MAX(min_bitpool, peer_min_bitpool);
            if (peer_max_bitpool >= 0)
                max_bitpool = BTA_AV_CO_MIN(max_bitpool, peer_max_bitpool);
            APPL_TRACE_EVENT("%s: sink bitpool min %d, max %d",
                             __func__, min_bitpool, max_bitpool);
            break;
        }
    }

    /*
     * Check if the remote Sink has a preferred bitpool range.
     * Adjust our preferred bitpool with the remote preference if within
     * our capable range.
     */
    if (A2D_IsValidCodec(bta_av_co_cb.codec_cfg_setconfig.info) &&
        A2D_CodecTypeEquals(p_codec_info,
                            bta_av_co_cb.codec_cfg_setconfig.info)) {
        int setconfig_min_bitpool =
            A2D_GetMinBitpool(bta_av_co_cb.codec_cfg_setconfig.info);
        int setconfig_max_bitpool =
            A2D_GetMaxBitpool(bta_av_co_cb.codec_cfg_setconfig.info);
        if (setconfig_min_bitpool >= 0)
            min_bitpool = BTA_AV_CO_MAX(min_bitpool, setconfig_min_bitpool);
        if (setconfig_max_bitpool >= 0)
            max_bitpool = BTA_AV_CO_MIN(max_bitpool, setconfig_max_bitpool);
        APPL_TRACE_EVENT("%s: sink adjusted bitpool min %d, max %d",
                         __func__, min_bitpool, max_bitpool);
    }

    /* Protect access to bta_av_co_cb.codec_cfg */
    mutex_global_unlock();

    if (min_bitpool > max_bitpool) {
        APPL_TRACE_ERROR("%s: Irrational min/max bitpool: [%d, %d]",
                         __func__, min_bitpool, max_bitpool);
        return;
    }

    msg->MinMtuSize = min_mtu;
    msg->MinBitPool = min_bitpool;
    msg->MaxBitPool = max_bitpool;
}

/*******************************************************************************
 **
 ** Function         bta_av_co_audio_discard_config
 **
 ** Description      Discard the codec configuration of a connection
 **
 ** Returns          Nothing
 **
 *******************************************************************************/
void bta_av_co_audio_discard_config(tBTA_AV_HNDL hndl)
{
    tBTA_AV_CO_PEER *p_peer;

    APPL_TRACE_DEBUG("%s", __func__);

    /* Find the peer info */
    p_peer = bta_av_co_get_peer(hndl);
    if (p_peer == NULL)
    {
        APPL_TRACE_ERROR("%s: could not find peer entry", __func__);
        return;
    }

    /* Reset the peer codec configuration */
    bta_av_co_audio_peer_reset_config(p_peer);
}

/*******************************************************************************
 **
 ** Function         bta_av_co_init
 **
 ** Description      Initialization
 **
 ** Returns          Nothing
 **
 *******************************************************************************/
void bta_av_co_init(void)
{
    APPL_TRACE_DEBUG("%s", __func__);

    /* Reset the control block */
    memset(&bta_av_co_cb, 0, sizeof(bta_av_co_cb));

    bta_av_co_cb.codec_cfg_setconfig.id = tA2D_AV_CODEC_NONE;

#if (BTA_AV_CO_CP_SCMS_T == TRUE)
    bta_av_co_cp_set_flag(BTA_AV_CP_SCMS_COPY_NEVER);
#else
    bta_av_co_cp_set_flag(BTA_AV_CP_SCMS_COPY_FREE);
#endif

    /* Reset the current config */
    bta_av_co_audio_codec_reset();
}


/*******************************************************************************
 **
 ** Function         bta_av_co_peer_cp_supported
 **
 ** Description      Checks if the peer supports CP
 **
 ** Returns          true if the peer supports CP
 **
 *******************************************************************************/
bool bta_av_co_peer_cp_supported(tBTA_AV_HNDL hndl)
{
    tBTA_AV_CO_PEER *p_peer;
    tBTA_AV_CO_SINK *p_sink;
    uint8_t index;

    APPL_TRACE_DEBUG("%s: handle = %d", __func__, hndl);

    /* Find the peer info */
    p_peer = bta_av_co_get_peer(hndl);
    if (p_peer == NULL)
    {
        APPL_TRACE_ERROR("%s: could not find peer entry", __func__);
        return false;
    }

    for (index = 0; index < p_peer->num_sup_snks; index++)
    {
        p_sink = &p_peer->snks[index];
        if (p_sink->codec_type == A2D_MEDIA_CT_SBC)
        {
            return bta_av_co_audio_sink_has_scmst(p_sink);
        }
    }
    APPL_TRACE_ERROR("%s: did not find SBC sink", __func__);
    return false;
}
