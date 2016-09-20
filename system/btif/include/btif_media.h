/******************************************************************************
 *
 *  Copyright (C) 2009-2012 Broadcom Corporation
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

/*******************************************************************************
 *
 *  Filename:      btif_media.h
 *
 *  Description:   This is the audio module for the BTIF system.
 *
 *******************************************************************************/

#ifndef BTIF_MEDIA_H
#define BTIF_MEDIA_H

#include <stdbool.h>

#include "bta_api.h"
#include "bta_av_api.h"
#include "bt_common.h"

/*******************************************************************************
 **  Constants
 *******************************************************************************/

/* Transcoding definition for TxTranscoding and RxTranscoding */
#define BTIF_MEDIA_TRSCD_OFF             0
#define BTIF_MEDIA_TRSCD_PCM_2_SBC       1  /* Tx */


/*******************************************************************************
 **  Data types
 *******************************************************************************/

/* tBTIF_MEDIA_INIT_AUDIO msg structure */
typedef struct
{
        BT_HDR hdr;
        uint16_t SamplingFreq; /* 16k, 32k, 44.1k or 48k*/
        uint8_t ChannelMode; /* mono, dual, stereo or joint stereo*/
        uint8_t NumOfSubBands; /* 4 or 8 */
        uint8_t NumOfBlocks; /* 4, 8, 12 or 16*/
        uint8_t AllocationMethod; /* loudness or SNR*/
        uint16_t MtuSize; /* peer mtu size */
} tBTIF_MEDIA_INIT_AUDIO;

/* tBTIF_MEDIA_UPDATE_AUDIO msg structure */
typedef struct
{
        BT_HDR hdr;
        uint16_t MinMtuSize; /* Minimum peer mtu size */
        uint8_t MaxBitPool; /* Maximum peer bitpool */
        uint8_t MinBitPool; /* Minimum peer bitpool */
} tBTIF_MEDIA_UPDATE_AUDIO;

/* tBTIF_MEDIA_INIT_AUDIO_FEEDING msg structure */
typedef struct
{
        BT_HDR hdr;
        tA2D_AV_MEDIA_FEEDINGS feeding;
} tBTIF_MEDIA_INIT_AUDIO_FEEDING;

typedef struct
{
        BT_HDR hdr;
        uint8_t codec_info[AVDT_CODEC_SIZE];
} tBTIF_MEDIA_SINK_CFG_UPDATE;

#ifdef USE_AUDIO_TRACK
typedef enum {
        BTIF_MEDIA_FOCUS_NOT_GRANTED = 0,
        BTIF_MEDIA_FOCUS_GRANTED
} btif_media_audio_focus_state;

typedef struct
{
        BT_HDR hdr;
        uint8_t focus_state;
} tBTIF_MEDIA_SINK_FOCUS_UPDATE;
#endif

/*******************************************************************************
 **  Public functions
 *******************************************************************************/

/*******************************************************************************
 **
 ** Function         btif_av_task
 **
 ** Description
 **
 ** Returns          void
 **
 *******************************************************************************/
extern void btif_media_task(void);

/*******************************************************************************
 **
 ** Function         btif_media_task_enc_init_req
 **
 ** Description      Request to initialize the media task encoder
 **
 ** Returns          true is success
 **
 *******************************************************************************/
extern bool btif_media_task_enc_init_req(tBTIF_MEDIA_INIT_AUDIO * p_msg);

/*******************************************************************************
 **
 ** Function         btif_media_task_enc_update_req
 **
 ** Description      Request to update the media task encoder
 **
 ** Returns          true is success
 **
 *******************************************************************************/
extern bool btif_media_task_enc_update_req(tBTIF_MEDIA_UPDATE_AUDIO * p_msg);

/*******************************************************************************
 **
 ** Function         btif_media_task_start_aa_req
 **
 ** Description      Request to start audio encoding task
 **
 ** Returns          true is success
 **
 *******************************************************************************/
extern bool btif_media_task_start_aa_req(void);

/*******************************************************************************
 **
 ** Function         btif_media_task_stop_aa_req
 **
 ** Description      Request to stop audio encoding task
 **
 ** Returns          true is success
 **
 *******************************************************************************/
extern bool btif_media_task_stop_aa_req(void);

/*******************************************************************************
 **
 ** Function         btif_media_task_aa_rx_flush_req
 **
 ** Description      Request to flush audio decoding pipe
 **
 ** Returns          true is success
 **
 *******************************************************************************/
extern bool btif_media_task_aa_rx_flush_req(void);
/*******************************************************************************
 **
 ** Function         btif_media_task_aa_tx_flush_req
 **
 ** Description      Request to flush audio encoding pipe
 **
 ** Returns          true is success
 **
 *******************************************************************************/
extern bool btif_media_task_aa_tx_flush_req(void);

/*******************************************************************************
 **
 ** Function         btif_media_aa_readbuf
 **
 ** Description      Read an audio GKI buffer from the BTIF media TX queue
 **
 ** Returns          pointer on a GKI aa buffer ready to send
 **
 *******************************************************************************/
extern BT_HDR *btif_media_aa_readbuf(void);

/*******************************************************************************
 **
 ** Function         btif_media_sink_enque_buf
 **
 ** Description      This function is called by the av_co to fill A2DP Sink Queue
 **
 **
 ** Returns          size of the queue
 *******************************************************************************/
 uint8_t btif_media_sink_enque_buf(BT_HDR *p_buf);



/*******************************************************************************
 **
 ** Function         btif_media_aa_writebuf
 **
 ** Description      Enqueue a Advance Audio media GKI buffer to be processed by btif media task.
 **
 ** Returns          true is success
 **
 *******************************************************************************/
extern void btif_media_aa_writebuf(BT_HDR *pBuf, uint32_t timestamp, uint16_t seq_num);

/*******************************************************************************
 **
 ** Function         btif_media_av_writebuf
 **
 ** Description      Enqueue a video media GKI buffer to be processed by btif media task.
 **
 ** Returns          true is success
 **
 *******************************************************************************/
extern bool btif_media_av_writebuf(uint8_t *p_media, uint32_t media_len,
                                     uint32_t timestamp, uint16_t seq_num);

/*******************************************************************************
 **
 ** Function         btif_media_task_audio_feeding_init_req
 **
 ** Description      Request to initialize audio feeding
 **
 ** Returns          true is success
 **
 *******************************************************************************/

extern bool btif_media_task_audio_feeding_init_req(tBTIF_MEDIA_INIT_AUDIO_FEEDING *p_msg);

/**
 * Local adaptation helper functions between btif and media task
 */

bool btif_a2dp_start_media_task(void);
void btif_a2dp_stop_media_task(void);

void btif_a2dp_on_init(void);
void btif_a2dp_setup_codec(void);
void btif_a2dp_on_idle(void);
void btif_a2dp_on_open(void);
bool btif_a2dp_on_started(tBTA_AV_START *p_av, bool pending_start);
void btif_a2dp_ack_fail(void);
void btif_a2dp_on_stop_req(void);
void btif_a2dp_on_stopped(tBTA_AV_SUSPEND *p_av);
void btif_a2dp_on_suspend(void);
void btif_a2dp_on_suspended(tBTA_AV_SUSPEND *p_av);
void btif_a2dp_set_tx_flush(bool enable);
void btif_a2dp_set_rx_flush(bool enable);
void btif_media_check_iop_exceptions(uint8_t *peer_bda);
void btif_reset_decoder(uint8_t *p_av);
void btif_a2dp_on_offload_started(tBTA_AV_STATUS status);

void btif_a2dp_set_peer_sep(uint8_t sep);
#ifdef USE_AUDIO_TRACK
void btif_a2dp_set_audio_focus_state(btif_media_audio_focus_state state);
void btif_a2dp_set_audio_track_gain(float gain);
#endif

void btif_debug_a2dp_dump(int fd);
void btif_update_a2dp_metrics(void);
#endif
