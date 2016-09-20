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

/******************************************************************************
 **
 **  Name:          btif_media_task.c
 **
 **  Description:   This is the multimedia module for the BTIF system.  It
 **                 contains task implementations AV, HS and HF profiles
 **                 audio & video processing
 **
 ******************************************************************************/

#define LOG_TAG "bt_btif_media"

#include <assert.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#include <hardware/bluetooth.h>

#include "a2d_api.h"
#include "a2d_int.h"
#include "a2d_sbc.h"
#include "audio_a2dp_hw.h"
#include "bt_target.h"
#include "bta_api.h"
#include "bta_av_api.h"
#include "bta_av_ci.h"
#include "bta_av_sbc.h"
#include "bta_sys.h"
#include "bta_sys_int.h"
#include "btif_av.h"
#include "btif_av_co.h"
#include "btif_hf.h"
#include "btif_media.h"
#include "btif_sm.h"
#include "btif_util.h"
#include "btu.h"
#include "bt_common.h"
#include "device/include/controller.h"
#include "l2c_api.h"
#include "osi/include/alarm.h"
#include "osi/include/fixed_queue.h"
#include "osi/include/log.h"
#include "osi/include/metrics.h"
#include "osi/include/mutex.h"
#include "osi/include/thread.h"

#include "sbc_encoder.h"

#if (BTA_AV_SINK_INCLUDED == TRUE)
#include "oi_codec_sbc.h"
#include "oi_status.h"
#endif

#ifdef USE_AUDIO_TRACK
#include "btif_avrcp_audio_track.h"
#endif

#if (BTA_AV_SINK_INCLUDED == TRUE)
OI_CODEC_SBC_DECODER_CONTEXT context;
OI_UINT32 contextData[CODEC_DATA_WORDS(2, SBC_CODEC_FAST_FILTER_BUFFERS)];
OI_INT16 pcmData[15*SBC_MAX_SAMPLES_PER_FRAME*SBC_MAX_CHANNELS];
#endif

/*****************************************************************************
 **  Constants
 *****************************************************************************/
#ifndef AUDIO_CHANNEL_OUT_MONO
#define AUDIO_CHANNEL_OUT_MONO 0x01
#endif

#ifndef AUDIO_CHANNEL_OUT_STEREO
#define AUDIO_CHANNEL_OUT_STEREO 0x03
#endif

/* BTIF media cmd event definition : BTIF_MEDIA_TASK_CMD */
enum
{
    BTIF_MEDIA_START_AA_TX = 1,
    BTIF_MEDIA_STOP_AA_TX,
    BTIF_MEDIA_AA_RX_RDY,
    BTIF_MEDIA_UIPC_RX_RDY,
    BTIF_MEDIA_SBC_ENC_INIT,
    BTIF_MEDIA_SBC_ENC_UPDATE,
    BTIF_MEDIA_SBC_DEC_INIT,
    BTIF_MEDIA_VIDEO_DEC_INIT,
    BTIF_MEDIA_FLUSH_AA_TX,
    BTIF_MEDIA_FLUSH_AA_RX,
    BTIF_MEDIA_AUDIO_FEEDING_INIT,
    BTIF_MEDIA_AUDIO_RECEIVING_INIT,
    BTIF_MEDIA_AUDIO_SINK_CFG_UPDATE,
    BTIF_MEDIA_AUDIO_SINK_CLEAR_TRACK,
    BTIF_MEDIA_AUDIO_SINK_SET_FOCUS_STATE
};

enum {
    MEDIA_TASK_STATE_OFF = 0,
    MEDIA_TASK_STATE_ON = 1,
    MEDIA_TASK_STATE_SHUTTING_DOWN = 2
};

/* Macro to multiply the media task tick */
#ifndef BTIF_MEDIA_NUM_TICK
#define BTIF_MEDIA_NUM_TICK      1
#endif

/* Media task tick in milliseconds, must be set to multiple of
   (1000/TICKS_PER_SEC) (10) */

#define BTIF_MEDIA_TIME_TICK                     (20 * BTIF_MEDIA_NUM_TICK)
#define A2DP_DATA_READ_POLL_MS    (BTIF_MEDIA_TIME_TICK / 2)
#define BTIF_SINK_MEDIA_TIME_TICK_MS             (20 * BTIF_MEDIA_NUM_TICK)


/* buffer pool */
#define BTIF_MEDIA_AA_BUF_SIZE  BT_DEFAULT_BUFFER_SIZE

/* offset */
#if (BTA_AV_CO_CP_SCMS_T == TRUE)
#define BTIF_MEDIA_AA_SBC_OFFSET (AVDT_MEDIA_OFFSET + BTA_AV_SBC_HDR_SIZE + 1)
#else
#define BTIF_MEDIA_AA_SBC_OFFSET (AVDT_MEDIA_OFFSET + BTA_AV_SBC_HDR_SIZE)
#endif

/* Define the bitrate step when trying to match bitpool value */
#ifndef BTIF_MEDIA_BITRATE_STEP
#define BTIF_MEDIA_BITRATE_STEP 5
#endif

#ifndef BTIF_A2DP_DEFAULT_BITRATE
/* High quality quality setting @ 44.1 khz */
#define BTIF_A2DP_DEFAULT_BITRATE 328
#endif

#ifndef BTIF_A2DP_NON_EDR_MAX_RATE
#define BTIF_A2DP_NON_EDR_MAX_RATE 229
#endif

#if (BTA_AV_CO_CP_SCMS_T == TRUE)
/* A2DP header will contain a CP header of size 1 */
#define A2DP_HDR_SIZE               2
#else
#define A2DP_HDR_SIZE               1
#endif
#define MAX_SBC_HQ_FRAME_SIZE_44_1  119
#define MAX_SBC_HQ_FRAME_SIZE_48    115

/* 2DH5 payload size of 679 bytes - (4 bytes L2CAP Header + 12 bytes AVDTP Header) */
#define MAX_2MBPS_AVDTP_MTU         663
#define USEC_PER_SEC 1000000L
#define TPUT_STATS_INTERVAL_US (3000*1000)

/**
 * CONGESTION COMPENSATION CTRL ::
 *
 * Thus setting controls how many buffers we will hold in media task
 * during temp link congestion. Together with the stack buffer queues
 * it controls much temporary a2dp link congestion we can
 * compensate for. It however also depends on the default run level of sinks
 * jitterbuffers. Depending on type of sink this would vary.
 * Ideally the (SRC) max tx buffer capacity should equal the sinks
 * jitterbuffer runlevel including any intermediate buffers on the way
 * towards the sinks codec.
 */
#ifndef MAX_PCM_FRAME_NUM_PER_TICK
#define MAX_PCM_FRAME_NUM_PER_TICK     14
#endif
#define MAX_PCM_ITER_NUM_PER_TICK      3

/**
 * The typical runlevel of the tx queue size is ~1 buffer
 * but due to link flow control or thread preemption in lower
 * layers we might need to temporarily buffer up data.
 */
#define MAX_OUTPUT_A2DP_FRAME_QUEUE_SZ (MAX_PCM_FRAME_NUM_PER_TICK * 2)

/* In case of A2DP SINK, we will delay start by 5 AVDTP Packets*/
#define MAX_A2DP_DELAYED_START_FRAME_COUNT 5
#define PACKET_PLAYED_PER_TICK_48 8
#define PACKET_PLAYED_PER_TICK_44 7
#define PACKET_PLAYED_PER_TICK_32 5
#define PACKET_PLAYED_PER_TICK_16 3

/* Readability constants */
#define SBC_FRAME_HEADER_SIZE_BYTES 4 // A2DP Spec v1.3, 12.4, Table 12.12
#define SBC_SCALE_FACTOR_BITS       4 // A2DP Spec v1.3, 12.4, Table 12.13

typedef struct {
    // Counter for total updates
    size_t total_updates;

    // Last update timestamp (in us)
    uint64_t last_update_us;

    // Counter for overdue scheduling
    size_t overdue_scheduling_count;

    // Accumulated overdue scheduling deviations (in us)
    uint64_t total_overdue_scheduling_delta_us;

    // Max. overdue scheduling delta time (in us)
    uint64_t max_overdue_scheduling_delta_us;

    // Counter for premature scheduling
    size_t premature_scheduling_count;

    // Accumulated premature scheduling deviations (in us)
    uint64_t total_premature_scheduling_delta_us;

    // Max. premature scheduling delta time (in us)
    uint64_t max_premature_scheduling_delta_us;

    // Counter for exact scheduling
    size_t exact_scheduling_count;

    // Accumulated and counted scheduling time (in us)
    uint64_t total_scheduling_time_us;
} scheduling_stats_t;

typedef struct {
    uint64_t session_start_us;

    scheduling_stats_t tx_queue_enqueue_stats;
    scheduling_stats_t tx_queue_dequeue_stats;

    size_t tx_queue_total_frames;
    size_t tx_queue_max_frames_per_packet;

    uint64_t tx_queue_total_queueing_time_us;
    uint64_t tx_queue_max_queueing_time_us;

    size_t tx_queue_total_readbuf_calls;
    uint64_t tx_queue_last_readbuf_us;

    size_t tx_queue_total_flushed_messages;
    uint64_t tx_queue_last_flushed_us;

    size_t tx_queue_total_dropped_messages;
    size_t tx_queue_dropouts;
    uint64_t tx_queue_last_dropouts_us;

    size_t media_read_total_underflow_bytes;
    size_t media_read_total_underflow_count;
    uint64_t media_read_last_underflow_us;

    size_t media_read_total_underrun_bytes;
    size_t media_read_total_underrun_count;
    uint64_t media_read_last_underrun_us;

    size_t media_read_total_expected_frames;
    size_t media_read_max_expected_frames;
    size_t media_read_expected_count;

    size_t media_read_total_limited_frames;
    size_t media_read_max_limited_frames;
    size_t media_read_limited_count;
} btif_media_stats_t;

typedef struct
{
    uint16_t num_frames_to_be_processed;
    uint16_t len;
    uint16_t offset;
    uint16_t layer_specific;
} tBT_SBC_HDR;

typedef struct
{
    uint32_t aa_frame_counter;
    int32_t  aa_feed_counter;
    int32_t  aa_feed_residue;
    uint32_t counter;
    uint32_t bytes_per_tick;  /* pcm bytes read each media task tick */
} tBTIF_AV_MEDIA_FEEDINGS_PCM_STATE;

typedef union
{
    tBTIF_AV_MEDIA_FEEDINGS_PCM_STATE pcm;
} tBTIF_AV_MEDIA_FEEDINGS_STATE;

typedef struct
{
    fixed_queue_t *TxAaQ;
    fixed_queue_t *RxSbcQ;
    uint16_t TxAaMtuSize;
    uint32_t timestamp;
    uint8_t TxTranscoding;
    tBTIF_AV_FEEDING_MODE feeding_mode;
    tA2D_AV_MEDIA_FEEDINGS media_feeding;
    tBTIF_AV_MEDIA_FEEDINGS_STATE media_feeding_state;
    SBC_ENC_PARAMS encoder;
    uint8_t busy_level;
    uint8_t a2dp_cmd_pending; /* we can have max one command pending */
    bool tx_flush; /* discards any outgoing data when true */
    bool rx_flush; /* discards any incoming data when true */
    uint8_t peer_sep;
    bool data_channel_open;
    uint8_t frames_to_process;
    uint8_t tx_sbc_frames;

    uint32_t  sample_rate;
    uint8_t   channel_count;
#ifdef USE_AUDIO_TRACK
    btif_media_audio_focus_state rx_audio_focus_state;
    void *audio_track;
#endif
    alarm_t *media_alarm;
    alarm_t *decode_alarm;
    btif_media_stats_t stats;
} tBTIF_MEDIA_CB;

typedef struct {
    long long rx;
    long long rx_tot;
    long long tx;
    long long tx_tot;
    long long ts_prev_us;
} t_stat;

static uint64_t last_frame_us = 0;

static void btif_a2dp_data_cb(tUIPC_CH_ID ch_id, tUIPC_EVENT event);
static void btif_a2dp_ctrl_cb(tUIPC_CH_ID ch_id, tUIPC_EVENT event);
static void btif_a2dp_encoder_update(void);
#if (BTA_AV_SINK_INCLUDED == TRUE)
extern OI_STATUS OI_CODEC_SBC_DecodeFrame(OI_CODEC_SBC_DECODER_CONTEXT *context,
                                          const OI_BYTE **frameData,
                                          unsigned long *frameBytes,
                                          OI_INT16 *pcmData,
                                          unsigned long *pcmBytes);
extern OI_STATUS OI_CODEC_SBC_DecoderReset(OI_CODEC_SBC_DECODER_CONTEXT *context,
                                           unsigned long *decoderData,
                                           unsigned long decoderDataBytes,
                                           OI_UINT8 maxChannels,
                                           OI_UINT8 pcmStride,
                                           OI_BOOL enhanced);
#endif
static void btif_media_flush_q(fixed_queue_t *p_q);
static void btif_media_task_aa_handle_stop_decoding(void );
static void btif_media_task_aa_rx_flush(void);

static uint8_t calculate_max_frames_per_packet();
static const char *dump_media_event(uint16_t event);
static void btif_media_thread_init(void *context);
static void btif_media_thread_cleanup(void *context);
static void btif_media_thread_handle_cmd(fixed_queue_t *queue, void *context);

/* Handle incoming media packets A2DP SINK streaming*/
#if (BTA_AV_SINK_INCLUDED == TRUE)
static void btif_media_task_handle_inc_media(tBT_SBC_HDR*p_msg);
#endif

static void btif_media_send_aa_frame(uint64_t timestamp_us);
static void btif_media_task_feeding_state_reset(void);
static void btif_media_task_aa_start_tx(void);
static void btif_media_task_aa_stop_tx(void);
static void btif_media_task_enc_init(BT_HDR *p_msg);
static void btif_media_task_enc_update(BT_HDR *p_msg);
static void btif_media_task_audio_feeding_init(BT_HDR *p_msg);
static void btif_media_task_aa_tx_flush(BT_HDR *p_msg);
static void btif_media_aa_prep_2_send(uint8_t nb_frame, uint64_t timestamp_us);
#if (BTA_AV_SINK_INCLUDED == TRUE)
static void btif_media_task_aa_handle_decoder_reset(BT_HDR *p_msg);
static void btif_media_task_aa_handle_clear_track(void);
#endif
static void btif_media_task_aa_handle_start_decoding(void);
bool btif_media_task_clear_track(void);

static void btif_media_task_aa_handle_timer(UNUSED_ATTR void *context);
static void btif_media_task_avk_handle_timer(UNUSED_ATTR void *context);

static tBTIF_MEDIA_CB btif_media_cb;
static int media_task_running = MEDIA_TASK_STATE_OFF;

static fixed_queue_t *btif_media_cmd_msg_queue;
static thread_t *worker_thread;

/*****************************************************************************
 **  Misc helper functions
 *****************************************************************************/

static void update_scheduling_stats(scheduling_stats_t *stats,
                                    uint64_t now_us, uint64_t expected_delta)
{
    uint64_t last_us = stats->last_update_us;

    stats->total_updates++;
    stats->last_update_us = now_us;

    if (last_us == 0)
      return;           // First update: expected delta doesn't apply

    uint64_t deadline_us = last_us + expected_delta;
    if (deadline_us < now_us) {
        // Overdue scheduling
        uint64_t delta_us = now_us - deadline_us;
        // Ignore extreme outliers
        if (delta_us < 10 * expected_delta) {
            if (stats->max_overdue_scheduling_delta_us < delta_us)
                stats->max_overdue_scheduling_delta_us = delta_us;
            stats->total_overdue_scheduling_delta_us += delta_us;
            stats->overdue_scheduling_count++;
            stats->total_scheduling_time_us += now_us - last_us;
        }
    } else if (deadline_us > now_us) {
        // Premature scheduling
        uint64_t delta_us = deadline_us - now_us;
        // Ignore extreme outliers
        if (delta_us < 10 * expected_delta) {
            if (stats->max_premature_scheduling_delta_us < delta_us)
                stats->max_premature_scheduling_delta_us = delta_us;
            stats->total_premature_scheduling_delta_us += delta_us;
            stats->premature_scheduling_count++;
            stats->total_scheduling_time_us += now_us - last_us;
        }
    } else {
        // On-time scheduling
        stats->exact_scheduling_count++;
        stats->total_scheduling_time_us += now_us - last_us;
    }
}

static uint64_t time_now_us()
{
    struct timespec ts_now;
    clock_gettime(CLOCK_BOOTTIME, &ts_now);
    return ((uint64_t)ts_now.tv_sec * USEC_PER_SEC) + ((uint64_t)ts_now.tv_nsec / 1000);
}

static void log_tstamps_us(const char *comment, uint64_t timestamp_us)
{
    static uint64_t prev_us = 0;
    APPL_TRACE_DEBUG("[%s] ts %08llu, diff : %08llu, queue sz %d", comment, timestamp_us,
        timestamp_us - prev_us, fixed_queue_length(btif_media_cb.TxAaQ));
    prev_us = timestamp_us;
}

UNUSED_ATTR static const char *dump_media_event(uint16_t event)
{
    switch (event)
    {
        CASE_RETURN_STR(BTIF_MEDIA_START_AA_TX)
        CASE_RETURN_STR(BTIF_MEDIA_STOP_AA_TX)
        CASE_RETURN_STR(BTIF_MEDIA_AA_RX_RDY)
        CASE_RETURN_STR(BTIF_MEDIA_UIPC_RX_RDY)
        CASE_RETURN_STR(BTIF_MEDIA_SBC_ENC_INIT)
        CASE_RETURN_STR(BTIF_MEDIA_SBC_ENC_UPDATE)
        CASE_RETURN_STR(BTIF_MEDIA_SBC_DEC_INIT)
        CASE_RETURN_STR(BTIF_MEDIA_VIDEO_DEC_INIT)
        CASE_RETURN_STR(BTIF_MEDIA_FLUSH_AA_TX)
        CASE_RETURN_STR(BTIF_MEDIA_FLUSH_AA_RX)
        CASE_RETURN_STR(BTIF_MEDIA_AUDIO_FEEDING_INIT)
        CASE_RETURN_STR(BTIF_MEDIA_AUDIO_RECEIVING_INIT)
        CASE_RETURN_STR(BTIF_MEDIA_AUDIO_SINK_CFG_UPDATE)
        CASE_RETURN_STR(BTIF_MEDIA_AUDIO_SINK_CLEAR_TRACK)
        CASE_RETURN_STR(BTIF_MEDIA_AUDIO_SINK_SET_FOCUS_STATE)

        default:
            return "UNKNOWN MEDIA EVENT";
    }
}

static void btm_read_rssi_cb(void *data)
{
    assert(data);

    tBTM_RSSI_RESULTS *result = (tBTM_RSSI_RESULTS*)data;
    if (result->status != BTM_SUCCESS)
    {
        LOG_ERROR(LOG_TAG, "%s unable to read remote RSSI (status %d)",
            __func__, result->status);
        return;
    }

    char temp_buffer[20] = {0};
    LOG_WARN(LOG_TAG, "%s device: %s, rssi: %d", __func__,
        bdaddr_to_string((bt_bdaddr_t *)result->rem_bda, temp_buffer,
            sizeof(temp_buffer)),
        result->rssi);
}

/*****************************************************************************
 **  A2DP CTRL PATH
 *****************************************************************************/

static const char* dump_a2dp_ctrl_event(uint8_t event)
{
    switch (event)
    {
        CASE_RETURN_STR(A2DP_CTRL_CMD_NONE)
        CASE_RETURN_STR(A2DP_CTRL_CMD_CHECK_READY)
        CASE_RETURN_STR(A2DP_CTRL_CMD_START)
        CASE_RETURN_STR(A2DP_CTRL_CMD_STOP)
        CASE_RETURN_STR(A2DP_CTRL_CMD_SUSPEND)
        CASE_RETURN_STR(A2DP_CTRL_CMD_OFFLOAD_START)

        default:
            return "UNKNOWN MSG ID";
    }
}

static void btif_audiopath_detached(void)
{
    APPL_TRACE_EVENT("## AUDIO PATH DETACHED ##");

    /*  send stop request only if we are actively streaming and haven't received
        a stop request. Potentially audioflinger detached abnormally */
    if (alarm_is_scheduled(btif_media_cb.media_alarm)) {
        /* post stop event and wait for audio path to stop */
        btif_dispatch_sm_event(BTIF_AV_STOP_STREAM_REQ_EVT, NULL, 0);
    }
}

static void a2dp_cmd_acknowledge(int status)
{
    uint8_t ack = status;

    APPL_TRACE_EVENT("## a2dp ack : %s, status %d ##",
          dump_a2dp_ctrl_event(btif_media_cb.a2dp_cmd_pending), status);

    /* sanity check */
    if (btif_media_cb.a2dp_cmd_pending == A2DP_CTRL_CMD_NONE)
    {
        APPL_TRACE_ERROR("warning : no command pending, ignore ack");
        return;
    }

    /* clear pending */
    btif_media_cb.a2dp_cmd_pending = A2DP_CTRL_CMD_NONE;

    /* acknowledge start request */
    UIPC_Send(UIPC_CH_ID_AV_CTRL, 0, &ack, 1);
}


static void btif_recv_ctrl_data(void)
{
    uint8_t cmd = 0;
    int n;
    n = UIPC_Read(UIPC_CH_ID_AV_CTRL, NULL, &cmd, 1);

    /* detach on ctrl channel means audioflinger process was terminated */
    if (n == 0)
    {
        APPL_TRACE_EVENT("CTRL CH DETACHED");
        UIPC_Close(UIPC_CH_ID_AV_CTRL);
        /* we can operate only on datachannel, if af client wants to
           do send additional commands the ctrl channel would be reestablished */
        //btif_audiopath_detached();
        return;
    }

    APPL_TRACE_DEBUG("a2dp-ctrl-cmd : %s", dump_a2dp_ctrl_event(cmd));

    btif_media_cb.a2dp_cmd_pending = cmd;

    switch (cmd)
    {
        case A2DP_CTRL_CMD_CHECK_READY:

            if (media_task_running == MEDIA_TASK_STATE_SHUTTING_DOWN)
            {
                APPL_TRACE_WARNING("%s: A2DP command %s while media task shutting down",
                                   __func__, dump_a2dp_ctrl_event(cmd));
                a2dp_cmd_acknowledge(A2DP_CTRL_ACK_FAILURE);
                return;
            }

            /* check whether av is ready to setup a2dp datapath */
            if ((btif_av_stream_ready() == true) || (btif_av_stream_started_ready() == true))
            {
                a2dp_cmd_acknowledge(A2DP_CTRL_ACK_SUCCESS);
            }
            else
            {
                APPL_TRACE_WARNING("%s: A2DP command %s while AV stream is not ready",
                                   __func__, dump_a2dp_ctrl_event(cmd));
                a2dp_cmd_acknowledge(A2DP_CTRL_ACK_FAILURE);
            }
            break;

        case A2DP_CTRL_CMD_START:
            /* Don't sent START request to stack while we are in call.
               Some headsets like the Sony MW600, don't allow AVDTP START
               in call and respond BAD_STATE. */
            if (!btif_hf_is_call_idle())
            {
                a2dp_cmd_acknowledge(A2DP_CTRL_ACK_INCALL_FAILURE);
                break;
            }

            if (alarm_is_scheduled(btif_media_cb.media_alarm))
            {
                APPL_TRACE_WARNING("%s: A2DP command %s when media alarm already scheduled",
                                   __func__, dump_a2dp_ctrl_event(cmd));
                a2dp_cmd_acknowledge(A2DP_CTRL_ACK_FAILURE);
                break;
            }

            if (btif_av_stream_ready() == true)
            {
                /* setup audio data channel listener */
                UIPC_Open(UIPC_CH_ID_AV_AUDIO, btif_a2dp_data_cb);

                /* post start event and wait for audio path to open */
                btif_dispatch_sm_event(BTIF_AV_START_STREAM_REQ_EVT, NULL, 0);

#if (BTA_AV_SINK_INCLUDED == TRUE)
                if (btif_media_cb.peer_sep == AVDT_TSEP_SRC)
                    a2dp_cmd_acknowledge(A2DP_CTRL_ACK_SUCCESS);
#endif
            }
            else if (btif_av_stream_started_ready())
            {
                /* already started, setup audio data channel listener
                   and ack back immediately */
                UIPC_Open(UIPC_CH_ID_AV_AUDIO, btif_a2dp_data_cb);

                a2dp_cmd_acknowledge(A2DP_CTRL_ACK_SUCCESS);
            }
            else
            {
                APPL_TRACE_WARNING("%s: A2DP command %s while AV stream is not ready",
                                   __func__, dump_a2dp_ctrl_event(cmd));
                a2dp_cmd_acknowledge(A2DP_CTRL_ACK_FAILURE);
                break;
            }
            break;

        case A2DP_CTRL_CMD_STOP:
            if (btif_media_cb.peer_sep == AVDT_TSEP_SNK &&
                (!alarm_is_scheduled(btif_media_cb.media_alarm)))
            {
                /* we are already stopped, just ack back */
                a2dp_cmd_acknowledge(A2DP_CTRL_ACK_SUCCESS);
                break;
            }

            btif_dispatch_sm_event(BTIF_AV_STOP_STREAM_REQ_EVT, NULL, 0);
            a2dp_cmd_acknowledge(A2DP_CTRL_ACK_SUCCESS);
            break;

        case A2DP_CTRL_CMD_SUSPEND:
            /* local suspend */
            if (btif_av_stream_started_ready())
            {
                btif_dispatch_sm_event(BTIF_AV_SUSPEND_STREAM_REQ_EVT, NULL, 0);
            }
            else
            {
                /* if we are not in started state, just ack back ok and let
                   audioflinger close the channel. This can happen if we are
                   remotely suspended, clear REMOTE SUSPEND Flag */
                btif_av_clear_remote_suspend_flag();
                a2dp_cmd_acknowledge(A2DP_CTRL_ACK_SUCCESS);
            }
            break;

        case A2DP_CTRL_GET_AUDIO_CONFIG:
        {
            uint32_t sample_rate = btif_media_cb.sample_rate;
            uint8_t channel_count = btif_media_cb.channel_count;

            a2dp_cmd_acknowledge(A2DP_CTRL_ACK_SUCCESS);
            UIPC_Send(UIPC_CH_ID_AV_CTRL, 0, (uint8_t *)&sample_rate, 4);
            UIPC_Send(UIPC_CH_ID_AV_CTRL, 0, &channel_count, 1);
            break;
        }

        case A2DP_CTRL_CMD_OFFLOAD_START:
                btif_dispatch_sm_event(BTIF_AV_OFFLOAD_START_REQ_EVT, NULL, 0);
            break;

        default:
            APPL_TRACE_ERROR("UNSUPPORTED CMD (%d)", cmd);
            a2dp_cmd_acknowledge(A2DP_CTRL_ACK_FAILURE);
            break;
    }
    APPL_TRACE_DEBUG("a2dp-ctrl-cmd : %s DONE", dump_a2dp_ctrl_event(cmd));
}

static void btif_a2dp_ctrl_cb(tUIPC_CH_ID ch_id, tUIPC_EVENT event)
{
    UNUSED(ch_id);

    APPL_TRACE_DEBUG("A2DP-CTRL-CHANNEL EVENT %s", dump_uipc_event(event));

    switch (event)
    {
        case UIPC_OPEN_EVT:
            break;

        case UIPC_CLOSE_EVT:
            /* restart ctrl server unless we are shutting down */
            if (media_task_running == MEDIA_TASK_STATE_ON)
                UIPC_Open(UIPC_CH_ID_AV_CTRL , btif_a2dp_ctrl_cb);
            break;

        case UIPC_RX_DATA_READY_EVT:
            btif_recv_ctrl_data();
            break;

        default :
            APPL_TRACE_ERROR("### A2DP-CTRL-CHANNEL EVENT %d NOT HANDLED ###", event);
            break;
    }
}

static void btif_a2dp_data_cb(tUIPC_CH_ID ch_id, tUIPC_EVENT event)
{
    UNUSED(ch_id);

    APPL_TRACE_DEBUG("BTIF MEDIA (A2DP-DATA) EVENT %s", dump_uipc_event(event));

    switch (event)
    {
        case UIPC_OPEN_EVT:

            /*  read directly from media task from here on (keep callback for
                connection events */
            UIPC_Ioctl(UIPC_CH_ID_AV_AUDIO, UIPC_REG_REMOVE_ACTIVE_READSET, NULL);
            UIPC_Ioctl(UIPC_CH_ID_AV_AUDIO, UIPC_SET_READ_POLL_TMO,
                       (void *)A2DP_DATA_READ_POLL_MS);

            if (btif_media_cb.peer_sep == AVDT_TSEP_SNK) {
                /* Start the media task to encode SBC */
                btif_media_task_start_aa_req();

                /* make sure we update any changed sbc encoder params */
                btif_a2dp_encoder_update();
            }
            btif_media_cb.data_channel_open = true;

            /* ack back when media task is fully started */
            break;

        case UIPC_CLOSE_EVT:
            a2dp_cmd_acknowledge(A2DP_CTRL_ACK_SUCCESS);
            btif_audiopath_detached();
            btif_media_cb.data_channel_open = false;
            break;

        default :
            APPL_TRACE_ERROR("### A2DP-DATA EVENT %d NOT HANDLED ###", event);
            break;
    }
}


/*****************************************************************************
 **  BTIF ADAPTATION
 *****************************************************************************/

static uint16_t btif_media_task_get_sbc_rate(void)
{
    uint16_t rate = BTIF_A2DP_DEFAULT_BITRATE;

    /* restrict bitrate if a2dp link is non-edr */
    if (!btif_av_is_peer_edr())
    {
        rate = BTIF_A2DP_NON_EDR_MAX_RATE;
        APPL_TRACE_DEBUG("non-edr a2dp sink detected, restrict rate to %d", rate);
    }

    return rate;
}

static void btif_a2dp_encoder_init(void)
{
    tBTIF_MEDIA_INIT_AUDIO msg;

    APPL_TRACE_DEBUG("%s", __func__);

    bta_av_co_audio_encoder_init(&msg);

    /* Init the media task to encode audio properly */
    btif_media_task_enc_init_req(&msg);
}

static void btif_a2dp_encoder_update(void)
{
    tBTIF_MEDIA_UPDATE_AUDIO msg;

    APPL_TRACE_DEBUG("%s", __func__);

    bta_av_co_audio_encoder_update(&msg);

    /* Update the media task to encode audio properly */
    btif_media_task_enc_update_req(&msg);
}

bool btif_a2dp_start_media_task(void)
{
    if (media_task_running != MEDIA_TASK_STATE_OFF)
    {
        APPL_TRACE_ERROR("warning : media task already running");
        return false;
    }

    APPL_TRACE_EVENT("## A2DP START MEDIA THREAD ##");

    btif_media_cmd_msg_queue = fixed_queue_new(SIZE_MAX);

    /* start a2dp media task */
    worker_thread = thread_new("media_worker");
    if (worker_thread == NULL)
        goto error_exit;

    fixed_queue_register_dequeue(btif_media_cmd_msg_queue,
        thread_get_reactor(worker_thread),
        btif_media_thread_handle_cmd,
        NULL);

    thread_post(worker_thread, btif_media_thread_init, NULL);
    APPL_TRACE_EVENT("## A2DP MEDIA THREAD STARTED ##");

    return true;

 error_exit:;
    APPL_TRACE_ERROR("%s unable to start up media thread", __func__);
    return false;
}

void btif_a2dp_stop_media_task(void)
{
    APPL_TRACE_EVENT("## A2DP STOP MEDIA THREAD ##");

    // Stop timer
    alarm_free(btif_media_cb.media_alarm);
    btif_media_cb.media_alarm = NULL;

    // Exit thread
    fixed_queue_free(btif_media_cmd_msg_queue, NULL);
    btif_media_cmd_msg_queue = NULL;
    thread_post(worker_thread, btif_media_thread_cleanup, NULL);
    thread_free(worker_thread);
    worker_thread = NULL;
}

/*****************************************************************************
**
** Function        btif_a2dp_on_init
**
** Description
**
** Returns
**
*******************************************************************************/

void btif_a2dp_on_init(void)
{
#ifdef USE_AUDIO_TRACK
    btif_media_cb.rx_audio_focus_state = BTIF_MEDIA_FOCUS_NOT_GRANTED;
    btif_media_cb.audio_track = NULL;
#endif
}


/*****************************************************************************
**
** Function        btif_a2dp_setup_codec
**
** Description
**
** Returns
**
*******************************************************************************/

void btif_a2dp_setup_codec(void)
{
    tA2D_AV_MEDIA_FEEDINGS media_feeding;

    APPL_TRACE_EVENT("## A2DP SETUP CODEC ##");

    mutex_global_lock();

    /* for now hardcode 44.1 khz 16 bit stereo PCM format */
    media_feeding.cfg.pcm.sampling_freq = BTIF_A2DP_SRC_SAMPLING_RATE;
    media_feeding.cfg.pcm.bit_per_sample = BTIF_A2DP_SRC_BIT_DEPTH;
    media_feeding.cfg.pcm.num_channel = BTIF_A2DP_SRC_NUM_CHANNELS;
    media_feeding.format = tA2D_AV_CODEC_PCM;

    if (bta_av_co_audio_set_codec(&media_feeding))
    {
        tBTIF_MEDIA_INIT_AUDIO_FEEDING mfeed;

        /* Init the encoding task */
        btif_a2dp_encoder_init();

        /* Build the media task configuration */
        mfeed.feeding = media_feeding;
        mfeed.feeding_mode = BTIF_AV_FEEDING_ASYNCHRONOUS;
        /* Send message to Media task to configure transcoding */
        btif_media_task_audio_feeding_init_req(&mfeed);
    }

    mutex_global_unlock();
}


/*****************************************************************************
**
** Function        btif_a2dp_on_idle
**
** Description
**
** Returns
**
*******************************************************************************/

void btif_a2dp_on_idle(void)
{
    APPL_TRACE_EVENT("## ON A2DP IDLE ## peer_sep = %d", btif_media_cb.peer_sep);
    if (btif_media_cb.peer_sep == AVDT_TSEP_SNK)
    {
        /* Make sure media task is stopped */
        btif_media_task_stop_aa_req();
    }

    bta_av_co_init();
#if (BTA_AV_SINK_INCLUDED == TRUE)
    if (btif_media_cb.peer_sep == AVDT_TSEP_SRC)
    {
        btif_media_cb.rx_flush = true;
        btif_media_task_aa_rx_flush_req();
        btif_media_task_aa_handle_stop_decoding();
        btif_media_task_clear_track();
        APPL_TRACE_DEBUG("Stopped BT track");
    }
#endif
}

/*****************************************************************************
**
** Function        btif_a2dp_on_open
**
** Description
**
** Returns
**
*******************************************************************************/

void btif_a2dp_on_open(void)
{
    APPL_TRACE_EVENT("## ON A2DP OPEN ##");

    /* always use callback to notify socket events */
    UIPC_Open(UIPC_CH_ID_AV_AUDIO, btif_a2dp_data_cb);
}

/*******************************************************************************
 **
 ** Function         btif_media_task_clear_track
 **
 ** Description
 **
 ** Returns          true is success
 **
 *******************************************************************************/
bool btif_media_task_clear_track(void)
{
    BT_HDR *p_buf = (BT_HDR *)osi_malloc(sizeof(BT_HDR));

    p_buf->event = BTIF_MEDIA_AUDIO_SINK_CLEAR_TRACK;
    fixed_queue_enqueue(btif_media_cmd_msg_queue, p_buf);

    return true;
}

/*****************************************************************************
**
** Function        btif_reset_decoder
**
** Description
**
** Returns
**
*******************************************************************************/

void btif_reset_decoder(uint8_t *p_av)
{
    tBTIF_MEDIA_SINK_CFG_UPDATE *p_buf = (tBTIF_MEDIA_SINK_CFG_UPDATE *)
        osi_malloc(sizeof(tBTIF_MEDIA_SINK_CFG_UPDATE));

    APPL_TRACE_EVENT("btif_reset_decoder");
    APPL_TRACE_DEBUG("btif_reset_decoder p_codec_info[%x:%x:%x:%x:%x:%x]",
            p_av[1], p_av[2], p_av[3],
            p_av[4], p_av[5], p_av[6]);

    memcpy(p_buf->codec_info,p_av, AVDT_CODEC_SIZE);
    p_buf->hdr.event = BTIF_MEDIA_AUDIO_SINK_CFG_UPDATE;

    fixed_queue_enqueue(btif_media_cmd_msg_queue, p_buf);
}

/*****************************************************************************
**
** Function        btif_a2dp_on_started
**
** Description
**
** Returns
**
*******************************************************************************/

bool btif_a2dp_on_started(tBTA_AV_START *p_av, bool pending_start)
{
    bool ack = false;

    APPL_TRACE_EVENT("## ON A2DP STARTED ##");

    if (p_av == NULL)
    {
        /* ack back a local start request */
        a2dp_cmd_acknowledge(A2DP_CTRL_ACK_SUCCESS);
        return true;
    }

    if (p_av->status == BTA_AV_SUCCESS)
    {
        if (p_av->suspending == false)
        {
            if (p_av->initiator)
            {
                if (pending_start) {
                    a2dp_cmd_acknowledge(A2DP_CTRL_ACK_SUCCESS);
                    ack = true;
                }
            }
            else
            {
                /* we were remotely started,  make sure codec
                   is setup before datapath is started */
                btif_a2dp_setup_codec();
            }

            /* media task is autostarted upon a2dp audiopath connection */
        }
    }
    else if (pending_start)
    {
        APPL_TRACE_WARNING("%s: A2DP start request failed: status = %d",
                         __func__, p_av->status);
        a2dp_cmd_acknowledge(A2DP_CTRL_ACK_FAILURE);
        ack = true;
    }
    return ack;
}


/*****************************************************************************
**
** Function        btif_a2dp_ack_fail
**
** Description
**
** Returns
**
*******************************************************************************/

void btif_a2dp_ack_fail(void)
{
    APPL_TRACE_EVENT("## A2DP_CTRL_ACK_FAILURE ##");
    a2dp_cmd_acknowledge(A2DP_CTRL_ACK_FAILURE);
}

/*****************************************************************************
**
** Function        btif_a2dp_on_stopped
**
** Description
**
** Returns
**
*******************************************************************************/

void btif_a2dp_on_stopped(tBTA_AV_SUSPEND *p_av)
{
    APPL_TRACE_EVENT("## ON A2DP STOPPED ##");
    if (btif_media_cb.peer_sep == AVDT_TSEP_SRC) /*  Handling for A2DP SINK cases*/
    {
        btif_media_cb.rx_flush = true;
        btif_media_task_aa_rx_flush_req();
        btif_media_task_aa_handle_stop_decoding();
#ifndef USE_AUDIO_TRACK
        UIPC_Close(UIPC_CH_ID_AV_AUDIO);
#endif
        btif_media_cb.data_channel_open = false;
        return;
    }
    /* allow using this api for other than suspend */
    if (p_av != NULL)
    {
        if (p_av->status != BTA_AV_SUCCESS)
        {
            APPL_TRACE_EVENT("AV STOP FAILED (%d)", p_av->status);

            if (p_av->initiator) {
                APPL_TRACE_WARNING("%s: A2DP stop request failed: status = %d",
                                   __func__, p_av->status);
                a2dp_cmd_acknowledge(A2DP_CTRL_ACK_FAILURE);
            }
            return;
        }
    }

    /* ensure tx frames are immediately suspended */
    btif_media_cb.tx_flush = 1;

    /* request to stop media task  */
    btif_media_task_aa_tx_flush_req();
    btif_media_task_stop_aa_req();

    /* once stream is fully stopped we will ack back */
}


/*****************************************************************************
**
** Function        btif_a2dp_on_suspended
**
** Description
**
** Returns
**
*******************************************************************************/

void btif_a2dp_on_suspended(tBTA_AV_SUSPEND *p_av)
{
    APPL_TRACE_EVENT("## ON A2DP SUSPENDED ##");
    if (btif_media_cb.peer_sep == AVDT_TSEP_SRC)
    {
        btif_media_cb.rx_flush = true;
        btif_media_task_aa_rx_flush_req();
        btif_media_task_aa_handle_stop_decoding();
#ifndef USE_AUDIO_TRACK
        UIPC_Close(UIPC_CH_ID_AV_AUDIO);
#endif
        return;
    }

    /* check for status failures */
    if (p_av->status != BTA_AV_SUCCESS)
    {
        if (p_av->initiator == true) {
            APPL_TRACE_WARNING("%s: A2DP suspend request failed: status = %d",
                               __func__, p_av->status);
            a2dp_cmd_acknowledge(A2DP_CTRL_ACK_FAILURE);
        }
    }

    /* once stream is fully stopped we will ack back */

    /* ensure tx frames are immediately flushed */
    btif_media_cb.tx_flush = 1;

    /* stop timer tick */
    btif_media_task_stop_aa_req();
}


/*****************************************************************************
**
** Function        btif_a2dp_on_offload_started
**
** Description
**
** Returns
**
*******************************************************************************/
void btif_a2dp_on_offload_started(tBTA_AV_STATUS status)
{
    tA2DP_CTRL_ACK ack;
    APPL_TRACE_EVENT("%s status %d", __func__, status);

    switch (status) {
        case BTA_AV_SUCCESS:
            ack = A2DP_CTRL_ACK_SUCCESS;
            break;

        case BTA_AV_FAIL_RESOURCES:
            APPL_TRACE_ERROR("%s FAILED UNSUPPORTED", __func__);
            ack = A2DP_CTRL_ACK_UNSUPPORTED;
            break;
        default:
            APPL_TRACE_ERROR("%s FAILED: status = %d", __func__, status);
            ack = A2DP_CTRL_ACK_FAILURE;
            break;
    }
    a2dp_cmd_acknowledge(ack);
}

/* when true media task discards any rx frames */
void btif_a2dp_set_rx_flush(bool enable)
{
    APPL_TRACE_EVENT("## DROP RX %d ##", enable);
    btif_media_cb.rx_flush = enable;
}

/* when true media task discards any tx frames */
void btif_a2dp_set_tx_flush(bool enable)
{
    APPL_TRACE_EVENT("## DROP TX %d ##", enable);
    btif_media_cb.tx_flush = enable;
}

#ifdef USE_AUDIO_TRACK
void btif_a2dp_set_audio_focus_state(btif_media_audio_focus_state state)
{
    tBTIF_MEDIA_SINK_FOCUS_UPDATE *p_buf = (tBTIF_MEDIA_SINK_FOCUS_UPDATE *)
        osi_malloc(sizeof(tBTIF_MEDIA_SINK_FOCUS_UPDATE));

    APPL_TRACE_EVENT("%s", __func__);

    p_buf->focus_state = state;
    p_buf->hdr.event = BTIF_MEDIA_AUDIO_SINK_SET_FOCUS_STATE;
    fixed_queue_enqueue(btif_media_cmd_msg_queue, p_buf);
}

void btif_a2dp_set_audio_track_gain(float gain)
{
    APPL_TRACE_DEBUG("%s set gain to %f", __func__, gain);
    BtifAvrcpSetAudioTrackGain(btif_media_cb.audio_track, gain);
}
#endif

#if (BTA_AV_SINK_INCLUDED == TRUE)
static void btif_media_task_avk_handle_timer(UNUSED_ATTR void *context)
{
    tBT_SBC_HDR *p_msg;
    int num_sbc_frames;
    int num_frames_to_process;

    if (fixed_queue_is_empty(btif_media_cb.RxSbcQ))
    {
        APPL_TRACE_DEBUG("  QUE  EMPTY ");
    }
    else
    {
#ifdef USE_AUDIO_TRACK
        /* Don't Do anything in case of Not granted */
        if (btif_media_cb.rx_audio_focus_state == BTIF_MEDIA_FOCUS_NOT_GRANTED)
        {
            APPL_TRACE_DEBUG("%s skipping frames since focus is not present.", __func__);
            return;
        }
        /* play only in BTIF_MEDIA_FOCUS_GRANTED case */
#endif
        if (btif_media_cb.rx_flush == true)
        {
            btif_media_flush_q(btif_media_cb.RxSbcQ);
            return;
        }

        num_frames_to_process = btif_media_cb.frames_to_process;
        APPL_TRACE_DEBUG(" Process Frames + ");

        do
        {
            p_msg = (tBT_SBC_HDR *)fixed_queue_try_peek_first(btif_media_cb.RxSbcQ);
            if (p_msg == NULL)
                return;
            num_sbc_frames  = p_msg->num_frames_to_be_processed; /* num of frames in Que Packets */
            APPL_TRACE_DEBUG(" Frames left in topmost packet %d", num_sbc_frames);
            APPL_TRACE_DEBUG(" Remaining frames to process in tick %d", num_frames_to_process);
            APPL_TRACE_DEBUG(" Num of Packets in Que %d",
                             fixed_queue_length(btif_media_cb.RxSbcQ));

            if ( num_sbc_frames > num_frames_to_process) /*  Que Packet has more frames*/
            {
                 p_msg->num_frames_to_be_processed= num_frames_to_process;
                 btif_media_task_handle_inc_media(p_msg);
                 p_msg->num_frames_to_be_processed = num_sbc_frames - num_frames_to_process;
                 num_frames_to_process = 0;
                 break;
            }
            else                                        /*  Que packet has less frames */
            {
                btif_media_task_handle_inc_media(p_msg);
                p_msg = (tBT_SBC_HDR *)fixed_queue_try_dequeue(btif_media_cb.RxSbcQ);
                if( p_msg == NULL )
                {
                     APPL_TRACE_ERROR("Insufficient data in que ");
                     break;
                }
                num_frames_to_process = num_frames_to_process - p_msg->num_frames_to_be_processed;
                osi_free(p_msg);
            }
        } while(num_frames_to_process > 0);

        APPL_TRACE_DEBUG(" Process Frames - ");
    }
}
#else
static void btif_media_task_avk_handle_timer(UNUSED_ATTR void *context) {}
#endif

static void btif_media_task_aa_handle_timer(UNUSED_ATTR void *context)
{
    uint64_t timestamp_us = time_now_us();
    log_tstamps_us("media task tx timer", timestamp_us);

    if (alarm_is_scheduled(btif_media_cb.media_alarm))
    {
        btif_media_send_aa_frame(timestamp_us);
    }
    else
    {
        APPL_TRACE_ERROR("ERROR Media task Scheduled after Suspend");
    }
}

static void btif_media_task_aa_handle_uipc_rx_rdy(void)
{
    /* process all the UIPC data */
    btif_media_aa_prep_2_send(0xFF, time_now_us());

    /* send it */
    LOG_VERBOSE(LOG_TAG, "%s calls bta_av_ci_src_data_ready", __func__);
    bta_av_ci_src_data_ready(BTA_AV_CHNL_AUDIO);
}

static void btif_media_thread_init(UNUSED_ATTR void *context) {
  // Check to make sure the platform has 8 bits/byte since
  // we're using that in frame size calculations now.
  assert(CHAR_BIT == 8);

  memset(&btif_media_cb, 0, sizeof(btif_media_cb));
  btif_media_cb.stats.session_start_us = time_now_us();

  UIPC_Init(NULL);

  btif_media_cb.TxAaQ = fixed_queue_new(SIZE_MAX);
  btif_media_cb.RxSbcQ = fixed_queue_new(SIZE_MAX);
  UIPC_Open(UIPC_CH_ID_AV_CTRL , btif_a2dp_ctrl_cb);

  raise_priority_a2dp(TASK_HIGH_MEDIA);
  media_task_running = MEDIA_TASK_STATE_ON;
}

static void btif_media_thread_cleanup(UNUSED_ATTR void *context) {
  /* make sure no channels are restarted while shutting down */
  media_task_running = MEDIA_TASK_STATE_SHUTTING_DOWN;

  /* this calls blocks until uipc is fully closed */
  UIPC_Close(UIPC_CH_ID_ALL);

  fixed_queue_free(btif_media_cb.TxAaQ, NULL);
  btif_media_cb.TxAaQ = NULL;
  fixed_queue_free(btif_media_cb.RxSbcQ, NULL);
  btif_media_cb.RxSbcQ = NULL;

  /* Clear media task flag */
  media_task_running = MEDIA_TASK_STATE_OFF;
}

/*******************************************************************************
 **
 ** Function         btif_media_task_send_cmd_evt
 **
 ** Description
 **
 ** Returns          true is success
 **
 *******************************************************************************/
bool btif_media_task_send_cmd_evt(uint16_t Evt)
{
    BT_HDR *p_buf = (BT_HDR *)osi_malloc(sizeof(BT_HDR));

    p_buf->event = Evt;
    fixed_queue_enqueue(btif_media_cmd_msg_queue, p_buf);

    return true;
}

/*******************************************************************************
 **
 ** Function         btif_media_flush_q
 **
 ** Description
 **
 ** Returns          void
 **
 *******************************************************************************/
static void btif_media_flush_q(fixed_queue_t *p_q)
{
    while (! fixed_queue_is_empty(p_q))
    {
        osi_free(fixed_queue_try_dequeue(p_q));
    }
}

static void btif_media_thread_handle_cmd(fixed_queue_t *queue, UNUSED_ATTR void *context)
{
    BT_HDR *p_msg = (BT_HDR *)fixed_queue_dequeue(queue);
    LOG_VERBOSE(LOG_TAG, "btif_media_thread_handle_cmd : %d %s", p_msg->event,
             dump_media_event(p_msg->event));

    switch (p_msg->event)
    {
    case BTIF_MEDIA_START_AA_TX:
        btif_media_task_aa_start_tx();
        break;
    case BTIF_MEDIA_STOP_AA_TX:
        btif_media_task_aa_stop_tx();
        break;
    case BTIF_MEDIA_SBC_ENC_INIT:
        btif_media_task_enc_init(p_msg);
        break;
    case BTIF_MEDIA_SBC_ENC_UPDATE:
        btif_media_task_enc_update(p_msg);
        break;
    case BTIF_MEDIA_AUDIO_FEEDING_INIT:
        btif_media_task_audio_feeding_init(p_msg);
        break;
    case BTIF_MEDIA_FLUSH_AA_TX:
        btif_media_task_aa_tx_flush(p_msg);
        break;
    case BTIF_MEDIA_UIPC_RX_RDY:
        btif_media_task_aa_handle_uipc_rx_rdy();
        break;
#ifdef USE_AUDIO_TRACK
    case BTIF_MEDIA_AUDIO_SINK_SET_FOCUS_STATE:
        if(!btif_av_is_connected())
            break;
        btif_media_cb.rx_audio_focus_state = ((btif_media_audio_focus_state)
            ((tBTIF_MEDIA_SINK_FOCUS_UPDATE *)p_msg)->focus_state);
        APPL_TRACE_DEBUG("Setting focus state to %d ",btif_media_cb.rx_audio_focus_state);
        break;
#endif
    case BTIF_MEDIA_AUDIO_SINK_CFG_UPDATE:
#if (BTA_AV_SINK_INCLUDED == TRUE)
        btif_media_task_aa_handle_decoder_reset(p_msg);
#endif
        break;
    case BTIF_MEDIA_AUDIO_SINK_CLEAR_TRACK:
#if (BTA_AV_SINK_INCLUDED == TRUE)
        btif_media_task_aa_handle_clear_track();
#endif
        break;
     case BTIF_MEDIA_FLUSH_AA_RX:
        btif_media_task_aa_rx_flush();
        break;
    default:
        APPL_TRACE_ERROR("ERROR in %s unknown event %d", __func__, p_msg->event);
    }
    osi_free(p_msg);
    LOG_VERBOSE(LOG_TAG, "%s: %s DONE", __func__, dump_media_event(p_msg->event));
}

#if (BTA_AV_SINK_INCLUDED == TRUE)
/*******************************************************************************
 **
 ** Function         btif_media_task_handle_inc_media
 **
 ** Description
 **
 ** Returns          void
 **
 *******************************************************************************/
static void btif_media_task_handle_inc_media(tBT_SBC_HDR*p_msg)
{
    uint8_t *sbc_start_frame = ((uint8_t*)(p_msg + 1) + p_msg->offset + 1);
    int count;
    uint32_t pcmBytes, availPcmBytes;
    OI_INT16 *pcmDataPointer = pcmData; /*Will be overwritten on next packet receipt*/
    OI_STATUS status;
    int num_sbc_frames = p_msg->num_frames_to_be_processed;
    uint32_t sbc_frame_len = p_msg->len - 1;
    availPcmBytes = sizeof(pcmData);

    if ((btif_media_cb.peer_sep == AVDT_TSEP_SNK) || (btif_media_cb.rx_flush))
    {
        APPL_TRACE_DEBUG(" State Changed happened in this tick ");
        return;
    }
#ifndef USE_AUDIO_TRACK
    // ignore data if no one is listening
    if (!btif_media_cb.data_channel_open)
    {
        APPL_TRACE_ERROR("%s Channel not open, returning", __func__);
        return;
    }
#endif
    APPL_TRACE_DEBUG("%s Number of sbc frames %d, frame_len %d",
                     __func__, num_sbc_frames, sbc_frame_len);

    for(count = 0; count < num_sbc_frames && sbc_frame_len != 0; count ++)
    {
        pcmBytes = availPcmBytes;
        status = OI_CODEC_SBC_DecodeFrame(&context, (const OI_BYTE**)&sbc_start_frame,
                                                        (OI_UINT32 *)&sbc_frame_len,
                                                        (OI_INT16 *)pcmDataPointer,
                                                        (OI_UINT32 *)&pcmBytes);
        if (!OI_SUCCESS(status)) {
            APPL_TRACE_ERROR("Decoding failure: %d\n", status);
            break;
        }
        availPcmBytes -= pcmBytes;
        pcmDataPointer += pcmBytes/2;
        p_msg->offset += (p_msg->len - 1) - sbc_frame_len;
        p_msg->len = sbc_frame_len + 1;
    }

#ifdef USE_AUDIO_TRACK
    BtifAvrcpAudioTrackWriteData(
        btif_media_cb.audio_track, (void*)pcmData, (sizeof(pcmData) - availPcmBytes));
#else
    UIPC_Send(UIPC_CH_ID_AV_AUDIO, 0, (uint8_t *)pcmData, (sizeof(pcmData) - availPcmBytes));
#endif
}
#endif

/*******************************************************************************
 **
 ** Function         btif_media_task_enc_init_req
 **
 ** Description
 **
 ** Returns          true is success
 **
 *******************************************************************************/
bool btif_media_task_enc_init_req(tBTIF_MEDIA_INIT_AUDIO *p_msg)
{
    tBTIF_MEDIA_INIT_AUDIO *p_buf = (tBTIF_MEDIA_INIT_AUDIO *)osi_malloc(sizeof(tBTIF_MEDIA_INIT_AUDIO));

    memcpy(p_buf, p_msg, sizeof(tBTIF_MEDIA_INIT_AUDIO));
    p_buf->hdr.event = BTIF_MEDIA_SBC_ENC_INIT;
    fixed_queue_enqueue(btif_media_cmd_msg_queue, p_buf);

    return true;
}

/*******************************************************************************
 **
 ** Function         btif_media_task_enc_update_req
 **
 ** Description
 **
 ** Returns          true is success
 **
 *******************************************************************************/
bool btif_media_task_enc_update_req(tBTIF_MEDIA_UPDATE_AUDIO *p_msg)
{
    tBTIF_MEDIA_UPDATE_AUDIO *p_buf = (tBTIF_MEDIA_UPDATE_AUDIO *)
        osi_malloc(sizeof(tBTIF_MEDIA_UPDATE_AUDIO));

    memcpy(p_buf, p_msg, sizeof(tBTIF_MEDIA_UPDATE_AUDIO));
    p_buf->hdr.event = BTIF_MEDIA_SBC_ENC_UPDATE;
    fixed_queue_enqueue(btif_media_cmd_msg_queue, p_buf);

    return true;
}

/*******************************************************************************
 **
 ** Function         btif_media_task_audio_feeding_init_req
 **
 ** Description
 **
 ** Returns          true is success
 **
 *******************************************************************************/
bool btif_media_task_audio_feeding_init_req(tBTIF_MEDIA_INIT_AUDIO_FEEDING *p_msg)
{
    tBTIF_MEDIA_INIT_AUDIO_FEEDING *p_buf = (tBTIF_MEDIA_INIT_AUDIO_FEEDING *)
        osi_malloc(sizeof(tBTIF_MEDIA_INIT_AUDIO_FEEDING));

    memcpy(p_buf, p_msg, sizeof(tBTIF_MEDIA_INIT_AUDIO_FEEDING));
    p_buf->hdr.event = BTIF_MEDIA_AUDIO_FEEDING_INIT;
    fixed_queue_enqueue(btif_media_cmd_msg_queue, p_buf);

    return true;
}

/*******************************************************************************
 **
 ** Function         btif_media_task_start_aa_req
 **
 ** Description
 **
 ** Returns          true is success
 **
 *******************************************************************************/
bool btif_media_task_start_aa_req(void)
{
    BT_HDR *p_buf = (BT_HDR *)osi_malloc(sizeof(BT_HDR));

    p_buf->event = BTIF_MEDIA_START_AA_TX;
    fixed_queue_enqueue(btif_media_cmd_msg_queue, p_buf);

    return true;
}

/*******************************************************************************
 **
 ** Function         btif_media_task_stop_aa_req
 **
 ** Description
 **
 ** Returns          true is success
 **
 *******************************************************************************/
bool btif_media_task_stop_aa_req(void)
{
    BT_HDR *p_buf = (BT_HDR *)osi_malloc(sizeof(BT_HDR));

    p_buf->event = BTIF_MEDIA_STOP_AA_TX;

    /*
     * Explicitly check whether the btif_media_cmd_msg_queue is not NULL to
     * avoid a race condition during shutdown of the Bluetooth stack.
     * This race condition is triggered when A2DP audio is streaming on
     * shutdown:
     * "btif_a2dp_on_stopped() -> btif_media_task_stop_aa_req()" is called
     * to stop the particular audio stream, and this happens right after
     * the "cleanup() -> btif_a2dp_stop_media_task()" processing during
     * the shutdown of the Bluetooth stack.
     */
    if (btif_media_cmd_msg_queue != NULL)
        fixed_queue_enqueue(btif_media_cmd_msg_queue, p_buf);

    return true;
}
/*******************************************************************************
 **
 ** Function         btif_media_task_aa_rx_flush_req
 **
 ** Description
 **
 ** Returns          true is success
 **
 *******************************************************************************/
bool btif_media_task_aa_rx_flush_req(void)
{
    if (fixed_queue_is_empty(btif_media_cb.RxSbcQ)) /*  Que is already empty */
        return true;

    BT_HDR *p_buf = (BT_HDR *)osi_malloc(sizeof(BT_HDR));
    p_buf->event = BTIF_MEDIA_FLUSH_AA_RX;
    fixed_queue_enqueue(btif_media_cmd_msg_queue, p_buf);

    return true;
}

/*******************************************************************************
 **
 ** Function         btif_media_task_aa_tx_flush_req
 **
 ** Description
 **
 ** Returns          true is success
 **
 *******************************************************************************/
bool btif_media_task_aa_tx_flush_req(void)
{
    BT_HDR *p_buf = (BT_HDR *)osi_malloc(sizeof(BT_HDR));

    p_buf->event = BTIF_MEDIA_FLUSH_AA_TX;

    /*
     * Explicitly check whether the btif_media_cmd_msg_queue is not NULL to
     * avoid a race condition during shutdown of the Bluetooth stack.
     * This race condition is triggered when A2DP audio is streaming on
     * shutdown:
     * "btif_a2dp_on_stopped() -> btif_media_task_aa_tx_flush_req()" is called
     * to stop the particular audio stream, and this happens right after
     * the "cleanup() -> btif_a2dp_stop_media_task()" processing during
     * the shutdown of the Bluetooth stack.
     */
    if (btif_media_cmd_msg_queue != NULL)
        fixed_queue_enqueue(btif_media_cmd_msg_queue, p_buf);

    return true;
}
/*******************************************************************************
 **
 ** Function         btif_media_task_aa_rx_flush
 **
 ** Description
 **
 ** Returns          void
 **
 *******************************************************************************/
static void btif_media_task_aa_rx_flush(void)
{
    /* Flush all enqueued GKI SBC  buffers (encoded) */
    APPL_TRACE_DEBUG("btif_media_task_aa_rx_flush");

    btif_media_flush_q(btif_media_cb.RxSbcQ);
}


/*******************************************************************************
 **
 ** Function         btif_media_task_aa_tx_flush
 **
 ** Description
 **
 ** Returns          void
 **
 *******************************************************************************/
static void btif_media_task_aa_tx_flush(BT_HDR *p_msg)
{
    UNUSED(p_msg);

    /* Flush all enqueued GKI music buffers (encoded) */
    APPL_TRACE_DEBUG("btif_media_task_aa_tx_flush");

    btif_media_cb.media_feeding_state.pcm.counter = 0;
    btif_media_cb.media_feeding_state.pcm.aa_feed_residue = 0;

    btif_media_cb.stats.tx_queue_total_flushed_messages +=
        fixed_queue_length(btif_media_cb.TxAaQ);
    btif_media_cb.stats.tx_queue_last_flushed_us = time_now_us();
    btif_media_flush_q(btif_media_cb.TxAaQ);

    UIPC_Ioctl(UIPC_CH_ID_AV_AUDIO, UIPC_REQ_RX_FLUSH, NULL);
}

/*******************************************************************************
 **
 ** Function       btif_media_task_enc_init
 **
 ** Description    Initialize encoding task
 **
 ** Returns        void
 **
 *******************************************************************************/
static void btif_media_task_enc_init(BT_HDR *p_msg)
{
    tBTIF_MEDIA_INIT_AUDIO *pInitAudio = (tBTIF_MEDIA_INIT_AUDIO *) p_msg;

    APPL_TRACE_DEBUG("btif_media_task_enc_init");

    btif_media_cb.timestamp = 0;

    /* SBC encoder config (enforced even if not used) */
    btif_media_cb.encoder.s16ChannelMode = pInitAudio->ChannelMode;
    btif_media_cb.encoder.s16NumOfSubBands = pInitAudio->NumOfSubBands;
    btif_media_cb.encoder.s16NumOfBlocks = pInitAudio->NumOfBlocks;
    btif_media_cb.encoder.s16AllocationMethod = pInitAudio->AllocationMethod;
    btif_media_cb.encoder.s16SamplingFreq = pInitAudio->SamplingFreq;

    btif_media_cb.encoder.u16BitRate = btif_media_task_get_sbc_rate();

    /* Default transcoding is PCM to SBC, modified by feeding configuration */
    btif_media_cb.TxTranscoding = BTIF_MEDIA_TRSCD_PCM_2_SBC;
    btif_media_cb.TxAaMtuSize = ((BTIF_MEDIA_AA_BUF_SIZE-BTIF_MEDIA_AA_SBC_OFFSET-sizeof(BT_HDR))
            < pInitAudio->MtuSize) ? (BTIF_MEDIA_AA_BUF_SIZE - BTIF_MEDIA_AA_SBC_OFFSET
            - sizeof(BT_HDR)) : pInitAudio->MtuSize;

    APPL_TRACE_EVENT("btif_media_task_enc_init busy %d, mtu %d, peer mtu %d",
                     btif_media_cb.busy_level, btif_media_cb.TxAaMtuSize, pInitAudio->MtuSize);
    APPL_TRACE_EVENT("      ch mode %d, subnd %d, nb blk %d, alloc %d, rate %d, freq %d",
            btif_media_cb.encoder.s16ChannelMode, btif_media_cb.encoder.s16NumOfSubBands,
            btif_media_cb.encoder.s16NumOfBlocks,
            btif_media_cb.encoder.s16AllocationMethod, btif_media_cb.encoder.u16BitRate,
            btif_media_cb.encoder.s16SamplingFreq);

    /* Reset entirely the SBC encoder */
    SBC_Encoder_Init(&(btif_media_cb.encoder));

    btif_media_cb.tx_sbc_frames = calculate_max_frames_per_packet();

    APPL_TRACE_DEBUG("%s bit pool %d", __func__, btif_media_cb.encoder.s16BitPool);
}

/*******************************************************************************
 **
 ** Function       btif_media_task_enc_update
 **
 ** Description    Update encoding task
 **
 ** Returns        void
 **
 *******************************************************************************/

static void btif_media_task_enc_update(BT_HDR *p_msg)
{
    tBTIF_MEDIA_UPDATE_AUDIO * pUpdateAudio = (tBTIF_MEDIA_UPDATE_AUDIO *) p_msg;
    SBC_ENC_PARAMS *pstrEncParams = &btif_media_cb.encoder;
    uint16_t s16SamplingFreq;
    SINT16 s16BitPool = 0;
    SINT16 s16BitRate;
    SINT16 s16FrameLen;
    uint8_t protect = 0;

    APPL_TRACE_DEBUG("%s : minmtu %d, maxbp %d minbp %d", __func__,
                     pUpdateAudio->MinMtuSize, pUpdateAudio->MaxBitPool,
                     pUpdateAudio->MinBitPool);

    if (!pstrEncParams->s16NumOfSubBands)
    {
        APPL_TRACE_WARNING("%s SubBands are set to 0, resetting to max (%d)",
          __func__, SBC_MAX_NUM_OF_SUBBANDS);
        pstrEncParams->s16NumOfSubBands = SBC_MAX_NUM_OF_SUBBANDS;
    }

    if (!pstrEncParams->s16NumOfBlocks)
    {
        APPL_TRACE_WARNING("%s Blocks are set to 0, resetting to max (%d)",
          __func__, SBC_MAX_NUM_OF_BLOCKS);
        pstrEncParams->s16NumOfBlocks = SBC_MAX_NUM_OF_BLOCKS;
    }

    if (!pstrEncParams->s16NumOfChannels)
    {
        APPL_TRACE_WARNING("%s Channels are set to 0, resetting to max (%d)",
          __func__, SBC_MAX_NUM_OF_CHANNELS);
        pstrEncParams->s16NumOfChannels = SBC_MAX_NUM_OF_CHANNELS;
    }

    btif_media_cb.TxAaMtuSize = ((BTIF_MEDIA_AA_BUF_SIZE -
                                  BTIF_MEDIA_AA_SBC_OFFSET - sizeof(BT_HDR))
            < pUpdateAudio->MinMtuSize) ? (BTIF_MEDIA_AA_BUF_SIZE - BTIF_MEDIA_AA_SBC_OFFSET
            - sizeof(BT_HDR)) : pUpdateAudio->MinMtuSize;

    /* Set the initial target bit rate */
    pstrEncParams->u16BitRate = btif_media_task_get_sbc_rate();

    if (pstrEncParams->s16SamplingFreq == SBC_sf16000)
        s16SamplingFreq = 16000;
    else if (pstrEncParams->s16SamplingFreq == SBC_sf32000)
        s16SamplingFreq = 32000;
    else if (pstrEncParams->s16SamplingFreq == SBC_sf44100)
        s16SamplingFreq = 44100;
    else
        s16SamplingFreq = 48000;

    do {
        if (pstrEncParams->s16NumOfBlocks == 0 ||
            pstrEncParams->s16NumOfSubBands == 0 ||
            pstrEncParams->s16NumOfChannels == 0) {
            APPL_TRACE_ERROR("%s - Avoiding division by zero...", __func__);
            APPL_TRACE_ERROR("%s - block=%d, subBands=%d, channels=%d",
                             __func__,
                             pstrEncParams->s16NumOfBlocks,
                             pstrEncParams->s16NumOfSubBands,
                             pstrEncParams->s16NumOfChannels);
            break;
        }

        if ((pstrEncParams->s16ChannelMode == SBC_JOINT_STEREO) ||
            (pstrEncParams->s16ChannelMode == SBC_STEREO)) {
            s16BitPool = (SINT16)((pstrEncParams->u16BitRate *
                    pstrEncParams->s16NumOfSubBands * 1000 / s16SamplingFreq)
                    - ((32 + (4 * pstrEncParams->s16NumOfSubBands *
                    pstrEncParams->s16NumOfChannels)
                    + ((pstrEncParams->s16ChannelMode - 2) *
                    pstrEncParams->s16NumOfSubBands))
                    / pstrEncParams->s16NumOfBlocks));

            s16FrameLen = 4 + (4*pstrEncParams->s16NumOfSubBands *
                    pstrEncParams->s16NumOfChannels) / 8
                    + (((pstrEncParams->s16ChannelMode - 2) *
                    pstrEncParams->s16NumOfSubBands)
                    + (pstrEncParams->s16NumOfBlocks * s16BitPool)) / 8;

            s16BitRate = (8 * s16FrameLen * s16SamplingFreq)
                    / (pstrEncParams->s16NumOfSubBands *
                    pstrEncParams->s16NumOfBlocks * 1000);

            if (s16BitRate > pstrEncParams->u16BitRate)
                s16BitPool--;

            if (pstrEncParams->s16NumOfSubBands == 8)
                s16BitPool = (s16BitPool > 255) ? 255 : s16BitPool;
            else
                s16BitPool = (s16BitPool > 128) ? 128 : s16BitPool;
        } else {
            s16BitPool = (SINT16)(((pstrEncParams->s16NumOfSubBands *
                    pstrEncParams->u16BitRate * 1000)
                    / (s16SamplingFreq * pstrEncParams->s16NumOfChannels))
                    - (((32 / pstrEncParams->s16NumOfChannels) +
                    (4 * pstrEncParams->s16NumOfSubBands))
                    / pstrEncParams->s16NumOfBlocks));

            pstrEncParams->s16BitPool =
                (s16BitPool > (16 * pstrEncParams->s16NumOfSubBands)) ?
                        (16 * pstrEncParams->s16NumOfSubBands) : s16BitPool;
        }

        if (s16BitPool < 0)
            s16BitPool = 0;

        APPL_TRACE_EVENT("%s bitpool candidate : %d (%d kbps)", __func__,
                         s16BitPool, pstrEncParams->u16BitRate);

        if (s16BitPool > pUpdateAudio->MaxBitPool) {
            APPL_TRACE_DEBUG("%s computed bitpool too large (%d)", __func__,
                             s16BitPool);
            /* Decrease bitrate */
            btif_media_cb.encoder.u16BitRate -= BTIF_MEDIA_BITRATE_STEP;
            /* Record that we have decreased the bitrate */
            protect |= 1;
        } else if (s16BitPool < pUpdateAudio->MinBitPool) {
            APPL_TRACE_WARNING("%s computed bitpool too small (%d)", __func__,
                               s16BitPool);

            /* Increase bitrate */
            uint16_t previous_u16BitRate = btif_media_cb.encoder.u16BitRate;
            btif_media_cb.encoder.u16BitRate += BTIF_MEDIA_BITRATE_STEP;
            /* Record that we have increased the bitrate */
            protect |= 2;
            /* Check over-flow */
            if (btif_media_cb.encoder.u16BitRate < previous_u16BitRate)
                protect |= 3;
        } else {
            break;
        }
        /* In case we have already increased and decreased the bitrate, just stop */
        if (protect == 3) {
            APPL_TRACE_ERROR("%s could not find bitpool in range", __func__);
            break;
        }
    } while (1);

    /* Finally update the bitpool in the encoder structure */
    pstrEncParams->s16BitPool = s16BitPool;

    APPL_TRACE_DEBUG("%s final bit rate %d, final bit pool %d", __func__,
                     btif_media_cb.encoder.u16BitRate,
                     btif_media_cb.encoder.s16BitPool);

    /* make sure we reinitialize encoder with new settings */
    SBC_Encoder_Init(&(btif_media_cb.encoder));

    btif_media_cb.tx_sbc_frames = calculate_max_frames_per_packet();
}

/*******************************************************************************
 **
 ** Function         btif_media_task_pcm2sbc_init
 **
 ** Description      Init encoding task for PCM to SBC according to feeding
 **
 ** Returns          void
 **
 *******************************************************************************/
static void btif_media_task_pcm2sbc_init(tBTIF_MEDIA_INIT_AUDIO_FEEDING * p_feeding)
{
    bool reconfig_needed = false;

    APPL_TRACE_DEBUG("PCM feeding:");
    APPL_TRACE_DEBUG("sampling_freq:%d", p_feeding->feeding.cfg.pcm.sampling_freq);
    APPL_TRACE_DEBUG("num_channel:%d", p_feeding->feeding.cfg.pcm.num_channel);
    APPL_TRACE_DEBUG("bit_per_sample:%d", p_feeding->feeding.cfg.pcm.bit_per_sample);

    /* Check the PCM feeding sampling_freq */
    switch (p_feeding->feeding.cfg.pcm.sampling_freq)
    {
        case  8000:
        case 12000:
        case 16000:
        case 24000:
        case 32000:
        case 48000:
            /* For these sampling_freq the AV connection must be 48000 */
            if (btif_media_cb.encoder.s16SamplingFreq != SBC_sf48000)
            {
                /* Reconfiguration needed at 48000 */
                APPL_TRACE_DEBUG("SBC Reconfiguration needed at 48000");
                btif_media_cb.encoder.s16SamplingFreq = SBC_sf48000;
                reconfig_needed = true;
            }
            break;

        case 11025:
        case 22050:
        case 44100:
            /* For these sampling_freq the AV connection must be 44100 */
            if (btif_media_cb.encoder.s16SamplingFreq != SBC_sf44100)
            {
                /* Reconfiguration needed at 44100 */
                APPL_TRACE_DEBUG("SBC Reconfiguration needed at 44100");
                btif_media_cb.encoder.s16SamplingFreq = SBC_sf44100;
                reconfig_needed = true;
            }
            break;
        default:
            APPL_TRACE_DEBUG("Feeding PCM sampling_freq unsupported");
            break;
    }

    /* Some AV Headsets do not support Mono => always ask for Stereo */
    if (btif_media_cb.encoder.s16ChannelMode == SBC_MONO)
    {
        APPL_TRACE_DEBUG("SBC Reconfiguration needed in Stereo");
        btif_media_cb.encoder.s16ChannelMode = SBC_JOINT_STEREO;
        reconfig_needed = true;
    }

    if (reconfig_needed != false)
    {
        APPL_TRACE_DEBUG("btif_media_task_pcm2sbc_init :: mtu %d", btif_media_cb.TxAaMtuSize);
        APPL_TRACE_DEBUG("ch mode %d, nbsubd %d, nb %d, alloc %d, rate %d, freq %d",
                btif_media_cb.encoder.s16ChannelMode,
                btif_media_cb.encoder.s16NumOfSubBands, btif_media_cb.encoder.s16NumOfBlocks,
                btif_media_cb.encoder.s16AllocationMethod, btif_media_cb.encoder.u16BitRate,
                btif_media_cb.encoder.s16SamplingFreq);

        SBC_Encoder_Init(&(btif_media_cb.encoder));
    }
    else
    {
        APPL_TRACE_DEBUG("btif_media_task_pcm2sbc_init no SBC reconfig needed");
    }
}


/*******************************************************************************
 **
 ** Function         btif_media_task_audio_feeding_init
 **
 ** Description      Initialize the audio path according to the feeding format
 **
 ** Returns          void
 **
 *******************************************************************************/
static void btif_media_task_audio_feeding_init(BT_HDR *p_msg)
{
    tBTIF_MEDIA_INIT_AUDIO_FEEDING *p_feeding = (tBTIF_MEDIA_INIT_AUDIO_FEEDING *) p_msg;

    APPL_TRACE_DEBUG("btif_media_task_audio_feeding_init format:%d", p_feeding->feeding.format);

    /* Save Media Feeding information */
    btif_media_cb.feeding_mode = p_feeding->feeding_mode;
    btif_media_cb.media_feeding = p_feeding->feeding;

    /* Handle different feeding formats */
    switch (p_feeding->feeding.format)
    {
        case tA2D_AV_CODEC_PCM:
            btif_media_cb.TxTranscoding = BTIF_MEDIA_TRSCD_PCM_2_SBC;
            btif_media_task_pcm2sbc_init(p_feeding);
            break;

        default :
            APPL_TRACE_ERROR("unknown feeding format %d", p_feeding->feeding.format);
            break;
    }
}

void btif_a2dp_set_peer_sep(uint8_t sep) {
    btif_media_cb.peer_sep = sep;
}

static void btif_decode_alarm_cb(UNUSED_ATTR void *context) {
  if(worker_thread != NULL)
      thread_post(worker_thread, btif_media_task_avk_handle_timer, NULL);
}

static void btif_media_task_aa_handle_stop_decoding(void) {
  alarm_free(btif_media_cb.decode_alarm);
  btif_media_cb.decode_alarm = NULL;
#ifdef USE_AUDIO_TRACK
  BtifAvrcpAudioTrackPause(btif_media_cb.audio_track);
#endif
}

static void btif_media_task_aa_handle_start_decoding(void) {
  if (btif_media_cb.decode_alarm)
    return;
#ifdef USE_AUDIO_TRACK
  BtifAvrcpAudioTrackStart(btif_media_cb.audio_track);
#endif
  btif_media_cb.decode_alarm = alarm_new_periodic("btif.media_decode");
  if (!btif_media_cb.decode_alarm) {
    LOG_ERROR(LOG_TAG, "%s unable to allocate decode alarm.", __func__);
    return;
  }

  alarm_set(btif_media_cb.decode_alarm, BTIF_SINK_MEDIA_TIME_TICK_MS,
            btif_decode_alarm_cb, NULL);
}

#if (BTA_AV_SINK_INCLUDED == TRUE)

static void btif_media_task_aa_handle_clear_track (void)
{
    APPL_TRACE_DEBUG("btif_media_task_aa_handle_clear_track");
#ifdef USE_AUDIO_TRACK
    BtifAvrcpAudioTrackStop(btif_media_cb.audio_track);
    BtifAvrcpAudioTrackDelete(btif_media_cb.audio_track);
    btif_media_cb.audio_track = NULL;
#endif
}

/*******************************************************************************
 **
 ** Function         btif_media_task_aa_handle_decoder_reset
 **
 ** Description
 **
 ** Returns          void
 **
 *******************************************************************************/
static void btif_media_task_aa_handle_decoder_reset(BT_HDR *p_msg)
{
    tBTIF_MEDIA_SINK_CFG_UPDATE *p_buf = (tBTIF_MEDIA_SINK_CFG_UPDATE*) p_msg;
    OI_STATUS       status;

    APPL_TRACE_DEBUG("%s: p_codec_info[%x:%x:%x:%x:%x:%x]", __func__,
            p_buf->codec_info[1], p_buf->codec_info[2], p_buf->codec_info[3],
            p_buf->codec_info[4], p_buf->codec_info[5], p_buf->codec_info[6]);

    int sample_rate = A2D_GetTrackFrequency(p_buf->codec_info);
    if (sample_rate == -1) {
        APPL_TRACE_ERROR("%s: cannot get the track frequency", __func__);
        return;
    }
    int channel_count = A2D_GetTrackChannelCount(p_buf->codec_info);
    if (channel_count == -1) {
        APPL_TRACE_ERROR("%s: cannot get the channel count", __func__);
        return;
    }
    int channel_type = A2D_GetSinkTrackChannelType(p_buf->codec_info);
    if (channel_type == -1) {
        APPL_TRACE_ERROR("%s: cannot get the sink channel type", __func__);
        return;
    }
    btif_media_cb.sample_rate = sample_rate;
    btif_media_cb.channel_count = channel_count;

    btif_media_cb.rx_flush = false;
    APPL_TRACE_DEBUG("Reset to sink role");
    status = OI_CODEC_SBC_DecoderReset(&context, contextData, sizeof(contextData), 2, 2, false);
    if (!OI_SUCCESS(status)) {
        APPL_TRACE_ERROR("OI_CODEC_SBC_DecoderReset failed with error code %d\n", status);
    }

#ifdef USE_AUDIO_TRACK
    APPL_TRACE_DEBUG("%s A2dpSink: sbc Create Track", __func__);
    btif_media_cb.audio_track = BtifAvrcpAudioTrackCreate(sample_rate,
                                                          channel_type);
    if (btif_media_cb.audio_track == NULL) {
        APPL_TRACE_ERROR("%s A2dpSink: Track creation fails!!!", __func__);
        return;
    }
#else
    UIPC_Open(UIPC_CH_ID_AV_AUDIO, btif_a2dp_data_cb);
#endif

    btif_media_cb.frames_to_process =
        A2D_GetSinkFramesCountToProcess(20, p_buf->codec_info);
    APPL_TRACE_DEBUG("Frames to be processed in 20 ms %d",
                     btif_media_cb.frames_to_process);
    if (btif_media_cb.frames_to_process == 0) {
        APPL_TRACE_ERROR("Cannot compute the number of frames to process");
    }
}
#endif

/*******************************************************************************
 **
 ** Function         btif_media_task_feeding_state_reset
 **
 ** Description      Reset the media feeding state
 **
 ** Returns          void
 **
 *******************************************************************************/
static void btif_media_task_feeding_state_reset(void)
{
    /* By default, just clear the entire state */
    memset(&btif_media_cb.media_feeding_state, 0, sizeof(btif_media_cb.media_feeding_state));

    if (btif_media_cb.TxTranscoding == BTIF_MEDIA_TRSCD_PCM_2_SBC)
    {
        btif_media_cb.media_feeding_state.pcm.bytes_per_tick =
                (btif_media_cb.media_feeding.cfg.pcm.sampling_freq *
                 btif_media_cb.media_feeding.cfg.pcm.bit_per_sample / 8 *
                 btif_media_cb.media_feeding.cfg.pcm.num_channel *
                 BTIF_MEDIA_TIME_TICK)/1000;

        APPL_TRACE_WARNING("pcm bytes per tick %d",
                            (int)btif_media_cb.media_feeding_state.pcm.bytes_per_tick);
    }
}

static void btif_media_task_alarm_cb(UNUSED_ATTR void *context) {
  thread_post(worker_thread, btif_media_task_aa_handle_timer, NULL);
}

/*******************************************************************************
 **
 ** Function         btif_media_task_aa_start_tx
 **
 ** Description      Start media task encoding
 **
 ** Returns          void
 **
 *******************************************************************************/
static void btif_media_task_aa_start_tx(void)
{
    APPL_TRACE_DEBUG("%s media_alarm %srunning, feeding mode %d", __func__,
                     alarm_is_scheduled(btif_media_cb.media_alarm)? "" : "not ",
                     btif_media_cb.feeding_mode);

    last_frame_us = 0;

    /* Reset the media feeding state */
    btif_media_task_feeding_state_reset();

    APPL_TRACE_EVENT("starting timer %dms", BTIF_MEDIA_TIME_TICK);

    alarm_free(btif_media_cb.media_alarm);
    btif_media_cb.media_alarm = alarm_new_periodic("btif.media_task");
    if (!btif_media_cb.media_alarm) {
      LOG_ERROR(LOG_TAG, "%s unable to allocate media alarm.", __func__);
      return;
    }

    alarm_set(btif_media_cb.media_alarm, BTIF_MEDIA_TIME_TICK,
              btif_media_task_alarm_cb, NULL);
}

/*******************************************************************************
 **
 ** Function         btif_media_task_aa_stop_tx
 **
 ** Description      Stop media task encoding
 **
 ** Returns          void
 **
 *******************************************************************************/
static void btif_media_task_aa_stop_tx(void)
{
    APPL_TRACE_DEBUG("%s media_alarm is %srunning", __func__,
                     alarm_is_scheduled(btif_media_cb.media_alarm)? "" : "not ");

    const bool send_ack = alarm_is_scheduled(btif_media_cb.media_alarm);

    /* Stop the timer first */
    alarm_free(btif_media_cb.media_alarm);
    btif_media_cb.media_alarm = NULL;

    UIPC_Close(UIPC_CH_ID_AV_AUDIO);

    /* Try to send acknowldegment once the media stream is
       stopped. This will make sure that the A2DP HAL layer is
       un-blocked on wait for acknowledgment for the sent command.
       This resolves a corner cases AVDTP SUSPEND collision
       when the DUT and the remote device issue SUSPEND simultaneously
       and due to the processing of the SUSPEND request from the remote,
       the media path is torn down. If the A2DP HAL happens to wait
       for ACK for the initiated SUSPEND, it would never receive it casuing
       a block/wait. Due to this acknowledgement, the A2DP HAL is guranteed
       to get the ACK for any pending command in such cases. */

    if (send_ack)
        a2dp_cmd_acknowledge(A2DP_CTRL_ACK_SUCCESS);

    /* audio engine stopped, reset tx suspended flag */
    btif_media_cb.tx_flush = 0;
    last_frame_us = 0;

    /* Reset the media feeding state */
    btif_media_task_feeding_state_reset();
}

static uint32_t get_frame_length()
{
    uint32_t frame_len = 0;
    APPL_TRACE_DEBUG("%s channel mode: %d, sub-band: %d, number of block: %d, \
            bitpool: %d, sampling frequency: %d, num channels: %d",
            __func__,
            btif_media_cb.encoder.s16ChannelMode,
            btif_media_cb.encoder.s16NumOfSubBands,
            btif_media_cb.encoder.s16NumOfBlocks,
            btif_media_cb.encoder.s16BitPool,
            btif_media_cb.encoder.s16SamplingFreq,
            btif_media_cb.encoder.s16NumOfChannels);

    switch (btif_media_cb.encoder.s16ChannelMode) {
        case SBC_MONO:
            /* FALLTHROUGH */
        case SBC_DUAL:
            frame_len = SBC_FRAME_HEADER_SIZE_BYTES +
                ((uint32_t)(SBC_SCALE_FACTOR_BITS * btif_media_cb.encoder.s16NumOfSubBands *
                btif_media_cb.encoder.s16NumOfChannels) / CHAR_BIT) +
                ((uint32_t)(btif_media_cb.encoder.s16NumOfBlocks *
                btif_media_cb.encoder.s16NumOfChannels *
                btif_media_cb.encoder.s16BitPool) / CHAR_BIT);
            break;
        case SBC_STEREO:
            frame_len = SBC_FRAME_HEADER_SIZE_BYTES +
                ((uint32_t)(SBC_SCALE_FACTOR_BITS * btif_media_cb.encoder.s16NumOfSubBands *
                btif_media_cb.encoder.s16NumOfChannels) / CHAR_BIT) +
                ((uint32_t)(btif_media_cb.encoder.s16NumOfBlocks *
                btif_media_cb.encoder.s16BitPool) / CHAR_BIT);
            break;
        case SBC_JOINT_STEREO:
            frame_len = SBC_FRAME_HEADER_SIZE_BYTES +
                ((uint32_t)(SBC_SCALE_FACTOR_BITS * btif_media_cb.encoder.s16NumOfSubBands *
                btif_media_cb.encoder.s16NumOfChannels) / CHAR_BIT) +
                ((uint32_t)(btif_media_cb.encoder.s16NumOfSubBands +
                (btif_media_cb.encoder.s16NumOfBlocks *
                btif_media_cb.encoder.s16BitPool)) / CHAR_BIT);
            break;
        default:
            APPL_TRACE_DEBUG("%s Invalid channel number: %d",
                __func__, btif_media_cb.encoder.s16ChannelMode);
            break;
    }
    APPL_TRACE_DEBUG("%s calculated frame length: %d", __func__, frame_len);
    return frame_len;
}

static uint8_t calculate_max_frames_per_packet()
{
    uint16_t result = 0;
    uint16_t effective_mtu_size = btif_media_cb.TxAaMtuSize;
    uint32_t frame_len;

    APPL_TRACE_DEBUG("%s original AVDTP MTU size: %d", __func__, btif_media_cb.TxAaMtuSize);
    if (btif_av_is_peer_edr() && (btif_av_peer_supports_3mbps() == false)) {
        // This condition would be satisfied only if the remote device is
        // EDR and supports only 2 Mbps, but the effective AVDTP MTU size
        // exceeds the 2DH5 packet size.
        APPL_TRACE_DEBUG("%s The remote devce is EDR but does not support 3 Mbps", __func__);

        if (effective_mtu_size > MAX_2MBPS_AVDTP_MTU) {
            APPL_TRACE_WARNING("%s Restricting AVDTP MTU size to %d",
                __func__, MAX_2MBPS_AVDTP_MTU);
            effective_mtu_size = MAX_2MBPS_AVDTP_MTU;
            btif_media_cb.TxAaMtuSize = effective_mtu_size;
        }
    }

    if (!btif_media_cb.encoder.s16NumOfSubBands) {
        APPL_TRACE_ERROR("%s SubBands are set to 0, resetting to %d",
            __func__, SBC_MAX_NUM_OF_SUBBANDS);
        btif_media_cb.encoder.s16NumOfSubBands = SBC_MAX_NUM_OF_SUBBANDS;
    }
    if (!btif_media_cb.encoder.s16NumOfBlocks) {
        APPL_TRACE_ERROR("%s Blocks are set to 0, resetting to %d",
            __func__, SBC_MAX_NUM_OF_BLOCKS);
        btif_media_cb.encoder.s16NumOfBlocks = SBC_MAX_NUM_OF_BLOCKS;
    }
    if (!btif_media_cb.encoder.s16NumOfChannels) {
        APPL_TRACE_ERROR("%s Channels are set to 0, resetting to %d",
            __func__, SBC_MAX_NUM_OF_CHANNELS);
        btif_media_cb.encoder.s16NumOfChannels = SBC_MAX_NUM_OF_CHANNELS;
    }

    frame_len = get_frame_length();

    APPL_TRACE_DEBUG("%s Effective Tx MTU to be considered: %d",
        __func__, effective_mtu_size);

    switch (btif_media_cb.encoder.s16SamplingFreq) {
        case SBC_sf44100:
            if (frame_len == 0) {
                APPL_TRACE_ERROR("%s Calculating frame length, \
                                        resetting it to default 119", __func__);
                frame_len = MAX_SBC_HQ_FRAME_SIZE_44_1;
            }
            result = (effective_mtu_size - A2DP_HDR_SIZE) / frame_len;
            APPL_TRACE_DEBUG("%s Max number of SBC frames: %d", __func__, result);
            break;

        case SBC_sf48000:
            if (frame_len == 0) {
                APPL_TRACE_ERROR("%s Calculating frame length, \
                                        resetting it to default 115", __func__);
                frame_len = MAX_SBC_HQ_FRAME_SIZE_48;
            }
            result = (effective_mtu_size - A2DP_HDR_SIZE) / frame_len;
            APPL_TRACE_DEBUG("%s Max number of SBC frames: %d", __func__, result);
            break;

        default:
            APPL_TRACE_ERROR("%s Max number of SBC frames: %d", __func__, result);
            break;

    }
    return result;
}

/*******************************************************************************
 **
 ** Function         btif_get_num_aa_frame_iteration
 **
 ** Description      returns number of frames to send and number of iterations
 **                  to be used. num_of_ietrations and num_of_frames parameters
 **                  are used as output param for returning the respective values
 **
 ** Returns          void
 **
 *******************************************************************************/
static void btif_get_num_aa_frame_iteration(uint8_t *num_of_iterations, uint8_t *num_of_frames)
{
    uint8_t nof = 0;
    uint8_t noi = 1;

    switch (btif_media_cb.TxTranscoding)
    {
        case BTIF_MEDIA_TRSCD_PCM_2_SBC:
        {
            uint32_t projected_nof = 0;
            uint32_t pcm_bytes_per_frame = btif_media_cb.encoder.s16NumOfSubBands *
                             btif_media_cb.encoder.s16NumOfBlocks *
                             btif_media_cb.media_feeding.cfg.pcm.num_channel *
                             btif_media_cb.media_feeding.cfg.pcm.bit_per_sample / 8;
            APPL_TRACE_DEBUG("%s pcm_bytes_per_frame %u", __func__, pcm_bytes_per_frame);

            uint32_t us_this_tick = BTIF_MEDIA_TIME_TICK * 1000;
            uint64_t now_us = time_now_us();
            if (last_frame_us != 0)
                us_this_tick = (now_us - last_frame_us);
            last_frame_us = now_us;

            btif_media_cb.media_feeding_state.pcm.counter +=
                                btif_media_cb.media_feeding_state.pcm.bytes_per_tick *
                                us_this_tick / (BTIF_MEDIA_TIME_TICK * 1000);

            /* calculate nbr of frames pending for this media tick */
            projected_nof = btif_media_cb.media_feeding_state.pcm.counter / pcm_bytes_per_frame;
            if (projected_nof > btif_media_cb.stats.media_read_max_expected_frames)
                btif_media_cb.stats.media_read_max_expected_frames = projected_nof;
            btif_media_cb.stats.media_read_total_expected_frames += projected_nof;
            btif_media_cb.stats.media_read_expected_count++;
            if (projected_nof > MAX_PCM_FRAME_NUM_PER_TICK)
            {
                APPL_TRACE_WARNING("%s() - Limiting frames to be sent from %d to %d"
                    , __func__, projected_nof, MAX_PCM_FRAME_NUM_PER_TICK);
                size_t delta = projected_nof - MAX_PCM_FRAME_NUM_PER_TICK;
                btif_media_cb.stats.media_read_limited_count++;
                btif_media_cb.stats.media_read_total_limited_frames += delta;
                if (delta > btif_media_cb.stats.media_read_max_limited_frames)
                    btif_media_cb.stats.media_read_max_limited_frames = delta;
                projected_nof = MAX_PCM_FRAME_NUM_PER_TICK;
            }

            APPL_TRACE_DEBUG("%s frames for available PCM data %u", __func__, projected_nof);

            if (btif_av_is_peer_edr())
            {
                if (!btif_media_cb.tx_sbc_frames)
                {
                    APPL_TRACE_ERROR("%s tx_sbc_frames not updated, update from here", __func__);
                    btif_media_cb.tx_sbc_frames = calculate_max_frames_per_packet();
                }

                nof = btif_media_cb.tx_sbc_frames;
                if (!nof) {
                    APPL_TRACE_ERROR("%s Number of frames not updated, set calculated values",
                                                        __func__);
                    nof = projected_nof;
                    noi = 1;
                } else {
                    if (nof < projected_nof)
                    {
                        noi = projected_nof / nof; // number of iterations would vary
                        if (noi > MAX_PCM_ITER_NUM_PER_TICK)
                        {
                            APPL_TRACE_ERROR("%s ## Audio Congestion (iterations:%d > max (%d))",
                                 __func__, noi, MAX_PCM_ITER_NUM_PER_TICK);
                            noi = MAX_PCM_ITER_NUM_PER_TICK;
                            btif_media_cb.media_feeding_state.pcm.counter
                                = noi * nof * pcm_bytes_per_frame;
                        }
                        projected_nof = nof;
                    } else {
                        noi = 1; // number of iterations is 1
                        APPL_TRACE_DEBUG("%s reducing frames for available PCM data", __func__);
                        nof = projected_nof;
                    }
                }
            } else {
                // For BR cases nof will be same as the value retrieved at projected_nof
                APPL_TRACE_DEBUG("%s headset BR, number of frames %u", __func__, nof);
                if (projected_nof > MAX_PCM_FRAME_NUM_PER_TICK)
                {
                    APPL_TRACE_ERROR("%s ## Audio Congestion (frames: %d > max (%d))",
                        __func__, projected_nof, MAX_PCM_FRAME_NUM_PER_TICK);
                    projected_nof = MAX_PCM_FRAME_NUM_PER_TICK;
                    btif_media_cb.media_feeding_state.pcm.counter =
                        noi * projected_nof * pcm_bytes_per_frame;
                }
                nof = projected_nof;
            }
            btif_media_cb.media_feeding_state.pcm.counter -= noi * nof * pcm_bytes_per_frame;
            APPL_TRACE_DEBUG("%s effective num of frames %u, iterations %u", __func__, nof, noi);
        }
        break;

        default:
            APPL_TRACE_ERROR("%s Unsupported transcoding format 0x%x",
                    __func__, btif_media_cb.TxTranscoding);
            nof = 0;
            noi = 0;
            break;
    }
    *num_of_frames = nof;
    *num_of_iterations = noi;
}

/*******************************************************************************
 **
 ** Function         btif_media_sink_enque_buf
 **
 ** Description      This function is called by the av_co to fill A2DP Sink Queue
 **
 **
 ** Returns          size of the queue
 *******************************************************************************/
uint8_t btif_media_sink_enque_buf(BT_HDR *p_pkt)
{
    if (btif_media_cb.rx_flush == true) /* Flush enabled, do not enque */
        return fixed_queue_length(btif_media_cb.RxSbcQ);
    if (fixed_queue_length(btif_media_cb.RxSbcQ) == MAX_OUTPUT_A2DP_FRAME_QUEUE_SZ)
    {
        uint8_t ret = fixed_queue_length(btif_media_cb.RxSbcQ);
        osi_free(fixed_queue_try_dequeue(btif_media_cb.RxSbcQ));
        return ret;
    }

    BTIF_TRACE_VERBOSE("%s +", __func__);
    /* allocate and Queue this buffer */
    tBT_SBC_HDR *p_msg =
        (tBT_SBC_HDR *)osi_malloc(sizeof(tBT_SBC_HDR) + p_pkt->offset +
                                  p_pkt->len);
    memcpy((uint8_t *)(p_msg + 1), (uint8_t *)(p_pkt + 1) + p_pkt->offset,
           p_pkt->len);
    p_msg->num_frames_to_be_processed = (*((uint8_t *)(p_pkt + 1) + p_pkt->offset))& 0x0f;
    p_msg->len = p_pkt->len;
    p_msg->offset = 0;
    p_msg->layer_specific = p_pkt->layer_specific;
    BTIF_TRACE_VERBOSE("%s frames to process %d, len %d  ",
                       __func__, p_msg->num_frames_to_be_processed,p_msg->len);
    fixed_queue_enqueue(btif_media_cb.RxSbcQ, p_msg);
    if (fixed_queue_length(btif_media_cb.RxSbcQ) == MAX_A2DP_DELAYED_START_FRAME_COUNT) {
        BTIF_TRACE_DEBUG(" Initiate Decoding ");
        btif_media_task_aa_handle_start_decoding();
    }

    return fixed_queue_length(btif_media_cb.RxSbcQ);
}

/*******************************************************************************
 **
 ** Function         btif_media_aa_readbuf
 **
 ** Description      This function is called by the av_co to get the next buffer to send
 **
 **
 ** Returns          void
 *******************************************************************************/
BT_HDR *btif_media_aa_readbuf(void)
{
    uint64_t now_us = time_now_us();
    BT_HDR *p_buf = (BT_HDR *)fixed_queue_try_dequeue(btif_media_cb.TxAaQ);

    btif_media_cb.stats.tx_queue_total_readbuf_calls++;
    btif_media_cb.stats.tx_queue_last_readbuf_us = now_us;
    if (p_buf != NULL) {
        // Update the statistics
        update_scheduling_stats(&btif_media_cb.stats.tx_queue_dequeue_stats,
                                now_us, BTIF_SINK_MEDIA_TIME_TICK_MS * 1000);
    }

    return p_buf;
}

/*******************************************************************************
 **
 ** Function         btif_media_aa_read_feeding
 **
 ** Description
 **
 ** Returns          void
 **
 *******************************************************************************/

bool btif_media_aa_read_feeding(tUIPC_CH_ID channel_id)
{
    uint16_t event;
    uint16_t blocm_x_subband = btif_media_cb.encoder.s16NumOfSubBands * \
                             btif_media_cb.encoder.s16NumOfBlocks;
    uint32_t read_size;
    uint16_t sbc_sampling = 48000;
    uint32_t src_samples;
    uint16_t bytes_needed = blocm_x_subband * btif_media_cb.encoder.s16NumOfChannels * \
                          btif_media_cb.media_feeding.cfg.pcm.bit_per_sample / 8;
    static uint16_t up_sampled_buffer[SBC_MAX_NUM_FRAME * SBC_MAX_NUM_OF_BLOCKS
            * SBC_MAX_NUM_OF_CHANNELS * SBC_MAX_NUM_OF_SUBBANDS * 2];
    static uint16_t read_buffer[SBC_MAX_NUM_FRAME * SBC_MAX_NUM_OF_BLOCKS
            * SBC_MAX_NUM_OF_CHANNELS * SBC_MAX_NUM_OF_SUBBANDS];
    uint32_t src_size_used;
    uint32_t dst_size_used;
    bool fract_needed;
    int32_t   fract_max;
    int32_t   fract_threshold;
    uint32_t  nb_byte_read;

    /* Get the SBC sampling rate */
    switch (btif_media_cb.encoder.s16SamplingFreq)
    {
    case SBC_sf48000:
        sbc_sampling = 48000;
        break;
    case SBC_sf44100:
        sbc_sampling = 44100;
        break;
    case SBC_sf32000:
        sbc_sampling = 32000;
        break;
    case SBC_sf16000:
        sbc_sampling = 16000;
        break;
    }

    if (sbc_sampling == btif_media_cb.media_feeding.cfg.pcm.sampling_freq) {
        read_size = bytes_needed - btif_media_cb.media_feeding_state.pcm.aa_feed_residue;
        nb_byte_read = UIPC_Read(channel_id, &event,
                  ((uint8_t *)btif_media_cb.encoder.as16PcmBuffer) +
                  btif_media_cb.media_feeding_state.pcm.aa_feed_residue,
                  read_size);
        if (nb_byte_read == read_size) {
            btif_media_cb.media_feeding_state.pcm.aa_feed_residue = 0;
            return true;
        } else {
            APPL_TRACE_WARNING("### UNDERFLOW :: ONLY READ %d BYTES OUT OF %d ###",
                nb_byte_read, read_size);
            btif_media_cb.media_feeding_state.pcm.aa_feed_residue += nb_byte_read;
            btif_media_cb.stats.media_read_total_underflow_bytes += (read_size - nb_byte_read);
            btif_media_cb.stats.media_read_total_underflow_count++;
            btif_media_cb.stats.media_read_last_underflow_us = time_now_us();
            return false;
        }
    }

    /* Some Feeding PCM frequencies require to split the number of sample */
    /* to read. */
    /* E.g 128/6=21.3333 => read 22 and 21 and 21 => max = 2; threshold = 0*/
    fract_needed = false;   /* Default */
    switch (btif_media_cb.media_feeding.cfg.pcm.sampling_freq)
    {
    case 32000:
    case 8000:
        fract_needed = true;
        fract_max = 2;          /* 0, 1 and 2 */
        fract_threshold = 0;    /* Add one for the first */
        break;
    case 16000:
        fract_needed = true;
        fract_max = 2;          /* 0, 1 and 2 */
        fract_threshold = 1;    /* Add one for the first two frames*/
        break;
    }

    /* Compute number of sample to read from source */
    src_samples = blocm_x_subband;
    src_samples *= btif_media_cb.media_feeding.cfg.pcm.sampling_freq;
    src_samples /= sbc_sampling;

    /* The previous division may have a remainder not null */
    if (fract_needed)
    {
        if (btif_media_cb.media_feeding_state.pcm.aa_feed_counter <= fract_threshold)
        {
            src_samples++; /* for every read before threshold add one sample */
        }

        /* do nothing if counter >= threshold */
        btif_media_cb.media_feeding_state.pcm.aa_feed_counter++; /* one more read */
        if (btif_media_cb.media_feeding_state.pcm.aa_feed_counter > fract_max)
        {
            btif_media_cb.media_feeding_state.pcm.aa_feed_counter = 0;
        }
    }

    /* Compute number of bytes to read from source */
    read_size = src_samples;
    read_size *= btif_media_cb.media_feeding.cfg.pcm.num_channel;
    read_size *= (btif_media_cb.media_feeding.cfg.pcm.bit_per_sample / 8);

    /* Read Data from UIPC channel */
    nb_byte_read = UIPC_Read(channel_id, &event, (uint8_t *)read_buffer, read_size);

    //tput_mon(true, nb_byte_read, false);

    if (nb_byte_read < read_size)
    {
        APPL_TRACE_WARNING("### UNDERRUN :: ONLY READ %d BYTES OUT OF %d ###",
                nb_byte_read, read_size);
        btif_media_cb.stats.media_read_total_underrun_bytes += (read_size - nb_byte_read);
        btif_media_cb.stats.media_read_total_underrun_count++;
        btif_media_cb.stats.media_read_last_underrun_us = time_now_us();

        if (nb_byte_read == 0)
            return false;

        if(btif_media_cb.feeding_mode == BTIF_AV_FEEDING_ASYNCHRONOUS)
        {
            /* Fill the unfilled part of the read buffer with silence (0) */
            memset(((uint8_t *)read_buffer) + nb_byte_read, 0, read_size - nb_byte_read);
            nb_byte_read = read_size;
        }
    }

    /* Initialize PCM up-sampling engine */
    bta_av_sbc_init_up_sample(btif_media_cb.media_feeding.cfg.pcm.sampling_freq,
            sbc_sampling, btif_media_cb.media_feeding.cfg.pcm.bit_per_sample,
            btif_media_cb.media_feeding.cfg.pcm.num_channel);

    /* re-sample read buffer */
    /* The output PCM buffer will be stereo, 16 bit per sample */
    dst_size_used = bta_av_sbc_up_sample((uint8_t *)read_buffer,
            (uint8_t *)up_sampled_buffer + btif_media_cb.media_feeding_state.pcm.aa_feed_residue,
            nb_byte_read,
            sizeof(up_sampled_buffer) - btif_media_cb.media_feeding_state.pcm.aa_feed_residue,
            &src_size_used);

    /* update the residue */
    btif_media_cb.media_feeding_state.pcm.aa_feed_residue += dst_size_used;

    /* only copy the pcm sample when we have up-sampled enough PCM */
    if(btif_media_cb.media_feeding_state.pcm.aa_feed_residue >= bytes_needed)
    {
        /* Copy the output pcm samples in SBC encoding buffer */
        memcpy((uint8_t *)btif_media_cb.encoder.as16PcmBuffer,
                (uint8_t *)up_sampled_buffer,
                bytes_needed);
        /* update the residue */
        btif_media_cb.media_feeding_state.pcm.aa_feed_residue -= bytes_needed;

        if (btif_media_cb.media_feeding_state.pcm.aa_feed_residue != 0)
        {
            memcpy((uint8_t *)up_sampled_buffer,
                   (uint8_t *)up_sampled_buffer + bytes_needed,
                   btif_media_cb.media_feeding_state.pcm.aa_feed_residue);
        }
        return true;
    }

    return false;
}

/*******************************************************************************
 **
 ** Function         btif_media_aa_prep_sbc_2_send
 **
 ** Description
 **
 ** Returns          void
 **
 *******************************************************************************/
static void btif_media_aa_prep_sbc_2_send(uint8_t nb_frame,
                                          uint64_t timestamp_us)
{
    uint8_t remain_nb_frame = nb_frame;
    uint16_t blocm_x_subband = btif_media_cb.encoder.s16NumOfSubBands *
                             btif_media_cb.encoder.s16NumOfBlocks;

    while (nb_frame) {
        BT_HDR *p_buf = (BT_HDR *)osi_malloc(BTIF_MEDIA_AA_BUF_SIZE);

        /* Init buffer */
        p_buf->offset = BTIF_MEDIA_AA_SBC_OFFSET;
        p_buf->len = 0;
        p_buf->layer_specific = 0;

        do
        {
            /* Write @ of allocated buffer in encoder.pu8Packet */
            btif_media_cb.encoder.pu8Packet = (uint8_t *) (p_buf + 1) + p_buf->offset + p_buf->len;
            /* Fill allocated buffer with 0 */
            memset(btif_media_cb.encoder.as16PcmBuffer, 0, blocm_x_subband
                    * btif_media_cb.encoder.s16NumOfChannels);

            /* Read PCM data and upsample them if needed */
            if (btif_media_aa_read_feeding(UIPC_CH_ID_AV_AUDIO))
            {
                SBC_Encoder(&(btif_media_cb.encoder));

                /* Update SBC frame length */
                p_buf->len += btif_media_cb.encoder.u16PacketLength;
                nb_frame--;
                p_buf->layer_specific++;
            }
            else
            {
                APPL_TRACE_WARNING("btif_media_aa_prep_sbc_2_send underflow %d, %d",
                    nb_frame, btif_media_cb.media_feeding_state.pcm.aa_feed_residue);
                btif_media_cb.media_feeding_state.pcm.counter += nb_frame *
                     btif_media_cb.encoder.s16NumOfSubBands *
                     btif_media_cb.encoder.s16NumOfBlocks *
                     btif_media_cb.media_feeding.cfg.pcm.num_channel *
                     btif_media_cb.media_feeding.cfg.pcm.bit_per_sample / 8;
                /* no more pcm to read */
                nb_frame = 0;

                /* break read loop if timer was stopped (media task stopped) */
                if (! alarm_is_scheduled(btif_media_cb.media_alarm))
                {
                    osi_free(p_buf);
                    return;
                }
            }

        } while (((p_buf->len + btif_media_cb.encoder.u16PacketLength) < btif_media_cb.TxAaMtuSize)
                && (p_buf->layer_specific < 0x0F) && nb_frame);

        if(p_buf->len)
        {
            /* timestamp of the media packet header represent the TS of the first SBC frame
               i.e the timestamp before including this frame */
            *((uint32_t *) (p_buf + 1)) = btif_media_cb.timestamp;

            btif_media_cb.timestamp += p_buf->layer_specific * blocm_x_subband;

            if (btif_media_cb.tx_flush)
            {
                APPL_TRACE_DEBUG("### tx suspended, discarded frame ###");

                btif_media_cb.stats.tx_queue_total_flushed_messages +=
                    fixed_queue_length(btif_media_cb.TxAaQ);
                btif_media_cb.stats.tx_queue_last_flushed_us =
                    timestamp_us;
                btif_media_flush_q(btif_media_cb.TxAaQ);

                osi_free(p_buf);
                return;
            }

            /* Enqueue the encoded SBC frame in AA Tx Queue */
            update_scheduling_stats(&btif_media_cb.stats.tx_queue_enqueue_stats,
                                    timestamp_us,
                                    BTIF_SINK_MEDIA_TIME_TICK_MS * 1000);
            uint8_t done_nb_frame = remain_nb_frame - nb_frame;
            remain_nb_frame = nb_frame;
            btif_media_cb.stats.tx_queue_total_frames += done_nb_frame;
            if (done_nb_frame > btif_media_cb.stats.tx_queue_max_frames_per_packet)
                btif_media_cb.stats.tx_queue_max_frames_per_packet = done_nb_frame;
            fixed_queue_enqueue(btif_media_cb.TxAaQ, p_buf);
        }
        else
        {
            osi_free(p_buf);
        }
    }
}


/*******************************************************************************
 **
 ** Function         btif_media_aa_prep_2_send
 **
 ** Description
 **
 ** Returns          void
 **
 *******************************************************************************/

static void btif_media_aa_prep_2_send(uint8_t nb_frame, uint64_t timestamp_us)
{
    // Check for TX queue overflow

    if (nb_frame > MAX_OUTPUT_A2DP_FRAME_QUEUE_SZ)
        nb_frame = MAX_OUTPUT_A2DP_FRAME_QUEUE_SZ;

    if (fixed_queue_length(btif_media_cb.TxAaQ) > (MAX_OUTPUT_A2DP_FRAME_QUEUE_SZ - nb_frame))
    {
        APPL_TRACE_WARNING("%s() - TX queue buffer count %d/%d", __func__,
                           fixed_queue_length(btif_media_cb.TxAaQ),
                           MAX_OUTPUT_A2DP_FRAME_QUEUE_SZ - nb_frame);
        // Keep track of drop-outs
        btif_media_cb.stats.tx_queue_dropouts++;
        btif_media_cb.stats.tx_queue_last_dropouts_us = timestamp_us;

        // Flush all queued buffers...
        while (fixed_queue_length(btif_media_cb.TxAaQ)) {
            btif_media_cb.stats.tx_queue_total_dropped_messages++;
            osi_free(fixed_queue_try_dequeue(btif_media_cb.TxAaQ));
        }

        // Request RSSI for log purposes if we had to flush buffers
        bt_bdaddr_t peer_bda = btif_av_get_addr();
        BTM_ReadRSSI(peer_bda.address, btm_read_rssi_cb);
    }

    // Transcode frame

    switch (btif_media_cb.TxTranscoding)
    {
    case BTIF_MEDIA_TRSCD_PCM_2_SBC:
        btif_media_aa_prep_sbc_2_send(nb_frame, timestamp_us);
        break;

    default:
        APPL_TRACE_ERROR("%s unsupported transcoding format 0x%x", __func__, btif_media_cb.TxTranscoding);
        break;
    }
}

/*******************************************************************************
 **
 ** Function         btif_media_send_aa_frame
 **
 ** Description
 **
 ** Returns          void
 **
 *******************************************************************************/
static void btif_media_send_aa_frame(uint64_t timestamp_us)
{
    uint8_t nb_frame_2_send = 0;
    uint8_t nb_iterations = 0;

    btif_get_num_aa_frame_iteration(&nb_iterations, &nb_frame_2_send);

    if (nb_frame_2_send != 0) {
        for (uint8_t counter = 0; counter < nb_iterations; counter++)
        {
            /* format and queue buffer to send */
            btif_media_aa_prep_2_send(nb_frame_2_send, timestamp_us);
        }
    }

    LOG_VERBOSE(LOG_TAG, "%s Sent %d frames per iteration, %d iterations",
                        __func__, nb_frame_2_send, nb_iterations);
    bta_av_ci_src_data_ready(BTA_AV_CHNL_AUDIO);
}

void btif_debug_a2dp_dump(int fd)
{
    uint64_t now_us = time_now_us();
    btif_media_stats_t *stats = &btif_media_cb.stats;
    scheduling_stats_t *enqueue_stats = &stats->tx_queue_enqueue_stats;
    scheduling_stats_t *dequeue_stats = &stats->tx_queue_dequeue_stats;
    size_t ave_size;
    uint64_t ave_time_us;

    dprintf(fd, "\nA2DP State:\n");
    dprintf(fd, "  TxQueue:\n");

    dprintf(fd, "  Counts (enqueue/dequeue/readbuf)                        : %zu / %zu / %zu\n",
            enqueue_stats->total_updates,
            dequeue_stats->total_updates,
            stats->tx_queue_total_readbuf_calls);

    dprintf(fd, "  Last update time ago in ms (enqueue/dequeue/readbuf)    : %llu / %llu / %llu\n",
            (enqueue_stats->last_update_us > 0) ?
                (unsigned long long)(now_us - enqueue_stats->last_update_us) / 1000 : 0,
            (dequeue_stats->last_update_us > 0) ?
                (unsigned long long)(now_us - dequeue_stats->last_update_us) / 1000 : 0,
            (stats->tx_queue_last_readbuf_us > 0)?
                (unsigned long long)(now_us - stats->tx_queue_last_readbuf_us) / 1000 : 0);

    ave_size = 0;
    if (stats->media_read_expected_count != 0)
        ave_size = stats->media_read_total_expected_frames / stats->media_read_expected_count;
    dprintf(fd, "  Frames expected (total/max/ave)                         : %zu / %zu / %zu\n",
            stats->media_read_total_expected_frames,
            stats->media_read_max_expected_frames,
            ave_size);

    ave_size = 0;
    if (stats->media_read_limited_count != 0)
        ave_size = stats->media_read_total_limited_frames / stats->media_read_limited_count;
    dprintf(fd, "  Frames limited (total/max/ave)                          : %zu / %zu / %zu\n",
            stats->media_read_total_limited_frames,
            stats->media_read_max_limited_frames,
            ave_size);

    dprintf(fd, "  Counts (expected/limited)                               : %zu / %zu\n",
            stats->media_read_expected_count,
            stats->media_read_limited_count);

    ave_size = 0;
    if (enqueue_stats->total_updates != 0)
        ave_size = stats->tx_queue_total_frames / enqueue_stats->total_updates;
    dprintf(fd, "  Frames per packet (total/max/ave)                       : %zu / %zu / %zu\n",
            stats->tx_queue_total_frames,
            stats->tx_queue_max_frames_per_packet,
            ave_size);

    dprintf(fd, "  Counts (flushed/dropped/dropouts)                       : %zu / %zu / %zu\n",
            stats->tx_queue_total_flushed_messages,
            stats->tx_queue_total_dropped_messages,
            stats->tx_queue_dropouts);

    dprintf(fd, "  Last update time ago in ms (flushed/dropped)            : %llu / %llu\n",
            (stats->tx_queue_last_flushed_us > 0) ?
                (unsigned long long)(now_us - stats->tx_queue_last_flushed_us) / 1000 : 0,
            (stats->tx_queue_last_dropouts_us > 0)?
                (unsigned long long)(now_us - stats->tx_queue_last_dropouts_us)/ 1000 : 0);

    dprintf(fd, "  Counts (underflow/underrun)                             : %zu / %zu\n",
            stats->media_read_total_underflow_count,
            stats->media_read_total_underrun_count);

    dprintf(fd, "  Bytes (underflow/underrun)                              : %zu / %zu\n",
            stats->media_read_total_underflow_bytes,
            stats->media_read_total_underrun_bytes);

    dprintf(fd, "  Last update time ago in ms (underflow/underrun)         : %llu / %llu\n",
            (stats->media_read_last_underflow_us > 0) ?
                (unsigned long long)(now_us - stats->media_read_last_underflow_us) / 1000 : 0,
            (stats->media_read_last_underrun_us > 0)?
                (unsigned long long)(now_us - stats->media_read_last_underrun_us) / 1000 : 0);

    //
    // TxQueue enqueue stats
    //
    dprintf(fd, "  Enqueue deviation counts (overdue/premature)            : %zu / %zu\n",
            enqueue_stats->overdue_scheduling_count,
            enqueue_stats->premature_scheduling_count);

    ave_time_us = 0;
    if (enqueue_stats->overdue_scheduling_count != 0) {
        ave_time_us = enqueue_stats->total_overdue_scheduling_delta_us /
            enqueue_stats->overdue_scheduling_count;
    }
    dprintf(fd, "  Enqueue overdue scheduling time in ms (total/max/ave)   : %llu / %llu / %llu\n",
            (unsigned long long)enqueue_stats->total_overdue_scheduling_delta_us / 1000,
            (unsigned long long)enqueue_stats->max_overdue_scheduling_delta_us / 1000,
            (unsigned long long)ave_time_us / 1000);

    ave_time_us = 0;
    if (enqueue_stats->premature_scheduling_count != 0) {
        ave_time_us = enqueue_stats->total_premature_scheduling_delta_us /
            enqueue_stats->premature_scheduling_count;
    }
    dprintf(fd, "  Enqueue premature scheduling time in ms (total/max/ave) : %llu / %llu / %llu\n",
            (unsigned long long)enqueue_stats->total_premature_scheduling_delta_us / 1000,
            (unsigned long long)enqueue_stats->max_premature_scheduling_delta_us / 1000,
            (unsigned long long)ave_time_us / 1000);


    //
    // TxQueue dequeue stats
    //
    dprintf(fd, "  Dequeue deviation counts (overdue/premature)            : %zu / %zu\n",
            dequeue_stats->overdue_scheduling_count,
            dequeue_stats->premature_scheduling_count);

    ave_time_us = 0;
    if (dequeue_stats->overdue_scheduling_count != 0) {
        ave_time_us = dequeue_stats->total_overdue_scheduling_delta_us /
            dequeue_stats->overdue_scheduling_count;
    }
    dprintf(fd, "  Dequeue overdue scheduling time in ms (total/max/ave)   : %llu / %llu / %llu\n",
            (unsigned long long)dequeue_stats->total_overdue_scheduling_delta_us / 1000,
            (unsigned long long)dequeue_stats->max_overdue_scheduling_delta_us / 1000,
            (unsigned long long)ave_time_us / 1000);

    ave_time_us = 0;
    if (dequeue_stats->premature_scheduling_count != 0) {
        ave_time_us = dequeue_stats->total_premature_scheduling_delta_us /
            dequeue_stats->premature_scheduling_count;
    }
    dprintf(fd, "  Dequeue premature scheduling time in ms (total/max/ave) : %llu / %llu / %llu\n",
            (unsigned long long)dequeue_stats->total_premature_scheduling_delta_us / 1000,
            (unsigned long long)dequeue_stats->max_premature_scheduling_delta_us / 1000,
            (unsigned long long)ave_time_us / 1000);

}

void btif_update_a2dp_metrics(void)
{
    uint64_t now_us = time_now_us();
    btif_media_stats_t *stats = &btif_media_cb.stats;
    scheduling_stats_t *dequeue_stats = &stats->tx_queue_dequeue_stats;
    int32_t media_timer_min_ms = 0;
    int32_t media_timer_max_ms = 0;
    int32_t media_timer_avg_ms = 0;
    int32_t buffer_overruns_max_count = 0;
    int32_t buffer_overruns_total = 0;
    float buffer_underruns_average = 0.0;
    int32_t buffer_underruns_count = 0;

    int64_t session_duration_sec =
        (now_us - stats->session_start_us) / (1000 * 1000);

    /* NOTE: Disconnect reason is unused */
    const char *disconnect_reason = NULL;
    uint32_t device_class = BTM_COD_MAJOR_AUDIO;

    if (dequeue_stats->total_updates > 1) {
        media_timer_min_ms = BTIF_SINK_MEDIA_TIME_TICK_MS -
            (dequeue_stats->max_premature_scheduling_delta_us / 1000);
        media_timer_max_ms = BTIF_SINK_MEDIA_TIME_TICK_MS +
            (dequeue_stats->max_overdue_scheduling_delta_us / 1000);

        uint64_t total_scheduling_count =
            dequeue_stats->overdue_scheduling_count +
            dequeue_stats->premature_scheduling_count +
            dequeue_stats->exact_scheduling_count;
        if (total_scheduling_count > 0) {
            media_timer_avg_ms = dequeue_stats->total_scheduling_time_us /
                (1000 * total_scheduling_count);
        }

        buffer_overruns_max_count = stats->media_read_max_expected_frames;
        buffer_overruns_total = stats->tx_queue_total_dropped_messages;
        buffer_underruns_count = stats->media_read_total_underflow_count +
            stats->media_read_total_underrun_count;
        if (buffer_underruns_count > 0) {
            buffer_underruns_average =
                (stats->media_read_total_underflow_bytes + stats->media_read_total_underrun_bytes) / buffer_underruns_count;
        }
    }

    metrics_a2dp_session(session_duration_sec, disconnect_reason, device_class,
                         media_timer_min_ms, media_timer_max_ms,
                         media_timer_avg_ms, buffer_overruns_max_count,
                         buffer_overruns_total, buffer_underruns_average,
                         buffer_underruns_count);
}
