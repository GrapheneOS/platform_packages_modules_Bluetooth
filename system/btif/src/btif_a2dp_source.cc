/******************************************************************************
 *
 *  Copyright (C) 2016 The Android Open Source Project
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

#define LOG_TAG "bt_btif_a2dp_source"

#include <assert.h>
#include <system/audio.h>

#include "audio_a2dp_hw.h"
#include "bt_common.h"
#include "bta_av_ci.h"
#include "bta_av_sbc.h"
#include "btif_a2dp.h"
#include "btif_a2dp_control.h"
#include "btif_a2dp_source.h"
#include "btif_av.h"
#include "btif_av_co.h"
#include "btif_util.h"
#include "btcore/include/bdaddr.h"
#include "osi/include/fixed_queue.h"
#include "osi/include/log.h"
#include "osi/include/metrics.h"
#include "osi/include/mutex.h"
#include "osi/include/osi.h"
#include "osi/include/thread.h"
#include "osi/include/time.h"
#include "sbc_encoder.h"
#include "stack/include/a2d_sbc.h"
#include "uipc.h"


/* offset */
#if (BTA_AV_CO_CP_SCMS_T == TRUE)
#define BTIF_MEDIA_AA_SBC_OFFSET (AVDT_MEDIA_OFFSET + A2D_SBC_MPL_HDR_LEN + 1)
#else
#define BTIF_MEDIA_AA_SBC_OFFSET (AVDT_MEDIA_OFFSET + A2D_SBC_MPL_HDR_LEN)
#endif

/*
 * 2DH5 payload size of:
 * 679 bytes - (4 bytes L2CAP Header + 12 bytes AVDTP Header)
 */
#define MAX_2MBPS_AVDTP_MTU             663
#define MAX_PCM_ITER_NUM_PER_TICK       3

/**
 * The typical runlevel of the tx queue size is ~1 buffer
 * but due to link flow control or thread preemption in lower
 * layers we might need to temporarily buffer up data.
 */
#define MAX_OUTPUT_A2DP_FRAME_QUEUE_SZ (MAX_PCM_FRAME_NUM_PER_TICK * 2)

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

/* Readability constants */
#define SBC_FRAME_HEADER_SIZE_BYTES 4 // A2DP Spec v1.3, 12.4, Table 12.12
#define SBC_SCALE_FACTOR_BITS       4 // A2DP Spec v1.3, 12.4, Table 12.13


/* Transcoding definition for TxTranscoding */
#define BTIF_MEDIA_TRSCD_OFF             0
#define BTIF_MEDIA_TRSCD_PCM_2_SBC       1  /* Tx */

/* Buffer pool */
#define BTIF_MEDIA_AA_BUF_SIZE  BT_DEFAULT_BUFFER_SIZE

enum {
    BTIF_A2DP_SOURCE_STATE_OFF,
    BTIF_A2DP_SOURCE_STATE_STARTING_UP,
    BTIF_A2DP_SOURCE_STATE_RUNNING,
    BTIF_A2DP_SOURCE_STATE_SHUTTING_DOWN
};

/* BTIF Media Source event definition */
enum {
    BTIF_MEDIA_START_AA_TX = 1,
    BTIF_MEDIA_STOP_AA_TX,
    BTIF_MEDIA_SBC_ENC_INIT,
    BTIF_MEDIA_SBC_ENC_UPDATE,
    BTIF_MEDIA_AUDIO_FEEDING_INIT,
    BTIF_MEDIA_FLUSH_AA_TX
};

/* tBTIF_A2DP_SOURCE_INIT_AUDIO_FEEDING msg structure */
typedef struct {
    BT_HDR hdr;
    tA2D_AV_MEDIA_FEEDINGS feeding;
} tBTIF_A2DP_SOURCE_INIT_AUDIO_FEEDING;

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

typedef struct {
    uint32_t aa_frame_counter;
    int32_t  aa_feed_counter;
    int32_t  aa_feed_residue;
    uint32_t counter;
    uint32_t bytes_per_tick;  /* pcm bytes read each media task tick */
} tBTIF_AV_MEDIA_FEEDINGS_STATE;

typedef struct {
    thread_t *worker_thread;
    fixed_queue_t *cmd_msg_queue;
    fixed_queue_t *TxAaQ;
    uint32_t timestamp;         /* Timestamp for the A2DP frames */
    uint8_t TxTranscoding;
    uint16_t TxAaMtuSize;
    uint8_t tx_sbc_frames;
    bool tx_flush;              /* Discards any outgoing data when true */
    tA2D_AV_MEDIA_FEEDINGS media_feeding;
    tBTIF_AV_MEDIA_FEEDINGS_STATE media_feeding_state;
    bool is_streaming;
    alarm_t *media_alarm;
    btif_media_stats_t stats;

    SBC_ENC_PARAMS sbc_encoder_params;
} tBTIF_A2DP_SOURCE_CB;

static tBTIF_A2DP_SOURCE_CB btif_a2dp_source_cb;
static int btif_a2dp_source_state = BTIF_A2DP_SOURCE_STATE_OFF;
static uint64_t last_frame_us = 0;


static void btif_a2dp_source_command_ready(fixed_queue_t *queue,
                                           void *context);
static void btif_a2dp_source_startup_delayed(void *context);
static void btif_a2dp_source_shutdown_delayed(void *context);
static void btif_a2dp_source_aa_start_tx(void);
static void btif_a2dp_source_aa_stop_tx(void);
static void btif_a2dp_source_enc_init(BT_HDR *p_msg);
static void btif_a2dp_source_enc_update(BT_HDR *p_msg);
static void btif_a2dp_source_audio_feeding_init(BT_HDR *p_msg);
static void btif_a2dp_source_aa_tx_flush(BT_HDR *p_msg);
static void btif_a2dp_source_encoder_init(void);
static void btif_a2dp_source_feeding_init_req(tBTIF_A2DP_SOURCE_INIT_AUDIO_FEEDING *p_msg);
static void btif_a2dp_source_enc_init_req(tBTIF_A2DP_SOURCE_INIT_AUDIO *p_msg);
static void btif_a2dp_source_enc_update_req(tBTIF_A2DP_SOURCE_UPDATE_AUDIO *p_msg);
static uint16_t btif_a2dp_source_get_sbc_rate(void);
static uint8_t calculate_max_frames_per_packet(void);
static bool btif_a2dp_source_aa_tx_flush_req(void);
static void btif_a2dp_source_pcm2sbc_init(tBTIF_A2DP_SOURCE_INIT_AUDIO_FEEDING *p_feeding);
static void btif_a2dp_source_alarm_cb(void *context);
static void btif_a2dp_source_aa_handle_timer(void *context);
static void log_tstamps_us(const char *comment, uint64_t timestamp_us);
static void btif_a2dp_source_send_aa_frame(uint64_t timestamp_us);
static void btif_get_num_aa_frame_iteration(uint8_t *num_of_iterations,
                                            uint8_t *num_of_frames);
static void btif_a2dp_source_aa_prep_2_send(uint8_t nb_frame,
                                            uint64_t timestamp_us);
static void btm_read_rssi_cb(void *data);
static void btif_a2dp_source_aa_prep_sbc_2_send(uint8_t nb_frame,
                                                uint64_t timestamp_us);
static bool btif_a2dp_source_aa_read_feeding(void);
static void update_scheduling_stats(scheduling_stats_t *stats,
                                    uint64_t now_us, uint64_t expected_delta);
static uint32_t get_frame_length(void);


UNUSED_ATTR static const char *dump_media_event(uint16_t event)
{
    switch (event) {
        CASE_RETURN_STR(BTIF_MEDIA_START_AA_TX)
        CASE_RETURN_STR(BTIF_MEDIA_STOP_AA_TX)
        CASE_RETURN_STR(BTIF_MEDIA_SBC_ENC_INIT)
        CASE_RETURN_STR(BTIF_MEDIA_SBC_ENC_UPDATE)
        CASE_RETURN_STR(BTIF_MEDIA_AUDIO_FEEDING_INIT)
        CASE_RETURN_STR(BTIF_MEDIA_FLUSH_AA_TX)
    default:
        break;
    }
    return "UNKNOWN A2DP SOURCE EVENT";
}

bool btif_a2dp_source_startup(void)
{
    if (btif_a2dp_source_state != BTIF_A2DP_SOURCE_STATE_OFF) {
        APPL_TRACE_ERROR("%s: A2DP Source media task already running",
                         __func__);
        return false;
    }

    memset(&btif_a2dp_source_cb, 0, sizeof(btif_a2dp_source_cb));
    btif_a2dp_source_state = BTIF_A2DP_SOURCE_STATE_STARTING_UP;

    APPL_TRACE_EVENT("## A2DP SOURCE START MEDIA THREAD ##");

    /* Start A2DP Source media task */
    btif_a2dp_source_cb.worker_thread = thread_new("btif_a2dp_source_worker_thread");
    if (btif_a2dp_source_cb.worker_thread == NULL) {
        APPL_TRACE_ERROR("%s: unable to start up media thread", __func__);
        btif_a2dp_source_state = BTIF_A2DP_SOURCE_STATE_OFF;
        return false;
    }

    btif_a2dp_source_cb.stats.session_start_us = time_get_os_boottime_us();
    btif_a2dp_source_cb.TxAaQ = fixed_queue_new(SIZE_MAX);

    btif_a2dp_source_cb.cmd_msg_queue = fixed_queue_new(SIZE_MAX);
    fixed_queue_register_dequeue(btif_a2dp_source_cb.cmd_msg_queue,
        thread_get_reactor(btif_a2dp_source_cb.worker_thread),
        btif_a2dp_source_command_ready, NULL);

    APPL_TRACE_EVENT("## A2DP SOURCE MEDIA THREAD STARTED ##");

    /* Schedule the rest of the startup operations */
    thread_post(btif_a2dp_source_cb.worker_thread,
                btif_a2dp_source_startup_delayed, NULL);

    return true;
}

static void btif_a2dp_source_startup_delayed(UNUSED_ATTR void *context)
{
    raise_priority_a2dp(TASK_HIGH_MEDIA);
    btif_a2dp_control_init();
    btif_a2dp_source_state = BTIF_A2DP_SOURCE_STATE_RUNNING;
}

void btif_a2dp_source_shutdown(void)
{
    /* Make sure no channels are restarted while shutting down */
    btif_a2dp_source_state = BTIF_A2DP_SOURCE_STATE_SHUTTING_DOWN;

    APPL_TRACE_EVENT("## A2DP SOURCE STOP MEDIA THREAD ##");

    // Stop the timer
    btif_a2dp_source_cb.is_streaming = FALSE;
    alarm_free(btif_a2dp_source_cb.media_alarm);
    btif_a2dp_source_cb.media_alarm = NULL;

    // Exit the thread
    fixed_queue_free(btif_a2dp_source_cb.cmd_msg_queue, NULL);
    btif_a2dp_source_cb.cmd_msg_queue = NULL;
    thread_post(btif_a2dp_source_cb.worker_thread,
                btif_a2dp_source_shutdown_delayed, NULL);
    thread_free(btif_a2dp_source_cb.worker_thread);
    btif_a2dp_source_cb.worker_thread = NULL;
}

static void btif_a2dp_source_shutdown_delayed(UNUSED_ATTR void *context)
{
    btif_a2dp_control_cleanup();
    fixed_queue_free(btif_a2dp_source_cb.TxAaQ, NULL);
    btif_a2dp_source_cb.TxAaQ = NULL;

    btif_a2dp_source_state = BTIF_A2DP_SOURCE_STATE_OFF;
}

bool btif_a2dp_source_media_task_is_running(void)
{
    return (btif_a2dp_source_state == BTIF_A2DP_SOURCE_STATE_RUNNING);
}

bool btif_a2dp_source_media_task_is_shutting_down(void)
{
    return (btif_a2dp_source_state == BTIF_A2DP_SOURCE_STATE_SHUTTING_DOWN);
}

bool btif_a2dp_source_is_streaming(void)
{
    return btif_a2dp_source_cb.is_streaming;
}

static void btif_a2dp_source_command_ready(fixed_queue_t *queue,
                                           UNUSED_ATTR void *context)
{
    BT_HDR *p_msg = (BT_HDR *)fixed_queue_dequeue(queue);

    LOG_VERBOSE(LOG_TAG, "%s: event %d %s", __func__, p_msg->event,
                dump_media_event(p_msg->event));

    switch (p_msg->event) {
    case BTIF_MEDIA_START_AA_TX:
        btif_a2dp_source_aa_start_tx();
        break;
    case BTIF_MEDIA_STOP_AA_TX:
        btif_a2dp_source_aa_stop_tx();
        break;
    case BTIF_MEDIA_SBC_ENC_INIT:
        btif_a2dp_source_enc_init(p_msg);
        break;
    case BTIF_MEDIA_SBC_ENC_UPDATE:
        btif_a2dp_source_enc_update(p_msg);
        break;
    case BTIF_MEDIA_AUDIO_FEEDING_INIT:
        btif_a2dp_source_audio_feeding_init(p_msg);
        break;
    case BTIF_MEDIA_FLUSH_AA_TX:
        btif_a2dp_source_aa_tx_flush(p_msg);
        break;
    default:
        APPL_TRACE_ERROR("ERROR in %s unknown event %d",
                         __func__, p_msg->event);
        break;
    }

    osi_free(p_msg);
    LOG_VERBOSE(LOG_TAG, "%s: %s DONE",
                __func__, dump_media_event(p_msg->event));
}

void btif_a2dp_source_setup_codec(void)
{
    tA2D_AV_MEDIA_FEEDINGS media_feeding;

    APPL_TRACE_EVENT("## A2DP SOURCE SETUP CODEC ##");

    mutex_global_lock();

    /* for now hardcode 44.1 khz 16 bit stereo PCM format */
    media_feeding.sampling_freq = BTIF_A2DP_SRC_SAMPLING_RATE;
    media_feeding.bit_per_sample = BTIF_A2DP_SRC_BIT_DEPTH;
    media_feeding.num_channel = BTIF_A2DP_SRC_NUM_CHANNELS;

    if (bta_av_co_audio_set_codec(&media_feeding)) {
        tBTIF_A2DP_SOURCE_INIT_AUDIO_FEEDING mfeed;

        /* Init the encoding task */
        btif_a2dp_source_encoder_init();

        /* Build the media task configuration */
        mfeed.feeding = media_feeding;
        /* Send message to Media task to configure transcoding */
        btif_a2dp_source_feeding_init_req(&mfeed);
    }

    mutex_global_unlock();
}

void btif_a2dp_source_start_aa_req(void)
{
    BT_HDR *p_buf = (BT_HDR *)osi_malloc(sizeof(BT_HDR));

    p_buf->event = BTIF_MEDIA_START_AA_TX;
    fixed_queue_enqueue(btif_a2dp_source_cb.cmd_msg_queue, p_buf);
}

void btif_a2dp_source_stop_aa_req(void)
{
    BT_HDR *p_buf = (BT_HDR *)osi_malloc(sizeof(BT_HDR));

    p_buf->event = BTIF_MEDIA_STOP_AA_TX;

    /*
     * Explicitly check whether btif_a2dp_source_cb.cmd_msg_queue is not NULL
     * to avoid a race condition during shutdown of the Bluetooth stack.
     * This race condition is triggered when A2DP audio is streaming on
     * shutdown:
     * "btif_a2dp_source_on_stopped() -> btif_a2dp_source_stop_aa_req()"
     * is called to stop the particular audio stream, and this happens right
     * after the "BTIF_AV_CLEANUP_REQ_EVT -> btif_a2dp_source_shutdown()"
     * processing during the shutdown of the Bluetooth stack.
     */
    if (btif_a2dp_source_cb.cmd_msg_queue != NULL)
        fixed_queue_enqueue(btif_a2dp_source_cb.cmd_msg_queue, p_buf);
}

static void btif_a2dp_source_encoder_init(void)
{
    tBTIF_A2DP_SOURCE_INIT_AUDIO msg;

    // Check to make sure the platform has 8 bits/byte since
    // we're using that in frame size calculations now.
    assert(CHAR_BIT == 8);

    APPL_TRACE_DEBUG("%s", __func__);

    bta_av_co_audio_encoder_init(&msg);
    btif_a2dp_source_enc_init_req(&msg);
}

void btif_a2dp_source_encoder_update(void)
{
    tBTIF_A2DP_SOURCE_UPDATE_AUDIO msg;

    APPL_TRACE_DEBUG("%s", __func__);

    bta_av_co_audio_encoder_update(&msg);

    /* Update the audio encoding */
    btif_a2dp_source_enc_update_req(&msg);
}

static void btif_a2dp_source_enc_init_req(tBTIF_A2DP_SOURCE_INIT_AUDIO *p_msg)
{
    tBTIF_A2DP_SOURCE_INIT_AUDIO *p_buf =
        (tBTIF_A2DP_SOURCE_INIT_AUDIO *)osi_malloc(sizeof(tBTIF_A2DP_SOURCE_INIT_AUDIO));

    memcpy(p_buf, p_msg, sizeof(tBTIF_A2DP_SOURCE_INIT_AUDIO));
    p_buf->hdr.event = BTIF_MEDIA_SBC_ENC_INIT;
    fixed_queue_enqueue(btif_a2dp_source_cb.cmd_msg_queue, p_buf);
}

static void btif_a2dp_source_enc_update_req(tBTIF_A2DP_SOURCE_UPDATE_AUDIO *p_msg)
{
    tBTIF_A2DP_SOURCE_UPDATE_AUDIO *p_buf = (tBTIF_A2DP_SOURCE_UPDATE_AUDIO *)
        osi_malloc(sizeof(tBTIF_A2DP_SOURCE_UPDATE_AUDIO));

    memcpy(p_buf, p_msg, sizeof(tBTIF_A2DP_SOURCE_UPDATE_AUDIO));
    p_buf->hdr.event = BTIF_MEDIA_SBC_ENC_UPDATE;
    fixed_queue_enqueue(btif_a2dp_source_cb.cmd_msg_queue, p_buf);
}

static void btif_a2dp_source_enc_init(BT_HDR *p_msg)
{
    tBTIF_A2DP_SOURCE_INIT_AUDIO *pInitAudio = (tBTIF_A2DP_SOURCE_INIT_AUDIO *) p_msg;

    APPL_TRACE_DEBUG("%s", __func__);

    btif_a2dp_source_cb.timestamp = 0;

    /* SBC encoder config (enforced even if not used) */
    btif_a2dp_source_cb.sbc_encoder_params.s16ChannelMode = pInitAudio->ChannelMode;
    btif_a2dp_source_cb.sbc_encoder_params.s16NumOfSubBands = pInitAudio->NumOfSubBands;
    btif_a2dp_source_cb.sbc_encoder_params.s16NumOfBlocks = pInitAudio->NumOfBlocks;
    btif_a2dp_source_cb.sbc_encoder_params.s16AllocationMethod = pInitAudio->AllocationMethod;
    btif_a2dp_source_cb.sbc_encoder_params.s16SamplingFreq = pInitAudio->SamplingFreq;

    btif_a2dp_source_cb.sbc_encoder_params.u16BitRate = btif_a2dp_source_get_sbc_rate();

    /* Default transcoding is PCM to SBC, modified by feeding configuration */
    btif_a2dp_source_cb.TxTranscoding = BTIF_MEDIA_TRSCD_PCM_2_SBC;
    btif_a2dp_source_cb.TxAaMtuSize = ((BTIF_MEDIA_AA_BUF_SIZE-BTIF_MEDIA_AA_SBC_OFFSET-sizeof(BT_HDR))
            < pInitAudio->MtuSize) ? (BTIF_MEDIA_AA_BUF_SIZE - BTIF_MEDIA_AA_SBC_OFFSET
            - sizeof(BT_HDR)) : pInitAudio->MtuSize;

    APPL_TRACE_EVENT("%s: mtu %d, peer mtu %d",
                     __func__,
                     btif_a2dp_source_cb.TxAaMtuSize, pInitAudio->MtuSize);
    APPL_TRACE_EVENT("%s: ch mode %d, subnd %d, nb blk %d, alloc %d, rate %d, freq %d",
                     __func__,
                     btif_a2dp_source_cb.sbc_encoder_params.s16ChannelMode,
                     btif_a2dp_source_cb.sbc_encoder_params.s16NumOfSubBands,
                     btif_a2dp_source_cb.sbc_encoder_params.s16NumOfBlocks,
                     btif_a2dp_source_cb.sbc_encoder_params.s16AllocationMethod,
                     btif_a2dp_source_cb.sbc_encoder_params.u16BitRate,
                     btif_a2dp_source_cb.sbc_encoder_params.s16SamplingFreq);

    /* Reset entirely the SBC encoder */
    SBC_Encoder_Init(&(btif_a2dp_source_cb.sbc_encoder_params));

    btif_a2dp_source_cb.tx_sbc_frames = calculate_max_frames_per_packet();

    APPL_TRACE_DEBUG("%s: bit pool %d", __func__,
                     btif_a2dp_source_cb.sbc_encoder_params.s16BitPool);
}

static void btif_a2dp_source_enc_update(BT_HDR *p_msg)
{
    tBTIF_A2DP_SOURCE_UPDATE_AUDIO * pUpdateAudio = (tBTIF_A2DP_SOURCE_UPDATE_AUDIO *) p_msg;
    SBC_ENC_PARAMS *pstrEncParams = &btif_a2dp_source_cb.sbc_encoder_params;
    uint16_t s16SamplingFreq;
    SINT16 s16BitPool = 0;
    SINT16 s16BitRate;
    SINT16 s16FrameLen;
    uint8_t protect = 0;

    APPL_TRACE_DEBUG("%s: minmtu %d, maxbp %d minbp %d", __func__,
                     pUpdateAudio->MinMtuSize, pUpdateAudio->MaxBitPool,
                     pUpdateAudio->MinBitPool);

    if (!pstrEncParams->s16NumOfSubBands) {
        APPL_TRACE_WARNING("%s: SubBands are set to 0, resetting to max (%d)",
          __func__, SBC_MAX_NUM_OF_SUBBANDS);
        pstrEncParams->s16NumOfSubBands = SBC_MAX_NUM_OF_SUBBANDS;
    }

    if (!pstrEncParams->s16NumOfBlocks) {
        APPL_TRACE_WARNING("%s: Blocks are set to 0, resetting to max (%d)",
          __func__, SBC_MAX_NUM_OF_BLOCKS);
        pstrEncParams->s16NumOfBlocks = SBC_MAX_NUM_OF_BLOCKS;
    }

    if (!pstrEncParams->s16NumOfChannels) {
        APPL_TRACE_WARNING("%s: Channels are set to 0, resetting to max (%d)",
          __func__, SBC_MAX_NUM_OF_CHANNELS);
        pstrEncParams->s16NumOfChannels = SBC_MAX_NUM_OF_CHANNELS;
    }

    btif_a2dp_source_cb.TxAaMtuSize = ((BTIF_MEDIA_AA_BUF_SIZE -
                                  BTIF_MEDIA_AA_SBC_OFFSET - sizeof(BT_HDR))
            < pUpdateAudio->MinMtuSize) ? (BTIF_MEDIA_AA_BUF_SIZE - BTIF_MEDIA_AA_SBC_OFFSET
            - sizeof(BT_HDR)) : pUpdateAudio->MinMtuSize;

    /* Set the initial target bit rate */
    pstrEncParams->u16BitRate = btif_a2dp_source_get_sbc_rate();

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

        APPL_TRACE_EVENT("%s: bitpool candidate: %d (%d kbps)", __func__,
                         s16BitPool, pstrEncParams->u16BitRate);

        if (s16BitPool > pUpdateAudio->MaxBitPool) {
            APPL_TRACE_DEBUG("%s: computed bitpool too large (%d)", __func__,
                             s16BitPool);
            /* Decrease bitrate */
            btif_a2dp_source_cb.sbc_encoder_params.u16BitRate -= BTIF_MEDIA_BITRATE_STEP;
            /* Record that we have decreased the bitrate */
            protect |= 1;
        } else if (s16BitPool < pUpdateAudio->MinBitPool) {
            APPL_TRACE_WARNING("%s: computed bitpool too small (%d)", __func__,
                               s16BitPool);

            /* Increase bitrate */
            uint16_t previous_u16BitRate = btif_a2dp_source_cb.sbc_encoder_params.u16BitRate;
            btif_a2dp_source_cb.sbc_encoder_params.u16BitRate += BTIF_MEDIA_BITRATE_STEP;
            /* Record that we have increased the bitrate */
            protect |= 2;
            /* Check over-flow */
            if (btif_a2dp_source_cb.sbc_encoder_params.u16BitRate < previous_u16BitRate)
                protect |= 3;
        } else {
            break;
        }
        /* In case we have already increased and decreased the bitrate, just stop */
        if (protect == 3) {
            APPL_TRACE_ERROR("%s could not find bitpool in range", __func__);
            break;
        }
    } while (true);

    /* Finally update the bitpool in the encoder structure */
    pstrEncParams->s16BitPool = s16BitPool;

    APPL_TRACE_DEBUG("%s: final bit rate %d, final bit pool %d", __func__,
                     btif_a2dp_source_cb.sbc_encoder_params.u16BitRate,
                     btif_a2dp_source_cb.sbc_encoder_params.s16BitPool);

    /* make sure we reinitialize encoder with new settings */
    SBC_Encoder_Init(&(btif_a2dp_source_cb.sbc_encoder_params));

    btif_a2dp_source_cb.tx_sbc_frames = calculate_max_frames_per_packet();
}

static void btif_a2dp_source_feeding_init_req(tBTIF_A2DP_SOURCE_INIT_AUDIO_FEEDING *p_msg)
{
    tBTIF_A2DP_SOURCE_INIT_AUDIO_FEEDING *p_buf =
        (tBTIF_A2DP_SOURCE_INIT_AUDIO_FEEDING *)osi_malloc(sizeof(tBTIF_A2DP_SOURCE_INIT_AUDIO_FEEDING));

    memcpy(p_buf, p_msg, sizeof(tBTIF_A2DP_SOURCE_INIT_AUDIO_FEEDING));
    p_buf->hdr.event = BTIF_MEDIA_AUDIO_FEEDING_INIT;
    fixed_queue_enqueue(btif_a2dp_source_cb.cmd_msg_queue, p_buf);
}

void btif_a2dp_source_on_idle(void)
{
    if (btif_a2dp_source_state == BTIF_A2DP_SOURCE_STATE_OFF)
        return;

    /* Make sure media task is stopped */
    btif_a2dp_source_stop_aa_req();
}

void btif_a2dp_source_on_stopped(tBTA_AV_SUSPEND *p_av_suspend)
{
    APPL_TRACE_EVENT("## ON A2DP SOURCE STOPPED ##");

    if (btif_a2dp_source_state == BTIF_A2DP_SOURCE_STATE_OFF)
        return;

    /* allow using this api for other than suspend */
    if (p_av_suspend != NULL) {
        if (p_av_suspend->status != BTA_AV_SUCCESS) {
            APPL_TRACE_EVENT("AV STOP FAILED (%d)", p_av_suspend->status);
            if (p_av_suspend->initiator) {
                APPL_TRACE_WARNING("%s: A2DP stop request failed: status = %d",
                                   __func__, p_av_suspend->status);
                btif_a2dp_command_ack(A2DP_CTRL_ACK_FAILURE);
            }
            return;
        }
    }

    /* ensure tx frames are immediately suspended */
    btif_a2dp_source_cb.tx_flush = true;

    /* request to stop media task  */
    btif_a2dp_source_aa_tx_flush_req();
    btif_a2dp_source_stop_aa_req();

    /* once stream is fully stopped we will ack back */
}

void btif_a2dp_source_on_suspended(tBTA_AV_SUSPEND *p_av_suspend)
{
    APPL_TRACE_EVENT("## ON A2DP SOURCE SUSPENDED ##");

    if (btif_a2dp_source_state == BTIF_A2DP_SOURCE_STATE_OFF)
        return;

    /* check for status failures */
    if (p_av_suspend->status != BTA_AV_SUCCESS) {
        if (p_av_suspend->initiator) {
            APPL_TRACE_WARNING("%s: A2DP suspend request failed: status = %d",
                               __func__, p_av_suspend->status);
            btif_a2dp_command_ack(A2DP_CTRL_ACK_FAILURE);
        }
    }

    /* once stream is fully stopped we will ack back */

    /* ensure tx frames are immediately flushed */
    btif_a2dp_source_cb.tx_flush = true;

    /* stop timer tick */
    btif_a2dp_source_stop_aa_req();
}

/* when true media task discards any tx frames */
void btif_a2dp_source_set_tx_flush(bool enable)
{
    APPL_TRACE_EVENT("## DROP TX %d ##", enable);
    btif_a2dp_source_cb.tx_flush = enable;
}

static void btif_a2dp_source_feeding_state_reset(void)
{
    /* By default, just clear the entire state */
    memset(&btif_a2dp_source_cb.media_feeding_state, 0,
           sizeof(btif_a2dp_source_cb.media_feeding_state));

    if (btif_a2dp_source_cb.TxTranscoding == BTIF_MEDIA_TRSCD_PCM_2_SBC) {
        btif_a2dp_source_cb.media_feeding_state.bytes_per_tick =
                (btif_a2dp_source_cb.media_feeding.sampling_freq *
                 btif_a2dp_source_cb.media_feeding.bit_per_sample / 8 *
                 btif_a2dp_source_cb.media_feeding.num_channel *
                 BTIF_A2DP_SOURCE_MEDIA_TIMER_MS) / 1000;

        APPL_TRACE_WARNING("pcm bytes per tick %d",
                (int)btif_a2dp_source_cb.media_feeding_state.bytes_per_tick);
    }
}

static void btif_a2dp_source_audio_feeding_init(BT_HDR *p_msg)
{
    tBTIF_A2DP_SOURCE_INIT_AUDIO_FEEDING *p_feeding =
        (tBTIF_A2DP_SOURCE_INIT_AUDIO_FEEDING *)p_msg;

    APPL_TRACE_DEBUG("%s", __func__);

    /* Save Media Feeding information */
    btif_a2dp_source_cb.media_feeding = p_feeding->feeding;
    btif_a2dp_source_cb.TxTranscoding = BTIF_MEDIA_TRSCD_PCM_2_SBC;

    btif_a2dp_source_pcm2sbc_init(p_feeding);
}

static void btif_a2dp_source_pcm2sbc_init(tBTIF_A2DP_SOURCE_INIT_AUDIO_FEEDING *p_feeding)
{
    bool reconfig_needed = false;

    APPL_TRACE_DEBUG("PCM feeding:");
    APPL_TRACE_DEBUG("sampling_freq:%d", p_feeding->feeding.sampling_freq);
    APPL_TRACE_DEBUG("num_channel:%d", p_feeding->feeding.num_channel);
    APPL_TRACE_DEBUG("bit_per_sample:%d", p_feeding->feeding.bit_per_sample);

    /* Check the PCM feeding sampling_freq */
    switch (p_feeding->feeding.sampling_freq) {
        case  8000:
        case 12000:
        case 16000:
        case 24000:
        case 32000:
        case 48000:
            /* For these sampling_freq the AV connection must be 48000 */
            if (btif_a2dp_source_cb.sbc_encoder_params.s16SamplingFreq !=
                SBC_sf48000) {
                /* Reconfiguration needed at 48000 */
                APPL_TRACE_DEBUG("SBC Reconfiguration needed at 48000");
                btif_a2dp_source_cb.sbc_encoder_params.s16SamplingFreq =
                    SBC_sf48000;
                reconfig_needed = true;
            }
            break;

        case 11025:
        case 22050:
        case 44100:
            /* For these sampling_freq the AV connection must be 44100 */
            if (btif_a2dp_source_cb.sbc_encoder_params.s16SamplingFreq !=
                SBC_sf44100) {
                /* Reconfiguration needed at 44100 */
                APPL_TRACE_DEBUG("SBC Reconfiguration needed at 44100");
                btif_a2dp_source_cb.sbc_encoder_params.s16SamplingFreq =
                    SBC_sf44100;
                reconfig_needed = true;
            }
            break;
        default:
            APPL_TRACE_DEBUG("Feeding PCM sampling_freq unsupported");
            break;
    }

    /* Some AV Headsets do not support Mono => always ask for Stereo */
    if (btif_a2dp_source_cb.sbc_encoder_params.s16ChannelMode == SBC_MONO) {
        APPL_TRACE_DEBUG("SBC Reconfiguration needed in Stereo");
        btif_a2dp_source_cb.sbc_encoder_params.s16ChannelMode = SBC_JOINT_STEREO;
        reconfig_needed = true;
    }

    if (reconfig_needed) {
        APPL_TRACE_DEBUG("%s: mtu %d", __func__,
                         btif_a2dp_source_cb.TxAaMtuSize);
        APPL_TRACE_DEBUG("%s: ch mode %d, nbsubd %d, nb %d, alloc %d, rate %d, freq %d",
                         __func__,
                         btif_a2dp_source_cb.sbc_encoder_params.s16ChannelMode,
                         btif_a2dp_source_cb.sbc_encoder_params.s16NumOfSubBands,
                         btif_a2dp_source_cb.sbc_encoder_params.s16NumOfBlocks,
                         btif_a2dp_source_cb.sbc_encoder_params.s16AllocationMethod,
                         btif_a2dp_source_cb.sbc_encoder_params.u16BitRate,
                         btif_a2dp_source_cb.sbc_encoder_params.s16SamplingFreq);

        SBC_Encoder_Init(&(btif_a2dp_source_cb.sbc_encoder_params));
    } else {
        APPL_TRACE_DEBUG("%s: no SBC reconfig needed", __func__);
    }
}

static void btif_a2dp_source_aa_start_tx(void)
{
    APPL_TRACE_DEBUG("%s media_alarm is %srunning, is_streaming %s", __func__,
                     alarm_is_scheduled(btif_a2dp_source_cb.media_alarm)? "" : "not ",
                     (btif_a2dp_source_cb.is_streaming)? "true" : "false");

    last_frame_us = 0;

    /* Reset the media feeding state */
    btif_a2dp_source_feeding_state_reset();

    APPL_TRACE_EVENT("starting timer %dms", BTIF_A2DP_SOURCE_MEDIA_TIMER_MS);

    alarm_free(btif_a2dp_source_cb.media_alarm);
    btif_a2dp_source_cb.media_alarm = alarm_new_periodic("btif.a2dp_source_media_alarm");
    if (btif_a2dp_source_cb.media_alarm == NULL) {
      LOG_ERROR(LOG_TAG, "%s unable to allocate media alarm", __func__);
      return;
    }

    alarm_set(btif_a2dp_source_cb.media_alarm, BTIF_A2DP_SOURCE_MEDIA_TIMER_MS,
              btif_a2dp_source_alarm_cb, NULL);
}

static void btif_a2dp_source_aa_stop_tx(void)
{
    APPL_TRACE_DEBUG("%s media_alarm is %srunning, is_streaming %s", __func__,
                     alarm_is_scheduled(btif_a2dp_source_cb.media_alarm)? "" : "not ",
                     (btif_a2dp_source_cb.is_streaming)? "true" : "false");

    const bool send_ack = btif_a2dp_source_cb.is_streaming;

    /* Stop the timer first */
    btif_a2dp_source_cb.is_streaming = false;
    alarm_free(btif_a2dp_source_cb.media_alarm);
    btif_a2dp_source_cb.media_alarm = NULL;

    UIPC_Close(UIPC_CH_ID_AV_AUDIO);

    /*
     * Try to send acknowldegment once the media stream is
     * stopped. This will make sure that the A2DP HAL layer is
     * un-blocked on wait for acknowledgment for the sent command.
     * This resolves a corner cases AVDTP SUSPEND collision
     * when the DUT and the remote device issue SUSPEND simultaneously
     * and due to the processing of the SUSPEND request from the remote,
     * the media path is torn down. If the A2DP HAL happens to wait
     * for ACK for the initiated SUSPEND, it would never receive it casuing
     * a block/wait. Due to this acknowledgement, the A2DP HAL is guranteed
     * to get the ACK for any pending command in such cases.
     */

    if (send_ack)
        btif_a2dp_command_ack(A2DP_CTRL_ACK_SUCCESS);

    /* audio engine stopped, reset tx suspended flag */
    btif_a2dp_source_cb.tx_flush = false;
    last_frame_us = 0;

    /* Reset the media feeding state */
    btif_a2dp_source_feeding_state_reset();
}

static void btif_a2dp_source_alarm_cb(UNUSED_ATTR void *context) {
  thread_post(btif_a2dp_source_cb.worker_thread,
              btif_a2dp_source_aa_handle_timer, NULL);
}

static void btif_a2dp_source_aa_handle_timer(UNUSED_ATTR void *context)
{
    uint64_t timestamp_us = time_get_os_boottime_us();
    log_tstamps_us("A2DP Source tx timer", timestamp_us);

    if (alarm_is_scheduled(btif_a2dp_source_cb.media_alarm)) {
        btif_a2dp_source_send_aa_frame(timestamp_us);
    } else {
        APPL_TRACE_ERROR("ERROR Media task Scheduled after Suspend");
    }
}

static void btif_a2dp_source_send_aa_frame(uint64_t timestamp_us)
{
    uint8_t nb_frame_2_send = 0;
    uint8_t nb_iterations = 0;

    btif_get_num_aa_frame_iteration(&nb_iterations, &nb_frame_2_send);

    if (nb_frame_2_send != 0) {
        for (uint8_t counter = 0; counter < nb_iterations; counter++) {
            /* format and queue buffer to send */
            btif_a2dp_source_aa_prep_2_send(nb_frame_2_send, timestamp_us);
        }
    }

    LOG_VERBOSE(LOG_TAG, "%s: Sent %d frames per iteration, %d iterations",
                        __func__, nb_frame_2_send, nb_iterations);
    bta_av_ci_src_data_ready(BTA_AV_CHNL_AUDIO);
}

static void btif_a2dp_source_aa_prep_2_send(uint8_t nb_frame,
                                            uint64_t timestamp_us)
{
    // Check for TX queue overflow

    if (nb_frame > MAX_OUTPUT_A2DP_FRAME_QUEUE_SZ)
        nb_frame = MAX_OUTPUT_A2DP_FRAME_QUEUE_SZ;

    if (fixed_queue_length(btif_a2dp_source_cb.TxAaQ) >
        (MAX_OUTPUT_A2DP_FRAME_QUEUE_SZ - nb_frame)) {
        APPL_TRACE_WARNING("%s() - TX queue buffer count %d/%d", __func__,
                           fixed_queue_length(btif_a2dp_source_cb.TxAaQ),
                           MAX_OUTPUT_A2DP_FRAME_QUEUE_SZ - nb_frame);
        // Keep track of drop-outs
        btif_a2dp_source_cb.stats.tx_queue_dropouts++;
        btif_a2dp_source_cb.stats.tx_queue_last_dropouts_us = timestamp_us;

        // Flush all queued buffers
        while (fixed_queue_length(btif_a2dp_source_cb.TxAaQ)) {
            btif_a2dp_source_cb.stats.tx_queue_total_dropped_messages++;
            osi_free(fixed_queue_try_dequeue(btif_a2dp_source_cb.TxAaQ));
        }

        // Request RSSI for log purposes if we had to flush buffers
        bt_bdaddr_t peer_bda = btif_av_get_addr();
        BTM_ReadRSSI(peer_bda.address, btm_read_rssi_cb);
    }

    // Transcode frame

    switch (btif_a2dp_source_cb.TxTranscoding) {
    case BTIF_MEDIA_TRSCD_PCM_2_SBC:
        btif_a2dp_source_aa_prep_sbc_2_send(nb_frame, timestamp_us);
        break;

    default:
        APPL_TRACE_ERROR("%s: unsupported transcoding format 0x%x",
                         __func__, btif_a2dp_source_cb.TxTranscoding);
        break;
    }
}

static void btif_a2dp_source_aa_prep_sbc_2_send(uint8_t nb_frame,
                                                uint64_t timestamp_us)
{
    uint8_t remain_nb_frame = nb_frame;
    uint16_t blocm_x_subband =
        btif_a2dp_source_cb.sbc_encoder_params.s16NumOfSubBands *
        btif_a2dp_source_cb.sbc_encoder_params.s16NumOfBlocks;

    while (nb_frame) {
        BT_HDR *p_buf = (BT_HDR *)osi_malloc(BTIF_MEDIA_AA_BUF_SIZE);

        /* Init buffer */
        p_buf->offset = BTIF_MEDIA_AA_SBC_OFFSET;
        p_buf->len = 0;
        p_buf->layer_specific = 0;

        do {
            /* Write @ of allocated buffer in sbc_encoder_params.pu8Packet */
            btif_a2dp_source_cb.sbc_encoder_params.pu8Packet =
                (uint8_t *) (p_buf + 1) + p_buf->offset + p_buf->len;
            /* Fill allocated buffer with 0 */
            memset(btif_a2dp_source_cb.sbc_encoder_params.as16PcmBuffer, 0,
                   blocm_x_subband * btif_a2dp_source_cb.sbc_encoder_params.s16NumOfChannels);

            /* Read PCM data and upsample them if needed */
            if (btif_a2dp_source_aa_read_feeding()) {
                SBC_Encoder(&(btif_a2dp_source_cb.sbc_encoder_params));

                /* Update SBC frame length */
                p_buf->len += btif_a2dp_source_cb.sbc_encoder_params.u16PacketLength;
                nb_frame--;
                p_buf->layer_specific++;
            } else {
                APPL_TRACE_WARNING("%s: underflow %d, %d",
                                   __func__, nb_frame,
                                   btif_a2dp_source_cb.media_feeding_state.aa_feed_residue);
                btif_a2dp_source_cb.media_feeding_state.counter +=
                    nb_frame *
                    btif_a2dp_source_cb.sbc_encoder_params.s16NumOfSubBands *
                    btif_a2dp_source_cb.sbc_encoder_params.s16NumOfBlocks *
                    btif_a2dp_source_cb.media_feeding.num_channel *
                    btif_a2dp_source_cb.media_feeding.bit_per_sample / 8;
                /* no more pcm to read */
                nb_frame = 0;

                /* break read loop if timer was stopped (media task stopped) */
                if (! alarm_is_scheduled(btif_a2dp_source_cb.media_alarm)) {
                    osi_free(p_buf);
                    return;
                }
            }

        } while (((p_buf->len + btif_a2dp_source_cb.sbc_encoder_params.u16PacketLength) < btif_a2dp_source_cb.TxAaMtuSize)
                && (p_buf->layer_specific < 0x0F) && nb_frame);

        if (p_buf->len) {
            /*
             * Timestamp of the media packet header represent the TS of the
             * first SBC frame, i.e the timestamp before including this frame.
             */
            *((uint32_t *) (p_buf + 1)) = btif_a2dp_source_cb.timestamp;

            btif_a2dp_source_cb.timestamp +=
                p_buf->layer_specific * blocm_x_subband;

            if (btif_a2dp_source_cb.tx_flush) {
                APPL_TRACE_DEBUG("### tx suspended, discarded frame ###");

                btif_a2dp_source_cb.stats.tx_queue_total_flushed_messages +=
                    fixed_queue_length(btif_a2dp_source_cb.TxAaQ);
                btif_a2dp_source_cb.stats.tx_queue_last_flushed_us =
                    timestamp_us;
                fixed_queue_flush(btif_a2dp_source_cb.TxAaQ, osi_free);

                osi_free(p_buf);
                return;
            }

            /* Enqueue the encoded SBC frame in AA Tx Queue */
            update_scheduling_stats(&btif_a2dp_source_cb.stats.tx_queue_enqueue_stats,
                                    timestamp_us,
                                    BTIF_A2DP_SOURCE_MEDIA_TIMER_MS * 1000);
            uint8_t done_nb_frame = remain_nb_frame - nb_frame;
            remain_nb_frame = nb_frame;
            btif_a2dp_source_cb.stats.tx_queue_total_frames += done_nb_frame;
            if (done_nb_frame > btif_a2dp_source_cb.stats.tx_queue_max_frames_per_packet)
                btif_a2dp_source_cb.stats.tx_queue_max_frames_per_packet = done_nb_frame;
            fixed_queue_enqueue(btif_a2dp_source_cb.TxAaQ, p_buf);
        } else {
            osi_free(p_buf);
        }
    }
}

static bool btif_a2dp_source_aa_read_feeding(void)
{
    uint16_t event;
    uint16_t blocm_x_subband =
        btif_a2dp_source_cb.sbc_encoder_params.s16NumOfSubBands *
        btif_a2dp_source_cb.sbc_encoder_params.s16NumOfBlocks;
    uint32_t read_size;
    uint32_t sbc_sampling = 48000;
    uint32_t src_samples;
    uint16_t bytes_needed = blocm_x_subband *
        btif_a2dp_source_cb.sbc_encoder_params.s16NumOfChannels *
        btif_a2dp_source_cb.media_feeding.bit_per_sample / 8;
    static uint16_t up_sampled_buffer[SBC_MAX_NUM_FRAME * SBC_MAX_NUM_OF_BLOCKS
            * SBC_MAX_NUM_OF_CHANNELS * SBC_MAX_NUM_OF_SUBBANDS * 2];
    static uint16_t read_buffer[SBC_MAX_NUM_FRAME * SBC_MAX_NUM_OF_BLOCKS
            * SBC_MAX_NUM_OF_CHANNELS * SBC_MAX_NUM_OF_SUBBANDS];
    uint32_t src_size_used;
    uint32_t dst_size_used;
    bool fract_needed;
    int32_t fract_max;
    int32_t fract_threshold;
    uint32_t nb_byte_read;

    /* Get the SBC sampling rate */
    switch (btif_a2dp_source_cb.sbc_encoder_params.s16SamplingFreq) {
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

    if (sbc_sampling == btif_a2dp_source_cb.media_feeding.sampling_freq) {
        read_size = bytes_needed - btif_a2dp_source_cb.media_feeding_state.aa_feed_residue;
        nb_byte_read = UIPC_Read(UIPC_CH_ID_AV_AUDIO, &event,
                ((uint8_t *)btif_a2dp_source_cb.sbc_encoder_params.as16PcmBuffer) +
                btif_a2dp_source_cb.media_feeding_state.aa_feed_residue,
                read_size);
        if (nb_byte_read == read_size) {
            btif_a2dp_source_cb.media_feeding_state.aa_feed_residue = 0;
            return true;
        } else {
            APPL_TRACE_WARNING("### UNDERFLOW :: ONLY READ %d BYTES OUT OF %d ###",
                nb_byte_read, read_size);
            btif_a2dp_source_cb.media_feeding_state.aa_feed_residue += nb_byte_read;
            btif_a2dp_source_cb.stats.media_read_total_underflow_bytes += (read_size - nb_byte_read);
            btif_a2dp_source_cb.stats.media_read_total_underflow_count++;
            btif_a2dp_source_cb.stats.media_read_last_underflow_us = time_get_os_boottime_us();
            return false;
        }
    }

    /*
     * Some Feeding PCM frequencies require to split the number of sample
     * to read.
     * E.g 128 / 6 = 21.3333 => read 22 and 21 and 21 => max = 2; threshold = 0
     */
    fract_needed = false;   /* Default */
    switch (btif_a2dp_source_cb.media_feeding.sampling_freq) {
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
    src_samples *= btif_a2dp_source_cb.media_feeding.sampling_freq;
    src_samples /= sbc_sampling;

    /* The previous division may have a remainder not null */
    if (fract_needed) {
        if (btif_a2dp_source_cb.media_feeding_state.aa_feed_counter <= fract_threshold) {
            src_samples++; /* for every read before threshold add one sample */
        }

        /* do nothing if counter >= threshold */
        btif_a2dp_source_cb.media_feeding_state.aa_feed_counter++; /* one more read */
        if (btif_a2dp_source_cb.media_feeding_state.aa_feed_counter > fract_max) {
            btif_a2dp_source_cb.media_feeding_state.aa_feed_counter = 0;
        }
    }

    /* Compute number of bytes to read from source */
    read_size = src_samples;
    read_size *= btif_a2dp_source_cb.media_feeding.num_channel;
    read_size *= (btif_a2dp_source_cb.media_feeding.bit_per_sample / 8);

    /* Read Data from UIPC channel */
    nb_byte_read = UIPC_Read(UIPC_CH_ID_AV_AUDIO, &event,
                             (uint8_t *)read_buffer, read_size);

    if (nb_byte_read < read_size) {
        APPL_TRACE_WARNING("### UNDERRUN :: ONLY READ %d BYTES OUT OF %d ###",
                           nb_byte_read, read_size);
        btif_a2dp_source_cb.stats.media_read_total_underrun_bytes += (read_size - nb_byte_read);
        btif_a2dp_source_cb.stats.media_read_total_underrun_count++;
        btif_a2dp_source_cb.stats.media_read_last_underrun_us = time_get_os_boottime_us();

        if (nb_byte_read == 0)
            return false;

        /* Fill the unfilled part of the read buffer with silence (0) */
        memset(((uint8_t *)read_buffer) + nb_byte_read, 0,
               read_size - nb_byte_read);
        nb_byte_read = read_size;
    }

    /* Initialize PCM up-sampling engine */
    bta_av_sbc_init_up_sample(btif_a2dp_source_cb.media_feeding.sampling_freq,
                              sbc_sampling,
                              btif_a2dp_source_cb.media_feeding.bit_per_sample,
                              btif_a2dp_source_cb.media_feeding.num_channel);

    /*
     * Re-sample the read buffer.
     * The output PCM buffer will be stereo, 16 bit per sample.
     */
    dst_size_used = bta_av_sbc_up_sample((uint8_t *)read_buffer,
            (uint8_t *)up_sampled_buffer + btif_a2dp_source_cb.media_feeding_state.aa_feed_residue,
            nb_byte_read,
            sizeof(up_sampled_buffer) - btif_a2dp_source_cb.media_feeding_state.aa_feed_residue,
            &src_size_used);

    /* update the residue */
    btif_a2dp_source_cb.media_feeding_state.aa_feed_residue += dst_size_used;

    /* only copy the pcm sample when we have up-sampled enough PCM */
    if (btif_a2dp_source_cb.media_feeding_state.aa_feed_residue >= bytes_needed) {
        /* Copy the output pcm samples in SBC encoding buffer */
        memcpy((uint8_t *)btif_a2dp_source_cb.sbc_encoder_params.as16PcmBuffer,
                (uint8_t *)up_sampled_buffer,
                bytes_needed);
        /* update the residue */
        btif_a2dp_source_cb.media_feeding_state.aa_feed_residue -= bytes_needed;

        if (btif_a2dp_source_cb.media_feeding_state.aa_feed_residue != 0) {
            memcpy((uint8_t *)up_sampled_buffer,
                   (uint8_t *)up_sampled_buffer + bytes_needed,
                   btif_a2dp_source_cb.media_feeding_state.aa_feed_residue);
        }
        return true;
    }

    return false;
}

static void btif_a2dp_source_aa_tx_flush(UNUSED_ATTR BT_HDR *p_msg)
{
    /* Flush all enqueued audio buffers (encoded) */
    APPL_TRACE_DEBUG("%s", __func__);

    btif_a2dp_source_cb.media_feeding_state.counter = 0;
    btif_a2dp_source_cb.media_feeding_state.aa_feed_residue = 0;

    btif_a2dp_source_cb.stats.tx_queue_total_flushed_messages +=
        fixed_queue_length(btif_a2dp_source_cb.TxAaQ);
    btif_a2dp_source_cb.stats.tx_queue_last_flushed_us = time_get_os_boottime_us();
    fixed_queue_flush(btif_a2dp_source_cb.TxAaQ, osi_free);

    UIPC_Ioctl(UIPC_CH_ID_AV_AUDIO, UIPC_REQ_RX_FLUSH, NULL);
}

static bool btif_a2dp_source_aa_tx_flush_req(void)
{
    BT_HDR *p_buf = (BT_HDR *)osi_malloc(sizeof(BT_HDR));

    p_buf->event = BTIF_MEDIA_FLUSH_AA_TX;

    /*
     * Explicitly check whether the btif_a2dp_source_cb.cmd_msg_queue is not
     * NULL to avoid a race condition during shutdown of the Bluetooth stack.
     * This race condition is triggered when A2DP audio is streaming on
     * shutdown:
     * "btif_a2dp_source_on_stopped() -> btif_a2dp_source_aa_tx_flush_req()"
     * is called to stop the particular audio stream, and this happens right
     * after the "BTIF_AV_CLEANUP_REQ_EVT -> btif_a2dp_source_shutdown()"
     * processing during the shutdown of the Bluetooth stack.
     */
    if (btif_a2dp_source_cb.cmd_msg_queue != NULL)
        fixed_queue_enqueue(btif_a2dp_source_cb.cmd_msg_queue, p_buf);

    return true;
}

BT_HDR *btif_a2dp_source_aa_readbuf(void)
{
    uint64_t now_us = time_get_os_boottime_us();
    BT_HDR *p_buf = (BT_HDR *)fixed_queue_try_dequeue(btif_a2dp_source_cb.TxAaQ);

    btif_a2dp_source_cb.stats.tx_queue_total_readbuf_calls++;
    btif_a2dp_source_cb.stats.tx_queue_last_readbuf_us = now_us;
    if (p_buf != NULL) {
        // Update the statistics
        update_scheduling_stats(&btif_a2dp_source_cb.stats.tx_queue_dequeue_stats,
                                now_us,
                                BTIF_A2DP_SOURCE_MEDIA_TIMER_MS * 1000);
    }

    return p_buf;
}

static void log_tstamps_us(const char *comment, uint64_t timestamp_us)
{
    static uint64_t prev_us = 0;
    APPL_TRACE_DEBUG("[%s] ts %08llu, diff : %08llu, queue sz %d", comment, timestamp_us,
        timestamp_us - prev_us, fixed_queue_length(btif_a2dp_source_cb.TxAaQ));
    prev_us = timestamp_us;
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

static uint16_t btif_a2dp_source_get_sbc_rate(void)
{
    uint16_t rate = BTIF_A2DP_DEFAULT_BITRATE;

    /* restrict bitrate if a2dp link is non-edr */
    if (!btif_av_is_peer_edr()) {
        rate = BTIF_A2DP_NON_EDR_MAX_RATE;
        APPL_TRACE_DEBUG("%s: non-edr a2dp sink detected, restrict rate to %d",
                         __func__, rate);
    }

    return rate;
}

// Obtains the number of frames to send and number of iterations
// to be used. |num_of_ietrations| and |num_of_frames| parameters
// are used as output param for returning the respective values.
static void btif_get_num_aa_frame_iteration(uint8_t *num_of_iterations,
                                            uint8_t *num_of_frames)
{
    uint8_t nof = 0;
    uint8_t noi = 1;

    switch (btif_a2dp_source_cb.TxTranscoding) {
        case BTIF_MEDIA_TRSCD_PCM_2_SBC:
        {
            uint32_t projected_nof = 0;
            uint32_t pcm_bytes_per_frame =
                btif_a2dp_source_cb.sbc_encoder_params.s16NumOfSubBands *
                btif_a2dp_source_cb.sbc_encoder_params.s16NumOfBlocks *
                btif_a2dp_source_cb.media_feeding.num_channel *
                btif_a2dp_source_cb.media_feeding.bit_per_sample / 8;
            APPL_TRACE_DEBUG("%s: pcm_bytes_per_frame %u", __func__,
                             pcm_bytes_per_frame);

            uint32_t us_this_tick = BTIF_A2DP_SOURCE_MEDIA_TIMER_MS * 1000;
            uint64_t now_us = time_get_os_boottime_us();
            if (last_frame_us != 0)
                us_this_tick = (now_us - last_frame_us);
            last_frame_us = now_us;

            btif_a2dp_source_cb.media_feeding_state.counter +=
                btif_a2dp_source_cb.media_feeding_state.bytes_per_tick *
                us_this_tick / (BTIF_A2DP_SOURCE_MEDIA_TIMER_MS * 1000);

            /* Calculate the number of frames pending for this media tick */
            projected_nof = btif_a2dp_source_cb.media_feeding_state.counter / pcm_bytes_per_frame;
            if (projected_nof > btif_a2dp_source_cb.stats.media_read_max_expected_frames)
                btif_a2dp_source_cb.stats.media_read_max_expected_frames = projected_nof;
            btif_a2dp_source_cb.stats.media_read_total_expected_frames += projected_nof;
            btif_a2dp_source_cb.stats.media_read_expected_count++;
            if (projected_nof > MAX_PCM_FRAME_NUM_PER_TICK) {
                APPL_TRACE_WARNING("%s() - Limiting frames to be sent from %d to %d",
                                   __func__, projected_nof,
                                   MAX_PCM_FRAME_NUM_PER_TICK);
                size_t delta = projected_nof - MAX_PCM_FRAME_NUM_PER_TICK;
                btif_a2dp_source_cb.stats.media_read_limited_count++;
                btif_a2dp_source_cb.stats.media_read_total_limited_frames += delta;
                if (delta > btif_a2dp_source_cb.stats.media_read_max_limited_frames)
                    btif_a2dp_source_cb.stats.media_read_max_limited_frames = delta;
                projected_nof = MAX_PCM_FRAME_NUM_PER_TICK;
            }

            APPL_TRACE_DEBUG("%s: frames for available PCM data %u",
                             __func__, projected_nof);

            if (btif_av_is_peer_edr()) {
                if (!btif_a2dp_source_cb.tx_sbc_frames) {
                    APPL_TRACE_ERROR("%s: tx_sbc_frames not updated, update from here", __func__);
                    btif_a2dp_source_cb.tx_sbc_frames = calculate_max_frames_per_packet();
                }

                nof = btif_a2dp_source_cb.tx_sbc_frames;
                if (!nof) {
                    APPL_TRACE_ERROR("%s: number of frames not updated, set calculated values",
                                     __func__);
                    nof = projected_nof;
                    noi = 1;
                } else {
                    if (nof < projected_nof) {
                        noi = projected_nof / nof; // number of iterations would vary
                        if (noi > MAX_PCM_ITER_NUM_PER_TICK) {
                            APPL_TRACE_ERROR("%s ## Audio Congestion (iterations:%d > max (%d))",
                                 __func__, noi, MAX_PCM_ITER_NUM_PER_TICK);
                            noi = MAX_PCM_ITER_NUM_PER_TICK;
                            btif_a2dp_source_cb.media_feeding_state.counter
                                = noi * nof * pcm_bytes_per_frame;
                        }
                        projected_nof = nof;
                    } else {
                        noi = 1;        // number of iterations is 1
                        APPL_TRACE_DEBUG("%s reducing frames for available PCM data", __func__);
                        nof = projected_nof;
                    }
                }
            } else {
                // For BR cases nof will be same as the value retrieved at projected_nof
                APPL_TRACE_DEBUG("%s headset BR, number of frames %u",
                                 __func__, nof);
                if (projected_nof > MAX_PCM_FRAME_NUM_PER_TICK) {
                    APPL_TRACE_ERROR("%s ## Audio Congestion (frames: %d > max (%d))",
                        __func__, projected_nof, MAX_PCM_FRAME_NUM_PER_TICK);
                    projected_nof = MAX_PCM_FRAME_NUM_PER_TICK;
                    btif_a2dp_source_cb.media_feeding_state.counter =
                        noi * projected_nof * pcm_bytes_per_frame;
                }
                nof = projected_nof;
            }
            btif_a2dp_source_cb.media_feeding_state.counter -= noi * nof * pcm_bytes_per_frame;
            APPL_TRACE_DEBUG("%s effective num of frames %u, iterations %u",
                             __func__, nof, noi);
        }
        break;

        default:
            APPL_TRACE_ERROR("%s: Unsupported transcoding format 0x%x",
                             __func__, btif_a2dp_source_cb.TxTranscoding);
            nof = 0;
            noi = 0;
            break;
    }
    *num_of_frames = nof;
    *num_of_iterations = noi;
}

static uint8_t calculate_max_frames_per_packet(void)
{
    uint16_t result = 0;
    uint16_t effective_mtu_size = btif_a2dp_source_cb.TxAaMtuSize;
    uint32_t frame_len;

    APPL_TRACE_DEBUG("%s original AVDTP MTU size: %d",
                     __func__, btif_a2dp_source_cb.TxAaMtuSize);
    if (btif_av_is_peer_edr() && !btif_av_peer_supports_3mbps()) {
        // This condition would be satisfied only if the remote device is
        // EDR and supports only 2 Mbps, but the effective AVDTP MTU size
        // exceeds the 2DH5 packet size.
        APPL_TRACE_DEBUG("%s The remote devce is EDR but does not support 3 Mbps", __func__);

        if (effective_mtu_size > MAX_2MBPS_AVDTP_MTU) {
            APPL_TRACE_WARNING("%s Restricting AVDTP MTU size to %d",
                __func__, MAX_2MBPS_AVDTP_MTU);
            effective_mtu_size = MAX_2MBPS_AVDTP_MTU;
            btif_a2dp_source_cb.TxAaMtuSize = effective_mtu_size;
        }
    }

    if (!btif_a2dp_source_cb.sbc_encoder_params.s16NumOfSubBands) {
        APPL_TRACE_ERROR("%s SubBands are set to 0, resetting to %d",
            __func__, SBC_MAX_NUM_OF_SUBBANDS);
        btif_a2dp_source_cb.sbc_encoder_params.s16NumOfSubBands = SBC_MAX_NUM_OF_SUBBANDS;
    }
    if (!btif_a2dp_source_cb.sbc_encoder_params.s16NumOfBlocks) {
        APPL_TRACE_ERROR("%s Blocks are set to 0, resetting to %d",
            __func__, SBC_MAX_NUM_OF_BLOCKS);
        btif_a2dp_source_cb.sbc_encoder_params.s16NumOfBlocks = SBC_MAX_NUM_OF_BLOCKS;
    }
    if (!btif_a2dp_source_cb.sbc_encoder_params.s16NumOfChannels) {
        APPL_TRACE_ERROR("%s Channels are set to 0, resetting to %d",
            __func__, SBC_MAX_NUM_OF_CHANNELS);
        btif_a2dp_source_cb.sbc_encoder_params.s16NumOfChannels = SBC_MAX_NUM_OF_CHANNELS;
    }

    frame_len = get_frame_length();

    APPL_TRACE_DEBUG("%s Effective Tx MTU to be considered: %d",
                     __func__, effective_mtu_size);

    switch (btif_a2dp_source_cb.sbc_encoder_params.s16SamplingFreq) {
        case SBC_sf44100:
            if (frame_len == 0) {
                APPL_TRACE_ERROR("%s Calculating frame length, \
                                        resetting it to default 119", __func__);
                frame_len = MAX_SBC_HQ_FRAME_SIZE_44_1;
            }
            result = (effective_mtu_size - A2DP_HDR_SIZE) / frame_len;
            APPL_TRACE_DEBUG("%s Max number of SBC frames: %d",
                             __func__, result);
            break;

        case SBC_sf48000:
            if (frame_len == 0) {
                APPL_TRACE_ERROR("%s Calculating frame length, \
                                        resetting it to default 115", __func__);
                frame_len = MAX_SBC_HQ_FRAME_SIZE_48;
            }
            result = (effective_mtu_size - A2DP_HDR_SIZE) / frame_len;
            APPL_TRACE_DEBUG("%s Max number of SBC frames: %d",
                             __func__, result);
            break;

        default:
            APPL_TRACE_ERROR("%s Max number of SBC frames: %d", __func__, result);
            break;

    }
    return result;
}

static uint32_t get_frame_length(void)
{
    uint32_t frame_len = 0;
    APPL_TRACE_DEBUG("%s channel mode: %d, sub-band: %d, number of block: %d, \
            bitpool: %d, sampling frequency: %d, num channels: %d",
            __func__,
            btif_a2dp_source_cb.sbc_encoder_params.s16ChannelMode,
            btif_a2dp_source_cb.sbc_encoder_params.s16NumOfSubBands,
            btif_a2dp_source_cb.sbc_encoder_params.s16NumOfBlocks,
            btif_a2dp_source_cb.sbc_encoder_params.s16BitPool,
            btif_a2dp_source_cb.sbc_encoder_params.s16SamplingFreq,
            btif_a2dp_source_cb.sbc_encoder_params.s16NumOfChannels);

    switch (btif_a2dp_source_cb.sbc_encoder_params.s16ChannelMode) {
        case SBC_MONO:
            /* FALLTHROUGH */
        case SBC_DUAL:
            frame_len = SBC_FRAME_HEADER_SIZE_BYTES +
                ((uint32_t)(SBC_SCALE_FACTOR_BITS * btif_a2dp_source_cb.sbc_encoder_params.s16NumOfSubBands *
                btif_a2dp_source_cb.sbc_encoder_params.s16NumOfChannels) / CHAR_BIT) +
                ((uint32_t)(btif_a2dp_source_cb.sbc_encoder_params.s16NumOfBlocks *
                btif_a2dp_source_cb.sbc_encoder_params.s16NumOfChannels *
                btif_a2dp_source_cb.sbc_encoder_params.s16BitPool) / CHAR_BIT);
            break;
        case SBC_STEREO:
            frame_len = SBC_FRAME_HEADER_SIZE_BYTES +
                ((uint32_t)(SBC_SCALE_FACTOR_BITS * btif_a2dp_source_cb.sbc_encoder_params.s16NumOfSubBands *
                btif_a2dp_source_cb.sbc_encoder_params.s16NumOfChannels) / CHAR_BIT) +
                ((uint32_t)(btif_a2dp_source_cb.sbc_encoder_params.s16NumOfBlocks *
                btif_a2dp_source_cb.sbc_encoder_params.s16BitPool) / CHAR_BIT);
            break;
        case SBC_JOINT_STEREO:
            frame_len = SBC_FRAME_HEADER_SIZE_BYTES +
                ((uint32_t)(SBC_SCALE_FACTOR_BITS * btif_a2dp_source_cb.sbc_encoder_params.s16NumOfSubBands *
                btif_a2dp_source_cb.sbc_encoder_params.s16NumOfChannels) / CHAR_BIT) +
                ((uint32_t)(btif_a2dp_source_cb.sbc_encoder_params.s16NumOfSubBands +
                (btif_a2dp_source_cb.sbc_encoder_params.s16NumOfBlocks *
                btif_a2dp_source_cb.sbc_encoder_params.s16BitPool)) / CHAR_BIT);
            break;
        default:
            APPL_TRACE_DEBUG("%s Invalid channel number: %d",
                __func__, btif_a2dp_source_cb.sbc_encoder_params.s16ChannelMode);
            break;
    }
    APPL_TRACE_DEBUG("%s calculated frame length: %d", __func__, frame_len);
    return frame_len;
}

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

void btif_a2dp_source_debug_dump(int fd)
{
    uint64_t now_us = time_get_os_boottime_us();
    btif_media_stats_t *stats = &btif_a2dp_source_cb.stats;
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

void btif_a2dp_source_update_metrics(void)
{
    uint64_t now_us = time_get_os_boottime_us();
    btif_media_stats_t *stats = &btif_a2dp_source_cb.stats;
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
        media_timer_min_ms = BTIF_A2DP_SOURCE_MEDIA_TIMER_MS -
            (dequeue_stats->max_premature_scheduling_delta_us / 1000);
        media_timer_max_ms = BTIF_A2DP_SOURCE_MEDIA_TIMER_MS +
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
