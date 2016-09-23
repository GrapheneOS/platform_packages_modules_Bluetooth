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

#ifndef BTIF_A2DP_SOURCE_H
#define BTIF_A2DP_SOURCE_H

#include <stdbool.h>

#include "bta_av_api.h"

#ifdef __cplusplus
extern "C" {
#endif

// A2DP Source media timer in milliseconds.
#define BTIF_A2DP_SOURCE_MEDIA_TIMER_MS         20

typedef struct {
    BT_HDR hdr;
    uint16_t SamplingFreq;      /* 16k, 32k, 44.1k or 48k */
    uint8_t ChannelMode;        /* mono, dual, stereo or joint stereo */
    uint8_t NumOfSubBands;      /* 4 or 8 */
    uint8_t NumOfBlocks;        /* 4, 8, 12 or 16 */
    uint8_t AllocationMethod;   /* loudness or SNR */
    uint16_t MtuSize;           /* peer mtu size */
} tBTIF_A2DP_SOURCE_INIT_AUDIO;

typedef struct {
    BT_HDR hdr;
    uint16_t MinMtuSize;        /* Minimum peer mtu size */
    uint8_t MaxBitPool;         /* Maximum peer bitpool */
    uint8_t MinBitPool;         /* Minimum peer bitpool */
} tBTIF_A2DP_SOURCE_UPDATE_AUDIO;

// Initialize and startup the A2DP Source module.
// This function should be called by the BTIF state machine prior to using the
// module.
bool btif_a2dp_source_startup(void);

// Shutdown and cleanup the A2DP Source module.
// This function should be called by the BTIF state machine during
// graceful shutdown and cleanup.
void btif_a2dp_source_shutdown(void);

// Check whether the A2DP Source media task is running.
// Returns true if the A2DP Source media task is running, otherwise false.
bool btif_a2dp_source_media_task_is_running(void);

// Check whether the A2DP Source media task is shutting down.
// Returns true if the A2DP Source media task is shutting down.
bool btif_a2dp_source_media_task_is_shutting_down(void);

// Return true if the A2DP Source module is streaming.
bool btif_a2dp_source_is_streaming(void);

// Setup the A2DP Source codec, and prepare the encoder.
// This function should be called prior to starting A2DP streaming.
void btif_a2dp_source_setup_codec(void);

// Process a request to start the A2DP audio encoding task.
void btif_a2dp_source_start_aa_req(void);

// Process a request to stop the A2DP audio encoding task.
void btif_a2dp_source_stop_aa_req(void);

// Process 'idle' request from the BTIF state machine during initialization.
void btif_a2dp_source_on_idle(void);

// Process 'stop' request from the BTIF state machine to stop A2DP streaming.
// |p_av_suspend| is the data associated with the request - see
// |tBTA_AV_SUSPEND|.
void btif_a2dp_source_on_stopped(tBTA_AV_SUSPEND *p_av_suspend);

// Process 'suspend' request from the BTIF state machine to suspend A2DP
// streaming.
// |p_av_suspend| is the data associated with the request - see
// |tBTA_AV_SUSPEND|.
void btif_a2dp_source_on_suspended(tBTA_AV_SUSPEND *p_av_suspend);

// Enable/disable discarding of transmitted frames.
// If |enable| is true, the discarding is enabled, otherwise is disabled.
void btif_a2dp_source_set_tx_flush(bool enable);

// Update any changed encoder paramenters of the A2DP Source codec.
void btif_a2dp_source_encoder_update(void);

// Get the next A2DP buffer to send.
// Returns the next A2DP buffer to send if available, otherwise NULL.
BT_HDR *btif_a2dp_source_aa_readbuf(void);

// Dump debug-related information for the A2DP Source module.
// |fd| is the file descriptor to use for writing the ASCII formatted
// information.
void btif_a2dp_source_debug_dump(int fd);

// Update the A2DP Source related metrics.
// This function should be called before collecting the metrics.
void btif_a2dp_source_update_metrics(void);

#ifdef __cplusplus
}
#endif

#endif /* BTIF_A2DP_SOURCE_H */
