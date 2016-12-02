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

//
// Interface to the A2DP SBC Encoder
//

#ifndef A2DP_SBC_ENCODER_H
#define A2DP_SBC_ENCODER_H

#include "a2dp_api.h"
#include "osi/include/time.h"

#ifdef __cplusplus
extern "C" {
#endif

// Loads the A2DP SBC encoder.
// Return true on success, otherwise false.
bool A2DP_LoadEncoderSbc(void);

// Unloads the A2DP SBC encoder.
void A2DP_UnloadEncoderSbc(void);

// Initialize the A2DP SBC encoder.
// If |is_peer_edr| is true, the A2DP peer device supports EDR.
// If |peer_supports_3mbps| is true, the A2DP peer device supports 3Mbps EDR.
// The encoder initialization parameters are in |p_init_params|.
// |enqueue_callback} is the callback for enqueueing the encoded audio data.
void a2dp_sbc_encoder_init(bool is_peer_edr, bool peer_supports_3mbps,
                           const tA2DP_ENCODER_INIT_PARAMS* p_init_params,
                           a2dp_source_read_callback_t read_callback,
                           a2dp_source_enqueue_callback_t enqueue_callback);

// Cleanup the A2DP SBC encoder.
void a2dp_sbc_encoder_cleanup(void);

// Initialize the feeding for the A2DP SBC encoder.
// The feeding initialization parameters are in |p_feeding_params|.
void a2dp_sbc_feeding_init(const tA2DP_FEEDING_PARAMS* p_feeding_params);

// Reset the feeding for the A2DP SBC encoder.
void a2dp_sbc_feeding_reset(void);

// Flush the feeding for the A2DP SBC encoder.
void a2dp_sbc_feeding_flush(void);

// Get the A2DP SBC encoder interval (in milliseconds).
period_ms_t a2dp_sbc_get_encoder_interval_ms(void);

// Prepare and send A2DP SBC encoded frames.
// |timestamp_us| is the current timestamp (in microseconds).
void a2dp_sbc_send_frames(uint64_t timestamp_us);

// Dump SBC codec-related statistics.
// |fd| is the file descriptor to use to dump the statistics information
// in user-friendly test format.
void a2dp_sbc_debug_codec_dump(int fd);

#ifdef __cplusplus
}
#endif

#endif  // A2DP_SBC_ENCODER_H
