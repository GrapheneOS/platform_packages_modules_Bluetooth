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

#ifndef BTIF_AV_CO_H
#define BTIF_AV_CO_H

#include "btif/include/btif_a2dp_source.h"
#include "stack/include/a2dp_api.h"

/*******************************************************************************
 *  Constants & Macros
 ******************************************************************************/

#ifdef __cplusplus
extern "C" {
#endif

/*******************************************************************************
 *  Functions
 ******************************************************************************/

// Prepares a message to initialize the encoder. The prepared message is
// stored in |p_init_params|.
// |p_init_params| cannot be null.
void bta_av_co_audio_encoder_init(tA2DP_ENCODER_INIT_PARAMS* p_init_params);

// Gets the current A2DP encoder's feeding parameters. The result
// is stored in |p_feeding_params|.
void bta_av_co_get_encoder_feeding_parameters(
    tA2DP_FEEDING_PARAMS* p_feeding_params);

// Gets the current A2DP encoder interface that can be used to encode and
// prepare A2DP packets for transmission - see |tA2DP_ENCODER_INTERFACE|.
// Returns the A2DP encoder interface if the current codec is setup,
// otherwise NULL.
const tA2DP_ENCODER_INTERFACE* bta_av_co_get_encoder_interface(void);

/*******************************************************************************
 **
 ** Function         bta_av_co_init
 **
 ** Description      Initialization
 **
 ** Returns          Nothing
 **
 ******************************************************************************/
void bta_av_co_init(void);

#ifdef __cplusplus
}
#endif

#endif /* BTIF_AV_CO_H */
