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

#include "btif_media.h"

/*******************************************************************************
**  Constants & Macros
********************************************************************************/

/*******************************************************************************
**  Functions
********************************************************************************/

/*******************************************************************************
 **
 ** Function         bta_av_co_audio_set_codec
 **
 ** Description      Set the current codec configuration from the feeding
 **                  information.
 **                  This function is starting to modify the configuration, it
 **                  should be protected.
 **
 ** Returns          true if successful, false otherwise
 **
 *******************************************************************************/
bool bta_av_co_audio_set_codec(const tA2D_AV_MEDIA_FEEDINGS *p_feeding);

// Prepares a message to initialize the encoder. The prepared message is
// stored in |msg|.
void bta_av_co_audio_encoder_init(tBTIF_MEDIA_INIT_AUDIO *msg);

// Prepares a message to update the encoder. The prepared message is
// stored in |msg|.
void bta_av_co_audio_encoder_update(tBTIF_MEDIA_UPDATE_AUDIO *msg);

/*******************************************************************************
 **
 ** Function         bta_av_co_init
 **
 ** Description      Initialization
 **
 ** Returns          Nothing
 **
 *******************************************************************************/
void bta_av_co_init(void);

#endif /* BTIF_AV_CO_H */
