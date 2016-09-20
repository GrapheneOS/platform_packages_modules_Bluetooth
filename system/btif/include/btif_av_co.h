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

// Gets the current codec info.
const uint8_t *bta_av_co_get_codec_info(void);

/*******************************************************************************
 **
 ** Function         bta_av_co_cp_is_active
 **
 ** Description      Get the current configuration of content protection
 **
 ** Returns          true if the current streaming has CP, false otherwise
 **
 *******************************************************************************/
bool bta_av_co_cp_is_active(void);

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
uint8_t bta_av_co_cp_get_flag(void);

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
bool bta_av_co_cp_set_flag(uint8_t cp_flag);

/*******************************************************************************
 **
 ** Function         bta_av_co_audio_codec_reset
 **
 ** Description      Reset the current codec configuration
 **
 ** Returns          void
 **
 *******************************************************************************/
void bta_av_co_audio_codec_reset(void);

/*******************************************************************************
 **
 ** Function         bta_av_co_audio_codec_supported
 **
 ** Description      Check if all opened connections are compatible with a codec
 **                  configuration
 **
 ** Returns          true if all opened devices support this codec, false otherwise
 **
 *******************************************************************************/
bool bta_av_co_audio_codec_supported(void);

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
bool bta_av_co_audio_set_codec(const tA2D_AV_MEDIA_FEEDINGS *p_feeding);

// Prepares a message to initialize the encoder. The prepared message is
// stored in |msg|.
void bta_av_co_audio_encoder_init(tBTIF_MEDIA_INIT_AUDIO *msg);

// Prepares a message to update the encoder. The prepared message is
// stored in |msg|.
void bta_av_co_audio_encoder_update(tBTIF_MEDIA_UPDATE_AUDIO *msg);

/*******************************************************************************
 **
 ** Function         bta_av_co_audio_discard_config
 **
 ** Description      Discard the codec configuration of a connection
 **
 ** Returns          Nothing
 **
 *******************************************************************************/
void bta_av_co_audio_discard_config(tBTA_AV_HNDL hndl);

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


/*******************************************************************************
 **
 ** Function         bta_av_co_peer_cp_supported
 **
 ** Description      Checks if the peer supports CP
 **
 ** Returns          true if the peer supports CP
 **
 *******************************************************************************/
bool bta_av_co_peer_cp_supported(tBTA_AV_HNDL hndl);

#endif
