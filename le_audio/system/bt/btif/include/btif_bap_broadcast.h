/******************************************************************************
 *
 *  Copyright 2021 The Android Open Source Project
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

 *
 *  Filename:      btif_bap_broadcast.h
 *
 *  Description:   Main API header file for all BTIF BAP Broadcast functions
 *                 accessed from internal stack.
 *
 ******************************************************************************/

#ifndef BTIF_BAP_BROADCAST_H
#define BTIF_BAP_BROADCAST_H

#include "bta_av_api.h"
#include "btif_common.h"
#include "btif_sm.h"


/*******************************************************************************
 *  Type definitions for callback functions
 ******************************************************************************/

typedef enum {
  /* Reuse BTA_AV_XXX_EVT - No need to redefine them here */
  BTIF_BAP_BROADCAST_ENABLE_EVT,
  BTIF_BAP_BROADCAST_DISABLE_EVT,
  BTIF_BAP_BROADCAST_START_STREAM_REQ_EVT,
  BTIF_BAP_BROADCAST_STOP_STREAM_REQ_EVT,
  BTIF_BAP_BROADCAST_SUSPEND_STREAM_REQ_EVT,
  BTIF_BAP_BROADCAST_SOURCE_CONFIG_REQ_EVT,
  BTIF_BAP_BROADCAST_CLEANUP_REQ_EVT,
  BTIF_BAP_BROADCAST_SET_ACTIVE_REQ_EVT,
  BTIF_BAP_BROADCAST_REMOVE_ACTIVE_REQ_EVT,
  BTIF_BAP_BROADCAST_SETUP_ISO_DATAPATH_EVT,
  BTIF_BAP_BROADCAST_REMOVE_ISO_DATAPATH_EVT,
  BTIF_BAP_BROADCAST_GENERATE_ENC_KEY_EVT,
  BTIF_BAP_BROADCAST_BISES_SETUP_EVT,
  BTIF_BAP_BROADCAST_BISES_REMOVE_EVT,
  BTIF_BAP_BROADCAST_BIG_SETUP_EVT,
  BTIF_BAP_BROADCAST_BIG_REMOVED_EVT,
  BTIF_BAP_BROADCAST_SETUP_NEXT_BIS_EVENT,
  BTIF_BAP_BROADCAST_PROCESS_HIDL_REQ_EVT,
} btif_bap_broadcast_sm_event_t;

enum {
  BTBAP_CODEC_CHANNEL_MODE_JOINT_STEREO = 0x01 << 2,
  BTBAP_CODEC_CHANNEL_MODE_DUAL_MONO = 0x1 << 3
};
/*******************************************************************************
 *  BTIF AV API
 ******************************************************************************/
bool btif_bap_broadcast_is_active();

uint16_t btif_bap_broadcast_get_sample_rate();
uint8_t btif_bap_broadcast_get_ch_mode();
uint16_t btif_bap_broadcast_get_framelength();
uint32_t btif_bap_broadcast_get_mtu(uint32_t bitrate);
uint32_t btif_bap_broadcast_get_bitrate();
uint8_t btif_bap_broadcast_get_ch_count();
bool btif_bap_broadcast_is_simulcast_enabled();
/*******************************************************************************
 *
 * Function         btif_dispatch_sm_event
 *
 * Description      Send event to AV statemachine
 *
 * Returns          None
 *
 ******************************************************************************/

/* used to pass events to AV statemachine from other tasks */
void btif_bap_ba_dispatch_sm_event(btif_bap_broadcast_sm_event_t event, void *p_data, int len);


#endif /* BTIF_BAP_BROADCAST_H */

