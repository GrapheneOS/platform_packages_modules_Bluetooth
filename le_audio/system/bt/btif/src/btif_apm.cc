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


#define LOG_TAG "btif_apm"

#include <base/logging.h>
#include <string.h>

#include <hardware/bluetooth.h>
#include <hardware/bt_apm.h>

#include "bt_common.h"
#include "btif_common.h"
#include "btif_ahim.h"

#define A2DP_PROFILE 0x0001
#define BROADCAST_BREDR 0x0400
#define BROADCAST_LE 0x0800
#define ACTIVE_VOICE_PROFILE_HFP 0x0002

std::mutex apm_mutex;
btapm_initiator_callbacks_t* callbacks_;

static bt_status_t init(btapm_initiator_callbacks_t* callbacks);
static void cleanup();
static bt_status_t update_active_device(const RawAddress& bd_addr, uint16_t profile, uint16_t audio_type);
static bt_status_t set_content_control_id(uint16_t content_control_id, uint16_t audio_type);
static bool apm_enabled = false;


#define CHECK_BTAPM_INIT()                                                   \
  do {                                                                       \
    if (!apm_enabled) {                                                  \
      BTIF_TRACE_WARNING("%s: BTAV not initialized", __func__);              \
      return BT_STATUS_NOT_READY;                                            \
    }                                                                        \
  } while (0)

typedef enum {
  BTIF_APM_AUDIO_TYPE_VOICE = 0x0,
  BTIF_APM_AUDIO_TYPE_MEDIA,

  BTIF_APM_AUDIO_TYPE_SIZE
} btif_av_state_t;

typedef struct {
  RawAddress peer_bda;
  int profile;
} btif_apm_device_profile_combo_t;

typedef struct {
  RawAddress peer_bda;
} btif_apm_get_active_profile;

int active_profile_info;

static btif_apm_device_profile_combo_t active_device_profile[BTIF_APM_AUDIO_TYPE_SIZE];
static uint16_t content_control_id[BTIF_APM_AUDIO_TYPE_SIZE];

static void btif_update_active_device(uint16_t audio_type, char* param);
void btif_get_active_device(btif_av_state_t audio_type, RawAddress* peer_bda);
static void btif_update_content_control(uint16_t audio_type, char* param);
uint16_t btif_get_content_control_id(btif_av_state_t audio_type);

static void btif_update_active_device(uint16_t audio_type, char* param) {
  btif_apm_device_profile_combo_t new_device_profile;
  if(audio_type != BTIF_APM_AUDIO_TYPE_MEDIA)
    return;

  memcpy(&new_device_profile, param, sizeof(new_device_profile));
  active_device_profile[audio_type].peer_bda = new_device_profile.peer_bda;
  active_device_profile[audio_type].profile = new_device_profile.profile;
  BTIF_TRACE_WARNING("%s() New Active Device: %s, Profile: %x\n", __func__,
                active_device_profile[audio_type].peer_bda.ToString().c_str(),
                active_device_profile[audio_type].profile);
  if(active_device_profile[audio_type].profile == A2DP_PROFILE) {
    btif_ahim_update_current_profile(A2DP);
  } else if(active_device_profile[audio_type].profile == BROADCAST_LE) {
    btif_ahim_update_current_profile(BROADCAST);
  } else {
    btif_ahim_update_current_profile(AUDIO_GROUP_MGR);
  }
}

void btif_get_active_device(btif_av_state_t audio_type, RawAddress* peer_bda) {
  if(audio_type >= BTIF_APM_AUDIO_TYPE_SIZE)
    return;
  peer_bda = &active_device_profile[audio_type].peer_bda;
}

static void btif_update_content_control(uint16_t audio_type, char* param) {
  if(audio_type >= BTIF_APM_AUDIO_TYPE_SIZE)
    return;
  uint16_t cc_id = (uint16_t)(*param);
  content_control_id[audio_type] = cc_id;
  /*Update ACM here*/
}

uint16_t btif_get_content_control_id(btif_av_state_t audio_type) {
  if(audio_type >= BTIF_APM_AUDIO_TYPE_SIZE)
    return 0;
  return content_control_id[audio_type];
}

static const bt_apm_interface_t bt_apm_interface = {
    sizeof(bt_apm_interface_t),
    init,
    update_active_device,
    set_content_control_id,
    cleanup,
};

const bt_apm_interface_t* btif_apm_get_interface(void) {
  BTIF_TRACE_EVENT("%s", __func__);
  return &bt_apm_interface;
}

static bt_status_t init(btapm_initiator_callbacks_t* callbacks) {
  BTIF_TRACE_EVENT("%s", __func__);
  callbacks_  = callbacks;
  apm_enabled = true;
  
  return BT_STATUS_SUCCESS;
}

static void cleanup() {
  BTIF_TRACE_EVENT("%s", __func__);
  apm_enabled = false;
}

static bt_status_t update_active_device(const RawAddress& bd_addr, uint16_t profile, uint16_t audio_type) {
  BTIF_TRACE_EVENT("%s", __func__);
  CHECK_BTAPM_INIT();
  btif_apm_device_profile_combo_t new_device_profile;
  new_device_profile.peer_bda = bd_addr;
  new_device_profile.profile = profile;

  std::unique_lock<std::mutex> guard(apm_mutex);

  return btif_transfer_context(btif_update_active_device, (uint8_t)audio_type,
            (char *)&new_device_profile, sizeof(btif_apm_device_profile_combo_t), NULL);
}

static bt_status_t set_content_control_id(uint16_t content_control_id, uint16_t audio_type) {
  BTIF_TRACE_EVENT("%s", __func__);
  CHECK_BTAPM_INIT();

  std::unique_lock<std::mutex> guard(apm_mutex);

  return btif_transfer_context(btif_update_content_control,
     (uint8_t)audio_type, (char *)&content_control_id, sizeof(content_control_id), NULL);
}

void call_active_profile_info(const RawAddress& bd_addr, uint16_t audio_type) {
  if (apm_enabled == true) {
     BTIF_TRACE_WARNING("%s", __func__);
     active_profile_info = callbacks_->active_profile_cb(bd_addr, audio_type);
     BTIF_TRACE_WARNING("%s: profile info is %d", __func__, active_profile_info);
  }
}

int get_active_profile(const RawAddress& bd_addr, uint16_t audio_type) {
  if (apm_enabled == true) {
     BTIF_TRACE_WARNING("%s: active profile is %d ", __func__, active_profile_info);
     return active_profile_info;
  }
  else {
     BTIF_TRACE_WARNING("%s: APM is not enabled, returning HFP as active profile %d ",
                                     __func__, ACTIVE_VOICE_PROFILE_HFP);
     return ACTIVE_VOICE_PROFILE_HFP;
  }
}

