//
//  Copyright (C) 2015 Google, Inc.
//
//  Licensed under the Apache License, Version 2.0 (the "License");
//  you may not use this file except in compliance with the License.
//  You may obtain a copy of the License at:
//
//  http://www.apache.org/licenses/LICENSE-2.0
//
//  Unless required by applicable law or agreed to in writing, software
//  distributed under the License is distributed on an "AS IS" BASIS,
//  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//  See the License for the specific language governing permissions and
//  limitations under the License.
//
#include "a2dp_source.h"

#define LOG_TAG "A2dpSource"
#include "osi/include/log.h"

#include "core_stack.h"
#include "logging_helpers.h"
#include "osi/include/osi.h"

namespace {

void ConnectionStateCallback(btav_connection_state_t state,
                             UNUSED_ATTR bt_bdaddr_t *bd_addr) {
  LOG_INFO("%s: %s", __func__, BtAvConnectionStateText(state));
}

void AudioStateCallback(btav_audio_state_t state,
                        UNUSED_ATTR bt_bdaddr_t *bd_addr) {
  LOG_INFO("%s: %s", __func__, BtAvAudioStateText(state));
}

void AudioConfigCallback(UNUSED_ATTR bt_bdaddr_t *bd_addr,
                         UNUSED_ATTR uint32_t sample_rate,
                         UNUSED_ATTR uint8_t channel_count) {
  // I think these are used for audio sink only?
  // TODO(icoolidge): revisit.
}

btav_callbacks_t av_callbacks = {
    sizeof(btav_callbacks_t), ConnectionStateCallback, AudioStateCallback,
    AudioConfigCallback,
};

}  // namespace

namespace bluetooth {

A2dpSource::A2dpSource(CoreStack *bt) : av_(nullptr), bt_(bt) {
  // TODO(icoolidge): DCHECK(bt);
}

int A2dpSource::Start() {
  // Get the interface to the a2dp source profile.
  const void *interface = bt_->GetInterface(BT_PROFILE_ADVANCED_AUDIO_ID);
  if (!interface) {
    LOG_ERROR("Error getting audio source interface");
    return -1;
  }

  av_ = reinterpret_cast<const btav_interface_t *>(interface);

  bt_status_t btstat = av_->init(&av_callbacks);
  if (btstat != BT_STATUS_SUCCESS && btstat != BT_STATUS_DONE) {
    LOG_ERROR("Failed to initialize audio source interface: %s %d",
              BtStatusText(btstat), btstat);
    return -1;
  }
  return 0;
}

int A2dpSource::Stop() {
  // TODO(icoolidge): DCHECK(av_);
  av_->cleanup();
  return 0;
}

}  // namespace bluetooth
