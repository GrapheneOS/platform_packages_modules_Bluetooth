/*
 * Copyright 2019 HIMSA II K/S - www.himsa.com. Represented by EHIMA -
 * www.ehima.com
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#pragma once

#include <array>
#include <optional>

#include "raw_address.h"

namespace bluetooth {
namespace le_audio {

enum class ConnectionState {
  DISCONNECTED = 0,
  CONNECTING,
  CONNECTED,
  DISCONNECTING
};

enum class GroupStatus {
  INACTIVE = 0,
  ACTIVE,
};

enum class GroupStreamStatus {
  IDLE = 0,
  STREAMING,
  RELEASING,
  SUSPENDING,
  SUSPENDED,
  RECONFIGURED,
  DESTROYED,
};

enum class GroupNodeStatus {
  ADDED = 1,
  REMOVED,
};

typedef enum {
  LE_AUDIO_CODEC_INDEX_SOURCE_LC3 = 0,
  LE_AUDIO_CODEC_INDEX_SOURCE_MAX
} btle_audio_codec_index_t;

typedef struct {
  btle_audio_codec_index_t codec_type;

  std::string ToString() const {
    std::string codec_name_str;

    switch (codec_type) {
      case LE_AUDIO_CODEC_INDEX_SOURCE_LC3:
        codec_name_str = "LC3";
        break;
      default:
        codec_name_str = "Unknown LE codec " + std::to_string(codec_type);
        break;
    }
    return "codec: " + codec_name_str;
  }
} btle_audio_codec_config_t;

class LeAudioClientCallbacks {
 public:
  virtual ~LeAudioClientCallbacks() = default;

  /** Callback for profile connection state change */
  virtual void OnConnectionState(ConnectionState state,
                                 const RawAddress& address) = 0;

  /* Callback with group status update */
  virtual void OnGroupStatus(int group_id, GroupStatus group_status) = 0;

  /* Callback with node status update */
  virtual void OnGroupNodeStatus(const RawAddress& bd_addr, int group_id,
                                 GroupNodeStatus node_status) = 0;
  /* Callback for newly recognized or reconfigured existing le audio group */
  virtual void OnAudioConf(uint8_t direction, int group_id,
                           uint32_t snk_audio_location,
                           uint32_t src_audio_location,
                           uint16_t avail_cont) = 0;
};

class LeAudioClientInterface {
 public:
  virtual ~LeAudioClientInterface() = default;

  /* Register the LeAudio callbacks */
  virtual void Initialize(
      LeAudioClientCallbacks* callbacks,
      const std::vector<btle_audio_codec_config_t>& offloading_preference) = 0;

  /** Connect to LEAudio */
  virtual void Connect(const RawAddress& address) = 0;

  /** Disconnect from LEAudio */
  virtual void Disconnect(const RawAddress& address) = 0;

  /* Cleanup the LeAudio */
  virtual void Cleanup(void) = 0;

  /* Called when LeAudio is unbonded. */
  virtual void RemoveDevice(const RawAddress& address) = 0;

  /* Attach le audio node to group */
  virtual void GroupAddNode(int group_id, const RawAddress& addr) = 0;

  /* Detach le audio node from a group */
  virtual void GroupRemoveNode(int group_id, const RawAddress& addr) = 0;

  /* Set active le audio group */
  virtual void GroupSetActive(int group_id) = 0;
};

static constexpr uint8_t INSTANCE_ID_UNDEFINED = 0xFF;

/* Represents the broadcast source state. */
enum class BroadcastState {
  STOPPED = 0,
  CONFIGURING,
  CONFIGURED,
  STOPPING,
  STREAMING,
};

/* A general hint for the codec configuration process. */
enum class BroadcastAudioProfile {
  SONIFICATION = 0,
  MEDIA,
};

using BroadcastCode = std::array<uint8_t, 16>;
using BroadcastId = std::array<uint8_t, 3>;
constexpr uint8_t kBroadcastAnnouncementBroadcastIdSize = 3;

class LeAudioBroadcasterCallbacks {
 public:
  virtual ~LeAudioBroadcasterCallbacks() = default;
  /* Callback for the newly created broadcast event. */
  virtual void OnBroadcastCreated(uint8_t instance_id, bool success) = 0;

  /* Callback for the destroyed broadcast event. */
  virtual void OnBroadcastDestroyed(uint8_t instance_id) = 0;
  /* Callback for the broadcast source state event. */
  virtual void OnBroadcastStateChanged(uint8_t instance_id,
                                       BroadcastState state) = 0;
  /* Callback for the broadcaster identifier. */
  virtual void OnBroadcastId(uint8_t instance_id,
                             const BroadcastId& broadcast_id) = 0;
};

class LeAudioBroadcasterInterface {
 public:
  virtual ~LeAudioBroadcasterInterface() = default;
  /* Register the LeAudio Broadcaster callbacks */
  virtual void Initialize(LeAudioBroadcasterCallbacks* callbacks) = 0;
  /* Stop the LeAudio Broadcaster and all active broadcasts */
  virtual void Stop(void) = 0;
  /* Cleanup the LeAudio Broadcaster */
  virtual void Cleanup(void) = 0;
  /* Create Broadcast instance */
  virtual void CreateBroadcast(std::vector<uint8_t> metadata,
                               BroadcastAudioProfile profile,
                               std::optional<BroadcastCode> broadcast_code) = 0;
  /* Update the ongoing Broadcast metadata */
  virtual void UpdateMetadata(uint8_t instance_id,
                              std::vector<uint8_t> metadata) = 0;

  /* Start the existing Broadcast stream */
  virtual void StartBroadcast(uint8_t instance_id) = 0;
  /* Pause the ongoing Broadcast stream */
  virtual void PauseBroadcast(uint8_t instance_id) = 0;
  /* Stop the Broadcast (no stream, no periodic advertisements */
  virtual void StopBroadcast(uint8_t instance_id) = 0;
  /* Destroy the existing Broadcast instance */
  virtual void DestroyBroadcast(uint8_t instance_id) = 0;
  /* Get Broadcasts identifier */
  virtual void GetBroadcastId(uint8_t instance_id) = 0;

  /* Get all broadcast states */
  virtual void GetAllBroadcastStates(void) = 0;
};

} /* namespace le_audio */
} /* namespace bluetooth */
