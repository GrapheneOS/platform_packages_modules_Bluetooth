/*
 * Copyright 2018 The Android Open Source Project
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

#ifndef ANDROID_INCLUDE_BT_PACS_CLIENT_H
#define ANDROID_INCLUDE_BT_PACS_CLIENT_H

#include <hardware/bluetooth.h>
#include <hardware/bt_av.h>

namespace bluetooth {
namespace bap {
namespace pacs {

#define BT_PROFILE_PACS_CLIENT_ID "bt_pacs_client"

enum class CodecDirection {
  CODEC_DIR_SINK = 0x1 << 0,
  CODEC_DIR_SRC  = 0x1 << 1
};

enum class CodecCapFrameDuration {
  FRAME_DUR_7_5         = 0x1 << 0,
  FRAME_DUR_10          = 0x1 << 1,
  FRAME_DUR_7_5_PREF    = 0x1 << 4,
  FRAME_DUR_10_PREF     = 0x1 << 5,
};

enum class CodecFrameDuration {
  FRAME_DUR_7_5         = 0x00,
  FRAME_DUR_10          = 0x01,
};

enum class CodecCapChnlCount {
  CHNL_COUNT_ONE         = 0x1 << 0,
  CHNL_COUNT_TWO         = 0x1 << 1,
  CHNL_COUNT_THREE       = 0x1 << 2,
  CHNL_COUNT_FOUR        = 0x1 << 3,
  CHNL_COUNT_FIVE        = 0x1 << 4,
  CHNL_COUNT_SIX         = 0x1 << 5,
  CHNL_COUNT_SEVEN       = 0x1 << 6,
  CHNL_COUNT_EIGHT       = 0x1 << 7,
};

enum class ConnectionState {
  DISCONNECTED = 0,
  CONNECTING,
  CONNECTED,
  DISCONNECTING
};

enum class CodecIndex {
  CODEC_INDEX_SOURCE_MIN = 0x09,

  // Add an entry for each source codec here.
  // NOTE: The values should be same as those listed in the following file:
  //   BluetoothCodecConfig.java
  CODEC_INDEX_SOURCE_LC3 = CODEC_INDEX_SOURCE_MIN,
  CODEC_INDEX_SOURCE_MAX,
  CODEC_INDEX_MIN = CODEC_INDEX_SOURCE_MIN,
  CODEC_INDEX_MAX = CODEC_INDEX_SOURCE_MAX,
};

enum class CodecPriority {
  // Disable the codec.
  CODEC_PRIORITY_DISABLED = -1,

  // Reset the codec priority to its default value.
  CODEC_PRIORITY_DEFAULT = 0,

  // Highest codec priority.
  CODEC_PRIORITY_HIGHEST = 1000 * 1000
};

enum class CodecSampleRate {
  CODEC_SAMPLE_RATE_NONE   = 0x0,
  CODEC_SAMPLE_RATE_44100  = 0x1 << 0,
  CODEC_SAMPLE_RATE_48000  = 0x1 << 1,
  CODEC_SAMPLE_RATE_88200  = 0x1 << 2,
  CODEC_SAMPLE_RATE_96000  = 0x1 << 3,
  CODEC_SAMPLE_RATE_176400 = 0x1 << 4,
  CODEC_SAMPLE_RATE_192000 = 0x1 << 5,
  CODEC_SAMPLE_RATE_16000  = 0x1 << 6,
  CODEC_SAMPLE_RATE_24000  = 0x1 << 7,
  CODEC_SAMPLE_RATE_32000  = 0x1 << 8,
  CODEC_SAMPLE_RATE_8000   = 0x1 << 9
};

enum class CodecBPS {
  CODEC_BITS_PER_SAMPLE_NONE = 0x0,
  CODEC_BITS_PER_SAMPLE_16   = 0x1 << 0,
  CODEC_BITS_PER_SAMPLE_24   = 0x1 << 1,
  CODEC_BITS_PER_SAMPLE_32   = 0x1 << 2
};

enum class CodecChannelMode {
  CODEC_CHANNEL_MODE_NONE   = 0x0,
  CODEC_CHANNEL_MODE_MONO   = 0x1 << 0,
  CODEC_CHANNEL_MODE_STEREO = 0x1 << 1
};

struct CodecConfig {
  CodecIndex codec_type;
  CodecPriority codec_priority; // Codec selection priority
                                // relative to other codecs: larger value
                                // means higher priority. If 0, reset to
                                // default.
  CodecSampleRate sample_rate;
  CodecBPS bits_per_sample;
  CodecChannelMode channel_mode;
  int64_t codec_specific_1;     // Codec-specific value 1
  int64_t codec_specific_2;     // Codec-specific value 2
  int64_t codec_specific_3;     // Codec-specific value 3
  int64_t codec_specific_4;     // Codec-specific value 4
};

class PacsClientCallbacks {
 public:
  virtual ~PacsClientCallbacks() = default;

  /** Callback for pacs server registration status */
  virtual void OnInitialized(int status, int client_id) = 0;

  /** Callback for pacs server connection state change */
  virtual void OnConnectionState(const RawAddress& address,
                                 ConnectionState state) = 0;

  /** Callback for audio ( media or voice) being available */
  virtual void OnAudioContextAvailable(const RawAddress& address,
                                       uint32_t available_contexts) = 0;

  /** Callback for pacs discovery results */
  virtual void OnSearchComplete(int status,
                 const RawAddress& address,
                 std::vector<CodecConfig> sink_pac_records,
                 std::vector<CodecConfig> src_pac_records,
                 uint32_t sink_locations,
                 uint32_t src_locations,
                 uint32_t available_contexts,
                 uint32_t supported_contexts) = 0;
};

class PacsClientInterface {
 public:
  virtual ~PacsClientInterface() = default;

  /** Register the Pacs client callbacks */
  virtual void Init(PacsClientCallbacks* callbacks) = 0;

  /** Connect to pacs server */
  virtual void Connect(uint16_t client_id, const RawAddress& address) = 0;

  /** Disconnect pacs server */
  virtual void Disconnect(uint16_t client_id, const RawAddress& address) = 0;

  /** start pacs discovery */
  virtual void StartDiscovery(uint16_t client_id,
                                const RawAddress& address) = 0;

  /** get available audio context */
  virtual void GetAvailableAudioContexts(uint16_t client_id,
                                         const RawAddress& address) = 0;
  /** Closes the interface. */
  virtual void Cleanup(uint16_t client_id) = 0;
};

}  // namespace pacs
}  // namespace bap
}  // namespace bluetooth

#endif /* ANDROID_INCLUDE_BT_CLIENT_H */
