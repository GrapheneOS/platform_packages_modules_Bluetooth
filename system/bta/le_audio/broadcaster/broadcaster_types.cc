/*
 * Copyright 2021 HIMSA II K/S - www.himsa.com.
 * Represented by EHIMA - www.ehima.com
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

#include "broadcaster_types.h"

#include <vector>

#include "bt_types.h"
#include "bta_le_audio_broadcaster_api.h"
#include "btm_ble_api_types.h"
#include "embdrv/lc3/include/lc3.h"

namespace le_audio {
namespace broadcaster {

static void EmitHeader(const BasicAudioAnnouncementData& announcement_data,
                       std::vector<uint8_t>& data) {
  size_t old_size = data.size();
  data.resize(old_size + 3);

  // Set the cursor behind the old data
  uint8_t* p_value = data.data() + old_size;

  UINT24_TO_STREAM(p_value, announcement_data.presentation_delay);
}

static void EmitCodecConfiguration(
    const BasicAudioAnnouncementCodecConfig& config, std::vector<uint8_t>& data,
    const BasicAudioAnnouncementCodecConfig* lower_lvl_config) {
  size_t old_size = data.size();

  // Add 5 for full, or 1 for short Codec ID
  uint8_t codec_config_length = 5;

  // Add 1 for the codec spec. config length + config spec. data itself
  codec_config_length += 1 + config.codec_specific_params.size();

  // Resize and set the cursor behind the old data
  data.resize(old_size + codec_config_length);
  uint8_t* p_value = data.data() + old_size;

  // Codec ID
  UINT8_TO_STREAM(p_value, config.codec_id);
  UINT16_TO_STREAM(p_value, config.vendor_company_id);
  UINT16_TO_STREAM(p_value, config.vendor_codec_id);

  // Codec specific config length
  UINT8_TO_STREAM(p_value, config.codec_specific_params.size());

  if (config.codec_specific_params.size() > 0) {
    // Codec specific config
    ARRAY_TO_STREAM(p_value, config.codec_specific_params.data(),
                    (int)config.codec_specific_params.size());
  }
}

static void EmitMetadata(const std::vector<uint8_t>& metadata,
                         std::vector<uint8_t>& data) {
  size_t old_size = data.size();
  data.resize(old_size + metadata.size() + 1);

  // Set the cursor behind the old data
  uint8_t* p_value = data.data() + old_size;

  UINT8_TO_STREAM(p_value, metadata.size());
  if (metadata.size() > 0)
    ARRAY_TO_STREAM(p_value, metadata.data(), (int)metadata.size());
}

static void EmitBisConfigs(
    const std::vector<BasicAudioAnnouncementBisConfig>& bis_configs,
    std::vector<uint8_t>& data) {
  // Emit each BIS config - that's the level 3 data
  for (auto const& bis_config : bis_configs) {
    size_t old_size = data.size();
    data.resize(old_size + bis_config.codec_specific_params.size() + 2);

    // Set the cursor behind the old data
    auto* p_value = data.data() + old_size;

    // BIS_index[i[k]]
    UINT8_TO_STREAM(p_value, bis_config.bis_index);

    // Per BIS Codec Specific Params[i[k]]
    UINT8_TO_STREAM(p_value, bis_config.codec_specific_params.size());
    ARRAY_TO_STREAM(p_value, bis_config.codec_specific_params.data(),
                    (int)bis_config.codec_specific_params.size());
  }
}

static void EmitSubgroup(const BasicAudioAnnouncementSubgroup& subgroup_config,
                         std::vector<uint8_t>& data) {
  // That's the level 2 data

  // Resize for the num_bis
  size_t initial_offset = data.size();
  data.resize(initial_offset + 1);

  // Set the cursor behind the old data and adds the level 2 Num_BIS[i]
  uint8_t* p_value = data.data() + initial_offset;
  UINT8_TO_STREAM(p_value, subgroup_config.bis_configs.size());

  EmitCodecConfiguration(subgroup_config.codec_config, data, nullptr);
  EmitMetadata(subgroup_config.metadata, data);

  // This adds the level 3 data
  EmitBisConfigs(subgroup_config.bis_configs, data);
}

bool BasicAudioAnnouncementData::ToRawPacket(std::vector<uint8_t>& data) const {
  EmitHeader(*this, data);

  // Set the cursor behind the old data and resize
  size_t old_size = data.size();
  data.resize(old_size + 1);
  uint8_t* p_value = data.data() + old_size;

  // Emit the subgroup size and each subgroup
  // That's the level 1 Num_Subgroups
  UINT8_TO_STREAM(p_value, this->subgroup_configs.size());
  for (const auto& subgroup_config : this->subgroup_configs) {
    // That's the level 2 and higher level data
    EmitSubgroup(subgroup_config, data);
  }

  return true;
}

void PrepareAdvertisingData(bluetooth::le_audio::BroadcastId& broadcast_id,
                            std::vector<uint8_t>& periodic_data) {
  periodic_data.resize(7);
  uint8_t* data_ptr = periodic_data.data();
  UINT8_TO_STREAM(data_ptr, 6);
  UINT8_TO_STREAM(data_ptr, BTM_BLE_AD_TYPE_SERVICE_DATA_TYPE);
  UINT16_TO_STREAM(data_ptr, kBroadcastAudioAnnouncementServiceUuid);
  ARRAY_TO_STREAM(data_ptr, broadcast_id.data(),
                  bluetooth::le_audio::kBroadcastAnnouncementBroadcastIdSize);
};

void PreparePeriodicData(const BasicAudioAnnouncementData& announcement,
                         std::vector<uint8_t>& periodic_data) {
  /* Account for AD Type + Service UUID */
  periodic_data.resize(4);
  /* Skip the data length field until the full content is generated */
  uint8_t* data_ptr = periodic_data.data() + 1;
  UINT8_TO_STREAM(data_ptr, BTM_BLE_AD_TYPE_SERVICE_DATA_TYPE);
  UINT16_TO_STREAM(data_ptr, kBasicAudioAnnouncementServiceUuid);

  /* Append the announcement */
  announcement.ToRawPacket(periodic_data);

  /* Update the length field accordingly */
  data_ptr = periodic_data.data();
  UINT8_TO_STREAM(data_ptr, periodic_data.size() - 1);
}

constexpr types::LeAudioCodecId kLeAudioCodecIdLc3 = {
    .coding_format = types::kLeAudioCodingFormatLC3,
    .vendor_company_id = types::kLeAudioVendorCompanyIdUndefined,
    .vendor_codec_id = types::kLeAudioVendorCodecIdUndefined};

static const BroadcastCodecWrapper lc3_mono_16_2 = BroadcastCodecWrapper(
    kLeAudioCodecIdLc3,
    // LeAudioCodecConfiguration
    {.num_channels = LeAudioCodecConfiguration::kChannelNumberMono,
     .sample_rate = LeAudioCodecConfiguration::kSampleRate16000,
     .bits_per_sample = LeAudioCodecConfiguration::kBitsPerSample16,
     .data_interval_us = LeAudioCodecConfiguration::kInterval10000Us},
    // Bitrate
    32000,
    // Frame len.
    40);

static const BroadcastCodecWrapper lc3_stereo_24_2 = BroadcastCodecWrapper(
    kLeAudioCodecIdLc3,
    // LeAudioCodecConfiguration
    {.num_channels = LeAudioCodecConfiguration::kChannelNumberStereo,
     .sample_rate = LeAudioCodecConfiguration::kSampleRate24000,
     .bits_per_sample = LeAudioCodecConfiguration::kBitsPerSample16,
     .data_interval_us = LeAudioCodecConfiguration::kInterval10000Us},
    // Bitrate
    48000,
    // Frame len.
    60);

const BroadcastCodecWrapper& BroadcastCodecWrapper::getCodecConfigForProfile(
    LeAudioBroadcaster::AudioProfile profile) {
  switch (profile) {
    case LeAudioBroadcaster::AudioProfile::SONIFICATION:
      return lc3_mono_16_2;
    case LeAudioBroadcaster::AudioProfile::MEDIA:
      return lc3_stereo_24_2;
  };
}

const std::map<uint32_t, uint8_t> sample_rate_to_sampling_freq_map = {
    {LeAudioCodecConfiguration::kSampleRate8000,
     codec_spec_conf::kLeAudioSamplingFreq8000Hz},
    {LeAudioCodecConfiguration::kSampleRate16000,
     codec_spec_conf::kLeAudioSamplingFreq16000Hz},
    {LeAudioCodecConfiguration::kSampleRate24000,
     codec_spec_conf::kLeAudioSamplingFreq24000Hz},
    {LeAudioCodecConfiguration::kSampleRate32000,
     codec_spec_conf::kLeAudioSamplingFreq32000Hz},
    {LeAudioCodecConfiguration::kSampleRate44100,
     codec_spec_conf::kLeAudioSamplingFreq44100Hz},
    {LeAudioCodecConfiguration::kSampleRate48000,
     codec_spec_conf::kLeAudioSamplingFreq48000Hz},
};

const std::map<uint32_t, uint8_t> data_interval_ms_to_frame_duration = {
    {LeAudioCodecConfiguration::kInterval7500Us,
     codec_spec_conf::kLeAudioCodecLC3FrameDur7500us},
    {LeAudioCodecConfiguration::kInterval10000Us,
     codec_spec_conf::kLeAudioCodecLC3FrameDur10000us},
};

std::vector<uint8_t> BroadcastCodecWrapper::GetCodecSpecData() const {
  LOG_ASSERT(
      sample_rate_to_sampling_freq_map.count(source_codec_config.sample_rate))
      << "Invalid sample_rate";
  LOG_ASSERT(data_interval_ms_to_frame_duration.count(
      source_codec_config.data_interval_us))
      << "Invalid data_interval";

  std::map<uint8_t, std::vector<uint8_t>> codec_spec_ltvs = {
      {codec_spec_conf::kLeAudioCodecLC3TypeSamplingFreq,
       UINT8_TO_VEC_UINT8(sample_rate_to_sampling_freq_map.at(
           source_codec_config.sample_rate))},
      {codec_spec_conf::kLeAudioCodecLC3TypeFrameDuration,
       UINT8_TO_VEC_UINT8(data_interval_ms_to_frame_duration.at(
           source_codec_config.data_interval_us))},
  };

  if (codec_id.coding_format == kLeAudioCodecIdLc3.coding_format) {
    uint16_t bc =
        lc3_frame_bytes(source_codec_config.data_interval_us, codec_bitrate);
    codec_spec_ltvs[codec_spec_conf::kLeAudioCodecLC3TypeOctetPerFrame] =
        UINT16_TO_VEC_UINT8(bc);
  }

  uint32_t audio_location;
  switch (source_codec_config.num_channels) {
    case 1:
      audio_location = codec_spec_conf::kLeAudioLocationMonoUnspecified;
      break;
    default:
      audio_location = codec_spec_conf::kLeAudioLocationFrontLeft |
                       codec_spec_conf::kLeAudioLocationFrontRight;
      break;
  }
  codec_spec_ltvs[codec_spec_conf::kLeAudioCodecLC3TypeAudioChannelAllocation] =
      UINT32_TO_VEC_UINT8(audio_location);

  types::LeAudioLtvMap ltv_map(codec_spec_ltvs);
  std::vector<uint8_t> data(ltv_map.RawPacketSize());
  ltv_map.RawPacket(data.data());
  return data;
}

} /* namespace broadcaster */
} /* namespace le_audio */

std::ostream& operator<<(
    std::ostream& os,
    const le_audio::broadcaster::BroadcastCodecWrapper& config) {
  os << " BroadcastCodecWrapper=[";
  os << "CodecID="
     << "{" << +config.GetLeAudioCodecId().coding_format << ":"
     << +config.GetLeAudioCodecId().vendor_company_id << ":"
     << +config.GetLeAudioCodecId().vendor_codec_id << "}";
  os << ", LeAudioCodecConfiguration="
     << "{NumChannels=" << +config.GetNumChannels()
     << ", SampleRate=" << +config.GetSampleRate()
     << ", BitsPerSample=" << +config.GetBitsPerSample()
     << ", DataIntervalUs=" << +config.GetDataIntervalUs() << "}";
  os << ", Bitrate=" << +config.GetBitrate();
  os << "]";
  return os;
}
