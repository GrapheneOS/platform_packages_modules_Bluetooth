/*
 * Copyright 2021 HIMSA II K/S - www.himsa.com. Represented by EHIMA -
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

#define LOG_TAG "BTAudioClientLEA_HIDL"

#include "le_audio_software_hidl.h"

#include <unordered_map>
#include <vector>

#include "codec_status_hidl.h"
#include "hal_version_manager.h"

namespace bluetooth {
namespace audio {
namespace hidl {
namespace le_audio {

using ::android::hardware::bluetooth::audio::V2_0::BitsPerSample;
using ::android::hardware::bluetooth::audio::V2_0::ChannelMode;
using ::android::hardware::bluetooth::audio::V2_1::CodecType;
using ::android::hardware::bluetooth::audio::V2_1::Lc3FrameDuration;
using ::android::hardware::bluetooth::audio::V2_1::Lc3Parameters;
using ::android::hardware::bluetooth::audio::V2_2::AudioLocation;
using ::bluetooth::audio::hidl::SampleRate_2_1;
using ::bluetooth::audio::hidl::SessionType;
using ::bluetooth::audio::hidl::SessionType_2_1;
using AudioCapabilities_2_2 =
    ::android::hardware::bluetooth::audio::V2_2::AudioCapabilities;
using ::android::hardware::bluetooth::audio::V2_2::LeAudioMode;
using ::android::hardware::bluetooth::audio::V2_2::UnicastConfig;
using ::android::hardware::bluetooth::audio::V2_2::UnicastStreamMap;
using ::le_audio::set_configurations::SetConfiguration;
using ::le_audio::types::LeAudioLc3Config;

using ::bluetooth::audio::le_audio::LeAudioClientInterface;

/**
 * Helper utils
 **/

static SampleRate_2_1 le_audio_sample_rate2audio_hal(uint32_t sample_rate_2_1) {
  switch (sample_rate_2_1) {
    case 8000:
      return SampleRate_2_1::RATE_8000;
    case 16000:
      return SampleRate_2_1::RATE_16000;
    case 24000:
      return SampleRate_2_1::RATE_24000;
    case 32000:
      return SampleRate_2_1::RATE_32000;
    case 44100:
      return SampleRate_2_1::RATE_44100;
    case 48000:
      return SampleRate_2_1::RATE_48000;
    case 88200:
      return SampleRate_2_1::RATE_88200;
    case 96000:
      return SampleRate_2_1::RATE_96000;
    case 176400:
      return SampleRate_2_1::RATE_176400;
    case 192000:
      return SampleRate_2_1::RATE_192000;
  };
  return SampleRate_2_1::RATE_UNKNOWN;
}

static BitsPerSample le_audio_bits_per_sample2audio_hal(
    uint8_t bits_per_sample) {
  switch (bits_per_sample) {
    case 16:
      return BitsPerSample::BITS_16;
    case 24:
      return BitsPerSample::BITS_24;
    case 32:
      return BitsPerSample::BITS_32;
  };
  return BitsPerSample::BITS_UNKNOWN;
}

static ChannelMode le_audio_channel_mode2audio_hal(uint8_t channels_count) {
  switch (channels_count) {
    case 1:
      return ChannelMode::MONO;
    case 2:
      return ChannelMode::STEREO;
  }
  return ChannelMode::UNKNOWN;
}

static Lc3FrameDuration le_audio_frame_duration2audio_hal(
    uint8_t frame_duration) {
  switch (frame_duration) {
    case 10000:
      return Lc3FrameDuration::DURATION_10000US;
    case 7500:
      return Lc3FrameDuration::DURATION_7500US;
  }
  // TODO: handle error in the aidl version
  return Lc3FrameDuration::DURATION_10000US;
}

AudioConfiguration_2_2 offload_config_to_hal_audio_config(
    const ::le_audio::offload_config& offload_config) {
  AudioConfiguration_2_2 audio_config;
  std::vector<UnicastStreamMap> unicast_map;
  for (auto& [handle, location] : offload_config.stream_map) {
    UnicastStreamMap stream = {.streamHandle = handle,
                               .audioChannelAllocation = location};
    unicast_map.emplace_back(stream);
  }
  hidl_vec<UnicastStreamMap> hal_map;
  hal_map.setToExternal(unicast_map.data(), unicast_map.size());
  LeAudioConfiguration le_audio_config;
  le_audio_config.mode = LeAudioMode::UNICAST;
  le_audio_config.config.unicastConfig() = {
      .streamMap = std::move(hal_map),
      .peerDelay = offload_config.peer_delay,
      .lc3Config = {.pcmBitDepth = le_audio_bits_per_sample2audio_hal(
                        offload_config.bits_per_sample),
                    .samplingFrequency = le_audio_sample_rate2audio_hal(
                        offload_config.sampling_rate),
                    .frameDuration = le_audio_frame_duration2audio_hal(
                        offload_config.frame_duration),
                    .octetsPerFrame = offload_config.octets_per_frame,
                    .blocksPerSdu = offload_config.blocks_per_sdu}};
  audio_config.leAudioConfig(le_audio_config);
  return audio_config;
}

bool is_source_hal_enabled() {
  return LeAudioSourceTransport::interface != nullptr;
}

bool is_sink_hal_enabled() {
  return LeAudioSinkTransport::interface != nullptr;
}

LeAudioTransport::LeAudioTransport(void (*flush)(void),
                                   StreamCallbacks stream_cb,
                                   PcmParameters pcm_config)
    : flush_(std::move(flush)),
      stream_cb_(std::move(stream_cb)),
      remote_delay_report_ms_(0),
      total_bytes_processed_(0),
      data_position_({}),
      pcm_config_(std::move(pcm_config)),
      is_pending_start_request_(false){};

BluetoothAudioCtrlAck LeAudioTransport::StartRequest() {
  LOG(INFO) << __func__;

  if (stream_cb_.on_resume_(true)) {
    is_pending_start_request_ = true;
    return BluetoothAudioCtrlAck::PENDING;
  }

  return BluetoothAudioCtrlAck::FAILURE;
}

BluetoothAudioCtrlAck LeAudioTransport::SuspendRequest() {
  LOG(INFO) << __func__;
  if (stream_cb_.on_suspend_()) {
    flush_();
    return BluetoothAudioCtrlAck::SUCCESS_FINISHED;
  } else {
    return BluetoothAudioCtrlAck::FAILURE;
  }
}

void LeAudioTransport::StopRequest() {
  LOG(INFO) << __func__;
  if (stream_cb_.on_suspend_()) {
    flush_();
  }
}

bool LeAudioTransport::GetPresentationPosition(uint64_t* remote_delay_report_ns,
                                               uint64_t* total_bytes_processed,
                                               timespec* data_position) {
  VLOG(2) << __func__ << ": data=" << total_bytes_processed_
          << " byte(s), timestamp=" << data_position_.tv_sec << "."
          << data_position_.tv_nsec
          << "s, delay report=" << remote_delay_report_ms_ << " msec.";
  if (remote_delay_report_ns != nullptr) {
    *remote_delay_report_ns = remote_delay_report_ms_ * 1000000u;
  }
  if (total_bytes_processed != nullptr)
    *total_bytes_processed = total_bytes_processed_;
  if (data_position != nullptr) *data_position = data_position_;

  return true;
}

void LeAudioTransport::MetadataChanged(
    const source_metadata_t& source_metadata) {
  auto track_count = source_metadata.track_count;

  if (track_count == 0) {
    LOG(WARNING) << ", invalid number of metadata changed tracks";
    return;
  }

  stream_cb_.on_metadata_update_(source_metadata);
}

void LeAudioTransport::SinkMetadataChanged(
    const sink_metadata_t& sink_metadata) {
  auto track_count = sink_metadata.track_count;

  if (track_count == 0) {
    LOG(WARNING) << ", invalid number of metadata changed tracks";
    return;
  }

  if (stream_cb_.on_sink_metadata_update_)
    stream_cb_.on_sink_metadata_update_(sink_metadata);
}

void LeAudioTransport::ResetPresentationPosition() {
  VLOG(2) << __func__ << ": called.";
  remote_delay_report_ms_ = 0;
  total_bytes_processed_ = 0;
  data_position_ = {};
}

void LeAudioTransport::LogBytesProcessed(size_t bytes_processed) {
  if (bytes_processed) {
    total_bytes_processed_ += bytes_processed;
    clock_gettime(CLOCK_MONOTONIC, &data_position_);
  }
}

void LeAudioTransport::SetRemoteDelay(uint16_t delay_report_ms) {
  LOG(INFO) << __func__ << ": delay_report=" << delay_report_ms << " msec";
  remote_delay_report_ms_ = delay_report_ms;
}

const PcmParameters& LeAudioTransport::LeAudioGetSelectedHalPcmConfig() {
  return pcm_config_;
}

void LeAudioTransport::LeAudioSetSelectedHalPcmConfig(uint32_t sample_rate_hz,
                                                      uint8_t bit_rate,
                                                      uint8_t channels_count,
                                                      uint32_t data_interval) {
  pcm_config_.sampleRate = le_audio_sample_rate2audio_hal(sample_rate_hz);
  pcm_config_.bitsPerSample = le_audio_bits_per_sample2audio_hal(bit_rate);
  pcm_config_.channelMode = le_audio_channel_mode2audio_hal(channels_count);
  pcm_config_.dataIntervalUs = data_interval;
}

bool LeAudioTransport::IsPendingStartStream(void) {
  return is_pending_start_request_;
}
void LeAudioTransport::ClearPendingStartStream(void) {
  is_pending_start_request_ = false;
}

void flush_sink() {
  if (!is_sink_hal_enabled()) return;

  LeAudioSinkTransport::interface->FlushAudioData();
}

LeAudioSinkTransport::LeAudioSinkTransport(SessionType_2_1 session_type,
                                           StreamCallbacks stream_cb)
    : IBluetoothSinkTransportInstance(session_type,
                                      (AudioConfiguration_2_2){}) {
  transport_ =
      new LeAudioTransport(flush_sink, std::move(stream_cb),
                           {SampleRate_2_1::RATE_16000, ChannelMode::STEREO,
                            BitsPerSample::BITS_16, 0});
};

LeAudioSinkTransport::~LeAudioSinkTransport() { delete transport_; }

BluetoothAudioCtrlAck LeAudioSinkTransport::StartRequest() {
  return transport_->StartRequest();
}

BluetoothAudioCtrlAck LeAudioSinkTransport::SuspendRequest() {
  return transport_->SuspendRequest();
}

void LeAudioSinkTransport::StopRequest() { transport_->StopRequest(); }

bool LeAudioSinkTransport::GetPresentationPosition(
    uint64_t* remote_delay_report_ns, uint64_t* total_bytes_read,
    timespec* data_position) {
  return transport_->GetPresentationPosition(remote_delay_report_ns,
                                             total_bytes_read, data_position);
}

void LeAudioSinkTransport::MetadataChanged(
    const source_metadata_t& source_metadata) {
  transport_->MetadataChanged(source_metadata);
}

void LeAudioSinkTransport::SinkMetadataChanged(
    const sink_metadata_t& sink_metadata) {
  transport_->SinkMetadataChanged(sink_metadata);
}

void LeAudioSinkTransport::ResetPresentationPosition() {
  transport_->ResetPresentationPosition();
}

void LeAudioSinkTransport::LogBytesRead(size_t bytes_read) {
  transport_->LogBytesProcessed(bytes_read);
}

void LeAudioSinkTransport::SetRemoteDelay(uint16_t delay_report_ms) {
  transport_->SetRemoteDelay(delay_report_ms);
}

const PcmParameters& LeAudioSinkTransport::LeAudioGetSelectedHalPcmConfig() {
  return transport_->LeAudioGetSelectedHalPcmConfig();
}

void LeAudioSinkTransport::LeAudioSetSelectedHalPcmConfig(
    uint32_t sample_rate_hz, uint8_t bit_rate, uint8_t channels_count,
    uint32_t data_interval) {
  transport_->LeAudioSetSelectedHalPcmConfig(sample_rate_hz, bit_rate,
                                             channels_count, data_interval);
}

bool LeAudioSinkTransport::IsPendingStartStream(void) {
  return transport_->IsPendingStartStream();
}
void LeAudioSinkTransport::ClearPendingStartStream(void) {
  transport_->ClearPendingStartStream();
}

void flush_source() {
  if (LeAudioSourceTransport::interface == nullptr) return;

  LeAudioSourceTransport::interface->FlushAudioData();
}

LeAudioSourceTransport::LeAudioSourceTransport(SessionType_2_1 session_type,
                                               StreamCallbacks stream_cb)
    : IBluetoothSourceTransportInstance(session_type,
                                        (AudioConfiguration_2_2){}) {
  transport_ =
      new LeAudioTransport(flush_source, std::move(stream_cb),
                           {SampleRate_2_1::RATE_16000, ChannelMode::MONO,
                            BitsPerSample::BITS_16, 0});
};

LeAudioSourceTransport::~LeAudioSourceTransport() { delete transport_; }

BluetoothAudioCtrlAck LeAudioSourceTransport::StartRequest() {
  return transport_->StartRequest();
}

BluetoothAudioCtrlAck LeAudioSourceTransport::SuspendRequest() {
  return transport_->SuspendRequest();
}

void LeAudioSourceTransport::StopRequest() { transport_->StopRequest(); }

bool LeAudioSourceTransport::GetPresentationPosition(
    uint64_t* remote_delay_report_ns, uint64_t* total_bytes_written,
    timespec* data_position) {
  return transport_->GetPresentationPosition(
      remote_delay_report_ns, total_bytes_written, data_position);
}

void LeAudioSourceTransport::MetadataChanged(
    const source_metadata_t& source_metadata) {
  transport_->MetadataChanged(source_metadata);
}

void LeAudioSourceTransport::SinkMetadataChanged(
    const sink_metadata_t& sink_metadata) {
  transport_->SinkMetadataChanged(sink_metadata);
}

void LeAudioSourceTransport::ResetPresentationPosition() {
  transport_->ResetPresentationPosition();
}

void LeAudioSourceTransport::LogBytesWritten(size_t bytes_written) {
  transport_->LogBytesProcessed(bytes_written);
}

void LeAudioSourceTransport::SetRemoteDelay(uint16_t delay_report_ms) {
  transport_->SetRemoteDelay(delay_report_ms);
}

const PcmParameters& LeAudioSourceTransport::LeAudioGetSelectedHalPcmConfig() {
  return transport_->LeAudioGetSelectedHalPcmConfig();
}

void LeAudioSourceTransport::LeAudioSetSelectedHalPcmConfig(
    uint32_t sample_rate_hz, uint8_t bit_rate, uint8_t channels_count,
    uint32_t data_interval) {
  transport_->LeAudioSetSelectedHalPcmConfig(sample_rate_hz, bit_rate,
                                             channels_count, data_interval);
}

bool LeAudioSourceTransport::IsPendingStartStream(void) {
  return transport_->IsPendingStartStream();
}
void LeAudioSourceTransport::ClearPendingStartStream(void) {
  transport_->ClearPendingStartStream();
}

std::unordered_map<SampleRate_2_1, uint8_t> sampling_freq_map{
    {SampleRate_2_1::RATE_8000,
     ::le_audio::codec_spec_conf::kLeAudioSamplingFreq8000Hz},
    {SampleRate_2_1::RATE_16000,
     ::le_audio::codec_spec_conf::kLeAudioSamplingFreq16000Hz},
    {SampleRate_2_1::RATE_24000,
     ::le_audio::codec_spec_conf::kLeAudioSamplingFreq24000Hz},
    {SampleRate_2_1::RATE_32000,
     ::le_audio::codec_spec_conf::kLeAudioSamplingFreq32000Hz},
    {SampleRate_2_1::RATE_44100,
     ::le_audio::codec_spec_conf::kLeAudioSamplingFreq44100Hz},
    {SampleRate_2_1::RATE_48000,
     ::le_audio::codec_spec_conf::kLeAudioSamplingFreq48000Hz},
    {SampleRate_2_1::RATE_88200,
     ::le_audio::codec_spec_conf::kLeAudioSamplingFreq88200Hz},
    {SampleRate_2_1::RATE_96000,
     ::le_audio::codec_spec_conf::kLeAudioSamplingFreq96000Hz},
    {SampleRate_2_1::RATE_176400,
     ::le_audio::codec_spec_conf::kLeAudioSamplingFreq176400Hz},
    {SampleRate_2_1::RATE_192000,
     ::le_audio::codec_spec_conf::kLeAudioSamplingFreq192000Hz}};

std::unordered_map<Lc3FrameDuration, uint8_t> frame_duration_map{
    {Lc3FrameDuration::DURATION_7500US,
     ::le_audio::codec_spec_conf::kLeAudioCodecLC3FrameDur7500us},
    {Lc3FrameDuration::DURATION_10000US,
     ::le_audio::codec_spec_conf::kLeAudioCodecLC3FrameDur10000us}};

std::unordered_map<uint32_t, uint16_t> octets_per_frame_map{
    {30, ::le_audio::codec_spec_conf::kLeAudioCodecLC3FrameLen30},
    {40, ::le_audio::codec_spec_conf::kLeAudioCodecLC3FrameLen40},
    {120, ::le_audio::codec_spec_conf::kLeAudioCodecLC3FrameLen120}};

std::unordered_map<AudioLocation, uint32_t> audio_location_map{
    {AudioLocation::UNKNOWN,
     ::le_audio::codec_spec_conf::kLeAudioLocationMonoUnspecified},
    {AudioLocation::FRONT_LEFT,
     ::le_audio::codec_spec_conf::kLeAudioLocationFrontLeft},
    {AudioLocation::FRONT_RIGHT,
     ::le_audio::codec_spec_conf::kLeAudioLocationFrontRight},
    {static_cast<AudioLocation>(AudioLocation::FRONT_LEFT |
                                AudioLocation::FRONT_RIGHT),
     ::le_audio::codec_spec_conf::kLeAudioLocationFrontLeft |
         ::le_audio::codec_spec_conf::kLeAudioLocationFrontRight}};

bool halConfigToCodecCapabilitySetting(
    UnicastCapability halConfig, CodecCapabilitySetting& codecCapability) {
  if (halConfig.codecType != CodecType::LC3) {
    LOG(WARNING) << "Unsupported codecType: " << toString(halConfig.codecType);
    return false;
  }

  Lc3Parameters halLc3Config = halConfig.capabilities;
  AudioLocation supportedChannel = halConfig.supportedChannel;

  if (sampling_freq_map.find(halLc3Config.samplingFrequency) ==
          sampling_freq_map.end() ||
      frame_duration_map.find(halLc3Config.frameDuration) ==
          frame_duration_map.end() ||
      octets_per_frame_map.find(halLc3Config.octetsPerFrame) ==
          octets_per_frame_map.end() ||
      audio_location_map.find(supportedChannel) == audio_location_map.end()) {
    LOG(ERROR) << __func__ << ": Failed to convert HAL format to stack format"
               << "\nsample rate = " << (uint8_t)halLc3Config.samplingFrequency
               << "\nframe duration = " << (uint8_t)halLc3Config.frameDuration
               << "\noctets per frame= " << halLc3Config.octetsPerFrame
               << "\naudio location = " << (uint8_t)supportedChannel;

    return false;
  }

  codecCapability = {
      .id = ::le_audio::set_configurations::LeAudioCodecIdLc3,
      .config = LeAudioLc3Config(
          {.sampling_frequency =
               sampling_freq_map[halLc3Config.samplingFrequency],
           .frame_duration = frame_duration_map[halLc3Config.frameDuration],
           .octets_per_codec_frame =
               octets_per_frame_map[halLc3Config.octetsPerFrame],
           .audio_channel_allocation = audio_location_map[supportedChannel]})};

  return true;
}

std::vector<AudioSetConfiguration> get_offload_capabilities() {
  LOG(INFO) << __func__;
  std::vector<AudioSetConfiguration> offload_capabilities;
  std::vector<AudioCapabilities_2_2> le_audio_hal_capabilities =
      BluetoothAudioSinkClientInterface::GetAudioCapabilities_2_2(
          SessionType_2_1::LE_AUDIO_HARDWARE_OFFLOAD_ENCODING_DATAPATH);
  std::string strCapabilityLog;

  for (auto halCapability : le_audio_hal_capabilities) {
    CodecCapabilitySetting encodeCapability;
    CodecCapabilitySetting decodeCapability;
    UnicastCapability halEncodeConfig =
        halCapability.leAudioCapabilities().unicastEncodeCapability;
    UnicastCapability halDecodeConfig =
        halCapability.leAudioCapabilities().unicastDecodeCapability;
    AudioSetConfiguration audioSetConfig = {.name = "offload capability"};
    strCapabilityLog.clear();

    if (halConfigToCodecCapabilitySetting(halEncodeConfig, encodeCapability)) {
      audioSetConfig.confs.push_back(SetConfiguration(
          ::le_audio::types::kLeAudioDirectionSink, halEncodeConfig.deviceCount,
          halEncodeConfig.deviceCount * halEncodeConfig.channelCountPerDevice,
          encodeCapability));
      strCapabilityLog = " Encode Capability: " + toString(halEncodeConfig);
    }

    if (halConfigToCodecCapabilitySetting(halDecodeConfig, decodeCapability)) {
      audioSetConfig.confs.push_back(SetConfiguration(
          ::le_audio::types::kLeAudioDirectionSource,
          halDecodeConfig.deviceCount,
          halDecodeConfig.deviceCount * halDecodeConfig.channelCountPerDevice,
          decodeCapability));
      strCapabilityLog += " Decode Capability: " + toString(halDecodeConfig);
    }

    if (!audioSetConfig.confs.empty()) {
      offload_capabilities.push_back(audioSetConfig);
      LOG(INFO) << __func__
                << ": Supported codec capability =" << strCapabilityLog;

    } else {
      LOG(INFO) << __func__
                << ": Unknown codec capability =" << toString(halCapability);
    }
  }

  return offload_capabilities;
}

}  // namespace le_audio
}  // namespace hidl
}  // namespace audio
}  // namespace bluetooth
