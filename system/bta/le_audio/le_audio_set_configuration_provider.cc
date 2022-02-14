/*
 *  Copyright (c) 2022 The Android Open Source Project
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
 */

#include "le_audio_set_configuration_provider.h"

#include "bta_le_audio_api.h"
#include "codec_manager.h"

using le_audio::set_configurations::AudioSetConfiguration;
using le_audio::set_configurations::AudioSetConfigurations;
using le_audio::set_configurations::CodecCapabilitySetting;
using le_audio::set_configurations::LeAudioCodecIdLc3;
using le_audio::set_configurations::SetConfiguration;
using le_audio::types::LeAudioContextType;

namespace le_audio {
using ::le_audio::CodecManager;

/**
 * Supported audio codec capability settings
 *
 * The subset of capabilities defined in BAP_Validation_r13 Table 3.6.
 */
constexpr CodecCapabilitySetting codec_lc3_16_1(uint8_t channel_count) {
  return CodecCapabilitySetting{
      .id = LeAudioCodecIdLc3,
      .config = types::LeAudioLc3Config({
          .sampling_frequency = codec_spec_conf::kLeAudioSamplingFreq16000Hz,
          .frame_duration = codec_spec_conf::kLeAudioCodecLC3FrameDur7500us,
          .octets_per_codec_frame = codec_spec_conf::kLeAudioCodecLC3FrameLen30,
          .channel_count = channel_count,
          .audio_channel_allocation = 0,
      })};
}

constexpr CodecCapabilitySetting codec_lc3_16_2(uint8_t channel_count) {
  return CodecCapabilitySetting{
      .id = LeAudioCodecIdLc3,
      .config = types::LeAudioLc3Config({
          .sampling_frequency = codec_spec_conf::kLeAudioSamplingFreq16000Hz,
          .frame_duration = codec_spec_conf::kLeAudioCodecLC3FrameDur10000us,
          .octets_per_codec_frame = codec_spec_conf::kLeAudioCodecLC3FrameLen40,
          .channel_count = channel_count,
          .audio_channel_allocation = 0,
      })};
}

constexpr CodecCapabilitySetting codec_lc3_48_4(uint8_t channel_count) {
  return CodecCapabilitySetting{
      .id = LeAudioCodecIdLc3,
      .config = types::LeAudioLc3Config({
          .sampling_frequency = codec_spec_conf::kLeAudioSamplingFreq48000Hz,
          .frame_duration = codec_spec_conf::kLeAudioCodecLC3FrameDur10000us,
          .octets_per_codec_frame =
              codec_spec_conf::kLeAudioCodecLC3FrameLen120,
          .channel_count = channel_count,
          .audio_channel_allocation = 0,
      })};
}

/*
 * AudioSetConfiguration defines the audio set configuration and codec settings
 * to to be used by le audio policy to match the required configuration with
 * audio server capabilities. The codec settings are defined with respect to
 * "Broadcast Source audio capability configuration support requirements"
 * defined in BAP d09r06
 */
const AudioSetConfiguration kSingleDev_OneChanMonoSnk_16_2 = {
    .name = "kSingleDev_OneChanMonoSnk_16_2",
    .confs = {SetConfiguration(
        types::kLeAudioDirectionSink, 1, 1,
        codec_lc3_16_2(
            codec_spec_caps::kLeAudioCodecLC3ChannelCountSingleChannel))}};

const AudioSetConfiguration kSingleDev_OneChanMonoSnk_16_1 = {
    .name = "kSingleDev_OneChanMonoSnk_16_1",
    .confs = {SetConfiguration(
        types::kLeAudioDirectionSink, 1, 1,
        codec_lc3_16_1(
            codec_spec_caps::kLeAudioCodecLC3ChannelCountSingleChannel))}};

const AudioSetConfiguration kSingleDev_TwoChanStereoSnk_16_1 = {
    .name = "kSingleDev_TwoChanStereoSnk_16_1",
    .confs = {SetConfiguration(
        types::kLeAudioDirectionSink, 1, 1,
        codec_lc3_16_1(codec_spec_caps::kLeAudioCodecLC3ChannelCountTwoChannel),
        le_audio::types::LeAudioConfigurationStrategy::
            STEREO_ONE_CIS_PER_DEVICE)}};

const AudioSetConfiguration kSingleDev_OneChanStereoSnk_16_1 = {
    .name = "kSingleDev_OneChanStereoSnk_16_1",
    .confs = {SetConfiguration(
        types::kLeAudioDirectionSink, 1, 2,
        codec_lc3_16_1(
            codec_spec_caps::kLeAudioCodecLC3ChannelCountSingleChannel),
        le_audio::types::LeAudioConfigurationStrategy::
            STEREO_TWO_CISES_PER_DEVICE)}};

const AudioSetConfiguration kDualDev_OneChanStereoSnk_16_1 = {
    .name = "kDualDev_OneChanStereoSnk_16_1",
    .confs = {SetConfiguration(
        types::kLeAudioDirectionSink, 2, 2,
        codec_lc3_16_1(
            codec_spec_caps::kLeAudioCodecLC3ChannelCountSingleChannel))}};

const AudioSetConfiguration kSingleDev_TwoChanStereoSnk_48_4 = {
    .name = "kSingleDev_TwoChanStereoSnk_48_4",
    .confs = {SetConfiguration(
        types::kLeAudioDirectionSink, 1, 1,
        codec_lc3_48_4(codec_spec_caps::kLeAudioCodecLC3ChannelCountTwoChannel),
        le_audio::types::LeAudioConfigurationStrategy::
            STEREO_ONE_CIS_PER_DEVICE)}};

const AudioSetConfiguration kDualDev_OneChanStereoSnk_48_4 = {
    .name = "kDualDev_OneChanStereoSnk_48_4",
    .confs = {SetConfiguration(
        types::kLeAudioDirectionSink, 2, 2,
        codec_lc3_48_4(
            codec_spec_caps::kLeAudioCodecLC3ChannelCountSingleChannel))}};

const AudioSetConfiguration kSingleDev_OneChanStereoSnk_48_4 = {
    .name = "kSingleDev_OneChanStereoSnk_48_4",
    .confs = {SetConfiguration(
        types::kLeAudioDirectionSink, 1, 2,
        codec_lc3_48_4(
            codec_spec_caps::kLeAudioCodecLC3ChannelCountSingleChannel),
        le_audio::types::LeAudioConfigurationStrategy::
            STEREO_TWO_CISES_PER_DEVICE)}};

const AudioSetConfiguration kSingleDev_OneChanMonoSnk_48_4 = {
    .name = "kSingleDev_OneChanMonoSnk_48_4",
    .confs = {SetConfiguration(
        types::kLeAudioDirectionSink, 1, 1,
        codec_lc3_48_4(
            codec_spec_caps::kLeAudioCodecLC3ChannelCountSingleChannel))}};

const AudioSetConfiguration kSingleDev_TwoChanStereoSnk_16_2 = {
    .name = "kSingleDev_TwoChanStereoSnk_16_2",
    .confs = {SetConfiguration(
        types::kLeAudioDirectionSink, 1, 1,
        codec_lc3_16_2(codec_spec_caps::kLeAudioCodecLC3ChannelCountTwoChannel),
        le_audio::types::LeAudioConfigurationStrategy::
            STEREO_ONE_CIS_PER_DEVICE)}};

const AudioSetConfiguration kSingleDev_OneChanStereoSnk_16_2 = {
    .name = "kSingleDev_OneChanStereoSnk_16_2",
    .confs = {SetConfiguration(
        types::kLeAudioDirectionSink, 1, 2,
        codec_lc3_16_2(
            codec_spec_caps::kLeAudioCodecLC3ChannelCountSingleChannel),
        le_audio::types::LeAudioConfigurationStrategy::
            STEREO_TWO_CISES_PER_DEVICE)}};

const AudioSetConfiguration kDualDev_OneChanStereoSnk_16_2 = {
    .name = "kDualDev_OneChanStereoSnk_16_2",
    .confs = {SetConfiguration(
        types::kLeAudioDirectionSink, 2, 2,
        codec_lc3_16_2(
            codec_spec_caps::kLeAudioCodecLC3ChannelCountSingleChannel))}};

const AudioSetConfiguration kSingleDev_OneChanMonoSnk_OneChanMonoSrc_16_1 = {
    .name = "kSingleDev_OneChanMonoSnk_OneChanMonoSrc_16_1",
    .confs = {
        SetConfiguration(
            types::kLeAudioDirectionSink, 1, 1,
            codec_lc3_16_1(
                codec_spec_caps::kLeAudioCodecLC3ChannelCountSingleChannel)),
        SetConfiguration(
            types::kLeAudioDirectionSource, 1, 1,
            codec_lc3_16_1(
                codec_spec_caps::kLeAudioCodecLC3ChannelCountSingleChannel))}};

const AudioSetConfiguration kSingleDev_OneChanMonoSnk_OneChanMonoSrc_16_2 = {
    .name = "kSingleDev_OneChanMonoSnk_OneChanMonoSrc_16_2",
    .confs = {
        SetConfiguration(
            types::kLeAudioDirectionSink, 1, 1,
            codec_lc3_16_2(
                codec_spec_caps::kLeAudioCodecLC3ChannelCountSingleChannel)),
        SetConfiguration(
            types::kLeAudioDirectionSource, 1, 1,
            codec_lc3_16_2(
                codec_spec_caps::kLeAudioCodecLC3ChannelCountSingleChannel))}};

const AudioSetConfiguration kSingleDev_TwoChanStereoSnk_OneChanMonoSrc_16_2 = {
    .name = "kSingleDev_TwoChanStereoSnk_OneChanMonoSrc_16_2",
    .confs = {
        SetConfiguration(
            types::kLeAudioDirectionSink, 1, 1,
            codec_lc3_16_2(
                codec_spec_caps::kLeAudioCodecLC3ChannelCountTwoChannel),
            le_audio::types::LeAudioConfigurationStrategy::
                STEREO_ONE_CIS_PER_DEVICE),
        SetConfiguration(
            types::kLeAudioDirectionSource, 1, 1,
            codec_lc3_16_2(
                codec_spec_caps::kLeAudioCodecLC3ChannelCountSingleChannel))}};

const AudioSetConfiguration
    kDualDev_OneChanDoubleStereoSnk_OneChanMonoSrc_16_2 = {
        .name = "kDualDev_OneChanDoubleStereoSnk_OneChanMonoSrc_16_2",
        .confs = {
            SetConfiguration(
                types::kLeAudioDirectionSink, 2, 4,
                codec_lc3_16_2(
                    codec_spec_caps::kLeAudioCodecLC3ChannelCountSingleChannel),
                le_audio::types::LeAudioConfigurationStrategy::
                    STEREO_TWO_CISES_PER_DEVICE),
            SetConfiguration(
                types::kLeAudioDirectionSource, 1, 1,
                codec_lc3_16_2(
                    codec_spec_caps::
                        kLeAudioCodecLC3ChannelCountSingleChannel))}};

const AudioSetConfiguration kSingleDev_OneChanStereoSnk_OneChanMonoSrc_16_2 = {
    .name = "kSingleDev_OneChanStereoSnk_OneChanMonoSrc_16_2",
    .confs = {
        SetConfiguration(
            types::kLeAudioDirectionSink, 1, 2,
            codec_lc3_16_2(
                codec_spec_caps::kLeAudioCodecLC3ChannelCountSingleChannel),
            le_audio::types::LeAudioConfigurationStrategy::
                STEREO_TWO_CISES_PER_DEVICE),
        SetConfiguration(
            types::kLeAudioDirectionSource, 1, 1,
            codec_lc3_16_2(
                codec_spec_caps::kLeAudioCodecLC3ChannelCountSingleChannel))}};

const AudioSetConfiguration kDualDev_OneChanStereoSnk_OneChanMonoSrc_16_2 = {
    .name = "kDualDev_OneChanStereoSnk_OneChanMonoSrc_16_2",
    .confs = {
        SetConfiguration(
            types::kLeAudioDirectionSink, 2, 2,
            codec_lc3_16_2(
                codec_spec_caps::kLeAudioCodecLC3ChannelCountSingleChannel)),
        SetConfiguration(
            types::kLeAudioDirectionSource, 1, 1,
            codec_lc3_16_2(
                codec_spec_caps::kLeAudioCodecLC3ChannelCountSingleChannel))}};

const AudioSetConfiguration kSingleDev_TwoChanStereoSnk_OneChanMonoSrc_16_1 = {
    .name = "kSingleDev_TwoChanStereoSnk_OneChanMonoSrc_16_1",
    .confs = {
        SetConfiguration(
            types::kLeAudioDirectionSink, 1, 1,
            codec_lc3_16_1(
                codec_spec_caps::kLeAudioCodecLC3ChannelCountTwoChannel),
            le_audio::types::LeAudioConfigurationStrategy::
                STEREO_ONE_CIS_PER_DEVICE),
        SetConfiguration(
            types::kLeAudioDirectionSource, 1, 1,
            codec_lc3_16_1(
                codec_spec_caps::kLeAudioCodecLC3ChannelCountSingleChannel))}};

const AudioSetConfiguration kSingleDev_OneChanStereoSnk_OneChanMonoSrc_16_1 = {
    .name = "kSingleDev_OneChanStereoSnk_OneChanMonoSrc_16_1",
    .confs = {
        SetConfiguration(
            types::kLeAudioDirectionSink, 1, 2,
            codec_lc3_16_1(
                codec_spec_caps::kLeAudioCodecLC3ChannelCountSingleChannel),
            le_audio::types::LeAudioConfigurationStrategy::
                STEREO_TWO_CISES_PER_DEVICE),
        SetConfiguration(
            types::kLeAudioDirectionSource, 1, 1,
            codec_lc3_16_1(
                codec_spec_caps::kLeAudioCodecLC3ChannelCountSingleChannel))}};

const AudioSetConfiguration kDualDev_OneChanStereoSnk_OneChanMonoSrc_16_1 = {
    .name = "kDualDev_OneChanStereoSnk_OneChanMonoSrc_16_1",
    .confs = {
        SetConfiguration(
            types::kLeAudioDirectionSink, 2, 2,
            codec_lc3_16_1(
                codec_spec_caps::kLeAudioCodecLC3ChannelCountSingleChannel)),
        SetConfiguration(
            types::kLeAudioDirectionSource, 1, 1,
            codec_lc3_16_1(
                codec_spec_caps::kLeAudioCodecLC3ChannelCountSingleChannel))}};

const AudioSetConfiguration
    kDualDev_OneChanDoubleStereoSnk_OneChanMonoSrc_16_1 = {
        .name = "kDualDev_OneChanDoubleStereoSnk_OneChanMonoSrc_16_1",
        .confs = {
            SetConfiguration(
                types::kLeAudioDirectionSink, 2, 4,
                codec_lc3_16_1(
                    codec_spec_caps::kLeAudioCodecLC3ChannelCountSingleChannel),
                le_audio::types::LeAudioConfigurationStrategy::
                    STEREO_TWO_CISES_PER_DEVICE),
            SetConfiguration(
                types::kLeAudioDirectionSource, 1, 1,
                codec_lc3_16_1(
                    codec_spec_caps::
                        kLeAudioCodecLC3ChannelCountSingleChannel))}};

/* Defined audio scenario linked with context type, priority sorted */
const AudioSetConfigurations audio_set_conf_ringtone = {
    &kDualDev_OneChanStereoSnk_16_2,   &kDualDev_OneChanStereoSnk_16_1,
    &kSingleDev_OneChanStereoSnk_16_2, &kSingleDev_OneChanStereoSnk_16_1,
    &kSingleDev_TwoChanStereoSnk_16_2, &kSingleDev_TwoChanStereoSnk_16_1,
    &kSingleDev_OneChanMonoSnk_16_2,   &kSingleDev_OneChanMonoSnk_16_1,
};

const AudioSetConfigurations audio_set_conf_conversational = {
    &kDualDev_OneChanStereoSnk_OneChanMonoSrc_16_2,
    &kDualDev_OneChanStereoSnk_OneChanMonoSrc_16_1,
    &kDualDev_OneChanDoubleStereoSnk_OneChanMonoSrc_16_2,
    &kDualDev_OneChanDoubleStereoSnk_OneChanMonoSrc_16_1,
    &kSingleDev_TwoChanStereoSnk_OneChanMonoSrc_16_2,
    &kSingleDev_TwoChanStereoSnk_OneChanMonoSrc_16_1,
    &kSingleDev_OneChanStereoSnk_OneChanMonoSrc_16_2,
    &kSingleDev_OneChanStereoSnk_OneChanMonoSrc_16_1,
    &kSingleDev_OneChanMonoSnk_OneChanMonoSrc_16_2,
    &kSingleDev_OneChanMonoSnk_OneChanMonoSrc_16_1,
};

const AudioSetConfigurations audio_set_conf_media = {
    &kDualDev_OneChanStereoSnk_48_4,   &kDualDev_OneChanStereoSnk_16_2,
    &kDualDev_OneChanStereoSnk_16_1,   &kSingleDev_OneChanStereoSnk_48_4,
    &kSingleDev_OneChanStereoSnk_16_2, &kSingleDev_OneChanStereoSnk_16_1,
    &kSingleDev_TwoChanStereoSnk_48_4, &kSingleDev_TwoChanStereoSnk_16_2,
    &kSingleDev_TwoChanStereoSnk_16_1, &kSingleDev_OneChanMonoSnk_48_4,
    &kSingleDev_OneChanMonoSnk_16_2,   &kSingleDev_OneChanMonoSnk_16_1,
};

const AudioSetConfigurations audio_set_conf_default = {
    &kDualDev_OneChanStereoSnk_16_2,
    &kSingleDev_OneChanStereoSnk_16_2,
    &kSingleDev_TwoChanStereoSnk_16_2,
    &kSingleDev_OneChanMonoSnk_16_2,
};

/** Provides a set configurations for the given context type. */
struct AudioSetConfigurationProviderStatic {
  const AudioSetConfigurations* GetConfigurationsByContextType(
      LeAudioContextType context_type) const {
    if (CodecManager::GetInstance()->GetCodecLocation() ==
        types::CodecLocation::ADSP) {
      DLOG(INFO) << __func__ << "Get offload config for the context type: "
                 << (int)context_type;
      const AudioSetConfigurations* offload_confs =
          CodecManager::GetInstance()->GetOffloadCodecConfig(context_type);

      if (offload_confs != nullptr && !(*offload_confs).empty()) {
        return offload_confs;
      }

      // TODO: Need to have a mechanism to switch to software session if offload
      // doesn't support.
    }

    DLOG(INFO) << __func__ << "Get software config for the context type: "
               << (int)context_type;

    switch (context_type) {
      case LeAudioContextType::MEDIA:
        return &audio_set_conf_media;
      case LeAudioContextType::CONVERSATIONAL:
        return &audio_set_conf_conversational;
      case LeAudioContextType::RINGTONE:
        return &audio_set_conf_ringtone;
      default:
        return &audio_set_conf_default;
    }
  };
};

struct AudioSetConfigurationProvider::impl {
  impl(const AudioSetConfigurationProvider& config_provider)
      : config_provider_(config_provider) {}

  void Initialize() {
    LOG_ASSERT(!config_provider_impl_);
    config_provider_impl_ =
        std::make_unique<AudioSetConfigurationProviderStatic>();
  }

  void Cleanup() {
    LOG_ASSERT(config_provider_impl_);
    config_provider_impl_.reset();
  }

  bool IsRunning() { return config_provider_impl_ ? true : false; }

  const AudioSetConfigurationProvider& config_provider_;
  std::unique_ptr<AudioSetConfigurationProviderStatic> config_provider_impl_;
};

static std::unique_ptr<AudioSetConfigurationProvider> config_provider;

AudioSetConfigurationProvider::AudioSetConfigurationProvider()
    : pimpl_(std::make_unique<AudioSetConfigurationProvider::impl>(*this)) {}

void AudioSetConfigurationProvider::Initialize() {
  if (!config_provider) {
    config_provider = std::make_unique<AudioSetConfigurationProvider>();
  }

  if (!config_provider->pimpl_->IsRunning()) {
    config_provider->pimpl_->Initialize();
  }
}

void AudioSetConfigurationProvider::Cleanup() {
  if (!config_provider) return;
  if (config_provider->pimpl_->IsRunning()) config_provider->pimpl_->Cleanup();
  config_provider.reset();
}

AudioSetConfigurationProvider* AudioSetConfigurationProvider::Get() {
  return config_provider.get();
}

const set_configurations::AudioSetConfigurations*
AudioSetConfigurationProvider::GetConfigurations(
    ::le_audio::types::LeAudioContextType content_type) const {
  if (pimpl_->IsRunning()) {
    return pimpl_->config_provider_impl_->GetConfigurationsByContextType(
        content_type);
  }
  return nullptr;
}

}  // namespace le_audio

void LeAudioClient::InitializeAudioSetConfigurationProvider(void) {
  le_audio::AudioSetConfigurationProvider::Initialize();
}

void LeAudioClient::CleanupAudioSetConfigurationProvider(void) {
  le_audio::AudioSetConfigurationProvider::Cleanup();
}
