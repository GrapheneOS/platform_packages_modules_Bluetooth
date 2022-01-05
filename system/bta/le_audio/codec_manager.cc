/*
 * Copyright 2022 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "codec_manager.h"

#include "client_audio.h"
#include "device/include/controller.h"
#include "osi/include/log.h"
#include "osi/include/properties.h"
#include "stack/acl/acl.h"
#include "stack/include/acl_api.h"

namespace {

using bluetooth::hci::iso_manager::kIsoDataPathHci;
using bluetooth::hci::iso_manager::kIsoDataPathPlatformDefault;
using le_audio::CodecManager;
using le_audio::types::CodecLocation;
}  // namespace

namespace le_audio {

struct codec_manager_impl {
 public:
  codec_manager_impl() {
    offload_enable_ = osi_property_get_bool(
                          "ro.bluetooth.leaudio_offload.supported", false) &&
                      osi_property_get_bool(
                          "persist.bluetooth.leaudio_offload.enabled", true);
    if (offload_enable_ == false) {
      LOG_INFO("offload disabled");
      return;
    }

    if (!LeAudioHalVerifier::SupportsLeAudioHardwareOffload()) {
      LOG_WARN("HAL not support hardware offload");
      return;
    }

    if (!controller_get_interface()->supports_configure_data_path()) {
      LOG_WARN("Controller does not support config data path command");
      return;
    }

    LOG_INFO("LeAudioCodecManagerImpl: configure_data_path for encode");
    btm_configure_data_path(btm_data_direction::HOST_TO_CONTROLLER,
                            kIsoDataPathPlatformDefault, {});
    SetCodecLocation(CodecLocation::ADSP);
  }
  ~codec_manager_impl() {
    if (GetCodecLocation() != CodecLocation::HOST) {
      btm_configure_data_path(btm_data_direction::HOST_TO_CONTROLLER,
                              kIsoDataPathHci, {});
    }
  }
  CodecLocation GetCodecLocation(void) const { return codec_location_; }

  void UpdateActiveAudioConfig(
      const le_audio::stream_configuration& stream_conf, uint16_t delay) {
    if (!stream_conf.sink_streams.empty()) {
      sink_config.stream_map = std::move(stream_conf.sink_streams);
      // TODO: set the default value 16 for now, would change it if we support
      // mode bits_per_sample
      sink_config.bits_per_sample = 16;
      sink_config.sampling_rate = stream_conf.sink_sample_frequency_hz;
      sink_config.frame_duration = stream_conf.sink_frame_duration_us;
      sink_config.octets_per_frame = stream_conf.sink_octets_per_codec_frame;
      // TODO: set the default value 1 for now, would change it if we need more
      // configuration
      sink_config.blocks_per_sdu = 1;
      sink_config.peer_delay = delay;
      LeAudioClientAudioSource::UpdateAudioConfigToHal(sink_config);
    }
  }

 private:
  void SetCodecLocation(CodecLocation location) {
    if (offload_enable_ == false) return;
    codec_location_ = location;
  }
  CodecLocation codec_location_ = CodecLocation::HOST;
  bool offload_enable_ = false;
  le_audio::offload_config sink_config;
};

struct CodecManager::impl {
  impl(const CodecManager& codec_manager) : codec_manager_(codec_manager) {}

  void Start() {
    LOG_ASSERT(!codec_manager_impl_);
    codec_manager_impl_ = std::make_unique<codec_manager_impl>();
  }

  void Stop() {
    LOG_ASSERT(codec_manager_impl_);
    codec_manager_impl_.reset();
  }

  bool IsRunning() { return codec_manager_impl_ ? true : false; }

  const CodecManager& codec_manager_;
  std::unique_ptr<codec_manager_impl> codec_manager_impl_;
};

CodecManager::CodecManager() : pimpl_(std::make_unique<impl>(*this)) {}

void CodecManager::Start() {
  if (!pimpl_->IsRunning()) pimpl_->Start();
}

void CodecManager::Stop() {
  if (pimpl_->IsRunning()) pimpl_->Stop();
}

types::CodecLocation CodecManager::GetCodecLocation(void) const {
  if (!pimpl_->IsRunning()) {
    return CodecLocation::HOST;
  }

  return pimpl_->codec_manager_impl_->GetCodecLocation();
}

void CodecManager::UpdateActiveAudioConfig(
    const stream_configuration& stream_conf, uint16_t delay) {
  if (pimpl_->IsRunning())
    pimpl_->codec_manager_impl_->UpdateActiveAudioConfig(stream_conf, delay);
}

}  // namespace le_audio
