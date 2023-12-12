/*
 * Copyright 2023 The Android Open Source Project
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

#include <cstdint>

#define LOG_TAG "BTAudioClientHfpStub"

#include "aidl/client_interface_aidl.h"
#include "aidl/hfp_client_interface_aidl.h"
#include "hal_version_manager.h"
#include "hfp_client_interface.h"
#include "osi/include/log.h"
#include "osi/include/properties.h"

using ::bluetooth::audio::aidl::hfp::HfpDecodingTransport;
using AudioConfiguration =
    ::aidl::android::hardware::bluetooth::audio::AudioConfiguration;
using ::aidl::android::hardware::bluetooth::audio::ChannelMode;
using ::aidl::android::hardware::bluetooth::audio::CodecId;
using ::aidl::android::hardware::bluetooth::audio::HfpConfiguration;
using ::aidl::android::hardware::bluetooth::audio::PcmConfiguration;

namespace bluetooth {
namespace audio {
namespace hfp {

// Helper functions
aidl::BluetoothAudioSinkClientInterface* get_decode_client_interface() {
  return HfpDecodingTransport::active_hal_interface;
}

HfpDecodingTransport* get_decode_transport_instance() {
  return HfpDecodingTransport::instance_;
}

PcmConfiguration get_default_pcm_configuration() {
  PcmConfiguration pcm_config{
      .sampleRateHz = 8000,
      .channelMode = ChannelMode::MONO,
      .bitsPerSample = 16,
  };
  return pcm_config;
}

HfpConfiguration get_default_hfp_configuration() {
  HfpConfiguration hfp_config{
      .codecId = CodecId::Core::CVSD,
      .connectionHandle = 6,
      .nrec = false,
      .controllerCodec = true,
  };
  return hfp_config;
}

CodecId get_codec_id_by_peer_codec(tBTA_AG_PEER_CODEC sco_codec) {
  if (sco_codec & BTM_SCO_CODEC_LC3) return CodecId::Core::LC3;
  if (sco_codec & BTM_SCO_CODEC_MSBC) return CodecId::Core::MSBC;
  if (sco_codec & BTM_SCO_CODEC_CVSD) return CodecId::Core::CVSD;
  // Unknown vendor codec otherwise
  CodecId codec_id = CodecId::Vendor();
  return codec_id;
}

AudioConfiguration offload_config_to_hal_audio_config(
    const ::hfp::offload_config& offload_config) {
  HfpConfiguration hfp_config{
      .codecId = get_codec_id_by_peer_codec(offload_config.sco_codec),
      .connectionHandle = offload_config.connection_handle,
      .nrec = offload_config.is_nrec,
      .controllerCodec = offload_config.is_controller_codec,
  };
  return AudioConfiguration(hfp_config);
}

bool is_hal_enabled() {
  return !osi_property_get_bool(BLUETOOTH_AUDIO_HAL_PROP_DISABLED, false);
}

bool is_aidl_support_hfp() {
  return HalVersionManager::GetHalTransport() ==
             BluetoothAudioHalTransport::AIDL &&
         HalVersionManager::GetHalVersion() >=
             BluetoothAudioHalVersion::VERSION_AIDL_V4;
}

// Decode client implementation
void HfpClientInterface::Decode::Cleanup() {
  LOG(INFO) << __func__ << " decode";
  StopSession();
  if (HfpDecodingTransport::instance_) {
    delete HfpDecodingTransport::software_hal_interface;
    HfpDecodingTransport::software_hal_interface = nullptr;
    delete HfpDecodingTransport::instance_;
    HfpDecodingTransport::instance_ = nullptr;
  }
}

void HfpClientInterface::Decode::StartSession() {
  if (!is_aidl_support_hfp()) {
    LOG(WARNING) << __func__ << ": Unsupported HIDL or AIDL version";
    return;
  }
  LOG(INFO) << __func__ << " decode";
  AudioConfiguration audio_config;
  audio_config.set<AudioConfiguration::pcmConfig>(
      get_default_pcm_configuration());
  if (!get_decode_client_interface()->UpdateAudioConfig(audio_config)) {
    LOG(ERROR) << __func__ << ": cannot update audio config to HAL";
    return;
  }
  get_decode_client_interface()->StartSession();
}

void HfpClientInterface::Decode::StopSession() {
  if (!is_aidl_support_hfp()) {
    LOG(WARNING) << __func__ << ": Unsupported HIDL or AIDL version";
    return;
  }
  LOG(INFO) << __func__ << " decode";
  get_decode_client_interface()->EndSession();
  if (get_decode_transport_instance()) {
    get_decode_transport_instance()->ResetPendingCmd();
    get_decode_transport_instance()->ResetPresentationPosition();
  }
}

void HfpClientInterface::Decode::UpdateAudioConfigToHal(
    const ::hfp::offload_config& offload_config) {
  if (!is_aidl_support_hfp()) {
    LOG(WARNING) << __func__ << ": Unsupported HIDL or AIDL version";
    return;
  }

  LOG(INFO) << __func__ << " decode";
  get_decode_client_interface()->UpdateAudioConfig(
      offload_config_to_hal_audio_config(offload_config));
}

size_t HfpClientInterface::Decode::Read(uint8_t* p_buf, uint32_t len) {
  if (!is_aidl_support_hfp()) {
    LOG(WARNING) << __func__ << ": Unsupported HIDL or AIDL version";
    return 0;
  }
  LOG(INFO) << __func__ << " decode";
  return get_decode_client_interface()->ReadAudioData(p_buf, len);
}

HfpClientInterface::Decode* HfpClientInterface::GetDecode(
    bluetooth::common::MessageLoopThread* message_loop) {
  if (!is_aidl_support_hfp()) {
    LOG(WARNING) << __func__ << ": Unsupported HIDL or AIDL version";
    return nullptr;
  }

  if (decode_ == nullptr) {
    decode_ = new Decode();
  } else {
    LOG(WARNING) << __func__ << ": Decode is already acquired";
    return nullptr;
  }

  LOG(INFO) << __func__ << " decode";

  HfpDecodingTransport::instance_ = new HfpDecodingTransport(
      aidl::SessionType::HFP_SOFTWARE_DECODING_DATAPATH);
  HfpDecodingTransport::software_hal_interface =
      new aidl::BluetoothAudioSinkClientInterface(
          HfpDecodingTransport::instance_, message_loop);
  if (!HfpDecodingTransport::software_hal_interface->IsValid()) {
    LOG(WARNING) << __func__ << ": BluetoothAudio HAL for HFP is invalid";
    delete HfpDecodingTransport::software_hal_interface;
    HfpDecodingTransport::software_hal_interface = nullptr;
    delete HfpDecodingTransport::instance_;
    return nullptr;
  }

  HfpDecodingTransport::active_hal_interface =
      HfpDecodingTransport::software_hal_interface;

  return decode_;
}

bool HfpClientInterface::ReleaseDecode(HfpClientInterface::Decode* decode) {
  if (decode != decode_) {
    LOG(WARNING) << __func__ << ", can't release not acquired decode";
    return false;
  }

  LOG(INFO) << __func__ << " decode";
  if (get_decode_client_interface()) decode->Cleanup();

  delete decode_;
  decode_ = nullptr;

  return true;
}

}  // namespace hfp
}  // namespace audio
}  // namespace bluetooth
