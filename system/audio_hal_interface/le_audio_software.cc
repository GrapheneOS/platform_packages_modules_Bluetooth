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

#define LOG_TAG "BTAudioClientLeAudio"

#include "le_audio_software.h"

#include <unordered_map>
#include <vector>

#include "bta/le_audio/codec_manager.h"
#include "hal_version_manager.h"
#include "hidl/le_audio_software_hidl.h"
#include "osi/include/log.h"
#include "osi/include/properties.h"

namespace bluetooth {
namespace audio {
namespace le_audio {

namespace {

using ::android::hardware::bluetooth::audio::V2_1::PcmParameters;
using ::bluetooth::audio::hidl::BluetoothAudioCtrlAck;
using AudioConfiguration_2_1 =
    ::android::hardware::bluetooth::audio::V2_1::AudioConfiguration;
using AudioConfiguration_2_2 =
    ::android::hardware::bluetooth::audio::V2_2::AudioConfiguration;

using ::le_audio::CodecManager;
using ::le_audio::set_configurations::AudioSetConfiguration;
using ::le_audio::types::CodecLocation;
}  // namespace

std::vector<AudioSetConfiguration> get_offload_capabilities() {
  if (HalVersionManager::GetHalTransport() ==
      BluetoothAudioHalTransport::HIDL) {
    return hidl::le_audio::get_offload_capabilities();
  }
  return {};
}

LeAudioClientInterface* LeAudioClientInterface::interface = nullptr;
LeAudioClientInterface* LeAudioClientInterface::Get() {
  if (osi_property_get_bool(BLUETOOTH_AUDIO_HAL_PROP_DISABLED, false)) {
    LOG(ERROR) << __func__ << ": BluetoothAudio HAL is disabled";
    return nullptr;
  }

  if (LeAudioClientInterface::interface == nullptr)
    LeAudioClientInterface::interface = new LeAudioClientInterface();

  return LeAudioClientInterface::interface;
}

void LeAudioClientInterface::Sink::Cleanup() {
  LOG(INFO) << __func__ << " sink";
  StopSession();
  delete hidl::le_audio::LeAudioSinkTransport::interface;
  hidl::le_audio::LeAudioSinkTransport::interface = nullptr;
  delete hidl::le_audio::LeAudioSinkTransport::instance;
  hidl::le_audio::LeAudioSinkTransport::instance = nullptr;
}

void LeAudioClientInterface::Sink::SetPcmParameters(
    const PcmParameters& params) {
  if (HalVersionManager::GetHalTransport() ==
      BluetoothAudioHalTransport::HIDL) {
    return hidl::le_audio::LeAudioSinkTransport::instance
        ->LeAudioSetSelectedHalPcmConfig(
            params.sample_rate, params.bits_per_sample, params.channels_count,
            params.data_interval_us);
  }
}

// Update Le Audio delay report to BluetoothAudio HAL
void LeAudioClientInterface::Sink::SetRemoteDelay(uint16_t delay_report_ms) {
  LOG(INFO) << __func__ << ": delay_report_ms=" << delay_report_ms << " ms";

  if (HalVersionManager::GetHalTransport() ==
      BluetoothAudioHalTransport::HIDL) {
    hidl::le_audio::LeAudioSinkTransport::instance->SetRemoteDelay(
        delay_report_ms);
    return;
  }
}

void LeAudioClientInterface::Sink::StartSession() {
  LOG(INFO) << __func__;
  if (HalVersionManager::GetHalVersion() ==
      BluetoothAudioHalVersion::VERSION_2_1) {
    AudioConfiguration_2_1 audio_config;
    audio_config.pcmConfig(hidl::le_audio::LeAudioSinkTransport::instance
                               ->LeAudioGetSelectedHalPcmConfig());
    if (!hidl::le_audio::LeAudioSinkTransport::interface->UpdateAudioConfig_2_1(
            audio_config)) {
      LOG(ERROR) << __func__ << ": cannot update audio config to HAL";
      return;
    }
    hidl::le_audio::LeAudioSinkTransport::interface->StartSession_2_1();
    return;
  } else if (HalVersionManager::GetHalVersion() ==
             BluetoothAudioHalVersion::VERSION_2_2) {
    AudioConfiguration_2_2 audio_config;
    if (hidl::le_audio::LeAudioSinkTransport::interface->GetTransportInstance()
            ->GetSessionType_2_1() ==
        hidl::SessionType_2_1::LE_AUDIO_HARDWARE_OFFLOAD_ENCODING_DATAPATH) {
      hidl::le_audio::LeAudioConfiguration le_audio_config = {};
      audio_config.leAudioConfig(le_audio_config);
    } else {
      audio_config.pcmConfig(hidl::le_audio::LeAudioSinkTransport::instance
                                 ->LeAudioGetSelectedHalPcmConfig());
    }
    if (!hidl::le_audio::LeAudioSinkTransport::interface->UpdateAudioConfig_2_2(
            audio_config)) {
      LOG(ERROR) << __func__ << ": cannot update audio config to HAL";
      return;
    }
    hidl::le_audio::LeAudioSinkTransport::interface->StartSession_2_2();
    return;
  }
}

void LeAudioClientInterface::Sink::ConfirmStreamingRequest() {
  LOG(INFO) << __func__;

  if (HalVersionManager::GetHalTransport() ==
      BluetoothAudioHalTransport::HIDL) {
    if (!hidl::le_audio::LeAudioSinkTransport::instance
             ->IsPendingStartStream()) {
      LOG(WARNING) << ", no pending start stream request";
      return;
    }
    hidl::le_audio::LeAudioSinkTransport::instance->ClearPendingStartStream();
    hidl::le_audio::LeAudioSinkTransport::interface->StreamStarted(
        BluetoothAudioCtrlAck::SUCCESS_FINISHED);
    return;
  }
}

void LeAudioClientInterface::Sink::CancelStreamingRequest() {
  LOG(INFO) << __func__;
  if (HalVersionManager::GetHalTransport() ==
      BluetoothAudioHalTransport::HIDL) {
    if (!hidl::le_audio::LeAudioSinkTransport::instance
             ->IsPendingStartStream()) {
      LOG(WARNING) << ", no pending start stream request";
      return;
    }
    hidl::le_audio::LeAudioSinkTransport::instance->ClearPendingStartStream();
    hidl::le_audio::LeAudioSinkTransport::interface->StreamStarted(
        BluetoothAudioCtrlAck::FAILURE);
    return;
  }
}

void LeAudioClientInterface::Sink::StopSession() {
  LOG(INFO) << __func__ << " sink";
  if (HalVersionManager::GetHalTransport() ==
      BluetoothAudioHalTransport::HIDL) {
    hidl::le_audio::LeAudioSinkTransport::instance->ClearPendingStartStream();
    hidl::le_audio::LeAudioSinkTransport::interface->EndSession();
    return;
  }
}

void LeAudioClientInterface::Sink::UpdateAudioConfigToHal(
    const ::le_audio::offload_config& offload_config) {
  if (HalVersionManager::GetHalTransport() ==
      BluetoothAudioHalTransport::HIDL) {
    if (hidl::le_audio::LeAudioSinkTransport::interface->GetTransportInstance()
            ->GetSessionType_2_1() !=
        hidl::SessionType_2_1::LE_AUDIO_HARDWARE_OFFLOAD_ENCODING_DATAPATH) {
      return;
    }
    hidl::le_audio::LeAudioSinkTransport::interface->UpdateAudioConfig_2_2(
        hidl::le_audio::offload_config_to_hal_audio_config(offload_config));
    return;
  }
}

size_t LeAudioClientInterface::Sink::Read(uint8_t* p_buf, uint32_t len) {
  if (HalVersionManager::GetHalTransport() ==
      BluetoothAudioHalTransport::HIDL) {
    return hidl::le_audio::LeAudioSinkTransport::interface->ReadAudioData(p_buf,
                                                                          len);
  }
  return 0;
}

void LeAudioClientInterface::Source::Cleanup() {
  LOG(INFO) << __func__ << " source";
  StopSession();
  delete hidl::le_audio::LeAudioSourceTransport::interface;
  hidl::le_audio::LeAudioSourceTransport::interface = nullptr;
  delete hidl::le_audio::LeAudioSourceTransport::instance;
  hidl::le_audio::LeAudioSourceTransport::instance = nullptr;
}

void LeAudioClientInterface::Source::SetPcmParameters(
    const PcmParameters& params) {
  if (HalVersionManager::GetHalTransport() ==
      BluetoothAudioHalTransport::HIDL) {
    hidl::le_audio::LeAudioSourceTransport::instance
        ->LeAudioSetSelectedHalPcmConfig(
            params.sample_rate, params.bits_per_sample, params.channels_count,
            params.data_interval_us);
    return;
  }
}

void LeAudioClientInterface::Source::SetRemoteDelay(uint16_t delay_report_ms) {
  LOG(INFO) << __func__ << ": delay_report_ms=" << delay_report_ms << " ms";
  if (HalVersionManager::GetHalTransport() ==
      BluetoothAudioHalTransport::HIDL) {
    hidl::le_audio::LeAudioSourceTransport::instance->SetRemoteDelay(
        delay_report_ms);
    return;
  }
}

void LeAudioClientInterface::Source::StartSession() {
  LOG(INFO) << __func__;
  if (!hidl::le_audio::is_source_hal_enabled()) return;

  if (HalVersionManager::GetHalVersion() ==
      BluetoothAudioHalVersion::VERSION_2_1) {
    AudioConfiguration_2_1 audio_config;
    audio_config.pcmConfig(hidl::le_audio::LeAudioSourceTransport::instance
                               ->LeAudioGetSelectedHalPcmConfig());
    if (!hidl::le_audio::LeAudioSourceTransport::
             interface->UpdateAudioConfig_2_1(audio_config)) {
      LOG(ERROR) << __func__ << ": cannot update audio config to HAL";
      return;
    }
    hidl::le_audio::LeAudioSourceTransport::interface->StartSession_2_1();
    return;
  } else if (HalVersionManager::GetHalVersion() ==
             BluetoothAudioHalVersion::VERSION_2_2) {
    AudioConfiguration_2_2 audio_config;
    if (hidl::le_audio::LeAudioSourceTransport::
            interface->GetTransportInstance()
                ->GetSessionType_2_1() ==
        hidl::SessionType_2_1::LE_AUDIO_HARDWARE_OFFLOAD_DECODING_DATAPATH) {
      hidl::le_audio::LeAudioConfiguration le_audio_config = {};
      audio_config.leAudioConfig(le_audio_config);
    } else {
      audio_config.pcmConfig(hidl::le_audio::LeAudioSourceTransport::instance
                                 ->LeAudioGetSelectedHalPcmConfig());
    }

    if (!hidl::le_audio::LeAudioSourceTransport::
             interface->UpdateAudioConfig_2_2(audio_config)) {
      LOG(ERROR) << __func__ << ": cannot update audio config to HAL";
      return;
    }
    hidl::le_audio::LeAudioSourceTransport::interface->StartSession_2_2();
    return;
  }
}

void LeAudioClientInterface::Source::ConfirmStreamingRequest() {
  LOG(INFO) << __func__;
  if (HalVersionManager::GetHalTransport() ==
      BluetoothAudioHalTransport::HIDL) {
    if (!hidl::le_audio::LeAudioSourceTransport::instance
             ->IsPendingStartStream()) {
      LOG(WARNING) << ", no pending start stream request";
      return;
    }
    hidl::le_audio::LeAudioSourceTransport::instance->ClearPendingStartStream();
    hidl::le_audio::LeAudioSourceTransport::interface->StreamStarted(
        BluetoothAudioCtrlAck::SUCCESS_FINISHED);
    return;
  }
}

void LeAudioClientInterface::Source::CancelStreamingRequest() {
  LOG(INFO) << __func__;
  if (HalVersionManager::GetHalTransport() ==
      BluetoothAudioHalTransport::HIDL) {
    if (!hidl::le_audio::LeAudioSourceTransport::instance
             ->IsPendingStartStream()) {
      LOG(WARNING) << ", no pending start stream request";
      return;
    }
    hidl::le_audio::LeAudioSourceTransport::instance->ClearPendingStartStream();
    hidl::le_audio::LeAudioSourceTransport::interface->StreamStarted(
        BluetoothAudioCtrlAck::FAILURE);
    return;
  }
}

void LeAudioClientInterface::Source::StopSession() {
  LOG(INFO) << __func__ << " source";
  if (HalVersionManager::GetHalTransport() ==
      BluetoothAudioHalTransport::HIDL) {
    hidl::le_audio::LeAudioSourceTransport::instance->ClearPendingStartStream();
    hidl::le_audio::LeAudioSourceTransport::interface->EndSession();
    return;
  }
}

void LeAudioClientInterface::Source::UpdateAudioConfigToHal(
    const ::le_audio::offload_config& offload_config) {
  if (HalVersionManager::GetHalTransport() ==
      BluetoothAudioHalTransport::HIDL) {
    if (hidl::le_audio::LeAudioSourceTransport::
            interface->GetTransportInstance()
                ->GetSessionType_2_1() !=
        hidl::SessionType_2_1::LE_AUDIO_HARDWARE_OFFLOAD_DECODING_DATAPATH) {
      return;
    }
    hidl::le_audio::LeAudioSourceTransport::interface->UpdateAudioConfig_2_2(
        hidl::le_audio::offload_config_to_hal_audio_config(offload_config));
    return;
  }
}

size_t LeAudioClientInterface::Source::Write(const uint8_t* p_buf,
                                             uint32_t len) {
  if (HalVersionManager::GetHalTransport() ==
      BluetoothAudioHalTransport::HIDL) {
    return hidl::le_audio::LeAudioSourceTransport::interface->WriteAudioData(
        p_buf, len);
  }
  return 0;
}

LeAudioClientInterface::Sink* LeAudioClientInterface::GetSink(
    StreamCallbacks stream_cb,
    bluetooth::common::MessageLoopThread* message_loop) {
  if (sink_ == nullptr) {
    sink_ = new Sink();
  } else {
    LOG(WARNING) << __func__ << ", Sink is already acquired";
    return nullptr;
  }

  LOG(INFO) << __func__;

  if (HalVersionManager::GetHalTransport() ==
      BluetoothAudioHalTransport::HIDL) {
    hidl::SessionType_2_1 session_type =
        hidl::SessionType_2_1::LE_AUDIO_SOFTWARE_ENCODING_DATAPATH;
    if (CodecManager::GetInstance()->GetCodecLocation() !=
        CodecLocation::HOST) {
      session_type =
          hidl::SessionType_2_1::LE_AUDIO_HARDWARE_OFFLOAD_ENCODING_DATAPATH;
    }
    hidl::le_audio::LeAudioSinkTransport::instance =
        new hidl::le_audio::LeAudioSinkTransport(session_type,
                                                 std::move(stream_cb));
    hidl::le_audio::LeAudioSinkTransport::interface =
        new hidl::BluetoothAudioSinkClientInterface(
            hidl::le_audio::LeAudioSinkTransport::instance, message_loop);
    if (!hidl::le_audio::LeAudioSinkTransport::interface->IsValid()) {
      LOG(WARNING) << __func__
                   << ": BluetoothAudio HAL for Le Audio is invalid?!";
      delete hidl::le_audio::LeAudioSinkTransport::interface;
      hidl::le_audio::LeAudioSinkTransport::interface = nullptr;
      delete hidl::le_audio::LeAudioSinkTransport::instance;
      hidl::le_audio::LeAudioSinkTransport::instance = nullptr;
      delete sink_;
      sink_ = nullptr;

      return nullptr;
    }
  }

  return sink_;
}

bool LeAudioClientInterface::IsSinkAcquired() { return sink_ != nullptr; }

bool LeAudioClientInterface::ReleaseSink(LeAudioClientInterface::Sink* sink) {
  if (sink != sink_) {
    LOG(WARNING) << __func__ << ", can't release not acquired sink";
    return false;
  }

  if (hidl::le_audio::LeAudioSinkTransport::interface &&
      hidl::le_audio::LeAudioSinkTransport::instance)
    sink->Cleanup();

  delete (sink_);
  sink_ = nullptr;

  return true;
}

LeAudioClientInterface::Source* LeAudioClientInterface::GetSource(
    StreamCallbacks stream_cb,
    bluetooth::common::MessageLoopThread* message_loop) {
  if (source_ == nullptr) {
    source_ = new Source();
  } else {
    LOG(WARNING) << __func__ << ", Source is already acquired";
    return nullptr;
  }

  LOG(INFO) << __func__;

  if (HalVersionManager::GetHalTransport() ==
      BluetoothAudioHalTransport::HIDL) {
    hidl::SessionType_2_1 session_type =
        hidl::SessionType_2_1::LE_AUDIO_SOFTWARE_DECODED_DATAPATH;
    if (CodecManager::GetInstance()->GetCodecLocation() !=
        CodecLocation::HOST) {
      session_type =
          hidl::SessionType_2_1::LE_AUDIO_HARDWARE_OFFLOAD_DECODING_DATAPATH;
    }

    hidl::le_audio::LeAudioSourceTransport::instance =
        new hidl::le_audio::LeAudioSourceTransport(session_type,
                                                   std::move(stream_cb));
    hidl::le_audio::LeAudioSourceTransport::interface =
        new hidl::BluetoothAudioSourceClientInterface(
            hidl::le_audio::LeAudioSourceTransport::instance, message_loop);
    if (!hidl::le_audio::LeAudioSourceTransport::interface->IsValid()) {
      LOG(WARNING) << __func__
                   << ": BluetoothAudio HAL for Le Audio is invalid?!";
      delete hidl::le_audio::LeAudioSourceTransport::interface;
      hidl::le_audio::LeAudioSourceTransport::interface = nullptr;
      delete hidl::le_audio::LeAudioSourceTransport::instance;
      hidl::le_audio::LeAudioSourceTransport::instance = nullptr;
      delete source_;
      source_ = nullptr;

      return nullptr;
    }
  }

  return source_;
}

bool LeAudioClientInterface::IsSourceAcquired() { return source_ != nullptr; }

bool LeAudioClientInterface::ReleaseSource(
    LeAudioClientInterface::Source* source) {
  if (source != source_) {
    LOG(WARNING) << __func__ << ", can't release not acquired source";
    return false;
  }

  if (hidl::le_audio::LeAudioSourceTransport::interface &&
      hidl::le_audio::LeAudioSourceTransport::instance)
    source->Cleanup();

  delete (source_);
  source_ = nullptr;

  return true;
}

}  // namespace le_audio
}  // namespace audio
}  // namespace bluetooth
