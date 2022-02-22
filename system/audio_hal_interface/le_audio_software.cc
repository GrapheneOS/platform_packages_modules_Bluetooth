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

#include "aidl/le_audio_software.h"
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
using AudioConfiguration_2_1 =
    ::android::hardware::bluetooth::audio::V2_1::AudioConfiguration;
using AudioConfigurationAIDL =
    ::aidl::android::hardware::bluetooth::audio::AudioConfiguration;

using ::le_audio::CodecManager;
using ::le_audio::set_configurations::AudioSetConfiguration;
using ::le_audio::types::CodecLocation;
}  // namespace

std::vector<AudioSetConfiguration> get_offload_capabilities() {
  if (HalVersionManager::GetHalTransport() ==
      BluetoothAudioHalTransport::HIDL) {
    return std::vector<AudioSetConfiguration>(0);
  }
  return aidl::le_audio::get_offload_capabilities();
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
  if (hidl::le_audio::LeAudioSinkTransport::interface) {
    delete hidl::le_audio::LeAudioSinkTransport::interface;
    hidl::le_audio::LeAudioSinkTransport::interface = nullptr;
  }
  if (hidl::le_audio::LeAudioSinkTransport::instance) {
    delete hidl::le_audio::LeAudioSinkTransport::instance;
    hidl::le_audio::LeAudioSinkTransport::instance = nullptr;
  }
  if (aidl::le_audio::LeAudioSinkTransport::interface) {
    delete aidl::le_audio::LeAudioSinkTransport::interface;
    aidl::le_audio::LeAudioSinkTransport::interface = nullptr;
  }
  if (aidl::le_audio::LeAudioSinkTransport::instance) {
    delete aidl::le_audio::LeAudioSinkTransport::instance;
    aidl::le_audio::LeAudioSinkTransport::instance = nullptr;
  }
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
  return aidl::le_audio::LeAudioSinkTransport::instance
      ->LeAudioSetSelectedHalPcmConfig(
          params.sample_rate, params.bits_per_sample, params.channels_count,
          params.data_interval_us);
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
  aidl::le_audio::LeAudioSinkTransport::instance->SetRemoteDelay(
      delay_report_ms);
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
             BluetoothAudioHalVersion::VERSION_AIDL_V1) {
    AudioConfigurationAIDL audio_config;
    if (aidl::le_audio::LeAudioSinkTransport::interface->GetTransportInstance()
            ->GetSessionType() ==
        aidl::SessionType::LE_AUDIO_HARDWARE_OFFLOAD_ENCODING_DATAPATH) {
      aidl::le_audio::LeAudioConfiguration le_audio_config = {};
      audio_config.set<AudioConfigurationAIDL::leAudioConfig>(le_audio_config);
    } else {
      audio_config.set<AudioConfigurationAIDL::pcmConfig>(
          aidl::le_audio::LeAudioSinkTransport::instance
              ->LeAudioGetSelectedHalPcmConfig());
    }
    if (!aidl::le_audio::LeAudioSinkTransport::interface->UpdateAudioConfig(
            audio_config)) {
      LOG(ERROR) << __func__ << ": cannot update audio config to HAL";
      return;
    }
    aidl::le_audio::LeAudioSinkTransport::interface->StartSession();
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
        hidl::BluetoothAudioCtrlAck::SUCCESS_FINISHED);
    return;
  }
  if (!aidl::le_audio::LeAudioSinkTransport::instance->IsPendingStartStream()) {
    LOG(WARNING) << ", no pending start stream request";
    return;
  }
  aidl::le_audio::LeAudioSinkTransport::instance->ClearPendingStartStream();
  aidl::le_audio::LeAudioSinkTransport::interface->StreamStarted(
      aidl::BluetoothAudioCtrlAck::SUCCESS_FINISHED);
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
        hidl::BluetoothAudioCtrlAck::FAILURE);
    return;
  }
  if (!aidl::le_audio::LeAudioSinkTransport::instance->IsPendingStartStream()) {
    LOG(WARNING) << ", no pending start stream request";
    return;
  }
  aidl::le_audio::LeAudioSinkTransport::instance->ClearPendingStartStream();
  aidl::le_audio::LeAudioSinkTransport::interface->StreamStarted(
      aidl::BluetoothAudioCtrlAck::FAILURE);
}

void LeAudioClientInterface::Sink::StopSession() {
  LOG(INFO) << __func__ << " sink";
  if (HalVersionManager::GetHalTransport() ==
      BluetoothAudioHalTransport::HIDL) {
    hidl::le_audio::LeAudioSinkTransport::instance->ClearPendingStartStream();
    hidl::le_audio::LeAudioSinkTransport::interface->EndSession();
    return;
  }
  aidl::le_audio::LeAudioSinkTransport::instance->ClearPendingStartStream();
  aidl::le_audio::LeAudioSinkTransport::interface->EndSession();
}

void LeAudioClientInterface::Sink::UpdateAudioConfigToHal(
    const ::le_audio::offload_config& offload_config) {
  if (HalVersionManager::GetHalTransport() ==
      BluetoothAudioHalTransport::HIDL) {
    return;
  }
  if (aidl::le_audio::LeAudioSinkTransport::interface->GetTransportInstance()
          ->GetSessionType() !=
      aidl::SessionType::LE_AUDIO_HARDWARE_OFFLOAD_ENCODING_DATAPATH) {
    return;
  }
  aidl::le_audio::LeAudioSinkTransport::interface->UpdateAudioConfig(
      aidl::le_audio::offload_config_to_hal_audio_config(offload_config));
}

size_t LeAudioClientInterface::Sink::Read(uint8_t* p_buf, uint32_t len) {
  if (HalVersionManager::GetHalTransport() ==
      BluetoothAudioHalTransport::HIDL) {
    return hidl::le_audio::LeAudioSinkTransport::interface->ReadAudioData(p_buf,
                                                                          len);
  }
  return aidl::le_audio::LeAudioSinkTransport::interface->ReadAudioData(p_buf,
                                                                        len);
}

void LeAudioClientInterface::Source::Cleanup() {
  LOG(INFO) << __func__ << " source";
  StopSession();
  if (hidl::le_audio::LeAudioSourceTransport::interface) {
    delete hidl::le_audio::LeAudioSourceTransport::interface;
    hidl::le_audio::LeAudioSourceTransport::interface = nullptr;
  }
  if (hidl::le_audio::LeAudioSourceTransport::instance) {
    delete hidl::le_audio::LeAudioSourceTransport::instance;
    hidl::le_audio::LeAudioSourceTransport::instance = nullptr;
  }
  if (aidl::le_audio::LeAudioSourceTransport::interface) {
    delete aidl::le_audio::LeAudioSourceTransport::interface;
    aidl::le_audio::LeAudioSourceTransport::interface = nullptr;
  }
  if (aidl::le_audio::LeAudioSourceTransport::instance) {
    delete aidl::le_audio::LeAudioSourceTransport::instance;
    aidl::le_audio::LeAudioSourceTransport::instance = nullptr;
  }
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
  return aidl::le_audio::LeAudioSourceTransport::instance
      ->LeAudioSetSelectedHalPcmConfig(
          params.sample_rate, params.bits_per_sample, params.channels_count,
          params.data_interval_us);
}

void LeAudioClientInterface::Source::SetRemoteDelay(uint16_t delay_report_ms) {
  LOG(INFO) << __func__ << ": delay_report_ms=" << delay_report_ms << " ms";
  if (HalVersionManager::GetHalTransport() ==
      BluetoothAudioHalTransport::HIDL) {
    hidl::le_audio::LeAudioSourceTransport::instance->SetRemoteDelay(
        delay_report_ms);
    return;
  }
  return aidl::le_audio::LeAudioSourceTransport::instance->SetRemoteDelay(
      delay_report_ms);
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
             BluetoothAudioHalVersion::VERSION_AIDL_V1) {
    AudioConfigurationAIDL audio_config;
    if (aidl::le_audio::LeAudioSourceTransport::
            interface->GetTransportInstance()
                ->GetSessionType() ==
        aidl::SessionType::LE_AUDIO_HARDWARE_OFFLOAD_DECODING_DATAPATH) {
      aidl::le_audio::LeAudioConfiguration le_audio_config;
      audio_config.set<AudioConfigurationAIDL::leAudioConfig>(
          aidl::le_audio::LeAudioConfiguration{});
    } else {
      audio_config.set<AudioConfigurationAIDL::pcmConfig>(
          aidl::le_audio::LeAudioSourceTransport::instance
              ->LeAudioGetSelectedHalPcmConfig());
    }

    if (!aidl::le_audio::LeAudioSourceTransport::interface->UpdateAudioConfig(
            audio_config)) {
      LOG(ERROR) << __func__ << ": cannot update audio config to HAL";
      return;
    }
    aidl::le_audio::LeAudioSourceTransport::interface->StartSession();
  }
}

void LeAudioClientInterface::Source::ConfirmStreamingRequest() {
  LOG(INFO) << __func__;
  if ((hidl::le_audio::LeAudioSourceTransport::instance &&
       !hidl::le_audio::LeAudioSourceTransport::instance
            ->IsPendingStartStream()) ||
      (aidl::le_audio::LeAudioSourceTransport::instance &&
       !aidl::le_audio::LeAudioSourceTransport::instance
            ->IsPendingStartStream())) {
    LOG(WARNING) << ", no pending start stream request";
    return;
  }

  if (HalVersionManager::GetHalTransport() ==
      BluetoothAudioHalTransport::HIDL) {
    hidl::le_audio::LeAudioSourceTransport::instance->ClearPendingStartStream();
    hidl::le_audio::LeAudioSourceTransport::interface->StreamStarted(
        hidl::BluetoothAudioCtrlAck::SUCCESS_FINISHED);
    return;
  }
  aidl::le_audio::LeAudioSourceTransport::instance->ClearPendingStartStream();
  aidl::le_audio::LeAudioSourceTransport::interface->StreamStarted(
      aidl::BluetoothAudioCtrlAck::SUCCESS_FINISHED);
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
        hidl::BluetoothAudioCtrlAck::FAILURE);
    return;
  }
  if (!aidl::le_audio::LeAudioSourceTransport::instance
           ->IsPendingStartStream()) {
    LOG(WARNING) << ", no pending start stream request";
    return;
  }
  aidl::le_audio::LeAudioSourceTransport::instance->ClearPendingStartStream();
  aidl::le_audio::LeAudioSourceTransport::interface->StreamStarted(
      aidl::BluetoothAudioCtrlAck::FAILURE);
}

void LeAudioClientInterface::Source::StopSession() {
  LOG(INFO) << __func__ << " source";
  if (HalVersionManager::GetHalTransport() ==
      BluetoothAudioHalTransport::HIDL) {
    hidl::le_audio::LeAudioSourceTransport::instance->ClearPendingStartStream();
    hidl::le_audio::LeAudioSourceTransport::interface->EndSession();
    return;
  }
  aidl::le_audio::LeAudioSourceTransport::instance->ClearPendingStartStream();
  aidl::le_audio::LeAudioSourceTransport::interface->EndSession();
}

void LeAudioClientInterface::Source::UpdateAudioConfigToHal(
    const ::le_audio::offload_config& offload_config) {
  if (HalVersionManager::GetHalTransport() ==
      BluetoothAudioHalTransport::HIDL) {
    return;
  }

  if (aidl::le_audio::LeAudioSourceTransport::interface->GetTransportInstance()
          ->GetSessionType() !=
      aidl::SessionType::LE_AUDIO_HARDWARE_OFFLOAD_DECODING_DATAPATH) {
    return;
  }
  aidl::le_audio::LeAudioSourceTransport::interface->UpdateAudioConfig(
      aidl::le_audio::offload_config_to_hal_audio_config(offload_config));
}

size_t LeAudioClientInterface::Source::Write(const uint8_t* p_buf,
                                             uint32_t len) {
  if (HalVersionManager::GetHalTransport() ==
      BluetoothAudioHalTransport::HIDL) {
    return hidl::le_audio::LeAudioSourceTransport::interface->WriteAudioData(
        p_buf, len);
  }
  return aidl::le_audio::LeAudioSourceTransport::interface->WriteAudioData(
      p_buf, len);
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
  } else {
    aidl::SessionType session_type =
        aidl::SessionType::LE_AUDIO_SOFTWARE_ENCODING_DATAPATH;
    if (CodecManager::GetInstance()->GetCodecLocation() !=
        CodecLocation::HOST) {
      session_type =
          aidl::SessionType::LE_AUDIO_HARDWARE_OFFLOAD_ENCODING_DATAPATH;
    }

    aidl::le_audio::LeAudioSinkTransport::instance =
        new aidl::le_audio::LeAudioSinkTransport(session_type,
                                                 std::move(stream_cb));
    aidl::le_audio::LeAudioSinkTransport::interface =
        new aidl::BluetoothAudioSinkClientInterface(
            aidl::le_audio::LeAudioSinkTransport::instance, message_loop);
    if (!aidl::le_audio::LeAudioSinkTransport::interface->IsValid()) {
      LOG(WARNING) << __func__
                   << ": BluetoothAudio HAL for Le Audio is invalid?!";
      delete aidl::le_audio::LeAudioSinkTransport::interface;
      aidl::le_audio::LeAudioSinkTransport::interface = nullptr;
      delete aidl::le_audio::LeAudioSinkTransport::instance;
      aidl::le_audio::LeAudioSinkTransport::instance = nullptr;
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

  if ((hidl::le_audio::LeAudioSinkTransport::interface &&
       hidl::le_audio::LeAudioSinkTransport::instance) ||
      (aidl::le_audio::LeAudioSinkTransport::interface &&
       aidl::le_audio::LeAudioSinkTransport::instance))
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
  } else {
    aidl::SessionType session_type =
        aidl::SessionType::LE_AUDIO_SOFTWARE_DECODING_DATAPATH;
    if (CodecManager::GetInstance()->GetCodecLocation() !=
        CodecLocation::HOST) {
      session_type =
          aidl::SessionType::LE_AUDIO_HARDWARE_OFFLOAD_DECODING_DATAPATH;
    }

    aidl::le_audio::LeAudioSourceTransport::instance =
        new aidl::le_audio::LeAudioSourceTransport(session_type,
                                                   std::move(stream_cb));
    aidl::le_audio::LeAudioSourceTransport::interface =
        new aidl::BluetoothAudioSourceClientInterface(
            aidl::le_audio::LeAudioSourceTransport::instance, message_loop);
    if (!aidl::le_audio::LeAudioSourceTransport::interface->IsValid()) {
      LOG(WARNING) << __func__
                   << ": BluetoothAudio HAL for Le Audio is invalid?!";
      delete aidl::le_audio::LeAudioSourceTransport::interface;
      aidl::le_audio::LeAudioSourceTransport::interface = nullptr;
      delete aidl::le_audio::LeAudioSourceTransport::instance;
      aidl::le_audio::LeAudioSourceTransport::instance = nullptr;
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

  if ((hidl::le_audio::LeAudioSourceTransport::interface &&
       hidl::le_audio::LeAudioSourceTransport::instance) ||
      (aidl::le_audio::LeAudioSourceTransport::interface &&
       aidl::le_audio::LeAudioSourceTransport::instance))
    source->Cleanup();

  delete (source_);
  source_ = nullptr;

  return true;
}

}  // namespace le_audio
}  // namespace audio
}  // namespace bluetooth
