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

#include <base/bind.h>

#include "bta/include/bta_le_audio_api.h"
#include "bta/include/bta_le_audio_broadcaster_api.h"
#include "bta/le_audio/broadcaster/state_machine.h"
#include "bta/le_audio/le_audio_types.h"
#include "device/include/controller.h"
#include "embdrv/lc3/include/lc3.h"
#include "stack/include/btm_api_types.h"
#include "stack/include/btm_iso_api.h"
#include "osi/include/properties.h"

using bluetooth::hci::IsoManager;
using bluetooth::hci::iso_manager::big_create_cmpl_evt;
using bluetooth::hci::iso_manager::big_terminate_cmpl_evt;
using bluetooth::hci::iso_manager::BigCallbacks;
using bluetooth::le_audio::BroadcastId;
using le_audio::broadcaster::BasicAudioAnnouncementData;
using le_audio::broadcaster::BigConfig;
using le_audio::broadcaster::BroadcastCodecWrapper;
using le_audio::broadcaster::BroadcastStateMachine;
using le_audio::broadcaster::BroadcastStateMachineConfig;
using le_audio::broadcaster::IBroadcastStateMachineCallbacks;
using le_audio::types::kLeAudioCodingFormatLC3;

namespace {
class LeAudioBroadcasterImpl;
LeAudioBroadcasterImpl* instance;

/* Class definitions */

/* LeAudioBroadcasterImpl class represents main implementation class for le
 * audio broadcaster feature in the stack.
 *
 * This class may be bonded with Test socket which allows to drive an instance
 * for test purposes.
 */
class LeAudioBroadcasterImpl : public LeAudioBroadcaster, public BigCallbacks {
  enum class AudioDataPathState {
    INACTIVE,
    ACTIVE,
    SUSPENDED,
  };

 public:
  LeAudioBroadcasterImpl(
      bluetooth::le_audio::LeAudioBroadcasterCallbacks* callbacks_)
      : callbacks_(callbacks_),
        current_phy_(PHY_LE_2M),
        num_retransmit_(3),
        audio_data_path_state_(AudioDataPathState::INACTIVE),
        audio_instance_(nullptr) {
    LOG(INFO) << __func__;

    /* Register State machine callbacks */
    BroadcastStateMachine::Initialize(&state_machine_callbacks_);

    GenerateBroadcastIds();
  }

  ~LeAudioBroadcasterImpl() override = default;

  void GenerateBroadcastIds(void) {
    btsnd_hcic_ble_rand(base::Bind([](BT_OCTET8 rand) {
      if (!instance) return;

      /* LE Rand returns 8 octets. Lets' make 2 outstanding Broadcast Ids out
       * of it */
      for (int i = 0; i < 4; i += 3) {
        BroadcastId b_id = {rand[i], rand[i + 1], rand[i + 2]};
        instance->available_broadcast_ids_.emplace_back(b_id);
      }
    }));
  }

  void CleanUp() {
    DLOG(INFO) << "Broadcaster " << __func__;
    broadcasts_.clear();
    callbacks_ = nullptr;

    if (audio_instance_) {
      LeAudioClientAudioSource::Stop();
      LeAudioClientAudioSource::Release(audio_instance_);
      audio_instance_ = nullptr;
    }
  }

  void Stop() {
    DLOG(INFO) << "Broadcaster " << __func__;

    for (auto& sm_pair : broadcasts_) {
      StopAudioBroadcast(sm_pair.first);
    }
  }

  static BasicAudioAnnouncementData prepareAnnouncement(
      const BroadcastCodecWrapper& codec_config,
      std::vector<uint8_t> metadata) {
    BasicAudioAnnouncementData announcement;

    /* Prepare the announcement */
    announcement.presentation_delay = 0x004E20; /* TODO: Use the proper value */

    auto const& codec_id = codec_config.GetLeAudioCodecId();
    auto codec_spec_data = codec_config.GetCodecSpecData();

    /* Note: Currently we have a single audio source configured with a one
     *       set of codec/pcm parameters thus we can use a single subgroup
     *       for all the BISes. And configure codec params at the BIG level,
     *       since all these BISes share common codec configuration.
     */
    announcement.subgroup_configs = {{
        .codec_config =
            {
                .codec_id = codec_id.coding_format,
                .vendor_company_id = codec_id.vendor_company_id,
                .vendor_codec_id = codec_id.vendor_codec_id,
                .codec_specific_params = std::move(codec_spec_data),
            },
        .metadata = metadata,
        .bis_configs = {},
    }};

    /* In general we could have individual BISes in this single subgroup
     * have different codec configurations, but here we put all channel bises
     * into this one subgroup and assign every BIS's index with an empty config
     * to indicate that the lower lvl config should be used instead.
     * BIS indices range is [1-31] - BASS, Sec.3.2 Broadcast Receive State.
     */
    for (uint8_t i = 0; i < codec_config.GetNumChannels(); ++i) {
      announcement.subgroup_configs[0].bis_configs.push_back(
          {.codec_specific_params = {},
           .bis_index = static_cast<uint8_t>(i + 1)});
    }

    return announcement;
  }

  void UpdateMetadata(uint8_t instance_id,
                      std::vector<uint8_t> metadata) override {
    if (broadcasts_.count(instance_id) == 0) {
      LOG(ERROR) << __func__ << " no such instance_id=" << int{instance_id};
      return;
    }

    DLOG(INFO) << __func__ << " for instance_id=" << int{instance_id};

    auto& codec_config = audio_receiver_.getCurrentCodecConfig();

    /* Prepare the announcement format */
    BasicAudioAnnouncementData announcement =
        prepareAnnouncement(codec_config, std::move(metadata));

    broadcasts_[instance_id]->UpdateBroadcastAnnouncement(
        std::move(announcement));
  }

  void CreateAudioBroadcast(
      std::vector<uint8_t> metadata, LeAudioBroadcaster::AudioProfile profile,
      std::optional<LeAudioBroadcaster::Code> broadcast_code) override {
    DLOG(INFO) << __func__;

    auto& codec_wrapper =
        BroadcastCodecWrapper::getCodecConfigForProfile(profile);

    auto broadcast_id = available_broadcast_ids_.back();
    available_broadcast_ids_.pop_back();
    if (available_broadcast_ids_.size() == 0) GenerateBroadcastIds();

    /* Prepare the announcement format */
    BasicAudioAnnouncementData announcement =
        prepareAnnouncement(codec_wrapper, std::move(metadata));

    BroadcastStateMachineConfig msg = {
        .broadcast_id = broadcast_id,
        .streaming_phy = GetStreamingPhy(),
        .codec_wrapper = codec_wrapper,
        .announcement = std::move(announcement),
        .broadcast_code = std::move(broadcast_code)};

    /* Create the broadcaster instance - we'll receive it's init state in the
     * async callback
     */
    pending_broadcasts_.push_back(
        std::move(BroadcastStateMachine::CreateInstance(std::move(msg))));

    // Notify the error instead just fail silently
    if (!pending_broadcasts_.back()->Initialize()) {
      pending_broadcasts_.pop_back();
      callbacks_->OnBroadcastCreated(
          BroadcastStateMachine::kInstanceIdUndefined, false);
    }
  }

  void SuspendAudioBroadcast(uint8_t instance_id) override {
    DLOG(INFO) << __func__ << " suspending instance_id=" << int{instance_id};
    if (broadcasts_.count(instance_id) != 0) {
      DLOG(INFO) << __func__ << " Stopping LeAudioClientAudioSource";
      LeAudioClientAudioSource::Stop();
      broadcasts_[instance_id]->SetMuted(true);
      broadcasts_[instance_id]->ProcessMessage(
          BroadcastStateMachine::Message::SUSPEND, nullptr);
    } else {
      LOG(ERROR) << __func__ << " no such instance_id=" << int{instance_id};
    }
  }

  static bool IsAnyoneStreaming() {
    if (!instance) return false;

    auto const& iter =
        std::find_if(instance->broadcasts_.cbegin(),
                     instance->broadcasts_.cend(), [](auto const& sm) {
                       return sm.second->GetState() ==
                              BroadcastStateMachine::State::STREAMING;
                     });
    return (iter != instance->broadcasts_.cend());
  }

  void StartAudioBroadcast(uint8_t instance_id) override {
    DLOG(INFO) << __func__ << " starting instance_id=" << int{instance_id};

    if (IsAnyoneStreaming()) {
      LOG(ERROR) << __func__ << ": Stop the other broadcast first!";
      return;
    }

    if (broadcasts_.count(instance_id) != 0) {
      if (!audio_instance_) {
        audio_instance_ = LeAudioClientAudioSource::Acquire();
        if (!audio_instance_) {
          LOG(ERROR) << __func__ << " could not acquire le audio";
          return;
        }
      }

      broadcasts_[instance_id]->ProcessMessage(
          BroadcastStateMachine::Message::START, nullptr);
    } else {
      LOG(ERROR) << __func__ << " no such instance_id=" << int{instance_id};
    }
  }

  void StopAudioBroadcast(uint8_t instance_id) override {
    if (broadcasts_.count(instance_id) == 0) {
      LOG(ERROR) << __func__ << " no such instance_id=" << int{instance_id};
      return;
    }

    DLOG(INFO) << __func__ << " stopping instance_id=" << int{instance_id};

    DLOG(INFO) << __func__ << " Stopping LeAudioClientAudioSource";
    LeAudioClientAudioSource::Stop();
    broadcasts_[instance_id]->SetMuted(true);
    broadcasts_[instance_id]->ProcessMessage(
        BroadcastStateMachine::Message::STOP, nullptr);
  }

  void DestroyAudioBroadcast(uint8_t instance_id) override {
    DLOG(INFO) << __func__ << " destroying instance_id=" << int{instance_id};
    broadcasts_.erase(instance_id);
  }

  void GetBroadcastId(uint8_t instance_id) override {
    if (broadcasts_.count(instance_id) == 0) {
      LOG(ERROR) << __func__ << " no such instance_id=" << int{instance_id};
      return;
    }

    auto broadcast_id = broadcasts_[instance_id]->GetBroadcastId();
    callbacks_->OnBroadcastId(instance_id, broadcast_id);
  }

  void GetAllBroadcastStates(void) override {
    for (auto const& kv_it : broadcasts_) {
      callbacks_->OnBroadcastStateChanged(
          kv_it.second->GetInstanceId(),
          static_cast<bluetooth::le_audio::BroadcastState>(
              kv_it.second->GetState()));
    }
  }

  void IsValidBroadcast(
      uint8_t instance_id, uint8_t addr_type, RawAddress addr,
      base::Callback<void(uint8_t /* instance_id */, uint8_t /* addr_type */,
                          RawAddress /* addr */, bool /* is_local */)>
          cb) override {
    if (broadcasts_.count(instance_id) == 0) {
      LOG(ERROR) << __func__ << " no such instance_id=" << int{instance_id};
      std::move(cb).Run(instance_id, addr_type, addr, false);
      return;
    }

    broadcasts_[instance_id]->RequestOwnAddress(base::Bind(
        [](uint8_t instance_id, uint8_t req_address_type,
           RawAddress req_address,
           base::Callback<void(uint8_t /* instance_id */,
                               uint8_t /* addr_type */, RawAddress /* addr */,
                               bool /* is_local */)>
               cb,
           uint8_t rcv_address_type, RawAddress rcv_address) {
          bool is_local = (req_address_type == rcv_address_type) &&
                          (req_address == rcv_address);
          std::move(cb).Run(instance_id, req_address_type, req_address,
                            is_local);
        },
        instance_id, addr_type, addr, std::move(cb)));
  }

  void SetNumRetransmit(uint8_t count) override { num_retransmit_ = count; }

  uint8_t GetNumRetransmit(void) const override { return num_retransmit_; }

  void SetStreamingPhy(uint8_t phy) override { current_phy_ = phy; }

  uint8_t GetStreamingPhy(void) const override { return current_phy_; }

  void OnSetupIsoDataPath(uint8_t status, uint16_t conn_handle,
                          uint8_t big_id) override {
    CHECK(broadcasts_.count(big_id) != 0);
    broadcasts_[big_id]->OnSetupIsoDataPath(status, conn_handle);
  }

  void OnRemoveIsoDataPath(uint8_t status, uint16_t conn_handle,
                           uint8_t big_id) override {
    CHECK(broadcasts_.count(big_id) != 0);
    broadcasts_[big_id]->OnRemoveIsoDataPath(status, conn_handle);
  }

  void OnBigEvent(uint8_t event, void* data) override {
    switch (event) {
      case bluetooth::hci::iso_manager::kIsoEventBigOnCreateCmpl: {
        auto* evt = static_cast<big_create_cmpl_evt*>(data);
        CHECK(broadcasts_.count(evt->big_id) != 0);
        broadcasts_[evt->big_id]->HandleHciEvent(HCI_BLE_CREATE_BIG_CPL_EVT,
                                                 evt);

      } break;
      case bluetooth::hci::iso_manager::kIsoEventBigOnTerminateCmpl: {
        auto* evt = static_cast<big_terminate_cmpl_evt*>(data);
        CHECK(broadcasts_.count(evt->big_id) != 0);
        broadcasts_[evt->big_id]->HandleHciEvent(HCI_BLE_TERM_BIG_CPL_EVT, evt);
        LeAudioClientAudioSource::Release(audio_instance_);
        audio_instance_ = nullptr;
      } break;
      default:
        LOG(ERROR) << __func__ << " Invalid event: " << int{event};
    }
  }

  void Dump(int fd) {
    std::stringstream stream;

    stream << "    Number of broadcasts: " << broadcasts_.size() << "\n";
    for (auto& broadcast_pair : broadcasts_) {
      auto& broadcast = broadcast_pair.second;
      if (broadcast) stream << *broadcast;
    }

    dprintf(fd, "%s", stream.str().c_str());
  }

 private:
  uint8_t GetNumRetransmit(uint8_t broadcaster_id) {
    /* TODO: Should be based on QOS settings */
    return GetNumRetransmit();
  }

  uint32_t GetSduItv(uint8_t broadcaster_id) {
    /* TODO: Should be based on QOS settings
     * currently tuned for media profile (music band)
     */
    return 0x002710;
  }

  uint16_t GetMaxTransportLatency(uint8_t broadcaster_id) {
    /* TODO: Should be based on QOS settings
     * currently tuned for media profile (music band)
     */
    return 0x3C;
  }

  static class BroadcastStateMachineCallbacks
      : public IBroadcastStateMachineCallbacks {
    void OnStateMachineCreateStatus(uint8_t instance_id,
                                    bool initialized) override {
      auto pending_broadcast = std::find_if(
          instance->pending_broadcasts_.begin(),
          instance->pending_broadcasts_.end(), [instance_id](auto& sm) {
            return (sm->GetInstanceId() == instance_id);
          });
      LOG_ASSERT(pending_broadcast != instance->pending_broadcasts_.end());
      LOG_ASSERT(instance->broadcasts_.count(instance_id) == 0);

      if (initialized) {
        const uint8_t instance_id = (*pending_broadcast)->GetInstanceId();
        DLOG(INFO) << __func__ << " instance_id=" << int{instance_id}
                   << " state=" << (*pending_broadcast)->GetState();

        instance->broadcasts_[instance_id] = std::move(*pending_broadcast);
      } else {
        LOG(ERROR) << "Failed creating broadcast!";
      }
      instance->pending_broadcasts_.erase(pending_broadcast);
      instance->callbacks_->OnBroadcastCreated(instance_id, initialized);
    }

    void OnStateMachineDestroyed(uint8_t instance_id) override {
      /* This is a special case when state machine destructor calls this
       * callback. It may happen during the Cleanup() call when all state
       * machines are erased and instance can already be set to null to avoid
       * unnecessary calls.
       */
      if (instance) instance->callbacks_->OnBroadcastDestroyed(instance_id);
    }

    static int getStreamerCount() {
      return std::count_if(instance->broadcasts_.begin(),
                           instance->broadcasts_.end(), [](auto const& sm) {
                             LOG(INFO)
                                 << "\t<< state :" << sm.second->GetState();
                             return sm.second->GetState() ==
                                    BroadcastStateMachine::State::STREAMING;
                           });
    }

    void OnStateMachineEvent(uint8_t instance_id,
                             BroadcastStateMachine::State state,
                             const void* data) override {
      DLOG(INFO) << __func__ << " instance_id=" << int{instance_id}
                 << " state=" << state;

      switch (state) {
        case BroadcastStateMachine::State::STOPPED:
          /* Pass through */
        case BroadcastStateMachine::State::CONFIGURING:
          /* Pass through */
        case BroadcastStateMachine::State::CONFIGURED:
          /* Pass through */
        case BroadcastStateMachine::State::STOPPING:
          /* Nothing to do here? */
          break;
        case BroadcastStateMachine::State::STREAMING:
          if (getStreamerCount() == 1) {
            DLOG(INFO) << __func__ << " Starting LeAudioClientAudioSource";

            if (instance->broadcasts_.count(instance_id) != 0) {
              const auto& broadcast = instance->broadcasts_.at(instance_id);

              // Reconfigure encoder instance for the new stream requirements
              audio_receiver_.setCurrentCodecConfig(
                  broadcast->GetCodecConfig());
              audio_receiver_.CheckAndReconfigureEncoders();

              broadcast->SetMuted(false);
              auto cfg = static_cast<const LeAudioCodecConfiguration*>(data);
              auto is_started =
                  LeAudioClientAudioSource::Start(*cfg, &audio_receiver_);
              if (!is_started) {
                /* Audio Source setup failed - stop the broadcast */
                instance->StopAudioBroadcast(instance_id);
                return;
              }

              instance->audio_data_path_state_ = AudioDataPathState::ACTIVE;
            }
          }
          break;
      };

      instance->callbacks_->OnBroadcastStateChanged(
          instance_id, static_cast<bluetooth::le_audio::BroadcastState>(state));
    }

    void OnOwnAddressResponse(uint8_t instance_id, uint8_t addr_type,
                              RawAddress addr) override {
      /* Not used currently */
    }

    uint8_t GetNumRetransmit(uint8_t instance_id) override {
      return instance->GetNumRetransmit(instance_id);
    }

    uint32_t GetSduItv(uint8_t instance_id) override {
      return instance->GetSduItv(instance_id);
    }

    uint16_t GetMaxTransportLatency(uint8_t instance_id) override {
      return instance->GetMaxTransportLatency(instance_id);
    }
  } state_machine_callbacks_;

  static class LeAudioClientAudioSinkReceiverImpl
      : public LeAudioClientAudioSinkReceiver {
   public:
    LeAudioClientAudioSinkReceiverImpl()
        : codec_wrapper_(BroadcastCodecWrapper::getCodecConfigForProfile(
              LeAudioBroadcaster::AudioProfile::SONIFICATION)) {}

    void CheckAndReconfigureEncoders() {
      auto const& codec_id = codec_wrapper_.GetLeAudioCodecId();
      if (codec_id.coding_format != kLeAudioCodingFormatLC3) {
        LOG(ERROR) << "Invalid codec ID: "
                   << "[" << +codec_id.coding_format << ":"
                   << +codec_id.vendor_company_id << ":"
                   << +codec_id.vendor_codec_id << "]";
        return;
      }

      if (enc_audio_buffers_.size() != codec_wrapper_.GetNumChannels()) {
        enc_audio_buffers_.resize(codec_wrapper_.GetNumChannels());
      }

      const int dt_us = codec_wrapper_.GetDataIntervalUs();
      const int sr_hz = codec_wrapper_.GetSampleRate();
      const auto encoder_bytes = lc3_encoder_size(dt_us, sr_hz);
      const auto channel_bytes = codec_wrapper_.GetMaxSduSizePerChannel();

      /* TODO: We should act smart and reuse current configurations */
      encoders_.clear();
      encoders_mem_.clear();
      while (encoders_.size() < codec_wrapper_.GetNumChannels()) {
        auto& encoder_buf = enc_audio_buffers_.at(encoders_.size());
        encoder_buf.resize(channel_bytes);

        encoders_mem_.emplace_back(malloc(encoder_bytes), &std::free);
        encoders_.emplace_back(
            lc3_setup_encoder(dt_us, sr_hz, encoders_mem_.back().get()));
      }
    }

    const BroadcastCodecWrapper& getCurrentCodecConfig(void) const {
      return codec_wrapper_;
    }

    void setCurrentCodecConfig(BroadcastCodecWrapper const& config) {
      codec_wrapper_ = config;
    }

    void encodeLc3Channel(lc3_encoder_t encoder,
                          std::vector<uint8_t>& out_buffer,
                          const std::vector<uint8_t>& data,
                          int initial_channel_offset, int pitch_samples,
                          int num_channels) {
      auto encoder_status =
          lc3_encode(encoder, (int16_t*)(data.data() + initial_channel_offset),
                     pitch_samples, out_buffer.size(), out_buffer.data());
      if (encoder_status != 0) {
        LOG(ERROR) << "Error while encoding"
                   << "\terror: " << encoder_status;
      }
    }

    static void sendBroadcastData(
        const std::unique_ptr<BroadcastStateMachine>& broadcast,
        std::vector<std::vector<uint8_t>>& encoded_channels) {
      auto const& config = broadcast->GetBigConfig();
      if (config == std::nullopt) {
        LOG(ERROR) << "Broadcast instance_id= "
                   << int{broadcast->GetInstanceId()}
                   << " has no valid BIS configurations in state= "
                   << broadcast->GetState();
        return;
      }

      if (config->connection_handles.size() < encoded_channels.size()) {
        LOG(ERROR) << "Not enough BIS'es to broadcast all channels!";
        return;
      }

      for (uint8_t chan = 0; chan < encoded_channels.size(); ++chan) {
        IsoManager::GetInstance()->SendIsoData(config->connection_handles[chan],
                                               encoded_channels[chan].data(),
                                               encoded_channels[chan].size());
      }
    }

    virtual void OnAudioDataReady(const std::vector<uint8_t>& data) override {
      if (!instance) return;

      DVLOG(INFO) << __func__ << ": " << data.size() << " bytes received.";

      /* Constants for the channel data configuration */
      const auto num_channels = codec_wrapper_.GetNumChannels();
      const auto bytes_per_sample = (codec_wrapper_.GetBitsPerSample() / 8);

      /* Prepare encoded data for all channels */
      for (uint8_t chan = 0; chan < num_channels; ++chan) {
        /* TODO: Use encoder agnostic wrapper */
        encodeLc3Channel(encoders_[chan], enc_audio_buffers_[chan], data,
                         chan * bytes_per_sample, num_channels, num_channels);
      }

      /* Currently there is no way to broadcast multiple distinct streams.
       * We just receive all system sounds mixed into a one stream and each
       * broadcast gets the same data.
       */
      for (auto& broadcast_pair : instance->broadcasts_) {
        auto& broadcast = broadcast_pair.second;
        if ((broadcast->GetState() ==
             BroadcastStateMachine::State::STREAMING) &&
            !broadcast->IsMuted())
          sendBroadcastData(broadcast, enc_audio_buffers_);
      }
      DVLOG(INFO) << __func__ << ": END";
    }

    virtual void OnAudioSuspend(
        std::promise<void> do_suspend_promise) override {
      LOG(INFO) << __func__;
      /* TODO: Should we suspend all broadcasts - remove BIGs? */
      do_suspend_promise.set_value();
      if (instance)
        instance->audio_data_path_state_ = AudioDataPathState::SUSPENDED;
    }

    virtual void OnAudioResume(void) override {
      LOG(INFO) << __func__;
      /* TODO: Should we resume all broadcasts - recreate BIGs? */
      if (instance)
        instance->audio_data_path_state_ = AudioDataPathState::ACTIVE;

      if (!IsAnyoneStreaming()) {
        LeAudioClientAudioSource::CancelStreamingRequest();
        return;
      }

      LeAudioClientAudioSource::ConfirmStreamingRequest();
    }

    virtual void OnAudioMetadataUpdate(
        std::promise<void> do_update_metadata_promise,
        const source_metadata_t& source_metadata) override {
      LOG(INFO) << __func__;
      if (!instance) return;
      do_update_metadata_promise.set_value();
      /* TODO: We probably don't want to change stream type or update the
       * advertized metadata on each call. We should rather make sure we get
       * only a single content audio stream from the media frameworks.
       */
    }

   private:
    BroadcastCodecWrapper codec_wrapper_;
    std::vector<lc3_encoder_t> encoders_;
    std::vector<std::unique_ptr<void, decltype(&std::free)>> encoders_mem_;
    std::vector<std::vector<uint8_t>> enc_audio_buffers_;
  } audio_receiver_;

  bluetooth::le_audio::LeAudioBroadcasterCallbacks* callbacks_;
  std::map<uint8_t, std::unique_ptr<BroadcastStateMachine>> broadcasts_;
  std::vector<std::unique_ptr<BroadcastStateMachine>> pending_broadcasts_;

  /* Some BIG params are set globally */
  uint8_t current_phy_;
  uint8_t num_retransmit_;
  AudioDataPathState audio_data_path_state_;
  const void* audio_instance_;
  std::vector<BroadcastId> available_broadcast_ids_;
};

/* Static members definitions */
LeAudioBroadcasterImpl::BroadcastStateMachineCallbacks
    LeAudioBroadcasterImpl::state_machine_callbacks_;
LeAudioBroadcasterImpl::LeAudioClientAudioSinkReceiverImpl
    LeAudioBroadcasterImpl::audio_receiver_;

} /* namespace */

void LeAudioBroadcaster::Initialize(
    bluetooth::le_audio::LeAudioBroadcasterCallbacks* callbacks,
    base::Callback<bool()> hal_2_1_verifier) {
  LOG(INFO) << "Broadcaster " << __func__;
  if (instance) {
    LOG(ERROR) << "Already initialized";
    return;
  }

  if (!controller_get_interface()->supports_ble_isochronous_broadcaster() &&
      !osi_property_get_bool("persist.bluetooth.fake_iso_support", false)) {
    LOG(WARNING) << "Isochronous Broadcast not supported by the controller!";
    return;
  }

  IsoManager::GetInstance()->Start();

  if (!std::move(hal_2_1_verifier).Run()) {
    LOG_ASSERT(false) << __func__ << ", HAL 2.1 not supported, Init aborted.";
    return;
  }

  instance = new LeAudioBroadcasterImpl(callbacks);
  /* Register HCI event handlers */
  IsoManager::GetInstance()->RegisterBigCallbacks(instance);
}

bool LeAudioBroadcaster::IsLeAudioBroadcasterRunning() { return instance; }

LeAudioBroadcaster* LeAudioBroadcaster::Get(void) {
  LOG(INFO) << "Broadcaster " << __func__;
  CHECK(instance);
  return instance;
}

void LeAudioBroadcaster::Stop(void) {
  LOG(INFO) << "Broadcaster " << __func__;

  if (instance) {
    instance->Stop();
  }
}

void LeAudioBroadcaster::Cleanup(void) {
  LOG(INFO) << "Broadcaster " << __func__;

  if (instance == nullptr) return;

  LeAudioBroadcasterImpl* ptr = instance;
  instance = nullptr;

  ptr->CleanUp();
  delete ptr;
}

void LeAudioBroadcaster::DebugDump(int fd) {
  dprintf(fd, "Le Audio Broadcaster:\n");
  if (instance) instance->Dump(fd);
  dprintf(fd, "\n");
}
