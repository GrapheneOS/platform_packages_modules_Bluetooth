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

#include "bta/le_audio/broadcaster/state_machine.h"

#include <base/bind_helpers.h>

#include <functional>
#include <iostream>

#include "base/bind.h"
#include "base/callback.h"
#include "base/logging.h"
#include "bta/le_audio/broadcaster/broadcaster_types.h"
#include "bta/le_audio/le_audio_types.h"
#include "service/common/bluetooth/low_energy_constants.h"
#include "stack/include/ble_advertiser.h"
#include "stack/include/btm_iso_api.h"
#include "stack/include/btu.h"

using bluetooth::hci::IsoManager;
using bluetooth::hci::iso_manager::big_create_cmpl_evt;
using bluetooth::hci::iso_manager::big_terminate_cmpl_evt;

using namespace le_audio::broadcaster;

namespace {

class BroadcastStateMachineImpl : public BroadcastStateMachine {
 public:
  BroadcastStateMachineImpl(BroadcastStateMachineConfig msg)
      : active_config_(std::nullopt),
        sm_config_(std::move(msg)),
        suspending_(false) {}

  ~BroadcastStateMachineImpl() {
    if (GetState() == State::STREAMING) TerminateBig();
    DestroyBroadcastAnnouncement();
    if (callbacks_) callbacks_->OnStateMachineDestroyed(GetInstanceId());
  }

  bool Initialize() override {
    static constexpr uint8_t sNumBisMax = 31;

    if (sm_config_.codec_wrapper.GetNumChannels() > sNumBisMax) {
      DLOG(ERROR) << int{sm_config_.codec_wrapper.GetNumChannels()}
                  << " channel count exceeds " << int{sNumBisMax}
                  << " - the maximum number of possible BISes!";
      return false;
    }

    CreateBroadcastAnnouncement(sm_config_.broadcast_id,
                                sm_config_.announcement,
                                sm_config_.streaming_phy);
    return true;
  }

  const BroadcastCodecWrapper& GetCodecConfig() const override {
    return sm_config_.codec_wrapper;
  }

  std::optional<BigConfig> const& GetBigConfig() override {
    return active_config_;
  }

  void RequestOwnAddress(
      base::Callback<void(uint8_t /* address_type*/, RawAddress /*address*/)>
          cb) override {
    uint8_t instance_id = GetInstanceId();
    advertiser_if_->GetOwnAddress(instance_id, cb);
  }

  void RequestOwnAddress(void) override {
    uint8_t instance_id = GetInstanceId();
    RequestOwnAddress(
        base::Bind(&IBroadcastStateMachineCallbacks::OnOwnAddressResponse,
                   base::Unretained(this->callbacks_), instance_id));
  }

  RawAddress GetOwnAddress() override {
    LOG(INFO) << __func__;
    return addr_;
  }

  uint8_t GetOwnAddressType() override {
    LOG(INFO) << __func__;
    return addr_type_;
  }

  bluetooth::le_audio::BroadcastId GetBroadcastId() const override {
    return sm_config_.broadcast_id;
  }

  void UpdateBroadcastAnnouncement(
      BasicAudioAnnouncementData announcement) override {
    std::vector<uint8_t> periodic_data;
    PreparePeriodicData(announcement, periodic_data);

    sm_config_.announcement = std::move(announcement);
    advertiser_if_->SetPeriodicAdvertisingData(instance_id_, periodic_data,
                                               base::DoNothing());
  }

  void ProcessMessage(Message msg, const void* data = nullptr) override {
    DLOG(INFO) << __func__ << " instance_id=" << int{GetInstanceId()}
               << " state=" << GetState() << " message=" << msg;
    switch (msg) {
      case Message::START:
        start_msg_handlers[StateMachine::GetState()](data);
        break;
      case Message::STOP:
        stop_msg_handlers[StateMachine::GetState()](data);
        break;
      case Message::SUSPEND:
        suspend_msg_handlers[StateMachine::GetState()](data);
        break;
    };
  }

  static IBroadcastStateMachineCallbacks* callbacks_;
  static base::WeakPtr<BleAdvertisingManager> advertiser_if_;

 private:
  std::optional<BigConfig> active_config_;
  BroadcastStateMachineConfig sm_config_;
  bool suspending_;

  /* Message handlers for each possible state */
  typedef std::function<void(const void*)> msg_handler_t;
  const std::array<msg_handler_t, BroadcastStateMachine::STATE_COUNT>
      start_msg_handlers{
          /* in STOPPED state */
          [this](const void*) {
            SetState(State::CONFIGURING);
            callbacks_->OnStateMachineEvent(GetInstanceId(), GetState());
            EnableAnnouncement();
          },
          /* in CONFIGURING state */
          [](const void*) { /* Do nothing */ },
          /* in CONFIGURED state */
          [this](const void*) { CreateBig(); },
          /* in STOPPING state */
          [](const void*) { /* Do nothing */ },
          /* in STREAMING state */
          [](const void*) { /* Do nothing */ }};

  const std::array<msg_handler_t, BroadcastStateMachine::STATE_COUNT>
      stop_msg_handlers{
          /* in STOPPED state */
          [](const void*) { /* Already stopped */ },
          /* in CONFIGURING state */
          [](const void*) { /* Do nothing */ },
          /* in CONFIGURED state */
          [this](const void*) {
            SetState(State::STOPPING);
            callbacks_->OnStateMachineEvent(GetInstanceId(), GetState());
            DisableAnnouncement();
          },
          /* in STOPPING state */
          [](const void*) { /* Do nothing */ },
          /* in STREAMING state */
          [this](const void*) {
            if ((active_config_ != std::nullopt) && !suspending_) {
              suspending_ = false;
              SetState(State::STOPPING);
              callbacks_->OnStateMachineEvent(GetInstanceId(), GetState());
              TriggerIsoDatapathTeardown(active_config_->connection_handles[0]);
            }
          }};

  const std::array<msg_handler_t, BroadcastStateMachine::STATE_COUNT>
      suspend_msg_handlers{
          /* in STOPPED state */
          [](const void*) { /* Do nothing */ },
          /* in CONFIGURING state */
          [](const void*) { /* Do nothing */ },
          /* in CONFIGURED state */
          [](const void*) { /* Already suspended */ },
          /* in STOPPING state */
          [](const void*) { /* Do nothing */ },
          /* in STREAMING state */
          [this](const void*) {
            if ((active_config_ != std::nullopt) && !suspending_) {
              suspending_ = true;
              TriggerIsoDatapathTeardown(active_config_->connection_handles[0]);
            }
          }};

  const std::array<msg_handler_t, BroadcastStateMachine::STATE_COUNT>
      resume_msg_handlers{/* in STOPPED state */
                          [](const void*) { /* Do nothing */ },
                          /* in CONFIGURING state */
                          [](const void*) { /* Do nothing */ },
                          /* in CONFIGURED state */
                          [this](const void*) { CreateBig(); },
                          /* in STOPPING state */
                          [](const void*) { /* Do nothing */ },
                          /* in STREAMING state */
                          [](const void*) { /* Already streaming */ }};

  void OnAddressResponse(uint8_t addr_type, RawAddress addr) {
    DLOG(INFO) << __func__ << " own address: " << addr
               << " own address type: " << +addr_type;
    addr_ = addr;
    addr_type_ = addr_type;
  }

  void CreateAnnouncementCb(uint8_t instance_id, int8_t tx_power,
                            uint8_t status) {
    DLOG(INFO) << __func__ << " instance_id=" << int{instance_id}
               << " tx_power=" << int{tx_power} << " status=" << int{status};

    /* If this callback gets called the instance_id is valid even though the
     * status can be other than BTM_BLE_MULTI_ADV_SUCCESS. We must set it here
     * to properly identify the instance when callback gets called.
     */
    instance_id_ = instance_id;

    if (status != BTM_BLE_MULTI_ADV_SUCCESS) {
      callbacks_->OnStateMachineCreateStatus(instance_id, false);
      return;
    }

    /* Ext. advertisings are already on */
    SetState(State::CONFIGURED);

    callbacks_->OnStateMachineCreateStatus(instance_id, true);
    callbacks_->OnStateMachineEvent(instance_id, State::CONFIGURED);

    advertiser_if_->GetOwnAddress(
        instance_id, base::Bind(&BroadcastStateMachineImpl::OnAddressResponse,
                                base::Unretained(this)));
  }

  void CreateAnnouncementTimeoutCb(uint8_t instance_id, uint8_t status) {
    DLOG(INFO) << __func__ << " instance_id=" << int{instance_id}
               << " status=" << int{status};
    instance_id_ = instance_id;
    callbacks_->OnStateMachineCreateStatus(instance_id, false);
  }

  void CreateBroadcastAnnouncement(
      bluetooth::le_audio::BroadcastId& broadcast_id,
      const BasicAudioAnnouncementData& announcement, uint8_t streaming_phy) {
    DLOG(INFO) << __func__;
    if (advertiser_if_ != nullptr) {
      tBTM_BLE_ADV_PARAMS adv_params;
      tBLE_PERIODIC_ADV_PARAMS periodic_params;
      std::vector<uint8_t> adv_data;
      std::vector<uint8_t> periodic_data;

      PrepareAdvertisingData(broadcast_id, adv_data);
      PreparePeriodicData(announcement, periodic_data);

      adv_params.adv_int_min = 0x00A0; /* 160 * 0,625 = 100ms */
      adv_params.adv_int_max = 0x0140; /* 320 * 0,625 = 200ms */
      adv_params.advertising_event_properties = 0;
      adv_params.channel_map = bluetooth::kAdvertisingChannelAll;
      adv_params.adv_filter_policy = 0;
      adv_params.tx_power = -15;
      adv_params.primary_advertising_phy = PHY_LE_1M;
      adv_params.secondary_advertising_phy = streaming_phy;
      adv_params.scan_request_notification_enable = 0;

      periodic_params.max_interval = BroadcastStateMachine::kPaIntervalMax;
      periodic_params.min_interval = BroadcastStateMachine::kPaIntervalMin;
      periodic_params.periodic_advertising_properties = 0;
      periodic_params.enable = true;

      /* Callback returns the status and handle which we use later in
       * CreateBIG command.
       */
      advertiser_if_->StartAdvertisingSet(
          base::Bind(&BroadcastStateMachineImpl::CreateAnnouncementCb,
                     base::Unretained(this)),
          &adv_params, adv_data, std::vector<uint8_t>(), &periodic_params,
          periodic_data, 0 /* duration */, 0 /* maxExtAdvEvents */,
          base::Bind(&BroadcastStateMachineImpl::CreateAnnouncementTimeoutCb,
                     base::Unretained(this)));
    }
  }

  void DestroyBroadcastAnnouncement() {
    if (BleAdvertisingManager::IsInitialized())
      advertiser_if_->Unregister(GetInstanceId());
  }

  void EnableAnnouncementCb(bool enable, uint8_t status) {
    DLOG(INFO) << __func__ << " operation=" << (enable ? "enable" : "disable")
               << " instance_id=" << int{GetInstanceId()}
               << " status=" << int{status};

    if (status == BTM_BLE_MULTI_ADV_SUCCESS) {
      /* Periodic is enabled but without BIGInfo. Stream is suspended. */
      if (enable) {
        SetState(State::CONFIGURED);
        /* Target state is always STREAMING state - start it now. */
        ProcessMessage(Message::START);
      } else {
        /* User wanted to stop the announcement - report target state reached */
        SetState(State::STOPPED);
        callbacks_->OnStateMachineEvent(GetInstanceId(), GetState());
      }
    }
  }

  void EnableAnnouncementTimeoutCb(bool enable, uint8_t status) {
    DLOG(INFO) << __func__ << " operation=" << (enable ? "enable" : "disable")
               << " status=" << int{status};
    if (enable) {
      /* Timeout on enabling */
      SetState(State::STOPPED);
    } else {
      /* Timeout on disabling */
      SetState(State::CONFIGURED);
    }
    callbacks_->OnStateMachineEvent(GetInstanceId(), GetState());
  }

  void EnableAnnouncement() {
    DLOG(INFO) << __func__ << "instance_id: " << int{GetInstanceId()};
    advertiser_if_->Enable(
        GetInstanceId(), true,
        base::Bind(&BroadcastStateMachineImpl::EnableAnnouncementCb,
                   base::Unretained(this), true),
        0, 0, /* Enable until stopped */
        base::Bind(&BroadcastStateMachineImpl::EnableAnnouncementTimeoutCb,
                   base::Unretained(this), true));
  }

  void CreateBig(void) {
    DLOG(INFO) << __func__ << " instance_id=" << int{GetInstanceId()};
    /* TODO: Figure out how to decide on the currently hard-codded params. */
    struct bluetooth::hci::iso_manager::big_create_params big_params = {
        .adv_handle = GetInstanceId(),
        .num_bis = sm_config_.codec_wrapper.GetNumChannels(),
        .sdu_itv = callbacks_->GetSduItv(GetInstanceId()),
        .max_sdu_size = sm_config_.codec_wrapper.GetMaxSduSize(),
        .max_transport_latency =
            callbacks_->GetMaxTransportLatency(GetInstanceId()),
        .rtn = callbacks_->GetNumRetransmit(GetInstanceId()),
        .phy = sm_config_.streaming_phy,
        .packing = 0x00, /* Sequencial */
        .framing = 0x00, /* Unframed */
        .enc = static_cast<uint8_t>(sm_config_.broadcast_code ? 1 : 0),
        .enc_code = sm_config_.broadcast_code ? *sm_config_.broadcast_code
                                              : std::array<uint8_t, 16>({0}),
    };

    IsoManager::GetInstance()->CreateBig(GetInstanceId(),
                                         std::move(big_params));
  }

  void DisableAnnouncement(void) {
    DLOG(INFO) << __func__ << "instance_id: " << int{instance_id_};
    advertiser_if_->Enable(
        GetInstanceId(), false,
        base::Bind(&BroadcastStateMachineImpl::EnableAnnouncementCb,
                   base::Unretained(this), false),
        0, 0,
        base::Bind(&BroadcastStateMachineImpl::EnableAnnouncementTimeoutCb,
                   base::Unretained(this), false));
  }

  void TerminateBig() {
    DLOG(INFO) << __func__ << "suspending: " << suspending_;
    /* Terminate with reason: Connection Terminated By Local Host */
    IsoManager::GetInstance()->TerminateBig(GetInstanceId(), 0x16);
  }

  void OnSetupIsoDataPath(uint8_t status, uint16_t conn_hdl) override {
    LOG_ASSERT(active_config_ != std::nullopt);

    if (status != 0) {
      DLOG(ERROR) << "Failure creating data path. Tearing down the BIG now.";
      suspending_ = true;
      TerminateBig();
      return;
    }

    /* Look for the next BIS handle */
    auto handle_it = std::find_if(
        active_config_->connection_handles.begin(),
        active_config_->connection_handles.end(),
        [conn_hdl](const auto& handle) { return conn_hdl == handle; });
    LOG_ASSERT(handle_it != active_config_->connection_handles.end());
    handle_it = std::next(handle_it);

    if (handle_it == active_config_->connection_handles.end()) {
      /* It was the last BIS to set up - change state to streaming */
      SetState(State::STREAMING);
      callbacks_->OnStateMachineEvent(
          GetInstanceId(), GetState(),
          &sm_config_.codec_wrapper.GetLeAudioCodecConfiguration());
    } else {
      /* Note: We would feed a watchdog here if we had one */
      /* There are more BISes to set up data path for */
      TriggerIsoDatapathSetup(*handle_it);
    }
  }

  void OnRemoveIsoDataPath(uint8_t status, uint16_t conn_handle) override {
    LOG_ASSERT(active_config_ != std::nullopt);

    if (status != 0) {
      DLOG(ERROR) << "Failure removing data path. Tearing down the BIG now.";
      TerminateBig();
      return;
    }

    /* Look for the next BIS handle */
    auto handle_it = std::find_if(
        active_config_->connection_handles.begin(),
        active_config_->connection_handles.end(),
        [conn_handle](const auto& handle) { return conn_handle == handle; });
    LOG_ASSERT(handle_it != active_config_->connection_handles.end());
    handle_it = std::next(handle_it);

    if (handle_it == active_config_->connection_handles.end()) {
      /* It was the last one to set up - start tearing down the BIG */
      TerminateBig();
    } else {
      /* Note: We would feed a watchdog here if we had one */
      /* There are more BISes to tear down data path for */
      TriggerIsoDatapathTeardown(*handle_it);
    }
  }

  void TriggerIsoDatapathSetup(uint16_t conn_handle) {
    LOG_ASSERT(active_config_ != std::nullopt);

    /* Note: For the LC3 software encoding on the Host side, the coding format
     * should be set to 'Transparent' and no codec configuration shall be sent
     * to the controller. 'codec_id_company' and 'codec_id_vendor' shall be
     * ignored if 'codec_id_format' is not set to 'Vendor'.
     */
    auto codec_id = sm_config_.codec_wrapper.GetLeAudioCodecId();
    uint8_t hci_coding_format =
        (codec_id.coding_format == le_audio::types::kLeAudioCodingFormatLC3)
            ? bluetooth::hci::kIsoCodingFormatTransparent
            : bluetooth::hci::kIsoCodingFormatVendorSpecific;
    bluetooth::hci::iso_manager::iso_data_path_params param = {
        .data_path_dir = bluetooth::hci::iso_manager::kIsoDataPathDirectionIn,
        .data_path_id = bluetooth::hci::iso_manager::kIsoDataPathHci,
        .codec_id_format = hci_coding_format,
        .codec_id_company = codec_id.vendor_company_id,
        .codec_id_vendor = codec_id.vendor_codec_id,
        /* TODO: Implement HCI command to get the controller delay */
        .controller_delay = 0x00000000,
    };
    if (codec_id.coding_format != le_audio::types::kLeAudioCodingFormatLC3)
      param.codec_conf = sm_config_.codec_wrapper.GetCodecSpecData();

    IsoManager::GetInstance()->SetupIsoDataPath(conn_handle, std::move(param));
  }

  void TriggerIsoDatapathTeardown(uint16_t conn_handle) {
    LOG(INFO) << __func__;
    LOG_ASSERT(active_config_ != std::nullopt);

    SetMuted(true);
    IsoManager::GetInstance()->RemoveIsoDataPath(
        conn_handle, bluetooth::hci::iso_manager::kIsoDataPathDirectionIn);
  }

  void HandleHciEvent(uint16_t event, void* data) override {
    switch (event) {
      case HCI_BLE_CREATE_BIG_CPL_EVT: {
        auto* evt = static_cast<big_create_cmpl_evt*>(data);

        if (evt->big_id != GetInstanceId()) {
          LOG(ERROR) << __func__ << " State=" << GetState()
                     << " Event=" << +event
                     << " Unknown big, big_id= " << +evt->big_id;
          break;
        }

        if (evt->status == 0x00) {
          DLOG(INFO) << __func__
                     << " BIG create BIG cmpl, big_id=" << +evt->big_id;
          active_config_ = {
              .status = evt->status,
              .big_id = evt->big_id,
              .big_sync_delay = evt->big_sync_delay,
              .transport_latency_big = evt->transport_latency_big,
              .phy = evt->phy,
              .nse = evt->nse,
              .bn = evt->bn,
              .pto = evt->pto,
              .irc = evt->irc,
              .max_pdu = evt->max_pdu,
              .iso_interval = evt->iso_interval,
              .connection_handles = evt->conn_handles,
          };
          TriggerIsoDatapathSetup(evt->conn_handles[0]);
        } else {
          LOG(ERROR) << __func__ << " State=" << GetState()
                     << " Event=" << +event
                     << ". Unable to create big, big_id= " << +evt->big_id
                     << ", status=" << +evt->status;
        }
      } break;
      case HCI_BLE_TERM_BIG_CPL_EVT: {
        auto* evt = static_cast<big_terminate_cmpl_evt*>(data);

        DLOG(INFO) << __func__
                   << " BIG terminate BIG cmpl, reason=" << int{evt->reason}
                   << " big_id=" << int{evt->big_id};

        if (evt->big_id != GetInstanceId()) {
          LOG(ERROR) << __func__ << " State=" << GetState()
                     << " Event=" << +event
                     << " Unknown instance= " << +evt->big_id;
          break;
        }

        active_config_ = std::nullopt;

        /* Go back to configured if BIG is inactive (we are still announcing) */
        SetState(State::CONFIGURED);

        /* Check if we got this HCI event due to STOP or SUSPEND message. */
        if (suspending_) {
          callbacks_->OnStateMachineEvent(GetInstanceId(), GetState(), evt);
          suspending_ = false;
        } else {
          DisableAnnouncement();
        }
      } break;
      default:
        LOG(ERROR) << __func__ << " State=" << GetState()
                   << " Unknown event= " << int{event};
        break;
    }
  }
};

IBroadcastStateMachineCallbacks* BroadcastStateMachineImpl::callbacks_ =
    nullptr;
base::WeakPtr<BleAdvertisingManager> BroadcastStateMachineImpl::advertiser_if_;
} /* namespace */

std::unique_ptr<BroadcastStateMachine> BroadcastStateMachine::CreateInstance(
    BroadcastStateMachineConfig msg) {
  return std::make_unique<BroadcastStateMachineImpl>(std::move(msg));
}

void BroadcastStateMachine::Initialize(
    IBroadcastStateMachineCallbacks* callbacks) {
  BroadcastStateMachineImpl::callbacks_ = callbacks;
  /* Get BLE advertiser interface */
  if (BleAdvertisingManager::IsInitialized()) {
    DLOG(INFO) << __func__ << " BleAdvertisingManager acquired";
    BroadcastStateMachineImpl::advertiser_if_ = BleAdvertisingManager::Get();
  } else {
    LOG(ERROR) << __func__ << " Could not acquire BleAdvertisingManager!";
    BroadcastStateMachineImpl::advertiser_if_ = nullptr;
  }
}

std::ostream& operator<<(std::ostream& os,
                         const BroadcastStateMachine::Message& state) {
  static const char* char_value_[BroadcastStateMachine::MESSAGE_COUNT] = {
      "START", "SUSPEND", "STOP"};
  os << char_value_[static_cast<uint8_t>(state)];
  return os;
}

std::ostream& operator<<(std::ostream& os,
                         const BroadcastStateMachine::State& state) {
  static const char* char_value_[BroadcastStateMachine::STATE_COUNT] = {
      "STOPPED", "CONFIGURING", "CONFIGURED", "STOPPING", "STREAMING"};
  os << char_value_[static_cast<uint8_t>(state)];
  return os;
}

std::ostream& operator<<(
    std::ostream& os,
    const le_audio::broadcaster::BroadcastStateMachine& machine) {
  os << "    Broadcast state machine: {"
     << "      State: " << machine.GetState()
     << "      Instance ID: " << +machine.GetInstanceId() << "\n"
     << "      Codec Config: " << machine.GetCodecConfig() << "\n";
  os << "      Broadcast ID: [";
  for (auto& el : machine.GetBroadcastId()) {
    os << std::hex << +el << ":";
  }
  os << "]}\n";
  return os;
}
