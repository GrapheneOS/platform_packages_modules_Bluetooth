/*
 * Copyright (C) 2021 The Android Open Source Project
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

#include "gd/rust/topshim/hfp/hfp_shim.h"

#include "btif/include/btif_hf.h"
#include "gd/os/log.h"
#include "include/hardware/bt_hf.h"
#include "src/profiles/hfp.rs.h"
#include "types/raw_address.h"

namespace rusty = ::bluetooth::topshim::rust;

namespace bluetooth {
namespace topshim {
namespace rust {
namespace internal {
static HfpIntf* g_hfpif;

static void connection_state_cb(bluetooth::headset::bthf_connection_state_t state, RawAddress* addr) {
  rusty::hfp_connection_state_callback(state, *addr);
}

static void audio_state_cb(bluetooth::headset::bthf_audio_state_t state, RawAddress* addr) {
  rusty::hfp_audio_state_callback(state, *addr);
}

static void volume_update_cb(uint8_t volume, RawAddress* addr) {
  rusty::hfp_volume_update_callback(volume, *addr);
}

static void battery_level_update_cb(uint8_t battery_level, RawAddress* addr) {
  rusty::hfp_battery_level_update_callback(battery_level, *addr);
}
}  // namespace internal

class DBusHeadsetCallbacks : public headset::Callbacks {
 public:
  static Callbacks* GetInstance(headset::Interface* headset) {
    static Callbacks* instance = new DBusHeadsetCallbacks(headset);
    return instance;
  }

  DBusHeadsetCallbacks(headset::Interface* headset) : headset_(headset) {
    call_status = 0;
  };

  // headset::Callbacks
  void ConnectionStateCallback(headset::bthf_connection_state_t state, RawAddress* bd_addr) override {
    LOG_INFO("ConnectionStateCallback from %s", ADDRESS_TO_LOGGABLE_CSTR(*bd_addr));
    topshim::rust::internal::connection_state_cb(state, bd_addr);
  }

  void AudioStateCallback(headset::bthf_audio_state_t state, RawAddress* bd_addr) override {
    LOG_INFO("AudioStateCallback %u from %s", state, ADDRESS_TO_LOGGABLE_CSTR(*bd_addr));
    topshim::rust::internal::audio_state_cb(state, bd_addr);

    switch (state) {
      case headset::bthf_audio_state_t::BTHF_AUDIO_STATE_CONNECTED:
        SetCallStatus(1, bd_addr);
        return;
      case headset::bthf_audio_state_t::BTHF_AUDIO_STATE_DISCONNECTED:
        SetCallStatus(0, bd_addr);
        return;
      default:
        return;
    }
  }

  void VoiceRecognitionCallback(
      [[maybe_unused]] headset::bthf_vr_state_t state, [[maybe_unused]] RawAddress* bd_addr) override {}

  void AnswerCallCallback([[maybe_unused]] RawAddress* bd_addr) override {}

  void HangupCallCallback([[maybe_unused]] RawAddress* bd_addr) override {}

  void VolumeControlCallback(headset::bthf_volume_type_t type, int volume, RawAddress* bd_addr) override {
    if (type != headset::bthf_volume_type_t::BTHF_VOLUME_TYPE_SPK || volume < 0) return;
    if (volume > 15) volume = 15;
    LOG_INFO("VolumeControlCallback %d from %s", volume, ADDRESS_TO_LOGGABLE_CSTR(*bd_addr));
    topshim::rust::internal::volume_update_cb(volume, bd_addr);
  }

  void DialCallCallback([[maybe_unused]] char* number, [[maybe_unused]] RawAddress* bd_addr) override {}

  void DtmfCmdCallback([[maybe_unused]] char tone, [[maybe_unused]] RawAddress* bd_addr) override {}

  void NoiseReductionCallback(
      [[maybe_unused]] headset::bthf_nrec_t nrec, [[maybe_unused]] RawAddress* bd_addr) override {}

  void WbsCallback(headset::bthf_wbs_config_t wbs, RawAddress* addr) override {
    LOG_INFO("WbsCallback %d from %s", wbs, ADDRESS_TO_LOGGABLE_CSTR(*addr));
    rusty::hfp_caps_update_callback(wbs == headset::BTHF_WBS_YES, *addr);
  }

  void AtChldCallback([[maybe_unused]] headset::bthf_chld_type_t chld, [[maybe_unused]] RawAddress* bd_addr) override {}

  void AtCnumCallback([[maybe_unused]] RawAddress* bd_addr) override {}

  void AtCindCallback(RawAddress* bd_addr) override {
    // This is required to setup the SLC, the format of the response should be
    // +CIND: <call>,<callsetup>,<service>,<signal>,<roam>,<battery>,<callheld>
    LOG_WARN("Respond +CIND: 0,0,1,5,0,5,0 to AT+CIND? from %s",
             ADDRESS_TO_LOGGABLE_CSTR(*bd_addr));

    // headset::Interface::CindResponse's parameters are similar but different
    // from the actual CIND response. It will construct the final response for
    // you based on the arguments you provide.
    // CindResponse(network_service_availability, active_call_num,
    //              held_call_num, callsetup_state, signal_strength,
    //              roam_state, battery_level, bd_addr);
    headset_->CindResponse(1, 0, 0, headset::BTHF_CALL_STATE_IDLE, 5, 0, 5, bd_addr);
  }

  void AtCopsCallback(RawAddress* bd_addr) override {
    LOG_WARN("Respond +COPS: 0 to AT+COPS? from %s",
             ADDRESS_TO_LOGGABLE_CSTR(*bd_addr));
    headset_->CopsResponse("", bd_addr);
  }

  void AtClccCallback(RawAddress* bd_addr) override {
    // Reply +CLCC:<idx>,<dir>,<status>,<mode>,<mprty>[,<number>,<type>] if
    // there is an active audio connection. Simply rely OK otherwise.
    // This is required for some headsets to start to send actual data to AG.
    if (call_status)
      headset_->ClccResponse(
          /*index=*/1,
          /*dir=*/headset::BTHF_CALL_DIRECTION_OUTGOING,
          /*state=*/headset::BTHF_CALL_STATE_ACTIVE,
          /*mode=*/headset::BTHF_CALL_TYPE_VOICE,
          /*multi_party=*/headset::BTHF_CALL_MPTY_TYPE_SINGLE,
          /*number=*/"",
          /*type=*/headset::BTHF_CALL_ADDRTYPE_UNKNOWN,
          bd_addr);

    headset_->AtResponse(headset::BTHF_AT_RESPONSE_OK, 0, bd_addr);
  }

  void UnknownAtCallback(char* at_string, RawAddress* bd_addr) override {
    LOG_WARN("Reply Error to UnknownAtCallback:%s", at_string);
    headset_->AtResponse(headset::BTHF_AT_RESPONSE_ERROR, 0, bd_addr);
  }

  void KeyPressedCallback([[maybe_unused]] RawAddress* bd_addr) override {}

  void AtBindCallback(char* at_string, RawAddress* bd_addr) override {
    LOG_WARN(
        "AT+BIND %s from addr %s: Bluetooth HF Indicators is not supported.",
        at_string,
        ADDRESS_TO_LOGGABLE_CSTR(*bd_addr));
  }

  void AtBievCallback(headset::bthf_hf_ind_type_t ind_id, int ind_value, RawAddress* bd_addr) override {
    switch (ind_id) {
      case headset::bthf_hf_ind_type_t::BTHF_HF_IND_ENHANCED_DRIVER_SAFETY:
        // We don't do anything with this but we do know what it is, send OK.
        headset_->AtResponse(headset::BTHF_AT_RESPONSE_OK, 0, bd_addr);
        break;
      case headset::bthf_hf_ind_type_t::BTHF_HF_IND_BATTERY_LEVEL_STATUS:
        topshim::rust::internal::battery_level_update_cb(ind_value, bd_addr);
        headset_->AtResponse(headset::BTHF_AT_RESPONSE_OK, 0, bd_addr);
        break;
      default:
        LOG_WARN(
            "AT+BIEV indicator %i with value %i from addr %s",
            ind_id,
            ind_value,
            ADDRESS_TO_LOGGABLE_CSTR(*bd_addr) );
        return;
    }
  }

  void AtBiaCallback(bool service, bool roam, bool signal, bool battery, RawAddress* bd_addr) override {
    LOG_WARN("AT+BIA=,,%d,%d,%d,%d,from addr %s", service, signal, roam,
             battery, ADDRESS_TO_LOGGABLE_CSTR(*bd_addr));
  }

 private:
  headset::Interface* headset_;
  int call_status;

  void SetCallStatus(int call, RawAddress* bd_addr) {
    if (call == call_status) return;

    if (call) {
      // This triggers a +CIEV command to set the call status for HFP
      // devices. It is required along with the SCO establishment for some
      // devices to provide sound.
      headset_->PhoneStateChange(
          /*num_active=*/1,
          /*num_held=*/0,
          /*call_setup_state=*/headset::bthf_call_state_t::BTHF_CALL_STATE_IDLE,
          /*number=*/"",
          /*type=*/(headset::bthf_call_addrtype_t)0,
          /*name=*/"",
          /*bd_addr=*/bd_addr);
    } else {
      headset_->PhoneStateChange(
          /*num_active=*/0,
          /*num_held=*/0,
          /*call_setup_state=*/headset::bthf_call_state_t::BTHF_CALL_STATE_IDLE,
          /*number=*/"",
          /*type=*/(headset::bthf_call_addrtype_t)0,
          /*name=*/"",
          /*bd_addr=*/bd_addr);
    }

    call_status = call;
  }
};

int HfpIntf::init() {
  return intf_->Init(DBusHeadsetCallbacks::GetInstance(intf_), 1, false);
}

uint32_t HfpIntf::connect(RawAddress addr) {
  return intf_->Connect(&addr);
}

int HfpIntf::connect_audio(RawAddress addr, bool sco_offload, bool force_cvsd) {
  intf_->SetScoOffloadEnabled(sco_offload);
  return intf_->ConnectAudio(&addr, force_cvsd);
}

int HfpIntf::set_active_device(RawAddress addr) {
  return intf_->SetActiveDevice(&addr);
}

int HfpIntf::set_volume(int8_t volume, RawAddress addr) {
  return intf_->VolumeControl(headset::bthf_volume_type_t::BTHF_VOLUME_TYPE_SPK, volume, &addr);
}

uint32_t HfpIntf::disconnect(RawAddress addr) {
  return intf_->Disconnect(&addr);
}

int HfpIntf::disconnect_audio(RawAddress addr) {
  return intf_->DisconnectAudio(&addr);
}

void HfpIntf::cleanup() {}

std::unique_ptr<HfpIntf> GetHfpProfile(const unsigned char* btif) {
  if (internal::g_hfpif) std::abort();

  const bt_interface_t* btif_ = reinterpret_cast<const bt_interface_t*>(btif);

  auto hfpif = std::make_unique<HfpIntf>(const_cast<headset::Interface*>(
      reinterpret_cast<const headset::Interface*>(btif_->get_profile_interface("handsfree"))));
  internal::g_hfpif = hfpif.get();

  return hfpif;
}

}  // namespace rust
}  // namespace topshim
}  // namespace bluetooth
