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
#include "types/raw_address.h"

namespace bluetooth::headset {
class DBusHeadsetCallbacks : public Callbacks {
 public:
  static Callbacks* GetInstance() {
    static Callbacks* instance = new DBusHeadsetCallbacks();
    return instance;
  }

  void ConnectionStateCallback(
      [[maybe_unused]] bthf_connection_state_t state, [[maybe_unused]] RawAddress* bd_addr) override {}

  void AudioStateCallback([[maybe_unused]] bthf_audio_state_t state, [[maybe_unused]] RawAddress* bd_addr) override {}

  void VoiceRecognitionCallback([[maybe_unused]] bthf_vr_state_t state, [[maybe_unused]] RawAddress* bd_addr) override {
  }

  void AnswerCallCallback([[maybe_unused]] RawAddress* bd_addr) override {}

  void HangupCallCallback([[maybe_unused]] RawAddress* bd_addr) override {}

  void VolumeControlCallback(
      [[maybe_unused]] bthf_volume_type_t type,
      [[maybe_unused]] int volume,
      [[maybe_unused]] RawAddress* bd_addr) override {}

  void DialCallCallback([[maybe_unused]] char* number, [[maybe_unused]] RawAddress* bd_addr) override {}

  void DtmfCmdCallback([[maybe_unused]] char tone, [[maybe_unused]] RawAddress* bd_addr) override {}

  void NoiseReductionCallback([[maybe_unused]] bthf_nrec_t nrec, [[maybe_unused]] RawAddress* bd_addr) override {}

  void WbsCallback([[maybe_unused]] bthf_wbs_config_t wbs, [[maybe_unused]] RawAddress* bd_addr) override {}

  void AtChldCallback([[maybe_unused]] bthf_chld_type_t chld, [[maybe_unused]] RawAddress* bd_addr) override {}

  void AtCnumCallback([[maybe_unused]] RawAddress* bd_addr) override {}

  void AtCindCallback([[maybe_unused]] RawAddress* bd_addr) override {}

  void AtCopsCallback([[maybe_unused]] RawAddress* bd_addr) override {}

  void AtClccCallback([[maybe_unused]] RawAddress* bd_addr) override {}

  void UnknownAtCallback([[maybe_unused]] char* at_string, [[maybe_unused]] RawAddress* bd_addr) override {}

  void KeyPressedCallback([[maybe_unused]] RawAddress* bd_addr) override {}

  void AtBindCallback([[maybe_unused]] char* at_string, [[maybe_unused]] RawAddress* bd_addr) override {}

  void AtBievCallback(
      [[maybe_unused]] bthf_hf_ind_type_t ind_id,
      [[maybe_unused]] int ind_value,
      [[maybe_unused]] RawAddress* bd_addr) override {}

  void AtBiaCallback(
      [[maybe_unused]] bool service,
      [[maybe_unused]] bool roam,
      [[maybe_unused]] bool signal,
      [[maybe_unused]] bool battery,
      [[maybe_unused]] RawAddress* bd_addr) override {}
};
}  // namespace bluetooth::headset

namespace bluetooth {
namespace topshim {
namespace rust {
namespace internal {
static HfpIntf* g_hfpif;

}  // namespace internal

int HfpIntf::init() {
  return intf_->Init(headset::DBusHeadsetCallbacks::GetInstance(), 1, false);
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
