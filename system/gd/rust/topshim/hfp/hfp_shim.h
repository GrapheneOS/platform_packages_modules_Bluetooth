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

#pragma once

#include <memory>

#include "btif/include/btif_hf.h"
#include "include/hardware/bluetooth_headset_callbacks.h"
#include "types/raw_address.h"

namespace bluetooth {
namespace topshim {
namespace rust {

class HfpIntf {
 public:
  HfpIntf(headset::Interface* intf) : intf_(intf){};

  int init();
  uint32_t connect(RawAddress addr);
  int connect_audio(RawAddress addr, bool sco_offload, bool force_cvsd);
  int set_active_device(RawAddress addr);
  int set_volume(int8_t volume, RawAddress addr);
  uint32_t disconnect(RawAddress addr);
  int disconnect_audio(RawAddress addr);
  void cleanup();

 private:
  headset::Interface* intf_;
};

std::unique_ptr<HfpIntf> GetHfpProfile(const unsigned char* btif);

}  // namespace rust
}  // namespace topshim
}  // namespace bluetooth
