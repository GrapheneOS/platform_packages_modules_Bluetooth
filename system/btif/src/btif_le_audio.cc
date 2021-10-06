/*
 * Copyright 2019 HIMSA II K/S - www.himsa.com. Represented by EHIMA -
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

#include <hardware/bluetooth.h>
#include <hardware/bt_le_audio.h>

#include <vector>

#include "audio_hal_interface/hal_version_manager.h"
#include "bta_le_audio_api.h"
#include "btif_common.h"
#include "btif_storage.h"
#include "stack/include/btu.h"

using base::Bind;
using base::Unretained;
using bluetooth::le_audio::ConnectionState;
using bluetooth::le_audio::GroupNodeStatus;
using bluetooth::le_audio::GroupStatus;
using bluetooth::le_audio::LeAudioClientCallbacks;
using bluetooth::le_audio::LeAudioClientInterface;

namespace {
class LeAudioClientInterfaceImpl;
std::unique_ptr<LeAudioClientInterface> leAudioInstance;

class LeAudioClientInterfaceImpl : public LeAudioClientInterface,
                                   public LeAudioClientCallbacks {
  ~LeAudioClientInterfaceImpl() = default;

  void OnConnectionState(ConnectionState state,
                         const RawAddress& address) override {
    do_in_jni_thread(FROM_HERE, Bind(&LeAudioClientCallbacks::OnConnectionState,
                                     Unretained(callbacks), state, address));
  }

  void OnGroupStatus(int group_id, GroupStatus group_status) override {
    do_in_jni_thread(FROM_HERE,
                     Bind(&LeAudioClientCallbacks::OnGroupStatus,
                          Unretained(callbacks), group_id, group_status));
  }

  void OnGroupNodeStatus(const RawAddress& addr, int group_id,
                         GroupNodeStatus node_status) override {
    do_in_jni_thread(FROM_HERE,
                     Bind(&LeAudioClientCallbacks::OnGroupNodeStatus,
                          Unretained(callbacks), addr, group_id, node_status));
  }

  void OnAudioConf(uint8_t direction, int group_id, uint32_t snk_audio_location,
                   uint32_t src_audio_location, uint16_t avail_cont) override {
    do_in_jni_thread(FROM_HERE,
                     Bind(&LeAudioClientCallbacks::OnAudioConf,
                          Unretained(callbacks), direction, group_id,
                          snk_audio_location, src_audio_location, avail_cont));
  }

  void Initialize(LeAudioClientCallbacks* callbacks) override {
    this->callbacks = callbacks;
    do_in_main_thread(
        FROM_HERE,
        Bind(&LeAudioClient::Initialize, this,
             jni_thread_wrapper(FROM_HERE,
                                Bind(&btif_storage_load_bonded_leaudio)),
             base::Bind([]() -> bool {
               return bluetooth::audio::HalVersionManager::GetHalVersion() ==
                      bluetooth::audio::BluetoothAudioHalVersion::VERSION_2_1;
             })));
  }

  void Cleanup(void) override {
    DVLOG(2) << __func__;
    do_in_main_thread(FROM_HERE, Bind(&LeAudioClient::Cleanup));
  }

  void RemoveDevice(const RawAddress& address) override {
    DVLOG(2) << __func__ << " address: " << address;
    do_in_main_thread(FROM_HERE,
                      Bind(&LeAudioClient::RemoveDevice,
                           Unretained(LeAudioClient::Get()), address));

    do_in_jni_thread(FROM_HERE, Bind(&btif_storage_remove_leaudio, address));
  }

  void Connect(const RawAddress& address) override {
    DVLOG(2) << __func__ << " address: " << address;
    do_in_main_thread(FROM_HERE,
                      Bind(&LeAudioClient::Connect,
                           Unretained(LeAudioClient::Get()), address));
  }

  void Disconnect(const RawAddress& address) override {
    DVLOG(2) << __func__ << " address: " << address;
    do_in_main_thread(FROM_HERE,
                      Bind(&LeAudioClient::Disconnect,
                           Unretained(LeAudioClient::Get()), address));
    do_in_jni_thread(
        FROM_HERE, Bind(&btif_storage_set_leaudio_autoconnect, address, false));
  }

  void GroupAddNode(const int group_id, const RawAddress& address) override {
    DVLOG(2) << __func__ << " group_id: " << group_id
             << " address: " << address;
    do_in_main_thread(
        FROM_HERE, Bind(&LeAudioClient::GroupAddNode,
                        Unretained(LeAudioClient::Get()), group_id, address));
  }

  void GroupRemoveNode(const int group_id, const RawAddress& address) override {
    DVLOG(2) << __func__ << " group_id: " << group_id
             << " address: " << address;
    do_in_main_thread(
        FROM_HERE, Bind(&LeAudioClient::GroupRemoveNode,
                        Unretained(LeAudioClient::Get()), group_id, address));
  }

  void GroupSetActive(const int group_id) override {
    DVLOG(2) << __func__ << " group_id: " << group_id;
    do_in_main_thread(FROM_HERE,
                      Bind(&LeAudioClient::GroupSetActive,
                           Unretained(LeAudioClient::Get()), group_id));
  }

 private:
  LeAudioClientCallbacks* callbacks;
};

} /* namespace */

LeAudioClientInterface* btif_le_audio_get_interface() {
  if (!leAudioInstance) {
    leAudioInstance.reset(new LeAudioClientInterfaceImpl());
  }

  return leAudioInstance.get();
}
