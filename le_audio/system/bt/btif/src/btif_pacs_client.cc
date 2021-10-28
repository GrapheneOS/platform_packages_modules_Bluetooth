/*
 * Copyright (c) 2020, The Linux Foundation. All rights reserved.
 */

/******************************************************************************
 *
 *  Copyright 2018 The Android Open Source Project
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at:
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 ******************************************************************************/

#include "bta_closure_api.h"
#include "bta_pacs_client_api.h"
#include "btif_common.h"
#include "btif_storage.h"

#include <base/bind.h>
#include <base/callback.h>
#include <base/location.h>
#include <base/logging.h>
#include <hardware/bluetooth.h>
#include <hardware/bt_pacs_client.h>
#include "osi/include/thread.h"

using base::Bind;
using base::Unretained;
using bluetooth::bap::pacs::PacsClient;
using bluetooth::bap::pacs::CodecConfig;
using bluetooth::bap::pacs::ConnectionState;
using bluetooth::bap::pacs::PacsClientCallbacks;
using bluetooth::bap::pacs::PacsClientInterface;


namespace {

class PacsClientInterfaceImpl;
std::unique_ptr<PacsClientInterface> PacsClientInstance;

class PacsClientInterfaceImpl
    : public PacsClientInterface,
      public PacsClientCallbacks {
  ~PacsClientInterfaceImpl() = default;

  void Init(PacsClientCallbacks* callbacks) override {
    DVLOG(2) << __func__;
    this->callbacks = callbacks;

    do_in_bta_thread(
        FROM_HERE,
        Bind(&PacsClient::Initialize, this));
  }

  void OnInitialized(int status, int client_id) override {
    do_in_jni_thread(FROM_HERE, Bind(&PacsClientCallbacks::OnInitialized,
                                     Unretained(callbacks), status,
                                     client_id));
  }

  void OnConnectionState(const RawAddress& address,
                         ConnectionState state) override {
    DVLOG(2) << __func__ << " address: " << address;
    do_in_jni_thread(FROM_HERE, Bind(&PacsClientCallbacks::OnConnectionState,
                                     Unretained(callbacks), address, state));
  }

  void OnAudioContextAvailable(const RawAddress& address,
                        uint32_t available_contexts) override {
    do_in_jni_thread(FROM_HERE,
                     Bind(&PacsClientCallbacks::OnAudioContextAvailable,
                          Unretained(callbacks),
                          address, available_contexts));
  }

  void OnSearchComplete(int status,
                        const RawAddress& address,
                        std::vector<CodecConfig> sink_pac_records,
                        std::vector<CodecConfig> src_pac_records,
                        uint32_t sink_locations,
                        uint32_t src_locations,
                        uint32_t available_contexts,
                        uint32_t supported_contexts) override {
    do_in_jni_thread(FROM_HERE, Bind(&PacsClientCallbacks::OnSearchComplete,
                                     Unretained(callbacks),
                                     status,
                                     address,
                                     sink_pac_records,
                                     src_pac_records,
                                     sink_locations,
                                     src_locations,
                                     available_contexts,
                                     supported_contexts));
  }

  void Connect(uint16_t client_id, const RawAddress& address) override {
    do_in_bta_thread(FROM_HERE, Bind(&PacsClient::Connect,
                                      Unretained(PacsClient::Get()),
                                      client_id, address, false));
  }

  void Disconnect(uint16_t client_id, const RawAddress& address) override {
    do_in_bta_thread(FROM_HERE, Bind(&PacsClient::Disconnect,
                                      Unretained(PacsClient::Get()),
                                      client_id, address));
  }

  void StartDiscovery(uint16_t client_id,
                                const RawAddress& address) override {
    do_in_bta_thread(FROM_HERE, Bind(&PacsClient::StartDiscovery,
                                      Unretained(PacsClient::Get()),
                                      client_id, address));
  }

  void GetAvailableAudioContexts(uint16_t client_id,
                                    const RawAddress& address) override {
    do_in_bta_thread(FROM_HERE, Bind(&PacsClient::GetAudioAvailability,
                                      Unretained(PacsClient::Get()),
                                      client_id, address));
  }

  void Cleanup(uint16_t client_id) override {
    DVLOG(2) << __func__;
    do_in_bta_thread(FROM_HERE, Bind(&PacsClient::CleanUp, client_id));
  }

 private:
  PacsClientCallbacks* callbacks;
};

}  // namespace

PacsClientInterface* btif_pacs_client_get_interface() {
  if (!PacsClientInstance)
    PacsClientInstance.reset(new PacsClientInterfaceImpl());

  return PacsClientInstance.get();
}
