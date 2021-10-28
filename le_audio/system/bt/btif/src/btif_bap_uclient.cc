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
#include "bta_bap_uclient_api.h"
#include "btif_common.h"
#include "btif_storage.h"
#include "osi/include/thread.h"
#include "btif_bap_codec_utils.h"

#include "osi/include/properties.h"

extern void do_in_bta_thread(const base::Location& from_here,
                             const base::Closure& task);
#include <base/bind.h>
#include <base/callback.h>
#include <base/location.h>
#include <base/logging.h>
#include <hardware/bluetooth.h>
#include <hardware/bt_pacs_client.h>
#include <hardware/bt_bap_uclient.h>
#include "btif_api.h"

using base::Bind;
using base::Unretained;
using bluetooth::bap::ucast::UcastClient;
using bluetooth::bap::pacs::CodecConfig;
using bluetooth::bap::pacs::ConnectionState;
using bluetooth::bap::ucast::UcastClientCallbacks;
using bluetooth::bap::ucast::UcastClientInterface;
using bluetooth::bap::ucast::StreamConnect;
using bluetooth::bap::ucast::StreamType;
using bluetooth::bap::ucast::StreamStateInfo;
using bluetooth::bap::ucast::StreamConfigInfo;
using bluetooth::bap::ucast::StreamReconfig;

namespace bluetooth {
namespace bap {
namespace ucast {

class UcastClientInterfaceImpl;
static std::unique_ptr<UcastClientInterface> UcastClientInstance = nullptr;

class UcastClientInterfaceImpl
    : public UcastClientInterface,
      public UcastClientCallbacks {
  ~UcastClientInterfaceImpl() = default;
  void Init(UcastClientCallbacks* client_callbacks) override {
    if(is_initialized) {
      LOG(WARNING) << __func__ << " Already initialized, return";
      return;
    }
    is_initialized = true;
    callbacks = client_callbacks;
    char value[PROPERTY_VALUE_MAX];
    if(property_get("persist.vendor.service.bt.bap.enable_ucast", value, "false")
                    && !strcmp(value, "true")) {
      LOG(INFO) << __func__ << " Registering PACS UUID ";
      btif_register_uuid_srvc_disc(Uuid::FromString("1850"));
      btif_register_uuid_srvc_disc(Uuid::FromString("184E"));
    }
    do_in_bta_thread( FROM_HERE, Bind(&UcastClient::Initialize, this));
  }

  void OnStreamState(const RawAddress &address,
                   std::vector<StreamStateInfo> streams_state_info) override {
    if(!is_initialized) return;
    do_in_jni_thread(FROM_HERE, Bind(&UcastClientCallbacks::OnStreamState,
                                     Unretained(callbacks), address,
                                     streams_state_info));
  }

  void OnStreamConfig(const RawAddress &address,
                std::vector<StreamConfigInfo> streams_config_info) override {
    if(!is_initialized) return;
    do_in_jni_thread(FROM_HERE, Bind(&UcastClientCallbacks::OnStreamConfig,
                                     Unretained(callbacks),
                                     address, streams_config_info));
  }

  void OnStreamAvailable(const RawAddress &address,
                      uint16_t src_audio_contexts,
                      uint16_t sink_audio_contexts) override {
    if(!is_initialized) return;
    do_in_jni_thread(FROM_HERE,
                     Bind(&UcastClientCallbacks::OnStreamAvailable,
                          Unretained(callbacks),
                          address, src_audio_contexts,
                          sink_audio_contexts));
  }

  void Reconfigure(const RawAddress& address,
                   std::vector<StreamReconfig> &streams_info) override {
    LOG(INFO) << __func__ << " " << address;
    if(!is_initialized) return;
    do_in_bta_thread(FROM_HERE, Bind(&UcastClient::Reconfigure,
                                      Unretained(UcastClient::Get()),
                                      address, streams_info));
  }

  void Start(const RawAddress& address,
             std::vector<StreamType> &streams_info) override {
    LOG(INFO) << __func__ << " " << address;
    if(!is_initialized) return;
    do_in_bta_thread(FROM_HERE, Bind(&UcastClient::Start,
                                      Unretained(UcastClient::Get()),
                                      address, streams_info));
  }

  void Connect(std::vector<RawAddress> &address, bool is_direct,
               std::vector<StreamConnect> &streams_info) override {
    for (auto it = address.begin(); it != address.end(); it++) {
      LOG(INFO) << __func__ << " " << (*it);
    }
    if(!is_initialized) return;
    do_in_bta_thread(FROM_HERE, Bind(&UcastClient::Connect,
                                      Unretained(UcastClient::Get()),
                                      address, is_direct, streams_info));
  }

  void Disconnect(const RawAddress& address,
                  std::vector<StreamType> &streams_info) override {
    LOG(INFO) << __func__ << " " << address;
    if(!is_initialized) return;
    do_in_bta_thread(FROM_HERE, Bind(&UcastClient::Disconnect,
                                      Unretained(UcastClient::Get()),
                                      address, streams_info));
  }

  void Stop(const RawAddress& address,
            std::vector<StreamType> &streams_info) override {
    LOG(INFO) << __func__ << " " << address;
    if(!is_initialized) return;
    do_in_bta_thread(FROM_HERE, Bind(&UcastClient::Stop,
                                      Unretained(UcastClient::Get()),
                                      address, streams_info));
  }

  void UpdateStream(const RawAddress& address,
                    std::vector<StreamUpdate> &update_streams) override {
    LOG(INFO) << __func__ << " " << address;
    if(!is_initialized) return;
    do_in_bta_thread(FROM_HERE, Bind(&UcastClient::UpdateStream,
                                      Unretained(UcastClient::Get()),
                                      address, update_streams));
  }

  void Cleanup() override {
    if(!is_initialized) return;
    do_in_bta_thread(FROM_HERE, Bind(&UcastClient::CleanUp));
    is_initialized = false;
  }

 private:
  bool is_initialized = false;;
  UcastClientCallbacks* callbacks;
};

UcastClientInterface* btif_bap_uclient_get_interface() {
  if (!UcastClientInstance)
    UcastClientInstance.reset(new UcastClientInterfaceImpl());
  return UcastClientInstance.get();
}

}  // namespace ucast
}  // namespace bap
}  // namespace bluetooth
