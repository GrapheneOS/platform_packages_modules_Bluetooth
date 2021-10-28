/*
 * Copyright (c) 2020-2021, The Linux Foundation. All rights reserved.
 */

/*
 * Copyright 2018 The Android Open Source Project
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

/* CC Interface */
#define LOG_TAG "bt_btif_cc"

#include "bt_target.h"
#include "bta_closure_api.h"
#include "btif_common.h"
#include "btif_storage.h"
#include "bta_cc_api.h"

#include <base/at_exit.h>
#include <base/bind.h>
#include <base/threading/thread.h>
#include <base/callback.h>
#include <hardware/bluetooth.h>
#include <hardware/bluetooth_callcontrol_callbacks.h>
#include <hardware/bluetooth_callcontrol_interface.h>

using base::Bind;
using base::Unretained;
using base::Owned;
using bluetooth::Uuid;
using std::vector;

using base::Unretained;
using bluetooth::call_control::CallControllerInterface;
using bluetooth::call_control::CallControllerCallbacks;

namespace {
class CallControllerInterfaceImpl;
std::unique_ptr<CallControllerInterface> CallControllerInstance;

class CallControllerInterfaceImpl
  : public CallControllerInterface, public CallControllerCallbacks {
  ~CallControllerInterfaceImpl() = default;

 bt_status_t Init(CallControllerCallbacks* callbacks, Uuid uuid, int max_ccs_clients,
                              bool inband_ringing_enabled) override {

    LOG(INFO) << __func__ ;
    this->callbacks = callbacks;
    do_in_bta_thread(FROM_HERE,Bind(&CallController::Initialize,
           this, uuid,max_ccs_clients, inband_ringing_enabled));
    return BT_STATUS_SUCCESS;
 }

 bt_status_t UpdateBearerName(uint8_t* operator_str) {

    LOG(INFO) << __func__ << ": bearer name " << operator_str;
    uint8_t* bName = (uint8_t*)malloc(sizeof(uint8_t)*strlen((char*)operator_str)+1);
    if (bName != NULL) {
      memcpy(bName, operator_str, strlen((char*)operator_str)+1);
      do_in_bta_thread(FROM_HERE,Bind(&CallController::BearerInfoName,
              Unretained(CallController::Get()), bName));
      free(bName);
    }
    return BT_STATUS_SUCCESS;
 }

 void Cleanup() {
   LOG(INFO) << __func__ ;
   do_in_bta_thread(FROM_HERE,Bind(&CallController::CleanUp));
 }

bt_status_t UpdateBearerTechnology(int bearer_tech) {

  LOG(INFO) << __func__ << ": " << bearer_tech;
  do_in_bta_thread(FROM_HERE,Bind(&CallController::UpdateBearerTechnology,
                Unretained(CallController::Get()), bearer_tech));
  return BT_STATUS_SUCCESS;
}

bt_status_t  UpdateSupportedBearerList(uint8_t* supportedbearer_list) {

 LOG(INFO) << __func__ << ": " << supportedbearer_list;
 uint8_t* sList = (uint8_t*)malloc(sizeof(uint8_t)*strlen((char*)supportedbearer_list)+1);
 if (sList != NULL) {
   memcpy(sList, supportedbearer_list, strlen((char*)supportedbearer_list)+1);
   do_in_bta_thread(FROM_HERE,Bind(&CallController::UpdateSupportedBearerList,
        Unretained(CallController::Get()), sList));
   free(sList);
 }
 return BT_STATUS_SUCCESS;

}
bt_status_t UpdateStatusFlags(uint8_t status_flag) {
  LOG(INFO) << __func__ << ": " << status_flag;
  do_in_bta_thread(FROM_HERE,Bind(&CallController::UpdateStatusFlags,
            Unretained(CallController::Get()), status_flag));
  return BT_STATUS_SUCCESS;
}

bt_status_t UpdateSignalStatus(int signal) {

 LOG(INFO) << __func__ << ": " << signal;
 do_in_bta_thread(FROM_HERE,Bind(&CallController::UpdateBearerSignalStrength,
           Unretained(CallController::Get()), signal));
 return BT_STATUS_SUCCESS;

}

bt_status_t CallControlOptionalOpSupported(int feature) {

 LOG(INFO) << __func__ << ": " << feature;
 do_in_bta_thread(FROM_HERE,Bind(&CallController::CallControlOptionalOpSupported,
           Unretained(CallController::Get()), feature));
 return BT_STATUS_SUCCESS;
}

bt_status_t CallState(int len, std::vector<uint8_t> call_state_list) {

 LOG(INFO) << __func__ << ": ";
    do_in_bta_thread(FROM_HERE,Bind(&CallController::CallState,
           Unretained(CallController::Get()), len, std::move(call_state_list)));
 return BT_STATUS_SUCCESS;

}

void UpdateIncomingCall(int index, uint8_t* Uri) {
  LOG(INFO) << __func__ << ": " <<Uri;
  uint8_t* callUri = (uint8_t*)malloc(sizeof(uint8_t)*strlen((char*)Uri)+1);
  if (callUri != NULL) {
    memcpy(callUri, Uri, strlen((char*)Uri)+1);
    do_in_bta_thread(FROM_HERE,Bind(&CallController::UpdateIncomingCall,
           Unretained(CallController::Get()), index, callUri));
    free(callUri);
  }
}

void IncomingCallTargetUri(int index, uint8_t* target_uri) {
  LOG(INFO) << __func__ << ": " <<target_uri;
  uint8_t* callUri = (uint8_t*)malloc(sizeof(uint8_t)*strlen((char*)target_uri)+1);
  if (callUri != NULL) {
    memcpy(callUri, target_uri, strlen((char*)target_uri)+1);

    do_in_bta_thread(FROM_HERE,Bind(&CallController::UpdateIncomingCallTargetUri,
           Unretained(CallController::Get()), index, callUri));
    free(callUri);
  }
}

void Disconnect(const RawAddress& address) {

 LOG(INFO) << __func__ << ": " <<address;
 do_in_bta_thread(FROM_HERE,Bind(&CallController::Disconnect,
           Unretained(CallController::Get()), address));
 return;

}

void ContentControlId(uint32_t ccid) {
  LOG(INFO) << __func__ << ": " << ccid;
  do_in_bta_thread(FROM_HERE,
     Bind(&CallController::ContentControlId, Unretained(CallController::Get()), ccid));
}

bt_status_t CallControlResponse(uint8_t op, uint8_t index,  uint32_t status, const RawAddress& address) {

 LOG(INFO) << __func__ << ": ";
 do_in_bta_thread(FROM_HERE,Bind(&CallController::CallControlResponse,
       Unretained(CallController::Get()), op, index, status, address));
 return BT_STATUS_SUCCESS;
}

void SetActiveDevice(const RawAddress& address, int set_id) override {
    LOG(INFO) << __func__ << ": set_id" << set_id<< ": device"<< address;
    do_in_bta_thread(FROM_HERE,
          Bind(&CallController::SetActiveDevice, Unretained(CallController::Get()), address, set_id));
}

void ConnectionStateCallback(uint8_t state, const RawAddress& address) override {

 LOG(INFO) << __func__ << ": device=" << address << " state=" << state;
    do_in_jni_thread(FROM_HERE, Bind(&CallControllerCallbacks::ConnectionStateCallback,
            Unretained(callbacks), state, address));

}

void CallControlCallback(uint8_t op, std::vector<int32_t> indicies, int count, std::vector<uint8_t> uri_data, const RawAddress& address) override {

  LOG(INFO) << __func__ << ": device=" << address << " operation=" << op;

  do_in_jni_thread(FROM_HERE, Bind(&CallControllerCallbacks::CallControlCallback,
             Unretained(callbacks), op, std::move(indicies), count, std::move(uri_data), address));
}

 void CallControlInitializedCallback(uint8_t state) override {
   LOG(INFO) << __func__ << ": state=" << state;
   do_in_jni_thread(FROM_HERE, Bind(&CallControllerCallbacks::CallControlInitializedCallback,
              Unretained(callbacks), state));
 }

 private:
   CallControllerCallbacks* callbacks;
  };
}//namespace

const CallControllerInterface* btif_cc_server_get_interface(void) {
   LOG(INFO) << __func__;
   if (!CallControllerInstance)
     CallControllerInstance.reset(new CallControllerInterfaceImpl());
   return CallControllerInstance.get();
}
