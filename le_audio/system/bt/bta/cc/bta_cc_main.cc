/*
 * Copyright (c) 2020-2021, The Linux Foundation. All rights reserved.
 */
/*
 * Copyright (C) 2003-2012 Broadcom Corporation
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
 */
/******************************************************************************
 *
 *  This is the main implementation file for the BTA  LE audio call Gateway.
 *
 ******************************************************************************/

#include "bta_api.h"
#include "btif_util.h"
#include "bt_target.h"
#include "bta_cc_api.h"
#include "gatts_ops_queue.h"
#include "btm_int.h"
#include "device/include/controller.h"

#include "osi/include/properties.h"
#include "osi/include/alarm.h"
#include "osi/include/allocator.h"
#include "osi/include/osi.h"
#include "bta_sys.h"

#include <vector>
#include <iostream>
#include <string.h>
#include <base/bind.h>
#include <base/callback.h>
#include <base/logging.h>
#include <base/location.h>
#include <hardware/bluetooth.h>

#include <base/strings/string_number_conversions.h>

#include <vector>
#include <string.h>
#include <algorithm>
#include <map>

#define MAX_URI_SIZE 50
#define STANDARD_BEARER_UCI "un000"
#define MS_IN_SEC 1000
#define CCS_DEFAULT_INDEX_VAL 0
#define DEFAULT_INDICIES_COUNT 1

using bluetooth::Uuid;
using bluetooth::bap::GattsOpsQueue;
class CallControllerImpl;
static CallControllerImpl *cc_instance;
static bool gIsTerminatedInitiatedFromClient = false;
static int gTerminateIntiatedIndex = 0;
static bool gIsActiveCC = false;

//GTBS UUID (4B: TBS, 4C: GTBS)
Uuid CALL_CONTROL_SERVER_UUID = Uuid::FromString("0000184C-0000-1000-8000-00805F9B34FB");

Uuid GTBS_CALL_BEARER_NAME_UUID = Uuid::FromString("00002bb3-0000-1000-8000-00805F9B34FB");
Uuid GTBS_BEARER_UCI = Uuid::FromString("00002bb4-0000-1000-8000-00805F9B34FB");
Uuid GTBS_BEARER_TECHNOLOGY = Uuid::FromString("00002bb5-0000-1000-8000-00805F9B34FB");
Uuid GTBS_BEARER_URI_SCHEMES = Uuid::FromString("00002bb6-0000-1000-8000-00805F9B34FB");
Uuid GTBS_SIGNAL_STRENGTH = Uuid::FromString("00002bb7-0000-1000-8000-00805F9B34FB");
Uuid GTBS_SIGNAL_STRENGTH_REPORTINTERVAL = Uuid::FromString("00002bb8-0000-1000-8000-00805F9B34FB");
Uuid GTBS_BEARER_LIST_CURRENT_CALLS = Uuid::FromString("00002bb9-0000-1000-8000-00805F9B34FB");
Uuid GTBS_CONTENT_CONTROLID = Uuid::FromString("00002bba-0000-1000-8000-00805F9B34FB");
Uuid GTBS_CALL_STATUS_FLAGS = Uuid::FromString("00002bbb-0000-1000-8000-00805F9B34FB");
Uuid GTBS_INCOMINGCALL_TARGET_URI = Uuid::FromString("00002bbc-0000-1000-8000-00805F9B34FB");
Uuid GTBS_CALL_STATE_UUID = Uuid::FromString("00002bbd-0000-1000-8000-00805F9B34FB");
Uuid GTBS_CALL_CONTROL_POINT_OPS = Uuid::FromString("00002bbe-0000-1000-8000-00805F9B34FB");
Uuid GTBS_CALL_CONTROL_POINT_OPTIONAL_OPS = Uuid::FromString("00002bbf-0000-1000-8000-00805F9B34FB");
Uuid GTBS_CALL_TERMINATION_REASON = Uuid::FromString("00002bc0-0000-1000-8000-00805F9B34FB");
Uuid GTBS_INCOMING_CALL = Uuid::FromString("00002bc1-0000-1000-8000-00805F9B34FB");
Uuid GTBS_CALL_FRIENDLY_NAME = Uuid::FromString("00002bc2-0000-1000-8000-00805F9B34FB");


Uuid GTBS_DESCRIPTOR_UUID = Uuid::FromString("00002902-0000-1000-8000-00805f9b34fb");

//global varibale
CcsControlServiceInfo_t ccsControlServiceInfo;
tCCS_CALL_STATE CallStateInfo;
std::map<uint8_t, tCCS_CALL_STATE> CallStatelist;
std::map<uint8_t, tCCS_BEARER_LIST_CURRENT_CALLS> BlccInfolist;
tCCS_CALL_CONTROL_POINT CallControllerOps;
tCCS_CALL_CONTROL_RESPONSE CallControllerResp;
tCCS_BEARER_LIST_CURRENT_CALLS BlccInfo;
tCCS_BEARER_PROVIDER_INFO  BearerProviderInfo;
tCCS_CONTENT_CONTROL_ID CcidInfo;
tCCS_STATUS_FLAGS StatusFlags;
tCCS_INCOMING_CALL IncomingCallInfo;
tCCS_INCOMING_CALL_URI IncomingCallTargetUri;
tCCS_TERM_REASON TerminationReason;
tCCS_FRIENDLY_NAME FriendlyName;
tCCS_SUPP_OPTIONAL_OPCODES SupportedOptionalOpcodes;

void BTCcCback(tBTA_GATTS_EVT event, tBTA_GATTS* param);
void ReverseByteOrder(unsigned char s[], int length);

typedef base::Callback<void(uint8_t status, int server_if,
                             std::vector<btgatt_db_element_t> service)>
                            OnGtbsServiceAdded;

static void OnGtbsServiceAddedCb(uint8_t status, int serverIf,
                              std::vector<btgatt_db_element_t> service);

const char* bta_cc_event_str(uint32_t event) {
  switch (event) {
        CASE_RETURN_STR(CCS_NONE_EVENT)
      CASE_RETURN_STR(CCS_INIT_EVENT)
      CASE_RETURN_STR(CCS_CLEANUP_EVENT)
      CASE_RETURN_STR(CCS_CALL_STATE_UPDATE)
      CASE_RETURN_STR(CCS_BEARER_NAME_UPDATE)
      CASE_RETURN_STR(CCS_BEARER_UCI_UPDATE)
      CASE_RETURN_STR(CCS_BEARER_URI_SCHEMES_SUPPORTED)
      CASE_RETURN_STR(CCS_UPDATE)
      CASE_RETURN_STR(CCS_OPT_OPCODES)
      CASE_RETURN_STR(CCS_BEARER_CURRENT_CALL_LIST_UPDATE)
      CASE_RETURN_STR(CCS_BEARER_SIGNAL_STRENGTH_UPDATE)
      CASE_RETURN_STR(CCS_SIGNAL_STRENGTH_REPORT_INTERVAL)
      CASE_RETURN_STR(CCS_STATUS_FLAGS_UPDATE)
      CASE_RETURN_STR(CCS_INCOMING_CALL_UPDATE)
      CASE_RETURN_STR(CCS_INCOMING_TARGET_URI_UPDATE)
      CASE_RETURN_STR(CCS_TERMINATION_REASON_UPDATE)
      CASE_RETURN_STR(CCS_BEARER_TECHNOLOGY_UPDATE)
      CASE_RETURN_STR(CCS_CCID_UPDATE)
      CASE_RETURN_STR(CCS_ACTIVE_DEVICE_UPDATE)
      CASE_RETURN_STR(CCS_CALL_CONTROL_RESPONSE)
      CASE_RETURN_STR(CCS_NOTIFY_ALL)
      CASE_RETURN_STR(CCS_WRITE_RSP)
      CASE_RETURN_STR(CCS_READ_RSP)
      CASE_RETURN_STR(CCS_DESCRIPTOR_WRITE_RSP)
      CASE_RETURN_STR(CCS_DESCRIPTOR_READ_RSP)
      CASE_RETURN_STR(CCS_CONNECTION)
      CASE_RETURN_STR(CCS_DISCONNECTION)
      CASE_RETURN_STR(CCS_CONNECTION_UPDATE)
      CASE_RETURN_STR(CCS_CONGESTION_UPDATE)
      CASE_RETURN_STR(CCS_PHY_UPDATE)
      CASE_RETURN_STR(CCS_MTU_UPDATE)
      CASE_RETURN_STR(CCS_SET_ACTIVE_DEVICE)
      CASE_RETURN_STR(CCS_CONNECTION_CLOSE_EVENT)
      CASE_RETURN_STR(CCS_BOND_STATE_CHANGE_EVENT)
    default:
      return (char*)"Unknown bta cc event";
  }
}


class CallControllerDevices {
 private:
   CallActiveDevice activeDevice;
   //int max_connection;
 public:
  bool Add(CallControllerDeviceList device) {
    if (devices.size() == MAX_CCS_CONNECTION) {
      return false;
    }
    if (FindByAddress(device.peer_bda) != nullptr) return false;

    device.DeviceStateHandlerPointer[CCS_DISCONNECTED] = DeviceStateDisconnectedHandler;
    device.DeviceStateHandlerPointer[CCS_CONNECTED] = DeviceStateConnectionHandler;
    device.signal_strength_report_interval = 0;
    std::string alarmName = device.peer_bda.ToString();
    alarmName.append("-CC_SSReportingTimer");

    device.signal_strength_reporting_timer = alarm_new_periodic(alarmName.c_str());
    devices.push_back(device);
    return true;
  }

  void Remove(RawAddress& address) {
    for (auto it = devices.begin(); it != devices.end();) {
      if (it->peer_bda != address) {
        ++it;
        continue;
      }
      if (it == devices.end()) {
          LOG(ERROR) << __func__ <<"no matching device";
        return;
      }
      //Cancel SSReporting timer
      if (it->signal_strength_report_interval != 0 &&
          it->signal_strength_reporting_timer != nullptr) {
          alarm_cancel(it->signal_strength_reporting_timer);
        alarm_free(it->signal_strength_reporting_timer);
      }

      it = devices.erase(it);

      return;
    }
  }

  void RemoveDevices() {
    for (auto it = devices.begin(); it != devices.end();) {
       it = devices.erase(it);
    }
    return;
  }

  CallControllerDeviceList* FindByAddress(const RawAddress& address) {
    auto iter = std::find_if(devices.begin(), devices.end(),
                             [&address](const CallControllerDeviceList& device) {
                               return device.peer_bda == address;
                             });

    return (iter == devices.end()) ? nullptr : &(*iter);
  }

  CallControllerDeviceList* FindByConnId(uint16_t conn_id) {
    auto iter = std::find_if(devices.begin(), devices.end(),
                             [&conn_id](const CallControllerDeviceList& device) {
                               return device.conn_id == conn_id;
                             });

    return (iter == devices.end()) ? nullptr : &(*iter);
  }

  size_t size() { return (devices.size()); }

  std::vector<CallControllerDeviceList> GetRemoteDevices() {
    return devices;
  }
  std::vector<CallControllerDeviceList> FindNotifyDevices(uint16_t handle) {
    std::vector<CallControllerDeviceList> notify_devices;
    for (size_t it = 0; it != devices.size(); it++){
      if(ccsControlServiceInfo.bearer_provider_name_handle == handle &&
        devices[it].bearer_provider_name_notify) {
        notify_devices.push_back(devices[it]);
      } else if(ccsControlServiceInfo.bearer_technology_handle == handle &&
        devices[it].bearer_technology_changed_notify) {
        notify_devices.push_back(devices[it]);
      } else if(ccsControlServiceInfo.bearer_signal_strength_handle == handle &&
        devices[it].bearer_signal_strength_notify) {
        notify_devices.push_back(devices[it]);
      } else if(ccsControlServiceInfo.bearer_list_currentcalls_handle == handle &&
        devices[it].bearer_current_calls_list_notify) {
        notify_devices.push_back(devices[it]);
      } else if(ccsControlServiceInfo.call_status_flags_handle == handle &&
        devices[it].status_flags_notify) {
        notify_devices.push_back(devices[it]);
      } else if(ccsControlServiceInfo.incoming_call_target_beareruri_handle == handle &&
        devices[it].incoming_call_target_URI_notify) {
        notify_devices.push_back(devices[it]);
      } else if(ccsControlServiceInfo.call_state_handle == handle &&
        devices[it].call_state_notify) {
        notify_devices.push_back(devices[it]);
      } else if(ccsControlServiceInfo.call_control_point_handle == handle &&
        devices[it].call_control_point_notify) {
        notify_devices.push_back(devices[it]);
      } else if(ccsControlServiceInfo.call_termination_reason_handle == handle &&
        devices[it].call_termination_reason_notify) {
        notify_devices.push_back(devices[it]);
      } else if(ccsControlServiceInfo.incoming_call_handle == handle &&
        devices[it].incoming_call_state_notify) {
        notify_devices.push_back(devices[it]);
      } else if(ccsControlServiceInfo.call_friendly_name_handle == handle &&
        devices[it].call_friendly_name_notify) {
        notify_devices.push_back(devices[it]);
      }
    }
    return notify_devices;
  }
  void AddSetActiveDevice(tCCS_SET_ACTIVE_DEVICE *device) {
    if (device->set_id == activeDevice.set_id) {
      activeDevice.address.push_back(device->address);
    } else {
      activeDevice.address.clear();
      activeDevice.set_id = device->set_id;
      activeDevice.address.push_back(device->address);
    }
  }

  bool FindActiveDevice(CallControllerDeviceList *remoteDevice) {
    bool flag = false;
    for (auto& it : activeDevice.address) {
      if(remoteDevice->peer_bda == it) {
        flag = true;
        break;
      }
    }
    return flag;
  }
  static void SSReportingTimerExpired(void *data) {
      LOG(INFO) << __func__ ;
    CallControllerDeviceList* dev = (CallControllerDeviceList*)data;
    if (dev == nullptr) {
        LOG(ERROR) << __func__ << "no valid dev handle";
        return;
    }

    //send Notification for Signal Strength
    tcc_resp_t *rsp = new tcc_resp_t();
    if (rsp == NULL) {
       LOG(ERROR) << __func__ << "Allocation error!";
       return;
    }
    std::vector<uint8_t> _data;
    _data.clear();
    rsp->remoteDevice = dev;
    rsp->event = CCS_NOTIFY_ALL;
    rsp->handle = ccsControlServiceInfo.bearer_signal_strength_handle;
    _data.push_back(BearerProviderInfo.signal);
    rsp->oper.CallControllerOp.data = std::move(_data);
    //force the Notification on timer expiry
    rsp->force = true;

    if (dev->bearer_signal_strength_notify) {
       LOG(INFO) << "Caling device state handler for SSReporting";
       dev->DeviceStateHandlerPointer[dev->state](CCS_NOTIFY_ALL, rsp);
    } else {
       LOG(INFO) << "SSReporting Interval set without Desc write for SSR";
    }
  }

  static void SetupSSReportingInterval (CallControllerDeviceList* dev) {
    LOG(INFO) << __func__ ;
    if (alarm_is_scheduled(dev->signal_strength_reporting_timer)) {
       alarm_cancel(dev->signal_strength_reporting_timer);
    }
    if (dev->signal_strength_report_interval != 0) {
       alarm_set(dev->signal_strength_reporting_timer,
                       (period_ms_t)dev->signal_strength_report_interval*MS_IN_SEC,
                       SSReportingTimerExpired,
                       (void*)dev);
    }
  }

  bool UpdateSSReportingInterval(const RawAddress& address, uint8_t ssrInterval) {
      bool ret = false;
      CallControllerDeviceList *dev = FindByAddress(address);

      if (dev != nullptr) {
         dev->signal_strength_report_interval = ssrInterval;
         SetupSSReportingInterval(dev);
         ret = true;
      }
      return ret;
  }

  std::vector<CallControllerDeviceList> devices;
};


class CallControllerImpl : public CallController {
  bluetooth::call_control::CallControllerCallbacks* callbacks;
  Uuid app_uuid;
  int max_clients;
  bool inband_ring_support;

  public:
     CallControllerDevices remoteDevices;
     virtual ~CallControllerImpl() = default;


  CallControllerImpl(bluetooth::call_control::CallControllerCallbacks* callback,
              Uuid uuid, int max_ccs_clients, bool inband_ringing_enabled)
        :callbacks(callback),
     app_uuid(uuid),
     max_clients(max_ccs_clients),
     inband_ring_support(inband_ringing_enabled)  {
    // HandleCcsEvent(CCS_INIT_EVENT, &app_uuid);
    LOG(INFO) << "max_clients " << max_clients;
     if (inband_ring_support) {
       StatusFlags.supported_flags =  (StatusFlags.supported_flags & 0x0000) | INBAND_RINGTONE_FEATURE_BIT;
     } else {
       StatusFlags.supported_flags = 0x0000;
     }
     LOG(INFO) << "CallControllerImpl gatts app register";
     BTA_GATTS_AppRegister(app_uuid, BTCcCback, true);

  }

 void Disconnect(const RawAddress& bd_addr) {
    LOG(INFO) << __func__;
    tCCS_CONNECTION_CLOSE ConnectClosingOp;
    ConnectClosingOp.addr = bd_addr;
    HandleCcsEvent(CCS_CONNECTION_CLOSE_EVENT, &ConnectClosingOp);
 }

 void SetActiveDevice(const RawAddress& address, int setId) {
    LOG(INFO) << __func__ ;
    tCCS_SET_ACTIVE_DEVICE SetActiveDeviceOp;
    SetActiveDeviceOp.set_id = setId;
    SetActiveDeviceOp.address = address;
    HandleCcsEvent(CCS_ACTIVE_DEVICE_UPDATE, &SetActiveDeviceOp);
  }

  void CallState(int len, std::vector<uint8_t> call_state_list) {
    tCCS_CALL_STATE CallStateOp;
    for (int k=0; k<len; k++) {
        LOG(INFO) << __func__ << " " << k <<" : index: " << (unsigned)call_state_list[3*k + 0]
                          << " state: " << (unsigned) call_state_list[3*k + 1]
                          << " flags: " << (unsigned) call_state_list[3*k + 2];
        CallStateOp.index = call_state_list[3*k + 0];
        CallStateOp.state = call_state_list[3*k + 1];
        CallStateOp.flags = call_state_list[3*k + 2];

        BlccInfo.call_flags = CallStateOp.flags;
        BlccInfo.call_index = CallStateOp.index;
        BlccInfo.call_state = CallStateOp.state;

        if (CallStateOp.state == CCS_STATE_INCOMING) {
            int len = strlen((char *)IncomingCallInfo.incoming_uri);
            memcpy(BlccInfo.call_uri, IncomingCallInfo.incoming_uri, len);
            BlccInfo.list_length = 3 + len;
        } else {
            BlccInfo.list_length = 3;
        }

        if (CallStateOp.state == CCS_STATE_DISCONNECTED) {
            //clear off the Incoming call related things as well
            if (IncomingCallInfo.index == CallStateOp.index) {
                IncomingCallInfo.index = 0;
                memset(IncomingCallInfo.incoming_uri, 0, MAX_URI_LENGTH);
            }
            if (IncomingCallTargetUri.index == CallStateOp.index) {
                IncomingCallTargetUri.index = 0;
                memset(IncomingCallTargetUri.incoming_target_uri, 0, MAX_URI_LENGTH);
            }

            TerminationReason.index = CallStateOp.index;
            if (gIsTerminatedInitiatedFromClient &&
                 CallStateOp.index == gIsTerminatedInitiatedFromClient) {
                TerminationReason.reason = CC_TERM_END_FROM_CLIENT;
            } else {
                TerminationReason.reason = CC_TERM_END_FROM_SERVER;
            }
            gIsTerminatedInitiatedFromClient = false;
            gTerminateIntiatedIndex = 0;
            HandleCcsEvent(CCS_INCOMING_CALL_UPDATE, &IncomingCallInfo);
            HandleCcsEvent(CCS_INCOMING_TARGET_URI_UPDATE, &IncomingCallTargetUri);
            HandleCcsEvent(CCS_TERMINATION_REASON_UPDATE, &TerminationReason);

            //erase the disconnected Indicies
            BlccInfolist.erase(CallStateOp.index);
            CallStatelist.erase(CallStateOp.index);
        } else {
            //keep appending the data
            std::map<uint8_t, tCCS_BEARER_LIST_CURRENT_CALLS>::iterator i = BlccInfolist.find(BlccInfo.call_index);
            if (i != BlccInfolist.end()) {
                LOG(INFO) << __func__ << " update existing Blcc";
                i->second = BlccInfo;
            } else {
                BlccInfolist.insert({BlccInfo.call_index, BlccInfo});
            }
            std::map<uint8_t, tCCS_CALL_STATE>::iterator j = CallStatelist.find(CallStateOp.index);
            if (j != CallStatelist.end()) {
                j->second = CallStateOp;
            } else {
                CallStatelist.insert({CallStateOp.index, CallStateOp});
            }
            //clear the term reason
            if (CallStateOp.index == TerminationReason.index) {
                TerminationReason.index = 0;
                TerminationReason.reason = CC_TERM_INVALID_ORIG_URI;
            }
        }
    }
    HandleCcsEvent(CCS_CALL_STATE_UPDATE, &CallStatelist);
    HandleCcsEvent(CCS_BEARER_CURRENT_CALL_LIST_UPDATE, &BlccInfolist);
 }

 void BearerInfoName(uint8_t* name) {
   LOG(INFO) << __func__ << name;
   tCCS_BEARER_PROVIDER_INFO BearerProviderOp;
   BearerProviderOp.length = strlen((char *)name);
   memcpy(BearerProviderOp.name, name, BearerProviderOp.length+1);
   HandleCcsEvent(CCS_BEARER_NAME_UPDATE, &BearerProviderOp);
 }

 void UpdateBearerTechnology(int tech_type) {
   LOG(INFO) << __func__ << " tech type: " <<tech_type;
   tCCS_BEARER_PROVIDER_INFO bearerProviderOp;
   BearerProviderInfo.technology_type = tech_type;

   HandleCcsEvent(CCS_BEARER_TECHNOLOGY_UPDATE, &bearerProviderOp);
 }
 void UpdateBearerSignalStrength(int signal) {
   LOG(INFO) << __func__<< " signal: " << signal;
   tCCS_BEARER_PROVIDER_INFO BearerProviderOp;
   BearerProviderOp.signal = signal;
   HandleCcsEvent(CCS_BEARER_SIGNAL_STRENGTH_UPDATE, &BearerProviderOp);
 }

 void UpdateStatusFlags(uint8_t status_flag) {
   LOG(INFO) << __func__ << " status_flag: " <<status_flag;
   tCCS_STATUS_FLAGS StatusFlagsOp;
   StatusFlagsOp.supported_flags = status_flag;
   HandleCcsEvent(CCS_STATUS_FLAGS_UPDATE, &StatusFlagsOp);
 }

 void CallControlOptionalOpSupported(int feature) {
   LOG(INFO) << __func__ << " feature: " << feature;
   tCCS_SUPP_OPTIONAL_OPCODES opSupportedFeatures;
   opSupportedFeatures.supp_opcode = (uint16_t)0x00FF&feature;

   HandleCcsEvent(CCS_OPT_OPCODES, &opSupportedFeatures);
 }

 void UpdateSupportedBearerList(uint8_t* list) {
   LOG(INFO) << __func__ << " list: " <<list;
   tCCS_BEARER_PROVIDER_INFO BearerProviderOp;
   BearerProviderOp.bearer_list_len = strlen((char *)list);
   LOG(INFO) << __func__ << " list len:" << BearerProviderOp.bearer_list_len;
   memcpy(BearerProviderOp.bearer_schemes_list, list, BearerProviderOp.bearer_list_len+1);
   HandleCcsEvent(CCS_BEARER_URI_SCHEMES_SUPPORTED, &BearerProviderOp);
 }

 void UpdateIncomingCall(int index, uint8_t* Uri) {
    LOG(INFO) << __func__ << " Uri: " << Uri;
    std::map<uint8_t, tCCS_BEARER_LIST_CURRENT_CALLS>::iterator it;
    tCCS_INCOMING_CALL IncomingCall;
    int len = strlen((char *)Uri);
    memcpy(IncomingCall.incoming_uri, Uri, len+1);
    IncomingCall.index = index;
    for (it = BlccInfolist.begin(); it != BlccInfolist.end(); it++) {
        tCCS_BEARER_LIST_CURRENT_CALLS blccObj = it->second;
       if (blccObj.call_index == index) {
          memcpy(blccObj.call_uri, Uri, strlen((char *)Uri)+1);
          break;
       }
    }
    HandleCcsEvent(CCS_INCOMING_CALL_UPDATE, &IncomingCall);
    //update Target URI as well with same Info
    UpdateIncomingCallTargetUri(index, Uri);
 }

 void UpdateIncomingCallTargetUri(int index, uint8_t* target_uri) {
    LOG(INFO) << __func__ << " target_uri: " << target_uri;
    tCCS_INCOMING_CALL_URI IncomingcallUri;
    int len = strlen((char *)target_uri);
    memcpy(IncomingcallUri.incoming_target_uri, target_uri, len+1);
    IncomingcallUri.index = index;
    HandleCcsEvent(CCS_INCOMING_TARGET_URI_UPDATE, &IncomingcallUri);
 }

 void ContentControlId(uint32_t ccid) {
    LOG(INFO) << __func__;
    tCCS_CONTENT_CONTROL_ID ContentControlIdOp;
    ContentControlIdOp.ccid = ccid;
    HandleCcsEvent(CCS_CCID_UPDATE, &ContentControlIdOp);
 }

 int GetDialingCallIndex() {
    int retIndex = 0;
    std::map<uint8_t, tCCS_CALL_STATE>::iterator it;
     for (it = CallStatelist.begin(); it != CallStatelist.end(); it++) {
        tCCS_CALL_STATE obj = it->second;
        if (obj.state == CCS_STATE_DIALING || obj.state == CCS_STATE_ALERTING) {
           LOG(INFO) << __func__ << " call state match: " << obj.index;
           retIndex = obj.index;
           break;
         }
    }
    return retIndex;
 }
 void CallControlResponse(uint8_t op, uint8_t index, uint32_t status,  const RawAddress& address) {
   LOG(INFO) << __func__;
   tCCS_CALL_CONTROL_RESPONSE CallControlResponse;
   CallControllerResp.opcode = op;
   CallControllerResp.response_status = status;
   CallControllerResp.remote_address = address;
   CallControllerResp.index = index;
   if (status == CCS_STATUS_SUCCESS && op == CALL_ORIGINATE) {
       //get proper call Index for call orignate status
       CallControllerResp.index = GetDialingCallIndex();
   }
   HandleCcsEvent(CCS_CALL_CONTROL_RESPONSE, &CallControlResponse);
 }

 void CallControlInitializedCallback(uint8_t state) {
    LOG(INFO) << __func__ << " state" << state;
    callbacks->CallControlInitializedCallback(state);
    if (state == 0) {
        //Initialize local char values
        memcpy(BearerProviderInfo.uci, STANDARD_BEARER_UCI, strlen(STANDARD_BEARER_UCI));
    }
 }

 void ConnectionStateCallback(uint8_t state,  const RawAddress&  address) {
    LOG(INFO) << __func__ << " state: " << state;
    callbacks->ConnectionStateCallback(state, address);
 }

 void CallControlPointChange(uint8_t op, uint8_t* indices, int count, char* uri, const RawAddress&  address) {
     LOG(INFO) << __func__ << " op: " <<op << " count :" << count;
     std::vector<uint8_t> uri_data;
     if (uri != NULL) {
         LOG(INFO) << __func__ <<" uri=" << uri;
         uri_data.insert(uri_data.begin(), uri, uri + strlen(uri));
     }
     std::vector<int32_t> call_indicies;
     for (int i=0; i<count; i++) {
         call_indicies.push_back(indices[i]);

     }
     callbacks->CallControlCallback(op, call_indicies, count, uri_data, address);
 }
};

void CallController::CleanUp() {
  HandleCcsEvent(CCS_CLEANUP_EVENT, NULL);
  delete cc_instance;
  cc_instance = nullptr;
 }

CallController* CallController::Get() {
  CHECK(cc_instance);
  return cc_instance;
}

void  CallController::Initialize(bluetooth::call_control::CallControllerCallbacks* callbacks,
                        Uuid uuid, int max_ccs_clients, bool inband_ringing_enabled) {
  if (cc_instance) {
  LOG(ERROR) << "Already initialized!";
  } else {
     cc_instance = new CallControllerImpl(callbacks, uuid, max_ccs_clients, inband_ringing_enabled);
  }
  char activeCC[PROPERTY_VALUE_MAX] = "false";
  if(osi_property_get("persist.vendor.service.bt.activeCC", activeCC, "false") &&
        !strcmp(activeCC, "true")) {
    gIsActiveCC = true;
  }
}

bool CallController::IsCcServiceRunnig() { return cc_instance; }

static std::vector<btgatt_db_element_t> CcAddService(int server_if) {

  std::vector<btgatt_db_element_t> ccs_services;
  ccs_services.clear();
  //service
  btgatt_db_element_t service = {};
  service.uuid = CALL_CONTROL_SERVER_UUID;
  service.type = BTGATT_DB_PRIMARY_SERVICE;
  ccs_services.push_back(service);
  ccsControlServiceInfo.ccs_service_uuid = service.uuid;

  btgatt_db_element_t bearer_provider_name_char = {};
  bearer_provider_name_char.uuid = GTBS_CALL_BEARER_NAME_UUID;
  bearer_provider_name_char.type = BTGATT_DB_CHARACTERISTIC;
  bearer_provider_name_char.properties = GATT_CHAR_PROP_BIT_READ|GATT_CHAR_PROP_BIT_NOTIFY;
  bearer_provider_name_char.permissions = GATT_PERM_READ;
  ccs_services.push_back(bearer_provider_name_char);
  ccsControlServiceInfo.bearer_provider_name_uuid = bearer_provider_name_char.uuid;

  btgatt_db_element_t bearer_provider_name_desc = {};
  bearer_provider_name_desc.uuid = GTBS_DESCRIPTOR_UUID;
  bearer_provider_name_desc.type = BTGATT_DB_DESCRIPTOR;
  bearer_provider_name_desc.permissions = GATT_PERM_READ|GATT_PERM_WRITE;
  ccs_services.push_back(bearer_provider_name_desc);

  btgatt_db_element_t bearer_technology_char = {};
  bearer_technology_char.uuid = GTBS_BEARER_TECHNOLOGY;
  bearer_technology_char.type = BTGATT_DB_CHARACTERISTIC;
  bearer_technology_char.properties = GATT_CHAR_PROP_BIT_READ|GATT_CHAR_PROP_BIT_NOTIFY;
  bearer_technology_char.permissions = GATT_PERM_READ;
  ccs_services.push_back(bearer_technology_char);
  ccsControlServiceInfo.bearer_technology_uuid = bearer_technology_char.uuid;

  btgatt_db_element_t bearer_technology_desc = {};
  bearer_technology_desc.uuid = GTBS_DESCRIPTOR_UUID;
  bearer_technology_desc.type = BTGATT_DB_DESCRIPTOR;
  bearer_technology_desc.permissions = GATT_PERM_READ|GATT_PERM_WRITE;
  ccs_services.push_back(bearer_technology_desc);

  btgatt_db_element_t gtbs_cc_optional_opcode_char = {};
  gtbs_cc_optional_opcode_char.uuid = GTBS_CALL_CONTROL_POINT_OPTIONAL_OPS;
  gtbs_cc_optional_opcode_char.type = BTGATT_DB_CHARACTERISTIC;
  gtbs_cc_optional_opcode_char.properties = GATT_CHAR_PROP_BIT_READ;
  gtbs_cc_optional_opcode_char.permissions = GATT_PERM_READ;
  ccs_services.push_back(gtbs_cc_optional_opcode_char);
  ccsControlServiceInfo.call_control_point_opcode_supported_uuid = gtbs_cc_optional_opcode_char.uuid;

  btgatt_db_element_t gtbs_call_state_char = {};
  gtbs_call_state_char.uuid = GTBS_CALL_STATE_UUID;
  gtbs_call_state_char.type = BTGATT_DB_CHARACTERISTIC;
  gtbs_call_state_char.properties = GATT_CHAR_PROP_BIT_READ|GATT_CHAR_PROP_BIT_NOTIFY;
  gtbs_call_state_char.permissions = GATT_PERM_READ;
  ccs_services.push_back(gtbs_call_state_char);
  ccsControlServiceInfo.call_state_uuid = gtbs_call_state_char.uuid;

  btgatt_db_element_t gtbs_call_state_desc = {};
  gtbs_call_state_desc.uuid = GTBS_DESCRIPTOR_UUID;
  gtbs_call_state_desc.type = BTGATT_DB_DESCRIPTOR;
  gtbs_call_state_desc.permissions = GATT_PERM_READ|GATT_PERM_WRITE;
  ccs_services.push_back(gtbs_call_state_desc);

  btgatt_db_element_t gtbs_call_control_point_char = {};
  gtbs_call_control_point_char.uuid = GTBS_CALL_CONTROL_POINT_OPS;
  gtbs_call_control_point_char.type = BTGATT_DB_CHARACTERISTIC;
  gtbs_call_control_point_char.properties = GATT_CHAR_PROP_BIT_WRITE|GATT_CHAR_PROP_BIT_NOTIFY|GATT_CHAR_PROP_BIT_WRITE_NR;
  gtbs_call_control_point_char.permissions = GATT_PERM_WRITE;
  ccs_services.push_back(gtbs_call_control_point_char);
  ccsControlServiceInfo.call_control_point_uuid = gtbs_call_control_point_char.uuid;

  btgatt_db_element_t gtbs_call_control_point_desc = {};
  gtbs_call_control_point_desc.uuid = GTBS_DESCRIPTOR_UUID;
  gtbs_call_control_point_desc.type = BTGATT_DB_DESCRIPTOR;
  gtbs_call_control_point_desc.permissions = GATT_PERM_READ|GATT_PERM_WRITE;
  ccs_services.push_back(gtbs_call_control_point_desc);

  btgatt_db_element_t gtbs_bearer_uci_char = {};
  gtbs_bearer_uci_char.uuid = GTBS_BEARER_UCI;
  gtbs_bearer_uci_char.type = BTGATT_DB_CHARACTERISTIC;
  gtbs_bearer_uci_char.properties = GATT_CHAR_PROP_BIT_READ;
  gtbs_bearer_uci_char.permissions = GATT_PERM_READ;
  ccs_services.push_back(gtbs_bearer_uci_char);
  ccsControlServiceInfo.bearer_uci_uuid= gtbs_bearer_uci_char.uuid;

  btgatt_db_element_t gtbs_bearer_URI_schemes_char = {};
  gtbs_bearer_URI_schemes_char.uuid = GTBS_BEARER_URI_SCHEMES;
  gtbs_bearer_URI_schemes_char.type = BTGATT_DB_CHARACTERISTIC;
  gtbs_bearer_URI_schemes_char.properties = GATT_CHAR_PROP_BIT_READ|GATT_CHAR_PROP_BIT_NOTIFY;
  gtbs_bearer_URI_schemes_char.permissions = GATT_PERM_READ;

  ccs_services.push_back(gtbs_bearer_URI_schemes_char);
  ccsControlServiceInfo.bearer_uri_schemes_supported_uuid = gtbs_bearer_URI_schemes_char.uuid;

  btgatt_db_element_t gtbs_bearer_URI_schemes_desc = {};
  gtbs_bearer_URI_schemes_desc.uuid = GTBS_DESCRIPTOR_UUID;
  gtbs_bearer_URI_schemes_desc.type = BTGATT_DB_DESCRIPTOR;
  gtbs_bearer_URI_schemes_desc.permissions = GATT_PERM_READ|GATT_PERM_WRITE;
  ccs_services.push_back(gtbs_bearer_URI_schemes_desc);

  btgatt_db_element_t gtbs_signal_strength_char = {};
  gtbs_signal_strength_char.uuid = GTBS_SIGNAL_STRENGTH;
  gtbs_signal_strength_char.type = BTGATT_DB_CHARACTERISTIC;
  gtbs_signal_strength_char.properties = GATT_CHAR_PROP_BIT_READ|GATT_CHAR_PROP_BIT_NOTIFY;
  gtbs_signal_strength_char.permissions = GATT_PERM_READ;

  ccs_services.push_back(gtbs_signal_strength_char);
  ccsControlServiceInfo.bearer_signal_strength_uuid = gtbs_signal_strength_char.uuid;

  btgatt_db_element_t gtbs_signal_strength_desc = {};
  gtbs_signal_strength_desc.uuid = GTBS_DESCRIPTOR_UUID;
  gtbs_signal_strength_desc.type = BTGATT_DB_DESCRIPTOR;
  gtbs_signal_strength_desc.permissions = GATT_PERM_READ|GATT_PERM_WRITE;
  ccs_services.push_back(gtbs_signal_strength_desc);

 btgatt_db_element_t gtbs_signal_strength_report_interval_char = {};
  gtbs_signal_strength_report_interval_char.uuid = GTBS_SIGNAL_STRENGTH_REPORTINTERVAL;
  gtbs_signal_strength_report_interval_char.type = BTGATT_DB_CHARACTERISTIC;
  gtbs_signal_strength_report_interval_char.properties = GATT_CHAR_PROP_BIT_READ|GATT_CHAR_PROP_BIT_WRITE|GATT_CHAR_PROP_BIT_WRITE_NR;
  gtbs_signal_strength_report_interval_char.permissions = GATT_PERM_READ|GATT_PERM_WRITE;
  ccs_services.push_back(gtbs_signal_strength_report_interval_char);
  ccsControlServiceInfo.bearer_signal_strength_report_interval_uuid = gtbs_signal_strength_report_interval_char.uuid;

  btgatt_db_element_t gtbs_list_current_calls_char = {};
  gtbs_list_current_calls_char.uuid = GTBS_BEARER_LIST_CURRENT_CALLS;
  gtbs_list_current_calls_char.type = BTGATT_DB_CHARACTERISTIC;
  gtbs_list_current_calls_char.properties = GATT_CHAR_PROP_BIT_READ|GATT_CHAR_PROP_BIT_NOTIFY;
  gtbs_list_current_calls_char.permissions = GATT_PERM_READ;
  ccs_services.push_back(gtbs_list_current_calls_char);
  ccsControlServiceInfo.bearer_list_currentcalls_uuid = gtbs_list_current_calls_char.uuid;

  btgatt_db_element_t gtbs_list_current_calls_desc = {};
  gtbs_list_current_calls_desc.uuid = GTBS_DESCRIPTOR_UUID;
  gtbs_list_current_calls_desc.type = BTGATT_DB_DESCRIPTOR;
  gtbs_list_current_calls_desc.permissions = GATT_PERM_READ|GATT_PERM_WRITE;
  ccs_services.push_back(gtbs_list_current_calls_desc);

  btgatt_db_element_t gtbs_call_status_flags_char = {};
  gtbs_call_status_flags_char.uuid = GTBS_CALL_STATUS_FLAGS;
  gtbs_call_status_flags_char.type = BTGATT_DB_CHARACTERISTIC;
  gtbs_call_status_flags_char.properties = GATT_CHAR_PROP_BIT_READ|GATT_CHAR_PROP_BIT_NOTIFY;
  gtbs_call_status_flags_char.permissions = GATT_PERM_READ;
  ccs_services.push_back(gtbs_call_status_flags_char);
  ccsControlServiceInfo.call_status_flags_uuid = gtbs_call_status_flags_char.uuid;

  btgatt_db_element_t gtbs_call_status_flags_desc = {};
  gtbs_call_status_flags_desc.uuid = GTBS_DESCRIPTOR_UUID;
  gtbs_call_status_flags_desc.type = BTGATT_DB_DESCRIPTOR;
  gtbs_call_status_flags_desc.permissions = GATT_PERM_READ|GATT_PERM_WRITE;
  ccs_services.push_back(gtbs_call_status_flags_desc);

  btgatt_db_element_t gtbs_incomingcall_target_bearer_URI_char = {};
  gtbs_incomingcall_target_bearer_URI_char.uuid = GTBS_INCOMINGCALL_TARGET_URI;
  gtbs_incomingcall_target_bearer_URI_char.type = BTGATT_DB_CHARACTERISTIC;
  gtbs_incomingcall_target_bearer_URI_char.properties = GATT_CHAR_PROP_BIT_READ|GATT_CHAR_PROP_BIT_NOTIFY;
  gtbs_incomingcall_target_bearer_URI_char.permissions = GATT_PERM_READ;
  ccs_services.push_back(gtbs_incomingcall_target_bearer_URI_char);
  ccsControlServiceInfo.incoming_call_target_beareruri_uuid = gtbs_incomingcall_target_bearer_URI_char.uuid;

  btgatt_db_element_t gtbs_incomingcall_target_bearer_URI_desc = {};
  gtbs_incomingcall_target_bearer_URI_desc.uuid = GTBS_DESCRIPTOR_UUID;
  gtbs_incomingcall_target_bearer_URI_desc.type = BTGATT_DB_DESCRIPTOR;
  gtbs_incomingcall_target_bearer_URI_desc.permissions = GATT_PERM_READ|GATT_PERM_WRITE;
  ccs_services.push_back(gtbs_incomingcall_target_bearer_URI_desc);

  btgatt_db_element_t gtbs_incomingcall_char = {};
  gtbs_incomingcall_char.uuid = GTBS_INCOMING_CALL;
  gtbs_incomingcall_char.type = BTGATT_DB_CHARACTERISTIC;
  gtbs_incomingcall_char.properties = GATT_CHAR_PROP_BIT_READ|GATT_CHAR_PROP_BIT_NOTIFY;
  gtbs_incomingcall_char.permissions = GATT_PERM_READ;
  ccs_services.push_back(gtbs_incomingcall_char);
  ccsControlServiceInfo.incoming_call_uuid = gtbs_incomingcall_char.uuid;

  btgatt_db_element_t gtbs_incomingcall_desc = {};
  gtbs_incomingcall_desc.uuid = GTBS_DESCRIPTOR_UUID;
  gtbs_incomingcall_desc.type = BTGATT_DB_DESCRIPTOR;
  gtbs_incomingcall_desc.permissions = GATT_PERM_READ|GATT_PERM_WRITE;
  ccs_services.push_back(gtbs_incomingcall_desc);

  btgatt_db_element_t gtbs_call_termination_reason_char = {};
  gtbs_call_termination_reason_char.uuid = GTBS_CALL_TERMINATION_REASON;
  gtbs_call_termination_reason_char.type = BTGATT_DB_CHARACTERISTIC;
  gtbs_call_termination_reason_char.properties = GATT_CHAR_PROP_BIT_NOTIFY;
  ccs_services.push_back(gtbs_call_termination_reason_char);
  ccsControlServiceInfo.call_termination_reason_uuid = gtbs_call_termination_reason_char.uuid;

  btgatt_db_element_t gtbs_call_termination_reason_desc = {};
  gtbs_call_termination_reason_desc.uuid = GTBS_DESCRIPTOR_UUID;
  gtbs_call_termination_reason_desc.type = BTGATT_DB_DESCRIPTOR;
  gtbs_call_termination_reason_desc.permissions = GATT_PERM_READ|GATT_PERM_WRITE;
  ccs_services.push_back(gtbs_call_termination_reason_desc);

  btgatt_db_element_t gtbs_call_friendly_name_char = {};
  gtbs_call_friendly_name_char.uuid = GTBS_CALL_FRIENDLY_NAME;
  gtbs_call_friendly_name_char.type = BTGATT_DB_CHARACTERISTIC;
  gtbs_call_friendly_name_char.properties = GATT_CHAR_PROP_BIT_READ|GATT_CHAR_PROP_BIT_NOTIFY;
  gtbs_call_friendly_name_char.permissions = GATT_PERM_READ;
  ccs_services.push_back(gtbs_call_friendly_name_char);
  ccsControlServiceInfo.call_friendly_name_uuid = gtbs_call_friendly_name_char.uuid;

  btgatt_db_element_t gtbs_call_friendly_name_desc = {};
  gtbs_call_friendly_name_desc.uuid = GTBS_DESCRIPTOR_UUID;
  gtbs_call_friendly_name_desc.type = BTGATT_DB_DESCRIPTOR;
  gtbs_call_friendly_name_desc.permissions =  GATT_PERM_READ|GATT_PERM_WRITE;
  ccs_services.push_back(gtbs_call_friendly_name_desc);

  btgatt_db_element_t gtbs_ccid_char = {};
  gtbs_ccid_char.uuid = GTBS_CONTENT_CONTROLID;
  gtbs_ccid_char.type = BTGATT_DB_CHARACTERISTIC;
  gtbs_ccid_char.properties = GATT_CHAR_PROP_BIT_READ;
  gtbs_ccid_char.permissions = GATT_PERM_READ;
  ccs_services.push_back(gtbs_ccid_char);
  ccsControlServiceInfo.gtbs_ccid_uuid = gtbs_ccid_char.uuid;

  return ccs_services;
}

static void OnGtbsServiceAddedCb(uint8_t status, int serverIf,
                                std::vector<btgatt_db_element_t> service) {

  if (service[0].uuid == Uuid::From16Bit(UUID_SERVCLASS_GATT_SERVER) ||
      service[0].uuid == Uuid::From16Bit(UUID_SERVCLASS_GAP_SERVER)) {
    LOG(INFO) << "%s: Attempt to register restricted service"<< __func__;
    return;
  }

   for(int i=0; i< (int)service.size(); i++) {

    if (service[i].uuid == CALL_CONTROL_SERVER_UUID) {
      LOG(INFO) << __func__ << " GTBS service added attr handle: " << service[i].attribute_handle;
    } else if(service[i].uuid ==  GTBS_CALL_BEARER_NAME_UUID) {
      ccsControlServiceInfo.bearer_provider_name_handle = service[i++].attribute_handle;
      ccsControlServiceInfo.bearer_provider_name_desc  = service[i].attribute_handle;
      LOG(INFO) << __func__ << " bearer_provider_name_attr: "
                << ccsControlServiceInfo.bearer_provider_name_handle
                << " bearer_provider_name_desc: "
                << ccsControlServiceInfo.bearer_provider_name_desc;
    } else if(service[i].uuid == GTBS_BEARER_TECHNOLOGY) {
      ccsControlServiceInfo.bearer_technology_handle = service[i++].attribute_handle;
      ccsControlServiceInfo.bearer_technology_desc = service[i].attribute_handle;
      LOG(INFO) << __func__ << " bearer_technology_handle: "
                << ccsControlServiceInfo.bearer_technology_handle
                << " bearer_technology_desc: "
                << ccsControlServiceInfo.bearer_technology_desc;
    } else if(service[i].uuid == GTBS_CALL_CONTROL_POINT_OPTIONAL_OPS) {
      ccsControlServiceInfo.call_control_point_opcode_supported_handle =
          service[i].attribute_handle;
      LOG(INFO) << __func__ << " call_control_point_opcode_supported_handle register: "
                << ccsControlServiceInfo.call_control_point_opcode_supported_handle;
    } else if (service[i].uuid == GTBS_CALL_STATE_UUID) {

      ccsControlServiceInfo.call_state_handle = service[i++].attribute_handle;
      ccsControlServiceInfo.call_state_desc = service[i].attribute_handle;
      LOG(INFO) << __func__ << " call_state_handle: "
                << ccsControlServiceInfo.call_state_handle
                << " call_state_handle desc: "
                << ccsControlServiceInfo.call_state_desc;
    } else if(service[i].uuid == GTBS_CALL_CONTROL_POINT_OPS) {
      ccsControlServiceInfo.call_control_point_handle = service[i++].attribute_handle;
      ccsControlServiceInfo.call_control_point_desc =  service[i].attribute_handle;
       LOG(INFO) << __func__ << " call_control_point_handle: "
                 << ccsControlServiceInfo.call_control_point_handle
                 << " call_control_point_desc: "
                 << ccsControlServiceInfo.call_control_point_desc;
    } else if(service[i].uuid == GTBS_BEARER_UCI)  {
      ccsControlServiceInfo.bearer_uci_handle = service[i].attribute_handle;
       LOG(INFO) << __func__ << " bearer_uci_handle: "
                 << ccsControlServiceInfo.bearer_uci_handle;

    } else if(service[i].uuid == GTBS_BEARER_URI_SCHEMES)  {
      ccsControlServiceInfo.bearer_uri_schemes_supported_handle =
           service[i++].attribute_handle;
      ccsControlServiceInfo.bearer_uri_schemes_supported_desc =
           service[i].attribute_handle;
      LOG(INFO) << __func__ << " bearer_uri_schemes_supported_handle: "
                << ccsControlServiceInfo.bearer_uri_schemes_supported_handle
                << " bearer_uri_schemes_supported_desc: "
                << ccsControlServiceInfo.bearer_uri_schemes_supported_desc;

    } else if(service[i].uuid == GTBS_SIGNAL_STRENGTH)  {
      ccsControlServiceInfo.bearer_signal_strength_handle =
           service[i++].attribute_handle;
      ccsControlServiceInfo.bearer_signal_strength_desc =
           service[i].attribute_handle;
      LOG(INFO) << __func__ << " bearer_signal_strength_handle: "
                << ccsControlServiceInfo.bearer_signal_strength_handle
                << " bearer_signal_strength_desc: "
                << ccsControlServiceInfo.bearer_signal_strength_desc;

    } else if(service[i].uuid == GTBS_SIGNAL_STRENGTH_REPORTINTERVAL)  {
      ccsControlServiceInfo.bearer_signal_strength_report_interval_handle =
              service[i].attribute_handle;

      LOG(INFO) << __func__ << " bearer_signal_strength_report_interval_handle: "
                << ccsControlServiceInfo.bearer_signal_strength_report_interval_handle;

    } else if(service[i].uuid == GTBS_BEARER_LIST_CURRENT_CALLS)  {
      ccsControlServiceInfo.bearer_list_currentcalls_handle =
            service[i++].attribute_handle;
      ccsControlServiceInfo.bearer_list_currentcalls_desc =
            service[i].attribute_handle;
      LOG(INFO) << __func__ << " bearer_list_currentcalls_handle: "
                << ccsControlServiceInfo.bearer_list_currentcalls_handle
                << " bearer_list_currentcalls_desc: "
                << ccsControlServiceInfo.bearer_list_currentcalls_desc;

    } else if(service[i].uuid == GTBS_CALL_STATUS_FLAGS)  {
      ccsControlServiceInfo.call_status_flags_handle = service[i++].attribute_handle;
      ccsControlServiceInfo.call_status_flags_desc = service[i].attribute_handle;
      LOG(INFO) << __func__ << " call_status_flags_handle: "
                << ccsControlServiceInfo.call_status_flags_handle
                << " call_status_flags_desc: "
                << ccsControlServiceInfo.call_status_flags_desc;

    } else if(service[i].uuid == GTBS_INCOMINGCALL_TARGET_URI)  {
      ccsControlServiceInfo.incoming_call_target_beareruri_handle =
           service[i++].attribute_handle;
      ccsControlServiceInfo.incoming_call_target_bearerURI_desc =
           service[i].attribute_handle;
      LOG(INFO) << __func__ << " incoming_call_target_beareruri_handle: "
                << ccsControlServiceInfo.incoming_call_target_beareruri_handle
                << " incoming_call_target_bearerURI_desc: "
                << ccsControlServiceInfo.incoming_call_target_bearerURI_desc;
    } else if(service[i].uuid == GTBS_INCOMING_CALL)  {
      ccsControlServiceInfo.incoming_call_handle = service[i++].attribute_handle;
      ccsControlServiceInfo.incoming_call_desc = service[i].attribute_handle;
      LOG(INFO) << __func__ << " incoming_call_handle: "
                << ccsControlServiceInfo.incoming_call_handle
                << " incoming_call_desc: "
                << ccsControlServiceInfo.incoming_call_desc;
    } else if(service[i].uuid == GTBS_CONTENT_CONTROLID)  {
      ccsControlServiceInfo.ccid_handle = service[i].attribute_handle;
      LOG(INFO) << __func__ << " ccid_handle: " << ccsControlServiceInfo.ccid_handle;
      //Declare the CC Initialization
      cc_instance->CallControlInitializedCallback(0);
    } else if(service[i].uuid == GTBS_CALL_TERMINATION_REASON)  {
      ccsControlServiceInfo.call_termination_reason_handle =
           service[i++].attribute_handle;
      ccsControlServiceInfo.call_termination_reason_desc =
           service[i].attribute_handle;
      LOG(INFO) << __func__ << " call_termination_reason_handle: "
                << ccsControlServiceInfo.call_termination_reason_handle
                << " call_termination_reason_desc: "
                << ccsControlServiceInfo.call_termination_reason_desc;
    } else if(service[i].uuid == GTBS_CALL_FRIENDLY_NAME)  {
      ccsControlServiceInfo.call_friendly_name_handle = service[i++].attribute_handle;
      ccsControlServiceInfo.call_friendly_name_desc = service[i].attribute_handle;
      LOG(INFO) << __func__ << " call_friendly_name_handle: "
                << ccsControlServiceInfo.call_friendly_name_handle
                << " call_friendly_name_desc: "
                << ccsControlServiceInfo.call_friendly_name_desc;
    }
  }
}

void PrintData(uint8_t data[], uint16_t len) {
    for (int i=0; i<len; i++) {
        LOG(INFO) << __func__ << " data[" << i << "] = " << std::hex << std::setfill('0') << std::setw(2) << data[i] << std::endl;
    }
}

void ReverseByteOrder(unsigned char s[], int length)
{
    char revbytes_enabled[PROPERTY_VALUE_MAX] = "false";
    osi_property_get("persist.bluetooth.ccp_rev", revbytes_enabled, "false");
    bool revNeeded = strncmp(revbytes_enabled, "true", 4) == 0;;
    if (revNeeded) {
        int tmp, i, j;

        for (i = 0, j = length-1; i < j; i++, j--)
        {
            tmp = s[i];
            s[i] = s[j];
            s[j] = tmp;
        }
    }
}

void HandleCcsEvent(uint32_t event, void* param) {
  LOG(INFO) << __func__ << " event: " << bta_cc_event_str(event);
  tBTA_GATTS* p_data = NULL;
  tcc_resp_t *rsp = new tcc_resp_t();
  if (rsp == NULL) {
    LOG(INFO) << __func__ << " ccs handle return rsp not allocated ";
    return;
  }
  std::vector<uint8_t> _data;
  _data.clear();
  uint8_t status = BT_STATUS_SUCCESS;
  rsp->event = CCS_NONE_EVENT;
  bool isCallControllerOpUsed = false;
  switch (event) {

    case CCS_INIT_EVENT:
    {
      Uuid aap_uuid = bluetooth::Uuid::GetRandom();
      BTA_GATTS_AppRegister(aap_uuid, BTCcCback, true);
      break;
    }

    case CCS_CLEANUP_EVENT:
    {
      //unregister APP
      BTA_GATTS_AppDeregister(ccsControlServiceInfo.server_if);
      cc_instance->remoteDevices.RemoveDevices();
      break;
    }
    case BTA_GATTS_REG_EVT:
    {
       p_data = (tBTA_GATTS*)param;
       if (p_data->reg_oper.status == BT_STATUS_SUCCESS) {
           ccsControlServiceInfo.server_if = p_data->reg_oper.server_if;
         std::vector<btgatt_db_element_t> service;
         service = CcAddService(ccsControlServiceInfo.server_if);
         if (service[0].uuid == Uuid::From16Bit(UUID_SERVCLASS_GATT_SERVER) ||
                 service[0].uuid == Uuid::From16Bit(UUID_SERVCLASS_GAP_SERVER)) {
           LOG(INFO) << __func__ << " service app register uuid is not valid";
           break;
         }
         LOG(INFO) << __func__ << " service app register";
         BTA_GATTS_AddService(ccsControlServiceInfo.server_if, service, base::Bind(&OnGtbsServiceAddedCb));
       }
       break;
    }

    case BTA_GATTS_DEREG_EVT:
    {
      break;
    }

    case BTA_GATTS_CONF_EVT: {
      p_data = (tBTA_GATTS*)param;
      uint16_t conn_id = p_data->req_data.conn_id;
      uint8_t status = p_data->req_data.status;
      LOG(INFO) << __func__ << "conn_id :" << conn_id << "status:" << status;
      if (status == BT_STATUS_SUCCESS) {
          LOG(INFO) << __func__ << "Notification callback for conn_id :" << conn_id;
          GattsOpsQueue::NotificationCallback(conn_id);
      }
      break;
    }

    case BTA_GATTS_CONGEST_EVT:
    {
      p_data = (tBTA_GATTS*)param;
      CallControllerDeviceList *remoteDevice;
      remoteDevice = cc_instance->remoteDevices.FindByConnId(p_data->congest.conn_id);
      if(remoteDevice == NULL) {
        LOG(INFO) << __func__ << " connection entry not found conn_id: "
          << p_data->congest.conn_id;
        break;
      }
     // rsp->ConngestionOp.status = p_data->req_data.status;
      rsp->remoteDevice = remoteDevice;
      rsp->oper.CongestionOp.congested = p_data->congest.congested;
      rsp->event = CCS_CONGESTION_UPDATE;
      break;
    }
    case BTA_GATTS_MTU_EVT: {
      p_data = (tBTA_GATTS*)param;

      CallControllerDeviceList *remoteDevice;
      remoteDevice = cc_instance->remoteDevices.FindByConnId(p_data->congest.conn_id);
      if(remoteDevice == NULL) {
        LOG(INFO) << __func__ << " connection entry not found conn_id: "
          << p_data->congest.conn_id;
        break;
      }
      rsp->event = CCS_MTU_UPDATE;
      rsp->remoteDevice = remoteDevice;
      rsp->oper.MtuOp.mtu = p_data->req_data.p_data->mtu;
      break;
    }
    case BTA_GATTS_CONNECT_EVT: {

      p_data = (tBTA_GATTS*)param;
      LOG(INFO) << __func__ << " remote devices connected";
      /*
      #if (!defined(BTA_SKIP_BLE_START_ENCRYPTION) || BTA_SKIP_BLE_START_ENCRYPTION == FALSE)
        btif_gatt_check_encrypted_link(p_data->conn.remote_bda,
                                     p_data->conn.transport);
      #endif*/
      CallControllerDeviceList remoteDevice;
      memset(&remoteDevice, 0, sizeof(remoteDevice));
      if(cc_instance->remoteDevices.FindByAddress(p_data->conn.remote_bda)) {
      LOG(INFO) << __func__ << " remote devices already there is connected list";
        status = BT_STATUS_FAIL;
        return;
      }
      remoteDevice.peer_bda = p_data->conn.remote_bda;
      remoteDevice.conn_id = p_data->conn.conn_id;
      if(cc_instance->remoteDevices.Add(remoteDevice) == false) {
        LOG(INFO) << __func__ << " remote device is not added : max connection reached";
        //<TBD> need to check disconnection required
        break;
      }
      remoteDevice.state = CCS_DISCONNECTED;

      LOG(INFO) << __func__ << " remote devices connected conn_id: "<< remoteDevice.conn_id <<
         "bd_addr " << remoteDevice.peer_bda;

      rsp->event = CCS_CONNECTION;
      rsp->remoteDevice = cc_instance->remoteDevices.FindByAddress(p_data->conn.remote_bda);
      if (rsp->remoteDevice == NULL) {
          LOG(INFO)<<__func__ << " remote dev is null";
        break;
      }
      break;
    }

    case BTA_GATTS_DISCONNECT_EVT: {
      LOG(INFO) << __func__ << " remote devices disconnected";
      p_data = (tBTA_GATTS*)param;
      CallControllerDeviceList *remoteDevice;
      remoteDevice = cc_instance->remoteDevices.FindByConnId(p_data->conn_update.conn_id);
      if((!remoteDevice) ) {
        status = BT_STATUS_FAIL;
        break;
      }

      rsp->remoteDevice->peer_bda = remoteDevice->peer_bda;
      rsp->event = CCS_DISCONNECTION;
      rsp->remoteDevice = remoteDevice;
      break;
    }

    case BTA_GATTS_STOP_EVT:
      //Do nothing
      break;

    case BTA_GATTS_DELELTE_EVT:
      //Do nothing
      break;

    case BTA_GATTS_READ_CHARACTERISTIC_EVT: {
      p_data = (tBTA_GATTS*)param;
      std::vector<uint8_t> value;
      CallControllerDeviceList *remoteDevice =
          cc_instance->remoteDevices.FindByConnId(p_data->req_data.conn_id);
      LOG(INFO) << __func__ << " charateristcs read handle " <<
          p_data->req_data.p_data->read_req.handle <<" trans_id : " <<
              p_data->req_data.trans_id;

      if(remoteDevice == NULL) {
        LOG(INFO) << __func__ << " device not found ignore read operation";
        status = BT_STATUS_FAIL;
        break;
      }

      LOG(INFO) <<" offset: " << p_data->req_data.p_data->read_req.offset <<
          " long : " << p_data->req_data.p_data->read_req.is_long;

      tGATTS_RSP rsp_struct;
      rsp_struct.attr_value.auth_req  = 0;
      rsp_struct.attr_value.handle = p_data->req_data.p_data->read_req.handle;
      rsp_struct.attr_value.offset = p_data->req_data.p_data->read_req.offset;

      if(p_data->req_data.p_data->read_req.handle ==
          ccsControlServiceInfo.call_state_handle) {
        std::vector<uint8_t> loc_desc_value;
        std::map<uint8_t, tCCS_CALL_STATE>::iterator it;
        for (it = CallStatelist.begin(); it != CallStatelist.end(); it++){
            tCCS_CALL_STATE obj = it->second;
            loc_desc_value.push_back(obj.index);
            loc_desc_value.push_back(obj.state);
            loc_desc_value.push_back(obj.flags);
        }
        size_t count = std::min((size_t)GATT_MAX_ATTR_LEN, loc_desc_value.size());
        rsp_struct.attr_value.len = count;
        memcpy(rsp_struct.attr_value.value, loc_desc_value.data(), rsp_struct.attr_value.len);


        LOG(INFO) << __func__ << " CallStateInfo read";
      } else if(p_data->req_data.p_data->read_req.handle ==
           ccsControlServiceInfo.call_control_point_opcode_supported_handle) {

        rsp_struct.attr_value.len = sizeof(SupportedOptionalOpcodes.supp_opcode);
        memcpy(rsp_struct.attr_value.value, &SupportedOptionalOpcodes.supp_opcode, rsp_struct.attr_value.len);
        LOG(INFO) << __func__ << " callcontrol_point_opcode_supported_handle read";
      } else if(p_data->req_data.p_data->read_req.handle ==
           ccsControlServiceInfo.bearer_provider_name_handle) {
        LOG(INFO) << __func__ << " BearerProviderInfo name read " << BearerProviderInfo.name;
        rsp_struct.attr_value.len = strlen((char *)BearerProviderInfo.name);
        LOG(INFO) << __func__ << " BearerProviderInfo name len: " <<rsp_struct.attr_value.len;
        memcpy(rsp_struct.attr_value.value, BearerProviderInfo.name, rsp_struct.attr_value.len);
      } else if(p_data->req_data.p_data->read_req.handle ==
           ccsControlServiceInfo.bearer_list_currentcalls_handle) {

        std::vector<uint8_t> loc_desc_value;
        std::map<uint8_t, tCCS_BEARER_LIST_CURRENT_CALLS>::iterator it;
        for (it = BlccInfolist.begin(); it != BlccInfolist.end(); it++){
            tCCS_BEARER_LIST_CURRENT_CALLS obj = it->second;
            loc_desc_value.push_back(obj.list_length);
            loc_desc_value.push_back(obj.call_index);
            loc_desc_value.push_back(obj.call_state);
            loc_desc_value.push_back(obj.call_flags);

            loc_desc_value.insert(loc_desc_value.end(),
                obj.call_uri, obj.call_uri+(obj.list_length-3));
        }
        size_t count = std::min((size_t)GATT_MAX_ATTR_LEN, loc_desc_value.size());
        rsp_struct.attr_value.len = count;
        memcpy(rsp_struct.attr_value.value, loc_desc_value.data(), rsp_struct.attr_value.len);
        LOG(INFO) << __func__ << " BlccInfo read";
      } else if(p_data->req_data.p_data->read_req.handle ==
           ccsControlServiceInfo.bearer_technology_handle) {
        rsp_struct.attr_value.len = sizeof(BearerProviderInfo.technology_type);
        memcpy(rsp_struct.attr_value.value, &BearerProviderInfo.technology_type, rsp_struct.attr_value.len);
        LOG(INFO) << __func__ << " technology_type read";
      } else if(p_data->req_data.p_data->read_req.handle ==
           ccsControlServiceInfo.bearer_uci_handle) {
           rsp_struct.attr_value.len = strlen((char *)BearerProviderInfo.uci);
           memcpy(rsp_struct.attr_value.value, BearerProviderInfo.uci, rsp_struct.attr_value.len);
           LOG(INFO) << __func__ << " Bearer UCI read";
      } else if(p_data->req_data.p_data->read_req.handle ==
           ccsControlServiceInfo.bearer_signal_strength_handle) {
        rsp_struct.attr_value.len = sizeof(BearerProviderInfo.signal);
        memcpy(rsp_struct.attr_value.value, &BearerProviderInfo.signal, rsp_struct.attr_value.len);
        LOG(INFO) << __func__ << " signal strength read";
      } else if(p_data->req_data.p_data->read_req.handle ==
           ccsControlServiceInfo.bearer_signal_strength_report_interval_handle) {
        rsp_struct.attr_value.len = sizeof(BearerProviderInfo.signal_report_interval);
        memcpy(rsp_struct.attr_value.value, &BearerProviderInfo.signal_report_interval, rsp_struct.attr_value.len);
        LOG(INFO) << __func__ << " signal_report_interval read";
      } else if(p_data->req_data.p_data->read_req.handle ==
           ccsControlServiceInfo.bearer_uri_schemes_supported_handle) {
            rsp_struct.attr_value.len = strlen((const char*)BearerProviderInfo.bearer_schemes_list);
            memcpy(rsp_struct.attr_value.value, BearerProviderInfo.bearer_schemes_list, rsp_struct.attr_value.len);
            LOG(INFO) << __func__ << " bearer_schemes_list read";
      }else if(p_data->req_data.p_data->read_req.handle ==
           ccsControlServiceInfo.incoming_call_handle) {
        rsp_struct.attr_value.len = 1 + strlen((char*)IncomingCallInfo.incoming_uri);
        memcpy(rsp_struct.attr_value.value, &IncomingCallInfo, rsp_struct.attr_value.len);
        LOG(INFO) << __func__ << " Incoming call read";
      } else if(p_data->req_data.p_data->read_req.handle ==
           ccsControlServiceInfo.incoming_call_target_beareruri_handle) {
        rsp_struct.attr_value.len = 1 + strlen((char*)IncomingCallTargetUri.incoming_target_uri);
        memcpy(rsp_struct.attr_value.value, &IncomingCallTargetUri, rsp_struct.attr_value.len);
        LOG(INFO) << __func__ << " Incoming Call target URI read";
      } else if(p_data->req_data.p_data->read_req.handle ==
           ccsControlServiceInfo.ccid_handle) {
        rsp_struct.attr_value.len = sizeof(CcidInfo);
        memcpy(rsp_struct.attr_value.value, &CcidInfo, rsp_struct.attr_value.len);
        LOG(INFO) << __func__ << " Content Control read";
      } else if(p_data->req_data.p_data->read_req.handle ==
           ccsControlServiceInfo.call_status_flags_handle) {
        rsp_struct.attr_value.len = sizeof(StatusFlags.supported_flags);
        memcpy(rsp_struct.attr_value.value, &StatusFlags.supported_flags, rsp_struct.attr_value.len);
        LOG(INFO) << __func__ << " Status flags read";
      } else if(p_data->req_data.p_data->read_req.handle ==
           ccsControlServiceInfo.call_friendly_name_handle) {
        rsp_struct.attr_value.len = 1 + strlen((char*)FriendlyName.name);
        memcpy(rsp_struct.attr_value.value, &FriendlyName, rsp_struct.attr_value.len);
        LOG(INFO) << __func__ << " Call friendly name read";
      }else if(p_data->req_data.p_data->read_req.handle ==
           ccsControlServiceInfo.call_termination_reason_handle) {
        rsp_struct.attr_value.len = sizeof(TerminationReason);
        memcpy(rsp_struct.attr_value.value, &TerminationReason, rsp_struct.attr_value.len);
        LOG(INFO) << __func__ << " Termination Reason read";
      }
      else {
        LOG(INFO) << __func__ << " read request for unknow handle " << p_data->req_data.p_data->read_req.handle;
        status = BT_STATUS_FAIL;
        break;
      }
      LOG(INFO) << __func__ << " read request handle " << p_data->req_data.p_data->read_req.handle <<
        "connection id " << p_data->req_data.conn_id;
      rsp->oper.ReadOp.char_handle = rsp_struct.attr_value.handle;
      rsp->oper.ReadOp.trans_id = p_data->req_data.trans_id;
      rsp->oper.ReadOp.status = BT_STATUS_SUCCESS;
      rsp->event = CCS_READ_RSP;
      rsp->remoteDevice = remoteDevice;

      memcpy((void*)&rsp->rsp_value, &rsp_struct, sizeof(rsp_struct));
      break;
    }

    case BTA_GATTS_READ_DESCRIPTOR_EVT: {
      LOG(INFO) << __func__ << " read descriptor";
      p_data = (tBTA_GATTS*)param;
      LOG(INFO) << __func__ << " charateristcs read desc handle " <<
          p_data->req_data.p_data->read_req.handle << " offset : "
          << p_data->req_data.p_data->read_req.offset;
       CallControllerDeviceList *remoteDevice =
          cc_instance->remoteDevices.FindByConnId(p_data->req_data.conn_id);
      if(remoteDevice == NULL) {
        LOG(INFO) << __func__ << " device not found ignore write";
        status = BT_STATUS_FAIL;
        break;
      }
      uint16_t data = 0x00;
      if(p_data->req_data.p_data->read_req.handle ==
          ccsControlServiceInfo.call_state_desc) {
        LOG(INFO) << __func__ << " call_state_desc read";
        data = remoteDevice->call_state_notify;
      } else if(p_data->req_data.p_data->read_req.handle ==
          ccsControlServiceInfo.call_control_point_desc) {
        LOG(INFO) << __func__ << " callcontrol_point_desc read";
        data = remoteDevice->call_control_point_notify;
      } else if(p_data->req_data.p_data->read_req.handle ==
          ccsControlServiceInfo.bearer_provider_name_desc) {
        LOG(INFO) << __func__ << " bearer_provider_name_desc read";
        data = remoteDevice->bearer_provider_name_notify;
      } else if(p_data->req_data.p_data->read_req.handle ==
          ccsControlServiceInfo.bearer_signal_strength_desc) {
        LOG(INFO) << __func__ << " bearer_signal_strength desc read";
        data = remoteDevice->bearer_signal_strength_notify;
      } else if(p_data->req_data.p_data->read_req.handle ==
          ccsControlServiceInfo.bearer_list_currentcalls_desc) {
        LOG(INFO) << __func__ << " bearer_list_currentcall read";
        data = remoteDevice->bearer_current_calls_list_notify;
      } else if(p_data->req_data.p_data->read_req.handle ==
          ccsControlServiceInfo.bearer_technology_desc) {
        LOG(INFO) << __func__ << " bearer_technology_desc read";
        data = remoteDevice->bearer_technology_changed_notify;
      } else if(p_data->req_data.p_data->read_req.handle ==
          ccsControlServiceInfo.bearer_uci_desc) {
        LOG(INFO) << __func__ << " bearer_uci_desc read";
        data = remoteDevice->bearer_uci_notify;
      } else if(p_data->req_data.p_data->read_req.handle ==
          ccsControlServiceInfo.bearer_uri_schemes_supported_desc) {
        LOG(INFO) << __func__ << " bearer_uri_schemes_supported_desc read";
        data = remoteDevice->bearer_uri_schemes_supported_notify;
      }  else if(p_data->req_data.p_data->read_req.handle ==
          ccsControlServiceInfo.call_friendly_name_desc) {
        LOG(INFO) << __func__ << " call_friendly_name_desc read";
        data = remoteDevice->call_friendly_name_notify;
      }  else if(p_data->req_data.p_data->read_req.handle ==
          ccsControlServiceInfo.call_control_point_opcode_supported_desc) {
        LOG(INFO) << __func__ << " call_control_point_opcode_supported_desc read";
        data = remoteDevice->call_control_point_opcode_supported_notify;
      }  else if(p_data->req_data.p_data->read_req.handle ==
          ccsControlServiceInfo.call_termination_reason_desc) {
        LOG(INFO) << __func__ << " call_termination_reason_desc read";
        data = remoteDevice->call_termination_reason_notify;
      }  else if(p_data->req_data.p_data->read_req.handle ==
          ccsControlServiceInfo.bearer_signal_strength_report_interval_desc) {
        LOG(INFO) << __func__ << " bearer_signal_strength_report_interval_desc read";
        data = remoteDevice->bearer_signal_strength_report_interval_notify;
      } else {
        LOG(INFO) << __func__ << " read request for unknown handle " << p_data->req_data.p_data->read_req.handle;
        status = BT_STATUS_FAIL;
        break;
      }
      rsp->rsp_value.attr_value.auth_req  = 0;
      rsp->rsp_value.attr_value.handle = p_data->req_data.p_data->read_req.handle;
      rsp->rsp_value.attr_value.offset = p_data->req_data.p_data->read_req.offset;
      *(uint16_t *)rsp->rsp_value.attr_value.value = (uint16_t)data;
      rsp->rsp_value.attr_value.len = sizeof(data);
      //cc response
      rsp->oper.ReadDescOp.desc_handle = p_data->req_data.p_data->read_req.handle;
      rsp->oper.ReadDescOp.trans_id = p_data->req_data.trans_id;
      rsp->oper.ReadDescOp.status = BT_STATUS_SUCCESS;
      rsp->remoteDevice = remoteDevice;
      rsp->event = CCS_DESCRIPTOR_READ_RSP;
      break;
    }

    case BTA_GATTS_WRITE_CHARACTERISTIC_EVT: {

      p_data = (tBTA_GATTS*)param;
      tGATT_WRITE_REQ req = p_data->req_data.p_data->write_req;
      LOG(INFO) << __func__ << " write characteristics len: " << req.len;
      PrintData(req.value, req.len);
      CallControllerDeviceList *remoteDevice =
          cc_instance->remoteDevices.FindByConnId(p_data->req_data.conn_id);
      if(remoteDevice == NULL) {
        LOG(INFO) << __func__ << " device not found ignore write";
        status = BT_STATUS_FAIL;
        break;
      }
      if ( status != BT_STATUS_FAIL) {
        rsp->oper.WriteOp.char_handle = req.handle;
        rsp->oper.WriteOp.trans_id = p_data->req_data.trans_id;
        rsp->oper.WriteOp.status = BT_STATUS_SUCCESS;
        rsp->remoteDevice = remoteDevice;
        rsp->oper.WriteOp.need_rsp = req.need_rsp;
        rsp->oper.WriteOp.offset = req.offset;
        rsp->oper.WriteOp.len = req.len;
        rsp->oper.WriteOp.data = (uint8_t*) malloc(sizeof(uint8_t)*req.len);
        memcpy(rsp->oper.WriteOp.data, req.value, req.len);
        rsp->event = CCS_WRITE_RSP;
      }
      break;
    }

    case BTA_GATTS_WRITE_DESCRIPTOR_EVT: {

      p_data = (tBTA_GATTS* )param;
      std::vector<uint8_t> write_desc_value;
      write_desc_value.clear();
      uint16_t handle = 0;
      uint16_t req_value = 0;
      const auto& req = p_data->req_data.p_data->write_req;
      CallControllerDeviceList *remoteDevice =
           cc_instance->remoteDevices.FindByConnId(p_data->req_data.conn_id);
      if(remoteDevice == NULL) {
        LOG(INFO) << __func__ << " device not found ignore notification";
        break;
      }
      req_value = *(uint16_t* )req.value;
      //need to initialized with proper error code
      int status = BT_STATUS_SUCCESS;
      LOG(INFO) << __func__ << " write descriptor :" << req.handle <<
         " is resp: " << req.need_rsp << "is prep: " << req.is_prep << " value " << req_value;

      if(req.handle ==
          ccsControlServiceInfo.call_state_desc) {
        LOG(INFO) << __func__ << " call_state_desc descriptor write";
        remoteDevice->call_state_notify = req_value;
        std::map<uint8_t, tCCS_CALL_STATE>::iterator it;
        for (it = CallStatelist.begin(); it != CallStatelist.end(); it++){
            tCCS_CALL_STATE obj = it->second;
            write_desc_value.push_back(obj.index);
            write_desc_value.push_back(obj.state);
            write_desc_value.push_back(obj.flags);
        }
        handle = ccsControlServiceInfo.call_state_handle;
      } else if(req.handle ==
        ccsControlServiceInfo.bearer_provider_name_desc) {
        remoteDevice->bearer_provider_name_notify = req_value;
        LOG(INFO) << __func__ << " bearer_provider_name_desc descriptor write";
           write_desc_value.assign(BearerProviderInfo.name,
            BearerProviderInfo.name + strlen((char*)BearerProviderInfo.name));
        handle = ccsControlServiceInfo.bearer_provider_name_handle;
      } else if(req.handle ==
          ccsControlServiceInfo.call_control_point_desc) {
        LOG(INFO) << __func__ << " callcontrol_point_desc write";
        write_desc_value.push_back(CallControllerResp.opcode);
        write_desc_value.push_back(CallControllerResp.index);
        write_desc_value.push_back(CallControllerResp.response_status);

        remoteDevice->call_control_point_notify = req_value;
        handle = ccsControlServiceInfo.call_control_point_handle;
      } else if(req.handle ==
          ccsControlServiceInfo.bearer_signal_strength_desc) {
        LOG(INFO) << __func__ << " bearer_signal_strength desc write";
        write_desc_value.push_back(BearerProviderInfo.signal);
        remoteDevice->bearer_signal_strength_notify = req_value;
        handle = ccsControlServiceInfo.bearer_signal_strength_handle;
      }  else if(req.handle ==
           ccsControlServiceInfo.bearer_uri_schemes_supported_desc) {
            remoteDevice->bearer_uri_schemes_supported_notify = req_value;
            write_desc_value.assign(BearerProviderInfo.bearer_schemes_list,
            BearerProviderInfo.bearer_schemes_list + strlen((char*)BearerProviderInfo.bearer_schemes_list));
            LOG(INFO) << __func__ << " bearer_schemes_list Desc write";
      } else if(req.handle ==
          ccsControlServiceInfo.bearer_list_currentcalls_desc) {
        std::map<uint8_t, tCCS_BEARER_LIST_CURRENT_CALLS>::iterator it;
        LOG(INFO) << __func__ << " bearer_list_currentcall desc write";
        for (it = BlccInfolist.begin(); it != BlccInfolist.end(); it++){
            tCCS_BEARER_LIST_CURRENT_CALLS obj = it->second;
            write_desc_value.push_back(obj.list_length);
            write_desc_value.push_back(obj.call_index);
            write_desc_value.push_back(obj.call_state);
            write_desc_value.push_back(obj.call_flags);
            write_desc_value.insert(write_desc_value.end(),
                obj.call_uri, obj.call_uri+(obj.list_length-3));
        }
        remoteDevice->bearer_current_calls_list_notify = req_value;
        handle = ccsControlServiceInfo.bearer_list_currentcalls_handle;

      } else if(req.handle ==
          ccsControlServiceInfo.bearer_technology_desc) {
        LOG(INFO) << __func__ << " bearer_technology_desc write";
        remoteDevice->bearer_technology_changed_notify = req_value;
        write_desc_value.push_back(BearerProviderInfo.technology_type);
        handle = ccsControlServiceInfo.bearer_technology_handle;
      } else if(req.handle ==
          ccsControlServiceInfo.call_friendly_name_desc) {
        LOG(INFO) << __func__ << " call_friendly_name_desc read";
        remoteDevice->call_friendly_name_notify = req_value;
        int len = 1 + strlen((char*)FriendlyName.name);
        write_desc_value.assign((uint8_t*)&FriendlyName, (uint8_t*)&FriendlyName+len);
        handle = ccsControlServiceInfo.call_friendly_name_handle;
      } else if(req.handle ==
          ccsControlServiceInfo.call_termination_reason_desc) {
        LOG(INFO) << __func__ << " call_termination_reason_desc write";
        remoteDevice->call_termination_reason_notify = req_value;
        handle = ccsControlServiceInfo.call_termination_reason_handle;
        write_desc_value.push_back(TerminationReason.index);
        write_desc_value.push_back(TerminationReason.reason);

        handle = ccsControlServiceInfo.call_termination_reason_handle;
    } else if(req.handle ==
          ccsControlServiceInfo.call_status_flags_desc) {
        LOG(INFO) << __func__ << " Status Flags Desc write";
        remoteDevice->status_flags_notify= req_value;
        write_desc_value.push_back(StatusFlags.supported_flags);
        handle = ccsControlServiceInfo.call_status_flags_handle;

      } else if(req.handle ==
          ccsControlServiceInfo.incoming_call_target_bearerURI_desc) {
        LOG(INFO) << __func__ << " Incoming target bearer desc write";
        int len = 1 + strlen((char*)IncomingCallTargetUri.incoming_target_uri);
        write_desc_value.assign((uint8_t*)&IncomingCallTargetUri, (uint8_t*)&IncomingCallTargetUri+len);
        remoteDevice->incoming_call_target_URI_notify= req_value;
        handle = ccsControlServiceInfo.incoming_call_target_beareruri_handle;

      } else if(req.handle ==
          ccsControlServiceInfo.incoming_call_desc) {
        LOG(INFO) << __func__ << " Incoming Call desc write";
        remoteDevice->incoming_call_state_notify = req_value;
        int len = 1 + strlen((char*)IncomingCallInfo.incoming_uri);
        write_desc_value.assign((uint8_t*)&IncomingCallInfo, (uint8_t*)&IncomingCallInfo+len);

        handle = ccsControlServiceInfo.incoming_call_handle;
      } else {
        LOG(INFO) << __func__ << " descriptor write not matched";
        status = 4; //check error code
      }
      rsp->oper.WriteDescOp.desc_handle = req.handle;
      rsp->oper.WriteDescOp.char_handle = handle;
      rsp->oper.WriteDescOp.trans_id = p_data->req_data.trans_id;
      rsp->oper.WriteDescOp.status = status;
      rsp->oper.WriteDescOp.need_rsp = req.need_rsp;
      rsp->oper.WriteDescOp.notification = req_value;
      rsp->oper.WriteDescOp.value = std::move(write_desc_value);
      rsp->event = CCS_DESCRIPTOR_WRITE_RSP;
      rsp->remoteDevice = remoteDevice;
      break;
    }

    case BTA_GATTS_EXEC_WRITE_EVT: {
      p_data = (tBTA_GATTS*)param;
      break;
    }

    case BTA_GATTS_CLOSE_EVT: {
       //not required
       break;
    }

    case BTA_GATTS_PHY_UPDATE_EVT: {

      p_data = (tBTA_GATTS*)param;
      CallControllerDeviceList *remoteDevice =
        cc_instance->remoteDevices.FindByConnId(p_data->phy_update.conn_id);
      if(remoteDevice == NULL) {
        LOG(INFO) << __func__ << " device not found ignore phy update "
             << p_data->phy_update.status;
        status = BT_STATUS_FAIL;
        break;
      }
      rsp->event = CCS_PHY_UPDATE;
      rsp->oper.PhyOp.rx_phy = p_data->phy_update.rx_phy;
      rsp->oper.PhyOp.tx_phy = p_data->phy_update.tx_phy;
      rsp->remoteDevice = remoteDevice;
      break;
    }

    case BTA_GATTS_CONN_UPDATE_EVT: {
      p_data = (tBTA_GATTS*)param;
      CallControllerDeviceList *remoteDevice =
        cc_instance->remoteDevices.FindByConnId(p_data->phy_update.conn_id);
      if(remoteDevice == NULL) {
        LOG(INFO) << __func__ << " connection update device not found";
        break;
      }
      LOG(INFO) << __func__ << " connection update status " << p_data->phy_update.status;
      rsp->event = CCS_CONNECTION_UPDATE;
      rsp->oper.ConnectionUpdateOp.remoteDevice = remoteDevice;
      rsp->oper.ConnectionUpdateOp.remoteDevice->latency = p_data->conn_update.latency;
      rsp->oper.ConnectionUpdateOp.remoteDevice->timeout = p_data->conn_update.timeout;
      rsp->oper.ConnectionUpdateOp.remoteDevice->interval = p_data->conn_update.interval;
      rsp->oper.ConnectionUpdateOp.status = p_data->conn_update.status;
      rsp->remoteDevice = remoteDevice;
      break;
    }

    case CCS_ACTIVE_DEVICE_UPDATE:
    {
      tCCS_SET_ACTIVE_DEVICE *data = (tCCS_SET_ACTIVE_DEVICE *)param;
      LOG(INFO) << __func__ << " CCS_ACTIVE_DEVICE_UPDATE address " << data->address;
      if (cc_instance->remoteDevices.FindByAddress(data->address) != NULL) {
        cc_instance->remoteDevices.AddSetActiveDevice(data);
      } else {
          LOG(ERROR) << __func__ << " CCS_ACTIVE_DEVICE_UPDATE failed as given remote is not registered for notif " << data->address;
      }
      break;
    }
    case CCS_CONNECTION_CLOSE_EVENT:
    {
     break;
    }
    case CCS_CALL_STATE_UPDATE:
    {
      std::map<uint8_t, tCCS_CALL_STATE>::iterator it;
      for (it = CallStatelist.begin(); it != CallStatelist.end(); it++){
        tCCS_CALL_STATE obj = it->second;
        _data.push_back(obj.index);
        _data.push_back(obj.state);
        _data.push_back(obj.flags);
      }
      rsp->event = CCS_NOTIFY_ALL;
      rsp->handle = ccsControlServiceInfo.call_state_handle;
      isCallControllerOpUsed = true;
      break;
    }
    case CCS_BEARER_NAME_UPDATE:
    {
      LOG(INFO) << __func__ << " CCS_BEARER_NAME_UPDATE";
      tCCS_BEARER_PROVIDER_INFO *data = (tCCS_BEARER_PROVIDER_INFO*) param;
      uint16_t len = strlen((char*)data->name);
      ReverseByteOrder(data->name, len);
      memcpy(BearerProviderInfo.name, data->name, len);
      rsp->event = CCS_NOTIFY_ALL;
      rsp->handle = ccsControlServiceInfo.bearer_provider_name_handle;
      _data.assign(BearerProviderInfo.name,
          BearerProviderInfo.name + len);
      isCallControllerOpUsed = true;
      break;
    }

    case CCS_OPT_OPCODES:
    {
      LOG(INFO) << __func__ << " CCS_OPT_OPCODES";
      tCCS_SUPP_OPTIONAL_OPCODES *data = (tCCS_SUPP_OPTIONAL_OPCODES*) param;
      SupportedOptionalOpcodes.supp_opcode = data->supp_opcode;

      rsp->event = CCS_NOTIFY_ALL;
      rsp->handle = ccsControlServiceInfo.call_control_point_opcode_supported_handle;

      _data.push_back(SupportedOptionalOpcodes.supp_opcode);
      isCallControllerOpUsed = true;
      break;
    }

    case CCS_BEARER_CURRENT_CALL_LIST_UPDATE:
    {
      LOG(INFO) << __func__ << " CCS_BEARER_CURRENT_CALL_LIST_UPDATE";
      std::map<uint8_t, tCCS_BEARER_LIST_CURRENT_CALLS>::iterator it;
      for (it = BlccInfolist.begin(); it != BlccInfolist.end(); it++){
          tCCS_BEARER_LIST_CURRENT_CALLS obj = it->second;
          _data.push_back(obj.list_length);
          _data.push_back(obj.call_index);
          _data.push_back(obj.call_state);
          _data.push_back(obj.call_flags);
          _data.insert(_data.end(),
              obj.call_uri, obj.call_uri+(obj.list_length-3));
      }

      rsp->event = CCS_NOTIFY_ALL;
      rsp->handle = ccsControlServiceInfo.bearer_list_currentcalls_handle;
      isCallControllerOpUsed = true;
      break;
    }

    case CCS_BEARER_SIGNAL_STRENGTH_UPDATE:
    {
      LOG(INFO) << __func__ << " CCS_BEARER_SIGNAL_STRENGTH_UPDATE";
      tCCS_BEARER_PROVIDER_INFO *data = (tCCS_BEARER_PROVIDER_INFO *) param;
      BearerProviderInfo.signal = data->signal;
      rsp->event = CCS_NOTIFY_ALL;
      rsp->handle = ccsControlServiceInfo.bearer_signal_strength_handle;
      //control whether notification has to happen based
      //on reporting Interval time or not
      rsp->force = false;
      _data.push_back(BearerProviderInfo.signal);
      isCallControllerOpUsed = true;
      break;
    }

    case CCS_BEARER_TECHNOLOGY_UPDATE:
    {
      LOG(INFO) << __func__ << " CCS_BEARER_TECHNOLOGY_UPDATE";
      tCCS_BEARER_PROVIDER_INFO *data = (tCCS_BEARER_PROVIDER_INFO *) param;
      BearerProviderInfo.technology_type = data->technology_type;
      rsp->event = CCS_NOTIFY_ALL;
      rsp->handle = ccsControlServiceInfo.bearer_technology_handle;
      _data.push_back(BearerProviderInfo.technology_type);
      isCallControllerOpUsed = true;
      break;
    }

    case CCS_BEARER_URI_SCHEMES_SUPPORTED: {
      LOG(INFO) << __func__ << " CCS_BEARER_URI_SCHEMES_SUPPORTED";
      tCCS_BEARER_PROVIDER_INFO *data = (tCCS_BEARER_PROVIDER_INFO*) param;
      BearerProviderInfo.bearer_list_len = data->bearer_list_len;
      LOG(INFO) << __func__ << " CCS_BEARER_URI_SCHEMES_SUPPORTED: len " <<BearerProviderInfo.bearer_list_len;
      ReverseByteOrder(data->bearer_schemes_list, BearerProviderInfo.bearer_list_len);
      memcpy(BearerProviderInfo.bearer_schemes_list, data->bearer_schemes_list, BearerProviderInfo.bearer_list_len);
      rsp->event = CCS_NOTIFY_ALL;
      rsp->handle = ccsControlServiceInfo.bearer_uri_schemes_supported_handle;
      isCallControllerOpUsed = true;
      _data.assign(BearerProviderInfo.bearer_schemes_list,
          BearerProviderInfo.bearer_schemes_list + BearerProviderInfo.bearer_list_len);
      isCallControllerOpUsed = true;
      break;
    }

    case CCS_INCOMING_CALL_UPDATE:
    {
      LOG(INFO) << __func__ << " CCS_INCOMING_CALL_UPDATE";
      tCCS_INCOMING_CALL* data = (tCCS_INCOMING_CALL *) param;
      IncomingCallInfo.index = data->index;
      uint16_t len = strlen((char*)data->incoming_uri);
      ReverseByteOrder(data->incoming_uri, len);
      memcpy(IncomingCallInfo.incoming_uri, data->incoming_uri, len);

      rsp->event = CCS_NOTIFY_ALL;
      rsp->handle = ccsControlServiceInfo.incoming_call_handle;
      _data.push_back(IncomingCallInfo.index);
      _data.insert(_data.end(), IncomingCallInfo.incoming_uri,
                   IncomingCallInfo.incoming_uri + len);
      isCallControllerOpUsed = true;
      break;
    }

    case CCS_INCOMING_TARGET_URI_UPDATE:
    {
      LOG(INFO) << __func__ << " CCS_INCOMING_TARGET_URI_UPDATE";
      tCCS_INCOMING_CALL_URI* data = (tCCS_INCOMING_CALL_URI *) param;
      IncomingCallTargetUri.index = data->index;
      uint16_t len = strlen((char*)data->incoming_target_uri);
      LOG(INFO) << __func__ << " CCS_INCOMING_TARGET_URI_UPDATE: urilen " << len;
      ReverseByteOrder(data->incoming_target_uri, len);
      memcpy(IncomingCallTargetUri.incoming_target_uri, data->incoming_target_uri, len);

      rsp->event = CCS_NOTIFY_ALL;
      rsp->handle = ccsControlServiceInfo.incoming_call_target_beareruri_handle;
      _data.push_back(IncomingCallTargetUri.index);
      _data.insert(_data.end(), IncomingCallTargetUri.incoming_target_uri,
                   IncomingCallTargetUri.incoming_target_uri + len);
      isCallControllerOpUsed = true;
      break;
    }

    case CCS_TERMINATION_REASON_UPDATE:
    {
        LOG(INFO) << __func__ << " CCS_TERMINATION_REASON_UPDATE";
        tCCS_TERM_REASON* data = (tCCS_TERM_REASON *) param;
        TerminationReason.index = data->index;
        TerminationReason.reason = data->reason;

        rsp->event = CCS_NOTIFY_ALL;
        rsp->handle = ccsControlServiceInfo.call_termination_reason_handle;
        _data.push_back(TerminationReason.index);
        _data.push_back(TerminationReason.reason);

        isCallControllerOpUsed = true;
        break;
    }

    case CCS_STATUS_FLAGS_UPDATE:
    {
      LOG(INFO) << __func__ << " CCS_STATUS_FLAGS_UPDATE";
      tCCS_STATUS_FLAGS *data = (tCCS_STATUS_FLAGS*) param;

      ReverseByteOrder((unsigned char*)&data->supported_flags, sizeof(data->supported_flags));
      StatusFlags.supported_flags = data->supported_flags;
      rsp->event = CCS_NOTIFY_ALL;
      rsp->handle = ccsControlServiceInfo.call_status_flags_handle;
      _data.push_back(StatusFlags.supported_flags);
      isCallControllerOpUsed = true;
      break;
    }

    case CCS_CCID_UPDATE:
    {
      LOG(INFO) << __func__ << " CCS_CCID_UPDATE";
      tCCS_CONTENT_CONTROL_ID *data = (tCCS_CONTENT_CONTROL_ID *) param;
      ReverseByteOrder((unsigned char*)&data->ccid, sizeof(data->ccid));
      CcidInfo.ccid = (uint32_t)data->ccid;
      rsp->event = CCS_NOTIFY_ALL;
      rsp->handle = ccsControlServiceInfo.ccid_handle;
      _data.push_back(CcidInfo.ccid);
      isCallControllerOpUsed = true;
      break;
    }

    case CCS_CALL_CONTROL_RESPONSE:
    {
      LOG(INFO) << __func__ << " CCS_CALL_CONTROL_RESPONSE";

      rsp->event = CCS_NOTIFY_ALL;
      rsp->handle = ccsControlServiceInfo.call_control_point_handle;
      _data.push_back(CallControllerResp.opcode);
      _data.push_back(CallControllerResp.index);
      _data.push_back(CallControllerResp.response_status);
      isCallControllerOpUsed = true;
      break;
    }
    default:
      LOG(INFO) << __func__ << " event not matched !!";
      break;
  }

  if(rsp->event != CCS_NONE_EVENT) {
    if (isCallControllerOpUsed == true) {
        rsp->oper.CallControllerOp.data = std::move(_data);
        LOG(INFO) << __func__ << " After Moving size " << rsp->oper.CallControllerOp.data.size();
    }
    CCSHandler(rsp->event, rsp);
  }
  if(rsp) {
    LOG(INFO) << __func__ << "free rsp data";
    free(rsp);
  }
}



void BTCcCback(tBTA_GATTS_EVT event, tBTA_GATTS* param) {

   HandleCcsEvent((uint32_t)event, param);
}


 bool DeviceStateConnectionHandler(uint32_t event, void* param) {
  LOG(INFO) << __func__ << " device connected handle " << event;
  tcc_resp_t *p_data = (tcc_resp_t *) param;
  switch (event) {

    case CCS_NOTIFY_ALL: {
      LOG(INFO) << __func__ << " device notify all";
      if (p_data->handle == ccsControlServiceInfo.bearer_signal_strength_handle) {
          if (p_data->force == false &&
               p_data->remoteDevice->signal_strength_report_interval != 0) {
           LOG(INFO) << __func__ << "Not a timer expired push, dont notify to remote";
           break;
        }
      }

      GattsOpsQueue::SendNotification(p_data->remoteDevice->conn_id, p_data->handle,
                                      p_data->oper.CallControllerOp.data, false);
      break;
    }

    case CCS_READ_RSP:

      LOG(INFO) << __func__ << " device CCS_READ_RSP update " << event;
      BTA_GATTS_SendRsp(p_data->remoteDevice->conn_id, p_data->oper.ReadOp.trans_id,
          BT_STATUS_SUCCESS, &p_data->rsp_value);
      break;

    case CCS_DESCRIPTOR_READ_RSP:

      LOG(INFO) << __func__ << " device CCS_DESCRIPTOR_READ_RSP update " << event;
      BTA_GATTS_SendRsp(p_data->remoteDevice->conn_id, p_data->oper.ReadDescOp.trans_id,
          BT_STATUS_SUCCESS, &p_data->rsp_value);
      break;

    case CCS_DESCRIPTOR_WRITE_RSP:
    {
      LOG(INFO) << __func__ << " device CCS_DESCRIPTOR_WRITE_RSP update rsp: " << p_data->oper.WriteDescOp.need_rsp;
      tGATTS_RSP rsp_struct;
      rsp_struct.attr_value.handle = p_data->rsp_value.attr_value.handle;
      rsp_struct.attr_value.offset = p_data->rsp_value.attr_value.offset;
      if (p_data->remoteDevice->congested == false &&
            p_data->oper.WriteDescOp.need_rsp) {
        //send rsp to write
        LOG(INFO) << __func__ << " gett send rsp";
        BTA_GATTS_SendRsp(p_data->remoteDevice->conn_id, p_data->oper.WriteDescOp.trans_id,
            p_data->oper.WriteDescOp.status, &rsp_struct);
      }
      if (!p_data->oper.WriteDescOp.status && p_data->oper.WriteDescOp.notification) {
        //notify update to register device
        GattsOpsQueue::SendNotification(p_data->remoteDevice->conn_id,
                                        p_data->oper.WriteDescOp.char_handle,
                                        p_data->oper.WriteDescOp.value, false);
      } else {
        LOG(INFO) << __func__ << " notification disable  handle : " << p_data->oper.WriteDescOp.char_handle;
      }
      break;
    }

    case CCS_WRITE_RSP: {
      LOG(INFO) << __func__ << " device CCS_WRITE_RSP update " << event;
      bool need_rsp = p_data->oper.WriteOp.need_rsp;
      LOG(INFO) << __func__ << " device CCS_WRITE_RSP update " << event << " need_rsp: " <<need_rsp;
      if (need_rsp) {
         BTA_GATTS_SendRsp(p_data->remoteDevice->conn_id, p_data->oper.WriteOp.trans_id,
             BT_STATUS_SUCCESS, &p_data->rsp_value);
      }
      break;
    }

    case CCS_CONNECTION_UPDATE: {
      LOG(INFO) << __func__ << " device cconnection update " << event;
      break;
    }

    case CCS_PHY_UPDATE: {
      LOG(INFO) << __func__ << " device CCS_PHY_UPDATE update " << event;
      p_data->remoteDevice->rx_phy = p_data->oper.PhyOp.rx_phy;
      p_data->remoteDevice->tx_phy = p_data->oper.PhyOp.tx_phy;
      break;
    }

    case CCS_MTU_UPDATE: {
      LOG(INFO) << __func__ << " device CCS_MTU_UPDATE update " << event;
      p_data->remoteDevice->mtu = p_data->oper.MtuOp.mtu;
      break;
    }

    case CCS_CONGESTION_UPDATE: {
      LOG(INFO) << __func__ << ": device CCS_CONGESTION_UPDATE update: " << event;
      CcpCongestionUpdate(p_data);
      break;
    }

    case CCS_DISCONNECTION: {
      LOG(INFO) << __func__ << " device CCS_DISCONNECTION remove " << event;
      cc_instance->remoteDevices.Remove(p_data->remoteDevice->peer_bda);
      cc_instance->ConnectionStateCallback(CCS_DISCONNECTED, p_data->remoteDevice->peer_bda);
      break;
    }

    case CCS_CONNECTION_CLOSE_EVENT: {
      LOG(INFO) << __func__ << " device connection closing";
        // Close active connection
      if (p_data->remoteDevice->conn_id != 0)
        BTA_GATTS_Close(p_data->remoteDevice->conn_id);
      else
        BTA_GATTS_CancelOpen(ccsControlServiceInfo.server_if, p_data->remoteDevice->peer_bda, true);
        // Cancel pending background connections
        BTA_GATTS_CancelOpen(ccsControlServiceInfo.server_if, p_data->remoteDevice->peer_bda, false);
      break;
    }

    case CCS_BOND_STATE_CHANGE_EVENT:
      LOG(INFO) << __func__ << " Bond state change";
      cc_instance->remoteDevices.Remove(p_data->remoteDevice->peer_bda);
      break;

    default:
      LOG(INFO) << __func__ << " event not matched";
      break;
  }

  return BT_STATUS_SUCCESS;
}


bool DeviceStateDisconnectedHandler(uint32_t event, void* param) {
  LOG(INFO) << __func__ << " device disconnected handle " << event;
  tcc_resp_t *p_data = (tcc_resp_t *) param;
  switch (event) {
    case CCS_CONNECTION:
    {
      LOG(INFO) << __func__ << " connection processing " << event;
      p_data->remoteDevice->state = CCS_CONNECTED;
      p_data->remoteDevice->call_state_notify = 0x00;
      p_data->remoteDevice->bearer_provider_name_notify = 0x00;
      p_data->remoteDevice->call_control_point_notify = 0x00;
      p_data->remoteDevice->bearer_technology_changed_notify = 0x00;
      p_data->remoteDevice->bearer_uci_notify = 0x00;
      p_data->remoteDevice->bearer_current_calls_list_notify = 0x00;
      p_data->remoteDevice->call_friendly_name_notify = 0x00;
      p_data->remoteDevice->call_termination_reason_notify = 0x00;
      p_data->remoteDevice->congested = false;
      // p_data->remoteDevice->conn_id;

      p_data->remoteDevice->timeout = 0;
      p_data->remoteDevice->latency = 0;
      p_data->remoteDevice->interval = 0;
      p_data->remoteDevice->rx_phy = 0;
      p_data->remoteDevice->tx_phy = 0;
      cc_instance->ConnectionStateCallback(CCS_CONNECTED, p_data->remoteDevice->peer_bda);
      break;
    }

    case CCS_CONGESTION_UPDATE: {
      LOG(INFO) << __func__ << ": device CCS_CONGESTION_UPDATE update: " << event;
      CcpCongestionUpdate(p_data);
      break;
    }

    case CCS_MTU_UPDATE:
    case CCS_PHY_UPDATE:
    case CCS_DISCONNECTED:
    case CCS_READ_RSP:
    case CCS_DESCRIPTOR_READ_RSP:
    case CCS_WRITE_RSP:
    case CCS_DESCRIPTOR_WRITE_RSP:
    case CCS_NOTIFY_ALL:
    case CCS_DISCONNECTION:

    default:
      //ignore event
      LOG(INFO) << __func__ << " Ignore event " << event;
      break;
  }
  return BT_STATUS_SUCCESS;
}

bool is_digits(const std::string &str)
{
    return str.find_first_not_of("0123456789+") == std::string::npos;
}

bool IsValidOriginateUri(std::string uri) {
    bool ret = false;
    std::vector<std::string> out;
    char *token;
    char* rest = const_cast<char*>(uri.c_str());
    while ((token = strtok_r(rest, ":", &rest)))
    {
        out.push_back(std::string(token));
    }
    if (out.size() == 2) {
        if (out[0].compare("tel") == 0 && is_digits(out[1])) {
            ret = true;
        }
    }
    LOG(INFO) << __func__ << " ret: " << ret;
    return ret;
}

bool CCSActiveProfile(RawAddress addr) {
    bool isCCSActiveProfile = false;
    int32_t activeProfile;
    activeProfile = osi_property_get_int32("persist.vendor.qcom.bluetooth.default_profiles",0);
    if ((activeProfile&0x2000) == 0x2000) {
        isCCSActiveProfile = true;
    }
    LOG(INFO) << __func__ << " activeProfile "<< activeProfile <<" for" << addr;
    return isCCSActiveProfile;
}

bool CCSHandler(uint32_t event, void* param) {

  tcc_resp_t *p_data = (tcc_resp_t *)param;

  CallControllerDeviceList *device = p_data->remoteDevice;
  LOG(INFO) << __func__ << " inactive ccs handle event "<< bta_cc_event_str(event);
  switch(p_data->event) {
    case CCS_NOTIFY_ALL: {

      std::vector<CallControllerDeviceList>notifyDevices = cc_instance->remoteDevices.FindNotifyDevices(p_data->handle);
      std::vector<CallControllerDeviceList>::iterator it;
      LOG(INFO) << __func__ << " Notify all handle "<< p_data->handle;
      if (notifyDevices.size() <= 0) {
         LOG(INFO) << __func__ << " No device register for notification";
         break;
      }
      for (it = notifyDevices.begin(); it != notifyDevices.end(); it++){
        if (CCSActiveProfile(it->peer_bda)) {
            LOG(INFO) << __func__ << " Notify all handle device id " << it->conn_id;
            p_data->remoteDevice = cc_instance->remoteDevices.FindByConnId(it->conn_id);
            it->DeviceStateHandlerPointer[it->state](p_data->event, p_data);
        }
      }
      break;
    }
    case CCS_WRITE_RSP: {

      LOG(INFO) << __func__ << " Push Write response first: " << device->state;
      device = p_data->remoteDevice;
      device->DeviceStateHandlerPointer[device->state](p_data->event, p_data);
      //Process the values now
      uint8_t* data = p_data->oper.WriteOp.data;
      int len = p_data->oper.WriteOp.len;
      RawAddress peer_bda = p_data->remoteDevice->peer_bda;
      std::map<uint8_t, tCCS_CALL_STATE>::iterator it;
      bool valid_index = false;
      uint8_t indices[10];
      char URI[MAX_URI_SIZE];
      int i;
      uint32_t handle = p_data->oper.WriteOp.char_handle;
      if(handle == ccsControlServiceInfo.call_control_point_handle) {
           CallControllerOps.operation = data[0];
           LOG(INFO) << __func__ << " operation: " << std::hex << CallControllerOps.operation;
           if (gIsActiveCC == true && !cc_instance->remoteDevices.FindActiveDevice(p_data->remoteDevice) &&
               (CallControllerOps.operation == CALL_TERMINATE ||
               CallControllerOps.operation == CALL_LOCAL_HOLD ||
               CallControllerOps.operation == CALL_LOCAL_RETRIEVE)) {
                   LOG(ERROR) << __func__ << "TERM|HOLD|RET|JOIN triggered from non-active Device";
                cc_instance->CallControlResponse(CallControllerOps.operation,
                                                                   CCS_DEFAULT_INDEX_VAL,
                                                                   CCS_OPCODE_UNSUCCESSFUL, peer_bda);
                return true;
           }
           switch(CallControllerOps.operation) {
            case CALL_ACCEPT:{
                if (len != 2) {
                    LOG(ERROR) << __func__ << " Invalid params";
                    valid_index = false;
                } else {
                    indices[0] = data[1];
                    valid_index = false;
                    for (i=0,it = CallStatelist.begin(); it != CallStatelist.end(); it++, i++){
                        tCCS_CALL_STATE obj = it->second;
                        if (obj.index == indices[0] && obj.state == CCS_STATE_INCOMING) {
                            valid_index = true;
                            break;
                        }
                    }
                }
                if (valid_index == true) {
                    cc_instance->CallControlPointChange(CallControllerOps.operation, indices,
                                                      DEFAULT_INDICIES_COUNT, NULL,
                                                      device->peer_bda);
                    cc_instance->CallControlResponse(CallControllerOps.operation,
                                                   indices[0],
                                                   CCS_STATUS_SUCCESS, peer_bda);
                } else {
                    LOG(INFO) << " ACCEPT ignored as there is no valid Index";
                    cc_instance->CallControlResponse(CallControllerOps.operation,
                                                   CCS_DEFAULT_INDEX_VAL,
                                                   CCS_INVALID_INDEX, peer_bda);
                }
                break;
            }
            case CALL_TERMINATE: {
               if (len != 2) {
                   LOG(ERROR) << __func__ << " Invalid params";
                   valid_index = false;
               } else {
                   indices[0] = data[1];
                   valid_index = false;
                   for (i=0,it = CallStatelist.begin(); it != CallStatelist.end(); it++, i++) {
                       tCCS_CALL_STATE obj = it->second;
                       if (obj.index == indices[0]) {
                           LOG(INFO) << __func__ << " call index match: " << indices[0];
                           valid_index = true;
                           break;
                       }
                    }
               }
               if (valid_index == true) {
                    cc_instance->CallControlPointChange(CallControllerOps.operation, indices,
                                                       DEFAULT_INDICIES_COUNT, NULL,
                                                       device->peer_bda);
                    cc_instance->CallControlResponse(CallControllerOps.operation,
                                                    indices[0],
                                                    CCS_STATUS_SUCCESS, peer_bda);
                    gIsTerminatedInitiatedFromClient = true;
                    gTerminateIntiatedIndex = indices[0];
               } else {
                    LOG(INFO) << " TERMINATE ignored as there is no valid Index";
                    cc_instance->CallControlResponse(CallControllerOps.operation,
                                                    CCS_DEFAULT_INDEX_VAL,
                                                    CCS_INVALID_INDEX, peer_bda);
               }
             break;
            }
            case CALL_LOCAL_HOLD: {
                if (len != 2) {
                   LOG(ERROR) << __func__ << " Invalid params";
                   valid_index = false;
                } else {
                    indices[0]= data[1];
                    valid_index = false;
                    for (i=0,it = CallStatelist.begin(); it != CallStatelist.end(); it++, i++) {
                        tCCS_CALL_STATE obj = it->second;
                        if (obj.index ==  indices[0] &&
                            (obj.state == CCS_STATE_INCOMING || obj.state == CCS_STATE_ACTIVE)) {
                            LOG(INFO) << __func__ << " call index match: " << indices[0];
                            valid_index = true;
                            break;
                        }
                    }
                }
                if (valid_index == true) {
                     cc_instance->CallControlPointChange(CallControllerOps.operation, indices,
                                                         DEFAULT_INDICIES_COUNT, NULL,
                                                         device->peer_bda);

                } else {
                     LOG(INFO) << " CALL_LOCAL_HOLD ignored as there is no valid Index";
                     cc_instance->CallControlResponse(CallControllerOps.operation,
                                                      CCS_DEFAULT_INDEX_VAL,
                                                      CCS_INVALID_INDEX, peer_bda);
                }
                break;
            }
            case CALL_LOCAL_RETRIEVE: {
                if (len != 2) {
                    LOG(ERROR) << __func__ << " Invalid params";
                    valid_index = false;
                } else {
                    indices[0]= data[1];
                    valid_index = false;
                    for (i=0,it = CallStatelist.begin(); it != CallStatelist.end(); it++, i++) {
                        tCCS_CALL_STATE obj = it->second;
                        if (obj.index ==  indices[0] && (obj.state == CCS_STATE_LOCAL_HELD )) {
                            LOG(INFO) << __func__ << " call index match: " << indices[0];
                            valid_index = true;
                            break;
                        }
                    }
                }
                if (valid_index == true) {
                    cc_instance->CallControlPointChange( CallControllerOps.operation, indices,
                                                      DEFAULT_INDICIES_COUNT, NULL,
                                                      device->peer_bda);

                } else {
                    LOG(INFO) << " CALL_LOCAL_RETRIEVE ignored as there is no valid Index";
                    cc_instance->CallControlResponse(CallControllerOps.operation,
                                                    CCS_DEFAULT_INDEX_VAL,
                                                    CCS_INVALID_INDEX, peer_bda);
                }
                break;
            }
            case CALL_ORIGINATE: {
                  LOG(INFO) << __func__ << " CALL_ORIGINATE match:";
                  memset(URI, '\0', sizeof(char)*MAX_URI_SIZE);
                  strlcpy(URI, (char*)&data[1], len);
                  LOG(INFO) << __func__ << " ORIGINATE: " << URI;
                  if (IsValidOriginateUri(URI)) {
                      cc_instance->CallControlPointChange(CallControllerOps.operation, /*unused*/0,
                                                       /*count*/0, URI, device->peer_bda);
                  } else {
                    cc_instance->CallControlResponse(CallControllerOps.operation,
                                                   CCS_DEFAULT_INDEX_VAL,
                                                   CCS_INVALID_OUTGOING_URI, peer_bda);
                  }
                  break;
               }
            case CALL_JOIN: {
                  int count = len-1;
                  uint8_t *start_of_indicies = &(data[1]);
                  uint8_t indices[MAX_CCS_CONNECTION];
                  valid_index = true;
                  bool atleastOneHeldCall = false;
                  for (int i=0; i<count; i++) {
                      indices[i] = start_of_indicies[i];
                      LOG(INFO) << __func__ << " Indicies: " << i << ": " <<indices[i];
                      std::map<uint8_t, tCCS_CALL_STATE>::iterator j = CallStatelist.find(indices[i]);
                      if (j == CallStatelist.end()) {
                        valid_index = false;
                        break;
                      } else if (j->second.state == CCS_STATE_LOCAL_HELD) {
                         atleastOneHeldCall = true;
                      }
                  }
                  if (CallStatelist.size() < 2 || atleastOneHeldCall == false) {
                      LOG(INFO) << __func__ << " Join is not valid: ";
                      valid_index = false;
                  }
                  if (count > 1 && valid_index == true) {
                     cc_instance->CallControlPointChange(CallControllerOps.operation,
                                                        indices, count,
                                                        NULL, device->peer_bda);
                  } else {
                     LOG(INFO) << __func__ << " no valid indices found for JOIN operation ";
                     cc_instance->CallControlResponse(CallControllerOps.operation,
                                                     CCS_DEFAULT_INDEX_VAL,
                                                     CCS_INVALID_INDEX, peer_bda);
                  }
                  break;
                }
            default:
                LOG(ERROR) << __func__ << " Unhandled Event: " << CallControllerOps.operation;
                cc_instance->CallControlResponse(CallControllerOps.operation,
                                                CCS_DEFAULT_INDEX_VAL,
                                                CCS_OPCODE_NOT_SUPPORTED, peer_bda);
            }
        } else if (handle == ccsControlServiceInfo.bearer_signal_strength_report_interval_handle) {
            if (len != 1) {
                LOG(ERROR) << " Invalid input for SSR interval";
                return BT_STATUS_SUCCESS;
            }
            LOG(INFO) << __func__ << " signal strength repo Interval: " << data[0];
            BearerProviderInfo.signal_report_interval = data[0];
            cc_instance->remoteDevices.UpdateSSReportingInterval(device->peer_bda, BearerProviderInfo.signal_report_interval);
        }
        break;
    }

    case CCS_CONGESTION_UPDATE: {
      LOG(INFO) << __func__ << ": device CCS_CONGESTION_UPDATE update: " << event;
      CcpCongestionUpdate(p_data);
      break;
    }

    case CCS_READ_RSP:
    case CCS_DESCRIPTOR_READ_RSP:
    case CCS_DESCRIPTOR_WRITE_RSP:
    case CCS_CONNECTION_UPDATE:
    case CCS_PHY_UPDATE:
    case CCS_CONNECTION:
      LOG(INFO) << __func__ << " calling device state " << device->state;
      device = p_data->remoteDevice;
      device->DeviceStateHandlerPointer[device->state](p_data->event, p_data);
      break;

      default:
      LOG(INFO) << __func__ << " event is not in list";
      break;
    }

  return BT_STATUS_SUCCESS;

}

void CcpCongestionUpdate(tcc_resp_t* p_data) {
  p_data->remoteDevice->congested = p_data->oper.CongestionOp.congested;
  LOG(INFO) << __func__ << ": conn_id: " << p_data->remoteDevice->conn_id
                        << ", congested: " << p_data->remoteDevice->congested;

  GattsOpsQueue::CongestionCallback(p_data->remoteDevice->conn_id,
                                    p_data->remoteDevice->congested);
}
