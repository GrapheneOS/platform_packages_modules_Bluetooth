/*
 *Copyright (c) 2020-2021, The Linux Foundation. All rights reserved.
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
 * limitations under the License.
 */
#pragma once

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "bta_gatt_api.h"
#include <hardware/bluetooth_callcontrol_callbacks.h>
#include <hardware/bluetooth_callcontrol_interface.h>

using bluetooth::Uuid;
using bluetooth::call_control::CallControllerCallbacks;
#define MAX_RESPONSE_DATA_LEN 255
#define MAX_CCS_CONNECTION   5
#define MAX_BEARER_NAME        255
#define MAX_UCI_NAME           255
#define MAX_URI_LENGTH         255
#define MAX_BEARER_LIST_LEN    255
#define MAX_FRIENDLY_NAME_LEN      255
//Atmost there could be only two Indicies (for JOIN)
//Keeping this as Internal max as SPec don't define any upper limit on this
#define MAX_NUM_INDICIES 10

#define INBAND_RINGTONE_FEATURE_BIT  0x01
#define SILENT_MODE_FEATURE_BIT  0x02

typedef enum {
  CCS_NONE_EVENT = 120,
  CCS_INIT_EVENT,
  CCS_CLEANUP_EVENT,
  CCS_CALL_STATE_UPDATE,
  CCS_BEARER_NAME_UPDATE,
  CCS_BEARER_UCI_UPDATE,
  CCS_BEARER_URI_SCHEMES_SUPPORTED,
  CCS_UPDATE,
  CCS_OPT_OPCODES,
  CCS_BEARER_CURRENT_CALL_LIST_UPDATE,
  CCS_BEARER_SIGNAL_STRENGTH_UPDATE,
  CCS_SIGNAL_STRENGTH_REPORT_INTERVAL,
  CCS_STATUS_FLAGS_UPDATE,
  CCS_INCOMING_CALL_UPDATE,
  CCS_INCOMING_TARGET_URI_UPDATE,
  CCS_TERMINATION_REASON_UPDATE,
  CCS_BEARER_TECHNOLOGY_UPDATE,
  CCS_CCID_UPDATE,
  CCS_ACTIVE_DEVICE_UPDATE,
  CCS_CALL_CONTROL_RESPONSE,
  //events to handle in CCS state machine
  CCS_NOTIFY_ALL,
  CCS_WRITE_RSP,
  CCS_READ_RSP,
  CCS_DESCRIPTOR_WRITE_RSP,
  CCS_DESCRIPTOR_READ_RSP,
  CCS_CONNECTION,
  CCS_DISCONNECTION,
  CCS_CONNECTION_UPDATE,
  CCS_CONGESTION_UPDATE,
  CCS_PHY_UPDATE,
  CCS_MTU_UPDATE,
  CCS_SET_ACTIVE_DEVICE,
  CCS_CONNECTION_CLOSE_EVENT,
  CCS_BOND_STATE_CHANGE_EVENT,
}cc_event_t;

typedef enum {
  CCS_STATUS_SUCCESS = 0x00,
  CCS_OPCODE_NOT_SUPPORTED,
  CCS_OPCODE_UNSUCCESSFUL,
  CCS_INVALID_INDEX,
  CCS_STATE_MISMATCH,
  CCS_LACK_OF_RESOURCES,
  CCS_INVALID_OUTGOING_URI,
  CCS_CALL_STATE_INACTIVE,
}cc_error_t;

typedef enum {
  CCS_DISCONNECTED = 0x00,
  CCS_CONNECTED,
  CCS_MAX_DEVICE_STATE
} call_connect_state_t;

typedef enum {
  CALL_ACCEPT = 0x00,
  CALL_TERMINATE,
  CALL_LOCAL_HOLD,
  CALL_LOCAL_RETRIEVE,
  CALL_ORIGINATE,
  CALL_JOIN,
 } cc_opcode_t;

 typedef enum {
   CC_TERM_INVALID_ORIG_URI = 0x00,
   CC_TERM_FAILED,
   CC_TERM_END_FROM_REMOTE,
   CC_TERM_END_FROM_SERVER,
   CC_TERM_LINE_BUSY,
   CC_TERM_NW_CONGESTION,
   CC_TERM_END_FROM_CLIENT,
   CC_TERM_NO_SERVICE,
   CC_TERM_NO_ANSWER,
  } cc_term_reason_t;

 typedef enum {
   CCS_STATE_INCOMING = 0x00,
   CCS_STATE_DIALING,
   CCS_STATE_ALERTING,
   CCS_STATE_ACTIVE,
   CCS_STATE_LOCAL_HELD,
   CCS_STATE_REMOTELY_HELD,
   CCS_STATE_LOCAL_REMOTE_HELD,
   CCS_STATE_DISCONNECTED,
 } cc_state_t;

 //connection state machine
 bool DeviceStateConnectionHandler(uint32_t event, void* param);
 bool DeviceStateDisConnectingHandler(uint32_t event, void* param);
 bool DeviceStateDisconnectedHandler(uint32_t event, void* param);

typedef struct {
  int server_if;
  Uuid ccs_service_uuid;
  Uuid bearer_provider_name_uuid;
  Uuid call_control_point_uuid;
  Uuid call_control_point_opcode_supported_uuid;
  Uuid bearer_uci_uuid;
  Uuid bearer_technology_uuid;
  Uuid bearer_uri_schemes_supported_uuid;
  Uuid bearer_signal_strength_uuid;
  Uuid bearer_signal_strength_report_interval_uuid;
  Uuid bearer_list_currentcalls_uuid;
  Uuid incoming_call_target_beareruri_uuid;
  Uuid call_status_flags_uuid;
  Uuid call_state_uuid;
  Uuid gtbs_ccid_uuid;
  Uuid call_termination_reason_uuid;
  Uuid incoming_call_uuid;
  Uuid call_friendly_name_uuid;
  //handle for characteristics
  uint16_t call_state_handle;
  uint16_t bearer_provider_name_handle;
  uint16_t call_control_point_opcode_supported_handle;
  uint16_t call_control_point_handle;
  uint16_t bearer_uci_handle;
  uint16_t bearer_technology_handle;
  uint16_t bearer_uri_schemes_supported_handle;
  uint16_t bearer_signal_strength_handle;
  uint16_t bearer_signal_strength_report_interval_handle;
  uint16_t bearer_list_currentcalls_handle;
  uint16_t incoming_call_target_beareruri_handle;
  uint16_t call_status_flags_handle;
  uint16_t call_termination_reason_handle;
  uint16_t incoming_call_handle;
  uint16_t call_friendly_name_handle;
  uint16_t ccid_handle;
  uint16_t call_state_desc;
  uint16_t bearer_provider_name_desc;
  uint16_t call_control_point_opcode_supported_desc;
  uint16_t call_control_point_desc;
  uint16_t bearer_uci_desc;
  uint16_t bearer_technology_desc;
  uint16_t bearer_uri_schemes_supported_desc;
  uint16_t bearer_signal_strength_desc;
  uint16_t bearer_signal_strength_report_interval_desc;
  uint16_t bearer_list_currentcalls_desc;
  uint16_t incoming_call_target_bearerURI_desc;
  uint16_t call_status_flags_desc;
  uint16_t call_termination_reason_desc;
  uint16_t incoming_call_desc;
  uint16_t call_friendly_name_desc;
  uint16_t ccid_desc;
}CcsControlServiceInfo_t;

typedef struct {
  call_connect_state_t state;
  uint16_t call_state_notify;
  uint16_t bearer_provider_name_notify;
  uint16_t call_control_point_notify;
  uint16_t call_control_point_opcode_supported_notify;
  uint16_t bearer_technology_changed_notify;
  uint16_t bearer_uci_notify;
  uint16_t bearer_uri_schemes_supported_notify;
  uint16_t bearer_current_calls_list_notify;
  uint16_t bearer_signal_strength_notify;
  uint16_t bearer_signal_strength_report_interval_notify;
  uint16_t incoming_call_state_notify;
  uint16_t incoming_call_target_URI_notify;
  uint16_t status_flags_notify;
  uint16_t call_termination_reason_notify;
  uint16_t call_friendly_name_notify;
  uint8_t signal_strength_report_interval;
  alarm_t* signal_strength_reporting_timer;
  bool congested;
  int conn_id;
  int trans_id;
  int timeout;
  int latency;
  int interval;
  int rx_phy;
  int tx_phy;
  int mtu;

  RawAddress peer_bda;
  bool (*DeviceStateHandlerPointer[2])(uint32_t event, void* param);
}CallControllerDeviceList;

typedef struct {
  std::vector<RawAddress> address;
  int set_id;
}CallActiveDevice;

typedef struct {
  uint8_t index;
  uint8_t state;
  uint8_t flags;
}tCCS_CALL_STATE;

typedef struct {
 uint8_t index;
 uint8_t incoming_target_uri[MAX_URI_LENGTH];
}tCCS_INCOMING_CALL_URI;

typedef struct {
 uint8_t index;
 uint8_t incoming_uri[MAX_URI_LENGTH];
}tCCS_INCOMING_CALL;

typedef struct {
  uint8_t operation;
  uint8_t  index[MAX_NUM_INDICIES];
  uint8_t supported_flags;
  char* uri;
  uint32_t ccid;
}tCCS_CALL_CONTROL_POINT;

typedef struct {
 uint8_t opcode;
 uint8_t index;
 uint8_t  response_status;
 RawAddress remote_address;
}tCCS_CALL_CONTROL_RESPONSE;

typedef struct {
  uint16_t supported_flags;
}tCCS_STATUS_FLAGS;

typedef struct {
  uint16_t supp_opcode;
}tCCS_SUPP_OPTIONAL_OPCODES;


typedef struct {
    uint8_t index;
    uint8_t reason;
}tCCS_TERM_REASON;

typedef struct {
    uint8_t index;
    uint8_t name[MAX_FRIENDLY_NAME_LEN];
}tCCS_FRIENDLY_NAME;

typedef struct {
  uint32_t ccid;
}tCCS_CONTENT_CONTROL_ID;

typedef struct {
  RawAddress addr;
}tCCS_CONNECTION_CLOSE;

typedef struct {
  uint8_t list_length;
  uint8_t call_index;
  uint8_t call_state;
  uint8_t call_flags;
  uint8_t call_uri[MAX_URI_LENGTH];
 }tCCS_BEARER_LIST_CURRENT_CALLS;

typedef struct {
  uint8_t name[MAX_BEARER_NAME];
  uint8_t  uci[MAX_UCI_NAME];
  uint8_t length;
  uint8_t  technology_type;
  uint8_t signal;
  uint8_t signal_report_interval;
  int bearer_list_len;
  uint8_t bearer_schemes_list[MAX_BEARER_LIST_LEN];
}tCCS_BEARER_PROVIDER_INFO;

typedef struct {
  bool status;
}tCCS_BEARER_URI_SCHEMES;

//Union ops
struct tCCS_CHAR_DESC_WRITE {
  tCCS_CHAR_DESC_WRITE() {};
  ~tCCS_CHAR_DESC_WRITE() {};
  std::vector<uint8_t> value;
  uint8_t status;
  uint16_t notification;
  uint32_t trans_id;
  uint32_t desc_handle;
  uint32_t char_handle;
  bool need_rsp;
  bool prep_rsp;
  //is to send notification
};

struct tCCS_CHAR_DESC_READ {
  tCCS_CHAR_DESC_READ() {};
  ~tCCS_CHAR_DESC_READ() {};
  uint8_t status;
  uint32_t trans_id;
  uint32_t desc_handle;
  uint32_t char_handle;
};

struct tCCS_CHAR_GATT_READ {
  tCCS_CHAR_GATT_READ() {};
  ~tCCS_CHAR_GATT_READ() {};
  uint8_t status;
  uint32_t trans_id;
  uint32_t char_handle;
};

struct tCCS_CHAR_WRITE {
  tCCS_CHAR_WRITE() {};
  ~tCCS_CHAR_WRITE() {};
  uint8_t status;
  bool need_rsp;
  bool prep_rsp;
  uint16_t offset;
  uint16_t trans_id;
  uint32_t char_handle;
  int len;
  std::vector<uint8_t> value;
  uint8_t *data;
};

struct tCCS_CONNECTION {
  uint8_t status;
  CallControllerDeviceList remoteDevice;
};

struct tCCS_CONN_UPDATE {
  tCCS_CONN_UPDATE() {};
  ~tCCS_CONN_UPDATE() {};
  uint8_t status;
  CallControllerDeviceList *remoteDevice;
};

struct tCCS_DISCONNECTION {
  tCCS_DISCONNECTION() {};
  ~tCCS_DISCONNECTION() {};
  uint8_t status;
  CallControllerDeviceList *remoteDevice;
};

struct tCCS_CONGESTION {
  tCCS_CONGESTION() {};
  ~tCCS_CONGESTION() {};
  bool congested;
  CallControllerDeviceList *remoteDevice;
};

struct tCCS_PHY{
  tCCS_PHY();
  ~tCCS_PHY();
  uint8_t status;
  uint8_t tx_phy;
  uint8_t rx_phy;
  CallControllerDeviceList *remoteDevice;
};

struct tCCS_MTU {
  tCCS_MTU() {};
  ~tCCS_MTU() {};
  uint8_t status;
  uint16_t mtu;
  CallControllerDeviceList *remoteDevice;
};

struct tCCS_SET_ACTIVE_DEVICE {
  tCCS_SET_ACTIVE_DEVICE() {};
  ~tCCS_SET_ACTIVE_DEVICE() {};
  RawAddress address;
  uint16_t set_id;
};

struct tCALL_CONTROL_UPDATE {
  tCALL_CONTROL_UPDATE() {};
  ~tCALL_CONTROL_UPDATE() {};
  std::vector<uint8_t> data;
};

union CALL_CONTROL_OPERATION{
  CALL_CONTROL_OPERATION() : CallControllerOp() {
  };
  ~CALL_CONTROL_OPERATION() {};
  tCALL_CONTROL_UPDATE CallControllerOp;
  tCCS_SET_ACTIVE_DEVICE SetActiveDeviceOp;
  tCCS_CHAR_DESC_WRITE WriteDescOp;
  tCCS_CHAR_DESC_READ ReadDescOp;
  tCCS_CHAR_WRITE WriteOp;
  tCCS_CHAR_GATT_READ ReadOp;
  tCCS_CONNECTION ConnectionOp;
  tCCS_CONN_UPDATE ConnectionUpdateOp;
  tCCS_DISCONNECTION DisconnectionOp;
  tCCS_CONGESTION CongestionOp;
  tCCS_MTU MtuOp;
  tCCS_PHY PhyOp;
};

typedef union CALL_CONTROL_OPERATION tCCS_OPERATION;

struct tcc_resp_t {
  tcc_resp_t()    {};
  ~tcc_resp_t()    {};
  uint32_t event = 0;
  uint16_t handle = 0;
  uint16_t status = 0;
  bool force = false;
  CallControllerDeviceList *remoteDevice = nullptr;
  tGATTS_RSP rsp_value;
  tCCS_OPERATION oper;
 };

class CallController {

  public:
  virtual ~CallController() = default;
  static void Initialize(bluetooth::call_control::CallControllerCallbacks* callbacks,
                     Uuid app_id, int max_ccs_clients, bool inband_ringing_enabled);
  static void CleanUp();
  static CallController* Get();
  static bool IsCcServiceRunnig();

  virtual void CallState(int len, std::vector<uint8_t> value) = 0;
  virtual void BearerInfoName(uint8_t* bearer_name) = 0;
  virtual void UpdateBearerTechnology(int tech_type) = 0;
  virtual void UpdateSupportedBearerList(uint8_t* list) = 0;
  virtual void UpdateIncomingCallTargetUri(int index, uint8_t* target_uri) = 0;
  virtual void UpdateIncomingCall(int index, uint8_t* Uri) = 0;
  virtual void UpdateBearerSignalStrength(int signal) = 0;
  virtual void UpdateStatusFlags(uint8_t status_flag) = 0;
  virtual void CallControlOptionalOpSupported(int feature) = 0;
  virtual void CallControlResponse(uint8_t op, uint8_t index, uint32_t status, const RawAddress& address)= 0;
  virtual void SetActiveDevice(const RawAddress& address, int setId) = 0;
  virtual void ContentControlId(uint32_t ccid) = 0;
  virtual void Disconnect(const RawAddress& bd_add) = 0;
};

void HandleCcsEvent(uint32_t event, void* param);
bool CCSHandler(uint32_t event, void* param);
void CcpCongestionUpdate(tcc_resp_t * p_data);
