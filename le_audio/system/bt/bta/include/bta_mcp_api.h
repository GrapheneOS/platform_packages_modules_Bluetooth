/******************************************************************************
 *
 *  Copyright 2021 The Android Open Source Project
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


#ifndef BTA_MCP_API_H
#define BTA_MCP_API_H

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <hardware/bt_mcp.h>
#include "bta_gatt_api.h"

using bluetooth::Uuid;
using bluetooth::mcp_server::McpServerCallbacks;


#define MAX_PLAYER_NAME_SIZE    GATT_MAX_ATTR_LEN
#define MAX_TRACK_TITLE_SIZE    GATT_MAX_ATTR_LEN
#define MAX_RESPONSE_DATA_LEN   GATT_MAX_ATTR_LEN
#define MAX_MCP_CONNECTION      5

#define TRACK_POSITION_UNAVAILABLE 0xFFFFFFFF
#define TRACK_DURATION_UNAVAILABLE 0xFFFFFFFF

/* Media Control Point Opcodes Supported characteristics bit values */
#define MCP_MEDIA_CONTROL_SUP_PLAY               1<<0
#define MCP_MEDIA_CONTROL_SUP_PAUSE              1<<1
#define MCP_MEDIA_CONTROL_SUP_FAST_REWIND        1<<2
#define MCP_MEDIA_CONTROL_SUP_FAST_FORWARD       1<<3
#define MCP_MEDIA_CONTROL_SUP_STOP               1<<4
#define MCP_MEDIA_CONTROL_SUP_MOVE_RELATIVE      1<<5
#define MCP_MEDIA_CONTROL_SUP_PREVIOUS_SEGMENT   1<<6
#define MCP_MEDIA_CONTROL_SUP_NEXT_SEGMENT       1<<7
#define MCP_MEDIA_CONTROL_SUP_FIRST_SEGMENT      1<<8
#define MCP_MEDIA_CONTROL_SUP_LAST_SEGMENT       1<<9
#define MCP_MEDIA_CONTROL_SUP_GOTO_SEGMENT       1<<10
#define MCP_MEDIA_CONTROL_SUP_PREVIOUS_TRACK     1<<11
#define MCP_MEDIA_CONTROL_SUP_NEXT_TRACK         1<<12
#define MCP_MEDIA_CONTROL_SUP_FIRST_TRACK        1<<13
#define MCP_MEDIA_CONTROL_SUP_LAST_TRACK         1<<14
#define MCP_MEDIA_CONTROL_SUP_GOTO_TRACK         1<<15
#define MCP_MEDIA_CONTROL_SUP_PREVIOUS_GROUP     1<<16
#define MCP_MEDIA_CONTROL_SUP_NEXT_GROUP         1<<17
#define MCP_MEDIA_CONTROL_SUP_FIRST_GROUP        1<<18
#define MCP_MEDIA_CONTROL_SUP_LAST_GROUP         1<<19
#define MCP_MEDIA_CONTROL_SUP_GOTO_GROUP         1<<20

//media control point opcodes
#define MCP_MEDIA_CONTROL_OPCODE_PLAY              0x01
#define MCP_MEDIA_CONTROL_OPCODE_PAUSE             0x02
#define MCP_MEDIA_CONTROL_OPCODE_FAST_REWIND       0x03
#define MCP_MEDIA_CONTROL_OPCODE_FAST_FORWARD      0x04
#define MCP_MEDIA_CONTROL_OPCODE_STOP              0x05
#define MCP_MEDIA_CONTROL_OPCODE_PREV_TRACK        0x30
#define MCP_MEDIA_CONTROL_OPCODE_NEXT_TRACK        0x31
#define MCP_MEDIA_CONTROL_OPCODE_MOVE_RELATIVE     0x10

/* Playing Order Supported characteristic bit values */
#define MCP_PLAYING_OREDR_SINGLE_ONCE        1<<0
#define MCP_PLAYING_OREDR_SINGLE_REPEAT      1<<1
#define MCP_PLAYING_OREDR_IN_ORDER_ONCE      1<<2
#define MCP_PLAYING_OREDR_IN_ORDER_REPEAT    1<<3
#define MCP_PLAYING_OREDR_OLDEST_ONCE        1<<4
#define MCP_PLAYING_OREDR_OLDEST_REPEAT      1<<5
#define MCP_PLAYING_OREDR_NEWEST_ONCE        1<<6
#define MCP_PLAYING_OREDR_NEWEST_REPEAT      1<<7
#define MCP_PLAYING_OREDR_SHUFFLE_ONCE       1<<8
#define MCP_PLAYING_OREDR_SHUFFLE_REPEAT     1<<9

#define MCP_DEFAULT_MEDIA_CTRL_SUPP_FEAT  MCP_MEDIA_CONTROL_SUP_PLAY|           \
                                          MCP_MEDIA_CONTROL_SUP_PAUSE|          \
                                          MCP_MEDIA_CONTROL_SUP_FAST_REWIND|    \
                                          MCP_MEDIA_CONTROL_SUP_FAST_FORWARD|   \
                                          MCP_MEDIA_CONTROL_SUP_STOP|           \
                                          MCP_MEDIA_CONTROL_SUP_PREVIOUS_TRACK| \
                                          MCP_MEDIA_CONTROL_SUP_NEXT_TRACK

typedef enum {
  // TO-DO: Naming in such a way to distinguish BTIF and lower layer events
  MCP_NONE_EVENT = 70,
  MCP_INIT_EVENT,
  MCP_CLEANUP_EVENT,
  MCP_MEDIA_STATE_UPDATE,
  MCP_MEDIA_PLAYER_NAME_UPDATE,
  MCP_MEDIA_SUPPORTED_OPCODE_UPDATE,
  MCP_MEDIA_CONTROL_POINT_UPDATE,
  MCP_PLAYING_ORDER_SUPPORTED_UPDATE,
  MCP_PLAYING_ORDER_UPDATE,
  MCP_TRACK_CHANGED_UPDATE,
  MCP_TRACK_POSITION_UPDATE,
  MCP_TRACK_DURATION_UPDATE,
  MCP_TRACK_TITLE_UPDATE,
  MCP_CCID_UPDATE,
  MCP_ACTIVE_DEVICE_UPDATE,
  MCP_ACTIVE_PROFILE,

  //local event to handle in mcp state machine,
  MCP_PLAYING_ORDER_SUPPORTED_READ,
  MCP_PLAYING_ORDER_READ,
  MCP_MEDIA_STATE_READ,
  MCP_MEDIA_CONTROL_POINT_OPCODE_SUPPORTED_READ,
  MCP_MEDIA_PLAYER_NAME_READ,
  MCP_TRACK_TITLE_READ,
  MCP_TRACK_POSITION_READ,
  MCP_TRACK_DURATION_READ,
  MCP_CCID_READ,
  MCP_SEEKING_SPEED_READ,
  MCP_MEDIA_STATE_READ_DESCRIPTOR,
  MCP_MEDIA_CONTROL_POINT_READ_DESCRIPTOR,
  MCP_MEDIA_CONTROL_POINT_OPCODE_SUPPORTED_DESCRIPTOR_READ,
  MCP_MEDIA_PLAYER_NAME_DESCRIPTOR_READ,
  MCP_TRACK_CHANGED_DESCRIPTOR_READ,
  MCP_TRACK_TITLE_DESCRIPTOR_READ,
  MCP_TRACK_POSITION_DESCRIPTOR_READ,
  MCP_TRACK_DURATION_DESCRIPTOR_READ,
  MCP_PLAYING_ORDER_DESCRIPTOR_READ,
  MCP_MEDIA_STATE_DESCRIPTOR_WRITE,
  MCP_MEDIA_PLAYER_NAME_DESCRIPTOR_WRITE,
  MCP_MEDIA_CONTROL_POINT_DESCRIPTOR_WRITE,
  MCP_MEDIA_CONTROL_POINT_SUPPORTED_DESCRIPTOR_WRITE,
  MCP_TRACK_CHANGED_DESCRIPTOR_WRITE,
  MCP_TRACK_TITLE_DESCRIPTOR_WRITE,
  MCP_TRACK_POSITION_DESCRIPTOR_WRITE,
  MCP_TRACK_DURATION_DESCRIPTOR_WRITE,
  MCP_PLAYING_ORDER_DESCRIPTOR_WRITE,
  MCP_MEDIA_CONTROL_POINT_WRITE,
  MCP_PLAYING_ORDER_WRITE,
  MCP_TRACK_POSITION_WRITE,
//device state event
  MCP_NOTIFY_ALL,
  MCP_WRITE_RSP,
  MCP_READ_RSP,
  MCP_DESCRIPTOR_WRITE_RSP,
  MCP_DESCRIPTOR_READ_RSP,
  MCP_CONNECTION,
  MCP_DISCONNECTION,
  MCP_CONNECTION_UPDATE,
  MCP_CONGESTION_UPDATE,
  MCP_PHY_UPDATE,
  MCP_MTU_UPDATE,
  MCP_SET_ACTIVE_DEVICE,
  MCP_CONNECTION_CLOSE_EVENT,
  MCP_BOND_STATE_CHANGE_EVENT,
//media write op code event
  MCP_MEDIA_CONTROL_PLAY_READ_REQ,
  MCP_MEDIA_CONTROL_PAUSE_REQ,
  MCP_MEDIA_CONTROL_FAST_FORWARD_REQ,
  MCP_MEDIA_CONTROL_FAST_REWIND_REQ,
  MCP_MEDIA_CONTROL_MOVE_RELATIVE_REQ,
  MCP_MEDIA_CONTROL_STOP_REQ,
  MCP_MEDIA_CONTROL_NEXT_TRACK_REQ,
  MCP_MEDIA_CONTROL_PREVIOUS_TRACK_REQ,
  MCP_PLAYING_OREDR_SHUFFLE_REPEAT_REQ,

}mcp_event_t;

//state handler declaration
typedef bool (*mcp_handler)(uint32_t event, void* param, uint8_t state);
typedef enum {
  //media conrol point success or error code
  MCP_STATUS_SUCCESS = 1,
  MCP_OPCODE_NOT_SUPPORTED,
  MCP_MEDIA_PLAYER_INACTIVE,
  MCP_COMMAND_CANNOT_COMPLETED,

  BT_STATUS_DEVICE_NOT_CONNECTED,
  BT_STATUS_HANLDE_NOT_MATCHED,
}mcp_error_t;

typedef enum {
  MCP_DISCONNECTED = 0x00,
  MCP_CONNECTED,
  MCP_MAX_DEVICE_STATE
} remote_device_state_t;

typedef enum {
  MCP_STATE_INACTIVE = 0x00,
  MCP_STATE_PLAYING,
  MCP_STATE_PAUSE,
  MCP_STATE_SEEKING,
  MCP_MAX_MEDIA_STATE
} mcp_state_t;

typedef struct {
  uint8_t media_state;
  uint16_t media_ctrl_point;
  uint32_t media_supported_feature;
  uint8_t player_name[MAX_PLAYER_NAME_SIZE];
  uint16_t player_name_len;
  uint8_t track_changed;
  int32_t duration;
  int32_t position;
  uint16_t playing_order_supported;
  uint8_t playing_order_value;
  uint8_t title[MAX_TRACK_TITLE_SIZE];
  uint16_t track_title_len;
  uint8_t ccid;
  uint8_t seeking_speed;
  mcp_handler MediaStateHandlerPointer[MCP_MAX_MEDIA_STATE];
} MediaPlayerInfo_t;

typedef struct {
  int server_if;
  Uuid mcs_service_uuid;
  Uuid media_state_uuid;
  Uuid media_player_name_uuid;
  Uuid media_control_point_uuid;
  Uuid media_control_point_opcode_supported_uuid;
  Uuid track_changed_uuid;
  Uuid track_title_uuid;
  Uuid track_duration_uuid;
  Uuid track_position_uuid;
  Uuid playing_order_supported_uuid;
  Uuid playing_order_uuid;
  Uuid ccid_uuid;
  Uuid seeking_speed_uuid;
  //handle for characteristics
  uint16_t media_state_handle;
  uint16_t media_player_name_handle;
  uint16_t media_control_point_opcode_supported_handle;
  uint16_t media_control_point_handle;
  uint16_t track_changed_handle;
  uint16_t track_title_handle;
  uint16_t track_duration_handle;
  uint16_t track_position_handle;
  uint16_t playing_order_supported_handle;
  uint16_t playing_order_handle;
  uint16_t ccid_handle;
  uint16_t seeking_speed_handle;
  uint16_t media_state_desc;
  uint16_t media_player_name_desc;
  uint16_t media_control_point_opcode_supported_desc;
  uint16_t media_control_point_desc;
  uint16_t track_changed_desc;
  uint16_t track_title_desc;
  uint16_t track_duration_desc;
  uint16_t track_position_desc;
  uint16_t playing_order_supported_desc;
  uint16_t playing_order_desc;
  uint16_t ccid_desc;
  uint16_t seeking_speed_desc;
} mcsServerServiceInfo_t;

typedef struct {
  remote_device_state_t state;
  uint8_t active_profile;
  uint16_t media_state_notify;
  uint16_t media_player_name_notify;
  uint16_t media_control_point_notify;
  uint16_t media_control_point_opcode_supported_notify;
  uint16_t track_changed_notify;
  uint16_t track_duration_notify;
  uint16_t track_title_notify;
  uint16_t track_position_notify;
  uint16_t playing_order_notify;
  uint16_t seeking_speed_notify;
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
  mcp_handler DeviceStateHandlerPointer[MCP_MAX_DEVICE_STATE];
}RemoteDevice;

typedef struct {
  std::vector<RawAddress> address;
  int set_id;
}ActiveDevice;

typedef struct {
  uint8_t status;
  uint16_t notification;
  uint32_t trans_id;
  uint32_t desc_handle;
  uint32_t char_handle;
  bool need_rsp;
  bool prep_rsp;
  //is to send notification
  uint8_t *data;
  uint16_t len;
}tMCP_DESC_WRITE;

typedef struct {
  uint8_t status;
  uint32_t trans_id;
  uint32_t desc_handle;
  uint32_t char_handle;
}tMCP_DESC_READ;

typedef struct {
  bool is_long;
  uint8_t status;
  uint32_t trans_id;
  uint32_t char_handle;
}tMCP_READ;

typedef struct {
  uint8_t status;
  bool need_rsp;
  bool prep_rsp;
  uint16_t offset;
  uint32_t trans_id;
  uint16_t char_handle;
  //is to send notification
  uint8_t data[GATT_MAX_ATTR_LEN];
}tMCP_WRITE;

typedef struct {
  uint8_t status;
  RemoteDevice remoteDevice;
}tMCP_CONNECTION;

typedef struct {
  uint8_t status;
  int timeout;
  int latency;
  int interval;
}tMCP_CONN_UPDATE;

typedef struct {
  uint8_t status;
  RemoteDevice *remoteDevice;
}tMCP_DISCONNECTION;

typedef struct {
  bool congested;
  RemoteDevice *remoteDevice;
} tMCP_CONGESTION;

typedef struct {
  uint8_t status;
  uint8_t tx_phy;
  uint8_t rx_phy;
  RemoteDevice *remoteDevice;
} tMCP_PHY;

typedef struct {
  uint8_t status;
  uint16_t mtu;
  RemoteDevice *remoteDevice;
} tMCP_MTU;

typedef struct {
  uint8_t state;
}tMCP_MEDIA_STATE;

typedef struct {
  uint32_t req_opcode;
  uint8_t result;
}tMCP_MEDIA_CONTROL_POINT;

typedef struct {
  uint32_t supported;
}tMCP_MEDIA_OPCODE_SUPPORT;

typedef struct {
  uint8_t *name;
  uint16_t len;
}tMCP_MEDIA_PLAYER_NAME;

typedef struct {
  bool status;
}tMCP_TRACK_CHANGED;

typedef struct {
  int32_t position;
}tMCP_TRACK_POSTION;

typedef struct {
  uint32_t duration;
}tMCP_TRACK_DURATION;

typedef struct {
  uint8_t *title;
  uint16_t len;
}tMCP_TRACK_TITLE;

typedef struct {
  uint8_t ccid;
}tMCP_CONTENT_CONTROL_ID;

typedef struct {
  uint8_t seek_speed;
}tMCP_SEEKING_SPEED_CONTROL_ID;

typedef struct {
  RawAddress addr;
}tMCP_CONNECTION_CLOSE;

typedef struct {
  RawAddress addr;
  int state;
}tMCP_BOND_STATE_CHANGE;

typedef struct {
  uint32_t order_supported;
}tMCP_PLAYING_ORDER_SUPPORT;

typedef struct {
  uint8_t order;
}tMCP_PLAYING_ORDER;

typedef struct {
  RawAddress address;
  uint16_t set_id;
  uint8_t profile;
}tMCP_SET_ACTIVE_DEVICE;

typedef struct {
  uint8_t *data;
  uint16_t len;
}tMCP_MEDIA_UPDATE;

union tMCP_MEDIA_OPERATION{
  tMCP_MEDIA_UPDATE MediaUpdateOp;
  tMCP_SET_ACTIVE_DEVICE SetActiveDeviceOp;
  tMCP_DESC_WRITE WriteDescOp;
  tMCP_DESC_READ ReadDescOp;
  tMCP_WRITE WriteOp;
  tMCP_READ ReadOp;
  tMCP_CONNECTION ConnectionOp;
  tMCP_CONN_UPDATE ConnectionUpdateOp;
  tMCP_DISCONNECTION DisconnectionOp;
  tMCP_CONGESTION CongestionOp;
  tMCP_MTU MtuOp;
  tMCP_PHY PhyOp;
};

typedef union tMCP_MEDIA_OPERATION tMCP_MEDIA_OPERATION;

struct mcp_resp_t {
  uint32_t event;
  uint16_t handle;
  uint16_t status;
  RemoteDevice *remoteDevice;
  tGATTS_RSP rsp_value;
  tMCP_MEDIA_OPERATION oper;
};

typedef struct mcp_resp_t mcp_resp_t;

class McpServer {
  public:
  virtual ~McpServer() = default;
  static void Initialize(bluetooth::mcp_server::McpServerCallbacks* callbacks, Uuid ap_id);
  static void CleanUp();
  static McpServer* Get();
  static bool isMcpServiceRunnig();
  virtual void MediaState(uint8_t state) = 0;
  virtual void MediaPlayerName(uint8_t* player_name) = 0;
  virtual void MediaControlPointOpcodeSupported(uint32_t feature) = 0;
  virtual void MediaControlPoint(uint8_t value) = 0;
  virtual void TrackChanged(bool status) = 0;
  virtual void TrackDuration(int32_t duration) = 0;
  virtual void TrackTitle(uint8_t* title) = 0;
  virtual void TrackPosition(int32_t position) = 0;
  virtual void PlayingOrderSupported(uint16_t order) = 0;
  virtual void PlayingOrder(uint8_t value) = 0;
  virtual void SetActiveDevice(const RawAddress& address, int setId, int profile) = 0;
  virtual void ContentControlId(uint8_t ccid) = 0;
  virtual void DisconnectMcp(const RawAddress& address) = 0;
  virtual void BondStateChange(const RawAddress& address, int state) = 0;
};

void McpCongestionUpdate(mcp_resp_t *p_data);

#endif // BTA_MCP_API_H
