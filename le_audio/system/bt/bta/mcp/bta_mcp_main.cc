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




/******************************************************************************
 *
 *  This file contains the MCP server main functions and state machine.
 *
 ******************************************************************************/

#include "bta_api.h"
#include "bt_target.h"
#include "bta_mcp_api.h"
#include "gatts_ops_queue.h"
#include "btm_int.h"
#include "device/include/controller.h"
#include "osi/include/properties.h"
#include "bta_sys.h"
#include "btif_util.h"

#include <base/bind.h>
#include <base/callback.h>
#include <base/logging.h>
#include <base/location.h>
#include <hardware/bluetooth.h>
#include <base/strings/string_number_conversions.h>
#include <vector>
#include <string.h>

using bluetooth::Uuid;
using bluetooth::bap::GattsOpsQueue;

class McpServerImpl;
static McpServerImpl *instance;

//global variables
mcsServerServiceInfo_t mcsServerServiceInfo;
MediaPlayerInfo_t mediaPlayerInfo;

void HandleMcsEvent(uint32_t event, void* param);

typedef base::Callback<void(uint8_t status, int server_if,
                             std::vector<btgatt_db_element_t> service)>
                            OnMcpServiceAdded;

static void OnMcpServiceAddedCb(uint8_t status, int serverIf,
                              std::vector<btgatt_db_element_t> service);

/* Media state handlers */
static bool MediaStateInactiveHandler(uint32_t event, void* param, uint8_t state);
static bool MediaStatePauseHandler(uint32_t event, void* param, uint8_t state);
static bool MediaStatePlayingHandler(uint32_t event, void* param, uint8_t state);
static bool MediaStateSeekingHandler(uint32_t event, void* param, uint8_t state);

/* Connection state machine handlers */
static bool DeviceStateConnectionHandler(uint32_t event, void* param, uint8_t state);
static bool DeviceStateDisconnectedHandler(uint32_t event, void* param, uint8_t state);

Uuid MCS_UUID   = Uuid::FromString("1848");
Uuid GMCS_UUID  = Uuid::FromString("1849");

Uuid DESCRIPTOR_UUID = Uuid::FromString("2902");

Uuid GMCS_MEDIA_STATE_UUID                      = Uuid::FromString("2BA3");
Uuid GMCS_MEDIA_CONTROL_POINT_OPCODE_SUPPORTED  = Uuid::FromString("2BA5");
Uuid GMCS_MEDIA_PLAYER_NAME_UUID                = Uuid::FromString("2B93");
Uuid GMCS_MEDIA_CONTROL_POINT                   = Uuid::FromString("2BA4");
Uuid GMCS_TRACK_CHANGED                         = Uuid::FromString("2B96");
Uuid GMCS_TRACK_TITLE                           = Uuid::FromString("2B97");
Uuid GMCS_TRACK_DURATION                        = Uuid::FromString("2B98");
Uuid GMCS_TRACK_POSITION                        = Uuid::FromString("2B99");
Uuid GMCS_PLAYING_ORDER_SUPPORTED               = Uuid::FromString("2BA2");
Uuid GMCS_PLAYING_ORDER                         = Uuid::FromString("2BA1");
Uuid GMCS_CONTENT_CONTROLID                     = Uuid::FromString("2BBA");
Uuid GMCS_SEEKING_SPEED_UUID                    = Uuid::FromString("2B9B");


  bool is_pts_running() {
    char value[PROPERTY_VALUE_MAX] = {'\0'};
    bool pts_test_enabled = false;
    osi_property_get("persist.vendor.service.bt.mcs.pts", value, "false");
    pts_test_enabled = (strcmp(value, "true") == 0);
    LOG(INFO) << "pts test enabled " << pts_test_enabled;
    return pts_test_enabled;
  }

  int playing_order_opcode(int data) {
    int event = 0;
    if (data & MCP_PLAYING_OREDR_SHUFFLE_REPEAT) {
      event = MCP_PLAYING_OREDR_SHUFFLE_REPEAT_REQ;
    } else
      LOG(INFO) << "opcode not matched or not supported";
    return event;
  }

  bool is_opcode_supported(int data) {
    LOG(INFO) << __func__ << "data " << data << "media_supported_feature " << mediaPlayerInfo.media_supported_feature;
    switch (data) {
      case MCP_MEDIA_CONTROL_OPCODE_PLAY:
        return (mediaPlayerInfo.media_supported_feature & MCP_MEDIA_CONTROL_SUP_PLAY);
      case MCP_MEDIA_CONTROL_OPCODE_PAUSE:
        return (mediaPlayerInfo.media_supported_feature & MCP_MEDIA_CONTROL_SUP_PAUSE);
      case MCP_MEDIA_CONTROL_OPCODE_FAST_REWIND:
        return (mediaPlayerInfo.media_supported_feature & MCP_MEDIA_CONTROL_SUP_FAST_REWIND);
      case MCP_MEDIA_CONTROL_OPCODE_FAST_FORWARD:
        return (mediaPlayerInfo.media_supported_feature & MCP_MEDIA_CONTROL_SUP_FAST_FORWARD);
      case MCP_MEDIA_CONTROL_OPCODE_STOP:
        return (mediaPlayerInfo.media_supported_feature & MCP_MEDIA_CONTROL_SUP_STOP);
      case MCP_MEDIA_CONTROL_OPCODE_PREV_TRACK:
        return (mediaPlayerInfo.media_supported_feature & MCP_MEDIA_CONTROL_SUP_PREVIOUS_TRACK);
      case MCP_MEDIA_CONTROL_OPCODE_NEXT_TRACK:
        return (mediaPlayerInfo.media_supported_feature & MCP_MEDIA_CONTROL_SUP_NEXT_TRACK);
    
      // Fallthrough for all unknown key mappings
      default:
        LOG(INFO) << __func__ << "opcode is not supported";
        return false;
    }
  }

const char* get_mcp_event_name(uint32_t event) {
  switch (event) {
    CASE_RETURN_STR(MCP_INIT_EVENT)
    CASE_RETURN_STR(MCP_CLEANUP_EVENT)
    CASE_RETURN_STR(MCP_MEDIA_STATE_UPDATE)
    CASE_RETURN_STR(MCP_MEDIA_PLAYER_NAME_UPDATE)
    CASE_RETURN_STR(MCP_MEDIA_SUPPORTED_OPCODE_UPDATE)
    CASE_RETURN_STR(MCP_MEDIA_CONTROL_POINT_UPDATE)
    CASE_RETURN_STR(MCP_PLAYING_ORDER_SUPPORTED_UPDATE)
    CASE_RETURN_STR(MCP_PLAYING_ORDER_UPDATE)
    CASE_RETURN_STR(MCP_TRACK_CHANGED_UPDATE)
    CASE_RETURN_STR(MCP_TRACK_POSITION_UPDATE)
    CASE_RETURN_STR(MCP_TRACK_DURATION_UPDATE)
    CASE_RETURN_STR(MCP_TRACK_TITLE_UPDATE)
    CASE_RETURN_STR(MCP_CCID_UPDATE)
    CASE_RETURN_STR(MCP_ACTIVE_DEVICE_UPDATE)
    CASE_RETURN_STR(MCP_ACTIVE_PROFILE)

    //local event to handle in mcp state machine,
    CASE_RETURN_STR(MCP_PLAYING_ORDER_SUPPORTED_READ)
    CASE_RETURN_STR(MCP_PLAYING_ORDER_READ)
    CASE_RETURN_STR(MCP_MEDIA_STATE_READ)
    CASE_RETURN_STR(MCP_MEDIA_CONTROL_POINT_OPCODE_SUPPORTED_READ)
    CASE_RETURN_STR(MCP_MEDIA_PLAYER_NAME_READ)
    CASE_RETURN_STR(MCP_TRACK_TITLE_READ)
    CASE_RETURN_STR(MCP_TRACK_POSITION_READ)
    CASE_RETURN_STR(MCP_TRACK_DURATION_READ)
    CASE_RETURN_STR(MCP_CCID_READ)
    CASE_RETURN_STR(MCP_SEEKING_SPEED_READ)
    CASE_RETURN_STR(MCP_MEDIA_STATE_READ_DESCRIPTOR)
    CASE_RETURN_STR(MCP_MEDIA_CONTROL_POINT_READ_DESCRIPTOR)
    CASE_RETURN_STR(MCP_MEDIA_CONTROL_POINT_OPCODE_SUPPORTED_DESCRIPTOR_READ)
    CASE_RETURN_STR(MCP_MEDIA_PLAYER_NAME_DESCRIPTOR_READ)
    CASE_RETURN_STR(MCP_TRACK_CHANGED_DESCRIPTOR_READ)
    CASE_RETURN_STR(MCP_TRACK_TITLE_DESCRIPTOR_READ)
    CASE_RETURN_STR(MCP_TRACK_POSITION_DESCRIPTOR_READ)
    CASE_RETURN_STR(MCP_TRACK_DURATION_DESCRIPTOR_READ)
    CASE_RETURN_STR(MCP_PLAYING_ORDER_DESCRIPTOR_READ)
    CASE_RETURN_STR(MCP_MEDIA_STATE_DESCRIPTOR_WRITE)
    CASE_RETURN_STR(MCP_MEDIA_PLAYER_NAME_DESCRIPTOR_WRITE)
    CASE_RETURN_STR(MCP_MEDIA_CONTROL_POINT_DESCRIPTOR_WRITE)
    CASE_RETURN_STR(MCP_MEDIA_CONTROL_POINT_SUPPORTED_DESCRIPTOR_WRITE)
    CASE_RETURN_STR(MCP_TRACK_CHANGED_DESCRIPTOR_WRITE)
    CASE_RETURN_STR(MCP_TRACK_TITLE_DESCRIPTOR_WRITE)
    CASE_RETURN_STR(MCP_TRACK_POSITION_DESCRIPTOR_WRITE)
    CASE_RETURN_STR(MCP_TRACK_DURATION_DESCRIPTOR_WRITE)
    CASE_RETURN_STR(MCP_PLAYING_ORDER_DESCRIPTOR_WRITE)
    CASE_RETURN_STR(MCP_MEDIA_CONTROL_POINT_WRITE)
    CASE_RETURN_STR(MCP_PLAYING_ORDER_WRITE)
    CASE_RETURN_STR(MCP_TRACK_POSITION_WRITE)

    CASE_RETURN_STR(MCP_NOTIFY_ALL)
    CASE_RETURN_STR(MCP_WRITE_RSP)
    CASE_RETURN_STR(MCP_READ_RSP)
    CASE_RETURN_STR(MCP_DESCRIPTOR_WRITE_RSP)
    CASE_RETURN_STR(MCP_DESCRIPTOR_READ_RSP)
    CASE_RETURN_STR(MCP_CONNECTION)
    CASE_RETURN_STR(MCP_DISCONNECTION)
    CASE_RETURN_STR(MCP_CONNECTION_UPDATE)
    CASE_RETURN_STR(MCP_CONGESTION_UPDATE)
    CASE_RETURN_STR(MCP_PHY_UPDATE)
    CASE_RETURN_STR(MCP_MTU_UPDATE)
    CASE_RETURN_STR(MCP_SET_ACTIVE_DEVICE)
    CASE_RETURN_STR(MCP_CONNECTION_CLOSE_EVENT)
    CASE_RETURN_STR(MCP_BOND_STATE_CHANGE_EVENT)
    //media write op code event
    CASE_RETURN_STR(MCP_MEDIA_CONTROL_PLAY_READ_REQ)
    CASE_RETURN_STR(MCP_MEDIA_CONTROL_PAUSE_REQ)
    CASE_RETURN_STR(MCP_MEDIA_CONTROL_FAST_FORWARD_REQ)
    CASE_RETURN_STR(MCP_MEDIA_CONTROL_FAST_REWIND_REQ)
    CASE_RETURN_STR(MCP_MEDIA_CONTROL_MOVE_RELATIVE_REQ)
    CASE_RETURN_STR(MCP_MEDIA_CONTROL_STOP_REQ)
    CASE_RETURN_STR(MCP_MEDIA_CONTROL_NEXT_TRACK_REQ)
    CASE_RETURN_STR(MCP_MEDIA_CONTROL_PREVIOUS_TRACK_REQ)
    CASE_RETURN_STR(MCP_PLAYING_OREDR_SHUFFLE_REPEAT_REQ)
  default:
    return "Unknown Event";
  }
}

const char* get_mcp_media_state_name(uint8_t media_state) {
  switch (media_state) {
    CASE_RETURN_STR(MCP_STATE_INACTIVE)
    CASE_RETURN_STR(MCP_STATE_PLAYING)
    CASE_RETURN_STR(MCP_STATE_PAUSE)
    CASE_RETURN_STR(MCP_STATE_SEEKING)
  default:
    return "Unknown Media State";
  }
}

class RemoteDevices {
 private:
   ActiveDevice activeDevice;
   //int max_connection;
 public:
  bool Add(RemoteDevice device) {
    if (devices.size() == MAX_MCP_CONNECTION) {
      return false;
    }
    if (FindByAddress(device.peer_bda) != nullptr) return false;
      device.DeviceStateHandlerPointer[MCP_DISCONNECTED] = DeviceStateDisconnectedHandler;
      device.DeviceStateHandlerPointer[MCP_CONNECTED] = DeviceStateConnectionHandler;
      devices.push_back(device);
      return true;
  }

  void Remove(RawAddress& address) {
    for (auto it = devices.begin(); it != devices.end();) {
      if (it->peer_bda != address) {
        ++it;
        continue;
      }

      it = devices.erase(it);
      return;
    }
  }

  RemoteDevice* FindByAddress(const RawAddress& address) {
    auto iter = std::find_if(devices.begin(), devices.end(),
                             [&address](const RemoteDevice& device) {
                               return device.peer_bda == address;
                             });

    return (iter == devices.end()) ? nullptr : &(*iter);
  }

  RemoteDevice* FindByConnId(uint16_t conn_id) {
    auto iter = std::find_if(devices.begin(), devices.end(),
                             [&conn_id](const RemoteDevice& device) {
                               return device.conn_id == conn_id;
                             });

    return (iter == devices.end()) ? nullptr : &(*iter);
  }

  size_t size() { return (devices.size()); }

  std::vector<RemoteDevice> GetRemoteDevices() {
    return devices;
  }
  std::vector<RemoteDevice> FindNotifyDevices(uint16_t handle) {
    std::vector<RemoteDevice> notify_devices;
    for (size_t it = 0; it != devices.size(); it++){
      if(mcsServerServiceInfo.media_state_handle == handle &&
        devices[it].media_state_notify) {
        notify_devices.push_back(devices[it]);
      } else if(mcsServerServiceInfo.media_player_name_handle == handle &&
        devices[it].media_player_name_notify) {
        notify_devices.push_back(devices[it]);
      }  else if (mcsServerServiceInfo.media_control_point_opcode_supported_handle == handle &&
        devices[it].media_control_point_opcode_supported_notify) {
        notify_devices.push_back(devices[it]);
      } else if(mcsServerServiceInfo.media_control_point_handle == handle &&
        devices[it].media_control_point_notify) {
        notify_devices.push_back(devices[it]);
      } else if(mcsServerServiceInfo.track_changed_handle == handle &&
        devices[it].track_changed_notify) {
        notify_devices.push_back(devices[it]);
      } else if(mcsServerServiceInfo.track_title_handle == handle &&
        devices[it].track_title_notify) {
        notify_devices.push_back(devices[it]);
      } else if(mcsServerServiceInfo.track_duration_handle == handle &&
        devices[it].track_duration_notify) {
        notify_devices.push_back(devices[it]);
      } else if(mcsServerServiceInfo.track_position_handle == handle &&
        devices[it].track_position_notify) {
        notify_devices.push_back(devices[it]);
      } else if(mcsServerServiceInfo.playing_order_handle == handle &&
        devices[it].playing_order_notify) {
        notify_devices.push_back(devices[it]);
      }
    }
    return notify_devices;
  }
  void AddSetActiveDevice(tMCP_SET_ACTIVE_DEVICE *device) {
    if (device->set_id == activeDevice.set_id) {
      activeDevice.address.push_back(device->address);
    } else {
      activeDevice.address.clear();
      activeDevice.set_id = device->set_id;
      activeDevice.address.push_back(device->address);
    }
  }

  bool FindActiveDevice(RemoteDevice *remoteDevice) {
    bool flag = false;
    for (auto& it : activeDevice.address) {
      if(remoteDevice->peer_bda == it) {
        flag = true;
        break;
      }
    }
    return flag;
  }

  std::vector<RemoteDevice> devices;
};


class McpServerImpl : public McpServer {
  bluetooth::mcp_server::McpServerCallbacks* callbacks;
  Uuid app_uuid;

  public:
     RemoteDevices remoteDevices;
     virtual ~McpServerImpl() = default;


  McpServerImpl(bluetooth::mcp_server::McpServerCallbacks* callback, Uuid uuid)
        :callbacks(callback),
     app_uuid(uuid){
    LOG(INFO) << "McpServerImpl gatts app register";
    HandleMcsEvent(MCP_INIT_EVENT, &app_uuid);

  }

  void SetActiveDevice(const RawAddress& address, int setId, int profile) {
    LOG(INFO) << __func__ ;
    tMCP_SET_ACTIVE_DEVICE SetActiveDeviceOp;
    SetActiveDeviceOp.set_id = setId;
    SetActiveDeviceOp.address = address;
    SetActiveDeviceOp.profile = profile;
    HandleMcsEvent(MCP_ACTIVE_DEVICE_UPDATE, &SetActiveDeviceOp);
  }

  void MediaState(uint8_t state) {
    LOG(INFO) << __func__ << " state: " << unsigned(state);
    tMCP_MEDIA_STATE MediaStateOp;
    MediaStateOp.state = state;
    HandleMcsEvent(MCP_MEDIA_STATE_UPDATE, &MediaStateOp);
  }

  void MediaPlayerName(uint8_t* player_name) {
    LOG(INFO) << __func__;
    tMCP_MEDIA_PLAYER_NAME MediaPlayerNameOp;
    MediaPlayerNameOp.name = player_name;
    MediaPlayerNameOp.len = strlen((char *)player_name);
    if(MediaPlayerNameOp.len != 0)
      HandleMcsEvent(MCP_MEDIA_PLAYER_NAME_UPDATE, &MediaPlayerNameOp);
  }

  void MediaControlPointOpcodeSupported(uint32_t feature) {
    LOG(INFO) << __func__;
    tMCP_MEDIA_OPCODE_SUPPORT MediaControlPointOpcodeSupportedOp;
    MediaControlPointOpcodeSupportedOp.supported = feature;
    HandleMcsEvent(MCP_MEDIA_SUPPORTED_OPCODE_UPDATE, &MediaControlPointOpcodeSupportedOp);
  }

  void MediaControlPoint(uint8_t value) {
    LOG(INFO) << __func__;
    tMCP_MEDIA_CONTROL_POINT MediaControlPoint;
    MediaControlPoint.req_opcode = value;
    MediaControlPoint.result = MCP_STATUS_SUCCESS; // success
    HandleMcsEvent(MCP_MEDIA_CONTROL_POINT_UPDATE, &MediaControlPoint);
  }

  void TrackChanged(bool status) {
    LOG(INFO) << __func__;
    tMCP_TRACK_CHANGED TrackChangedOp;
    TrackChangedOp.status = status;
    HandleMcsEvent(MCP_TRACK_CHANGED_UPDATE, &TrackChangedOp);
  }

  void TrackTitle(uint8_t* track_name) {
    LOG(INFO) << __func__;
    tMCP_TRACK_TITLE TrackTitleOp;
    TrackTitleOp.title = track_name;
    TrackTitleOp.len = strlen((char *)track_name);
    if (TrackTitleOp.len != 0)
      HandleMcsEvent(MCP_TRACK_TITLE_UPDATE, &TrackTitleOp);
  }

  void TrackDuration(int32_t duration) {
    LOG(INFO) << __func__;
    tMCP_TRACK_DURATION TrackDurationOp;
    TrackDurationOp.duration = duration;
    HandleMcsEvent(MCP_TRACK_DURATION_UPDATE, &TrackDurationOp);
  }

  void TrackPosition(int32_t position) {
    LOG(INFO) << __func__;
    tMCP_TRACK_POSTION TrackPositionOp;
    TrackPositionOp.position = position;
    HandleMcsEvent(MCP_TRACK_POSITION_UPDATE, &TrackPositionOp);
  }

  void PlayingOrderSupported(uint16_t order) {
    LOG(INFO) << __func__;
    tMCP_PLAYING_ORDER_SUPPORT PlayingOrderSupportedOp;
    PlayingOrderSupportedOp.order_supported = order;
    HandleMcsEvent(MCP_PLAYING_ORDER_SUPPORTED_UPDATE, &PlayingOrderSupportedOp);
  }

  void PlayingOrder(uint8_t value) {
    LOG(INFO) << __func__;
    tMCP_PLAYING_ORDER PlayingOrderOp;
    PlayingOrderOp.order = value;
    HandleMcsEvent(MCP_PLAYING_ORDER_UPDATE, &PlayingOrderOp);
  }

  void ContentControlId(uint8_t ccid) {
    LOG(INFO) << __func__;
    tMCP_CONTENT_CONTROL_ID ContentControlIdOp;
    ContentControlIdOp.ccid = ccid;
    HandleMcsEvent(MCP_CCID_UPDATE, &ContentControlIdOp);
  }

  void DisconnectMcp(const RawAddress& bd_addr) {
    LOG(INFO) << __func__;
    tMCP_CONNECTION_CLOSE ConnectClosingOp;
    ConnectClosingOp.addr = bd_addr;
    HandleMcsEvent(MCP_CONNECTION_CLOSE_EVENT, &ConnectClosingOp);
  }

  void BondStateChange(const RawAddress& bd_addr, int state) {
    LOG(INFO) << __func__;
    tMCP_BOND_STATE_CHANGE BondStateChangeOP;
    BondStateChangeOP.addr = bd_addr;
    BondStateChangeOP.state = state;
    HandleMcsEvent(MCP_BOND_STATE_CHANGE_EVENT, &BondStateChangeOP);
  }

  void OnConnectionStateChange(uint8_t state, const RawAddress& address) {
    LOG(INFO) << __func__ << "   bta";
    callbacks->OnConnectionStateChange(state, address);
  }

  void MediaControlPointChangeReq(uint8_t state, const RawAddress& address) {
    callbacks->MediaControlPointChangeReq(state, address);
    LOG(INFO) << __func__;
  }

  void TrackPositionChangeReq(int32_t position) {
    callbacks->TrackPositionChangeReq(position);
    LOG(INFO) << __func__;
  }

  void PlayingOrderChangeReq(uint16_t playingOrder) {
    callbacks->PlayingOrderChangeReq(playingOrder);
    LOG(INFO) << __func__;
  }

};


void McpServer::CleanUp() {
  HandleMcsEvent(MCP_CLEANUP_EVENT, NULL);
  delete instance;
  instance = nullptr;
}

McpServer* McpServer::Get() {
  CHECK(instance);
  return instance;
}

void  McpServer::Initialize(bluetooth::mcp_server::McpServerCallbacks* callbacks, Uuid uuid) {
  if (instance) {
  LOG(ERROR) << "Already initialized!";
  } else {
     instance = new McpServerImpl(callbacks, uuid);
  }
}

bool McpServer::isMcpServiceRunnig() { return instance; }

static std::vector<btgatt_db_element_t> McpAddService(int server_if) {

  std::vector<btgatt_db_element_t> mcs_services;
  mcs_services.clear();
  //service
  btgatt_db_element_t service = {.uuid = GMCS_UUID, .type = BTGATT_DB_PRIMARY_SERVICE, 0};
  mcs_services.push_back(service);
  mcsServerServiceInfo.mcs_service_uuid = service.uuid;

  //media state service
  btgatt_db_element_t mcs_media_state_char = {.uuid = GMCS_MEDIA_STATE_UUID,
                                              .type = BTGATT_DB_CHARACTERISTIC,
                                              .properties = GATT_CHAR_PROP_BIT_READ|
                                                            GATT_CHAR_PROP_BIT_NOTIFY,
                                              .permissions = GATT_PERM_READ};
  mcs_services.push_back(mcs_media_state_char);
  mcsServerServiceInfo.media_state_uuid = mcs_media_state_char.uuid;

  //1st desc
  btgatt_db_element_t desc1 = {.uuid = DESCRIPTOR_UUID,
                               .type = BTGATT_DB_DESCRIPTOR,
                               .permissions = GATT_PERM_READ|GATT_PERM_WRITE};
  mcs_services.push_back(desc1);

  //media supported feature
  btgatt_db_element_t mcs_media_opcode_supported_char = {.uuid = GMCS_MEDIA_CONTROL_POINT_OPCODE_SUPPORTED,
                                                         .type = BTGATT_DB_CHARACTERISTIC,
                                                         .properties = GATT_CHAR_PROP_BIT_READ|
                                                                       GATT_CHAR_PROP_BIT_NOTIFY,
                                                         .permissions = GATT_PERM_READ};

  mcs_services.push_back(mcs_media_opcode_supported_char);
  mcsServerServiceInfo.media_control_point_opcode_supported_uuid =
    mcs_media_opcode_supported_char.uuid;

  //2nd desc
  btgatt_db_element_t desc2 = {.uuid = DESCRIPTOR_UUID,
                               .type = BTGATT_DB_DESCRIPTOR,
                               .permissions = GATT_PERM_READ|GATT_PERM_WRITE};
  mcs_services.push_back(desc2);

  ////media player name
  btgatt_db_element_t mcs_media_player_name_char = {.uuid = GMCS_MEDIA_PLAYER_NAME_UUID,
                                                    .type = BTGATT_DB_CHARACTERISTIC,
                                                    .properties = GATT_CHAR_PROP_BIT_READ|
                                                                  GATT_CHAR_PROP_BIT_NOTIFY,
                                                    .permissions = GATT_PERM_READ};
  mcs_services.push_back(mcs_media_player_name_char);
  mcsServerServiceInfo.media_player_name_uuid = mcs_media_player_name_char.uuid;

  //3rd desc
  btgatt_db_element_t desc3 = {.uuid = DESCRIPTOR_UUID,
                               .type = BTGATT_DB_DESCRIPTOR,
                               .permissions = GATT_PERM_READ|GATT_PERM_WRITE};
  mcs_services.push_back(desc3);

  //media control point
  btgatt_db_element_t mcs_media_control_point_char = {.uuid = GMCS_MEDIA_CONTROL_POINT,
                                                      .type = BTGATT_DB_CHARACTERISTIC,
                                                      .properties = GATT_CHAR_PROP_BIT_WRITE_NR|
                                                                    GATT_CHAR_PROP_BIT_WRITE|
                                                                    GATT_CHAR_PROP_BIT_NOTIFY,
                                                      .permissions = GATT_PERM_WRITE};

  mcs_services.push_back(mcs_media_control_point_char);

  mcsServerServiceInfo.media_player_name_uuid = mcs_media_control_point_char.uuid;

  //4th desc
  btgatt_db_element_t desc4 = {.uuid = DESCRIPTOR_UUID,
                               .type = BTGATT_DB_DESCRIPTOR,
                               .permissions = GATT_PERM_READ|GATT_PERM_WRITE};
  mcs_services.push_back(desc4);

  btgatt_db_element_t track_changed_char = {.uuid = GMCS_TRACK_CHANGED,
                                            .type = BTGATT_DB_CHARACTERISTIC,
                                            .properties = GATT_CHAR_PROP_BIT_NOTIFY,
                                            .permissions = GATT_PERM_READ};

  mcs_services.push_back(track_changed_char);
  mcsServerServiceInfo.track_changed_uuid = track_changed_char.uuid;

  //5th desc
  btgatt_db_element_t desc5 = {.uuid = DESCRIPTOR_UUID,
                               .type = BTGATT_DB_DESCRIPTOR,
                               .permissions = GATT_PERM_READ|GATT_PERM_WRITE};
  mcs_services.push_back(desc5);

  btgatt_db_element_t track_title_char = {.uuid = GMCS_TRACK_TITLE,
                                          .type = BTGATT_DB_CHARACTERISTIC,
                                          .properties = GATT_CHAR_PROP_BIT_NOTIFY|
                                                        GATT_CHAR_PROP_BIT_READ,
                                          .permissions = GATT_PERM_READ};

  mcs_services.push_back(track_title_char);
  mcsServerServiceInfo.track_title_uuid = track_title_char.uuid;

  //6th desc
  btgatt_db_element_t desc6 = {.uuid = DESCRIPTOR_UUID,
                               .type = BTGATT_DB_DESCRIPTOR,
                               .permissions = GATT_PERM_READ|GATT_PERM_WRITE};
  mcs_services.push_back(desc6);


  btgatt_db_element_t track_duration_char = {.uuid = GMCS_TRACK_DURATION,
                                             .type = BTGATT_DB_CHARACTERISTIC,
                                             .properties = GATT_CHAR_PROP_BIT_NOTIFY|
                                                           GATT_CHAR_PROP_BIT_READ,
                                             .permissions = GATT_PERM_READ};

  mcs_services.push_back(track_duration_char);
  mcsServerServiceInfo.track_duration_uuid = track_duration_char.uuid;

  //7th desc
  btgatt_db_element_t desc7 = {.uuid = DESCRIPTOR_UUID,
                               .type = BTGATT_DB_DESCRIPTOR,
                               .permissions = GATT_PERM_READ|GATT_PERM_WRITE};
  mcs_services.push_back(desc7);

  btgatt_db_element_t track_position_char = {.uuid = GMCS_TRACK_POSITION,
                                             .type = BTGATT_DB_CHARACTERISTIC,
                                             .properties = GATT_CHAR_PROP_BIT_READ|
                                                           GATT_CHAR_PROP_BIT_WRITE_NR|
                                                           GATT_CHAR_PROP_BIT_WRITE|
                                                           GATT_CHAR_PROP_BIT_NOTIFY,
                                             .permissions = GATT_PERM_READ|GATT_PERM_WRITE};

  mcs_services.push_back(track_position_char);
  mcsServerServiceInfo.track_position_uuid = track_position_char.uuid;

  //8th desc
  btgatt_db_element_t desc8 = {.uuid = DESCRIPTOR_UUID,
                               .type = BTGATT_DB_DESCRIPTOR,
                               .permissions = GATT_PERM_READ|GATT_PERM_WRITE};
  mcs_services.push_back(desc8);

  btgatt_db_element_t playing_order_supported_char = {.uuid = GMCS_PLAYING_ORDER_SUPPORTED,
                                                      .type = BTGATT_DB_CHARACTERISTIC,
                                                      .properties = GATT_CHAR_PROP_BIT_READ,
                                                      .permissions = GATT_PERM_READ};

  mcs_services.push_back(playing_order_supported_char);
  mcsServerServiceInfo.playing_order_supported_uuid = playing_order_supported_char.uuid;

  btgatt_db_element_t playing_order_char = {.uuid = GMCS_PLAYING_ORDER,
                                            .type = BTGATT_DB_CHARACTERISTIC,
                                             .properties = GATT_CHAR_PROP_BIT_READ|
                                                           GATT_CHAR_PROP_BIT_WRITE_NR|
                                                           GATT_CHAR_PROP_BIT_WRITE|
                                                           GATT_CHAR_PROP_BIT_NOTIFY,
                                            .permissions = GATT_PERM_READ|GATT_PERM_WRITE};

  mcs_services.push_back(playing_order_char);
  mcsServerServiceInfo.playing_order_uuid = playing_order_char.uuid;

  //10th desc
  btgatt_db_element_t desc10 = {.uuid = DESCRIPTOR_UUID,
                                .type = BTGATT_DB_DESCRIPTOR,
                                .permissions = GATT_PERM_READ|GATT_PERM_WRITE};
  mcs_services.push_back(desc10);

  btgatt_db_element_t ccid_char = {.uuid = GMCS_CONTENT_CONTROLID,
                                   .type = BTGATT_DB_CHARACTERISTIC,
                                   .properties = GATT_CHAR_PROP_BIT_READ,
                                   .permissions = GATT_PERM_READ};

  mcs_services.push_back(ccid_char);
  mcsServerServiceInfo.ccid_uuid = ccid_char.uuid;

  btgatt_db_element_t seek_speed_char = {.uuid = GMCS_SEEKING_SPEED_UUID,
                                         .type = BTGATT_DB_CHARACTERISTIC,
                                         .properties = GATT_CHAR_PROP_BIT_READ,
                                         .permissions = GATT_PERM_READ};
  mcs_services.push_back(seek_speed_char);
  mcsServerServiceInfo.seeking_speed_uuid = seek_speed_char.uuid;

  return mcs_services;
}


static void OnMcpServiceAddedCb(uint8_t status, int serverIf,
                                std::vector<btgatt_db_element_t> service) {

  if (service[0].uuid == Uuid::From16Bit(UUID_SERVCLASS_GATT_SERVER) ||
      service[0].uuid == Uuid::From16Bit(UUID_SERVCLASS_GAP_SERVER)) {
    LOG(INFO) << "%s: Attempt to register restricted service"<< __func__;
    return;
  }
  for(int i = 0; i < (int)service.size(); i++) {

    if (service[i].uuid == GMCS_UUID) {
      LOG(INFO) << __func__ << " mcs service added attr handle " << service[i].attribute_handle;
    } else if (service[i].uuid == GMCS_MEDIA_STATE_UUID) {
      mcsServerServiceInfo.media_state_handle = service[i++].attribute_handle;
      mcsServerServiceInfo.media_state_desc = service[i].attribute_handle;
      LOG(INFO) << __func__ << " media_state_handle" <<
      mcsServerServiceInfo.media_state_handle;
      LOG(INFO) << __func__ << " media_state_handle desc" <<
      mcsServerServiceInfo.media_state_desc;
   } else if(service[i].uuid == GMCS_MEDIA_CONTROL_POINT_OPCODE_SUPPORTED) {
     mcsServerServiceInfo.media_control_point_opcode_supported_handle =
         service[i++].attribute_handle;
     LOG(INFO) << __func__ << " media_control_point_opcode_supported_handle register" <<
         mcsServerServiceInfo.media_control_point_opcode_supported_handle;
      mcsServerServiceInfo.media_control_point_opcode_supported_desc =
         service[i].attribute_handle;
     LOG(INFO) << __func__ << " media_control_point_opcode_supported_handle desc register" <<
         mcsServerServiceInfo.media_control_point_opcode_supported_desc;
    } else if(service[i].uuid == GMCS_MEDIA_PLAYER_NAME_UUID) {
      mcsServerServiceInfo.media_player_name_handle =
          service[i++].attribute_handle;
      LOG(INFO) << __func__ << " media_player_name_handle GMCS_MEDIA_PLAYER_NAME_UUID register"
          << mcsServerServiceInfo.media_player_name_handle;
      mcsServerServiceInfo.media_player_name_desc =
          service[i].attribute_handle;
      LOG(INFO) << __func__ << " media_player_name_handle GMCS_MEDIA_PLAYER_NAME_UUID desc"
          << mcsServerServiceInfo.media_player_name_desc;
    } else if(service[i].uuid == GMCS_MEDIA_CONTROL_POINT) {
      mcsServerServiceInfo.media_control_point_handle =
          service[i++].attribute_handle;
      LOG(INFO) << __func__ << " media_control_point_handle GMCS_MEDIA_CONTROL_POINT register"
          << mcsServerServiceInfo.media_control_point_handle;
      mcsServerServiceInfo.media_control_point_desc =
          service[i].attribute_handle;
      LOG(INFO) << __func__ << " media_control_point_handle GMCS_MEDIA_CONTROL_POINT desc"
          << mcsServerServiceInfo.media_control_point_desc;
    } else if(service[i].uuid == GMCS_TRACK_CHANGED) {
      mcsServerServiceInfo.track_changed_handle =
          service[i++].attribute_handle;
      LOG(INFO) << __func__ << "track_changed_handle GMCS_TRACK_CHANGED register"
          << mcsServerServiceInfo.track_changed_handle;
      mcsServerServiceInfo.track_changed_desc =
          service[i].attribute_handle;
      LOG(INFO) << __func__ << "track_changed_handle GMCS_TRACK_CHANGED desc"
          << mcsServerServiceInfo.track_changed_desc;
    } else if(service[i].uuid == GMCS_TRACK_TITLE) {
      mcsServerServiceInfo.track_title_handle =
          service[i++].attribute_handle;
      LOG(INFO) << __func__ << "track_title_handle GMCS_TRACK_TITLE register"
          << mcsServerServiceInfo.track_title_handle;
      mcsServerServiceInfo.track_title_desc =
          service[i].attribute_handle;
      LOG(INFO) << __func__ << "track_title_handle GMCS_TRACK_TITLE desc"
         << mcsServerServiceInfo.track_title_desc;
    } else if(service[i].uuid == GMCS_TRACK_DURATION) {
      mcsServerServiceInfo.track_duration_handle =
          service[i++].attribute_handle;

      LOG(INFO) << __func__ << "track_duration_handle GMCS_TRACK_DURATION register"
        << mcsServerServiceInfo.track_duration_handle;
      mcsServerServiceInfo.track_duration_desc =
        service[i].attribute_handle;

      LOG(INFO) << __func__ << "track_duration_handle GMCS_TRACK_DURATION desc"
        << mcsServerServiceInfo.track_duration_desc;

    } else if(service[i].uuid == GMCS_TRACK_POSITION) {
      mcsServerServiceInfo.track_position_handle =
        service[i++].attribute_handle;
      LOG(INFO) << __func__ << "track_position_handle GMCS_TRACK_POSITION register"
        << mcsServerServiceInfo.track_position_handle;
      mcsServerServiceInfo.track_position_desc =
        service[i].attribute_handle;
      LOG(INFO) << __func__ << "track_position_handle GMCS_TRACK_POSITION desc"
        << mcsServerServiceInfo.track_position_handle;

    } else if(service[i].uuid == GMCS_PLAYING_ORDER_SUPPORTED) {
      mcsServerServiceInfo.playing_order_supported_handle =
          service[i].attribute_handle;
      LOG(INFO) << __func__ << "playing_order_supported_handle GMCS_PLAYING_ORDER_SUPPORTED register"
          << mcsServerServiceInfo.playing_order_supported_handle;
    } else if(service[i].uuid == GMCS_PLAYING_ORDER) {
      mcsServerServiceInfo.playing_order_handle =
          service[i++].attribute_handle;
      LOG(INFO) << __func__ << "playing_order_handle GMCS_PLAYING_ORDER register"
          << mcsServerServiceInfo.playing_order_handle;
      mcsServerServiceInfo.playing_order_desc =
          service[i].attribute_handle;
      LOG(INFO) << __func__ << "playing_order_handle GMCS_PLAYING_ORDER desc"
          << mcsServerServiceInfo.playing_order_desc;
    } else if(service[i].uuid == GMCS_CONTENT_CONTROLID) {
      mcsServerServiceInfo.ccid_handle =
          service[i].attribute_handle;
      LOG(INFO) << __func__ << "ccid_handle GMCS_CONTENT_CONTROLID register" <<
          mcsServerServiceInfo.ccid_handle;
    } else if(service[i].uuid == GMCS_SEEKING_SPEED_UUID) {
      mcsServerServiceInfo.seeking_speed_handle =
          service[i].attribute_handle;
      LOG(INFO) << __func__ << "ccid_handle GMCS_SEEKING_SPEED_ID register" <<
          mcsServerServiceInfo.seeking_speed_handle;
    }
  } //for
}


void BTMcpCback(tBTA_GATTS_EVT event, tBTA_GATTS* param) {
  HandleMcsEvent((uint32_t)event, param);
}

//mcs handle event
void HandleMcsEvent(uint32_t event, void* param) {
  LOG(INFO) << __func__ << "   mcs handle event " << get_mcp_event_name(event);
  tBTA_GATTS* p_data = NULL;
  uint32_t proc_event;
  mcp_resp_t *rsp = (mcp_resp_t *)osi_malloc(sizeof(mcp_resp_t));
  if (rsp == NULL) {
    LOG(INFO) << __func__ << " mcs handle return rsp not allocated ";
    return;
  }
  uint8_t status = BT_STATUS_SUCCESS;
  proc_event = MCP_NONE_EVENT;
  rsp->event = MCP_NONE_EVENT;
  switch (event) {

    case MCP_INIT_EVENT:
    {
       // Uuid app_uuid = (Uuid)*param;
      Uuid aap_uuid = Uuid::FromString("1849");
      mediaPlayerInfo.media_state = MCP_STATE_INACTIVE;
      mediaPlayerInfo.MediaStateHandlerPointer[MCP_STATE_INACTIVE] =
          MediaStateInactiveHandler;
      mediaPlayerInfo.MediaStateHandlerPointer[MCP_STATE_PAUSE] =
          MediaStatePauseHandler;
      mediaPlayerInfo.MediaStateHandlerPointer[MCP_STATE_PLAYING] =
          MediaStatePlayingHandler;
      mediaPlayerInfo.MediaStateHandlerPointer[MCP_STATE_SEEKING] =
          MediaStateSeekingHandler;

      mediaPlayerInfo.media_supported_feature = MCP_DEFAULT_MEDIA_CTRL_SUPP_FEAT;
      mediaPlayerInfo.ccid = 0;
      mediaPlayerInfo.seeking_speed = 0;
      mediaPlayerInfo.duration = TRACK_POSITION_UNAVAILABLE;
      mediaPlayerInfo.position = TRACK_DURATION_UNAVAILABLE;
      mediaPlayerInfo.track_changed = false;
      mediaPlayerInfo.playing_order_value = 1;
      mediaPlayerInfo.playing_order_supported = 1;
      mediaPlayerInfo.player_name_len = 0;
      mediaPlayerInfo.track_title_len = 0;
      mediaPlayerInfo.media_ctrl_point = 0;
      //adding app with random uuid
      BTA_GATTS_AppRegister(aap_uuid, BTMcpCback, true);
      break;
    }

    case MCP_CLEANUP_EVENT:
    {
      //initiate disconnection to all connected device
      //unregister APP
      BTA_GATTS_AppDeregister(mcsServerServiceInfo.server_if);
      break;
    }
    case BTA_GATTS_REG_EVT:
    {
       p_data = (tBTA_GATTS*)param;
       if (p_data->reg_oper.status == BT_STATUS_SUCCESS) {
           mcsServerServiceInfo.server_if = p_data->reg_oper.server_if;
         std::vector<btgatt_db_element_t> service;
         service = McpAddService(mcsServerServiceInfo.server_if);
         if (service[0].uuid == Uuid::From16Bit(UUID_SERVCLASS_GATT_SERVER) ||
                 service[0].uuid == Uuid::From16Bit(UUID_SERVCLASS_GAP_SERVER)) {
           LOG(INFO) << __func__ << "   service app register uuid is not valid";
           break;
         }
         LOG(INFO) << __func__ << "   service app register";
         BTA_GATTS_AddService(mcsServerServiceInfo.server_if, service, base::Bind(&OnMcpServiceAddedCb));
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
      RemoteDevice *remoteDevice;
      remoteDevice = instance->remoteDevices.FindByConnId(p_data->congest.conn_id);
      if(remoteDevice == NULL) {
        LOG(INFO) << __func__ << "   connection entry not found conn_id :"
          << p_data->congest.conn_id;
        break;
      }
     // rsp->ConngestionOp.status = p_data->req_data.status;
      rsp->remoteDevice = remoteDevice;
      rsp->oper.CongestionOp.congested = p_data->congest.congested;
      proc_event = MCP_CONGESTION_UPDATE;
      rsp->event = MCP_CONGESTION_UPDATE;
      break;
    }
    case BTA_GATTS_MTU_EVT: {
      p_data = (tBTA_GATTS*)param;
      RemoteDevice *remoteDevice;
      remoteDevice = instance->remoteDevices.FindByConnId(p_data->req_data.p_data->mtu);
      if(remoteDevice == NULL) {
        LOG(INFO) << __func__ << " connection entry not found conn_id :"
          << p_data->congest.conn_id;
        break;
      }
      LOG(INFO) << __func__ << " conn_id :"<< p_data->req_data.p_data->mtu;
      LOG(INFO) <<"mtu " <<p_data->req_data.p_data->mtu;
      proc_event = MCP_MTU_UPDATE;
      rsp->event = MCP_MTU_UPDATE;
      rsp->remoteDevice = remoteDevice;
      rsp->oper.MtuOp.mtu = p_data->req_data.p_data->mtu;
      break;
    }
    case BTA_GATTS_CONNECT_EVT: {
      p_data = (tBTA_GATTS*)param;
      LOG(INFO) << __func__ << "   remote devices connected";
      //<TBD> need to discuss how to get encryption support
    /*
    #if (!defined(BTA_SKIP_BLE_START_ENCRYPTION) || BTA_SKIP_BLE_START_ENCRYPTION == FALSE)
        btif_gatt_check_encrypted_link(p_data->conn.remote_bda,
                                     p_data->conn.transport);
    #endif*/
      RemoteDevice remoteDevice;
      memset(&remoteDevice, 0, sizeof(remoteDevice));
      if(instance->remoteDevices.FindByAddress(p_data->conn.remote_bda)) {
      LOG(INFO) << __func__ << "  remote devices already there is connected list";
        status = BT_STATUS_FAIL;
        return;
      }
      remoteDevice.peer_bda = p_data->conn.remote_bda;
      remoteDevice.conn_id = p_data->conn.conn_id;
      if(instance->remoteDevices.Add(remoteDevice) == false) {
        LOG(INFO) << __func__ << "  remote device is not added : max connection reached";
        //<TBD> need to check disconnection required
        break;
      }
      remoteDevice.state = MCP_DISCONNECTED;

      LOG(INFO) << __func__ << "   remote devices connected conn_id: "<< remoteDevice.conn_id <<
         "bd_addr " << remoteDevice.peer_bda;
      rsp->remoteDevice = instance->remoteDevices.FindByAddress(p_data->conn.remote_bda);
      if ( rsp->remoteDevice == NULL) {
        LOG(INFO) << __func__ ;
        break;
      }
      proc_event = MCP_CONNECTION;
      rsp->event = MCP_CONNECTION;
      break;
    }

    case BTA_GATTS_CLOSE_EVT:
    case BTA_GATTS_DISCONNECT_EVT: {
      p_data = (tBTA_GATTS*)param;
      LOG(INFO) << __func__ << "   remote devices disconnected conn_id " << p_data->conn.conn_id;
      RemoteDevice *remoteDevice;
      remoteDevice = instance->remoteDevices.FindByConnId(p_data->conn.conn_id);
      if((!remoteDevice) ) {
        status = BT_STATUS_FAIL;
        break;
      }

      rsp->remoteDevice = remoteDevice;
      proc_event = MCP_DISCONNECTION;
      rsp->event = MCP_DISCONNECTION;
      LOG(INFO) << __func__ << "  disconnected conn_id " << p_data->conn.conn_id;
      break;
    }

    case BTA_GATTS_STOP_EVT:
      //<TBD> not required
      break;

    case BTA_GATTS_DELELTE_EVT:
      //<TBD> not required
      break;

    case BTA_GATTS_READ_CHARACTERISTIC_EVT: {
      p_data = (tBTA_GATTS*)param;
      std::vector<uint8_t> value;
      RemoteDevice *remoteDevice =
          instance->remoteDevices.FindByConnId(p_data->req_data.conn_id);
      LOG(INFO) << __func__ << " charateristcs read handle " <<
          p_data->req_data.p_data->read_req.handle <<" trans_id : " <<
          p_data->req_data.trans_id;

      if(remoteDevice == NULL) {
        LOG(INFO) << __func__ << " device not found ignore read operation";
        status = BT_STATUS_FAIL;
        break;
      }

      LOG(INFO) <<"   offset: " << p_data->req_data.p_data->read_req.offset <<
          " long : " << p_data->req_data.p_data->read_req.is_long;

      rsp->rsp_value.attr_value.auth_req  = 0;
      rsp->rsp_value.attr_value.handle = p_data->req_data.p_data->read_req.handle;
      rsp->rsp_value.attr_value.offset = p_data->req_data.p_data->read_req.offset;

      if(p_data->req_data.p_data->read_req.handle ==
          mcsServerServiceInfo.media_state_handle) {
        proc_event = MCP_MEDIA_STATE_READ;
        LOG(INFO) << __func__ << " media_state_handle read";
      } else if(p_data->req_data.p_data->read_req.handle ==
        mcsServerServiceInfo.media_control_point_opcode_supported_handle) {
        proc_event = MCP_MEDIA_CONTROL_POINT_OPCODE_SUPPORTED_READ;
        LOG(INFO) << __func__ << " media_control_point_opcode_supported_handle read";
      } else if(p_data->req_data.p_data->read_req.handle ==
        mcsServerServiceInfo.media_player_name_handle) {
        proc_event = MCP_MEDIA_PLAYER_NAME_READ;
        LOG(INFO) << __func__ << " media_player_name_handle read";
      } else if(p_data->req_data.p_data->read_req.handle ==
        mcsServerServiceInfo.track_title_handle) {
        proc_event = MCP_TRACK_TITLE_READ;
        LOG(INFO) << __func__ << " track_title_handle read";
      } else if(p_data->req_data.p_data->read_req.handle ==
        mcsServerServiceInfo.track_position_handle) {
        proc_event = MCP_TRACK_POSITION_READ;
        LOG(INFO) << __func__ << " track_position_handle read";
      } else if(p_data->req_data.p_data->read_req.handle ==
        mcsServerServiceInfo.track_duration_handle) {
        proc_event = MCP_TRACK_DURATION_READ;
        LOG(INFO) << __func__ << " track_duration_handle read";
      } else if(p_data->req_data.p_data->read_req.handle ==
        mcsServerServiceInfo.ccid_handle) {
        LOG(INFO) << __func__ << " ccid_handle read";
        proc_event = MCP_CCID_READ;
      } else if(p_data->req_data.p_data->read_req.handle ==
        mcsServerServiceInfo.seeking_speed_handle) {
        LOG(INFO) << __func__ << " seeking_speed_handle read";
        proc_event = MCP_SEEKING_SPEED_READ;
      } else if(p_data->req_data.p_data->read_req.handle ==
        mcsServerServiceInfo.playing_order_supported_handle) {
        LOG(INFO) << __func__ << " playing_order_supported_handle read";
        proc_event = MCP_PLAYING_ORDER_SUPPORTED_READ;
      } else if(p_data->req_data.p_data->read_req.handle ==
        mcsServerServiceInfo.playing_order_handle) {
        LOG(INFO) << __func__ << " playing_order_handle read";
        proc_event = MCP_PLAYING_ORDER_READ;
      } else {
        LOG(INFO) << __func__ << " read request for unknown handle" << p_data->req_data.p_data->read_req.handle;
        status = BT_STATUS_FAIL;
        break;
      }
      LOG(INFO) << __func__ << " read request handle" << p_data->req_data.p_data->read_req.handle <<
        "connection id" << p_data->req_data.conn_id;
      rsp->event = MCP_READ_RSP;
      rsp->oper.ReadOp.trans_id = p_data->req_data.trans_id;
      rsp->oper.ReadOp.is_long = p_data->req_data.p_data->read_req.is_long;
      rsp->oper.ReadOp.status = BT_STATUS_SUCCESS;
      rsp->remoteDevice = remoteDevice;
      break;
    }

    case BTA_GATTS_READ_DESCRIPTOR_EVT: {
      LOG(INFO) << __func__ << "  read descriptor";
      p_data = (tBTA_GATTS*)param;
      LOG(INFO) << __func__ << "  charateristcs read desc handle " <<
          p_data->req_data.p_data->read_req.handle << " offset : "
          << p_data->req_data.p_data->read_req.offset;
      RemoteDevice *remoteDevice =
          instance->remoteDevices.FindByConnId(p_data->req_data.conn_id);
      if(remoteDevice == NULL) {
        LOG(INFO) << __func__ << " device not found ignore write";
        status = BT_STATUS_FAIL;
        break;
      }

      if(p_data->req_data.p_data->read_req.handle ==
          mcsServerServiceInfo.media_state_desc) {
        LOG(INFO) << __func__ << " media_state_desc read";
        proc_event = MCP_MEDIA_STATE_READ_DESCRIPTOR;
      } else if(p_data->req_data.p_data->read_req.handle ==
          mcsServerServiceInfo.media_control_point_desc) {
        LOG(INFO) << __func__ << " media_control_point_desc read";
        proc_event = MCP_MEDIA_CONTROL_POINT_READ_DESCRIPTOR;
      } else if(p_data->req_data.p_data->read_req.handle ==
          mcsServerServiceInfo.media_control_point_opcode_supported_desc) {
        LOG(INFO) << __func__ << " media_control_point_opcode_supported_desc read";
        proc_event = MCP_MEDIA_CONTROL_POINT_OPCODE_SUPPORTED_DESCRIPTOR_READ;
      } else if(p_data->req_data.p_data->read_req.handle ==
          mcsServerServiceInfo.media_player_name_desc) {
        LOG(INFO) << __func__ << " media_player_name_desc read";
        proc_event = MCP_MEDIA_PLAYER_NAME_DESCRIPTOR_READ;
      } else if(p_data->req_data.p_data->read_req.handle ==
          mcsServerServiceInfo.track_changed_desc) {
        LOG(INFO) << __func__ << " track_changed_desc read";
        proc_event = MCP_TRACK_CHANGED_DESCRIPTOR_READ;
      } else if(p_data->req_data.p_data->read_req.handle ==
          mcsServerServiceInfo.track_title_desc) {
        LOG(INFO) << __func__ << " track_title_desc read";
        proc_event = MCP_TRACK_TITLE_DESCRIPTOR_READ;
      } else if(p_data->req_data.p_data->read_req.handle ==
          mcsServerServiceInfo.track_position_desc) {
        LOG(INFO) << __func__ << " track_position_desc read";
        proc_event = MCP_TRACK_POSITION_DESCRIPTOR_READ;
      } else if(p_data->req_data.p_data->read_req.handle ==
          mcsServerServiceInfo.track_duration_desc) {
        LOG(INFO) << __func__ << " track_duration_desc read";
        proc_event = MCP_TRACK_DURATION_DESCRIPTOR_READ;
      } else if(p_data->req_data.p_data->read_req.handle ==
          mcsServerServiceInfo.playing_order_desc) {
        LOG(INFO) << __func__ << " playing_order_desc read";
        proc_event = MCP_PLAYING_ORDER_DESCRIPTOR_READ;
      } else {
        LOG(INFO) << __func__ << " read request for unknown handle" << p_data->req_data.p_data->read_req.handle;
        status = BT_STATUS_FAIL;
        break;
      }
      rsp->event = MCP_DESCRIPTOR_READ_RSP;
      rsp->rsp_value.attr_value.auth_req  = 0;
      rsp->rsp_value.attr_value.handle = p_data->req_data.p_data->read_req.handle;
      rsp->rsp_value.attr_value.offset = p_data->req_data.p_data->read_req.offset;
      //mcp response
      rsp->oper.ReadDescOp.desc_handle = p_data->req_data.p_data->read_req.handle;
      rsp->oper.ReadDescOp.trans_id = p_data->req_data.trans_id;
      rsp->oper.ReadDescOp.status = BT_STATUS_SUCCESS;
      rsp->remoteDevice = remoteDevice;
      break;
    }

    case BTA_GATTS_WRITE_CHARACTERISTIC_EVT: {
      p_data = (tBTA_GATTS*)param;
        const auto& req = p_data->req_data.p_data->write_req;
      LOG(INFO) << __func__ << " write characteristics len : " << req.len << " value "<< req.value[0];
      RemoteDevice *remoteDevice =
          instance->remoteDevices.FindByConnId(p_data->req_data.conn_id);
      if(remoteDevice == NULL) {
        LOG(INFO) << __func__ << " device not found ignore write";
        status = BT_STATUS_DEVICE_NOT_CONNECTED;
        break;
      }

      rsp->event = MCP_WRITE_RSP;
      rsp->oper.WriteOp.status = BT_STATUS_SUCCESS;
      if (req.handle == mcsServerServiceInfo.playing_order_handle) {
        proc_event = MCP_PLAYING_ORDER_WRITE;
      } else if (req.handle == mcsServerServiceInfo.media_control_point_handle) {
        proc_event = MCP_MEDIA_CONTROL_POINT_WRITE;
      } else if (req.handle == mcsServerServiceInfo.track_position_handle) {
        proc_event = MCP_TRACK_POSITION_WRITE;
      } else  {
        //characteristics handle not matched.
        //<TBD>
        rsp->oper.WriteOp.status = BT_STATUS_HANLDE_NOT_MATCHED;
      }
      rsp->oper.WriteOp.char_handle = req.handle;
      rsp->oper.WriteOp.trans_id = p_data->req_data.trans_id;
      rsp->remoteDevice = remoteDevice;
      rsp->oper.WriteOp.need_rsp = req.need_rsp;
      rsp->oper.WriteOp.offset = req.offset; //<TBD> need to check requirement
      memcpy(rsp->oper.WriteOp.data, req.value, req.len);
      LOG(INFO) << __func__ << " Local Tx ID " << rsp->oper.WriteOp.trans_id << " Gatt Tx ID: " << p_data->req_data.trans_id;
      break;
    }

    case BTA_GATTS_WRITE_DESCRIPTOR_EVT: {
      p_data = (tBTA_GATTS* )param;
      uint16_t req_value = 0;
      const auto& req = p_data->req_data.p_data->write_req;
      RemoteDevice *remoteDevice =
           instance->remoteDevices.FindByConnId(p_data->req_data.conn_id);
      if(remoteDevice == NULL) {
        LOG(INFO) << __func__ << " device not found ignore notification";
        break;
      }
      req_value = *(uint16_t* )req.value;
      //need to initialized with proper error code
      int status = BT_STATUS_SUCCESS;
      LOG(INFO) << __func__ << "   write descriptor :" << req.handle <<
         "is resp: " << req.need_rsp << "is prep: " << req.is_prep << " value " << req_value;

      if(req.handle ==
          mcsServerServiceInfo.media_state_desc) {
        LOG(INFO) << __func__ << " media_state_desc descriptor write";
        remoteDevice->media_state_notify = req_value;
        proc_event = MCP_MEDIA_STATE_DESCRIPTOR_WRITE;
      } else if(req.handle ==
        mcsServerServiceInfo.media_player_name_desc) {
        remoteDevice->media_player_name_notify = req_value;
        LOG(INFO) << __func__ << " media_player_name_desc descriptor write";
        proc_event = MCP_MEDIA_PLAYER_NAME_DESCRIPTOR_WRITE;
      } else if(req.handle ==
        mcsServerServiceInfo.media_control_point_desc) {
            remoteDevice->media_control_point_notify = req_value;
        LOG(INFO) << __func__ << " media_player_control_point_desc descriptor write";
        proc_event = MCP_MEDIA_CONTROL_POINT_DESCRIPTOR_WRITE;
      } else if(req.handle ==
        mcsServerServiceInfo.media_control_point_opcode_supported_desc) {
            remoteDevice->media_control_point_opcode_supported_notify = req_value;
        LOG(INFO) << __func__ << " media_control_point_opcode_supported_desc descriptor write";
        proc_event = MCP_MEDIA_CONTROL_POINT_SUPPORTED_DESCRIPTOR_WRITE;
      } else if(req.handle ==
          mcsServerServiceInfo.track_changed_desc) {
        remoteDevice->track_changed_notify = req_value;
        LOG(INFO) << __func__ << " track_changed_desc descriptor write";
        proc_event = MCP_TRACK_CHANGED_DESCRIPTOR_WRITE;
      } else if(req.handle ==
          mcsServerServiceInfo.track_title_desc) {
        remoteDevice->track_title_notify = req_value;
        LOG(INFO) << __func__ << " track_title_desc descriptor write";
        proc_event = MCP_TRACK_TITLE_DESCRIPTOR_WRITE;
      } else if(req.handle ==
        mcsServerServiceInfo.track_position_desc) {
        remoteDevice->track_position_notify   = req_value;
        LOG(INFO) << __func__ << " track_position_desc descriptor write";
        proc_event = MCP_TRACK_POSITION_DESCRIPTOR_WRITE;
      } else if(req.handle ==
          mcsServerServiceInfo.track_duration_desc) {
        remoteDevice->track_duration_notify   = req_value;
        LOG(INFO) << __func__ << " track_duration_desc descriptor write";
        proc_event = MCP_TRACK_DURATION_DESCRIPTOR_WRITE;
      } else if(req.handle ==
          mcsServerServiceInfo.playing_order_desc) {
        remoteDevice->playing_order_notify = req_value;
        LOG(INFO) << __func__ << " playing_order_desc descriptor write";
        proc_event = MCP_PLAYING_ORDER_DESCRIPTOR_WRITE;
      } else {
        LOG(INFO) << __func__ << "  descriptor write not matched ";
        status = 4; //<TBD>need to check error code
      }
      rsp->event = MCP_DESCRIPTOR_WRITE_RSP;
      rsp->oper.WriteDescOp.desc_handle = req.handle;
      rsp->oper.WriteDescOp.trans_id = p_data->req_data.trans_id;
      rsp->oper.WriteDescOp.status = status;
      rsp->oper.WriteDescOp.need_rsp = req.need_rsp;
      rsp->oper.WriteDescOp.notification = req_value;
      rsp->remoteDevice = remoteDevice;
      break;
    }

    case BTA_GATTS_EXEC_WRITE_EVT: {
      p_data = (tBTA_GATTS*)param;
      //<TBD> need to check requirement
      break;
    }

    case BTA_GATTS_PHY_UPDATE_EVT: {
      p_data = (tBTA_GATTS*)param;
      RemoteDevice *remoteDevice =
        instance->remoteDevices.FindByConnId(p_data->phy_update.conn_id);
      if(remoteDevice == NULL) {
        LOG(INFO) << __func__ << " device not found ignore phy update"
            << p_data->phy_update.status;
        status = BT_STATUS_FAIL;
        break;
      }
      proc_event = MCP_PHY_UPDATE;
      rsp->event = MCP_PHY_UPDATE;
      rsp->oper.PhyOp.rx_phy = p_data->phy_update.rx_phy;
      rsp->oper.PhyOp.tx_phy = p_data->phy_update.tx_phy;
      rsp->remoteDevice = remoteDevice;
      break;
    }

    case BTA_GATTS_CONN_UPDATE_EVT: {
      p_data = (tBTA_GATTS*)param;
      RemoteDevice *remoteDevice =
        instance->remoteDevices.FindByConnId(p_data->phy_update.conn_id);
      if(remoteDevice == NULL) {
        LOG(INFO) << __func__ << " connection update device not found";
        break;
      }
      LOG(INFO) << __func__ << " connection update status" << p_data->phy_update.status;
      proc_event = MCP_CONNECTION_UPDATE;
      rsp->event = MCP_CONNECTION_UPDATE;
      rsp->oper.ConnectionUpdateOp.latency = p_data->conn_update.latency;
      rsp->oper.ConnectionUpdateOp.timeout = p_data->conn_update.timeout;
      rsp->oper.ConnectionUpdateOp.interval = p_data->conn_update.interval;
      rsp->oper.ConnectionUpdateOp.status = p_data->conn_update.status;
      rsp->remoteDevice = remoteDevice;
      break;
    }

    case MCP_ACTIVE_DEVICE_UPDATE:
    {
      tMCP_SET_ACTIVE_DEVICE *data = (tMCP_SET_ACTIVE_DEVICE *)param;
      LOG(INFO) << __func__ << " address " << data->address;
      RemoteDevice *remoteDevice = instance->remoteDevices.FindByAddress(data->address);
      if(remoteDevice == NULL) {
        LOG(INFO) << __func__ << " active device update device address not found";
        break;
      }
      instance->remoteDevices.AddSetActiveDevice(data);
      rsp->remoteDevice = remoteDevice;
      rsp->oper.SetActiveDeviceOp.profile = data->profile;
      proc_event = MCP_ACTIVE_DEVICE_UPDATE;
      rsp->event = MCP_ACTIVE_DEVICE_UPDATE;


      break;
    }

    case MCP_MEDIA_STATE_UPDATE:
    {
      tMCP_MEDIA_STATE *data = (tMCP_MEDIA_STATE *) param;
      if (mediaPlayerInfo.media_state != data->state)
        mediaPlayerInfo.media_state = data->state;
      LOG(INFO) << __func__ << " state: " << unsigned(mediaPlayerInfo.media_state);
      proc_event = MCP_NOTIFY_ALL;
      rsp->event = MCP_NOTIFY_ALL;
      rsp->handle = mcsServerServiceInfo.media_state_handle;
      rsp->oper.MediaUpdateOp.data = &mediaPlayerInfo.media_state;
      rsp->oper.MediaUpdateOp.len = sizeof(mediaPlayerInfo.media_state);
      break;
    }

    case MCP_MEDIA_PLAYER_NAME_UPDATE:
    {
      tMCP_MEDIA_PLAYER_NAME *data = (tMCP_MEDIA_PLAYER_NAME *) param;
      if (memcmp(mediaPlayerInfo.player_name, data->name, data->len)) {
        memcpy(mediaPlayerInfo.player_name, data, data->len);
        mediaPlayerInfo.player_name_len = data->len;
      }
      proc_event = MCP_NOTIFY_ALL;
      rsp->event = MCP_NOTIFY_ALL;
      rsp->handle = mcsServerServiceInfo.media_player_name_handle;
      rsp->oper.MediaUpdateOp.data = (uint8_t *)mediaPlayerInfo.player_name;
      rsp->oper.MediaUpdateOp.len = mediaPlayerInfo.player_name_len;
      break;
    }

    case MCP_MEDIA_SUPPORTED_OPCODE_UPDATE:
    {
      tMCP_MEDIA_OPCODE_SUPPORT *data = (tMCP_MEDIA_OPCODE_SUPPORT *)param;
      mediaPlayerInfo.media_supported_feature = data->supported;
      proc_event = MCP_NOTIFY_ALL;
      rsp->event = MCP_NOTIFY_ALL;
      rsp->handle = mcsServerServiceInfo.media_control_point_opcode_supported_handle;
      rsp->oper.MediaUpdateOp.data = (uint8_t *)&mediaPlayerInfo.media_supported_feature;
      rsp->oper.MediaUpdateOp.len = sizeof(mediaPlayerInfo.media_supported_feature);
      break;
    }

    case MCP_MEDIA_CONTROL_POINT_UPDATE:
    {
      tMCP_MEDIA_CONTROL_POINT *data = (tMCP_MEDIA_CONTROL_POINT *)param;
      mediaPlayerInfo.media_ctrl_point = data->req_opcode | (data->result << 8);
      proc_event = MCP_NOTIFY_ALL;
      rsp->event = MCP_NOTIFY_ALL;
      rsp->handle = mcsServerServiceInfo.media_control_point_handle;
      rsp->oper.MediaUpdateOp.data = (uint8_t *)&mediaPlayerInfo.media_ctrl_point;
      rsp->oper.MediaUpdateOp.len = sizeof(mediaPlayerInfo.media_ctrl_point);
      break;
    }
    case MCP_PLAYING_ORDER_SUPPORTED_UPDATE:
    {
      tMCP_PLAYING_ORDER_SUPPORT *data = (tMCP_PLAYING_ORDER_SUPPORT *) param;
      mediaPlayerInfo.playing_order_supported = data->order_supported;
      proc_event = MCP_NOTIFY_ALL;
      rsp->event = MCP_NOTIFY_ALL;
      rsp->handle =
          mcsServerServiceInfo.media_control_point_opcode_supported_handle;
      rsp->oper.MediaUpdateOp.data = (uint8_t *)&mediaPlayerInfo.playing_order_supported;
      rsp->oper.MediaUpdateOp.len = sizeof(mediaPlayerInfo.playing_order_supported);
      break;
    }

    case MCP_PLAYING_ORDER_UPDATE:
    {
      tMCP_PLAYING_ORDER *data = (tMCP_PLAYING_ORDER *) param;
      mediaPlayerInfo.playing_order_value = data->order;
      proc_event = MCP_NOTIFY_ALL;
      rsp->event = MCP_NOTIFY_ALL;
      rsp->handle = mcsServerServiceInfo.playing_order_handle;
      rsp->oper.MediaUpdateOp.data = (uint8_t *)&mediaPlayerInfo.playing_order_value;
      rsp->oper.MediaUpdateOp.len = sizeof(mediaPlayerInfo.playing_order_value);
      break;
    }

    case MCP_TRACK_CHANGED_UPDATE:
    {
      tMCP_TRACK_CHANGED *data = (tMCP_TRACK_CHANGED *) param;
      mediaPlayerInfo.track_changed = data->status;
      proc_event = MCP_NOTIFY_ALL;
      rsp->event = MCP_NOTIFY_ALL;
      rsp->handle = mcsServerServiceInfo.track_changed_handle;
      rsp->oper.MediaUpdateOp.data = (uint8_t *)&mediaPlayerInfo.track_changed;
      rsp->oper.MediaUpdateOp.len = sizeof(mediaPlayerInfo.track_changed);
      break;
    }

    case MCP_TRACK_POSITION_UPDATE:
    {
      tMCP_TRACK_POSTION *data = (tMCP_TRACK_POSTION*) param;
      if(data->position != mediaPlayerInfo.position) {
        mediaPlayerInfo.position = data->position;
      }
      proc_event = MCP_NOTIFY_ALL;
      rsp->event = MCP_NOTIFY_ALL;
      rsp->handle = mcsServerServiceInfo.track_position_handle;
      rsp->oper.MediaUpdateOp.data = (uint8_t *)&mediaPlayerInfo.position;
      rsp->oper.MediaUpdateOp.len = sizeof(mediaPlayerInfo.position);
      break;
    }

    case MCP_TRACK_DURATION_UPDATE:
    {
      tMCP_TRACK_DURATION* data = (tMCP_TRACK_DURATION *) param;
      mediaPlayerInfo.duration = data->duration;
      proc_event = MCP_NOTIFY_ALL;
      rsp->event = MCP_NOTIFY_ALL;
      rsp->rsp_value.handle = mcsServerServiceInfo.track_duration_handle;
      rsp->handle = mcsServerServiceInfo.track_duration_handle;
      rsp->oper.MediaUpdateOp.data = (uint8_t *)&mediaPlayerInfo.duration;
      rsp->oper.MediaUpdateOp.len = sizeof(mediaPlayerInfo.duration);
      break;
    }

    case MCP_TRACK_TITLE_UPDATE:
    {
      tMCP_TRACK_TITLE *data = (tMCP_TRACK_TITLE*) param;
      proc_event = MCP_NOTIFY_ALL;
      rsp->event = MCP_NOTIFY_ALL;
      rsp->handle = mcsServerServiceInfo.track_title_handle;
      if (memcmp(mediaPlayerInfo.title, data->title, data->len)) {
        memcpy(mediaPlayerInfo.title, data->title, data->len);
        mediaPlayerInfo.track_title_len = data->len;
      }
      rsp->oper.MediaUpdateOp.data = (uint8_t *)mediaPlayerInfo.title;
      rsp->oper.MediaUpdateOp.len = sizeof(mediaPlayerInfo.track_title_len);
      break;
    }
    case MCP_CCID_UPDATE:
    {
      tMCP_CONTENT_CONTROL_ID *data = (tMCP_CONTENT_CONTROL_ID *) param;
      mediaPlayerInfo.ccid = (uint8_t)data->ccid;
      proc_event = MCP_NOTIFY_ALL;
      rsp->event = MCP_NOTIFY_ALL;
      rsp->handle = mcsServerServiceInfo.ccid_handle;
      rsp->oper.MediaUpdateOp.data = (uint8_t *)&mediaPlayerInfo.ccid;
      rsp->oper.MediaUpdateOp.len = sizeof(mediaPlayerInfo.ccid);
      break;
    }

    case MCP_CONNECTION_CLOSE_EVENT:
    {
      tMCP_CONNECTION_CLOSE* p_data = (tMCP_CONNECTION_CLOSE *)param;
      RemoteDevice* remoteDevice = instance->remoteDevices.FindByAddress(p_data->addr);
      if(remoteDevice == NULL) {
        LOG(INFO) << __func__ << " address is not in list";
        break;
      }
      proc_event = MCP_CONNECTION_CLOSE_EVENT;
      rsp->remoteDevice = remoteDevice;
      break;
    }

    case MCP_BOND_STATE_CHANGE_EVENT:
    {
      tMCP_BOND_STATE_CHANGE* p_data = (tMCP_BOND_STATE_CHANGE *)param;
      RemoteDevice* remoteDevice = instance->remoteDevices.FindByAddress(p_data->addr);
      if(remoteDevice == NULL) {
        LOG(INFO) << __func__ << " address is not in list";
        break;
      }
      instance->remoteDevices.Remove(p_data->addr);
      break;
    }
    default:
      LOG(INFO) << __func__ << " event not matched !!";
      break;
  }

  if(rsp->event != MCP_NONE_EVENT) {
    LOG(INFO) << __func__ << " event to media handler " << get_mcp_event_name(rsp->event);
    mediaPlayerInfo.MediaStateHandlerPointer[mediaPlayerInfo.media_state](proc_event, rsp, mediaPlayerInfo.media_state);
  }
  if(rsp) {
    LOG(INFO) << __func__ << "free rsp data";
    osi_free(rsp);
  }
}


bool MediaStateInactiveHandler(uint32_t event, void* param, uint8_t state) {
  LOG(INFO) << __func__ << " handle event " << get_mcp_event_name(event)
            << " in state " << get_mcp_media_state_name(state);

  mcp_resp_t *p_data = (mcp_resp_t *)param;

  RemoteDevice *device = p_data->remoteDevice;
  LOG(INFO) << __func__ << " inactive mcs handle event "<< get_mcp_event_name(p_data->event);
  switch(event) {
    case MCP_NOTIFY_ALL: {
      LOG(INFO) << __func__ << " Notify all handle "<< p_data->handle;
      std::vector<RemoteDevice>notifyDevices = instance->remoteDevices.FindNotifyDevices(p_data->handle);
      std::vector<RemoteDevice>::iterator it;
      if (notifyDevices.size() <= 0) {
        LOG(INFO) << __func__ << " No device register for notification";
        break;
      }
      for (it = notifyDevices.begin(); it != notifyDevices.end(); it++){
      LOG(INFO) << __func__ << " Notify all handle device id " << it->conn_id;
      p_data->remoteDevice = instance->remoteDevices.FindByConnId(it->conn_id);
        it->DeviceStateHandlerPointer[it->state](p_data->event, p_data, it->state);
      }
      break;
    }

    case MCP_TRACK_POSITION_WRITE:
    case MCP_PLAYING_ORDER_WRITE: {
      LOG(INFO) << __func__ << "Ignore other request as player is not active";
      //need to ignore write rsp because no player is active
      p_data->rsp_value.attr_value.len = 0;
      uint8_t data = (uint8_t)(*p_data->oper.WriteOp.data);
      std::vector<uint8_t> value;
      value.push_back(data);
      value.push_back(0x03); // To-Do check ???
      LOG(INFO) << __func__ << "hndl " << p_data->oper.WriteOp.char_handle;
      GattsOpsQueue::SendNotification(device->conn_id, p_data->oper.WriteOp.char_handle, value, false);
      break;
    }

    case MCP_MEDIA_CONTROL_POINT_WRITE: {
      LOG(INFO) << __func__ << "Ignore other request as player is not active ctrl pt write";
      //need to ignore write rsp because no player is active
      p_data->rsp_value.attr_value.len = 0;
      device->DeviceStateHandlerPointer[device->state](p_data->event, p_data, device->state);
      uint8_t data = (uint8_t)(*p_data->oper.WriteOp.data);
      uint8_t status = MCP_MEDIA_PLAYER_INACTIVE;
      std::vector<uint8_t> value;
      bool opcode_support = is_opcode_supported(data);
      if (!opcode_support) {
        status = MCP_OPCODE_NOT_SUPPORTED;
        LOG(INFO) << __func__ << "Sending OPCode Unsupported indication";
      } else {
        LOG(INFO) << __func__ << "Sending INACTIVE indication";
      }
      value.push_back(data);
      value.push_back(status);
      LOG(INFO) << __func__ << "handle " << p_data->oper.WriteOp.char_handle;
      GattsOpsQueue::SendNotification(device->conn_id, p_data->oper.WriteOp.char_handle, value, false);
      break;
    }
    case MCP_MEDIA_STATE_READ: {
      p_data->rsp_value.attr_value.len = sizeof(mediaPlayerInfo.media_state);
      *(uint8_t *)p_data->rsp_value.attr_value.value =  (uint8_t)mediaPlayerInfo.media_state;
      p_data->event = MCP_READ_RSP;
      device = p_data->remoteDevice;
      p_data->rsp_value.attr_value.len = sizeof(mediaPlayerInfo.media_state);
      device->DeviceStateHandlerPointer[device->state](p_data->event, p_data, device->state);
      break;
    }
    case MCP_MEDIA_PLAYER_NAME_READ: {
      uint16_t len = mediaPlayerInfo.player_name_len;
      if (device->mtu != -1 && len >= device->mtu - 3) //to check player len should not greater than mtu
        len = device->mtu - 3;
      p_data->rsp_value.attr_value.len = len;
      memcpy(p_data->rsp_value.attr_value.value, mediaPlayerInfo.player_name,
          p_data->rsp_value.attr_value.len);
      p_data->event = MCP_READ_RSP;
      device = p_data->remoteDevice;
      device->DeviceStateHandlerPointer[device->state](p_data->event, p_data, device->state);
      break;
    }
    case MCP_MEDIA_CONTROL_POINT_OPCODE_SUPPORTED_READ: {
      p_data->rsp_value.attr_value.len = sizeof(mediaPlayerInfo.media_supported_feature);
      *(uint32_t*)p_data->rsp_value.attr_value.value =
          MCP_DEFAULT_MEDIA_CTRL_SUPP_FEAT;
      p_data->event = MCP_READ_RSP;
      device = p_data->remoteDevice;
      device->DeviceStateHandlerPointer[device->state](p_data->event, p_data, device->state);
      break;
    }
    case MCP_TRACK_TITLE_READ: {
      uint16_t len = mediaPlayerInfo.track_title_len;
      if (device->mtu != -1 && len >= device->mtu - 3) //to check title len should not greater than mtu
        len = device->mtu - 3;
      p_data->rsp_value.attr_value.len = len;
      memcpy(p_data->rsp_value.attr_value.value, mediaPlayerInfo.title,
          p_data->rsp_value.attr_value.len);
      p_data->event = MCP_READ_RSP;
      device = p_data->remoteDevice;
      device->DeviceStateHandlerPointer[device->state](p_data->event, p_data, device->state);
      break;
    }
    case MCP_TRACK_POSITION_READ: {
      p_data->rsp_value.attr_value.len = sizeof(mediaPlayerInfo.position);
      *(int *)p_data->rsp_value.attr_value.value = (int)mediaPlayerInfo.position;
      p_data->event = MCP_READ_RSP;
      device = p_data->remoteDevice;
      device->DeviceStateHandlerPointer[device->state](p_data->event, p_data, device->state);
      break;
    }
    case MCP_TRACK_DURATION_READ: {
      p_data->rsp_value.attr_value.len = sizeof(mediaPlayerInfo.duration);
      *(int *)p_data->rsp_value.attr_value.value = (int)mediaPlayerInfo.duration;
      p_data->event = MCP_READ_RSP;
      device = p_data->remoteDevice;
      device->DeviceStateHandlerPointer[device->state](p_data->event, p_data, device->state);
      break;
    }
    case MCP_PLAYING_ORDER_SUPPORTED_READ: {
      p_data->rsp_value.attr_value.len = sizeof(mediaPlayerInfo.playing_order_supported);
      *(uint16_t *)p_data->rsp_value.attr_value.value =
          (uint16_t)mediaPlayerInfo.playing_order_supported;
      p_data->event = MCP_READ_RSP;
      device = p_data->remoteDevice;
      device->DeviceStateHandlerPointer[device->state](p_data->event, p_data, device->state);
      break;
    }
    case MCP_PLAYING_ORDER_READ: {
      p_data->rsp_value.attr_value.len = sizeof(mediaPlayerInfo.playing_order_value);
      *(uint16_t *)p_data->rsp_value.attr_value.value = (uint16_t)mediaPlayerInfo.playing_order_value;
      p_data->event = MCP_READ_RSP;
      device = p_data->remoteDevice;
      device->DeviceStateHandlerPointer[device->state](p_data->event, p_data, device->state);
      break;
    }
    case MCP_CCID_READ: {
      p_data->rsp_value.attr_value.len = sizeof(mediaPlayerInfo.ccid);
      *(uint32_t *)p_data->rsp_value.attr_value.value = (uint8_t)mediaPlayerInfo.ccid;
      p_data->event = MCP_READ_RSP;
      device = p_data->remoteDevice;
      device->DeviceStateHandlerPointer[device->state](p_data->event, p_data, device->state);
      break;
    }
    case MCP_SEEKING_SPEED_READ: {
      p_data->rsp_value.attr_value.len = sizeof(mediaPlayerInfo.seeking_speed);
      *(uint8_t *)p_data->rsp_value.attr_value.value = (uint8_t)mediaPlayerInfo.seeking_speed;
      p_data->event = MCP_READ_RSP;
      device = p_data->remoteDevice;
      device->DeviceStateHandlerPointer[device->state](p_data->event, p_data, device->state);
      break;
    }
    case MCP_MEDIA_STATE_READ_DESCRIPTOR:{
      *(uint16_t *)p_data->rsp_value.attr_value.value = (uint16_t)device->media_state_notify;
      p_data->rsp_value.attr_value.len = sizeof(device->media_state_notify);
      p_data->event = MCP_DESCRIPTOR_READ_RSP;
      device = p_data->remoteDevice;
      device->DeviceStateHandlerPointer[device->state](p_data->event, p_data, device->state);
      break;
    }
    case MCP_MEDIA_CONTROL_POINT_READ_DESCRIPTOR: {
      *(uint16_t *)p_data->rsp_value.attr_value.value = (uint16_t)device->media_control_point_notify;
      p_data->rsp_value.attr_value.len = sizeof(device->media_control_point_notify);
      p_data->event = MCP_DESCRIPTOR_READ_RSP;
      device = p_data->remoteDevice;
      device->DeviceStateHandlerPointer[device->state](p_data->event, p_data, device->state);
      break;
    }
    case MCP_MEDIA_CONTROL_POINT_OPCODE_SUPPORTED_DESCRIPTOR_READ: {
      *(uint16_t *)p_data->rsp_value.attr_value.value =
         (uint16_t)device->media_control_point_opcode_supported_notify;
      p_data->rsp_value.attr_value.len = sizeof(device->media_control_point_opcode_supported_notify);
      p_data->event = MCP_DESCRIPTOR_READ_RSP;
      device = p_data->remoteDevice;
      device->DeviceStateHandlerPointer[device->state](p_data->event, p_data, device->state);
      break;
    }
    case MCP_MEDIA_PLAYER_NAME_DESCRIPTOR_READ: {
      *(uint16_t *)p_data->rsp_value.attr_value.value = (uint16_t)device->media_player_name_notify;
      p_data->rsp_value.attr_value.len = sizeof(device->media_player_name_notify);
      p_data->event = MCP_DESCRIPTOR_READ_RSP;
      device = p_data->remoteDevice;
      device->DeviceStateHandlerPointer[device->state](p_data->event, p_data, device->state);
      break;
    }
    case MCP_TRACK_CHANGED_DESCRIPTOR_READ: {
      *(uint16_t *)p_data->rsp_value.attr_value.value = (uint16_t)device->track_changed_notify;
      p_data->rsp_value.attr_value.len = sizeof(device->track_changed_notify);
      p_data->event = MCP_DESCRIPTOR_READ_RSP;
      device = p_data->remoteDevice;
      device->DeviceStateHandlerPointer[device->state](p_data->event, p_data, device->state);
      break;
    }
    case MCP_TRACK_TITLE_DESCRIPTOR_READ: {
      *(uint16_t *)p_data->rsp_value.attr_value.value = (uint16_t)device->track_title_notify;
      p_data->rsp_value.attr_value.len = sizeof(device->track_title_notify);
      p_data->event = MCP_DESCRIPTOR_READ_RSP;
      device = p_data->remoteDevice;
      device->DeviceStateHandlerPointer[device->state](p_data->event, p_data, device->state);
      break;
    }
    case MCP_TRACK_POSITION_DESCRIPTOR_READ: {
      *(uint16_t *)p_data->rsp_value.attr_value.value = (uint16_t)device->track_position_notify;
      p_data->rsp_value.attr_value.len = sizeof(device->track_position_notify);
      p_data->event = MCP_DESCRIPTOR_READ_RSP;
      device = p_data->remoteDevice;
      device->DeviceStateHandlerPointer[device->state](p_data->event, p_data, device->state);
      break;
    }
    case MCP_TRACK_DURATION_DESCRIPTOR_READ: {
      *(uint16_t *)p_data->rsp_value.attr_value.value = (uint16_t)device->track_duration_notify;;
      p_data->rsp_value.attr_value.len = sizeof(device->track_duration_notify);
      p_data->event = MCP_DESCRIPTOR_READ_RSP;
      device = p_data->remoteDevice;
      device->DeviceStateHandlerPointer[device->state](p_data->event, p_data, device->state);
      break;
    }
    case MCP_PLAYING_ORDER_DESCRIPTOR_READ: {
      *(uint16_t *)p_data->rsp_value.attr_value.value = (uint16_t)device->playing_order_notify;
      p_data->rsp_value.attr_value.len = sizeof(device->playing_order_notify);
      p_data->event = MCP_DESCRIPTOR_READ_RSP;
      device = p_data->remoteDevice;
      device->DeviceStateHandlerPointer[device->state](p_data->event, p_data, device->state);
      break;
    }

    case MCP_MEDIA_STATE_DESCRIPTOR_WRITE: {
      p_data->oper.WriteDescOp.data = (uint8_t *)&mediaPlayerInfo.media_state;
      p_data->oper.WriteDescOp.len = sizeof (mediaPlayerInfo.media_state);
      p_data->oper.WriteDescOp.char_handle = mcsServerServiceInfo.media_state_handle;
      p_data->event = MCP_DESCRIPTOR_WRITE_RSP;
      device = p_data->remoteDevice;
      device->DeviceStateHandlerPointer[device->state](p_data->event, p_data, device->state);
      break;
    }
    case MCP_MEDIA_PLAYER_NAME_DESCRIPTOR_WRITE: {
      p_data->oper.WriteDescOp.data = (uint8_t *)&mediaPlayerInfo.player_name;
      p_data->oper.WriteDescOp.len = mediaPlayerInfo.player_name_len;
      p_data->oper.WriteDescOp.char_handle = mcsServerServiceInfo.media_player_name_handle;
      p_data->event = MCP_DESCRIPTOR_WRITE_RSP;
      device = p_data->remoteDevice;
      device->DeviceStateHandlerPointer[device->state](p_data->event, p_data, device->state);
      break;
    }
    case MCP_MEDIA_CONTROL_POINT_DESCRIPTOR_WRITE: {
      p_data->oper.WriteDescOp.data = (uint8_t *)&mediaPlayerInfo.media_ctrl_point;
      p_data->oper.WriteDescOp.len = sizeof (mediaPlayerInfo.media_ctrl_point);
      p_data->oper.WriteDescOp.char_handle = mcsServerServiceInfo.media_control_point_handle;
      p_data->event = MCP_DESCRIPTOR_WRITE_RSP;
      device = p_data->remoteDevice;
      device->DeviceStateHandlerPointer[device->state](p_data->event, p_data, device->state);
      break;
    }
    case MCP_MEDIA_CONTROL_POINT_SUPPORTED_DESCRIPTOR_WRITE: {
      p_data->oper.WriteDescOp.data = (uint8_t *)&mediaPlayerInfo.media_supported_feature;
      p_data->oper.WriteDescOp.len = sizeof (mediaPlayerInfo.media_supported_feature);
      p_data->oper.WriteDescOp.char_handle = mcsServerServiceInfo.media_control_point_opcode_supported_handle;
      p_data->event = MCP_DESCRIPTOR_WRITE_RSP;
      device = p_data->remoteDevice;
      device->DeviceStateHandlerPointer[device->state](p_data->event, p_data, device->state);
      break;
    }
    case MCP_TRACK_CHANGED_DESCRIPTOR_WRITE: {
      p_data->oper.WriteDescOp.data = (uint8_t *)&mediaPlayerInfo.track_changed;
      p_data->oper.WriteDescOp.len = sizeof (mediaPlayerInfo.track_changed);
      p_data->oper.WriteDescOp.char_handle = mcsServerServiceInfo.track_changed_handle;
      p_data->event = MCP_DESCRIPTOR_WRITE_RSP;
      device = p_data->remoteDevice;
      device->DeviceStateHandlerPointer[device->state](p_data->event, p_data, device->state);
      break;
    }
    case MCP_TRACK_TITLE_DESCRIPTOR_WRITE: {
      p_data->oper.WriteDescOp.data = (uint8_t *)&mediaPlayerInfo.title;
      p_data->oper.WriteDescOp.len = mediaPlayerInfo.track_title_len;
      p_data->oper.WriteDescOp.char_handle = mcsServerServiceInfo.track_title_handle;
      p_data->event = MCP_DESCRIPTOR_WRITE_RSP;
      device = p_data->remoteDevice;
      device->DeviceStateHandlerPointer[device->state](p_data->event, p_data, device->state);
      break;
    }

    case MCP_TRACK_POSITION_DESCRIPTOR_WRITE: {
      p_data->oper.WriteDescOp.data = (uint8_t *)&mediaPlayerInfo.position;
      p_data->oper.WriteDescOp.len = sizeof(mediaPlayerInfo.position);
      p_data->oper.WriteDescOp.char_handle = mcsServerServiceInfo.track_position_handle;
      p_data->event = MCP_DESCRIPTOR_WRITE_RSP;
      device = p_data->remoteDevice;
      device->DeviceStateHandlerPointer[device->state](p_data->event, p_data, device->state);
      break;
    }

    case MCP_TRACK_DURATION_DESCRIPTOR_WRITE: {
      p_data->oper.WriteDescOp.data = (uint8_t *)&mediaPlayerInfo.duration;
      p_data->oper.WriteDescOp.len = sizeof(mediaPlayerInfo.duration);
      p_data->oper.WriteDescOp.char_handle = mcsServerServiceInfo.track_duration_handle;
      p_data->event = MCP_DESCRIPTOR_WRITE_RSP;
      device = p_data->remoteDevice;
      device->DeviceStateHandlerPointer[device->state](p_data->event, p_data, device->state);
      break;
    }

    case MCP_PLAYING_ORDER_DESCRIPTOR_WRITE : {
      p_data->oper.WriteDescOp.data = (uint8_t *)&mediaPlayerInfo.playing_order_value;
      p_data->oper.WriteDescOp.len = sizeof(mediaPlayerInfo.playing_order_value);
      p_data->event = MCP_DESCRIPTOR_WRITE_RSP;
      device = p_data->remoteDevice;
      device->DeviceStateHandlerPointer[device->state](p_data->event, p_data, device->state);
      break;
    }

    case MCP_CONGESTION_UPDATE: {
      McpCongestionUpdate(p_data);
      break;
    }

    case MCP_CONNECTION_UPDATE:
    case MCP_ACTIVE_DEVICE_UPDATE:
    case MCP_PHY_UPDATE:
    case MCP_CONNECTION:
    case MCP_CONNECTION_CLOSE_EVENT:
    case MCP_DISCONNECTION:
    case MCP_BOND_STATE_CHANGE_EVENT:
      device = p_data->remoteDevice;
      device->DeviceStateHandlerPointer[device->state](p_data->event, p_data, device->state);
      break;

    default:
      LOG(INFO) << __func__ << "  event is not in list";
      break;
    }

  return BT_STATUS_SUCCESS;
}



bool MediaStatePlayingHandler(uint32_t event, void* param, uint8_t state) {
  LOG(INFO) << __func__ << " handle event " << get_mcp_event_name(event)
            << " in state " << get_mcp_media_state_name(state);
  mcp_resp_t *p_data = (mcp_resp_t *)param;
  RemoteDevice *device = p_data->remoteDevice;
  switch(event) {
    case MCP_NOTIFY_ALL: {
      LOG(INFO) << __func__ << " Notify all handle "<< p_data->handle;
      std::vector<RemoteDevice>notifyDevices = instance->remoteDevices.FindNotifyDevices(p_data->handle);
      std::vector<RemoteDevice>::iterator it;
      if (notifyDevices.size() <= 0) {
        LOG(INFO) << __func__ << " No device register for notification";
      }
      for (it = notifyDevices.begin(); it != notifyDevices.end(); it++){
        LOG(INFO) << __func__ << " Notify all handle device id " << it->conn_id;
        p_data->remoteDevice = instance->remoteDevices.FindByConnId(it->conn_id);
        it->DeviceStateHandlerPointer[it->state](p_data->event, p_data, it->state);
      }
      break;
    }
    case MCP_PLAYING_ORDER_WRITE: {
      uint8_t data = (uint8_t)(*p_data->oper.WriteOp.data);
      if (mediaPlayerInfo.playing_order_supported & data) {
        instance->PlayingOrderChangeReq(data & mediaPlayerInfo.playing_order_value);
      } else {
        LOG(INFO) << __func__ << " ignore playing_order_handle write feature is not supported";
        break;
      }
      p_data->rsp_value.attr_value.len = 0;
      device->DeviceStateHandlerPointer[device->state](p_data->event, p_data, device->state);
      break;
    }
    case MCP_MEDIA_CONTROL_POINT_WRITE: {
      uint8_t data = (uint8_t)(*p_data->oper.WriteOp.data);
      uint8_t opcode_support = is_opcode_supported(data);
      LOG(INFO) << __func__ << " data " << data << " Tx ID: " << p_data->oper.WriteOp.trans_id;
      if (!opcode_support) {
        uint8_t status = MCP_OPCODE_NOT_SUPPORTED;
        std::vector<uint8_t> value;
        value.push_back(data);
        value.push_back(status);
        LOG(INFO) << __func__ << "hndl " << p_data->oper.WriteOp.char_handle;
        LOG(INFO) << __func__ << "opcode not supported " << data;
        GattsOpsQueue::SendNotification(device->conn_id, p_data->oper.WriteOp.char_handle, value, false);
      }
      if (data != MCP_MEDIA_CONTROL_OPCODE_PLAY) {
        instance->MediaControlPointChangeReq((uint32_t)data, device->peer_bda);
        LOG(INFO) << __func__ << "media_control_point_handle write ";
      } else {
        LOG(INFO) << __func__ << " ignore media_control_point_handle write feature is not supported/already playing";
      }
      p_data->rsp_value.attr_value.len = 0;
      device = p_data->remoteDevice;
      LOG(INFO) << __func__ << " p_data->event "<< p_data->event;
      device->DeviceStateHandlerPointer[device->state](p_data->event, p_data, device->state);
      break;
    }
    case MCP_TRACK_POSITION_WRITE: {
      uint32_t track_duration = mediaPlayerInfo.duration;
      uint32_t track_position = mediaPlayerInfo.position;
      uint32_t data;
      uint8_t *w_data = p_data->oper.WriteOp.data;
      STREAM_TO_UINT32(data, w_data);
      uint32_t position = track_duration;
      if ((track_position == (uint32_t)data) || (data < 0) ||
          (track_duration == 0xFFFF) || (track_duration > 0 && track_duration < data)) {
        LOG(INFO) << __func__ << " ignore track_position_handle write";
      } else {
        position = data;
        instance->TrackPositionChangeReq(data);
        LOG(INFO) << __func__ << " track_position_handle write";
      }
      std::vector<uint8_t> value;
      value.push_back(position & 0xff);
      value.push_back((position >> 8)  & 0xff);
      value.push_back((position >> 16) & 0xff);
      value.push_back((position >> 24) & 0xff);
      GattsOpsQueue::SendNotification(device->conn_id, p_data->oper.WriteOp.char_handle, value, false);
      device = p_data->remoteDevice;
      device->DeviceStateHandlerPointer[device->state](p_data->event, p_data, device->state);
      break;
    }
    case MCP_MEDIA_STATE_READ: {
      p_data->rsp_value.attr_value.len = sizeof(mediaPlayerInfo.media_state);
      *(uint8_t *)p_data->rsp_value.attr_value.value =  *(uint8_t *)&mediaPlayerInfo.media_state;
      p_data->event = MCP_READ_RSP;
      device = p_data->remoteDevice;
      device->DeviceStateHandlerPointer[device->state](p_data->event, p_data, device->state);
      break;
    }
    case MCP_MEDIA_PLAYER_NAME_READ: {
      uint16_t len = mediaPlayerInfo.player_name_len;
      if (device->mtu != -1 && len >= device->mtu - 3) //to check player len should not greater than mtu
        len = device->mtu - 3;
      p_data->rsp_value.attr_value.len = len;
      memcpy(p_data->rsp_value.attr_value.value, mediaPlayerInfo.player_name,
          p_data->rsp_value.attr_value.len);
      p_data->event = MCP_READ_RSP;
      device = p_data->remoteDevice;
      device->DeviceStateHandlerPointer[device->state](p_data->event, p_data, device->state);
      break;
    }
    case MCP_MEDIA_CONTROL_POINT_OPCODE_SUPPORTED_READ: {
      p_data->rsp_value.attr_value.len = sizeof(mediaPlayerInfo.media_supported_feature);
      *(uint32_t*)p_data->rsp_value.attr_value.value =
      *(uint32_t *)&mediaPlayerInfo.media_supported_feature;
      p_data->event = MCP_READ_RSP;
      device = p_data->remoteDevice;
      device->DeviceStateHandlerPointer[device->state](p_data->event, p_data, device->state);
      break;
    }
    case MCP_TRACK_TITLE_READ: {
      uint16_t len = mediaPlayerInfo.track_title_len;
      if (device->mtu != -1 && len >= device->mtu - 3) //to check title len should not greater than mtu
        len = device->mtu - 3;
      p_data->rsp_value.attr_value.len = len;
      memcpy(p_data->rsp_value.attr_value.value, mediaPlayerInfo.title,
          p_data->rsp_value.attr_value.len);
      p_data->event = MCP_READ_RSP;
      device = p_data->remoteDevice;
      device->DeviceStateHandlerPointer[device->state](p_data->event, p_data, device->state);
      break;
    }
    case MCP_TRACK_POSITION_READ: {
      p_data->rsp_value.attr_value.len = sizeof(mediaPlayerInfo.position);
      *(int *)p_data->rsp_value.attr_value.value = *(int *)&mediaPlayerInfo.position;
      p_data->event = MCP_READ_RSP;
      device = p_data->remoteDevice;
      device->DeviceStateHandlerPointer[device->state](p_data->event, p_data, device->state);
      break;
    }
    case MCP_TRACK_DURATION_READ: {
      p_data->rsp_value.attr_value.len = sizeof(mediaPlayerInfo.duration);
      *(int *)p_data->rsp_value.attr_value.value = *(int *)&mediaPlayerInfo.duration;
      p_data->event = MCP_READ_RSP;
      device = p_data->remoteDevice;
      device->DeviceStateHandlerPointer[device->state](p_data->event, p_data, device->state);
      break;
    }

    case MCP_PLAYING_ORDER_SUPPORTED_READ: {
      p_data->rsp_value.attr_value.len = sizeof(mediaPlayerInfo.playing_order_supported);
      *(uint16_t *)p_data->rsp_value.attr_value.value =
          *(uint16_t *)&mediaPlayerInfo.playing_order_supported;
      p_data->event = MCP_READ_RSP;
      device = p_data->remoteDevice;
      device->DeviceStateHandlerPointer[device->state](p_data->event, p_data, device->state);
      break;
    }

    case MCP_PLAYING_ORDER_READ: {
      p_data->rsp_value.attr_value.len = sizeof(mediaPlayerInfo.playing_order_value);
      *(uint16_t *)p_data->rsp_value.attr_value.value = *(uint16_t *)&mediaPlayerInfo.playing_order_value;
      p_data->event = MCP_READ_RSP;
      device = p_data->remoteDevice;
      device->DeviceStateHandlerPointer[device->state](p_data->event, p_data, device->state);
      break;
    }

    case MCP_CCID_READ: {
      p_data->rsp_value.attr_value.len = sizeof(mediaPlayerInfo.ccid);
      *(uint32_t *)p_data->rsp_value.attr_value.value = *(uint8_t *)&mediaPlayerInfo.ccid;
      p_data->event = MCP_READ_RSP;
      device = p_data->remoteDevice;
      device->DeviceStateHandlerPointer[device->state](p_data->event, p_data, device->state);
      break;
    }

    case MCP_SEEKING_SPEED_READ: {
      p_data->rsp_value.attr_value.len = sizeof(mediaPlayerInfo.seeking_speed);
      *(uint8_t *)p_data->rsp_value.attr_value.value = (uint8_t)mediaPlayerInfo.seeking_speed;
      p_data->event = MCP_READ_RSP;
      device = p_data->remoteDevice;
      device->DeviceStateHandlerPointer[device->state](p_data->event, p_data, device->state);
      break;
    }

    case MCP_MEDIA_STATE_READ_DESCRIPTOR:{
      *(uint16_t *)p_data->rsp_value.attr_value.value = *(uint16_t *)&device->media_state_notify;
      p_data->rsp_value.attr_value.len = sizeof(device->media_state_notify);
      p_data->event = MCP_DESCRIPTOR_READ_RSP;
      device = p_data->remoteDevice;
      device->DeviceStateHandlerPointer[device->state](p_data->event, p_data, device->state);
      break;
    }

    case MCP_MEDIA_CONTROL_POINT_READ_DESCRIPTOR: {
      *(uint16_t *)p_data->rsp_value.attr_value.value = *(uint16_t *)&device->media_control_point_notify;
      p_data->rsp_value.attr_value.len = sizeof(device->media_control_point_notify);
      p_data->event = MCP_DESCRIPTOR_READ_RSP;
      device = p_data->remoteDevice;
      device->DeviceStateHandlerPointer[device->state](p_data->event, p_data, device->state);
      break;
    }

    case MCP_MEDIA_CONTROL_POINT_OPCODE_SUPPORTED_DESCRIPTOR_READ: {
      *(uint16_t *)p_data->rsp_value.attr_value.value =
         *(uint16_t *)&device->media_control_point_opcode_supported_notify;
      p_data->rsp_value.attr_value.len = sizeof(device->media_control_point_opcode_supported_notify);
      p_data->event = MCP_DESCRIPTOR_READ_RSP;
      device = p_data->remoteDevice;
      device->DeviceStateHandlerPointer[device->state](p_data->event, p_data, device->state);
      break;
    }

    case MCP_MEDIA_PLAYER_NAME_DESCRIPTOR_READ: {
      *(uint16_t *)p_data->rsp_value.attr_value.value = *(uint16_t *)&device->media_player_name_notify;
      p_data->rsp_value.attr_value.len = sizeof(device->media_player_name_notify);
      p_data->event = MCP_DESCRIPTOR_READ_RSP;
      device = p_data->remoteDevice;
      device->DeviceStateHandlerPointer[device->state](p_data->event, p_data, device->state);
      break;
    }

    case MCP_TRACK_CHANGED_DESCRIPTOR_READ: {
      *(uint16_t *)p_data->rsp_value.attr_value.value = *(uint16_t *)&device->track_changed_notify;
      p_data->rsp_value.attr_value.len = sizeof(device->track_changed_notify);
      p_data->event = MCP_DESCRIPTOR_READ_RSP;
      device = p_data->remoteDevice;
      device->DeviceStateHandlerPointer[device->state](p_data->event, p_data, device->state);
      break;
    }

    case MCP_TRACK_TITLE_DESCRIPTOR_READ: {
      *(uint16_t *)p_data->rsp_value.attr_value.value = *(uint16_t *)&device->track_title_notify;
      p_data->rsp_value.attr_value.len = sizeof(device->track_title_notify);
      p_data->event = MCP_DESCRIPTOR_READ_RSP;
      device = p_data->remoteDevice;
      device->DeviceStateHandlerPointer[device->state](p_data->event, p_data, device->state);
      break;
    }

    case MCP_TRACK_POSITION_DESCRIPTOR_READ: {
      *(uint16_t *)p_data->rsp_value.attr_value.value = *(uint16_t *)&device->track_position_notify;
      p_data->rsp_value.attr_value.len = sizeof(device->track_position_notify);
      p_data->event = MCP_DESCRIPTOR_READ_RSP;
      device = p_data->remoteDevice;
      device->DeviceStateHandlerPointer[device->state](p_data->event, p_data, device->state);
      break;
    }

    case MCP_TRACK_DURATION_DESCRIPTOR_READ: {
      *(uint16_t *)p_data->rsp_value.attr_value.value = *(uint16_t *)&device->track_duration_notify;;
      p_data->rsp_value.attr_value.len = sizeof(device->track_duration_notify);
      p_data->event = MCP_DESCRIPTOR_READ_RSP;
      device = p_data->remoteDevice;
      device->DeviceStateHandlerPointer[device->state](p_data->event, p_data, device->state);
      break;
    }

    case MCP_PLAYING_ORDER_DESCRIPTOR_READ: {
      *(uint16_t *)p_data->rsp_value.attr_value.value = *(uint16_t *)&device->playing_order_notify;
      p_data->rsp_value.attr_value.len = sizeof(device->playing_order_notify);
      p_data->event = MCP_DESCRIPTOR_READ_RSP;
      LOG(INFO) << __func__ << " calling device state" << device->state;
      device = p_data->remoteDevice;
      device->DeviceStateHandlerPointer[device->state](p_data->event, p_data, device->state);
      break;
    }

    case MCP_MEDIA_STATE_DESCRIPTOR_WRITE: {
      p_data->oper.WriteDescOp.data = (uint8_t *)&mediaPlayerInfo.media_state;
      p_data->oper.WriteDescOp.len = sizeof (mediaPlayerInfo.media_state);
      p_data->oper.WriteDescOp.char_handle = mcsServerServiceInfo.media_state_handle;
      p_data->event = MCP_DESCRIPTOR_WRITE_RSP;
      device = p_data->remoteDevice;
      device->DeviceStateHandlerPointer[device->state](p_data->event, p_data, device->state);
      break;
    }
    case MCP_MEDIA_PLAYER_NAME_DESCRIPTOR_WRITE: {
      p_data->oper.WriteDescOp.data = (uint8_t *)&mediaPlayerInfo.player_name;
      p_data->oper.WriteDescOp.len = mediaPlayerInfo.player_name_len;
      p_data->oper.WriteDescOp.char_handle = mcsServerServiceInfo.media_player_name_handle;
      p_data->event = MCP_DESCRIPTOR_WRITE_RSP;
      device = p_data->remoteDevice;
      device->DeviceStateHandlerPointer[device->state](p_data->event, p_data, device->state);
      break;
    }
    case MCP_MEDIA_CONTROL_POINT_DESCRIPTOR_WRITE: {
      p_data->oper.WriteDescOp.data = (uint8_t *)&mediaPlayerInfo.media_ctrl_point;
      p_data->oper.WriteDescOp.len = sizeof (mediaPlayerInfo.media_ctrl_point);
      p_data->oper.WriteDescOp.char_handle = mcsServerServiceInfo.media_control_point_handle;
      p_data->event = MCP_DESCRIPTOR_WRITE_RSP;
      device = p_data->remoteDevice;
      device->DeviceStateHandlerPointer[device->state](p_data->event, p_data, device->state);
      break;
    }
    case MCP_MEDIA_CONTROL_POINT_SUPPORTED_DESCRIPTOR_WRITE: {
      p_data->oper.WriteDescOp.data = (uint8_t *)&mediaPlayerInfo.media_supported_feature;
      p_data->oper.WriteDescOp.len = sizeof (mediaPlayerInfo.media_supported_feature);
      p_data->oper.WriteDescOp.char_handle = mcsServerServiceInfo.media_control_point_opcode_supported_handle;
      p_data->event = MCP_DESCRIPTOR_WRITE_RSP;
      device = p_data->remoteDevice;
      device->DeviceStateHandlerPointer[device->state](p_data->event, p_data, device->state);
      break;
    }
    case MCP_TRACK_CHANGED_DESCRIPTOR_WRITE: {
      p_data->oper.WriteDescOp.data = (uint8_t *)&mediaPlayerInfo.track_changed;
      p_data->oper.WriteDescOp.len = sizeof (mediaPlayerInfo.track_changed);
      p_data->oper.WriteDescOp.char_handle = mcsServerServiceInfo.track_changed_handle;
      p_data->event = MCP_DESCRIPTOR_WRITE_RSP;
      device = p_data->remoteDevice;
      device->DeviceStateHandlerPointer[device->state](p_data->event, p_data, device->state);
      break;
    }
    case MCP_TRACK_TITLE_DESCRIPTOR_WRITE: {
      p_data->oper.WriteDescOp.data = (uint8_t *)&mediaPlayerInfo.title;
      p_data->oper.WriteDescOp.len = mediaPlayerInfo.track_title_len;
      p_data->oper.WriteDescOp.char_handle = mcsServerServiceInfo.track_title_handle;
      p_data->event = MCP_DESCRIPTOR_WRITE_RSP;
      device = p_data->remoteDevice;
      device->DeviceStateHandlerPointer[device->state](p_data->event, p_data, device->state);
      break;
    }

    case MCP_TRACK_POSITION_DESCRIPTOR_WRITE: {
      p_data->oper.WriteDescOp.data = (uint8_t *)&mediaPlayerInfo.position;
      p_data->oper.WriteDescOp.len = sizeof(mediaPlayerInfo.position);
      p_data->oper.WriteDescOp.char_handle = mcsServerServiceInfo.track_position_handle;
      p_data->event = MCP_DESCRIPTOR_WRITE_RSP;
      device = p_data->remoteDevice;
      device->DeviceStateHandlerPointer[device->state](p_data->event, p_data, device->state);
      break;
    }

    case MCP_TRACK_DURATION_DESCRIPTOR_WRITE: {
      p_data->oper.WriteDescOp.data = (uint8_t *)&mediaPlayerInfo.duration;
      p_data->oper.WriteDescOp.len = sizeof(mediaPlayerInfo.duration);
      p_data->oper.WriteDescOp.char_handle = mcsServerServiceInfo.track_duration_handle;
      p_data->event = MCP_DESCRIPTOR_WRITE_RSP;
      device = p_data->remoteDevice;
      device->DeviceStateHandlerPointer[device->state](p_data->event, p_data, device->state);
      break;
    }

    case MCP_PLAYING_ORDER_DESCRIPTOR_WRITE : {
      p_data->oper.WriteDescOp.data = (uint8_t *)&mediaPlayerInfo.playing_order_value;
      p_data->oper.WriteDescOp.len = sizeof(mediaPlayerInfo.playing_order_value);
      p_data->event = MCP_DESCRIPTOR_WRITE_RSP;
      device = p_data->remoteDevice;
      device->DeviceStateHandlerPointer[device->state](p_data->event, p_data, device->state);
      break;
    }

    case MCP_CONGESTION_UPDATE: {
      McpCongestionUpdate(p_data);
      break;
    }

    case MCP_CONNECTION_UPDATE:
    case MCP_ACTIVE_DEVICE_UPDATE:
    case MCP_PHY_UPDATE:
    case MCP_CONNECTION:
    case MCP_DISCONNECTION:
    case MCP_CONNECTION_CLOSE_EVENT:
    case MCP_BOND_STATE_CHANGE_EVENT:
      device = p_data->remoteDevice;
      device->DeviceStateHandlerPointer[device->state](p_data->event, p_data, device->state);
      break;

    default:
      break;
  }

  return BT_STATUS_SUCCESS;
}

bool MediaStateSeekingHandler(uint32_t event, void* param, uint8_t state) {
  LOG(INFO) << __func__ << " handle event " << get_mcp_event_name(event)
            << " in state " << get_mcp_media_state_name(state);
  mcp_resp_t *p_data = (mcp_resp_t *)param;
  RemoteDevice *device = p_data->remoteDevice;
  switch(event) {
    case MCP_NOTIFY_ALL: {
      LOG(INFO) << __func__ << " Notify all handle "<< p_data->handle;
      std::vector<RemoteDevice>notifyDevices =
          instance->remoteDevices.FindNotifyDevices(p_data->handle);
      if (notifyDevices.size() <= 0) {
        LOG(INFO) << __func__ << " No device register for notification";
        break;
      }
      std::vector<RemoteDevice>::iterator it;
      for (it = notifyDevices.begin(); it != notifyDevices.end(); it++){
        p_data->remoteDevice = instance->remoteDevices.FindByConnId(it->conn_id);
        it->DeviceStateHandlerPointer[it->state](p_data->event, p_data, it->state);
        LOG(INFO) << __func__ << " Notify all handle device id " << it->conn_id;
      }

      break;
    }

    case MCP_PLAYING_ORDER_WRITE: {
      uint8_t data = (uint8_t)(*p_data->oper.WriteOp.data);
      if (mediaPlayerInfo.playing_order_supported & data) {
        instance->PlayingOrderChangeReq(data & mediaPlayerInfo.playing_order_value);
      } else {
        LOG(INFO) << __func__ << " ignore playing_order_handle write feature is not supported";
        break;
      }
      p_data->rsp_value.attr_value.len = 0;
      device = p_data->remoteDevice;
      device->DeviceStateHandlerPointer[device->state](p_data->event, p_data, device->state);
      break;
    }
    case MCP_MEDIA_CONTROL_POINT_WRITE: {
      uint8_t data = (uint8_t)(*p_data->oper.WriteOp.data);
      uint8_t opcode_support = is_opcode_supported(data);
      if (!opcode_support) {
        uint8_t status = MCP_OPCODE_NOT_SUPPORTED;
        std::vector<uint8_t> value;
        value.push_back(data);
        value.push_back(status);
        LOG(INFO) << __func__ << "hndl " << p_data->oper.WriteOp.char_handle;
        LOG(INFO) << __func__ << "opcode not supported " << data;
        GattsOpsQueue::SendNotification(device->conn_id, p_data->oper.WriteOp.char_handle, value, false);
      }

      if (((data == MCP_MEDIA_CONTROL_OPCODE_PAUSE) ||
          (data == MCP_MEDIA_CONTROL_OPCODE_PLAY)) &&
          (instance->remoteDevices.FindActiveDevice(p_data->remoteDevice)) == false) {
        LOG(INFO) << __func__ << " media control point write received from inactive device";
        break;
      }
      if ((data != MCP_MEDIA_CONTROL_OPCODE_FAST_FORWARD) && (data != MCP_MEDIA_CONTROL_OPCODE_FAST_REWIND)
          && (data != MCP_MEDIA_CONTROL_OPCODE_MOVE_RELATIVE)) {
        instance->MediaControlPointChangeReq(data, device->peer_bda);
        LOG(INFO) << __func__ << "media_control_point_handle write ";
      }
      p_data->rsp_value.attr_value.len = 0;
      device = p_data->remoteDevice;
      device->DeviceStateHandlerPointer[device->state](p_data->event, p_data, device->state);
      break;
    }
    case MCP_TRACK_POSITION_WRITE: {
      uint32_t track_duration = mediaPlayerInfo.duration;
      uint32_t track_position = mediaPlayerInfo.position;
      uint32_t data;
      uint8_t *w_data = p_data->oper.WriteOp.data;
      uint32_t position = track_duration;
      STREAM_TO_UINT32(data, w_data);
      if ((track_position == (uint32_t)data) || (data < 0) ||
          (track_duration == 0xFFFF) || (track_duration > 0 && track_duration < data)) {
        LOG(INFO) << __func__ << " ignore track_position_handle write";
      } else {
        position = data;
        instance->TrackPositionChangeReq(data);
        LOG(INFO) << __func__ << " track_position_handle write";
      }
      std::vector<uint8_t> value;
      value.push_back(position & 0xff);
      value.push_back((position >> 8)  & 0xff);
      value.push_back((position >> 16) & 0xff);
      value.push_back((position >> 24) & 0xff);
      GattsOpsQueue::SendNotification(device->conn_id, p_data->oper.WriteOp.char_handle, value, false);
      device = p_data->remoteDevice;
      device->DeviceStateHandlerPointer[device->state](p_data->event, p_data, device->state);
      break;
    }
    case MCP_MEDIA_STATE_READ: {
      p_data->rsp_value.attr_value.len = sizeof(mediaPlayerInfo.media_state);
      *(uint8_t *)p_data->rsp_value.attr_value.value =  *(uint8_t *)&mediaPlayerInfo.media_state;
      p_data->event = MCP_READ_RSP;
      device = p_data->remoteDevice;
      device->DeviceStateHandlerPointer[device->state](p_data->event, p_data, device->state);
      break;
    }
    case MCP_MEDIA_PLAYER_NAME_READ: {
      uint16_t len = mediaPlayerInfo.player_name_len;
      if (device->mtu != -1 && len >= device->mtu - 3) //to check player len should not greater than mtu
        len = device->mtu - 3;
      p_data->rsp_value.attr_value.len = len;
      memcpy(p_data->rsp_value.attr_value.value, mediaPlayerInfo.player_name,
          p_data->rsp_value.attr_value.len);
      p_data->event = MCP_READ_RSP;
      device = p_data->remoteDevice;
      device->DeviceStateHandlerPointer[device->state](p_data->event, p_data, device->state);
      break;
    }
    case MCP_MEDIA_CONTROL_POINT_OPCODE_SUPPORTED_READ: {
      p_data->rsp_value.attr_value.len = sizeof(mediaPlayerInfo.media_supported_feature);
      *(uint32_t*)p_data->rsp_value.attr_value.value =
      *(uint32_t *)&mediaPlayerInfo.media_supported_feature;
      p_data->event = MCP_READ_RSP;
      device = p_data->remoteDevice;
      device->DeviceStateHandlerPointer[device->state](p_data->event, p_data, device->state);
      break;
    }
    case MCP_TRACK_TITLE_READ: {
      uint16_t len = mediaPlayerInfo.track_title_len;
      if (device->mtu != -1 && len >= device->mtu - 3) //to check title len should not greater than mtu
        len = device->mtu - 3;
      p_data->rsp_value.attr_value.len = len;
      memcpy(p_data->rsp_value.attr_value.value, mediaPlayerInfo.title,
          p_data->rsp_value.attr_value.len);
      p_data->event = MCP_READ_RSP;
      device = p_data->remoteDevice;
      device->DeviceStateHandlerPointer[device->state](p_data->event, p_data, device->state);
      break;
    }
    case MCP_TRACK_POSITION_READ: {
      p_data->rsp_value.attr_value.len = sizeof(mediaPlayerInfo.position);
      *(int *)p_data->rsp_value.attr_value.value = *(int *)&mediaPlayerInfo.position;
      p_data->event = MCP_READ_RSP;
      device = p_data->remoteDevice;
      device->DeviceStateHandlerPointer[device->state](p_data->event, p_data, device->state);
      break;
    }
    case MCP_TRACK_DURATION_READ: {
      p_data->rsp_value.attr_value.len = sizeof(mediaPlayerInfo.duration);
      *(int *)p_data->rsp_value.attr_value.value = *(int *)&mediaPlayerInfo.duration;
      p_data->event = MCP_READ_RSP;
      device = p_data->remoteDevice;
      device->DeviceStateHandlerPointer[device->state](p_data->event, p_data, device->state);
      break;
    }
    case MCP_PLAYING_ORDER_SUPPORTED_READ: {
      p_data->rsp_value.attr_value.len = sizeof(mediaPlayerInfo.playing_order_supported);
      *(uint16_t *)p_data->rsp_value.attr_value.value =
          *(uint16_t *)&mediaPlayerInfo.playing_order_supported;
      p_data->event = MCP_READ_RSP;
      device = p_data->remoteDevice;
      device->DeviceStateHandlerPointer[device->state](p_data->event, p_data, device->state);
      break;
    }
    case MCP_PLAYING_ORDER_READ: {
      p_data->rsp_value.attr_value.len = sizeof(mediaPlayerInfo.playing_order_value);
      *(uint16_t *)p_data->rsp_value.attr_value.value = *(uint16_t *)&mediaPlayerInfo.playing_order_value;
      p_data->event = MCP_READ_RSP;
      device = p_data->remoteDevice;
      device->DeviceStateHandlerPointer[device->state](p_data->event, p_data, device->state);
      break;
    }
    case MCP_CCID_READ: {
      p_data->rsp_value.attr_value.len = sizeof(mediaPlayerInfo.ccid);
      *(uint32_t *)p_data->rsp_value.attr_value.value = *(uint8_t *)&mediaPlayerInfo.ccid;
      p_data->event = MCP_READ_RSP;
      device = p_data->remoteDevice;
      device->DeviceStateHandlerPointer[device->state](p_data->event, p_data, device->state);
      break;
    }
    case MCP_SEEKING_SPEED_READ: {
      p_data->rsp_value.attr_value.len = sizeof(mediaPlayerInfo.seeking_speed);
      *(uint8_t *)p_data->rsp_value.attr_value.value = (uint8_t)mediaPlayerInfo.seeking_speed;
      p_data->event = MCP_READ_RSP;
      device = p_data->remoteDevice;
      device->DeviceStateHandlerPointer[device->state](p_data->event, p_data, device->state);
      break;
    }
    case MCP_MEDIA_STATE_READ_DESCRIPTOR:{
      *(uint16_t *)p_data->rsp_value.attr_value.value = *(uint16_t *)&device->media_state_notify;
      p_data->rsp_value.attr_value.len = sizeof(device->media_state_notify);
      p_data->event = MCP_DESCRIPTOR_READ_RSP;
      device = p_data->remoteDevice;
      device->DeviceStateHandlerPointer[device->state](p_data->event, p_data, device->state);
      break;
    }
    case MCP_MEDIA_CONTROL_POINT_READ_DESCRIPTOR: {
      *(uint16_t *)p_data->rsp_value.attr_value.value = *(uint16_t *)&device->media_control_point_notify;
      p_data->rsp_value.attr_value.len = sizeof(device->media_control_point_notify);
      p_data->event = MCP_DESCRIPTOR_READ_RSP;
      device = p_data->remoteDevice;
      device->DeviceStateHandlerPointer[device->state](p_data->event, p_data, device->state);
      break;
    }
    case MCP_MEDIA_CONTROL_POINT_OPCODE_SUPPORTED_DESCRIPTOR_READ: {
      *(uint16_t *)p_data->rsp_value.attr_value.value =
         *(uint16_t *)&device->media_control_point_opcode_supported_notify;
      p_data->rsp_value.attr_value.len = sizeof(device->media_control_point_opcode_supported_notify);
      p_data->event = MCP_DESCRIPTOR_READ_RSP;
      device = p_data->remoteDevice;
      device->DeviceStateHandlerPointer[device->state](p_data->event, p_data, device->state);
      break;
    }
    case MCP_MEDIA_PLAYER_NAME_DESCRIPTOR_READ: {
      *(uint16_t *)p_data->rsp_value.attr_value.value = *(uint16_t *)&device->media_player_name_notify;
      p_data->rsp_value.attr_value.len = sizeof(device->media_player_name_notify);
      p_data->event = MCP_DESCRIPTOR_READ_RSP;
      device = p_data->remoteDevice;
      device->DeviceStateHandlerPointer[device->state](p_data->event, p_data, device->state);
      break;
    }
    case MCP_TRACK_CHANGED_DESCRIPTOR_READ: {
      *(uint16_t *)p_data->rsp_value.attr_value.value = *(uint16_t *)&device->track_changed_notify;
      p_data->rsp_value.attr_value.len = sizeof(device->track_changed_notify);
      p_data->event = MCP_DESCRIPTOR_READ_RSP;
      device = p_data->remoteDevice;
      device->DeviceStateHandlerPointer[device->state](p_data->event, p_data, device->state);
      break;
    }
    case MCP_TRACK_TITLE_DESCRIPTOR_READ: {
      *(uint16_t *)p_data->rsp_value.attr_value.value = *(uint16_t *)&device->track_title_notify;
      p_data->rsp_value.attr_value.len = sizeof(device->track_title_notify);
      p_data->event = MCP_DESCRIPTOR_READ_RSP;
      device = p_data->remoteDevice;
      device->DeviceStateHandlerPointer[device->state](p_data->event, p_data, device->state);
      break;
    }
    case MCP_TRACK_POSITION_DESCRIPTOR_READ: {
      *(uint16_t *)p_data->rsp_value.attr_value.value = *(uint16_t *)&device->track_position_notify;
      p_data->rsp_value.attr_value.len = sizeof(device->track_position_notify);
      p_data->event = MCP_DESCRIPTOR_READ_RSP;
      device = p_data->remoteDevice;
      device->DeviceStateHandlerPointer[device->state](p_data->event, p_data, device->state);
      break;
    }
    case MCP_TRACK_DURATION_DESCRIPTOR_READ: {
      *(uint16_t *)p_data->rsp_value.attr_value.value = *(uint16_t *)&device->track_duration_notify;;
      p_data->rsp_value.attr_value.len = sizeof(device->track_duration_notify);
      p_data->event = MCP_DESCRIPTOR_READ_RSP;
      device = p_data->remoteDevice;
      device->DeviceStateHandlerPointer[device->state](p_data->event, p_data, device->state);
      break;
    }
    case MCP_PLAYING_ORDER_DESCRIPTOR_READ: {
      *(uint16_t *)p_data->rsp_value.attr_value.value = *(uint16_t *)&device->playing_order_notify;
      p_data->rsp_value.attr_value.len = sizeof(device->playing_order_notify);
      p_data->event = MCP_DESCRIPTOR_READ_RSP;
      device = p_data->remoteDevice;
      device->DeviceStateHandlerPointer[device->state](p_data->event, p_data, device->state);
      break;
    }

    case MCP_MEDIA_STATE_DESCRIPTOR_WRITE: {
      p_data->oper.WriteDescOp.data = (uint8_t *)&mediaPlayerInfo.media_state;
      p_data->oper.WriteDescOp.len = sizeof (mediaPlayerInfo.media_state);
      p_data->oper.WriteDescOp.char_handle = mcsServerServiceInfo.media_state_handle;
      p_data->event = MCP_DESCRIPTOR_WRITE_RSP;
      device = p_data->remoteDevice;
      device->DeviceStateHandlerPointer[device->state](p_data->event, p_data, device->state);
      break;
    }
    case MCP_MEDIA_PLAYER_NAME_DESCRIPTOR_WRITE: {
      p_data->oper.WriteDescOp.data = (uint8_t *)&mediaPlayerInfo.player_name;
      p_data->oper.WriteDescOp.len = mediaPlayerInfo.player_name_len;
      p_data->oper.WriteDescOp.char_handle = mcsServerServiceInfo.media_player_name_handle;
      p_data->event = MCP_DESCRIPTOR_WRITE_RSP;
      device = p_data->remoteDevice;
      device->DeviceStateHandlerPointer[device->state](p_data->event, p_data, device->state);
      break;
    }
    case MCP_MEDIA_CONTROL_POINT_DESCRIPTOR_WRITE: {
      p_data->oper.WriteDescOp.data = (uint8_t *)&mediaPlayerInfo.media_ctrl_point;
      p_data->oper.WriteDescOp.len = sizeof (mediaPlayerInfo.media_ctrl_point);
      p_data->oper.WriteDescOp.char_handle = mcsServerServiceInfo.media_control_point_handle;
      p_data->event = MCP_DESCRIPTOR_WRITE_RSP;
      device = p_data->remoteDevice;
      device->DeviceStateHandlerPointer[device->state](p_data->event, p_data, device->state);
      break;
    }
    case MCP_MEDIA_CONTROL_POINT_SUPPORTED_DESCRIPTOR_WRITE: {
      p_data->oper.WriteDescOp.data = (uint8_t *)&mediaPlayerInfo.media_supported_feature;
      p_data->oper.WriteDescOp.len = sizeof (mediaPlayerInfo.media_supported_feature);
      p_data->oper.WriteDescOp.char_handle = mcsServerServiceInfo.media_control_point_opcode_supported_handle;
      p_data->event = MCP_DESCRIPTOR_WRITE_RSP;
      device = p_data->remoteDevice;
      device->DeviceStateHandlerPointer[device->state](p_data->event, p_data, device->state);
      break;
    }
    case MCP_TRACK_CHANGED_DESCRIPTOR_WRITE: {
      p_data->oper.WriteDescOp.data = (uint8_t *)&mediaPlayerInfo.track_changed;
      p_data->oper.WriteDescOp.len = sizeof (mediaPlayerInfo.track_changed);
      p_data->oper.WriteDescOp.char_handle = mcsServerServiceInfo.track_changed_handle;
      p_data->event = MCP_DESCRIPTOR_WRITE_RSP;
      device = p_data->remoteDevice;
      device->DeviceStateHandlerPointer[device->state](p_data->event, p_data, device->state);
      break;
    }
    case MCP_TRACK_TITLE_DESCRIPTOR_WRITE: {
      p_data->oper.WriteDescOp.data = (uint8_t *)&mediaPlayerInfo.title;
      p_data->oper.WriteDescOp.len = mediaPlayerInfo.track_title_len;
      p_data->oper.WriteDescOp.char_handle = mcsServerServiceInfo.track_title_handle;
      p_data->event = MCP_DESCRIPTOR_WRITE_RSP;
      device = p_data->remoteDevice;
      device->DeviceStateHandlerPointer[device->state](p_data->event, p_data, device->state);
      break;
    }

    case MCP_TRACK_POSITION_DESCRIPTOR_WRITE: {
      p_data->oper.WriteDescOp.data = (uint8_t *)&mediaPlayerInfo.position;
      p_data->oper.WriteDescOp.len = sizeof(mediaPlayerInfo.position);
      p_data->oper.WriteDescOp.char_handle = mcsServerServiceInfo.track_position_handle;
      p_data->event = MCP_DESCRIPTOR_WRITE_RSP;
      device = p_data->remoteDevice;
      device->DeviceStateHandlerPointer[device->state](p_data->event, p_data, device->state);
      break;
    }

    case MCP_TRACK_DURATION_DESCRIPTOR_WRITE: {
      p_data->oper.WriteDescOp.data = (uint8_t *)&mediaPlayerInfo.duration;
      p_data->oper.WriteDescOp.len = sizeof(mediaPlayerInfo.duration);
      p_data->oper.WriteDescOp.char_handle = mcsServerServiceInfo.track_duration_handle;
      p_data->event = MCP_DESCRIPTOR_WRITE_RSP;
      device = p_data->remoteDevice;
      device->DeviceStateHandlerPointer[device->state](p_data->event, p_data, device->state);
      break;
    }

    case MCP_PLAYING_ORDER_DESCRIPTOR_WRITE : {
      p_data->oper.WriteDescOp.data = (uint8_t *)&mediaPlayerInfo.playing_order_value;
      p_data->oper.WriteDescOp.len = sizeof(mediaPlayerInfo.playing_order_value);
      p_data->event = MCP_DESCRIPTOR_WRITE_RSP;
      device = p_data->remoteDevice;
      device->DeviceStateHandlerPointer[device->state](p_data->event, p_data, device->state);
      break;
    }

    case MCP_CONGESTION_UPDATE: {
      LOG(INFO) << __func__ << ": device MCP_CONGESTION_UPDATE update: " << event;
      McpCongestionUpdate(p_data);
      break;
    }

    case MCP_CONNECTION_UPDATE:
    case MCP_ACTIVE_DEVICE_UPDATE:
    case MCP_PHY_UPDATE:
    case MCP_CONNECTION:
    case MCP_DISCONNECTION:
    case MCP_CONNECTION_CLOSE_EVENT:
    case MCP_BOND_STATE_CHANGE_EVENT:
      device = p_data->remoteDevice;
      device->DeviceStateHandlerPointer[device->state](p_data->event, p_data, device->state);
      break;

    default:
      break;
  }
  return BT_STATUS_SUCCESS;
}


bool MediaStatePauseHandler(uint32_t event, void* param, uint8_t state) {
  LOG(INFO) << __func__ << " handle event " << get_mcp_event_name(event)
            << " in state " << get_mcp_media_state_name(state);

  mcp_resp_t *p_data = (mcp_resp_t *)param;
  RemoteDevice *device = p_data->remoteDevice;
  switch(event) {
    case MCP_NOTIFY_ALL: {
      LOG(INFO) << __func__ << " Notify all handle "<< p_data->handle;
      std::vector<RemoteDevice>notifyDevices = instance->remoteDevices.FindNotifyDevices(p_data->handle);
      std::vector<RemoteDevice>::iterator it;
      if (notifyDevices.size() <= 0) {
        LOG(INFO) << __func__ << " No device register for notification";
      }
      for (it = notifyDevices.begin(); it != notifyDevices.end(); it++){
        p_data->remoteDevice = instance->remoteDevices.FindByConnId(it->conn_id);
        it->DeviceStateHandlerPointer[it->state](p_data->event, p_data, it->state);
        LOG(INFO) << __func__ << " Notify all handle device id " << it->conn_id;

      }
      break;
    }

    case MCP_PLAYING_ORDER_WRITE: {
      uint8_t data = (uint8_t)(*p_data->oper.WriteOp.data);
      if (mediaPlayerInfo.playing_order_supported & data) {
        instance->PlayingOrderChangeReq(data & mediaPlayerInfo.playing_order_value);
      } else {
        LOG(INFO) << __func__ << " ignore playing_order_handle write feature is not supported";
        break;
      }
      p_data->rsp_value.attr_value.len = 0;
      device = p_data->remoteDevice;
      device->DeviceStateHandlerPointer[device->state](p_data->event, p_data, device->state);
      break;
    }
    case MCP_MEDIA_CONTROL_POINT_WRITE: {
      uint8_t data = (uint8_t)(*p_data->oper.WriteOp.data);
      uint8_t opcode_support = is_opcode_supported(data);
      if (!opcode_support) {
        uint8_t status = MCP_OPCODE_NOT_SUPPORTED;
        std::vector<uint8_t> value;
        value.push_back(data);
        value.push_back(status);
        LOG(INFO) << __func__ << "hndl " << p_data->oper.WriteOp.char_handle;
        LOG(INFO) << __func__ << "opcode not supported " << data;
        GattsOpsQueue::SendNotification(device->conn_id, p_data->oper.WriteOp.char_handle, value, false);
      }

      if ((data != MCP_MEDIA_CONTROL_OPCODE_PLAY) &&
         (instance->remoteDevices.FindActiveDevice(p_data->remoteDevice) == false)
         && is_pts_running() == false) {
        LOG(INFO) << __func__ << " media control point write received from inactive device";
        break;
      }
      if (data != MCP_MEDIA_CONTROL_OPCODE_PAUSE) {
        //<TBD> MCP_MEDIA_CONTROL_STOP need to check for stop
        instance->MediaControlPointChangeReq(data, device->peer_bda);
        LOG(INFO) << __func__ << "media_control_point_handle write ";
      } else {
        LOG(INFO) << __func__ << " ignore media_control_point_handle write feature is not supported / already paused";
      }
      p_data->rsp_value.attr_value.len = 0;
      device = p_data->remoteDevice;
      device->DeviceStateHandlerPointer[device->state](p_data->event, p_data, device->state);
      break;
    }
    case MCP_TRACK_POSITION_WRITE: {
      uint32_t track_duration = mediaPlayerInfo.duration;
      uint32_t track_position = mediaPlayerInfo.position;
      uint32_t data;
      uint8_t *w_data = p_data->oper.WriteOp.data;
      STREAM_TO_UINT32(data, w_data);
      uint32_t position = track_duration;
      if ((track_position == (uint32_t)data) || (data < 0) ||
          (track_duration == 0xFFFF) || (track_duration > 0 && track_duration < data)) {
        LOG(INFO) << __func__ << " ignore track_position_handle write";
      } else {
        position = data;
        instance->TrackPositionChangeReq(data);
        LOG(INFO) << __func__ << " track_position_handle write";
      }
      std::vector<uint8_t> value;
      value.push_back(position & 0xff);
      value.push_back((position >> 8)  & 0xff);
      value.push_back((position >> 16) & 0xff);
      value.push_back((position >> 24) & 0xff);
      GattsOpsQueue::SendNotification(device->conn_id, p_data->oper.WriteOp.char_handle, value, false);
      device = p_data->remoteDevice;
      device->DeviceStateHandlerPointer[device->state](p_data->event, p_data, device->state);
      break;
    }
    case MCP_MEDIA_STATE_READ: {
      p_data->rsp_value.attr_value.len = sizeof(mediaPlayerInfo.media_state);
      *(uint8_t *)p_data->rsp_value.attr_value.value =  *(uint8_t *)&mediaPlayerInfo.media_state;
      p_data->event = MCP_READ_RSP;
      device = p_data->remoteDevice;
      device->DeviceStateHandlerPointer[device->state](p_data->event, p_data, device->state);
      break;
    }
    case MCP_MEDIA_PLAYER_NAME_READ: {
      uint16_t len = mediaPlayerInfo.player_name_len;
      LOG(INFO) << __func__ << " before player name len: " << len;
      LOG(INFO) << __func__ << " before player name mtu: " << device->mtu;
      if (device->mtu != -1 && len >= device->mtu - 3) //to check player len should not greater than mtu
        len = device->mtu - 3;
      p_data->rsp_value.attr_value.len = len;
      LOG(INFO) << __func__ << " player name len: " << len;
      memcpy(p_data->rsp_value.attr_value.value, mediaPlayerInfo.player_name,
          p_data->rsp_value.attr_value.len);
      p_data->event = MCP_READ_RSP;
      LOG(INFO) << __func__ << " calling player name read";
      device = p_data->remoteDevice;
      device->DeviceStateHandlerPointer[device->state](p_data->event, p_data, device->state);
      break;
    }
    case MCP_MEDIA_CONTROL_POINT_OPCODE_SUPPORTED_READ: {
      p_data->rsp_value.attr_value.len = sizeof(mediaPlayerInfo.media_supported_feature);
      *(uint32_t*)p_data->rsp_value.attr_value.value =
      *(uint32_t *)&mediaPlayerInfo.media_supported_feature;
      p_data->event = MCP_READ_RSP;
      device = p_data->remoteDevice;
      device->DeviceStateHandlerPointer[device->state](p_data->event, p_data, device->state);
      break;
    }
    case MCP_TRACK_TITLE_READ: {
      uint16_t len = mediaPlayerInfo.track_title_len;
      if (device->mtu != -1 && len >= device->mtu - 3) //to check title len should not greater than mtu
        len = device->mtu - 3;
      p_data->rsp_value.attr_value.len = len;
      memcpy(p_data->rsp_value.attr_value.value, mediaPlayerInfo.title,
          p_data->rsp_value.attr_value.len);
      p_data->event = MCP_READ_RSP;
      device = p_data->remoteDevice;
      device->DeviceStateHandlerPointer[device->state](p_data->event, p_data, device->state);
      break;
    }
    case MCP_TRACK_POSITION_READ: {
      p_data->rsp_value.attr_value.len = sizeof(mediaPlayerInfo.position);
      *(int *)p_data->rsp_value.attr_value.value = *(int *)&mediaPlayerInfo.position;
      p_data->event = MCP_READ_RSP;
      device = p_data->remoteDevice;
      device->DeviceStateHandlerPointer[device->state](p_data->event, p_data, device->state);
      break;
    }
    case MCP_TRACK_DURATION_READ: {
      p_data->rsp_value.attr_value.len = sizeof(mediaPlayerInfo.duration);
      *(int *)p_data->rsp_value.attr_value.value = *(int *)&mediaPlayerInfo.duration;
      p_data->event = MCP_READ_RSP;
      device = p_data->remoteDevice;
      device->DeviceStateHandlerPointer[device->state](p_data->event, p_data, device->state);
      break;
    }
    case MCP_PLAYING_ORDER_SUPPORTED_READ: {
      p_data->rsp_value.attr_value.len = sizeof(mediaPlayerInfo.playing_order_supported);
      *(uint16_t *)p_data->rsp_value.attr_value.value =
          *(uint16_t*)&mediaPlayerInfo.playing_order_supported;
      p_data->event = MCP_READ_RSP;
      device = p_data->remoteDevice;
      device->DeviceStateHandlerPointer[device->state](p_data->event, p_data, device->state);
      break;
    }
    case MCP_PLAYING_ORDER_READ: {
      p_data->rsp_value.attr_value.len = sizeof(mediaPlayerInfo.playing_order_value);
      *(uint16_t *)p_data->rsp_value.attr_value.value = *(uint16_t *)&mediaPlayerInfo.playing_order_value;
      p_data->event = MCP_READ_RSP;
      device = p_data->remoteDevice;
      device->DeviceStateHandlerPointer[device->state](p_data->event, p_data, device->state);
      break;
    }
    case MCP_CCID_READ: {
      p_data->rsp_value.attr_value.len = sizeof(mediaPlayerInfo.ccid);
      *(uint32_t *)p_data->rsp_value.attr_value.value = *(uint8_t *)&mediaPlayerInfo.ccid;
      p_data->event = MCP_READ_RSP;
      device = p_data->remoteDevice;
      device->DeviceStateHandlerPointer[device->state](p_data->event, p_data, device->state);
      break;
    }
    case MCP_SEEKING_SPEED_READ: {
      p_data->rsp_value.attr_value.len = sizeof(mediaPlayerInfo.seeking_speed);
      *(uint8_t *)p_data->rsp_value.attr_value.value = (uint8_t)mediaPlayerInfo.seeking_speed;
      p_data->event = MCP_READ_RSP;
      device = p_data->remoteDevice;
      device->DeviceStateHandlerPointer[device->state](p_data->event, p_data, device->state);
      break;
    }
    case MCP_MEDIA_STATE_READ_DESCRIPTOR:{
      *(uint16_t *)p_data->rsp_value.attr_value.value = *(uint16_t *)&device->media_state_notify;
      p_data->rsp_value.attr_value.len = sizeof(device->media_state_notify);
      p_data->event = MCP_DESCRIPTOR_READ_RSP;
      device = p_data->remoteDevice;
      device->DeviceStateHandlerPointer[device->state](p_data->event, p_data, device->state);
      break;
    }
    case MCP_MEDIA_CONTROL_POINT_READ_DESCRIPTOR: {
      *(uint16_t *)p_data->rsp_value.attr_value.value = *(uint16_t *)&device->media_control_point_notify;
      p_data->rsp_value.attr_value.len = sizeof(device->media_control_point_notify);
      p_data->event = MCP_DESCRIPTOR_READ_RSP;
      device = p_data->remoteDevice;
      device->DeviceStateHandlerPointer[device->state](p_data->event, p_data, device->state);
      break;
    }
    case MCP_MEDIA_CONTROL_POINT_OPCODE_SUPPORTED_DESCRIPTOR_READ: {
      *(uint16_t *)p_data->rsp_value.attr_value.value =
         *(uint16_t *)&device->media_control_point_opcode_supported_notify;
      p_data->rsp_value.attr_value.len = sizeof(device->media_control_point_opcode_supported_notify);
      p_data->event = MCP_DESCRIPTOR_READ_RSP;
      device = p_data->remoteDevice;
      device->DeviceStateHandlerPointer[device->state](p_data->event, p_data, device->state);
      break;
    }
    case MCP_MEDIA_PLAYER_NAME_DESCRIPTOR_READ: {
      *(uint16_t *)p_data->rsp_value.attr_value.value = *(uint16_t *)&device->media_player_name_notify;
      p_data->rsp_value.attr_value.len = sizeof(device->media_player_name_notify);
      p_data->event = MCP_DESCRIPTOR_READ_RSP;
      device = p_data->remoteDevice;
      device->DeviceStateHandlerPointer[device->state](p_data->event, p_data, device->state);
      break;
    }
    case MCP_TRACK_CHANGED_DESCRIPTOR_READ: {
      *(uint16_t *)p_data->rsp_value.attr_value.value = *(uint16_t *)&device->track_changed_notify;
      p_data->rsp_value.attr_value.len = sizeof(device->track_changed_notify);
      p_data->event = MCP_DESCRIPTOR_READ_RSP;
      device = p_data->remoteDevice;
      device->DeviceStateHandlerPointer[device->state](p_data->event, p_data, device->state);
      break;
    }
    case MCP_TRACK_TITLE_DESCRIPTOR_READ: {
      *(uint16_t *)p_data->rsp_value.attr_value.value = *(uint16_t *)&device->track_title_notify;
      p_data->rsp_value.attr_value.len = sizeof(device->track_title_notify);
      p_data->event = MCP_DESCRIPTOR_READ_RSP;
      device = p_data->remoteDevice;
      device->DeviceStateHandlerPointer[device->state](p_data->event, p_data, device->state);
      break;
    }
    case MCP_TRACK_POSITION_DESCRIPTOR_READ: {
      *(uint16_t *)p_data->rsp_value.attr_value.value = *(uint16_t *)&device->track_position_notify;
      p_data->rsp_value.attr_value.len = sizeof(device->track_position_notify);
      p_data->event = MCP_DESCRIPTOR_READ_RSP;
      device = p_data->remoteDevice;
      device->DeviceStateHandlerPointer[device->state](p_data->event, p_data, device->state);
      break;
    }
    case MCP_TRACK_DURATION_DESCRIPTOR_READ: {
      *(uint16_t *)p_data->rsp_value.attr_value.value = *(uint16_t *)&device->track_duration_notify;;
      p_data->rsp_value.attr_value.len = sizeof(device->track_duration_notify);
      p_data->event = MCP_DESCRIPTOR_READ_RSP;
      device = p_data->remoteDevice;
      device->DeviceStateHandlerPointer[device->state](p_data->event, p_data, device->state);
      break;
    }
    case MCP_PLAYING_ORDER_DESCRIPTOR_READ: {
      *(uint16_t *)p_data->rsp_value.attr_value.value = *(uint16_t *)&device->playing_order_notify;
      p_data->rsp_value.attr_value.len = sizeof(device->playing_order_notify);
      p_data->event = MCP_DESCRIPTOR_READ_RSP;
      device = p_data->remoteDevice;
      device->DeviceStateHandlerPointer[device->state](p_data->event, p_data, device->state);
      break;
    }

    case MCP_MEDIA_STATE_DESCRIPTOR_WRITE: {
      p_data->oper.WriteDescOp.data = (uint8_t *)&mediaPlayerInfo.media_state;
      p_data->oper.WriteDescOp.len = sizeof (mediaPlayerInfo.media_state);
      p_data->oper.WriteDescOp.char_handle = mcsServerServiceInfo.media_state_handle;
      p_data->event = MCP_DESCRIPTOR_WRITE_RSP;
      device = p_data->remoteDevice;
      device->DeviceStateHandlerPointer[device->state](p_data->event, p_data, device->state);
      break;
    }
    case MCP_MEDIA_PLAYER_NAME_DESCRIPTOR_WRITE: {
      p_data->oper.WriteDescOp.data = (uint8_t *)&mediaPlayerInfo.player_name;
      p_data->oper.WriteDescOp.len = mediaPlayerInfo.player_name_len;
      p_data->oper.WriteDescOp.char_handle = mcsServerServiceInfo.media_player_name_handle;
      p_data->event = MCP_DESCRIPTOR_WRITE_RSP;
      device = p_data->remoteDevice;
      device->DeviceStateHandlerPointer[device->state](p_data->event, p_data, device->state);
      break;
    }
    case MCP_MEDIA_CONTROL_POINT_DESCRIPTOR_WRITE: {
      p_data->oper.WriteDescOp.data = (uint8_t *)&mediaPlayerInfo.media_ctrl_point;
      p_data->oper.WriteDescOp.len = sizeof (mediaPlayerInfo.media_ctrl_point);
      p_data->oper.WriteDescOp.char_handle = mcsServerServiceInfo.media_control_point_handle;
      p_data->event = MCP_DESCRIPTOR_WRITE_RSP;
      device = p_data->remoteDevice;
      device->DeviceStateHandlerPointer[device->state](p_data->event, p_data, device->state);
      break;
    }
    case MCP_MEDIA_CONTROL_POINT_SUPPORTED_DESCRIPTOR_WRITE: {
      p_data->oper.WriteDescOp.data = (uint8_t *)&mediaPlayerInfo.media_supported_feature;
      p_data->oper.WriteDescOp.len = sizeof (mediaPlayerInfo.media_supported_feature);
      p_data->oper.WriteDescOp.char_handle = mcsServerServiceInfo.media_control_point_opcode_supported_handle;
      p_data->event = MCP_DESCRIPTOR_WRITE_RSP;
      device = p_data->remoteDevice;
      device->DeviceStateHandlerPointer[device->state](p_data->event, p_data, device->state);
      break;
    }
    case MCP_TRACK_CHANGED_DESCRIPTOR_WRITE: {
      p_data->oper.WriteDescOp.data = (uint8_t *)&mediaPlayerInfo.track_changed;
      p_data->oper.WriteDescOp.len = sizeof (mediaPlayerInfo.track_changed);
      p_data->oper.WriteDescOp.char_handle = mcsServerServiceInfo.track_changed_handle;
      p_data->event = MCP_DESCRIPTOR_WRITE_RSP;
      device = p_data->remoteDevice;
      device->DeviceStateHandlerPointer[device->state](p_data->event, p_data, device->state);
      break;
    }
    case MCP_TRACK_TITLE_DESCRIPTOR_WRITE: {
      p_data->oper.WriteDescOp.data = (uint8_t *)&mediaPlayerInfo.title;
      p_data->oper.WriteDescOp.len = mediaPlayerInfo.track_title_len;
      p_data->oper.WriteDescOp.char_handle = mcsServerServiceInfo.track_title_handle;
      p_data->event = MCP_DESCRIPTOR_WRITE_RSP;
      device = p_data->remoteDevice;
      device->DeviceStateHandlerPointer[device->state](p_data->event, p_data, device->state);
      break;
    }

    case MCP_TRACK_POSITION_DESCRIPTOR_WRITE: {
      p_data->oper.WriteDescOp.data = (uint8_t *)&mediaPlayerInfo.position;
      p_data->oper.WriteDescOp.len = sizeof(mediaPlayerInfo.position);
      p_data->oper.WriteDescOp.char_handle = mcsServerServiceInfo.track_position_handle;
      p_data->event = MCP_DESCRIPTOR_WRITE_RSP;
      device = p_data->remoteDevice;
      device->DeviceStateHandlerPointer[device->state](p_data->event, p_data, device->state);
      break;
    }

    case MCP_TRACK_DURATION_DESCRIPTOR_WRITE: {
      p_data->oper.WriteDescOp.data = (uint8_t *)&mediaPlayerInfo.duration;
      p_data->oper.WriteDescOp.len = sizeof(mediaPlayerInfo.duration);
      p_data->oper.WriteDescOp.char_handle = mcsServerServiceInfo.track_duration_handle;
      p_data->event = MCP_DESCRIPTOR_WRITE_RSP;
      device = p_data->remoteDevice;
      device->DeviceStateHandlerPointer[device->state](p_data->event, p_data, device->state);
      break;
    }

    case MCP_PLAYING_ORDER_DESCRIPTOR_WRITE : {
      p_data->oper.WriteDescOp.data = (uint8_t *)&mediaPlayerInfo.playing_order_value;
      p_data->oper.WriteDescOp.len = sizeof(mediaPlayerInfo.playing_order_value);
      p_data->event = MCP_DESCRIPTOR_WRITE_RSP;
      device = p_data->remoteDevice;
      device->DeviceStateHandlerPointer[device->state](p_data->event, p_data, device->state);
      break;
    }

    case MCP_CONGESTION_UPDATE: {
      McpCongestionUpdate(p_data);
      break;
    }

    case MCP_CONNECTION_UPDATE:
    case MCP_ACTIVE_DEVICE_UPDATE:
    case MCP_PHY_UPDATE:
    case MCP_CONNECTION:
    case MCP_DISCONNECTION:
    case MCP_CONNECTION_CLOSE_EVENT:
    case MCP_BOND_STATE_CHANGE_EVENT:
      device = p_data->remoteDevice;
      device->DeviceStateHandlerPointer[device->state](p_data->event, p_data, device->state);
      break;

      default:
      break;
  }
  return BT_STATUS_SUCCESS;
}

bool DeviceStateConnectionHandler(uint32_t event, void* param, uint8_t state) {
  LOG(INFO) << __func__ << "  device connected handle " << get_mcp_event_name(event);
  mcp_resp_t *p_data = (mcp_resp_t *) param;
  switch (event) {
    case MCP_NOTIFY_ALL: {
      LOG(INFO) << __func__ << "  device notify all ";
      if (is_pts_running() || p_data->remoteDevice->active_profile == 0x10) {// need to check profile value
        std::vector<uint8_t> value;
        tMCP_MEDIA_UPDATE *notfiyUpdate = &p_data->oper.MediaUpdateOp;
        value.assign(notfiyUpdate->data, notfiyUpdate->data + notfiyUpdate->len);
        GattsOpsQueue::SendNotification(p_data->remoteDevice->conn_id,
                                        p_data->handle, value, false);
      }
      break;
    }

    case MCP_READ_RSP:
      BTA_GATTS_SendRsp(p_data->remoteDevice->conn_id, p_data->oper.ReadOp.trans_id,
          BT_STATUS_SUCCESS, &p_data->rsp_value);

      break;

    case MCP_DESCRIPTOR_READ_RSP:
      BTA_GATTS_SendRsp(p_data->remoteDevice->conn_id, p_data->oper.ReadDescOp.trans_id,
          BT_STATUS_SUCCESS, &p_data->rsp_value);

      break;

    case MCP_DESCRIPTOR_WRITE_RSP: {
      LOG(INFO) << __func__ << "  device MCP_DESCRIPTOR_WRITE_RSP update rsp :" << p_data->oper.WriteDescOp.need_rsp;
      tGATTS_RSP rsp_struct;
      rsp_struct.attr_value.handle = p_data->rsp_value.attr_value.handle;
      rsp_struct.attr_value.offset = p_data->rsp_value.attr_value.offset;
      if (p_data->remoteDevice->congested == false &&
            p_data->oper.WriteDescOp.need_rsp) {
      //send rsp to write
        LOG(INFO) << __func__ << " gatt send rsp status" << p_data->oper.WriteDescOp.status;
        BTA_GATTS_SendRsp(p_data->remoteDevice->conn_id, p_data->oper.WriteDescOp.trans_id,
            p_data->oper.WriteDescOp.status, &rsp_struct);
      }
      break;
    }

    case MCP_WRITE_RSP: {
      LOG(INFO) << __func__ << " device MCP_WRITE_RSP update Tx ID: " << p_data->oper.WriteOp.trans_id;
      bool need_rsp = p_data->oper.WriteOp.need_rsp;
      if (need_rsp) {
      BTA_GATTS_SendRsp(p_data->remoteDevice->conn_id, p_data->oper.WriteOp.trans_id,
          BT_STATUS_SUCCESS, &p_data->rsp_value);
      }
      break;
    }

    case MCP_CONNECTION_UPDATE: {
      p_data->remoteDevice->latency = p_data->oper.ConnectionUpdateOp.latency;
      p_data->remoteDevice->timeout = p_data->oper.ConnectionUpdateOp.timeout;
      p_data->remoteDevice->interval = p_data->oper.ConnectionUpdateOp.interval;
      p_data->remoteDevice->active_profile = 0x10;
      break;
    }

    case MCP_ACTIVE_DEVICE_UPDATE: {
      p_data->remoteDevice->active_profile = p_data->oper.SetActiveDeviceOp.profile;
      break;
    }
    case MCP_PHY_UPDATE: {
      p_data->remoteDevice->rx_phy = p_data->oper.PhyOp.rx_phy;
      p_data->remoteDevice->tx_phy = p_data->oper.PhyOp.tx_phy;
      break;
    }

    case MCP_MTU_UPDATE: {
      p_data->remoteDevice->mtu = p_data->oper.MtuOp.mtu;
      break;
    }

    case MCP_CONGESTION_UPDATE: {
      McpCongestionUpdate(p_data);
      break;
    }

    case MCP_DISCONNECTION: {
      LOG(INFO) << __func__ << "  device event MCP_DISCONNECTION remove ";
      instance->remoteDevices.Remove(p_data->remoteDevice->peer_bda);
      instance->OnConnectionStateChange(MCP_DISCONNECTED, p_data->remoteDevice->peer_bda);
      break;
    }

    case MCP_CONNECTION_CLOSE_EVENT: {
      LOG(INFO) << __func__ << "  device connection closing";
        // Close active connection
      if (p_data->remoteDevice->conn_id != 0)
        BTA_GATTS_Close(p_data->remoteDevice->conn_id);
      else
        BTA_GATTS_CancelOpen(mcsServerServiceInfo.server_if, p_data->remoteDevice->peer_bda, true);

      // Cancel pending background connections
      BTA_GATTS_CancelOpen(mcsServerServiceInfo.server_if, p_data->remoteDevice->peer_bda, false);
      break;
    }

    case MCP_BOND_STATE_CHANGE_EVENT:
      LOG(INFO) << __func__ << "Bond state change : ";
      instance->remoteDevices.Remove(p_data->remoteDevice->peer_bda);
      break;

    default:
      LOG(INFO) << __func__ << "  event not matched";
      break;
  }

  return BT_STATUS_SUCCESS;
}


bool DeviceStateDisconnectedHandler(uint32_t event, void* param, uint8_t state) {
  LOG(INFO) << __func__ << "  device disconnected handle " << get_mcp_event_name(event);
  mcp_resp_t *p_data = (mcp_resp_t *) param;
  switch (event) {
    case MCP_CONNECTION: {
      p_data->remoteDevice->state = MCP_CONNECTED;
      p_data->remoteDevice->media_state_notify = 0x00;
      p_data->remoteDevice->media_player_name_notify = 0x00;
      p_data->remoteDevice->media_control_point_notify = 0x00;
      p_data->remoteDevice->track_changed_notify = 0x00;
      p_data->remoteDevice->track_duration_notify = 0x00;
      p_data->remoteDevice->track_title_notify = 0x00;
      p_data->remoteDevice->track_position_notify = 0x00;
      p_data->remoteDevice->playing_order_notify = 0x00;
      p_data->remoteDevice->congested = false;

      p_data->remoteDevice->timeout = 0;
      p_data->remoteDevice->latency = 0;
      p_data->remoteDevice->interval = 0;
      p_data->remoteDevice->rx_phy = 0;
      p_data->remoteDevice->tx_phy = 0;
      p_data->remoteDevice->mtu = -1;
      instance->OnConnectionStateChange(MCP_CONNECTED, p_data->remoteDevice->peer_bda);
      break;
    }

    case MCP_CONGESTION_UPDATE: {
      McpCongestionUpdate(p_data);
      break;
    }

    case MCP_MTU_UPDATE:
    case MCP_PHY_UPDATE:
    case MCP_READ_RSP:
    case MCP_DESCRIPTOR_READ_RSP:
    case MCP_WRITE_RSP:
    case MCP_DESCRIPTOR_WRITE_RSP:
    case MCP_NOTIFY_ALL:
    case MCP_DISCONNECTION:
    case MCP_CONNECTION_CLOSE_EVENT:
    case MCP_BOND_STATE_CHANGE_EVENT:
    default:
      //ignore event
      LOG(INFO) << __func__ << "  Ignore event " << get_mcp_event_name(event);
      break;
  }
  return BT_STATUS_SUCCESS;
}

void McpCongestionUpdate(mcp_resp_t *p_data) {
  p_data->remoteDevice->congested = p_data->oper.CongestionOp.congested;
  LOG(INFO) << __func__ << ": conn_id: " << p_data->remoteDevice->conn_id
                        << ", congested: " << p_data->remoteDevice->congested;

  GattsOpsQueue::CongestionCallback(p_data->remoteDevice->conn_id,
                                    p_data->remoteDevice->congested);
}
