/******************************************************************************
 *  Copyright (c) 2020-2021, The Linux Foundation. All rights reserved.
 *
 *****************************************************************************/

/* MCP Interface */
#define LOG_TAG "bt_btif_mcp"

#include "bt_target.h"
#include "bta_closure_api.h"
#include "bta_mcp_api.h"
#include "btif_common.h"
#include "btif_storage.h"

#include <base/bind.h>
#include <base/callback.h>
#include <hardware/bluetooth.h>
#include <hardware/bt_mcp.h>

using base::Bind;
using base::Unretained;
using base::Owned;
using bluetooth::Uuid;
using std::vector;
using base::Bind;
using base::Unretained;

using bluetooth::mcp_server::McpServerCallbacks;
using bluetooth::mcp_server::McpServerInterface;

namespace {
class McpServerInterfaceImpl;
std::unique_ptr<McpServerInterface> McpServerInstance;

class McpServerInterfaceImpl
  : public McpServerInterface, public McpServerCallbacks {
  ~McpServerInterfaceImpl() = default;

  void Init(McpServerCallbacks* callback, Uuid bt_uuid) override {
    LOG(INFO) << __func__ ;
    this->callbacks = callback;
    do_in_bta_thread(FROM_HERE,
          Bind(&McpServer::Initialize, this, bt_uuid));
  }

  void MediaState(uint8_t state) override {
    LOG(INFO) << __func__ << ": state " << state;
    do_in_bta_thread(FROM_HERE,
          Bind(&McpServer::MediaState, Unretained(McpServer::Get()), state));
  }

  void MediaPlayerName(uint8_t* name) override {
    LOG(INFO) << __func__ << ": name" << name;
    do_in_bta_thread(FROM_HERE,
          Bind(&McpServer::MediaPlayerName, Unretained(McpServer::Get()), name));
  }

  void MediaControlPointOpcodeSupported(uint32_t feature) override {
    LOG(INFO) << __func__ << ": feature" << feature;
    do_in_bta_thread(FROM_HERE,
          Bind(&McpServer::MediaControlPointOpcodeSupported, Unretained(McpServer::Get()), feature));
  }

  void MediaControlPoint(uint8_t value) override {
    LOG(INFO) << __func__ << ": value" << value;
    do_in_bta_thread(FROM_HERE,
          Bind(&McpServer::MediaControlPoint, Unretained(McpServer::Get()), value));
  }

  void TrackChanged(bool status) override {
    LOG(INFO) << __func__ << ": status" << status;
    do_in_bta_thread(FROM_HERE,
          Bind(&McpServer::TrackChanged, Unretained(McpServer::Get()), status));
  }

  void TrackTitle(uint8_t* title) override {
    LOG(INFO) << __func__ << ": title" << title;
    do_in_bta_thread(FROM_HERE,
          Bind(&McpServer::TrackTitle, Unretained(McpServer::Get()), title));
  }

  void TrackPosition(int32_t position) override {
    LOG(INFO) << __func__ << ": position" << position;
    do_in_bta_thread(FROM_HERE,
          Bind(&McpServer::TrackPosition, Unretained(McpServer::Get()), position));
  }

  void TrackDuration(int32_t duration) override {
    LOG(INFO) << __func__ << ": duration" << duration;
    do_in_bta_thread(FROM_HERE,
          Bind(&McpServer::TrackDuration, Unretained(McpServer::Get()), duration));
  }

  void ContentControlId(uint8_t ccid) override {
    LOG(INFO) << __func__ << ": ccid" << ccid;
    do_in_bta_thread(FROM_HERE,
          Bind(&McpServer::ContentControlId, Unretained(McpServer::Get()), ccid));
  }

  void PlayingOrderSupported(uint16_t order) override {
    LOG(INFO) << __func__ << ": order" << order;
    do_in_bta_thread(FROM_HERE,
          Bind(&McpServer::PlayingOrderSupported, Unretained(McpServer::Get()), order));
  }

  void PlayingOrder(uint8_t value) override {
    LOG(INFO) << __func__ << ": value" << value;
    do_in_bta_thread(FROM_HERE,
          Bind(&McpServer::PlayingOrder, Unretained(McpServer::Get()), value));
  }

  void SetActiveDevice(const RawAddress& address, int set_id, int profile) override {
    LOG(INFO) << __func__ << ": set_id" << set_id<< ": device"<< address;
    do_in_bta_thread(FROM_HERE,
          Bind(&McpServer::SetActiveDevice, Unretained(McpServer::Get()), address, set_id, profile));
  }

  void DisconnectMcp(const RawAddress& address) override {
    LOG(INFO) << __func__ << ": device"<< address;
    do_in_bta_thread(FROM_HERE,
          Bind(&McpServer::DisconnectMcp, Unretained(McpServer::Get()), address));
  }

  void BondStateChange(const RawAddress& address, int state) override {
    LOG(INFO) << __func__ << ": device"<< address << " state : " << state;
    do_in_bta_thread(FROM_HERE,
          Bind(&McpServer::BondStateChange, Unretained(McpServer::Get()), address, state));
  }

  void Cleanup(void) override {
    LOG(INFO) << __func__;
    do_in_bta_thread(FROM_HERE, Bind(&McpServer::CleanUp));
  }

  void OnConnectionStateChange(int status,
                         const RawAddress& address) override {
    LOG(INFO) << __func__ << ": device=" << address << " state=" << (int)status;
    do_in_jni_thread(FROM_HERE, Bind(&McpServerCallbacks::OnConnectionStateChange,
            Unretained(callbacks), status, address));
  }

  void MediaControlPointChangeReq(uint8_t state,
                         const RawAddress& address) override {
    LOG(INFO) << __func__ << ": device=" << address << " state=" << (int)state;
    do_in_jni_thread(FROM_HERE, Bind(&McpServerCallbacks::MediaControlPointChangeReq,
            Unretained(callbacks), state, address));
  }

  void TrackPositionChangeReq(int32_t position) override {
    LOG(INFO) << __func__ << " position=" << (int)position;
    do_in_jni_thread(FROM_HERE, Bind(&McpServerCallbacks::TrackPositionChangeReq,
            Unretained(callbacks), position));
  }

  void PlayingOrderChangeReq(uint32_t order) override {
    LOG(INFO) << __func__ << ": order=" << order;
    do_in_jni_thread(FROM_HERE, Bind(&McpServerCallbacks::PlayingOrderChangeReq,
            Unretained(callbacks), order));
  }

  private:
    McpServerCallbacks* callbacks;
  };
}//namespace

const McpServerInterface* btif_mcp_server_get_interface(void) {
   LOG(INFO) << __func__;
   if (!McpServerInstance)
     McpServerInstance.reset(new McpServerInterfaceImpl());
   return McpServerInstance.get();
}
