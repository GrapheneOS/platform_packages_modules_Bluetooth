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


#ifndef ANDROID_INCLUDE_BT_MCP_H
#define ANDROID_INCLUDE_BT_MCP_H



#include <hardware/bluetooth.h>
#include <vector>

#define BT_PROFILE_MCP_ID "mcs_server"

namespace bluetooth {
namespace mcp_server {

class McpServerCallbacks {
  public:
  virtual ~McpServerCallbacks() = default;
  virtual void OnConnectionStateChange(int status, const RawAddress& bd_addr) = 0;
  virtual void MediaControlPointChangeReq(uint8_t state,  const RawAddress& bd_addr) = 0;
  virtual void TrackPositionChangeReq(int32_t position) = 0;
  virtual void PlayingOrderChangeReq(uint32_t order) = 0;
};


class McpServerInterface {
  public:
    virtual ~McpServerInterface() = default;
    virtual void Init(McpServerCallbacks* callbacks, Uuid uuid) = 0;
    virtual void MediaState(uint8_t state) = 0;
    virtual void MediaPlayerName(uint8_t *name) = 0;
    virtual void MediaControlPointOpcodeSupported(uint32_t feature) = 0;
    virtual void MediaControlPoint(uint8_t value) = 0;
    virtual void TrackChanged(bool status) = 0;
    virtual void TrackTitle(uint8_t* title) = 0;
    virtual void TrackPosition(int32_t position) = 0;
    virtual void TrackDuration(int32_t duration) = 0;
    virtual void PlayingOrderSupported(uint16_t order) = 0;
    virtual void PlayingOrder(uint8_t value) = 0;
    virtual void ContentControlId(uint8_t ccid) = 0;
    virtual void SetActiveDevice(const RawAddress& address, int set_id, int profile) = 0;
    virtual void DisconnectMcp(const RawAddress& address) = 0;
    virtual void BondStateChange(const RawAddress& address, int state) = 0;
    virtual void Cleanup(void) = 0;
};

}
}
#endif /* ANDROID_INCLUDE_BT_MCP_H */
