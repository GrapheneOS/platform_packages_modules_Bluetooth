/*
 *Copyright (c) 2020, The Linux Foundation. All rights reserved.
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

#include "bt_target.h"
#include "bta_vcp_controller_api.h"
#include "bta_gatt_api.h"
#include "btm_int.h"
#include "device/include/controller.h"
#include "gap_api.h"
#include "gatt_api.h"
#include "gattc_ops_queue.h"
#include "osi/include/properties.h"

#include <base/bind.h>
#include <base/callback.h>
#include <base/logging.h>
#include <base/strings/string_number_conversions.h>
#include <hardware/bt_vcp_controller.h>
#include <vector>

using base::Closure;
using bluetooth::Uuid;
using bluetooth::bap::GattOpsQueue;
using bluetooth::vcp_controller::ConnectionState;

// Assigned Numbers for VCS
Uuid VCS_UUID          = Uuid::FromString("1844");
Uuid VCS_VOLUME_STATE_UUID      = Uuid::FromString("2B7D");
Uuid VCS_VOLUME_CONTROL_POINT_UUID   = Uuid::FromString("2B7E");
Uuid VCS_VOLUME_FLAGS_UUID      = Uuid::FromString("2B7F");

#define VCS_RETRY_SET_ABS_VOL 0x01
#define VCS_RETRY_SET_MUTE_STATE 0x02

// VCS Application Error Code
#define VCS_INVALID_CHANGE_COUNTER 0x80
#define VCS_OPCODE_NOT_SUPPORTED 0x81

void vcp_controller_gattc_callback(tBTA_GATTC_EVT event, tBTA_GATTC* p_data);
void vcp_controller_encryption_callback(const RawAddress*, tGATT_TRANSPORT, void*, tBTM_STATUS);
const char* vcp_controller_gatt_callback_evt_str(uint8_t event);
const char* vcp_controller_handle_vcs_evt_str(uint8_t event);

class VcpControllerImpl;
static VcpControllerImpl* instance;

class RendererDevices {
 private:

 public:
  void Add(RendererDevice device) {
    if (FindByAddress(device.address) != nullptr) return;
    devices.push_back(device);
  }

  void Remove(const RawAddress& address) {
    for (auto it = devices.begin(); it != devices.end();) {
      if (it->address != address) {
        ++it;
        continue;
      }

      it = devices.erase(it);
      return;
    }
  }

  RendererDevice* FindByAddress(const RawAddress& address) {
    auto iter = std::find_if(devices.begin(), devices.end(),
                             [&address](const RendererDevice& device) {
                               return device.address == address;
                             });

    return (iter == devices.end()) ? nullptr : &(*iter);
  }

  RendererDevice* FindByConnId(uint16_t conn_id) {
    auto iter = std::find_if(devices.begin(), devices.end(),
                             [&conn_id](const RendererDevice& device) {
                               return device.conn_id == conn_id;
                             });

    return (iter == devices.end()) ? nullptr : &(*iter);
  }

  size_t size() { return (devices.size()); }

  std::vector<RendererDevice> devices;
};

class VcpControllerImpl : public VcpController {
 private:
  uint8_t gatt_if;
  bluetooth::vcp_controller::VcpControllerCallbacks* callbacks;
  RendererDevices rendererDevices;

 public:
  virtual ~VcpControllerImpl() = default;

  VcpControllerImpl(bluetooth::vcp_controller::VcpControllerCallbacks* callbacks)
      : gatt_if(0),
        callbacks(callbacks) {
    LOG(INFO) << "VcpControllerImpl gattc app register";

    BTA_GATTC_AppRegister(
        vcp_controller_gattc_callback,
        base::Bind(
            [](uint8_t client_id, uint8_t status) {
              if (status != GATT_SUCCESS) {
                LOG(ERROR) << "Can't start Vcp profile - no gatt "
                              "clients left!";
                return;
              }
              instance->gatt_if = client_id;
            }), true);
  }

  void Connect(const RawAddress& address, bool isDirect) override {
    LOG(INFO) << __func__ << " " << address << ", isDirect = " << logbool(isDirect);
    RendererDevice* rendererDevice = rendererDevices.FindByAddress(address);

    if (rendererDevice) {
      LOG(INFO) << "Device already in connected/connecting state" << address;
      return;
    }

    rendererDevices.Add(RendererDevice(address));
    rendererDevice = rendererDevices.FindByAddress(address);
    if (!rendererDevice) {
      LOG(INFO) << "Device address could not be foundL";
      return;
    }
    rendererDevice->state = BTA_VCP_CONNECTING;
    callbacks->OnConnectionState(ConnectionState::CONNECTING, rendererDevice->address);

    if (!isDirect) {
      rendererDevice->bg_conn = true;
    }

    BTA_GATTC_Open(gatt_if, address, isDirect, GATT_TRANSPORT_LE, false);
  }

  void Disconnect(const RawAddress& address) override {
    RendererDevice* rendererDevice = rendererDevices.FindByAddress(address);

    if (!rendererDevice) {
      LOG(INFO) << "Device not connected to profile" << address;
      return;
    }

    LOG(INFO) << __func__ << " " << address;
    rendererDevice->state = BTA_VCP_DISCONNECTING;
    callbacks->OnConnectionState(ConnectionState::DISCONNECTING, rendererDevice->address);
    VcpGattClose(rendererDevice);
  }

  void SetAbsVolume(const RawAddress& address, uint8_t volume) {
    RendererDevice* rendererDevice = rendererDevices.FindByAddress(address);

    if (!rendererDevice) {
      LOG(INFO) << "Device not connected to profile" << address;
      return;
    }

    if (rendererDevice->conn_id == 0) {
        LOG(INFO) << __func__ << ": GATT is not connected, skip set absolute volume";
        return;
    }

    if (rendererDevice->state != BTA_VCP_CONNECTED) {
      LOG(INFO)
          << __func__ << ": VCP is not connected, skip set absolute volume, state = "
          << loghex(rendererDevice->state);
      return;
    }
    // Send the data packet
    LOG(INFO) << __func__ << ": Set abs volume. device=" << rendererDevice->address
              << ", volume=" << loghex(volume);

    rendererDevice->vcs.pending_volume_setting = volume;

    uint8_t p_buf[256];
    SetAbsVolumeOp set_abs_vol_op;
    set_abs_vol_op.op_id  = VCS_CONTROL_POINT_OP_SET_ABS_VOL;
    set_abs_vol_op.change_counter = rendererDevice->vcs.volume_state.change_counter;
    set_abs_vol_op.volume_setting = volume;

    memcpy(p_buf, &set_abs_vol_op , sizeof(set_abs_vol_op));
    std::vector<uint8_t> vect_val(p_buf, p_buf + sizeof(set_abs_vol_op));

    GattOpsQueue::WriteCharacteristic(gatt_if,
        rendererDevice->conn_id, rendererDevice->vcs.volume_control_point_handle, vect_val,
        GATT_WRITE, VcpControllerImpl::OnSetAbsVolumeStatic, nullptr);
  }

  void Mute(const RawAddress& address) {
    RendererDevice* rendererDevice = rendererDevices.FindByAddress(address);

    if (!rendererDevice) {
      LOG(INFO) << "Device not connected to profile" << address;
      return;
    }

    if (rendererDevice->conn_id == 0) {
        LOG(INFO) << __func__ << ": GATT is not connected, skip mute";
        return;
    }

    if (rendererDevice->state != BTA_VCP_CONNECTED) {
      LOG(INFO)
          << __func__ << ": VCP is not connected, skip mute, state = "
          << loghex(rendererDevice->state);
      return;
    }
    // Send the data packet
    LOG(INFO) << __func__ << ": Mute device=" << rendererDevice->address;

    rendererDevice->vcs.pending_mute_setting = VCS_MUTE_STATE;

    uint8_t p_buf[256];
    MuteOp mute_op;
    mute_op.op_id  = VCS_CONTROL_POINT_OP_MUTE;
    mute_op.change_counter = rendererDevice->vcs.volume_state.change_counter;

    memcpy(p_buf, &mute_op , sizeof(mute_op));
    std::vector<uint8_t> vect_val(p_buf, p_buf + sizeof(mute_op));

    GattOpsQueue::WriteCharacteristic(gatt_if,
        rendererDevice->conn_id, rendererDevice->vcs.volume_control_point_handle, vect_val,
        GATT_WRITE, VcpControllerImpl::OnMuteStatic, nullptr);
  }

  void Unmute(const RawAddress& address) {
    RendererDevice* rendererDevice = rendererDevices.FindByAddress(address);

    if (!rendererDevice) {
      LOG(WARNING) << "Device not connected to profile" << address;
      return;
    }

    if (rendererDevice->conn_id == 0) {
        LOG(INFO) << __func__ << ": GATT is not connected, skip unmute.";
        return;
    }

    if (rendererDevice->state != BTA_VCP_CONNECTED) {
      LOG(INFO)
          << __func__ << ": VCP is not connected, skip unmute, state = "
          << loghex(rendererDevice->state);
      return;
    }
    // Send the data packet
    LOG(INFO) << __func__ << ": unmute device=" << rendererDevice->address;

    rendererDevice->vcs.pending_mute_setting = VCS_UNMUTE_STATE;

    uint8_t p_buf[256];
    UnmuteOp unmute_op;
    unmute_op.op_id  = VCS_CONTROL_POINT_OP_UNMUTE;
    unmute_op.change_counter = rendererDevice->vcs.volume_state.change_counter;

    memcpy(p_buf, &unmute_op , sizeof(unmute_op));
    std::vector<uint8_t> vect_val(p_buf, p_buf + sizeof(unmute_op));

    GattOpsQueue::WriteCharacteristic(gatt_if,
        rendererDevice->conn_id, rendererDevice->vcs.volume_control_point_handle, vect_val,
        GATT_WRITE, VcpControllerImpl::OnUnmuteStatic, nullptr);
  }

  void VcpGattClose(RendererDevice* rendererDevice) {
    LOG(INFO) << __func__ << " " << rendererDevice->address;

    // Removes all registrations for connection.
    BTA_GATTC_CancelOpen(gatt_if, rendererDevice->address, false);
    rendererDevice->bg_conn = false;

    if (rendererDevice->conn_id) {
      GattOpsQueue::Clean(rendererDevice->conn_id);
      BTA_GATTC_Close(rendererDevice->conn_id);
    } else {
       // cancel pending direct connect
      BTA_GATTC_CancelOpen(gatt_if, rendererDevice->address, true);
      PostDisconnected(rendererDevice);
    }
  }

  void OnGattConnected(tGATT_STATUS status, uint16_t conn_id,
                       tGATT_IF client_if, RawAddress address,
                       tBTA_TRANSPORT transport, uint16_t mtu) {
    RendererDevice* rendererDevice = rendererDevices.FindByAddress(address);
    LOG(INFO) << __func__ <<  ": address=" << address << ", conn_id=" << conn_id;

    if (!rendererDevice) {
      LOG(WARNING) << "Closing connection to non volume renderer device, address="
                   << address;
      BTA_GATTC_Close(conn_id);
      return;
    }

    if (status != GATT_SUCCESS) {
      if (rendererDevice->bg_conn) {
        // whitelist connection failed, that's ok.
        LOG(INFO) << "bg conn failed, return immediately";
        return;
      }

      LOG(INFO) << "Failed to connect to volume renderer device";
      rendererDevices.Remove(address);
      callbacks->OnConnectionState(ConnectionState::DISCONNECTED, address);
      return;
    }

    if (rendererDevice->bg_conn) {
        LOG(INFO) << __func__ <<  ": backgound connection from: address=" << address;
    }

    rendererDevice->bg_conn = false;
    rendererDevice->conn_id = conn_id;

    /* verify bond */
    uint8_t sec_flag = 0;
    BTM_GetSecurityFlagsByTransport(address, &sec_flag, BT_TRANSPORT_LE);

    LOG(INFO) << __func__ <<  ": sec_flag =" << loghex(sec_flag);
    if (sec_flag & BTM_SEC_FLAG_ENCRYPTED) {
      /* if link has been encrypted */
      OnEncryptionComplete(address, true);
      return;
    }

    if (sec_flag & BTM_SEC_FLAG_LKEY_KNOWN) {
      /* if bonded and link not encrypted */
      sec_flag = BTM_BLE_SEC_ENCRYPT;
      BTM_SetEncryption(address, BTA_TRANSPORT_LE, vcp_controller_encryption_callback, nullptr,
                        sec_flag);
      return;
    }

    /* otherwise let it go through */
    OnEncryptionComplete(address, true);
  }

  void OnGattDisconnected(tGATT_STATUS status, uint16_t conn_id,
                          tGATT_IF client_if, RawAddress remote_bda,
                          tBTA_GATT_REASON reason) {
    RendererDevice* rendererDevice = rendererDevices.FindByConnId(conn_id);

    if (!rendererDevice) {
      LOG(WARNING) << "Skipping unknown device disconnect, conn_id="
              << loghex(conn_id);
      return;
    }
    LOG(INFO) << __func__ << ": conn_id=" << loghex(conn_id)
            << ", reason=" << loghex(reason) << ", remote_bda=" << remote_bda;

    PostDisconnected(rendererDevice);
  }

  void PostDisconnected(RendererDevice* rendererDevice) {
    LOG(INFO) << __func__ << " " << rendererDevice->address;
    rendererDevice->state = BTA_VCP_DISCONNECTED;

    if(rendererDevice->vcs.volume_state_handle != 0xFFFF) {
      BTIF_TRACE_WARNING("%s: Deregister notifications", __func__);
      BTA_GATTC_DeregisterForNotifications(gatt_if,
                         rendererDevice->address,
                         rendererDevice->vcs.volume_state_handle);
    }
    if(rendererDevice->vcs.volume_flags_handle != 0xFFFF) {
      BTIF_TRACE_WARNING("%s: Deregister notifications", __func__);
      BTA_GATTC_DeregisterForNotifications(gatt_if,
                         rendererDevice->address,
                         rendererDevice->vcs.volume_flags_handle);
    }

    if (rendererDevice->conn_id) {
      GattOpsQueue::Clean(rendererDevice->conn_id);
      rendererDevice->conn_id = 0;
    }

    callbacks->OnConnectionState(ConnectionState::DISCONNECTED, rendererDevice->address);
    rendererDevices.Remove(rendererDevice->address);
  }

  void OnEncryptionComplete(const RawAddress& address, bool success) {
    RendererDevice* rendererDevice = rendererDevices.FindByAddress(address);
    LOG(INFO) << __func__ << " " << address;

    if (!rendererDevice) {
      LOG(WARNING)  << "Skipping unknown device" << address;
      return;
    }

    if (!success) {
      LOG(ERROR) << "encryption failed";
      BTA_GATTC_Close(rendererDevice->conn_id);
      return;
    }

     BTA_GATTC_ServiceSearchRequest(rendererDevice->conn_id, &VCS_UUID);
  }

  void OnServiceSearchComplete(uint16_t conn_id, tGATT_STATUS status) {
    RendererDevice* rendererDevice = rendererDevices.FindByConnId(conn_id);
    LOG(INFO) << __func__;

    if (!rendererDevice) {
      LOG(WARNING)  << "Skipping unknown device, conn_id=" << loghex(conn_id);
      return;
    }

    if (status != GATT_SUCCESS) {
      /* close connection and report service discovery complete with error */
      LOG(ERROR) << "Service discovery failed";
      VcpGattClose(rendererDevice);
      return;
    }

    const std::vector<gatt::Service>* services = BTA_GATTC_GetServices(conn_id);

    const gatt::Service* service = nullptr;
    if (services) {
      for (const gatt::Service& tmp : *services) {
        if (tmp.uuid == Uuid::From16Bit(UUID_SERVCLASS_GATT_SERVER)) {
            /*
          LOG(INFO) << "Found UUID_SERVCLASS_GATT_SERVER, handle="
                    << loghex(tmp.handle);
          const gatt::Service* service_changed_service = &tmp;
          FindServerChangedCCCHandle(conn_id, service_changed_service);
          */
        } else if (tmp.uuid == VCS_UUID) {
          LOG(INFO) << "Found Volume Control service, handle=" << loghex(tmp.handle);
          service = &tmp;
        }
      }
    } else {
      LOG(ERROR) << "no services found for conn_id: " << conn_id;
      return;
    }

    if (!service) {
      LOG(ERROR) << "No VCS found";
      VcpGattClose(rendererDevice);
      return;
    }

    for (const gatt::Characteristic& charac : service->characteristics) {
      if (charac.uuid == VCS_VOLUME_STATE_UUID) {
        rendererDevice->vcs.volume_state_handle = charac.value_handle;

        rendererDevice->vcs.volume_state_ccc_handle =
            FindCccHandle(conn_id, charac.value_handle);
        if (!rendererDevice->vcs.volume_state_ccc_handle) {
          LOG(ERROR) << __func__ << ": cannot find volume state CCC descriptor";
          continue;
        }

        LOG(INFO) << __func__
                  << ": vcs volume_state_handle=" << loghex(charac.value_handle)
                  << ", ccc=" << loghex(rendererDevice->vcs.volume_state_ccc_handle);
      } else if (charac.uuid == VCS_VOLUME_FLAGS_UUID) {
        rendererDevice->vcs.volume_flags_handle = charac.value_handle;

        rendererDevice->vcs.volume_flags_ccc_handle =
            FindCccHandle(conn_id, charac.value_handle);
        if (!rendererDevice->vcs.volume_flags_ccc_handle) {
          LOG(ERROR) << __func__ << ": cannot find volume flags CCC descriptor";
          continue;
        }

        LOG(INFO) << __func__
                  << ": vcs volume_flags_handle=" << loghex(charac.value_handle)
                  << ", ccc=" << loghex(rendererDevice->vcs.volume_flags_ccc_handle);
      } else if (charac.uuid == VCS_VOLUME_CONTROL_POINT_UUID) {
        // store volume control point!
        rendererDevice->vcs.volume_control_point_handle = charac.value_handle;
      } else {
        LOG(WARNING) << "Unknown characteristic found:" << charac.uuid;
      }
    }

    LOG(WARNING) << "reading vcs volume_state_handle";
    GattOpsQueue::ReadCharacteristic(gatt_if,
        conn_id, rendererDevice->vcs.volume_state_handle,
        VcpControllerImpl::OnVolumeStateReadStatic, nullptr);

  }

  void OnServiceChangeEvent(const RawAddress& address) {
    RendererDevice* rendererDevice = rendererDevices.FindByAddress(address);
    if (!rendererDevice) {
      VLOG(2) << "Skipping unknown device" << address;
      return;
    }
    LOG(INFO) << __func__ << ": address=" << address;
    rendererDevice->service_changed_rcvd = true;
    GattOpsQueue::Clean(rendererDevice->conn_id);
  }

  void OnServiceDiscDoneEvent(const RawAddress& address) {
    RendererDevice* rendererDevice = rendererDevices.FindByAddress(address);
    if (!rendererDevice) {
      VLOG(2) << "Skipping unknown device" << address;
      return;
    }
    if (rendererDevice->service_changed_rcvd) {
      BTA_GATTC_ServiceSearchRequest(rendererDevice->conn_id, &VCS_UUID);
    }
  }

  void OnVolumeStateRead(uint16_t client_id, uint16_t conn_id, tGATT_STATUS status,
                 uint16_t handle, uint16_t len, uint8_t* value, void* data) {
    RendererDevice* rendererDevice = rendererDevices.FindByConnId(conn_id);

    if (!rendererDevice) {
      LOG(WARNING)  << "Skipping unknown read event, conn_id=" << loghex(conn_id);
      return;
    }

    LOG(INFO) << __func__ << " " << rendererDevice->address << ", status: " << loghex(status)
                        << ", renderer device state: " << loghex(rendererDevice->state);

    if (status != GATT_SUCCESS) {
      LOG(ERROR) << "Error reading Volume State for device" << rendererDevice->address;
    } else {
      uint8_t* p = value;
      uint8_t volume_setting;
      STREAM_TO_UINT8(volume_setting, p);
      rendererDevice->vcs.volume_state.volume_setting = volume_setting;

      uint8_t mute;
      STREAM_TO_UINT8(mute, p);
      rendererDevice->vcs.volume_state.mute = mute;

      uint8_t change_counter;
      STREAM_TO_UINT8(change_counter, p);
      rendererDevice->vcs.volume_state.change_counter = change_counter;
    }

    HandleVCSEvent(rendererDevice, VCS_VOLUME_STATE_READ_CMPL_EVT, status);
  }

  void OnVolumeFlagsRead(uint16_t client_id, uint16_t conn_id, tGATT_STATUS status,
                 uint16_t handle, uint16_t len, uint8_t* value, void* data) {
    RendererDevice* rendererDevice = rendererDevices.FindByConnId(conn_id);

    if (!rendererDevice) {
      LOG(WARNING)  << "Skipping unknown read event, conn_id=" << loghex(conn_id);
      return;
    }

    LOG(INFO) << __func__ << " " << rendererDevice->address << ", status: " << loghex(status);

    if (status != GATT_SUCCESS) {
      LOG(ERROR) << "Error reading Volume Flags for device" << rendererDevice->address;
    } else {
      uint8_t* p = value;
      uint8_t volume_flags;
      STREAM_TO_UINT8(volume_flags, p);
      rendererDevice->vcs.volume_flags = volume_flags;
    }

    HandleVCSEvent(rendererDevice, VCS_VOLUME_FLAGS_READ_CMPL_EVT, status);
  }

   void OnVolumeStateCCCWrite(uint16_t client_id, uint16_t conn_id, tGATT_STATUS status,
                                 uint16_t handle, void* data) {
     RendererDevice* rendererDevice = rendererDevices.FindByConnId(conn_id);

     if (!rendererDevice) {
       LOG(WARNING)  << "Skipping unknown read event, conn_id=" << loghex(conn_id);
       return;
     }

     LOG(INFO) << __func__ << " " << rendererDevice->address << ", status: " << loghex(status);

     HandleVCSEvent(rendererDevice, VCS_VOLUME_STATE_CCC_WRITE_CMPL_EVT, status);
   }

   void OnVolumeFlagsCCCWrite(uint16_t client_id, uint16_t conn_id, tGATT_STATUS status,
                                 uint16_t handle, void* data) {
     RendererDevice* rendererDevice = rendererDevices.FindByConnId(conn_id);

     if (!rendererDevice) {
       LOG(WARNING)  << "Skipping unknown read event, conn_id=" << loghex(conn_id);
       return;
     }

     LOG(INFO) << __func__ << " " << rendererDevice->address << ", status: " << loghex(status);

     HandleVCSEvent(rendererDevice, VCS_VOLUME_FLAGS_CCC_WRITE_CMPL_EVT, status);
   }

   void OnSetAbsVolume(uint16_t client_id, uint16_t conn_id, tGATT_STATUS status,
                                 uint16_t handle, void* data) {
     RendererDevice* rendererDevice = rendererDevices.FindByConnId(conn_id);

     if (!rendererDevice) {
       LOG(WARNING) << "Skipping unknown read event, conn_id=" << loghex(conn_id);
       return;
     }

     LOG(INFO) << __func__ << " " << rendererDevice->address << ", status: " << loghex(status);

     if (status != GATT_SUCCESS) {
       // Check for VCS Invalid Change Counter error, it may
       // conflict with GATT_NO_RESOURCES error.
       if (status == VCS_INVALID_CHANGE_COUNTER ||
           status == VCS_OPCODE_NOT_SUPPORTED) {
         LOG(ERROR) << __func__  << ": Error code: " << status
                               << " device: " << rendererDevice->address
                               << " Read Volume State to update change counter";

         rendererDevice->vcs.retry_cmd |= VCS_RETRY_SET_ABS_VOL;
         GattOpsQueue::ReadCharacteristic(gatt_if,
             conn_id, rendererDevice->vcs.volume_state_handle,
             VcpControllerImpl::OnVolumeStateReadStatic, nullptr);
       } else {
         LOG(ERROR) <<  __func__ << ": Other errors, not retry";
       }
     } else {
       rendererDevice->vcs.retry_cmd &= ~VCS_RETRY_SET_ABS_VOL;
       LOG(INFO) << "Set abs volume success " << rendererDevice->address;
     }
   }

   void OnMute(uint16_t client_id, uint16_t conn_id, tGATT_STATUS status,
                                 uint16_t handle, void* data) {
     RendererDevice* rendererDevice = rendererDevices.FindByConnId(conn_id);

     if (!rendererDevice) {
       LOG(WARNING) << "Skipping unknown read event, conn_id=" << loghex(conn_id);
       return;
     }

     LOG(INFO) << __func__ << " " << rendererDevice->address << ", status: " << loghex(status);

     if (status != GATT_SUCCESS) {
       LOG(ERROR) << "Volume State Write failed" << rendererDevice->address
                            << "Read Volume State";

       rendererDevice->vcs.retry_cmd |= VCS_RETRY_SET_MUTE_STATE;
       GattOpsQueue::ReadCharacteristic(gatt_if,
           conn_id, rendererDevice->vcs.volume_state_handle,
           VcpControllerImpl::OnVolumeStateReadStatic, nullptr);
     } else {
       LOG(INFO) << "Mute success" << rendererDevice->address;
     }

   }

   void OnUnmute(uint16_t client_id, uint16_t conn_id, tGATT_STATUS status,
                                 uint16_t handle, void* data) {
     RendererDevice* rendererDevice = rendererDevices.FindByConnId(conn_id);

     if (!rendererDevice) {
       LOG(WARNING) << "Skipping unknown read event, conn_id=" << loghex(conn_id);
       return;
     }

     LOG(INFO) << __func__ << " " << rendererDevice->address << ", status: " << loghex(status);

     if (status != GATT_SUCCESS) {
       LOG(ERROR) << "Volume State Write failed" << rendererDevice->address
                            << "Read Volume State";

       rendererDevice->vcs.retry_cmd |= VCS_RETRY_SET_MUTE_STATE;
       GattOpsQueue::ReadCharacteristic(gatt_if,
           conn_id, rendererDevice->vcs.volume_state_handle,
           VcpControllerImpl::OnVolumeStateReadStatic, nullptr);
     } else {
       LOG(INFO) << "Unmute success" << rendererDevice->address;
     }
   }

  void RetryVolumeControlOp(RendererDevice* rendererDevice) {
    LOG(INFO) << __func__ << " " << rendererDevice->address;

    if (rendererDevice->vcs.retry_cmd & VCS_RETRY_SET_ABS_VOL) {
      rendererDevice->vcs.retry_cmd &= ~VCS_RETRY_SET_ABS_VOL;
      SetAbsVolume(rendererDevice->address, rendererDevice->vcs.pending_volume_setting);
    }

    if (rendererDevice->vcs.retry_cmd & VCS_RETRY_SET_MUTE_STATE) {
      rendererDevice->vcs.retry_cmd &= ~VCS_RETRY_SET_MUTE_STATE;
      if (rendererDevice->vcs.pending_mute_setting == VCS_MUTE_STATE) {
        Mute(rendererDevice->address);
      } else {
        Unmute(rendererDevice->address);
      }
    }
  }

  static void OnVolumeStateReadStatic(uint16_t client_id, uint16_t conn_id,
                                             tGATT_STATUS status,
                                             uint16_t handle, uint16_t len,
                                             uint8_t* value, void* data) {
    if (instance)
      instance->OnVolumeStateRead(client_id, conn_id, status, handle, len, value,
                                         data);
  }

  static void OnVolumeFlagsReadStatic(uint16_t client_id, uint16_t conn_id,
                                             tGATT_STATUS status,
                                             uint16_t handle, uint16_t len,
                                             uint8_t* value, void* data) {
    if (instance)
      instance->OnVolumeFlagsRead(client_id, conn_id, status, handle, len, value,
                                         data);
  }

  static void OnVolumeStateCCCWriteStatic(uint16_t client_id, uint16_t conn_id,
                                 tGATT_STATUS status, uint16_t handle, void* data) {
    if (instance)
      instance->OnVolumeStateCCCWrite(client_id, conn_id, status, handle, data);
  }

  static void OnVolumeFlagsCCCWriteStatic(uint16_t client_id, uint16_t conn_id,
                                 tGATT_STATUS status, uint16_t handle, void* data) {
    if (instance)
      instance->OnVolumeFlagsCCCWrite(client_id, conn_id, status, handle, data);
  }

  static void OnSetAbsVolumeStatic(uint16_t client_id, uint16_t conn_id,
                                 tGATT_STATUS status, uint16_t handle, void* data) {
    if (instance)
      instance->OnSetAbsVolume(client_id, conn_id, status, handle, data);
  }

  static void OnMuteStatic(uint16_t client_id, uint16_t conn_id,
                                 tGATT_STATUS status, uint16_t handle, void* data) {
    if (instance)
      instance->OnMute(client_id, conn_id, status, handle, data);
  }

  static void OnUnmuteStatic(uint16_t client_id, uint16_t conn_id,
                                 tGATT_STATUS status, uint16_t handle, void* data) {
    if (instance)
      instance->OnUnmute(client_id, conn_id, status, handle, data);
  }


  void OnNotificationEvent(uint16_t conn_id, uint16_t handle, uint16_t len,
                           uint8_t* value) {
    RendererDevice* device = rendererDevices.FindByConnId(conn_id);

    if (!device) {
      LOG(INFO) << __func__
                << ": Skipping unknown device, conn_id=" << loghex(conn_id);
      return;
    }

    if (handle == device->vcs.volume_state_handle) {
      if ( len != sizeof(device->vcs.volume_state)) {
        LOG(ERROR) << __func__ << ": Data Length mismatch, len=" << len
                << ", expecting " << sizeof(device->vcs.volume_state);
        return;
      }

      LOG(INFO) << __func__ << " " << device->address << " volume state notification";
      memcpy(&device->vcs.volume_state, value, len);
      callbacks->OnVolumeStateChange(device->vcs.volume_state.volume_setting,
              device->vcs.volume_state.mute, device->address);
    } else if (handle == device->vcs.volume_flags_handle) {
      if ( len != sizeof(device->vcs.volume_flags)) {
        LOG(ERROR) << __func__ << ": Data Length mismatch, len=" << len
                << ", expecting " << sizeof(device->vcs.volume_flags);
        return;
      }

      LOG(INFO) << __func__ << " " << device->address << " volume flags notification";
      memcpy(&device->vcs.volume_flags, value, len);
      callbacks->OnVolumeFlagsChange(device->vcs.volume_flags, device->address);
    } else {
      LOG(INFO) << __func__ << ": Mismatched handle, "
                << loghex(device->vcs.volume_state_handle)
                << " or " << loghex(device->vcs.volume_flags_handle)
                << "!=" << loghex(handle);
      return;
    }
  }

  void OnCongestionEvent(uint16_t conn_id, bool congested) {
    RendererDevice* device = rendererDevices.FindByConnId(conn_id);
    if (!device) {
      LOG(INFO) << __func__
                << ": Skipping unknown device, conn_id=" << loghex(conn_id);
      return;
    }

    LOG(WARNING) << __func__ << ": conn_id:" << loghex(conn_id)
                             << ", congested: " << congested;
    GattOpsQueue::CongestionCallback(conn_id, congested);
  }

  void HandleVCSEvent(RendererDevice* rendererDevice, uint32_t event, tGATT_STATUS status) {
    LOG(INFO) << __func__ << " event = " << vcp_controller_handle_vcs_evt_str(event);

    if (status != GATT_SUCCESS) {
      if (rendererDevice->state == BTA_VCP_CONNECTING) {
        LOG(ERROR) << __func__ << ": Error status while VCP connecting, Close GATT for device: "
                              << rendererDevice->address;
        VcpGattClose(rendererDevice);
        return;
      } else if  (rendererDevice->state == BTA_VCP_CONNECTED) {
        LOG(ERROR) << __func__ << ": Error status while VCP is connected for device: "
                              << rendererDevice->address;
        if (rendererDevice->vcs.retry_cmd != 0) {
          rendererDevice->vcs.retry_cmd = 0;
        }
        return;
      } else {
        LOG(ERROR) << __func__ << ": Error status in disconnected or disconnecting "
                              << "Igore handle VCS Event  for device: " << rendererDevice->address;
        return;
      }
    }

    switch (event) {
      case VCS_VOLUME_STATE_READ_CMPL_EVT: {
         if (rendererDevice->state == BTA_VCP_CONNECTING) {
          LOG(WARNING) << "Setup VCP connection, reading vcs volume_flags_handle";
          GattOpsQueue::ReadCharacteristic(gatt_if,
              rendererDevice->conn_id, rendererDevice->vcs.volume_flags_handle,
              VcpControllerImpl::OnVolumeFlagsReadStatic, nullptr);
          break;
        } else if (rendererDevice->state == BTA_VCP_CONNECTED) {
          if (rendererDevice->vcs.retry_cmd != 0) {
            RetryVolumeControlOp(rendererDevice);
          }
        }
        break;
      }

      case VCS_VOLUME_FLAGS_READ_CMPL_EVT: {
        if (rendererDevice->state == BTA_VCP_CONNECTING) {
          /* Register and enable the Volume State Notification */
          tGATT_STATUS register_status;
          register_status = BTA_GATTC_RegisterForNotifications(
              gatt_if, rendererDevice->address, rendererDevice->vcs.volume_state_handle);
          if (register_status != GATT_SUCCESS) {
            LOG(ERROR) << __func__
                       << ": BTA_GATTC_RegisterForNotifications failed, status="
                       << loghex(register_status);
            VcpGattClose(rendererDevice);
            return;
          }

          std::vector<uint8_t> value(2);
          uint8_t* ptr = value.data();
          UINT16_TO_STREAM(ptr, GATT_CHAR_CLIENT_CONFIG_NOTIFICATION);
          GattOpsQueue::WriteDescriptor(gatt_if,
                  rendererDevice->conn_id, rendererDevice->vcs.volume_state_ccc_handle,
                  std::move(value), GATT_WRITE, VcpControllerImpl::OnVolumeStateCCCWriteStatic,
                  nullptr);
        }
        break;
      }

      case VCS_VOLUME_STATE_CCC_WRITE_CMPL_EVT: {
        if (rendererDevice->state == BTA_VCP_CONNECTING) {
          /* Register and enable the Volume State Notification */
          tGATT_STATUS register_status;
          register_status = BTA_GATTC_RegisterForNotifications(
              gatt_if, rendererDevice->address, rendererDevice->vcs.volume_flags_handle);
          if (register_status != GATT_SUCCESS) {
            LOG(ERROR) << __func__
                   << ": BTA_GATTC_RegisterForNotifications failed, status="
                   << loghex(register_status);
            VcpGattClose(rendererDevice);
            return;
          }

          std::vector<uint8_t> value(2);
          uint8_t* ptr = value.data();
          UINT16_TO_STREAM(ptr, GATT_CHAR_CLIENT_CONFIG_NOTIFICATION);
          GattOpsQueue::WriteDescriptor(gatt_if,
                  rendererDevice->conn_id, rendererDevice->vcs.volume_flags_ccc_handle,
                  std::move(value), GATT_WRITE, VcpControllerImpl::OnVolumeFlagsCCCWriteStatic,
                  nullptr);
        }
        break;
      }

      case VCS_VOLUME_FLAGS_CCC_WRITE_CMPL_EVT: {
        if (rendererDevice->state == BTA_VCP_CONNECTING) {
            LOG(INFO) << __func__ << ": VCP Connection Setup complete";
            rendererDevice->state = BTA_VCP_CONNECTED;
            callbacks->OnConnectionState(ConnectionState::CONNECTED, rendererDevice->address);
            callbacks->OnVolumeFlagsChange(rendererDevice->vcs.volume_flags,
                    rendererDevice->address);
            callbacks->OnVolumeStateChange(rendererDevice->vcs.volume_state.volume_setting,
                    rendererDevice->vcs.volume_state.mute, rendererDevice->address);
            break;
        }
        break;
      }

      default:
        LOG(INFO) << __func__ << ": unexpected VCS event";
        break;
    }
  }

    // Find the handle for the client characteristics configuration of a given
  // characteristics
  uint16_t FindCccHandle(uint16_t conn_id, uint16_t char_handle) {
    const gatt::Characteristic* p_char =
        BTA_GATTC_GetCharacteristic(conn_id, char_handle);
    LOG(INFO) << __func__ << " " << ", conn_id: " << conn_id << ", char_handle: " << char_handle;

    if (!p_char) {
      LOG(WARNING) << __func__ << ": No such characteristic: " << char_handle;
      return 0;
    }

    for (const gatt::Descriptor& desc : p_char->descriptors) {
      if (desc.uuid == Uuid::From16Bit(GATT_UUID_CHAR_CLIENT_CONFIG))
        return desc.handle;
    }
    return 0;
  }

  void CleanUp() {
    LOG(INFO) << __func__;
    BTA_GATTC_AppDeregister(gatt_if);
    for (RendererDevice& device : rendererDevices.devices) {
      PostDisconnected(&device);
    }

    rendererDevices.devices.clear();
  }
};

void vcp_controller_gattc_callback(tBTA_GATTC_EVT event, tBTA_GATTC* p_data) {
  LOG(INFO) << __func__ << " event = " << vcp_controller_gatt_callback_evt_str(event);

  if (p_data == nullptr) return;

  switch (event) {
    case BTA_GATTC_DEREG_EVT:
      break;

    case BTA_GATTC_OPEN_EVT: {
      if (!instance) return;
      tBTA_GATTC_OPEN& o = p_data->open;
      instance->OnGattConnected(o.status, o.conn_id, o.client_if, o.remote_bda,
                                o.transport, o.mtu);
      break;
    }

    case BTA_GATTC_CLOSE_EVT: {
      if (!instance) return;
      tBTA_GATTC_CLOSE& c = p_data->close;
      instance->OnGattDisconnected(c.status, c.conn_id, c.client_if,
                                   c.remote_bda, c.reason);
    } break;

    case BTA_GATTC_SEARCH_CMPL_EVT:
      if (!instance) return;
      instance->OnServiceSearchComplete(p_data->search_cmpl.conn_id,
                                        p_data->search_cmpl.status);
      break;

    case BTA_GATTC_NOTIF_EVT:
      if (!instance) return;
      if (!p_data->notify.is_notify || p_data->notify.len > GATT_MAX_ATTR_LEN) {
        LOG(ERROR) << __func__ << ": rejected BTA_GATTC_NOTIF_EVT. is_notify="
                   << p_data->notify.is_notify
                   << ", len=" << p_data->notify.len;
        break;
      }
      instance->OnNotificationEvent(p_data->notify.conn_id,
                                    p_data->notify.handle, p_data->notify.len,
                                    p_data->notify.value);
      break;

    case BTA_GATTC_ENC_CMPL_CB_EVT:
      if (!instance) return;
      instance->OnEncryptionComplete(p_data->enc_cmpl.remote_bda, true);
      break;

    case BTA_GATTC_SRVC_CHG_EVT:
      if (!instance) return;
      instance->OnServiceChangeEvent(p_data->remote_bda);
      break;

    case BTA_GATTC_SRVC_DISC_DONE_EVT:
      if (!instance) return;
      instance->OnServiceDiscDoneEvent(p_data->remote_bda);
      break;

    case BTA_GATTC_CONGEST_EVT:
      if (!instance) return;
      instance->OnCongestionEvent(p_data->congest.conn_id,
                                  p_data->congest.congested);
      break;

    case BTA_GATTC_SEARCH_RES_EVT:
    case BTA_GATTC_CANCEL_OPEN_EVT:
    case BTA_GATTC_CONN_UPDATE_EVT:

    default:
      break;
  }
}

void vcp_controller_encryption_callback(const RawAddress* address,
                            UNUSED_ATTR tGATT_TRANSPORT transport,
                            UNUSED_ATTR void* data, tBTM_STATUS status) {
  if (instance) {
    instance->OnEncryptionComplete(*address,
                                   status == BTM_SUCCESS ? true : false);
  }
}

void VcpController::Initialize(
            bluetooth::vcp_controller::VcpControllerCallbacks* callbacks) {
  LOG(INFO) << __func__ ;

  if (instance) {
    LOG(ERROR) << "Already initialized!";
  }

  instance = new VcpControllerImpl(callbacks);
}

bool VcpController::IsVcpControllerRunning() { return instance; }

VcpController* VcpController::Get() {
  CHECK(instance);
  return instance;
};

int VcpController::GetDeviceCount() {
  if (!instance) {
    LOG(INFO) << __func__ << ": Not initialized yet";
    return 0;
  }

  return (instance->GetDeviceCount());
}

void VcpController::CleanUp() {
  VcpControllerImpl* ptr = instance;
  instance = nullptr;

  ptr->CleanUp();

  delete ptr;
};

/*******************************************************************************
 *  Debugging functions
 ******************************************************************************/
#define CASE_RETURN_STR(const) \
  case const:                  \
    return #const;

const char* vcp_controller_gatt_callback_evt_str(uint8_t event) {
  switch (event) {
    CASE_RETURN_STR(BTA_GATTC_DEREG_EVT)
    CASE_RETURN_STR(BTA_GATTC_OPEN_EVT)
    CASE_RETURN_STR(BTA_GATTC_CLOSE_EVT)
    CASE_RETURN_STR(BTA_GATTC_SEARCH_CMPL_EVT)
    CASE_RETURN_STR(BTA_GATTC_NOTIF_EVT)
    CASE_RETURN_STR(BTA_GATTC_ENC_CMPL_CB_EVT)
    CASE_RETURN_STR(BTA_GATTC_SEARCH_RES_EVT)
    CASE_RETURN_STR(BTA_GATTC_CANCEL_OPEN_EVT)
    CASE_RETURN_STR(BTA_GATTC_SRVC_CHG_EVT)
    CASE_RETURN_STR(BTA_GATTC_CONN_UPDATE_EVT)
    CASE_RETURN_STR(BTA_GATTC_SRVC_DISC_DONE_EVT)
    CASE_RETURN_STR(BTA_GATTC_CONGEST_EVT)
    default:
      return (char*)"Unknown GATT Callback Event";
  }
}

const char* vcp_controller_handle_vcs_evt_str(uint8_t event) {
  switch (event) {
    CASE_RETURN_STR(VCS_VOLUME_STATE_READ_CMPL_EVT)
    CASE_RETURN_STR(VCS_VOLUME_FLAGS_READ_CMPL_EVT)
    CASE_RETURN_STR(VCS_VOLUME_STATE_CCC_WRITE_CMPL_EVT)
    CASE_RETURN_STR(VCS_VOLUME_FLAGS_CCC_WRITE_CMPL_EVT)
    default:
      return (char*)"Unknown handling VCS Event";
  }
}

