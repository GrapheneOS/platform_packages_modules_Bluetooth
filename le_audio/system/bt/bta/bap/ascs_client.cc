/*
 * Copyright (c) 2020, The Linux Foundation. All rights reserved.
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

#include "bta_gatt_api.h"
#include "bta_ascs_client_api.h"
#include "gattc_ops_queue.h"
#include <map>
#include <base/bind.h>
#include <base/callback.h>
#include <base/logging.h>
#include "stack/btm/btm_int.h"
#include "device/include/controller.h"

#include <vector>
#include "btif/include/btif_bap_config.h"
#include "osi/include/log.h"
#include "btif_util.h"

namespace bluetooth {
namespace bap {
namespace ascs {

using base::Closure;
using bluetooth::bap::GattOpsQueue;

Uuid ASCS_UUID               = Uuid::FromString("184E");
Uuid ASCS_SINK_ASE_UUID      = Uuid::FromString("2BC4");
Uuid ASCS_SRC_ASE_UUID       = Uuid::FromString("2BC5");
Uuid ASCS_ASE_CP_UUID        = Uuid::FromString("2BC6");

class AscsClientImpl;
AscsClientImpl* instance;

typedef uint8_t codec_type_t[5];

enum class ProfleOP {
  CONNECT,
  DISCONNECT
};

struct ProfileOperation {
  uint16_t client_id;
  ProfleOP type;
};

enum class DevState {
  IDLE = 0,
  CONNECTING,
  CONNECTED,
  DISCONNECTING
};

void ascs_gattc_callback(tBTA_GATTC_EVT event, tBTA_GATTC* p_data);
void encryption_callback(const RawAddress*, tGATT_TRANSPORT, void*,
                         tBTM_STATUS);

std::map<uint8_t, std::string> resp_codes = {
  {0x01,   "Un Supported Opcode"},
  {0x02,   "Invalid Length"},
  {0x03,   "Invalid ASE ID"},
  {0x04,   "Invalid ASE SM Transition"},
  {0x05,   "Invalid ASE Direction"},
  {0x06,   "Un Supported Audio Capabilities"},
  {0x07,   "Un Supported Config Param"},
  {0x08,   "Rejected Config Param"},
  {0x09,   "Invalid Config Param"},
  {0x0A,   "Un Supported Metadata"},
  {0x0B,   "Rejected Metadata"},
  {0x0C,   "Invalid Metadata"},
  {0x0D,   "InSufficient Resources"},
  {0x0E,   "Unspecified Error"},
};

std::map<uint8_t, std::string> reason_codes = {
  {0x01,   "Codec ID"},
  {0x02,   "Codec Specific Config"},
  {0x03,   "SDU Interval"},
  {0x04,   "Framing"},
  {0x05,   "PHY"},
  {0x06,   "Maximum SDU Size"},
  {0x07,   "RTN"},
  {0x08,   "MTL"},
  {0x09,   "PD"},
  {0x0A,   "Invalid ASE CIS Mapping"},
};

std::vector<AseParams> sink_ase_value_list, src_ase_value_list;
AseParams ase;

struct AscsDevice {
  RawAddress address;
  /* This is true only during first connection to profile, until we store the
   * device */
  bool first_connection;
  bool service_changed_rcvd;

  uint16_t conn_id;
  std::vector<Ase> sink_ase_list;
  std::vector<Ase> src_ase_list;
  uint16_t ase_cp_handle;
  uint16_t ase_cp_ccc_handle;
  uint16_t srv_changed_ccc_handle;
  bool discovery_completed;
  uint8_t num_ases_read;
  bool notifications_enabled;
  DevState state;
  bool is_congested;
  std::vector<ProfileOperation> profile_queue;
  std::vector<uint16_t> connected_client_list; //list client requested for connection
  AscsDevice(const RawAddress& address) : address(address) {}
};

class AscsDevices {
 public:
  void Add(AscsDevice device) {
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

  AscsDevice* FindByAddress(const RawAddress& address) {
    auto iter = std::find_if(devices.begin(), devices.end(),
                             [&address](const AscsDevice& device) {
                               return device.address == address;
                             });

    return (iter == devices.end()) ? nullptr : &(*iter);
  }

  AscsDevice* FindByConnId(uint16_t conn_id) {
    auto iter = std::find_if(devices.begin(), devices.end(),
                             [&conn_id](const AscsDevice& device) {
                               return device.conn_id == conn_id;
                             });

    return (iter == devices.end()) ? nullptr : &(*iter);
  }

  size_t size() { return (devices.size()); }

  std::vector<AscsDevice> devices;
};

class AscsClientImpl : public AscsClient {
 public:
  ~AscsClientImpl() override = default;

  AscsClientImpl() : gatt_client_id(BTA_GATTS_INVALID_IF) {};

  bool Register(AscsClientCallbacks *callback) {
    LOG(WARNING) << __func__  << callback;
    // looks for client is already registered
    bool is_client_registered = false;
    for (auto it : callbacks) {
      AscsClientCallbacks *pac_callback = it.second;
      if(callback == pac_callback) {
        is_client_registered = true;
        break;
      }
    }

    LOG(WARNING) << __func__ ;

    if(is_client_registered) {
      LOG(WARNING) << __func__  << " already registered";
      return false;
    }

    if(gatt_client_id == BTA_GATTS_INVALID_IF) {
      BTA_GATTC_AppRegister(
        ascs_gattc_callback,
        base::Bind(
          [](AscsClientCallbacks *callback, uint8_t client_id, uint8_t status) {
            if (status != GATT_SUCCESS) {
              LOG(ERROR) << "Can't start ASCS profile - no gatt "
                            "clients left!";
              return;
            }

            if (instance) {
              LOG(WARNING) << " ASCS gatt_client_id "
                           << instance->gatt_client_id;
              instance->gatt_client_id = client_id;
              instance->callbacks.insert(std::make_pair(
                          ++instance->ascs_client_id, callback));
              callback->OnAscsInitialized(0, instance->ascs_client_id);
            }
          },
          callback), true);
    } else {
      instance->callbacks.insert(std::make_pair(
                    ++instance->ascs_client_id, callback));
      callback->OnAscsInitialized(0, instance->ascs_client_id);
    }
    return true;
  }

  bool Deregister (uint16_t client_id) {
    bool status = false;
    auto it = callbacks.find(client_id);
    if (it != callbacks.end()) {
      callbacks.erase(it);
      if(callbacks.empty()) {
       // deregister with GATT
       LOG(WARNING) << __func__ << " Gatt de-register from ascs";
       BTA_GATTC_AppDeregister(gatt_client_id);
       gatt_client_id = BTA_GATTS_INVALID_IF;
      }
      status = true;
    }
    return status;
  }

  uint8_t GetClientCount () {
    return callbacks.size();
  }

  void Connect(uint16_t client_id, const RawAddress& address,
                         bool is_direct) override {
    LOG(WARNING) << __func__ << " " << address;
    AscsDevice *dev = ascsDevices.FindByAddress(address);
    ProfileOperation op;
    op.client_id = client_id;
    op.type = ProfleOP::CONNECT;

    if(dev == nullptr) {
      AscsDevice pac_dev(address);
      ascsDevices.Add(pac_dev);
      dev = ascsDevices.FindByAddress(address);
    }
    if (dev == nullptr) {
      LOG(ERROR) << __func__ << "dev is null";
      return;
    }

    switch(dev->state) {
      case DevState::IDLE: {
        BTA_GATTC_Open(gatt_client_id, address, is_direct,
                                           GATT_TRANSPORT_LE, false);
        dev->state = DevState::CONNECTING;
        dev->profile_queue.push_back(op);
      } break;
      case DevState::CONNECTING: {
        dev->profile_queue.push_back(op);
      } break;
      case DevState::CONNECTED: {
        auto iter = std::find_if(dev->connected_client_list.begin(),
                                 dev->connected_client_list.end(),
                             [&client_id](uint16_t id) {
                               return id == client_id;
                             });

        if(iter == dev->connected_client_list.end())
          dev->connected_client_list.push_back(client_id);

        auto it = callbacks.find(client_id);
        if (it != callbacks.end()) {
          AscsClientCallbacks *callback = it->second;
          callback->OnConnectionState(address, GattState::CONNECTED);
        }
      } break;
      case DevState::DISCONNECTING: {
        dev->profile_queue.push_back(op);
      } break;
    }
  }

  void Disconnect(uint16_t client_id, const RawAddress& address) override {
    LOG(WARNING) << __func__ << " " << address;
    AscsDevice* dev = ascsDevices.FindByAddress(address);
    if (!dev) {
      LOG(INFO) << "Device not connected to profile" << address;
      return;
    }

    ProfileOperation op;
    op.client_id = client_id;
    op.type = ProfleOP::DISCONNECT;

    switch(dev->state) {
      case DevState::CONNECTING: {
        auto iter = std::find_if(dev->profile_queue.begin(),
                                 dev->profile_queue.end(),
                             [&client_id]( ProfileOperation entry) {
                               return ((entry.type == ProfleOP::CONNECT) &&
                                      (entry.client_id == client_id));
                             });
        // If it is the last client requested for disconnect
        if(iter != dev->profile_queue.end() &&
           dev->profile_queue.size() == 1) {
          if (dev->conn_id) {
            // Removes all registrations for connection.
            BTA_GATTC_CancelOpen(dev->conn_id, address, false);
            GattOpsQueue::Clean(dev->conn_id);
            BTA_GATTC_Close(dev->conn_id);
            dev->profile_queue.push_back(op);
            dev->state = DevState::DISCONNECTING;
          } else {
            // clear the connection queue and
            // move the state to DISCONNECTING to better track
            dev->profile_queue.clear();
            dev->state = DevState::DISCONNECTING;
            dev->profile_queue.push_back(op);
          }
        } else {
           // remove the connection entry from the list
           // as the same client has requested for disconnection
           dev->profile_queue.erase(iter);
        }
      } break;
      case DevState::CONNECTED: {
        auto iter = std::find_if(dev->connected_client_list.begin(),
                                 dev->connected_client_list.end(),
                             [&client_id]( uint16_t stored_client_id) {
                               return stored_client_id == client_id;
                             });
        // if it is the last client requested for disconnection
        if(iter != dev->connected_client_list.end() &&
           dev->connected_client_list.size() == 1) {
          if (dev->conn_id) {
            // Removes all registrations for connection.
            BTA_GATTC_CancelOpen(dev->conn_id, address, false);
            GattOpsQueue::Clean(dev->conn_id);
            BTA_GATTC_Close(dev->conn_id);
            dev->profile_queue.push_back(op);
            dev->state = DevState::DISCONNECTING;
          }
        } else {
          // remove the client from connected_client_list
          dev->connected_client_list.erase(iter);
          // remove the  pending gatt ops( not the ongoing one )
          // initiated from client which requested disconnect
          // TODO and send callback as disconnected
        }
      } break;
      case DevState::DISCONNECTING: {
        dev->profile_queue.push_back(op);
      } break;
      default:
        break;
    }
  }

  void StartDiscovery(uint16_t client_id, const RawAddress& address) override {
    AscsDevice* dev = ascsDevices.FindByAddress(address);
    if (!dev) {
      LOG(INFO) << "Device not connected to profile" << address;
      return;
    }
    LOG(WARNING) << __func__ << " " << address;

    switch(dev->state) {
      case DevState::CONNECTED: {
        auto iter = std::find_if(dev->connected_client_list.begin(),
                                 dev->connected_client_list.end(),
                             [&client_id]( uint16_t stored_client_id) {
                  LOG(WARNING) << __func__ << client_id << stored_client_id;
                               return stored_client_id == client_id;
                             });
        // check if the client present in the connected client list
        if(iter == dev->connected_client_list.end()) {
           break;
        }
        // check if the discovery is already finished
        // send back the same results to the other client
        if(dev->discovery_completed && dev->notifications_enabled) {
          sink_ase_value_list.clear();
          src_ase_value_list.clear();
          auto iter = callbacks.find(client_id);
          if (iter != callbacks.end()) {
            for (auto it : dev->sink_ase_list) {
              memcpy(&ase, (void *) &it.ase_params, sizeof(ase));
              sink_ase_value_list.push_back(ase);
            }
            for (auto it : dev->src_ase_list) {
              memcpy(&ase, (void *) &it.ase_params, sizeof(ase));
              src_ase_value_list.push_back(ase);
            }

            AscsClientCallbacks *callback = iter->second;
            // send out the callback as service discovery completed
            callback->OnSearchComplete(0, dev->address,
                                          sink_ase_value_list,
                                          src_ase_value_list);
          }
          break;
        }
        // reset it
        dev->num_ases_read = 0x00;
        dev->discovery_completed = false;
        dev->notifications_enabled = false;
        // queue the request to GATT queue module
        GattOpsQueue::ServiceSearch(client_id, dev->conn_id, &ASCS_UUID);
      } break;
      default:
        break;
    }
  }

  void CodecConfig(uint16_t client_id, const RawAddress& address,
                           std::vector<AseCodecConfigOp> codec_configs) {
    AscsDevice* dev = ascsDevices.FindByAddress(address);
    std::vector<uint8_t> vect_val;
    uint8_t opcode = static_cast<uint8_t> (AseOpId::CODEC_CONFIG);
    uint8_t num_ases = codec_configs.size();
    if (!dev || (dev->state != DevState::CONNECTED)) {
      LOG(INFO) << "Device not connected to profile" << address;
      return;
    }

    LOG(INFO) << __func__ << ": BD Addr : " << address
                          << ": Num ASEs :" << loghex(num_ases);

    vect_val.insert(vect_val.end(), &opcode, &opcode + 1);
    vect_val.insert(vect_val.end(), &num_ases, &num_ases + 1);

    auto it = codec_configs.begin();
    while (it != codec_configs.end()) {
      vect_val.insert(vect_val.end(), &it->ase_id, &it->ase_id + 1);
      vect_val.insert(vect_val.end(), &it->tgt_latency, &it->tgt_latency + 1);
      vect_val.insert(vect_val.end(), &it->tgt_phy, &it->tgt_phy + 1);
      vect_val.insert(vect_val.end(), it->codec_id,
                ((uint8_t *)it->codec_id) + sizeof(codec_type_t));

      vect_val.insert(vect_val.end(), &it->codec_params_len,
                                      &it->codec_params_len + 1);
      vect_val.insert(vect_val.end(), it->codec_params.begin(),
                                      it->codec_params.end());

      LOG(INFO) << ": ASE Id = " << loghex(it->ase_id);
      LOG(INFO) << ": Target Latency = " << loghex(it->tgt_latency);
      LOG(INFO) << ": target Phy = " << loghex(it->tgt_phy);
      LOG(INFO) << ": Codec ID = " << loghex(it->codec_id[0]);
      it++;
    }

    GattOpsQueue::WriteCharacteristic(client_id, dev->conn_id,
                                      dev->ase_cp_handle, vect_val,
                                      GATT_WRITE, nullptr, nullptr);
  }

  void QosConfig(uint16_t client_id, const RawAddress& address,
                           std::vector<AseQosConfigOp> qos_configs) {
    AscsDevice* dev = ascsDevices.FindByAddress(address);
    std::vector<uint8_t> vect_val;
    uint8_t opcode = static_cast<uint8_t> (AseOpId::QOS_CONFIG);
    uint8_t num_ases = qos_configs.size();
    if (!dev || (dev->state != DevState::CONNECTED)) {
      LOG(INFO) << "Device not connected to profile" << address;
      return;
    }
    LOG(INFO) << __func__ << ": BD Addr : " << address
                          << ": Num ASEs :" << loghex(num_ases);

    vect_val.insert(vect_val.end(), &opcode, &opcode + 1);
    vect_val.insert(vect_val.end(), &num_ases, &num_ases + 1);

    auto it = qos_configs.begin();
    while (it != qos_configs.end()) {
      vect_val.insert(vect_val.end(), &it->ase_id, &it->ase_id + 1);
      vect_val.insert(vect_val.end(), &it->cig_id, &it->cig_id + 1);
      vect_val.insert(vect_val.end(), &it->cis_id, &it->cis_id + 1);

      vect_val.insert(vect_val.end(), it->sdu_interval,
                     (uint8_t *)it->sdu_interval + sizeof(sdu_interval_t));

      // test change it->framing = 0xFF;
      vect_val.insert(vect_val.end(), &it->framing, &it->framing + 1);
      vect_val.insert(vect_val.end(), &it->phy, &it->phy + 1);

      vect_val.insert(vect_val.end(), (uint8_t *) &it->max_sdu_size,
                   (uint8_t *)&it->max_sdu_size + sizeof(uint16_t));

      vect_val.insert(vect_val.end(), &it->retrans_number,
                                      &it->retrans_number + 1);

      vect_val.insert(vect_val.end(), (uint8_t *) &it->trans_latency,
                   (uint8_t *)&it->trans_latency + sizeof(uint16_t));

      vect_val.insert(vect_val.end(), it->present_delay,
                (uint8_t *)it->present_delay + sizeof(presentation_delay_t));

      LOG(INFO) << ": ASE Id = " << loghex(it->ase_id);
      LOG(INFO) << ": Cig Id = " << loghex(it->cig_id);
      LOG(INFO) << ": Cis Id = " << loghex(it->cis_id);
      LOG(INFO) << ": SDU interval ="
                << " " << loghex(it->sdu_interval[0])
                << " " << loghex(it->sdu_interval[1])
                << " " << loghex(it->sdu_interval[2]);
      LOG(INFO) << ": Framing = " << loghex(it->framing);
      LOG(INFO) << ": Phy = " << loghex(it->phy);
      LOG(INFO) << ": Max SDU size = " << loghex(it->max_sdu_size);
      LOG(INFO) << ": RTN = " << loghex(it->retrans_number);
      LOG(INFO) << ": MTL = " << loghex(it->trans_latency);
      LOG(INFO) << ": PD ="
                << " " << loghex(it->present_delay[0])
                << " " << loghex(it->present_delay[1])
                << " " << loghex(it->present_delay[2]);
      it++;
    }

    GattOpsQueue::WriteCharacteristic(client_id, dev->conn_id,
                                      dev->ase_cp_handle, vect_val,
                                      GATT_WRITE, nullptr, nullptr);
  }

  void Enable(uint16_t client_id, const RawAddress& address,
                           std::vector<AseEnableOp> enable_ops) {
    AscsDevice* dev = ascsDevices.FindByAddress(address);
    std::vector<uint8_t> vect_val;
    uint8_t opcode = static_cast<uint8_t> (AseOpId::ENABLE);
    uint8_t num_ases = enable_ops.size();
    if (!dev || (dev->state != DevState::CONNECTED)) {
      LOG(INFO) << "Device not connected to profile" << address;
      return;
    }
    LOG(INFO) << __func__ << ": BD Addr : " << address
                          << ": Num ASEs :" << loghex(num_ases);

    vect_val.insert(vect_val.end(), &opcode, &opcode + 1);
    vect_val.insert(vect_val.end(), &num_ases, &num_ases + 1);

    auto it = enable_ops.begin();
    while (it != enable_ops.end()) {
      LOG(INFO) << ": ASE Id = " << loghex(it->ase_id);
      vect_val.insert(vect_val.end(), &it->ase_id, &it->ase_id + 1);
      // test change it->meta_data_len = 0xFF;
      vect_val.insert(vect_val.end(), &it->meta_data_len,
                                      &it->meta_data_len + 1);
      vect_val.insert(vect_val.end(), it->meta_data.begin(),
                                      it->meta_data.end());
      it++;
    }

    GattOpsQueue::WriteCharacteristic(client_id, dev->conn_id,
                                      dev->ase_cp_handle, vect_val,
                                      GATT_WRITE, nullptr, nullptr);
  }

  void StartReady(uint16_t client_id, const RawAddress& address,
                           std::vector<AseStartReadyOp> start_ready_ops) {
    AscsDevice* dev = ascsDevices.FindByAddress(address);
    std::vector<uint8_t> vect_val;
    uint8_t opcode = static_cast<uint8_t> (AseOpId::START_READY);
    uint8_t num_ases = start_ready_ops.size();
    if (!dev || (dev->state != DevState::CONNECTED)) {
      LOG(INFO) << "Device not connected to profile" << address;
      return;
    }
    LOG(INFO) << __func__ << ": BD Addr : " << address
                          << ": Num ASEs :" << loghex(num_ases);

    vect_val.insert(vect_val.end(), &opcode, &opcode + 1);
    vect_val.insert(vect_val.end(), &num_ases, &num_ases + 1);

    auto it = start_ready_ops.begin();
    while (it != start_ready_ops.end()) {
      LOG(INFO) << ": ASE Id = " << loghex(it->ase_id);
      vect_val.insert(vect_val.end(), &it->ase_id, &it->ase_id + 1);
      it++;
    }

    GattOpsQueue::WriteCharacteristic(client_id, dev->conn_id,
                                      dev->ase_cp_handle, vect_val,
                                      GATT_WRITE, nullptr, nullptr);
  }

  void Disable(uint16_t client_id, const RawAddress& address,
                           std::vector<AseDisableOp> disable_ops) {
    AscsDevice* dev = ascsDevices.FindByAddress(address);
    std::vector<uint8_t> vect_val;
    uint8_t opcode = static_cast<uint8_t> (AseOpId::DISABLE);
    uint8_t num_ases = disable_ops.size();
    if (!dev || (dev->state != DevState::CONNECTED)) {
      LOG(INFO) << "Device not connected to profile" << address;
      return;
    }
    LOG(INFO) << __func__ << ": BD Addr : " << address
                          << ": Num ASEs :" << loghex(num_ases);

    vect_val.insert(vect_val.end(), &opcode, &opcode + 1);
    vect_val.insert(vect_val.end(), &num_ases, &num_ases + 1);

    auto it = disable_ops.begin();
    while (it != disable_ops.end()) {
      LOG(INFO) << ": ASE Id = " << loghex(it->ase_id);
      vect_val.insert(vect_val.end(), &it->ase_id, &it->ase_id + 1);
      it++;
    }

    GattOpsQueue::WriteCharacteristic(client_id, dev->conn_id,
                                      dev->ase_cp_handle, vect_val,
                                      GATT_WRITE, nullptr, nullptr);
  }

  void StopReady(uint16_t client_id, const RawAddress& address,
                           std::vector<AseStopReadyOp> stop_ready_ops) {
    AscsDevice* dev = ascsDevices.FindByAddress(address);
    std::vector<uint8_t> vect_val;
    uint8_t opcode = static_cast<uint8_t> (AseOpId::STOP_READY);
    uint8_t num_ases = stop_ready_ops.size();
    if (!dev || (dev->state != DevState::CONNECTED)) {
      LOG(INFO) << "Device not connected to profile" << address;
      return;
    }
    LOG(INFO) << __func__ << ": BD Addr : " << address
                          << ": Num ASEs :" << loghex(num_ases);

    vect_val.insert(vect_val.end(), &opcode, &opcode + 1);
    vect_val.insert(vect_val.end(), &num_ases, &num_ases + 1);

    auto it = stop_ready_ops.begin();
    while (it != stop_ready_ops.end()) {
      LOG(INFO) << ": ASE Id = " << loghex(it->ase_id);
      vect_val.insert(vect_val.end(), &it->ase_id, &it->ase_id + 1);
      it++;
    }

    GattOpsQueue::WriteCharacteristic(client_id, dev->conn_id,
                                      dev->ase_cp_handle, vect_val,
                                      GATT_WRITE, nullptr, nullptr);
  }

  void Release(uint16_t client_id, const RawAddress& address,
                           std::vector<AseReleaseOp> release_ops) {
    AscsDevice* dev = ascsDevices.FindByAddress(address);
    std::vector<uint8_t> vect_val;
    uint8_t opcode = static_cast<uint8_t> (AseOpId::RELEASE);
    uint8_t num_ases = release_ops.size();
    if (!dev || (dev->state != DevState::CONNECTED)) {
      LOG(INFO) << "Device not connected to profile" << address;
      return;
    }
    LOG(INFO) << __func__ << ": BD Addr : " << address
                          << ": Num ASEs :" << loghex(num_ases);

    vect_val.insert(vect_val.end(), &opcode, &opcode + 1);
    vect_val.insert(vect_val.end(), &num_ases, &num_ases + 1);

    auto it = release_ops.begin();
    while (it != release_ops.end()) {
      LOG(INFO) << ": ASE Id = " << loghex(it->ase_id);
      vect_val.insert(vect_val.end(), &it->ase_id, &it->ase_id + 1);
      it++;
    }

    GattOpsQueue::WriteCharacteristic(client_id, dev->conn_id,
                                      dev->ase_cp_handle, vect_val,
                                      GATT_WRITE, nullptr, nullptr);
  }

  void UpdateStream(uint16_t client_id, const RawAddress& address,
                    std::vector<AseUpdateMetadataOp> metadata_ops) {
    AscsDevice* dev = ascsDevices.FindByAddress(address);
    std::vector<uint8_t> vect_val;
    uint8_t opcode = static_cast<uint8_t> (AseOpId::UPDATE_META_DATA);
    uint8_t num_ases = metadata_ops.size();
    if (!dev || (dev->state != DevState::CONNECTED)) {
      LOG(INFO) << "Device not connected to profile" << address;
      return;
    }
    LOG(INFO) << __func__ << ": BD Addr : " << address
                          << ": Num ASEs :" << loghex(num_ases);

    vect_val.insert(vect_val.end(), &opcode, &opcode + 1);
    vect_val.insert(vect_val.end(), &num_ases, &num_ases + 1);

    auto it = metadata_ops.begin();
    while (it != metadata_ops.end()) {
      LOG(INFO) << ": ASE Id = " << loghex(it->ase_id);
      vect_val.insert(vect_val.end(), &it->ase_id, &it->ase_id + 1);
      vect_val.insert(vect_val.end(), &it->meta_data_len,
                                      &it->meta_data_len + 1);
      vect_val.insert(vect_val.end(), it->meta_data.begin(),
                                      it->meta_data.end());
      it++;
    }

    GattOpsQueue::WriteCharacteristic(client_id, dev->conn_id,
                                      dev->ase_cp_handle, vect_val,
                                      GATT_WRITE, nullptr, nullptr);
  }

  bool GetAseParams(const RawAddress& address, uint8_t ase_id,
                    AseParams *ase_params) {
    bool ase_found = false;
    AscsDevice* dev = ascsDevices.FindByAddress(address);
    if (!dev) {
      LOG(INFO) << "Device not connected to profile" << address;
      return false;
    }

    // first look for sink ASEs
    for (auto it = dev->sink_ase_list.begin();
              it != dev->sink_ase_list.end(); it++) {
      if (it->ase_params.ase_id == ase_id) {
        *ase_params = it->ase_params;
        ase_found = true;
        break;
      }
    }
    if(ase_found) return ase_found;

    for (auto it = dev->src_ase_list.begin();
              it != dev->src_ase_list.end(); it++) {
      if (it->ase_params.ase_id == ase_id) {
        *ase_params = it->ase_params;
        ase_found = true;
        break;
      }
    }
    return ase_found;
  }

  bool GetAseHandle(const RawAddress& address, uint8_t ase_id,
                    uint16_t *ase_handle) {
    bool ase_found = false;
    AscsDevice* dev = ascsDevices.FindByAddress(address);
    if (!dev) {
      LOG(INFO) << "Device not connected to profile" << address;
      return false;
    }

    // first look for sink ASEs
    for (auto it = dev->sink_ase_list.begin();
              it != dev->sink_ase_list.end(); it++) {
      if (it->ase_params.ase_id == ase_id) {
        *ase_handle = it->ase_handle;
        ase_found = true;
        break;
      }
    }
    if(ase_found) return ase_found;

    for (auto it = dev->src_ase_list.begin();
              it != dev->src_ase_list.end(); it++) {
      if (it->ase_params.ase_id == ase_id) {
        *ase_handle = it->ase_handle;
        ase_found = true;
        break;
      }
    }
    return ase_found;
  }

  void GetAseState(uint16_t client_id, const RawAddress& address,
                   uint8_t ase_id) {
    AscsDevice* dev = ascsDevices.FindByAddress(address);
    if (!dev) {
      LOG(INFO) << "Device not connected to profile" << address;
      return;
    }
    LOG(WARNING) << __func__ << " " << address;

    switch(dev->state) {
      case DevState::CONNECTED: {
        uint16_t ase_handle;
        auto iter = std::find_if(dev->connected_client_list.begin(),
                                 dev->connected_client_list.end(),
                             [&client_id]( uint16_t stored_client_id) {
                               return stored_client_id == client_id;
                             });
        // check if the client present in the connected client list
        if(iter == dev->connected_client_list.end()) {
           break;
        }

        // check if the discovery is already finished
        // send back the same results to the other client
        if(dev->discovery_completed && dev->notifications_enabled) {
          auto iter = callbacks.find(client_id);
          AseParams ase_params;
          if(iter != callbacks.end() &&
             GetAseParams(address, ase_id, &ase_params)) {
            AscsClientCallbacks *callback = iter->second;
            callback->OnAseState(dev->address, ase_params);
          }
          break;
        }

        if(GetAseHandle(address, ase_id, &ase_handle)) {
          // queue the request to GATT queue module
          GattOpsQueue::ReadCharacteristic(client_id, dev->conn_id,
                         ase_handle,
                         AscsClientImpl::OnReadAseStateStatic, nullptr);
        }
      } break;
      default:
        LOG(WARNING) << __func__ << "un-handled event";
        break;
    }
  }

  void OnGattConnected(tGATT_STATUS status, uint16_t conn_id,
                       tGATT_IF client_if, RawAddress address,
                       tBTA_TRANSPORT transport, uint16_t mtu) {

    AscsDevice* dev = ascsDevices.FindByAddress(address);
    if (!dev) {
      /* When device is quickly disabled and enabled in settings, this case
       * might happen */
      LOG(ERROR) << "Closing connection to non ascs device, address="
                   << address;
      BTA_GATTC_Close(conn_id);
      return;
    }
    LOG(INFO) << __func__ << ": BD Addr : " << address
                          << ": Status : " << loghex(status);

    if(dev->state == DevState::CONNECTING) {
      if (status != GATT_SUCCESS) {
        LOG(ERROR) << "Failed to connect to ASCS device";
        for (auto it = dev->profile_queue.begin();
                             it != dev->profile_queue.end();) {
          if(it->type == ProfleOP::CONNECT) {
            // get the callback and update the upper layers
            auto iter = callbacks.find(it->client_id);
            if (iter != callbacks.end()) {
              AscsClientCallbacks *callback = iter->second;
              callback->OnConnectionState(address, GattState::DISCONNECTED);
            }
            dev->profile_queue.erase(it);
          } else {
            it++;
          }
        }
        dev->state = DevState::IDLE;
        ascsDevices.Remove(address);
        return;
      }
    } else if(dev->state == DevState::DISCONNECTING) {
      // TODO will this happens ?
      // it could have called the cancel open to expect the
      // open cancelled event
      if (status != GATT_SUCCESS) {
        LOG(ERROR) << "Failed to connect to ASCS device";
        for (auto it = dev->profile_queue.begin();
                             it != dev->profile_queue.end();) {
          if(it->type == ProfleOP::DISCONNECT) {
            // get the callback and update the upper layers
            auto iter = callbacks.find(it->client_id);
            if (iter != callbacks.end()) {
              AscsClientCallbacks *callback = iter->second;
              callback->OnConnectionState(address, GattState::DISCONNECTED);
            }
            dev->profile_queue.erase(it);
          } else {
            it++;
          }
        }
        dev->state = DevState::IDLE;
        ascsDevices.Remove(address);
        return;
      } else {
        // gatt connected successfully
        // if the disconnect entry is found we need to initiate the
        // gatt disconnect. may be a race condition just after sending
        // cancel open gatt connected event received
        for (auto it = dev->profile_queue.begin();
                             it != dev->profile_queue.end();) {
          if(it->type == ProfleOP::DISCONNECT) {
            // get the callback and update the upper layers
            auto iter = callbacks.find(it->client_id);
            if (iter != callbacks.end()) {
              // Removes all registrations for connection.
              BTA_GATTC_CancelOpen(dev->conn_id, address, false);
              GattOpsQueue::Clean(dev->conn_id);
              BTA_GATTC_Close(dev->conn_id);
              break;
            }
          } else {
            it++;
          }
        }
        return;
      }
    } else {
      // return unconditinally
      return;
    }

    // success scenario code
    dev->conn_id = conn_id;

    tACL_CONN* p_acl = btm_bda_to_acl(address, BT_TRANSPORT_LE);
    if (p_acl != nullptr &&
        controller_get_interface()->supports_ble_2m_phy() &&
        HCI_LE_2M_PHY_SUPPORTED(p_acl->peer_le_features)) {
      LOG(INFO) << address << " set preferred PHY to 2M";
      BTM_BleSetPhy(address, PHY_LE_2M, PHY_LE_2M, 0);
    }

    /* verify bond */
    uint8_t sec_flag = 0;
    BTM_GetSecurityFlagsByTransport(address, &sec_flag, BT_TRANSPORT_LE);

    if (sec_flag & BTM_SEC_FLAG_ENCRYPTED) {
      /* if link has been encrypted */
      OnEncryptionComplete(address, true);
      return;
    }

    if (sec_flag & BTM_SEC_FLAG_LKEY_KNOWN) {
      /* if bonded and link not encrypted */
      sec_flag = BTM_BLE_SEC_ENCRYPT;
      LOG(WARNING) << "trying to encrypt now";
      BTM_SetEncryption(address, BTA_TRANSPORT_LE, encryption_callback, nullptr,
                        sec_flag);
      return;
    }

    /* otherwise let it go through */
    OnEncryptionComplete(address, true);
  }

  void OnGattDisconnected(tGATT_STATUS status, uint16_t conn_id,
                          tGATT_IF client_if, RawAddress remote_bda,
                          tBTA_GATT_REASON reason) {
    AscsDevice* dev = ascsDevices.FindByAddress(remote_bda);
    if (!dev) {
      LOG(ERROR) << "Skipping unknown device disconnect, conn_id="
                 << loghex(conn_id);
      return;
    }

    LOG(INFO) << __func__ << ": BD Addr : " << remote_bda
                          << ", Status : " << loghex(status)
                          << ", state: " << static_cast<int>(dev->state);

    switch(dev->state) {
      case DevState::CONNECTING: {
        // sudden disconnection
        for (auto it = dev->profile_queue.begin();
                             it != dev->profile_queue.end();) {
          if(it->type == ProfleOP::CONNECT) {
            // get the callback and update the upper layers
            auto iter = callbacks.find(it->client_id);
            if (iter != callbacks.end()) {
              AscsClientCallbacks *callback = iter->second;
              callback->OnConnectionState(remote_bda, GattState::DISCONNECTED);
            }
            it = dev->profile_queue.erase(it);
          } else {
            it++;
          }
        }
      } break;
      case DevState::CONNECTED: {
        // sudden disconnection
        for (auto it = dev->connected_client_list.begin();
                             it != dev->connected_client_list.end();) {
          // get the callback and update the upper layers
          auto iter = callbacks.find(*it);
          if (iter != callbacks.end()) {
            AscsClientCallbacks *callback = iter->second;
            callback->OnConnectionState(remote_bda, GattState::DISCONNECTED);
          }
          it = dev->connected_client_list.erase(it);
        }
      } break;
      case DevState::DISCONNECTING: {
        for (auto it = dev->profile_queue.begin();
                             it != dev->profile_queue.end();) {
          if(it->type == ProfleOP::DISCONNECT) {
            // get the callback and update the upper layers
            auto iter = callbacks.find(it->client_id);
            if (iter != callbacks.end()) {
              AscsClientCallbacks *callback = iter->second;
              callback->OnConnectionState(remote_bda, GattState::DISCONNECTED);
            }
            it = dev->profile_queue.erase(it);
          } else {
            it++;
          }
        }

        for (auto it = dev->connected_client_list.begin();
                             it != dev->connected_client_list.end();) {
          // get the callback and update the upper layers
          it = dev->connected_client_list.erase(it);
        }
        // check if the connection queue is not empty
        // if not initiate the Gatt connection
      } break;
      default:
        break;
    }

    if (dev->conn_id) {
      GattOpsQueue::Clean(dev->conn_id);
      BTA_GATTC_Close(dev->conn_id);
      dev->conn_id = 0;
    }

    dev->state = DevState::IDLE;
    ascsDevices.Remove(remote_bda);
  }

  void OnConnectionUpdateComplete(uint16_t conn_id, tBTA_GATTC* p_data) {
    AscsDevice* dev = ascsDevices.FindByConnId(conn_id);
    if (!dev) {
      LOG(ERROR) << "Skipping unknown device, conn_id=" << loghex(conn_id);
      return;
    }
  }

  void OnEncryptionComplete(const RawAddress& address, bool success) {
    AscsDevice* dev = ascsDevices.FindByAddress(address);
    if (!dev) {
      LOG(ERROR) << "Skipping unknown device" << address;
      return;
    }

    if(dev->state != DevState::CONNECTING) {
      LOG(ERROR) << "received in wrong state" << address;
      return;
    }

    LOG(INFO) << __func__ << ": BD Addr : " << address
                          << ": Status : " << loghex(success);

    // encryption failed
    if (!success) {
      for (auto it = dev->profile_queue.begin();
                           it != dev->profile_queue.end();) {
        if(it->type == ProfleOP::CONNECT) {
          // get the callback and update the upper layers
          auto iter = callbacks.find(it->client_id);
          if (iter != callbacks.end()) {
            AscsClientCallbacks *callback = iter->second;
            callback->OnConnectionState(address, GattState::DISCONNECTED);
          }
          // change the type to disconnect
          it->type = ProfleOP::DISCONNECT;
        } else {
          it++;
        }
      }
      dev->state = DevState::DISCONNECTING;
      // Removes all registrations for connection.
      BTA_GATTC_CancelOpen(dev->conn_id, address, false);
      BTA_GATTC_Close(dev->conn_id);
    } else {
      for (auto it = dev->profile_queue.begin();
                           it != dev->profile_queue.end();) {
        if(it->type == ProfleOP::CONNECT) {
          // get the callback and update the upper layers
          auto iter = callbacks.find(it->client_id);
          if (iter != callbacks.end()) {
            dev->connected_client_list.push_back(it->client_id);
            AscsClientCallbacks *callback = iter->second;
            callback->OnConnectionState(address, GattState::CONNECTED);
          }
          dev->profile_queue.erase(it);
        } else {
          it++;
        }
      }
      dev->state = DevState::CONNECTED;
    }
  }

  void OnServiceChangeEvent(const RawAddress& address) {
    AscsDevice* dev = ascsDevices.FindByAddress(address);
    if (!dev) {
      LOG(ERROR) << "Skipping unknown device" << address;
      return;
    }
    LOG(INFO) << __func__ << ": address=" << address;
    dev->first_connection = true;
    dev->service_changed_rcvd = true;
    GattOpsQueue::Clean(dev->conn_id);
  }

  void OnServiceDiscDoneEvent(const RawAddress& address) {
    AscsDevice* dev = ascsDevices.FindByAddress(address);
    if (!dev) {
      LOG(ERROR) << "Skipping unknown device" << address;
      return;
    }
    if (dev->service_changed_rcvd) {
      // queue the request to GATT queue module with dummu client id
      GattOpsQueue::ServiceSearch(0XFF, dev->conn_id, &ASCS_UUID);
    }
  }

  void OnServiceSearchComplete(uint16_t conn_id, tGATT_STATUS status) {
    AscsDevice* dev = ascsDevices.FindByConnId(conn_id);
    if (!dev) {
      LOG(ERROR) << "Skipping unknown device, conn_id=" << loghex(conn_id);
      return;
    }

    LOG(INFO) << __func__ << ": BD Addr : " << dev->address
                          << ": Status : " << loghex(status);

    uint16_t client_id = GattOpsQueue::ServiceSearchComplete(conn_id,
                                          status);
    auto iter = callbacks.find(client_id);
    if (status != GATT_SUCCESS) {
      /* close connection and report service discovery complete with error */
      LOG(ERROR) << "Service discovery failed";
      if (iter != callbacks.end()) {
        AscsClientCallbacks *callback = iter->second;
        std::vector<AseParams> ase_value_list;
        callback->OnSearchComplete(0xFF, dev->address, ase_value_list,
                                   ase_value_list);
      }
      return;
    }

    const std::vector<gatt::Service>* services = BTA_GATTC_GetServices(conn_id);

    const gatt::Service* service = nullptr;
    if (services) {
      for (const gatt::Service& tmp : *services) {
        if (tmp.uuid == Uuid::From16Bit(UUID_SERVCLASS_GATT_SERVER)) {
          LOG(INFO) << "Found UUID_SERVCLASS_GATT_SERVER, handle="
                    << loghex(tmp.handle);
          const gatt::Service* service_changed_service = &tmp;
          find_server_changed_ccc_handle(conn_id, service_changed_service);
        } else if (tmp.uuid == ASCS_UUID) {
          LOG(INFO) << "Found ASCS service, handle=" << loghex(tmp.handle);
          service = &tmp;
        }
      }
    } else {
      LOG(ERROR) << "no services found for conn_id: " << conn_id;
      return;
    }

    if (!service) {
      LOG(ERROR) << "No ASCS service found";
      if (iter != callbacks.end()) {
        AscsClientCallbacks *callback = iter->second;
        std::vector<AseParams> ase_value_list;
        callback->OnSearchComplete(0xFF, dev->address, ase_value_list,
                                   ase_value_list);
      }
      return;
    }

    for (const gatt::Characteristic& charac : service->characteristics) {
      if (charac.uuid == ASCS_SINK_ASE_UUID ||
          charac.uuid == ASCS_SRC_ASE_UUID) {
        Ase ase_info;
        ase_info.ase_handle = charac.value_handle;
        GattOpsQueue::ReadCharacteristic(
                 client_id, conn_id, charac.value_handle,
                 AscsClientImpl::OnReadOnlyPropertiesReadStatic, nullptr);

        ase_info.ase_ccc_handle =
            find_ccc_handle(conn_id, charac.value_handle);

        if(charac.uuid == ASCS_SINK_ASE_UUID) {
          dev->sink_ase_list.push_back(ase_info);
        } else if(charac.uuid == ASCS_SRC_ASE_UUID) {
          dev->src_ase_list.push_back(ase_info);
        }
        if(ase_info.ase_ccc_handle) {
          /* Register and enable the Audio Status Notification */
          tGATT_STATUS register_status;
          register_status = BTA_GATTC_RegisterForNotifications(
              conn_id, dev->address, ase_info.ase_handle);
          if (register_status != GATT_SUCCESS) {
            LOG(ERROR) << __func__
                       << ": BTA_GATTC_RegisterForNotifications failed, status="
                       << loghex(register_status);
          }
          std::vector<uint8_t> value(2);
          uint8_t* ptr = value.data();
          UINT16_TO_STREAM(ptr, GATT_CHAR_CLIENT_CONFIG_NOTIFICATION);
          GattOpsQueue::WriteDescriptor(
              client_id, conn_id, ase_info.ase_ccc_handle,
              std::move(value), GATT_WRITE, nullptr, nullptr);
        }
      } else if (charac.uuid == ASCS_ASE_CP_UUID) {
        dev->ase_cp_handle = charac.value_handle;

        dev->ase_cp_ccc_handle =
            find_ccc_handle(conn_id, charac.value_handle);
        if(dev->ase_cp_ccc_handle) {
          /* Register and enable the Audio Status Notification */
          tGATT_STATUS register_status;
          register_status = BTA_GATTC_RegisterForNotifications(
              conn_id, dev->address, dev->ase_cp_handle);
          if (register_status != GATT_SUCCESS) {
            LOG(ERROR) << __func__
                       << ": BTA_GATTC_RegisterForNotifications failed, status="
                       << loghex(register_status);
          }
          std::vector<uint8_t> value(2);
          uint8_t* ptr = value.data();
          UINT16_TO_STREAM(ptr, GATT_CHAR_CLIENT_CONFIG_NOTIFICATION);
          GattOpsQueue::WriteDescriptor(
              client_id, conn_id, dev->ase_cp_ccc_handle,
              std::move(value), GATT_WRITE, nullptr, nullptr);
        }
      } else {
         LOG(WARNING) << "Unknown characteristic found:" << charac.uuid;
      }
    }

    dev->notifications_enabled = true;

    if (dev->service_changed_rcvd) {
      dev->service_changed_rcvd = false;
    }
  }

  const char* GetAseState(uint8_t event) {
    switch (event) {
      CASE_RETURN_STR(ASE_STATE_IDLE)
      CASE_RETURN_STR(ASE_STATE_CODEC_CONFIGURED)
      CASE_RETURN_STR(ASE_STATE_QOS_CONFIGURED)
      CASE_RETURN_STR(ASE_STATE_ENABLING)
      CASE_RETURN_STR(ASE_STATE_STREAMING)
      CASE_RETURN_STR(ASE_STATE_DISABLING)
      CASE_RETURN_STR(ASE_STATE_RELEASING)
      default:
       return "Unknown State";
    }
  }

  const char* GetAseDirection(uint8_t event) {
    switch (event) {
      CASE_RETURN_STR(ASE_DIRECTION_SINK)
      CASE_RETURN_STR(ASE_DIRECTION_SOURCE)
      default:
       return "Unknown Direction";
    }
  }

  void ParseAseParams(uint8_t *p, AseParams *ase_params, uint8_t ase_dir) {
    STREAM_TO_UINT8(ase_params->ase_id, p);
    STREAM_TO_UINT8(ase_params->ase_state, p);
    LOG(INFO) << __func__
              << ": ASE Id = " << loghex(ase_params->ase_id)
              << ": ASE State = " << GetAseState(ase_params->ase_state)
              << ": ASE Direction = " << GetAseDirection(ase_dir);
    switch(ase_params->ase_state) {
      case ASE_STATE_CODEC_CONFIGURED: {
        AseCodecConfigParams *codec_config =
                         &ase_params->codec_config_params;
        STREAM_TO_UINT8(codec_config->framing, p);
        STREAM_TO_UINT8(codec_config->pref_phy, p);

        STREAM_TO_UINT8(codec_config->pref_rtn, p);
        STREAM_TO_UINT16(codec_config->mtl, p);
        STREAM_TO_ARRAY(&(codec_config->pd_min), p,
                       static_cast<int> (sizeof(presentation_delay_t)));
        STREAM_TO_ARRAY(&(codec_config->pd_max), p,
                       static_cast<int> (sizeof(presentation_delay_t)));
        STREAM_TO_ARRAY(&(codec_config->pref_pd_min), p,
                       static_cast<int> (sizeof(presentation_delay_t)));
        STREAM_TO_ARRAY(&(codec_config->pref_pd_max), p,
                       static_cast<int> (sizeof(presentation_delay_t)));
        STREAM_TO_ARRAY(&(codec_config->codec_id),
                          p, static_cast<int> (sizeof(codec_type_t)));
        STREAM_TO_UINT8(codec_config->codec_params_len, p);
        if(codec_config->codec_params_len) {
          codec_config->codec_params.resize(codec_config->codec_params_len);
          STREAM_TO_ARRAY(codec_config->codec_params.data(),
                  p, codec_config->codec_params_len);
        }
        LOG(INFO) << ": Framing = " << loghex(codec_config->framing);
        LOG(INFO) << ": Pref Phy = " << loghex(codec_config->pref_phy);
        LOG(INFO) << ": Pref RTN = " << loghex(codec_config->pref_rtn);
        LOG(INFO) << ": MTL = " << loghex(codec_config->mtl);
        LOG(INFO) << ": PD Min ="
                  << " " << loghex(codec_config->pd_min[0])
                  << " " << loghex(codec_config->pd_min[1])
                  << " " << loghex(codec_config->pd_min[2]);
        LOG(INFO) << ": PD Max ="
                  << " " << loghex(codec_config->pd_max[0])
                  << " " << loghex(codec_config->pd_max[1])
                  << " " << loghex(codec_config->pd_max[2]);
        LOG(INFO) << ": Pref PD Min ="
                  << " " << loghex(codec_config->pref_pd_min[0])
                  << " " << loghex(codec_config->pref_pd_min[1])
                  << " " << loghex(codec_config->pref_pd_min[2]);
        LOG(INFO) << ": Pref PD Max ="
                  << " " << loghex(codec_config->pref_pd_max[0])
                  << " " << loghex(codec_config->pref_pd_max[1])
                  << " " << loghex(codec_config->pref_pd_max[2]);

        LOG(INFO) << ": Codec ID = " << loghex(codec_config->codec_id[0]);
      } break;
      case ASE_STATE_QOS_CONFIGURED: {
        AseQosConfigParams *qos_config = &ase_params->qos_config_params;
        STREAM_TO_UINT8(qos_config->cig_id, p);
        STREAM_TO_UINT8(qos_config->cis_id, p);
        STREAM_TO_ARRAY(&(qos_config->sdu_interval), p,
                       static_cast<int> (sizeof(sdu_interval_t)));
        STREAM_TO_UINT8(qos_config->framing, p);
        STREAM_TO_UINT8(qos_config->phy, p);
        STREAM_TO_UINT16(qos_config->max_sdu_size, p);
        STREAM_TO_UINT8(qos_config->rtn, p);
        STREAM_TO_UINT16(qos_config->mtl, p);
        STREAM_TO_ARRAY(&(qos_config->pd), p,
                       static_cast<int> (sizeof(presentation_delay_t)));

        LOG(INFO) << ": Cig Id = " << loghex(qos_config->cig_id);
        LOG(INFO) << ": Cis Id = " << loghex(qos_config->cis_id);
        LOG(INFO) << ": SDU interval ="
                  << " " << loghex(qos_config->sdu_interval[0])
                  << " " << loghex(qos_config->sdu_interval[1])
                  << " " << loghex(qos_config->sdu_interval[2]);
        LOG(INFO) << ": Framing = " << loghex(qos_config->framing);
        LOG(INFO) << ": Phy = " << loghex(qos_config->phy);
        LOG(INFO) << ": Max SDU size = " << loghex(qos_config->max_sdu_size);
        LOG(INFO) << ": RTN = " << loghex(qos_config->rtn);
        LOG(INFO) << ": MTL = " << loghex(qos_config->mtl);
        LOG(INFO) << ": PD ="
                  << " " << loghex(qos_config->pd[0])
                  << " " << loghex(qos_config->pd[1])
                  << " " << loghex(qos_config->pd[2]);
      } break;
      case ASE_STATE_ENABLING:
      case ASE_STATE_STREAMING:
      case ASE_STATE_DISABLING: {
        AseGenericParams *gen_params = &ase_params->generic_params;
        STREAM_TO_UINT8(gen_params->cig_id, p);
        STREAM_TO_UINT8(gen_params->cis_id, p);
        STREAM_TO_UINT8(gen_params->meta_data_len, p);
        if(gen_params->meta_data_len) {
          gen_params->meta_data.resize(gen_params->meta_data_len);
          STREAM_TO_ARRAY(gen_params->meta_data.data(),
                  p, gen_params->meta_data_len);
        }
        LOG(INFO) << ": Cig Id = " << loghex(gen_params->cig_id);
        LOG(INFO) << ": Cis Id = " << loghex(gen_params->cis_id);
      } break;
    }
  }

  void ParseAseNotification(uint16_t conn_id,
                             uint16_t handle, uint16_t len, uint8_t* value ) {
    uint8_t *p = value;
    bool ase_found = false;
    AscsDevice* dev = ascsDevices.FindByConnId(conn_id);
    if (!dev) {
      LOG(INFO) << __func__
                << ": Skipping unknown device, conn_id=" << loghex(conn_id);
      return;
    }

    for (auto it = dev->sink_ase_list.begin();
              it != dev->sink_ase_list.end(); it++) {
      if (it->ase_handle == handle) {
        LOG(INFO) << __func__ << ": BD Addr : " << dev->address;
        ParseAseParams(p, &it->ase_params, ASE_DIRECTION_SINK);
        for (auto iter : callbacks) {
          AscsClientCallbacks *ascs_callback = iter.second;
          ascs_callback->OnAseState(dev->address, it->ase_params);
        }
        ase_found = true;
        break;
      }
    }
    if(!ase_found) {
      for (auto it = dev->src_ase_list.begin();
                it != dev->src_ase_list.end(); it++) {
        if (it->ase_handle == handle) {
          LOG(INFO) << __func__ << ": BD Addr : " << dev->address;
          ParseAseParams(p, &it->ase_params,ASE_DIRECTION_SOURCE);
          for (auto iter : callbacks) {
            AscsClientCallbacks *ascs_callback = iter.second;
            ascs_callback->OnAseState(dev->address, it->ase_params);
          }
          ase_found = true;
          break;
        }
      }
    }
  }

  void OnNotificationEvent(uint16_t conn_id, uint16_t handle, uint16_t len,
                           uint8_t* value) {
    uint8_t* p = value;
    AscsDevice* dev = ascsDevices.FindByConnId(conn_id);
    if (!dev) {
      LOG(INFO) << __func__
                << ": Skipping unknown device, conn_id=" << loghex(conn_id);
      return;
    }

    // check if the notification is for ASEs
    if( dev->ase_cp_handle == handle) { // control point notification
      AseCpNotification cp_notification;
      STREAM_TO_UINT8(cp_notification.ase_opcode, p);
      STREAM_TO_UINT8(cp_notification.num_ases, p);
      uint8_t num_ases = cp_notification.num_ases;
      std::vector<AseOpStatus> ase_cp_notify_list;
      AseOpStatus status;
      bool notify = false;

      while(num_ases--) {
        STREAM_TO_UINT8(status.ase_id, p);
        STREAM_TO_UINT8(status.resp_code, p);
        STREAM_TO_UINT8(status.reason, p);
        if(status.resp_code) {
          LOG(ERROR) << __func__
                     << ": ASE Id = " << loghex(status.ase_id)
                     << ": Resp code = " << resp_codes[status.resp_code];
          if(status.reason) {
            LOG(ERROR) << ": Reason = " << reason_codes[status.reason];
          }
          notify = true;
        }

        ase_cp_notify_list.push_back(status);
      }
      if(notify) {
        for (auto iter : callbacks) {
          AscsClientCallbacks *ascs_callback = iter.second;
          LOG(ERROR) << __func__ << " ASE Operation failed";
          ascs_callback->OnAseOpFailed(dev->address,
                                       (AseOpId) cp_notification.ase_opcode,
                                       ase_cp_notify_list);
        }
      }
    } else {
      ParseAseNotification(conn_id, handle, len, value);
    }
  }


  void OnCongestionEvent(uint16_t conn_id, bool congested) {
    AscsDevice* dev = ascsDevices.FindByConnId(conn_id);
    if (!dev) {
      LOG(INFO) << __func__
                << ": Skipping unknown device, conn_id=" << loghex(conn_id);
      return;
    }

    LOG(WARNING) << __func__ << ": conn_id:" << loghex(conn_id)
                             << ", congested: " << congested;
    dev->is_congested = congested;
    GattOpsQueue::CongestionCallback(conn_id, congested);
  }

  void OnReadAseState(uint16_t client_id,
                            uint16_t conn_id, tGATT_STATUS status,
                            uint16_t handle, uint16_t len, uint8_t* value,
                            void* data) {

    AscsDevice* dev = ascsDevices.FindByConnId(conn_id);
    if (!dev) {
      LOG(ERROR) << __func__ << "unknown conn_id=" << loghex(conn_id);
      return;
    }
    LOG(WARNING) << __func__;

    // check if the notification is for ASEs
    ParseAseNotification(conn_id, handle, len, value);
  }

  void OnReadOnlyPropertiesRead(uint16_t client_id,
                                uint16_t conn_id, tGATT_STATUS status,
                                uint16_t handle, uint16_t len,
                                uint8_t *value, void* data) {
    AscsDevice* dev = ascsDevices.FindByConnId(conn_id);
    uint8_t *p = value;
    if (!dev) {
      LOG(ERROR) << __func__ << "unknown conn_id=" << loghex(conn_id);
      return;
    }

    for (auto it = dev->sink_ase_list.begin();
              it != dev->sink_ase_list.end(); it++) {
      if (it->ase_handle == handle) {
        dev->num_ases_read++;
        ParseAseParams(p, &it->ase_params, ASE_DIRECTION_SINK);
        break;
      }
    }

    for (auto it = dev->src_ase_list.begin();
              it != dev->src_ase_list.end(); it++) {
      if (it->ase_handle == handle) {
        dev->num_ases_read++;
        ParseAseParams(p, &it->ase_params, ASE_DIRECTION_SOURCE);
        break;
      }
    }

    LOG(INFO) << __func__ << ": num_ases_read : "
                          << loghex(dev->num_ases_read);

    if(dev->num_ases_read == (dev->sink_ase_list.size() +
                              dev->src_ase_list.size())) {
      sink_ase_value_list.clear();
      src_ase_value_list.clear();
      dev->discovery_completed = true;
      // Now update using service discovery callback
      auto iter = callbacks.find(client_id);
      if (iter != callbacks.end()) {
        for (auto it : dev->sink_ase_list) {
          memcpy(&ase, (void *) &it.ase_params, sizeof(ase));
          sink_ase_value_list.push_back(ase);
        }
        for (auto it : dev->src_ase_list) {
          memcpy(&ase, (void *) &it.ase_params, sizeof(ase));
          src_ase_value_list.push_back(ase);
        }
        AscsClientCallbacks *callback = iter->second;
        // check if all ascs characteristics are read
        // send out the callback as service discovery completed
        callback->OnSearchComplete(0, dev->address,
                                      sink_ase_value_list,
                                      src_ase_value_list);
      }
    }
  }

  static void OnReadOnlyPropertiesReadStatic(uint16_t client_id,
                                             uint16_t conn_id,
                                             tGATT_STATUS status,
                                             uint16_t handle, uint16_t len,
                                             uint8_t* value, void* data) {
    if (instance)
      instance->OnReadOnlyPropertiesRead(client_id, conn_id, status, handle,
                                         len, value, data);
  }

  static void OnReadAseStateStatic(uint16_t client_id,
                             uint16_t conn_id,
                             tGATT_STATUS status,
                             uint16_t handle, uint16_t len,
                             uint8_t* value, void* data) {
    if (instance)
      instance->OnReadAseState(client_id, conn_id, status, handle,
                               len, value, data);
  }

 private:
  uint8_t gatt_client_id = BTA_GATTS_INVALID_IF;
  uint16_t ascs_client_id = 0;
  AscsDevices ascsDevices;
  // client id to callbacks mapping
  std::map<uint16_t, AscsClientCallbacks *> callbacks;

  void find_server_changed_ccc_handle(uint16_t conn_id,
                                      const gatt::Service* service) {
    AscsDevice* ascsDevice = ascsDevices.FindByConnId(conn_id);
    if (!ascsDevice) {
      LOG(ERROR) << "Skipping unknown device, conn_id=" << loghex(conn_id);
      return;
    }
    for (const gatt::Characteristic& charac : service->characteristics) {
      if (charac.uuid == Uuid::From16Bit(GATT_UUID_GATT_SRV_CHGD)) {
        ascsDevice->srv_changed_ccc_handle =
            find_ccc_handle(conn_id, charac.value_handle);
        if (!ascsDevice->srv_changed_ccc_handle) {
          LOG(ERROR) << __func__
                     << ": cannot find service changed CCC descriptor";
          continue;
        }
        LOG(INFO) << __func__ << " service_changed_ccc="
                  << loghex(ascsDevice->srv_changed_ccc_handle);
        break;
      }
    }
  }

  // Find the handle for the client characteristics configuration of a given
  // characteristics
  uint16_t find_ccc_handle(uint16_t conn_id, uint16_t char_handle) {
    const gatt::Characteristic* p_char =
        BTA_GATTC_GetCharacteristic(conn_id, char_handle);

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
};

const char* get_gatt_event_name(uint32_t event) {
  switch (event) {
    CASE_RETURN_STR(BTA_GATTC_DEREG_EVT)
    CASE_RETURN_STR(BTA_GATTC_OPEN_EVT)
    CASE_RETURN_STR(BTA_GATTC_CLOSE_EVT)
    CASE_RETURN_STR(BTA_GATTC_SEARCH_CMPL_EVT)
    CASE_RETURN_STR(BTA_GATTC_NOTIF_EVT)
    CASE_RETURN_STR(BTA_GATTC_ENC_CMPL_CB_EVT)
    CASE_RETURN_STR(BTA_GATTC_CONN_UPDATE_EVT)
    CASE_RETURN_STR(BTA_GATTC_SRVC_CHG_EVT)
    CASE_RETURN_STR(BTA_GATTC_SRVC_DISC_DONE_EVT)
    CASE_RETURN_STR(BTA_GATTC_CONGEST_EVT)
    default:
      return "Unknown Event";
  }
}

void ascs_gattc_callback(tBTA_GATTC_EVT event, tBTA_GATTC* p_data) {
  if (p_data == nullptr || !instance) return;

  LOG(INFO) << __func__ << ": Event : " << get_gatt_event_name(event);

  switch (event) {
    case BTA_GATTC_DEREG_EVT:
      break;

    case BTA_GATTC_OPEN_EVT: {
      tBTA_GATTC_OPEN& o = p_data->open;
      instance->OnGattConnected(o.status, o.conn_id, o.client_if, o.remote_bda,
                                o.transport, o.mtu);
      break;
    }

    case BTA_GATTC_CLOSE_EVT: {
      tBTA_GATTC_CLOSE& c = p_data->close;
      instance->OnGattDisconnected(c.status, c.conn_id, c.client_if,
                                   c.remote_bda, c.reason);
    } break;

    case BTA_GATTC_SEARCH_CMPL_EVT:
      instance->OnServiceSearchComplete(p_data->search_cmpl.conn_id,
                                        p_data->search_cmpl.status);
      break;

    case BTA_GATTC_NOTIF_EVT:
      if (!p_data->notify.is_notify ||
           p_data->notify.len > GATT_MAX_ATTR_LEN) {
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
      instance->OnEncryptionComplete(p_data->enc_cmpl.remote_bda, true);
      break;

    case BTA_GATTC_CONN_UPDATE_EVT:
      instance->OnConnectionUpdateComplete(p_data->conn_update.conn_id, p_data);
      break;

    case BTA_GATTC_SRVC_CHG_EVT:
      instance->OnServiceChangeEvent(p_data->remote_bda);
      break;

    case BTA_GATTC_SRVC_DISC_DONE_EVT:
      instance->OnServiceDiscDoneEvent(p_data->remote_bda);
      break;
    case BTA_GATTC_CONGEST_EVT:
      instance->OnCongestionEvent(p_data->congest.conn_id,
                                  p_data->congest.congested);
      break;
    default:
      break;
  }
}

void encryption_callback(const RawAddress* address, tGATT_TRANSPORT, void*,
                         tBTM_STATUS status) {
  if (instance) {
    instance->OnEncryptionComplete(*address,
                                   status == BTM_SUCCESS ? true : false);
  }
}

void AscsClient::Init(AscsClientCallbacks* callbacks) {
  if (instance) {
    instance->Register(callbacks);
  } else {
    instance = new AscsClientImpl();
    instance->Register(callbacks);
  }
}

void AscsClient::CleanUp(uint16_t client_id) {
  if(instance->GetClientCount()) {
    instance->Deregister(client_id);
    if(!instance->GetClientCount()) {
      delete instance;
      instance = nullptr;
    }
  }
}

AscsClient* AscsClient::Get() {
  CHECK(instance);
  return instance;
}

}  // namespace ascs
}  // namespace bap
}  // namespace bluetooth
