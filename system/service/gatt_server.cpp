//
//  Copyright (C) 2015 Google, Inc.
//
//  Licensed under the Apache License, Version 2.0 (the "License");
//  you may not use this file except in compliance with the License.
//  You may obtain a copy of the License at:
//
//  http://www.apache.org/licenses/LICENSE-2.0
//
//  Unless required by applicable law or agreed to in writing, software
//  distributed under the License is distributed on an "AS IS" BASIS,
//  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//  See the License for the specific language governing permissions and
//  limitations under the License.
//
#include "gatt_server.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <condition_variable>
#include <map>
#include <memory>
#include <mutex>
#include <set>
#include <string>
#include <unordered_map>
#include <vector>

#define LOG_TAG "GattServer"
#include "osi/include/log.h"

#include "core_stack.h"
#include "hardware/bluetooth.h"
#include "hardware/bt_gatt.h"
#include "logging_helpers.h"
#include "osi/include/osi.h"
#include "uuid.h"

namespace {

const size_t kMaxGattAttributeSize = 512;
// TODO(icoolidge): Difficult to generalize without knowing how many attributes.
const int kNumBlueDroidHandles = 60;

// TODO(icoolidge): Support multiple instances
static bluetooth::gatt::ServerInternals *internal = nullptr;

enum { kPipeReadEnd = 0, kPipeWriteEnd = 1, kPipeNumEnds = 2 };

}  // namespace

namespace bluetooth {
namespace gatt {

struct Characteristic {
  Uuid uuid;
  int blob_section;
  std::vector<uint8_t> blob;

  // Support synchronized blob updates by latching under mutex.
  std::vector<uint8_t> next_blob;
  bool next_blob_pending;
  bool notify;
};

struct ServerInternals {
  ServerInternals();
  ~ServerInternals();
  int Initialize(CoreStack *bt);

  // This maps API attribute UUIDs to BlueDroid handles.
  std::map<Uuid, int> uuid_to_attribute;

  // The attribute cache, indexed by BlueDroid handles.
  std::unordered_map<int, Characteristic> characteristics;

  // Associate a control attribute with its value attribute.
  std::unordered_map<int, int> controlled_blobs;

  ScanResults scan_results;

  Uuid last_write;
  const btgatt_interface_t *gatt;
  int server_if;
  int client_if;
  int service_handle;
  btgatt_srvc_id_t service_id;
  std::set<int> connections;

  std::mutex lock;
  std::condition_variable api_synchronize;
  int pipefd[kPipeNumEnds];
};

}  // namespace gatt
}  // namespace bluetooth

namespace {

/** Callback invoked in response to register_server */
void RegisterServerCallback(int status, int server_if, bt_uuid_t *app_uuid) {
  LOG_INFO("%s: status:%d server_if:%d app_uuid:%p", __func__, status,
           server_if, app_uuid);

  internal->server_if = server_if;

  btgatt_srvc_id_t service_id;
  service_id.id.uuid = *app_uuid;
  service_id.id.inst_id = 0;
  service_id.is_primary = true;

  bt_status_t btstat = internal->gatt->server->add_service(
      server_if, &service_id, kNumBlueDroidHandles);
}

void ServiceAddedCallback(int status, int server_if, btgatt_srvc_id_t *srvc_id,
                          int srvc_handle) {
  LOG_INFO("%s: status:%d server_if:%d gatt_srvc_id:%u srvc_handle:%d",
           __func__, status, server_if, srvc_id->id.inst_id, srvc_handle);

  std::lock_guard<std::mutex> lock(internal->lock);
  internal->server_if = server_if;
  internal->service_handle = srvc_handle;
  internal->service_id = *srvc_id;
  // This finishes the Initialize call.
  internal->api_synchronize.notify_one();
}

void RequestReadCallback(int conn_id, int trans_id, bt_bdaddr_t *bda,
                         int attr_handle, int attribute_offset_octets,
                         bool is_long) {
  std::lock_guard<std::mutex> lock(internal->lock);

  bluetooth::gatt::Characteristic &ch = internal->characteristics[attr_handle];

  // Latch next_blob to blob on a 'fresh' read.
  if (ch.next_blob_pending && attribute_offset_octets == 0 &&
      ch.blob_section == 0) {
    std::swap(ch.blob, ch.next_blob);
    ch.next_blob_pending = false;
  }

  const size_t blob_offset_octets =
      std::min(ch.blob.size(), ch.blob_section * kMaxGattAttributeSize);
  const size_t blob_remaining = ch.blob.size() - blob_offset_octets;
  const size_t attribute_size = std::min(kMaxGattAttributeSize, blob_remaining);

  std::string addr(BtAddrString(bda));
  LOG_INFO(
      "%s: connection:%d (%s) reading attr:%d attribute_offset_octets:%d "
      "blob_section:%u (is_long:%u)",
      __func__, conn_id, addr.c_str(), attr_handle, attribute_offset_octets,
      ch.blob_section, is_long);

  btgatt_response_t response;
  response.attr_value.len = 0;

  if (attribute_offset_octets < static_cast<int>(attribute_size)) {
    std::copy(ch.blob.begin() + blob_offset_octets + attribute_offset_octets,
              ch.blob.begin() + blob_offset_octets + attribute_size,
              response.attr_value.value);
    response.attr_value.len = attribute_size - attribute_offset_octets;
  }

  response.attr_value.handle = attr_handle;
  response.attr_value.offset = attribute_offset_octets;
  response.attr_value.auth_req = 0;
  internal->gatt->server->send_response(conn_id, trans_id, 0, &response);
}

void RequestWriteCallback(int conn_id, int trans_id, bt_bdaddr_t *bda,
                          int attr_handle, int attribute_offset, int length,
                          bool need_rsp, bool is_prep, uint8_t *value) {
  std::string addr(BtAddrString(bda));
  LOG_INFO(
      "%s: connection:%d (%s:trans:%d) write attr:%d attribute_offset:%d "
      "length:%d "
      "need_resp:%u is_prep:%u",
      __func__, conn_id, addr.c_str(), trans_id, attr_handle, attribute_offset,
      length, need_rsp, is_prep);

  std::lock_guard<std::mutex> lock(internal->lock);

  bluetooth::gatt::Characteristic &ch = internal->characteristics[attr_handle];

  ch.blob.resize(attribute_offset + length);

  std::copy(value, value + length, ch.blob.begin() + attribute_offset);

  auto target_blob = internal->controlled_blobs.find(attr_handle);
  // If this is a control attribute, adjust offset of the target blob.
  if (target_blob != internal->controlled_blobs.end() && ch.blob.size() == 1u) {
    internal->characteristics[target_blob->second].blob_section = ch.blob[0];
    LOG_INFO("%s: updating attribute %d blob_section to %u", __func__,
             target_blob->second, ch.blob[0]);
  } else if (!is_prep) {
    // This is a single frame characteristic write.
    // Notify upwards because we're done now.
    const bluetooth::Uuid::Uuid128Bit &attr_uuid = ch.uuid.GetFullBigEndian();
    int status = write(internal->pipefd[kPipeWriteEnd], attr_uuid.data(),
                       attr_uuid.size());
    if (-1 == status)
      LOG_ERROR("%s: write failed: %s", __func__, strerror(errno));
  } else {
    // This is a multi-frame characteristic write.
    // Wait for an 'RequestExecWriteCallback' to notify completion.
    internal->last_write = ch.uuid;
  }

  // Respond only if needed.
  if (!need_rsp) return;

  btgatt_response_t response;
  response.attr_value.handle = attr_handle;
  response.attr_value.offset = attribute_offset;
  response.attr_value.len = length;
  response.attr_value.auth_req = 0;
  internal->gatt->server->send_response(conn_id, trans_id, 0, &response);
}

void RequestExecWriteCallback(int conn_id, int trans_id, bt_bdaddr_t *bda,
                              int exec_write) {
  std::string addr(BtAddrString(bda));
  LOG_INFO("%s: connection:%d (%s:trans:%d) exec_write:%d", __func__, conn_id,
           addr.c_str(), trans_id, exec_write);

  if (!exec_write)
    return;

  std::lock_guard<std::mutex> lock(internal->lock);
  // Communicate the attribute UUID as notification of a write update.
  const bluetooth::Uuid::Uuid128Bit uuid =
      internal->last_write.GetFullBigEndian();
  int status = write(internal->pipefd[kPipeWriteEnd], uuid.data(), uuid.size());
  if (-1 == status)
    LOG_ERROR("%s: write failed: %s", __func__, strerror(errno));
}

void ConnectionCallback(int conn_id, int server_if, int connected,
                        bt_bdaddr_t *bda) {
  std::string addr(BtAddrString(bda));
  LOG_INFO("%s: connection:%d server_if:%d connected:%d addr:%s", __func__,
           conn_id, server_if, connected, addr.c_str());
  if (connected == 1) {
    internal->connections.insert(conn_id);
  } else if (connected == 0) {
    internal->connections.erase(conn_id);
  }
}

void CharacteristicAddedCallback(int status, int server_if, bt_uuid_t *uuid,
                                 int srvc_handle, int char_handle) {
  LOG_INFO("%s: status:%d server_if:%d service_handle:%d char_handle:%d",
           __func__, status, server_if, srvc_handle, char_handle);

  bluetooth::Uuid id(*uuid);

  std::lock_guard<std::mutex> lock(internal->lock);

  internal->uuid_to_attribute[id] = char_handle;
  internal->characteristics[char_handle].uuid = id;
  internal->characteristics[char_handle].blob_section = 0;

  // This terminates an AddCharacteristic.
  internal->api_synchronize.notify_one();
}

void DescriptorAddedCallback(int status, int server_if, bt_uuid_t *uuid,
                             int srvc_handle, int descr_handle) {
  LOG_INFO(
      "%s: status:%d server_if:%d service_handle:%d uuid[0]:%u "
      "descr_handle:%d",
      __func__, status, server_if, srvc_handle, uuid->uu[0], descr_handle);
}

void ServiceStartedCallback(int status, int server_if, int srvc_handle) {
  LOG_INFO("%s: status:%d server_if:%d srvc_handle:%d", __func__, status,
           server_if, srvc_handle);

  // The UUID provided here is unimportant, and is only used to satisfy
  // BlueDroid.
  // It must be different than any other registered UUID.
  bt_uuid_t client_id = internal->service_id.id.uuid;
  ++client_id.uu[15];

  bt_status_t btstat = internal->gatt->client->register_client(&client_id);
  if (btstat != BT_STATUS_SUCCESS) {
    LOG_ERROR("%s: Failed to register client", __func__);
  }
}

void RegisterClientCallback(int status, int client_if, bt_uuid_t *app_uuid) {
  LOG_INFO("%s: status:%d client_if:%d uuid[0]:%u", __func__, status,
           client_if, app_uuid->uu[0]);
  internal->client_if = client_if;

  // Setup our advertisement. This has no callback.
  bt_status_t btstat = internal->gatt->client->set_adv_data(
      client_if, false, /* beacon, not scan response */
      false,            /* name */
      false,            /* no txpower */
      2, 2,             /* interval */
      0,                /* appearance */
      0, nullptr,       /* no mfg data */
      0, nullptr,       /* no service data */
      0, nullptr /* no service id yet */);
  if (btstat != BT_STATUS_SUCCESS) {
    LOG_ERROR("Failed to set advertising data");
    return;
  }

  // TODO(icoolidge): Deprecated, use multi-adv interface.
  // This calls back to ListenCallback.
  btstat = internal->gatt->client->listen(client_if, true);
  if (btstat != BT_STATUS_SUCCESS) {
    LOG_ERROR("Failed to start listening");
  }
}

void ListenCallback(int status, int client_if) {
  LOG_INFO("%s: status:%d client_if:%d", __func__, status, client_if);
  // This terminates a Start call.
  std::lock_guard<std::mutex> lock(internal->lock);
  internal->api_synchronize.notify_one();
}

void ServiceStoppedCallback(int status, int server_if, int srvc_handle) {
  LOG_INFO("%s: status:%d server_if:%d srvc_handle:%d", __func__, status,
           server_if, srvc_handle);
  // This terminates a Stop call.
  // TODO(icoolidge): make this symmetric with start
  std::lock_guard<std::mutex> lock(internal->lock);
  internal->api_synchronize.notify_one();
}

void ScanResultCallback(bt_bdaddr_t *bda, int rssi, uint8_t *adv_data) {
  std::string addr(BtAddrString(bda));
  (void)adv_data;
  std::lock_guard<std::mutex> lock(internal->lock);
  internal->scan_results[addr] = rssi;
}

void ClientConnectCallback(int conn_id, int status, int client_if,
                           bt_bdaddr_t *bda) {
  std::string addr(BtAddrString(bda));
  LOG_INFO("%s: conn_id:%d status:%d client_if:%d %s", __func__, conn_id,
           status, client_if, addr.c_str());
}

void ClientDisconnectCallback(int conn_id, int status, int client_if,
                              bt_bdaddr_t *bda) {
  std::string addr(BtAddrString(bda));
  LOG_INFO("%s: conn_id:%d status:%d client_if:%d %s", __func__, conn_id,
           status, client_if, addr.c_str());
}

void IndicationSentCallback(UNUSED_ATTR int conn_id,
                            UNUSED_ATTR int status) {
  // TODO(icoolidge): what to do
}

void ResponseConfirmationCallback(UNUSED_ATTR int status,
                                  UNUSED_ATTR int handle) {
  // TODO(icoolidge): what to do
}

const btgatt_server_callbacks_t gatt_server_callbacks = {
    RegisterServerCallback,
    ConnectionCallback,
    ServiceAddedCallback,
    nullptr, /* included_service_added_cb */
    CharacteristicAddedCallback,
    DescriptorAddedCallback,
    ServiceStartedCallback,
    ServiceStoppedCallback,
    nullptr, /* service_deleted_cb */
    RequestReadCallback,
    RequestWriteCallback,
    RequestExecWriteCallback,
    ResponseConfirmationCallback,
    IndicationSentCallback,
    nullptr, /* congestion_cb*/
    nullptr, /* mtu_changed_cb */
};

// TODO(eisenbach): Refactor GATT interface to not require servers
// to refer to the client interface.
const btgatt_client_callbacks_t gatt_client_callbacks = {
    RegisterClientCallback,
    ScanResultCallback,
    ClientConnectCallback,
    ClientDisconnectCallback,
    nullptr, /* search_complete_cb; */
    nullptr, /* search_result_cb; */
    nullptr, /* get_characteristic_cb; */
    nullptr, /* get_descriptor_cb; */
    nullptr, /* get_included_service_cb; */
    nullptr, /* register_for_notification_cb; */
    nullptr, /* notify_cb; */
    nullptr, /* read_characteristic_cb; */
    nullptr, /* write_characteristic_cb; */
    nullptr, /* read_descriptor_cb; */
    nullptr, /* write_descriptor_cb; */
    nullptr, /* execute_write_cb; */
    nullptr, /* read_remote_rssi_cb; */
    ListenCallback,
    nullptr, /* configure_mtu_cb; */
    nullptr, /* scan_filter_cfg_cb; */
    nullptr, /* scan_filter_param_cb; */
    nullptr, /* scan_filter_status_cb; */
    nullptr, /* multi_adv_enable_cb */
    nullptr, /* multi_adv_update_cb; */
    nullptr, /* multi_adv_data_cb*/
    nullptr, /* multi_adv_disable_cb; */
    nullptr, /* congestion_cb; */
    nullptr, /* batchscan_cfg_storage_cb; */
    nullptr, /* batchscan_enb_disable_cb; */
    nullptr, /* batchscan_reports_cb; */
    nullptr, /* batchscan_threshold_cb; */
    nullptr, /* track_adv_event_cb; */
};

const btgatt_callbacks_t gatt_callbacks = {
    /** Set to sizeof(btgatt_callbacks_t) */
    sizeof(btgatt_callbacks_t),

    /** GATT Client callbacks */
    &gatt_client_callbacks,

    /** GATT Server callbacks */
    &gatt_server_callbacks};

}  // namespace

namespace bluetooth {
namespace gatt {

int ServerInternals::Initialize(CoreStack *bt) {
  // Get the interface to the GATT profile.
  gatt = reinterpret_cast<const btgatt_interface_t *>(
      bt->GetInterface(BT_PROFILE_GATT_ID));
  if (!gatt) {
    LOG_ERROR("Error getting GATT interface");
    return -1;
  }

  bt_status_t btstat = gatt->init(&gatt_callbacks);
  if (btstat != BT_STATUS_SUCCESS) {
    LOG_ERROR("Failed to initialize gatt interface");
    return -1;
  }

  int status = pipe(pipefd);
  if (status == -1) {
    LOG_ERROR("pipe creation failed: %s", strerror(errno));
    return -1;
  }

  return 0;
}

ServerInternals::ServerInternals()
    : gatt(nullptr),
      server_if(0),
      client_if(0),
      service_handle(0),
      pipefd{INVALID_FD, INVALID_FD} {}

ServerInternals::~ServerInternals() {
  if (pipefd[0] != INVALID_FD)
    close(pipefd[0]);
  if (pipefd[1] != INVALID_FD)
    close(pipefd[1]);
}

Server::Server() : internal_(nullptr) {}

Server::~Server() {}

bool Server::Initialize(const Uuid &service_id, int *gatt_pipe, CoreStack *bt) {
  internal_.reset(new ServerInternals);
  if (!internal_) {
    LOG_ERROR("Error creating internals");
    return false;
  }
  internal = internal_.get();

  std::unique_lock<std::mutex> lock(internal_->lock);
  int status = internal_->Initialize(bt);
  if (status) {
    LOG_ERROR("Error initializing internals");
    return false;
  }

  bt_uuid_t uuid = service_id.GetBlueDroid();

  bt_status_t btstat = internal_->gatt->server->register_server(&uuid);
  if (btstat != BT_STATUS_SUCCESS) {
    LOG_ERROR("Failed to register server");
    return false;
  }

  internal_->api_synchronize.wait(lock);
  // TODO(icoolidge): Better error handling.
  if (internal_->server_if == 0) {
    LOG_ERROR("Initialization of server failed");
    return false;
  }

  *gatt_pipe = internal_->pipefd[kPipeReadEnd];
  LOG_INFO("Server Initialize succeeded");
  return true;
}

bool Server::SetAdvertisement(const std::vector<Uuid> &ids,
                              const std::vector<uint8_t> &service_data,
                              bool transmit_name) {
  std::vector<uint8_t> id_data;
  auto mutable_service_data = service_data;

  for (const Uuid &id : ids) {
    const auto le_id = id.GetFullLittleEndian();
    id_data.insert(id_data.end(), le_id.begin(), le_id.end());
  }

  std::lock_guard<std::mutex> lock(internal_->lock);

  // Setup our advertisement. This has no callback.
  bt_status_t btstat = internal->gatt->client->set_adv_data(
      internal_->client_if, false, /* beacon, not scan response */
      transmit_name,               /* name */
      false,                       /* no txpower */
      2, 2,                        /* interval */
      0,                           /* appearance */
      0, nullptr,                  /* no mfg data */
      mutable_service_data.size(),
      reinterpret_cast<char *>(mutable_service_data.data()), id_data.size(),
      reinterpret_cast<char *>(id_data.data()));
  if (btstat != BT_STATUS_SUCCESS) {
    LOG_ERROR("Failed to set advertising data");
    return false;
  }
  return true;
}

bool Server::SetScanResponse(const std::vector<Uuid> &ids,
                            const std::vector<uint8_t> &service_data,
                            bool transmit_name) {
  std::vector<uint8_t> id_data;
  auto mutable_service_data = service_data;

  for (const Uuid &id : ids) {
    const auto le_id = id.GetFullLittleEndian();
    id_data.insert(id_data.end(), le_id.begin(), le_id.end());
  }

  std::lock_guard<std::mutex> lock(internal_->lock);

  // Setup our advertisement. This has no callback.
  bt_status_t btstat = internal->gatt->client->set_adv_data(
      internal_->client_if, true, /* scan response */
      transmit_name,              /* name */
      false,                      /* no txpower */
      2, 2,                       /* interval */
      0,                          /* appearance */
      0, nullptr,                 /* no mfg data */
      mutable_service_data.size(),
      reinterpret_cast<char *>(mutable_service_data.data()), id_data.size(),
      reinterpret_cast<char *>(id_data.data()));
  if (btstat != BT_STATUS_SUCCESS) {
    LOG_ERROR("Failed to set scan response data");
    return false;
  }
  return true;
}

bool Server::AddCharacteristic(const Uuid &id, int properties, int permissions) {
  bt_uuid_t char_id = id.GetBlueDroid();

  std::unique_lock<std::mutex> lock(internal->lock);
  bt_status_t btstat = internal->gatt->server->add_characteristic(
      internal->server_if, internal->service_handle, &char_id, properties,
      permissions);
  internal_->api_synchronize.wait(lock);
  const int handle = internal->uuid_to_attribute[id];
  internal->characteristics[handle].notify = properties & kPropertyNotify;
  return true;
}

bool Server::AddBlob(const Uuid &id, const Uuid &control_id, int properties,
                    int permissions) {
  bt_uuid_t char_id = id.GetBlueDroid();
  bt_uuid_t ctrl_id = control_id.GetBlueDroid();

  std::unique_lock<std::mutex> lock(internal->lock);

  // First, add the primary attribute (characteristic value)
  bt_status_t btstat = internal->gatt->server->add_characteristic(
      internal->server_if, internal->service_handle, &char_id, properties,
      permissions);
  internal->api_synchronize.wait(lock);

  // Next, add the secondary attribute (blob control).
  // Control attributes have fixed permissions/properties.
  const int kControlPermissions = kPermissionRead | kPermissionWrite;
  const int kControlProperties = kPropertyRead | kPropertyWrite;

  btstat = internal->gatt->server->add_characteristic(
      internal->server_if, internal->service_handle, &ctrl_id,
      kControlProperties, kControlPermissions);
  internal->api_synchronize.wait(lock);

  // Finally, associate the control attribute with the value attribute.
  // Also, initialize the control attribute to a readable zero.
  const int control_attribute = internal->uuid_to_attribute[control_id];
  const int blob_attribute = internal->uuid_to_attribute[id];
  internal->controlled_blobs[control_attribute] = blob_attribute;
  internal->characteristics[blob_attribute].notify = properties & kPropertyNotify;

  Characteristic &ctrl = internal->characteristics[control_attribute];
  ctrl.next_blob.clear();
  ctrl.next_blob.push_back(0);
  ctrl.next_blob_pending = true;
  ctrl.blob_section = 0;
  ctrl.notify = false;
  return true;
}

bool Server::Start() {
  std::unique_lock<std::mutex> lock(internal_->lock);
  bt_status_t btstat = internal_->gatt->server->start_service(
      internal_->server_if, internal_->service_handle, GATT_TRANSPORT_LE);
  internal_->api_synchronize.wait(lock);
  return true;
}

bool Server::Stop() {
  std::unique_lock<std::mutex> lock(internal_->lock);
  bt_status_t btstat = internal_->gatt->server->stop_service(
      internal_->server_if, internal_->service_handle);
  internal_->api_synchronize.wait(lock);
  return true;
}

bool Server::ScanEnable() {
  bt_status_t btstat = internal_->gatt->client->scan(true);
  if (btstat) {
    LOG_ERROR("Enable scan failed: %d", btstat);
    return false;
  }
  return true;
}

bool Server::ScanDisable() {
  bt_status_t btstat = internal_->gatt->client->scan(false);
  if (btstat) {
    LOG_ERROR("Disable scan failed: %d", btstat);
    return false;
  }
  return true;
}

bool Server::GetScanResults(ScanResults *results) {
  std::lock_guard<std::mutex> lock(internal_->lock);
  *results = internal_->scan_results;
  return true;
}

bool Server::SetCharacteristicValue(const Uuid &id,
                              const std::vector<uint8_t> &value) {
  std::lock_guard<std::mutex> lock(internal->lock);
  const int attribute_id = internal->uuid_to_attribute[id];
  Characteristic &ch = internal->characteristics[attribute_id];
  ch.next_blob = value;
  ch.next_blob_pending = true;

  if (!ch.notify)
    return true;

  for (auto connection : internal->connections) {
    char dummy = 0;
    internal_->gatt->server->send_indication(internal->server_if,
                                             attribute_id,
                                             connection,
                                             sizeof(dummy),
                                             true,
                                             &dummy);
  }
  return true;
}

bool Server::GetCharacteristicValue(const Uuid &id, std::vector<uint8_t> *value) {
  std::lock_guard<std::mutex> lock(internal_->lock);
  const int attribute_id = internal_->uuid_to_attribute[id];
  *value = internal_->characteristics[attribute_id].blob;
  return true;
}

}  // namespace gatt
}  // namespace bluetooth
