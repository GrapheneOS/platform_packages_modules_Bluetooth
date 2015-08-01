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

#include "service/ipc/unix_ipc_host.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

#include <algorithm>

#include <base/base64.h>
#include <base/strings/string_number_conversions.h>
#include <base/strings/string_split.h>

#define LOG_TAG "bt_bluetooth_host"
#include "osi/include/log.h"
#include "service/core_stack.h"
#include "service/gatt_server.h"
#include "service/uuid.h"

using bluetooth::CoreStack;
using bluetooth::Uuid;

using namespace bluetooth::gatt;

namespace {

// IPC API is according to:
// https://docs.google.com/document/d/1eRnku-jAyVU1wGJsLT2CzWi0-8bs2g49s1b3FR_GApM
const char kSetAdapterNameCommand[] = "set-device-name";
const char kCreateServiceCommand[] = "create-service";
const char kDestroyServiceCommand[] = "destroy-service";
const char kAddCharacteristicCommand[] = "add-characteristic";
const char kSetCharacteristicValueCommand[] = "set-characteristic-value";
const char kSetAdvertisementCommand[] = "set-advertisement";
const char kSetScanResponseCommand[] = "set-scan-response";
const char kStartServiceCommand[] = "start-service";
const char kStopServiceCommand[] = "stop-service";
const char kWriteCharacteristicCommand[] = "write-characteristic";

// Useful values for indexing UnixIPCHost::pfds_
// Not super general considering that we should be able to support
// many GATT FDs owned by one UnixIPCHost.
enum {
  kFdIpc = 0,
  kFdGatt = 1,
  kPossibleFds = 2,
};

bool TokenBool(const std::string& text) {
  return text == "true";
}

}  // namespace

namespace ipc {

UnixIPCHost::UnixIPCHost(int sockfd, CoreStack* bt)
    : bt_(bt), pfds_(1, {sockfd, POLLIN, 0}) {}

UnixIPCHost::~UnixIPCHost() {
  close(pfds_[0].fd);
}

bool UnixIPCHost::EventLoop() {
  while (true) {
    int status =
        TEMP_FAILURE_RETRY(ppoll(pfds_.data(), pfds_.size(), nullptr, nullptr));
    if (status < 1) {
      LOG_ERROR(LOG_TAG, "ppoll error");
      return false;
    }

    if (pfds_[kFdIpc].revents && !OnMessage()) {
      return false;
    }

    if (pfds_.size() == kPossibleFds &&
        pfds_[kFdGatt].revents &&
        !OnGattWrite()) {
      return false;
    }
  }
  return true;
}

bool UnixIPCHost::OnSetAdapterName(const std::string& name) {
  std::string decoded_data;
  base::Base64Decode(name, &decoded_data);
  return bt_->SetAdapterName(decoded_data);
}

bool UnixIPCHost::OnCreateService(const std::string& service_uuid) {
  gatt_servers_[service_uuid] = std::unique_ptr<Server>(new Server);

  int gattfd;
  bool status =
      gatt_servers_[service_uuid]->Initialize(Uuid(service_uuid), &gattfd, bt_);
  if (!status) {
    LOG_ERROR(LOG_TAG, "Failed to initialize bluetooth");
    return false;
  }
  pfds_.resize(kPossibleFds);
  pfds_[kFdGatt] = {gattfd, POLLIN, 0};
  return true;
}

bool UnixIPCHost::OnDestroyService(const std::string& service_uuid) {
  gatt_servers_.erase(service_uuid);
  close(pfds_[1].fd);
  pfds_.resize(1);
  return true;
}

bool UnixIPCHost::OnAddCharacteristic(const std::string& service_uuid,
                               const std::string& characteristic_uuid,
                               const std::string& control_uuid,
                               const std::string& options) {
  std::vector<std::string> option_tokens;
  base::SplitString(options, '.', &option_tokens);

  int properties_mask = 0;
  int permissions_mask = 0;

  if (std::find(option_tokens.begin(), option_tokens.end(), "notify") !=
      option_tokens.end()) {
    permissions_mask |= kPermissionRead;
    properties_mask |= kPropertyRead;
    properties_mask |= kPropertyNotify;
  }
  if (std::find(option_tokens.begin(), option_tokens.end(), "read") !=
      option_tokens.end()) {
    permissions_mask |= kPermissionRead;
    properties_mask |= kPropertyRead;
  }
  if (std::find(option_tokens.begin(), option_tokens.end(), "write") !=
      option_tokens.end()) {
    permissions_mask |= kPermissionWrite;
    properties_mask |= kPropertyWrite;
  }

  if (control_uuid.empty()) {
    gatt_servers_[service_uuid]->AddCharacteristic(
        Uuid(characteristic_uuid), properties_mask, permissions_mask);
  } else {
    gatt_servers_[service_uuid]->AddBlob(Uuid(characteristic_uuid),
                                         Uuid(control_uuid), properties_mask,
                                         permissions_mask);
  }
  return true;
}

bool UnixIPCHost::OnSetCharacteristicValue(const std::string& service_uuid,
                                    const std::string& characteristic_uuid,
                                    const std::string& value) {
  std::string decoded_data;
  base::Base64Decode(value, &decoded_data);
  std::vector<uint8_t> blob_data(decoded_data.begin(), decoded_data.end());
  gatt_servers_[service_uuid]->SetCharacteristicValue(Uuid(characteristic_uuid),
                                                      blob_data);
  return true;
}

bool UnixIPCHost::OnSetAdvertisement(const std::string& service_uuid,
                              const std::string& advertise_uuids,
                              const std::string& advertise_data,
                              const std::string& transmit_name) {
  LOG_INFO(LOG_TAG, "%s: service:%s uuids:%s data:%s", __func__, service_uuid.c_str(),
           advertise_uuids.c_str(), advertise_data.c_str());

  std::vector<std::string> advertise_uuid_tokens;
  base::SplitString(advertise_uuids, '.', &advertise_uuid_tokens);

  // string -> vector<Uuid>
  std::vector<Uuid> ids;
  for (const auto& uuid_token : advertise_uuid_tokens)
    ids.emplace_back(uuid_token);

  std::string decoded_data;
  base::Base64Decode(advertise_data, &decoded_data);
  std::vector<uint8_t> blob_data(decoded_data.begin(), decoded_data.end());
  gatt_servers_[service_uuid]->SetAdvertisement(ids, blob_data,
                                                TokenBool(transmit_name));
  return true;
}

bool UnixIPCHost::OnSetScanResponse(const std::string& service_uuid,
                             const std::string& scan_response_uuids,
                             const std::string& scan_response_data,
                             const std::string& transmit_name) {
  std::vector<std::string> scan_response_uuid_tokens;
  base::SplitString(scan_response_uuids, '.', &scan_response_uuid_tokens);

  // string -> vector<Uuid>
  std::vector<Uuid> ids;
  for (const auto& uuid_token : scan_response_uuid_tokens)
    ids.emplace_back(uuid_token);

  std::string decoded_data;
  base::Base64Decode(scan_response_data, &decoded_data);
  std::vector<uint8_t> blob_data(decoded_data.begin(), decoded_data.end());
  gatt_servers_[service_uuid]->SetScanResponse(ids, blob_data,
                                               TokenBool(transmit_name));
  return true;
}

bool UnixIPCHost::OnStartService(const std::string& service_uuid) {
  return gatt_servers_[service_uuid]->Start();
}

bool UnixIPCHost::OnStopService(const std::string& service_uuid) {
  return gatt_servers_[service_uuid]->Stop();
}

bool UnixIPCHost::OnMessage() {
  std::string ipc_msg;
  int size = recv(pfds_[kFdIpc].fd, &ipc_msg[0], 0, MSG_PEEK | MSG_TRUNC);
  if (-1 == size) {
    LOG_ERROR(LOG_TAG, "Error reading datagram size: %s", strerror(errno));
    return false;
  } else if (0 == size) {
    LOG_INFO(LOG_TAG, "%s:%d: Connection closed", __func__, __LINE__);
    return false;
  }

  ipc_msg.resize(size);
  size = read(pfds_[kFdIpc].fd, &ipc_msg[0], ipc_msg.size());
  if (-1 == size) {
    LOG_ERROR(LOG_TAG, "Error reading IPC: %s", strerror(errno));
    return false;
  } else if (0 == size) {
    LOG_INFO(LOG_TAG, "%s:%d: Connection closed", __func__, __LINE__);
    return false;
  }

  std::vector<std::string> tokens;
  base::SplitString(ipc_msg, '|', &tokens);
  switch (tokens.size()) {
    case 2:
      if (tokens[0] == kSetAdapterNameCommand)
        return OnSetAdapterName(tokens[1]);
      if (tokens[0] == kCreateServiceCommand)
        return OnCreateService(tokens[1]);
      if (tokens[0] == kDestroyServiceCommand)
        return OnDestroyService(tokens[1]);
      if (tokens[0] == kStartServiceCommand)
        return OnStartService(tokens[1]);
      if (tokens[0] == kStopServiceCommand)
        return OnStopService(tokens[1]);
      break;
    case 4:
      if (tokens[0] == kSetCharacteristicValueCommand)
        return OnSetCharacteristicValue(tokens[1], tokens[2], tokens[3]);
      break;
    case 5:
      if (tokens[0] == kSetAdvertisementCommand)
        return OnSetAdvertisement(tokens[1], tokens[2], tokens[3], tokens[4]);
      if (tokens[0] == kSetScanResponseCommand)
        return OnSetScanResponse(tokens[1], tokens[2], tokens[3], tokens[4]);
      if (tokens[0] == kAddCharacteristicCommand)
        return OnAddCharacteristic(tokens[1], tokens[2], tokens[3], tokens[4]);
      break;
    default:
      break;
  }

  LOG_ERROR(LOG_TAG, "Malformed IPC message: %s", ipc_msg.c_str());
  return false;
}

bool UnixIPCHost::OnGattWrite() {
  Uuid::Uuid128Bit id;
  int r = read(pfds_[kFdGatt].fd, id.data(), id.size());
  if (r != id.size()) {
    LOG_ERROR(LOG_TAG, "Error reading GATT attribute ID");
    return false;
  }

  std::vector<uint8_t> value;
  // TODO(icoolidge): Generalize this for multiple clients.
  auto server = gatt_servers_.begin();
  server->second->GetCharacteristicValue(Uuid(id), &value);
  const std::string value_string(value.begin(), value.end());
  std::string encoded_value;
  base::Base64Encode(value_string, &encoded_value);

  std::string transmit(kWriteCharacteristicCommand);
  transmit += "|" + server->first;
  transmit += "|" + base::HexEncode(id.data(), id.size());
  transmit += "|" + encoded_value;

  r = write(pfds_[kFdIpc].fd, transmit.data(), transmit.size());
  if (-1 == r) {
    LOG_ERROR(LOG_TAG, "Error replying to IPC: %s", strerror(errno));
    return false;
  }

  return true;
}

}  // namespace ipc
