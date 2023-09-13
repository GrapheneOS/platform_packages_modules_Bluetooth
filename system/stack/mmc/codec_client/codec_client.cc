/*
 * Copyright 2023 The Android Open Source Project
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

#include "mmc/codec_client/codec_client.h"

#include <base/logging.h>
#include <dbus/bus.h>
#include <dbus/message.h>
#include <dbus/object_proxy.h>
#include <errno.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include <cstring>

#include "mmc/daemon/constants.h"
#include "mmc/proto/mmc_config.pb.h"
#include "mmc/proto/mmc_service.pb.h"

namespace mmc {

CodecClient::CodecClient() {
  skt_fd_ = -1;
  codec_manager_ = nullptr;

  // Set up DBus connection.
  dbus::Bus::Options options;
  options.bus_type = dbus::Bus::SYSTEM;
  bus_ = new dbus::Bus(options);

  if (!bus_->Connect()) {
    LOG(ERROR) << "Failed to connect system bus";
    return;
  }

  // Get proxy to send DBus method call.
  codec_manager_ = bus_->GetObjectProxy(mmc::kMmcServiceName,
                                        dbus::ObjectPath(mmc::kMmcServicePath));
  if (!codec_manager_) {
    LOG(ERROR) << "Failed to get object proxy";
    return;
  }
}

CodecClient::~CodecClient() { cleanup(); }

int CodecClient::init(const ConfigParam config) {
  if (skt_fd_ >= 0) {
    close(skt_fd_);
    skt_fd_ = -1;
  }

  dbus::MethodCall method_call(mmc::kMmcServiceInterface,
                               mmc::kCodecInitMethod);
  dbus::MessageWriter writer(&method_call);

  mmc::CodecInitRequest request;
  *request.mutable_config() = config;
  if (!writer.AppendProtoAsArrayOfBytes(request)) {
    LOG(ERROR) << "Failed to encode CodecInitRequest protobuf";
    return -EINVAL;
  }

  std::unique_ptr<dbus::Response> dbus_response =
      codec_manager_
          ->CallMethodAndBlock(&method_call,
                               dbus::ObjectProxy::TIMEOUT_USE_DEFAULT)
// TODO(b/297976471): remove the build flag once libchrome uprev is done.
#if BASE_VER >= 1170299
          .value_or(nullptr)
#endif
      ;

  if (!dbus_response) {
    LOG(ERROR) << "CodecInit failed";
    return -ECOMM;
  }

  dbus::MessageReader reader(dbus_response.get());
  mmc::CodecInitResponse response;
  if (!reader.PopArrayOfBytesAsProto(&response)) {
    LOG(ERROR) << "Failed to parse response protobuf";
    return -EINVAL;
  }

  if (response.socket_token().empty()) {
    LOG(ERROR) << "CodecInit returned empty socket token";
    return -EBADMSG;
  }

  if (response.input_frame_size() < 0) {
    LOG(ERROR) << "CodecInit returned negative frame size";
    return -EBADMSG;
  }

  // Create socket.
  skt_fd_ = socket(AF_UNIX, SOCK_SEQPACKET, 0);
  if (skt_fd_ < 0) {
    LOG(ERROR) << "Failed to create socket: " << strerror(errno);
    return -errno;
  }

  struct sockaddr_un addr = {};
  addr.sun_family = AF_UNIX;
  strncpy(addr.sun_path, response.socket_token().c_str(),
          sizeof(addr.sun_path) - 1);

  // Connect to socket for transcoding.
  int rc =
      connect(skt_fd_, (struct sockaddr*)&addr, sizeof(struct sockaddr_un));
  if (rc < 0) {
    LOG(ERROR) << "Failed to connect socket: " << strerror(errno);
    return -errno;
  }
  unlink(addr.sun_path);
  return response.input_frame_size();
}

void CodecClient::cleanup() {
  if (skt_fd_ >= 0) {
    close(skt_fd_);
    skt_fd_ = -1;
  }

  dbus::MethodCall method_call(mmc::kMmcServiceInterface,
                               mmc::kCodecCleanUpMethod);

  std::unique_ptr<dbus::Response> dbus_response =
      codec_manager_
          ->CallMethodAndBlock(&method_call,
                               dbus::ObjectProxy::TIMEOUT_USE_DEFAULT)
// TODO(b/297976471): remove the build flag once libchrome uprev is done.
#if BASE_VER >= 1170299
          .value_or(nullptr)
#endif
      ;

  if (!dbus_response) {
    LOG(WARNING) << "CodecCleanUp failed";
  }
  return;
}

int CodecClient::transcode(uint8_t* i_buf, int i_len, uint8_t* o_buf,
                           int o_len) {
  // i_buf and o_buf cannot be null.
  if (i_buf == nullptr || o_buf == nullptr) {
    LOG(ERROR) << "Buffer is null";
    return -EINVAL;
  }

  if (i_len <= 0 || o_len <= 0) {
    LOG(ERROR) << "Non-positive buffer length";
    return -EINVAL;
  }

  // Use MSG_NOSIGNAL to ignore SIGPIPE.
  int rc = send(skt_fd_, i_buf, i_len, MSG_NOSIGNAL);

  if (rc < 0) {
    LOG(ERROR) << "Failed to send data: " << strerror(errno);
    return -errno;
  }
  // Full packet should be sent under SOCK_SEQPACKET setting.
  if (rc < i_len) {
    LOG(ERROR) << "Failed to send full packet";
    return -EIO;
  }

  struct pollfd pfd;
  pfd.fd = skt_fd_;
  pfd.events = POLLIN;

  int pollret = poll(&pfd, 1, -1);
  if (pollret < 0) {
    LOG(ERROR) << "Failed to poll: " << strerror(errno);
    return -errno;
  }

  if (pfd.revents & (POLLHUP | POLLNVAL)) {
    LOG(ERROR) << "Socket closed remotely.";
    return -EIO;
  }

  // POLLIN is returned..
  rc = recv(skt_fd_, o_buf, o_len, MSG_NOSIGNAL);
  if (rc < 0) {
    LOG(ERROR) << "Failed to recv data: " << strerror(errno);
    return -errno;
  }
  // Should be able to recv data when POLLIN is returned.
  if (rc == 0) {
    LOG(ERROR) << "Failed to recv data";
    return -EIO;
  }
  return rc;
}

}  // namespace mmc
