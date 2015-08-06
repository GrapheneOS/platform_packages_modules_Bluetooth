//
// Copyright 2015 The Android Open Source Project
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

#define LOG_TAG "hci_transport"

#include "vendor_libs/test_vendor_lib/include/hci_transport.h"

#include "base/logging.h"

extern "C" {
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <fcntl.h>
#include <unistd.h>

#include "stack/include/hcidefs.h"
#include "osi/include/log.h"
}  // extern "C"

namespace test_vendor_lib {

int HciTransport::GetHciFd() const {
  return socketpair_fds_[0];
}

int HciTransport::GetVendorFd() const {
  return socketpair_fds_[1];
}

bool HciTransport::SetUp() {
  // TODO(dennischeng): Use SOCK_SEQPACKET here.
  return socketpair(AF_LOCAL, SOCK_STREAM, 0, socketpair_fds_) >= 0;
}

void HciTransport::OnFileCanReadWithoutBlocking(int fd) {
  CHECK(fd == GetVendorFd());

  LOG_INFO(LOG_TAG, "Event ready in HciTransport.");
  serial_data_type_t packet_type = packet_stream_.ReceivePacketType();

  switch (packet_type) {
    case (DATA_TYPE_COMMAND): {
      ReceiveReadyCommand();
      break;
    }

    case (DATA_TYPE_ACL): {
      LOG_INFO(LOG_TAG, "ACL data packets not currently supported.");
      break;
    }

    case (DATA_TYPE_SCO): {
      LOG_INFO(LOG_TAG, "SCO data packets not currently supported.");
      break;
    }

    // TODO(dennischeng): Add debug level assert here.
    default: {
      LOG_INFO(LOG_TAG, "Error received an invalid packet type from the HCI.");
    }
  }
}

void HciTransport::ReceiveReadyCommand() const {
  std::unique_ptr<CommandPacket> command =
      packet_stream_.ReceiveCommand();
  LOG_INFO(LOG_TAG, "Received command packet.");
  command_handler_(std::move(command));
}

void HciTransport::RegisterCommandHandler(
    std::function<void(std::unique_ptr<CommandPacket>)> callback) {
  command_handler_ = callback;
}

// TODO(dennischeng): Use std::move() semantics here.
void HciTransport::SendEvent(std::unique_ptr<EventPacket> event) {
  outgoing_events_.push(event.get());
}

void HciTransport::OnFileCanWriteWithoutBlocking(int fd) {
  CHECK(fd == GetVendorFd());
  if (!outgoing_events_.empty()) {
    packet_stream_.SendEvent(*outgoing_events_.front());
    outgoing_events_.pop();
  }
}

}  // namespace test_vendor_lib
