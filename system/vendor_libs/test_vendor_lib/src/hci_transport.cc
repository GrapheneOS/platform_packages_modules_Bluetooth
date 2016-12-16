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

#include "hci_transport.h"

#include <base/logging.h>
#include <sys/socket.h>

#include "osi/include/log.h"
#include "stack/include/hcidefs.h"

namespace test_vendor_lib {

HciTransport::HciTransport() = default;

void HciTransport::CloseHciFd() { hci_fd_.reset(nullptr); }

void HciTransport::CloseVendorFd() { vendor_fd_.reset(nullptr); }

int HciTransport::GetHciFd() const { return hci_fd_->get(); }

int HciTransport::GetVendorFd() const { return vendor_fd_->get(); }

bool HciTransport::SetUp() {
  int socketpair_fds[2];

  const int success = socketpair(AF_LOCAL, SOCK_STREAM, 0, socketpair_fds);
  if (success < 0) return false;
  hci_fd_.reset(new base::ScopedFD(socketpair_fds[0]));
  vendor_fd_.reset(new base::ScopedFD(socketpair_fds[1]));
  return true;
}

void HciTransport::OnCommandReady(int fd) {
  CHECK(fd == GetVendorFd());
  LOG_VERBOSE(LOG_TAG, "Command ready in HciTransport on fd: %d.", fd);

  const serial_data_type_t packet_type = packet_stream_.ReceivePacketType(fd);
  switch (packet_type) {
    case (DATA_TYPE_COMMAND): {
      command_handler_(packet_stream_.ReceiveCommand(fd));
      break;
    }

    case (DATA_TYPE_ACL): {
      LOG_ERROR(LOG_TAG, "ACL data packets not currently supported.");
      break;
    }

    case (DATA_TYPE_SCO): {
      LOG_ERROR(LOG_TAG, "SCO data packets not currently supported.");
      break;
    }

    default: {
      LOG_ERROR(LOG_TAG, "Error received an invalid packet type from the HCI.");
      CHECK(packet_type == DATA_TYPE_COMMAND);
      break;
    }
  }
}

void HciTransport::RegisterCommandHandler(
    const std::function<void(std::unique_ptr<CommandPacket>)>& callback) {
  command_handler_ = callback;
}

void HciTransport::SendEvent(std::unique_ptr<EventPacket> event) {
  packet_stream_.SendEvent(std::move(event), GetVendorFd());
}

}  // namespace test_vendor_lib
