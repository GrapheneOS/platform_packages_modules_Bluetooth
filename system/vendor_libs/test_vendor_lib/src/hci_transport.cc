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

extern "C" {
#include "stack/include/hcidefs.h"
#include "osi/include/log.h"

#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <assert.h>
#include <fcntl.h>
#include <unistd.h>
}  // extern "C"

namespace {
// The maximum number of events in the epoll event buffer.
const int kMaxEpollEvents = 10;
}  // namespace

namespace test_vendor_lib {

// Global HciTransport instance used in the vendor library.
// TODO(dennischeng): Should this be moved to an unnamed namespace?
HciTransport* g_transporter = nullptr;

HciTransport::HciTransport() : epoll_fd_(-1), connected_(false) {}

HciTransport::~HciTransport() {
  close(epoll_fd_);
}

bool HciTransport::ConfigEpoll() {
  epoll_fd_ = epoll_create1(EPOLL_CLOEXEC);
  epoll_event event;
  event.events = EPOLLIN;
  event.data.fd = socketpair_fds_[0];
  return epoll_ctl(epoll_fd_, EPOLL_CTL_ADD, socketpair_fds_[0], &event) >= 0;
}

int HciTransport::GetHciFd() const {
  return socketpair_fds_[1];
}

// static
HciTransport* HciTransport::Get() {
  // Initialize should have been called already.
  // TODO(dennischeng): use CHECK and DCHECK when libbase is imported.
  assert(g_transporter);
  return g_transporter;
}

// static
void HciTransport::Initialize() {
  // Multiple calls to Initialize should not be made.
  // TODO(dennischeng): use CHECK and DCHECK when libbase is imported.
  assert(!g_transporter);
  g_transporter = new HciTransport();
}

// static
void HciTransport::CleanUp() {
  delete g_transporter;
  g_transporter = nullptr;
}

bool HciTransport::Connect() {
  if (connected_) {
    LOG_ERROR(LOG_TAG, "Error: transporter is already connected.");
    return false;
  }

  // TODO(dennischeng): Use SOCK_SEQPACKET here.
  if (socketpair(AF_LOCAL, SOCK_STREAM, 0, socketpair_fds_) < 0) {
    LOG_ERROR(LOG_TAG, "Error: creating socketpair in HciTransport.");
    return false;
  }

  // Set the descriptor for the packet stream object. |packet_stream_| will take
  // ownership of the descriptor.
  packet_stream_.SetFd(socketpair_fds_[0]);

  // Initialize epoll instance and set the file descriptor to listen on.
  if (ConfigEpoll() < 0) {
    LOG_ERROR(LOG_TAG, "Error: registering hci listener with epoll instance.");
    return false;
  }

  connected_ = true;
  return true;
}

bool HciTransport::Listen() {
  epoll_event event_buffer[kMaxEpollEvents];
  int num_ready;

  // Check for ready events.
  if ((num_ready = epoll_wait(epoll_fd_, event_buffer, kMaxEpollEvents, -1)) <
      0) {
     LOG_ERROR(LOG_TAG, "Error: epoll wait.");
     return false;
  }

  return ReceiveReadyPackets(*event_buffer, num_ready);
}

bool HciTransport::ReceiveReadyPackets(const epoll_event& event_buffer,
                                       int num_ready) {
  for (int i = 0; i < num_ready; ++i) {
    // Event has data ready to be read.
    if ((&event_buffer)[i].events & EPOLLIN) {
      LOG_INFO(LOG_TAG, "Event ready in HciTransport.");
      serial_data_type_t packet_type = packet_stream_.ReceivePacketType();

      switch (packet_type) {
        case (DATA_TYPE_COMMAND): {
          ReceiveReadyCommand();
          return true;
        }

        case (DATA_TYPE_ACL): {
          LOG_INFO(LOG_TAG, "ACL data packets not currently supported.");
          return true;
        }

        case (DATA_TYPE_SCO): {
          LOG_INFO(LOG_TAG, "SCO data packets not currently supported.");
          return true;
        }

        // TODO(dennischeng): Add debug level assert here.
        default: {
          LOG_INFO(LOG_TAG,
                   "Error received an invalid packet type from the HCI.");
          return false;
        }
      }
    }
  }
  return false;
}

void HciTransport::ReceiveReadyCommand() {
  std::unique_ptr<CommandPacket> command =
      packet_stream_.ReceiveCommand();
  command_callback_(std::move(command));
}

void HciTransport::RegisterCommandCallback(
    std::function<void(std::unique_ptr<CommandPacket>)> callback) {
  command_callback_ = callback;
}

void HciTransport::SendEvent(const EventPacket& event) {
  packet_stream_.SendEvent(event);
}

}  // namespace test_vendor_lib
