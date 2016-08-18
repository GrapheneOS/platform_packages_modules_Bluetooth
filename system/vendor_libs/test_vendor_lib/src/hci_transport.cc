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

#include <cinttypes>

#include "hci_transport.h"

extern "C" {
#include <sys/socket.h>

#include "osi/include/log.h"
#include "stack/include/hcidefs.h"
}  // extern "C"

namespace test_vendor_lib {

HciTransport::HciTransport() = default;

void HciTransport::CloseHciFd() {
  hci_fd_.reset(nullptr);
}

void HciTransport::CloseVendorFd() {
  vendor_fd_.reset(nullptr);
}

int HciTransport::GetHciFd() const {
  return hci_fd_->get();
}

int HciTransport::GetVendorFd() const {
  return vendor_fd_->get();
}

bool HciTransport::SetUp() {
  int socketpair_fds[2];
  // TODO(dennischeng): Use SOCK_SEQPACKET here.
  const int success = socketpair(AF_LOCAL, SOCK_STREAM, 0, socketpair_fds);
  if (success < 0)
    return false;
  hci_fd_.reset(new base::ScopedFD(socketpair_fds[0]));
  vendor_fd_.reset(new base::ScopedFD(socketpair_fds[1]));
  return true;
}

void HciTransport::OnFileCanReadWithoutBlocking(int fd) {
  CHECK(fd == GetVendorFd());
  LOG_INFO(LOG_TAG, "Event ready in HciTransport on fd: %d.", fd);

  const serial_data_type_t packet_type = packet_stream_.ReceivePacketType(fd);
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
      break;
    }
  }
}

void HciTransport::ReceiveReadyCommand() const {
  std::unique_ptr<CommandPacket> command =
      packet_stream_.ReceiveCommand(GetVendorFd());
  LOG_INFO(LOG_TAG, "Received command packet.");
  command_handler_(std::move(command));
}

void HciTransport::RegisterCommandHandler(
    const std::function<void(std::unique_ptr<CommandPacket>)>& callback) {
  command_handler_ = callback;
}

void HciTransport::RegisterEventScheduler(
    const std::function<void(std::chrono::milliseconds, const TaskCallback&)>&
        evtScheduler) {
  schedule_event_ = evtScheduler;
}

void HciTransport::RegisterPeriodicEventScheduler(
    const std::function<void(std::chrono::milliseconds,
                       std::chrono::milliseconds,
                       const TaskCallback&)>& periodicEvtScheduler) {
  schedule_periodic_event_ = periodicEvtScheduler;
}

void HciTransport::PostEventResponse(const EventPacket& event) {
  schedule_event_(std::chrono::milliseconds(0), [this, event]() {
    packet_stream_.SendEvent(event, GetVendorFd());
  });
}

void HciTransport::PostDelayedEventResponse(const EventPacket& event,
                                            std::chrono::milliseconds delay) {
  // TODO(dennischeng): When it becomes available for MessageLoopForIO, use the
  // thread's task runner to post |PostEventResponse| as a delayed task, being
  // sure to CHECK the appropriate task runner attributes using
  // base::ThreadTaskRunnerHandle.

  // The system does not support high resolution timing and the clock could be
  // as coarse as ~15.6 ms so the event is sent without a delay to avoid
  // inconsistent event responses.
  if (!base::TimeTicks::IsHighResolution()) {
    LOG_INFO(LOG_TAG,
             "System does not support high resolution timing. Sending event "
             "without delay.");
    schedule_event_(std::chrono::milliseconds(0), [this, event]() {
      packet_stream_.SendEvent(event, GetVendorFd());
    });
  }

  LOG_INFO(LOG_TAG,
           "Posting event response with delay of %" PRId64 " ms.",
           static_cast<int64_t>(std::chrono::milliseconds(delay).count()));

  schedule_event_(delay, [this, event]() {
    packet_stream_.SendEvent(event, GetVendorFd());
  });
}

}  // namespace test_vendor_lib
