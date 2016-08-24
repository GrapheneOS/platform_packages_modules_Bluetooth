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

#pragma once

#include <functional>
#include <list>
#include <memory>

extern "C" {
#include <sys/epoll.h>
}  // extern "C"

#include "async_manager.h"
#include "base/files/scoped_file.h"
#include "base/time/time.h"
#include "command_packet.h"
#include "event_packet.h"
#include "packet.h"
#include "packet_stream.h"

namespace test_vendor_lib {

// Manages communication channel between HCI and the controller by providing the
// socketing mechanisms for reading/writing between the HCI and the controller.
class HciTransport {
 public:
  HciTransport();

  virtual ~HciTransport() = default;

  void CloseHciFd();

  void CloseVendorFd();

  int GetHciFd() const;

  int GetVendorFd() const;

  // Creates the underlying socketpair to be used as a communication channel
  // between the HCI and the vendor library/controller. Returns false if an
  // error occurs.
  bool SetUp();

  // Sets the callback that is run when command packets are received.
  void RegisterCommandHandler(
      const std::function<void(std::unique_ptr<CommandPacket>)>& callback);

  // Sets the callback that is to schedule events.
  void RegisterEventScheduler(
      const std::function<void(std::chrono::milliseconds, const TaskCallback&)>&
          evtScheduler);

  // Sets the callback that is to schedule events.
  void RegisterPeriodicEventScheduler(
      const std::function<void(std::chrono::milliseconds,
                               std::chrono::milliseconds,
                               const TaskCallback&)>& periodicEvtScheduler);

  // Posts the event onto |outbound_events_| to be written sometime in the
  // future when the vendor file descriptor is ready for writing.
  void PostEventResponse(const EventPacket& event);

  // Posts the event onto |outbound_events_| after |delay| ms. A call to
  // |PostEventResponse| with |delay| 0 is equivalent to a call to |PostEvent|.
  void PostDelayedEventResponse(const EventPacket& event,
                                std::chrono::milliseconds delay);

  void OnFileCanReadWithoutBlocking(int fd);

 private:
  // Reads in a command packet and calls the command ready callback,
  // |command_handler_|, passing ownership of the command packet to the handler.
  void ReceiveReadyCommand() const;

  // Callback executed in ReceiveReadyCommand() to pass the incoming command
  // over to the handler for further processing.
  std::function<void(std::unique_ptr<CommandPacket>)> command_handler_;

  // Callbacks to schedule events.
  std::function<void(std::chrono::milliseconds, const TaskCallback&)>
      schedule_event_;
  std::function<void(std::chrono::milliseconds,
                     std::chrono::milliseconds,
                     const TaskCallback&)>
      schedule_periodic_event_;

  // For performing packet-based IO.
  PacketStream packet_stream_;

  // The two ends of the socketpair. |hci_fd_| is handed back to the HCI in
  // bt_vendor.cc and |vendor_fd_| is used by |packet_stream_| to receive/send
  // data from/to the HCI. Both file descriptors are owned and managed by the
  // transport object, although |hci_fd_| can be closed by the HCI in
  // TestVendorOp().
  std::unique_ptr<base::ScopedFD> hci_fd_;
  std::unique_ptr<base::ScopedFD> vendor_fd_;

  HciTransport(const HciTransport& cmdPckt) = delete;
  HciTransport& operator=(const HciTransport& cmdPckt) = delete;
};

}  // namespace test_vendor_lib
