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
#include <memory>
#include <queue>

extern "C" {
#include <sys/epoll.h>
}  // extern "C"

#include "base/message_loop/message_loop.h"
#include "vendor_libs/test_vendor_lib/include/command_packet.h"
#include "vendor_libs/test_vendor_lib/include/event_packet.h"
#include "vendor_libs/test_vendor_lib/include/packet.h"
#include "vendor_libs/test_vendor_lib/include/packet_stream.h"

namespace test_vendor_lib {

// Manages communication channel between HCI and the controller by providing the
// socketing mechanisms for reading/writing between the HCI and the controller.
class HciTransport : public base::MessageLoopForIO::Watcher {
 public:
  HciTransport() = default;

  virtual ~HciTransport() = default;

  int GetHciFd() const;

  int GetVendorFd() const;

  // Creates the underlying socketpair to be used as a communication channel
  // between the HCI and the vendor library/controller.
  bool SetUp();

  // Sets the callback that is run when command packets are received.
  void RegisterCommandHandler(
      std::function<void(std::unique_ptr<CommandPacket>)> callback);

  // Posts the event onto |outgoing_events_| to be written sometime in the
  // future when the vendor file descriptor is ready for writing.
  void SendEvent(std::unique_ptr<EventPacket> event);

 private:
  // base::MessageLoopForIO::Watcher overrides:
  void OnFileCanReadWithoutBlocking(int fd) override;

  void OnFileCanWriteWithoutBlocking(int fd) override;

  // Reads in a command packet and calls the HciHandler's command ready
  // callback, passing owernship of the command packet to the HciHandler.
  void ReceiveReadyCommand() const;

  // Write queue for sending events to the HCI. Event packets are removed from
  // the queue and written when write-readiness is signalled by the message
  // loop.
  // TODO(dennischeng): Use std::unique_ptr here.
  std::queue<EventPacket*> outgoing_events_;

  // Callback executed in ReceiveReadyCommand() to pass the incoming command
  // over to the HciHandler for further processing.
  std::function<void(std::unique_ptr<CommandPacket>)> command_handler_;

  // For performing packet-based IO.
  PacketStream packet_stream_;

  // The two ends of the socket pair used to communicate with the HCI.
  // |socketpair_fds_[0]| is the end that is handed back to the HCI in
  // bt_vendor.cc. It is also closed in bt_vendor.cc by the HCI.
  // |socketpair_fds_[1]| is the vendor end, used to receive and send data in
  // the vendor library and controller. It is closed by |packet_stream_|.
  int socketpair_fds_[2];
};

}  // namespace test_vendor_lib
