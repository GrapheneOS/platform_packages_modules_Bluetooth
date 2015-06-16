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

#include "vendor_libs/test_vendor_lib/include/command_packet.h"
#include "vendor_libs/test_vendor_lib/include/event_packet.h"
#include "vendor_libs/test_vendor_lib/include/packet.h"
#include "vendor_libs/test_vendor_lib/include/packet_stream.h"

#include <functional>
#include <memory>

#include <base/macros.h>

extern "C" {
#include <sys/epoll.h>
}  // extern "C"

namespace test_vendor_lib {

// Manages communication channel between HCI and the controller. Listens for
// available events from the host and receives packeted data when it is ready.
// Also exposes a single send method for the controller to pass events back to
// the HCI.
// TODO(dennischeng): Create a nested delegate interface and have the HciHandler
// subclass that interface instead of using callbacks.
class HciTransport {
 public:
  // Returns the HCI's file descriptor for sending commands and data to the
  // controller and for receiving events back.
  int GetHciFd() const;

  // Functions that operate on the global transport instance. Initialize()
  // is called by the vendor library's Init() function to create the global
  // transport and must be called before Get() and CleanUp().
  // CleanUp() should be called when a call to TestVendorCleanUp() is made
  // since the global transport should live throughout the entire time the test
  // vendor library is in use.
  static HciTransport* Get();

  static void Initialize();

  static void CleanUp();

  // Creates the underlying socketpair and packet stream object. Returns true if
  // the connection was successfully made.
  bool Connect();

  // Waits for events on the listener end of the socketpair. Fires the
  // associated callback for each type of packet when data is received via
  // |packet_stream_|. Returns false if an error occurs.
  bool Listen();

  // Sets the callback that is run when command packets are sent by the HCI.
  void RegisterCommandCallback(
      std::function<void(std::unique_ptr<CommandPacket>)> callback);

  // TODO(dennischeng): Determine correct management of event object, what if
  // write doesn't finish before destruction?
  void SendEvent(const EventPacket& event);

 private:
  // Loops through the epoll event buffer and receives packets if they are
  // ready. Fires the corresponding handler callback for each received packet.
  bool ReceiveReadyPackets(const epoll_event& event_buffer,
                          int num_ready);

  // Reads in a command packet and calls the handler's command ready callback,
  // passing owernship of the command packet to the handler.
  void ReceiveReadyCommand();

  // There will only be one global instance of the HCI transport used by
  // bt_vendor.cc and accessed via the static GetInstance() function.
  HciTransport();

  // The destructor can only be indirectly accessed through the static
  // CleanUp() method that destructs the global transport.
  ~HciTransport();

  // Sets up the epoll instance and registers the listener fd. Returns true on
  // success.
  // TODO(dennischeng): import base/ and use a MessageLoopForIO for event loop.
  bool ConfigEpoll();

  // Disallow any copies of the singleton to be made.
  DISALLOW_COPY_AND_ASSIGN(HciTransport);

  // Callback executed in Listen() for command packets.
  std::function<void(std::unique_ptr<CommandPacket>)> command_callback_;

  // File descriptor for epoll instance. Closed in the HciTransport destructor.
  int epoll_fd_;

  // Used to guard against multiple calls to Connect().
  bool connected_;

  // For performing packet IO.
  PacketStream packet_stream_;

  // The two ends of the socket pair used to communicate with the HCI.
  // |socketpair_fds_[0]| is the listener end and is closed in the PacketStream
  // object. |socketpair_fds_[1]| is the HCI end and is closed in bt_vendor.cc.
  int socketpair_fds_[2];
};

}  // namespace test_vendor_lib
