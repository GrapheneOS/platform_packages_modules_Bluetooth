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

#include "vendor_libs/test_vendor_lib/include/packet.h"

#include <cstdint>
#include <memory>
#include <vector>

namespace test_vendor_lib {

// The following is specified in the Bluetooth Core Specification Version 4.2,
// Volume 2, Part E, Section 5.4.4 (page 477). Event Packets begin with a 2
// octet header formatted as follows:
// - Event code: 1 octet
// - Payload size (in octets): 1 octet
// The header is followed by the payload, which contains event specific
// parameters and has a maximum size of 255 octets. Valid event codes are
// listed in stack/include/hcidefs.h. They can range from 0x00 to 0xFF, with
// 0xFF reserved for vendor specific debug events. Note the payload size
// describes the total size of the event parameters and not the number of
// parameters. The event parameters contained in the payload will be an integer
// number of octets in size. Each flavor of event packet is created via a static
// factory function that takes the event type-specific parameters and returns an
// initialized event packet from that data.
class EventPacket : public Packet {
 public:
  virtual ~EventPacket() override = default;

  std::uint8_t GetEventCode() const;

  // Static functions for creating event packets:

  // Creates and returns a command complete event packet. See the Bluetooth
  // Core Specification Version 4.2, Volume 2, Part E, Section 7.7.14 (page 861)
  // for more information about the command complete event.
  // |num_hci_command_packets| indicates the number of HCI command packets the
  // host can send to the controller. If |num_hci_command_packets| is 0, the
  // controller would like to stop receiving commands from the host (to indicate
  // readiness again, the controller sends a command complete event with
  // |command_opcode| to 0x0000 (no op) and |num_hci_command_packets| > 1).
  // |command_opcode| is the opcode of the command that caused this event.
  // |return_parameters| will contain any event specific parameters that should
  // be sent to the host.
  static std::unique_ptr<EventPacket> CreateCommandCompleteEvent(
      std::uint8_t num_hci_command_packets, std::uint16_t command_opcode,
      const std::vector<std::uint8_t>& event_return_parameters);

  // Size in octets of a data packet header, which consists of a 1 octet
  // event code and a 1 octet payload size.
  static const size_t kEventHeaderSize = 2;

 private:
  // Takes in the event parameters in |payload|. These parameters vary by event
  // and are detailed in the Bluetooth Core Specification.
  EventPacket(std::uint8_t event_code,
              const std::vector<std::uint8_t>& payload);
};

}  // namespace test_vendor_lib
