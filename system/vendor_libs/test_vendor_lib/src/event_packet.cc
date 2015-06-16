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

#define LOG_TAG "event_packet"

#include "vendor_libs/test_vendor_lib/include/event_packet.h"

extern "C" {
#include "osi/include/log.h"
#include "stack/include/hcidefs.h"

#include <assert.h>
}  // extern "C"

namespace test_vendor_lib {

EventPacket::EventPacket(uint8_t event_code,
                         const std::vector<uint8_t>& payload)
    : Packet(DATA_TYPE_EVENT) {
  Encode({event_code, static_cast<uint8_t>(payload.size())}, payload);
}

uint8_t EventPacket::GetEventCode() const {
  return GetHeader()[0];
}

// static
std::unique_ptr<EventPacket> EventPacket::CreateCommandCompleteEvent(
    uint8_t num_hci_command_packets, uint16_t command_opcode,
    const std::vector<uint8_t>& event_return_parameters) {
  size_t payload_size = sizeof(num_hci_command_packets) +
                        sizeof(command_opcode) + event_return_parameters.size();

  std::vector<uint8_t> payload;
  payload.reserve(payload_size);
  payload.push_back(num_hci_command_packets);
  payload.push_back(command_opcode);
  payload.push_back(command_opcode >> 8);
  std::copy(event_return_parameters.begin(), event_return_parameters.end(),
            std::back_inserter(payload));

  return std::unique_ptr<EventPacket>(
      new EventPacket(HCI_COMMAND_COMPLETE_EVT, payload));
}

}  // namespace test_vendor_lib
