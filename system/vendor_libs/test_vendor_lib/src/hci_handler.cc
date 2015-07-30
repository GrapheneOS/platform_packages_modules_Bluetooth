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

#define LOG_TAG "hci_handler"

#include "vendor_libs/test_vendor_lib/include/hci_handler.h"

extern "C" {
#include "osi/include/log.h"
}  // extern "C"

namespace test_vendor_lib {

void HciHandler::RegisterHandlersWithTransport(HciTransport& transport) {
  // Register the command packet callback with the HciTransport.
  transport.RegisterCommandHandler(
      std::bind(&HciHandler::HandleCommand, this, std::placeholders::_1));
}

void HciHandler::HandleCommand(std::unique_ptr<CommandPacket> command_packet) {
  uint16_t opcode = command_packet->GetOpcode();
  LOG_INFO(LOG_TAG, "Command opcode: 0x%04X, OGF: 0x%04X, OCF: 0x%04X", opcode,
           command_packet->GetOGF(), command_packet->GetOCF());

  // The command hasn't been registered with the handler yet. There is nothing
  // to do.
  if (commands_.count(opcode) == 0) {
    return;
  }
  std::function<void(const std::vector<uint8_t> args)> command =
      commands_[opcode];
  command(command_packet->GetPayload());
}

void HciHandler::RegisterControllerCommand(
    uint16_t opcode,
    std::function<void(const std::vector<uint8_t> args)> callback) {
  commands_[opcode] = callback;
}

}  // namespace test_vendor_lib
