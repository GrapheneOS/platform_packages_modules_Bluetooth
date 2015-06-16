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
#include "vendor_libs/test_vendor_lib/include/hci_transport.h"

extern "C" {
#include "osi/include/log.h"

#include <assert.h>
}  // extern "C"

namespace test_vendor_lib {

// Global HciHandler instance used in the vendor library.
// TODO(dennischeng): Should this be moved to an unnamed namespace?
HciHandler* g_handler = nullptr;

void HciHandler::RegisterTransportCallbacks() {
  HciTransport* transporter = HciTransport::Get();
  // Register the command packet callback with the HciTransport.
  transporter->RegisterCommandCallback(
      std::bind(&HciHandler::HandleCommand, this, std::placeholders::_1));
}

// static
HciHandler* HciHandler::Get() {
  // Initialize should have been called already.
  // TODO(dennischeng): use CHECK and DCHECK when libbase is imported.
  assert(g_handler);
  return g_handler;
}

// static
void HciHandler::Initialize() {
  // Multiple calls to Initialize() should not be made and the HciTransport
  // should already be initialized.
  // TODO(dennischeng): use CHECK and DCHECK when libbase is imported.
  assert(!g_handler);
  assert(HciTransport::Get());
  g_handler = new HciHandler();
  g_handler->RegisterTransportCallbacks();
}

// static
void HciHandler::CleanUp() {
  delete g_handler;
  g_handler = nullptr;
}

void HciHandler::HandleCommand(std::unique_ptr<CommandPacket> command) {
  uint16_t opcode = command->GetOpcode();
  LOG_INFO(LOG_TAG, "Command opcode: 0x%04X, OGF: 0x%04X, OCF: 0x%04X", opcode,
           command->GetOGF(), command->GetOCF());

  // The command hasn't been registered with the handler yet. There is nothing
  // to do.
  if (callbacks_.count(opcode) == 0) {
    return;
  }
  std::function<void(const std::vector<uint8_t> args)> callback =
      callbacks_[opcode];
  callback(command->GetPayload());
}

void HciHandler::RegisterControllerCallback(
    uint16_t opcode,
    std::function<void(const std::vector<uint8_t> args)> callback) {
  callbacks_[opcode] = callback;
}

}  // namespace test_vendor_lib
