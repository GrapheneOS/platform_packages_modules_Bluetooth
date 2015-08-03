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

#define LOG_TAG "bredr_controller"

#include "vendor_libs/test_vendor_lib/include/bredr_controller.h"
#include "vendor_libs/test_vendor_lib/include/event_packet.h"
#include "vendor_libs/test_vendor_lib/include/hci_handler.h"
#include "vendor_libs/test_vendor_lib/include/hci_transport.h"

extern "C" {
#include "stack/include/hcidefs.h"
#include "osi/include/log.h"

#include <assert.h>
}  // extern "C"

namespace {

// Controller constants and packaged command return parameters.
// All page numbers refer to the Bluetooth Core Specification, Version 4.2,
// Volume 2, Part E, Secion 7.1.
// TODO(dennischeng): Move this into member variables so the controller is
// configurable.

// Included in certain events to indicate the successful completion of the
// associated command.
const uint8_t kReturnStatusSuccess = 0;

// The default number encoded in event packets to indicate to the HCI how many
// command packets it can send to the controller.
const uint8_t kNumHciCommandPackets = 1;

// Creates a command complete event and sends it back to the HCI.
void SendCommandComplete(uint16_t command_opcode,
                         const std::vector<uint8_t>& return_parameters) {
  std::unique_ptr<test_vendor_lib::EventPacket> command_complete =
      test_vendor_lib::EventPacket::CreateCommandCompleteEvent(
          kNumHciCommandPackets, command_opcode, return_parameters);
  // TODO(dennischeng): Should this dependency on HciTransport be removed?
  test_vendor_lib::HciTransport::Get()->SendEvent(*command_complete);
}

// Sends a command complete event with no return parameters. This event is
// typically sent for commands that can be completed immediately.
void SendCommandCompleteSuccess(uint16_t command_opcode) {
  SendCommandComplete(command_opcode, {kReturnStatusSuccess});
}

}  // namespace

namespace test_vendor_lib {

// Global controller instance used in the vendor library.
// TODO(dennischeng): Should this be moved to an unnamed namespace?
BREDRController* g_controller = nullptr;

// static
BREDRController* BREDRController::Get() {
  // Initialize should have been called already.
  // TODO(dennischeng): use CHECK and DCHECK when libbase is imported.
  assert(g_controller);
  return g_controller;
}

// static
void BREDRController::Initialize() {
  // Multiple calls to Initialize() should not be made and the HciHandler should
  // already be initialized.
  // TODO(dennischeng): use CHECK and DCHECK when libbase is imported.
  assert(!g_controller);
  assert(HciHandler::Get());
  g_controller = new BREDRController();
  g_controller->RegisterHandlerCallbacks();
}

// static
void BREDRController::CleanUp() {
  delete g_controller;
  g_controller = nullptr;
}

BREDRController::BREDRController() {
#define SET_HANDLER(opcode, command) \
  active_commands_[opcode] =         \
      std::bind(&BREDRController::command, this, std::placeholders::_1);
  SET_HANDLER(HCI_RESET, HciReset);
#undef SET_HANDLER
}

void BREDRController::RegisterHandlerCallbacks() {
  HciHandler* handler = HciHandler::Get();
  for (auto it = active_commands_.begin(); it != active_commands_.end(); ++it) {
    handler->RegisterControllerCallback(it->first, it->second);
  }
}

void BREDRController::HciReset(const std::vector<uint8_t>& /* args */) {
  LOG_INFO(LOG_TAG, "%s", __func__);
  SendCommandCompleteSuccess(HCI_RESET);
}

}  // namespace test_vendor_lib
