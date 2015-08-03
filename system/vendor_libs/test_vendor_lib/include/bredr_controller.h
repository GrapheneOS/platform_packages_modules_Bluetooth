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

#include <cstdint>
#include <vector>
#include <unordered_map>

#include <base/macros.h>

namespace test_vendor_lib {

// Emulates a BR/EDR controller by maintaining the link layer state machine
// detailed in the Bluetooth Core Specification Version 4.2, Volume 2, Part B,
// Section 8 (page 159). Provides actions corresponding to commands sent by the
// HCI. These actions will be registered from a single global controller
// instance as callbacks and called from the HciHandler.
// TODO(dennischeng): Should the controller implement an interface provided by
// the HciHandler and be used as a delegate (i.e. the HciHandler would hold a
// controller object) instead of registering its methods as callbacks?
class BREDRController {
 public:
  // Functions that operate on the global controller instance. Initialize()
  // is called by the vendor library's Init() function to create the global
  // controller and must be called before Get() and CleanUp().
  // CleanUp() should be called when a call to TestVendorCleanUp() is made
  // since the global controller should live throughout the entire time the test
  // vendor library is in use.
  static BREDRController* Get();

  static void Initialize();

  static void CleanUp();

  // Controller commands. For error codes, see the Bluetooth Core Specification,
  // Version 4.2, Volume 2, Part D (page 370).

  // Resets the controller. For now, this just generates and sends a command
  // complete event back to the HCI.
  // Command parameters: none.
  // Command response:
  //   Status (1 octet)
  //     0x00: Success.
  //     0x01-0xFF: Failed. Check error codes.
  void HciReset(const std::vector<std::uint8_t>& args);

 private:
  // There will only be a single global instance of this class.
  BREDRController();

  // The destructor can only be indirectly accessed through the static
  // CleanUp() method that destructs the global controller.
  ~BREDRController() = default;

  // Registers command callbacks with the HciHandler instance so that they are
  // fired when the corresponding opcode is received from the HCI. For now, each
  // command must be individually registered. This allows for some flexibility
  // in which commands are made available by which controller.
  void RegisterHandlerCallbacks();

  // Maintains the commands to be registered and used in the HciHandler object.
  // Keys are command opcodes and values are the callbacks to handle each
  // command.
  std::unordered_map<std::uint16_t,
                     std::function<void(const std::vector<std::uint8_t>&)>>
      active_commands_;

  // Disallow any copies of the singleton to be made.
  DISALLOW_COPY_AND_ASSIGN(BREDRController);
};

}  // namespace test_vendor_lib
