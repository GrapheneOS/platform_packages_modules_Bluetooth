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

#define LOG_TAG "test_channel_handler"

#include "vendor_libs/test_vendor_lib/include/test_channel_handler.h"

extern "C" {
#include "osi/include/log.h"
}  // extern "C"

namespace test_vendor_lib {

void TestChannelHandler::RegisterHandlersWithTransport(
    TestChannelTransport& transport) {
  transport.RegisterCommandHandler(
      std::bind(&TestChannelHandler::HandleTestCommand, this,
                std::placeholders::_1, std::placeholders::_2));
}

void TestChannelHandler::HandleTestCommand(std::string command_name,
                                           std::vector<std::string> args) {
  LOG_INFO(LOG_TAG, "Test Channel command: %s", command_name.c_str());

  // The command hasn't been registered with the handler yet. There is nothing
  // to do.
  if (commands_.count(command_name) == 0) {
    return;
  }
  std::function<void(const std::vector<std::string> args)> command =
      commands_[command_name];
  command(args);
}

void TestChannelHandler::RegisterControllerCommand(
    std::string command_name,
    std::function<void(const std::vector<std::string> args)> callback) {
  commands_[command_name] = callback;
}

}  // namespace test_vendor_lib
