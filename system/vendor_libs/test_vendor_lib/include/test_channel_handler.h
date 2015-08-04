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
#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

#include "vendor_libs/test_vendor_lib/include/test_channel_transport.h"

namespace test_vendor_lib {

// Manages mappings from test channel commands to test channel callbacks
// provided by the controller. Parallels the functionality of the HciHandler for
// the test channel.
class TestChannelHandler {
 public:
  TestChannelHandler() = default;

  ~TestChannelHandler() = default;

  // Callback to be fired when a command is received from the test channel.
  void HandleTestCommand(std::string command_name,
                         std::vector<std::uint8_t> args);

  // Creates the mapping from the |command_name| to the method |callback|,
  // which is provided by the controller and will be fired when its command is
  // received from the test channel.
  void RegisterControllerCommand(
      std::string command_name,
      std::function<void(const std::vector<std::uint8_t> args)> callback);

  void RegisterHandlersWithTransport(TestChannelTransport& transport);

 private:
  // Controller callbacks to be executed in handlers and registered in
  // RegisterControllerCommand().
  std::unordered_map<std::string,
                     std::function<void(const std::vector<std::uint8_t> args)> >
      commands_;

  DISALLOW_COPY_AND_ASSIGN(TestChannelHandler);
};

}  // namespace test_vendor_lib
