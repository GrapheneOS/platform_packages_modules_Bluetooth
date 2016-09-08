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

#include "hci_transport.h"
#include "command_packet.h"

#include "async_manager.h"

#include <gtest/gtest.h>
#include <functional>
#include <mutex>
#include <thread>

extern "C" {
#include "stack/include/hcidefs.h"
}  // extern "C"

namespace {
const vector<uint8_t> stub_command({DATA_TYPE_COMMAND,
                                    static_cast<uint8_t>(HCI_RESET),
                                    static_cast<uint8_t>(HCI_RESET >> 8),
                                    0});

const int kMultiIterations = 10000;

void WriteStubCommand(int fd) {
  write(fd, &stub_command[0], stub_command.size());
}

}  // namespace

namespace test_vendor_lib {

class HciTransportTest : public ::testing::Test {
 public:
  HciTransportTest() : command_callback_count_(0) {
    SetUpTransport();
    StartThread();
  }

  ~HciTransportTest() {
    async_manager_.StopWatchingFileDescriptor(transport_.GetVendorFd());
    transport_.CloseVendorFd();
    async_manager_.StopWatchingFileDescriptor(transport_.GetHciFd());
    transport_.CloseHciFd();
  }

  void CommandCallback(std::unique_ptr<CommandPacket> command) {
    ++command_callback_count_;
    // Ensure that the received packet matches the stub command.
    EXPECT_EQ(DATA_TYPE_COMMAND, command->GetType());
    EXPECT_EQ(HCI_RESET, command->GetOpcode());
    EXPECT_EQ(static_cast<size_t>(1), command->GetPayloadSize());
    SignalCommandhandlerFinished();
  }

  void MultiCommandCallback(std::unique_ptr<CommandPacket> command) {
    ++command_callback_count_;
    // Ensure that the received packet matches the stub command.
    EXPECT_EQ(DATA_TYPE_COMMAND, command->GetType());
    EXPECT_EQ(HCI_RESET, command->GetOpcode());
    EXPECT_EQ(static_cast<size_t>(1), command->GetPayloadSize());
    if (command_callback_count_ == kMultiIterations) {
      SignalCommandhandlerFinished();
    }
  }

 protected:
  // Tracks the number of commands received.
  int command_callback_count_;
  AsyncManager async_manager_;
  HciTransport transport_;
  bool command_handler_finished_ = false;
  std::mutex mutex_;
  std::condition_variable cond_var_;

  void WaitCommandhandlerFinish() {
    std::unique_lock<std::mutex> lock(mutex_);
    while (!command_handler_finished_) {
      cond_var_.wait(lock);
    }
  }

 private:
  // Workarounds because ASSERT cannot be used directly in a constructor
  void SetUpTransport() { ASSERT_TRUE(transport_.SetUp()); }

  void StartThread() {
    ASSERT_TRUE(async_manager_.WatchFdForNonBlockingReads(
                    transport_.GetVendorFd(),
                    [this](int fd) { transport_.OnCommandReady(fd); }) == 0);
  }

  void SignalCommandhandlerFinished() {
    std::unique_lock<std::mutex> lock(mutex_);
    command_handler_finished_ = true;
    cond_var_.notify_one();
  }
};

TEST_F(HciTransportTest, SingleCommandCallback) {
  transport_.RegisterCommandHandler(
      [this](std::unique_ptr<CommandPacket> command) {
        CommandCallback(std::move(command));
      });
  EXPECT_EQ(0, command_callback_count_);
  WriteStubCommand(transport_.GetHciFd());
  WaitCommandhandlerFinish();
  EXPECT_EQ(1, command_callback_count_);
}

TEST_F(HciTransportTest, MultiCommandCallback) {
  transport_.RegisterCommandHandler(
      [this](std::unique_ptr<CommandPacket> command) {
        MultiCommandCallback(std::move(command));
      });
  EXPECT_EQ(0, command_callback_count_);
  WriteStubCommand(transport_.GetHciFd());
  for (int i = 1; i < kMultiIterations; ++i)
    WriteStubCommand(transport_.GetHciFd());
  WaitCommandhandlerFinish();
  EXPECT_EQ(kMultiIterations, command_callback_count_);
}

}  // namespace test_vendor_lib
