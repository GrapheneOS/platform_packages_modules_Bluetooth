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

#define LOG_TAG "vendor_manager"

#include "vendor_manager.h"

#include <base/logging.h>

#include "osi/include/log.h"

#include <vector>

namespace test_vendor_lib {

VendorManager* g_manager = nullptr;

void VendorManager::CleanUp() { test_channel_transport_.CleanUp(); }

bool VendorManager::Initialize() {
  if (!transport_.SetUp()) {
    LOG_ERROR(LOG_TAG, "Error setting up transport object.");
    return false;
  }

  transport_.RegisterCommandHandler(
      [this](std::unique_ptr<CommandPacket> command) {
        CommandPacket& cmd =
            *command;  // only to be copied into the lambda, not a memory leak
        async_manager_.ExecAsync(std::chrono::milliseconds(0), [this, cmd]() {
          controller_.HandleCommand(std::unique_ptr<CommandPacket>(
              new CommandPacket(std::move(cmd))));
        });
      });

  test_channel_transport_.RegisterCommandHandler(
      [this](const std::string& name, const std::vector<std::string>& args) {
        async_manager_.ExecAsync(
            std::chrono::milliseconds(0), [this, name, args]() {
              controller_.HandleTestChannelCommand(name, args);
            });
      });

  controller_.RegisterEventChannel([this](std::unique_ptr<EventPacket> event) {
    transport_.SendEvent(std::move(event));
  });

  controller_.RegisterTaskScheduler(
      [this](std::chrono::milliseconds delay, const TaskCallback& task) {
        return async_manager_.ExecAsync(delay, task);
      });

  controller_.RegisterPeriodicTaskScheduler(
      [this](std::chrono::milliseconds delay, std::chrono::milliseconds period,
             const TaskCallback& task) {
        return async_manager_.ExecAsyncPeriodically(delay, period, task);
      });

  controller_.RegisterTaskCancel(
      [this](AsyncTaskId task) { async_manager_.CancelAsyncTask(task); });

  if (async_manager_.WatchFdForNonBlockingReads(
          transport_.GetVendorFd(),
          [this](int fd) { transport_.OnCommandReady(fd); }) != 0) {
    LOG_ERROR(LOG_TAG, "Error watching vendor fd.");
    return true;
  }

  SetUpTestChannel(6111);

  return true;
}

VendorManager::VendorManager() : test_channel_transport_() {}

void VendorManager::SetUpTestChannel(int port) {
  int socket_fd = test_channel_transport_.SetUp(port);

  if (socket_fd == -1) {
    LOG_ERROR(LOG_TAG, "Test channel SetUp(%d) failed.", port);
    return;
  }

  LOG_INFO(LOG_TAG, "Test channel SetUp() successful");
  async_manager_.WatchFdForNonBlockingReads(socket_fd, [this](int socket_fd) {
    int conn_fd = test_channel_transport_.Accept(socket_fd);
    if (conn_fd < 0) {
      LOG_ERROR(LOG_TAG, "Error watching test channel fd.");
      return;
    }
    LOG_INFO(LOG_TAG, "Test channel connection accepted.");
    async_manager_.WatchFdForNonBlockingReads(conn_fd, [this](int conn_fd) {
      test_channel_transport_.OnCommandReady(conn_fd, [this, conn_fd]() {
        async_manager_.StopWatchingFileDescriptor(conn_fd);
      });
    });
  });
}

void VendorManager::CloseHciFd() {
  async_manager_.StopWatchingFileDescriptor(transport_.GetHciFd());
  transport_.CloseHciFd();
}

int VendorManager::GetHciFd() const { return transport_.GetHciFd(); }

}  // namespace test_vendor_lib
