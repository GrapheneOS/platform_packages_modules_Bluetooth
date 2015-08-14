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

#include "base/bind.h"
#include "base/logging.h"

extern "C" {
#include "osi/include/log.h"

#include <sys/socket.h>
#include <netinet/in.h>
}  // extern "C"

namespace {
// TODO(dennischeng): Get port from a config file.
const uint16_t kTestChannelPort = 6111;
}  // namespace

namespace test_vendor_lib {

VendorManager* g_manager = nullptr;

// static
void VendorManager::CleanUp() {
  delete g_manager;
  g_manager = nullptr;
}

// static
VendorManager* VendorManager::Get() {
  // Initialize should have been called already.
  CHECK(g_manager);
  return g_manager;
}

// static
void VendorManager::Initialize() {
  CHECK(!g_manager);
  g_manager = new VendorManager();
}

VendorManager::VendorManager()
    : running_(false), thread_("TestVendorLibrary"), weak_ptr_factory_(this) {}

bool VendorManager::Run() {
  CHECK(!running_);

  if (!transport_.SetUp()) {
    LOG_ERROR(LOG_TAG, "Error setting up transport object.");
    return false;
  }

  if (!test_channel_.SetUp()) {
    LOG_ERROR(LOG_TAG, "Error setting up test channel object.");
    return false;
  }

  handler_.RegisterHandlersWithTransport(transport_);
  controller_.RegisterCommandsWithHandler(handler_);
  controller_.RegisterEventChannel(
      std::bind(&HciTransport::SendEvent, &transport_, std::placeholders::_1));

  running_ = true;
  if (!thread_.StartWithOptions(
          base::Thread::Options(base::MessageLoop::TYPE_IO, 0))) {
    LOG_ERROR(LOG_TAG, "Error starting TestVendorLibrary thread.");
    running_ = false;
    return false;
  }

  thread_.task_runner()->PostTask(
      FROM_HERE, base::Bind(&VendorManager::StartWatchingOnThread,
                            weak_ptr_factory_.GetWeakPtr()));
  return true;
}

void VendorManager::StartWatchingOnThread() {
  CHECK(running_);
  CHECK(base::MessageLoopForIO::IsCurrent());
  if (!base::MessageLoopForIO::current()->WatchFileDescriptor(
      transport_.GetVendorFd(), true, base::MessageLoopForIO::WATCH_READ_WRITE,
      &hci_watcher_, &transport_)) {
    LOG_ERROR(LOG_TAG, "Error watching vendor fd.");
    return;
  }
  if (!base::MessageLoopForIO::current()->WatchFileDescriptor(
      test_channel_.GetFd(), true, base::MessageLoopForIO::WATCH_READ,
      &test_channel_watcher_, &transport_)) {
    LOG_ERROR(LOG_TAG, "Error watching test channel fd.");
  }
 }

void VendorManager::SetVendorCallbacks(const bt_vendor_callbacks_t& callbacks) {
  vendor_callbacks_ = callbacks;
}

const bt_vendor_callbacks_t& VendorManager::GetVendorCallbacks() const {
  return vendor_callbacks_;
}

void VendorManager::CloseHciFd() {
  transport_.CloseHciFd();
}

int VendorManager::GetHciFd() const {
  return transport_.GetHciFd();
}

bool VendorManager::TestChannel::SetUp() {
  struct sockaddr_in listen_address, test_channel_address;
  int sockaddr_in_size = sizeof(struct sockaddr_in);
  int listen_fd = -1;
  memset(&listen_address, 0, sockaddr_in_size);
  memset(&test_channel_address, 0, sockaddr_in_size);
  if ((listen_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
    LOG_INFO(LOG_TAG, "Error creating socket for test channel.");
    return false;
  }
  listen_address.sin_family = AF_INET;
  listen_address.sin_port = htons(kTestChannelPort);
  listen_address.sin_addr.s_addr = htonl(INADDR_ANY);
  if (bind(listen_fd, reinterpret_cast<sockaddr*>(&listen_address),
           sockaddr_in_size) < 0) {
    LOG_INFO(LOG_TAG, "Error binding test channel listener socket to address.");
    close(listen_fd);
    return false;
  }
  if (listen(listen_fd, 1) < 0) {
    LOG_INFO(LOG_TAG, "Error listening for test channel.");
    close(listen_fd);
    return false;
  }
  fd_ = accept(listen_fd, reinterpret_cast<sockaddr*>(&test_channel_address),
               &sockaddr_in_size);
  return fd_ >= 0;
}

int VendorManager::TestChannel::GetFd() {
  return fd_;
}

VendorManager::TestChannel::~TestChannel() {
  close(fd_);
}

}  // namespace test_vendor_lib
