//
//  Copyright (C) 2015 Google, Inc.
//
//  Licensed under the Apache License, Version 2.0 (the "License");
//  you may not use this file except in compliance with the License.
//  You may obtain a copy of the License at:
//
//  http://www.apache.org/licenses/LICENSE-2.0
//
//  Unless required by applicable law or agreed to in writing, software
//  distributed under the License is distributed on an "AS IS" BASIS,
//  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//  See the License for the specific language governing permissions and
//  limitations under the License.
//

#include "service/daemon.h"

#include <memory>

#include <base/logging.h>

#include "service/core_stack.h"
#include "service/ipc/ipc_manager.h"
#include "service/settings.h"

namespace bluetooth {

namespace {

// The global Daemon instance.
Daemon* g_daemon = nullptr;

class DaemonImpl : public Daemon {
 public:
  DaemonImpl() = default;
  ~DaemonImpl() override = default;

  void StartMainLoop() override {
    message_loop_->Run();
  }

  Settings* GetSettings() const override {
    return settings_.get();
  }

  base::MessageLoop* GetMessageLoop() const override {
    return message_loop_.get();
  }

 private:
  bool Init() override {
    message_loop_.reset(new base::MessageLoop());

    settings_.reset(new Settings());
    if (!settings_->Init()) {
      LOG(ERROR) << "Failed to set up Settings";
      return false;
    }

    core_stack_ = CoreStack::Create();
    if (!core_stack_->Initialize()) {
      LOG(ERROR) << "Failed to set up CoreStack";
      return false;
    }

    ipc_manager_.reset(new ipc::IPCManager(core_stack_.get()));

    // If an IPC socket path was given, initialize IPC with it. Otherwise
    // initialize Binder IPC.
    if (settings_->UseSocketIPC()) {
      if (!ipc_manager_->Start(ipc::IPCManager::TYPE_UNIX, nullptr)) {
        LOG(ERROR) << "Failed to set up UNIX domain-socket IPCManager";
        return false;
      }
    } else if (!ipc_manager_->Start(ipc::IPCManager::TYPE_BINDER, nullptr)) {
      LOG(ERROR) << "Failed to set up Binder IPCManager";
      return false;
    }

    return true;
  }

  std::unique_ptr<base::MessageLoop> message_loop_;
  std::unique_ptr<Settings> settings_;
  std::unique_ptr<CoreStack> core_stack_;
  std::unique_ptr<ipc::IPCManager> ipc_manager_;

  DISALLOW_COPY_AND_ASSIGN(DaemonImpl);
};

}  // namespace

// static
bool Daemon::Initialize() {
  CHECK(!g_daemon);

  g_daemon = new DaemonImpl();
  if (g_daemon->Init())
    return true;

  LOG(ERROR) << "Failed to initialize the Daemon object";

  delete g_daemon;
  g_daemon = nullptr;

  return false;
}

// static
void Daemon::ShutDown() {
  CHECK(g_daemon);
  delete g_daemon;
  g_daemon = nullptr;
}

// static
void Daemon::InitializeForTesting(Daemon* test_daemon) {
  CHECK(test_daemon);
  CHECK(!g_daemon);

  g_daemon = test_daemon;
}

// static
Daemon* Daemon::Get() {
  CHECK(g_daemon);
  return g_daemon;
}

}  // namespace bluetooth
