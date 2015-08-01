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

#include <base/logging.h>

#include "service/core_stack.h"
#include "service/ipc/ipc_manager.h"
#include "service/settings.h"

namespace bluetooth {

namespace {

// The global Daemon instance.
Daemon* g_daemon = nullptr;

}  // namespace

// static
bool Daemon::Initialize() {
  CHECK(!g_daemon);

  g_daemon = new Daemon();
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
  CHECK(g_daemon->initialized_);

  delete g_daemon;
  g_daemon = NULL;
}

// static
Daemon* Daemon::Get() {
  CHECK(g_daemon);
  return g_daemon;
}

Daemon::Daemon() : initialized_(false) {
}

Daemon::~Daemon() {
}

void Daemon::StartMainLoop() {
  CHECK(initialized_);
  message_loop_->Run();
}

bool Daemon::Init() {
  CHECK(!initialized_);

  message_loop_.reset(new base::MessageLoop());

  settings_.reset(new Settings());
  if (!settings_->Init()) {
    LOG(ERROR) << "Failed to set up Settings";
    return false;
  }

  core_stack_.reset(new CoreStack());
  if (!core_stack_->Initialize()) {
    LOG(ERROR) << "Failed to set up CoreStack";
    return false;
  }

  ipc_manager_.reset(new ipc::IPCManager(core_stack_.get()));

  // If an IPC socket path was given, initialize IPC with it.
  if ((!settings_->create_ipc_socket_path().empty() ||
       !settings_->android_ipc_socket_suffix().empty()) &&
      !ipc_manager_->Start(ipc::IPCManager::TYPE_UNIX)) {
    LOG(ERROR) << "Failed to set up UNIX domain-socket IPCManager";
    return false;
  }

  initialized_ = true;

  return true;
}

}  // namespace bluetooth
