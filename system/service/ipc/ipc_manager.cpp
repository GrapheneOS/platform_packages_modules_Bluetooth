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

#include "service/ipc/ipc_manager.h"

#include "service/ipc/ipc_handler_unix.h"

namespace ipc {

IPCManager::IPCManager(bluetooth::CoreStack* core_stack)
    : core_stack_(core_stack) {
  CHECK(core_stack_);
}

IPCManager::~IPCManager() {
}

bool IPCManager::Start(Type type) {
  switch (type) {
  case TYPE_UNIX:
    unix_handler_ = new IPCHandlerUnix(core_stack_);
    return unix_handler_->Run();
  case TYPE_BINDER:
    // TODO(armansito): Support Binder
  default:
    LOG(ERROR) << "Unsupported IPC type given: " << type;
  }

  return false;
}

bool IPCManager::BinderStarted() const {
  return binder_handler_.get();
}

bool IPCManager::UnixStarted() const {
  return unix_handler_.get();
}

}  // namespace ipc
