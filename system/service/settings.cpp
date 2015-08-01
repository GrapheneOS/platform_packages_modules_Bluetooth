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

#include "service/settings.h"

#include <base/command_line.h>
#include <base/logging.h>

#include "service/switches.h"

namespace bluetooth {

Settings::Settings() : initialized_(false) {
}

Settings::~Settings() {
}

bool Settings::Init() {
  CHECK(!initialized_);
  auto command_line = base::CommandLine::ForCurrentProcess();
  const auto& switches = command_line->GetSwitches();

  for (const auto& iter : switches) {
    if (iter.first == switches::kIPCSocketPath) {
      // kIPCSocketPath: An optional argument that initializes an IPC socket
      // path for IPC. If this is not present, the daemon will default to Binder
      // for the IPC mechanism.
      base::FilePath path(iter.second);
      if (path.empty() || path.EndsWithSeparator()) {
        LOG(ERROR) << "Invalid IPC socket path";
        return false;
      }

      ipc_socket_path_ = path;
    } else {
      LOG(ERROR) << "Unexpected command-line switches found";
      return false;
    }
  }

  // The daemon has no arguments
  if (command_line->GetArgs().size()) {
    LOG(ERROR) << "Unexpected command-line arguments found";
    return false;
  }

  initialized_ = true;
  return true;
}

}  // namespace bluetooth
