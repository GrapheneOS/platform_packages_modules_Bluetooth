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
#include <base/lazy_instance.h>
#include <base/logging.h>

#include "service/switches.h"

namespace bluetooth {

namespace {

// The global settings instance. We use a LazyInstance here so that we can
// lazily initialize the instance AND guarantee that it will be cleaned up at
// exit time without violating the Google C++ style guide.
base::LazyInstance<Settings> g_settings = LAZY_INSTANCE_INITIALIZER;

void LogRequiredOption(const std::string& option) {
  LOG(ERROR) << "Required option: \"" << option << "\"";
}

}  // namespace

// static
bool Settings::Initialize() {
  return g_settings.Get().Init();
}

// static
const Settings& Settings::Get() {
  CHECK(g_settings.Get().initialized_);
  return g_settings.Get();
}

Settings::Settings() : initialized_(false) {
}

Settings::~Settings() {
}

bool Settings::Init() {
  CHECK(!initialized_);
  auto command_line = base::CommandLine::ForCurrentProcess();

  // Since we have only one meaningful command-line flag for now, it's OK to
  // hard-code this here. As we add more switches, we should process this in a
  // more meaningful way.
  if (command_line->GetSwitches().size() > 1) {
    LOG(ERROR) << "Unexpected command-line switches found";
    return false;
  }

  if (!command_line->HasSwitch(switches::kIPCSocketPath)) {
    LogRequiredOption(switches::kIPCSocketPath);
    return false;
  }

  base::FilePath path = command_line->GetSwitchValuePath(
      switches::kIPCSocketPath);
  if (path.value().empty() || path.EndsWithSeparator()) {
    LOG(ERROR) << "Invalid IPC socket path";
    return false;
  }

  // The daemon has no arguments
  if (command_line->GetArgs().size()) {
    LOG(ERROR) << "Unexpected command-line arguments found";
    return false;
  }

  ipc_socket_path_ = path;

  initialized_ = true;
  return true;
}

}  // namespace bluetooth
