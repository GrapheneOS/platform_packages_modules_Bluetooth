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

#pragma once

#include <string>

#include <base/files/file_path.h>
#include <base/macros.h>

namespace bluetooth {

// The Settings class stores global runtime configurations, such as IPC domain
// namespace, configuration file locations, and other system properties and
// flags.
class Settings {
 public:
  // Constant for the "--help" command-line switches.
  static const char kHelp[];

  // Initializes Settings from the command-line arguments and switches for the
  // current process. Returns false if initialization fails, for example if an
  // incorrect command-line option has been given.
  static bool Initialize();

  // Non-mutable getter for the global Settings object. Use this getter for
  // accessing settings in a read-only fashion (which should be the case for
  // most of the code that wants to use this class).
  static const Settings& Get();

  // DO NOT call these directly. Instead, interact with the global instance
  // using the static Initialize and Get methods.
  Settings();
  ~Settings();

  // TODO(armansito): Write an instance method for storing things into a file.

  // Path to the unix domain socket for Bluetooth IPC. On Android, this needs to
  // match the init provided socket domain prefix. Outside Android, this will be
  // the path for the traditional Unix domain socket that the daemon will
  // create.
  const base::FilePath& ipc_socket_path() const {
    return ipc_socket_path_;
  }

 private:
  // Instance helper for the static Initialize() method.
  bool Init();

  bool initialized_;
  base::FilePath ipc_socket_path_;

  DISALLOW_COPY_AND_ASSIGN(Settings);
};

}  // namespace bluetooth
