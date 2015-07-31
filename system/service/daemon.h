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

#include <memory>

#include <base/macros.h>
#include <base/message_loop/message_loop.h>

namespace ipc {
class IPCManager;
}  // namespace ipc

namespace bluetooth {

class CoreStack;
class Settings;

// The Daemon class is a singleton that represents the root of the ownership
// hierarchy. The single instance sets up and owns the main event loop, the IPC
// handlers, global Settings, and the core Bluetooth stack.
class Daemon {
 public:
  // Initializes the daemon. This must be called to at the start of the
  // application to set up the global daemon instance and everything it manages.
  // Returns false in case of a failure.
  static bool Initialize();

  // Cleans up all the resources associated with the global Daemon object.
  static void ShutDown();

  // Returns the singleton Daemon instance. All classes can interact with the
  // Daemon, obtain its resources etc using this getter.
  static Daemon* Get();

  // The global Settings object. All classes have direct access to this through
  // the Daemon object.
  Settings* settings() const { return settings_.get(); }

  // The main event loop. This should be used for any events and delayed tasks
  // that should be executed on the daemon's main thread.
  base::MessageLoop* message_loop() const { return message_loop_.get(); }

  // Starts the daemon's main loop.
  void StartMainLoop();

 private:
  Daemon();
  ~Daemon();

  // Private instance helper for Initialize().
  bool Init();

  bool initialized_;
  std::unique_ptr<base::MessageLoop> message_loop_;
  std::unique_ptr<Settings> settings_;
  std::unique_ptr<CoreStack> core_stack_;
  std::unique_ptr<ipc::IPCManager> ipc_manager_;

  DISALLOW_COPY_AND_ASSIGN(Daemon);
};

}  // namespace bluetooth
