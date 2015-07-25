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

#include <base/files/scoped_file.h>
#include <base/macros.h>
#include <base/threading/thread.h>

#include "service/ipc/ipc_handler.h"

namespace base {
class SingleThreadTaskRunner;
}  // namespace base

namespace bluetooth {
class CoreStack;
}  // namespace bluetooth

namespace ipc {

// Implements a UNIX domain-socket based IPCHandler
class IPCHandlerUnix : public IPCHandler {
 public:
  explicit IPCHandlerUnix(bluetooth::CoreStack* core_stack);
  ~IPCHandlerUnix() override;

  // IPCHandler override:
  bool Run() override;

 private:
  IPCHandlerUnix() = default;

  // Starts listening for incoming connections. Posted on |thread_| by Run().
  void StartListeningOnThread();

  // Stops the IPC thread. This helper is needed since base::Thread requires
  // threads to be stopped on the thread that started them.
  void ShutDownOnOriginThread();

  // True, if the IPC mechanism is running.
  bool running_;

  // The server socket on which we listen to incoming connections.
  base::ScopedFD socket_;

  // We use a dedicated thread for listening to incoming connections and
  // polling from the socket to avoid blocking the main thread.
  base::Thread thread_;

  // The origin thread's task runner.
  scoped_refptr<base::SingleThreadTaskRunner> origin_task_runner_;

  DISALLOW_COPY_AND_ASSIGN(IPCHandlerUnix);
};

}  // namespace ipc
