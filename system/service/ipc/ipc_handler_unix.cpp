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

#include "service/ipc/ipc_handler_unix.h"

#include <sys/socket.h>
#include <sys/un.h>

#include <base/bind.h>

#include "service/daemon.h"
#include "service/ipc/unix_ipc_host.h"
#include "service/settings.h"

namespace ipc {

IPCHandlerUnix::IPCHandlerUnix(bluetooth::CoreStack* core_stack)
    : IPCHandler(core_stack),
      running_(false),
      thread_("IPCHandlerUnix") {
}

IPCHandlerUnix::~IPCHandlerUnix() {
}

bool IPCHandlerUnix::Run() {
  CHECK(!running_);

  const base::FilePath& path =
      bluetooth::Daemon::Get()->settings()->ipc_socket_path();
  if (path.empty()) {
    LOG(ERROR) << "No domain socket path provided";
    return false;
  }

  CHECK(base::MessageLoop::current());  // An origin event loop is required.
  origin_task_runner_ = base::MessageLoop::current()->task_runner();

  // TODO(armansito): This is opens the door to potentially unlinking files in
  // the current directory that we're not supposed to. For now we will have an
  // assumption that the daemon runs in a sandbox but we should generally do
  // this properly.
  //
  // Also, the daemon should clean this up properly as it shuts down.
  unlink(path.value().c_str());

  base::ScopedFD server_socket(socket(PF_UNIX, SOCK_SEQPACKET, 0));
  if (!server_socket.is_valid()) {
    LOG(ERROR) << "Failed to open domain socket for IPC";
    return false;
  }

  struct sockaddr_un address;
  memset(&address, 0, sizeof(address));
  address.sun_family = AF_UNIX;
  strncpy(address.sun_path, path.value().c_str(), sizeof(address.sun_path) - 1);
  if (bind(server_socket.get(), (struct sockaddr*)&address,
           sizeof(address)) < 0) {
    LOG(ERROR) << "Failed to bind IPC socket to address: " << strerror(errno);
    return false;
  }

  socket_.swap(server_socket);
  running_ = true;  // Set this here before launching the thread.

  // Start an IO thread and post the listening task.
  base::Thread::Options options(base::MessageLoop::TYPE_IO, 0);
  if (!thread_.StartWithOptions(options)) {
    LOG(ERROR) << "Failed to start IPCHandlerUnix thread";
    running_ = false;
    return false;
  }

  thread_.task_runner()->PostTask(
      FROM_HERE,
      base::Bind(&IPCHandlerUnix::StartListeningOnThread, this));

  return true;
}

void IPCHandlerUnix::StartListeningOnThread() {
  CHECK(socket_.is_valid());
  CHECK(core_stack_);
  CHECK(running_);

  LOG(INFO) << "Listening to incoming connections";

  int status = listen(socket_.get(), SOMAXCONN);
  if (status < 0) {
    LOG(ERROR) << "Failed to listen on domain socket: " << strerror(errno);
    origin_task_runner_->PostTask(
        FROM_HERE,
        base::Bind(&IPCHandlerUnix::ShutDownOnOriginThread, this));
    return;
  }

  // TODO(icoolidge): accept simultaneous clients
  while (true) {
    int client_socket = accept4(socket_.get(), nullptr, nullptr, SOCK_NONBLOCK);
    if (status == -1) {
      LOG(ERROR) << "Failed to accept client connection: " << strerror(errno);
      continue;
    }

    LOG(INFO) << "Established client connection: fd=" << client_socket;
    UnixIPCHost ipc_host(client_socket, core_stack_);
    // TODO(armansito): Use |thread_|'s MessageLoopForIO instead of using a
    // custom event loop to poll from the socket.
    ipc_host.EventLoop();
  }
}

void IPCHandlerUnix::ShutDownOnOriginThread() {
  LOG(INFO) << "Shutting down IPCHandlerUnix thread";
  thread_.Stop();
  running_ = false;

  // TODO(armansito): Notify the upper layer so that they can perform clean-up
  // tasks on unexpected shut-down.
}

}  // namespace ipc
