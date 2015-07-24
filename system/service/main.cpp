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

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include <base/at_exit.h>
#include <base/command_line.h>
#include <base/files/scoped_file.h>

#define LOG_TAG "bt_host"
// For system properties
// TODO(icoolidge): abstraction or non-cutils stub.
#if !defined(OS_GENERIC)
#include <cutils/properties.h>
#endif  // !defined(OS_GENERIC)

#include "osi/include/log.h"
#include "osi/include/socket_utils/sockets.h"
#include "service/core_stack.h"
#include "service/host.h"
#include "service/settings.h"
#include "service/switches.h"

namespace {

// TODO(armansito): None of these should be hardcoded here. Instead, pass these
// via commandline.
const char kDisableProperty[] = "persist.bluetooth.disable";

}  // namespace

int main(int argc, char *argv[]) {
  base::AtExitManager exit_manager;
  base::CommandLine::Init(argc, argv);

  // TODO(armansito): Initialize base/logging. By default it will dump to stdout
  // but we might want to change that based on a command-line switch. Figure out
  // how to route the logging to Android's syslog. Once that's done, we won't
  // need to use osi/include/log.h anymore.

  // TODO(armansito): Register exit-time clean-up handlers for the IPC sockets.
  // Register signal handlers.
  auto command_line = base::CommandLine::ForCurrentProcess();
  if (command_line->HasSwitch(bluetooth::switches::kHelpLong) ||
      command_line->HasSwitch(bluetooth::switches::kHelpShort)) {
    LOG(INFO) << bluetooth::switches::kHelpMessage;
    return EXIT_SUCCESS;
  }

  if (!bluetooth::Settings::Initialize()) {
    LOG(ERROR) << "Failed to parse the command-line.";
    return EXIT_FAILURE;
  }

  // TODO(armansito): Move all of the IPC connection establishment into its own
  // class. Here we should only need to initialize and start the main
  // MessageLoop and the CoreStack instance.
  int status;

#if !defined(OS_GENERIC)
  // TODO(armansito): Remove Chromecast specific property out of here. This
  // should just be obtained from global config.
  char disable_value[PROPERTY_VALUE_MAX];
  status = property_get(kDisableProperty, disable_value, nullptr);
  if (status && !strcmp(disable_value, "1")) {
    LOG(INFO) << "service disabled";
    return EXIT_SUCCESS;
  }
#endif  // !defined(OS_GENERIC)

  base::ScopedFD server_socket(socket(PF_UNIX, SOCK_SEQPACKET, 0));
  if (!server_socket.is_valid()) {
    LOG(ERROR) << "failed to open domain socket for IPC";
    return EXIT_FAILURE;
  }

  // TODO(armansito): This is opens the door to potentially unlinking files in
  // the current directory that we're not supposed to. For now we will have an
  // assumption that the daemon runs in a sandbox but we should generally do
  // this properly.
  //
  // Also, the daemon should clean this up properly as it shuts down.
  unlink(bluetooth::Settings::Get().ipc_socket_path().value().c_str());

  struct sockaddr_un address;
  memset(&address, 0, sizeof(address));
  address.sun_family = AF_UNIX;
  strncpy(address.sun_path,
          bluetooth::Settings::Get().ipc_socket_path().value().c_str(),
          sizeof(address.sun_path) - 1);
  if (bind(server_socket.get(), (struct sockaddr*)&address,
           sizeof(address)) < 0) {
    LOG(ERROR) << "Failed to bind IPC socket to address: " << strerror(errno);
    return EXIT_FAILURE;
  }

  status = listen(server_socket.get(), SOMAXCONN);
  if (status < 0) {
    LOG(ERROR) << "Failed to listen on IPC socket: " << strerror(errno);
    return EXIT_FAILURE;
  }

  bluetooth::CoreStack bt;
  if (!bt.Initialize()) {
    LOG(ERROR) << "Failed to initialize the Bluetooth stack";
    return EXIT_FAILURE;
  }

  // TODO(icoolidge): accept simultaneous clients
  while (true) {
    int client_socket = accept4(server_socket.get(), nullptr,
                                nullptr, SOCK_NONBLOCK);
    if (status == -1) {
      LOG(ERROR) << "accept failed: %s" << strerror(errno);
      return EXIT_FAILURE;
    }

    LOG(INFO) << "client connected: %d" << client_socket;
    bluetooth::Host bluetooth_host(client_socket, &bt);
    bluetooth_host.EventLoop();
  }

  return EXIT_SUCCESS;
}
