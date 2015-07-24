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

#define LOG_TAG "bt_host"
// For system properties
// TODO(icoolidge): abstraction or non-cutils stub.
#if !defined(OS_GENERIC)
#include <cutils/properties.h>
#endif  // !defined(OS_GENERIC)

#include "core_stack.h"
#include "host.h"
#include "osi/include/log.h"
#include "osi/include/socket_utils/sockets.h"

namespace {

// TODO(armansito): None of these should be hardcoded here. Instead, pass these
// via commandline.
const char kDisableProperty[] = "persist.bluetooth.disable";
const char kSocketFromInit[] = "bluetooth";
const char kUnixIpcSocketPath[] = "bluetooth-ipc-socket";

}  // namespace

int main() {
  // TODO(armansito): Move all  of the IPC connection establishment into its own
  // class. Here we should only need to initialize and start the main
  // MessageLoop and the CoreStack instance.
  int status;

#if !defined(OS_GENERIC)
  char disable_value[PROPERTY_VALUE_MAX];
  status = property_get(kDisableProperty, disable_value, nullptr);
  if (status && !strcmp(disable_value, "1")) {
    LOG_INFO(LOG_TAG, "%s", "service disabled");
    return EXIT_SUCCESS;
  }

  int server_socket = osi_android_get_control_socket(kSocketFromInit);
  if (server_socket < 0) {
    LOG_ERROR(LOG_TAG, "failed to get socket from init");
    return EXIT_FAILURE;
  }
#else  // defined(OS_GENERIC)
  int server_socket = socket(PF_UNIX, SOCK_SEQPACKET, 0);
  if (server_socket < 0) {
    LOG_ERROR(LOG_TAG, "failed to open domain socket for IPC");
    return EXIT_FAILURE;
  }

  // TODO(armansito): This is opens the door to potentially unlinking files in
  // the current directory that we're not supposed to. For now we will have an
  // assumption that the daemon runs in a sandbox but we should generally do
  // this properly.
  //
  // Also, the daemon should clean this up properly as it shuts down.
  unlink(kUnixIpcSocketPath);

  struct sockaddr_un address;
  memset(&address, 0, sizeof(address));
  address.sun_family = AF_UNIX;
  strncpy(address.sun_path, kUnixIpcSocketPath, sizeof(address.sun_path) - 1);

  if (bind(server_socket, (struct sockaddr*)&address, sizeof(address)) < 0) {
    LOG_ERROR(LOG_TAG, "Failed to bind IPC socket to address");
    return EXIT_FAILURE;
  }

#endif  // !defined(OS_GENERIC)

  status = listen(server_socket, SOMAXCONN);
  if (status < 0) {
    LOG_ERROR(LOG_TAG, "listen failed: %s", strerror(errno));
    return EXIT_FAILURE;
  }

  bluetooth::CoreStack bt;
  bt.Initialize();

  // TODO(icoolidge): accept simultaneous clients
  while (true) {
    int client_socket = accept4(server_socket, nullptr, nullptr, SOCK_NONBLOCK);
    if (status == -1) {
      LOG_ERROR(LOG_TAG, "accept failed: %s", strerror(errno));
      return EXIT_FAILURE;
    }

    LOG_INFO(LOG_TAG, "client connected: %d", client_socket);
    bluetooth::Host bluetooth_host(client_socket, &bt);
    bluetooth_host.EventLoop();
  }

  close(server_socket);

  return EXIT_SUCCESS;
}
