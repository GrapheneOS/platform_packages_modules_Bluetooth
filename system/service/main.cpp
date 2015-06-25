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

#define LOG_TAG "BtHost"
// For system properties
// TODO(icoolidge): abstraction or non-cutils stub.
#include <cutils/properties.h>

#include "core_stack.h"
#include "host.h"
#include "osi/include/log.h"
#include "osi/include/socket_utils/sockets.h"

namespace {

const char kDisableProperty[] = "persist.bluetooth.disable";
const char kSocketFromInit[] = "bluetooth";

}  // namespace

int main() {
  char disable_value[PROPERTY_VALUE_MAX];
  int status = property_get(kDisableProperty, disable_value, nullptr);
  if (status && !strcmp(disable_value, "1")) {
    LOG_INFO("service disabled");
    return EXIT_SUCCESS;
  }

  int server_socket = osi_android_get_control_socket(kSocketFromInit);
  if (server_socket == -1) {
    LOG_ERROR("failed to get socket from init");
    return EXIT_FAILURE;
  }

  status = listen(server_socket, SOMAXCONN);
  if (status == -1) {
    LOG_ERROR("listen failed: %s", strerror(errno));
    return EXIT_FAILURE;
  }

  bluetooth::CoreStack bt;
  bt.Initialize();

  // TODO(icoolidge): accept simultaneous clients
  while (true) {
    int client_socket = accept4(server_socket, nullptr, nullptr, SOCK_NONBLOCK);
    if (status == -1) {
      LOG_ERROR("accept failed: %s", strerror(errno));
      return EXIT_FAILURE;
    }

    LOG_INFO("client connected: %d", client_socket);
    bluetooth::Host bluetooth_host(client_socket, &bt);
    bluetooth_host.EventLoop();
  }

  close(server_socket);
  return EXIT_SUCCESS;
}
