/******************************************************************************
 *
 *  Copyright (C) 2014 Google, Inc.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at:
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 ******************************************************************************/

#define LOG_TAG "bt_osi_socket"

#include <assert.h>
#include <errno.h>
#include <netinet/in.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <utils/Log.h>

#include "reactor.h"
#include "socket.h"
#include "thread.h"

struct socket_t {
  thread_t *thread;
  reactor_object_t socket_object;
  socket_cb read_ready;
  socket_cb write_ready;
  void *context;
};

static void internal_read_ready(void *context);
static void internal_write_ready(void *context);

socket_t *socket_new(void) {
  socket_t *ret = (socket_t *)calloc(1, sizeof(socket_t));
  if (!ret) {
    ALOGE("%s unable to allocate memory for socket.", __func__);
    goto error;
  }

  ret->socket_object.fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (ret->socket_object.fd == -1) {
    ALOGE("%s unable to create socket: %s", __func__, strerror(errno));
    goto error;
  }

  int enable = 1;
  if (setsockopt(ret->socket_object.fd, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(enable)) == -1) {
    ALOGE("%s unable to set SO_REUSEADDR: %s", __func__, strerror(errno));
    goto error;
  }

  return ret;

error:;
  if (ret)
    close(ret->socket_object.fd);
  free(ret);
  return NULL;
}

void socket_free(socket_t *socket) {
  if (!socket)
    return;

  socket_unregister(socket);
  close(socket->socket_object.fd);
  free(socket);
}

bool socket_listen(const socket_t *socket, port_t port) {
  assert(socket != NULL);

  struct sockaddr_in addr;
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = 0;
  addr.sin_port = htons(port);
  if (bind(socket->socket_object.fd, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
    ALOGE("%s unable to bind socket to port %u: %s", __func__, port, strerror(errno));
    return false;
  }

  if (listen(socket->socket_object.fd, 10) == -1) {
    ALOGE("%s unable to listen on port %u: %s", __func__, port, strerror(errno));
    return false;
  }

  return true;
}

socket_t *socket_accept(const socket_t *socket) {
  assert(socket != NULL);

  int fd = accept(socket->socket_object.fd, NULL, NULL);
  if (fd == -1) {
    ALOGE("%s unable to accept socket: %s", __func__, strerror(errno));
    return NULL;
  }

  socket_t *ret = (socket_t *)calloc(1, sizeof(socket_t));
  if (!ret) {
    close(fd);
    ALOGE("%s unable to allocate memory for socket.", __func__);
    return NULL;
  }

  ret->socket_object.fd = fd;
  return ret;
}

ssize_t socket_read(const socket_t *socket, void *buf, size_t count) {
  assert(socket != NULL);
  assert(buf != NULL);

  return recv(socket->socket_object.fd, buf, count, MSG_DONTWAIT);
}

ssize_t socket_write(const socket_t *socket, const void *buf, size_t count) {
  assert(socket != NULL);
  assert(buf != NULL);

  return send(socket->socket_object.fd, buf, count, MSG_DONTWAIT);
}

void socket_register(socket_t *socket, thread_t *thread, socket_cb read_cb, socket_cb write_cb, void *context) {
  assert(socket != NULL);
  assert(reactor != NULL);
  assert(read_cb || write_cb);

  // Make sure the socket isn't currently registered.
  socket_unregister(socket);

  socket->thread = thread;
  socket->read_ready = read_cb;
  socket->write_ready = write_cb;
  socket->context = context;

  socket->socket_object.read_ready = internal_read_ready;
  socket->socket_object.write_ready = internal_write_ready;
  socket->socket_object.context = socket;
  if (read_cb && write_cb)
    socket->socket_object.interest = REACTOR_INTEREST_READ_WRITE;
  else if (read_cb)
    socket->socket_object.interest = REACTOR_INTEREST_READ;
  else if (write_cb)
    socket->socket_object.interest = REACTOR_INTEREST_WRITE;

  thread_register(thread, &socket->socket_object);
}

void socket_unregister(socket_t *socket) {
  assert(socket != NULL);

  if (socket->thread)
    thread_unregister(socket->thread, &socket->socket_object);
}

static void internal_read_ready(void *context) {
  assert(context != NULL);

  socket_t *socket = (void *)context;
  socket->read_ready(socket, socket->context);
}

static void internal_write_ready(void *context) {
  assert(context != NULL);

  socket_t *socket = (void *)context;
  socket->write_ready(socket, socket->context);
}
