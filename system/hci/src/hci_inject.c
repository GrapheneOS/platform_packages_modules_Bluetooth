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

#define LOG_TAG "bt_hci_inject"

#include <assert.h>
#include <errno.h>
#include <utils/Log.h>

#include "bt_hci_bdroid.h"
#include "bt_types.h"
#include "hci_inject.h"
#include "list.h"
#include "osi.h"
#include "socket.h"
#include "thread.h"

typedef enum {
  HCI_PACKET_COMMAND  = 1,
  HCI_PACKET_ACL_DATA = 2,
  HCI_PACKET_SCO_DATA = 3,
  HCI_PACKET_EVENT    = 4,
} hci_packet_t;

typedef struct {
  socket_t *socket;
  uint8_t buffer[65536 + 3];  // 2 bytes length prefix, 1 byte type prefix.
  size_t buffer_size;
} client_t;

static const port_t LISTEN_PORT = 8873;

static const bt_hc_interface_t *hci;
static socket_t *listen_socket;
static thread_t *thread;
static list_t *clients;

static int hci_packet_to_event(hci_packet_t packet);
static void accept_ready(socket_t *socket, void *context);
static void read_ready(socket_t *socket, void *context);
static void client_free(void *ptr);

bool hci_inject_open(void) {
  assert(listen_socket == NULL);
  assert(thread == NULL);
  assert(clients == NULL);

  hci = bt_hc_get_interface();

  thread = thread_new("hci_inject");
  if (!thread)
    goto error;

  clients = list_new(client_free);
  if (!clients)
    goto error;

  listen_socket = socket_new();
  if (!listen_socket)
    goto error;

  if (!socket_listen(listen_socket, LISTEN_PORT))
    goto error;

  socket_register(listen_socket, thread_get_reactor(thread), NULL, accept_ready, NULL);
  return true;

error:;
  hci_inject_close();
  return false;
}

void hci_inject_close(void) {
  socket_free(listen_socket);
  list_free(clients);
  thread_free(thread);

  listen_socket = NULL;
  thread = NULL;
  clients = NULL;
}

static int hci_packet_to_event(hci_packet_t packet) {
  switch (packet) {
    case HCI_PACKET_COMMAND:
      return MSG_STACK_TO_HC_HCI_CMD;
    case HCI_PACKET_ACL_DATA:
      return MSG_STACK_TO_HC_HCI_ACL;
    case HCI_PACKET_SCO_DATA:
      return MSG_STACK_TO_HC_HCI_SCO;
    default:
      ALOGE("%s unsupported packet type: %d", __func__, packet);
      return -1;
  }
}

static void accept_ready(socket_t *socket, UNUSED_ATTR void *context) {
  assert(socket != NULL);
  assert(socket == listen_socket);

  socket = socket_accept(socket);
  if (!socket)
    return;

  client_t *client = (client_t *)calloc(1, sizeof(client_t));
  if (!client) {
    ALOGE("%s unable to allocate memory for client.", __func__);
    socket_free(socket);
    return;
  }

  client->socket = socket;

  if (!list_append(clients, client)) {
    ALOGE("%s unable to add client to list.", __func__);
    client_free(client);
    return;
  }

  socket_register(socket, thread_get_reactor(thread), client, read_ready, NULL);
}

static void read_ready(UNUSED_ATTR socket_t *socket, void *context) {
  assert(bt_hc_cbacks != NULL);
  assert(socket != NULL);
  assert(context != NULL);

  client_t *client = (client_t *)context;

  ssize_t ret = socket_read(client->socket, client->buffer + client->buffer_size, sizeof(client->buffer) - client->buffer_size);
  if (ret == 0 || (ret == -1 && ret != EWOULDBLOCK && ret != EAGAIN)) {
    list_remove(clients, client);
    return;
  }
  client->buffer_size += ret;

  while (client->buffer_size > 3) {
    uint8_t *buffer = client->buffer;
    hci_packet_t packet_type = (hci_packet_t)buffer[0];
    size_t packet_len = (buffer[2] << 8) | buffer[1];
    size_t frame_len = 3 + packet_len;

    if (client->buffer_size < frame_len)
      break;

    // TODO(sharvil): validate incoming HCI messages.
    // TODO(sharvil): once we have an HCI parser, we can eliminate
    //   the 2-byte size field since it will be contained in the packet.

    BT_HDR *buf = (BT_HDR *)bt_hc_cbacks->alloc(packet_len);
    if (buf) {
      buf->event = hci_packet_to_event(packet_type);
      buf->offset = 0;
      buf->layer_specific = 0;
      buf->len = packet_len;
      memcpy(buf->data, buffer + 3, packet_len);
      hci->transmit_buf(buf, NULL, 0);
    } else {
      ALOGE("%s dropping injected packet of length %zu", __func__, packet_len);
    }

    size_t remainder = client->buffer_size - frame_len;
    memmove(buffer, buffer + frame_len, remainder);
    client->buffer_size -= frame_len;
  }
}

static void client_free(void *ptr) {
  if (!ptr)
    return;

  client_t *client = (client_t *)ptr;
  socket_free(client->socket);
}
