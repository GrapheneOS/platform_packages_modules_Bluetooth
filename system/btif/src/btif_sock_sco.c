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

#define LOG_TAG "btif_sock_sco"

#include <assert.h>
#include <hardware/bluetooth.h>
#include <hardware/bt_sock.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <utils/Log.h>

#include "btif_common.h"
#include "btif_sock_thread.h"
#include "btif_sock_util.h"
#include "list.h"
#include "osi.h"

// This module provides a socket abstraction for SCO connections to a higher
// layer. It returns file descriptors representing two types of sockets:
// listening (server) and connected (client) sockets. No SCO data is
// transferred across these sockets; instead, they are used to manage SCO
// connection lifecycles while the data routing takes place over the I2S bus.
//
// This code bridges the gap between the BTM layer, which implements SCO
// connections, and the Android HAL. It adapts the BTM representation of SCO
// connections (integer handles) to a file descriptor representation usable by
// Android's LocalSocket implementation.
//
// Sample flow for an incoming connection:
//   btsock_sco_listen()       - listen for incoming connections
//   connection_request_cb()   - incoming connection request from remote host
//   connect_completed_cb()    - connection successfully established
//   btsock_sco_signaled()     - local host closed SCO socket
//   disconnect_completed_cb() - connection terminated

typedef struct {
  uint16_t sco_handle;
  int user_fd;
  bool connect_completed;
} sco_socket_t;

// TODO: verify packet types that are being sent OTA.
static tBTM_ESCO_PARAMS sco_parameters = {
    BTM_64KBITS_RATE,                   /* TX Bandwidth (64 kbits/sec)              */
    BTM_64KBITS_RATE,                   /* RX Bandwidth (64 kbits/sec)              */
    0x000a,                             /* 10 ms (HS/HF can use EV3, 2-EV3, 3-EV3)  */
    0x0060,                             /* Inp Linear, Air CVSD, 2s Comp, 16bit     */
    (BTM_SCO_LINK_ALL_PKT_MASK       |
     BTM_SCO_PKT_TYPES_MASK_NO_2_EV5 |
     BTM_SCO_PKT_TYPES_MASK_NO_3_EV5),
     BTM_ESCO_RETRANS_POWER       /* Retransmission effort                      */
};

static sco_socket_t *sco_socket_establish_locked(bool is_listening, const bt_bdaddr_t *bd_addr, int *sock_fd);
static sco_socket_t *sco_socket_new(void);
static void sco_socket_free_locked(sco_socket_t *socket);
static sco_socket_t *sco_socket_find_locked(uint16_t sco_handle);
static void connection_request_cb(tBTM_ESCO_EVT event, tBTM_ESCO_EVT_DATA *data);
static void connect_completed_cb(uint16_t sco_handle);
static void disconnect_completed_cb(uint16_t sco_handle);

// |lock| protects all of the static variables below and
// calls into the BTM layer.
static pthread_mutex_t lock;
static list_t *sockets;              // Owns a collection of sco_socket_t objects.
static sco_socket_t *listen_socket;  // Not owned, do not free.
static int thread_handle = -1;       // Thread is not owned, do not tear down.

bt_status_t btsock_sco_init(int poll_thread_handle) {
  assert(poll_thread_handle != -1);

  sockets = list_new((list_free_cb)sco_socket_free_locked);
  if (!sockets)
    return BT_STATUS_FAIL;

  pthread_mutex_init(&lock, NULL);

  thread_handle = poll_thread_handle;
  BTM_SetEScoMode(BTM_LINK_TYPE_SCO, &sco_parameters);

  return BT_STATUS_SUCCESS;
}

bt_status_t btsock_sco_cleanup(void) {
  list_free(sockets);
  sockets = NULL;
  pthread_mutex_destroy(&lock);
  return BT_STATUS_SUCCESS;
}

bt_status_t btsock_sco_listen(int *sock_fd, UNUSED_ATTR int flags) {
  assert(sock_fd != NULL);

  pthread_mutex_lock(&lock);

  sco_socket_t *socket = sco_socket_establish_locked(true, NULL, sock_fd);
  if (socket) {
    BTM_RegForEScoEvts(socket->sco_handle, connection_request_cb);
    listen_socket = socket;
  }

  pthread_mutex_unlock(&lock);

  return socket ? BT_STATUS_SUCCESS : BT_STATUS_FAIL;
}

bt_status_t btsock_sco_connect(const bt_bdaddr_t *bd_addr, int *sock_fd, UNUSED_ATTR int flags) {
  assert(bd_addr != NULL);
  assert(sock_fd != NULL);

  pthread_mutex_lock(&lock);
  sco_socket_t *socket = sco_socket_establish_locked(false, bd_addr, sock_fd);
  pthread_mutex_unlock(&lock);

  return (socket != NULL) ? BT_STATUS_SUCCESS : BT_STATUS_FAIL;
}

// Must be called with |lock| held.
static sco_socket_t *sco_socket_establish_locked(bool is_listening, const bt_bdaddr_t *bd_addr, int *sock_fd) {
  int pair[2] = { INVALID_FD, INVALID_FD };
  sco_socket_t *socket = NULL;

  if (socketpair(AF_LOCAL, SOCK_STREAM, 0, pair) == -1) {
    ALOGE("%s unable to allocate socket pair: %s", __func__, strerror(errno));
    goto error;
  }

  socket = sco_socket_new();
  if (!socket) {
    ALOGE("%s unable to allocate new SCO socket.", __func__);
    goto error;
  }

  tBTM_STATUS status = BTM_CreateSco((uint8_t *)bd_addr, !is_listening, sco_parameters.packet_types, &socket->sco_handle, connect_completed_cb, disconnect_completed_cb);
  if (status != BTM_CMD_STARTED) {
    ALOGE("%s unable to create SCO socket: %d", __func__, status);
    goto error;
  }

  *sock_fd = pair[0];         // Transfer ownership of one end to caller.
  socket->user_fd = pair[1];  // Hang on to the other end.
  list_append(sockets, socket);

  btsock_thread_add_fd(thread_handle, socket->user_fd, BTSOCK_SCO, SOCK_THREAD_FD_EXCEPTION, 0);
  return socket;

error:;
  if (pair[0] != INVALID_FD)
    close(pair[0]);
  if (pair[1] != INVALID_FD)
    close(pair[1]);

  sco_socket_free_locked(socket);
  return NULL;
}

static sco_socket_t *sco_socket_new(void) {
  sco_socket_t *socket = (sco_socket_t *)calloc(1, sizeof(sco_socket_t));
  if (socket) {
    socket->sco_handle = BTM_INVALID_SCO_INDEX;
    socket->user_fd = INVALID_FD;
  }
  return socket;
}

// Must be called with |lock| held except during teardown when we know btsock_thread is
// no longer alive.
static void sco_socket_free_locked(sco_socket_t *socket) {
  if (!socket)
    return;

  if (socket->sco_handle != BTM_INVALID_SCO_INDEX)
    BTM_RemoveSco(socket->sco_handle);
  if (socket->user_fd != INVALID_FD)
    close(socket->user_fd);
  free(socket);
}

// Must be called with |lock| held.
static sco_socket_t *sco_socket_find_locked(uint16_t sco_handle) {
  for (const list_node_t *node = list_begin(sockets); node != list_end(sockets); node = list_next(node)) {
    sco_socket_t *socket = (sco_socket_t *)list_node(node);
    if (socket->sco_handle == sco_handle)
      return socket;
  }
  return NULL;
}

static void connection_request_cb(tBTM_ESCO_EVT event, tBTM_ESCO_EVT_DATA *data) {
  assert(data != NULL);

  // Don't care about change of link parameters, only connection requests.
  if (event != BTM_ESCO_CONN_REQ_EVT)
    return;

  pthread_mutex_lock(&lock);

  const tBTM_ESCO_CONN_REQ_EVT_DATA *conn_data = &data->conn_evt;
  sco_socket_t *socket = sco_socket_find_locked(conn_data->sco_inx);
  int client_fd = INVALID_FD;

  if (!socket) {
    ALOGE("%s unable to find sco_socket for handle: %hu", __func__, conn_data->sco_inx);
    goto error;
  }

  if (socket != listen_socket) {
    ALOGE("%s received connection request on non-listening socket handle: %hu", __func__, conn_data->sco_inx);
    goto error;
  }

  sco_socket_t *new_socket = sco_socket_establish_locked(true, NULL, &client_fd);
  if (!new_socket) {
    ALOGE("%s unable to allocate new sco_socket.", __func__);
    goto error;
  }

  // Swap socket->sco_handle and new_socket->sco_handle
  uint16_t temp = socket->sco_handle;
  socket->sco_handle = new_socket->sco_handle;
  new_socket->sco_handle = temp;

  sock_connect_signal_t connect_signal;
  connect_signal.size = sizeof(connect_signal);
  memcpy(&connect_signal.bd_addr, conn_data->bd_addr, sizeof(bt_bdaddr_t));
  connect_signal.channel = 0;
  connect_signal.status = 0;

  if (sock_send_fd(socket->user_fd, (const uint8_t *)&connect_signal, sizeof(connect_signal), client_fd) != sizeof(connect_signal)) {
    ALOGE("%s unable to send new file descriptor to listening socket.", __func__);
    goto error;
  }

  BTM_RegForEScoEvts(listen_socket->sco_handle, connection_request_cb);
  BTM_EScoConnRsp(conn_data->sco_inx, HCI_SUCCESS, NULL);
  btsock_thread_add_fd(thread_handle, listen_socket->user_fd, BTSOCK_SCO, SOCK_THREAD_FD_EXCEPTION, 0);

  pthread_mutex_unlock(&lock);
  return;

error:;
  pthread_mutex_unlock(&lock);

  if (client_fd != INVALID_FD)
    close(client_fd);
  BTM_EScoConnRsp(conn_data->sco_inx, HCI_ERR_HOST_REJECT_RESOURCES, NULL);
}

static void connect_completed_cb(uint16_t sco_handle) {
  pthread_mutex_lock(&lock);

  sco_socket_t *socket = sco_socket_find_locked(sco_handle);
  if (!socket) {
    ALOGE("%s SCO socket not found on connect for handle: %hu", __func__, sco_handle);
    goto out;
  }

  // If user_fd was closed, we should tear down because there is no app-level
  // interest in the SCO socket.
  if (socket->user_fd == INVALID_FD) {
    BTM_RemoveSco(socket->sco_handle);
    list_remove(sockets, socket);
    goto out;
  }

  socket->connect_completed = true;

out:;
  pthread_mutex_unlock(&lock);
}

static void disconnect_completed_cb(uint16_t sco_handle) {
  pthread_mutex_lock(&lock);

  sco_socket_t *socket = sco_socket_find_locked(sco_handle);
  if (!socket) {
    ALOGE("%s SCO socket not found on disconnect for handle: %hu", __func__, sco_handle);
    goto out;
  }

  // TODO: why doesn't close(2) unblock the reader on the other end immediately?
  // We shouldn't have to write data on the socket as an indication of closure.
  if (socket->user_fd != INVALID_FD) {
    write(socket->user_fd, &socket->user_fd, 1);
    btsock_thread_remove_fd_and_close(thread_handle, socket->user_fd);
    socket->user_fd = INVALID_FD;
  }

  list_remove(sockets, socket);

out:;
  pthread_mutex_unlock(&lock);
}

// Called back in a separate thread from all of the other interface functions.
void btsock_sco_signaled(int fd, UNUSED_ATTR int flags, UNUSED_ATTR uint32_t user_id) {
  pthread_mutex_lock(&lock);

  sco_socket_t *socket = NULL;
  for (const list_node_t *node = list_begin(sockets); node != list_end(sockets); node = list_next(node)) {
    sco_socket_t *cur_socket = (sco_socket_t *)list_node(node);
    if (cur_socket->user_fd == fd) {
      socket = cur_socket;
      break;
    }
  }

  if (!socket)
    goto out;

  close(socket->user_fd);
  socket->user_fd = INVALID_FD;

  // Defer the underlying disconnect until the connection completes
  // since the BTM code doesn't behave correctly when a disconnect
  // request is issued while a connect is in progress. The fact that
  // socket->user_fd == INVALID_FD indicates to the connect callback
  // routine that the socket is no longer desired and should be torn
  // down.
  if (socket->connect_completed || socket == listen_socket) {
    if (BTM_RemoveSco(socket->sco_handle) == BTM_SUCCESS)
      list_remove(sockets, socket);
    if (socket == listen_socket)
      listen_socket = NULL;
  }

out:;
  pthread_mutex_unlock(&lock);
}
