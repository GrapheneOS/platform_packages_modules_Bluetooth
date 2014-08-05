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

#pragma once

#include <stddef.h>
#include <stdint.h>

#include "thread.h"

typedef struct reactor_t reactor_t;
typedef struct socket_t socket_t;
typedef uint16_t port_t;

typedef void (*socket_cb)(socket_t *socket, void *context);

// Returns a new socket object. The socket is in an idle, disconnected state when
// it is returned by this function. The returned object must be freed by calling
// |socket_free|. Returns NULL on failure.
socket_t *socket_new(void);

// Frees a socket object created by |socket_new| or |socket_accept|. |socket| may
// be NULL. If the socket was connected, it will be disconnected.
void socket_free(socket_t *socket);

// Puts |socket| in listening mode for incoming TCP connections on the specified
// |port|. Returns true on success, false on failure (e.g. |port| is bound by
// another socket). |socket| may not be NULL.
bool socket_listen(const socket_t *socket, port_t port);

// Blocks on a listening socket, |socket|, until a client connects to it. Returns
// a connected socket on success, NULL on failure. The returned object must be
// freed by calling |socket_free|. |socket| may not be NULL.
socket_t *socket_accept(const socket_t *socket);

// Reads up to |count| bytes from |socket| into |buf|. This function will not
// block. This function returns a positive integer representing the number
// of bytes copied into |buf| on success, 0 if the socket has disconnected,
// and -1 on error. This function may return a value less than |count| if not
// enough data is currently available. If this function returns -1, errno will also
// be set (see recv(2) for possible errno values). If there were no bytes available
// to be read, this function returns -1 and sets errno to EWOULDBLOCK. Neither
// |socket| nor |buf| may be NULL.
ssize_t socket_read(const socket_t *socket, void *buf, size_t count);

// Writes up to |count| bytes from |buf| into |socket|. This function will not
// block. Returns a positive integer representing the number of bytes written
// to |socket| on success, 0 if the socket has disconnected, and -1 on error. This
// function may return a value less than |count| if writing more bytes would result
// in blocking. If this function returns -1, errno will also be set (see send(2) for
// possible errno values). If no bytes could be written without blocking, this
// function will return -1 and set errno to EWOULDBLOCK. Neither |socket| nor |buf|
// may be NULL.
ssize_t socket_write(const socket_t *socket, const void *buf, size_t count);

// Registers |socket| with the |thread|. When the socket becomes readable, |read_cb|
// will be called. When the socket becomes writeable, |write_cb| will be called. The
// |context| parameter is passed, untouched, to each of the callback routines. Neither
// |socket| nor |thread| may be NULL. |read_cb| or |write_cb|, but not both, may be NULL.
// |context| may be NULL.
void socket_register(socket_t *socket, thread_t *thread, socket_cb read_cb, socket_cb write_cb, void *context);

// Unregisters |socket| from whichever thread it is registered with, if any. This
// function is idempotent.
void socket_unregister(socket_t *socket);
