/******************************************************************************
 *
 *  Copyright (C) 2014 Android Open Source Project
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

#include <resolv.h>
#include <zlib.h>
#include "bt_target.h"
#include "btif_debug.h"
#include "btif_debug_btsnoop.h"
#include "btsnoop_mem.h"
#include "ringbuffer.h"

// Total btsnoop memory log buffer size
#ifndef BTSNOOP_MEM_BUFFER_SIZE
#define BTSNOOP_MEM_BUFFER_SIZE 131072
#endif

// Block size for copying buffers (for compression/encoding etc.)
#define BLOCK_SIZE 16384

// Maximum line length in bugreport (should be multiple of 4 for base64 output)
#define MAX_LINE_LENGTH 128

static ringbuffer_t *s_buffer = NULL;
static uint64_t s_last_ts = 0;

static void btsnoop_cb(const uint8_t type, const uint16_t len, const uint8_t *p_data) {
  btsnooz_hdr_t hdr;

  // Make room in the ring buffer

  while (ringbuffer_available(s_buffer) < (len + sizeof(btsnooz_hdr_t))) {
    ringbuffer_pop(s_buffer, (uint8_t*)&hdr, sizeof(btsnooz_hdr_t));
    ringbuffer_delete(s_buffer, hdr.len-1);
  }

  // Insert data

  const uint64_t now = btif_debug_ts();

  hdr.type = type;
  hdr.len = len;
  hdr.delta = s_last_ts ? now - s_last_ts : 0;
  s_last_ts = now;

  ringbuffer_insert(s_buffer, (uint8_t*)&hdr, sizeof(btsnooz_hdr_t));
  ringbuffer_insert(s_buffer, p_data, len-1);
}

static bool btsnoop_compress(ringbuffer_t *rb_in, ringbuffer_t *rb_out) {
  if (rb_in == NULL || rb_out == NULL)
    return false;

  z_stream zs = {0};
  if (deflateInit(&zs, Z_DEFAULT_COMPRESSION) != Z_OK)
    return false;

  bool rc = true;
  uint8_t b_in[BLOCK_SIZE];
  uint8_t b_out[BLOCK_SIZE];

  while(ringbuffer_size(rb_in) > 0) {
    zs.avail_in = ringbuffer_pop(rb_in, b_in, BLOCK_SIZE);
    zs.next_in = b_in;

    do {
      zs.avail_out = BLOCK_SIZE;
      zs.next_out = b_out;

      int err = deflate(&zs, ringbuffer_size(rb_in) == 0 ? Z_FINISH : Z_NO_FLUSH);
      if (err == Z_STREAM_ERROR) {
        rc = false;
        break;
      }

      const size_t len = BLOCK_SIZE - zs.avail_out;
      ringbuffer_insert(rb_out, b_out, len);
    } while (zs.avail_out == 0);
  }

  deflateEnd(&zs);
  return rc;
}

void btif_debug_btsnoop_init() {
  if (s_buffer == NULL)
    s_buffer = ringbuffer_init(BTSNOOP_MEM_BUFFER_SIZE);
  btsnoop_mem_set_callback(btsnoop_cb);
}

void btif_debug_btsnoop_dump(int fd) {
  dprintf(fd, "\n--- BEGIN:BTSNOOP_LOG_SUMMARY (%zu bytes in) ---\n", ringbuffer_size(s_buffer));

  ringbuffer_t *rb = ringbuffer_init(BTSNOOP_MEM_BUFFER_SIZE);
  if (rb == NULL) {
    dprintf(fd, "%s() - Unable to allocate memory for compression", __FUNCTION__);
    return;
  }

  // Prepend preamble

  btsnooz_preamble_t preamble;
  preamble.version = BTSNOOZ_CURRENT_VERSION;
  preamble.last_ts = s_last_ts;
  ringbuffer_insert(rb, (uint8_t*)&preamble, sizeof(btsnooz_preamble_t));

  // Compress data

  bool rc = btsnoop_compress(s_buffer, rb);
  if (rc == false) {
    dprintf(fd, "%s() - Log compression failed", __FUNCTION__);
    goto err;
  }

  // Base64 encode & output

  uint8_t b64_in[3] = {0};
  char b64_out[5] = {0};

  size_t i = sizeof(btsnooz_preamble_t);
  while (ringbuffer_size(rb) > 0) {
    size_t read = ringbuffer_pop(rb, b64_in, 3);
    if (i > 0 && i % MAX_LINE_LENGTH == 0)
      dprintf(fd, "\n");
    i += b64_ntop(b64_in, read, b64_out, 5);
    dprintf(fd, b64_out);
  }

  dprintf(fd, "\n--- END:BTSNOOP_LOG_SUMMARY (%zu bytes out) ---\n", i);

err:
  ringbuffer_free(rb);
}
