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

#include <stdlib.h>
#include "ringbuffer.h"

struct ringbuffer_t {
  size_t total;
  size_t available;
  uint8_t *base;
  uint8_t *head;
  uint8_t *tail;
};

ringbuffer_t* ringbuffer_init(const size_t size) {
  ringbuffer_t* p = malloc(sizeof(ringbuffer_t));
  if (p == 0) {
    return NULL;
  }

  p->base = malloc(size);
  if (p->base == 0) {
    free(p);
    return NULL;
  }

  p->head = p->tail = p->base;
  p->total = p->available = size;

  return p;
}

void ringbuffer_free(ringbuffer_t *rb) {
  if (rb != NULL)
    free(rb->base);
  free(rb);
}

size_t ringbuffer_available(const ringbuffer_t *rb) {
  if (!rb)
    return 0;
  return rb->available;
}

size_t ringbuffer_size(const ringbuffer_t *rb) {
  if (!rb)
    return 0;
  return rb->total - rb->available;
}

size_t ringbuffer_insert(ringbuffer_t *rb, const uint8_t *p, size_t len) {
  if (!rb || !p)
    return 0;

  if (len > ringbuffer_available(rb))
    len = ringbuffer_available(rb);

  for (size_t i = 0; i != len; ++i) {
    *rb->tail++ = *p++;
    if (rb->tail >= (rb->base + rb->total))
      rb->tail = rb->base;
  }

  rb->available -= len;
  return len;
}

size_t ringbuffer_delete(ringbuffer_t *rb, size_t len) {
  if (!rb)
    return 0;

  if (len > ringbuffer_size(rb))
    len = ringbuffer_size(rb);

  rb->head += len;
  if (rb->head >= (rb->base + rb->total))
    rb->head -= rb->total;

  rb->available += len;
  return len;
}

size_t ringbuffer_peek(const ringbuffer_t *rb, uint8_t *p, size_t len) {
  if (!rb || !p)
    return 0;

  uint8_t *b = rb->head;
  size_t copied = 0;

  while (copied < len && copied < ringbuffer_size(rb)) {
    *p++ = *b++;
    if (b >= (rb->base + rb->total))
      b = rb->base;
    ++copied;
  }

  return copied;
}

size_t ringbuffer_pop(ringbuffer_t *rb, uint8_t *p, size_t len) {
  if (!rb || !p)
    return 0;

  const size_t copied = ringbuffer_peek(rb, p, len);
  rb->head += copied;
  if (rb->head >= (rb->base + rb->total))
    rb->head -= rb->total;

  rb->available += copied;
  return copied;
}
