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
#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include "osi/include/allocator.h"
#include "osi/include/allocation_tracker.h"

static const allocator_id_t alloc_allocator_id = 42;

char *osi_strdup(const char *str) {
  size_t size = strlen(str) + 1;  // + 1 for the null terminator
  size_t real_size = allocation_tracker_resize_for_canary(size);
  void *ptr = malloc(real_size);
  assert(ptr);

  char *new_string = allocation_tracker_notify_alloc(
      alloc_allocator_id,
      ptr,
      size);
  if (!new_string)
    return NULL;

  memcpy(new_string, str, size);
  return new_string;
}

char *osi_strndup(const char *str, size_t len) {
  size_t size = strlen(str);
  if (len < size)
    size = len;

  size_t real_size = allocation_tracker_resize_for_canary(size + 1);
  void *ptr = malloc(real_size);
  assert(ptr);

  char *new_string = allocation_tracker_notify_alloc(
      alloc_allocator_id,
      ptr,
      size + 1);
  if (!new_string)
    return NULL;

  memcpy(new_string, str, size);
  new_string[size] = '\0';
  return new_string;
}

void *osi_malloc(size_t size) {
  size_t real_size = allocation_tracker_resize_for_canary(size);
  void *ptr = malloc(real_size);
  assert(ptr);
  return allocation_tracker_notify_alloc(alloc_allocator_id, ptr, size);
}

void *osi_calloc(size_t size) {
  size_t real_size = allocation_tracker_resize_for_canary(size);
  void *ptr = calloc(1, real_size);
  assert(ptr);
  return allocation_tracker_notify_alloc(alloc_allocator_id, ptr, size);
}

void osi_free(void *ptr) {
  free(allocation_tracker_notify_free(alloc_allocator_id, ptr));
}

const allocator_t allocator_calloc = {
  osi_calloc,
  osi_free
};

const allocator_t allocator_malloc = {
  osi_malloc,
  osi_free
};

//
// TODO: Temporary buffer-allocation wrappers: should be removed
//
#define MAGIC_NUMBER 0xDDBADDBA
typedef struct _buffer_hdr
{
  uint16_t size;
  uint32_t magic_number;
} BUFFER_HDR_T;

void *osi_getbuf(uint16_t size)
{
  BUFFER_HDR_T *header = osi_malloc(size + sizeof(BUFFER_HDR_T));
  header->size = size;
  header->magic_number = MAGIC_NUMBER;
  return header + 1;
}

void osi_freebuf(void *p_buf)
{
  BUFFER_HDR_T *header = (BUFFER_HDR_T *)p_buf - 1;
  assert(header->magic_number == MAGIC_NUMBER);
  osi_free(header);
}

uint16_t osi_get_buf_size(void *p_buf)
{
  BUFFER_HDR_T *header = (BUFFER_HDR_T *)p_buf - 1;
  assert(header->magic_number == MAGIC_NUMBER);
  return header->size;
}
