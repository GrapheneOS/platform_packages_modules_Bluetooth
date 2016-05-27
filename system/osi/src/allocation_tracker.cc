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

#define LOG_TAG "bt_osi_allocation_tracker"

#include "osi/include/allocation_tracker.h"

#include <assert.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <unordered_map>

#include "osi/include/allocator.h"
#include "osi/include/log.h"
#include "osi/include/osi.h"

typedef struct {
  uint8_t allocator_id;
  void *ptr;
  size_t size;
  bool freed;
} allocation_t;

static const size_t canary_size = 8;
static char canary[canary_size];

static std::unordered_map<void*, allocation_t*> allocations;
static pthread_mutex_t lock;
static bool enabled = false;

void allocation_tracker_init(void) {
  if (enabled)
    return;

  // randomize the canary contents
  for (size_t i = 0; i < canary_size; i++)
     canary[i] = (char)osi_rand();

  LOG_DEBUG(LOG_TAG, "canary initialized");

  pthread_mutex_init(&lock, NULL);

  pthread_mutex_lock(&lock);
  enabled = true;
  pthread_mutex_unlock(&lock);
}

// Test function only. Do not call in the normal course of operations.
void allocation_tracker_uninit(void) {
  if (!enabled)
    return;

  pthread_mutex_lock(&lock);
  allocations.clear();
  enabled = false;
  pthread_mutex_unlock(&lock);
}

void allocation_tracker_reset(void) {
  if (!enabled)
    return;

  pthread_mutex_lock(&lock);
  allocations.clear();
  pthread_mutex_unlock(&lock);
}

size_t allocation_tracker_expect_no_allocations(void) {
  if (!enabled)
    return 0;

  pthread_mutex_lock(&lock);

  size_t unfreed_memory_size = 0;

  for (const auto &entry : allocations) {
    allocation_t *allocation = entry.second;
    if (!allocation->freed) {
      unfreed_memory_size += allocation->size; // Report back the unfreed byte count
      LOG_ERROR(LOG_TAG, "%s found unfreed allocation. address: 0x%zx size: %zd bytes", __func__, (uintptr_t)allocation->ptr, allocation->size);
    }
  }

  pthread_mutex_unlock(&lock);

  return unfreed_memory_size;
}

void *allocation_tracker_notify_alloc(uint8_t allocator_id, void *ptr, size_t requested_size) {
  if (!enabled || !ptr)
    return ptr;

  char *return_ptr = (char *)ptr;

  return_ptr += canary_size;

  pthread_mutex_lock(&lock);

  auto map_entry = allocations.find(return_ptr);
  allocation_t *allocation;
  if (map_entry != allocations.end()) {
    allocation = map_entry->second;
    assert(allocation->freed); // Must have been freed before
  } else {
    allocation = (allocation_t *)calloc(1, sizeof(allocation_t));
    allocations[return_ptr] = allocation;
  }

  allocation->allocator_id = allocator_id;
  allocation->freed = false;
  allocation->size = requested_size;
  allocation->ptr = return_ptr;

  pthread_mutex_unlock(&lock);

  // Add the canary on both sides
  memcpy(return_ptr - canary_size, canary, canary_size);
  memcpy(return_ptr + requested_size, canary, canary_size);

  return return_ptr;
}

void *allocation_tracker_notify_free(UNUSED_ATTR uint8_t allocator_id, void *ptr) {
  if (!enabled || !ptr)
    return ptr;

  pthread_mutex_lock(&lock);

  auto map_entry = allocations.find(ptr);
  assert(map_entry != allocations.end());
  allocation_t *allocation = map_entry->second;
  assert(allocation);                               // Must have been tracked before
  assert(!allocation->freed);                       // Must not be a double free
  assert(allocation->allocator_id == allocator_id); // Must be from the same allocator
  allocation->freed = true;

  UNUSED_ATTR const char *beginning_canary = ((char *)ptr) - canary_size;
  UNUSED_ATTR const char *end_canary = ((char *)ptr) + allocation->size;

  for (size_t i = 0; i < canary_size; i++) {
    assert(beginning_canary[i] == canary[i]);
    assert(end_canary[i] == canary[i]);
  }

  // Free the hash map entry to avoid unlimited memory usage growth.
  // Double-free of memory is detected with "assert(allocation)" above
  // as the allocation entry will not be present.
  allocations.erase(ptr);

  pthread_mutex_unlock(&lock);

  return ((char *)ptr) - canary_size;
}

size_t allocation_tracker_resize_for_canary(size_t size) {
  return (!enabled) ? size : size + (2 * canary_size);
}
