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
#include <pthread.h>
#include <utils/Log.h>

#include "allocation_tracker.h"
#include "hash_functions.h"
#include "hash_map.h"
#include "osi.h"

#define ALLOCATION_HASH_MAP_SIZE 1024

typedef struct {
  void *ptr;
  size_t size;
  bool freed;
} allocation_t;

static bool allocation_entry_freed_checker(hash_map_entry_t *entry, void *context);

static hash_map_t *allocations;
static pthread_mutex_t lock;

void allocation_tracker_init(void) {
  if (allocations)
    return;

  allocations = hash_map_new(ALLOCATION_HASH_MAP_SIZE, hash_function_knuth, NULL, free);
  pthread_mutex_init(&lock, NULL);
}

void allocation_tracker_reset(void) {
  if (!allocations)
    return;

  hash_map_clear(allocations);
}

size_t allocation_tracker_expect_no_allocations() {
  if (!allocations)
    return 0;

  pthread_mutex_lock(&lock);

  size_t unfreed_memory_size = 0;
  hash_map_foreach(allocations, allocation_entry_freed_checker, &unfreed_memory_size);

  pthread_mutex_unlock(&lock);

  return unfreed_memory_size;
}

void allocation_tracker_notify_alloc(void *ptr, size_t size) {
  if (!allocations || !ptr)
    return;

  pthread_mutex_lock(&lock);

  allocation_t *allocation = (allocation_t *)hash_map_get(allocations, ptr);
  if (allocation) {
    assert(allocation->freed); // Must have been freed before
  } else {
    allocation = (allocation_t *)calloc(1, sizeof(allocation_t));
    hash_map_set(allocations, ptr, allocation);
  }

  allocation->freed = false;
  allocation->size = size;
  allocation->ptr = ptr;

  pthread_mutex_unlock(&lock);
}

void allocation_tracker_notify_free(void *ptr) {
  if (!allocations || !ptr)
    return;

  pthread_mutex_lock(&lock);

  allocation_t *allocation = (allocation_t *)hash_map_get(allocations, ptr);
  assert(allocation);         // Must have been tracked before
  assert(!allocation->freed); // Must not be a double free
  allocation->freed = true;

  pthread_mutex_unlock(&lock);
}

static bool allocation_entry_freed_checker(hash_map_entry_t *entry, void *context) {
  allocation_t *allocation = (allocation_t *)entry->data;
  if (!allocation->freed) {
    *((size_t *)context) += allocation->size; // Report back the unfreed byte count
    ALOGE("%s found unfreed allocation. address: 0x%x size: %d bytes", __func__, (uintptr_t)allocation->ptr, allocation->size);
  }

  return true;
}
