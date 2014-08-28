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
#include "allocator.h"
#include "hash_functions.h"
#include "hash_map.h"
#include "osi.h"

#define ALLOCATION_HASH_MAP_SIZE 1024

typedef struct {
  void *ptr;
  size_t size;
  bool freed;
  bool is_canaried;
} allocation_t;

// Hidden constructor for hash map for our use only. Everything else should use the
// normal interface.
hash_map_t *hash_map_new_internal(
    size_t size,
    hash_index_fn hash_fn,
    key_free_fn key_fn,
    data_free_fn,
    const allocator_t *zeroed_allocator);

static bool allocation_entry_freed_checker(hash_map_entry_t *entry, void *context);
static void *untracked_calloc(size_t size);

static const char *canary = "tinybird";
static const allocator_t untracked_calloc_allocator = {
  untracked_calloc,
  free
};

static bool using_canaries;
static size_t canary_size;
static hash_map_t *allocations;
static pthread_mutex_t lock;

void allocation_tracker_init(bool use_canaries) {
  if (allocations)
    return;

  using_canaries = use_canaries;
  canary_size = strlen(canary);

  pthread_mutex_init(&lock, NULL);
  allocations = hash_map_new_internal(
    ALLOCATION_HASH_MAP_SIZE,
    hash_function_knuth,
    NULL,
    free,
    &untracked_calloc_allocator);
}

// Test function only. Do not call in the normal course of operations.
void allocation_tracker_uninit() {
  hash_map_free(allocations);
  allocations = NULL;
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

void *allocation_tracker_notify_alloc(void *ptr, size_t requested_size, bool add_canary) {
  if (!allocations || !ptr)
    return ptr;

  char *return_ptr = (char *)ptr;

  bool using_canaries_here = using_canaries && add_canary;
  if (using_canaries_here)
    return_ptr += canary_size;

  pthread_mutex_lock(&lock);

  allocation_t *allocation = (allocation_t *)hash_map_get(allocations, return_ptr);
  if (allocation) {
    assert(allocation->freed); // Must have been freed before
  } else {
    allocation = (allocation_t *)calloc(1, sizeof(allocation_t));
    hash_map_set(allocations, return_ptr, allocation);
  }

  allocation->is_canaried = using_canaries_here;
  allocation->freed = false;
  allocation->size = requested_size;
  allocation->ptr = return_ptr;

  pthread_mutex_unlock(&lock);

  if (using_canaries_here) {
    // Add the canary on both sides
    memcpy(return_ptr - canary_size, canary, canary_size);
    memcpy(return_ptr + requested_size, canary, canary_size);
  }

  return return_ptr;
}

void *allocation_tracker_notify_free(void *ptr) {
  if (!allocations || !ptr)
    return ptr;

  pthread_mutex_lock(&lock);

  allocation_t *allocation = (allocation_t *)hash_map_get(allocations, ptr);
  assert(allocation);         // Must have been tracked before
  assert(!allocation->freed); // Must not be a double free
  allocation->freed = true;

  if (allocation->is_canaried) {
    const char *beginning_canary = ((char *)ptr) - canary_size;
    const char *end_canary = ((char *)ptr) + allocation->size;

    for (size_t i = 0; i < canary_size; i++) {
      assert(beginning_canary[i] == canary[i]);
      assert(end_canary[i] == canary[i]);
    }
  }

  pthread_mutex_unlock(&lock);

  return allocation->is_canaried ? ((char *)ptr) - canary_size : ptr;
}

size_t allocation_tracker_resize_for_canary(size_t size) {
  return (!allocations || !using_canaries) ? size : size + (2 * canary_size);
}

static bool allocation_entry_freed_checker(hash_map_entry_t *entry, void *context) {
  allocation_t *allocation = (allocation_t *)entry->data;
  if (!allocation->freed) {
    *((size_t *)context) += allocation->size; // Report back the unfreed byte count
    ALOGE("%s found unfreed allocation. address: 0x%x size: %d bytes", __func__, (uintptr_t)allocation->ptr, allocation->size);
  }

  return true;
}

static void *untracked_calloc(size_t size) {
  return calloc(size, 1);
}
