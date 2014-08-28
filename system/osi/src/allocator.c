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

#include "allocator.h"
#include "allocation_tracker.h"

char *osi_strdup(const char *str) {
  return allocation_tracker_notify_alloc(strdup(str), strlen(str) + 1, false); // + 1 for the null terminator
}

void *osi_malloc(size_t size) {
  size_t real_size = allocation_tracker_resize_for_canary(size);
  return allocation_tracker_notify_alloc(malloc(real_size), size, true);
}

void *osi_calloc(size_t size) {
  size_t real_size = allocation_tracker_resize_for_canary(size);
  return allocation_tracker_notify_alloc(calloc(1, real_size), size, true);
}

void osi_free(void *ptr) {
  free(allocation_tracker_notify_free(ptr));
}

const allocator_t allocator_malloc = {
  osi_malloc,
  osi_free
};

const allocator_t allocator_calloc = {
  osi_calloc,
  osi_free
};
