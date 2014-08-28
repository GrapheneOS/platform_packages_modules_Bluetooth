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
  char *ret = strdup(str);
  allocation_tracker_notify_alloc(ret, strlen(ret) + 1); // + 1 for the null terminator
  return ret;
}

void *osi_malloc(size_t size) {
  void *ptr = malloc(size);
  allocation_tracker_notify_alloc(ptr, size);
  return ptr;
}

void *osi_calloc(size_t size) {
  void *ptr = calloc(1, size);
  allocation_tracker_notify_alloc(ptr, size);
  return ptr;
}

void osi_free(void *ptr) {
  allocation_tracker_notify_free(ptr);
  free(ptr);
}

const allocator_t allocator_malloc = {
  osi_malloc,
  osi_free
};

const allocator_t allocator_calloc = {
  osi_calloc,
  osi_free
};
