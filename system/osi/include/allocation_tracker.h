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

#include "allocator.h"

typedef struct allocation_tracker_t allocation_tracker_t;

// Initialize the allocation tracker. If you do not call this function,
// the allocation tracker functions do nothing but are still safe to call.
void allocation_tracker_init(void);

// Reset the allocation tracker. Don't call this in the normal course of
// operations. Useful mostly for testing.
void allocation_tracker_reset(void);

// Expects that there are no allocations at the time of this call. Dumps
// information about unfreed allocations to the log. Returns the amount of
// unallocated memory.
size_t allocation_tracker_expect_no_allocations(void);

// Notify the tracker of a new allocation. If |ptr| is NULL, this function
// does nothing.
void allocation_tracker_notify_alloc(void *ptr, size_t size);

// Notify the tracker of an allocation that is being freed. |ptr| must have
// been tracked before using |allocation_tracker_notify_alloc|. If |ptr| is
// NULL, this function does nothing.
void allocation_tracker_notify_free(void *ptr);
