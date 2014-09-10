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

typedef struct async_result_t async_result_t;

// Constructs a new async result object. The return value must be freed with a
// call to |async_result_free|. Returns NULL on failure.
async_result_t *async_result_new(void);

// Frees an async result object created with |async_result_new|. |async_result|
// may be NULL. This function is idempotent.
void async_result_free(async_result_t *async_result);

// Signals that the |async_result| is ready, passing |value| back to the context
// waiting for the result. If you call this more than once, the behavior is
// undefined. |async_result| may not be NULL.
void async_result_ready(async_result_t *async_result, void *value);

// Waits for the |async_result| to be ready. Returns the value set in
// |async_result_ready|. |async_result| may not be NULL.
void *async_result_wait_for(async_result_t *async_result);
