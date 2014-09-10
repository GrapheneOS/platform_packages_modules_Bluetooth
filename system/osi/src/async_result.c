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

#define LOG_TAG "osi_async_result"

#include <assert.h>
#include <utils/Log.h>

#include "allocator.h"
#include "async_result.h"
#include "osi.h"
#include "semaphore.h"

struct async_result_t {
  semaphore_t *semaphore;
  void *result;
};

async_result_t *async_result_new(void) {
  async_result_t *ret = osi_calloc(sizeof(async_result_t));
  if (!ret) {
    ALOGE("%s unable to allocate memory for return value.", __func__);
    goto error;
  }

  ret->semaphore = semaphore_new(0);
  if (!ret->semaphore) {
    ALOGE("%s unable to allocate memory for the semaphore.", __func__);
    goto error;
  }

  return ret;
error:;
  async_result_free(ret);
  return NULL;
}

void async_result_free(async_result_t *async_result) {
  if (!async_result)
    return;

  semaphore_free(async_result->semaphore);
  osi_free(async_result);
}

void async_result_ready(async_result_t *async_result, void *value) {
  assert(async_result != NULL);

  async_result->result = value;
  semaphore_post(async_result->semaphore);
}

void *async_result_wait_for(async_result_t *async_result) {
  assert(async_result != NULL);

  semaphore_wait(async_result->semaphore);
  return async_result->result;
}
