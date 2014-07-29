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

#define LOG_TAG "bt_osi_data_dispatcher"

#include <assert.h>
#include <utils/Log.h>

#include "data_dispatcher.h"
#include "hash_map.h"
#include "osi.h"

#define DEFAULT_TABLE_BUCKETS 10

struct data_dispatcher_t {
  char *name;
  hash_map_t *dispatch_table;
  // We don't own these queues, so don't free them
  fixed_queue_t *zero_queue;
  fixed_queue_t *default_queue;
};

static hash_index_t default_hash_function(const void *key);

data_dispatcher_t *data_dispatcher_new(const char *name) {
  assert(name != NULL);

  data_dispatcher_t *ret = calloc(1, sizeof(data_dispatcher_t));
  if (!ret) {
    ALOGE("%s unable to allocate memory for new data dispatcher.", __func__);
    goto error;
  }

  ret->dispatch_table = hash_map_new(DEFAULT_TABLE_BUCKETS, default_hash_function, NULL, NULL);
  if (!ret->dispatch_table) {
    ALOGE("%s unable to create dispatch table.", __func__);
    goto error;
  }

  ret->name = strdup(name);
  if (!ret->name) {
    ALOGE("%s unable to duplicate provided name.", __func__);
    goto error;
  }

  return ret;

error:;
  data_dispatcher_free(ret);
  return NULL;
}

void data_dispatcher_free(data_dispatcher_t *dispatcher) {
  if (!dispatcher)
    return;

  hash_map_free(dispatcher->dispatch_table);

  if (dispatcher->name)
    free(dispatcher->name);

  free(dispatcher);
}

void data_dispatcher_register(data_dispatcher_t *dispatcher, data_dispatcher_type_t type, fixed_queue_t *queue) {
  assert(dispatcher != NULL);

  if (type == 0) {
    dispatcher->zero_queue = queue;
  } else {
    hash_map_erase(dispatcher->dispatch_table, (void *)type);
    if (queue)
      hash_map_set(dispatcher->dispatch_table, (void *)type, queue);
  }
}

void data_dispatcher_register_default(data_dispatcher_t *dispatcher, fixed_queue_t *queue) {
  assert(dispatcher != NULL);

  dispatcher->default_queue = queue;
}

bool data_dispatcher_dispatch(data_dispatcher_t *dispatcher, data_dispatcher_type_t type, void *data) {
  assert(dispatcher != NULL);
  assert(data != NULL);

  fixed_queue_t *queue = (type == 0) ? dispatcher->zero_queue : hash_map_get(dispatcher->dispatch_table, (void *)type);
  if (!queue)
    queue = dispatcher->default_queue;

  if (queue)
    fixed_queue_enqueue(queue, data);
  else
    ALOGW("%s has no handler for type (%d) in data dispatcher named: %s", __func__, type, dispatcher->name);

  return queue != NULL;
}

static hash_index_t default_hash_function(const void *key) {
  hash_index_t hash_key = (hash_index_t)key;
  return hash_key;
}
