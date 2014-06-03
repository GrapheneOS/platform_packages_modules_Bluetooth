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

#include <stdbool.h>

struct hash_map_t;
typedef struct hash_map_t hash_map_t;

typedef size_t hash_index_t;

// Takes a key structure and returns a hash value.
typedef hash_index_t (*hash_index_fn)(const void *key);

typedef void (*key_free_fn)(void *data);
typedef void (*data_free_fn)(void *data);

// Lifecycle.
hash_map_t *hash_map_new(size_t size, hash_index_fn hash_fn,
    key_free_fn key_fn, data_free_fn);
void hash_map_free(hash_map_t *hash_map);

// Accessors.
void *hash_map_get(const hash_map_t *hash_map, const void *key);
bool hash_map_has_key(const hash_map_t *hash_map, const void *key);
bool hash_map_is_empty(const hash_map_t *hash_map);
size_t hash_map_size(const hash_map_t *hash_map);
size_t hash_map_num_buckets(const hash_map_t *hash_map);

// Mutators.
bool hash_map_set(hash_map_t *hash_map, const void *key, void *data);
bool hash_map_erase(hash_map_t *hash_map, const void *key);
void hash_map_clear(hash_map_t *hash_map);
