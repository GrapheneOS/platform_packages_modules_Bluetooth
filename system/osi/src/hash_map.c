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
#include <list.h>
#include <hash_map.h>

struct hash_map_t;

typedef struct hash_map_entry_t {
  const void *key;
  void *data;
  const hash_map_t *hash_map;
} hash_map_entry_t;

typedef struct hash_map_bucket_t {
  list_t *list;
} hash_map_bucket_t;

typedef struct hash_map_t {
  hash_map_bucket_t *bucket;
  size_t num_bucket;
  size_t hash_size;
  hash_index_fn hash_fn;
  key_free_fn key_fn;
  data_free_fn data_fn;
} hash_map_t;

static void bucket_free_(void *data);
static hash_map_entry_t *find_bucket_entry_(list_t *hash_bucket_list,
    const void *key);

// Returns a new, empty hash_map. Returns NULL if not enough memory could be allocated
// for the hash_map structure. The returned hash_map must be freed with |hash_map_free|.
// The |num_bucket| specifies the number of hashable buckets for the map and must not
// be zero.  The |hash_fn| specifies a hash function to be used and must not be NULL.
// The |key_fn| and |data_fn| are called whenever a hash_map element is removed from
// the hash_map. They can be used to release resources held by the hash_map element,
// e.g.  memory or file descriptor.  |key_fn| and |data_fn| may be NULL if no cleanup
// is necessary on element removal.
hash_map_t * hash_map_new(size_t num_bucket, hash_index_fn hash_fn,
    key_free_fn key_fn, data_free_fn data_fn) {
  assert(hash_fn != NULL);
  assert(num_bucket > 0);

  hash_map_t *hash_map = calloc(sizeof(hash_map_t), 1);
  if (hash_map == NULL)
    return NULL;

  hash_map->hash_fn = hash_fn;
  hash_map->key_fn = key_fn;
  hash_map->data_fn = data_fn;

  hash_map->num_bucket = num_bucket;
  hash_map->bucket = calloc(sizeof(hash_map_bucket_t), num_bucket);
  if (hash_map->bucket == NULL) {
    free(hash_map);
    return NULL;
  }
  return hash_map;
}

// Frees the hash_map. This function accepts NULL as an argument, in which case it
// behaves like a no-op.
void hash_map_free(hash_map_t *hash_map) {
  if (hash_map == NULL)
    return;
  hash_map_clear(hash_map);
  free(hash_map->bucket);
  free(hash_map);
}

// Returns true if the hash_map is empty (has no elements), false otherwise.
// Note that a NULL |hash_map| is not the same as an empty |hash_map|. This function
// does not accept a NULL |hash_map|.
bool hash_map_is_empty(const hash_map_t *hash_map) {
  assert(hash_map != NULL);
  return (hash_map->hash_size == 0);
}

// Returns the number of elements in the hash map.  This function does not accept a
// NULL |hash_map|.
size_t hash_map_size(const hash_map_t *hash_map) {
  assert(hash_map != NULL);
  return hash_map->hash_size;
}

// Returns the number of buckets in the hash map.  This function does not accept a
// NULL |hash_map|.
size_t hash_map_num_buckets(const hash_map_t *hash_map) {
  assert(hash_map != NULL);
  return hash_map->num_bucket;
}

// Returns true if the hash_map has a valid entry for the presented key.
// This function does not accept a NULL |hash_map|.
bool hash_map_has_key(const hash_map_t *hash_map, const void *key) {
  assert(hash_map != NULL);

  hash_index_t hash_key = hash_map->hash_fn(key) % hash_map->num_bucket;
  list_t *hash_bucket_list = hash_map->bucket[hash_key].list;

  hash_map_entry_t *hash_map_entry = find_bucket_entry_(hash_bucket_list, key);
  return (hash_map_entry != NULL);
}

// Sets the value |data| indexed by |key| into the |hash_map|. Neither |data| nor
// |hash_map| may be NULL.  This function does not make copies of |data| nor |key|
// so the pointers must remain valid at least until the element is removed from the
// hash_map or the hash_map is freed.  Returns true if |data| could be set, false
// otherwise (e.g. out of memory).
bool hash_map_set(hash_map_t *hash_map, const void *key, void *data) {
  assert(hash_map != NULL);
  assert(data != NULL);

  hash_index_t hash_key = hash_map->hash_fn(key) % hash_map->num_bucket;

  if (hash_map->bucket[hash_key].list == NULL) {
    hash_map->bucket[hash_key].list = list_new(bucket_free_);
    if (hash_map->bucket[hash_key].list == NULL)
        return false;
  }
  list_t *hash_bucket_list = hash_map->bucket[hash_key].list;

  hash_map_entry_t *hash_map_entry = find_bucket_entry_(hash_bucket_list, key);

  if (hash_map_entry) {
    // Calls hash_map callback to delete the hash_map_entry.
    bool rc = list_remove(hash_bucket_list, hash_map_entry);
    assert(rc == true);
  } else {
    hash_map->hash_size++;
  }
  hash_map_entry = calloc(sizeof(hash_map_entry_t), 1);
  if (hash_map_entry == NULL)
    return false;

  hash_map_entry->key = key;
  hash_map_entry->data = data;
  hash_map_entry->hash_map = hash_map;

  return list_append(hash_bucket_list, hash_map_entry);
}

// Removes data indexed by |key| from the hash_map. |hash_map| may not be NULL.
// If |key_fn| or |data_fn| functions were specified in |hash_map_new|, they
// will be called back with |key| or |data| respectively. This function returns true
// if |key| was found in the hash_map and removed, false otherwise.
bool hash_map_erase(hash_map_t *hash_map, const void *key) {
  assert(hash_map != NULL);

  hash_index_t hash_key = hash_map->hash_fn(key) % hash_map->num_bucket;
  list_t *hash_bucket_list = hash_map->bucket[hash_key].list;

  hash_map_entry_t *hash_map_entry = find_bucket_entry_(hash_bucket_list, key);
  if (hash_map_entry == NULL) {
    return false;
  }

  hash_map->hash_size--;

  return list_remove(hash_bucket_list, hash_map_entry);
}

// Returns the element indexed by |key| in the hash_map without removing it. |hash_map|
// may not be NULL.  Returns NULL if no entry indexed by |key|.
void * hash_map_get(const hash_map_t *hash_map, const void *key) {
  assert(hash_map != NULL);

  hash_index_t hash_key = hash_map->hash_fn(key) % hash_map->num_bucket;
  list_t *hash_bucket_list = hash_map->bucket[hash_key].list;

  hash_map_entry_t *hash_map_entry = find_bucket_entry_(hash_bucket_list, key);
  if (hash_map_entry != NULL)
    return hash_map_entry->data;

  return NULL;
}

// Removes all elements in the hash_map. Calling this function will return the hash_map
// to the same state it was in after |hash_map_new|. |hash_map| may not be NULL.
void hash_map_clear(hash_map_t *hash_map) {
  assert(hash_map != NULL);

  for (hash_index_t i = 0; i < hash_map->num_bucket; i++){
    if (hash_map->bucket[i].list == NULL)
      continue;
    list_free(hash_map->bucket[i].list);
    hash_map->bucket[i].list = NULL;
  }
}

static void bucket_free_(void *data) {
  assert(data != NULL);
  hash_map_entry_t *hash_map_entry = (hash_map_entry_t *)data;

  if (hash_map_entry->hash_map->key_fn)
    hash_map_entry->hash_map->key_fn((void *)hash_map_entry->key);
  if (hash_map_entry->hash_map->data_fn)
    hash_map_entry->hash_map->data_fn(hash_map_entry->data);
  free(hash_map_entry);
}

static hash_map_entry_t * find_bucket_entry_(list_t *hash_bucket_list,
    const void *key) {

  if (hash_bucket_list == NULL)
    return NULL;

  for (const list_node_t *iter = list_begin(hash_bucket_list);
      iter != list_end(hash_bucket_list);
      iter = list_next(iter)) {
    hash_map_entry_t *hash_map_entry = (hash_map_entry_t *)list_node(iter);
    if (hash_map_entry->key == key) {
      return hash_map_entry;
    }
  }
  return NULL;
}
