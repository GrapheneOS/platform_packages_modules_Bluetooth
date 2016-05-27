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

#define LOG_TAG "bt_classic_peer"

#include "device/include/classic/peer.h"

#include <assert.h>
#include <pthread.h>
#include <stdbool.h>
#include <unordered_map>

#include "btcore/include/module.h"
#include "osi/include/allocator.h"
#include "osi/include/future.h"
#include "osi/include/osi.h"

struct classic_peer_t {
  bt_bdaddr_t address;
};


static bool initialized;
static pthread_mutex_t bag_of_peers_lock;

static std::unordered_map<bt_bdaddr_t*,classic_peer_t*> peers_by_addresz;

// Module lifecycle functions

static future_t *init(void) {
  pthread_mutex_init(&bag_of_peers_lock, NULL);

  initialized = true;
  return NULL;
}

static future_t *clean_up(void) {
  initialized = false;

  peers_by_addresz.clear();

  pthread_mutex_destroy(&bag_of_peers_lock);
  return NULL;
}

extern "C" EXPORT_SYMBOL const module_t classic_peer_module = {
  .name = CLASSIC_PEER_MODULE,
  .init = init,
  .start_up = NULL,
  .shut_down = NULL,
  .clean_up = clean_up
};

// Interface functions

classic_peer_t *classic_peer_by_address(bt_bdaddr_t *address) {
  assert(initialized);
  assert(address != NULL);

  auto map_ptr = peers_by_addresz.find(address);
  if (map_ptr != peers_by_addresz.end()) {
    return map_ptr->second;
  }

  pthread_mutex_lock(&bag_of_peers_lock);

  // Make sure it didn't get added in the meantime
  map_ptr = peers_by_addresz.find(address);
  if (map_ptr != peers_by_addresz.end())
    return map_ptr->second;

  // Splice in a new peer struct on behalf of the caller.
  classic_peer_t *peer = (classic_peer_t*)osi_calloc(sizeof(classic_peer_t));
  peer->address = *address;
  peers_by_addresz[&peer->address] = peer;

  pthread_mutex_unlock(&bag_of_peers_lock);
  return peer;
}

const bt_bdaddr_t *classic_peer_get_address(classic_peer_t *peer) {
  assert(peer != NULL);
  return &peer->address;
}
