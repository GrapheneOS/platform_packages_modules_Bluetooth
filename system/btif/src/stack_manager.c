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

#define LOG_TAG "bt_stack_manager"

#include <hardware/bluetooth.h>
#include <utils/Log.h>

#include "btif_api.h"
#include "bt_utils.h"
#include "osi.h"
#include "semaphore.h"
#include "stack_manager.h"
#include "thread.h"

static thread_t *management_thread;

// If initialized, any of the bluetooth API functions can be called.
// (e.g. turning logging on and off, enabling/disabling the stack, etc)
static bool stack_is_initialized;
// If running, the stack is fully up and able to bluetooth.
static bool stack_is_running;

static void event_init_stack(void *context);
static void event_start_up_stack(void *context);
static void event_shut_down_stack(void *context);
static void event_clean_up_stack(void *context);

// Unvetted includes/imports, etc which should be removed or vetted in the future
static future_t *hack_future;
void bte_main_enable();
// End unvetted section

// Interface functions

static void init_stack(void) {
  // This is a synchronous process. Post it to the thread though, so
  // state modification only happens there.
  semaphore_t *semaphore = semaphore_new(0);
  thread_post(management_thread, event_init_stack, semaphore);
  semaphore_wait(semaphore);
  semaphore_free(semaphore);
}

static void start_up_stack_async(void) {
  thread_post(management_thread, event_start_up_stack, NULL);
}

static void shut_down_stack_async(void) {
  thread_post(management_thread, event_shut_down_stack, NULL);
}

static void clean_up_stack_async(void) {
  thread_post(management_thread, event_clean_up_stack, NULL);
}

static bool get_stack_is_running(void) {
  return stack_is_running;
}

// Internal functions

// Synchronous function to initialize the stack
static void event_init_stack(void *context) {
  semaphore_t *semaphore = (semaphore_t *)context;

  if (!stack_is_initialized) {
    bt_utils_init();
    btif_init_bluetooth();

    // stack init is synchronous, so no waiting necessary here
    stack_is_initialized = true;
  }

  if (semaphore)
    semaphore_post(semaphore);
}

static void ensure_stack_is_initialized(void) {
  if (!stack_is_initialized) {
    ALOGW("%s found the stack was uninitialized. Initializing now.", __func__);
    // No semaphore needed since we are calling it directly
    event_init_stack(NULL);
  }
}

// Synchronous function to start up the stack
static void event_start_up_stack(UNUSED_ATTR void *context) {
  if (stack_is_running) {
    ALOGD("%s stack already brought up.", __func__);
    return;
  }

  ensure_stack_is_initialized();

  ALOGD("%s is bringing up the stack.", __func__);
  hack_future = future_new();

  bte_main_enable();

  if (future_await(hack_future) == FUTURE_SUCCESS)
    stack_is_running = true;
  ALOGD("%s finished", __func__);
}

// Synchronous function to shut down the stack
static void event_shut_down_stack(UNUSED_ATTR void *context) {
  if (!stack_is_running) {
    ALOGD("%s stack is already brought down.", __func__);
    return;
  }

  ALOGD("%s is bringing down the stack.", __func__);
  hack_future = future_new();
  stack_is_running = false;

  btif_disable_bluetooth();

  future_await(hack_future);
  ALOGD("%s finished.", __func__);
}

static void ensure_stack_is_not_running(void) {
  if (stack_is_running) {
    ALOGW("%s found the stack was still running. Bringing it down now.", __func__);
    event_shut_down_stack(NULL);
  }
}

// Synchronous function to clean up the stack
static void event_clean_up_stack(UNUSED_ATTR void *context) {
  if (!stack_is_initialized) {
    ALOGD("%s found the stack already in a clean state.", __func__);
    return;
  }

  ensure_stack_is_not_running();

  ALOGD("%s is cleaning up the stack.", __func__);
  hack_future = future_new();
  stack_is_initialized = false;

  btif_shutdown_bluetooth();

  future_await(hack_future);
  ALOGD("%s finished.", __func__);
}

static void ensure_manager_initialized(void) {
  if (management_thread)
    return;

  management_thread = thread_new("stack_manager");
  if (!management_thread) {
    ALOGE("%s unable to create stack management thread.", __func__);
    return;
  }
}

static const stack_manager_t interface = {
  init_stack,
  start_up_stack_async,
  shut_down_stack_async,
  clean_up_stack_async,

  get_stack_is_running
};

const stack_manager_t *stack_manager_get_interface() {
  ensure_manager_initialized();
  return &interface;
}

future_t *stack_manager_get_hack_future() {
  return hack_future;
}
