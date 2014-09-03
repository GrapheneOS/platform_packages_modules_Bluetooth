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

#include <pthread.h>
#include <stdlib.h>
#include <unistd.h>

#include "base.h"
#include "cases/cases.h"
#include "support/callbacks.h"
#include "support/hal.h"
#include "support/pan.h"
#include "support/rfcomm.h"

// How long the watchdog thread should wait before checking if a test has completed.
// Any individual test will have at least WATCHDOG_PERIOD_SEC and at most
// 2 * WATCHDOG_PERIOD_SEC seconds to complete.
static const int WATCHDOG_PERIOD_SEC = 1 * 60;

const bt_interface_t *bt_interface;
bt_bdaddr_t bt_remote_bdaddr;

static pthread_t watchdog_thread;
static int watchdog_id;
static bool watchdog_running;

static bool parse_bdaddr(const char *str, bt_bdaddr_t *addr) {
  if (!addr) {
    return false;
  }

  int v[6];
  if (sscanf(str, "%02x:%02x:%02x:%02x:%02x:%02x", &v[0], &v[1], &v[2], &v[3], &v[4], &v[5]) != 6) {
    return false;
  }

  for (int i = 0; i < 6; ++i) {
    addr->address[i] = (uint8_t)v[i];
  }

  return true;
}

void *watchdog_fn(void *arg) {
  int current_id = 0;
  for (;;) {
    // Check every second whether this thread should exit and check
    // every WATCHDOG_PERIOD_SEC whether we should terminate the process.
    for (int i = 0; watchdog_running && i < WATCHDOG_PERIOD_SEC; ++i) {
      sleep(1);
    }

    if (!watchdog_running)
      break;

    if (current_id == watchdog_id) {
      printf("Watchdog detected hanging test suite, aborting...\n");
      exit(-1);
    }
    current_id = watchdog_id;
  }
  return NULL;
}

int main(int argc, char **argv) {
  if (argc < 2 || !parse_bdaddr(argv[1], &bt_remote_bdaddr)) {
    printf("Usage: %s <bdaddr>\n", argv[0]);
    return -1;
  }

  if (!hal_open(callbacks_get_adapter_struct())) {
    printf("Unable to open Bluetooth HAL.\n");
    return 1;
  }

  if (!btsocket_init()) {
    printf("Unable to initialize Bluetooth sockets.\n");
    return 2;
  }

  if (!pan_init()) {
    printf("Unable to initialize PAN.\n");
    return 3;
  }

  watchdog_running = true;
  pthread_create(&watchdog_thread, NULL, watchdog_fn, NULL);

  static const char *GRAY  = "\x1b[0;37m";
  static const char *GREEN = "\x1b[0;32m";
  static const char *RED   = "\x1b[0;31m";

  // If the output is not a TTY device, don't colorize output.
  if (!isatty(fileno(stdout))) {
    GRAY = GREEN = RED = "";
  }

  int pass = 0;
  int fail = 0;
  int case_num = 0;

  // Run through the sanity suite.
  for (size_t i = 0; i < sanity_suite_size; ++i) {
    callbacks_init();
    if (sanity_suite[i].function()) {
      printf("[%4d] %-64s [%sPASS%s]\n", ++case_num, sanity_suite[i].function_name, GREEN, GRAY);
      ++pass;
    } else {
      printf("[%4d] %-64s [%sFAIL%s]\n", ++case_num, sanity_suite[i].function_name, RED, GRAY);
      ++fail;
    }
    callbacks_cleanup();
    ++watchdog_id;
  }

  // If there was a failure in the sanity suite, don't bother running the rest of the tests.
  if (fail) {
    printf("\n%sSanity suite failed with %d errors.%s\n", RED, fail, GRAY);
    hal_close();
    return 4;
  }

  // Run the full test suite.
  for (size_t i = 0; i < test_suite_size; ++i) {
    callbacks_init();
    CALL_AND_WAIT(bt_interface->enable(), adapter_state_changed);
    if (test_suite[i].function()) {
      printf("[%4d] %-64s [%sPASS%s]\n", ++case_num, test_suite[i].function_name, GREEN, GRAY);
      ++pass;
    } else {
      printf("[%4d] %-64s [%sFAIL%s]\n", ++case_num, test_suite[i].function_name, RED, GRAY);
      ++fail;
    }
    CALL_AND_WAIT(bt_interface->disable(), adapter_state_changed);
    callbacks_cleanup();
    ++watchdog_id;
  }

  printf("\n");

  if (fail) {
    printf("%d/%d tests failed. See above for failed test cases.\n", fail, test_suite_size);
  } else {
    printf("All tests passed!\n");
  }

  watchdog_running = false;
  pthread_join(watchdog_thread, NULL);

  hal_close();

  return 0;
}
