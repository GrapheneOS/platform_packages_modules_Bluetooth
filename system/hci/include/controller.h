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

#include <stdint.h>

#include "allocator.h"
#include "hci_layer.h"
#include "hci_packet_factory.h"
#include "hci_packet_parser.h"

typedef void (*fetch_finished_cb)(void);

typedef struct controller_t {
  // Initialize the controller module. Does no work; no clean up required.
  void (*init)(const hci_t *hci_interface);

  // Starts the acl buffer size fetch sequence. |callback| is called when
  // the process is complete.
  void (*begin_acl_size_fetch)(fetch_finished_cb callback);

  // Get the cached classic acl size for the controller.
  uint16_t (*get_acl_size_classic)(void);
  // Get the cached ble acl size of the controller.
  uint16_t (*get_acl_size_ble)(void);
} controller_t;

const controller_t *controller_get_interface();

const controller_t *controller_get_test_interface(
    const allocator_t *buffer_allocator_interface,
    const hci_packet_factory_t *packet_factory_interface,
    const hci_packet_parser_t *packet_parser_interface);
