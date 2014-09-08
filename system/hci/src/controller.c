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
#include <stdbool.h>
#include <utils/Log.h>

#include "bt_types.h"
#include "buffer_allocator.h"
#include "controller.h"
#include "hcimsgs.h"
#include "hci_layer.h"
#include "hci_packet_factory.h"
#include "hci_packet_parser.h"

static const hci_t *hci;
static const hci_packet_factory_t *packet_factory;
static const hci_packet_parser_t *packet_parser;
static const allocator_t *buffer_allocator;

static fetch_finished_cb fetch_finished_callback;

static void on_read_buffer_size_complete(BT_HDR *response, void *context);
static void on_ble_read_buffer_size_complete(BT_HDR *response, void *context);

static bool acl_sizes_fetched;
static uint16_t acl_size_classic;
static uint16_t acl_size_ble;

// Interface functions

static void init(const hci_t *hci_interface) {
  hci = hci_interface;
}

static void begin_acl_size_fetch(fetch_finished_cb callback) {
  assert(fetch_finished_callback == NULL); // Must not already be fetching
  assert(callback != NULL);

  fetch_finished_callback = callback;

  hci->transmit_command(
    packet_factory->make_read_buffer_size_command(),
    on_read_buffer_size_complete,
    NULL,
    NULL
  );
}

static uint16_t get_acl_size_classic(void) {
  assert(acl_sizes_fetched);
  return acl_size_classic;
}

static uint16_t get_acl_size_ble(void) {
  assert(acl_sizes_fetched);
  return acl_size_ble;
}

// Internal functions

static void on_read_buffer_size_complete(BT_HDR *response, UNUSED_ATTR void *context) {
  uint8_t status;
  packet_parser->parse_read_buffer_size_response(response, &status, &acl_size_classic);
  assert(status == HCI_SUCCESS);

  buffer_allocator->free(response);

  hci->transmit_command(
    packet_factory->make_ble_read_buffer_size_command(),
    on_ble_read_buffer_size_complete,
    NULL,
    NULL
  );
}

static void on_ble_read_buffer_size_complete(BT_HDR *response, UNUSED_ATTR void *context) {
  uint8_t status;
  packet_parser->parse_ble_read_buffer_size_response(response, &status, &acl_size_ble);
  assert(status == HCI_SUCCESS);

  // Response of 0 indicates ble has the same buffer size as classic
  if (acl_size_ble == 0)
    acl_size_ble = acl_size_classic;

  buffer_allocator->free(response);

  acl_sizes_fetched = true;
  fetch_finished_callback();

  // Null out the callback to indicate we are done fetching
  fetch_finished_callback = NULL;
}

static const controller_t interface = {
  init,
  begin_acl_size_fetch,

  get_acl_size_classic,
  get_acl_size_ble
};

const controller_t *controller_get_interface() {
  buffer_allocator = buffer_allocator_get_interface();
  packet_factory = hci_packet_factory_get_interface();
  packet_parser = hci_packet_parser_get_interface();
  return &interface;
}

const controller_t *controller_get_test_interface(
    const allocator_t *buffer_allocator_interface,
    const hci_packet_factory_t *packet_factory_interface,
    const hci_packet_parser_t *packet_parser_interface) {

  buffer_allocator = buffer_allocator_interface;
  packet_factory = packet_factory_interface;
  packet_parser = packet_parser_interface;
  return &interface;
}
