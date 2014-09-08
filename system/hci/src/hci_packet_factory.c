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

#include "allocator.h"
#include "bt_types.h"
#include "buffer_allocator.h"
#include "hcidefs.h"
#include "hcimsgs.h"
#include "hci_internals.h"
#include "hci_layer.h"
#include "hci_packet_factory.h"

static const allocator_t *buffer_allocator;

static BT_HDR *make_packet(size_t data_size);

// Interface functions

static BT_HDR *make_read_buffer_size_command(void) {
  BT_HDR *packet = make_packet(HCI_COMMAND_PREAMBLE_SIZE);

  uint8_t *stream = packet->data;
  UINT16_TO_STREAM(stream, HCI_READ_BUFFER_SIZE);
  UINT8_TO_STREAM(stream, 0); // no parameters

  return packet;
}

static BT_HDR *make_ble_read_buffer_size_command(void) {
  BT_HDR *packet = make_packet(HCI_COMMAND_PREAMBLE_SIZE);

  uint8_t *stream = packet->data;
  UINT16_TO_STREAM(stream, HCI_BLE_READ_BUFFER_SIZE);
  UINT8_TO_STREAM(stream, 0); // no parameters

  return packet;
}

// Internal functions

static BT_HDR *make_packet(size_t data_size) {
  BT_HDR *ret = (BT_HDR *)buffer_allocator->alloc(sizeof(BT_HDR) + data_size);
  assert(ret);
  ret->event = 0;
  ret->offset = 0;
  ret->layer_specific = 0;
  ret->len = data_size;
  return ret;
}

static const hci_packet_factory_t interface = {
  make_read_buffer_size_command,
  make_ble_read_buffer_size_command
};

const hci_packet_factory_t *hci_packet_factory_get_interface() {
  buffer_allocator = buffer_allocator_get_interface();
  return &interface;
}
