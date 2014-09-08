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

#include "bt_types.h"
#include "hcimsgs.h"
#include "hci_layer.h"
#include "hci_packet_parser.h"

static void parse_read_buffer_size_response(
    BT_HDR *response,
    uint8_t *status_ptr,
    uint16_t *data_size_ptr) {
  uint8_t *stream = response->data + response->offset;
  command_opcode_t opcode;

  stream += 3; // skip the event header fields, and the number of hci command packets field
  STREAM_TO_UINT16(opcode, stream);
  STREAM_TO_UINT8(*status_ptr, stream);
  STREAM_TO_UINT16(*data_size_ptr, stream);

  assert(opcode == HCI_READ_BUFFER_SIZE);
}

static void parse_ble_read_buffer_size_response(
    BT_HDR *response,
    uint8_t *status_ptr,
    uint16_t *data_size_ptr) {
  uint8_t *stream = response->data + response->offset;
  command_opcode_t opcode;

  stream += 3; // skip the event header fields, and the number of hci command packets field
  STREAM_TO_UINT16(opcode, stream);
  STREAM_TO_UINT8(*status_ptr, stream);
  STREAM_TO_UINT16(*data_size_ptr, stream);

  assert(opcode == HCI_BLE_READ_BUFFER_SIZE);
}

static const hci_packet_parser_t interface = {
  parse_read_buffer_size_response,
  parse_ble_read_buffer_size_response
};

const hci_packet_parser_t *hci_packet_parser_get_interface() {
  return &interface;
}
