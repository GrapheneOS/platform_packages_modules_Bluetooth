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

#include "bt_types.h"

typedef struct {
  void (*parse_read_buffer_size_response)(BT_HDR *response, uint8_t *status_ptr, uint16_t *data_size_ptr);
  void (*parse_ble_read_buffer_size_response)(BT_HDR *response, uint8_t *status_ptr, uint16_t *data_size_ptr);
} hci_packet_parser_t;

const hci_packet_parser_t *hci_packet_parser_get_interface();
