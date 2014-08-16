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

#include "allocator.h"
#include "data_dispatcher.h"
#include "osi.h"

///// LEGACY DEFINITIONS /////

/* Message event mask across Host/Controller lib and stack */
#define MSG_EVT_MASK                    0xFF00 /* eq. BT_EVT_MASK */
#define MSG_SUB_EVT_MASK                0x00FF /* eq. BT_SUB_EVT_MASK */

/* Message event ID passed from Host/Controller lib to stack */
#define MSG_HC_TO_STACK_HCI_ERR        0x1300 /* eq. BT_EVT_TO_BTU_HCIT_ERR */
#define MSG_HC_TO_STACK_HCI_ACL        0x1100 /* eq. BT_EVT_TO_BTU_HCI_ACL */
#define MSG_HC_TO_STACK_HCI_SCO        0x1200 /* eq. BT_EVT_TO_BTU_HCI_SCO */
#define MSG_HC_TO_STACK_HCI_EVT        0x1000 /* eq. BT_EVT_TO_BTU_HCI_EVT */
#define MSG_HC_TO_STACK_L2C_SEG_XMIT   0x1900 /* eq. BT_EVT_TO_BTU_L2C_SEG_XMIT */

/* Message event ID passed from stack to vendor lib */
#define MSG_STACK_TO_HC_HCI_ACL        0x2100 /* eq. BT_EVT_TO_LM_HCI_ACL */
#define MSG_STACK_TO_HC_HCI_SCO        0x2200 /* eq. BT_EVT_TO_LM_HCI_SCO */
#define MSG_STACK_TO_HC_HCI_CMD        0x2000 /* eq. BT_EVT_TO_LM_HCI_CMD */

/* Local Bluetooth Controller ID for BR/EDR */
#define LOCAL_BR_EDR_CONTROLLER_ID      0

///// END LEGACY DEFINITIONS /////

typedef struct hci_hal_interface_t hci_hal_interface_t;
typedef struct btsnoop_interface_t btsnoop_interface_t;
typedef struct hci_inject_interface_t hci_inject_interface_t;
typedef struct packet_fragmenter_interface_t packet_fragmenter_interface_t;
typedef struct vendor_interface_t vendor_interface_t;
typedef struct low_power_manager_interface_t low_power_manager_interface_t;

typedef unsigned char * bdaddr_t;

typedef enum {
  LPM_DISABLE,
  LPM_ENABLE,
  LPM_WAKE_ASSERT,
  LPM_WAKE_DEASSERT
} low_power_command_t;

typedef void (*preload_finished_cb)(bool success);
typedef void (*transmit_finished_cb)(void *buffer, bool all_fragments_sent);

typedef struct {
  // Called when the HCI layer finishes the preload sequence.
  preload_finished_cb preload_finished;

  // Called when the HCI layer finishes sending a packet.
  transmit_finished_cb transmit_finished;
} hci_callbacks_t;

typedef struct hci_interface_t {
  // Initialize the hci layer, with the specified |local_bdaddr|.
  bool (*init)(
      bdaddr_t local_bdaddr,
      const allocator_t *upward_buffer_allocator,
      const hci_callbacks_t *upper_callbacks
  );

  // Tear down and relese all resources
  void (*cleanup)(void);

  // Turn the Bluetooth chip on or off, depending on |value|.
  void (*set_chip_power_on)(bool value);

  // Send a low power command, if supported and the low power manager is enabled.
  void (*send_low_power_command)(low_power_command_t command);

  // Do the preload sequence (call before the rest of the BT stack initializes).
  void (*do_preload)(void);

  // Do the postload sequence (call after the rest of the BT stack initializes).
  void (*do_postload)(void);

  // Turn logging on, and log to the specified |path|.
  void (*turn_on_logging)(const char *path);

  void (*turn_off_logging)(void);

  // Register with this data dispatcher to receive data flowing upward out of the HCI layer
  data_dispatcher_t *upward_dispatcher;

  // Send some data downward through the HCI layer
  void (*transmit_downward)(data_dispatcher_type_t type, void *data);
} hci_interface_t;

const hci_interface_t *hci_layer_get_interface();

const hci_interface_t *hci_layer_get_test_interface(
    const hci_hal_interface_t *hal_interface,
    const btsnoop_interface_t *btsnoop_interface,
    const hci_inject_interface_t *hci_inject_interface,
    const packet_fragmenter_interface_t *packet_fragmenter_interface,
    const vendor_interface_t *vendor_interface,
    const low_power_manager_interface_t *low_power_manager_interface);
