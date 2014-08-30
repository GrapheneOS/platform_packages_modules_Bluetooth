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

#define LOG_TAG "hci_layer"

#include <assert.h>
#include <utils/Log.h>

#include "alarm.h"
#include "bt_types.h"
#include "btsnoop.h"
#include "fixed_queue.h"
#include "hci_hal.h"
#include "hci_internals.h"
#include "hci_inject.h"
#include "hci_layer.h"
#include "low_power_manager.h"
#include "osi.h"
#include "packet_fragmenter.h"
#include "reactor.h"
#include "vendor.h"

#define HCI_COMMAND_COMPLETE_EVT    0x0E
#define HCI_COMMAND_STATUS_EVT      0x0F
#define HCI_READ_BUFFER_SIZE        0x1005
#define HCI_LE_READ_BUFFER_SIZE     0x2002

#define INBOUND_PACKET_TYPE_COUNT 3
#define PACKET_TYPE_TO_INBOUND_INDEX(type) ((type) - 2)
#define PACKET_TYPE_TO_INDEX(type) ((type) - 1)

#define PREAMBLE_BUFFER_SIZE 4 // max preamble size, ACL
#define RETRIEVE_ACL_LENGTH(preamble) ((((preamble)[3]) << 8) | (preamble)[2])

#define MAX_WAITING_INTERNAL_COMMANDS 8

static const uint8_t preamble_sizes[] = {
  HCI_COMMAND_PREAMBLE_SIZE,
  HCI_ACL_PREAMBLE_SIZE,
  HCI_SCO_PREAMBLE_SIZE,
  HCI_EVENT_PREAMBLE_SIZE
};

static const uint16_t outbound_event_types[] =
{
  MSG_HC_TO_STACK_HCI_ERR,
  MSG_HC_TO_STACK_HCI_ACL,
  MSG_HC_TO_STACK_HCI_SCO,
  MSG_HC_TO_STACK_HCI_EVT
};

typedef enum {
  BRAND_NEW,
  PREAMBLE,
  BODY,
  IGNORE,
  FINISHED
} receive_state_t;

typedef struct {
  receive_state_t state;
  uint16_t bytes_remaining;
  uint8_t preamble[PREAMBLE_BUFFER_SIZE];
  uint16_t index;
  BT_HDR *buffer;
} packet_receive_data_t;

typedef struct {
  uint16_t opcode;
  internal_command_cb callback;
} waiting_internal_command_t;

static const uint32_t EPILOG_TIMEOUT_MS = 3000;

// Our interface
static bool interface_created;
static hci_interface_t interface;

// Modules we import and callbacks we export
static const allocator_t *buffer_allocator;
static const btsnoop_interface_t *btsnoop;
static const hci_callbacks_t *callbacks;
static const hci_hal_interface_t *hal;
static const hci_hal_callbacks_t hal_callbacks;
static const hci_inject_interface_t *hci_inject;
static const low_power_manager_interface_t *low_power_manager;
static const packet_fragmenter_interface_t *packet_fragmenter;
static const packet_fragmenter_callbacks_t packet_fragmenter_callbacks;
static const vendor_interface_t *vendor;

static thread_t *thread; // We own this

static volatile bool firmware_is_configured = false;
static volatile bool has_shut_down = false;
static alarm_t *epilog_alarm;

// Outbound-related
static int command_credits = 1;
static fixed_queue_t *command_queue;
static fixed_queue_t *packet_queue;

// Inbound-related
static fixed_queue_t *waiting_internal_commands;
static packet_receive_data_t incoming_packets[INBOUND_PACKET_TYPE_COUNT];

static void event_preload(void *context);
static void event_postload(void *context);
static void event_epilog(void *context);
static void event_command_ready(fixed_queue_t *queue, void *context);
static void event_packet_ready(fixed_queue_t *queue, void *context);

static void firmware_config_callback(bool success);
static void sco_config_callback(bool success);
static void epilog_finished_callback(bool success);

static void hal_says_data_ready(serial_data_type_t type);
static bool send_internal_command(uint16_t opcode, BT_HDR *packet, internal_command_cb callback);
static void start_epilog_wait_timer();

// Interface functions

static bool start_up(
    bdaddr_t local_bdaddr,
    const allocator_t *upward_buffer_allocator,
    const hci_callbacks_t *upper_callbacks) {
  assert(local_bdaddr != NULL);
  assert(upward_buffer_allocator != NULL);
  assert(upper_callbacks != NULL);

  ALOGI("%s", __func__);

  // The host is only allowed to send at most one command initially,
  // as per the Bluetooth spec, Volume 2, Part E, 4.4 (Command Flow Control)
  // This value can change when you get a command complete or command status event.
  command_credits = 1;
  firmware_is_configured = false;
  has_shut_down = false;

  epilog_alarm = alarm_new();
  if (!epilog_alarm) {
    ALOGE("%s unable to create epilog alarm.", __func__);
    goto error;
  }

  command_queue = fixed_queue_new(SIZE_MAX);
  if (!command_queue) {
    ALOGE("%s unable to create pending command queue.", __func__);
    goto error;
  }

  packet_queue = fixed_queue_new(SIZE_MAX);
  if (!packet_queue) {
    ALOGE("%s unable to create pending packet queue.", __func__);
    goto error;
  }

  thread = thread_new("hci_thread");
  if (!thread) {
    ALOGE("%s unable to create thread.", __func__);
    goto error;
  }

  waiting_internal_commands = fixed_queue_new(MAX_WAITING_INTERNAL_COMMANDS);
  if (!waiting_internal_commands) {
    ALOGE("%s unable to create waiting internal command queue.", __func__);
    goto error;
  }

  callbacks = upper_callbacks;
  buffer_allocator = upward_buffer_allocator;
  memset(incoming_packets, 0, sizeof(incoming_packets));

  packet_fragmenter->init(&packet_fragmenter_callbacks, buffer_allocator);

  fixed_queue_register_dequeue(command_queue, thread_get_reactor(thread), event_command_ready, NULL);
  fixed_queue_register_dequeue(packet_queue, thread_get_reactor(thread), event_packet_ready, NULL);

  vendor->open(local_bdaddr, buffer_allocator);
  hal->init(&hal_callbacks, thread);
  low_power_manager->init(thread);

  vendor->set_callback(VENDOR_CONFIGURE_FIRMWARE, firmware_config_callback);
  vendor->set_callback(VENDOR_CONFIGURE_SCO, sco_config_callback);
  vendor->set_callback(VENDOR_DO_EPILOG, epilog_finished_callback);
  vendor->set_send_internal_command_callback(send_internal_command);

  if (!hci_inject->open(&interface, buffer_allocator)) {
    // TODO(sharvil): gracefully propagate failures from this layer.
  }

  return true;
error:;
  interface.shut_down();
  return false;
}

static void shut_down() {
  if (has_shut_down) {
    ALOGW("%s already happened for this session", __func__);
    return;
  }

  ALOGI("%s", __func__);

  hci_inject->close();

  if (thread) {
    if (firmware_is_configured) {
      start_epilog_wait_timer();
      thread_post(thread, event_epilog, NULL);
    } else {
      thread_stop(thread);
    }

    thread_join(thread);
  }

  fixed_queue_free(command_queue, buffer_allocator->free);
  fixed_queue_free(packet_queue, buffer_allocator->free);
  fixed_queue_free(waiting_internal_commands, osi_free);

  packet_fragmenter->cleanup();

  alarm_free(epilog_alarm);
  epilog_alarm = NULL;

  low_power_manager->cleanup();
  hal->close();

  interface.set_chip_power_on(false);
  vendor->close();

  thread_free(thread);
  thread = NULL;
  firmware_is_configured = false;
  has_shut_down = true;
}

static void set_chip_power_on(bool value) {
  ALOGD("%s setting bluetooth chip power on to: %d", __func__, value);

  int power_state = value ? BT_VND_PWR_ON : BT_VND_PWR_OFF;
  vendor->send_command(VENDOR_CHIP_POWER_CONTROL, &power_state);
}

static void do_preload() {
  ALOGD("%s posting preload work item", __func__);
  thread_post(thread, event_preload, NULL);
}

static void do_postload() {
  ALOGD("%s posting postload work item", __func__);
  thread_post(thread, event_postload, NULL);
}

static void turn_on_logging(const char *path) {
  ALOGD("%s", __func__);

  if (path != NULL)
    btsnoop->open(path);
  else
    ALOGW("%s wanted to start logging, but path was NULL", __func__);
}

static void turn_off_logging() {
  ALOGD("%s", __func__);
  btsnoop->close();
}

static void transmit_downward(data_dispatcher_type_t type, void *data) {
  if (type == MSG_STACK_TO_HC_HCI_CMD) {
    fixed_queue_enqueue(command_queue, data);
  } else {
    fixed_queue_enqueue(packet_queue, data);
  }
}

// Internal functions

// Inspects an incoming event for interesting information, like how many
// commands are now able to be sent. Returns true if the event should
// not proceed to higher layers (i.e. was intercepted for internal use).
static bool filter_incoming_event(BT_HDR *packet) {
  uint8_t *stream = packet->data;
  uint8_t event_code;

  STREAM_TO_UINT8(event_code, stream);
  STREAM_SKIP_UINT8(stream); // Skip the parameter total length field

  if (event_code == HCI_COMMAND_COMPLETE_EVT) {
    uint16_t opcode;

    STREAM_TO_UINT8(command_credits, stream);
    STREAM_TO_UINT16(opcode, stream);

    // TODO make this look back in the commands rather than just the first one
    waiting_internal_command_t *first_waiting = fixed_queue_try_peek(waiting_internal_commands);
    if (first_waiting != NULL && opcode == first_waiting->opcode) {
      fixed_queue_dequeue(waiting_internal_commands);

      if (first_waiting->callback)
        first_waiting->callback(packet);
      else
        buffer_allocator->free(packet);

      osi_free(first_waiting);
      return true;
    }

  } else if (event_code == HCI_COMMAND_STATUS_EVT) {
    STREAM_SKIP_UINT8(stream); // Skip the status field
    STREAM_TO_UINT8(command_credits, stream);
  }

  return false;
}

// Send an internal command. Called by the vendor library, and also
// internally by the HCI layer to fetch controller buffer sizes.
static bool send_internal_command(uint16_t opcode, BT_HDR *packet, internal_command_cb callback) {
  waiting_internal_command_t *wait_entry = osi_calloc(sizeof(waiting_internal_command_t));
  if (!wait_entry) {
    ALOGE("%s couldn't allocate space for wait entry.", __func__);
    return false;
  }

  wait_entry->opcode = opcode;
  wait_entry->callback = callback;

  if (!fixed_queue_try_enqueue(waiting_internal_commands, wait_entry)) {
    osi_free(wait_entry);
    ALOGE("%s too many waiting internal commands. Rejecting 0x%04X", __func__, opcode);
    return false;
  }

  packet->layer_specific = opcode;
  transmit_downward(packet->event, packet);
  return true;
}

static void request_acl_buffer_size_callback(void *response) {
  BT_HDR *packet = (BT_HDR *)response;
  uint8_t *stream = packet->data;
  uint16_t opcode;
  uint8_t status;
  uint16_t data_size = 0;

  stream += 3; // Skip the event header fields, and the number of hci command packets field
  STREAM_TO_UINT16(opcode, stream);
  STREAM_TO_UINT8(status, stream);

  if (status == 0)
    STREAM_TO_UINT16(data_size, stream);

  if (opcode == HCI_READ_BUFFER_SIZE) {
    if (status == 0)
      packet_fragmenter->set_acl_data_size(data_size);

    // Now request the ble buffer size, using the same buffer
    packet->event = HCI_LE_READ_BUFFER_SIZE;
    packet->offset = 0;
    packet->layer_specific = 0;
    packet->len = HCI_COMMAND_PREAMBLE_SIZE;

    stream = packet->data;
    UINT16_TO_STREAM(stream, HCI_LE_READ_BUFFER_SIZE);
    UINT8_TO_STREAM(stream, 0); // no parameters

    if (!send_internal_command(HCI_LE_READ_BUFFER_SIZE, packet, request_acl_buffer_size_callback)) {
      buffer_allocator->free(packet);
      ALOGI("%s couldn't send ble read buffer command, so postload finished.", __func__);
    }
  } else if (opcode == HCI_LE_READ_BUFFER_SIZE) {
    if (status == 0)
      packet_fragmenter->set_ble_acl_data_size(data_size);

    buffer_allocator->free(packet);
    ALOGI("%s postload finished.", __func__);
  } else {
    ALOGE("%s unexpected opcode %d", __func__, opcode);
  }
}

static void request_acl_buffer_size() {
  ALOGI("%s", __func__);
  BT_HDR *packet = (BT_HDR *)buffer_allocator->alloc(sizeof(BT_HDR) + HCI_COMMAND_PREAMBLE_SIZE);
  if (!packet) {
    ALOGE("%s couldn't get buffer for packet.", __func__);
    return;
  }

  packet->event = MSG_STACK_TO_HC_HCI_CMD;
  packet->offset = 0;
  packet->layer_specific = 0;
  packet->len = HCI_COMMAND_PREAMBLE_SIZE;

  uint8_t *stream = packet->data;
  UINT16_TO_STREAM(stream, HCI_READ_BUFFER_SIZE);
  UINT8_TO_STREAM(stream, 0); // no parameters

  if (!send_internal_command(HCI_READ_BUFFER_SIZE, packet, request_acl_buffer_size_callback)) {
    buffer_allocator->free(packet);
    ALOGE("%s couldn't send internal command, so postload aborted.", __func__);
  }
}

static void sco_config_callback(UNUSED_ATTR bool success) {
  request_acl_buffer_size();
}

static void firmware_config_callback(UNUSED_ATTR bool success) {
  firmware_is_configured = true;
  callbacks->preload_finished(true);
}

static void epilog_finished_callback(UNUSED_ATTR bool success) {
  ALOGI("%s", __func__);
  thread_stop(thread);
}

static void epilog_wait_timer_expired(UNUSED_ATTR void *context) {
  ALOGI("%s", __func__);
  thread_stop(thread);
}

static void start_epilog_wait_timer() {
  alarm_set(epilog_alarm, EPILOG_TIMEOUT_MS, epilog_wait_timer_expired, NULL);
}

static void event_preload(UNUSED_ATTR void *context) {
  ALOGI("%s", __func__);
  hal->open();
  vendor->send_async_command(VENDOR_CONFIGURE_FIRMWARE, NULL);
}

static void event_postload(UNUSED_ATTR void *context) {
  ALOGI("%s", __func__);
  if(vendor->send_async_command(VENDOR_CONFIGURE_SCO, NULL) == -1) {
    // If couldn't configure sco, we won't get the sco configuration callback
    // so go pretend to do it now
    sco_config_callback(false);
  }
}

static void event_epilog(UNUSED_ATTR void *context) {
  vendor->send_async_command(VENDOR_DO_EPILOG, NULL);
}

static void event_command_ready(fixed_queue_t *queue, UNUSED_ATTR void *context) {
  if (command_credits > 0) {
    event_packet_ready(queue, context);
  }
}

static void event_packet_ready(fixed_queue_t *queue, UNUSED_ATTR void *context) {
  // The queue may be the command queue or the packet queue, we don't care
  BT_HDR *packet = (BT_HDR *)fixed_queue_dequeue(queue);

  low_power_manager->wake_assert();
  packet_fragmenter->fragment_and_dispatch(packet);
  low_power_manager->transmit_done();
}

// This function is not required to read all of a packet in one go, so
// be wary of reentry. But this function must return after finishing a packet.
static void hal_says_data_ready(serial_data_type_t type) {
  packet_receive_data_t *incoming = &incoming_packets[PACKET_TYPE_TO_INBOUND_INDEX(type)];

  uint8_t byte;
  while (hal->read_data(type, &byte, 1, false) != 0) {
    switch (incoming->state) {
      case BRAND_NEW:
        // Initialize and prepare to jump to the preamble reading state
        incoming->bytes_remaining = preamble_sizes[PACKET_TYPE_TO_INDEX(type)];
        memset(incoming->preamble, 0, PREAMBLE_BUFFER_SIZE);
        incoming->index = 0;
        incoming->state = PREAMBLE;
        // INTENTIONAL FALLTHROUGH
      case PREAMBLE:
        incoming->preamble[incoming->index] = byte;
        incoming->index++;
        incoming->bytes_remaining--;

        if (incoming->bytes_remaining == 0) {
          // For event and sco preambles, the last byte we read is the length
          incoming->bytes_remaining = (type == DATA_TYPE_ACL) ? RETRIEVE_ACL_LENGTH(incoming->preamble) : byte;

          size_t buffer_size = BT_HDR_SIZE + incoming->index + incoming->bytes_remaining;
          incoming->buffer = (BT_HDR *)buffer_allocator->alloc(buffer_size);

          if (!incoming->buffer) {
            ALOGE("%s error getting buffer for incoming packet", __func__);
            // Can't read any more of this current packet, so jump out
            incoming->state = incoming->bytes_remaining == 0 ? BRAND_NEW : IGNORE;
            break;
          }

          // Initialize the buffer
          incoming->buffer->offset = 0;
          incoming->buffer->layer_specific = 0;
          incoming->buffer->event = outbound_event_types[PACKET_TYPE_TO_INDEX(type)];
          memcpy(incoming->buffer->data, incoming->preamble, incoming->index);

          incoming->state = incoming->bytes_remaining > 0 ? BODY : FINISHED;
        }

        break;
      case BODY:
        incoming->buffer->data[incoming->index] = byte;
        incoming->index++;
        incoming->bytes_remaining--;

        size_t bytes_read = hal->read_data(type, (incoming->buffer->data + incoming->index), incoming->bytes_remaining, false);
        incoming->index += bytes_read;
        incoming->bytes_remaining -= bytes_read;

        incoming->state = incoming->bytes_remaining == 0 ? FINISHED : incoming->state;
        break;
      case IGNORE:
        incoming->bytes_remaining--;
        incoming->state = incoming->bytes_remaining == 0 ? BRAND_NEW : incoming->state;
        break;
      case FINISHED:
        ALOGE("%s the state machine should not have been left in the finished state.", __func__);
        break;
    }

    if (incoming->state == FINISHED) {
      incoming->buffer->len = incoming->index;
      btsnoop->capture(incoming->buffer, true);

      if (type != DATA_TYPE_EVENT || !filter_incoming_event(incoming->buffer)) {
        packet_fragmenter->reassemble_and_dispatch(incoming->buffer);
      }

      // We don't control the buffer anymore
      incoming->buffer = NULL;
      incoming->state = BRAND_NEW;
      hal->packet_finished(type);

      // We return after a packet is finished for two reasons:
      // 1. The type of the next packet could be different.
      // 2. We don't want to hog cpu time.
      return;
    }
  }
}

// TODO(zachoverflow): we seem to do this a couple places, like the HCI inject module. #centralize
static serial_data_type_t event_to_data_type(uint16_t event) {
  if (event == MSG_STACK_TO_HC_HCI_ACL)
    return DATA_TYPE_ACL;
  else if (event == MSG_STACK_TO_HC_HCI_SCO)
    return DATA_TYPE_SCO;
  else if (event == MSG_STACK_TO_HC_HCI_CMD)
    return DATA_TYPE_COMMAND;
  else
    ALOGE("%s invalid event type, could not translate.", __func__);

  return 0;
}

// Callback for the fragmenter to send a fragment
static void transmit_fragment(BT_HDR *packet, bool send_transmit_finished) {
  uint16_t opcode = 0;
  uint8_t *stream = packet->data + packet->offset;
  uint16_t event = packet->event & MSG_EVT_MASK;
  serial_data_type_t type = event_to_data_type(event);

  if (event == MSG_STACK_TO_HC_HCI_CMD) {
    command_credits--;
    STREAM_TO_UINT16(opcode, stream);
  }

  btsnoop->capture(packet, false);
  hal->transmit_data(type, packet->data + packet->offset, packet->len);

  if (event == MSG_STACK_TO_HC_HCI_CMD
    && !fixed_queue_is_empty(waiting_internal_commands)
    && packet->layer_specific == opcode) {
    // This is an internal command, so nobody owns the buffer now
    buffer_allocator->free(packet);
  } else if (send_transmit_finished) {
    callbacks->transmit_finished(packet, true);
  }
}

// Callback for the fragmenter to dispatch up a completely reassembled packet
static void dispatch_reassembled(BT_HDR *packet) {
  data_dispatcher_dispatch(
    interface.upward_dispatcher,
    packet->event & MSG_EVT_MASK,
    packet
  );
}

static void fragmenter_transmit_finished(void *buffer, bool all_fragments_sent) {
  callbacks->transmit_finished(buffer, all_fragments_sent);
}

static void init_layer_interface() {
  if (!interface_created) {
    interface.start_up = start_up;
    interface.shut_down = shut_down;

    interface.set_chip_power_on = set_chip_power_on;
    interface.send_low_power_command = low_power_manager->post_command;
    interface.do_preload = do_preload;
    interface.do_postload = do_postload;
    interface.turn_on_logging = turn_on_logging;
    interface.turn_off_logging = turn_off_logging;

    // It's probably ok for this to live forever. It's small and
    // there's only one instance of the hci interface.
    interface.upward_dispatcher = data_dispatcher_new("hci_layer");
    if (!interface.upward_dispatcher) {
      ALOGE("%s could not create upward dispatcher.", __func__);
      return;
    }

    interface.transmit_downward = transmit_downward;
    interface_created = true;
  }
}

static const hci_hal_callbacks_t hal_callbacks = {
  hal_says_data_ready
};

static const packet_fragmenter_callbacks_t packet_fragmenter_callbacks = {
  transmit_fragment,
  dispatch_reassembled,
  fragmenter_transmit_finished
};

const hci_interface_t *hci_layer_get_interface() {
  hal = hci_hal_get_interface();
  btsnoop = btsnoop_get_interface();
  hci_inject = hci_inject_get_interface();
  packet_fragmenter = packet_fragmenter_get_interface();
  vendor = vendor_get_interface();
  low_power_manager = low_power_manager_get_interface();

  init_layer_interface();
  return &interface;
}

const hci_interface_t *hci_layer_get_test_interface(
    const hci_hal_interface_t *hal_interface,
    const btsnoop_interface_t *btsnoop_interface,
    const hci_inject_interface_t *hci_inject_interface,
    const packet_fragmenter_interface_t *packet_fragmenter_interface,
    const vendor_interface_t *vendor_interface,
    const low_power_manager_interface_t *low_power_manager_interface) {

  hal = hal_interface;
  btsnoop = btsnoop_interface;
  hci_inject = hci_inject_interface;
  packet_fragmenter = packet_fragmenter_interface;
  vendor = vendor_interface;
  low_power_manager = low_power_manager_interface;

  init_layer_interface();
  return &interface;
}
