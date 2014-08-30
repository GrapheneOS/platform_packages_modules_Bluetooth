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

#include <gtest/gtest.h>

#include "AlarmTestHarness.h"

extern "C" {
#include <stdint.h>
#include <utils/Log.h>

#include "allocation_tracker.h"
#include "allocator.h"
#include "btsnoop.h"
#include "hci_hal.h"
#include "hci_inject.h"
#include "hci_layer.h"
#include "low_power_manager.h"
#include "osi.h"
#include "packet_fragmenter.h"
#include "semaphore.h"
#include "test_stubs.h"
#include "vendor.h"
}

DECLARE_TEST_MODES(
  start_up,
  shut_down,
  cycle_power,
  preload,
  postload,
  transmit_simple,
  receive_simple,
  send_internal_command,
  turn_on_logging,
  turn_off_logging
);

static const char *small_sample_data = "\"It is easy to see,\" replied Don Quixote";
static const char *command_sample_data = "that thou art not used to this business of adventures; those are giants";

static const char *logging_path = "this/is/a/test/logging/path";

static const hci_interface_t *hci;
static bdaddr_t test_addr = (bdaddr_t)"testaddress123";
static const hci_hal_callbacks_t *hal_callbacks;
static thread_t *internal_thread;
static vendor_cb firmware_config_callback;
static vendor_cb sco_config_callback;
static vendor_cb epilog_callback;
static send_internal_command_cb send_internal_command_callback;
static semaphore_t *done;
static const uint16_t test_handle = (0x1992 & 0xCFFF);
static const uint16_t test_handle_continuation = (0x1992 & 0xCFFF) | 0x1000;
static int packet_index;
static unsigned int data_size_sum;
static BT_HDR *data_to_receive;

// TODO move this to a common packet testing helper
static BT_HDR *manufacture_packet(uint16_t event, const char *data) {
  uint16_t data_length = strlen(data);
  uint16_t size = data_length;
  if (event == MSG_STACK_TO_HC_HCI_ACL) {
    size += 4; // 2 for the handle, 2 for the length;
  }

  BT_HDR *packet = (BT_HDR *)osi_malloc(size + sizeof(BT_HDR));
  packet->len = size;
  packet->offset = 0;
  packet->event = event;
  packet->layer_specific = 0;
  uint8_t *packet_data = packet->data;

  if (event == MSG_STACK_TO_HC_HCI_ACL) {
    UINT16_TO_STREAM(packet_data, test_handle);
    UINT16_TO_STREAM(packet_data, data_length);
  }

  for (int i = 0; i < data_length; i++) {
    packet_data[i] = data[i];
  }

  return packet;
}

static void expect_packet(uint16_t event, int max_acl_data_size, const uint8_t *data, uint16_t data_length, const char *expected_data) {
  int expected_data_offset;
  int length_to_check;

  if (event == MSG_STACK_TO_HC_HCI_ACL) {
    uint16_t handle;
    uint16_t length;
    STREAM_TO_UINT16(handle, data);
    STREAM_TO_UINT16(length, data);

    if (packet_index == 0)
      EXPECT_EQ(test_handle, handle);
    else
      EXPECT_EQ(test_handle_continuation, handle);

    int length_remaining = strlen(expected_data) - data_size_sum;
    int packet_data_length = data_length - HCI_ACL_PREAMBLE_SIZE;
    EXPECT_EQ(length_remaining, length);

    if (length_remaining < max_acl_data_size)
      EXPECT_EQ(length, packet_data_length);
    else
      EXPECT_EQ(max_acl_data_size, packet_data_length);

    length_to_check = packet_data_length;
    expected_data_offset = packet_index * max_acl_data_size;
    packet_index++;
  } else {
    length_to_check = strlen(expected_data);
    expected_data_offset = 0;
  }

  for (int i = 0; i < length_to_check; i++) {
    EXPECT_EQ(expected_data[expected_data_offset + i], data[i]);
    data_size_sum++;
  }
}

STUB_FUNCTION(bool, hal_init, (const hci_hal_callbacks_t *callbacks, thread_t *working_thread))
  DURING(start_up) AT_CALL(0) {
    hal_callbacks = callbacks;
    internal_thread = working_thread;
    return true;
  }

  UNEXPECTED_CALL;
  return false;
}

STUB_FUNCTION(bool, hal_open, ())
  DURING(preload) AT_CALL(0) return true;
  UNEXPECTED_CALL;
  return false;
}

STUB_FUNCTION(void, hal_close, ())
  DURING(shut_down) AT_CALL(0) return;
  UNEXPECTED_CALL;
}

STUB_FUNCTION(uint16_t, hal_transmit_data, (serial_data_type_t type, uint8_t *data, uint16_t length))
  DURING(transmit_simple) AT_CALL(0) {
    EXPECT_EQ(DATA_TYPE_ACL, type);
    expect_packet(MSG_STACK_TO_HC_HCI_ACL, 1021, data, length, small_sample_data);
    return length;
  }

  DURING(send_internal_command) AT_CALL(0) {
    EXPECT_EQ(DATA_TYPE_COMMAND, type);
    expect_packet(MSG_STACK_TO_HC_HCI_CMD, 1021, data, length, command_sample_data);
    return length;
  }

  UNEXPECTED_CALL;
  return 0;
}

STUB_FUNCTION(size_t, hal_read_data, (serial_data_type_t type, uint8_t *buffer, size_t max_size, UNUSED_ATTR bool block))
  DURING(receive_simple) {
    EXPECT_EQ(DATA_TYPE_ACL, type);
    for (size_t i = 0; i < max_size; i++) {
      if (data_to_receive->offset >= data_to_receive->len)
        break;

      buffer[i] = data_to_receive->data[data_to_receive->offset++];

      if (i == (max_size - 1))
        return i + 1; // We return the length, not the index;
    }
  }

  UNEXPECTED_CALL;
  return 0;
}

STUB_FUNCTION(void, hal_packet_finished, (serial_data_type_t type))
  DURING(receive_simple) AT_CALL(0) {
    EXPECT_EQ(DATA_TYPE_ACL, type);
    return;
  }

  UNEXPECTED_CALL;
}

STUB_FUNCTION(void, btsnoop_open, (const char *path))
  DURING(turn_on_logging) AT_CALL(0) {
    EXPECT_EQ(logging_path, path);
    return;
  }

  UNEXPECTED_CALL;
}

STUB_FUNCTION(void, btsnoop_close, ())
  DURING(turn_off_logging) AT_CALL(0) return;
  UNEXPECTED_CALL;
}

STUB_FUNCTION(bool, hci_inject_open, (
    UNUSED_ATTR const hci_interface_t *hci_interface,
    UNUSED_ATTR const allocator_t *buffer_allocator))
  DURING(start_up) AT_CALL(0) return true;
  UNEXPECTED_CALL;
  return false;
}

STUB_FUNCTION(void, hci_inject_close, ())
  DURING(shut_down) AT_CALL(0) return;
  UNEXPECTED_CALL;
}

STUB_FUNCTION(void, btsnoop_capture, (const BT_HDR *buffer, bool is_received))
  DURING(transmit_simple) AT_CALL(0) {
    EXPECT_FALSE(is_received);
    expect_packet(MSG_STACK_TO_HC_HCI_ACL, 1021, buffer->data + buffer->offset, buffer->len, small_sample_data);
    packet_index = 0;
    data_size_sum = 0;
    return;
  }

  DURING(send_internal_command) AT_CALL(0) {
    EXPECT_FALSE(is_received);
    expect_packet(MSG_STACK_TO_HC_HCI_CMD, 1021, buffer->data + buffer->offset, buffer->len, command_sample_data);
    packet_index = 0;
    data_size_sum = 0;
    return;
  }

  DURING(receive_simple) AT_CALL(0) {
    EXPECT_TRUE(is_received);
    EXPECT_TRUE(buffer->len == data_to_receive->len);
    const uint8_t *buffer_base = buffer->data + buffer->offset;
    const uint8_t *expected_base = data_to_receive->data;
    for (int i = 0; i < buffer->len; i++) {
      EXPECT_EQ(expected_base[i], buffer_base[i]);
    }

    return;
  }

  UNEXPECTED_CALL;
}

STUB_FUNCTION(void, low_power_init, (UNUSED_ATTR thread_t *thread))
  DURING(start_up) AT_CALL(0) return;
  UNEXPECTED_CALL;
}

STUB_FUNCTION(void, low_power_cleanup, ())
  DURING(shut_down) AT_CALL(0) return;
  UNEXPECTED_CALL;
}

STUB_FUNCTION(void, low_power_wake_assert, ())
  DURING(transmit_simple) AT_CALL(0) return;
  DURING(send_internal_command) AT_CALL(0) return;
  UNEXPECTED_CALL;
}

STUB_FUNCTION(void, low_power_transmit_done, ())
  DURING(transmit_simple) AT_CALL(0) return;
  DURING(send_internal_command) AT_CALL(0) return;
  UNEXPECTED_CALL;
}

STUB_FUNCTION(bool, vendor_open, (const uint8_t *addr, const allocator_t *allocator))
  DURING(start_up) AT_CALL(0) {
    EXPECT_EQ(test_addr, addr);
    EXPECT_EQ(&allocator_malloc, allocator);
    return true;
  }

  UNEXPECTED_CALL;
  return true;
}

STUB_FUNCTION(void, vendor_close, ())
  DURING(shut_down) AT_CALL(0) return;
  UNEXPECTED_CALL;
}

STUB_FUNCTION(void, vendor_set_callback, (vendor_async_opcode_t opcode, UNUSED_ATTR vendor_cb callback))
  DURING(start_up) {
    AT_CALL(0) {
      EXPECT_EQ(VENDOR_CONFIGURE_FIRMWARE, opcode);
      firmware_config_callback = callback;
      return;
    }
    AT_CALL(1) {
      EXPECT_EQ(VENDOR_CONFIGURE_SCO, opcode);
      sco_config_callback = callback;
      return;
    }
    AT_CALL(2) {
      EXPECT_EQ(VENDOR_DO_EPILOG, opcode);
      epilog_callback = callback;
      return;
    }
  }

  UNEXPECTED_CALL;
}

STUB_FUNCTION(void, vendor_set_send_internal_command_callback, (UNUSED_ATTR send_internal_command_cb callback))
  DURING(start_up) AT_CALL (0) {
    EXPECT_TRUE(callback != NULL);
    send_internal_command_callback = callback;
    return;
  }

  UNEXPECTED_CALL;
}

STUB_FUNCTION(int, vendor_send_command, (vendor_opcode_t opcode, void *param))
  DURING(shut_down) AT_CALL(0) {
    EXPECT_EQ(VENDOR_CHIP_POWER_CONTROL, opcode);
    EXPECT_EQ(BT_VND_PWR_OFF, *(int *)param);
    return 0;
  }

  DURING(cycle_power) {
    AT_CALL(0) {
      EXPECT_EQ(VENDOR_CHIP_POWER_CONTROL, opcode);
      EXPECT_EQ(BT_VND_PWR_ON, *(int *)param);
      return 0;
    }
    AT_CALL(1) {
      EXPECT_EQ(VENDOR_CHIP_POWER_CONTROL, opcode);
      EXPECT_EQ(BT_VND_PWR_OFF, *(int *)param);
      return 0;
    }
  }

  UNEXPECTED_CALL;
  return 0;
}

STUB_FUNCTION(int, vendor_send_async_command, (UNUSED_ATTR vendor_async_opcode_t opcode, UNUSED_ATTR void *param))
  DURING(preload) AT_CALL(0) {
    EXPECT_EQ(VENDOR_CONFIGURE_FIRMWARE, opcode);
    return 0;
  }

  DURING(postload) AT_CALL(0) {
    EXPECT_EQ(VENDOR_CONFIGURE_SCO, opcode);
    return 0;
  }

  UNEXPECTED_CALL;
  return 0;
}

STUB_FUNCTION(void, callback_transmit_finished, (UNUSED_ATTR void *buffer, bool all_fragments_sent))
  DURING(transmit_simple) AT_CALL(0) {
    EXPECT_TRUE(all_fragments_sent);
    osi_free(buffer);
    return;
  }

  DURING(send_internal_command) AT_CALL(0) {
    EXPECT_TRUE(all_fragments_sent);
    osi_free(buffer);
    return;
  }

  UNEXPECTED_CALL;
}

STUB_FUNCTION(void, internal_command_response, (UNUSED_ATTR void *response))
  UNEXPECTED_CALL;
}

static void reset_for(TEST_MODES_T next) {
  RESET_CALL_COUNT(vendor_open);
  RESET_CALL_COUNT(vendor_close);
  RESET_CALL_COUNT(vendor_set_callback);
  RESET_CALL_COUNT(vendor_set_send_internal_command_callback);
  RESET_CALL_COUNT(vendor_send_command);
  RESET_CALL_COUNT(vendor_send_async_command);
  RESET_CALL_COUNT(hal_init);
  RESET_CALL_COUNT(hal_open);
  RESET_CALL_COUNT(hal_close);
  RESET_CALL_COUNT(hal_read_data);
  RESET_CALL_COUNT(hal_packet_finished);
  RESET_CALL_COUNT(hal_transmit_data);
  RESET_CALL_COUNT(btsnoop_open);
  RESET_CALL_COUNT(btsnoop_close);
  RESET_CALL_COUNT(btsnoop_capture);
  RESET_CALL_COUNT(hci_inject_open);
  RESET_CALL_COUNT(hci_inject_close);
  RESET_CALL_COUNT(low_power_init);
  RESET_CALL_COUNT(low_power_cleanup);
  RESET_CALL_COUNT(low_power_wake_assert);
  RESET_CALL_COUNT(low_power_transmit_done);
  RESET_CALL_COUNT(callback_transmit_finished);
  RESET_CALL_COUNT(internal_command_response);
  CURRENT_TEST_MODE = next;
}

class HciLayerTest : public AlarmTestHarness {
  protected:
    virtual void SetUp() {
      AlarmTestHarness::SetUp();

      hci = hci_layer_get_test_interface(
        &hal,
        &btsnoop,
        &hci_inject,
        packet_fragmenter_get_interface(),
        &vendor,
        &low_power_manager
      );

      // Make sure the data dispatcher allocation isn't tracked
      allocation_tracker_reset();

      packet_index = 0;
      data_size_sum = 0;

      vendor.open = vendor_open;
      vendor.close = vendor_close;
      vendor.set_callback = vendor_set_callback;
      vendor.set_send_internal_command_callback = vendor_set_send_internal_command_callback;
      vendor.send_command = vendor_send_command;
      vendor.send_async_command = vendor_send_async_command;
      hal.init = hal_init;
      hal.open = hal_open;
      hal.close = hal_close;
      hal.read_data = hal_read_data;
      hal.packet_finished = hal_packet_finished;
      hal.transmit_data = hal_transmit_data;
      btsnoop.open = btsnoop_open;
      btsnoop.close = btsnoop_close;
      btsnoop.capture = btsnoop_capture;
      hci_inject.open = hci_inject_open;
      hci_inject.close = hci_inject_close;
      low_power_manager.init = low_power_init;
      low_power_manager.cleanup = low_power_cleanup;
      low_power_manager.wake_assert = low_power_wake_assert;
      low_power_manager.transmit_done = low_power_transmit_done;
      callbacks.transmit_finished = callback_transmit_finished;

      done = semaphore_new(0);

      reset_for(start_up);
      hci->start_up(test_addr, &allocator_malloc, &callbacks);

      EXPECT_CALL_COUNT(vendor_open, 1);
      EXPECT_CALL_COUNT(hal_init, 1);
      EXPECT_CALL_COUNT(low_power_init, 1);
      EXPECT_CALL_COUNT(vendor_set_callback, 3);
      EXPECT_CALL_COUNT(vendor_set_send_internal_command_callback, 1);
    }

    virtual void TearDown() {
      reset_for(shut_down);
      hci->shut_down();

      EXPECT_CALL_COUNT(low_power_cleanup, 1);
      EXPECT_CALL_COUNT(hal_close, 1);
      EXPECT_CALL_COUNT(vendor_send_command, 1);
      EXPECT_CALL_COUNT(vendor_close, 1);

      semaphore_free(done);
      AlarmTestHarness::TearDown();
    }

    hci_hal_interface_t hal;
    btsnoop_interface_t btsnoop;
    hci_inject_interface_t hci_inject;
    vendor_interface_t vendor;
    low_power_manager_interface_t low_power_manager;
    hci_callbacks_t callbacks;
};

static void signal_work_item(UNUSED_ATTR void *context) {
  semaphore_post(done);
}

static void flush_thread(thread_t *thread) {
  thread_post(thread, signal_work_item, NULL);
  semaphore_wait(done);
}

TEST_F(HciLayerTest, test_cycle_power) {
  reset_for(cycle_power);
  hci->set_chip_power_on(true);
  hci->set_chip_power_on(false);

  EXPECT_CALL_COUNT(vendor_send_command, 2);
}

TEST_F(HciLayerTest, test_preload) {
  reset_for(preload);
  hci->do_preload();

  flush_thread(internal_thread);
  EXPECT_CALL_COUNT(hal_open, 1);
  EXPECT_CALL_COUNT(vendor_send_async_command, 1);
}

TEST_F(HciLayerTest, test_postload) {
  reset_for(postload);
  hci->do_postload();

  flush_thread(internal_thread);
  EXPECT_CALL_COUNT(vendor_send_async_command, 1);
}

TEST_F(HciLayerTest, test_transmit_simple) {
  reset_for(transmit_simple);
  BT_HDR *packet = manufacture_packet(MSG_STACK_TO_HC_HCI_ACL, small_sample_data);
  hci->transmit_downward(MSG_STACK_TO_HC_HCI_ACL, packet);

  flush_thread(internal_thread);
  EXPECT_CALL_COUNT(hal_transmit_data, 1);
  EXPECT_CALL_COUNT(btsnoop_capture, 1);
  EXPECT_CALL_COUNT(low_power_transmit_done, 1);
  EXPECT_CALL_COUNT(low_power_wake_assert, 1);
  EXPECT_CALL_COUNT(callback_transmit_finished, 1);
}

TEST_F(HciLayerTest, test_receive_simple) {
  reset_for(receive_simple);
  data_to_receive = manufacture_packet(MSG_STACK_TO_HC_HCI_ACL, small_sample_data);

  // Not running on the internal thread, unlike the real hal
  hal_callbacks->data_ready(DATA_TYPE_ACL);
  EXPECT_CALL_COUNT(hal_packet_finished, 1);
  EXPECT_CALL_COUNT(btsnoop_capture, 1);

  osi_free(data_to_receive);
}

TEST_F(HciLayerTest, test_send_internal_command) {
  // Send a test command
  reset_for(send_internal_command);
  data_to_receive = manufacture_packet(MSG_STACK_TO_HC_HCI_CMD, command_sample_data);
  send_internal_command_callback(MSG_STACK_TO_HC_HCI_CMD, data_to_receive, internal_command_response);

  flush_thread(internal_thread);
  EXPECT_CALL_COUNT(hal_transmit_data, 1);
  EXPECT_CALL_COUNT(btsnoop_capture, 1);
  EXPECT_CALL_COUNT(low_power_transmit_done, 1);
  EXPECT_CALL_COUNT(low_power_wake_assert, 1);
  EXPECT_CALL_COUNT(callback_transmit_finished, 1);

  // TODO(zachoverflow): send a response and make sure the response ends up at the callback
}

// TODO(zachoverflow): test post-reassembly better, stub out fragmenter instead of using it

TEST_F(HciLayerTest, test_turn_on_logging) {
  reset_for(turn_on_logging);
  hci->turn_on_logging(logging_path);
  EXPECT_CALL_COUNT(btsnoop_open, 1);
}

TEST_F(HciLayerTest, test_turn_off_logging) {
  reset_for(turn_off_logging);
  hci->turn_off_logging();
  EXPECT_CALL_COUNT(btsnoop_close, 1);
}
