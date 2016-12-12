/******************************************************************************
 *
 *  Copyright (C) 2016 The Android Open Source Project
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

#include "bta/closure/bta_closure_int.h"
#include "bta/include/bta_closure_api.h"
#include "include/bt_trace.h"

namespace {

/* There is no test class, because we talk to C code that accepts plain
 * functions as arguments.
 */

int test_counter = 0;
int msg_send_counter = 0;
tBTA_SYS_EVT_HDLR* closure_handler = NULL;
void* msg = NULL;

void test_plus_one_task() { test_counter++; }

void test_plus_two_task() { test_counter += 2; }

void fake_bta_sys_sendmsg(void* p_msg) {
  msg_send_counter++;
  msg = p_msg;
}

void fake_bta_sys_register(uint8_t id, const tBTA_SYS_REG* p_reg) {
  closure_handler = p_reg->evt_hdlr;
}

bool fake_bta_sys_sendmsg_execute() { return closure_handler((BT_HDR*)msg); }

}  // namespace

// TODO(jpawlowski): there is some weird dependency issue in tests, and the
// tests here fail to compile without this definition.
void LogMsg(uint32_t trace_set_mask, const char* fmt_str, ...) {}

TEST(ClosureTest, test_post_task) {
  msg_send_counter = 0;
  test_counter = 0;

  bta_closure_init(fake_bta_sys_register, fake_bta_sys_sendmsg);

  msg_send_counter = 0;
  do_in_bta_thread(FROM_HERE, base::Bind(&test_plus_one_task));
  EXPECT_EQ(1, msg_send_counter);
  EXPECT_TRUE(msg != NULL) << "Message should not be NULL";

  EXPECT_TRUE(fake_bta_sys_sendmsg_execute());
  EXPECT_EQ(1, test_counter);

  // We sent only one task for execution, attempt to execute non-exiting
  // task should fail, counter shouldn't be updated
  EXPECT_FALSE(fake_bta_sys_sendmsg_execute());
  EXPECT_EQ(1, test_counter);
}

TEST(ClosureTest, test_post_multiple_tasks) {
  msg_send_counter = 0;
  test_counter = 0;

  bta_closure_init(fake_bta_sys_register, fake_bta_sys_sendmsg);

  do_in_bta_thread(FROM_HERE, base::Bind(&test_plus_one_task));
  do_in_bta_thread(FROM_HERE, base::Bind(&test_plus_two_task));
  do_in_bta_thread(FROM_HERE, base::Bind(&test_plus_one_task));
  do_in_bta_thread(FROM_HERE, base::Bind(&test_plus_two_task));
  do_in_bta_thread(FROM_HERE, base::Bind(&test_plus_one_task));
  do_in_bta_thread(FROM_HERE, base::Bind(&test_plus_two_task));

  EXPECT_EQ(6, msg_send_counter);
  EXPECT_TRUE(msg != NULL) << "Message should not be NULL";

  EXPECT_TRUE(fake_bta_sys_sendmsg_execute());
  EXPECT_EQ(1, test_counter);

  EXPECT_TRUE(fake_bta_sys_sendmsg_execute());
  EXPECT_EQ(3, test_counter);

  EXPECT_TRUE(fake_bta_sys_sendmsg_execute());
  EXPECT_EQ(4, test_counter);

  EXPECT_TRUE(fake_bta_sys_sendmsg_execute());
  EXPECT_EQ(6, test_counter);

  EXPECT_TRUE(fake_bta_sys_sendmsg_execute());
  EXPECT_EQ(7, test_counter);

  EXPECT_TRUE(fake_bta_sys_sendmsg_execute());
  EXPECT_EQ(9, test_counter);

  // We sent only one task for execution, attempt to execute non-exiting
  // task should fail, counter shouldn't be updated
  EXPECT_FALSE(fake_bta_sys_sendmsg_execute());
  EXPECT_EQ(9, test_counter);
}
