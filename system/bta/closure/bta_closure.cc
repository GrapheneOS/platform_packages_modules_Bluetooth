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

#include "base/pending_task.h"
#include "base/time/time.h"
#include "bta_closure_int.h"
#include "bta_sys.h"

using base::PendingTask;
using base::TaskQueue;
using base::TimeTicks;

namespace {

enum {
  /* these events are handled by the state machine */
  BTA_CLOSURE_EXECUTE_EVT = BTA_SYS_EVT_START(BTA_ID_CLOSURE),
};

struct tBTA_CLOSURE_EXECUTE {
  BT_HDR hdr;
};

static const tBTA_SYS_REG bta_closure_hw_reg = {bta_closure_execute, NULL};

// The incoming queue receiving all posted tasks.
TaskQueue task_queue;

tBTA_SYS_SENDMSG bta_closure_sys_sendmsg = NULL;

}  // namespace

/* Accept bta_sys_register, and bta_sys_sendmsg. Those parameters can be used to
 * override system methods for tests.
 */
void bta_closure_init(tBTA_SYS_REGISTER registerer, tBTA_SYS_SENDMSG sender) {
  /* register closure message handler */
  registerer(BTA_ID_CLOSURE, &bta_closure_hw_reg);
  bta_closure_sys_sendmsg = sender;
}

bool bta_closure_execute(BT_HDR *p_msg) {
  if (p_msg->event != BTA_CLOSURE_EXECUTE_EVT) {
    APPL_TRACE_ERROR("%s: don't know how to execute event type %d", __func__,
                     p_msg->event);
    return false;
  }

  if (task_queue.empty()) {
    APPL_TRACE_ERROR("%s: trying to execute event, but queue is empty.",
                     __func__);
    return false;
  }

  PendingTask pending_task = std::move(task_queue.front());
  task_queue.pop();

  APPL_TRACE_VERBOSE("%s: executing closure %s", __func__,
                     pending_task.posted_from.ToString().c_str());

  pending_task.task.Run();
  return true;
}

/*
 * This function posts a closure for execution on the btu_bta_msg_queue. Please
 * see documentation at
 * https://www.chromium.org/developers/coding-style/important-abstractions-and-data-structures
 * for how to handle dynamic memory ownership/smart pointers with base::Owned(),
 * base::Passed(), base::ConstRef() and others.
 */
void do_in_bta_thread(const tracked_objects::Location &from_here,
                      const base::Closure &task) {
  PendingTask pending_task(from_here, task, TimeTicks(), true);

  task_queue.push(std::move(pending_task));

  tBTA_CLOSURE_EXECUTE *p_msg =
      (tBTA_CLOSURE_EXECUTE *)osi_malloc(sizeof(tBTA_CLOSURE_EXECUTE));

  APPL_TRACE_API("%s", __func__);

  p_msg->hdr.event = BTA_CLOSURE_EXECUTE_EVT;
  bta_closure_sys_sendmsg(p_msg);
}
