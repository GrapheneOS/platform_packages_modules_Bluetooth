/******************************************************************************
 *
 *  Copyright (C) 2014 Android Open Source Project
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

#include "btsnoop_mem.h"
#include <time.h>

static btsnoop_data_cb s_data_cb = NULL;

void btsnoop_mem_set_callback(btsnoop_data_cb cb) {
  s_data_cb = cb;
}

void btsnoop_mem_capture(const HC_BT_HDR *p_buf) {
  if (s_data_cb == NULL)
    return;

  const uint8_t *p = (uint8_t *)(p_buf + 1) + p_buf->offset;
  const uint16_t type = p_buf->event & MSG_EVT_MASK;
  uint16_t len = 0;

  switch (type) {
    case MSG_STACK_TO_HC_HCI_CMD:
      len = p[2] + 4;
      break;

    case MSG_HC_TO_STACK_HCI_EVT:
      len = p[1] + 3;
      break;

    // Ignore data for privacy
    case MSG_STACK_TO_HC_HCI_ACL:
    case MSG_STACK_TO_HC_HCI_SCO:
    case MSG_HC_TO_STACK_HCI_ACL:
    case MSG_HC_TO_STACK_HCI_SCO:
      break;
  }

  if (len)
    (*s_data_cb)(type >> 8, len, p);
}
