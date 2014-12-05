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

#include <unistd.h>
#include "bt_target.h"
#include "btif_debug.h"
#include "btif_debug_btsnoop.h"
#include "btif_debug_conn.h"

void btif_debug_init() {
#if defined(BTSNOOP_MEM) && (BTSNOOP_MEM == TRUE)
  btif_debug_btsnoop_init();
#endif
}

void btif_debug_dump(int fd) {
  btif_debug_conn_dump(fd);
#if defined(BTSNOOP_MEM) && (BTSNOOP_MEM == TRUE)
  btif_debug_btsnoop_dump(fd);
#endif

  fsync(fd);
  close(fd);
}

uint64_t btif_debug_ts() {
  struct timeval tv;
  gettimeofday(&tv, NULL);
  return (tv.tv_sec * 1000000LL) + tv.tv_usec;
}
