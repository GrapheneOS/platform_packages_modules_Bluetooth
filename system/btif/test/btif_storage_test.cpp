/******************************************************************************
 *
 *  Copyright (C) 2016 Google, Inc.
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

extern "C" {
#include "btif/include/btif_util.h"
}

TEST(BtifStorageTest, test_string_to_uuid) {
  const char *s1 = "e39c6285-867f-4b1d-9db0-35fbd9aebf22";
  const uint8_t o1[] = {0xe3, 0x9c, 0x62, 0x85, 0x86, 0x7f, 0x4b, 0x1d,
                     0x9d, 0xb0, 0x35, 0xfb, 0xd9, 0xae, 0xbf, 0x22};

  bt_uuid_t uuid;
  memset(&uuid, 0, sizeof(uuid));
  EXPECT_FALSE(memcmp(&uuid, o1, sizeof(o1)) == 0);

  string_to_uuid(s1, &uuid);
  EXPECT_TRUE(memcmp(&uuid, o1, sizeof(o1)) == 0);
}

