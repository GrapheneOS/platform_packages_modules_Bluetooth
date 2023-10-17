/*
 *
 *  Copyright 2023 The Android Open Source Project
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
 */

#include "stack/btm/btm_scn.h"

#include <gtest/gtest.h>

#include "stack/btm/btm_int_types.h"  // tBTM_CB
#include "stack/include/rfcdefs.h"    // RFCOMM_MAX_SCN

extern tBTM_CB btm_cb;

using testing::Test;

class BtmAllocateSCNTest : public Test {
 public:
 protected:
  void SetUp() override {
    btm_cb.btm_available_index = 1;
    for (int i = 0; i < RFCOMM_MAX_SCN; i++) {
      btm_cb.btm_scn[i] = false;
    }
  }

  void TearDown() override {}
};

TEST_F(BtmAllocateSCNTest, scn_available_after_available_index) {
  ASSERT_EQ(BTM_AllocateSCN(), 2);
  ASSERT_EQ(BTM_AllocateSCN(), 3);
  ASSERT_TRUE(BTM_TryAllocateSCN(4));
  ASSERT_TRUE(BTM_TryAllocateSCN(5));

  // Available index should be 3, and the next available scn is 6
  ASSERT_EQ(BTM_AllocateSCN(), 6);
}

TEST_F(BtmAllocateSCNTest, scn_available_before_available_index) {
  for (uint8_t scn = 2; scn <= RFCOMM_MAX_SCN; scn++) {
    ASSERT_TRUE(BTM_TryAllocateSCN(scn));
  }
  ASSERT_TRUE(BTM_FreeSCN(28));
  ASSERT_EQ(BTM_AllocateSCN(), 28);
  ASSERT_TRUE(BTM_FreeSCN(2));

  // Available index is 27, and the available scn is 2
  ASSERT_EQ(BTM_AllocateSCN(), 2);
}

TEST_F(BtmAllocateSCNTest, can_allocate_all_scns) {
  for (uint8_t scn = 2; scn <= RFCOMM_MAX_SCN; scn++) {
    ASSERT_EQ(BTM_AllocateSCN(), scn);
  }
}

TEST_F(BtmAllocateSCNTest, only_last_scn_available) {
  // Fill all relevant SCN except the last
  for (uint8_t scn = 2; scn < RFCOMM_MAX_SCN; scn++) {
    ASSERT_EQ(BTM_AllocateSCN(), scn);
  }

  ASSERT_EQ(BTM_AllocateSCN(), RFCOMM_MAX_SCN);
}

TEST_F(BtmAllocateSCNTest, no_scn_available) {
  for (uint8_t scn = 2; scn <= RFCOMM_MAX_SCN; scn++) {
    ASSERT_EQ(BTM_AllocateSCN(), scn);
  }

  ASSERT_EQ(BTM_AllocateSCN(), 0);
}
