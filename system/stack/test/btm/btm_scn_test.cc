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
  btm_cb.btm_available_index = 5;
  uint8_t occupied_idx[] = {1, 2, 3, 4, 5, 6, 7};
  for (uint8_t idx : occupied_idx) {
    btm_cb.btm_scn[idx] = true;
  }

  uint8_t scn = BTM_AllocateSCN();
  ASSERT_EQ(scn, 9);  // All indexes up to 7 are occupied; hence index 8 i.e.
                      // scn 9 should return
}

TEST_F(BtmAllocateSCNTest, scn_available_before_available_index) {
  btm_cb.btm_available_index = 28;
  uint8_t occupied_idx[] = {26, 27, 28, 29};
  for (uint8_t idx : occupied_idx) {
    btm_cb.btm_scn[idx] = true;
  }

  uint8_t scn = BTM_AllocateSCN();
  ASSERT_EQ(scn, 2);  // All SCN from available to 30 are occupied; hence cycle
                      // to beginning.
}

TEST_F(BtmAllocateSCNTest, can_allocate_all_scns) {
  for (uint8_t scn = 2; scn <= RFCOMM_MAX_SCN; scn++) {
    EXPECT_EQ(BTM_AllocateSCN(), scn);
  }
}

TEST_F(BtmAllocateSCNTest, only_last_scn_available) {
  // Fill all relevant SCN except the last
  for (uint8_t scn = 2; scn < RFCOMM_MAX_SCN; scn++) {
    btm_cb.btm_scn[scn - 1] = true;
  }

  EXPECT_EQ(BTM_AllocateSCN(), RFCOMM_MAX_SCN);
}

TEST_F(BtmAllocateSCNTest, no_scn_available) {
  for (int i = 1; i < RFCOMM_MAX_SCN;
       i++) {  // Fill all relevant SCN indexes (1 to 29)
    btm_cb.btm_scn[i] = true;
  }

  uint8_t scn = BTM_AllocateSCN();
  EXPECT_EQ(scn, 0) << "scn = " << scn << "and not 0";
}
