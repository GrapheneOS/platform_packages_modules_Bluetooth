//
//  Copyright (C) 2015 Google, Inc.
//
//  Licensed under the Apache License, Version 2.0 (the "License");
//  you may not use this file except in compliance with the License.
//  You may obtain a copy of the License at:
//
//  http://www.apache.org/licenses/LICENSE-2.0
//
//  Unless required by applicable law or agreed to in writing, software
//  distributed under the License is distributed on an "AS IS" BASIS,
//  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//  See the License for the specific language governing permissions and
//  limitations under the License.
//

#include <gtest/gtest.h>

#include "service/util/address_helper.h"

TEST(UtilTest, IsAddressValid) {
  EXPECT_FALSE(util::IsAddressValid(""));
  EXPECT_FALSE(util::IsAddressValid("000000000000"));
  EXPECT_FALSE(util::IsAddressValid("00:00:00:00:0000"));
  EXPECT_FALSE(util::IsAddressValid("00:00:00:00:00:0"));
  EXPECT_FALSE(util::IsAddressValid("00:00:00:00:00:0;"));
  EXPECT_TRUE(util::IsAddressValid("00:00:00:00:00:00"));
  EXPECT_TRUE(util::IsAddressValid("aB:cD:eF:Gh:iJ:Kl"));
}
