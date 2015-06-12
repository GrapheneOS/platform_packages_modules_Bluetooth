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
#include <algorithm>
#include <array>
#include <stdint.h>

#include <gtest/gtest.h>

#include "uuid.h"

using namespace bluetooth;

struct UuidTest : public ::testing::Test {
  typedef std::array<uint8_t, Uuid::kUuid128Octets> UuidData;

  UuidTest()
      : kBtSigBaseUuid({0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00,
              0x80, 0x00, 0x00, 0x80, 0x5f, 0x9b, 0x34, 0xfb})
  {}

  const UuidData kBtSigBaseUuid;
};

// Verify that an uninitialized Uuid is equal
// To the BT SIG Base UUID.
TEST_F(UuidTest, DefaultUuid) {
  Uuid uuid;
  ASSERT_TRUE(uuid.GetFullBigEndian() == kBtSigBaseUuid);
}

// Verify that we initialize a 16-bit UUID in a
// way consistent with how we read it.
TEST_F(UuidTest, Init16Bit) {
  auto My16BitUuid = kBtSigBaseUuid;
  My16BitUuid[2] = 0xde;
  My16BitUuid[3] = 0xad;
  Uuid uuid(Uuid::Uuid16Bit({0xde, 0xad}));
  ASSERT_TRUE(uuid.GetFullBigEndian() == My16BitUuid);
}

// Verify that we initialize a 16-bit UUID in a
// way consistent with how we read it.
TEST_F(UuidTest, Init16BitString) {
  auto My16BitUuid = kBtSigBaseUuid;
  My16BitUuid[2] = 0xde;
  My16BitUuid[3] = 0xad;
  Uuid uuid("dead");
  ASSERT_TRUE(uuid.GetFullBigEndian() == My16BitUuid);
}


// Verify that we initialize a 32-bit UUID in a
// way consistent with how we read it.
TEST_F(UuidTest, Init32Bit) {
  auto My32BitUuid = kBtSigBaseUuid;
  My32BitUuid[0] = 0xde;
  My32BitUuid[1] = 0xad;
  My32BitUuid[2] = 0xbe;
  My32BitUuid[3] = 0xef;
  Uuid uuid(Uuid::Uuid32Bit({0xde, 0xad, 0xbe, 0xef}));
  ASSERT_TRUE(uuid.GetFullBigEndian() == My32BitUuid);
}

// Verify correct reading of a 32-bit UUID initialized from string.
TEST_F(UuidTest, Init32BitString) {
  auto My32BitUuid = kBtSigBaseUuid;
  My32BitUuid[0] = 0xde;
  My32BitUuid[1] = 0xad;
  My32BitUuid[2] = 0xbe;
  My32BitUuid[3] = 0xef;
  Uuid uuid("deadbeef");
  ASSERT_TRUE(uuid.GetFullBigEndian() == My32BitUuid);
}

// Verify that we initialize a 128-bit UUID in a
// way consistent with how we read it.
TEST_F(UuidTest, Init128Bit) {
  auto My128BitUuid = kBtSigBaseUuid;
  for (int i = 0; i < static_cast<int>(My128BitUuid.size()); ++i) {
    My128BitUuid[i] = i;
  }

  Uuid uuid(My128BitUuid);
  ASSERT_TRUE(uuid.GetFullBigEndian() == My128BitUuid);
}

// Verify that we initialize a 128-bit UUID in a
// way consistent with how we read it as LE.
TEST_F(UuidTest, Init128BitLittleEndian) {
  auto My128BitUuid = kBtSigBaseUuid;
  for (int i = 0; i < static_cast<int>(My128BitUuid.size()); ++i) {
    My128BitUuid[i] = i;
  }

  Uuid uuid(My128BitUuid);
  std::reverse(My128BitUuid.begin(), My128BitUuid.end());
  ASSERT_TRUE(uuid.GetFullLittleEndian() == My128BitUuid);
}

// Verify that we initialize a 128-bit UUID in a
// way consistent with how we read it.
TEST_F(UuidTest, Init128BitString) {
  auto My128BitUuid = kBtSigBaseUuid;
  for (int i = 0; i < static_cast<int>(My128BitUuid.size()); ++i) {
    My128BitUuid[i] = i;
  }

  std::string uuid_text("000102030405060708090A0B0C0D0E0F");
  ASSERT_TRUE(uuid_text.size() == (16 * 2));
  Uuid uuid(uuid_text);
  ASSERT_TRUE(uuid.GetFullBigEndian() == My128BitUuid);
}
