/*
 *
 *  Copyright 2022 The Android Open Source Project
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

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <algorithm>
#include <map>
#include <memory>

#include "stack/btm/btm_sco.h"
#include "udrv/include/uipc.h"

extern std::map<std::string, int> mock_function_count_map;
extern std::unique_ptr<tUIPC_STATE> mock_uipc_init_ret;
extern uint32_t mock_uipc_read_ret;
extern bool mock_uipc_send_ret;

namespace {

using testing::Test;

const uint8_t msbc_zero_packet[] = {
    0x01, 0x08, 0xad, 0x00, 0x00, 0xc5, 0x00, 0x00, 0x00, 0x00, 0x77, 0x6d,
    0xb6, 0xdd, 0xdb, 0x6d, 0xb7, 0x76, 0xdb, 0x6d, 0xdd, 0xb6, 0xdb, 0x77,
    0x6d, 0xb6, 0xdd, 0xdb, 0x6d, 0xb7, 0x76, 0xdb, 0x6d, 0xdd, 0xb6, 0xdb,
    0x77, 0x6d, 0xb6, 0xdd, 0xdb, 0x6d, 0xb7, 0x76, 0xdb, 0x6d, 0xdd, 0xb6,
    0xdb, 0x77, 0x6d, 0xb6, 0xdd, 0xdb, 0x6d, 0xb7, 0x76, 0xdb, 0x6c, 0x00};

class ScoHciTest : public Test {
 public:
 protected:
  void SetUp() override {
    mock_function_count_map.clear();
    mock_uipc_init_ret = nullptr;
    mock_uipc_read_ret = 0;
    mock_uipc_send_ret = true;
  }
  void TearDown() override {}
};

class ScoHciWithOpenCleanTest : public ScoHciTest {
 public:
 protected:
  void SetUp() override {
    ScoHciTest::SetUp();
    mock_uipc_init_ret = std::make_unique<tUIPC_STATE>();
    bluetooth::audio::sco::open();
  }
  void TearDown() override { bluetooth::audio::sco::cleanup(); }
};

class ScoHciWbsWithInitCleanTest : public Test {
 public:
 protected:
  void SetUp() override { bluetooth::audio::sco::wbs::init(60); }
  void TearDown() override { bluetooth::audio::sco::wbs::cleanup(); }
};

TEST_F(ScoHciTest, ScoOverHciOpenFail) {
  bluetooth::audio::sco::open();
  ASSERT_EQ(mock_function_count_map["UIPC_Init"], 1);
  ASSERT_EQ(mock_function_count_map["UIPC_Open"], 0);
  bluetooth::audio::sco::cleanup();

  // UIPC is nullptr and shouldn't require an actual call of UIPC_Close;
  ASSERT_EQ(mock_function_count_map["UIPC_Close"], 0);
}

TEST_F(ScoHciWithOpenCleanTest, ScoOverHciOpenClean) {
  ASSERT_EQ(mock_function_count_map["UIPC_Init"], 1);
  ASSERT_EQ(mock_function_count_map["UIPC_Open"], 1);
  ASSERT_EQ(mock_uipc_init_ret, nullptr);

  mock_uipc_init_ret = std::make_unique<tUIPC_STATE>();
  // Double open will override uipc
  bluetooth::audio::sco::open();
  ASSERT_EQ(mock_function_count_map["UIPC_Init"], 2);
  ASSERT_EQ(mock_function_count_map["UIPC_Open"], 2);
  ASSERT_EQ(mock_uipc_init_ret, nullptr);

  bluetooth::audio::sco::cleanup();
  ASSERT_EQ(mock_function_count_map["UIPC_Close"], 1);

  // Double clean shouldn't fail
  bluetooth::audio::sco::cleanup();
  ASSERT_EQ(mock_function_count_map["UIPC_Close"], 1);
}

TEST_F(ScoHciTest, ScoOverHciReadNoOpen) {
  uint8_t buf[100];
  ASSERT_EQ(bluetooth::audio::sco::read(buf, sizeof(buf)), size_t(0));
  ASSERT_EQ(mock_function_count_map["UIPC_Read"], 0);
}

TEST_F(ScoHciWithOpenCleanTest, ScoOverHciRead) {
  uint8_t buf[100];
  // The UPIC should be ready
  ASSERT_EQ(mock_function_count_map["UIPC_Init"], 1);
  ASSERT_EQ(mock_function_count_map["UIPC_Open"], 1);
  ASSERT_EQ(mock_uipc_init_ret, nullptr);

  mock_uipc_read_ret = sizeof(buf);
  ASSERT_EQ(bluetooth::audio::sco::read(buf, sizeof(buf)), mock_uipc_read_ret);
  ASSERT_EQ(mock_function_count_map["UIPC_Read"], 1);
}

TEST_F(ScoHciTest, ScoOverHciWriteNoOpen) {
  uint8_t buf[100];
  bluetooth::audio::sco::write(buf, sizeof(buf));
  ASSERT_EQ(mock_function_count_map["UIPC_Send"], 0);
}

TEST_F(ScoHciWithOpenCleanTest, ScoOverHciWrite) {
  uint8_t buf[100];
  // The UPIC should be ready
  ASSERT_EQ(mock_function_count_map["UIPC_Init"], 1);
  ASSERT_EQ(mock_function_count_map["UIPC_Open"], 1);
  ASSERT_EQ(mock_uipc_init_ret, nullptr);

  ASSERT_EQ(bluetooth::audio::sco::write(buf, sizeof(buf)), sizeof(buf));
  ASSERT_EQ(mock_function_count_map["UIPC_Send"], 1);

  // Send fails
  mock_uipc_send_ret = false;
  ASSERT_EQ(bluetooth::audio::sco::write(buf, sizeof(buf)), size_t(0));
  ASSERT_EQ(mock_function_count_map["UIPC_Send"], 2);
}

TEST(ScoHciWbsTest, WbsInit) {
  ASSERT_EQ(bluetooth::audio::sco::wbs::init(60), size_t(60));
  ASSERT_EQ(bluetooth::audio::sco::wbs::init(72), size_t(72));
  // Fallback to 60 if the packet size is not supported
  ASSERT_EQ(bluetooth::audio::sco::wbs::init(48), size_t(60));
  bluetooth::audio::sco::wbs::cleanup();
}

TEST(ScoHciWbsTest, WbsEnqueuePacketWithoutInit) {
  uint8_t payload[60];
  // Return 0 if buffer is uninitialized
  ASSERT_EQ(
      bluetooth::audio::sco::wbs::enqueue_packet(payload, sizeof(payload)),
      size_t(0));
}

TEST_F(ScoHciWbsWithInitCleanTest, WbsEnqueuePacket) {
  uint8_t payload[60];
  // Return 0 if payload is invalid
  ASSERT_EQ(
      bluetooth::audio::sco::wbs::enqueue_packet(nullptr, sizeof(payload)),
      size_t(0));
  // Return 0 if packet size is consistent
  ASSERT_EQ(bluetooth::audio::sco::wbs::enqueue_packet(payload, 72), size_t(0));
  ASSERT_EQ(
      bluetooth::audio::sco::wbs::enqueue_packet(payload, sizeof(payload)),
      size_t(60));
  // Return 0 if buffer is full
  ASSERT_EQ(
      bluetooth::audio::sco::wbs::enqueue_packet(payload, sizeof(payload)),
      size_t(0));
}

TEST(ScoHciWbsTest, WbsDecodeWithoutInit) {
  const uint8_t* decoded = nullptr;
  // Return 0 if buffer is uninitialized
  ASSERT_EQ(bluetooth::audio::sco::wbs::decode(&decoded), size_t(0));
  ASSERT_EQ(decoded, nullptr);
}

TEST_F(ScoHciWbsWithInitCleanTest, WbsDecode) {
  const uint8_t* decoded = nullptr;
  uint8_t payload[60] = {0};

  // No data to decode
  ASSERT_EQ(bluetooth::audio::sco::wbs::decode(&decoded), size_t(0));
  ASSERT_EQ(decoded, nullptr);
  // Fill in invalid packet, all zeros.
  ASSERT_EQ(
      bluetooth::audio::sco::wbs::enqueue_packet(payload, sizeof(payload)),
      sizeof(payload));

  // Return all zero frames when there comes an invalid packet.
  ASSERT_EQ(bluetooth::audio::sco::wbs::decode(&decoded),
            size_t(BTM_MSBC_CODE_SIZE));
  ASSERT_NE(decoded, nullptr);
  for (size_t i = 0; i < BTM_MSBC_CODE_SIZE; i++) {
    ASSERT_EQ(decoded[i], 0);
  }

  decoded = nullptr;
  ASSERT_EQ(bluetooth::audio::sco::wbs::enqueue_packet(msbc_zero_packet,
                                                       sizeof(payload)),
            sizeof(msbc_zero_packet));
  ASSERT_EQ(bluetooth::audio::sco::wbs::decode(&decoded),
            size_t(BTM_MSBC_CODE_SIZE));
  ASSERT_NE(decoded, nullptr);
  for (size_t i = 0; i < BTM_MSBC_CODE_SIZE; i++) {
    ASSERT_EQ(decoded[i], 0);
  }

  decoded = nullptr;
  // No remaining data to decode
  ASSERT_EQ(bluetooth::audio::sco::wbs::decode(&decoded), size_t(0));
  ASSERT_EQ(decoded, nullptr);
}

TEST(ScoHciWbsTest, WbsEncodeWithoutInit) {
  int16_t data[120] = {0};
  // Return 0 if buffer is uninitialized
  ASSERT_EQ(bluetooth::audio::sco::wbs::encode(data, sizeof(data)), size_t(0));
}

TEST_F(ScoHciWbsWithInitCleanTest, WbsEncode) {
  int16_t data[120] = {0};

  // Return 0 if data is invalid
  ASSERT_EQ(bluetooth::audio::sco::wbs::encode(nullptr, sizeof(data)),
            size_t(0));
  // Return 0 if data length is insufficient
  ASSERT_EQ(bluetooth::audio::sco::wbs::encode(data, sizeof(data) - 1),
            size_t(0));
  ASSERT_EQ(bluetooth::audio::sco::wbs::encode(data, sizeof(data)),
            sizeof(data));

  // Return 0 if the packet buffer is full
  ASSERT_EQ(bluetooth::audio::sco::wbs::encode(data, sizeof(data)), size_t(0));
}

TEST(ScoHciWbsTest, WbsDequeuePacketWithoutInit) {
  const uint8_t* encoded = nullptr;
  // Return 0 if buffer is uninitialized
  ASSERT_EQ(bluetooth::audio::sco::wbs::dequeue_packet(&encoded), size_t(0));
  ASSERT_EQ(encoded, nullptr);
}

TEST_F(ScoHciWbsWithInitCleanTest, WbsDequeuePacket) {
  const uint8_t* encoded = nullptr;
  // Return 0 if output pointer is invalid
  ASSERT_EQ(bluetooth::audio::sco::wbs::dequeue_packet(nullptr), size_t(0));
  ASSERT_EQ(encoded, nullptr);

  // Return 0 if there is insufficient data to dequeue
  ASSERT_EQ(bluetooth::audio::sco::wbs::dequeue_packet(&encoded), size_t(0));
  ASSERT_EQ(encoded, nullptr);
}

TEST_F(ScoHciWbsWithInitCleanTest, WbsEncodeDequeuePackets) {
  uint8_t h2_header_frames_count[] = {0x08, 0x38, 0xc8, 0xf8};
  int16_t data[120] = {0};
  const uint8_t* encoded = nullptr;

  for (size_t i = 0; i < 5; i++) {
    ASSERT_EQ(bluetooth::audio::sco::wbs::encode(data, sizeof(data)),
              sizeof(data));
    ASSERT_EQ(bluetooth::audio::sco::wbs::dequeue_packet(&encoded), size_t(60));
    ASSERT_NE(encoded, nullptr);
    for (size_t j = 0; j < 60; j++) {
      ASSERT_EQ(encoded[j],
                j == 1 ? h2_header_frames_count[i % 4] : msbc_zero_packet[j]);
    }
  }
}

}  // namespace
