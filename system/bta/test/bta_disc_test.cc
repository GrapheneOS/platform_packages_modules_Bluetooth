/*
 * Copyright 2023 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <base/strings/stringprintf.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <sys/socket.h>

#include "bta/dm/bta_dm_disc.h"
#include "bta/dm/bta_dm_int.h"
#include "osi/include/allocator.h"
#include "stack/btm/neighbor_inquiry.h"
#include "test/common/main_handler.h"
#include "test/fake/fake_osi.h"
#include "types/bt_transport.h"

namespace {

const RawAddress kRawAddress({0x11, 0x22, 0x33, 0x44, 0x55, 0x66});

}

// Test hooks
namespace bluetooth {
namespace legacy {
namespace testing {

bool bta_dm_read_remote_device_name(const RawAddress& bd_addr,
                                    tBT_TRANSPORT transport);
void bta_dm_discover_next_device();
void bta_dm_execute_queued_request();
void bta_dm_find_services(const RawAddress& bd_addr);
void bta_dm_inq_cmpl(uint8_t num);
void bta_dm_inq_cmpl_cb(void* p_result);
void bta_dm_observe_cmpl_cb(void* p_result);
void bta_dm_observe_results_cb(tBTM_INQ_RESULTS* p_inq, const uint8_t* p_eir,
                               uint16_t eir_len);
void bta_dm_opportunistic_observe_results_cb(tBTM_INQ_RESULTS* p_inq,
                                             const uint8_t* p_eir,
                                             uint16_t eir_len);
void bta_dm_queue_search(tBTA_DM_MSG* p_data);
void bta_dm_search_result(tBTA_DM_MSG* p_data);
void bta_dm_search_timer_cback(void* data);
void bta_dm_service_search_remname_cback(const RawAddress& bd_addr,
                                         DEV_CLASS dc, tBTM_BD_NAME bd_name);
void bta_dm_start_scan(uint8_t duration_sec, bool low_latency_scan = false);
void store_avrcp_profile_feature(tSDP_DISC_REC* sdp_rec);

}  // namespace testing
}  // namespace legacy
}  // namespace bluetooth

class BtaDiscTest : public testing::Test {
 protected:
  void SetUp() override {
    fake_osi_ = std::make_unique<test::fake::FakeOsi>();
    main_thread_start_up();
  }

  void TearDown() override {
    sync_main_handler();
    main_thread_shut_down();
  }

  std::unique_ptr<test::fake::FakeOsi> fake_osi_;
};

TEST_F(BtaDiscTest, nop) {}

TEST_F(BtaDiscTest, DumpsysBtaDmDisc) {
  std::FILE* file = std::tmpfile();
  DumpsysBtaDmDisc(fileno(file));
}

TEST_F(BtaDiscTest, bta_dm_ble_csis_observe) {
  bta_dm_ble_csis_observe(true, [](tBTA_DM_SEARCH_EVT, tBTA_DM_SEARCH*) {});
};

TEST_F(BtaDiscTest, bta_dm_ble_csis_observe__false) {
  bta_dm_ble_csis_observe(false, [](tBTA_DM_SEARCH_EVT, tBTA_DM_SEARCH*) {});
};

TEST_F(BtaDiscTest, bta_dm_ble_scan) {
  // bool start, uint8_t duration_sec, bool low_latency_scan
  constexpr bool kStartLeScan = true;
  constexpr bool kStopLeScan = false;
  const uint8_t duration_in_seconds = 5;
  constexpr bool kLowLatencyScan = true;
  constexpr bool kHighLatencyScan = false;

  bta_dm_ble_scan(kStartLeScan, duration_in_seconds, kLowLatencyScan);
  bta_dm_ble_scan(kStopLeScan, duration_in_seconds, kLowLatencyScan);

  bta_dm_ble_scan(kStartLeScan, duration_in_seconds, kHighLatencyScan);
  bta_dm_ble_scan(kStopLeScan, duration_in_seconds, kHighLatencyScan);
}

TEST_F(BtaDiscTest, bta_dm_disc_discover_next_device) {
  bta_dm_disc_discover_next_device();
}

TEST_F(BtaDiscTest, bta_dm_disc_remove_device) {
  bta_dm_disc_remove_device(kRawAddress);
}

TEST_F(BtaDiscTest, bta_dm_discover_next_device) {
  bluetooth::legacy::testing::bta_dm_discover_next_device();
}

TEST_F(BtaDiscTest, bta_dm_execute_queued_request) {
  bluetooth::legacy::testing::bta_dm_execute_queued_request();
}

TEST_F(BtaDiscTest, bta_dm_find_services) {
  bluetooth::legacy::testing::bta_dm_find_services(kRawAddress);
}

TEST_F(BtaDiscTest, bta_dm_inq_cmpl) {
  bluetooth::legacy::testing::bta_dm_inq_cmpl(0);
  bluetooth::legacy::testing::bta_dm_inq_cmpl(1);
  bluetooth::legacy::testing::bta_dm_inq_cmpl(2);
  bluetooth::legacy::testing::bta_dm_inq_cmpl(255);
}

TEST_F(BtaDiscTest, bta_dm_inq_cmpl_cb) {
  tBTM_INQUIRY_CMPL complete;
  bluetooth::legacy::testing::bta_dm_inq_cmpl_cb(&complete);
}

TEST_F(BtaDiscTest, bta_dm_observe_cmpl_cb) {
  tBTM_INQUIRY_CMPL complete;
  bluetooth::legacy::testing::bta_dm_observe_cmpl_cb(&complete);
}
TEST_F(BtaDiscTest, bta_dm_observe_results_cb) {
  tBTM_INQ_RESULTS result;
  const uint8_t p_eir[] = {0x0, 0x1, 0x2, 0x3};
  uint16_t eir_len = sizeof(p_eir);
  bluetooth::legacy::testing::bta_dm_observe_results_cb(&result, p_eir,
                                                        eir_len);
}

TEST_F(BtaDiscTest, bta_dm_opportunistic_observe_results_cb) {
  tBTM_INQ_RESULTS result;
  const uint8_t p_eir[] = {0x0, 0x1, 0x2, 0x3};
  uint16_t eir_len = sizeof(p_eir);
  bluetooth::legacy::testing::bta_dm_opportunistic_observe_results_cb(
      &result, p_eir, eir_len);
}

TEST_F(BtaDiscTest, bta_dm_queue_search) {
  tBTA_DM_MSG msg = {
      .search = {},
  };
  bluetooth::legacy::testing::bta_dm_queue_search(&msg);

  // Release the queued search
  osi_free_and_reset((void**)&bta_dm_search_cb.p_pending_search);
}

TEST_F(BtaDiscTest, bta_dm_read_remote_device_name) {
  bluetooth::legacy::testing::bta_dm_read_remote_device_name(
      kRawAddress, BT_TRANSPORT_BR_EDR);
}

TEST_F(BtaDiscTest, DISABLED_bta_dm_search_result) {  // b/309463889
  tBTA_DM_MSG msg = {
      .disc_result = {},
  };
  bluetooth::legacy::testing::bta_dm_search_result(&msg);
}

TEST_F(BtaDiscTest, bta_dm_search_sm_execute) {
  BT_HDR_RIGID bt_hdr = {};
  bta_dm_search_sm_execute(&bt_hdr);
}

TEST_F(BtaDiscTest, bta_dm_search_timer_cback) {
  constexpr void* kUnusedPointer = nullptr;
  bluetooth::legacy::testing::bta_dm_search_timer_cback(kUnusedPointer);
}

TEST_F(BtaDiscTest, bta_dm_service_search_remname_cback__expected_name) {
  DEV_CLASS dc;
  tBTM_BD_NAME bd_name;
  bta_dm_search_cb.peer_bdaddr = kRawAddress;
  bluetooth::legacy::testing::bta_dm_service_search_remname_cback(kRawAddress,
                                                                  dc, bd_name);
}

TEST_F(BtaDiscTest, bta_dm_service_search_remname_cback__unexpected_name) {
  DEV_CLASS dc;
  tBTM_BD_NAME bd_name;
  bta_dm_search_cb.peer_bdaddr = RawAddress::kAny;
  bluetooth::legacy::testing::bta_dm_service_search_remname_cback(kRawAddress,
                                                                  dc, bd_name);
}

TEST_F(BtaDiscTest, bta_dm_start_scan) {
  constexpr bool kLowLatencyScan = true;
  constexpr bool kHighLatencyScan = false;
  const uint8_t duration_sec = 5;
  bluetooth::legacy::testing::bta_dm_start_scan(duration_sec, kLowLatencyScan);
  bluetooth::legacy::testing::bta_dm_start_scan(duration_sec, kHighLatencyScan);
}

TEST_F(BtaDiscTest, store_avrcp_profile_feature) {
  tSDP_DISC_REC sdp_rec = {};
  bluetooth::legacy::testing::store_avrcp_profile_feature(&sdp_rec);
}
