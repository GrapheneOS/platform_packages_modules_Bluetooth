/*
 * Copyright 2022 The Android Open Source Project
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
#include <frameworks/proto_logging/stats/enums/bluetooth/enums.pb.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <stdlib.h>
#include <vector>

#include <cstddef>
#include <cstdint>

#include "bta/ag/bta_ag_int.h"
#include "bta/sys/bta_sys.h"
#include "include/macros.h"
#include "osi/include/allocator.h"
#include "stack/include/bt_uuid16.h"
#include "stack/include/bt_types.h"
#include "stack/include/sdp_api.h"
#include "stack/include/sdpdefs.h"
#include "stack/mock/mock_stack_l2cap_interface.h"
#include "stack/sdp/internal/sdp_api.h"
#include "stack/sdp/sdpint.h"
#include "test/fake/fake_osi.h"
#include "test/mock/mock_osi_allocator.h"

#ifndef BT_DEFAULT_BUFFER_SIZE
#define BT_DEFAULT_BUFFER_SIZE (4096 + 16)
#endif

using ::testing::_;
using ::testing::DoAll;
using ::testing::Invoke;
using ::testing::NotNull;
using ::testing::Pointee;
using ::testing::Return;
using ::testing::ReturnArg;
using ::testing::SaveArg;
using ::testing::SaveArgPointee;
using ::testing::StrEq;
using ::testing::StrictMock;
using ::testing::Test;

// TODO: remove dependency on BTA symbols.
bool bta_ag_get_swb_supported() { return false; }
void bta_sys_add_uuid(uint16_t) {}

namespace {
constexpr uint8_t kSDP_MAX_CONNECTIONS = static_cast<uint8_t>(SDP_MAX_CONNECTIONS);

RawAddress addr = RawAddress("A1:A2:A3:A4:A5:A6");
int L2CA_ConnectReqWithSecurity_cid = 42;
tSDP_DISCOVERY_DB* sdp_db = nullptr;

class StackSdpWithMocksTest : public ::testing::Test {
protected:
  void SetUp() override {
    fake_osi_ = std::make_unique<test::fake::FakeOsi>();
    bluetooth::testing::stack::l2cap::set_interface(&mock_stack_l2cap_interface_);

    EXPECT_CALL(mock_stack_l2cap_interface_, L2CA_RegisterWithSecurity(_, _, _, _, _, _, _))
            .WillOnce(DoAll(SaveArg<1>(&l2cap_callbacks), ::testing::ReturnArg<0>()));
    EXPECT_CALL(mock_stack_l2cap_interface_, L2CA_Deregister(_));
  }

  void TearDown() override {
    bluetooth::testing::stack::l2cap::reset_interface();
    fake_osi_.reset();
  }

  tL2CAP_APPL_INFO l2cap_callbacks{};
  bluetooth::testing::stack::l2cap::Mock mock_stack_l2cap_interface_;
  std::unique_ptr<test::fake::FakeOsi> fake_osi_;
};

class StackSdpInitTest : public StackSdpWithMocksTest {
protected:
  void SetUp() override {
    StackSdpWithMocksTest::SetUp();
    sdp_init();
    sdp_db = (tSDP_DISCOVERY_DB*)osi_malloc(BT_DEFAULT_BUFFER_SIZE);
  }

  void TearDown() override {
    osi_free(sdp_db);
    sdp_free();
    StackSdpWithMocksTest::TearDown();
  }
};

}  // namespace

TEST_F(StackSdpInitTest, nop) {}

TEST_F(StackSdpInitTest, sdp_service_search_request) {
  EXPECT_CALL(mock_stack_l2cap_interface_, L2CA_ConnectReqWithSecurity(_, _, _))
          .WillOnce(Invoke([](uint16_t /* psm */, const RawAddress& /* p_bd_addr */,
                              uint16_t /* sec_level */) -> uint16_t {
            return L2CA_ConnectReqWithSecurity_cid;
          }));
  EXPECT_CALL(mock_stack_l2cap_interface_, L2CA_DisconnectReq(_)).WillOnce(Return(true));

  EXPECT_CALL(mock_stack_l2cap_interface_, L2CA_DataWrite(_, _))
          .WillOnce(Invoke([](uint16_t /* cid */, BT_HDR* p_data) -> tL2CAP_DW_RESULT {
            osi_free_and_reset((void**)&p_data);
            return tL2CAP_DW_RESULT::SUCCESS;
          }));

  ASSERT_TRUE(SDP_ServiceSearchRequest(addr, sdp_db, nullptr));
  int cid = L2CA_ConnectReqWithSecurity_cid;
  tCONN_CB* p_ccb = sdpu_find_ccb_by_cid(cid);
  ASSERT_NE(p_ccb, nullptr);
  ASSERT_EQ(p_ccb->con_state, tSDP_STATE::CONN_SETUP);

  tL2CAP_CFG_INFO cfg;
  sdp_cb.reg_info.pL2CA_ConfigCfm_Cb(p_ccb->connection_id, 0, &cfg);

  ASSERT_EQ(p_ccb->con_state, tSDP_STATE::CONNECTED);

  sdp_disconnect(p_ccb, tSDP_STATUS::SDP_SUCCESS);
  sdp_cb.reg_info.pL2CA_DisconnectCfm_Cb(p_ccb->connection_id, 0);

  ASSERT_EQ(p_ccb->con_state, tSDP_STATE::IDLE);
}

static tCONN_CB* find_ccb(uint16_t cid, tSDP_STATE state) {
  uint16_t xx;
  tCONN_CB* p_ccb;

  // Look through each connection control block
  for (xx = 0, p_ccb = sdp_cb.ccb; xx < SDP_MAX_CONNECTIONS; xx++, p_ccb++) {
    if ((p_ccb->con_state == state) && (p_ccb->connection_id == cid)) {
      return p_ccb;
    }
  }
  return nullptr;  // not found
}

TEST_F(StackSdpInitTest, sdp_service_search_request_queuing) {
  EXPECT_CALL(mock_stack_l2cap_interface_, L2CA_ConnectReqWithSecurity(_, _, _))
          .WillOnce(Invoke([](uint16_t /* psm */, const RawAddress& /* p_bd_addr */,
                              uint16_t /* sec_level */) -> uint16_t {
            return L2CA_ConnectReqWithSecurity_cid;
          }));
  EXPECT_CALL(mock_stack_l2cap_interface_, L2CA_DataWrite(_, _))
          .WillRepeatedly(Invoke([](uint16_t /* cid */, BT_HDR* data) -> tL2CAP_DW_RESULT {
            osi_free(data);
            return tL2CAP_DW_RESULT::SUCCESS;
          }));

  EXPECT_CALL(mock_stack_l2cap_interface_, L2CA_DisconnectReq(_)).WillOnce(Return(true));

  ASSERT_TRUE(SDP_ServiceSearchRequest(addr, sdp_db, nullptr));
  const int cid = L2CA_ConnectReqWithSecurity_cid;
  tCONN_CB* p_ccb1 = find_ccb(cid, tSDP_STATE::CONN_SETUP);
  ASSERT_NE(p_ccb1, nullptr);
  ASSERT_EQ(p_ccb1->con_state, tSDP_STATE::CONN_SETUP);

  ASSERT_TRUE(SDP_ServiceSearchRequest(addr, sdp_db, nullptr));
  tCONN_CB* p_ccb2 = find_ccb(cid, tSDP_STATE::CONN_PEND);
  ASSERT_NE(p_ccb2, nullptr);
  ASSERT_NE(p_ccb2, p_ccb1);
  ASSERT_EQ(p_ccb2->con_state, tSDP_STATE::CONN_PEND);

  tL2CAP_CFG_INFO cfg;
  sdp_cb.reg_info.pL2CA_ConfigCfm_Cb(p_ccb1->connection_id, 0, &cfg);

  ASSERT_EQ(p_ccb1->con_state, tSDP_STATE::CONNECTED);
  ASSERT_EQ(p_ccb2->con_state, tSDP_STATE::CONN_PEND);

  p_ccb1->disconnect_reason = tSDP_STATUS::SDP_SUCCESS;
  sdp_disconnect(p_ccb1, tSDP_STATUS::SDP_SUCCESS);

  ASSERT_EQ(p_ccb1->con_state, tSDP_STATE::IDLE);
  ASSERT_EQ(p_ccb2->con_state, tSDP_STATE::CONNECTED);

  sdp_disconnect(p_ccb2, tSDP_STATUS::SDP_SUCCESS);
  sdp_cb.reg_info.pL2CA_DisconnectCfm_Cb(p_ccb2->connection_id, 0);

  ASSERT_EQ(p_ccb1->con_state, tSDP_STATE::IDLE);
  ASSERT_EQ(p_ccb2->con_state, tSDP_STATE::IDLE);
}

static void sdp_callback(const RawAddress& /* bd_addr */, tSDP_RESULT result) {
  if (result == tSDP_STATUS::SDP_SUCCESS) {
    ASSERT_TRUE(SDP_ServiceSearchRequest(addr, sdp_db, nullptr));
  }
}

TEST_F(StackSdpInitTest, sdp_service_search_request_queuing_race_condition) {
  uint16_t cid = L2CA_ConnectReqWithSecurity_cid;
  EXPECT_CALL(mock_stack_l2cap_interface_, L2CA_ConnectReqWithSecurity(_, _, _))
          .WillRepeatedly(Invoke([&cid](uint16_t /* psm */, const RawAddress& /* p_bd_addr */,
                                        uint16_t /* sec_level */) -> uint16_t { return cid++; }));
  EXPECT_CALL(mock_stack_l2cap_interface_, L2CA_DisconnectReq(_)).WillRepeatedly(Return(true));

  EXPECT_CALL(mock_stack_l2cap_interface_, L2CA_DataWrite(_, _))
          .WillOnce(Invoke([](uint16_t /* cid */, BT_HDR* p_data) -> tL2CAP_DW_RESULT {
            osi_free_and_reset((void**)&p_data);
            return tL2CAP_DW_RESULT::SUCCESS;
          }));

  // start first request
  ASSERT_TRUE(SDP_ServiceSearchRequest(addr, sdp_db, sdp_callback));
  const uint16_t cid1 = L2CA_ConnectReqWithSecurity_cid;
  tCONN_CB* p_ccb1 = find_ccb(cid1, tSDP_STATE::CONN_SETUP);
  ASSERT_NE(p_ccb1, nullptr);
  ASSERT_EQ(p_ccb1->con_state, tSDP_STATE::CONN_SETUP);

  tL2CAP_CFG_INFO cfg;
  sdp_cb.reg_info.pL2CA_ConfigCfm_Cb(p_ccb1->connection_id, 0, &cfg);

  ASSERT_EQ(p_ccb1->con_state, tSDP_STATE::CONNECTED);

  sdp_disconnect(p_ccb1, tSDP_STATUS::SDP_SUCCESS);
  sdp_cb.reg_info.pL2CA_DisconnectCfm_Cb(p_ccb1->connection_id, 0);

  const uint16_t cid2 = L2CA_ConnectReqWithSecurity_cid + 1;
  ASSERT_NE(cid1, cid2);  // The callback a queued a new request
  tCONN_CB* p_ccb2 = find_ccb(cid2, tSDP_STATE::CONN_SETUP);
  ASSERT_NE(p_ccb2, nullptr);
  // If race condition, this will be stuck in PEND
  ASSERT_EQ(p_ccb2->con_state, tSDP_STATE::CONN_SETUP);

  sdp_disconnect(p_ccb2, tSDP_STATUS::SDP_SUCCESS);
}

TEST_F(StackSdpInitTest, sdp_disc_wait_text) {
  std::vector<std::pair<tSDP_DISC_WAIT, std::string>> states = {
          std::make_pair(SDP_DISC_WAIT_CONN, "SDP_DISC_WAIT_CONN"),
          std::make_pair(SDP_DISC_WAIT_HANDLES, "SDP_DISC_WAIT_HANDLES"),
          std::make_pair(SDP_DISC_WAIT_ATTR, "SDP_DISC_WAIT_ATTR"),
          std::make_pair(SDP_DISC_WAIT_SEARCH_ATTR, "SDP_DISC_WAIT_SEARCH_ATTR"),
          std::make_pair(SDP_DISC_WAIT_CANCEL, "SDP_DISC_WAIT_CANCEL"),
  };
  for (const auto& state : states) {
    ASSERT_STREQ(state.second.c_str(), sdp_disc_wait_text(state.first).c_str());
  }
  auto unknown = std::format("UNKNOWN[{}]", std::numeric_limits<uint8_t>::max());
  ASSERT_STREQ(unknown.c_str(),
               sdp_disc_wait_text(static_cast<tSDP_DISC_WAIT>(std::numeric_limits<uint8_t>::max()))
                       .c_str());
}

TEST_F(StackSdpInitTest, sdp_state_text) {
  std::vector<std::pair<tSDP_STATE, std::string>> states = {
          std::make_pair(tSDP_STATE::IDLE, "tSDP_STATE::IDLE(0x0)"),
          std::make_pair(tSDP_STATE::CONN_SETUP, "tSDP_STATE::CONN_SETUP(0x1)"),
          std::make_pair(tSDP_STATE::CFG_SETUP, "tSDP_STATE::CFG_SETUP(0x2)"),
          std::make_pair(tSDP_STATE::CONNECTED, "tSDP_STATE::CONNECTED(0x3)"),
          std::make_pair(tSDP_STATE::CONN_PEND, "tSDP_STATE::CONN_PEND(0x4)"),
  };
  for (const auto& state : states) {
    ASSERT_STREQ(state.second.c_str(), sdp_state_text(state.first).c_str());
  }
  auto unknown = []() {
    RETURN_UNKNOWN_TYPE_STRING(tSDP_STATE, std::numeric_limits<std::uint8_t>::max());
  }();
  ASSERT_STREQ(unknown.c_str(),
               sdp_state_text(static_cast<tSDP_STATE>(std::numeric_limits<std::uint8_t>::max()))
                       .c_str());
}

TEST_F(StackSdpInitTest, sdp_flags_text) {
  std::vector<std::pair<tSDP_DISC_WAIT, std::string>> flags = {
          std::make_pair(SDP_FLAGS_IS_ORIG, "SDP_FLAGS_IS_ORIG"),
          std::make_pair(SDP_FLAGS_HIS_CFG_DONE, "SDP_FLAGS_HIS_CFG_DONE"),
          std::make_pair(SDP_FLAGS_MY_CFG_DONE, "SDP_FLAGS_MY_CFG_DONE"),
  };
  for (const auto& flag : flags) {
    ASSERT_STREQ(flag.second.c_str(), sdp_flags_text(flag.first).c_str());
  }
  auto unknown = std::format("UNKNOWN[{}]", std::numeric_limits<uint8_t>::max());
  ASSERT_STREQ(
          unknown.c_str(),
          sdp_flags_text(static_cast<tSDP_DISC_WAIT>(std::numeric_limits<uint8_t>::max())).c_str());
}

TEST_F(StackSdpInitTest, sdp_status_text) {
  std::vector<std::pair<tSDP_STATUS, std::string>> status = {
          std::make_pair(tSDP_STATUS::SDP_SUCCESS, "tSDP_STATUS::SDP_SUCCESS"),
          std::make_pair(tSDP_STATUS::SDP_INVALID_VERSION, "tSDP_STATUS::SDP_INVALID_VERSION"),
          std::make_pair(tSDP_STATUS::SDP_INVALID_SERV_REC_HDL,
                         "tSDP_STATUS::SDP_INVALID_SERV_REC_HDL"),
          std::make_pair(tSDP_STATUS::SDP_INVALID_REQ_SYNTAX,
                         "tSDP_STATUS::SDP_INVALID_REQ_SYNTAX"),
          std::make_pair(tSDP_STATUS::SDP_INVALID_PDU_SIZE, "tSDP_STATUS::SDP_INVALID_PDU_SIZE"),
          std::make_pair(tSDP_STATUS::SDP_INVALID_CONT_STATE,
                         "tSDP_STATUS::SDP_INVALID_CONT_STATE"),
          std::make_pair(tSDP_STATUS::SDP_NO_RESOURCES, "tSDP_STATUS::SDP_NO_RESOURCES"),
          std::make_pair(tSDP_STATUS::SDP_DI_REG_FAILED, "tSDP_STATUS::SDP_DI_REG_FAILED"),
          std::make_pair(tSDP_STATUS::SDP_DI_DISC_FAILED, "tSDP_STATUS::SDP_DI_DISC_FAILED"),
          std::make_pair(tSDP_STATUS::SDP_NO_DI_RECORD_FOUND,
                         "tSDP_STATUS::SDP_NO_DI_RECORD_FOUND"),
          std::make_pair(tSDP_STATUS::SDP_ERR_ATTR_NOT_PRESENT,
                         "tSDP_STATUS::SDP_ERR_ATTR_NOT_PRESENT"),
          std::make_pair(tSDP_STATUS::SDP_ILLEGAL_PARAMETER, "tSDP_STATUS::SDP_ILLEGAL_PARAMETER"),
          std::make_pair(tSDP_STATUS::HID_SDP_NO_SERV_UUID, "tSDP_STATUS::HID_SDP_NO_SERV_UUID"),
          std::make_pair(tSDP_STATUS::HID_SDP_MANDATORY_MISSING,
                         "tSDP_STATUS::HID_SDP_MANDATORY_MISSING"),
          std::make_pair(tSDP_STATUS::SDP_NO_RECS_MATCH, "tSDP_STATUS::SDP_NO_RECS_MATCH"),
          std::make_pair(tSDP_STATUS::SDP_CONN_FAILED, "tSDP_STATUS::SDP_CONN_FAILED"),
          std::make_pair(tSDP_STATUS::SDP_CFG_FAILED, "tSDP_STATUS::SDP_CFG_FAILED"),
          std::make_pair(tSDP_STATUS::SDP_GENERIC_ERROR, "tSDP_STATUS::SDP_GENERIC_ERROR"),
          std::make_pair(tSDP_STATUS::SDP_DB_FULL, "tSDP_STATUS::SDP_DB_FULL"),
          std::make_pair(tSDP_STATUS::SDP_CANCEL, "tSDP_STATUS::SDP_CANCEL"),
  };
  for (const auto& stat : status) {
    ASSERT_STREQ(stat.second.c_str(), sdp_status_text(stat.first).c_str());
  }
  auto unknown = std::format("UNKNOWN[{}]", std::numeric_limits<uint16_t>::max());
  ASSERT_STREQ(
          unknown.c_str(),
          sdp_status_text(static_cast<tSDP_STATUS>(std::numeric_limits<uint16_t>::max())).c_str());
}

static tSDP_DISCOVERY_DB db{};
static tSDP_DISC_REC rec{};
static tSDP_DISC_ATTR uuid_desc_attr{};
static tSDP_DISC_ATTR client_exe_url_attr{};
static tSDP_DISC_ATTR service_desc_attr{};
static tSDP_DISC_ATTR doc_url_desc_attr{};
static tSDP_DISC_ATTR spec_id_attr{};
static tSDP_DISC_ATTR vendor_id_attr{};
static tSDP_DISC_ATTR vendor_id_src_attr{};
static tSDP_DISC_ATTR prod_id_attr{};
static tSDP_DISC_ATTR prod_version_attr{};
static tSDP_DISC_ATTR primary_rec_attr{};

class SDP_GetDiRecord_Tests : public ::testing::Test {
protected:
  void SetUp() override {
    db.p_first_rec = &rec;
    rec.p_first_attr = &uuid_desc_attr;

    uuid_desc_attr.attr_id = ATTR_ID_SERVICE_ID;
    uuid_desc_attr.p_next_attr = &client_exe_url_attr;

    client_exe_url_attr.attr_id = ATTR_ID_CLIENT_EXE_URL;
    client_exe_url_attr.p_next_attr = &service_desc_attr;

    service_desc_attr.attr_id = ATTR_ID_SERVICE_DESCRIPTION;
    service_desc_attr.p_next_attr = &doc_url_desc_attr;

    doc_url_desc_attr.attr_id = ATTR_ID_DOCUMENTATION_URL;
    doc_url_desc_attr.p_next_attr = &spec_id_attr;

    spec_id_attr.attr_id = ATTR_ID_SPECIFICATION_ID;
    spec_id_attr.p_next_attr = &vendor_id_attr;

    vendor_id_attr.attr_id = ATTR_ID_VENDOR_ID;
    vendor_id_attr.p_next_attr = &vendor_id_src_attr;

    vendor_id_src_attr.attr_id = ATTR_ID_VENDOR_ID_SOURCE;
    vendor_id_src_attr.p_next_attr = &prod_id_attr;

    prod_id_attr.attr_id = ATTR_ID_PRODUCT_ID;
    prod_id_attr.p_next_attr = &prod_version_attr;

    prod_version_attr.attr_id = ATTR_ID_PRODUCT_VERSION;
    prod_version_attr.p_next_attr = &primary_rec_attr;

    primary_rec_attr.attr_id = ATTR_ID_PRIMARY_RECORD;
    primary_rec_attr.p_next_attr = nullptr;
  }

  void TearDown() override {
    db = {};
    rec = {};
    uuid_desc_attr = {};
    client_exe_url_attr = {};
    service_desc_attr = {};
    doc_url_desc_attr = {};
    spec_id_attr = {};
    vendor_id_attr = {};
    vendor_id_src_attr = {};
    prod_id_attr = {};
    prod_version_attr = {};
    primary_rec_attr = {};
  }
};

// regression test for b/297831980 and others
TEST_F(SDP_GetDiRecord_Tests, SDP_GetDiRecord_Regression_test0) {
  // tune the type/len and value of each attribute in
  // each test
  uuid_desc_attr.attr_len_type = (UUID_DESC_TYPE << 12) | 2;
  uuid_desc_attr.attr_value.v.u16 = UUID_SERVCLASS_PNP_INFORMATION;

  // use a 2-byte string so that it can be
  // saved in tSDP_DISC_ATVAL
  const char* const text = "AB";
  int len = strlen(text);
  client_exe_url_attr.attr_len_type = (URL_DESC_TYPE << 12) | len;
  memcpy(client_exe_url_attr.attr_value.v.array, text, len);

  // make this attr not found by id
  service_desc_attr.attr_id = ATTR_ID_SERVICE_DESCRIPTION + 1;
  service_desc_attr.attr_len_type = (TEXT_STR_DESC_TYPE << 12) | len;
  memcpy(service_desc_attr.attr_value.v.array, text, len);

  // make a wrong type
  doc_url_desc_attr.attr_len_type = (TEXT_STR_DESC_TYPE << 12) | len;
  memcpy(doc_url_desc_attr.attr_value.v.array, text, len);

  // setup unexpected sizes for the following attrs
  spec_id_attr.attr_len_type = (UINT_DESC_TYPE << 12) | 1;
  spec_id_attr.attr_value.v.u16 = 0x1111;

  vendor_id_attr.attr_len_type = (UINT_DESC_TYPE << 12) | 1;
  vendor_id_attr.attr_value.v.u16 = 0x2222;

  vendor_id_src_attr.attr_len_type = (UINT_DESC_TYPE << 12) | 1;
  vendor_id_src_attr.attr_value.v.u16 = 0x3333;

  prod_id_attr.attr_len_type = (UINT_DESC_TYPE << 12) | 1;
  prod_id_attr.attr_value.v.u16 = 0x4444;

  prod_version_attr.attr_len_type = (UINT_DESC_TYPE << 12) | 1;
  prod_version_attr.attr_value.v.u16 = 0x5555;

  // setup wrong size for primary_rec_attr
  primary_rec_attr.attr_len_type = (BOOLEAN_DESC_TYPE << 12) | 0;
  primary_rec_attr.attr_value.v.u8 = 0x66;

  tSDP_DI_GET_RECORD device_info{};

  SDP_GetDiRecord(1, &device_info, &db);

  ASSERT_STREQ(text, device_info.rec.client_executable_url);

  // service description could not be found
  ASSERT_EQ(strlen(device_info.rec.service_description), (size_t)0);

  // with a wrong attr type, the attr value won't be accepted
  ASSERT_EQ(strlen(device_info.rec.documentation_url), (size_t)0);

  // none of the following values got setup
  ASSERT_EQ(device_info.spec_id, 0);
  ASSERT_EQ(device_info.rec.vendor, 0);
  ASSERT_EQ(device_info.rec.vendor_id_source, 0);
  ASSERT_EQ(device_info.rec.product, 0);
  ASSERT_EQ(device_info.rec.version, 0);
  ASSERT_FALSE(device_info.rec.primary_record);
}

TEST_F(StackSdpInitTest, sdpu_dump_all_ccb) {
  uint16_t cid = L2CA_ConnectReqWithSecurity_cid;
  EXPECT_CALL(mock_stack_l2cap_interface_, L2CA_ConnectReqWithSecurity(_, _, _))
          .WillRepeatedly(Invoke([&cid](uint16_t /* psm */, const RawAddress& /* p_bd_addr */,
                                        uint16_t /* sec_level */) -> uint16_t { return cid++; }));
  sdpu_dump_all_ccb();

  for (uint8_t i = 0; i < kSDP_MAX_CONNECTIONS; i++) {
    RawAddress bd_addr = RawAddress(std::array<uint8_t, 6>({0x11, 0x22, 0x33, 0x44, 0x55, i}));
    ASSERT_NE(nullptr, sdp_conn_originate(bd_addr));
  }
  RawAddress bd_addr_fail = RawAddress("11:22:33:44:55:ff");
  ASSERT_EQ(nullptr, sdp_conn_originate(bd_addr_fail));

  sdpu_dump_all_ccb();
}

TEST_F(StackSdpInitTest, SDP_Dumpsys) { SDP_Dumpsys(1); }

TEST_F(StackSdpInitTest, SDP_Dumpsys_ccb) {
  uint16_t cid = L2CA_ConnectReqWithSecurity_cid;
  EXPECT_CALL(mock_stack_l2cap_interface_, L2CA_ConnectReqWithSecurity(_, _, _))
          .WillRepeatedly(Invoke([&cid](uint16_t /* psm */, const RawAddress& /* p_bd_addr */,
                                        uint16_t /* sec_level */) -> uint16_t { return cid++; }));

  for (uint8_t i = 0; i < kSDP_MAX_CONNECTIONS; i++) {
    RawAddress bd_addr = RawAddress(std::array<uint8_t, 6>({0x11, 0x22, 0x33, 0x44, 0x55, i}));
    ASSERT_NE(nullptr, sdp_conn_originate(bd_addr));
  }
  RawAddress bd_addr_fail = RawAddress("11:22:33:44:55:ff");
  ASSERT_EQ(nullptr, sdp_conn_originate(bd_addr_fail));

  SDP_Dumpsys(1);
}

TEST_F(StackSdpInitTest, sdp_cancel_pending_conn) {
  EXPECT_CALL(mock_stack_l2cap_interface_, L2CA_ConnectReqWithSecurity(_, _, _))
          .WillOnce(Invoke([](uint16_t /* psm */, const RawAddress& /* p_bd_addr */,
                              uint16_t /* sec_level */) -> uint16_t {
            return L2CA_ConnectReqWithSecurity_cid;
          }));
  EXPECT_CALL(mock_stack_l2cap_interface_, L2CA_DisconnectReq(_)).WillOnce(Return(true));

  ASSERT_TRUE(SDP_ServiceSearchRequest(addr, sdp_db, nullptr));
  const int cid = L2CA_ConnectReqWithSecurity_cid;
  tCONN_CB* p_ccb1 = find_ccb(cid, tSDP_STATE::CONN_SETUP);
  ASSERT_NE(p_ccb1, nullptr);
  ASSERT_EQ(p_ccb1->con_state, tSDP_STATE::CONN_SETUP);

  ASSERT_TRUE(SDP_ServiceSearchRequest(addr, sdp_db, nullptr));
  tCONN_CB* p_ccb2 = find_ccb(cid, tSDP_STATE::CONN_PEND);
  ASSERT_NE(p_ccb2, nullptr);
  ASSERT_NE(p_ccb2, p_ccb1);
  ASSERT_EQ(p_ccb2->con_state, tSDP_STATE::CONN_PEND);

  // Cancel CCB that is pending connection, expect both CCBs to be idle
  sdp_disconnect(p_ccb2, tSDP_STATUS::SDP_CANCEL);
  ASSERT_EQ(p_ccb1->con_state, tSDP_STATE::IDLE);
  ASSERT_EQ(p_ccb2->con_state, tSDP_STATE::IDLE);
}

TEST_F(StackSdpInitTest, write_read_max_attr_len_slicing) {
  uint32_t handle = SDP_CreateRecord();
  ASSERT_NE(handle, 0u);

  // Write max size attribute payload into DB
  std::vector<uint8_t> val(SDP_MAX_ATTR_LEN, 'A');
  ASSERT_TRUE(SDP_AddAttribute(handle, 0x1234, TEXT_STR_DESC_TYPE, val.size(), val.data()));

  // Prepare Server CCB
  tCONN_CB* p_ccb = sdpu_allocate_ccb();
  ASSERT_NE(p_ccb, nullptr);
  p_ccb->con_state = tSDP_STATE::CONNECTED;
  p_ccb->connection_id = L2CA_ConnectReqWithSecurity_cid;
  p_ccb->rem_mtu_size = 512;

  std::vector<uint8_t> accumulated_attr_list;
  bool hit_continuation = false;
  uint16_t cont_offset = 0;

  for (int i = 0; i < 50; ++i) { // max 50 chunks safety limit
    // Allocate request msg buffer
    BT_HDR* p_req_msg = (BT_HDR*)osi_malloc(SDP_DATA_BUF_SIZE);
    p_req_msg->offset = L2CAP_MIN_OFFSET;
    uint8_t* p_req = (uint8_t*)(p_req_msg + 1) + L2CAP_MIN_OFFSET;

    // Build SDP request header
    UINT8_TO_BE_STREAM(p_req, SDP_PDU_SERVICE_ATTR_REQ);
    UINT16_TO_BE_STREAM(p_req, 1); // trans_num = 1

    // Skip param_len for now
    uint8_t* p_param_len = p_req;
    p_req += 2;

    uint8_t* p_param_start = p_req;

    UINT32_TO_BE_STREAM(p_req, handle);
    UINT16_TO_BE_STREAM(p_req, 50); // max_list_len = 50 to force slicing

    // Attribute ID list containing 0x1234
    UINT8_TO_BE_STREAM(p_req, 0x35); // DATA_ELE_SEQ_DESC_TYPE, next byte len
    UINT8_TO_BE_STREAM(p_req, 0x03); // sequence length
    UINT8_TO_BE_STREAM(p_req, 0x09); // UINT, 2 bytes
    UINT16_TO_BE_STREAM(p_req, 0x1234); // attribute ID

    // Continuation state
    if (hit_continuation) {
      UINT8_TO_BE_STREAM(p_req, 2);
      UINT16_TO_BE_STREAM(p_req, cont_offset);
    } else {
      UINT8_TO_BE_STREAM(p_req, 0);
    }

    uint16_t param_len = p_req - p_param_start;
    p_req = p_param_len;
    UINT16_TO_BE_STREAM(p_req, param_len);

    p_req_msg->len = (p_param_start - (uint8_t*)p_req_msg) + param_len -
                     sizeof(BT_HDR) - L2CAP_MIN_OFFSET;

    BT_HDR* p_rsp_msg = nullptr;
    EXPECT_CALL(mock_stack_l2cap_interface_, L2CA_DataWrite(_, _))
            .WillOnce(Invoke([&p_rsp_msg](uint16_t /* cid */, BT_HDR* p_data) -> tL2CAP_DW_RESULT {
              p_rsp_msg = p_data;
              return tL2CAP_DW_RESULT::SUCCESS;
            }));

    sdp_server_handle_client_req(p_ccb, p_req_msg);
    osi_free(p_req_msg);

    ASSERT_NE(p_rsp_msg, nullptr);
    uint8_t* p_rsp = (uint8_t*)(p_rsp_msg + 1) + p_rsp_msg->offset;
    uint8_t pdu_id;
    BE_STREAM_TO_UINT8(pdu_id, p_rsp);

    ASSERT_EQ(pdu_id, SDP_PDU_SERVICE_ATTR_RSP);

    uint16_t rsp_trans_num, rsp_param_len;
    BE_STREAM_TO_UINT16(rsp_trans_num, p_rsp);
    BE_STREAM_TO_UINT16(rsp_param_len, p_rsp);

    uint16_t attr_list_bytes;
    BE_STREAM_TO_UINT16(attr_list_bytes, p_rsp);

    accumulated_attr_list.insert(accumulated_attr_list.end(), p_rsp, p_rsp + attr_list_bytes);
    p_rsp += attr_list_bytes;

    uint8_t rsp_cont_len;
    BE_STREAM_TO_UINT8(rsp_cont_len, p_rsp);
    if (rsp_cont_len == 2) {
      hit_continuation = true;
      BE_STREAM_TO_UINT16(cont_offset, p_rsp);
    } else {
      hit_continuation = false;
    }

    osi_free(p_rsp_msg);

    if (!hit_continuation) {
      break;
    }
  }

  ASSERT_FALSE(hit_continuation);

  // Verification
  ASSERT_GE(accumulated_attr_list.size(), 3u + 3u + 400u);

  uint8_t* p_acc = accumulated_attr_list.data();
  uint8_t seq_descr;
  BE_STREAM_TO_UINT8(seq_descr, p_acc);
  // 0x36: DATA_ELE_SEQ_DESC_TYPE | SIZE_IN_NEXT_WORD ((6 << 3) | 6)
  ASSERT_EQ(seq_descr, 0x36);
  uint16_t seq_len;
  BE_STREAM_TO_UINT16(seq_len, p_acc);
  // Total sequence nested length: 3 (Attr ID element) + 3 (string val header) +
  // 400 (payload) = 406
  ASSERT_EQ(seq_len, 406);

  uint8_t id_descr;
  BE_STREAM_TO_UINT8(id_descr, p_acc);
  // 0x09: UINT_DESC_TYPE | SIZE_TWO_BYTES ((1 << 3) | 1)
  ASSERT_EQ(id_descr, 0x09);
  uint16_t returned_id;
  BE_STREAM_TO_UINT16(returned_id, p_acc);
  // Check the element returned has attribute ID 0x1234
  ASSERT_EQ(returned_id, 0x1234);

  uint8_t val_descr;
  BE_STREAM_TO_UINT8(val_descr, p_acc);
  // 0x26: TEXT_STR_DESC_TYPE | SIZE_IN_NEXT_WORD ((4 << 3) | 6)
  ASSERT_EQ(val_descr, 0x26);
  uint16_t val_len;
  BE_STREAM_TO_UINT16(val_len, p_acc);
  // 400 bytes matching stored SDP_MAX_ATTR_LEN (and not truncated to < 400)
  ASSERT_EQ(val_len, 400);

  // Validate the payload bytes match our expected write data
  for (int i = 0; i < 400; ++i) {
    ASSERT_EQ(p_acc[i], 'A');
  }

  sdpu_release_ccb(*p_ccb);
  SDP_DeleteRecord(handle);
}

TEST_F(StackSdpInitTest, SDP_AddAttribute__exceed_max_attr_len_truncation) {
  uint32_t record_handle = SDP_CreateRecord();
  ASSERT_NE((uint32_t)0, record_handle);

  // Create a buffer larger than SDP_MAX_ATTR_LEN
  uint32_t attr_len = SDP_MAX_ATTR_LEN + 10;
  std::vector<uint8_t> attr_val(attr_len, 'a');
  attr_val[attr_len - 1] = '\0';

  ASSERT_TRUE(SDP_AddAttribute(
          record_handle, ATTR_ID_SERVICE_NAME, TEXT_STR_DESC_TYPE, attr_len, attr_val.data()));

  tSDP_RECORD* record = sdp_db_find_record(record_handle);
  ASSERT_TRUE(record != nullptr);

  const tSDP_ATTRIBUTE* attribute =
          sdp_db_find_attr_in_rec(record, ATTR_ID_SERVICE_NAME, ATTR_ID_SERVICE_NAME);
  ASSERT_TRUE(attribute != nullptr);

  // Ensure that the attribute length was truncated to SDP_MAX_ATTR_LEN
  ASSERT_EQ((uint32_t)SDP_MAX_ATTR_LEN, attribute->len);
  ASSERT_EQ(sizeof(uint32_t) + SDP_MAX_ATTR_LEN, record->free_pad_ptr);

  ASSERT_TRUE(SDP_DeleteRecord(record_handle));
}
