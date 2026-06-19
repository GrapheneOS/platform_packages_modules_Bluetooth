/*
 * Copyright 2020 The Android Open Source Project
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

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <cstdint>
#include <memory>

#include "stack/connection_manager/connection_manager.h"
#include "stack/gatt/gatt_int.h"
#include "stack/include/bt_hdr.h"
#include "stack/include/main_thread.h"
#undef LOG_TAG
#include <bluetooth/types/address.h>

#include "stack/gatt/gatt_sr.cc"  // NOLINT(build/include)

#define MAX_UINT16 ((uint16_t)0xffff)

using namespace testing;
using stack::tGATT_REQ_CBACK;

tGATT_CB gatt_cb;

namespace {

struct TestMutables {
  struct {
    uint8_t op_code_;
  } attp_build_sr_msg;

  struct {
    int access_count_{0};
    tGATT_STATUS return_status_{GATT_SUCCESS};
  } gatts_write_attr_perm_check;
};

TestMutables test_state_;
}  // namespace

BT_HDR* attp_build_sr_msg(tGATT_TCB& /*tcb*/, uint8_t op_code, tGATT_SR_MSG* /*p_msg*/,
                          uint16_t /*payload_size*/) {
  test_state_.attp_build_sr_msg.op_code_ = op_code;
  return nullptr;
}
tGATT_STATUS attp_send_cl_confirmation_msg(tGATT_TCB& /*tcb*/, uint16_t /*cid*/) {
  return GATT_SUCCESS;
}
tGATT_STATUS attp_send_cl_msg(tGATT_TCB& /*tcb*/, tGATT_CLCB* /*p_clcb*/, uint8_t /*op_code*/,
                              tGATT_CL_MSG* /*p_msg*/) {
  return GATT_SUCCESS;
}
tGATT_STATUS attp_send_sr_msg(tGATT_TCB& /*tcb*/, uint16_t /*cid*/, BT_HDR* /*p_msg*/) {
  return GATT_SUCCESS;
}

void gatt_act_discovery(tGATT_CLCB* /*p_clcb*/) {}
void gatt_force_disconnect(tGATT_TCB* /*p_tcb*/, std::string /*comment*/) {}
bool gatt_disconnect(tGATT_TCB* /*p_tcb*/) { return false; }
tGATT_CH_STATE gatt_get_ch_state(tGATT_TCB* /*p_tcb*/) { return GATT_CH_CLOSE; }
tGATT_STATUS gatts_db_read_attr_value_by_type(tGATT_TCB& /*tcb*/, uint16_t /*cid*/,
                                              tGATT_SVC_DB* /*p_db*/, uint8_t /*op_code*/,
                                              BT_HDR* /*p_rsp*/, uint16_t /*s_handle*/,
                                              uint16_t /*e_handle*/, const Uuid& /*type*/,
                                              uint16_t* /*p_len*/, tGATT_SEC_FLAG /*sec_flag*/,
                                              uint8_t /*key_size*/, uint32_t /*trans_id*/,
                                              uint16_t* /*p_cur_handle*/) {
  return GATT_SUCCESS;
}
void gatt_set_ch_state(tGATT_TCB* /*p_tcb*/, tGATT_CH_STATE /*ch_state*/) {}
Uuid* gatts_get_service_uuid(tGATT_SVC_DB* /*p_db*/) { return nullptr; }

tGATT_STATUS gatts_read_attr_perm_check(tGATT_SVC_DB* /*p_db*/, bool /*is_long*/,
                                        uint16_t /*handle*/, tGATT_SEC_FLAG /*sec_flag*/,
                                        uint8_t /*key_size*/) {
  return GATT_SUCCESS;
}
tGATT_STATUS gatts_read_attr_value_by_handle(tGATT_TCB& /*tcb*/, uint16_t /*cid*/,
                                             tGATT_SVC_DB* /*p_db*/, uint8_t /*op_code*/,
                                             uint16_t /*handle*/, uint16_t /*offset*/,
                                             uint8_t* /*p_value*/, uint16_t* /*p_len*/,
                                             uint16_t /*mtu*/, tGATT_SEC_FLAG /*sec_flag*/,
                                             uint8_t /*key_size*/, uint32_t /*trans_id*/) {
  return GATT_SUCCESS;
}
tGATT_STATUS gatts_write_attr_perm_check(tGATT_SVC_DB* /*p_db*/, uint8_t /*op_code*/,
                                         uint16_t /*handle*/, uint16_t /*offset*/,
                                         uint8_t* /*p_data*/, uint16_t /*len*/,
                                         tGATT_SEC_FLAG /*sec_flag*/, uint8_t /*key_size*/) {
  test_state_.gatts_write_attr_perm_check.access_count_++;
  return test_state_.gatts_write_attr_perm_check.return_status_;
}
void gatt_update_app_use_link_flag(tGATT_IF /*gatt_if*/, tGATT_TCB* /*p_tcb*/, bool /*is_add*/,
                                   bool /*check_acl_link*/) {}
bluetooth::common::MessageLoopThread* get_main_thread() { return nullptr; }

MockFunction<void(tCONN_ID, uint32_t, const RawAddress&, uint16_t, uint16_t, bool)>
        mock_read_characteristic_cb;
static void ApplicationReadCharacteristicCallback(tCONN_ID conn_id, uint32_t trans_id,
                                                  const RawAddress& remote_bda, uint16_t handle,
                                                  uint16_t offset, bool is_long) {
  mock_read_characteristic_cb.Call(conn_id, trans_id, remote_bda, handle, offset, is_long);
}

MockFunction<void(tCONN_ID, uint32_t, const RawAddress&, uint16_t, uint16_t, bool)>
        mock_read_descriptor_cb;
static void ApplicationReadDescriptorCallback(tCONN_ID conn_id, uint32_t trans_id,
                                              const RawAddress& remote_bda, uint16_t handle,
                                              uint16_t offset, bool is_long) {
  mock_read_descriptor_cb.Call(conn_id, trans_id, remote_bda, handle, offset, is_long);
}

MockFunction<void(tCONN_ID, uint32_t, const RawAddress&, uint16_t, uint16_t, bool, bool, uint8_t*,
                  uint16_t)>
        mock_write_characteristic_cb;
static void ApplicationWriteCharacteristicCallback(tCONN_ID conn_id, uint32_t trans_id,
                                                   const RawAddress& remote_bda, uint16_t handle,
                                                   uint16_t offset, bool need_rsp, bool is_prep,
                                                   uint8_t* value, uint16_t len) {
  mock_write_characteristic_cb.Call(conn_id, trans_id, remote_bda, handle, offset, need_rsp,
                                    is_prep, value, len);
}

MockFunction<void(tCONN_ID, uint32_t, const RawAddress&, uint16_t, uint16_t, bool, bool, uint8_t*,
                  uint16_t)>
        mock_write_descriptor_cb;
static void ApplicationWriteDescriptorCallback(tCONN_ID conn_id, uint32_t trans_id,
                                               const RawAddress& remote_bda, uint16_t handle,
                                               uint16_t offset, bool need_rsp, bool is_prep,
                                               uint8_t* value, uint16_t len) {
  mock_write_descriptor_cb.Call(conn_id, trans_id, remote_bda, handle, offset, need_rsp, is_prep,
                                value, len);
}

MockFunction<void(tCONN_ID, uint32_t, const RawAddress&, tGATT_EXEC_FLAG)> mock_exec_write_cb;
static void ApplicationExecWriteCallback(tCONN_ID conn_id, uint32_t trans_id,
                                         const RawAddress& remote_bda, tGATT_EXEC_FLAG exec_write) {
  mock_exec_write_cb.Call(conn_id, trans_id, remote_bda, exec_write);
}

MockFunction<void(tCONN_ID, const RawAddress&, uint16_t)> mock_mtu_changed_cb;
static void ApplicationMtuChangedCallback(tCONN_ID conn_id, const RawAddress& remote_bda,
                                          uint16_t mtu) {
  mock_mtu_changed_cb.Call(conn_id, remote_bda, mtu);
}

MockFunction<void(tCONN_ID, uint32_t, const RawAddress&)> mock_conf_cb;
static void ApplicationConfCallback(tCONN_ID conn_id, uint32_t trans_id,
                                    const RawAddress& remote_bda) {
  mock_conf_cb.Call(conn_id, trans_id, remote_bda);
}

static stack::tGATT_REQ_CBACK ApplicationRequestCallback = {
        .read_characteristic_cb = ApplicationReadCharacteristicCallback,
        .read_descriptor_cb = ApplicationReadDescriptorCallback,
        .write_characteristic_cb = ApplicationWriteCharacteristicCallback,
        .write_descriptor_cb = ApplicationWriteDescriptorCallback,
        .exec_write_cb = ApplicationExecWriteCallback,
        .mtu_changed_cb = ApplicationMtuChangedCallback,
        .conf_cb = ApplicationConfCallback,
};

bool gatt_sr_is_cl_change_aware(tGATT_TCB& /*tcb*/) { return false; }
void gatt_sr_init_cl_status(tGATT_TCB& /*p_tcb*/) {}
void gatt_sr_update_cl_status(tGATT_TCB& p_tcb, bool chg_aware) {
  p_tcb.is_robust_cache_change_aware = chg_aware;
}

/**
 * Test class to test selected functionality in stack/gatt/gatt_sr.cc
 */
namespace {
uint16_t kHandle = 1;
bt_gatt_db_attribute_type_t kGattCharacteristicType = BTGATT_DB_CHARACTERISTIC;
}  // namespace
class GattSrTest : public ::testing::Test {
protected:
  void SetUp() override {
    memset(&gatt_cb.tcb[0], 0, sizeof(gatt_cb.tcb[0]));
    memset(&el_, 0, sizeof(el_));

    gatt_cb.tcb[0].trans_id = 0x12345677;
    gatt_cb.tcb[0].att_lcid = L2CAP_ATT_CID;
    gatt_cb.tcb[0].in_use = true;

    el_.gatt_if = 1;

    gatt_cb.cl_rcb_map.emplace(el_.gatt_if, std::make_unique<tGATT_REG>());
    tGATT_REG* p_reg = gatt_cb.cl_rcb_map[el_.gatt_if].get();
    p_reg->in_use = true;
    p_reg->gatt_if = el_.gatt_if;
    p_reg->app_cb.p_req_cb = &ApplicationRequestCallback;

    test_state_ = TestMutables();
  }

  void TearDown() override {
    gatt_cb.cl_rcb_map.erase(el_.gatt_if);

    gatt_cb.tcb[0] = {};
  }

  tGATT_TCB& tcb_ = gatt_cb.tcb[0];
  tGATT_SRV_LIST_ELEM el_;
};

/* Server Robust Caching Test */
class GattSrRobustCachingTest : public ::testing::Test {
protected:
  void SetUp() override {
    memset(&tcb_, 0, sizeof(tcb_));

    default_length_ = 2;
    memset(default_data_, 0, sizeof(default_data_));

    gatt_cb.handle_of_database_hash = 0x0010;
  }

  tGATT_TCB tcb_;
  uint16_t default_length_;
  uint8_t default_data_[2];
};

TEST_F(GattSrTest, gatts_process_write_req_request_prepare_write_no_data) {
  gatts_process_write_req(tcb_, L2CAP_ATT_CID, el_, kHandle, GATT_REQ_PREPARE_WRITE, 0, nullptr,
                          kGattCharacteristicType);
}

TEST_F(GattSrTest, gatts_process_write_req_request_prepare_write_max_len_no_data) {
  gatts_process_write_req(tcb_, L2CAP_ATT_CID, el_, kHandle, GATT_REQ_PREPARE_WRITE, MAX_UINT16,
                          nullptr, kGattCharacteristicType);
}

TEST_F(GattSrTest, gatts_process_write_req_request_prepare_write_zero_len_max_data) {
  uint8_t max_mem[MAX_UINT16];
  gatts_process_write_req(tcb_, L2CAP_ATT_CID, el_, kHandle, GATT_REQ_PREPARE_WRITE, 0, max_mem,
                          kGattCharacteristicType);
}

TEST_F(GattSrTest, gatts_process_write_req_request_prepare_write_typical) {
  uint8_t p_data[2] = {0x34, 0x12};
  uint16_t length = static_cast<uint16_t>(sizeof(p_data) / sizeof(p_data[0]));

  EXPECT_CALL(mock_write_characteristic_cb, Call(el_.gatt_if, 0x12345678u, testing::_, kHandle,
                                                 0x1234, testing::_, true, testing::_, 0));

  gatts_process_write_req(tcb_, L2CAP_ATT_CID, el_, kHandle, GATT_REQ_PREPARE_WRITE, length, p_data,
                          kGattCharacteristicType);

  ASSERT_EQ(test_state_.gatts_write_attr_perm_check.access_count_, 1);
  Mock::VerifyAndClearExpectations(&mock_write_characteristic_cb);
}

TEST_F(GattSrTest, gatts_process_write_req_signed_command_write_no_data) {
  gatts_process_write_req(tcb_, L2CAP_ATT_CID, el_, kHandle, GATT_SIGN_CMD_WRITE, 0, nullptr,
                          kGattCharacteristicType);
}

TEST_F(GattSrTest, gatts_process_write_req_signed_command_write_max_len_no_data) {
  gatts_process_write_req(tcb_, L2CAP_ATT_CID, el_, kHandle, GATT_SIGN_CMD_WRITE, MAX_UINT16,
                          nullptr, kGattCharacteristicType);
}

TEST_F(GattSrTest, gatts_process_write_req_signed_command_write_zero_len_max_data) {
  uint8_t max_mem[MAX_UINT16];
  gatts_process_write_req(tcb_, L2CAP_ATT_CID, el_, kHandle, GATT_SIGN_CMD_WRITE, 0, max_mem,
                          kGattCharacteristicType);
}

TEST_F(GattSrTest, gatts_process_write_req_signed_command_write_typical) {
  static constexpr size_t kDataLength = 4;
  uint8_t p_data[GATT_AUTH_SIGN_LEN + kDataLength] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
                                                      0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc,
                                                      0xdd, 0xee, 0xff, 0x01};
  uint16_t length = static_cast<uint16_t>(sizeof(p_data) / sizeof(p_data[0]));

  EXPECT_CALL(mock_write_characteristic_cb, Call(el_.gatt_if, 0x12345678u, testing::_, kHandle, 0x0,
                                                 false, false, testing::_, kDataLength));

  gatts_process_write_req(tcb_, L2CAP_ATT_CID, el_, kHandle, GATT_SIGN_CMD_WRITE, length, p_data,
                          kGattCharacteristicType);

  ASSERT_EQ(test_state_.gatts_write_attr_perm_check.access_count_, 1);
  Mock::VerifyAndClearExpectations(&mock_write_characteristic_cb);
}

TEST_F(GattSrTest, gatts_process_write_req_command_write_no_data) {
  gatts_process_write_req(tcb_, L2CAP_ATT_CID, el_, kHandle, GATT_CMD_WRITE, 0, nullptr,
                          kGattCharacteristicType);
}

TEST_F(GattSrTest, gatts_process_write_req_command_write_max_len_no_data) {
  gatts_process_write_req(tcb_, L2CAP_ATT_CID, el_, kHandle, GATT_CMD_WRITE, MAX_UINT16, nullptr,
                          kGattCharacteristicType);
}

TEST_F(GattSrTest, gatts_process_write_req_command_write_zero_len_max_data) {
  uint8_t max_mem[MAX_UINT16];
  gatts_process_write_req(tcb_, L2CAP_ATT_CID, el_, kHandle, GATT_CMD_WRITE, 0, max_mem,
                          kGattCharacteristicType);
}

TEST_F(GattSrTest, gatts_process_write_req_command_write_typical) {
  uint8_t p_data[16] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
                        0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x01};
  uint16_t length = static_cast<uint16_t>(sizeof(p_data) / sizeof(p_data[0]));

  EXPECT_CALL(mock_write_characteristic_cb, Call(el_.gatt_if, 0x12345678u, testing::_, kHandle, 0x0,
                                                 false, false, testing::_, length));

  gatts_process_write_req(tcb_, L2CAP_ATT_CID, el_, kHandle, GATT_CMD_WRITE, length, p_data,
                          kGattCharacteristicType);

  ASSERT_EQ(test_state_.gatts_write_attr_perm_check.access_count_, 1);
  Mock::VerifyAndClearExpectations(&mock_write_characteristic_cb);
}

TEST_F(GattSrTest, gatts_process_write_req_request_write_no_data) {
  gatts_process_write_req(tcb_, L2CAP_ATT_CID, el_, kHandle, GATT_REQ_WRITE, 0, nullptr,
                          kGattCharacteristicType);
}

TEST_F(GattSrTest, gatts_process_write_req_request_write_max_len_no_data) {
  gatts_process_write_req(tcb_, L2CAP_ATT_CID, el_, kHandle, GATT_REQ_WRITE, MAX_UINT16, nullptr,
                          kGattCharacteristicType);
}

TEST_F(GattSrTest, gatts_process_write_req_request_write_zero_len_max_data) {
  uint8_t max_mem[MAX_UINT16];
  gatts_process_write_req(tcb_, L2CAP_ATT_CID, el_, kHandle, GATT_REQ_WRITE, 0, max_mem,
                          kGattCharacteristicType);
}

TEST_F(GattSrTest, gatts_process_write_req_request_write_typical) {
  uint8_t p_data[16] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
                        0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x01};
  uint16_t length = static_cast<uint16_t>(sizeof(p_data) / sizeof(p_data[0]));

  EXPECT_CALL(mock_write_characteristic_cb, Call(el_.gatt_if, 0x12345678u, testing::_, kHandle, 0x0,
                                                 true, false, testing::_, length));

  gatts_process_write_req(tcb_, L2CAP_ATT_CID, el_, kHandle, GATT_REQ_WRITE, length, p_data,
                          kGattCharacteristicType);

  ASSERT_EQ(test_state_.gatts_write_attr_perm_check.access_count_, 1);
  Mock::VerifyAndClearExpectations(&mock_write_characteristic_cb);
}

TEST_F(GattSrRobustCachingTest, gatts_process_db_out_of_sync_for_gatt_req_read_by_grp_type) {
  tcb_.is_robust_cache_change_aware = false;

  bool should_ignore = gatts_process_db_out_of_sync(tcb_, L2CAP_ATT_CID, GATT_REQ_READ_BY_GRP_TYPE,
                                                    default_length_, default_data_);

  ASSERT_TRUE(should_ignore);
  ASSERT_TRUE(tcb_.is_robust_cache_change_aware);
}

TEST_F(GattSrRobustCachingTest, gatts_process_db_out_of_sync_for_gatt_req_find_type_value) {
  tcb_.is_robust_cache_change_aware = false;

  bool should_ignore = gatts_process_db_out_of_sync(tcb_, L2CAP_ATT_CID, GATT_REQ_FIND_TYPE_VALUE,
                                                    default_length_, default_data_);

  ASSERT_TRUE(should_ignore);
  ASSERT_TRUE(tcb_.is_robust_cache_change_aware);
}

TEST_F(GattSrRobustCachingTest, gatts_process_db_out_of_sync_for_gatt_req_find_info) {
  tcb_.is_robust_cache_change_aware = false;

  bool should_ignore = gatts_process_db_out_of_sync(tcb_, L2CAP_ATT_CID, GATT_REQ_FIND_INFO,
                                                    default_length_, default_data_);

  ASSERT_TRUE(should_ignore);
  ASSERT_TRUE(tcb_.is_robust_cache_change_aware);
}

TEST_F(GattSrRobustCachingTest,
       gatts_process_db_out_of_sync_for_gatt_req_read_by_type_parse_failed) {
  // INVALID_PDU
  uint16_t len = 4;
  uint8_t p_data[4] = {0x00, 0x02, 0x14, 0x02};
  tcb_.is_robust_cache_change_aware = false;

  bool should_ignore =
          gatts_process_db_out_of_sync(tcb_, L2CAP_ATT_CID, GATT_REQ_READ_BY_TYPE, len, p_data);

  ASSERT_TRUE(should_ignore);
  ASSERT_TRUE(tcb_.is_robust_cache_change_aware);
}

TEST_F(GattSrRobustCachingTest,
       gatts_process_db_out_of_sync_for_gatt_req_read_by_type_db_hash_uuid) {
  // ATT_READ_BY_TYPE_REQ(0x0001, 0x0010, 0x2B2A)
  uint16_t len = 6;
  uint8_t p_data[6] = {0x01, 0x00, 0x10, 0x00, 0x2A, 0x2B};
  tcb_.is_robust_cache_change_aware = false;

  bool should_ignore =
          gatts_process_db_out_of_sync(tcb_, L2CAP_ATT_CID, GATT_REQ_READ_BY_TYPE, len, p_data);

  ASSERT_FALSE(should_ignore);
}

TEST_F(GattSrRobustCachingTest,
       gatts_process_db_out_of_sync_for_gatt_req_read_by_type_wrong_range) {
  // ATT_READ_BY_TYPE_REQ(0x0200, 0x0214, 0x2803)
  uint16_t len = 6;
  uint8_t p_data[6] = {0x00, 0x02, 0x14, 0x02, 0x2A, 0x28};
  tcb_.is_robust_cache_change_aware = false;

  bool should_ignore =
          gatts_process_db_out_of_sync(tcb_, L2CAP_ATT_CID, GATT_REQ_READ_BY_TYPE, len, p_data);

  ASSERT_TRUE(should_ignore);
  ASSERT_TRUE(tcb_.is_robust_cache_change_aware);
}

TEST_F(GattSrRobustCachingTest, gatts_process_db_out_of_sync_for_gatt_req_read_by_type_other_uuid) {
  // ATT_READ_BY_TYPE_REQ(0x0200, 0x0214, 0x2803)
  uint16_t len = 6;
  uint8_t p_data[6] = {0x00, 0x02, 0x14, 0x02, 0x03, 0x28};
  tcb_.is_robust_cache_change_aware = false;

  bool should_ignore =
          gatts_process_db_out_of_sync(tcb_, L2CAP_ATT_CID, GATT_REQ_READ_BY_TYPE, len, p_data);

  ASSERT_TRUE(should_ignore);
  ASSERT_TRUE(tcb_.is_robust_cache_change_aware);
}

TEST_F(GattSrRobustCachingTest, gatts_process_db_out_of_sync_for_gatt_req_read_parse_failed) {
  // INVALID_PDU
  uint8_t p_data[1] = {0x02};
  uint16_t len = 1;
  tcb_.is_robust_cache_change_aware = false;

  bool should_ignore =
          gatts_process_db_out_of_sync(tcb_, L2CAP_ATT_CID, GATT_REQ_READ, len, p_data);

  ASSERT_TRUE(should_ignore);
  ASSERT_TRUE(tcb_.is_robust_cache_change_aware);
}

TEST_F(GattSrRobustCachingTest, gatts_process_db_out_of_sync_for_gatt_req_read_db_hash_handle) {
  // ATT_READ_REQ(0x0010)
  uint8_t p_data[2] = {0x10, 0x00};
  uint16_t len = 2;
  tcb_.is_robust_cache_change_aware = false;

  bool should_ignore =
          gatts_process_db_out_of_sync(tcb_, L2CAP_ATT_CID, GATT_REQ_READ, len, p_data);

  ASSERT_FALSE(should_ignore);
}

TEST_F(GattSrRobustCachingTest, gatts_process_db_out_of_sync_for_gatt_req_read_other_handle) {
  // ATT_READ_REQ(0x0002)
  uint8_t p_data[2] = {0x02, 0x00};
  uint16_t len = 2;
  tcb_.is_robust_cache_change_aware = false;

  bool should_ignore =
          gatts_process_db_out_of_sync(tcb_, L2CAP_ATT_CID, GATT_REQ_READ, len, p_data);

  ASSERT_TRUE(should_ignore);
  ASSERT_TRUE(tcb_.is_robust_cache_change_aware);
}

TEST_F(GattSrRobustCachingTest, gatts_process_db_out_of_sync_for_gatt_req_read_blob) {
  tcb_.is_robust_cache_change_aware = false;

  bool should_ignore = gatts_process_db_out_of_sync(tcb_, L2CAP_ATT_CID, GATT_REQ_READ_BLOB,
                                                    default_length_, default_data_);

  ASSERT_TRUE(should_ignore);
  ASSERT_TRUE(tcb_.is_robust_cache_change_aware);
}

TEST_F(GattSrRobustCachingTest, gatts_process_db_out_of_sync_for_gatt_req_read_multi) {
  tcb_.is_robust_cache_change_aware = false;

  bool should_ignore = gatts_process_db_out_of_sync(tcb_, L2CAP_ATT_CID, GATT_REQ_READ_MULTI,
                                                    default_length_, default_data_);

  ASSERT_TRUE(should_ignore);
  ASSERT_TRUE(tcb_.is_robust_cache_change_aware);
}

TEST_F(GattSrRobustCachingTest, gatts_process_db_out_of_sync_for_gatt_req_write) {
  tcb_.is_robust_cache_change_aware = false;

  bool should_ignore = gatts_process_db_out_of_sync(tcb_, L2CAP_ATT_CID, GATT_REQ_WRITE,
                                                    default_length_, default_data_);

  ASSERT_TRUE(should_ignore);
  ASSERT_TRUE(tcb_.is_robust_cache_change_aware);
}

TEST_F(GattSrRobustCachingTest, gatts_process_db_out_of_sync_for_gatt_cmd_write) {
  tcb_.is_robust_cache_change_aware = false;

  bool should_ignore = gatts_process_db_out_of_sync(tcb_, L2CAP_ATT_CID, GATT_CMD_WRITE,
                                                    default_length_, default_data_);

  ASSERT_TRUE(should_ignore);
  ASSERT_FALSE(tcb_.is_robust_cache_change_aware);
}

TEST_F(GattSrRobustCachingTest, gatts_process_db_out_of_sync_for_gatt_sign_cmd_write) {
  tcb_.is_robust_cache_change_aware = false;

  bool should_ignore = gatts_process_db_out_of_sync(tcb_, L2CAP_ATT_CID, GATT_SIGN_CMD_WRITE,
                                                    default_length_, default_data_);

  ASSERT_TRUE(should_ignore);
  ASSERT_FALSE(tcb_.is_robust_cache_change_aware);
}

TEST_F(GattSrRobustCachingTest, gatts_process_db_out_of_sync_for_gatt_req_prepare_write) {
  tcb_.is_robust_cache_change_aware = false;

  bool should_ignore = gatts_process_db_out_of_sync(tcb_, L2CAP_ATT_CID, GATT_REQ_PREPARE_WRITE,
                                                    default_length_, default_data_);

  ASSERT_TRUE(should_ignore);
  ASSERT_TRUE(tcb_.is_robust_cache_change_aware);
}

TEST_F(GattSrRobustCachingTest, gatts_process_db_out_of_sync_for_gatt_req_mtu) {
  tcb_.is_robust_cache_change_aware = false;

  bool should_ignore = gatts_process_db_out_of_sync(tcb_, L2CAP_ATT_CID, GATT_REQ_MTU,
                                                    default_length_, default_data_);

  ASSERT_FALSE(should_ignore);
}

TEST_F(GattSrRobustCachingTest, gatts_process_db_out_of_sync_for_gatt_req_exec_write) {
  tcb_.is_robust_cache_change_aware = false;

  bool should_ignore = gatts_process_db_out_of_sync(tcb_, L2CAP_ATT_CID, GATT_REQ_EXEC_WRITE,
                                                    default_length_, default_data_);

  ASSERT_FALSE(should_ignore);
}

TEST_F(GattSrRobustCachingTest, gatts_process_db_out_of_sync_for_gatt_handle_value_conf) {
  tcb_.is_robust_cache_change_aware = false;

  bool should_ignore = gatts_process_db_out_of_sync(tcb_, L2CAP_ATT_CID, GATT_HANDLE_VALUE_CONF,
                                                    default_length_, default_data_);

  ASSERT_FALSE(should_ignore);
}
