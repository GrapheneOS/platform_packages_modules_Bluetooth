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

#include <base/logging.h>
#include <gtest/gtest.h>
#include <stdio.h>

#include <cstdint>

#include "bta/include/bta_av_api.h"
#include "btif/include/btif_common.h"
#include "common/message_loop_thread.h"
#include "device/include/interop.h"
#include "include/hardware/bt_rc.h"
#include "stack/include/bt_hdr.h"
#include "stack/include/btm_api_types.h"
#include "test/common/mock_functions.h"
#include "test/mock/mock_osi_alarm.h"
#include "test/mock/mock_osi_allocator.h"
#include "test/mock/mock_osi_list.h"
#include "types/raw_address.h"
#undef LOG_TAG
#include "avrcp_service.h"
#include "btif/src/btif_rc.cc"

namespace bluetooth {
namespace avrcp {
int VolChanged = 0;
AvrcpService* AvrcpService::instance_ = nullptr;

void AvrcpService::SendMediaUpdate(bool track_changed, bool play_state,
                                   bool queue){};
void AvrcpService::SendFolderUpdate(bool available_players,
                                    bool addressed_players, bool uids){};
void AvrcpService::SendActiveDeviceChanged(const RawAddress& address){};
void AvrcpService::SendPlayerSettingsChanged(
    std::vector<PlayerAttribute> attributes, std::vector<uint8_t> values){};
void AvrcpService::ServiceInterfaceImpl::Init(
    MediaInterface* media_interface, VolumeInterface* volume_interface,
    PlayerSettingsInterface* player_settings_interface){};
void AvrcpService::ServiceInterfaceImpl::RegisterBipServer(int psm){};
void AvrcpService::ServiceInterfaceImpl::UnregisterBipServer(){};
bool AvrcpService::ServiceInterfaceImpl::ConnectDevice(
    const RawAddress& bdaddr) {
  return true;
};
bool AvrcpService::ServiceInterfaceImpl::DisconnectDevice(
    const RawAddress& bdaddr) {
  return true;
};
void AvrcpService::ServiceInterfaceImpl::SetBipClientStatus(
    const RawAddress& bdaddr, bool connected){};
bool AvrcpService::ServiceInterfaceImpl::Cleanup() { return true; };

AvrcpService* AvrcpService::Get() {
  CHECK(instance_ == nullptr);
  instance_ = new AvrcpService();
  return instance_;
}

void AvrcpService::RegisterVolChanged(const RawAddress& bdaddr) {
  VolChanged++;
}
}  // namespace avrcp
}  // namespace bluetooth

namespace {
int AVRC_BldResponse_ = 0;
int AVRC_BldCmd_ = 0;
}  // namespace

uint8_t appl_trace_level = BT_TRACE_LEVEL_WARNING;
uint8_t btif_trace_level = BT_TRACE_LEVEL_WARNING;

const RawAddress kDeviceAddress({0x11, 0x22, 0x33, 0x44, 0x55, 0x66});
bool avrcp_absolute_volume_is_enabled() { return true; }

tAVRC_STS AVRC_BldCommand(tAVRC_COMMAND* p_cmd, BT_HDR** pp_pkt) {
  AVRC_BldCmd_++;
  return 0;
}
tAVRC_STS AVRC_BldResponse(uint8_t handle, tAVRC_RESPONSE* p_rsp,
                           BT_HDR** pp_pkt) {
  AVRC_BldResponse_++;
  return 0;
}
tAVRC_STS AVRC_Ctrl_ParsCommand(tAVRC_MSG* p_msg, tAVRC_COMMAND* p_result) {
  return 0;
}
tAVRC_STS AVRC_Ctrl_ParsResponse(tAVRC_MSG* p_msg, tAVRC_RESPONSE* p_result,
                                 uint8_t* p_buf, uint16_t* buf_len) {
  return 0;
}
tAVRC_STS AVRC_ParsCommand(tAVRC_MSG* p_msg, tAVRC_COMMAND* p_result,
                           uint8_t* p_buf, uint16_t buf_len) {
  return 0;
}
tAVRC_STS AVRC_ParsResponse(tAVRC_MSG* p_msg, tAVRC_RESPONSE* p_result,
                            UNUSED_ATTR uint8_t* p_buf,
                            UNUSED_ATTR uint16_t buf_len) {
  return 0;
}
void BTA_AvCloseRc(uint8_t rc_handle) {}
void BTA_AvMetaCmd(uint8_t rc_handle, uint8_t label, tBTA_AV_CMD cmd_code,
                   BT_HDR* p_pkt) {}
void BTA_AvMetaRsp(uint8_t rc_handle, uint8_t label, tBTA_AV_CODE rsp_code,
                   BT_HDR* p_pkt) {}
void BTA_AvRemoteCmd(uint8_t rc_handle, uint8_t label, tBTA_AV_RC rc_id,
                     tBTA_AV_STATE key_state) {}
void BTA_AvRemoteVendorUniqueCmd(uint8_t rc_handle, uint8_t label,
                                 tBTA_AV_STATE key_state, uint8_t* p_msg,
                                 uint8_t buf_len) {}
void BTA_AvVendorCmd(uint8_t rc_handle, uint8_t label, tBTA_AV_CODE cmd_code,
                     uint8_t* p_data, uint16_t len) {}
void BTA_AvVendorRsp(uint8_t rc_handle, uint8_t label, tBTA_AV_CODE rsp_code,
                     uint8_t* p_data, uint16_t len, uint32_t company_id) {}
void btif_av_clear_remote_suspend_flag(void) {}
bool btif_av_is_connected(void) { return true; }
bool btif_av_is_sink_enabled(void) { return true; }
RawAddress btif_av_sink_active_peer(void) { return RawAddress(); }
RawAddress btif_av_source_active_peer(void) { return RawAddress(); }
bool btif_av_stream_started_ready(void) { return false; }
bt_status_t btif_transfer_context(tBTIF_CBACK* p_cback, uint16_t event,
                                  char* p_params, int param_len,
                                  tBTIF_COPY_CBACK* p_copy_cback) {
  return BT_STATUS_SUCCESS;
}
bool btif_av_src_sink_coexist_enabled() { return true; }
bool btif_av_is_connected_addr(const RawAddress& peer_address) { return true; }
bool btif_av_peer_is_connected_sink(const RawAddress& peer_address) {
  return false;
}
bool btif_av_peer_is_connected_source(const RawAddress& peer_address) {
  return true;
}
bool btif_av_peer_is_sink(const RawAddress& peer_address) { return false; }
bool btif_av_peer_is_source(const RawAddress& peer_address) { return true; }
bool btif_av_both_enable(void) { return true; }

const char* dump_rc_event(uint8_t event) { return nullptr; }
const char* dump_rc_notification_event_id(uint8_t event_id) { return nullptr; }
const char* dump_rc_pdu(uint8_t pdu) { return nullptr; }
const char* dump_rc_opcode(uint8_t pdu) { return nullptr; }
static bluetooth::common::MessageLoopThread jni_thread("bt_jni_thread");
bt_status_t do_in_jni_thread(const base::Location& from_here,
                             base::OnceClosure task) {
  if (!jni_thread.DoInThread(from_here, std::move(task))) {
    LOG(ERROR) << __func__ << ": Post task to task runner failed!";
    return BT_STATUS_FAIL;
  }
  return BT_STATUS_SUCCESS;
}
bluetooth::common::MessageLoopThread* get_main_thread() { return nullptr; }
bool interop_match_addr(const interop_feature_t feature,
                        const RawAddress* addr) {
  return false;
}

/**
 * Test class to test selected functionality in hci/src/hci_layer.cc
 */
class BtifRcTest : public ::testing::Test {};

TEST_F(BtifRcTest, get_element_attr_rsp) {
  RawAddress bd_addr;

  btif_rc_cb.rc_multi_cb[0].rc_addr = bd_addr;
  btif_rc_cb.rc_multi_cb[0].rc_connected = true;
  btif_rc_cb.rc_multi_cb[0]
      .rc_pdu_info[IDX_GET_ELEMENT_ATTR_RSP]
      .is_rsp_pending = true;
  btif_rc_cb.rc_multi_cb[0].rc_state = BTRC_CONNECTION_STATE_CONNECTED;

  btrc_element_attr_val_t p_attrs[BTRC_MAX_ELEM_ATTR_SIZE];
  uint8_t num_attr = BTRC_MAX_ELEM_ATTR_SIZE + 1;

  CHECK(get_element_attr_rsp(bd_addr, num_attr, p_attrs) == BT_STATUS_SUCCESS);
  CHECK(AVRC_BldResponse_ == 1);
}

TEST_F(BtifRcTest, btif_rc_get_addr_by_handle) {
  RawAddress get_bd_addr;

  btif_rc_cb.rc_multi_cb[0].rc_addr = kDeviceAddress;
  btif_rc_cb.rc_multi_cb[0].rc_state = BTRC_CONNECTION_STATE_CONNECTED;
  btif_rc_cb.rc_multi_cb[0].rc_handle = 0;

  btif_rc_get_addr_by_handle(0, get_bd_addr);
  CHECK(kDeviceAddress == get_bd_addr);
}

static btrc_ctrl_callbacks_t btrc_ctrl_callbacks = {
    .size = sizeof(btrc_ctrl_callbacks_t),
    .passthrough_rsp_cb = NULL,
    .groupnavigation_rsp_cb = NULL,
    .connection_state_cb = NULL,
    .getrcfeatures_cb = NULL,
    .setplayerappsetting_rsp_cb = NULL,
    .playerapplicationsetting_cb = NULL,
    .playerapplicationsetting_changed_cb = NULL,
    .setabsvol_cmd_cb = NULL,
    .registernotification_absvol_cb = NULL,
    .track_changed_cb = NULL,
    .play_position_changed_cb = NULL,
    .play_status_changed_cb = NULL,
    .get_folder_items_cb = NULL,
    .change_folder_path_cb = NULL,
    .set_browsed_player_cb = NULL,
    .set_addressed_player_cb = NULL,
    .addressed_player_changed_cb = NULL,
    .now_playing_contents_changed_cb = NULL,
    .available_player_changed_cb = NULL,
    .get_cover_art_psm_cb = NULL,
};

struct rc_connection_state_cb_t {
  bool rc_state;
  bool bt_state;
  RawAddress raw_address;
};

struct rc_feature_cb_t {
  int feature;
  RawAddress raw_address;
};

static std::promise<rc_connection_state_cb_t> g_btrc_connection_state_promise;
static std::promise<rc_connection_state_cb_t>
    g_btrc_browse_connection_state_promise;
static std::promise<rc_feature_cb_t> g_btrc_feature;

class BtifRcFeatureTest : public BtifRcTest {
 protected:
  void SetUp() override {
    BtifRcTest::SetUp();
    init_ctrl(&btrc_ctrl_callbacks);
    jni_thread.StartUp();
    btrc_ctrl_callbacks.getrcfeatures_cb = [](const RawAddress& bd_addr,
                                              int features) {
      rc_feature_cb_t rc_feature = {
          .feature = features,
          .raw_address = bd_addr,
      };
      g_btrc_feature.set_value(rc_feature);
    };
  }

  void TearDown() override {
    bt_rc_ctrl_callbacks->getrcfeatures_cb = [](const RawAddress& bd_addr,
                                                int features) {};
    BtifRcTest::TearDown();
  }
};

TEST_F(BtifRcFeatureTest, handle_rc_ctrl_features) {
  AVRC_BldCmd_ = 0;
  g_btrc_feature = std::promise<rc_feature_cb_t>();
  std::future<rc_feature_cb_t> future = g_btrc_feature.get_future();
  btif_rc_device_cb_t p_dev;

  p_dev.peer_tg_features =
      (BTA_AV_FEAT_RCTG | BTA_AV_FEAT_ADV_CTRL | BTA_AV_FEAT_RCCT |
       BTA_AV_FEAT_METADATA | BTA_AV_FEAT_VENDOR | BTA_AV_FEAT_BROWSE |
       BTA_AV_FEAT_COVER_ARTWORK);
  p_dev.rc_connected = true;

  handle_rc_ctrl_features(&p_dev);
  CHECK(AVRC_BldCmd_ == 1);

  CHECK(std::future_status::ready == future.wait_for(std::chrono::seconds(2)));
  auto res = future.get();
  LOG_INFO("FEATURES:%d", res.feature);
  CHECK(res.feature == (BTRC_FEAT_ABSOLUTE_VOLUME | BTRC_FEAT_METADATA |
                        BTRC_FEAT_BROWSE | BTRC_FEAT_COVER_ARTWORK));
}

class BtifRcBrowseConnectionTest : public BtifRcTest {
 protected:
  void SetUp() override {
    BtifRcTest::SetUp();
    init_ctrl(&btrc_ctrl_callbacks);
    jni_thread.StartUp();
    btrc_ctrl_callbacks.connection_state_cb = [](bool rc_state, bool bt_state,
                                                 const RawAddress& bd_addr) {
      rc_connection_state_cb_t rc_connection_state = {
          .rc_state = rc_state,
          .bt_state = bt_state,
          .raw_address = bd_addr,
      };
      g_btrc_browse_connection_state_promise.set_value(rc_connection_state);
    };
  }

  void TearDown() override {
    bt_rc_ctrl_callbacks->connection_state_cb =
        [](bool rc_state, bool bt_state, const RawAddress& bd_addr) {};
    BtifRcTest::TearDown();
  }
};

TEST_F(BtifRcBrowseConnectionTest, handle_rc_browse_connect) {
  g_btrc_browse_connection_state_promise =
      std::promise<rc_connection_state_cb_t>();
  std::future<rc_connection_state_cb_t> future =
      g_btrc_browse_connection_state_promise.get_future();

  tBTA_AV_RC_BROWSE_OPEN browse_data = {
      .rc_handle = 0,
      .status = BTA_AV_SUCCESS,
  };

  btif_rc_cb.rc_multi_cb[0].rc_handle = 0;
  btif_rc_cb.rc_multi_cb[0].rc_addr = RawAddress::kEmpty;
  btif_rc_cb.rc_multi_cb[0].rc_state = BTRC_CONNECTION_STATE_CONNECTED;
  btif_rc_cb.rc_multi_cb[0].rc_connected = false;

  /* process unit test  handle_rc_browse_connect */
  handle_rc_browse_connect(&browse_data);
  CHECK(std::future_status::ready == future.wait_for(std::chrono::seconds(2)));
  auto res = future.get();
  CHECK(res.bt_state == true);
}

class BtifRcConnectionTest : public BtifRcTest {
 protected:
  void SetUp() override {
    BtifRcTest::SetUp();
    init_ctrl(&btrc_ctrl_callbacks);
    jni_thread.StartUp();
    btrc_ctrl_callbacks.connection_state_cb = [](bool rc_state, bool bt_state,
                                                 const RawAddress& bd_addr) {
      rc_connection_state_cb_t rc_connection_state = {
          .rc_state = rc_state,
          .bt_state = bt_state,
          .raw_address = bd_addr,
      };
      g_btrc_connection_state_promise.set_value(rc_connection_state);
    };
  }

  void TearDown() override {
    bt_rc_ctrl_callbacks->connection_state_cb =
        [](bool rc_state, bool bt_state, const RawAddress& bd_addr) {};
    BtifRcTest::TearDown();
  }
};

TEST_F(BtifRcConnectionTest, btif_rc_check_pending_cmd) {
  AVRC_BldCmd_ = 0;
  g_btrc_connection_state_promise = std::promise<rc_connection_state_cb_t>();
  std::future<rc_connection_state_cb_t> future =
      g_btrc_connection_state_promise.get_future();

  btif_rc_cb.rc_multi_cb[0].rc_handle = 0xff;
  btif_rc_cb.rc_multi_cb[0].rc_addr = kDeviceAddress;
  btif_rc_cb.rc_multi_cb[0].rc_state = BTRC_CONNECTION_STATE_CONNECTED;
  btif_rc_cb.rc_multi_cb[0].rc_connected = true;
  btif_rc_cb.rc_multi_cb[0].launch_cmd_pending |=
      (RC_PENDING_ACT_REG_VOL | RC_PENDING_ACT_GET_CAP |
       RC_PENDING_ACT_REPORT_CONN);

  btif_rc_check_pending_cmd(kDeviceAddress);
  CHECK(AVRC_BldCmd_ == 1);

  CHECK(std::future_status::ready == future.wait_for(std::chrono::seconds(3)));
  auto res = future.get();
  CHECK(res.rc_state == true);
}

TEST_F(BtifRcConnectionTest, BTA_AV_RC_OPEN_EVT) {
  g_btrc_connection_state_promise = std::promise<rc_connection_state_cb_t>();
  std::future<rc_connection_state_cb_t> future =
      g_btrc_connection_state_promise.get_future();

  /* handle_rc_connect  */
  tBTA_AV data = {
      .rc_open =
          {
              .rc_handle = 0,
              .cover_art_psm = 0,
              .peer_features = 0,
              .peer_ct_features = 0,
              .peer_tg_features = (BTA_AV_FEAT_METADATA | BTA_AV_FEAT_VENDOR |
                                   BTA_AV_FEAT_RCTG | BTA_AV_FEAT_RCCT),
              .peer_addr = kDeviceAddress,
              .status = BTA_AV_SUCCESS,
          },
  };
  btif_rc_cb.rc_multi_cb[0].rc_handle = 0;
  btif_rc_cb.rc_multi_cb[0].rc_addr = RawAddress::kEmpty;
  btif_rc_cb.rc_multi_cb[0].rc_state = BTRC_CONNECTION_STATE_DISCONNECTED;
  btif_rc_cb.rc_multi_cb[0].rc_connected = false;

  btif_rc_handler(BTA_AV_RC_OPEN_EVT, &data);

  CHECK(btif_rc_cb.rc_multi_cb[data.rc_open.rc_handle].rc_connected == true);
  CHECK(btif_rc_cb.rc_multi_cb[data.rc_open.rc_handle].rc_state ==
        BTRC_CONNECTION_STATE_CONNECTED);

  CHECK(std::future_status::ready == future.wait_for(std::chrono::seconds(2)));
  auto res = future.get();
  CHECK(res.rc_state == true);
}

class BtifTrackChangeCBTest : public BtifRcTest {
 protected:
  void SetUp() override {
    BtifRcTest::SetUp();
    init_ctrl(&btrc_ctrl_callbacks);
    jni_thread.StartUp();
    btrc_ctrl_callbacks.track_changed_cb = [](const RawAddress& bd_addr,
                       uint8_t num_attr, btrc_element_attr_val_t* p_attrs) {
      btif_rc_cb.rc_multi_cb[0].rc_addr = bd_addr;
    };
  }

  void TearDown() override {
    btrc_ctrl_callbacks.track_changed_cb = [](const RawAddress& bd_addr,
                       uint8_t num_attr, btrc_element_attr_val_t* p_attrs) {};
    BtifRcTest::TearDown();
  }
};

TEST_F(BtifTrackChangeCBTest, handle_get_metadata_attr_response) {
  tBTA_AV_META_MSG meta_msg = {
    .rc_handle = 0,
  };

  tAVRC_GET_ATTRS_RSP rsp = {
    .status = AVRC_STS_NO_ERROR,
    .num_attrs = 0,
  };

  btif_rc_cb.rc_multi_cb[0].rc_handle = 0;
  btif_rc_cb.rc_multi_cb[0].rc_addr = RawAddress::kEmpty;
  btif_rc_cb.rc_multi_cb[0].rc_state = BTRC_CONNECTION_STATE_CONNECTED;
  btif_rc_cb.rc_multi_cb[0].rc_connected = true;

  handle_get_metadata_attr_response(&meta_msg, &rsp);

  ASSERT_EQ(1, get_func_call_count("osi_free_and_reset"));
}
