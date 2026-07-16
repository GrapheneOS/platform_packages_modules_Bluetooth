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

#include "btif/include/btif_rc.h"

#include <bluetooth/log.h>
#include <bluetooth/types/address.h>
#include <gtest/gtest.h>
#include <hardware/bluetooth.h>
#include <unistd.h>

#include <cstdint>
#include <future>
#include <shared_mutex>

#include "btif/avrcp/avrcp_service.h"
#include "btif/include/btif_av.h"
#include "btif/include/btif_common.h"
#include "btif_status.h"
#include "common/message_loop_thread.h"
#include "device/include/interop.h"
#include "include/bt_status.h"
#include "include/hardware/bt_rc.h"
#include "stack/include/main_thread.h"
#include "test/common/mock_functions.h"
#include "test/mock/mock_osi_alarm.h"
#include "test/mock/mock_osi_allocator.h"
#include "test/mock/mock_osi_list.h"

using namespace bluetooth;

namespace bluetooth {
namespace avrcp {
int VolChanged = 0;
AvrcpService* AvrcpService::instance_ = nullptr;

void AvrcpService::SendMediaUpdate(bool /*track_changed*/, bool /*play_state*/, bool /*queue*/) {}
void AvrcpService::SendFolderUpdate(bool /*available_players*/, bool /*addressed_players*/,
                                    bool /*uids*/) {}
void AvrcpService::SendPlayerSettingsChanged(std::vector<PlayerAttribute> /*attributes*/,
                                             std::vector<uint8_t> /*values*/) {}
void AvrcpService::ServiceInterfaceImpl::Init(
        MediaInterface* /*media_interface*/, VolumeInterface* /*volume_interface*/,
        PlayerSettingsInterface* /*player_settings_interface*/) {}
void AvrcpService::ServiceInterfaceImpl::RegisterBipServer(int /*psm*/) {}
void AvrcpService::ServiceInterfaceImpl::UnregisterBipServer() {}
bool AvrcpService::ServiceInterfaceImpl::ConnectDevice(const RawAddress& /*bdaddr*/) {
  return true;
}
bool AvrcpService::ServiceInterfaceImpl::DisconnectDevice(const RawAddress& /*bdaddr*/) {
  return true;
}
void AvrcpService::ServiceInterfaceImpl::SetBipClientStatus(const RawAddress& /*bdaddr*/,
                                                            bool /*connected*/) {}
bool AvrcpService::ServiceInterfaceImpl::Cleanup() { return true; }

AvrcpService* AvrcpService::Get() {
  if (instance_ == nullptr) {
    instance_ = new AvrcpService();
  }
  return instance_;
}

void AvrcpService::RegisterVolChanged(const RawAddress& /*bdaddr*/) { VolChanged++; }
}  // namespace avrcp
}  // namespace bluetooth

namespace {
const RawAddress kDeviceAddress("11:22:33:44:55:66");
const uint8_t kRcHandle = 123;
}  // namespace

void btif_av_clear_remote_suspend_flag(const A2dpType /*local_a2dp_type*/) {}
bool btif_av_is_connected(const A2dpType /*local_a2dp_type*/) { return true; }
bool btif_av_is_sink_enabled(void) { return true; }
RawAddress btif_av_sink_active_peer(void) { return RawAddress(); }
RawAddress btif_av_source_active_peer(void) { return RawAddress(); }
bool btif_av_stream_started_ready(const A2dpType /*local_a2dp_type*/) { return false; }
BtStatus btif_transfer_context(tBTIF_CBACK* p_cback, uint16_t event, char* p_params,
                               int param_len, tBTIF_COPY_CBACK* p_copy_cback) {
  inc_func_call_count("btif_transfer_context");
  if (p_cback) {
    if (param_len > 0 && p_params != nullptr) {
      if (p_copy_cback) {
        std::vector<char> buf(param_len);
        p_copy_cback(event, buf.data(), p_params);
        p_cback(event, buf.data());
      } else {
        std::vector<char> buf(p_params, p_params + param_len);
        p_cback(event, buf.data());
      }
    } else {
      p_cback(event, nullptr);
    }
  }
  return BtifStatus();
}
static bool btif_av_src_sink_coexist_enabled_value = true;
static void set_btif_av_src_sink_coexist_enabled(bool value) {
  btif_av_src_sink_coexist_enabled_value = value;
}
bool btif_av_src_sink_coexist_enabled() { return btif_av_src_sink_coexist_enabled_value; }
bool btif_av_is_connected_addr(const RawAddress& /*peer_address*/,
                               const A2dpType /*local_a2dp_type*/) {
  return true;
}
bool btif_av_peer_is_connected_sink(const RawAddress& /*peer_address*/) { return false; }
bool btif_av_peer_is_connected_source(const RawAddress& /*peer_address*/) { return true; }
bool btif_av_peer_is_sink(const RawAddress& /*peer_address*/) { return false; }
bool btif_av_peer_is_source(const RawAddress& /*peer_address*/) { return true; }
bool btif_av_both_enable(void) { return true; }

static std::shared_mutex g_jni_shared_mutex;
static bluetooth::common::MessageLoopThread* g_jni_thread{nullptr};
static void set_thread(bluetooth::common::MessageLoopThread* thread) {
  std::unique_lock<std::shared_mutex> lock(g_jni_shared_mutex);
  g_jni_thread = thread;
}
static void release_thread() { set_thread(nullptr); }

BtStatus do_in_jni_thread(base::OnceClosure task) {
  std::shared_lock<std::shared_mutex> lock(g_jni_shared_mutex);
  if (g_jni_thread && !g_jni_thread->DoInThread(std::move(task))) {
    log::error("Post task to task runner failed!");
    return BtifStatus(JNI_THREAD_ATTACH_ERROR);
  }
  return BtifStatus();
}
bluetooth::common::MessageLoopThread* get_main_thread() { return nullptr; }
bool interop_match_addr(const interop_feature_t /*feature*/, RawAddress /*addr*/) { return false; }

/**
 * Test class to test selected functionality in hci/src/hci_layer.cc
 */
class BtifRcTest : public ::testing::Test {
public:
  BtifRcTest() : jni_thread("bt_test_jni_thread") {}

protected:
  void SetUp() override {
    reset_mock_function_count_map();
    set_thread(&jni_thread);
  }
  void TearDown() override { release_thread(); }

  bluetooth::common::MessageLoopThread jni_thread;
};

static btif_rc_device_cb_t* allocate_dev(
        int i, const RawAddress& bd_addr = kDeviceAddress,
        btrc_connection_state_t state = BTRC_CONNECTION_STATE_CONNECTED, uint8_t handle = 0) {
  btif_rc_device_cb_t* p_dev =
          bluetooth::testing::avrc::btif_rc_ctrl_get_interface()->get_device_cb(i);
  if (p_dev != nullptr) {
    p_dev->rc_addr = bd_addr;
    p_dev->rc_state = state;
    p_dev->rc_handle = handle;
    for (int i = 0; i < MAX_TRANSACTIONS_PER_SESSION; i++) {
      p_dev->transaction_set.transaction[i].in_use = false;
      p_dev->transaction_set.transaction[i].label = 0xff;
      p_dev->transaction_set.transaction[i].timer = nullptr;
    }
  }
  return p_dev;
}

TEST_F(BtifRcTest, btif_rc_get_addr_by_handle) {
  ASSERT_NE(allocate_dev(0), nullptr);
  RawAddress bd_addr;
  btif_rc_get_addr_by_handle(0, bd_addr);
  ASSERT_EQ(kDeviceAddress, bd_addr);
}

TEST_F(BtifRcTest, btif_rc_is_connected_peer) {
  ASSERT_NE(allocate_dev(0), nullptr);
  ASSERT_TRUE(btif_rc_is_connected_peer(kDeviceAddress));
}

TEST_F(BtifRcTest, btif_rc_is_connected_peer_false) {
  ASSERT_NE(allocate_dev(0), nullptr);
  ASSERT_FALSE(btif_rc_is_connected_peer(RawAddress("00:00:00:00:00:00")));
}

static btrc_ctrl_callbacks_t default_btrc_ctrl_callbacks = {
        .size = sizeof(btrc_ctrl_callbacks_t),
        .passthrough_rsp_cb = [](const RawAddress& /* bd_addr */, int /* id */,
                                 int /* key_state */) { FAIL(); },
        .groupnavigation_rsp_cb = [](int /* id */, int /* key_state */) { FAIL(); },
        .connection_state_cb = [](const RawAddress& /* bd_addr */,
                                  btrc_connection_state_t /* rc_state */,
                                  btrc_connection_state_t /* browse_state */) { FAIL(); },
        .getrcfeatures_cb = [](const RawAddress& /* bd_addr */, int /* features */) { FAIL(); },
        .setplayerappsetting_rsp_cb = [](const RawAddress& /* bd_addr */,
                                         uint8_t /* accepted */) { FAIL(); },
        .playerapplicationsetting_cb = [](const RawAddress& /* bd_addr */, uint8_t /* num_attr */,
                                          btrc_player_app_attr_t* /* app_attrs */) { FAIL(); },
        .playerapplicationsetting_changed_cb =
                [](const RawAddress& /* bd_addr */, const btrc_player_settings_t& /* vals */) {
                  FAIL();
                },
        .setabsvol_cmd_cb = [](const RawAddress& /* bd_addr */, uint8_t /* abs_vol */,
                               uint8_t /* label */) { FAIL(); },
        .registernotification_absvol_cb = [](const RawAddress& /* bd_addr */,
                                             uint8_t /* label */) { FAIL(); },
        .track_changed_cb = [](const RawAddress& /* bd_addr */, uint8_t /* num_attr */,
                               btrc_element_attr_val_t* /* p_attrs */) { FAIL(); },
        .play_position_changed_cb = [](const RawAddress& /* bd_addr */, uint32_t /* song_len */,
                                       uint32_t /* song_pos */) { FAIL(); },
        .play_status_changed_cb = [](const RawAddress& /* bd_addr */,
                                     btrc_play_status_t /* play_status */) { FAIL(); },
        .get_folder_items_cb = [](const RawAddress& /* bd_addr */, btrc_status_t /* status */,
                                  const btrc_folder_items_t* /* folder_items */,
                                  uint8_t /* count */) { FAIL(); },
        .change_folder_path_cb = [](const RawAddress& /* bd_addr */,
                                    uint32_t /* count */) { FAIL(); },
        .set_browsed_player_cb = [](const RawAddress& /* bd_addr */, uint8_t /* num_items */,
                                    uint8_t /* depth */) { FAIL(); },
        .set_addressed_player_cb = [](const RawAddress& /* bd_addr */,
                                      uint8_t /* status */) { FAIL(); },
        .addressed_player_changed_cb = [](const RawAddress& /* bd_addr */,
                                          uint16_t /* id */) { FAIL(); },
        .now_playing_contents_changed_cb = [](const RawAddress& /* bd_addr */) { FAIL(); },
        .available_player_changed_cb = [](const RawAddress& /* bd_addr */) { FAIL(); },
        .get_cover_art_psm_cb = [](const RawAddress& /* bd_addr */,
                                   const uint16_t /* psm */) { FAIL(); },
};
static btrc_ctrl_callbacks_t btrc_ctrl_callbacks = default_btrc_ctrl_callbacks;

struct rc_connection_state_cb_t {
  btrc_connection_state_t rc_state;
  btrc_connection_state_t bt_state;
  RawAddress raw_address;
};

struct rc_feature_cb_t {
  int feature;
  RawAddress raw_address;
};

static std::promise<rc_connection_state_cb_t> g_btrc_connection_state_promise;
static std::promise<rc_feature_cb_t> g_btrc_feature;

class BtifRcWithCallbacksTest : public BtifRcTest {
protected:
  void SetUp() override {
    BtifRcTest::SetUp();
    btrc_ctrl_callbacks = default_btrc_ctrl_callbacks;
    ASSERT_TRUE(btif_rc_ctrl_get_interface()->init(&btrc_ctrl_callbacks).isSuccess());
    jni_thread.StartUp();
    btrc_ctrl_callbacks.getrcfeatures_cb = [](const RawAddress& bd_addr, int features) {
      rc_feature_cb_t rc_feature = {
              .feature = features,
              .raw_address = bd_addr,
      };
      g_btrc_feature.set_value(rc_feature);
    };
    allocate_dev(0, kDeviceAddress, BTRC_CONNECTION_STATE_CONNECTED, kRcHandle);
  }

  void TearDown() override {
    jni_thread.Suspend();
    btif_rc_ctrl_get_interface()->cleanup();
    btrc_ctrl_callbacks = default_btrc_ctrl_callbacks;
    set_btif_av_src_sink_coexist_enabled(true);
    BtifRcTest::TearDown();
  }
};

TEST_F(BtifRcWithCallbacksTest, send_groupnavigation_cmd_test) {
  btif_rc_device_cb_t* p_dev = allocate_dev(0);
  p_dev->rc_features = BTA_AV_FEAT_ADV_CTRL | BTA_AV_FEAT_RCTG;
  BtStatus status = btif_rc_ctrl_get_interface()->send_group_navigation_cmd(kDeviceAddress, 0, 0);
  ASSERT_EQ(status, BtifStatus());
  ASSERT_EQ(1, get_func_call_count("BTA_AvRemoteVendorUniqueCmd"));
}
TEST_F(BtifRcWithCallbacksTest, volume_change_notification_rsp_test) {
  BtStatus status = btif_rc_ctrl_get_interface()->register_abs_vol_rsp(
          kDeviceAddress, BTRC_NOTIFICATION_TYPE_INTERIM, 1, true);
  ASSERT_EQ(status, BtifStatus());
}

TEST_F(BtifRcWithCallbacksTest, set_volume_rsp_test) {
  BtStatus status = btif_rc_ctrl_get_interface()->set_volume_rsp(kDeviceAddress, 100, 1);
  ASSERT_EQ(status, BtifStatus());
}

TEST_F(BtifRcWithCallbacksTest, get_play_status_cmd_test) {
  btif_rc_device_cb_t* p_dev = allocate_dev(0);
  BtStatus status =
          bluetooth::testing::avrc::btif_rc_ctrl_get_interface()->get_play_status_cmd(p_dev);
  ASSERT_EQ(status, BtifStatus());
}

TEST_F(BtifRcWithCallbacksTest, get_element_attribute_cmd_test) {
  btif_rc_device_cb_t* p_dev = allocate_dev(0);
  uint32_t attrs[] = {AVRC_MEDIA_ATTR_ID_TITLE};
  BtStatus status =
          bluetooth::testing::avrc::btif_rc_ctrl_get_interface()->get_element_attribute_cmd(
                  1, attrs, p_dev);
  ASSERT_EQ(status, BtifStatus());
}

TEST_F(BtifRcWithCallbacksTest, register_notification_cmd_test) {
  btif_rc_device_cb_t* p_dev = allocate_dev(0);
  BtStatus status =
          bluetooth::testing::avrc::btif_rc_ctrl_get_interface()->register_notification_cmd(
                  AVRC_EVT_PLAY_STATUS_CHANGE, 0, p_dev);
  ASSERT_EQ(status, BtifStatus());
}

TEST_F(BtifRcWithCallbacksTest, get_player_app_setting_value_text_cmd_test) {
  btif_rc_device_cb_t* p_dev = allocate_dev(0);
  uint8_t vals[] = {AVRC_PLAYER_SETTING_REPEAT};
  BtStatus status = bluetooth::testing::avrc::btif_rc_ctrl_get_interface()
                            ->get_player_app_setting_value_text_cmd(vals, 1, p_dev);
  ASSERT_EQ(status, BtifStatus());
}

TEST_F(BtifRcWithCallbacksTest, get_player_app_setting_attr_text_cmd_test) {
  btif_rc_device_cb_t* p_dev = allocate_dev(0);
  uint8_t attrs[] = {AVRC_PLAYER_SETTING_REPEAT};
  BtStatus status = bluetooth::testing::avrc::btif_rc_ctrl_get_interface()
                            ->get_player_app_setting_attr_text_cmd(attrs, 1, p_dev);
  ASSERT_EQ(status, BtifStatus());
}

TEST_F(BtifRcWithCallbacksTest, play_item_cmd_test) {
  uint8_t uid[] = {0, 0, 0, 0, 0, 0, 0, 0};
  BtStatus status = btif_rc_ctrl_get_interface()->play_item_cmd(kDeviceAddress, 0, uid, 0);
  ASSERT_EQ(status, BtifStatus(NOT_READY));
}

TEST_F(BtifRcWithCallbacksTest, get_folder_items_cmd_test) {
  btif_rc_device_cb_t* p_dev = allocate_dev(0);
  p_dev->br_state = BTRC_CONNECTION_STATE_CONNECTED;
  BtStatus status = bluetooth::testing::avrc::btif_rc_ctrl_get_interface()->get_folder_items_cmd(
          kDeviceAddress, 0, 0, 0);
  ASSERT_EQ(status, BtifStatus(FAIL));
}

TEST_F(BtifRcWithCallbacksTest, set_addressed_player_cmd_test) {
  btif_rc_device_cb_t* p_dev = allocate_dev(0);
  p_dev->br_state = BTRC_CONNECTION_STATE_CONNECTED;
  BtStatus status = btif_rc_ctrl_get_interface()->set_addressed_player_cmd(kDeviceAddress, 1);
  ASSERT_EQ(status, BtifStatus(FAIL));
}

TEST_F(BtifRcWithCallbacksTest, set_browsed_player_cmd_test) {
  btif_rc_device_cb_t* p_dev = allocate_dev(0);
  p_dev->br_state = BTRC_CONNECTION_STATE_CONNECTED;
  BtStatus status = btif_rc_ctrl_get_interface()->set_browsed_player_cmd(kDeviceAddress, 1);
  ASSERT_EQ(status, BtifStatus(FAIL));
}

TEST_F(BtifRcWithCallbacksTest, handle_rc_ctrl_features) {
  g_btrc_feature = std::promise<rc_feature_cb_t>();
  std::future<rc_feature_cb_t> future = g_btrc_feature.get_future();
  btif_rc_device_cb_t p_dev;

  p_dev.peer_tg_features =
          (BTA_AV_FEAT_RCTG | BTA_AV_FEAT_ADV_CTRL | BTA_AV_FEAT_RCCT | BTA_AV_FEAT_METADATA |
           BTA_AV_FEAT_VENDOR | BTA_AV_FEAT_BROWSE | BTA_AV_FEAT_COVER_ARTWORK);
  p_dev.rc_state = BTRC_CONNECTION_STATE_CONNECTED;

  bluetooth::testing::avrc::btif_rc_ctrl_get_interface()->handle_rc_ctrl_features(&p_dev);

  ASSERT_EQ(std::future_status::ready, future.wait_for(std::chrono::seconds(2)));
  auto res = future.get();
  log::info("FEATURES:{}", res.feature);
  ASSERT_EQ(res.feature, BTRC_FEAT_ABSOLUTE_VOLUME | BTRC_FEAT_METADATA | BTRC_FEAT_BROWSE |
                                 BTRC_FEAT_COVER_ARTWORK);
}

TEST_F(BtifRcWithCallbacksTest, handle_rc_ctrl_features_coexist_disabled) {
  set_btif_av_src_sink_coexist_enabled(false);

  g_btrc_feature = std::promise<rc_feature_cb_t>();
  std::future<rc_feature_cb_t> future = g_btrc_feature.get_future();
  btif_rc_device_cb_t p_dev;
  p_dev.rc_addr = kDeviceAddress;
  p_dev.rc_handle = kRcHandle;
  p_dev.rc_features =
          (BTA_AV_FEAT_RCTG | BTA_AV_FEAT_ADV_CTRL | BTA_AV_FEAT_RCCT | BTA_AV_FEAT_METADATA |
           BTA_AV_FEAT_VENDOR | BTA_AV_FEAT_BROWSE | BTA_AV_FEAT_COVER_ARTWORK);
  p_dev.rc_features_processed = false;

  bluetooth::testing::avrc::btif_rc_ctrl_get_interface()->handle_rc_ctrl_features(&p_dev);

  ASSERT_EQ(std::future_status::ready, future.wait_for(std::chrono::seconds(2)));
  auto res = future.get();
  log::info("FEATURES:{}", res.feature);
  ASSERT_EQ(res.feature, BTRC_FEAT_ABSOLUTE_VOLUME | BTRC_FEAT_METADATA | BTRC_FEAT_BROWSE |
                                 BTRC_FEAT_COVER_ARTWORK);
}

TEST_F(BtifRcTest, handle_track_change_notification_response) {
  btif_rc_device_cb_t* p_dev =
          allocate_dev(0, kDeviceAddress, BTRC_CONNECTION_STATE_CONNECTED, kRcHandle);
  p_dev->br_state = BTRC_CONNECTION_STATE_CONNECTED;
  p_dev->rc_features = {};
  p_dev->rc_cover_art_psm = 0;
  p_dev->rc_volume = 0;
  p_dev->rc_vol_label = 0;
  p_dev->rc_supported_event_list = nullptr;
  p_dev->rc_app_settings = {};
  p_dev->rc_play_status_timer = nullptr;
  p_dev->rc_features_processed = false;
  p_dev->rc_playing_uid = 0;
  p_dev->rc_procedure_complete = false;
  p_dev->peer_ct_features = {};
  p_dev->peer_tg_features = {};
  p_dev->launch_cmd_pending = 0;
  ASSERT_TRUE(bluetooth::testing::avrc::btif_rc_ctrl_get_interface()->btif_rc_get_device_by_handle(
          kRcHandle));
  tBTA_AV_META_MSG meta_msg = {
          .rc_handle = kRcHandle,
          .len = 0,
          .label = 0,
          .code = AVRC_RSP_CHANGED,
          .company_id = 0,
          .p_data = {},
          .p_msg = nullptr,
  };
  tAVRC_NOTIF_RSP_PARAM param = {
          .track = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
  };
  tAVRC_REG_NOTIF_RSP track_change = {
          .pdu = 0,
          .status = AVRC_STS_NO_ERROR,
          .opcode = 0,
          .event_id = AVRC_EVT_TRACK_CHANGE,
          .param = param,
  };
  uint64_t now_playing_uid = 0x01;

  bluetooth::testing::avrc::btif_rc_ctrl_get_interface()->handle_notification_response(
          &meta_msg, &track_change);
  ASSERT_EQ(p_dev->rc_playing_uid, now_playing_uid);
}

TEST_F(BtifRcTest, handle_app_attr_response) {
  btif_rc_device_cb_t* p_dev =
          allocate_dev(0, kDeviceAddress, BTRC_CONNECTION_STATE_CONNECTED, kRcHandle);
  tBTA_AV_META_MSG meta_msg = {
          .rc_handle = kRcHandle,
          .code = AVRC_RSP_CHANGED,
  };
  tAVRC_LIST_APP_ATTR_RSP app_attr_rsp = {
          .pdu = 0,
          .status = AVRC_STS_NO_ERROR,
          .opcode = 0,
          .num_attr = 2,
          .attrs = {AVRC_PLAYER_SETTING_LOW_MENU_EXT, AVRC_PLAYER_SETTING_HIGH_MENU_EXT}};
  bluetooth::testing::avrc::btif_rc_ctrl_get_interface()->handle_app_attr_response(&meta_msg,
                                                                                   &app_attr_rsp);
}

TEST_F(BtifRcWithCallbacksTest, handle_notifications_rsp_play_status_changed) {
  btrc_ctrl_callbacks.play_status_changed_cb = [](const RawAddress& /* bd_addr */,
                                                  btrc_play_status_t /* play_status */) {};
  btif_rc_device_cb_t* p_dev =
          allocate_dev(0, kDeviceAddress, BTRC_CONNECTION_STATE_CONNECTED, kRcHandle);
  tAVRC_NOTIF_RSP_PARAM param = {
          .track = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
  };
  tBTA_AV_META_MSG meta_msg = {
          .rc_handle = kRcHandle,
          .code = AVRC_RSP_INTERIM,
  };
  tAVRC_REG_NOTIF_RSP track_change = {
          .pdu = 0,
          .status = AVRC_STS_NO_ERROR,
          .opcode = 0,
          .event_id = AVRC_EVT_PLAY_STATUS_CHANGE,
          .param = param,
  };

  bluetooth::testing::avrc::btif_rc_ctrl_get_interface()->handle_notification_response(
          &meta_msg, &track_change);
}

TEST_F(BtifRcWithCallbacksTest, handle_notifications_evt_track_change) {
  btif_rc_device_cb_t* p_dev =
          allocate_dev(0, kDeviceAddress, BTRC_CONNECTION_STATE_CONNECTED, kRcHandle);
  tAVRC_NOTIF_RSP_PARAM param = {
          .track = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
  };
  tBTA_AV_META_MSG meta_msg = {
          .rc_handle = kRcHandle,
          .code = AVRC_RSP_INTERIM,
  };
  tAVRC_REG_NOTIF_RSP track_change = {
          .pdu = 0,
          .status = AVRC_STS_NO_ERROR,
          .opcode = 0,
          .event_id = AVRC_EVT_TRACK_CHANGE,
          .param = param,
  };

  bluetooth::testing::avrc::btif_rc_ctrl_get_interface()->handle_notification_response(
          &meta_msg, &track_change);
}

TEST_F(BtifRcWithCallbacksTest, handle_notifications_evt_app_setting_changed) {
  btif_rc_device_cb_t* p_dev =
          allocate_dev(0, kDeviceAddress, BTRC_CONNECTION_STATE_CONNECTED, kRcHandle);
  tAVRC_NOTIF_RSP_PARAM param = {
          .track = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
  };
  tBTA_AV_META_MSG meta_msg = {
          .rc_handle = kRcHandle,
          .code = AVRC_RSP_INTERIM,
  };
  tAVRC_REG_NOTIF_RSP track_change = {
          .pdu = 0,
          .status = AVRC_STS_NO_ERROR,
          .opcode = 0,
          .event_id = AVRC_EVT_APP_SETTING_CHANGE,
          .param = param,
  };

  bluetooth::testing::avrc::btif_rc_ctrl_get_interface()->handle_notification_response(
          &meta_msg, &track_change);
}

TEST_F(BtifRcWithCallbacksTest, handle_notifications_evt_now_playing) {
  btrc_ctrl_callbacks.now_playing_contents_changed_cb = [](const RawAddress& /* bd_addr */) {};
  btif_rc_device_cb_t* p_dev =
          allocate_dev(0, kDeviceAddress, BTRC_CONNECTION_STATE_CONNECTED, kRcHandle);
  tAVRC_NOTIF_RSP_PARAM param = {
          .track = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
  };
  tBTA_AV_META_MSG meta_msg = {
          .rc_handle = kRcHandle,
          .code = AVRC_RSP_INTERIM,
  };
  tAVRC_REG_NOTIF_RSP track_change = {
          .pdu = 0,
          .status = AVRC_STS_NO_ERROR,
          .opcode = 0,
          .event_id = AVRC_EVT_NOW_PLAYING_CHANGE,
          .param = param,
  };

  bluetooth::testing::avrc::btif_rc_ctrl_get_interface()->handle_notification_response(
          &meta_msg, &track_change);
}

TEST_F(BtifRcWithCallbacksTest, handle_notifications_rsp_evt_aval_players_change) {
  btrc_ctrl_callbacks.available_player_changed_cb = [](const RawAddress& /* bd_addr */) {};
  btif_rc_device_cb_t* p_dev =
          allocate_dev(0, kDeviceAddress, BTRC_CONNECTION_STATE_CONNECTED, kRcHandle);
  tAVRC_NOTIF_RSP_PARAM param = {
          .track = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
  };
  tBTA_AV_META_MSG meta_msg = {
          .rc_handle = kRcHandle,
          .code = AVRC_RSP_INTERIM,
  };
  tAVRC_REG_NOTIF_RSP track_change = {
          .pdu = 0,
          .status = AVRC_STS_NO_ERROR,
          .opcode = 0,
          .event_id = AVRC_EVT_AVAL_PLAYERS_CHANGE,
          .param = param,
  };

  bluetooth::testing::avrc::btif_rc_ctrl_get_interface()->handle_notification_response(
          &meta_msg, &track_change);
}

TEST_F(BtifRcWithCallbacksTest, handle_notifications_rsp_evt_addrs_player_change) {
  btrc_ctrl_callbacks.addressed_player_changed_cb = [](const RawAddress& /* bd_addr */,
                                                       uint16_t /* player_id */) {};
  btif_rc_device_cb_t* p_dev =
          allocate_dev(0, kDeviceAddress, BTRC_CONNECTION_STATE_CONNECTED, kRcHandle);
  tAVRC_NOTIF_RSP_PARAM param = {
          .track = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
  };
  tBTA_AV_META_MSG meta_msg = {
          .rc_handle = kRcHandle,
          .code = AVRC_RSP_INTERIM,
  };
  tAVRC_REG_NOTIF_RSP track_change = {
          .pdu = 0,
          .status = AVRC_STS_NO_ERROR,
          .opcode = 0,
          .event_id = AVRC_EVT_ADDR_PLAYER_CHANGE,
          .param = param,
  };

  bluetooth::testing::avrc::btif_rc_ctrl_get_interface()->handle_notification_response(
          &meta_msg, &track_change);
}

TEST_F(BtifRcWithCallbacksTest, handle_notifications_rsp_evt_play_pos_change) {
  btrc_ctrl_callbacks.play_position_changed_cb =
          [](const RawAddress& /* bd_addr */, uint32_t /*song_len*/, uint32_t /* song_pos */) {};
  btif_rc_device_cb_t* p_dev =
          allocate_dev(0, kDeviceAddress, BTRC_CONNECTION_STATE_CONNECTED, kRcHandle);
  tAVRC_NOTIF_RSP_PARAM param = {
          .track = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
  };
  tBTA_AV_META_MSG meta_msg = {
          .rc_handle = kRcHandle,
          .code = AVRC_RSP_INTERIM,
  };
  tAVRC_REG_NOTIF_RSP track_change = {
          .pdu = 0,
          .status = AVRC_STS_NO_ERROR,
          .opcode = 0,
          .event_id = AVRC_EVT_PLAY_POS_CHANGED,
          .param = param,
  };

  bluetooth::testing::avrc::btif_rc_ctrl_get_interface()->handle_notification_response(
          &meta_msg, &track_change);
}

TEST_F(BtifRcWithCallbacksTest, handle_notifications_evt_uids_change) {
  btif_rc_device_cb_t* p_dev =
          allocate_dev(0, kDeviceAddress, BTRC_CONNECTION_STATE_CONNECTED, kRcHandle);
  tAVRC_NOTIF_RSP_PARAM param = {
          .track = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
  };
  tBTA_AV_META_MSG meta_msg = {
          .rc_handle = kRcHandle,
          .code = AVRC_RSP_INTERIM,
  };
  tAVRC_REG_NOTIF_RSP track_change = {
          .pdu = 0,
          .status = AVRC_STS_NO_ERROR,
          .opcode = 0,
          .event_id = AVRC_EVT_UIDS_CHANGE,
          .param = param,
  };

  bluetooth::testing::avrc::btif_rc_ctrl_get_interface()->handle_notification_response(
          &meta_msg, &track_change);
}

TEST_F(BtifRcWithCallbacksTest, handle_notifications_default) {
  btif_rc_device_cb_t* p_dev =
          allocate_dev(0, kDeviceAddress, BTRC_CONNECTION_STATE_CONNECTED, kRcHandle);
  tAVRC_NOTIF_RSP_PARAM param = {
          .track = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
  };
  tBTA_AV_META_MSG meta_msg = {
          .rc_handle = kRcHandle,
          .code = AVRC_RSP_INTERIM,
  };

  std::vector<uint8_t> event_ids = {AVRC_EVT_TRACK_REACHED_END, AVRC_EVT_TRACK_REACHED_START,
                                    AVRC_EVT_BATTERY_STATUS_CHANGE, AVRC_EVT_SYSTEM_STATUS_CHANGE};
  tAVRC_REG_NOTIF_RSP track_change = {
          .pdu = 0,
          .status = AVRC_STS_NO_ERROR,
          .opcode = 0,
          .event_id = 0,
          .param = param,
  };
  for (uint8_t i = 0; i < 4; i++) {
    track_change.event_id = event_ids[i];
    bluetooth::testing::avrc::btif_rc_ctrl_get_interface()->handle_notification_response(
            &meta_msg, &track_change);
    track_change.event_id = 0;
  }
}

TEST_F(BtifRcWithCallbacksTest, handle_notifications_rsp_changed_play_status_change) {
  btrc_ctrl_callbacks.play_status_changed_cb = [](const RawAddress& /* bd_addr */,
                                                  btrc_play_status_t /* play_status */) {};
  btif_rc_device_cb_t* p_dev =
          allocate_dev(0, kDeviceAddress, BTRC_CONNECTION_STATE_CONNECTED, kRcHandle);
  tAVRC_NOTIF_RSP_PARAM param = {
          .track = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
  };
  tBTA_AV_META_MSG meta_msg = {
          .rc_handle = kRcHandle,
          .code = AVRC_RSP_CHANGED,
  };
  tAVRC_REG_NOTIF_RSP track_change = {
          .pdu = 0,
          .status = AVRC_STS_NO_ERROR,
          .opcode = 0,
          .event_id = AVRC_EVT_PLAY_STATUS_CHANGE,
          .param = param,
  };

  bluetooth::testing::avrc::btif_rc_ctrl_get_interface()->handle_notification_response(
          &meta_msg, &track_change);
}

TEST_F(BtifRcWithCallbacksTest, handle_notifications_rsp_changed_evt_app_settings_change) {
  btrc_ctrl_callbacks.playerapplicationsetting_changed_cb =
          [](const RawAddress& /* bd_addr */, const btrc_player_settings_t& /* player_settings */) {
          };
  btif_rc_device_cb_t* p_dev =
          allocate_dev(0, kDeviceAddress, BTRC_CONNECTION_STATE_CONNECTED, kRcHandle);
  tAVRC_NOTIF_RSP_PARAM param = {
          .track = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
  };
  tBTA_AV_META_MSG meta_msg = {
          .rc_handle = kRcHandle,
          .code = AVRC_RSP_CHANGED,
  };
  tAVRC_REG_NOTIF_RSP track_change = {
          .pdu = 0,
          .status = AVRC_STS_NO_ERROR,
          .opcode = 0,
          .event_id = AVRC_EVT_APP_SETTING_CHANGE,
          .param = param,
  };

  bluetooth::testing::avrc::btif_rc_ctrl_get_interface()->handle_notification_response(
          &meta_msg, &track_change);
}

TEST_F(BtifRcWithCallbacksTest, handle_notifications_rsp_changed_default) {
  btif_rc_device_cb_t* p_dev =
          allocate_dev(0, kDeviceAddress, BTRC_CONNECTION_STATE_CONNECTED, kRcHandle);
  tAVRC_NOTIF_RSP_PARAM param = {
          .track = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
  };
  tBTA_AV_META_MSG meta_msg = {
          .rc_handle = kRcHandle,
          .code = AVRC_RSP_CHANGED,
  };

  std::vector<uint8_t> event_ids = {AVRC_EVT_NOW_PLAYING_CHANGE,  AVRC_EVT_AVAL_PLAYERS_CHANGE,
                                    AVRC_EVT_ADDR_PLAYER_CHANGE,  AVRC_EVT_PLAY_POS_CHANGED,
                                    AVRC_EVT_UIDS_CHANGE,         AVRC_EVT_TRACK_REACHED_END,
                                    AVRC_EVT_TRACK_REACHED_START, AVRC_EVT_BATTERY_STATUS_CHANGE,
                                    AVRC_EVT_SYSTEM_STATUS_CHANGE};

  tAVRC_REG_NOTIF_RSP track_change = {
          .pdu = 0,
          .status = AVRC_STS_NO_ERROR,
          .opcode = 0,
          .event_id = 0,
          .param = param,
  };
  for (uint8_t i = 0; i < 9; i++) {
    track_change.event_id = event_ids[i];
    bluetooth::testing::avrc::btif_rc_ctrl_get_interface()->handle_notification_response(
            &meta_msg, &track_change);
    track_change.event_id = 0;
  }
}

TEST_F(BtifRcWithCallbacksTest, handle_app_val_response) {
  btrc_ctrl_callbacks.playerapplicationsetting_cb = [](const RawAddress&, uint8_t,
                                                       btrc_player_app_attr_t*) {};

  btif_rc_device_cb_t* p_dev =
          bluetooth::testing::avrc::btif_rc_ctrl_get_interface()->get_device_cb(0);
  p_dev->rc_app_settings.attr_index = 0;
  p_dev->rc_app_settings.num_attrs = 1;
  p_dev->rc_app_settings.attrs[0].attr_id = 1;
  tBTA_AV_META_MSG meta_msg = {
          .rc_handle = kRcHandle,
  };

  tAVRC_LIST_APP_VALUES_RSP app_val_rsp = {
          .status = AVRC_STS_NO_ERROR,
          .num_val = 4,
          .vals = {1, 2, 3, 4},
  };
  bluetooth::testing::avrc::btif_rc_ctrl_get_interface()->handle_app_val_response(&meta_msg,
                                                                                  &app_val_rsp);
  ASSERT_EQ(p_dev->rc_app_settings.attrs[0].num_val, 4);
  ASSERT_EQ(p_dev->rc_app_settings.attr_index, 1u);
}

TEST_F(BtifRcWithCallbacksTest, handle_app_val_response_null_device) {
  tBTA_AV_META_MSG meta_msg = {
          .rc_handle = 0xff,  // Some handle that doesn't exist
  };
  tAVRC_LIST_APP_VALUES_RSP app_val_rsp = {
          .status = AVRC_STS_NO_ERROR,
  };
  // No device is set up, so btif_rc_get_device_by_handle will return NULL
  bluetooth::testing::avrc::btif_rc_ctrl_get_interface()->handle_app_val_response(&meta_msg,
                                                                                  &app_val_rsp);
  // No crash, and error should be logged. Nothing to assert here.
}

TEST_F(BtifRcWithCallbacksTest, handle_app_val_response_error_status) {
  btif_rc_device_cb_t* p_dev =
          bluetooth::testing::avrc::btif_rc_ctrl_get_interface()->get_device_cb(0);
  tBTA_AV_META_MSG meta_msg = {
          .rc_handle = kRcHandle,
  };
  tAVRC_LIST_APP_VALUES_RSP app_val_rsp = {
          .status = AVRC_STS_INTERNAL_ERR,
  };
  bluetooth::testing::avrc::btif_rc_ctrl_get_interface()->handle_app_val_response(&meta_msg,
                                                                                  &app_val_rsp);
  // No crash, and error should be logged. Nothing to assert here.
}

TEST_F(BtifRcWithCallbacksTest, handle_app_val_response_multiple_attrs) {
  btif_rc_device_cb_t* p_dev =
          bluetooth::testing::avrc::btif_rc_ctrl_get_interface()->get_device_cb(0);
  p_dev->rc_app_settings.attr_index = 0;
  p_dev->rc_app_settings.num_attrs = 2;
  p_dev->rc_app_settings.attrs[0].attr_id = 1;
  p_dev->rc_app_settings.attrs[1].attr_id = 2;
  tBTA_AV_META_MSG meta_msg = {
          .rc_handle = kRcHandle,
  };

  tAVRC_LIST_APP_VALUES_RSP app_val_rsp = {
          .status = AVRC_STS_NO_ERROR,
          .num_val = 1,
          .vals = {1},
  };
  bluetooth::testing::avrc::btif_rc_ctrl_get_interface()->handle_app_val_response(&meta_msg,
                                                                                  &app_val_rsp);
  ASSERT_EQ(p_dev->rc_app_settings.attrs[0].num_val, 1);
  ASSERT_EQ(p_dev->rc_app_settings.attr_index, 1u);
  // Check that list_player_app_setting_value_cmd was called
}

TEST_F(BtifRcWithCallbacksTest, handle_app_val_response_with_ext_attrs) {
  btif_rc_device_cb_t* p_dev =
          bluetooth::testing::avrc::btif_rc_ctrl_get_interface()->get_device_cb(0);
  p_dev->rc_app_settings.attr_index = 0;
  p_dev->rc_app_settings.num_attrs = 1;
  p_dev->rc_app_settings.attrs[0].attr_id = 1;
  p_dev->rc_app_settings.num_ext_attrs = 1;
  p_dev->rc_app_settings.ext_attrs[0].attr_id = 0x80;
  p_dev->rc_app_settings.ext_attr_index = 0;

  tBTA_AV_META_MSG meta_msg = {
          .rc_handle = kRcHandle,
  };

  tAVRC_LIST_APP_VALUES_RSP app_val_rsp = {
          .status = AVRC_STS_NO_ERROR,
          .num_val = 1,
          .vals = {1},
  };
  bluetooth::testing::avrc::btif_rc_ctrl_get_interface()->handle_app_val_response(&meta_msg,
                                                                                  &app_val_rsp);
  ASSERT_EQ(p_dev->rc_app_settings.attrs[0].num_val, 1);
  ASSERT_EQ(p_dev->rc_app_settings.attr_index, 1u);
  ASSERT_EQ(p_dev->rc_app_settings.ext_attr_index, 0u);
  // Check that list_player_app_setting_value_cmd was called for ext attr
}

TEST_F(BtifRcWithCallbacksTest, handle_app_val_response_ext_attrs_only) {
  btif_rc_device_cb_t* p_dev =
          bluetooth::testing::avrc::btif_rc_ctrl_get_interface()->get_device_cb(0);
  p_dev->rc_app_settings.attr_index = 0;
  p_dev->rc_app_settings.num_attrs = 0;
  p_dev->rc_app_settings.num_ext_attrs = 1;
  p_dev->rc_app_settings.ext_attrs[0].attr_id = 0x80;
  p_dev->rc_app_settings.ext_attr_index = 0;

  tBTA_AV_META_MSG meta_msg = {
          .rc_handle = kRcHandle,
  };

  tAVRC_LIST_APP_VALUES_RSP app_val_rsp = {
          .status = AVRC_STS_NO_ERROR,
          .num_val = 1,
          .vals = {1},
  };
  bluetooth::testing::avrc::btif_rc_ctrl_get_interface()->handle_app_val_response(&meta_msg,
                                                                                  &app_val_rsp);
  ASSERT_EQ(p_dev->rc_app_settings.ext_attrs[0].num_val, 1);
  ASSERT_EQ(p_dev->rc_app_settings.ext_attr_index, 1u);
  // Check that get_player_app_setting_attr_text_cmd was called
}

TEST_F(BtifRcWithCallbacksTest, handle_app_val_response_multiple_ext_attrs) {
  btif_rc_device_cb_t* p_dev =
          bluetooth::testing::avrc::btif_rc_ctrl_get_interface()->get_device_cb(0);
  p_dev->rc_app_settings.attr_index = 0;
  p_dev->rc_app_settings.num_attrs = 0;
  p_dev->rc_app_settings.num_ext_attrs = 2;
  p_dev->rc_app_settings.ext_attrs[0].attr_id = 0x80;
  p_dev->rc_app_settings.ext_attrs[1].attr_id = 0x81;
  p_dev->rc_app_settings.ext_attr_index = 0;

  tBTA_AV_META_MSG meta_msg = {
          .rc_handle = kRcHandle,
  };

  tAVRC_LIST_APP_VALUES_RSP app_val_rsp = {
          .status = AVRC_STS_NO_ERROR,
          .num_val = 1,
          .vals = {1},
  };
  bluetooth::testing::avrc::btif_rc_ctrl_get_interface()->handle_app_val_response(&meta_msg,
                                                                                  &app_val_rsp);
  ASSERT_EQ(p_dev->rc_app_settings.ext_attrs[0].num_val, 1);
  ASSERT_EQ(p_dev->rc_app_settings.ext_attr_index, 1u);
  // Check that list_player_app_setting_value_cmd was called for the next ext attr
}

class BtifRcConnectionTest : public BtifRcTest {
protected:
  void SetUp() override {
    BtifRcTest::SetUp();
    ASSERT_EQ(btif_rc_ctrl_get_interface()->init(&btrc_ctrl_callbacks), BtifStatus());
    jni_thread.StartUp();
    g_btrc_connection_state_promise = std::promise<rc_connection_state_cb_t>();
    g_btrc_connection_state_future = g_btrc_connection_state_promise.get_future();
    btrc_ctrl_callbacks.connection_state_cb = [](const RawAddress& bd_addr,
                                                 btrc_connection_state_t rc_state,
                                                 btrc_connection_state_t browse_state) {
      rc_connection_state_cb_t rc_connection_state = {
              .rc_state = rc_state,
              .bt_state = browse_state,
              .raw_address = bd_addr,
      };
      g_btrc_connection_state_promise.set_value(rc_connection_state);
    };
  }

  void TearDown() override {
    jni_thread.Suspend();
    btrc_ctrl_callbacks.connection_state_cb = [](const RawAddress& /*bd_addr*/,
                                                 btrc_connection_state_t /*rc_state*/,
                                                 btrc_connection_state_t /*browse_state*/) {};
    btif_rc_ctrl_get_interface()->cleanup();
    BtifRcTest::TearDown();
  }
  std::future<rc_connection_state_cb_t> g_btrc_connection_state_future;
};

TEST_F(BtifRcConnectionTest, handle_rc_browse_connect) {
  tBTA_AV_RC_BROWSE_OPEN browse_data = {
          .rc_handle = 0,
          .peer_addr = {},
          .status = BTA_AV_SUCCESS,
  };

  btif_rc_device_cb_t* p_dev =
          bluetooth::testing::avrc::btif_rc_ctrl_get_interface()->get_device_cb(0);
  p_dev->rc_handle = 0;
  p_dev->rc_addr = RawAddress::kEmpty;
  p_dev->rc_state = BTRC_CONNECTION_STATE_CONNECTED;

  /* process unit test  handle_rc_browse_connect */
  bluetooth::testing::avrc::btif_rc_ctrl_get_interface()->handle_rc_browse_connect(&browse_data);
  ASSERT_EQ(std::future_status::ready,
            g_btrc_connection_state_future.wait_for(std::chrono::seconds(2)));
  auto res = g_btrc_connection_state_future.get();
  ASSERT_TRUE(res.bt_state);
}

TEST_F(BtifRcConnectionTest, btif_rc_check_pending_cmd) {
  btif_rc_device_cb_t* p_dev =
          bluetooth::testing::avrc::btif_rc_ctrl_get_interface()->get_device_cb(0);
  p_dev->rc_handle = 0xff;
  p_dev->rc_addr = kDeviceAddress;
  p_dev->rc_state = BTRC_CONNECTION_STATE_CONNECTED;
  p_dev->launch_cmd_pending |=
          (RC_PENDING_ACT_REG_VOL | RC_PENDING_ACT_GET_CAP | RC_PENDING_ACT_REPORT_CONN);

  btif_rc_check_pending_cmd(kDeviceAddress);

  ASSERT_EQ(std::future_status::ready,
            g_btrc_connection_state_future.wait_for(std::chrono::seconds(3)));
  auto res = g_btrc_connection_state_future.get();
  ASSERT_TRUE(res.rc_state);
}

TEST_F(BtifRcConnectionTest, bt_av_rc_open_evt) {
  btrc_ctrl_callbacks.get_cover_art_psm_cb = [](const RawAddress& /* bd_addr */,
                                                const uint16_t /* psm */) {};
  btrc_ctrl_callbacks.getrcfeatures_cb = [](const RawAddress& /* bd_addr */, int /* features */) {};

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
  btif_rc_device_cb_t* p_dev =
          bluetooth::testing::avrc::btif_rc_ctrl_get_interface()->get_device_cb(0);
  p_dev->rc_handle = 0;
  p_dev->rc_addr = RawAddress::kEmpty;
  p_dev->rc_state = BTRC_CONNECTION_STATE_CONNECTED;

  btif_rc_handler(BTA_AV_RC_OPEN_EVT, &data);

  ASSERT_EQ(bluetooth::testing::avrc::btif_rc_ctrl_get_interface()
                    ->get_device_cb(data.rc_open.rc_handle)
                    ->rc_state,
            BTRC_CONNECTION_STATE_CONNECTED);
  ASSERT_EQ(bluetooth::testing::avrc::btif_rc_ctrl_get_interface()
                    ->get_device_cb(data.rc_open.rc_handle)
                    ->rc_state,
            BTRC_CONNECTION_STATE_CONNECTED);

  ASSERT_EQ(std::future_status::ready,
            g_btrc_connection_state_future.wait_for(std::chrono::seconds(2)));
  auto res = g_btrc_connection_state_future.get();
  ASSERT_TRUE(res.rc_state);
}

TEST_F(BtifRcConnectionTest, bt_av_rc_open_evt_coexist_disabled) {
  set_btif_av_src_sink_coexist_enabled(false);
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
                          .status = BTA_AV_FAIL,
                  },
  };

  btif_rc_device_cb_t* p_dev =
          bluetooth::testing::avrc::btif_rc_ctrl_get_interface()->get_device_cb(0);
  p_dev->rc_handle = 0;
  p_dev->rc_addr = RawAddress::kEmpty;
  p_dev->rc_state = BTRC_CONNECTION_STATE_CONNECTED;

  btif_rc_handler(BTA_AV_RC_OPEN_EVT, &data);
  EXPECT_EQ(p_dev->launch_cmd_pending, 0);
  EXPECT_EQ(p_dev->rc_vol_label, MAX_LABEL);
  EXPECT_EQ(p_dev->rc_volume, static_cast<unsigned int>(MAX_VOLUME));
  EXPECT_EQ(p_dev->rc_addr, RawAddress::kEmpty);
}

TEST_F(BtifRcConnectionTest, bt_av_rc_open_evt_rc_state_connected) {
  btrc_ctrl_callbacks.get_cover_art_psm_cb = [](const RawAddress& /* bd_addr */,
                                                const uint16_t /* psm */) {};
  btrc_ctrl_callbacks.getrcfeatures_cb = [](const RawAddress& /* bd_addr */, int /* features */) {};

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
  btif_rc_device_cb_t* p_dev =
          bluetooth::testing::avrc::btif_rc_ctrl_get_interface()->get_device_cb(0);
  p_dev->rc_handle = 0;
  p_dev->rc_addr = RawAddress::kEmpty;
  p_dev->rc_state = BTRC_CONNECTION_STATE_CONNECTED;

  btif_rc_handler(BTA_AV_RC_OPEN_EVT, &data);
  // no check as function just returns
}

class BtifTrackChangeCBTest : public BtifRcTest {
protected:
  void SetUp() override {
    BtifRcTest::SetUp();
    ASSERT_EQ(btif_rc_ctrl_get_interface()->init(&btrc_ctrl_callbacks), BtifStatus());
    jni_thread.StartUp();
    btrc_ctrl_callbacks.track_changed_cb = [](const RawAddress& bd_addr, uint8_t /*num_attr*/,
                                              btrc_element_attr_val_t* /*p_attrs*/) {
      btif_rc_device_cb_t* p_dev =
              bluetooth::testing::avrc::btif_rc_ctrl_get_interface()->get_device_cb(0);
      p_dev->rc_addr = bd_addr;
    };
  }

  void TearDown() override {
    jni_thread.Suspend();
    btrc_ctrl_callbacks.track_changed_cb = [](const RawAddress& /*bd_addr*/, uint8_t /*num_attr*/,
                                              btrc_element_attr_val_t* /*p_attrs*/) {};
    btif_rc_ctrl_get_interface()->cleanup();
    BtifRcTest::TearDown();
  }
};

TEST_F(BtifTrackChangeCBTest, handle_get_metadata_attr_response) {
  // Setup an already connected device
  btif_rc_device_cb_t* p_dev =
          bluetooth::testing::avrc::btif_rc_ctrl_get_interface()->get_device_cb(0);
  p_dev->rc_state = BTRC_CONNECTION_STATE_CONNECTED;
  p_dev->br_state = BTRC_CONNECTION_STATE_DISCONNECTED;
  p_dev->rc_handle = kRcHandle;
  p_dev->rc_features = {};
  p_dev->rc_cover_art_psm = 0;
  p_dev->rc_addr = kDeviceAddress;
  p_dev->rc_volume = 0;
  p_dev->rc_vol_label = 0;
  p_dev->rc_supported_event_list = nullptr;
  p_dev->rc_app_settings = {};
  p_dev->rc_play_status_timer = nullptr;
  p_dev->rc_features_processed = false;
  p_dev->rc_playing_uid = 0;
  p_dev->rc_procedure_complete = false;
  p_dev->peer_ct_features = {};
  p_dev->peer_tg_features = {};
  p_dev->launch_cmd_pending = 0;
  ASSERT_TRUE(bluetooth::testing::avrc::btif_rc_ctrl_get_interface()->btif_rc_get_device_by_handle(
          kRcHandle));

  tBTA_AV_META_MSG meta_msg = {
          .rc_handle = kRcHandle,
          .len = 0,
          .label = 0,
          .code{},
          .company_id = 0,
          .p_data = {},
          .p_msg = nullptr,
  };

  tAVRC_GET_ATTRS_RSP rsp = {
          .pdu = 0,
          .status = AVRC_STS_NO_ERROR,
          .opcode = 0,
          .num_attrs = 0,
          .p_attrs = nullptr,
  };

  bluetooth::testing::avrc::btif_rc_ctrl_get_interface()->handle_get_metadata_attr_response(
          &meta_msg, &rsp);

  ASSERT_EQ(1, get_func_call_count("osi_free_and_reset"));
}

TEST_F(BtifRcTest, btif_rc_handler_no_op_events) {
  tBTA_AV data{};
  // These events only log and do nothing else.
  btif_rc_handler(BTA_AV_RC_BROWSE_CLOSE_EVT, &data);
  btif_rc_handler(BTA_AV_REMOTE_CMD_EVT, &data);
  // Default case
  btif_rc_handler(BTA_AV_ENABLE_EVT, &data);
}

TEST_F(BtifRcConnectionTest, bt_av_rc_close_evt) {
  // Setup an already connected device
  btif_rc_device_cb_t* p_dev =
          allocate_dev(0, kDeviceAddress, BTRC_CONNECTION_STATE_CONNECTED, kRcHandle);

  // Disconnect
  tBTA_AV close_data = {
          .rc_close =
                  {
                          .rc_handle = kRcHandle,
                          .peer_addr = kDeviceAddress,
                  },
  };
  btif_rc_handler(BTA_AV_RC_CLOSE_EVT, &close_data);

  // Verify disconnected state
  ASSERT_EQ(p_dev->rc_state, BTRC_CONNECTION_STATE_DISCONNECTED);

  // Verify callback
  ASSERT_EQ(std::future_status::ready,
            g_btrc_connection_state_future.wait_for(std::chrono::seconds(2)));
  auto res = g_btrc_connection_state_future.get();
  ASSERT_FALSE(res.rc_state);
  ASSERT_EQ(res.raw_address, kDeviceAddress);
}

// New promises and structs
struct passthrough_rsp_cb_t {
  RawAddress raw_address;
  int id;
  int key_state;
};
static std::promise<passthrough_rsp_cb_t> g_passthrough_rsp_promise;

struct groupnavigation_rsp_cb_t {
  int id;
  int key_state;
};
static std::promise<groupnavigation_rsp_cb_t> g_groupnavigation_rsp_promise;

struct get_cover_art_psm_cb_t {
  RawAddress raw_address;
  uint16_t psm;
};
static std::promise<get_cover_art_psm_cb_t> g_get_cover_art_psm_promise;

struct setabsvol_cmd_cb_t {
  RawAddress raw_address;
  uint8_t abs_vol;
  uint8_t label;
};
static std::promise<setabsvol_cmd_cb_t> g_setabsvol_cmd_promise;

struct registernotification_absvol_cb_t {
  RawAddress raw_address;
  uint8_t label;
};
static std::promise<registernotification_absvol_cb_t> g_registernotification_absvol_promise;

struct get_folder_items_cb_t {
  RawAddress raw_address;
  btrc_status_t status;
  uint8_t count;
};
static std::promise<get_folder_items_cb_t> g_get_folder_items_promise;

#include "stack/include/avrc_defs.h"

[[maybe_unused]] static void BTA_AvRemoteVendorUniqueCmd(uint8_t, uint8_t, tBTA_AV_CODE, uint8_t*,
                                                         uint16_t) {
  inc_func_call_count(__func__);
}

struct setplayerappsetting_rsp_cb_t {
  RawAddress raw_address;
  uint8_t accepted;
};
static std::promise<setplayerappsetting_rsp_cb_t> g_setplayerappsetting_rsp_promise;

struct change_folder_path_cb_t {
  RawAddress raw_address;
  uint32_t count;
};
static std::promise<change_folder_path_cb_t> g_change_folder_path_promise;

struct set_browsed_player_cb_t {
  RawAddress raw_address;
  uint8_t num_items;
  uint8_t depth;
};
static std::promise<set_browsed_player_cb_t> g_set_browsed_player_promise;

struct track_changed_cb_t {
  RawAddress raw_address;
  uint8_t num_attr;
};
static std::promise<track_changed_cb_t> g_track_changed_promise;

struct playerapplicationsetting_changed_cb_t {
  RawAddress raw_address;
  btrc_player_settings_t settings;
};
static std::promise<playerapplicationsetting_changed_cb_t>
        g_playerapplicationsetting_changed_promise;

struct play_status_changed_cb_t {
  RawAddress raw_address;
  btrc_play_status_t play_status;
};
static std::promise<play_status_changed_cb_t> g_play_status_changed_promise;

struct play_position_changed_cb_t {
  RawAddress raw_address;
  uint32_t song_len;
  uint32_t song_pos;
};
static std::promise<play_position_changed_cb_t> g_play_position_changed_promise;

struct set_addressed_player_cb_t {
  RawAddress raw_address;
  uint8_t status;
};
static std::promise<set_addressed_player_cb_t> g_set_addressed_player_promise;

class BtifRcHandlerTest : public BtifRcWithCallbacksTest {
protected:
  void SetUp() override {
    BtifRcWithCallbacksTest::SetUp();
    btif_rc_device_cb_t* p_dev =
            bluetooth::testing::avrc::btif_rc_ctrl_get_interface()->get_device_cb(0);
    // Clear all transactions to avoid flakes from previous tests.
    for (int i = 0; i < MAX_TRANSACTIONS_PER_SESSION; i++) {
      p_dev->transaction_set.transaction[i].in_use = false;
      p_dev->transaction_set.transaction[i].label = 0xff;  // Invalid label
    }
    btrc_ctrl_callbacks.passthrough_rsp_cb = [](const RawAddress& bd_addr, int id, int key_state) {
      g_passthrough_rsp_promise.set_value({bd_addr, id, key_state});
    };
    btrc_ctrl_callbacks.groupnavigation_rsp_cb = [](int id, int key_state) {
      g_groupnavigation_rsp_promise.set_value({id, key_state});
    };
    btrc_ctrl_callbacks.get_cover_art_psm_cb = [](const RawAddress& bd_addr, const uint16_t psm) {
      g_get_cover_art_psm_promise.set_value({bd_addr, psm});
    };
    btrc_ctrl_callbacks.setabsvol_cmd_cb = [](const RawAddress& bd_addr, uint8_t abs_vol,
                                              uint8_t label) {
      g_setabsvol_cmd_promise.set_value({bd_addr, abs_vol, label});
    };
    btrc_ctrl_callbacks.get_folder_items_cb = [](const RawAddress& bd_addr, btrc_status_t status,
                                                 const btrc_folder_items_t* /* folder_items */,
                                                 uint8_t count) {
      g_get_folder_items_promise.set_value({bd_addr, status, count});
    };
    btrc_ctrl_callbacks.connection_state_cb = [](const RawAddress& bd_addr,
                                                 btrc_connection_state_t rc_state,
                                                 btrc_connection_state_t browse_state) {
      g_btrc_connection_state_promise.set_value({rc_state, browse_state, bd_addr});
    };
    btrc_ctrl_callbacks.setplayerappsetting_rsp_cb = [](const RawAddress& bd_addr,
                                                        uint8_t accepted) {
      g_setplayerappsetting_rsp_promise.set_value({bd_addr, accepted});
    };
    btrc_ctrl_callbacks.change_folder_path_cb = [](const RawAddress& bd_addr, uint32_t count) {
      g_change_folder_path_promise.set_value({bd_addr, count});
    };
    btrc_ctrl_callbacks.set_browsed_player_cb = [](const RawAddress& bd_addr, uint8_t num_items,
                                                   uint8_t depth) {
      g_set_browsed_player_promise.set_value({bd_addr, num_items, depth});
    };
    btrc_ctrl_callbacks.track_changed_cb = [](const RawAddress& bd_addr, uint8_t num_attr,
                                              btrc_element_attr_val_t* /* p_attrs */) {
      g_track_changed_promise.set_value({bd_addr, num_attr});
    };
    btrc_ctrl_callbacks.playerapplicationsetting_changed_cb =
            [](const RawAddress& bd_addr, const btrc_player_settings_t& vals) {
              g_playerapplicationsetting_changed_promise.set_value({bd_addr, vals});
            };

    btrc_ctrl_callbacks.play_status_changed_cb = [](const RawAddress& bd_addr,
                                                    btrc_play_status_t play_status) {
      g_play_status_changed_promise.set_value({bd_addr, play_status});
    };
    btrc_ctrl_callbacks.play_position_changed_cb = [](const RawAddress& bd_addr, uint32_t song_len,
                                                      uint32_t song_pos) {
      g_play_position_changed_promise.set_value({bd_addr, song_len, song_pos});
    };
    btrc_ctrl_callbacks.set_addressed_player_cb = [](const RawAddress& bd_addr, uint8_t status) {
      g_set_addressed_player_promise.set_value({bd_addr, status});
    };
    btrc_ctrl_callbacks.registernotification_absvol_cb = [](const RawAddress& bd_addr,
                                                            uint8_t label) {
      g_registernotification_absvol_promise.set_value({bd_addr, label});
    };
  }

  void TearDown() override {
    btrc_ctrl_callbacks.passthrough_rsp_cb = [](const RawAddress& /* bd_addr */, int /* id */,
                                                int /* key_state */) {};
    btrc_ctrl_callbacks.groupnavigation_rsp_cb = [](int /* id */, int /* key_state */) {};
    btrc_ctrl_callbacks.get_cover_art_psm_cb = [](const RawAddress& /* bd_addr */,
                                                  const uint16_t /* psm */) {};
    btrc_ctrl_callbacks.setabsvol_cmd_cb = [](const RawAddress& /* bd_addr */,
                                              uint8_t /* abs_vol */, uint8_t /* label */) {};
    btrc_ctrl_callbacks.get_folder_items_cb =
            [](const RawAddress& /* bd_addr */, btrc_status_t /* status */,
               const btrc_folder_items_t* /* folder_items */, uint8_t /* count */) {};
    btrc_ctrl_callbacks.connection_state_cb = [](const RawAddress&, btrc_connection_state_t,
                                                 btrc_connection_state_t) {};
    btrc_ctrl_callbacks.setplayerappsetting_rsp_cb = [](const RawAddress&, uint8_t) {};
    btrc_ctrl_callbacks.change_folder_path_cb = [](const RawAddress&, uint32_t) {};
    btrc_ctrl_callbacks.set_browsed_player_cb = [](const RawAddress&, uint8_t, uint8_t) {};
    btrc_ctrl_callbacks.track_changed_cb = [](const RawAddress&, uint8_t,
                                              btrc_element_attr_val_t*) {};
    btrc_ctrl_callbacks.playerapplicationsetting_changed_cb =
            [](const RawAddress& /* bd_addr */, const btrc_player_settings_t& /* vals */) {};
    btrc_ctrl_callbacks.play_position_changed_cb = [](const RawAddress& /* bd_addr */,
                                                      uint32_t /* song_len */,
                                                      uint32_t /* song_pos */) {};
    btrc_ctrl_callbacks.set_addressed_player_cb = [](const RawAddress& /* bd_addr */,
                                                     uint8_t /* status */) {};
    BtifRcWithCallbacksTest::TearDown();
  }
};

TEST_F(BtifRcHandlerTest, remote_rsp_passthrough) {
  g_passthrough_rsp_promise = std::promise<passthrough_rsp_cb_t>();
  auto future = g_passthrough_rsp_promise.get_future();

  // Setup connected device
  btif_rc_device_cb_t* p_dev =
          allocate_dev(0, kDeviceAddress, BTRC_CONNECTION_STATE_CONNECTED, kRcHandle);
  p_dev->rc_features = BTA_AV_FEAT_RCTG;

  tBTA_AV data = {.remote_rsp = {
                          .rc_handle = kRcHandle,
                          .rc_id = AVRC_ID_0,  // some non-vendor id
                          .key_state = 0,
                          .label = 1,
                  }};

  btif_rc_handler(BTA_AV_REMOTE_RSP_EVT, &data);

  ASSERT_EQ(std::future_status::ready, future.wait_for(std::chrono::seconds(2)));
  auto res = future.get();
  ASSERT_EQ(res.raw_address, kDeviceAddress);
  ASSERT_EQ(res.id, data.remote_rsp.rc_id);
  ASSERT_EQ(res.key_state, data.remote_rsp.key_state);
}

TEST_F(BtifRcHandlerTest, remote_rsp_vendor) {
  g_groupnavigation_rsp_promise = std::promise<groupnavigation_rsp_cb_t>();
  auto future = g_groupnavigation_rsp_promise.get_future();

  // Setup connected device
  btif_rc_device_cb_t* p_dev =
          allocate_dev(0, kDeviceAddress, BTRC_CONNECTION_STATE_CONNECTED, kRcHandle);
  p_dev->rc_features = BTA_AV_FEAT_RCTG;

  tBTA_AV data = {.remote_rsp = {
                          .rc_handle = kRcHandle,
                          .rc_id = AVRC_ID_VENDOR,
                          .key_state = 1,
                          .len = 0,
                          .p_data = nullptr,
                          .label = 2,
                  }};

  btif_rc_handler(BTA_AV_REMOTE_RSP_EVT, &data);

  ASSERT_EQ(std::future_status::ready, future.wait_for(std::chrono::seconds(2)));
  auto res = future.get();
  ASSERT_EQ(res.id, 0);  // vendor_id is 0 when p_data is null
  ASSERT_EQ(res.key_state, 1);
}

TEST_F(BtifRcHandlerTest, bt_av_rc_feat_evt) {
  g_btrc_feature = std::promise<rc_feature_cb_t>();
  std::future<rc_feature_cb_t> future = g_btrc_feature.get_future();

  // Setup connected device
  btif_rc_device_cb_t* p_dev =
          allocate_dev(0, kDeviceAddress, BTRC_CONNECTION_STATE_CONNECTED, kRcHandle);

  tBTA_AV data = {
          .rc_feat = {
                  .rc_handle = kRcHandle,
                  .peer_features = (BTA_AV_FEAT_RCTG | BTA_AV_FEAT_ADV_CTRL | BTA_AV_FEAT_RCCT |
                                    BTA_AV_FEAT_METADATA | BTA_AV_FEAT_VENDOR | BTA_AV_FEAT_BROWSE |
                                    BTA_AV_FEAT_COVER_ARTWORK),
                  .peer_ct_features = 0,
                  .peer_tg_features = (BTA_AV_FEAT_RCTG | BTA_AV_FEAT_ADV_CTRL | BTA_AV_FEAT_RCCT |
                                       BTA_AV_FEAT_METADATA | BTA_AV_FEAT_VENDOR |
                                       BTA_AV_FEAT_BROWSE | BTA_AV_FEAT_COVER_ARTWORK),
          }};

  btif_rc_handler(BTA_AV_RC_FEAT_EVT, &data);

  ASSERT_EQ(std::future_status::ready, future.wait_for(std::chrono::seconds(2)));
  auto res = future.get();
  ASSERT_EQ(res.raw_address, kDeviceAddress);
  ASSERT_EQ(res.feature, BTRC_FEAT_ABSOLUTE_VOLUME | BTRC_FEAT_METADATA | BTRC_FEAT_BROWSE |
                                 BTRC_FEAT_COVER_ARTWORK);
}

TEST_F(BtifRcHandlerTest, bt_av_rc_psm_evt) {
  g_get_cover_art_psm_promise = std::promise<get_cover_art_psm_cb_t>();
  auto future = g_get_cover_art_psm_promise.get_future();

  // Setup connected device
  btif_rc_device_cb_t* p_dev =
          allocate_dev(0, kDeviceAddress, BTRC_CONNECTION_STATE_CONNECTED, kRcHandle);

  const uint16_t psm = 0x1234;
  tBTA_AV data = {
          .rc_cover_art_psm =
                  {
                          .rc_handle = kRcHandle,
                          .cover_art_psm = psm,
                  },
  };

  btif_rc_handler(BTA_AV_RC_PSM_EVT, &data);

  ASSERT_EQ(std::future_status::ready, future.wait_for(std::chrono::seconds(2)));
  auto res = future.get();
  ASSERT_EQ(res.raw_address, kDeviceAddress);
  ASSERT_EQ(res.psm, psm);
}

TEST_F(BtifRcHandlerTest, meta_msg_vendor_rsp_get_caps) {
  // Setup connected device
  btif_rc_device_cb_t* p_dev =
          allocate_dev(0, kDeviceAddress, BTRC_CONNECTION_STATE_CONNECTED, kRcHandle);

  tAVRC_RESPONSE rsp_payload;
  rsp_payload.get_caps = {
          .pdu = AVRC_PDU_GET_CAPABILITIES,
          .status = AVRC_STS_NO_ERROR,
          .capability_id = AVRC_CAP_COMPANY_ID,
          .count = 1,
  };
  rsp_payload.get_caps.param.company_id[0] = 0x1234;

  tAVRC_MSG msg = {
          .vendor =
                  {
                          .hdr =
                                  {
                                          .ctype = rsp_payload.get_caps.pdu,
                                          .opcode = AVRC_OP_VENDOR,
                                  },
                          .p_vendor_data = (uint8_t*)&rsp_payload,
                  },
  };

  tBTA_AV data = {
          .meta_msg =
                  {
                          .rc_handle = kRcHandle,
                          .label = 4,
                          .code = AVRC_RSP_IMPL_STBL,
                          .p_msg = &msg,
                  },
  };

  btif_rc_handler(BTA_AV_META_MSG_EVT, &data);
}

TEST_F(BtifRcHandlerTest, meta_msg_vendor_rsp_get_caps_op_browse) {
  // Setup connected device
  btif_rc_device_cb_t* p_dev =
          allocate_dev(0, kDeviceAddress, BTRC_CONNECTION_STATE_CONNECTED, kRcHandle);

  tAVRC_RESPONSE rsp_payload;
  rsp_payload.get_caps = {
          .pdu = AVRC_PDU_GET_CAPABILITIES,
          .status = AVRC_STS_NO_ERROR,
          .capability_id = AVRC_CAP_COMPANY_ID,
          .count = 1,
  };
  rsp_payload.get_caps.param.company_id[0] = 0x1234;

  tAVRC_MSG msg = {
          .vendor =
                  {
                          .hdr =
                                  {
                                          .ctype = AVRC_CMD,
                                          .opcode = AVRC_OP_BROWSE,
                                  },
                          .p_vendor_data = (uint8_t*)&rsp_payload,
                  },
  };

  tBTA_AV data = {
          .meta_msg =
                  {
                          .rc_handle = kRcHandle,
                          .label = 4,
                          .code = AVRC_RSP_IMPL_STBL,
                          .p_msg = &msg,
                  },
  };

  btif_rc_handler(BTA_AV_META_MSG_EVT, &data);
}

TEST_F(BtifRcHandlerTest, meta_msg_vendor_rsp_get_caps_op_browse_rsp) {
  // Setup connected device
  btif_rc_device_cb_t* p_dev =
          allocate_dev(0, kDeviceAddress, BTRC_CONNECTION_STATE_CONNECTED, kRcHandle);

  tAVRC_RESPONSE rsp_payload;
  rsp_payload.get_caps = {
          .pdu = AVRC_PDU_GET_CAPABILITIES,
          .status = AVRC_STS_NO_ERROR,
          .capability_id = AVRC_CAP_COMPANY_ID,
          .count = 1,
  };
  rsp_payload.get_caps.param.company_id[0] = 0x1234;

  tAVRC_MSG msg = {
          .vendor =
                  {
                          .hdr =
                                  {
                                          .ctype = AVRC_RSP,
                                          .opcode = AVRC_OP_BROWSE,
                                  },
                          .p_vendor_data = (uint8_t*)&rsp_payload,
                  },
  };

  tBTA_AV data = {
          .meta_msg =
                  {
                          .rc_handle = kRcHandle,
                          .label = 4,
                          .code = AVRC_RSP_IMPL_STBL,
                          .p_msg = &msg,
                  },
  };

  btif_rc_handler(BTA_AV_META_MSG_EVT, &data);
}

TEST_F(BtifRcHandlerTest, bt_av_rc_browse_open_evt) {
  g_btrc_connection_state_promise = std::promise<rc_connection_state_cb_t>();
  std::future<rc_connection_state_cb_t> future = g_btrc_connection_state_promise.get_future();

  tBTA_AV data = {
          .rc_browse_open =
                  {
                          .rc_handle = 0,
                          .peer_addr = {},
                          .status = BTA_AV_SUCCESS,
                  },
  };

  btif_rc_device_cb_t* p_dev =
          bluetooth::testing::avrc::btif_rc_ctrl_get_interface()->get_device_cb(0);
  p_dev->rc_handle = 0;
  p_dev->rc_addr = RawAddress::kEmpty;
  p_dev->rc_state = BTRC_CONNECTION_STATE_CONNECTED;

  btif_rc_handler(BTA_AV_RC_BROWSE_OPEN_EVT, &data);
  ASSERT_EQ(std::future_status::ready, future.wait_for(std::chrono::seconds(2)));
  auto res = future.get();
  ASSERT_TRUE(res.bt_state);
}

TEST_F(BtifRcHandlerTest, vendor_cmd_timeout_handler_get_caps) {
  // Setup connected device
  btif_rc_device_cb_t* p_dev =
          allocate_dev(0, kDeviceAddress, BTRC_CONNECTION_STATE_CONNECTED, kRcHandle);

  rc_vendor_context_t context = {
          .pdu_id = AVRC_PDU_GET_CAPABILITIES,
  };

  bluetooth::testing::avrc::btif_rc_ctrl_get_interface()->vendor_cmd_timeout_handler(p_dev, 0,
                                                                                     &context);
  // ASSERT_EQ(1, get_func_call_count("getcapabilities_cmd"));
}

TEST_F(BtifRcHandlerTest, vendor_cmd_timeout_handler_null_device) {
  rc_vendor_context_t context = {
          .pdu_id = AVRC_PDU_GET_CAPABILITIES,
  };
  bluetooth::testing::avrc::btif_rc_ctrl_get_interface()->vendor_cmd_timeout_handler(nullptr, 0,
                                                                                     &context);
  // No op, just make sure it doesn't crash
}

TEST_F(BtifRcHandlerTest, vendor_cmd_timeout_handler_register_notification) {
  // Setup connected device
  btif_rc_device_cb_t* p_dev =
          allocate_dev(0, kDeviceAddress, BTRC_CONNECTION_STATE_CONNECTED, kRcHandle);
  p_dev->rc_supported_event_list = list_new(osi_free);

  rc_vendor_context_t context = {
          .pdu_id = AVRC_PDU_REGISTER_NOTIFICATION,
          .event_id = AVRC_EVT_PLAY_STATUS_CHANGE,
  };

  bluetooth::testing::avrc::btif_rc_ctrl_get_interface()->vendor_cmd_timeout_handler(p_dev, 0,
                                                                                     &context);

  list_free(p_dev->rc_supported_event_list);
}

TEST_F(BtifRcHandlerTest, vendor_cmd_timeout_handler_list_app_attr) {
  // Setup connected device
  btif_rc_device_cb_t* p_dev =
          allocate_dev(0, kDeviceAddress, BTRC_CONNECTION_STATE_CONNECTED, kRcHandle);

  rc_vendor_context_t context = {
          .pdu_id = AVRC_PDU_LIST_PLAYER_APP_ATTR,
  };

  bluetooth::testing::avrc::btif_rc_ctrl_get_interface()->vendor_cmd_timeout_handler(p_dev, 0,
                                                                                     &context);
}

TEST_F(BtifRcHandlerTest, vendor_cmd_timeout_handler_list_app_values) {
  // Setup connected device
  btif_rc_device_cb_t* p_dev =
          allocate_dev(0, kDeviceAddress, BTRC_CONNECTION_STATE_CONNECTED, kRcHandle);

  rc_vendor_context_t context = {
          .pdu_id = AVRC_PDU_LIST_PLAYER_APP_VALUES,
  };

  bluetooth::testing::avrc::btif_rc_ctrl_get_interface()->vendor_cmd_timeout_handler(p_dev, 0,
                                                                                     &context);
  // No op, just make sure it doesn't crash
}

TEST_F(BtifRcHandlerTest, vendor_cmd_timeout_handler_get_cur_app_value) {
  // Setup connected device
  btif_rc_device_cb_t* p_dev =
          allocate_dev(0, kDeviceAddress, BTRC_CONNECTION_STATE_CONNECTED, kRcHandle);

  rc_vendor_context_t context = {
          .pdu_id = AVRC_PDU_GET_CUR_PLAYER_APP_VALUE,
  };

  bluetooth::testing::avrc::btif_rc_ctrl_get_interface()->vendor_cmd_timeout_handler(p_dev, 0,
                                                                                     &context);
  // No op, just make sure it doesn't crash
}

TEST_F(BtifRcHandlerTest, vendor_cmd_timeout_handler_get_element_attr) {
  // Setup connected device
  btif_rc_device_cb_t* p_dev =
          allocate_dev(0, kDeviceAddress, BTRC_CONNECTION_STATE_CONNECTED, kRcHandle);

  rc_vendor_context_t context = {
          .pdu_id = AVRC_PDU_GET_ELEMENT_ATTR,
  };

  bluetooth::testing::avrc::btif_rc_ctrl_get_interface()->vendor_cmd_timeout_handler(p_dev, 0,
                                                                                     &context);
}

TEST_F(BtifRcHandlerTest, vendor_cmd_timeout_handler_get_play_status) {
  // Setup connected device
  btif_rc_device_cb_t* p_dev =
          allocate_dev(0, kDeviceAddress, BTRC_CONNECTION_STATE_CONNECTED, kRcHandle);

  rc_vendor_context_t context = {
          .pdu_id = AVRC_PDU_GET_PLAY_STATUS,
  };

  bluetooth::testing::avrc::btif_rc_ctrl_get_interface()->vendor_cmd_timeout_handler(p_dev, 0,
                                                                                     &context);
  // No op, just make sure it doesn't crash
}

TEST_F(BtifRcHandlerTest, vendor_cmd_timeout_handler_set_app_value) {
  g_setplayerappsetting_rsp_promise = std::promise<setplayerappsetting_rsp_cb_t>();
  auto future = g_setplayerappsetting_rsp_promise.get_future();

  // Setup connected device
  btif_rc_device_cb_t* p_dev =
          allocate_dev(0, kDeviceAddress, BTRC_CONNECTION_STATE_CONNECTED, kRcHandle);

  rc_vendor_context_t context = {
          .pdu_id = AVRC_PDU_SET_PLAYER_APP_VALUE,
  };

  bluetooth::testing::avrc::btif_rc_ctrl_get_interface()->vendor_cmd_timeout_handler(p_dev, 0,
                                                                                     &context);

  ASSERT_EQ(std::future_status::ready, future.wait_for(std::chrono::seconds(2)));
  auto res = future.get();
  ASSERT_EQ(res.raw_address, kDeviceAddress);
  ASSERT_EQ(res.accepted, 0);
}

TEST_F(BtifRcHandlerTest, vendor_cmd_timeout_handler_play_item) {
  // Setup connected device
  btif_rc_device_cb_t* p_dev =
          allocate_dev(0, kDeviceAddress, BTRC_CONNECTION_STATE_CONNECTED, kRcHandle);

  rc_vendor_context_t context = {
          .pdu_id = AVRC_PDU_PLAY_ITEM,
  };

  bluetooth::testing::avrc::btif_rc_ctrl_get_interface()->vendor_cmd_timeout_handler(p_dev, 0,
                                                                                     &context);
  // No op, just make sure it doesn't crash
}

TEST_F(BtifRcHandlerTest, vendor_cmd_timeout_handler_unknown_pdu) {
  // Setup connected device
  btif_rc_device_cb_t* p_dev =
          allocate_dev(0, kDeviceAddress, BTRC_CONNECTION_STATE_CONNECTED, kRcHandle);

  rc_vendor_context_t context = {
          .pdu_id = 0xFF,  // invalid pdu
  };

  bluetooth::testing::avrc::btif_rc_ctrl_get_interface()->vendor_cmd_timeout_handler(p_dev, 0,
                                                                                     &context);
  // No op, just make sure it doesn't crash
}

TEST_F(BtifRcHandlerTest, transaction_timeout_handler_browse) {
  g_get_folder_items_promise = std::promise<get_folder_items_cb_t>();

  // Setup connected device
  btif_rc_device_cb_t* p_dev =
          allocate_dev(0, kDeviceAddress, BTRC_CONNECTION_STATE_CONNECTED, kRcHandle);

  rc_transaction_context_t context = {
          .rc_addr = kDeviceAddress,
          .label = 2,
          .opcode = AVRC_OP_BROWSE,
          .command = {.browse = {.pdu_id = AVRC_PDU_GET_FOLDER_ITEMS}},
  };

  // Add a transaction to be released. The label must match the index.
  p_dev->transaction_set.transaction[2].in_use = true;
  p_dev->transaction_set.transaction[2].label = 2;

  bluetooth::testing::avrc::btif_rc_ctrl_get_interface()->btif_rc_transaction_timeout_handler(
          0, (char*)&context);

  // Verify transaction is released.
  ASSERT_FALSE(p_dev->transaction_set.transaction[2].in_use);
}

TEST_F(BtifRcHandlerTest, transaction_timeout_handler_passthru) {
  // Setup connected device
  btif_rc_device_cb_t* p_dev =
          allocate_dev(0, kDeviceAddress, BTRC_CONNECTION_STATE_CONNECTED, kRcHandle);

  rc_transaction_context_t context = {
          .rc_addr = kDeviceAddress,
          .label = 1,
          .opcode = AVRC_OP_PASS_THRU,
          .command = {.passthru = {.rc_id = 1, .key_state = 1, .custom_id = 1}},
  };

  // Add a transaction to be released. The label must match the index.
  p_dev->transaction_set.transaction[1].in_use = true;
  p_dev->transaction_set.transaction[1].label = 1;

  bluetooth::testing::avrc::btif_rc_ctrl_get_interface()->btif_rc_transaction_timeout_handler(
          0, (char*)&context);

  // Verify transaction is released.
  ASSERT_FALSE(p_dev->transaction_set.transaction[1].in_use);
}

TEST_F(BtifRcHandlerTest, transaction_timeout_handler_unknown_opcode) {
  // Setup connected device
  btif_rc_device_cb_t* p_dev =
          allocate_dev(0, kDeviceAddress, BTRC_CONNECTION_STATE_CONNECTED, kRcHandle);

  rc_transaction_context_t context = {
          .rc_addr = kDeviceAddress,
          .label = 3,
          .opcode = 0xFF,  // Unknown opcode
  };

  // Add a transaction. It should NOT be released.
  p_dev->transaction_set.transaction[2].in_use = true;
  p_dev->transaction_set.transaction[2].label = 3;

  bluetooth::testing::avrc::btif_rc_ctrl_get_interface()->btif_rc_transaction_timeout_handler(
          0, (char*)&context);

  // Verify transaction is NOT released because of early return.
  ASSERT_TRUE(p_dev->transaction_set.transaction[2].in_use);
}

TEST_F(BtifRcHandlerTest, browse_cmd_timeout_handler_change_path) {
  g_change_folder_path_promise = std::promise<change_folder_path_cb_t>();
  auto future = g_change_folder_path_promise.get_future();

  // Setup connected device
  btif_rc_device_cb_t* p_dev =
          allocate_dev(0, kDeviceAddress, BTRC_CONNECTION_STATE_CONNECTED, kRcHandle);

  rc_transaction_context_t context = {
          .rc_addr = kDeviceAddress,
          .label = 1,
          .opcode = AVRC_OP_BROWSE,
          .command = {.browse = {.pdu_id = AVRC_PDU_CHANGE_PATH}},
  };

  bluetooth::testing::avrc::btif_rc_ctrl_get_interface()->btif_rc_transaction_timeout_handler(
          0, (char*)&context);
}

TEST_F(BtifRcHandlerTest, browse_cmd_timeout_handler_set_browsed_player) {
  g_set_browsed_player_promise = std::promise<set_browsed_player_cb_t>();
  auto future = g_set_browsed_player_promise.get_future();

  // Setup connected device
  btif_rc_device_cb_t* p_dev =
          allocate_dev(0, kDeviceAddress, BTRC_CONNECTION_STATE_CONNECTED, kRcHandle);

  rc_transaction_context_t context = {
          .rc_addr = kDeviceAddress,
          .label = 1,
          .opcode = AVRC_OP_BROWSE,
          .command = {.browse = {.pdu_id = AVRC_PDU_SET_BROWSED_PLAYER}},
  };

  bluetooth::testing::avrc::btif_rc_ctrl_get_interface()->btif_rc_transaction_timeout_handler(
          0, (char*)&context);
}

TEST_F(BtifRcHandlerTest, browse_cmd_timeout_handler_get_item_attributes) {
  // Setup connected device
  btif_rc_device_cb_t* p_dev =
          allocate_dev(0, kDeviceAddress, BTRC_CONNECTION_STATE_CONNECTED, kRcHandle);
  p_dev->rc_features = BTA_AV_FEAT_RCTG;

  rc_transaction_context_t context = {
          .rc_addr = kDeviceAddress,
          .label = 1,
          .opcode = AVRC_OP_BROWSE,
          .command = {.browse = {.pdu_id = AVRC_PDU_GET_ITEM_ATTRIBUTES}},
  };

  bluetooth::testing::avrc::btif_rc_ctrl_get_interface()->btif_rc_transaction_timeout_handler(
          0, (char*)&context);

  // In timeout case, handle_get_metadata_attr_response is called with status=BTIF_RC_STS_TIMEOUT
  // which retries get_metadata_attribute_cmd.
  // get_metadata_attribute_cmd will call AVRC_BldCommand
}

TEST_F(BtifRcHandlerTest, TimeoutPduGetItemAttributes) {
  // Setup connected device
  btif_rc_device_cb_t* p_dev =
          allocate_dev(0, kDeviceAddress, BTRC_CONNECTION_STATE_CONNECTED, kRcHandle);
  p_dev->rc_features = BTA_AV_FEAT_RCTG;

  rc_transaction_context_t context = {
          .rc_addr = kDeviceAddress,
          .label = 1,
          .opcode = AVRC_OP_BROWSE,
          .command = {.browse = {.pdu_id = AVRC_PDU_GET_ITEM_ATTRIBUTES}},
  };

  bluetooth::testing::avrc::btif_rc_ctrl_get_interface()->btif_rc_transaction_timeout_handler(
          0, (char*)&context);

  // In timeout case, handle_get_metadata_attr_response is called with status=BTIF_RC_STS_TIMEOUT
  // which retries get_metadata_attribute_cmd.
  // get_metadata_attribute_cmd will call AVRC_BldCommand
}

TEST_F(BtifRcHandlerTest, TimeoutOpVendor) {
  // Setup connected device
  btif_rc_device_cb_t* p_dev =
          allocate_dev(0, kDeviceAddress, BTRC_CONNECTION_STATE_CONNECTED, kRcHandle);

  rc_transaction_context_t context = {
          .rc_addr = kDeviceAddress,
          .label = 4,
          .opcode = AVRC_OP_VENDOR,
          .command = {.vendor = {.pdu_id = AVRC_PDU_GET_CAPABILITIES, .event_id = 0}},
  };

  // Add a transaction to be released. The label must match the index.
  p_dev->transaction_set.transaction[4].in_use = true;
  p_dev->transaction_set.transaction[4].label = 4;

  bluetooth::testing::avrc::btif_rc_ctrl_get_interface()->btif_rc_transaction_timeout_handler(
          0, (char*)&context);
}

TEST_F(BtifRcHandlerTest, handle_app_cur_val_response_success) {
  g_playerapplicationsetting_changed_promise =
          std::promise<playerapplicationsetting_changed_cb_t>();
  auto future = g_playerapplicationsetting_changed_promise.get_future();
  btif_rc_device_cb_t* p_dev =
          bluetooth::testing::avrc::btif_rc_ctrl_get_interface()->get_device_cb(0);
  tBTA_AV_META_MSG meta_msg = {.rc_handle = kRcHandle};
  tAVRC_APP_SETTING setting = {.attr_id = 1, .attr_val = 2};
  tAVRC_GET_CUR_APP_VALUE_RSP rsp = {.status = AVRC_STS_NO_ERROR, .num_val = 1, .p_vals = &setting};
  bluetooth::testing::avrc::btif_rc_ctrl_get_interface()->handle_app_cur_val_response(&meta_msg,
                                                                                      &rsp);
  ASSERT_EQ(std::future_status::ready, future.wait_for(std::chrono::seconds(2)));
  auto res = future.get();
  ASSERT_EQ(res.raw_address, kDeviceAddress);
}

TEST_F(BtifRcHandlerTest, handle_app_cur_val_response_error_status) {
  tBTA_AV_META_MSG meta_msg = {.rc_handle = kRcHandle};
  tAVRC_GET_CUR_APP_VALUE_RSP rsp = {.status = AVRC_STS_INTERNAL_ERR};
  bluetooth::testing::avrc::btif_rc_ctrl_get_interface()->handle_app_cur_val_response(&meta_msg,
                                                                                      &rsp);
  // No crash, and error should be logged. Nothing to assert here.
}

TEST_F(BtifRcHandlerTest, handle_app_attr_txt_response_success) {
  btif_rc_device_cb_t* p_dev =
          bluetooth::testing::avrc::btif_rc_ctrl_get_interface()->get_device_cb(0);
  p_dev->rc_app_settings.num_ext_attrs = 1;
  p_dev->rc_app_settings.ext_attrs[0].attr_id = 1;
  p_dev->rc_app_settings.ext_attrs[0].num_val = 1;
  p_dev->rc_app_settings.ext_attrs[0].ext_attr_val[0].val = 1;
  tBTA_AV_META_MSG meta_msg = {.rc_handle = kRcHandle};
  tAVRC_APP_SETTING_TEXT attr_entry = {
          .attr_id = 1, .charset_id = 1, .str_len = 4, .p_str = (uint8_t*)"test"};
  tAVRC_GET_APP_ATTR_TXT_RSP rsp = {
          .status = AVRC_STS_NO_ERROR, .num_attr = 1, .p_attrs = &attr_entry};
  bluetooth::testing::avrc::btif_rc_ctrl_get_interface()->handle_app_attr_txt_response(&meta_msg,
                                                                                       &rsp);
}

TEST_F(BtifRcHandlerTest, handle_app_attr_txt_response_error_status) {
  btrc_ctrl_callbacks.playerapplicationsetting_cb = [](const RawAddress&, uint8_t,
                                                       btrc_player_app_attr_t*) {};
  btif_rc_device_cb_t* p_dev =
          bluetooth::testing::avrc::btif_rc_ctrl_get_interface()->get_device_cb(0);
  tBTA_AV_META_MSG meta_msg = {.rc_handle = kRcHandle};
  tAVRC_GET_APP_ATTR_TXT_RSP rsp = {.status = AVRC_STS_INTERNAL_ERR};
  bluetooth::testing::avrc::btif_rc_ctrl_get_interface()->handle_app_attr_txt_response(&meta_msg,
                                                                                       &rsp);
}

TEST_F(BtifRcTest, cleanup_app_attr_val_txt_response) {
  btif_rc_player_app_settings_t app_settings = {};
  app_settings.ext_attr_index = 1;
  app_settings.ext_attrs[0].num_val = 1;
  app_settings.ext_attrs[0].p_str = (uint8_t*)osi_malloc(10);
  app_settings.ext_attrs[0].ext_attr_val[0].p_str = (uint8_t*)osi_malloc(10);
  bluetooth::testing::avrc::btif_rc_ctrl_get_interface()->cleanup_app_attr_val_txt_response(
          &app_settings);
  ASSERT_EQ(app_settings.ext_attrs[0].num_val, 0);
  ASSERT_EQ(app_settings.ext_attrs[0].p_str, nullptr);
  ASSERT_EQ(app_settings.ext_attrs[0].ext_attr_val[0].p_str, nullptr);
}

TEST_F(BtifRcHandlerTest, handle_set_addressed_player_response_success) {
  g_set_addressed_player_promise = std::promise<set_addressed_player_cb_t>();
  auto future = g_set_addressed_player_promise.get_future();
  btif_rc_device_cb_t* p_dev =
          bluetooth::testing::avrc::btif_rc_ctrl_get_interface()->get_device_cb(0);

  tBTA_AV_META_MSG meta_msg = {.rc_handle = kRcHandle};
  tAVRC_RSP rsp = {.status = AVRC_STS_NO_ERROR};
  bluetooth::testing::avrc::btif_rc_ctrl_get_interface()->handle_set_addressed_player_response(
          &meta_msg, &rsp);
  ASSERT_EQ(std::future_status::ready, future.wait_for(std::chrono::seconds(2)));
  auto res = future.get();
  ASSERT_EQ(res.raw_address, kDeviceAddress);
  ASSERT_EQ(res.status, (uint8_t)AVRC_STS_NO_ERROR);
}

TEST_F(BtifRcHandlerTest, handle_set_addressed_player_response_error_handle) {
  btif_rc_device_cb_t* p_dev =
          bluetooth::testing::avrc::btif_rc_ctrl_get_interface()->get_device_cb(0);
  tBTA_AV_META_MSG meta_msg = {.rc_handle = 0};
  tAVRC_RSP rsp = {.status = AVRC_STS_NO_ERROR};
  bluetooth::testing::avrc::btif_rc_ctrl_get_interface()->handle_set_addressed_player_response(
          &meta_msg, &rsp);
}

TEST_F(BtifRcHandlerTest, handle_set_addressed_player_response_error) {
  btif_rc_device_cb_t* p_dev =
          bluetooth::testing::avrc::btif_rc_ctrl_get_interface()->get_device_cb(0);

  tBTA_AV_META_MSG meta_msg = {.rc_handle = kRcHandle};
  tAVRC_RSP rsp = {.status = AVRC_STS_INTERNAL_ERR};
  bluetooth::testing::avrc::btif_rc_ctrl_get_interface()->handle_set_addressed_player_response(
          &meta_msg, &rsp);
}

TEST_F(BtifRcHandlerTest, handle_change_path_response_error_handle) {
  btif_rc_device_cb_t* p_dev =
          bluetooth::testing::avrc::btif_rc_ctrl_get_interface()->get_device_cb(0);

  tBTA_AV_META_MSG meta_msg = {.rc_handle = 0};
  tAVRC_CHG_PATH_RSP rsp = {.status = AVRC_STS_NO_ERROR};
  bluetooth::testing::avrc::btif_rc_ctrl_get_interface()->handle_change_path_response(&meta_msg,
                                                                                      &rsp);
}

TEST_F(BtifRcHandlerTest, handle_change_path_response_success) {
  g_change_folder_path_promise = std::promise<change_folder_path_cb_t>();
  auto future = g_change_folder_path_promise.get_future();
  btif_rc_device_cb_t* p_dev =
          bluetooth::testing::avrc::btif_rc_ctrl_get_interface()->get_device_cb(0);

  tBTA_AV_META_MSG meta_msg = {.rc_handle = kRcHandle};
  tAVRC_CHG_PATH_RSP rsp = {.status = AVRC_STS_NO_ERROR, .num_items = 1};
  bluetooth::testing::avrc::btif_rc_ctrl_get_interface()->handle_change_path_response(&meta_msg,
                                                                                      &rsp);

  ASSERT_EQ(std::future_status::ready, future.wait_for(std::chrono::seconds(2)));
  auto res = future.get();
  ASSERT_EQ(res.raw_address, kDeviceAddress);
  ASSERT_EQ(res.count, 1u);
}

TEST_F(BtifRcHandlerTest, handle_change_path_response_error) {
  btif_rc_device_cb_t* p_dev =
          bluetooth::testing::avrc::btif_rc_ctrl_get_interface()->get_device_cb(0);

  tBTA_AV_META_MSG meta_msg = {.rc_handle = kRcHandle};
  tAVRC_CHG_PATH_RSP rsp = {.status = AVRC_STS_INTERNAL_ERR};
  bluetooth::testing::avrc::btif_rc_ctrl_get_interface()->handle_change_path_response(&meta_msg,
                                                                                      &rsp);
}

TEST_F(BtifRcHandlerTest, handle_set_browsed_player_success) {
  g_set_browsed_player_promise = std::promise<set_browsed_player_cb_t>();
  auto future = g_set_browsed_player_promise.get_future();
  btif_rc_device_cb_t* p_dev =
          bluetooth::testing::avrc::btif_rc_ctrl_get_interface()->get_device_cb(0);

  tBTA_AV_META_MSG meta_msg = {.rc_handle = kRcHandle};
  tAVRC_SET_BR_PLAYER_RSP rsp = {.status = AVRC_STS_NO_ERROR, .num_items = 1, .folder_depth = 1};
  bluetooth::testing::avrc::btif_rc_ctrl_get_interface()->handle_set_browsed_player_response(
          &meta_msg, &rsp);

  ASSERT_EQ(std::future_status::ready, future.wait_for(std::chrono::seconds(2)));
  auto res = future.get();
  ASSERT_EQ(res.raw_address, kDeviceAddress);
  ASSERT_EQ(res.num_items, 1u);
  ASSERT_EQ(res.depth, 1u);
}

TEST_F(BtifRcHandlerTest, handle_set_browsed_player_err_handle) {
  btif_rc_device_cb_t* p_dev =
          bluetooth::testing::avrc::btif_rc_ctrl_get_interface()->get_device_cb(0);

  tBTA_AV_META_MSG meta_msg = {.rc_handle = 0};
  tAVRC_SET_BR_PLAYER_RSP rsp = {.status = AVRC_STS_NO_ERROR, .num_items = 1, .folder_depth = 1};
  bluetooth::testing::avrc::btif_rc_ctrl_get_interface()->handle_set_browsed_player_response(
          &meta_msg, &rsp);
}

TEST_F(BtifRcHandlerTest, handle_set_browsed_player_error) {
  btif_rc_device_cb_t* p_dev =
          bluetooth::testing::avrc::btif_rc_ctrl_get_interface()->get_device_cb(0);

  tBTA_AV_META_MSG meta_msg = {.rc_handle = kRcHandle};
  tAVRC_SET_BR_PLAYER_RSP rsp = {
          .status = AVRC_STS_INTERNAL_ERR, .num_items = 1, .folder_depth = 1};
  bluetooth::testing::avrc::btif_rc_ctrl_get_interface()->handle_set_browsed_player_response(
          &meta_msg, &rsp);
}

TEST_F(BtifRcHandlerTest, handle_app_attr_value_rsp) {
  btrc_ctrl_callbacks.playerapplicationsetting_cb = [](const RawAddress&, uint8_t,
                                                       btrc_player_app_attr_t*) {};

  btif_rc_device_cb_t* p_dev =
          bluetooth::testing::avrc::btif_rc_ctrl_get_interface()->get_device_cb(0);
  p_dev->rc_addr = kDeviceAddress;
  p_dev->rc_handle = kRcHandle;
  p_dev->rc_app_settings.ext_attr_index = 2;
  p_dev->rc_app_settings.ext_attrs[0].num_val = 1;
  p_dev->rc_app_settings.ext_attrs[0].ext_attr_val[0].val = 1;
  p_dev->rc_app_settings.ext_attrs[1].num_val = 2;
  p_dev->rc_app_settings.ext_attrs[1].ext_attr_val[0].val = 1;
  p_dev->rc_app_settings.ext_attrs[1].ext_attr_val[1].val = 2;
  p_dev->rc_app_settings.num_attrs = 1;
  p_dev->rc_app_settings.attrs[0].attr_id = 1;
  p_dev->rc_app_settings.attrs[0].num_val = 1;
  p_dev->rc_app_settings.attrs[0].attr_val[0] = 1;
  tBTA_AV_META_MSG meta_msg = {.rc_handle = kRcHandle};

  tAVRC_GET_APP_ATTR_TXT_RSP rsp = {.status = AVRC_STS_INTERNAL_ERR};
  bluetooth::testing::avrc::btif_rc_ctrl_get_interface()->handle_app_attr_val_txt_response(
          &meta_msg, &rsp);
}

TEST_F(BtifRcHandlerTest, handle_get_statusplay) {
  g_play_status_changed_promise = std::promise<play_status_changed_cb_t>();
  auto future_play_status = g_play_status_changed_promise.get_future();
  g_play_position_changed_promise = std::promise<play_position_changed_cb_t>();
  auto future_play_position = g_play_position_changed_promise.get_future();

  btif_rc_device_cb_t* p_dev =
          bluetooth::testing::avrc::btif_rc_ctrl_get_interface()->get_device_cb(0);
  tBTA_AV_META_MSG meta_msg = {.rc_handle = kRcHandle};
  tAVRC_GET_PLAY_STATUS_RSP rsp = {.status = AVRC_STS_NO_ERROR,
                                   .song_len = 1,
                                   .song_pos = 1,
                                   .play_status = AVRC_PLAYSTATE_PLAYING};
  bluetooth::testing::avrc::btif_rc_ctrl_get_interface()->handle_get_playstatus_response(&meta_msg,
                                                                                         &rsp);

  ASSERT_EQ(std::future_status::ready, future_play_status.wait_for(std::chrono::seconds(2)));
  auto res_play_status = future_play_status.get();
  ASSERT_EQ(res_play_status.raw_address, kDeviceAddress);
  ASSERT_EQ(res_play_status.play_status, static_cast<btrc_play_status_t>(AVRC_PLAYSTATE_PLAYING));

  ASSERT_EQ(std::future_status::ready, future_play_position.wait_for(std::chrono::seconds(2)));
  auto res_play_position = future_play_position.get();
  ASSERT_EQ(res_play_position.raw_address, kDeviceAddress);
  ASSERT_EQ(res_play_position.song_len, 1u);
  ASSERT_EQ(res_play_position.song_pos, 1u);
}

TEST_F(BtifRcHandlerTest, handle_get_folder_items_response_error_status_test) {
  g_get_folder_items_promise = std::promise<get_folder_items_cb_t>();
  auto future = g_get_folder_items_promise.get_future();

  btif_rc_device_cb_t* p_dev =
          bluetooth::testing::avrc::btif_rc_ctrl_get_interface()->get_device_cb(0);

  tBTA_AV_META_MSG meta_msg = {.rc_handle = kRcHandle};
  tAVRC_GET_ITEMS_RSP rsp = {.status = AVRC_STS_INTERNAL_ERR};

  // Ensure no other unexpected call counts
  reset_mock_function_count_map();

  bluetooth::testing::avrc::btif_rc_ctrl_get_interface()->handle_get_folder_items_response(
          &meta_msg, &rsp);

  ASSERT_EQ(std::future_status::ready, future.wait_for(std::chrono::seconds(2)));
  auto res = future.get();
  // Expect the callback with the error status and zero count
  ASSERT_EQ(res.raw_address, kDeviceAddress);
  ASSERT_EQ(res.status, (btrc_status_t)AVRC_STS_INTERNAL_ERR);
  ASSERT_EQ(res.count, 0u);
}

TEST_F(BtifRcHandlerTest, handle_get_folder_items_response_success_zero_items_test) {
  g_get_folder_items_promise = std::promise<get_folder_items_cb_t>();
  auto future = g_get_folder_items_promise.get_future();
  reset_mock_function_count_map();

  btif_rc_device_cb_t* p_dev =
          bluetooth::testing::avrc::btif_rc_ctrl_get_interface()->get_device_cb(0);
  p_dev->rc_features = 0;  // No app setting feature

  tBTA_AV_META_MSG meta_msg = {.rc_handle = kRcHandle};
  tAVRC_GET_ITEMS_RSP rsp = {.status = AVRC_STS_NO_ERROR, .item_count = 0};

  bluetooth::testing::avrc::btif_rc_ctrl_get_interface()->handle_get_folder_items_response(
          &meta_msg, &rsp);

  ASSERT_EQ(std::future_status::ready, future.wait_for(std::chrono::seconds(2)));
  auto res = future.get();
  // Expect the callback with success status and zero count
  ASSERT_EQ(res.status, AVRC_STS_NO_ERROR);
  ASSERT_EQ(res.count, 0u);
}

TEST_F(BtifRcHandlerTest, btif_rc_transaction_timer_timeout_passthru) {
  // Setup connected device
  btif_rc_device_cb_t* p_dev =
          allocate_dev(0, kDeviceAddress, BTRC_CONNECTION_STATE_CONNECTED, kRcHandle);

  rc_transaction_context_t context = {
          .rc_addr = kDeviceAddress,
          .label = 1,
          .opcode = AVRC_OP_PASS_THRU,
          .command = {.passthru = {.rc_id = 1, .key_state = 1, .custom_id = 1}},
  };

  // Add a transaction to be released. The label must match the index.
  p_dev->transaction_set.transaction[1].in_use = true;
  p_dev->transaction_set.transaction[1].label = 1;

  bluetooth::testing::avrc::btif_rc_ctrl_get_interface()->btif_rc_transaction_timer_timeout(
          &context);

  // Verify transaction is released.
  ASSERT_FALSE(p_dev->transaction_set.transaction[1].in_use);
}

TEST_F(BtifRcWithCallbacksTest, send_passthrough_cmd_test) {
  btif_rc_device_cb_t* p_dev =
          allocate_dev(0, kDeviceAddress, BTRC_CONNECTION_STATE_CONNECTED, kRcHandle);
  p_dev->rc_features = BTA_AV_FEAT_RCTG;
  // Clear transactions
  for (int i = 0; i < MAX_TRANSACTIONS_PER_SESSION; i++) {
    p_dev->transaction_set.transaction[i].in_use = false;
    p_dev->transaction_set.transaction[i].label = i;
  }
  BtStatus status =
          btif_rc_ctrl_get_interface()->send_pass_through_cmd(kDeviceAddress, AVRC_ID_PLAY, 0);
  ASSERT_EQ(status, BtifStatus());
}

TEST_F(BtifRcWithCallbacksTest, change_folder_path_cmd_test) {
  btif_rc_device_cb_t* p_dev =
          allocate_dev(0, kDeviceAddress, BTRC_CONNECTION_STATE_CONNECTED, kRcHandle);
  p_dev->br_state = BTRC_CONNECTION_STATE_CONNECTED;
  // Clear transactions
  for (int i = 0; i < MAX_TRANSACTIONS_PER_SESSION; i++) {
    p_dev->transaction_set.transaction[i].in_use = false;
    p_dev->transaction_set.transaction[i].label = i;
  }
  uint8_t uid[] = {0, 0, 0, 0, 0, 0, 0, 1};
  BtStatus status =
          btif_rc_ctrl_get_interface()->change_folder_path_cmd(kDeviceAddress, AVRC_DIR_DOWN, uid);
  ASSERT_EQ(status, BtifStatus(FAIL));
}

TEST_F(BtifRcWithCallbacksTest, change_folder_path_cmd_not_ready_test) {
  btif_rc_device_cb_t* p_dev =
          allocate_dev(0, kDeviceAddress, BTRC_CONNECTION_STATE_CONNECTED, kRcHandle);
  p_dev->br_state = BTRC_CONNECTION_STATE_DISCONNECTED;  // Not ready for browsing

  uint8_t uid[] = {0, 0, 0, 0, 0, 0, 0, 1};
  BtStatus status =
          btif_rc_ctrl_get_interface()->change_folder_path_cmd(kDeviceAddress, AVRC_DIR_DOWN, uid);
  ASSERT_EQ(status, BtifStatus(NOT_READY));
}

TEST_F(BtifRcTest, btif_rc_get_connected_peer_handle_success) {
  btif_rc_device_cb_t* p_dev =
          bluetooth::testing::avrc::btif_rc_ctrl_get_interface()->get_device_cb(0);
  p_dev->rc_state = BTRC_CONNECTION_STATE_CONNECTED;
  p_dev->rc_addr = kDeviceAddress;
  p_dev->rc_handle = kRcHandle;

  ASSERT_EQ(btif_rc_get_connected_peer_handle(kDeviceAddress), kRcHandle);
}

TEST_F(BtifRcTest, btif_rc_get_connected_peer_handle_not_found) {
  btif_rc_device_cb_t* p_dev =
          bluetooth::testing::avrc::btif_rc_ctrl_get_interface()->get_device_cb(0);
  p_dev->rc_state = BTRC_CONNECTION_STATE_DISCONNECTED;
  RawAddress unknown_address = RawAddress("de:ad:be:ef:12:34");
  ASSERT_EQ(btif_rc_get_connected_peer_handle(unknown_address), 0xFF);
}

TEST_F(BtifRcWithCallbacksTest, send_reject_response_test) {
  bluetooth::testing::avrc::btif_rc_ctrl_get_interface()->send_reject_response(
          kRcHandle, 1, AVRC_PDU_REGISTER_NOTIFICATION, AVRC_STS_BAD_PARAM, AVRC_OP_VENDOR);
}

TEST_F(BtifRcHandlerTest, btif_rc_ctrl_upstreams_rsp_cmd_test) {
  g_setabsvol_cmd_promise = std::promise<setabsvol_cmd_cb_t>();
  auto future = g_setabsvol_cmd_promise.get_future();
  btif_rc_device_cb_t p_dev = {};
  p_dev.rc_handle = kRcHandle;
  p_dev.rc_addr = kDeviceAddress;
  tAVRC_COMMAND avrc_cmd = {
          .volume = {.pdu = AVRC_PDU_SET_ABSOLUTE_VOLUME, .volume = 0x5A},
  };
  uint8_t label = 1;

  bluetooth::testing::avrc::btif_rc_ctrl_get_interface()->btif_rc_ctrl_upstreams_rsp_cmd(
          AVRC_PDU_SET_ABSOLUTE_VOLUME, &avrc_cmd, label, &p_dev);

  ASSERT_EQ(std::future_status::ready, future.wait_for(std::chrono::seconds(2)));
  auto res = future.get();
  ASSERT_EQ(res.raw_address, kDeviceAddress);
  ASSERT_EQ(res.abs_vol, 0x5A);
  ASSERT_EQ(res.label, label);
}

TEST_F(BtifRcHandlerTest, btif_rc_ctrl_upstreams_rsp_cmd_test_reg_notif) {
  g_registernotification_absvol_promise = std::promise<registernotification_absvol_cb_t>();
  auto future = g_registernotification_absvol_promise.get_future();
  btif_rc_device_cb_t p_dev = {};
  p_dev.rc_handle = kRcHandle;
  p_dev.rc_addr = kDeviceAddress;
  tAVRC_COMMAND avrc_cmd = {
          .reg_notif = {.event_id = AVRC_EVT_VOLUME_CHANGE},
  };
  uint8_t label = 1;

  bluetooth::testing::avrc::btif_rc_ctrl_get_interface()->btif_rc_ctrl_upstreams_rsp_cmd(
          AVRC_PDU_REGISTER_NOTIFICATION, &avrc_cmd, label, &p_dev);

  ASSERT_EQ(std::future_status::ready, future.wait_for(std::chrono::seconds(2)));
  auto res = future.get();
  ASSERT_EQ(res.raw_address, kDeviceAddress);
  ASSERT_EQ(res.label, label);
}

TEST_F(BtifRcTest, iterate_supported_event_list_for_interim_rsp_match) {
  btif_rc_supported_event_t event = {AVRC_EVT_PLAY_STATUS_CHANGE, 0, eREGISTERED};
  uint8_t event_id = AVRC_EVT_PLAY_STATUS_CHANGE;

  bool continue_iteration =
          bluetooth::testing::avrc::btif_rc_ctrl_get_interface()
                  ->iterate_supported_event_list_for_interim_rsp(&event, &event_id);

  ASSERT_FALSE(continue_iteration);
  ASSERT_EQ(event.status, eINTERIM);
}

TEST_F(BtifRcTest, iterate_supported_event_list_for_interim_rsp_no_match) {
  btif_rc_supported_event_t event = {AVRC_EVT_TRACK_CHANGE, 0, eREGISTERED};
  uint8_t event_id = AVRC_EVT_PLAY_STATUS_CHANGE;

  bool continue_iteration =
          bluetooth::testing::avrc::btif_rc_ctrl_get_interface()
                  ->iterate_supported_event_list_for_interim_rsp(&event, &event_id);

  ASSERT_TRUE(continue_iteration);
  ASSERT_EQ(event.status, eREGISTERED);
}

TEST_F(BtifRcTest, btif_debug_rc_dump_test) {
  // 1. Setup device state
  btif_rc_device_cb_t* p_dev =
          bluetooth::testing::avrc::btif_rc_ctrl_get_interface()->get_device_cb(0);
  p_dev->rc_state = BTRC_CONNECTION_STATE_CONNECTED;
  p_dev->rc_addr = kDeviceAddress;

  // 2. Setup a transaction for the device
  rc_transaction_set_t* transaction_set = &(p_dev->transaction_set);
  rc_transaction_t* transaction = &transaction_set->transaction[5];  // Use index 5
  transaction->in_use = true;
  transaction->label = 5;
  transaction->context = {
          .rc_addr = kDeviceAddress,
          .label = 5,
          .opcode = AVRC_OP_VENDOR,
          .command = {.vendor = {.pdu_id = AVRC_PDU_GET_PLAY_STATUS}},
  };

  // 3. Create a pipe to capture the output
  int pipe_fd[2];
  ASSERT_NE(pipe(pipe_fd), -1);

  // 4. Call the function with the write-end of the pipe
  btif_debug_rc_dump(pipe_fd[1]);

  // 5. Close the write-end to signal EOF
  close(pipe_fd[1]);

  // 6. Read the output from the read-end
  char buf[2048] = {0};
  read(pipe_fd[0], buf, sizeof(buf) - 1);

  // 7. Close the read-end
  close(pipe_fd[0]);

  std::string output(buf);

  // 8. Assert the output contains expected strings
  ASSERT_NE(output.find("AVRCP Controller Native State:"), std::string::npos);
  ASSERT_NE(output.find(kDeviceAddress.ToRedactedStringForLogging()), std::string::npos);
  ASSERT_NE(output.find("Transaction Labels:"), std::string::npos);

  // Check the specific transaction we set up
  ASSERT_NE(output.find("label=5 in_use=true"), std::string::npos);

  // Cleanup the state for other tests
  bluetooth::testing::avrc::btif_rc_ctrl_get_interface()->initialize_device(p_dev);
}

TEST_F(BtifRcTest, cleanup_ctrl_resets_device) {
  btif_rc_device_cb_t* p_dev =
          bluetooth::testing::avrc::btif_rc_ctrl_get_interface()->get_device_cb(0);

  // Set some fields to non-default values to verify they get reset
  p_dev->rc_handle = 123;
  p_dev->rc_features = 0x1234;
  p_dev->rc_cover_art_psm = 0x5678;
  p_dev->rc_state = BTRC_CONNECTION_STATE_CONNECTED;
  p_dev->br_state = BTRC_CONNECTION_STATE_CONNECTED;
  p_dev->rc_addr = kDeviceAddress;
  p_dev->rc_volume = 50;
  p_dev->rc_vol_label = 5;
  p_dev->rc_features_processed = true;
  p_dev->rc_playing_uid = 0x11223344;
  p_dev->rc_procedure_complete = true;
  p_dev->peer_ct_features = 0x1111;
  p_dev->peer_tg_features = 0x2222;
  p_dev->launch_cmd_pending = 1;

  // Allocate a list to ensure it gets freed
  p_dev->rc_supported_event_list = list_new(osi_free);

  // Set up a transaction
  p_dev->transaction_set.transaction[0].in_use = true;
  p_dev->transaction_set.transaction[0].label = 10;

  // Call cleanup, which internally calls reset_device for all connections
  btif_rc_ctrl_get_interface()->cleanup();

  // Verify fields are safely reset to their default states
  EXPECT_EQ(p_dev->rc_handle, 0);
  EXPECT_EQ(p_dev->rc_features, 0u);
  EXPECT_EQ(p_dev->rc_cover_art_psm, 0);
  EXPECT_EQ(p_dev->rc_state, BTRC_CONNECTION_STATE_DISCONNECTED);
  EXPECT_EQ(p_dev->br_state, BTRC_CONNECTION_STATE_DISCONNECTED);
  EXPECT_EQ(p_dev->rc_addr, RawAddress::kEmpty);
  EXPECT_EQ(p_dev->rc_volume, static_cast<unsigned int>(MAX_VOLUME));
  EXPECT_EQ(p_dev->rc_vol_label, MAX_LABEL);
  EXPECT_EQ(p_dev->rc_supported_event_list, nullptr);
  EXPECT_FALSE(p_dev->rc_features_processed);
  EXPECT_EQ(p_dev->rc_playing_uid, 0u);
  EXPECT_FALSE(p_dev->rc_procedure_complete);
  EXPECT_EQ(p_dev->peer_ct_features, 0u);
  EXPECT_EQ(p_dev->peer_tg_features, 0u);
  EXPECT_EQ(p_dev->launch_cmd_pending, 0u);
  EXPECT_FALSE(p_dev->transaction_set.transaction[0].in_use);
  EXPECT_EQ(p_dev->transaction_set.transaction[0].label, 0);
}

TEST_F(BtifRcWithCallbacksTest, register_for_event_notification_test) {
  btif_rc_device_cb_t* p_dev =
          bluetooth::testing::avrc::btif_rc_ctrl_get_interface()->get_device_cb(0);
  // Clear transactions
  for (int i = 0; i < MAX_TRANSACTIONS_PER_SESSION; i++) {
    p_dev->transaction_set.transaction[i].in_use = false;
    p_dev->transaction_set.transaction[i].label = i;
  }

  btif_rc_supported_event_t event = {AVRC_EVT_PLAY_STATUS_CHANGE, true};

  bluetooth::testing::avrc::btif_rc_ctrl_get_interface()->register_for_event_notification(&event,
                                                                                          p_dev);
}

TEST_F(BtifRcHandlerTest, clear_cmd_timeout_test) {
  btif_rc_device_cb_t* p_dev =
          bluetooth::testing::avrc::btif_rc_ctrl_get_interface()->get_device_cb(0);
  uint8_t label = 1;
  p_dev->transaction_set.transaction[label].in_use = true;
  p_dev->transaction_set.transaction[label].timer = alarm_new("test");

  bluetooth::testing::avrc::btif_rc_ctrl_get_interface()->clear_cmd_timeout(p_dev, label);
  // The alarm_free mock will be called, which is what we are testing.
  // No direct assert, but this tests the path.
}

TEST_F(BtifRcWithCallbacksTest, list_player_app_setting_attrib_cmd_test) {
  btif_rc_device_cb_t* p_dev =
          bluetooth::testing::avrc::btif_rc_ctrl_get_interface()->get_device_cb(0);
  // Clear transactions
  for (int i = 0; i < MAX_TRANSACTIONS_PER_SESSION; i++) {
    p_dev->transaction_set.transaction[i].in_use = false;
    p_dev->transaction_set.transaction[i].label = i;
  }

  BtStatus status = bluetooth::testing::avrc::btif_rc_ctrl_get_interface()
                            ->list_player_app_setting_attrib_cmd(p_dev);
  ASSERT_EQ(status, BtifStatus());
}

TEST_F(BtifRcWithCallbacksTest, get_current_metadata_cmd_test) {
  btif_rc_device_cb_t* p_dev =
          allocate_dev(0, kDeviceAddress, BTRC_CONNECTION_STATE_CONNECTED, kRcHandle);
  // Clear transactions
  for (int i = 0; i < MAX_TRANSACTIONS_PER_SESSION; i++) {
    p_dev->transaction_set.transaction[i].in_use = false;
    p_dev->transaction_set.transaction[i].label = i;
  }
  BtStatus status = btif_rc_ctrl_get_interface()->get_current_metadata_cmd(kDeviceAddress);
  ASSERT_EQ(status, BtifStatus());
}
TEST_F(BtifRcWithCallbacksTest, get_current_metadata_cmd_test_error) {
  btif_rc_device_cb_t* p_dev =
          allocate_dev(0, kDeviceAddress, BTRC_CONNECTION_STATE_CONNECTED, kRcHandle);
  // Clear transactions
  for (int i = 0; i < MAX_TRANSACTIONS_PER_SESSION; i++) {
    p_dev->transaction_set.transaction[i].in_use = false;
    p_dev->transaction_set.transaction[i].label = i;
  }

  const RawAddress unknown_address = RawAddress("de:ad:be:ef:12:34");
  BtStatus status = btif_rc_ctrl_get_interface()->get_current_metadata_cmd(unknown_address);
  ASSERT_EQ(status, BtifStatus(DEVICE_NOT_FOUND));
}

TEST_F(BtifRcWithCallbacksTest, get_playback_state_cmd_test) {
  btif_rc_device_cb_t* p_dev =
          allocate_dev(0, kDeviceAddress, BTRC_CONNECTION_STATE_CONNECTED, kRcHandle);
  // Clear transactions
  for (int i = 0; i < MAX_TRANSACTIONS_PER_SESSION; i++) {
    p_dev->transaction_set.transaction[i].in_use = false;
    p_dev->transaction_set.transaction[i].label = i;
  }
  BtStatus status = btif_rc_ctrl_get_interface()->get_playback_state_cmd(kDeviceAddress);
  ASSERT_EQ(status, BtifStatus());
}

TEST_F(BtifRcWithCallbacksTest, get_now_playing_list_cmd_test) {
  btif_rc_device_cb_t* p_dev =
          bluetooth::testing::avrc::btif_rc_ctrl_get_interface()->get_device_cb(0);
  p_dev->br_state = BTRC_CONNECTION_STATE_CONNECTED;
  // Clear transactions
  for (int i = 0; i < MAX_TRANSACTIONS_PER_SESSION; i++) {
    p_dev->transaction_set.transaction[i].in_use = false;
    p_dev->transaction_set.transaction[i].label = i;
  }
  BtStatus status =
          btif_rc_ctrl_get_interface()->get_now_playing_list_cmd(kDeviceAddress, 0, 0xFFFFFFFF);
  ASSERT_EQ(status, BtifStatus(FAIL));
}

TEST_F(BtifRcWithCallbacksTest, get_folder_list_cmd_test) {
  btif_rc_device_cb_t* p_dev =
          bluetooth::testing::avrc::btif_rc_ctrl_get_interface()->get_device_cb(0);
  p_dev->br_state = BTRC_CONNECTION_STATE_CONNECTED;
  // Clear transactions
  for (int i = 0; i < MAX_TRANSACTIONS_PER_SESSION; i++) {
    p_dev->transaction_set.transaction[i].in_use = false;
    p_dev->transaction_set.transaction[i].label = i;
  }
  BtStatus status =
          btif_rc_ctrl_get_interface()->get_folder_list_cmd(kDeviceAddress, 0, 0xFFFFFFFF);
  ASSERT_EQ(status, BtifStatus(FAIL));
}
