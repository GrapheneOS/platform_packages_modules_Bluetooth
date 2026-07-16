/*
 * Copyright 2015 The Android Open Source Project
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

/*****************************************************************************
 *
 *  Filename:      btif_rc.cc
 *
 *  Description:   Bluetooth AVRC implementation
 *
 *****************************************************************************/

#define LOG_TAG "bt_btif_avrc"

#include "btif_rc.h"

#include <base/functional/bind.h>
#include <bluetooth/log.h>
#include <bluetooth/types/address.h>
#include <hardware/bluetooth.h>
#include <hardware/bt_rc.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include <cstdint>
#include <cstdio>
#include <mutex>
#include <sstream>
#include <string>

#include "bta/include/bta_av_api.h"
#include "btif/avrcp/avrcp_service.h"
#include "btif_av.h"
#include "btif_common.h"
#include "btif_status.h"
#include "btif_util.h"
#include "osi/include/alarm.h"
#include "osi/include/allocator.h"
#include "osi/include/list.h"
#include "osi/include/properties.h"
#include "stack/include/avrc_api.h"
#include "stack/include/avrc_defs.h"
#include "stack/include/bt_hdr.h"
#include "stack/include/bt_types.h"

using namespace bluetooth;

static void initialize_device(btif_rc_device_cb_t* p_dev);
static void send_reject_response(uint8_t rc_handle, uint8_t label, uint8_t pdu, uint8_t status,
                                 uint8_t opcode);
static void init_all_transactions(btif_rc_device_cb_t* p_dev);
static BtStatus get_transaction(btif_rc_device_cb_t* p_dev, rc_transaction_context_t& context,
                                rc_transaction_t** ptransaction);
static void start_transaction_timer(btif_rc_device_cb_t* p_dev, uint8_t label, uint64_t timeout_ms);
static void btif_rc_transaction_timer_timeout(void* data);
static void release_transaction(btif_rc_device_cb_t* p_dev, uint8_t label);
static std::string dump_transaction(const rc_transaction_t* const transaction);
static rc_transaction_t* get_transaction_by_lbl(btif_rc_device_cb_t* p_dev, uint8_t label);

static void handle_avk_rc_metamsg_cmd(tBTA_AV_META_MSG* pmeta_msg);
static void handle_avk_rc_metamsg_rsp(tBTA_AV_META_MSG* pmeta_msg);
static void btif_rc_ctrl_upstreams_rsp_cmd(uint8_t event, tAVRC_COMMAND* pavrc_cmd, uint8_t label,
                                           btif_rc_device_cb_t* p_dev);
static void rc_ctrl_procedure_complete(btif_rc_device_cb_t* p_dev);
static void register_for_event_notification(btif_rc_supported_event_t* p_event,
                                            btif_rc_device_cb_t* p_dev);
static void handle_get_capability_response(tBTA_AV_META_MSG* pmeta_msg, tAVRC_GET_CAPS_RSP* p_rsp);
static void handle_app_attr_response(tBTA_AV_META_MSG* pmeta_msg, tAVRC_LIST_APP_ATTR_RSP* p_rsp);
static void handle_app_val_response(tBTA_AV_META_MSG* pmeta_msg, tAVRC_LIST_APP_VALUES_RSP* p_rsp);
static void handle_app_cur_val_response(tBTA_AV_META_MSG* pmeta_msg,
                                        tAVRC_GET_CUR_APP_VALUE_RSP* p_rsp);
static void handle_app_attr_txt_response(tBTA_AV_META_MSG* pmeta_msg,
                                         tAVRC_GET_APP_ATTR_TXT_RSP* p_rsp);
static void handle_app_attr_val_txt_response(tBTA_AV_META_MSG* pmeta_msg,
                                             tAVRC_GET_APP_ATTR_TXT_RSP* p_rsp);
static void cleanup_app_attr_val_txt_response(btif_rc_player_app_settings_t* p_app_settings);
static void handle_get_playstatus_response(tBTA_AV_META_MSG* pmeta_msg,
                                           tAVRC_GET_PLAY_STATUS_RSP* p_rsp);
static void handle_set_addressed_player_response(tBTA_AV_META_MSG* pmeta_msg, tAVRC_RSP* p_rsp);
static void cleanup_btrc_folder_items(btrc_folder_items_t* btrc_items, uint8_t item_count);
static void handle_get_metadata_attr_response(tBTA_AV_META_MSG* pmeta_msg,
                                              tAVRC_GET_ATTRS_RSP* p_rsp);
static void handle_set_app_attr_val_response(tBTA_AV_META_MSG* pmeta_msg, tAVRC_RSP* p_rsp);
static BtStatus get_play_status_cmd(btif_rc_device_cb_t* p_dev);
static BtStatus get_player_app_setting_attr_text_cmd(uint8_t* attrs, uint8_t num_attrs,
                                                     btif_rc_device_cb_t* p_dev);
static BtStatus get_player_app_setting_value_text_cmd(uint8_t* vals, uint8_t num_vals,
                                                      btif_rc_device_cb_t* p_dev);
static BtStatus register_notification_cmd(uint8_t event_id, uint32_t event_value,
                                          btif_rc_device_cb_t* p_dev);
static BtStatus get_metadata_attribute_cmd(uint8_t num_attribute, const uint32_t* p_attr_ids,
                                           btif_rc_device_cb_t* p_dev);
static BtStatus get_element_attribute_cmd(uint8_t num_attribute, const uint32_t* p_attr_ids,
                                          btif_rc_device_cb_t* p_dev);
static BtStatus get_item_attribute_cmd(uint64_t uid, int scope, uint8_t num_attribute,
                                       const uint32_t* p_attr_ids, btif_rc_device_cb_t* p_dev);
static BtStatus getcapabilities_cmd(uint8_t cap_id, btif_rc_device_cb_t* p_dev);
static BtStatus list_player_app_setting_attrib_cmd(btif_rc_device_cb_t* p_dev);
static BtStatus list_player_app_setting_value_cmd(uint8_t attrib_id, btif_rc_device_cb_t* p_dev);
static BtStatus get_player_app_setting_cmd(uint8_t num_attrib, uint8_t* attrib_ids,
                                           btif_rc_device_cb_t* p_dev);
static void get_folder_item_type_media(const tAVRC_ITEM* avrc_item, btrc_folder_items_t* btrc_item);
static void get_folder_item_type_folder(const tAVRC_ITEM* avrc_item,
                                        btrc_folder_items_t* btrc_item);
static void get_folder_item_type_player(const tAVRC_ITEM* avrc_item,
                                        btrc_folder_items_t* btrc_item);
static BtStatus get_folder_items_cmd(const RawAddress& bd_addr, uint8_t scope, uint32_t start_item,
                                     uint32_t end_item);
static std::string dump_peer_features(const uint16_t feats);

#define CTRL_HAL_CBACK(P_CBACK, ...)                                          \
  do {                                                                        \
    if (bt_rc_ctrl_callbacks) {                                               \
      do_in_jni_thread(base::BindOnce(P_CBACK, __VA_ARGS__));                 \
    } else {                                                                  \
      bluetooth::log::error("bt_rc_ctrl_callbacks is null for {}", #P_CBACK); \
    }                                                                         \
  } while (0)

/*****************************************************************************
 *  Static variables
 *****************************************************************************/
constexpr btrc_connection_state_t kRcIsConnected = BTRC_CONNECTION_STATE_CONNECTED;
constexpr btrc_connection_state_t kRcIsDisconnected = BTRC_CONNECTION_STATE_DISCONNECTED;
constexpr btrc_connection_state_t kBrowseIsConnected = BTRC_CONNECTION_STATE_CONNECTED;
constexpr btrc_connection_state_t kBrowseIsDisconnected = BTRC_CONNECTION_STATE_DISCONNECTED;

static rc_cb_t btif_rc_cb;
static btrc_ctrl_callbacks_t* bt_rc_ctrl_callbacks = NULL;

// List of desired media attribute keys to request by default
static const uint32_t media_attr_list[] = {
        AVRC_MEDIA_ATTR_ID_TITLE,        AVRC_MEDIA_ATTR_ID_ARTIST,
        AVRC_MEDIA_ATTR_ID_ALBUM,        AVRC_MEDIA_ATTR_ID_TRACK_NUM,
        AVRC_MEDIA_ATTR_ID_NUM_TRACKS,   AVRC_MEDIA_ATTR_ID_GENRE,
        AVRC_MEDIA_ATTR_ID_PLAYING_TIME, AVRC_MEDIA_ATTR_ID_COVER_ARTWORK_HANDLE};
static const uint8_t media_attr_list_size = sizeof(media_attr_list) / sizeof(uint32_t);

// List of desired media attribute keys to request if cover artwork is not a
// supported feature
static const uint32_t media_attr_list_no_cover_art[] = {
        AVRC_MEDIA_ATTR_ID_TITLE,       AVRC_MEDIA_ATTR_ID_ARTIST,     AVRC_MEDIA_ATTR_ID_ALBUM,
        AVRC_MEDIA_ATTR_ID_TRACK_NUM,   AVRC_MEDIA_ATTR_ID_NUM_TRACKS, AVRC_MEDIA_ATTR_ID_GENRE,
        AVRC_MEDIA_ATTR_ID_PLAYING_TIME};
static const uint8_t media_attr_list_no_cover_art_size =
        sizeof(media_attr_list_no_cover_art) / sizeof(uint32_t);

/*****************************************************************************
 *  Static functions
 *****************************************************************************/

/*****************************************************************************
 *  Externs
 *****************************************************************************/

void btif_rc_get_addr_by_handle(uint8_t handle, RawAddress& rc_addr) {
  log::verbose("handle: 0x{:x}", handle);
  for (int idx = 0; idx < BTIF_RC_NUM_CONN; idx++) {
    if ((btif_rc_cb.rc_multi_cb[idx].rc_state != BTRC_CONNECTION_STATE_DISCONNECTED) &&
        (btif_rc_cb.rc_multi_cb[idx].rc_handle == handle)) {
      log::verbose("btif_rc_cb.rc_multi_cb[idx].rc_handle: 0x{:x}",
                   btif_rc_cb.rc_multi_cb[idx].rc_handle);
      rc_addr = btif_rc_cb.rc_multi_cb[idx].rc_addr;
      return;
    }
  }
  log::error("returning NULL");
  rc_addr = RawAddress::kEmpty;
  return;
}

/*****************************************************************************
 *  Functions
 *****************************************************************************/
static btif_rc_device_cb_t* alloc_device() {
  for (int idx = 0; idx < BTIF_RC_NUM_CONN; idx++) {
    if (btif_rc_cb.rc_multi_cb[idx].rc_state == BTRC_CONNECTION_STATE_DISCONNECTED) {
      return &btif_rc_cb.rc_multi_cb[idx];
    }
  }
  return NULL;
}

static void dealloc_device(btif_rc_device_cb_t* p_dev) {
  CHECK(p_dev != nullptr);
  p_dev->rc_handle = 0;
  p_dev->rc_features = 0;
  p_dev->rc_state = BTRC_CONNECTION_STATE_DISCONNECTED;
  p_dev->br_state = BTRC_CONNECTION_STATE_DISCONNECTED;
  p_dev->rc_addr = RawAddress::kEmpty;
  p_dev->rc_volume = MAX_VOLUME;
  p_dev->rc_vol_label = MAX_LABEL;
  p_dev->peer_ct_features = 0;
  p_dev->peer_tg_features = 0;
  p_dev->launch_cmd_pending = 0;
}

static void initialize_device(btif_rc_device_cb_t* p_dev) {
  if (p_dev == nullptr) {
    return;
  }

  dealloc_device(p_dev);
  p_dev->rc_cover_art_psm = 0;
  if (p_dev->rc_supported_event_list != nullptr) {
    list_clear(p_dev->rc_supported_event_list);
  }
  p_dev->rc_supported_event_list = nullptr;
  memset(&p_dev->rc_app_settings, 0, sizeof(btif_rc_player_app_settings_t));
  p_dev->rc_play_status_timer = nullptr;
  p_dev->rc_features_processed = false;
  p_dev->rc_playing_uid = 0;
  p_dev->rc_procedure_complete = false;

  // Reset the transaction set for this device. If this initialize_device() call
  // is made due to a disconnect event, this cancels any pending timers too.
  init_all_transactions(p_dev);
}

static btif_rc_device_cb_t* get_connected_device(int index) {
  log::verbose("index: {}", index);
  if (index >= BTIF_RC_NUM_CONN) {
    log::error("can't support more than {} connections", BTIF_RC_NUM_CONN);
    return NULL;
  }
  if (btif_rc_cb.rc_multi_cb[index].rc_state != BTRC_CONNECTION_STATE_CONNECTED) {
    return NULL;
  }
  return &btif_rc_cb.rc_multi_cb[index];
}

static btif_rc_device_cb_t* btif_rc_get_device_by_bda(const RawAddress& bd_addr) {
  log::verbose("bd_addr: {}", bd_addr);

  for (int idx = 0; idx < BTIF_RC_NUM_CONN; idx++) {
    if ((btif_rc_cb.rc_multi_cb[idx].rc_state != BTRC_CONNECTION_STATE_DISCONNECTED) &&
        btif_rc_cb.rc_multi_cb[idx].rc_addr == bd_addr) {
      return &btif_rc_cb.rc_multi_cb[idx];
    }
  }
  log::error("device not found, returning NULL!");
  return NULL;
}

static btif_rc_device_cb_t* btif_rc_get_device_by_handle(uint8_t handle) {
  log::verbose("handle: 0x{:x}", handle);
  for (int idx = 0; idx < BTIF_RC_NUM_CONN; idx++) {
    if ((btif_rc_cb.rc_multi_cb[idx].rc_state != BTRC_CONNECTION_STATE_DISCONNECTED) &&
        (btif_rc_cb.rc_multi_cb[idx].rc_handle == handle)) {
      log::verbose("btif_rc_cb.rc_multi_cb[idx].rc_handle: 0x{:x}",
                   btif_rc_cb.rc_multi_cb[idx].rc_handle);
      return &btif_rc_cb.rc_multi_cb[idx];
    }
  }
  log::error("returning NULL");
  return NULL;
}

static const uint32_t* get_requested_attributes_list(btif_rc_device_cb_t* p_dev) {
  return p_dev->rc_features & BTA_AV_FEAT_COVER_ARTWORK ? media_attr_list
                                                        : media_attr_list_no_cover_art;
}

static uint8_t get_requested_attributes_list_size(btif_rc_device_cb_t* p_dev) {
  return p_dev->rc_features & BTA_AV_FEAT_COVER_ARTWORK ? media_attr_list_size
                                                        : media_attr_list_no_cover_art_size;
}

static void handle_rc_ctrl_features_all(btif_rc_device_cb_t* p_dev) {
  if (!(p_dev->peer_tg_features & BTA_AV_FEAT_RCTG) &&
      (!(p_dev->peer_tg_features & BTA_AV_FEAT_RCCT) ||
       !(p_dev->peer_tg_features & BTA_AV_FEAT_ADV_CTRL))) {
    return;
  }

  int rc_features = 0;

  log::verbose(
          "peer_tg_features: 0x{:x}, rc_features_processed={}, connected={}, "
          "peer_is_src:{}",
          p_dev->peer_tg_features, p_dev->rc_features_processed,
          btif_av_is_connected_addr(p_dev->rc_addr, A2dpType::kSink),
          btif_av_peer_is_source(p_dev->rc_addr));

  if ((p_dev->peer_tg_features & BTA_AV_FEAT_ADV_CTRL) &&
      (p_dev->peer_tg_features & BTA_AV_FEAT_RCCT)) {
    rc_features |= BTRC_FEAT_ABSOLUTE_VOLUME;
  }

  if ((p_dev->peer_tg_features & BTA_AV_FEAT_METADATA) &&
      (p_dev->peer_tg_features & BTA_AV_FEAT_VENDOR) && (p_dev->rc_features_processed != true)) {
    rc_features |= BTRC_FEAT_METADATA;

    /* Mark rc features processed to avoid repeating
     * the AVRCP procedure every time on receiving this
     * update.
     */
    p_dev->rc_features_processed = true;
  }

  if (btif_av_is_connected_addr(p_dev->rc_addr, A2dpType::kSink)) {
    if (btif_av_peer_is_source(p_dev->rc_addr)) {
      p_dev->rc_features = p_dev->peer_tg_features;
      if ((p_dev->peer_tg_features & BTA_AV_FEAT_METADATA) &&
          (p_dev->peer_tg_features & BTA_AV_FEAT_VENDOR)) {
        getcapabilities_cmd(AVRC_CAP_COMPANY_ID, p_dev);
      }
    }
  } else {
    log::verbose("{} is not connected, pending", p_dev->rc_addr);
    p_dev->launch_cmd_pending |= (RC_PENDING_ACT_GET_CAP | RC_PENDING_ACT_REG_VOL);
  }

  /* Add browsing feature capability */
  if (p_dev->peer_tg_features & BTA_AV_FEAT_BROWSE) {
    rc_features |= BTRC_FEAT_BROWSE;
  }

  /* Add cover art feature capability */
  if (p_dev->peer_tg_features & BTA_AV_FEAT_COVER_ARTWORK) {
    rc_features |= BTRC_FEAT_COVER_ARTWORK;
  }

  log::verbose("Update rc features to CTRL: {}", rc_features);
  CTRL_HAL_CBACK(bt_rc_ctrl_callbacks->getrcfeatures_cb, p_dev->rc_addr, rc_features);
}

static void handle_rc_ctrl_features(btif_rc_device_cb_t* p_dev) {
  if (btif_av_src_sink_coexist_enabled() && btif_av_both_enable()) {
    handle_rc_ctrl_features_all(p_dev);
    return;
  }

  if (!(p_dev->rc_features & BTA_AV_FEAT_RCTG) &&
      (!(p_dev->rc_features & BTA_AV_FEAT_RCCT) || !(p_dev->rc_features & BTA_AV_FEAT_ADV_CTRL))) {
    return;
  }

  int rc_features = 0;

  if ((p_dev->rc_features & BTA_AV_FEAT_ADV_CTRL) && (p_dev->rc_features & BTA_AV_FEAT_RCCT)) {
    rc_features |= BTRC_FEAT_ABSOLUTE_VOLUME;
  }

  if (p_dev->rc_features & BTA_AV_FEAT_METADATA) {
    rc_features |= BTRC_FEAT_METADATA;
  }

  if ((p_dev->rc_features & BTA_AV_FEAT_VENDOR) && (p_dev->rc_features_processed != true)) {
    /* Mark rc features processed to avoid repeating
     * the AVRCP procedure every time on receiving this
     * update.
     */
    p_dev->rc_features_processed = true;
    if (btif_av_is_sink_enabled()) {
      getcapabilities_cmd(AVRC_CAP_COMPANY_ID, p_dev);
    }
  }

  /* Add browsing feature capability */
  if (p_dev->rc_features & BTA_AV_FEAT_BROWSE) {
    rc_features |= BTRC_FEAT_BROWSE;
  }

  /* Add cover art feature capability */
  if (p_dev->rc_features & BTA_AV_FEAT_COVER_ARTWORK) {
    rc_features |= BTRC_FEAT_COVER_ARTWORK;
  }

  log::verbose("Update rc features to CTRL: {}", rc_features);
  CTRL_HAL_CBACK(bt_rc_ctrl_callbacks->getrcfeatures_cb, p_dev->rc_addr, rc_features);
}
void btif_rc_check_pending_cmd(const RawAddress& peer_address) {
  btif_rc_device_cb_t* p_dev = btif_rc_get_device_by_bda(peer_address);
  if (p_dev == nullptr) {
    log::error("p_dev NULL for addr: {}", peer_address);
    return;
  }

  log::verbose(
          "launch_cmd_pending={}, rc_state={}, peer_ct_features=0x{:x}, peer_tg_features=0x{:x}",
          p_dev->launch_cmd_pending, p_dev->rc_state, p_dev->peer_ct_features,
          p_dev->peer_tg_features);

  uint8_t pending_cmds = p_dev->launch_cmd_pending;
  p_dev->launch_cmd_pending = 0;

  if (p_dev->rc_state != BTRC_CONNECTION_STATE_CONNECTED || pending_cmds == 0) {
    return;
  }

  if ((pending_cmds & RC_PENDING_ACT_REG_VOL) && btif_av_peer_is_sink(peer_address)) {
    if (bluetooth::avrcp::AvrcpService::Get() != nullptr) {
      bluetooth::avrcp::AvrcpService::Get()->RegisterVolChanged(peer_address);
    }
  }

  if ((pending_cmds & RC_PENDING_ACT_GET_CAP) && btif_av_peer_is_source(peer_address)) {
    p_dev->rc_features = p_dev->peer_tg_features;
    getcapabilities_cmd(AVRC_CAP_COMPANY_ID, p_dev);
  }

  if ((pending_cmds & RC_PENDING_ACT_REPORT_CONN) && btif_av_peer_is_source(peer_address)) {
    CTRL_HAL_CBACK(bt_rc_ctrl_callbacks->connection_state_cb, peer_address, kRcIsConnected,
                   kBrowseIsDisconnected);
  }
}

static void handle_rc_ctrl_psm(btif_rc_device_cb_t* p_dev) {
  uint16_t cover_art_psm = p_dev->rc_cover_art_psm;
  log::verbose("Update rc cover art psm to CTRL: {}", cover_art_psm);
  CTRL_HAL_CBACK(bt_rc_ctrl_callbacks->get_cover_art_psm_cb, p_dev->rc_addr, cover_art_psm);
}

/***************************************************************************
 *  Function       handle_rc_browse_connect
 *
 *  - Argument:    tBTA_AV_RC_OPEN  browse RC open data structure
 *
 *  - Description: browse RC connection event handler
 *
 ***************************************************************************/
static void handle_rc_browse_connect(tBTA_AV_RC_BROWSE_OPEN* p_rc_br_open) {
  log::verbose("rc_handle {} status {}", p_rc_br_open->rc_handle, p_rc_br_open->status);
  btif_rc_device_cb_t* p_dev = btif_rc_get_device_by_handle(p_rc_br_open->rc_handle);

  if (!p_dev) {
    log::error("p_dev is null");
    return;
  }

  /* check that we are already connected to this address since being connected
   * to a browse when not connected to the control channel over AVRCP is
   * probably not preferred anyways. */
  if (p_rc_br_open->status == BTA_AV_SUCCESS) {
    p_dev->br_state = BTRC_CONNECTION_STATE_CONNECTED;
    if (btif_av_src_sink_coexist_enabled()) {
      if (btif_av_peer_is_connected_source(p_dev->rc_addr)) {
        CTRL_HAL_CBACK(bt_rc_ctrl_callbacks->connection_state_cb, p_dev->rc_addr, kRcIsConnected,
                       kBrowseIsConnected);
      } else {
        p_dev->launch_cmd_pending |= RC_PENDING_ACT_REPORT_CONN;
        log::verbose("pending rc browse connection event");
      }
    } else {
      CTRL_HAL_CBACK(bt_rc_ctrl_callbacks->connection_state_cb, p_dev->rc_addr, kRcIsConnected,
                     kBrowseIsConnected);
    }
  }
}

/***************************************************************************
 *  Function       handle_rc_connect
 *
 *  - Argument:    tBTA_AV_RC_OPEN  RC open data structure
 *
 *  - Description: RC connection event handler
 *
 ***************************************************************************/
static void handle_rc_connect(tBTA_AV_RC_OPEN* p_rc_open) {
  log::info("handle_rc_connect(handle={}, addr={})", p_rc_open->rc_handle, p_rc_open->peer_addr);

  btif_rc_device_cb_t* p_dev = alloc_device();
  if (p_dev == NULL) {
    log::error("p_dev is NULL");
    return;
  }

  if (!(p_rc_open->status == BTA_AV_SUCCESS)) {
    log::error("Connect failed with error code: {}", p_rc_open->status);
    dealloc_device(p_dev);
    BTA_AvCloseRc(p_rc_open->rc_handle);
    return;
  }

  // check if already some RC is connected
  if (p_dev->rc_state == BTRC_CONNECTION_STATE_CONNECTED) {
    log::error("Got RC OPEN in connected state, Connected RC: {} and Current RC: {}",
               p_dev->rc_handle, p_rc_open->rc_handle);
    if (p_dev->rc_handle != p_rc_open->rc_handle && p_dev->rc_addr != p_rc_open->peer_addr) {
      log::verbose("Got RC connected for some other handle");
      BTA_AvCloseRc(p_rc_open->rc_handle);
      return;
    }
  }
  p_dev->rc_addr = p_rc_open->peer_addr;
  p_dev->rc_features = p_rc_open->peer_features;
  p_dev->peer_ct_features = p_rc_open->peer_ct_features;
  p_dev->peer_tg_features = p_rc_open->peer_tg_features;
  p_dev->rc_cover_art_psm = p_rc_open->cover_art_psm;
  p_dev->rc_vol_label = MAX_LABEL;
  p_dev->rc_volume = MAX_VOLUME;

  log::verbose(
          "handle_rc_connect in features={:#x}, out features={:#x}, "
          "ct_feature={:#x}, tg_feature={:#x}, cover art psm={:#x}",
          p_rc_open->peer_features, p_dev->rc_features, p_dev->peer_ct_features,
          p_dev->peer_tg_features, p_dev->rc_cover_art_psm);

  p_dev->rc_handle = p_rc_open->rc_handle;
  p_dev->rc_state = BTRC_CONNECTION_STATE_CONNECTED;

  p_dev->rc_playing_uid = RC_INVALID_TRACK_ID;

  if (btif_av_src_sink_coexist_enabled() && !btif_av_peer_is_connected_source(p_dev->rc_addr)) {
    p_dev->launch_cmd_pending |= RC_PENDING_ACT_REPORT_CONN;
    log::verbose("pending rc connection event");
    return;
  }
  CTRL_HAL_CBACK(bt_rc_ctrl_callbacks->connection_state_cb, p_dev->rc_addr, kRcIsConnected,
                 kBrowseIsDisconnected);

  /* report connection state if remote device is AVRCP target */
  handle_rc_ctrl_features(p_dev);

  /* report psm if remote device is AVRCP target */
  handle_rc_ctrl_psm(p_dev);
}

/***************************************************************************
 *  Function       handle_rc_disconnect
 *
 *  - Argument:    tBTA_AV_RC_CLOSE     RC close data structure
 *
 *  - Description: RC disconnection event handler
 *
 ***************************************************************************/
static void handle_rc_disconnect(tBTA_AV_RC_CLOSE* p_rc_close) {
  btif_rc_device_cb_t* p_dev = NULL;
  log::info("handle_rc_disconnect(handle={}, addr={})", p_rc_close->rc_handle,
               p_rc_close->peer_addr);

  p_dev = btif_rc_get_device_by_handle(p_rc_close->rc_handle);
  if (p_dev == NULL) {
    log::error("Got disconnect from invalid rc handle");
    return;
  }

  if (p_rc_close->rc_handle != p_dev->rc_handle && p_dev->rc_addr != p_rc_close->peer_addr) {
    log::error("Got disconnect of unknown device");
    return;
  }

  /* Report connection state if device is AVRCP target */
  CTRL_HAL_CBACK(bt_rc_ctrl_callbacks->connection_state_cb, p_dev->rc_addr, kRcIsDisconnected,
                 kBrowseIsDisconnected);

  // We'll re-initialize the device state back to what it looked like before
  // the connection. This will free ongoing transaction labels and clear any
  // running label timers
  initialize_device(p_dev);
}

/***************************************************************************
 *  Function       handle_rc_passthrough_rsp
 *
 *  - Argument:    tBTA_AV_REMOTE_RSP passthrough command response
 *
 *  - Description: Remote control passthrough response handler
 *
 ***************************************************************************/
static void handle_rc_passthrough_rsp(tBTA_AV_REMOTE_RSP* p_remote_rsp) {
  btif_rc_device_cb_t* p_dev = NULL;

  p_dev = btif_rc_get_device_by_handle(p_remote_rsp->rc_handle);
  if (p_dev == NULL) {
    log::error("passthrough response for Invalid rc handle");
    return;
  }

  if (!(p_dev->rc_features & BTA_AV_FEAT_RCTG)) {
    log::error("DUT does not support AVRCP controller role");
    return;
  }

  const char* status = (p_remote_rsp->key_state == 1) ? "released" : "pressed";
  log::verbose("rc_id: {} state: {}", p_remote_rsp->rc_id, status);

  release_transaction(p_dev, p_remote_rsp->label);
  CTRL_HAL_CBACK(bt_rc_ctrl_callbacks->passthrough_rsp_cb, p_dev->rc_addr, p_remote_rsp->rc_id,
                 p_remote_rsp->key_state);
}

/***************************************************************************
 *  Function       handle_rc_vendorunique_rsp
 *
 *  - Argument:    tBTA_AV_REMOTE_RSP  command response
 *
 *  - Description: Remote control vendor unique response handler
 *
 ***************************************************************************/
static void handle_rc_vendorunique_rsp(tBTA_AV_REMOTE_RSP* p_remote_rsp) {
  btif_rc_device_cb_t* p_dev = NULL;
  const char* status;
  uint8_t vendor_id = 0;

  p_dev = btif_rc_get_device_by_handle(p_remote_rsp->rc_handle);
  if (p_dev == NULL) {
    log::error("Got vendorunique rsp from invalid rc handle");
    return;
  }

  if (p_dev->rc_features & BTA_AV_FEAT_RCTG) {
    int key_state;
    if (p_remote_rsp->key_state == AVRC_STATE_RELEASE) {
      status = "released";
      key_state = 1;
    } else {
      status = "pressed";
      key_state = 0;
    }

    if (p_remote_rsp->len > 0 && p_remote_rsp->p_data != NULL) {
      if (p_remote_rsp->len >= AVRC_PASS_THRU_GROUP_LEN) {
        vendor_id = p_remote_rsp->p_data[AVRC_PASS_THRU_GROUP_LEN - 1];
      }
      osi_free_and_reset((void**)&p_remote_rsp->p_data);
    }
    log::verbose("vendor_id: {} status: {}", vendor_id, status);

    release_transaction(p_dev, p_remote_rsp->label);
    CTRL_HAL_CBACK(bt_rc_ctrl_callbacks->groupnavigation_rsp_cb, vendor_id, key_state);
  } else {
    log::error("Remote does not support AVRCP TG role");
  }
}

/***************************************************************************
 **
 ** Function       btif_rc_handler
 **
 ** Description    RC event handler
 **
 ***************************************************************************/
void btif_rc_handler(tBTA_AV_EVT event, tBTA_AV* p_data) {
  log::verbose("event: {}", dump_rc_event(event));
  btif_rc_device_cb_t* p_dev = NULL;
  switch (event) {
    case BTA_AV_RC_OPEN_EVT: {
      log::verbose("Peer_features: 0x{:x} Cover Art PSM: 0x{:x}", p_data->rc_open.peer_features,
                   p_data->rc_open.cover_art_psm);
      handle_rc_connect(&(p_data->rc_open));
    } break;

    case BTA_AV_RC_BROWSE_OPEN_EVT: {
      /* tell the UL that we have connection to browse channel and that
       * browse commands can be directed accordingly. */
      handle_rc_browse_connect(&p_data->rc_browse_open);
    } break;

    case BTA_AV_RC_CLOSE_EVT: {
      handle_rc_disconnect(&(p_data->rc_close));
    } break;

    case BTA_AV_RC_BROWSE_CLOSE_EVT: {
      log::verbose("BTA_AV_RC_BROWSE_CLOSE_EVT");
    } break;

    case BTA_AV_REMOTE_CMD_EVT: {
      log::error("AVRCP TG role not up, drop passthrough commands");
    } break;

    case BTA_AV_REMOTE_RSP_EVT: {
      log::verbose("RSP: rc_id: 0x{:x} key_state: {}", p_data->remote_rsp.rc_id,
                   p_data->remote_rsp.key_state);

      if (p_data->remote_rsp.rc_id == AVRC_ID_VENDOR) {
        handle_rc_vendorunique_rsp(&p_data->remote_rsp);
      } else {
        handle_rc_passthrough_rsp(&p_data->remote_rsp);
      }
    } break;

    case BTA_AV_RC_FEAT_EVT: {
      log::verbose("Peer_features: {:x}", p_data->rc_feat.peer_features);
      p_dev = btif_rc_get_device_by_handle(p_data->rc_feat.rc_handle);
      if (p_dev == NULL) {
        log::error("RC Feature event for Invalid rc handle");
        break;
      }
      log::verbose("peer_ct_features:0x{:x}, peer_tg_features=0x{:x}",
                   p_data->rc_feat.peer_ct_features, p_data->rc_feat.peer_tg_features);
      if (btif_av_src_sink_coexist_enabled() &&
          (p_dev->peer_ct_features == p_data->rc_feat.peer_ct_features) &&
          (p_dev->peer_tg_features == p_data->rc_feat.peer_tg_features)) {
        log::error("do SDP twice, no need callback rc_feature to framework again");
        break;
      }

      p_dev->peer_ct_features = p_data->rc_feat.peer_ct_features;
      p_dev->peer_tg_features = p_data->rc_feat.peer_tg_features;
      p_dev->rc_features = p_data->rc_feat.peer_features;

      if ((p_dev->rc_state == BTRC_CONNECTION_STATE_CONNECTED) && (bt_rc_ctrl_callbacks != NULL)) {
        handle_rc_ctrl_features(p_dev);
      }
    } break;

    case BTA_AV_RC_PSM_EVT: {
      log::verbose("Peer cover art PSM: {:x}", p_data->rc_cover_art_psm.cover_art_psm);
      p_dev = btif_rc_get_device_by_handle(p_data->rc_cover_art_psm.rc_handle);
      if (p_dev == NULL) {
        log::error("RC PSM event for Invalid rc handle");
        break;
      }

      p_dev->rc_cover_art_psm = p_data->rc_cover_art_psm.cover_art_psm;
      if ((p_dev->rc_state == BTRC_CONNECTION_STATE_CONNECTED) && (bt_rc_ctrl_callbacks != NULL)) {
        handle_rc_ctrl_psm(p_dev);
      }
    } break;

    case BTA_AV_META_MSG_EVT: {
      if (bt_rc_ctrl_callbacks != NULL) {
        /* This is case of Sink + CT + TG(for abs vol)) */
        log::verbose("BTA_AV_META_MSG_EVT code:{} label:{} opcode {} ctype {}",
                     p_data->meta_msg.code, p_data->meta_msg.label,
                     p_data->meta_msg.p_msg->hdr.opcode, p_data->meta_msg.p_msg->hdr.ctype);
        log::verbose("company_id:0x{:x} len:{} handle:{}", p_data->meta_msg.company_id,
                     p_data->meta_msg.len, p_data->meta_msg.rc_handle);
        switch (p_data->meta_msg.p_msg->hdr.opcode) {
          case AVRC_OP_VENDOR:
            if ((p_data->meta_msg.code >= AVRC_RSP_NOT_IMPL) &&
                (p_data->meta_msg.code <= AVRC_RSP_INTERIM)) {
              /* Its a response */
              handle_avk_rc_metamsg_rsp(&(p_data->meta_msg));
            } else if (p_data->meta_msg.code <= AVRC_CMD_GEN_INQ) {
              /* Its a command  */
              handle_avk_rc_metamsg_cmd(&(p_data->meta_msg));
            }
            break;

          case AVRC_OP_BROWSE:
            if (p_data->meta_msg.p_msg->hdr.ctype == AVRC_CMD) {
              handle_avk_rc_metamsg_cmd(&(p_data->meta_msg));
            } else if (p_data->meta_msg.p_msg->hdr.ctype == AVRC_RSP) {
              handle_avk_rc_metamsg_rsp(&(p_data->meta_msg));
            }
            break;
        }
      } else {
        log::error("Neither CTRL, nor TG is up, drop meta commands");
      }
    } break;

    default:
      log::verbose("Unhandled RC event : 0x{:x}", event);
  }
}

bool btif_rc_is_connected_peer(const RawAddress& peer_addr) {
  for (int idx = 0; idx < BTIF_RC_NUM_CONN; idx++) {
    btif_rc_device_cb_t* p_dev = get_connected_device(idx);
    if (p_dev != NULL && p_dev->rc_state == BTRC_CONNECTION_STATE_CONNECTED &&
        peer_addr == p_dev->rc_addr) {
      return true;
    }
  }
  return false;
}

/***************************************************************************
 **
 ** Function       btif_rc_get_connected_peer_handle
 **
 ** Description    Fetches the connected headset's handle if any
 **
 ***************************************************************************/
uint8_t btif_rc_get_connected_peer_handle(const RawAddress& peer_addr) {
  btif_rc_device_cb_t* p_dev = NULL;
  p_dev = btif_rc_get_device_by_bda(peer_addr);

  if (p_dev == NULL) {
    log::error("p_dev NULL");
    return BTRC_HANDLE_NONE;
  }
  return p_dev->rc_handle;
}

/* Generic reject response */
static void send_reject_response(uint8_t rc_handle, uint8_t label, uint8_t pdu, uint8_t status,
                                 uint8_t opcode) {
  uint8_t ctype = AVRC_RSP_REJ;
  tAVRC_RESPONSE avrc_rsp;
  BT_HDR* p_msg = NULL;
  memset(&avrc_rsp, 0, sizeof(tAVRC_RESPONSE));

  avrc_rsp.rsp.opcode = opcode;
  avrc_rsp.rsp.pdu = pdu;
  avrc_rsp.rsp.status = status;

  status = AVRC_BldResponse(rc_handle, &avrc_rsp, &p_msg);

  if (status != AVRC_STS_NO_ERROR) {
    log::error("status not AVRC_STS_NO_ERROR");
    return;
  }

  log::verbose("Sending error notification to handle: {}. pdu: {},status: 0x{:02x}", rc_handle,
               dump_rc_pdu(pdu), status);
  BTA_AvMetaRsp(rc_handle, label, ctype, p_msg);
}

/*******************************************************************************
 *
 * Function         btif_rc_ctrl_upstreams_rsp_cmd
 *
 * Description      Executes AVRC UPSTREAMS response events in btif context.
 *
 * Returns          void
 *
 ******************************************************************************/
static void btif_rc_ctrl_upstreams_rsp_cmd(uint8_t event, tAVRC_COMMAND* pavrc_cmd, uint8_t label,
                                           btif_rc_device_cb_t* p_dev) {
  log::verbose("pdu: {}: handle: 0x{:x}", dump_rc_pdu(pavrc_cmd->pdu), p_dev->rc_handle);
  switch (event) {
    case AVRC_PDU_SET_ABSOLUTE_VOLUME:
      CTRL_HAL_CBACK(bt_rc_ctrl_callbacks->setabsvol_cmd_cb, p_dev->rc_addr,
                     pavrc_cmd->volume.volume, label);
      break;
    case AVRC_PDU_REGISTER_NOTIFICATION:
      if (pavrc_cmd->reg_notif.event_id == AVRC_EVT_VOLUME_CHANGE) {
        CTRL_HAL_CBACK(bt_rc_ctrl_callbacks->registernotification_absvol_cb, p_dev->rc_addr, label);
      }
      break;
  }
}

/*******************************************************************************
 *  AVRCP API Functions
 ******************************************************************************/

/*******************************************************************************
 *
 * Function         init_ctrl
 *
 * Description      Initializes the AVRC interface
 *
 * Returns          BtStatus
 *
 ******************************************************************************/
static BtStatus init_ctrl(btrc_ctrl_callbacks_t* callbacks) {
  log::verbose("");

  if (bt_rc_ctrl_callbacks) {
    return BtifStatus(DONE);
  }

  bt_rc_ctrl_callbacks = callbacks;

  for (int idx = 0; idx < BTIF_RC_NUM_CONN; idx++) {
    initialize_device(&btif_rc_cb.rc_multi_cb[idx]);
  }

  return BtifStatus();
}

static void rc_ctrl_procedure_complete(btif_rc_device_cb_t* p_dev) {
  if (p_dev == NULL) {
    log::error("p_dev NULL");
    return;
  }

  if (p_dev->rc_procedure_complete) {
    return;
  }
  p_dev->rc_procedure_complete = true;
  const uint32_t* attr_list = get_requested_attributes_list(p_dev);
  const uint8_t attr_list_size = get_requested_attributes_list_size(p_dev);
  get_metadata_attribute_cmd(attr_list_size, attr_list, p_dev);
}

/***************************************************************************
 *
 * Function         iterate_supported_event_list_for_interim_rsp
 *
 * Description      iterator callback function to match the event and handle
 *                  timer cleanup
 * Returns          true to continue iterating, false to stop
 *
 **************************************************************************/
static bool iterate_supported_event_list_for_interim_rsp(void* data, void* cb_data) {
  uint8_t* p_event_id;
  btif_rc_supported_event_t* p_event = (btif_rc_supported_event_t*)data;

  p_event_id = (uint8_t*)cb_data;

  if (p_event->event_id == *p_event_id) {
    p_event->status = eINTERIM;
    return false;
  }
  return true;
}

/***************************************************************************
 *
 * Function         rc_notification_interim_timeout
 *
 * Description      Interim response timeout handler.
 *                  Runs the iterator to check and clear the timed out event.
 *                  Proceeds to register for the unregistered events.
 * Returns          None
 *
 **************************************************************************/
static void rc_notification_interim_timeout(btif_rc_device_cb_t* p_dev, uint8_t event_id) {
  /* Device disconnections clear the event list but can't free the timer */
  if (p_dev == NULL || p_dev->rc_supported_event_list == NULL) {
    log::warn("timeout for null device or event list");
    return;
  }

  // Remove the timed out event from the supported events list
  list_node_t* node = list_begin(p_dev->rc_supported_event_list);
  while (node != NULL) {
    btif_rc_supported_event_t* p_event = (btif_rc_supported_event_t*)list_node(node);
    if (p_event != nullptr && p_event->event_id == event_id) {
      list_remove(p_dev->rc_supported_event_list, p_event);
      break;
    }
    node = list_next(node);
  }

  /* Timeout happened for interim response for the registered event,
   * check if there are any pending for registration
   */
  node = list_begin(p_dev->rc_supported_event_list);
  while (node != NULL) {
    btif_rc_supported_event_t* p_event;

    p_event = (btif_rc_supported_event_t*)list_node(node);
    if ((p_event != NULL) && (p_event->status == eNOT_REGISTERED)) {
      register_for_event_notification(p_event, p_dev);
      break;
    }
    node = list_next(node);
  }
  /* Todo. Need to initiate application settings query if this
   * is the last event registration.
   */
}

/***************************************************************************
 *
 * Function         register_for_event_notification
 *
 * Description      Helper function registering notification events
 *                  sets an interim response timeout to handle if the remote
 *                  does not respond.
 * Returns          None
 *
 **************************************************************************/
static void register_for_event_notification(btif_rc_supported_event_t* p_event,
                                            btif_rc_device_cb_t* p_dev) {
  // interval is only valid for AVRC_EVT_PLAY_POS_CHANGED
  uint32_t interval_in_seconds = 0;
  if (p_event->event_id == AVRC_EVT_PLAY_POS_CHANGED) {
    interval_in_seconds = osi_property_get_int32(PLAY_POS_UPDATE_INTERVAL_PROPERTY,
                                                 DEFAULT_PLAY_POS_UPDATE_INTERVAL_SEC);
  }
  BtStatus status = register_notification_cmd(p_event->event_id, interval_in_seconds, p_dev);
  if (!status) {
    log::error("failed, status={}", status);
    return;
  }

  p_event->status = eREGISTERED;
}

/***************************************************************************
 *
 * Function         build_and_send_vendor_cmd
 *
 * Description      Send a command to a device on the browsing channel
 *
 * Parameters       avrc_cmd: The command you're sending
 *                  p_dev: Device control block
 *
 * Returns          BtifStatus() if command is issued successfully
 *                  otherwise BtifStatus(FAIL)
 *
 **************************************************************************/
static BtStatus build_and_send_vendor_cmd(tAVRC_COMMAND* avrc_cmd, tBTA_AV_CODE cmd_code,
                                          btif_rc_device_cb_t* p_dev) {
  rc_transaction_t* p_transaction = NULL;
  rc_transaction_context_t context = {.rc_addr = p_dev->rc_addr,
                                      .label = MAX_LABEL,
                                      .opcode = AVRC_OP_VENDOR,
                                      .command = {.vendor = {avrc_cmd->pdu, AVRC_EVT_INVALID}}};

  // Set the event ID in the context if this is a notification registration
  if (avrc_cmd->pdu == AVRC_PDU_REGISTER_NOTIFICATION) {
    context.command.vendor.event_id = avrc_cmd->reg_notif.event_id;
  }

  BtStatus tran_status = get_transaction(p_dev, context, &p_transaction);
  if (!tran_status || p_transaction == NULL) {
    log::error("failed to get label, pdu_id={}, status={}", dump_rc_pdu(avrc_cmd->pdu),
               tran_status);
    return BtifStatus(FAIL);
  }

  BT_HDR* p_msg = NULL;
  tAVRC_STS status = AVRC_BldCommand(avrc_cmd, &p_msg);
  BtStatus ret = BtifStatus(static_cast<BtifStatusCode>(status));
  if (status == AVRC_STS_NO_ERROR && p_msg != NULL) {
    uint8_t* data_start = (uint8_t*)(p_msg + 1) + p_msg->offset;
    log::verbose("{} msgreq being sent out with label: {}", dump_rc_pdu(avrc_cmd->pdu),
                 p_transaction->label);
    BTA_AvVendorCmd(p_dev->rc_handle, p_transaction->label, cmd_code, data_start, p_msg->len);
    ret = BtifStatus();
    start_transaction_timer(p_dev, p_transaction->label, BTIF_RC_TIMEOUT_MS);
  } else {
    log::error("failed to build command. status: 0x{:02x}", status);
    release_transaction(p_dev, p_transaction->label);
  }
  osi_free(p_msg);
  return ret;
}

/***************************************************************************
 *
 * Function         build_and_send_browsing_cmd
 *
 * Description      Send a command to a device on the browsing channel
 *
 * Parameters       avrc_cmd: The command you're sending
 *                  p_dev: Device control block
 *
 * Returns          BtifStatus() if command is issued successfully
 *                  otherwise BtifStatus(FAIL)
 *
 **************************************************************************/
static BtStatus build_and_send_browsing_cmd(tAVRC_COMMAND* avrc_cmd, btif_rc_device_cb_t* p_dev) {
  rc_transaction_t* p_transaction = NULL;
  rc_transaction_context_t context = {.rc_addr = p_dev->rc_addr,
                                      .label = MAX_LABEL,
                                      .opcode = AVRC_OP_BROWSE,
                                      .command = {.browse = {avrc_cmd->pdu}}};

  BtStatus tran_status = get_transaction(p_dev, context, &p_transaction);
  if (!tran_status || p_transaction == NULL) {
    log::error("failed to get label, pdu_id={}, status={}", dump_rc_pdu(avrc_cmd->pdu),
               tran_status);
    return BtifStatus(FAIL);
  }

  BT_HDR* p_msg = NULL;
  tAVRC_STS status = AVRC_BldCommand(avrc_cmd, &p_msg);
  if (status != AVRC_STS_NO_ERROR) {
    log::error("failed to build command status {}", status);
    release_transaction(p_dev, p_transaction->label);
    return BtifStatus(FAIL);
  }

  log::verbose("Send pdu_id={}, label={}", dump_rc_pdu(avrc_cmd->pdu), p_transaction->label);
  BTA_AvMetaCmd(p_dev->rc_handle, p_transaction->label, AVRC_CMD_CTRL, p_msg);
  start_transaction_timer(p_dev, p_transaction->label, BTIF_RC_TIMEOUT_MS);
  return BtifStatus();
}

/***************************************************************************
 *
 * Function         handle_get_capability_response
 *
 * Description      Handles the get_cap_response to populate company id info
 *                  and query the supported events.
 *                  Initiates Notification registration for events supported
 * Returns          None
 *
 **************************************************************************/
static void handle_get_capability_response(tBTA_AV_META_MSG* pmeta_msg, tAVRC_GET_CAPS_RSP* p_rsp) {
  int xx = 0;
  btif_rc_device_cb_t* p_dev = btif_rc_get_device_by_handle(pmeta_msg->rc_handle);

  /* Todo: Do we need to retry on command timeout */
  if (p_rsp->status != AVRC_STS_NO_ERROR) {
    log::error("Error capability response: 0x{:02X}", p_rsp->status);
    return;
  }

  if (p_rsp->capability_id == AVRC_CAP_EVENTS_SUPPORTED) {
    btif_rc_supported_event_t* p_event;

    /* Todo: Check if list can be active when we hit here */
    p_dev->rc_supported_event_list = list_new(osi_free);
    for (xx = 0; xx < p_rsp->count; xx++) {
      /* Skip registering for Play position change notification */
      if ((p_rsp->param.event_id[xx] == AVRC_EVT_PLAY_STATUS_CHANGE) ||
          (p_rsp->param.event_id[xx] == AVRC_EVT_TRACK_CHANGE) ||
          (p_rsp->param.event_id[xx] == AVRC_EVT_PLAY_POS_CHANGED) ||
          (p_rsp->param.event_id[xx] == AVRC_EVT_APP_SETTING_CHANGE) ||
          (p_rsp->param.event_id[xx] == AVRC_EVT_NOW_PLAYING_CHANGE) ||
          (p_rsp->param.event_id[xx] == AVRC_EVT_ADDR_PLAYER_CHANGE) ||
          (p_rsp->param.event_id[xx] == AVRC_EVT_UIDS_CHANGE) ||
          (p_rsp->param.event_id[xx] == AVRC_EVT_AVAL_PLAYERS_CHANGE)) {
        p_event = (btif_rc_supported_event_t*)osi_malloc(sizeof(btif_rc_supported_event_t));
        p_event->event_id = p_rsp->param.event_id[xx];
        p_event->status = eNOT_REGISTERED;
        list_append(p_dev->rc_supported_event_list, p_event);
      }
    }

    // On occasion a remote device can intermittently send a poorly configured
    // packet with 0 capabilities. This check ensures the stack does not crash.
    // Typically the remote device will send a proper packet in the future and
    // continue operation.
    if (list_is_empty(p_dev->rc_supported_event_list)) {
      return;
    }

    p_event = (btif_rc_supported_event_t*)list_front(p_dev->rc_supported_event_list);
    if (p_event != NULL) {
      register_for_event_notification(p_event, p_dev);
    }
  } else if (p_rsp->capability_id == AVRC_CAP_COMPANY_ID) {
    getcapabilities_cmd(AVRC_CAP_EVENTS_SUPPORTED, p_dev);
    log::verbose("AVRC_CAP_COMPANY_ID:");
    for (xx = 0; xx < p_rsp->count; xx++) {
      log::verbose("company_id: {}", p_rsp->param.company_id[xx]);
    }
  }
}

static bool rc_is_track_id_valid(tAVRC_UID uid) {
  tAVRC_UID invalid_uid = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

  if (memcmp(uid, invalid_uid, sizeof(tAVRC_UID)) == 0) {
    return false;
  } else {
    return true;
  }
}

/***************************************************************************
 *
 * Function         handle_notification_response
 *
 * Description      Main handler for notification responses to registered events
 *                  1. Register for unregistered event(in interim response path)
 *                  2. After registering for all supported events, start
 *                     retrieving application settings and values
 *                  3. Reregister for events on getting changed response
 *                  4. Run play status timer for getting position when the
 *                     status changes to playing
 *                  5. Get the Media details when the track change happens
 *                     or track change interim response is received with
 *                     valid track id
 *                  6. HAL callback for play status change and application
 *                     setting change
 * Returns          None
 *
 **************************************************************************/
static void handle_notification_response(tBTA_AV_META_MSG* pmeta_msg, tAVRC_REG_NOTIF_RSP* p_rsp) {
  btif_rc_device_cb_t* p_dev = btif_rc_get_device_by_handle(pmeta_msg->rc_handle);

  if (p_dev == NULL) {
    log::error("p_dev NULL");
    return;
  }

  if (btif_av_src_sink_coexist_enabled() && p_rsp->event_id == AVRC_EVT_VOLUME_CHANGE) {
    log::error("legacy TG don't handle absolute volume change. leave it to new avrcp");
    return;
  }

  const uint32_t* attr_list = get_requested_attributes_list(p_dev);
  const uint8_t attr_list_size = get_requested_attributes_list_size(p_dev);

  if (pmeta_msg->code == AVRC_RSP_INTERIM) {
    btif_rc_supported_event_t* p_event;
    list_node_t* node;

    log::verbose("Interim response: 0x{:2X}", p_rsp->event_id);
    switch (p_rsp->event_id) {
      case AVRC_EVT_PLAY_STATUS_CHANGE:
        get_play_status_cmd(p_dev);
        CTRL_HAL_CBACK(bt_rc_ctrl_callbacks->play_status_changed_cb, p_dev->rc_addr,
                       (btrc_play_status_t)p_rsp->param.play_status);
        break;

      case AVRC_EVT_TRACK_CHANGE:
        if (rc_is_track_id_valid(p_rsp->param.track) != true) {
          break;
        } else {
          uint8_t* p_data = p_rsp->param.track;
          BE_STREAM_TO_UINT64(p_dev->rc_playing_uid, p_data);
          get_play_status_cmd(p_dev);
          get_metadata_attribute_cmd(attr_list_size, attr_list, p_dev);
        }
        break;

      case AVRC_EVT_APP_SETTING_CHANGE:
        break;

      case AVRC_EVT_NOW_PLAYING_CHANGE:
        CTRL_HAL_CBACK(bt_rc_ctrl_callbacks->now_playing_contents_changed_cb, p_dev->rc_addr);
        break;

      case AVRC_EVT_AVAL_PLAYERS_CHANGE:
        log::verbose("AVRC_EVT_AVAL_PLAYERS_CHANGE");
        CTRL_HAL_CBACK(bt_rc_ctrl_callbacks->available_player_changed_cb, p_dev->rc_addr);
        break;

      case AVRC_EVT_ADDR_PLAYER_CHANGE:
        CTRL_HAL_CBACK(bt_rc_ctrl_callbacks->addressed_player_changed_cb, p_dev->rc_addr,
                       p_rsp->param.addr_player.player_id);
        break;

      case AVRC_EVT_PLAY_POS_CHANGED:
        CTRL_HAL_CBACK(bt_rc_ctrl_callbacks->play_position_changed_cb, p_dev->rc_addr, 0,
                       p_rsp->param.play_pos);

        break;
      case AVRC_EVT_UIDS_CHANGE:
        break;

      case AVRC_EVT_TRACK_REACHED_END:
      case AVRC_EVT_TRACK_REACHED_START:
      case AVRC_EVT_BATTERY_STATUS_CHANGE:
      case AVRC_EVT_SYSTEM_STATUS_CHANGE:
      default:
        log::error("Unhandled interim response: 0x{:2X}", p_rsp->event_id);
        return;
    }

    list_foreach(p_dev->rc_supported_event_list, iterate_supported_event_list_for_interim_rsp,
                 &p_rsp->event_id);

    node = list_begin(p_dev->rc_supported_event_list);

    while (node != NULL) {
      p_event = (btif_rc_supported_event_t*)list_node(node);
      if ((p_event != NULL) && (p_event->status == eNOT_REGISTERED)) {
        register_for_event_notification(p_event, p_dev);
        break;
      }
      node = list_next(node);
      p_event = NULL;
    }
    /* Registered for all events, we can request application settings */
    if (p_event == NULL && !p_dev->rc_app_settings.query_started) {
      /* we need to do this only if remote TG supports
       * player application settings
       */
      p_dev->rc_app_settings.query_started = true;
      if (p_dev->rc_features & BTA_AV_FEAT_APP_SETTING) {
        list_player_app_setting_attrib_cmd(p_dev);
      } else {
        log::verbose("App setting not supported, complete procedure");
        rc_ctrl_procedure_complete(p_dev);
      }
    }
  } else if (pmeta_msg->code == AVRC_RSP_CHANGED) {
    btif_rc_supported_event_t* p_event;
    list_node_t* node;

    log::verbose("Notification completed: 0x{:2X}", p_rsp->event_id);

    node = list_begin(p_dev->rc_supported_event_list);

    while (node != NULL) {
      p_event = (btif_rc_supported_event_t*)list_node(node);
      if (p_event != NULL && p_event->event_id == p_rsp->event_id) {
        p_event->status = eNOT_REGISTERED;
        register_for_event_notification(p_event, p_dev);
        break;
      }
      node = list_next(node);
    }

    switch (p_rsp->event_id) {
      case AVRC_EVT_PLAY_STATUS_CHANGE:
        /* Start timer to get play status periodically
         * if the play state is playing.
         */
        CTRL_HAL_CBACK(bt_rc_ctrl_callbacks->play_status_changed_cb, p_dev->rc_addr,
                       (btrc_play_status_t)p_rsp->param.play_status);

        break;

      case AVRC_EVT_TRACK_CHANGE:
        if (rc_is_track_id_valid(p_rsp->param.track) != true) {
          break;
        } else {
          uint8_t* p_data = p_rsp->param.track;
          BE_STREAM_TO_UINT64(p_dev->rc_playing_uid, p_data);
          get_metadata_attribute_cmd(attr_list_size, attr_list, p_dev);
        }
        break;

      case AVRC_EVT_APP_SETTING_CHANGE: {
        btrc_player_settings_t app_settings;
        uint16_t xx;

        app_settings.num_attr = p_rsp->param.player_setting.num_attr;
        for (xx = 0; xx < app_settings.num_attr; xx++) {
          app_settings.attr_ids[xx] = p_rsp->param.player_setting.attr_id[xx];
          app_settings.attr_values[xx] = p_rsp->param.player_setting.attr_value[xx];
        }
        CTRL_HAL_CBACK(bt_rc_ctrl_callbacks->playerapplicationsetting_changed_cb, p_dev->rc_addr,
                       app_settings);
      } break;

      case AVRC_EVT_NOW_PLAYING_CHANGE:
        break;

      case AVRC_EVT_AVAL_PLAYERS_CHANGE:
        break;

      case AVRC_EVT_ADDR_PLAYER_CHANGE:
        break;

      case AVRC_EVT_PLAY_POS_CHANGED:
        // handle on interim
        break;

      case AVRC_EVT_UIDS_CHANGE:
        break;

      case AVRC_EVT_TRACK_REACHED_END:
      case AVRC_EVT_TRACK_REACHED_START:
      case AVRC_EVT_BATTERY_STATUS_CHANGE:
      case AVRC_EVT_SYSTEM_STATUS_CHANGE:
      default:
        log::error("Unhandled completion response: 0x{:2X}", p_rsp->event_id);
        return;
    }
  }
}

/***************************************************************************
 *
 * Function         handle_app_attr_response
 *
 * Description      handles the the application attributes response and
 *                  initiates procedure to fetch the attribute values
 * Returns          None
 *
 **************************************************************************/
static void handle_app_attr_response(tBTA_AV_META_MSG* pmeta_msg, tAVRC_LIST_APP_ATTR_RSP* p_rsp) {
  uint8_t xx;
  btif_rc_device_cb_t* p_dev = btif_rc_get_device_by_handle(pmeta_msg->rc_handle);

  if (p_dev == NULL || p_rsp->status != AVRC_STS_NO_ERROR) {
    log::error("Error getting Player application settings: 0x{:2X}", p_rsp->status);
    rc_ctrl_procedure_complete(p_dev);
    return;
  }
  p_dev->rc_app_settings.num_attrs = 0;
  p_dev->rc_app_settings.num_ext_attrs = 0;

  for (xx = 0; xx < p_rsp->num_attr; xx++) {
    uint8_t st_index;

    if (p_rsp->attrs[xx] > AVRC_PLAYER_SETTING_LOW_MENU_EXT) {
      st_index = p_dev->rc_app_settings.num_ext_attrs;
      p_dev->rc_app_settings.ext_attrs[st_index].attr_id = p_rsp->attrs[xx];
      p_dev->rc_app_settings.num_ext_attrs++;
    } else {
      st_index = p_dev->rc_app_settings.num_attrs;
      p_dev->rc_app_settings.attrs[st_index].attr_id = p_rsp->attrs[xx];
      p_dev->rc_app_settings.num_attrs++;
    }
  }
  p_dev->rc_app_settings.attr_index = 0;
  p_dev->rc_app_settings.ext_attr_index = 0;
  p_dev->rc_app_settings.ext_val_index = 0;
  if (p_rsp->num_attr) {
    list_player_app_setting_value_cmd(p_dev->rc_app_settings.attrs[0].attr_id, p_dev);
  } else {
    log::error("No Player application settings found");
  }
}

/***************************************************************************
 *
 * Function         handle_app_val_response
 *
 * Description      handles the the attributes value response and if extended
 *                  menu is available, it initiates query for the attribute
 *                  text. If not, it initiates procedure to get the current
 *                  attribute values and calls the HAL callback for provding
 *                  application settings information.
 * Returns          None
 *
 **************************************************************************/
static void handle_app_val_response(tBTA_AV_META_MSG* pmeta_msg, tAVRC_LIST_APP_VALUES_RSP* p_rsp) {
  uint8_t xx, attr_index;
  uint8_t attrs[AVRC_MAX_APP_ATTR_SIZE];
  btif_rc_player_app_settings_t* p_app_settings;
  btif_rc_device_cb_t* p_dev = btif_rc_get_device_by_handle(pmeta_msg->rc_handle);

  /* Todo: Do we need to retry on command timeout */
  if (p_dev == NULL || p_rsp->status != AVRC_STS_NO_ERROR) {
    log::error("Error fetching attribute values: 0x{:02X}", p_rsp->status);
    return;
  }

  p_app_settings = &p_dev->rc_app_settings;

  if (p_app_settings->attr_index < p_app_settings->num_attrs) {
    attr_index = p_app_settings->attr_index;
    p_app_settings->attrs[attr_index].num_val = p_rsp->num_val;
    for (xx = 0; xx < p_rsp->num_val; xx++) {
      p_app_settings->attrs[attr_index].attr_val[xx] = p_rsp->vals[xx];
    }
    attr_index++;
    p_app_settings->attr_index++;
    if (attr_index < p_app_settings->num_attrs) {
      list_player_app_setting_value_cmd(p_app_settings->attrs[p_app_settings->attr_index].attr_id,
                                        p_dev);
    } else if (p_app_settings->ext_attr_index < p_app_settings->num_ext_attrs) {
      attr_index = 0;
      p_app_settings->ext_attr_index = 0;
      list_player_app_setting_value_cmd(p_app_settings->ext_attrs[attr_index].attr_id, p_dev);
    } else {
      for (xx = 0; xx < p_app_settings->num_attrs; xx++) {
        attrs[xx] = p_app_settings->attrs[xx].attr_id;
      }
      get_player_app_setting_cmd(p_app_settings->num_attrs, attrs, p_dev);
      CTRL_HAL_CBACK(bt_rc_ctrl_callbacks->playerapplicationsetting_cb, p_dev->rc_addr,
                     p_app_settings->num_attrs, p_app_settings->attrs);
    }
  } else if (p_app_settings->ext_attr_index < p_app_settings->num_ext_attrs) {
    attr_index = p_app_settings->ext_attr_index;
    p_app_settings->ext_attrs[attr_index].num_val = p_rsp->num_val;
    for (xx = 0; xx < p_rsp->num_val; xx++) {
      p_app_settings->ext_attrs[attr_index].ext_attr_val[xx].val = p_rsp->vals[xx];
    }
    attr_index++;
    p_app_settings->ext_attr_index++;
    if (attr_index < p_app_settings->num_ext_attrs) {
      list_player_app_setting_value_cmd(
              p_app_settings->ext_attrs[p_app_settings->ext_attr_index].attr_id, p_dev);
    } else {
      uint8_t attr[AVRC_MAX_APP_ATTR_SIZE];

      for (uint8_t xx = 0; xx < p_app_settings->num_ext_attrs; xx++) {
        attr[xx] = p_app_settings->ext_attrs[xx].attr_id;
      }
      get_player_app_setting_attr_text_cmd(attr, p_app_settings->num_ext_attrs, p_dev);
    }
  }
}

/***************************************************************************
 *
 * Function         handle_app_cur_val_response
 *
 * Description      handles the the get attributes value response.
 *
 * Returns          None
 *
 **************************************************************************/
static void handle_app_cur_val_response(tBTA_AV_META_MSG* pmeta_msg,
                                        tAVRC_GET_CUR_APP_VALUE_RSP* p_rsp) {
  btrc_player_settings_t app_settings;
  uint16_t xx;
  btif_rc_device_cb_t* p_dev = NULL;

  /* Todo: Do we need to retry on command timeout */
  if (p_rsp->status != AVRC_STS_NO_ERROR) {
    log::error("Error fetching current settings: 0x{:02X}", p_rsp->status);
    return;
  }
  p_dev = btif_rc_get_device_by_handle(pmeta_msg->rc_handle);
  if (p_dev == NULL) {
    log::error("Error in getting Device Address");
    osi_free_and_reset((void**)&p_rsp->p_vals);
    return;
  }

  app_settings.num_attr = p_rsp->num_val;

  if (app_settings.num_attr > BTRC_MAX_APP_SETTINGS) {
    app_settings.num_attr = BTRC_MAX_APP_SETTINGS;
  }

  for (xx = 0; xx < app_settings.num_attr; xx++) {
    app_settings.attr_ids[xx] = p_rsp->p_vals[xx].attr_id;
    app_settings.attr_values[xx] = p_rsp->p_vals[xx].attr_val;
  }

  CTRL_HAL_CBACK(bt_rc_ctrl_callbacks->playerapplicationsetting_changed_cb, p_dev->rc_addr,
                 app_settings);
  /* Application settings are fetched only once for initial values
   * initiate anything that follows after RC procedure.
   * Defer it if browsing is supported till players query
   */
  rc_ctrl_procedure_complete(p_dev);
  osi_free_and_reset((void**)&p_rsp->p_vals);
}

/***************************************************************************
 *
 * Function         handle_app_attr_txt_response
 *
 * Description      handles the the get attributes text response, if fails
 *                  calls HAL callback with just normal settings and initiates
 *                  query for current settings else initiates query for value
 *                  text
 * Returns          None
 *
 **************************************************************************/
static void handle_app_attr_txt_response(tBTA_AV_META_MSG* pmeta_msg,
                                         tAVRC_GET_APP_ATTR_TXT_RSP* p_rsp) {
  uint8_t xx;
  uint8_t vals[AVRC_MAX_APP_ATTR_SIZE];
  btif_rc_player_app_settings_t* p_app_settings;
  btif_rc_device_cb_t* p_dev = btif_rc_get_device_by_handle(pmeta_msg->rc_handle);

  if (p_dev == NULL) {
    log::error("p_dev NULL");
    return;
  }

  p_app_settings = &p_dev->rc_app_settings;

  /* Todo: Do we need to retry on command timeout */
  if (p_rsp->status != AVRC_STS_NO_ERROR) {
    uint8_t attrs[AVRC_MAX_APP_ATTR_SIZE];

    log::error("Error fetching attribute text: 0x{:02X}", p_rsp->status);
    /* Not able to fetch Text for extended Menu, skip the process
     * and cleanup used memory. Proceed to get the current settings
     * for standard attributes.
     */
    p_app_settings->num_ext_attrs = 0;
    for (xx = 0; xx < p_app_settings->ext_attr_index && xx < AVRC_MAX_APP_ATTR_SIZE; xx++) {
      osi_free_and_reset((void**)&p_app_settings->ext_attrs[xx].p_str);
    }
    p_app_settings->ext_attr_index = 0;

    for (xx = 0; xx < p_app_settings->num_attrs && xx < AVRC_MAX_APP_ATTR_SIZE; xx++) {
      attrs[xx] = p_app_settings->attrs[xx].attr_id;
    }

    CTRL_HAL_CBACK(bt_rc_ctrl_callbacks->playerapplicationsetting_cb, p_dev->rc_addr,
                   p_app_settings->num_attrs, p_app_settings->attrs);
    get_player_app_setting_cmd(xx, attrs, p_dev);

    return;
  }

  for (xx = 0; xx < p_rsp->num_attr; xx++) {
    uint8_t x;
    for (x = 0; x < p_app_settings->num_ext_attrs && x < AVRC_MAX_APP_ATTR_SIZE; x++) {
      if (p_app_settings->ext_attrs[x].attr_id == p_rsp->p_attrs[xx].attr_id) {
        p_app_settings->ext_attrs[x].charset_id = p_rsp->p_attrs[xx].charset_id;
        p_app_settings->ext_attrs[x].str_len = p_rsp->p_attrs[xx].str_len;
        p_app_settings->ext_attrs[x].p_str = p_rsp->p_attrs[xx].p_str;
        break;
      }
    }
  }

  for (xx = 0; xx < p_app_settings->ext_attrs[0].num_val && xx < BTRC_MAX_APP_ATTR_SIZE; xx++) {
    vals[xx] = p_app_settings->ext_attrs[0].ext_attr_val[xx].val;
  }
  get_player_app_setting_value_text_cmd(vals, xx, p_dev);
}

/***************************************************************************
 *
 * Function         handle_app_attr_val_txt_response
 *
 * Description      handles the the get attributes value text response, if fails
 *                  calls HAL callback with just normal settings and initiates
 *                  query for current settings
 * Returns          None
 *
 **************************************************************************/
static void handle_app_attr_val_txt_response(tBTA_AV_META_MSG* pmeta_msg,
                                             tAVRC_GET_APP_ATTR_TXT_RSP* p_rsp) {
  uint8_t xx, attr_index;
  uint8_t vals[AVRC_MAX_APP_ATTR_SIZE];
  uint8_t attrs[AVRC_MAX_APP_ATTR_SIZE];
  btif_rc_player_app_settings_t* p_app_settings;
  btif_rc_device_cb_t* p_dev = btif_rc_get_device_by_handle(pmeta_msg->rc_handle);

  if (p_dev == NULL) {
    log::error("p_dev NULL");
    return;
  }

  p_app_settings = &p_dev->rc_app_settings;

  /* Todo: Do we need to retry on command timeout */
  if (p_rsp->status != AVRC_STS_NO_ERROR) {
    uint8_t attrs[AVRC_MAX_APP_ATTR_SIZE];

    log::error("Error fetching attribute value text: 0x{:02X}", p_rsp->status);

    /* Not able to fetch Text for extended Menu, skip the process
     * and cleanup used memory. Proceed to get the current settings
     * for standard attributes.
     */
    p_app_settings->num_ext_attrs = 0;
    for (xx = 0; xx < p_app_settings->ext_attr_index && xx < AVRC_MAX_APP_ATTR_SIZE; xx++) {
      int x;
      btrc_player_app_ext_attr_t* p_ext_attr = &p_app_settings->ext_attrs[xx];

      for (x = 0; x < p_ext_attr->num_val && x < BTRC_MAX_APP_ATTR_SIZE; x++) {
        osi_free_and_reset((void**)&p_ext_attr->ext_attr_val[x].p_str);
      }
      p_ext_attr->num_val = 0;
      osi_free_and_reset((void**)&p_app_settings->ext_attrs[xx].p_str);
    }
    p_app_settings->ext_attr_index = 0;

    for (xx = 0; xx < p_app_settings->num_attrs; xx++) {
      attrs[xx] = p_app_settings->attrs[xx].attr_id;
    }
    CTRL_HAL_CBACK(bt_rc_ctrl_callbacks->playerapplicationsetting_cb, p_dev->rc_addr,
                   p_app_settings->num_attrs, p_app_settings->attrs);

    get_player_app_setting_cmd(xx, attrs, p_dev);
    return;
  }

  if (p_app_settings->ext_val_index >= AVRC_MAX_APP_ATTR_SIZE) {
    log::error("ext_val_index is 0x{:02x}, overflow!", p_app_settings->ext_val_index);
    return;
  }

  for (xx = 0; xx < p_rsp->num_attr; xx++) {
    uint8_t x;
    btrc_player_app_ext_attr_t* p_ext_attr;
    p_ext_attr = &p_app_settings->ext_attrs[p_app_settings->ext_val_index];
    for (x = 0; x < p_rsp->num_attr && x < BTRC_MAX_APP_ATTR_SIZE; x++) {
      if (p_ext_attr->ext_attr_val[x].val == p_rsp->p_attrs[xx].attr_id) {
        p_ext_attr->ext_attr_val[x].charset_id = p_rsp->p_attrs[xx].charset_id;
        p_ext_attr->ext_attr_val[x].str_len = p_rsp->p_attrs[xx].str_len;
        p_ext_attr->ext_attr_val[x].p_str = p_rsp->p_attrs[xx].p_str;
        break;
      }
    }
  }
  p_app_settings->ext_val_index++;

  if (p_app_settings->ext_val_index < p_app_settings->num_ext_attrs) {
    attr_index = p_app_settings->ext_val_index;
    for (xx = 0; xx < p_app_settings->ext_attrs[attr_index].num_val; xx++) {
      vals[xx] = p_app_settings->ext_attrs[attr_index].ext_attr_val[xx].val;
    }
    get_player_app_setting_value_text_cmd(vals, xx, p_dev);
  } else {
    uint8_t x;

    for (xx = 0; xx < p_app_settings->num_attrs; xx++) {
      attrs[xx] = p_app_settings->attrs[xx].attr_id;
    }
    for (x = 0; x < p_app_settings->num_ext_attrs; x++) {
      attrs[xx + x] = p_app_settings->ext_attrs[x].attr_id;
    }
    CTRL_HAL_CBACK(bt_rc_ctrl_callbacks->playerapplicationsetting_cb, p_dev->rc_addr,
                   p_app_settings->num_attrs, p_app_settings->attrs);
    get_player_app_setting_cmd(xx + x, attrs, p_dev);

    /* Free the application settings information after sending to
     * application.
     */
    cleanup_app_attr_val_txt_response(p_app_settings);
    p_app_settings->num_attrs = 0;
  }
}

/***************************************************************************
 *
 * Function         cleanup_app_attr_val_txt_response
 *
 * Description      Frees the memory that was allocated for reporting player
 *                  application settings.
 * Returns          None
 **************************************************************************/
static void cleanup_app_attr_val_txt_response(btif_rc_player_app_settings_t* p_app_settings) {
  for (uint8_t xx = 0; xx < p_app_settings->ext_attr_index && xx < AVRC_MAX_APP_ATTR_SIZE; xx++) {
    int x;
    btrc_player_app_ext_attr_t* p_ext_attr = &p_app_settings->ext_attrs[xx];
    for (x = 0; x < p_ext_attr->num_val && x < BTRC_MAX_APP_ATTR_SIZE; x++) {
      osi_free_and_reset((void**)&p_ext_attr->ext_attr_val[x].p_str);
    }
    p_ext_attr->num_val = 0;
    osi_free_and_reset((void**)&p_app_settings->ext_attrs[xx].p_str);
  }
}

/***************************************************************************
 *
 * Function         handle_set_app_attr_val_response
 *
 * Description      handles the the set attributes value response, if fails
 *                  calls HAL callback to indicate the failure
 * Returns          None
 *
 **************************************************************************/
static void handle_set_app_attr_val_response(tBTA_AV_META_MSG* pmeta_msg, tAVRC_RSP* /*p_rsp*/) {
  uint8_t accepted = 0;
  btif_rc_device_cb_t* p_dev = btif_rc_get_device_by_handle(pmeta_msg->rc_handle);

  if (p_dev == NULL) {
    log::error("p_dev NULL");
    return;
  }

  /* For timeout pmeta_msg will be NULL, else we need to
   * check if this is accepted by TG
   */
  if (pmeta_msg && (pmeta_msg->code == AVRC_RSP_ACCEPT)) {
    accepted = 1;
  }
  CTRL_HAL_CBACK(bt_rc_ctrl_callbacks->setplayerappsetting_rsp_cb, p_dev->rc_addr, accepted);
}

/***************************************************************************
 *
 * Function         handle_get_metadata_attr_response
 *
 * Description      handles the the element attributes response, calls
 *                  HAL callback to update track change information.
 * Returns          None
 *
 **************************************************************************/
static void handle_get_metadata_attr_response(tBTA_AV_META_MSG* pmeta_msg,
                                              tAVRC_GET_ATTRS_RSP* p_rsp) {
  btif_rc_device_cb_t* p_dev = btif_rc_get_device_by_handle(pmeta_msg->rc_handle);

  if (p_rsp->status == AVRC_STS_NO_ERROR) {
    size_t buf_size = p_rsp->num_attrs * sizeof(btrc_element_attr_val_t);
    btrc_element_attr_val_t* p_attr = (btrc_element_attr_val_t*)osi_calloc(buf_size);

    if (p_dev == NULL) {
      log::error("p_dev NULL");
      return;
    }

    for (int i = 0; i < p_rsp->num_attrs; i++) {
      p_attr[i].attr_id = p_rsp->p_attrs[i].attr_id;
      /* Todo. Length limit check to include null */
      if (p_rsp->p_attrs[i].name.str_len && p_rsp->p_attrs[i].name.p_str) {
        memcpy(p_attr[i].text, p_rsp->p_attrs[i].name.p_str, p_rsp->p_attrs[i].name.str_len);
        osi_free_and_reset((void**)&p_rsp->p_attrs[i].name.p_str);
      }
    }
    osi_free_and_reset((void**)&p_rsp->p_attrs);

    CTRL_HAL_CBACK(bt_rc_ctrl_callbacks->track_changed_cb, p_dev->rc_addr, p_rsp->num_attrs,
                   p_attr);
    do_in_jni_thread(base::BindOnce(osi_free, p_attr));
  } else if (p_rsp->status == BTIF_RC_STS_TIMEOUT) {
    /* Retry for timeout case, this covers error handling
     * for continuation failure also.
     */
    const uint32_t* attr_list = get_requested_attributes_list(p_dev);
    const uint8_t attr_list_size = get_requested_attributes_list_size(p_dev);
    get_metadata_attribute_cmd(attr_list_size, attr_list, p_dev);
  } else {
    log::error("Error in get element attr procedure: {}", p_rsp->status);
  }
}

/***************************************************************************
 *
 * Function         handle_get_playstatus_response
 *
 * Description      handles the the play status response, calls
 *                  HAL callback to update play position.
 * Returns          None
 *
 **************************************************************************/
static void handle_get_playstatus_response(tBTA_AV_META_MSG* pmeta_msg,
                                           tAVRC_GET_PLAY_STATUS_RSP* p_rsp) {
  btif_rc_device_cb_t* p_dev = btif_rc_get_device_by_handle(pmeta_msg->rc_handle);

  if (p_dev == NULL) {
    log::error("p_dev NULL");
    return;
  }

  if (p_rsp->status == AVRC_STS_NO_ERROR) {
    CTRL_HAL_CBACK(bt_rc_ctrl_callbacks->play_status_changed_cb, p_dev->rc_addr,
                   (btrc_play_status_t)p_rsp->play_status);
    CTRL_HAL_CBACK(bt_rc_ctrl_callbacks->play_position_changed_cb, p_dev->rc_addr, p_rsp->song_len,
                   p_rsp->song_pos);
  } else {
    log::error("Error in get play status procedure: {}", p_rsp->status);
  }
}

/***************************************************************************
 *
 * Function         handle_set_addressed_player_response
 *
 * Description      handles the the set addressed player response, calls
 *                  HAL callback
 * Returns          None
 *
 **************************************************************************/
static void handle_set_addressed_player_response(tBTA_AV_META_MSG* pmeta_msg, tAVRC_RSP* p_rsp) {
  btif_rc_device_cb_t* p_dev = btif_rc_get_device_by_handle(pmeta_msg->rc_handle);

  if (p_dev == NULL) {
    log::error("p_dev NULL");
    return;
  }

  if (p_rsp->status == AVRC_STS_NO_ERROR) {
    CTRL_HAL_CBACK(bt_rc_ctrl_callbacks->set_addressed_player_cb, p_dev->rc_addr, p_rsp->status);
  } else {
    log::error("Error in get play status procedure {}", p_rsp->status);
  }
}

/***************************************************************************
 *
 * Function         handle_get_folder_items_response
 *
 * Description      handles the the get folder items response, calls
 *                  HAL callback to send the folder items.
 * Returns          None
 *
 **************************************************************************/
static void handle_get_folder_items_response(tBTA_AV_META_MSG* pmeta_msg,
                                             tAVRC_GET_ITEMS_RSP* p_rsp) {
  btif_rc_device_cb_t* p_dev = btif_rc_get_device_by_handle(pmeta_msg->rc_handle);

  if (p_rsp->status == AVRC_STS_NO_ERROR) {
    /* Convert the internal folder listing into a response that can
     * be passed onto JNI via HAL_CBACK
     */
    uint8_t item_count = p_rsp->item_count;
    btrc_folder_items_t* btrc_items =
            (btrc_folder_items_t*)osi_malloc(sizeof(btrc_folder_items_t) * item_count);
    for (uint8_t i = 0; i < item_count; i++) {
      const tAVRC_ITEM* avrc_item = &(p_rsp->p_item_list[i]);
      btrc_folder_items_t* btrc_item = &(btrc_items[i]);
      log::verbose("folder item type {}", avrc_item->item_type);
      switch (avrc_item->item_type) {
        case AVRC_ITEM_MEDIA:
          log::verbose("setting type to {}", BTRC_ITEM_MEDIA);
          /* Allocate Space for Attributes */
          btrc_item->media.num_attrs = avrc_item->u.media.attr_count;
          btrc_item->media.p_attrs = (btrc_element_attr_val_t*)osi_malloc(
                  btrc_item->media.num_attrs * sizeof(btrc_element_attr_val_t));
          get_folder_item_type_media(avrc_item, btrc_item);
          break;

        case AVRC_ITEM_FOLDER:
          log::verbose("setting type to BTRC_ITEM_FOLDER");
          get_folder_item_type_folder(avrc_item, btrc_item);
          break;

        case AVRC_ITEM_PLAYER:
          log::verbose("setting type to BTRC_ITEM_PLAYER");
          get_folder_item_type_player(avrc_item, btrc_item);
          break;

        default:
          log::error("cannot understand folder item type {}", avrc_item->item_type);
      }
    }

    CTRL_HAL_CBACK(bt_rc_ctrl_callbacks->get_folder_items_cb, p_dev->rc_addr, BTRC_STS_NO_ERROR,
                   /* We want to make the ownership explicit in native */
                   btrc_items, item_count);

    if (item_count > 0) {
      if (btrc_items[0].item_type == AVRC_ITEM_PLAYER &&
          (p_dev->rc_features & BTA_AV_FEAT_APP_SETTING)) {
        list_player_app_setting_attrib_cmd(p_dev);
      }
    }
    /* Release the memory block for items and attributes allocated here.
     * Since the executor for do_in_jni_thread is a Single Thread Task Runner it
     * is okay to queue up the cleanup of btrc_items */
    do_in_jni_thread(base::BindOnce(cleanup_btrc_folder_items, btrc_items, item_count));

    log::verbose("get_folder_items_cb sent to JNI thread");
  } else {
    log::error("Error {}", p_rsp->status);
    CTRL_HAL_CBACK(bt_rc_ctrl_callbacks->get_folder_items_cb, p_dev->rc_addr,
                   (btrc_status_t)p_rsp->status, nullptr, 0);
  }
}
/***************************************************************************
 *
 * Function         cleanup_btrc_folder_items
 *
 * Description      Frees the memory that was allocated for a list of folder
 *                  items.
 * Returns          None
 **************************************************************************/
static void cleanup_btrc_folder_items(btrc_folder_items_t* btrc_items, uint8_t item_count) {
  for (uint8_t i = 0; i < item_count; i++) {
    btrc_folder_items_t* btrc_item = &(btrc_items[i]);
    switch (btrc_item->item_type) {
      case BTRC_ITEM_MEDIA:
        osi_free(btrc_item->media.p_attrs);
        break;
      case BTRC_ITEM_PLAYER:
      case BTRC_ITEM_FOLDER:
        /*Nothing to free*/
        break;
      default:
        log::warn("free unspecified type");
    }
  }
  osi_free(btrc_items);
}

/***************************************************************************
 *
 * Function         get_folder_item_type_media
 *
 * Description      Converts the AVRC representation of a folder item with
 *                  TYPE media to BTIF representation.
 * Returns          None
 *
 **************************************************************************/
static void get_folder_item_type_media(const tAVRC_ITEM* avrc_item,
                                       btrc_folder_items_t* btrc_item) {
  btrc_item->item_type = BTRC_ITEM_MEDIA;
  const tAVRC_ITEM_MEDIA* avrc_item_media = &(avrc_item->u.media);
  btrc_item_media_t* btrc_item_media = &(btrc_item->media);
  /* UID */
  memset(btrc_item_media->uid, 0, BTRC_UID_SIZE * sizeof(uint8_t));
  memcpy(btrc_item_media->uid, avrc_item_media->uid, sizeof(uint8_t) * BTRC_UID_SIZE);

  /* Audio/Video type */
  switch (avrc_item_media->type) {
    case AVRC_MEDIA_TYPE_AUDIO:
      btrc_item_media->type = BTRC_MEDIA_TYPE_AUDIO;
      break;
    case AVRC_MEDIA_TYPE_VIDEO:
      btrc_item_media->type = BTRC_MEDIA_TYPE_VIDEO;
      break;
  }

  /* Charset ID */
  btrc_item_media->charset_id = avrc_item_media->name.charset_id;

  /* Copy the name */
  log::verbose("max len {} str len {}", BTRC_MAX_ATTR_STR_LEN, avrc_item_media->name.str_len);
  memset(btrc_item_media->name, 0, BTRC_MAX_ATTR_STR_LEN * sizeof(uint8_t));
  memcpy(btrc_item_media->name, avrc_item_media->name.p_str,
         sizeof(uint8_t) * (avrc_item_media->name.str_len));

  /* Extract each attribute */
  for (int i = 0; i < avrc_item_media->attr_count; i++) {
    btrc_element_attr_val_t* btrc_attr_pair = &(btrc_item_media->p_attrs[i]);
    tAVRC_ATTR_ENTRY* avrc_attr_pair = &(avrc_item_media->p_attr_list[i]);

    log::verbose("media attr id 0x{:x}", avrc_attr_pair->attr_id);

    switch (avrc_attr_pair->attr_id) {
      case AVRC_MEDIA_ATTR_ID_TITLE:
        btrc_attr_pair->attr_id = BTRC_MEDIA_ATTR_ID_TITLE;
        break;
      case AVRC_MEDIA_ATTR_ID_ARTIST:
        btrc_attr_pair->attr_id = BTRC_MEDIA_ATTR_ID_ARTIST;
        break;
      case AVRC_MEDIA_ATTR_ID_ALBUM:
        btrc_attr_pair->attr_id = BTRC_MEDIA_ATTR_ID_ALBUM;
        break;
      case AVRC_MEDIA_ATTR_ID_TRACK_NUM:
        btrc_attr_pair->attr_id = BTRC_MEDIA_ATTR_ID_TRACK_NUM;
        break;
      case AVRC_MEDIA_ATTR_ID_NUM_TRACKS:
        btrc_attr_pair->attr_id = BTRC_MEDIA_ATTR_ID_NUM_TRACKS;
        break;
      case AVRC_MEDIA_ATTR_ID_GENRE:
        btrc_attr_pair->attr_id = BTRC_MEDIA_ATTR_ID_GENRE;
        break;
      case AVRC_MEDIA_ATTR_ID_PLAYING_TIME:
        btrc_attr_pair->attr_id = BTRC_MEDIA_ATTR_ID_PLAYING_TIME;
        break;
      case AVRC_MEDIA_ATTR_ID_COVER_ARTWORK_HANDLE:
        btrc_attr_pair->attr_id = BTRC_MEDIA_ATTR_ID_COVER_ARTWORK_HANDLE;
        break;
      default:
        log::error("invalid media attr id: 0x{:x}", avrc_attr_pair->attr_id);
        btrc_attr_pair->attr_id = BTRC_MEDIA_ATTR_ID_INVALID;
    }

    memset(btrc_attr_pair->text, 0, BTRC_MAX_ATTR_STR_LEN * sizeof(uint8_t));
    memcpy(btrc_attr_pair->text, avrc_attr_pair->name.p_str, avrc_attr_pair->name.str_len);
  }
}

/***************************************************************************
 *
 * Function         get_folder_item_type_folder
 *
 * Description      Converts the AVRC representation of a folder item with
 *                  TYPE folder to BTIF representation.
 * Returns          None
 *
 **************************************************************************/
static void get_folder_item_type_folder(const tAVRC_ITEM* avrc_item,
                                        btrc_folder_items_t* btrc_item) {
  btrc_item->item_type = BTRC_ITEM_FOLDER;
  const tAVRC_ITEM_FOLDER* avrc_item_folder = &(avrc_item->u.folder);
  btrc_item_folder_t* btrc_item_folder = &(btrc_item->folder);
  /* Copy the UID */
  memset(btrc_item_folder->uid, 0, BTRC_UID_SIZE * sizeof(uint8_t));
  memcpy(btrc_item_folder->uid, avrc_item_folder->uid, sizeof(uint8_t) * BTRC_UID_SIZE);

  /* Copy the type */
  switch (avrc_item_folder->type) {
    case AVRC_FOLDER_TYPE_MIXED:
      btrc_item_folder->type = BTRC_FOLDER_TYPE_MIXED;
      break;
    case AVRC_FOLDER_TYPE_TITLES:
      btrc_item_folder->type = BTRC_FOLDER_TYPE_TITLES;
      break;
    case AVRC_FOLDER_TYPE_ALNUMS:
      btrc_item_folder->type = BTRC_FOLDER_TYPE_ALBUMS;
      break;
    case AVRC_FOLDER_TYPE_ARTISTS:
      btrc_item_folder->type = BTRC_FOLDER_TYPE_ARTISTS;
      break;
    case AVRC_FOLDER_TYPE_GENRES:
      btrc_item_folder->type = BTRC_FOLDER_TYPE_GENRES;
      break;
    case AVRC_FOLDER_TYPE_PLAYLISTS:
      btrc_item_folder->type = BTRC_FOLDER_TYPE_PLAYLISTS;
      break;
    case AVRC_FOLDER_TYPE_YEARS:
      btrc_item_folder->type = BTRC_FOLDER_TYPE_YEARS;
      break;
  }

  /* Copy if playable */
  btrc_item_folder->playable = avrc_item_folder->playable;

  /* Copy name */
  log::verbose("max len {} str len {}", BTRC_MAX_ATTR_STR_LEN, avrc_item_folder->name.str_len);
  memset(btrc_item_folder->name, 0, BTRC_MAX_ATTR_STR_LEN * sizeof(uint8_t));
  memcpy(btrc_item_folder->name, avrc_item_folder->name.p_str,
         avrc_item_folder->name.str_len * sizeof(uint8_t));

  /* Copy charset */
  btrc_item_folder->charset_id = avrc_item_folder->name.charset_id;
}

/***************************************************************************
 *
 * Function         get_folder_item_type_player
 *
 * Description      Converts the AVRC representation of a folder item with
 *                  TYPE player to BTIF representation.
 * Returns          None
 *
 **************************************************************************/
static void get_folder_item_type_player(const tAVRC_ITEM* avrc_item,
                                        btrc_folder_items_t* btrc_item) {
  btrc_item->item_type = BTRC_ITEM_PLAYER;
  const tAVRC_ITEM_PLAYER* avrc_item_player = &(avrc_item->u.player);
  btrc_item_player_t* btrc_item_player = &(btrc_item->player);
  /* Player ID */
  btrc_item_player->player_id = avrc_item_player->player_id;
  /* Major type */
  btrc_item_player->major_type = avrc_item_player->major_type;
  /* Sub type */
  btrc_item_player->sub_type = avrc_item_player->sub_type;
  /* Play status */
  btrc_item_player->play_status = avrc_item_player->play_status;
  /* Features */
  memcpy(btrc_item_player->features, avrc_item_player->features, BTRC_FEATURE_BIT_MASK_SIZE);

  memset(btrc_item_player->name, 0, BTRC_MAX_ATTR_STR_LEN * sizeof(uint8_t));
  memcpy(btrc_item_player->name, avrc_item_player->name.p_str, avrc_item_player->name.str_len);
}

/***************************************************************************
 *
 * Function         handle_change_path_response
 *
 * Description      handles the the change path response, calls
 *                  HAL callback to send the updated folder
 * Returns          None
 *
 **************************************************************************/
static void handle_change_path_response(tBTA_AV_META_MSG* pmeta_msg, tAVRC_CHG_PATH_RSP* p_rsp) {
  btif_rc_device_cb_t* p_dev = btif_rc_get_device_by_handle(pmeta_msg->rc_handle);

  if (p_dev == NULL) {
    log::error("Invalid rc handle");
    return;
  }

  if (p_rsp->status == AVRC_STS_NO_ERROR) {
    CTRL_HAL_CBACK(bt_rc_ctrl_callbacks->change_folder_path_cb, p_dev->rc_addr, p_rsp->num_items);
  } else {
    log::error("error in handle_change_path_response {}", p_rsp->status);
  }
}

/***************************************************************************
 *
 * Function         handle_set_browsed_player_response
 *
 * Description      handles the the change path response, calls
 *                  HAL callback to send the updated folder
 * Returns          None
 *
 **************************************************************************/
static void handle_set_browsed_player_response(tBTA_AV_META_MSG* pmeta_msg,
                                               tAVRC_SET_BR_PLAYER_RSP* p_rsp) {
  btif_rc_device_cb_t* p_dev = btif_rc_get_device_by_handle(pmeta_msg->rc_handle);

  if (p_dev == NULL) {
    log::error("Invalid rc handle");
    return;
  }

  if (p_rsp->status == AVRC_STS_NO_ERROR) {
    CTRL_HAL_CBACK(bt_rc_ctrl_callbacks->set_browsed_player_cb, p_dev->rc_addr, p_rsp->num_items,
                   p_rsp->folder_depth);
  } else {
    log::error("error {}", p_rsp->status);
  }
}

/***************************************************************************
 *
 * Function         clear_cmd_timeout
 *
 * Description      helper function to stop the command timeout timer
 * Returns          None
 *
 **************************************************************************/
static void clear_cmd_timeout(btif_rc_device_cb_t* p_dev, uint8_t label) {
  rc_transaction_t* p_txn;

  p_txn = get_transaction_by_lbl(p_dev, label);
  if (p_txn == NULL) {
    log::error("Error in transaction label lookup");
    return;
  }

  if (p_txn->timer != NULL) {
    // Free also calls alarm_cancel() in its implementation
    alarm_free(p_txn->timer);
  }
  p_txn->timer = nullptr;
}

/***************************************************************************
 *
 * Function         handle_avk_rc_metamsg_rsp
 *
 * Description      Handle RC metamessage response
 *
 * Returns          void
 *
 **************************************************************************/
static void handle_avk_rc_metamsg_rsp(tBTA_AV_META_MSG* pmeta_msg) {
  tAVRC_RESPONSE avrc_response = {0};
  uint8_t scratch_buf[512] = {0};  // this variable is unused
  uint16_t buf_len;
  tAVRC_STS status;
  btif_rc_device_cb_t* p_dev = NULL;

  log::verbose("opcode: {} rsp_code: {}", pmeta_msg->p_msg->hdr.opcode, pmeta_msg->code);

  p_dev = btif_rc_get_device_by_handle(pmeta_msg->rc_handle);
  status = AVRC_Ctrl_ParsResponse(pmeta_msg->p_msg, &avrc_response, scratch_buf, &buf_len);
  if ((AVRC_OP_VENDOR == pmeta_msg->p_msg->hdr.opcode) && (pmeta_msg->code >= AVRC_RSP_NOT_IMPL) &&
      (pmeta_msg->code <= AVRC_RSP_INTERIM)) {
    log::verbose("parse status {} pdu = {} rsp_status = {}", status, avrc_response.pdu,
                 pmeta_msg->p_msg->vendor.hdr.ctype);

    switch (avrc_response.pdu) {
      case AVRC_PDU_REGISTER_NOTIFICATION:
        handle_notification_response(pmeta_msg, &avrc_response.reg_notif);
        if (pmeta_msg->code == AVRC_RSP_INTERIM) {
          /* Don't free the transaction Id */
          clear_cmd_timeout(p_dev, pmeta_msg->label);
          return;
        }
        break;

      case AVRC_PDU_GET_CAPABILITIES:
        handle_get_capability_response(pmeta_msg, &avrc_response.get_caps);
        break;

      case AVRC_PDU_LIST_PLAYER_APP_ATTR:
        handle_app_attr_response(pmeta_msg, &avrc_response.list_app_attr);
        break;

      case AVRC_PDU_LIST_PLAYER_APP_VALUES:
        handle_app_val_response(pmeta_msg, &avrc_response.list_app_values);
        break;

      case AVRC_PDU_GET_CUR_PLAYER_APP_VALUE:
        handle_app_cur_val_response(pmeta_msg, &avrc_response.get_cur_app_val);
        break;

      case AVRC_PDU_GET_PLAYER_APP_ATTR_TEXT:
        handle_app_attr_txt_response(pmeta_msg, &avrc_response.get_app_attr_txt);
        break;

      case AVRC_PDU_GET_PLAYER_APP_VALUE_TEXT:
        handle_app_attr_val_txt_response(pmeta_msg, &avrc_response.get_app_val_txt);
        break;

      case AVRC_PDU_SET_PLAYER_APP_VALUE:
        handle_set_app_attr_val_response(pmeta_msg, &avrc_response.set_app_val);
        break;

      case AVRC_PDU_GET_ELEMENT_ATTR:
        handle_get_metadata_attr_response(pmeta_msg, &avrc_response.get_attrs);
        break;

      case AVRC_PDU_GET_PLAY_STATUS:
        handle_get_playstatus_response(pmeta_msg, &avrc_response.get_play_status);
        break;

      case AVRC_PDU_SET_ADDRESSED_PLAYER:
        handle_set_addressed_player_response(pmeta_msg, &avrc_response.rsp);
        break;
    }
  } else if (AVRC_OP_BROWSE == pmeta_msg->p_msg->hdr.opcode) {
    log::verbose("AVRC_OP_BROWSE pdu {}", avrc_response.pdu);
    /* check what kind of command it is for browsing */
    switch (avrc_response.pdu) {
      case AVRC_PDU_GET_FOLDER_ITEMS:
        handle_get_folder_items_response(pmeta_msg, &avrc_response.get_items);
        break;
      case AVRC_PDU_CHANGE_PATH:
        handle_change_path_response(pmeta_msg, &avrc_response.chg_path);
        break;
      case AVRC_PDU_SET_BROWSED_PLAYER:
        handle_set_browsed_player_response(pmeta_msg, &avrc_response.br_player);
        break;
      case AVRC_PDU_GET_ITEM_ATTRIBUTES:
        handle_get_metadata_attr_response(pmeta_msg, &avrc_response.get_attrs);
        break;
      default:
        log::error("cannot handle browse pdu {}", pmeta_msg->p_msg->hdr.opcode);
    }
  } else {
    log::verbose("Invalid Vendor Command code: {} len: {}. Not processing it.", pmeta_msg->code,
                 pmeta_msg->len);
    return;
  }
  log::verbose("release transaction {}", pmeta_msg->label);
  release_transaction(p_dev, pmeta_msg->label);
}

/***************************************************************************
 *
 * Function         handle_avk_rc_metamsg_cmd
 *
 * Description      Handle RC metamessage response
 *
 * Returns          void
 *
 **************************************************************************/
static void handle_avk_rc_metamsg_cmd(tBTA_AV_META_MSG* pmeta_msg) {
  tAVRC_COMMAND avrc_cmd = {0};
  tAVRC_STS status = BT_STATUS_UNSUPPORTED;
  btif_rc_device_cb_t* p_dev = NULL;

  log::verbose("opcode: {} rsp_code: {}", pmeta_msg->p_msg->hdr.opcode, pmeta_msg->code);
  status = AVRC_Ctrl_ParsCommand(pmeta_msg->p_msg, &avrc_cmd);
  if ((AVRC_OP_VENDOR == pmeta_msg->p_msg->hdr.opcode) && (pmeta_msg->code <= AVRC_CMD_GEN_INQ)) {
    log::verbose("Received vendor command.code {}, PDU {} label {}", pmeta_msg->code, avrc_cmd.pdu,
                 pmeta_msg->label);

    if (status != AVRC_STS_NO_ERROR) {
      /* return error */
      log::warn("Error in parsing received metamsg command. status: 0x{:02x}", status);
      if (true == btif_av_both_enable()) {
        if (AVRC_PDU_GET_CAPABILITIES == avrc_cmd.pdu ||
            AVRC_PDU_GET_ELEMENT_ATTR == avrc_cmd.pdu || AVRC_PDU_GET_PLAY_STATUS == avrc_cmd.pdu ||
            AVRC_PDU_GET_FOLDER_ITEMS == avrc_cmd.pdu ||
            AVRC_PDU_GET_ITEM_ATTRIBUTES == avrc_cmd.pdu) {
          return;
        }
      }
      send_reject_response(pmeta_msg->rc_handle, pmeta_msg->label, avrc_cmd.pdu, status,
                           pmeta_msg->p_msg->hdr.opcode);
    } else {
      p_dev = btif_rc_get_device_by_handle(pmeta_msg->rc_handle);
      if (p_dev == NULL) {
        log::error("avk rc meta msg cmd for Invalid rc handle");
        return;
      }

      if (avrc_cmd.pdu == AVRC_PDU_REGISTER_NOTIFICATION) {
        uint8_t event_id = avrc_cmd.reg_notif.event_id;
        log::verbose("Register notification event_id: {}", dump_rc_notification_event_id(event_id));
      } else if (avrc_cmd.pdu == AVRC_PDU_SET_ABSOLUTE_VOLUME) {
        log::verbose("Abs Volume Cmd Recvd");
      }

      btif_rc_ctrl_upstreams_rsp_cmd(avrc_cmd.pdu, &avrc_cmd, pmeta_msg->label, p_dev);
    }
  } else {
    log::verbose("Invalid Vendor Command  code: {} len: {}. Not processing it.", pmeta_msg->code,
                 pmeta_msg->len);
    return;
  }
}

/***************************************************************************
 *
 * Function         cleanup_ctrl
 *
 * Description      Closes the AVRC Controller interface
 *
 * Returns          void
 *
 **************************************************************************/
static void reset_device(btif_rc_device_cb_t& dev) {
  dev.rc_handle = {};
  dev.rc_features = {};
  dev.rc_cover_art_psm = {};
  dev.rc_state = BTRC_CONNECTION_STATE_DISCONNECTED;
  dev.br_state = BTRC_CONNECTION_STATE_DISCONNECTED;
  dev.rc_addr = RawAddress::kEmpty;
  if (dev.rc_supported_event_list != nullptr) {
    list_free(dev.rc_supported_event_list);
    dev.rc_supported_event_list = nullptr;
  }
  dev.rc_volume = MAX_VOLUME;
  dev.rc_vol_label = MAX_LABEL;
  dev.rc_app_settings = {};

  alarm_free(dev.rc_play_status_timer);
  dev.rc_play_status_timer = nullptr;

  dev.rc_features_processed = {};
  dev.rc_playing_uid = {};
  dev.rc_procedure_complete = {};

  for (int i = 0; i < MAX_TRANSACTIONS_PER_SESSION; ++i) {
    dev.transaction_set.transaction[i].in_use = {};
    dev.transaction_set.transaction[i].label = {};
    dev.transaction_set.transaction[i].context = {};
    alarm_free(dev.transaction_set.transaction[i].timer);
    dev.transaction_set.transaction[i].timer = nullptr;
  }

  dev.peer_ct_features = {};
  dev.peer_tg_features = {};
  dev.launch_cmd_pending = {};
}

static void cleanup_ctrl() {
  log::verbose("");

  if (bt_rc_ctrl_callbacks) {
    bt_rc_ctrl_callbacks = nullptr;
  }

  for (int idx = 0; idx < BTIF_RC_NUM_CONN; idx++) {
    reset_device(btif_rc_cb.rc_multi_cb[idx]);
  }

  log::verbose("completed");
}

/***************************************************************************
 *
 * Function         getcapabilities_cmd
 *
 * Description      GetCapabilties from Remote(Company_ID, Events_Supported)
 *
 * Returns          void
 *
 **************************************************************************/
static BtStatus getcapabilities_cmd(uint8_t cap_id, btif_rc_device_cb_t* p_dev) {
  log::verbose("cap_id: {}", cap_id);
  CHECK_RC_CONNECTED(p_dev);

  tAVRC_COMMAND avrc_cmd = {0};
  avrc_cmd.get_caps.opcode = AVRC_OP_VENDOR;
  avrc_cmd.get_caps.capability_id = cap_id;
  avrc_cmd.get_caps.pdu = AVRC_PDU_GET_CAPABILITIES;
  avrc_cmd.get_caps.status = AVRC_STS_NO_ERROR;

  return build_and_send_vendor_cmd(&avrc_cmd, AVRC_CMD_STATUS, p_dev);
}

/***************************************************************************
 *
 * Function         list_player_app_setting_attrib_cmd
 *
 * Description      Get supported List Player Attributes
 *
 * Returns          void
 *
 **************************************************************************/
static BtStatus list_player_app_setting_attrib_cmd(btif_rc_device_cb_t* p_dev) {
  log::verbose("");
  CHECK_RC_CONNECTED(p_dev);

  tAVRC_COMMAND avrc_cmd = {0};
  avrc_cmd.list_app_attr.opcode = AVRC_OP_VENDOR;
  avrc_cmd.list_app_attr.pdu = AVRC_PDU_LIST_PLAYER_APP_ATTR;
  avrc_cmd.list_app_attr.status = AVRC_STS_NO_ERROR;

  return build_and_send_vendor_cmd(&avrc_cmd, AVRC_CMD_STATUS, p_dev);
}

/***************************************************************************
 *
 * Function         list_player_app_setting_value_cmd
 *
 * Description      Get values of supported Player Attributes
 *
 * Returns          void
 *
 **************************************************************************/
static BtStatus list_player_app_setting_value_cmd(uint8_t attrib_id, btif_rc_device_cb_t* p_dev) {
  log::verbose("attrib_id: {}", attrib_id);
  CHECK_RC_CONNECTED(p_dev);

  tAVRC_COMMAND avrc_cmd = {0};
  avrc_cmd.list_app_values.attr_id = attrib_id;
  avrc_cmd.list_app_values.opcode = AVRC_OP_VENDOR;
  avrc_cmd.list_app_values.pdu = AVRC_PDU_LIST_PLAYER_APP_VALUES;
  avrc_cmd.list_app_values.status = AVRC_STS_NO_ERROR;

  return build_and_send_vendor_cmd(&avrc_cmd, AVRC_CMD_STATUS, p_dev);
}

/***************************************************************************
 *
 * Function         get_player_app_setting_cmd
 *
 * Description      Get current values of Player Attributes
 *
 * Returns          void
 *
 **************************************************************************/
static BtStatus get_player_app_setting_cmd(uint8_t num_attrib, uint8_t* attrib_ids,
                                           btif_rc_device_cb_t* p_dev) {
  log::verbose("num_attrib: {}", num_attrib);
  CHECK_RC_CONNECTED(p_dev);

  tAVRC_COMMAND avrc_cmd = {0};
  avrc_cmd.get_cur_app_val.opcode = AVRC_OP_VENDOR;
  avrc_cmd.get_cur_app_val.status = AVRC_STS_NO_ERROR;
  avrc_cmd.get_cur_app_val.num_attr = num_attrib;
  avrc_cmd.get_cur_app_val.pdu = AVRC_PDU_GET_CUR_PLAYER_APP_VALUE;

  for (int count = 0; count < num_attrib; count++) {
    avrc_cmd.get_cur_app_val.attrs[count] = attrib_ids[count];
  }

  return build_and_send_vendor_cmd(&avrc_cmd, AVRC_CMD_STATUS, p_dev);
}

/***************************************************************************
 *
 * Function         get_current_metadata_cmd
 *
 * Description      Fetch the current track metadata for the device
 *
 * Returns          BtifStatus() if command issued successfully otherwise
 *                  BtifStatus(FAIL).
 *
 **************************************************************************/
static BtStatus get_current_metadata_cmd(const RawAddress& bd_addr) {
  log::verbose("");
  btif_rc_device_cb_t* p_dev = btif_rc_get_device_by_bda(bd_addr);
  if (p_dev == NULL) {
    log::error("p_dev NULL");
    return BtifStatus(DEVICE_NOT_FOUND);
  }
  const uint32_t* attr_list = get_requested_attributes_list(p_dev);
  const uint8_t attr_list_size = get_requested_attributes_list_size(p_dev);
  return get_metadata_attribute_cmd(attr_list_size, attr_list, p_dev);
}

/***************************************************************************
 *
 * Function         get_playback_state_cmd
 *
 * Description      Fetch the current playback state for the device
 *
 * Returns          BtifStatus() if command issued successfully otherwise
 *                  BtifStatus(FAIL).
 *
 **************************************************************************/
static BtStatus get_playback_state_cmd(const RawAddress& bd_addr) {
  log::verbose("");
  btif_rc_device_cb_t* p_dev = btif_rc_get_device_by_bda(bd_addr);
  return get_play_status_cmd(p_dev);
}

/***************************************************************************
 *
 * Function         get_now_playing_list_cmd
 *
 * Description      Fetch the now playing list
 *
 * Parameters       start_item: First item to fetch (0 to fetch from beganning)
 *                  end_item: Last item to fetch (0xffffffff to fetch until end)
 *
 * Returns          BtifStatus() if command issued successfully otherwise
 *                  BtifStatus(FAIL).
 *
 **************************************************************************/
static BtStatus get_now_playing_list_cmd(const RawAddress& bd_addr, uint32_t start_item,
                                         uint32_t end_item) {
  log::verbose("start, end: ({}, {})", start_item, end_item);
  return get_folder_items_cmd(bd_addr, AVRC_SCOPE_NOW_PLAYING, start_item, end_item);
}

/***************************************************************************
 *
 * Function         get_item_attribute_cmd
 *
 * Description      Fetch the item attributes for a given uid.
 *
 * Parameters       uid: Track UID you want attributes for
 *                  scope: Constant representing which scope you're querying
 *                         (i.e AVRC_SCOPE_FILE_SYSTEM)
 *                  p_dev: Device control block
 *
 * Returns          BtifStatus() if command is issued successfully
 *                  otherwise BtifStatus(FAIL)
 *
 **************************************************************************/
static BtStatus get_item_attribute_cmd(uint64_t uid, int scope, uint8_t /*num_attribute*/,
                                       const uint32_t* /*p_attr_ids*/, btif_rc_device_cb_t* p_dev) {
  tAVRC_COMMAND avrc_cmd = {0};
  avrc_cmd.pdu = AVRC_PDU_GET_ITEM_ATTRIBUTES;
  avrc_cmd.get_attrs.scope = scope;
  memcpy(avrc_cmd.get_attrs.uid, &uid, 8);
  avrc_cmd.get_attrs.uid_counter = 0;
  avrc_cmd.get_attrs.attr_count = 0;

  return build_and_send_browsing_cmd(&avrc_cmd, p_dev);
}

/***************************************************************************
 *
 * Function         get_folder_list_cmd
 *
 * Description      Fetch the currently selected folder list
 *
 * Parameters       start_item: First item to fetch (0 to fetch from beganning)
 *                  end_item: Last item to fetch (0xffffffff to fetch until end)
 *
 * Returns          BtifStatus() if command issued successfully otherwise
 *                  BtifStatus(FAIL).
 *
 **************************************************************************/
static BtStatus get_folder_list_cmd(const RawAddress& bd_addr, uint32_t start_item,
                                    uint32_t end_item) {
  log::verbose("start, end: ({}, {})", start_item, end_item);
  return get_folder_items_cmd(bd_addr, AVRC_SCOPE_FILE_SYSTEM, start_item, end_item);
}

/***************************************************************************
 *
 * Function         get_player_list_cmd
 *
 * Description      Fetch the player list
 *
 * Parameters       start_item: First item to fetch (0 to fetch from beganning)
 *                  end_item: Last item to fetch (0xffffffff to fetch until end)
 *
 * Returns          BtifStatus() if command issued successfully otherwise
 *                  BtifStatus(FAIL).
 *
 **************************************************************************/
static BtStatus get_player_list_cmd(const RawAddress& bd_addr, uint32_t start_item,
                                    uint32_t end_item) {
  log::verbose("start, end: ({}, {})", start_item, end_item);
  return get_folder_items_cmd(bd_addr, AVRC_SCOPE_PLAYER_LIST, start_item, end_item);
}

/***************************************************************************
 *
 * Function         change_folder_path_cmd
 *
 * Description      Change the folder.
 *
 * Parameters       direction: Direction (Up/Down) to change folder
 *                  uid: The UID of folder to move to
 *                  start_item: First item to fetch (0 to fetch from beganning)
 *                  end_item: Last item to fetch (0xffffffff to fetch until end)
 *
 * Returns          BtifStatus() if command issued successfully otherwise
 *                  BtifStatus(FAIL).
 *
 **************************************************************************/
static BtStatus change_folder_path_cmd(const RawAddress& bd_addr, uint8_t direction, uint8_t* uid) {
  log::verbose("direction {}", direction);
  btif_rc_device_cb_t* p_dev = btif_rc_get_device_by_bda(bd_addr);
  CHECK_RC_CONNECTED(p_dev);
  CHECK_BR_CONNECTED(p_dev);

  tAVRC_COMMAND avrc_cmd = {0};

  avrc_cmd.chg_path.pdu = AVRC_PDU_CHANGE_PATH;
  avrc_cmd.chg_path.status = AVRC_STS_NO_ERROR;
  // TODO(sanketa): Improve for database aware clients.
  avrc_cmd.chg_path.uid_counter = 0;
  avrc_cmd.chg_path.direction = direction;

  memset(avrc_cmd.chg_path.folder_uid, 0, AVRC_UID_SIZE * sizeof(uint8_t));
  memcpy(avrc_cmd.chg_path.folder_uid, uid, AVRC_UID_SIZE * sizeof(uint8_t));

  return build_and_send_browsing_cmd(&avrc_cmd, p_dev);
}

/***************************************************************************
 *
 * Function         set_browsed_player_cmd
 *
 * Description      Change the browsed player.
 *
 * Parameters       id: The UID of player to move to
 *
 * Returns          BtifStatus() if command issued successfully otherwise
 *                  BtifStatus(FAIL).
 *
 **************************************************************************/
static BtStatus set_browsed_player_cmd(const RawAddress& bd_addr, uint16_t id) {
  log::verbose("id {}", id);
  btif_rc_device_cb_t* p_dev = btif_rc_get_device_by_bda(bd_addr);
  CHECK_RC_CONNECTED(p_dev);
  CHECK_BR_CONNECTED(p_dev);

  tAVRC_COMMAND avrc_cmd = {0};
  avrc_cmd.br_player.pdu = AVRC_PDU_SET_BROWSED_PLAYER;
  avrc_cmd.br_player.status = AVRC_STS_NO_ERROR;
  // TODO(sanketa): Improve for database aware clients.
  avrc_cmd.br_player.player_id = id;

  return build_and_send_browsing_cmd(&avrc_cmd, p_dev);
}

/***************************************************************************
 **
 ** Function         set_addressed_player_cmd
 **
 ** Description      Change the addressed player.
 **
 ** Parameters       id: The UID of player to move to
 **
 ** Returns          BtifStatus() if command issued successfully otherwise
 **                  BtifStatus(FAIL).
 **
 ***************************************************************************/
static BtStatus set_addressed_player_cmd(const RawAddress& bd_addr, uint16_t id) {
  log::verbose("id {}", id);

  btif_rc_device_cb_t* p_dev = btif_rc_get_device_by_bda(bd_addr);
  CHECK_RC_CONNECTED(p_dev);
  CHECK_BR_CONNECTED(p_dev);

  tAVRC_COMMAND avrc_cmd = {0};
  avrc_cmd.addr_player.pdu = AVRC_PDU_SET_ADDRESSED_PLAYER;
  avrc_cmd.addr_player.status = AVRC_STS_NO_ERROR;
  // TODO(sanketa): Improve for database aware clients.
  avrc_cmd.addr_player.player_id = id;

  return build_and_send_browsing_cmd(&avrc_cmd, p_dev);
}

/***************************************************************************
 *
 * Function         get_folder_items_cmd
 *
 * Description      Helper function to browse the content hierarchy of the
 *                  TG device.
 *
 * Parameters       scope: AVRC_SCOPE_NOW_PLAYING (etc) for various browseable
 *                  content
 *                  start_item: First item to fetch (0 to fetch from beganning)
 *                  end_item: Last item to fetch (0xffff to fetch until end)
 *
 * Returns          BtifStatus() if command issued successfully otherwise
 *                  BtifStatus(FAIL).
 *
 **************************************************************************/
static BtStatus get_folder_items_cmd(const RawAddress& bd_addr, uint8_t scope, uint32_t start_item,
                                     uint32_t end_item) {
  /* Check that both avrcp and browse channel are connected. */
  btif_rc_device_cb_t* p_dev = btif_rc_get_device_by_bda(bd_addr);
  log::verbose("");
  CHECK_RC_CONNECTED(p_dev);
  CHECK_BR_CONNECTED(p_dev);

  tAVRC_COMMAND avrc_cmd = {0};

  /* Set the layer specific to point to browse although this should really
   * be done by lower layers and looking at the PDU
   */
  avrc_cmd.get_items.pdu = AVRC_PDU_GET_FOLDER_ITEMS;
  avrc_cmd.get_items.status = AVRC_STS_NO_ERROR;
  avrc_cmd.get_items.scope = scope;
  avrc_cmd.get_items.start_item = start_item;
  avrc_cmd.get_items.end_item = end_item;
  avrc_cmd.get_items.attr_count = 0; /* p_attr_list does not matter hence */

  return build_and_send_browsing_cmd(&avrc_cmd, p_dev);
}

/***************************************************************************
 *
 * Function         change_player_app_setting
 *
 * Description      Set current values of Player Attributes
 *
 * Returns          void
 *
 **************************************************************************/
static BtStatus change_player_app_setting(const RawAddress& bd_addr, uint8_t num_attrib,
                                          uint8_t* attrib_ids, uint8_t* attrib_vals) {
  log::verbose("num_attrib: {}", num_attrib);
  btif_rc_device_cb_t* p_dev = btif_rc_get_device_by_bda(bd_addr);
  CHECK_RC_CONNECTED(p_dev);

  tAVRC_COMMAND avrc_cmd = {0};
  avrc_cmd.set_app_val.opcode = AVRC_OP_VENDOR;
  avrc_cmd.set_app_val.status = AVRC_STS_NO_ERROR;
  avrc_cmd.set_app_val.num_val = num_attrib;
  avrc_cmd.set_app_val.pdu = AVRC_PDU_SET_PLAYER_APP_VALUE;
  avrc_cmd.set_app_val.p_vals =
          (tAVRC_APP_SETTING*)osi_malloc(sizeof(tAVRC_APP_SETTING) * num_attrib);
  for (int count = 0; count < num_attrib; count++) {
    avrc_cmd.set_app_val.p_vals[count].attr_id = attrib_ids[count];
    avrc_cmd.set_app_val.p_vals[count].attr_val = attrib_vals[count];
  }

  BtStatus st = build_and_send_vendor_cmd(&avrc_cmd, AVRC_CMD_CTRL, p_dev);
  osi_free_and_reset((void**)&avrc_cmd.set_app_val.p_vals);
  return st;
}

/***************************************************************************
 *
 * Function         play_item_cmd
 *
 * Description      Play the item specified by UID & scope
 *
 * Returns          void
 *
 **************************************************************************/
static BtStatus play_item_cmd(const RawAddress& bd_addr, uint8_t scope, uint8_t* uid,
                              uint16_t uid_counter) {
  log::verbose("scope {} uid_counter {}", scope, uid_counter);
  btif_rc_device_cb_t* p_dev = btif_rc_get_device_by_bda(bd_addr);
  CHECK_RC_CONNECTED(p_dev);
  CHECK_BR_CONNECTED(p_dev);

  tAVRC_COMMAND avrc_cmd = {0};
  avrc_cmd.pdu = AVRC_PDU_PLAY_ITEM;
  avrc_cmd.play_item.opcode = AVRC_OP_VENDOR;
  avrc_cmd.play_item.status = AVRC_STS_NO_ERROR;
  avrc_cmd.play_item.scope = scope;
  memcpy(avrc_cmd.play_item.uid, uid, AVRC_UID_SIZE);
  avrc_cmd.play_item.uid_counter = uid_counter;

  return build_and_send_vendor_cmd(&avrc_cmd, AVRC_CMD_CTRL, p_dev);
}

/***************************************************************************
 *
 * Function         get_player_app_setting_attr_text_cmd
 *
 * Description      Get text description for app attribute
 *
 * Returns          void
 *
 **************************************************************************/
static BtStatus get_player_app_setting_attr_text_cmd(uint8_t* attrs, uint8_t num_attrs,
                                                     btif_rc_device_cb_t* p_dev) {
  log::verbose("num attrs: {}", num_attrs);
  CHECK_RC_CONNECTED(p_dev);

  tAVRC_COMMAND avrc_cmd = {0};
  avrc_cmd.pdu = AVRC_PDU_GET_PLAYER_APP_ATTR_TEXT;
  avrc_cmd.get_app_attr_txt.opcode = AVRC_OP_VENDOR;
  avrc_cmd.get_app_attr_txt.num_attr = num_attrs;

  for (int count = 0; count < num_attrs; count++) {
    avrc_cmd.get_app_attr_txt.attrs[count] = attrs[count];
  }

  return build_and_send_vendor_cmd(&avrc_cmd, AVRC_CMD_STATUS, p_dev);
}

/***************************************************************************
 *
 * Function         get_player_app_setting_val_text_cmd
 *
 * Description      Get text description for app attribute values
 *
 * Returns          void
 *
 **************************************************************************/
static BtStatus get_player_app_setting_value_text_cmd(uint8_t* vals, uint8_t num_vals,
                                                      btif_rc_device_cb_t* p_dev) {
  log::verbose("num_vals: {}", num_vals);
  CHECK_RC_CONNECTED(p_dev);

  tAVRC_COMMAND avrc_cmd = {0};
  avrc_cmd.pdu = AVRC_PDU_GET_PLAYER_APP_VALUE_TEXT;
  avrc_cmd.get_app_val_txt.opcode = AVRC_OP_VENDOR;
  avrc_cmd.get_app_val_txt.num_val = num_vals;

  for (int count = 0; count < num_vals; count++) {
    avrc_cmd.get_app_val_txt.vals[count] = vals[count];
  }

  return build_and_send_vendor_cmd(&avrc_cmd, AVRC_CMD_STATUS, p_dev);
}

/***************************************************************************
 *
 * Function         register_notification_cmd
 *
 * Description      Send Command to register for a Notification ID
 *
 * Returns          void
 *
 **************************************************************************/
static BtStatus register_notification_cmd(uint8_t event_id, uint32_t event_value,
                                          btif_rc_device_cb_t* p_dev) {
  log::verbose("event_id: {} event_value {}", event_id, event_value);
  CHECK_RC_CONNECTED(p_dev);

  tAVRC_COMMAND avrc_cmd = {0};
  avrc_cmd.reg_notif.opcode = AVRC_OP_VENDOR;
  avrc_cmd.reg_notif.status = AVRC_STS_NO_ERROR;
  avrc_cmd.reg_notif.event_id = event_id;
  avrc_cmd.reg_notif.pdu = AVRC_PDU_REGISTER_NOTIFICATION;
  avrc_cmd.reg_notif.param = event_value;

  return build_and_send_vendor_cmd(&avrc_cmd, AVRC_CMD_NOTIF, p_dev);
}

/***************************************************************************
 *
 * Function         get_metadata_attribute_cmd
 *
 * Description      Get metadata attributes for attributeIds. This function
 *                  will make the right determination of whether to use the
 *                  control or browsing channel for the request
 *
 * Returns          BtifStatus() if the command is successfully issued
 *                  otherwise BtifStatus(FAIL)
 *
 **************************************************************************/
static BtStatus get_metadata_attribute_cmd(uint8_t num_attribute, const uint32_t* p_attr_ids,
                                           btif_rc_device_cb_t* p_dev) {
  log::verbose("num_attribute: {} attribute_id: {}", num_attribute, p_attr_ids[0]);

  // If browsing is connected then send the command out that channel
  if (p_dev->br_state == BTRC_CONNECTION_STATE_CONNECTED) {
    return get_item_attribute_cmd(p_dev->rc_playing_uid, AVRC_SCOPE_NOW_PLAYING, num_attribute,
                                  p_attr_ids, p_dev);
  }

  // Otherwise, default to the control channel
  return get_element_attribute_cmd(num_attribute, p_attr_ids, p_dev);
}

/***************************************************************************
 *
 * Function         get_element_attribute_cmd
 *
 * Description      Get Element Attribute for  attributeIds
 *
 * Returns          void
 *
 **************************************************************************/
static BtStatus get_element_attribute_cmd(uint8_t num_attribute, const uint32_t* p_attr_ids,
                                          btif_rc_device_cb_t* p_dev) {
  log::verbose("num_attribute: {} attribute_id: {}", num_attribute, p_attr_ids[0]);
  CHECK_RC_CONNECTED(p_dev);
  tAVRC_COMMAND avrc_cmd = {0};
  avrc_cmd.get_elem_attrs.opcode = AVRC_OP_VENDOR;
  avrc_cmd.get_elem_attrs.status = AVRC_STS_NO_ERROR;
  avrc_cmd.get_elem_attrs.num_attr = num_attribute;
  avrc_cmd.get_elem_attrs.pdu = AVRC_PDU_GET_ELEMENT_ATTR;
  for (int count = 0; count < num_attribute; count++) {
    avrc_cmd.get_elem_attrs.attrs[count] = p_attr_ids[count];
  }

  return build_and_send_vendor_cmd(&avrc_cmd, AVRC_CMD_STATUS, p_dev);
}

/***************************************************************************
 *
 * Function         get_play_status_cmd
 *
 * Description      Get Playing Status of a Device
 *
 * Returns          BtStatus
 *
 **************************************************************************/
static BtStatus get_play_status_cmd(btif_rc_device_cb_t* p_dev) {
  log::verbose("");
  CHECK_RC_CONNECTED(p_dev);

  tAVRC_COMMAND avrc_cmd = {0};
  avrc_cmd.get_play_status.opcode = AVRC_OP_VENDOR;
  avrc_cmd.get_play_status.pdu = AVRC_PDU_GET_PLAY_STATUS;
  avrc_cmd.get_play_status.status = AVRC_STS_NO_ERROR;

  return build_and_send_vendor_cmd(&avrc_cmd, AVRC_CMD_STATUS, p_dev);
}

/***************************************************************************
 *
 * Function         set_volume_rsp
 *
 * Description      Rsp for SetAbsoluteVolume Command
 *
 * Returns          void
 *
 **************************************************************************/
static BtStatus set_volume_rsp(const RawAddress& bd_addr, uint8_t abs_vol, uint8_t label) {
  tAVRC_RESPONSE avrc_rsp;
  BT_HDR* p_msg = NULL;
  btif_rc_device_cb_t* p_dev = btif_rc_get_device_by_bda(bd_addr);

  CHECK_RC_CONNECTED(p_dev);

  log::verbose("abs_vol: {}", abs_vol);

  avrc_rsp.volume.opcode = AVRC_OP_VENDOR;
  avrc_rsp.volume.pdu = AVRC_PDU_SET_ABSOLUTE_VOLUME;
  avrc_rsp.volume.status = AVRC_STS_NO_ERROR;
  avrc_rsp.volume.volume = abs_vol;

  tAVRC_STS status = AVRC_BldResponse(p_dev->rc_handle, &avrc_rsp, &p_msg);
  BtStatus ret = BtifStatus(static_cast<BtifStatusCode>(status));
  if (status == AVRC_STS_NO_ERROR) {
    uint8_t* data_start = (uint8_t*)(p_msg + 1) + p_msg->offset;
    log::verbose("msgreq being sent out with label: {}", p_dev->rc_vol_label);
    if (p_msg != NULL) {
      BTA_AvVendorRsp(p_dev->rc_handle, label, AVRC_RSP_ACCEPT, data_start, p_msg->len, 0);
      ret = BtifStatus();
    }
  } else {
    log::error("failed to build command. status: 0x{:02x}", status);
  }
  osi_free(p_msg);
  return ret;
}

/***************************************************************************
 *
 * Function         send_register_abs_vol_rsp
 *
 * Description      Rsp for Notification of Absolute Volume
 *
 * Returns          void
 *
 **************************************************************************/
static BtStatus volume_change_notification_rsp(const RawAddress& bd_addr,
                                               btrc_notification_type_t rsp_type, uint8_t abs_vol,
                                               uint8_t label) {
  tAVRC_RESPONSE avrc_rsp;
  BT_HDR* p_msg = NULL;
  log::verbose("rsp_type: {} abs_vol: {}", rsp_type, abs_vol);

  btif_rc_device_cb_t* p_dev = btif_rc_get_device_by_bda(bd_addr);

  CHECK_RC_CONNECTED(p_dev);

  avrc_rsp.reg_notif.opcode = AVRC_OP_VENDOR;
  avrc_rsp.reg_notif.pdu = AVRC_PDU_REGISTER_NOTIFICATION;
  avrc_rsp.reg_notif.status = AVRC_STS_NO_ERROR;
  avrc_rsp.reg_notif.param.volume = abs_vol;
  avrc_rsp.reg_notif.event_id = AVRC_EVT_VOLUME_CHANGE;

  tAVRC_STS status = AVRC_BldResponse(p_dev->rc_handle, &avrc_rsp, &p_msg);
  BtStatus ret = BtifStatus(static_cast<BtifStatusCode>(status));
  if (status == AVRC_STS_NO_ERROR) {
    log::verbose("msgreq being sent out with label: {}", label);
    uint8_t* data_start = (uint8_t*)(p_msg + 1) + p_msg->offset;
    BTA_AvVendorRsp(
            p_dev->rc_handle, label,
            (rsp_type == BTRC_NOTIFICATION_TYPE_INTERIM) ? AVRC_RSP_INTERIM : AVRC_RSP_CHANGED,
            data_start, p_msg->len, 0);
    ret = BtifStatus();
  } else {
    log::error("failed to build command. status: 0x{:02x}", status);
  }
  osi_free(p_msg);

  return ret;
}

/***************************************************************************
 *
 * Function         send_groupnavigation_cmd
 *
 * Description      Send Pass-Through command
 *
 * Returns          void
 *
 **************************************************************************/
static BtStatus send_groupnavigation_cmd(const RawAddress& bd_addr, uint8_t key_code,
                                         uint8_t key_state) {
  BtStatus status = BtifStatus(UNSUPPORTED);
  rc_transaction_t* p_transaction = NULL;
  log::verbose("key-code: {}, key-state: {}", key_code, key_state);
  btif_rc_device_cb_t* p_dev = btif_rc_get_device_by_bda(bd_addr);

  CHECK_RC_CONNECTED(p_dev);

  if (p_dev->rc_features & BTA_AV_FEAT_RCTG) {
    rc_transaction_context_t context = {
            .rc_addr = p_dev->rc_addr,
            .label = MAX_LABEL,
            .opcode = AVRC_OP_PASS_THRU,
            .command = {.passthru = {AVRC_ID_VENDOR, key_state, key_code}}};
    BtStatus tran_status = get_transaction(p_dev, context, &p_transaction);
    if (tran_status && (NULL != p_transaction)) {
      uint8_t buffer[AVRC_PASS_THRU_GROUP_LEN] = {0};
      uint8_t* start = buffer;
      UINT24_TO_BE_STREAM(start, AVRC_CO_METADATA);
      *(start)++ = 0;
      UINT8_TO_BE_STREAM(start, key_code);
      BTA_AvRemoteVendorUniqueCmd(p_dev->rc_handle, p_transaction->label, (tBTA_AV_STATE)key_state,
                                  buffer, AVRC_PASS_THRU_GROUP_LEN);
      status = BtifStatus();
      start_transaction_timer(p_dev, p_transaction->label, BTIF_RC_TIMEOUT_MS);
      log::verbose("Send command, key-code={}, key-state={}, label={}", key_code, key_state,
                   p_transaction->label);
    } else {
      status = BtifStatus(FAIL);
      log::error("failed to get label, key-code={}, key-state={}, status={}", key_code, key_state,
                 tran_status);
    }
  } else {
    status = BtifStatus(UNSUPPORTED);
    log::verbose("feature not supported");
  }
  return status;
}

/***************************************************************************
 *
 * Function         send_passthrough_cmd
 *
 * Description      Send Pass-Through command
 *
 * Returns          void
 *
 **************************************************************************/
static BtStatus send_passthrough_cmd(const RawAddress& bd_addr, uint8_t key_code,
                                     uint8_t key_state) {
  BtStatus status = BtifStatus(UNSUPPORTED);
  btif_rc_device_cb_t* p_dev = NULL;
  log::error("calling btif_rc_get_device_by_bda");
  p_dev = btif_rc_get_device_by_bda(bd_addr);

  CHECK_RC_CONNECTED(p_dev);

  rc_transaction_t* p_transaction = NULL;
  log::verbose("key-code: {}, key-state: {}", key_code, key_state);
  if (p_dev->rc_features & BTA_AV_FEAT_RCTG) {
    rc_transaction_context_t context = {
            .rc_addr = p_dev->rc_addr,
            .label = MAX_LABEL,
            .opcode = AVRC_OP_PASS_THRU,
            .command = {.passthru = {AVRC_ID_VENDOR, key_state, key_code}}};
    BtStatus tran_status = get_transaction(p_dev, context, &p_transaction);
    if (tran_status && NULL != p_transaction) {
      BTA_AvRemoteCmd(p_dev->rc_handle, p_transaction->label, (tBTA_AV_RC)key_code,
                      (tBTA_AV_STATE)key_state);
      status = BtifStatus();
      start_transaction_timer(p_dev, p_transaction->label, BTIF_RC_TIMEOUT_MS);
      log::verbose("Send command, key-code={}, key-state={}, label={}", key_code, key_state,
                   p_transaction->label);
    } else {
      status = BtifStatus(FAIL);
      log::error("failed to get label, key-code={}, key-state={}, status={}", key_code, key_state,
                 tran_status);
    }
  } else {
    status = BtifStatus(UNSUPPORTED);
    log::verbose("feature not supported");
  }
  return status;
}

static const btrc_ctrl_interface_t bt_rc_ctrl_interface = {
        sizeof(bt_rc_ctrl_interface),
        init_ctrl,
        send_passthrough_cmd,
        send_groupnavigation_cmd,
        change_player_app_setting,
        play_item_cmd,
        get_current_metadata_cmd,
        get_playback_state_cmd,
        get_now_playing_list_cmd,
        get_folder_list_cmd,
        get_player_list_cmd,
        change_folder_path_cmd,
        set_browsed_player_cmd,
        set_addressed_player_cmd,
        set_volume_rsp,
        volume_change_notification_rsp,
        cleanup_ctrl,
};

/*******************************************************************************
 *
 * Function         btif_rc_ctrl_get_interface
 *
 * Description      Get the AVRCP Controller callback interface
 *
 * Returns          btrc_ctrl_interface_t
 *
 ******************************************************************************/
const btrc_ctrl_interface_t* btif_rc_ctrl_get_interface(void) { return &bt_rc_ctrl_interface; }

/*******************************************************************************
 *      Function         initialize_transaction
 *
 *      Description    Initializes fields of the transaction structure
 *
 *      Returns          void
 ******************************************************************************/
static void initialize_transaction(btif_rc_device_cb_t* p_dev, uint8_t lbl) {
  if (p_dev == nullptr) {
    return;
  }
  rc_transaction_set_t* transaction_set = &(p_dev->transaction_set);
  std::unique_lock<std::recursive_mutex> lock(transaction_set->label_lock);
  if (lbl < MAX_TRANSACTIONS_PER_SESSION) {
    log::verbose("initialize transaction, dev={}, label={}", p_dev->rc_addr, lbl);
    if (alarm_is_scheduled(transaction_set->transaction[lbl].timer)) {
      log::warn("clearing pending timer event, dev={}, label={}", p_dev->rc_addr, lbl);
      clear_cmd_timeout(p_dev, lbl);
    }
    transaction_set->transaction[lbl] = {
            .in_use = false,
            .label = lbl,
            .context =
                    {
                            .rc_addr = RawAddress::kEmpty,
                            .label = MAX_LABEL,
                            .opcode = AVRC_OP_INVALID,
                            .command = {},
                    },
            .timer = nullptr,
    };
  }
}

/*******************************************************************************
 *
 * Function         init_all_transactions
 *
 * Description    Initializes all transactions
 *
 * Returns          void
 ******************************************************************************/
void init_all_transactions(btif_rc_device_cb_t* p_dev) {
  if (p_dev == nullptr) {
    return;
  }
  for (uint8_t i = 0; i < MAX_TRANSACTIONS_PER_SESSION; ++i) {
    initialize_transaction(p_dev, i);
  }
}

/*******************************************************************************
 *
 * Function         get_transaction_by_lbl
 *
 * Description    Will return a transaction based on the label. If not inuse
 *                     will return an error.
 *
 * Returns          Transaction
 ******************************************************************************/
rc_transaction_t* get_transaction_by_lbl(btif_rc_device_cb_t* p_dev, uint8_t lbl) {
  if (p_dev == nullptr) {
    return nullptr;
  }

  rc_transaction_t* transaction = NULL;
  rc_transaction_set_t* transaction_set = &(p_dev->transaction_set);
  std::unique_lock<std::recursive_mutex> lock(transaction_set->label_lock);

  /* Determine if this is a valid label */
  if (lbl < MAX_TRANSACTIONS_PER_SESSION) {
    if (!transaction_set->transaction[lbl].in_use) {
      transaction = NULL;
    } else {
      transaction = &(transaction_set->transaction[lbl]);
    }
  }
  return transaction;
}

/*******************************************************************************
 *
 * Function         get_transaction
 *
 * Description    Obtains the transaction details.
 *
 * Returns          BtStatus
 ******************************************************************************/
static BtStatus get_transaction(btif_rc_device_cb_t* p_dev, rc_transaction_context_t& context,
                                rc_transaction_t** ptransaction) {
  if (p_dev == NULL) {
    return BtifStatus(PARM_INVALID);
  }
  rc_transaction_set_t* transaction_set = &(p_dev->transaction_set);
  std::unique_lock<std::recursive_mutex> lock(transaction_set->label_lock);

  // Check for unused transactions in the device's transaction set
  for (uint8_t i = 0; i < MAX_TRANSACTIONS_PER_SESSION; i++) {
    if (!transaction_set->transaction[i].in_use) {
      context.label = i;
      transaction_set->transaction[i].context = context;
      transaction_set->transaction[i].in_use = true;
      *ptransaction = &(transaction_set->transaction[i]);
      log::verbose("Assigned transaction, dev={}, transaction={}", p_dev->rc_addr,
                   dump_transaction(*ptransaction));
      return BtifStatus();
    }
  }
  log::error("p_dev={}, failed to find free transaction", p_dev->rc_addr);
  return BtifStatus(NOMEM);
}

/*******************************************************************************
 *
 * Function       start_transaction_timer
 *
 * Description    Starts a timer to release the label in case we don't get a
 *                response. Uses the central timeout handler, which will route
 *                timeout events based on context opcode and pdu_id
 *
 * Returns        void
 ******************************************************************************/
static void start_transaction_timer(btif_rc_device_cb_t* p_dev, uint8_t label,
                                    uint64_t timeout_ms) {
  rc_transaction_t* transaction = get_transaction_by_lbl(p_dev, label);
  if (transaction == nullptr) {
    log::error("transaction is null");
    return;
  }

  if (alarm_is_scheduled(transaction->timer)) {
    log::warn("Restarting timer that's already scheduled");
  }

  std::string alarm_label = std::format("btif_rc.{}.{}", p_dev->rc_addr, transaction->label);
  alarm_free(transaction->timer);
  transaction->timer = alarm_new(alarm_label.c_str());
  alarm_set_on_mloop(transaction->timer, timeout_ms, btif_rc_transaction_timer_timeout,
                     &transaction->context);
}

/*******************************************************************************
 *
 * Function         release_transaction
 *
 * Description    Will release a transaction for reuse
 *
 * Returns          void
 ******************************************************************************/
void release_transaction(btif_rc_device_cb_t* p_dev, uint8_t lbl) {
  if (p_dev == nullptr) {
    log::warn("Failed to release transaction, dev=null, label={}", lbl);
    return;
  }
  rc_transaction_set_t* transaction_set = &(p_dev->transaction_set);
  std::unique_lock<std::recursive_mutex> lock(transaction_set->label_lock);

  rc_transaction_t* transaction = get_transaction_by_lbl(p_dev, lbl);

  /* If the transaction is in use... */
  if (transaction != NULL) {
    log::verbose("Released transaction, dev={}, label={}", p_dev->rc_addr, lbl);
    initialize_transaction(p_dev, lbl);
  } else {
    log::warn("Failed to release transaction, could not find dev={}, label={}", p_dev->rc_addr,
              lbl);
  }
}

/*******************************************************************************
 *
 * Function       dump_transaction
 *
 * Description    Dump transactions info for debugging
 *
 * Returns        String of transaction info
 ******************************************************************************/
static std::string dump_transaction(const rc_transaction_t* const transaction) {
  std::stringstream ss;

  ss << "label=" << (int)transaction->label;
  ss << " in_use=" << (transaction->in_use ? "true" : "false");

  rc_transaction_context_t context = transaction->context;
  ss << " context=(";
  uint8_t opcode_id = context.opcode;
  ss << "opcode=" << dump_rc_opcode(opcode_id);
  switch (opcode_id) {
    case AVRC_OP_VENDOR:
      ss << " pdu_id=" << dump_rc_pdu(context.command.vendor.pdu_id);
      if (context.command.vendor.pdu_id == AVRC_PDU_REGISTER_NOTIFICATION) {
        ss << " event_id=" << dump_rc_notification_event_id(context.command.vendor.event_id);
      }
      break;
    case AVRC_OP_BROWSE:
      ss << " pdu_id=" << dump_rc_pdu(context.command.browse.pdu_id);
      break;
    case AVRC_OP_PASS_THRU:
      ss << " rc_id=" << static_cast<int>(context.command.passthru.rc_id);
      ss << " key_state=" << static_cast<int>(context.command.passthru.key_state);
      break;
  }
  ss << ")";

  ss << " alarm=";
  alarm_t* alarm = transaction->timer;
  if (alarm != nullptr) {
    ss << "(set=" << alarm_is_scheduled(alarm) << " left=" << alarm_get_remaining_ms(alarm) << ")";
  } else {
    ss << "null";
  }
  return ss.str();
}

/***************************************************************************
 *
 * Function         vendor_cmd_timeout_handler
 *
 * Description      vendor dependent command timeout handler
 * Returns          None
 *
 **************************************************************************/
static void vendor_cmd_timeout_handler(btif_rc_device_cb_t* p_dev, uint8_t label,
                                       rc_vendor_context_t* p_context) {
  if (p_dev == NULL) {
    log::error("p_dev NULL");
    return;
  }

  tAVRC_RESPONSE avrc_response = {0};
  tBTA_AV_META_MSG meta_msg = {.rc_handle = p_dev->rc_handle};

  log::warn("timeout, addr={}, label={}, pdu_id={}, event_id={}", p_dev->rc_addr, label,
            dump_rc_pdu(p_context->pdu_id), dump_rc_notification_event_id(p_context->event_id));

  switch (p_context->pdu_id) {
    case AVRC_PDU_REGISTER_NOTIFICATION:
      rc_notification_interim_timeout(p_dev, p_context->event_id);
      break;

    case AVRC_PDU_GET_CAPABILITIES:
      avrc_response.get_caps.status = BTIF_RC_STS_TIMEOUT;
      handle_get_capability_response(&meta_msg, &avrc_response.get_caps);
      break;

    case AVRC_PDU_LIST_PLAYER_APP_ATTR:
      avrc_response.list_app_attr.status = BTIF_RC_STS_TIMEOUT;
      handle_app_attr_response(&meta_msg, &avrc_response.list_app_attr);
      break;

    case AVRC_PDU_LIST_PLAYER_APP_VALUES:
      avrc_response.list_app_values.status = BTIF_RC_STS_TIMEOUT;
      handle_app_val_response(&meta_msg, &avrc_response.list_app_values);
      break;

    case AVRC_PDU_GET_CUR_PLAYER_APP_VALUE:
      avrc_response.get_cur_app_val.status = BTIF_RC_STS_TIMEOUT;
      handle_app_cur_val_response(&meta_msg, &avrc_response.get_cur_app_val);
      break;

    case AVRC_PDU_GET_PLAYER_APP_ATTR_TEXT:
      avrc_response.get_app_attr_txt.status = BTIF_RC_STS_TIMEOUT;
      handle_app_attr_txt_response(&meta_msg, &avrc_response.get_app_attr_txt);
      break;

    case AVRC_PDU_GET_PLAYER_APP_VALUE_TEXT:
      avrc_response.get_app_val_txt.status = BTIF_RC_STS_TIMEOUT;
      handle_app_attr_txt_response(&meta_msg, &avrc_response.get_app_val_txt);
      break;

    case AVRC_PDU_GET_ELEMENT_ATTR:
      avrc_response.get_attrs.status = BTIF_RC_STS_TIMEOUT;
      handle_get_metadata_attr_response(&meta_msg, &avrc_response.get_attrs);
      break;

    case AVRC_PDU_GET_PLAY_STATUS:
      avrc_response.get_play_status.status = BTIF_RC_STS_TIMEOUT;
      handle_get_playstatus_response(&meta_msg, &avrc_response.get_play_status);
      break;

    case AVRC_PDU_SET_PLAYER_APP_VALUE:
      avrc_response.set_app_val.status = BTIF_RC_STS_TIMEOUT;
      handle_set_app_attr_val_response(&meta_msg, &avrc_response.set_app_val);
      break;

    case AVRC_PDU_PLAY_ITEM:
      // Nothing to notify on, just release the label
      break;

    default:
      log::warn("timeout for unknown pdu_id={}", p_context->pdu_id);
      break;
  }
}

/***************************************************************************
 *
 * Function         browse_cmd_timeout_handler
 *
 * Description      Browse command timeout handler
 * Returns          None
 *
 **************************************************************************/
static void browse_cmd_timeout_handler(btif_rc_device_cb_t* p_dev, uint8_t label,
                                       rc_browse_context_t* p_context) {
  if (p_dev == NULL) {
    log::error("p_dev NULL");
    return;
  }

  tAVRC_RESPONSE avrc_response = {0};
  tBTA_AV_META_MSG meta_msg = {
          .rc_handle = p_dev->rc_handle,
          .len = 0,
          .label = 0,
          .code = 0,
          .company_id = 0,
          .p_data = nullptr,
          .p_msg = nullptr,
  };

  log::warn("timeout, addr={}, label={}, pdu_id={}", p_dev->rc_addr, label,
            dump_rc_pdu(p_context->pdu_id));

  switch (p_context->pdu_id) {
    case AVRC_PDU_GET_FOLDER_ITEMS:
      avrc_response.get_items.status = BTIF_RC_STS_TIMEOUT;
      handle_get_folder_items_response(&meta_msg, &avrc_response.get_items);
      break;
    case AVRC_PDU_CHANGE_PATH:
      avrc_response.chg_path.status = BTIF_RC_STS_TIMEOUT;
      handle_change_path_response(&meta_msg, &avrc_response.chg_path);
      break;
    case AVRC_PDU_SET_BROWSED_PLAYER:
      avrc_response.br_player.status = BTIF_RC_STS_TIMEOUT;
      handle_set_browsed_player_response(&meta_msg, &avrc_response.br_player);
      break;
    case AVRC_PDU_GET_ITEM_ATTRIBUTES:
      avrc_response.get_attrs.status = BTIF_RC_STS_TIMEOUT;
      handle_get_metadata_attr_response(&meta_msg, &avrc_response.get_attrs);
      break;
    default:
      log::warn("timeout for unknown pdu_id={}", p_context->pdu_id);
      break;
  }
}

/***************************************************************************
 *
 * Function         passthru_cmd_timeout_handler
 *
 * Description      Pass-thru command timeout handler
 * Returns          None
 *
 **************************************************************************/
static void passthru_cmd_timeout_handler(btif_rc_device_cb_t* p_dev, uint8_t label,
                                         rc_passthru_context_t* p_context) {
  if (p_dev == NULL) {
    log::error("p_dev NULL");
    return;
  }

  log::warn("timeout, addr={}, label={}, rc_id={}, key_state={}", p_dev->rc_addr, label,
            p_context->rc_id, p_context->key_state);

  // Other requests are wrapped in a tAVRC_RESPONSE response object, but these
  // passthru events are not in there. As well, the upper layers don't handle
  // these events anyways. If that were to change, we could check the rc_id and
  // choose to route either the passthrough handler or vendorunique handler here
  return;
}

/***************************************************************************
 *
 * Function         btif_rc_transaction_timeout_handler
 *
 * Description      RC transaction timeout handler (Runs in BTIF context).
 * Returns          None
 *
 **************************************************************************/
static void btif_rc_transaction_timeout_handler(uint16_t /* event */, char* data) {
  rc_transaction_context_t* p_context = (rc_transaction_context_t*)data;
  if (p_context == nullptr) {
    log::error("p_context is null");
    return;
  }

  btif_rc_device_cb_t* p_dev = btif_rc_get_device_by_bda(p_context->rc_addr);
  if (p_dev == NULL) {
    log::error("p_dev is null");
    return;
  }

  uint8_t label = p_context->label;
  switch (p_context->opcode) {
    case AVRC_OP_VENDOR:
      vendor_cmd_timeout_handler(p_dev, label, &(p_context->command.vendor));
      break;
    case AVRC_OP_BROWSE:
      browse_cmd_timeout_handler(p_dev, label, &(p_context->command.browse));
      break;
    case AVRC_OP_PASS_THRU:
      passthru_cmd_timeout_handler(p_dev, label, &(p_context->command.passthru));
      break;
    default:
      log::warn("received timeout for unknown opcode={}", p_context->opcode);
      return;
  }
  release_transaction(p_dev, label);
}

/***************************************************************************
 *
 * Function         btif_rc_transaction_timer_timeout
 *
 * Description      RC transaction timeout callback.
 *                  This is called from BTU context and switches to BTIF
 *                  context to handle the timeout events
 * Returns          None
 *
 **************************************************************************/
static void btif_rc_transaction_timer_timeout(void* data) {
  rc_transaction_context_t* p_data = (rc_transaction_context_t*)data;

  btif_transfer_context(btif_rc_transaction_timeout_handler, 0, (char*)p_data,
                        sizeof(rc_transaction_context_t), NULL);
}

/***************************************************************************
 *
 * Function       dump_peer_features
 *
 * Description    Dump peer features bit field for debugging
 *
 * Returns        String of peer features info
 ******************************************************************************/
static std::string dump_peer_features(const uint16_t feats) {
  std::stringstream ss;

  if (feats == 0) {
    ss << "        EMPTY" << "\n";
  }
  if (feats & BTA_AV_FEAT_RCTG) {
    ss << "        BTA_AV_FEAT_RCTG" << "\n";
  }
  if (feats & BTA_AV_FEAT_RCCT) {
    ss << "        BTA_AV_FEAT_RCCT" << "\n";
  }
  if (feats & BTA_AV_FEAT_PROTECT) {
    ss << "        BTA_AV_FEAT_PROTECT" << "\n";
  }
  if (feats & BTA_AV_FEAT_VENDOR) {
    ss << "        BTA_AV_FEAT_VENDOR" << "\n";
  }
  if (feats & BTA_AV_FEAT_REPORT) {
    ss << "        BTA_AV_FEAT_REPORT" << "\n";
  }
  if (feats & BTA_AV_FEAT_METADATA) {
    ss << "        BTA_AV_FEAT_METADATA" << "\n";
  }
  if (feats & BTA_AV_FEAT_MULTI_AV) {
    ss << "        BTA_AV_FEAT_MULTI_AV" << "\n";
  }
  if (feats & BTA_AV_FEAT_BROWSE) {
    ss << "        BTA_AV_FEAT_BROWSE" << "\n";
  }
  if (feats & BTA_AV_FEAT_ADV_CTRL) {
    ss << "        BTA_AV_FEAT_ADV_CTRL" << "\n";
  }
  if (feats & BTA_AV_FEAT_DELAY_RPT) {
    ss << "        BTA_AV_FEAT_DELAY_RPT" << "\n";
  }
  if (feats & BTA_AV_FEAT_ACP_START) {
    ss << "        BTA_AV_FEAT_ACP_START" << "\n";
  }
  if (feats & BTA_AV_FEAT_COVER_ARTWORK) {
    ss << "        BTA_AV_FEAT_COVER_ARTWORK" << "\n";
  }
  if (feats & BTA_AV_FEAT_APP_SETTING) {
    ss << "        BTA_AV_FEAT_APP_SETTING" << "\n";
  }

  return ss.str();
}

/*******************************************************************************
 *      Function       btif_debug_rc_dump
 *
 *      Description    Dumps the state of the btif_rc subsytem
 *
 *      Returns        void
 ******************************************************************************/
void btif_debug_rc_dump(int fd) {
  dprintf(fd, "\nAVRCP Controller Native State:\n");

  int connected_count = 0;
  for (int i = 0; i < BTIF_RC_NUM_CONN; ++i) {
    const btrc_connection_state_t state = btif_rc_cb.rc_multi_cb[i].rc_state;
    if (state != BTRC_CONNECTION_STATE_DISCONNECTED) {
      ++connected_count;
    }
  }

  dprintf(fd, "  Devices (%d / %d):\n", connected_count, BTIF_RC_NUM_CONN - 1);
  for (int i = 0; i < BTIF_RC_NUM_CONN; ++i) {
    btif_rc_device_cb_t* p_dev = &btif_rc_cb.rc_multi_cb[i];
    if (p_dev->rc_state != BTRC_CONNECTION_STATE_DISCONNECTED) {
      dprintf(fd, "    %s:\n", p_dev->rc_addr.ToRedactedStringForLogging().c_str());

      dprintf(fd, "      Control: %s\n",
              (p_dev->rc_state == BTRC_CONNECTION_STATE_CONNECTED) ? "connected" : "disconnected");
      dprintf(fd, "      Browse: %s\n",
              (p_dev->br_state == BTRC_CONNECTION_STATE_CONNECTED) ? "connected" : "disconnected");
      dprintf(fd, "      Cover Art PSM: %i\n", p_dev->rc_cover_art_psm);

      dprintf(fd, "      Peer Target Features:\n%s",
              dump_peer_features(p_dev->peer_tg_features).c_str());
      dprintf(fd, "      Peer Controller Features:\n%s",
              dump_peer_features(p_dev->peer_ct_features).c_str());

      rc_transaction_set_t* transaction_set = &(p_dev->transaction_set);
      std::unique_lock<std::recursive_mutex> lock(transaction_set->label_lock);
      dprintf(fd, "      Transaction Labels:\n");
      for (auto j = 0; j < MAX_TRANSACTIONS_PER_SESSION; ++j) {
        dprintf(fd, "        %s\n", dump_transaction(&transaction_set->transaction[j]).c_str());
      }
    }
  }
}

static btif_rc_device_cb_t* get_device_cb(unsigned index) {
  return (index < BTIF_RC_NUM_CONN) ? &btif_rc_cb.rc_multi_cb[index] : nullptr;
}

namespace bluetooth::testing::avrc {

static btif_rc_interface interface = {
        /*************************************************************************
         * Group 1: Command Transmission & Infrastructure
         *************************************************************************/
        .build_and_send_browsing_cmd = ::build_and_send_browsing_cmd,
        .build_and_send_vendor_cmd = ::build_and_send_vendor_cmd,
        .btif_rc_ctrl_upstreams_rsp_cmd = ::btif_rc_ctrl_upstreams_rsp_cmd,
        .send_reject_response = ::send_reject_response,

        /*************************************************************************
         * Group 2: Player Metadata & Status Tracking
         *************************************************************************/
        .get_element_attribute_cmd = ::get_element_attribute_cmd,
        .get_metadata_attribute_cmd = ::get_metadata_attribute_cmd,
        .get_play_status_cmd = ::get_play_status_cmd,
        .get_player_app_setting_attr_text_cmd = ::get_player_app_setting_attr_text_cmd,
        .get_player_app_setting_cmd = ::get_player_app_setting_cmd,
        .get_player_app_setting_value_text_cmd = ::get_player_app_setting_value_text_cmd,
        .list_player_app_setting_attrib_cmd = ::list_player_app_setting_attrib_cmd,
        .list_player_app_setting_value_cmd = ::list_player_app_setting_value_cmd,
        .handle_app_attr_response = ::handle_app_attr_response,
        .handle_app_attr_txt_response = ::handle_app_attr_txt_response,
        .handle_app_attr_val_txt_response = ::handle_app_attr_val_txt_response,
        .handle_app_cur_val_response = ::handle_app_cur_val_response,
        .handle_app_val_response = ::handle_app_val_response,
        .handle_get_metadata_attr_response = ::handle_get_metadata_attr_response,
        .handle_get_playstatus_response = ::handle_get_playstatus_response,
        .handle_set_app_attr_val_response = ::handle_set_app_attr_val_response,
        .cleanup_app_attr_val_txt_response = ::cleanup_app_attr_val_txt_response,
        .rc_is_track_id_valid = ::rc_is_track_id_valid,

        /*************************************************************************
         * Group 3: Player & Feature Discovery
         *************************************************************************/
        .getcapabilities_cmd = ::getcapabilities_cmd,
        .handle_get_capability_response = ::handle_get_capability_response,
        .handle_rc_browse_connect = ::handle_rc_browse_connect,
        .handle_rc_connect = ::handle_rc_connect,
        .handle_rc_ctrl_features = ::handle_rc_ctrl_features,
        .handle_rc_ctrl_features_all = ::handle_rc_ctrl_features_all,
        .handle_rc_ctrl_psm = ::handle_rc_ctrl_psm,
        .handle_rc_disconnect = ::handle_rc_disconnect,
        .handle_set_addressed_player_response = ::handle_set_addressed_player_response,
        .handle_set_browsed_player_response = ::handle_set_browsed_player_response,
        .dump_peer_features = ::dump_peer_features,
        .get_requested_attributes_list_size = ::get_requested_attributes_list_size,

        /*************************************************************************
         * Group 4: Device & Transaction Management
         *************************************************************************/
        .get_device_cb = ::get_device_cb,
        .alloc_device = ::alloc_device,
        .btif_rc_get_device_by_bda = ::btif_rc_get_device_by_bda,
        .btif_rc_get_device_by_handle = ::btif_rc_get_device_by_handle,
        .get_connected_device = ::get_connected_device,
        .get_transaction = ::get_transaction,
        .get_transaction_by_lbl = ::get_transaction_by_lbl,
        .initialize_device = ::initialize_device,
        .init_all_transactions = ::init_all_transactions,
        .initialize_transaction = ::initialize_transaction,
        .release_transaction = ::release_transaction,
        .dump_transaction = ::dump_transaction,

        /*************************************************************************
         * Group 5: Browsing & Content Navigation
         *************************************************************************/
        .get_folder_items_cmd = ::get_folder_items_cmd,
        .get_item_attribute_cmd = ::get_item_attribute_cmd,
        .handle_change_path_response = ::handle_change_path_response,
        .handle_get_folder_items_response = ::handle_get_folder_items_response,
        .get_folder_item_type_folder = ::get_folder_item_type_folder,
        .get_folder_item_type_media = ::get_folder_item_type_media,
        .get_folder_item_type_player = ::get_folder_item_type_player,
        .cleanup_btrc_folder_items = ::cleanup_btrc_folder_items,

        /*************************************************************************
         * Group 6: Event Notification & Timeout Handling
         *************************************************************************/
        .register_notification_cmd = ::register_notification_cmd,
        .register_for_event_notification = ::register_for_event_notification,
        .handle_notification_response = ::handle_notification_response,
        .iterate_supported_event_list_for_interim_rsp =
                ::iterate_supported_event_list_for_interim_rsp,
        .rc_notification_interim_timeout = ::rc_notification_interim_timeout,
        .rc_ctrl_procedure_complete = ::rc_ctrl_procedure_complete,
        .start_transaction_timer = ::start_transaction_timer,
        .clear_cmd_timeout = ::clear_cmd_timeout,
        .passthru_cmd_timeout_handler = ::passthru_cmd_timeout_handler,
        .vendor_cmd_timeout_handler = ::vendor_cmd_timeout_handler,
        .browse_cmd_timeout_handler = ::browse_cmd_timeout_handler,
        .btif_rc_transaction_timer_timeout = ::btif_rc_transaction_timer_timeout,
        .btif_rc_transaction_timeout_handler = ::btif_rc_transaction_timeout_handler,
        .handle_rc_passthrough_rsp = ::handle_rc_passthrough_rsp,
        .handle_rc_vendorunique_rsp = ::handle_rc_vendorunique_rsp,
        .handle_avk_rc_metamsg_cmd = ::handle_avk_rc_metamsg_cmd,
        .handle_avk_rc_metamsg_rsp = ::handle_avk_rc_metamsg_rsp,
};

btif_rc_interface* btif_rc_ctrl_get_interface() { return &interface; }

}  // namespace bluetooth::testing::avrc
