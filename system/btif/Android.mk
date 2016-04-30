 ##############################################################################
 #
 #  Copyright (C) 2014 Google, Inc.
 #
 #  Licensed under the Apache License, Version 2.0 (the "License");
 #  you may not use this file except in compliance with the License.
 #  You may obtain a copy of the License at:
 #
 #  http://www.apache.org/licenses/LICENSE-2.0
 #
 #  Unless required by applicable law or agreed to in writing, software
 #  distributed under the License is distributed on an "AS IS" BASIS,
 #  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 #  See the License for the specific language governing permissions and
 #  limitations under the License.
 #
 ##############################################################################

LOCAL_PATH := $(call my-dir)

# Common variables
# ========================================================

# HAL layer
btifCommonSrc := \
  src/bluetooth.cc

# BTIF implementation
btifCommonSrc += \
  src/btif_av.cc \
  src/btif_avrcp_audio_track.cc \
  src/btif_config.cc \
  src/btif_config_transcode.cc \
  src/btif_core.cc \
  src/btif_debug.cc \
  src/btif_debug_btsnoop.cc \
  src/btif_debug_conn.cc \
  src/btif_dm.cc \
  src/btif_gatt.cc \
  src/btif_gatt_client.cc \
  src/btif_gatt_multi_adv_util.cc \
  src/btif_gatt_server.cc \
  src/btif_gatt_test.cc \
  src/btif_gatt_util.cc \
  src/btif_hf.cc \
  src/btif_hf_client.cc \
  src/btif_hh.cc \
  src/btif_hl.cc \
  src/btif_sdp.cc \
  src/btif_media_task.cc \
  src/btif_pan.cc \
  src/btif_profile_queue.cc \
  src/btif_rc.cc \
  src/btif_sm.cc \
  src/btif_sock.cc \
  src/btif_sock_rfc.cc \
  src/btif_sock_l2cap.cc \
  src/btif_sock_sco.cc \
  src/btif_sock_sdp.cc \
  src/btif_sock_thread.cc \
  src/btif_sdp_server.cc \
  src/btif_sock_util.cc \
  src/btif_storage.cc \
  src/btif_uid.cc \
  src/btif_util.cc \
  src/stack_manager.cc

# Callouts
btifCommonSrc += \
  co/bta_ag_co.cc \
  co/bta_dm_co.cc \
  co/bta_av_co.cc \
  co/bta_hh_co.cc \
  co/bta_hl_co.cc \
  co/bta_pan_co.cc \
  co/bta_gatts_co.cc

# Tests
btifTestSrc := \
  test/btif_storage_test.cc

# Includes
btifCommonIncludes := \
  $(LOCAL_PATH)/../ \
  $(LOCAL_PATH)/../bta/include \
  $(LOCAL_PATH)/../bta/sys \
  $(LOCAL_PATH)/../bta/dm \
  $(LOCAL_PATH)/../btcore/include \
  $(LOCAL_PATH)/../include \
  $(LOCAL_PATH)/../stack/include \
  $(LOCAL_PATH)/../stack/l2cap \
  $(LOCAL_PATH)/../stack/a2dp \
  $(LOCAL_PATH)/../stack/btm \
  $(LOCAL_PATH)/../stack/avdt \
  $(LOCAL_PATH)/../hcis \
  $(LOCAL_PATH)/../hcis/include \
  $(LOCAL_PATH)/../hcis/patchram \
  $(LOCAL_PATH)/../udrv/include \
  $(LOCAL_PATH)/../btif/include \
  $(LOCAL_PATH)/../btif/co \
  $(LOCAL_PATH)/../hci/include\
  $(LOCAL_PATH)/../vnd/include \
  $(LOCAL_PATH)/../brcm/include \
  $(LOCAL_PATH)/../embdrv/sbc/encoder/include \
  $(LOCAL_PATH)/../embdrv/sbc/decoder/include \
  $(LOCAL_PATH)/../audio_a2dp_hw \
  $(LOCAL_PATH)/../utils/include \
  $(bluetooth_C_INCLUDES) \
  external/tinyxml2 \
  external/zlib

# libbtif static library for target
# ========================================================
include $(CLEAR_VARS)

LOCAL_CPP_EXTENSION := .cc

LOCAL_C_INCLUDES := $(btifCommonIncludes)
LOCAL_SRC_FILES := $(btifCommonSrc)
# Many .h files have redefined typedefs
LOCAL_SHARED_LIBRARIES := libmedia libcutils liblog libchrome
LOCAL_MODULE_CLASS := STATIC_LIBRARIES
LOCAL_MODULE_TAGS := optional
LOCAL_MODULE := libbtif

LOCAL_CFLAGS += $(bluetooth_CFLAGS) -DBUILDCFG
LOCAL_CONLYFLAGS += $(bluetooth_CONLYFLAGS)
LOCAL_CPPFLAGS += $(bluetooth_CPPFLAGS)

include $(BUILD_STATIC_LIBRARY)

# btif unit tests for target
# ========================================================
include $(CLEAR_VARS)

LOCAL_CPP_EXTENSION := .cc

LOCAL_C_INCLUDES := $(btifCommonIncludes)
LOCAL_SRC_FILES := $(btifTestSrc)
LOCAL_SHARED_LIBRARIES += liblog libhardware libhardware_legacy libcutils
LOCAL_STATIC_LIBRARIES += libbtcore libbtif libosi
LOCAL_MODULE_TAGS := optional
LOCAL_MODULE := net_test_btif

LOCAL_CFLAGS += $(bluetooth_CFLAGS) -DBUILDCFG
LOCAL_CONLYFLAGS += $(bluetooth_CONLYFLAGS)
LOCAL_CPPFLAGS += $(bluetooth_CPPFLAGS)

include $(BUILD_NATIVE_TEST)
