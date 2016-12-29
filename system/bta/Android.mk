LOCAL_PATH:= $(call my-dir)

# Tests
btaTestSrc := \
  test/bta_closure_test.cc \
  test/bta_hf_client_test.cc

btaCommonIncludes := \
                   $(LOCAL_PATH)/../ \
                   $(LOCAL_PATH)/include \
                   $(LOCAL_PATH)/sys \
                   $(LOCAL_PATH)/dm \
                   $(LOCAL_PATH)/hh \
                   $(LOCAL_PATH)/hd \
                   $(LOCAL_PATH)/closure \
                   $(LOCAL_PATH)/../btcore/include \
                   $(LOCAL_PATH)/../hci/include \
                   $(LOCAL_PATH)/../include \
                   $(LOCAL_PATH)/../stack/include \
                   $(LOCAL_PATH)/../stack/btm \
                   $(LOCAL_PATH)/../udrv/include \
                   $(LOCAL_PATH)/../vnd/include \
                   $(LOCAL_PATH)/../utils/include \
                   $(bluetooth_C_INCLUDES)

# BTA static library for target
# ========================================================
include $(CLEAR_VARS)
LOCAL_CPP_EXTENSION := .cc

LOCAL_SRC_FILES:= \
    ./ag/bta_ag_act.cc \
    ./ag/bta_ag_api.cc \
    ./ag/bta_ag_at.cc \
    ./ag/bta_ag_cfg.cc \
    ./ag/bta_ag_ci.cc \
    ./ag/bta_ag_cmd.cc \
    ./ag/bta_ag_main.cc \
    ./ag/bta_ag_rfc.cc \
    ./ag/bta_ag_sco.cc \
    ./ag/bta_ag_sdp.cc \
    ./ar/bta_ar.cc \
    ./av/bta_av_aact.cc \
    ./av/bta_av_act.cc \
    ./av/bta_av_api.cc \
    ./av/bta_av_cfg.cc \
    ./av/bta_av_ci.cc \
    ./av/bta_av_main.cc \
    ./av/bta_av_ssm.cc \
    ./closure/bta_closure.cc \
    ./dm/bta_dm_act.cc \
    ./dm/bta_dm_api.cc \
    ./dm/bta_dm_cfg.cc \
    ./dm/bta_dm_ci.cc \
    ./dm/bta_dm_main.cc \
    ./dm/bta_dm_pm.cc \
    ./dm/bta_dm_sco.cc \
    ./gatt/bta_gattc_act.cc \
    ./gatt/bta_gattc_api.cc \
    ./gatt/bta_gattc_cache.cc \
    ./gatt/bta_gattc_main.cc \
    ./gatt/bta_gattc_utils.cc \
    ./gatt/bta_gatts_act.cc \
    ./gatt/bta_gatts_api.cc \
    ./gatt/bta_gatts_main.cc \
    ./gatt/bta_gatts_utils.cc \
    ./hf_client/bta_hf_client_act.cc \
    ./hf_client/bta_hf_client_api.cc \
    ./hf_client/bta_hf_client_at.cc \
    ./hf_client/bta_hf_client_main.cc \
    ./hf_client/bta_hf_client_rfc.cc \
    ./hf_client/bta_hf_client_sco.cc \
    ./hf_client/bta_hf_client_sdp.cc \
    ./hh/bta_hh_act.cc \
    ./hh/bta_hh_api.cc \
    ./hh/bta_hh_cfg.cc \
    ./hh/bta_hh_le.cc \
    ./hh/bta_hh_main.cc \
    ./hh/bta_hh_utils.cc \
    ./hd/bta_hd_act.cc \
    ./hd/bta_hd_api.cc \
    ./hd/bta_hd_main.cc \
    ./hl/bta_hl_act.cc \
    ./hl/bta_hl_api.cc \
    ./hl/bta_hl_ci.cc \
    ./hl/bta_hl_main.cc \
    ./hl/bta_hl_sdp.cc \
    ./hl/bta_hl_utils.cc \
    ./jv/bta_jv_act.cc \
    ./jv/bta_jv_api.cc \
    ./jv/bta_jv_cfg.cc \
    ./jv/bta_jv_main.cc \
    ./mce/bta_mce_act.cc \
    ./mce/bta_mce_api.cc \
    ./mce/bta_mce_cfg.cc \
    ./mce/bta_mce_main.cc \
    ./pan/bta_pan_act.cc \
    ./pan/bta_pan_api.cc \
    ./pan/bta_pan_ci.cc \
    ./pan/bta_pan_main.cc \
    ./sdp/bta_sdp.cc \
    ./sdp/bta_sdp_act.cc \
    ./sdp/bta_sdp_api.cc \
    ./sdp/bta_sdp_cfg.cc \
    ./sys/bta_sys_conn.cc \
    ./sys/bta_sys_main.cc \
    ./sys/utl.cc

LOCAL_MODULE := libbt-bta
LOCAL_MODULE_CLASS := STATIC_LIBRARIES
LOCAL_MODULE_TAGS := optional
LOCAL_SHARED_LIBRARIES := libcutils libc libchrome

LOCAL_C_INCLUDES := $(btaCommonIncludes)

LOCAL_CFLAGS += $(bluetooth_CFLAGS) -DBUILDCFG
LOCAL_CONLYFLAGS += $(bluetooth_CONLYFLAGS)
LOCAL_CPPFLAGS += $(bluetooth_CPPFLAGS)

include $(BUILD_STATIC_LIBRARY)

# bta unit tests for target
# ========================================================
include $(CLEAR_VARS)

LOCAL_CPP_EXTENSION := .cc

LOCAL_C_INCLUDES := $(btaCommonIncludes)
LOCAL_SRC_FILES := $(btaTestSrc)
LOCAL_SHARED_LIBRARIES := libcutils libc libchrome libhardware liblog libprotobuf-cpp-lite
LOCAL_STATIC_LIBRARIES := libbtcore libbt-bta libosi libbt-protos
LOCAL_MODULE_TAGS := optional
LOCAL_MODULE := net_test_bta

LOCAL_CFLAGS += $(bluetooth_CFLAGS) -DBUILDCFG
LOCAL_CONLYFLAGS += $(bluetooth_CONLYFLAGS)
LOCAL_CPPFLAGS += $(bluetooth_CPPFLAGS)

include $(BUILD_NATIVE_TEST)
