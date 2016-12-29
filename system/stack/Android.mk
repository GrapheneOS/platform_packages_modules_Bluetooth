LOCAL_PATH:= $(call my-dir)

# Bluetooth stack static library for target
# ========================================================
include $(CLEAR_VARS)
LOCAL_CPP_EXTENSION := .cc
LOCAL_C_INCLUDES := \
                   $(LOCAL_PATH)/include \
                   $(LOCAL_PATH)/avct \
                   $(LOCAL_PATH)/btm \
                   $(LOCAL_PATH)/avrc \
                   $(LOCAL_PATH)/l2cap \
                   $(LOCAL_PATH)/avdt \
                   $(LOCAL_PATH)/gatt \
                   $(LOCAL_PATH)/gap \
                   $(LOCAL_PATH)/pan \
                   $(LOCAL_PATH)/bnep \
                   $(LOCAL_PATH)/hid \
                   $(LOCAL_PATH)/sdp \
                   $(LOCAL_PATH)/smp \
                   $(LOCAL_PATH)/srvc \
                   $(LOCAL_PATH)/../btcore/include \
                   $(LOCAL_PATH)/../vnd/include \
                   $(LOCAL_PATH)/../vnd/ble \
                   $(LOCAL_PATH)/../btif/include \
                   $(LOCAL_PATH)/../hci/include \
                   $(LOCAL_PATH)/../include \
                   $(LOCAL_PATH)/../udrv/include \
                   $(LOCAL_PATH)/../bta/include \
                   $(LOCAL_PATH)/../bta/sys \
                   $(LOCAL_PATH)/../utils/include \
                   $(LOCAL_PATH)/../ \
                   $(bluetooth_C_INCLUDES)

LOCAL_SRC_FILES := \
    ./a2dp/a2dp_api.cc \
    ./a2dp/a2dp_sbc.cc \
    ./a2dp/a2dp_sbc_encoder.cc \
    ./a2dp/a2dp_sbc_up_sample.cc \
    ./a2dp/a2dp_vendor.cc \
    ./avct/avct_api.cc \
    ./avct/avct_bcb_act.cc \
    ./avct/avct_ccb.cc \
    ./avct/avct_l2c.cc \
    ./avct/avct_l2c_br.cc \
    ./avct/avct_lcb.cc \
    ./avct/avct_lcb_act.cc \
    ./avdt/avdt_ad.cc \
    ./avdt/avdt_api.cc \
    ./avdt/avdt_ccb.cc \
    ./avdt/avdt_ccb_act.cc \
    ./avdt/avdt_l2c.cc \
    ./avdt/avdt_msg.cc \
    ./avdt/avdt_scb.cc \
    ./avdt/avdt_scb_act.cc \
    ./avrc/avrc_api.cc \
    ./avrc/avrc_bld_ct.cc \
    ./avrc/avrc_bld_tg.cc \
    ./avrc/avrc_opt.cc \
    ./avrc/avrc_pars_ct.cc \
    ./avrc/avrc_pars_tg.cc \
    ./avrc/avrc_sdp.cc \
    ./avrc/avrc_utils.cc \
    ./bnep/bnep_api.cc \
    ./bnep/bnep_main.cc \
    ./bnep/bnep_utils.cc \
    ./btm/ble_advertiser_hci_interface.cc \
    ./btm/btm_acl.cc \
    ./btm/btm_ble.cc \
    ./btm/btm_ble_addr.cc \
    ./btm/btm_ble_adv_filter.cc \
    ./btm/btm_ble_batchscan.cc \
    ./btm/btm_ble_bgconn.cc \
    ./btm/btm_ble_cont_energy.cc \
    ./btm/btm_ble_gap.cc \
    ./btm/btm_ble_multi_adv.cc \
    ./btm/btm_ble_privacy.cc \
    ./btm/btm_dev.cc \
    ./btm/btm_devctl.cc \
    ./btm/btm_inq.cc \
    ./btm/btm_main.cc \
    ./btm/btm_pm.cc \
    ./btm/btm_sco.cc \
    ./btm/btm_sec.cc \
    ./btu/btu_hcif.cc \
    ./btu/btu_init.cc \
    ./btu/btu_task.cc \
    ./gap/gap_api.cc \
    ./gap/gap_ble.cc \
    ./gap/gap_conn.cc \
    ./gap/gap_utils.cc \
    ./gatt/att_protocol.cc \
    ./gatt/gatt_api.cc \
    ./gatt/gatt_attr.cc \
    ./gatt/gatt_auth.cc \
    ./gatt/gatt_cl.cc \
    ./gatt/gatt_db.cc \
    ./gatt/gatt_main.cc \
    ./gatt/gatt_sr.cc \
    ./gatt/gatt_utils.cc \
    ./hcic/hciblecmds.cc \
    ./hcic/hcicmds.cc \
    ./hid/hidh_api.cc \
    ./hid/hidh_conn.cc \
    ./hid/hidd_api.cc \
    ./hid/hidd_conn.cc \
    ./l2cap/l2c_api.cc \
    ./l2cap/l2c_ble.cc \
    ./l2cap/l2c_csm.cc \
    ./l2cap/l2c_fcr.cc \
    ./l2cap/l2c_link.cc \
    ./l2cap/l2c_main.cc \
    ./l2cap/l2c_ucd.cc \
    ./l2cap/l2c_utils.cc \
    ./l2cap/l2cap_client.cc \
    ./mcap/mca_api.cc \
    ./mcap/mca_cact.cc \
    ./mcap/mca_csm.cc \
    ./mcap/mca_dact.cc \
    ./mcap/mca_dsm.cc \
    ./mcap/mca_l2c.cc \
    ./mcap/mca_main.cc \
    ./pan/pan_api.cc \
    ./pan/pan_main.cc \
    ./pan/pan_utils.cc \
    ./rfcomm/port_api.cc \
    ./rfcomm/port_rfc.cc \
    ./rfcomm/port_utils.cc \
    ./rfcomm/rfc_l2cap_if.cc \
    ./rfcomm/rfc_mx_fsm.cc \
    ./rfcomm/rfc_port_fsm.cc \
    ./rfcomm/rfc_port_if.cc \
    ./rfcomm/rfc_ts_frames.cc \
    ./rfcomm/rfc_utils.cc \
    ./sdp/sdp_api.cc \
    ./sdp/sdp_db.cc \
    ./sdp/sdp_discovery.cc \
    ./sdp/sdp_main.cc \
    ./sdp/sdp_server.cc \
    ./sdp/sdp_utils.cc \
    ./smp/aes.cc \
    ./smp/p_256_curvepara.cc \
    ./smp/p_256_ecc_pp.cc \
    ./smp/p_256_multprecision.cc \
    ./smp/smp_act.cc \
    ./smp/smp_api.cc \
    ./smp/smp_br_main.cc \
    ./smp/smp_cmac.cc \
    ./smp/smp_keys.cc \
    ./smp/smp_l2c.cc \
    ./smp/smp_main.cc \
    ./smp/smp_utils.cc \
    ./srvc/srvc_battery.cc \
    ./srvc/srvc_dis.cc \
    ./srvc/srvc_eng.cc

LOCAL_MODULE := libbt-stack
LOCAL_STATIC_LIBRARIES := libbt-hci
LOCAL_SHARED_LIBRARIES := libcutils libchrome

LOCAL_CFLAGS += $(bluetooth_CFLAGS)
LOCAL_CONLYFLAGS += $(bluetooth_CONLYFLAGS)
LOCAL_CPPFLAGS += $(bluetooth_CPPFLAGS)

include $(BUILD_STATIC_LIBRARY)

# Bluetooth stack unit tests for target
# ========================================================
include $(CLEAR_VARS)

LOCAL_CPP_EXTENSION := .cc

LOCAL_C_INCLUDES := \
                   $(LOCAL_PATH)/include \
                   $(LOCAL_PATH)/../include \
                   $(LOCAL_PATH)/../ \
                   $(bluetooth_C_INCLUDES)

LOCAL_SRC_FILES := test/stack_a2dp_test.cc
LOCAL_SHARED_LIBRARIES :=
LOCAL_STATIC_LIBRARIES := libbt-stack liblog
LOCAL_MODULE_TAGS := tests
LOCAL_MODULE := net_test_stack

LOCAL_CFLAGS += $(bluetooth_CFLAGS)
LOCAL_CONLYFLAGS += $(bluetooth_CONLYFLAGS)
LOCAL_CPPFLAGS += $(bluetooth_CPPFLAGS)

include $(BUILD_NATIVE_TEST)

# Bluetooth smp unit tests for target
# ========================================================
include $(CLEAR_VARS)

LOCAL_CPP_EXTENSION := .cc

LOCAL_C_INCLUDES := \
                   $(LOCAL_PATH)/include \
                   $(LOCAL_PATH)/btm \
                   $(LOCAL_PATH)/l2cap \
                   $(LOCAL_PATH)/smp \
                   $(LOCAL_PATH)/../btcore/include \
                   $(LOCAL_PATH)/../hci/include \
                   $(LOCAL_PATH)/../include \
                   $(LOCAL_PATH)/../utils/include \
                   $(LOCAL_PATH)/../ \
                   $(bluetooth_C_INCLUDES)

LOCAL_SRC_FILES := smp/smp_keys.cc \
                    smp/aes.cc \
                    smp/smp_api.cc \
                    smp/smp_main.cc \
                    smp/smp_utils.cc \
                    test/stack_smp_test.cc
LOCAL_SHARED_LIBRARIES := libcutils libchrome
LOCAL_STATIC_LIBRARIES := liblog libgtest libgmock libosi
LOCAL_MODULE_TAGS := tests
LOCAL_MODULE := net_test_stack_smp

LOCAL_CFLAGS += $(bluetooth_CFLAGS)
LOCAL_CONLYFLAGS += $(bluetooth_CONLYFLAGS)
LOCAL_CPPFLAGS += $(bluetooth_CPPFLAGS)

include $(BUILD_NATIVE_TEST)

# Bluetooth stack multi-advertising unit tests for target
# ========================================================
include $(CLEAR_VARS)

LOCAL_CPP_EXTENSION := .cc

LOCAL_C_INCLUDES := \
                   $(LOCAL_PATH)/include \
                   $(LOCAL_PATH)/../include \
                   $(LOCAL_PATH)/../ \
                   $(LOCAL_PATH)/btm \
                   $(LOCAL_PATH)/../btcore/include \
                   $(LOCAL_PATH)/../hci/include \
                   $(LOCAL_PATH)/../include \
                   $(LOCAL_PATH)/../utils/include \
                   $(LOCAL_PATH)/../ \
                   $(bluetooth_C_INCLUDES)

LOCAL_SRC_FILES := btm/btm_ble_multi_adv.cc \
                   test/ble_advertiser_test.cc
LOCAL_SHARED_LIBRARIES := libcutils libchrome
LOCAL_STATIC_LIBRARIES := liblog libgmock libgtest
LOCAL_MODULE_TAGS := tests
LOCAL_MODULE := net_test_stack_multi_adv

LOCAL_CFLAGS += $(bluetooth_CFLAGS)
LOCAL_CONLYFLAGS += $(bluetooth_CONLYFLAGS)
LOCAL_CPPFLAGS += $(bluetooth_CPPFLAGS)

include $(BUILD_NATIVE_TEST)
