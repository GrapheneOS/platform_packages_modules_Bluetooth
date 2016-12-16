LOCAL_PATH := $(call my-dir)

# HCI static library for target
# ========================================================
include $(CLEAR_VARS)
LOCAL_CPP_EXTENSION := .cc

LOCAL_SRC_FILES := \
    src/btsnoop.cc \
    src/btsnoop_mem.cc \
    src/btsnoop_net.cc \
    src/buffer_allocator.cc \
    src/hci_audio.cc \
    src/hci_hal.cc \
    src/hci_hal_h4.cc \
    src/hci_hal_mct.cc \
    src/hci_inject.cc \
    src/hci_layer.cc \
    src/hci_packet_factory.cc \
    src/hci_packet_parser.cc \
    src/low_power_manager.cc \
    src/packet_fragmenter.cc \
    src/vendor.cc \
    ../../EventLogTags.logtags

LOCAL_C_INCLUDES := \
    $(LOCAL_PATH)/include \
    $(LOCAL_PATH)/.. \
    $(LOCAL_PATH)/../include \
    $(LOCAL_PATH)/../btcore/include \
    $(LOCAL_PATH)/../stack/include \
    $(LOCAL_PATH)/../utils/include \
    $(LOCAL_PATH)/../bta/include \
    $(bluetooth_C_INCLUDES)

LOCAL_MODULE := libbt-hci
LOCAL_SHARED_LIBRARIES := libchrome

ifeq ($(BLUETOOTH_HCI_USE_MCT),true)
    LOCAL_CFLAGS += -DHCI_USE_MCT
endif
LOCAL_CFLAGS += $(bluetooth_CFLAGS)
LOCAL_CONLYFLAGS += $(bluetooth_CONLYFLAGS)
LOCAL_CPPFLAGS += $(bluetooth_CPPFLAGS)

include $(BUILD_STATIC_LIBRARY)

# HCI unit tests for target
# ========================================================
ifeq (,$(strip $(SANITIZE_TARGET)))
include $(CLEAR_VARS)
LOCAL_CPP_EXTENSION := .cc

LOCAL_C_INCLUDES := \
    $(LOCAL_PATH)/include \
    $(LOCAL_PATH)/.. \
    $(LOCAL_PATH)/../include \
    $(LOCAL_PATH)/../btcore/include \
    $(LOCAL_PATH)/../osi/test \
    $(LOCAL_PATH)/../stack/include \
    $(LOCAL_PATH)/../utils/include \
    $(bluetooth_C_INCLUDES)

LOCAL_SRC_FILES := \
    ../osi/test/AllocationTestHarness.cc \
    ../osi/test/AlarmTestHarness.cc \
    ./test/hci_hal_h4_test.cc \
    ./test/hci_hal_mct_test.cc \
    ./test/hci_layer_test.cc \
    ./test/low_power_manager_test.cc \
    ./test/packet_fragmenter_test.cc

LOCAL_MODULE := net_test_hci
LOCAL_MODULE_TAGS := tests
LOCAL_SHARED_LIBRARIES := liblog libdl libprotobuf-cpp-lite libchrome
LOCAL_STATIC_LIBRARIES := libbt-hci libosi libcutils libbtcore libbt-protos

LOCAL_CFLAGS += $(bluetooth_CFLAGS)
LOCAL_CONLYFLAGS += $(bluetooth_CONLYFLAGS)
LOCAL_CPPFLAGS += $(bluetooth_CPPFLAGS)

include $(BUILD_NATIVE_TEST)
endif # SANITIZE_TARGET
