LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)

LOCAL_CFLAGS += $(bdroid_CFLAGS)

LOCAL_SRC_FILES := \
    src/btsnoop.c \
    src/btsnoop_net.c \
    src/hci_hal.c \
    src/hci_hal_h4.c \
    src/hci_hal_mct.c \
    src/hci_inject.c \
    src/hci_layer.c \
    src/low_power_manager.c \
    src/packet_fragmenter.c \
    src/vendor.c

LOCAL_CFLAGS := -Wno-unused-parameter

ifeq ($(BLUETOOTH_HCI_USE_MCT),true)
LOCAL_CFLAGS += -DHCI_USE_MCT
endif

LOCAL_CFLAGS += -std=c99

LOCAL_C_INCLUDES += \
    $(LOCAL_PATH)/include \
    $(LOCAL_PATH)/../include \
    $(LOCAL_PATH)/../gki/common \
    $(LOCAL_PATH)/../gki/ulinux \
    $(LOCAL_PATH)/../osi/include \
    $(LOCAL_PATH)/../stack/include \
    $(LOCAL_PATH)/../utils/include \
    $(bdroid_C_INCLUDES)

LOCAL_MODULE := libbt-hci
LOCAL_MODULE_TAGS := optional
LOCAL_MODULE_CLASS := STATIC_LIBRARIES

include $(BUILD_STATIC_LIBRARY)

#####################################################
include $(CLEAR_VARS)

LOCAL_C_INCLUDES := \
    $(LOCAL_PATH)/include \
    $(LOCAL_PATH)/../include \
    $(LOCAL_PATH)/../gki/common \
    $(LOCAL_PATH)/../gki/ulinux \
    $(LOCAL_PATH)/../osi/include \
    $(LOCAL_PATH)/../osi/test \
    $(LOCAL_PATH)/../stack/include \
    $(LOCAL_PATH)/../utils/include \
    $(bdroid_C_INCLUDES)

LOCAL_SRC_FILES := \
    ../osi/test/AllocationTestHarness.cpp \
    ../osi/test/AlarmTestHarness.cpp \
    ./test/hci_hal_h4_test.cpp \
    ./test/hci_hal_mct_test.cpp \
    ./test/hci_layer_test.cpp \
    ./test/low_power_manager_test.cpp \
    ./test/packet_fragmenter_test.cpp


LOCAL_CFLAGS := -Wall -Werror
LOCAL_MODULE := libbt-hcitests
LOCAL_MODULE_TAGS := tests
LOCAL_SHARED_LIBRARIES := liblog libdl
LOCAL_STATIC_LIBRARIES := libbt-hci libosi

include $(BUILD_NATIVE_TEST)
