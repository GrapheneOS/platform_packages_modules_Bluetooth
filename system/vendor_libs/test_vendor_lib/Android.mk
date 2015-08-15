LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)

BT_DIR := $(TOP_DIR)packages/modules/Bluetooth/system

LOCAL_SRC_FILES := \
    src/bt_vendor.cc \
    src/command_packet.cc \
    src/dual_mode_controller.cc \
    src/event_packet.cc \
    src/hci_transport.cc \
    src/packet.cc \
    src/packet_stream.cc \
    src/test_channel_transport.cc \
    src/vendor_manager.cc \

LOCAL_C_INCLUDES := \
    $(LOCAL_PATH)/include \
    $(BT_DIR) \
    $(BT_DIR)/hci/include \
    $(BT_DIR)/osi/include \
    $(BT_DIR)/stack/include \

LOCAL_SHARED_LIBRARIES := \
    liblog \
    libchrome

LOCAL_CPP_EXTENSION := .cc
LOCAL_MODULE := test-vendor
LOCAL_MODULE_TAGS := optional
LOCAL_MODULE_CLASS := SHARED_LIBRARIES

include $(BUILD_SHARED_LIBRARY)
