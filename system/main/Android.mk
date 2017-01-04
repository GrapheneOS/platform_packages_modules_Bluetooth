LOCAL_PATH:= $(call my-dir)

# Bluetooth main HW module / shared library for target
# ========================================================
include $(CLEAR_VARS)

LOCAL_CPP_EXTENSION := .cc

# platform specific
LOCAL_SRC_FILES := \
    bte_conf.cc \
    bte_init.cc \
    bte_init_cpp_logging.cc \
    bte_logmsg.cc \
    bte_main.cc \
    stack_config.cc

LOCAL_SRC_FILES += \
    ../udrv/ulinux/uipc.cc

LOCAL_C_INCLUDES := . \
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
    $(LOCAL_PATH)/../udrv/include \
    $(LOCAL_PATH)/../btif/include \
    $(LOCAL_PATH)/../btif/co \
    $(LOCAL_PATH)/../hci/include\
    $(LOCAL_PATH)/../vnd/include \
    $(LOCAL_PATH)/../embdrv/sbc/encoder/include \
    $(LOCAL_PATH)/../embdrv/sbc/decoder/include \
    $(LOCAL_PATH)/../audio_a2dp_hw \
    $(LOCAL_PATH)/../utils/include \
    $(bluetooth_C_INCLUDES) \
    external/tinyxml2 \
    external/zlib

LOCAL_SHARED_LIBRARIES := \
    libcutils \
    libdl \
    liblog \
    libz \
    libpower \
    libprotobuf-cpp-lite \
    libaudioclient \
    libutils \
    libchrome \
    libtinyxml2

LOCAL_STATIC_LIBRARIES := \
    libbt-sbc-decoder \
    libbt-sbc-encoder

LOCAL_WHOLE_STATIC_LIBRARIES := \
    libbt-bta \
    libbtdevice \
    libbtif \
    libbt-hci \
    libbt-protos \
    libbt-stack \
    libbt-utils \
    libbtcore \
    libosi

LOCAL_MODULE := bluetooth.default
LOCAL_MODULE_RELATIVE_PATH := hw
LOCAL_MODULE_TAGS := optional
LOCAL_MODULE_CLASS := SHARED_LIBRARIES

#
# Shared library link options.
# References to global symbols and functions should bind to the library
# itself. This is to avoid issues with some of the unit/system tests
# that might link statically with some of the code in the library, and
# also dlopen(3) the shared library.
#
LOCAL_LDLIBS := -Wl,-Bsymbolic,-Bsymbolic-functions

LOCAL_REQUIRED_MODULES := \
    bt_did.conf \
    bt_stack.conf \
    libbt-hci \
    libbt-vendor

LOCAL_CFLAGS += $(bluetooth_CFLAGS) -DBUILDCFG
LOCAL_CONLYFLAGS += $(bluetooth_CONLYFLAGS)
LOCAL_CPPFLAGS += $(bluetooth_CPPFLAGS)

include $(BUILD_SHARED_LIBRARY)
