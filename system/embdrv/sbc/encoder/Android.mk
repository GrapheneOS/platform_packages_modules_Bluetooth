LOCAL_PATH:= $(call my-dir)

# Bluetooth SBC encoder static library for target
# ========================================================
include $(CLEAR_VARS)

LOCAL_CPP_EXTENSION := .cc

# SBC encoder
LOCAL_SRC_FILES := \
        ./srce/sbc_analysis.c \
        ./srce/sbc_dct.c \
        ./srce/sbc_dct_coeffs.c \
        ./srce/sbc_enc_bit_alloc_mono.c \
        ./srce/sbc_enc_bit_alloc_ste.c \
        ./srce/sbc_enc_coeffs.c \
        ./srce/sbc_encoder.c \
        ./srce/sbc_packing.c

LOCAL_C_INCLUDES := $(LOCAL_PATH)/include \
        $(LOCAL_PATH)/../../../include \
        $(LOCAL_PATH)/../../../stack/include \
        $(LOCAL_PATH)/srce \
        $(bluetooth_C_INCLUDES)

LOCAL_MODULE := libbt-sbc-encoder
# LOCAL_MODULE_TAGS := optional
LOCAL_MODULE_CLASS := STATIC_LIBRARIES

LOCAL_CFLAGS += $(bluetooth_CFLAGS)
LOCAL_CONLYFLAGS += $(bluetooth_CONLYFLAGS)
LOCAL_CPPFLAGS += $(bluetooth_CPPFLAGS)

include $(BUILD_STATIC_LIBRARY)
