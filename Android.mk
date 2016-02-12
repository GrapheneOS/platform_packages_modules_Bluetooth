LOCAL_PATH := $(call my-dir)

# Setup Bluetooth local make variables for handling configuration
ifneq ($(BOARD_BLUETOOTH_BDROID_BUILDCFG_INCLUDE_DIR),)
  bluetooth_C_INCLUDES := $(BOARD_BLUETOOTH_BDROID_BUILDCFG_INCLUDE_DIR)
  bluetooth_CFLAGS += -DHAS_BDROID_BUILDCFG
else
  bluetooth_C_INCLUDES :=
  bluetooth_CFLAGS += -DHAS_NO_BDROID_BUILDCFG
endif

ifneq ($(BOARD_BLUETOOTH_BDROID_HCILP_INCLUDED),)
  bluetooth_CFLAGS += -DHCILP_INCLUDED=$(BOARD_BLUETOOTH_BDROID_HCILP_INCLUDED)
endif

ifneq ($(TARGET_BUILD_VARIANT),user)
bluetooth_CFLAGS += -DBLUEDROID_DEBUG
endif

bluetooth_CFLAGS += -DEXPORT_SYMBOL="__attribute__((visibility(\"default\")))"

#
# Common C/C++ compiler flags.
#
# - gnu-variable-sized-type-not-at-end is needed for a variable-size header in
#   a struct.
# - constant-logical-operand is needed for code in l2c_utils.c that looks
#   intentional.
#
bluetooth_CFLAGS += \
  -fvisibility=hidden \
  -Wall \
  -Wextra \
  -Werror \
  -Wno-typedef-redefinition \
  -Wno-gnu-variable-sized-type-not-at-end \
  -Wno-unused-parameter \
  -Wno-maybe-uninitialized \
  -Wno-uninitialized \
  -Wno-missing-field-initializers \
  -Wno-unused-variable \
  -Wno-non-literal-null-conversion \
  -Wno-sign-compare \
  -Wno-incompatible-pointer-types \
  -Wno-unused-function \
  -Wno-missing-braces \
  -Wno-enum-conversion \
  -Wno-logical-not-parentheses \
  -Wno-parentheses \
  -Wno-constant-logical-operand \
  -Wno-format \
  -UNDEBUG \
  -DLOG_NDEBUG=1

bluetooth_CONLYFLAGS += -std=c99
bluetooth_CPPFLAGS :=

include $(call all-subdir-makefiles)

# Cleanup our locals
bluetooth_C_INCLUDES :=
bluetooth_CFLAGS :=
bluetooth_CONLYFLAGS :=
bluetooth_CPPFLAGS :=
