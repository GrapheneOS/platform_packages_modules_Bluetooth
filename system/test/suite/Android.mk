#
#  Copyright (C) 2015 Google, Inc.
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

LOCAL_PATH := $(call my-dir)

# Bluetooth test suite for target
# ========================================================
include $(CLEAR_VARS)
LOCAL_CPP_EXTENSION := .cc
LOCAL_MODULE_TAGS := optional
LOCAL_MODULE := net_test_bluetooth

# These tests use the bluetoothtbd HAL wrappers in order to easily interact
# with the interface using C++
# TODO: Make the bluetoothtbd HAL a static library
bluetoothHalSrc := \
  ../../service/hal/bluetooth_gatt_interface.cc \
  ../../service/hal/bluetooth_interface.cc \
  ../../service/logging_helpers.cc

LOCAL_C_INCLUDES += \
    $(LOCAL_PATH)/../../

LOCAL_SRC_FILES := \
    adapter/adapter_unittest.cc \
    adapter/bluetooth_test.cc \
    gatt/gatt_test.cc \
    gatt/gatt_unittest.cc \
    $(bluetoothHalSrc)

LOCAL_SHARED_LIBRARIES += \
    liblog \
    libhardware \
    libhardware_legacy \
    libcutils \
    libchrome

LOCAL_STATIC_LIBRARIES += \
  libbtcore \
  libosi

LOCAL_CFLAGS += $(bluetooth_CFLAGS)
LOCAL_CONLYFLAGS += $(bluetooth_CONLYFLAGS)
LOCAL_CPPFLAGS += $(bluetooth_CPPFLAGS)

include $(BUILD_NATIVE_TEST)
