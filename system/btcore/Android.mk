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
btcoreCommonSrc := \
    src/bdaddr.c \
    src/counter.c \
    src/device_class.c \
    src/hal_util.c \
    src/module.c \
    src/osi_module.c \
    src/property.c \
    src/uuid.c

btcoreCommonTestSrc := \
    ./test/bdaddr_test.cpp \
    ./test/counter_test.cpp \
    ./test/device_class_test.cpp \
    ./test/property_test.cpp \
    ./test/uuid_test.cpp \
    ../osi/test/AllocationTestHarness.cpp

btcoreCommonIncludes := \
    $(LOCAL_PATH)/include \
    $(LOCAL_PATH)/../osi/include \
    $(LOCAL_PATH)/..

# libbtcore static library for target
# ========================================================
include $(CLEAR_VARS)
LOCAL_CLANG_CFLAGS += -Wno-error=typedef-redefinition
LOCAL_C_INCLUDES := $(btcoreCommonIncludes)
LOCAL_SRC_FILES := $(btcoreCommonSrc)
LOCAL_CFLAGS := -std=c99 $(bdroid_CFLAGS)
LOCAL_MODULE := libbtcore
LOCAL_MODULE_TAGS := optional
LOCAL_SHARED_LIBRARIES := libc liblog
LOCAL_MODULE_CLASS := STATIC_LIBRARIES
include $(BUILD_STATIC_LIBRARY)

# libbtcore static library for host
# ========================================================
ifeq ($(HOST_OS),linux)
include $(CLEAR_VARS)
LOCAL_CLANG_CFLAGS += -Wno-error=typedef-redefinition
LOCAL_C_INCLUDES := $(btcoreCommonIncludes)
LOCAL_SRC_FILES := $(btcoreCommonSrc)
# TODO(armansito): Setting _GNU_SOURCE isn't very platform-independent but
# should be compatible for a Linux host OS. We should figure out what to do for
# a non-Linux host OS.
LOCAL_CFLAGS := -std=c99 $(bdroid_CFLAGS) -D_GNU_SOURCE
LOCAL_MODULE := libbtcore-host
LOCAL_MODULE_TAGS := optional
LOCAL_SHARED_LIBRARIES := liblog
LOCAL_MODULE_CLASS := STATIC_LIBRARIES
include $(BUILD_HOST_STATIC_LIBRARY)
endif

# Note: It's good to get the tests compiled both for the host and the target so
# we get to test with both Bionic libc and glibc

# libbtcore unit tests for target
# ========================================================
include $(CLEAR_VARS)
LOCAL_CLANG_CFLAGS += -Wno-error=typedef-redefinition
LOCAL_C_INCLUDES := $(btcoreCommonIncludes)
LOCAL_SRC_FILES := $(btcoreCommonTestSrc)
LOCAL_CFLAGS := -Wall -Werror -Werror=unused-variable
LOCAL_MODULE := net_test_btcore
LOCAL_MODULE_TAGS := tests
LOCAL_SHARED_LIBRARIES := liblog libpower
LOCAL_STATIC_LIBRARIES := libbtcore libosi
include $(BUILD_NATIVE_TEST)

# libbtcore unit tests for host
# ========================================================
ifeq ($(HOST_OS),linux)
include $(CLEAR_VARS)
LOCAL_CLANG_CFLAGS += -Wno-error=typedef-redefinition
LOCAL_C_INCLUDES := $(btcoreCommonIncludes)
LOCAL_SRC_FILES := $(btcoreCommonTestSrc)
LOCAL_CFLAGS := -Wall -Werror -Werror=unused-variable
LOCAL_MODULE := net_test_btcore
LOCAL_MODULE_TAGS := tests
LOCAL_SHARED_LIBRARIES := liblog libpower
LOCAL_STATIC_LIBRARIES := libbtcore-host libosi-host
include $(BUILD_HOST_NATIVE_TEST)
endif
