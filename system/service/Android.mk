#
#  Copyright (C) 2015 Google
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

LOCAL_PATH:= $(call my-dir)

BASE_SRC := \
	base/base64.cpp \
	base/string_split.cpp \
	base/string_number_conversions.cpp \
	modp_b64/modp_b64.cpp

CORE_SRC := \
	a2dp_source.cpp \
	logging_helpers.cpp \
	core_stack.cpp \
	uuid.cpp \
	gatt_server.cpp

include $(CLEAR_VARS)
LOCAL_SRC_FILES := uuid_test.cpp uuid.cpp
LOCAL_CFLAGS += -std=c++11
LOCAL_MODULE_TAGS := tests
LOCAL_MODULE := uuid_test_bd
include $(BUILD_HOST_NATIVE_TEST)

include $(CLEAR_VARS)

LOCAL_SRC_FILES := \
    $(BASE_SRC) \
    $(CORE_SRC) \
    host.cpp \
    main.cpp

LOCAL_C_INCLUDES += \
        $(LOCAL_PATH)/../

LOCAL_CFLAGS += -std=c++11
LOCAL_MODULE_TAGS := optional
LOCAL_MODULE := bthost
LOCAL_REQUIRED_MODULES = bluetooth.default
LOCAL_SHARED_LIBRARIES += \
    libhardware \
    libcutils \
    liblog

include $(BUILD_EXECUTABLE)
