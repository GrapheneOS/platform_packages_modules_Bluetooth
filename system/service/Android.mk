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

ifeq ($(HOST_OS),linux)
include $(CLEAR_VARS)
LOCAL_SRC_FILES := \
	settings.cpp \
	test/settings_unittest.cpp \
	test/uuid_unittest.cpp \
	uuid.cpp
LOCAL_C_INCLUDES += \
	$(LOCAL_PATH)/../
LOCAL_CFLAGS += -std=c++11
LOCAL_MODULE_TAGS := tests
LOCAL_MODULE := bt_service_unittests
LOCAL_SHARED_LIBRARIES += libchrome-host
include $(BUILD_HOST_NATIVE_TEST)
endif

include $(CLEAR_VARS)

LOCAL_SRC_FILES := \
	a2dp_source.cpp \
	core_stack.cpp \
	daemon.cpp \
	gatt_server.cpp \
	ipc/ipc_handler.cpp \
	ipc/ipc_handler_unix.cpp \
	ipc/ipc_manager.cpp \
	ipc/unix_ipc_host.cpp \
	logging_helpers.cpp \
	main.cpp \
	settings.cpp \
	uuid.cpp

LOCAL_C_INCLUDES += \
        $(LOCAL_PATH)/../

LOCAL_CFLAGS += -std=c++11
LOCAL_MODULE_TAGS := optional
LOCAL_MODULE := bluetoothtbd
LOCAL_REQUIRED_MODULES = bluetooth.default
LOCAL_STATIC_LIBRARIES += libbtcore
LOCAL_SHARED_LIBRARIES += \
	libchrome \
	libcutils \
	libhardware \
	liblog

include $(BUILD_EXECUTABLE)
