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

# Common variables
# ========================================================
btserviceCommonSrc := \
	a2dp_source.cpp \
	core_stack.cpp \
	daemon.cpp \
	gatt_server.cpp \
	ipc/ipc_handler.cpp \
	ipc/ipc_handler_unix.cpp \
	ipc/ipc_manager.cpp \
	ipc/unix_ipc_host.cpp \
	logging_helpers.cpp \
	settings.cpp \
	uuid.cpp

btserviceBinderSrc := \
	ipc/binder/IBluetooth.cpp \
	ipc/binder/bluetooth_binder_server.cpp \
	ipc/binder/ipc_handler_binder.cpp

btserviceCommonIncludes := $(LOCAL_PATH)/../

# Native system service for target
# ========================================================
include $(CLEAR_VARS)
LOCAL_SRC_FILES := \
	$(btserviceBinderSrc) \
	$(btserviceCommonSrc) \
	main.cpp
LOCAL_C_INCLUDES += $(btserviceCommonIncludes)
LOCAL_CFLAGS += -std=c++11
LOCAL_MODULE_TAGS := optional
LOCAL_MODULE := bluetoothtbd
LOCAL_REQUIRED_MODULES = bluetooth.default
LOCAL_STATIC_LIBRARIES += libbtcore
LOCAL_SHARED_LIBRARIES += \
	libbinder \
	libchrome \
	libcutils \
	libhardware \
	liblog \
	libutils
include $(BUILD_EXECUTABLE)

# Native system service unittests for host
# ========================================================
ifeq ($(HOST_OS),linux)
include $(CLEAR_VARS)
LOCAL_SRC_FILES := \
	$(btserviceCommonSrc) \
	test/fake_hal_util.cpp \
	test/ipc_unix_unittest.cpp \
	test/settings_unittest.cpp \
	test/stub_ipc_handler_binder.cpp \
	test/uuid_unittest.cpp
LOCAL_C_INCLUDES += $(btserviceCommonIncludes)
LOCAL_CFLAGS += -std=c++11
LOCAL_LDLIBS += -lrt
LOCAL_MODULE_TAGS := tests
LOCAL_MODULE := bt_service_unittests
LOCAL_SHARED_LIBRARIES += libchrome-host
LOCAL_STATIC_LIBRARIES += libgmock_host liblog
include $(BUILD_HOST_NATIVE_TEST)
endif
