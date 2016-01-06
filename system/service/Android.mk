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

# Source variables
# ========================================================
btserviceCommonSrc := \
	common/bluetooth/adapter_state.cpp \
	common/bluetooth/advertise_data.cpp \
	common/bluetooth/advertise_settings.cpp \
	common/bluetooth/gatt_identifier.cpp \
	common/bluetooth/scan_filter.cpp \
	common/bluetooth/scan_result.cpp \
	common/bluetooth/scan_settings.cpp \
	common/bluetooth/util/address_helper.cpp \
	common/bluetooth/util/atomic_string.cpp \
	common/bluetooth/uuid.cpp

btserviceCommonBinderSrc := \
	common/bluetooth/binder/IBluetooth.cpp \
	common/bluetooth/binder/IBluetoothCallback.cpp \
	common/bluetooth/binder/IBluetoothGattClient.cpp \
	common/bluetooth/binder/IBluetoothGattClientCallback.cpp \
	common/bluetooth/binder/IBluetoothGattServer.cpp \
	common/bluetooth/binder/IBluetoothGattServerCallback.cpp \
	common/bluetooth/binder/IBluetoothLowEnergy.cpp \
	common/bluetooth/binder/IBluetoothLowEnergyCallback.cpp \
	common/bluetooth/binder/parcel_helpers.cpp

btserviceDaemonSrc := \
	adapter.cpp \
	daemon.cpp \
	gatt_client.cpp \
	gatt_server.cpp \
	gatt_server_old.cpp \
	hal/gatt_helpers.cpp \
	hal/bluetooth_gatt_interface.cpp \
	hal/bluetooth_interface.cpp \
	ipc/ipc_handler.cpp \
	ipc/ipc_manager.cpp \
	logging_helpers.cpp \
	low_energy_client.cpp \
	settings.cpp

btserviceLinuxSrc := \
	ipc/ipc_handler_linux.cpp \
	ipc/linux_ipc_host.cpp

btserviceBinderDaemonImplSrc := \
	ipc/binder/bluetooth_binder_server.cpp \
	ipc/binder/bluetooth_gatt_client_binder_server.cpp \
	ipc/binder/bluetooth_gatt_server_binder_server.cpp \
	ipc/binder/bluetooth_low_energy_binder_server.cpp \
	ipc/binder/interface_with_instances_base.cpp \
	ipc/binder/ipc_handler_binder.cpp \

btserviceBinderDaemonSrc := \
	$(btserviceCommonBinderSrc) \
	$(btserviceBinderDaemonImplSrc)

btserviceCommonIncludes := \
	$(LOCAL_PATH)/../ \
	$(LOCAL_PATH)/common

# Main unit test sources. These get built for host and target.
# ========================================================
btserviceBaseTestSrc := \
	hal/fake_bluetooth_gatt_interface.cpp \
	hal/fake_bluetooth_interface.cpp \
	test/adapter_unittest.cpp \
	test/advertise_data_unittest.cpp \
	test/fake_hal_util.cpp \
	test/gatt_client_unittest.cpp \
	test/gatt_identifier_unittest.cpp \
	test/gatt_server_unittest.cpp \
	test/low_energy_client_unittest.cpp \
	test/settings_unittest.cpp \
	test/util_unittest.cpp \
	test/uuid_unittest.cpp

# Some standard CFLAGS used in all targets.
btservice_common_flags :=
# libchrome has unused parameters in their .h files. b/26228533
btservice_common_flags += -Wno-unused-parameter

# Native system service for target
# ========================================================
include $(CLEAR_VARS)
LOCAL_SRC_FILES := \
	$(btserviceBinderDaemonSrc) \
	$(btserviceCommonSrc) \
	$(btserviceLinuxSrc) \
	$(btserviceDaemonSrc) \
	main.cpp
LOCAL_C_INCLUDES += $(btserviceCommonIncludes)
LOCAL_CFLAGS += $(btservice_common_flags)
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
LOCAL_INIT_RC := bluetoothtbd.rc
include $(BUILD_EXECUTABLE)

# Native system service unittests for host
# ========================================================
include $(CLEAR_VARS)
LOCAL_SRC_FILES := \
	$(btserviceBaseTestSrc) \
	$(btserviceCommonSrc) \
	$(btserviceDaemonSrc) \
	test/main.cpp \
	test/stub_ipc_handler_binder.cpp
ifeq ($(HOST_OS),linux)
LOCAL_SRC_FILES += \
	$(btserviceLinuxSrc) \
	test/ipc_linux_unittest.cpp
LOCAL_LDLIBS += -lrt
else
LOCAL_SRC_FILES += \
	test/stub_ipc_handler_linux.cpp
endif
LOCAL_C_INCLUDES += $(btserviceCommonIncludes)
LOCAL_CFLAGS += $(btservice_common_flags)
LOCAL_MODULE_TAGS := debug tests
LOCAL_MODULE := bluetoothtbd-host_test
LOCAL_SHARED_LIBRARIES += libchrome
LOCAL_STATIC_LIBRARIES += libgmock_host libgtest_host liblog
include $(BUILD_HOST_NATIVE_TEST)

# Native system service unittests for target. This
# includes Binder related tests that can only be run on
# target.
# ========================================================
include $(CLEAR_VARS)
LOCAL_SRC_FILES := \
	$(btserviceBaseTestSrc) \
	$(btserviceBinderDaemonSrc) \
	$(btserviceCommonSrc) \
	$(btserviceDaemonSrc) \
	test/main.cpp \
	test/parcel_helpers_unittest.cpp
LOCAL_C_INCLUDES += $(btserviceCommonIncludes)
LOCAL_CFLAGS += $(btservice_common_flags)
LOCAL_MODULE_TAGS := debug tests
LOCAL_MODULE := bluetoothtbd_test
LOCAL_SHARED_LIBRARIES += \
	libbinder \
	libchrome \
	libutils
LOCAL_STATIC_LIBRARIES += libgmock libgtest liblog
include $(BUILD_NATIVE_TEST)

# Client library for interacting with Bluetooth daemon
# ========================================================
include $(CLEAR_VARS)
LOCAL_SRC_FILES := \
	$(btserviceCommonSrc) \
	$(btserviceCommonBinderSrc)
LOCAL_C_INCLUDES += $(btserviceCommonIncludes)
LOCAL_EXPORT_C_INCLUDE_DIRS := $(LOCAL_PATH)/common
LOCAL_CFLAGS += $(btservice_common_flags)
LOCAL_MODULE := libbluetooth-client
LOCAL_SHARED_LIBRARIES += libbinder libchrome libutils
include $(BUILD_STATIC_LIBRARY)

# Native system service CLI for target
# ========================================================
include $(CLEAR_VARS)
LOCAL_SRC_FILES := client/main.cpp
LOCAL_CFLAGS += $(btservice_common_flags)
LOCAL_MODULE_TAGS := optional
LOCAL_MODULE := bluetooth-cli
LOCAL_STATIC_LIBRARIES += libbluetooth-client
LOCAL_SHARED_LIBRARIES += \
	libbinder \
	libchrome \
	libutils
include $(BUILD_EXECUTABLE)

# Heart Rate GATT service example
# ========================================================
# TODO(armansito): Move this into a new makefile under examples/ once we build a
# client static library that the examples can depend on.
include $(CLEAR_VARS)
LOCAL_SRC_FILES := \
	example/heart_rate/heart_rate_server.cpp \
	example/heart_rate/server_main.cpp
LOCAL_C_INCLUDES += $(LOCAL_PATH)/../
LOCAL_CFLAGS += $(btservice_common_flags)
LOCAL_MODULE_TAGS := optional
LOCAL_MODULE := bt-example-hr-server
LOCAL_STATIC_LIBRARIES += libbluetooth-client
LOCAL_SHARED_LIBRARIES += \
	libbinder \
	libchrome \
	libutils
include $(BUILD_EXECUTABLE)
