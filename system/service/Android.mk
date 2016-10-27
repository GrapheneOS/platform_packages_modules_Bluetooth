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

#
# Workaround for libchrome and -DNDEBUG usage.
#
# Test whether the original HOST_GLOBAL_CFLAGS and
# TARGET_GLOBAL_CFLAGS contain -DNDEBUG .
# This is needed as a workaround to make sure that
# libchrome and local files calling logging::InitLogging()
# are consistent with the usage of -DNDEBUG .
# ========================================================
ifneq (,$(findstring NDEBUG,$(HOST_GLOBAL_CFLAGS)))
  btservice_orig_HOST_NDEBUG := -DBT_LIBCHROME_NDEBUG
else
  btservice_orig_HOST_NDEBUG :=
endif
ifneq (,$(findstring NDEBUG,$(TARGET_GLOBAL_CFLAGS)))
  btservice_orig_TARGET_NDEBUG := -DBT_LIBCHROME_NDEBUG
else
  btservice_orig_TARGET_NDEBUG :=
endif

# Source variables
# ========================================================
btserviceCommonSrc := \
	common/bluetooth/adapter_state.cc \
	common/bluetooth/advertise_data.cc \
	common/bluetooth/advertise_settings.cc \
	common/bluetooth/descriptor.cc \
	common/bluetooth/characteristic.cc \
	common/bluetooth/scan_filter.cc \
	common/bluetooth/scan_result.cc \
	common/bluetooth/scan_settings.cc \
	common/bluetooth/service.cc \
	common/bluetooth/util/address_helper.cc \
	common/bluetooth/util/atomic_string.cc \
	common/bluetooth/uuid.cc

btserviceCommonBinderSrc := \
	common/android/bluetooth/IBluetooth.aidl \
	common/android/bluetooth/IBluetoothCallback.aidl \
	common/android/bluetooth/IBluetoothGattClient.aidl \
	common/android/bluetooth/IBluetoothGattClientCallback.aidl \
	common/android/bluetooth/IBluetoothGattServer.aidl \
	common/android/bluetooth/IBluetoothGattServerCallback.aidl \
	common/android/bluetooth/IBluetoothLeAdvertiser.aidl \
	common/android/bluetooth/IBluetoothLeAdvertiserCallback.aidl \
	common/android/bluetooth/IBluetoothLeScanner.aidl \
	common/android/bluetooth/IBluetoothLeScannerCallback.aidl \
	common/android/bluetooth/IBluetoothLowEnergy.aidl \
	common/android/bluetooth/IBluetoothLowEnergyCallback.aidl \
	common/android/bluetooth/advertise_data.cc \
	common/android/bluetooth/advertise_settings.cc \
	common/android/bluetooth/bluetooth_gatt_characteristic.cc \
	common/android/bluetooth/bluetooth_gatt_descriptor.cc \
	common/android/bluetooth/bluetooth_gatt_included_service.cc \
	common/android/bluetooth/bluetooth_gatt_service.cc \
	common/android/bluetooth/scan_filter.cc \
	common/android/bluetooth/scan_result.cc \
	common/android/bluetooth/scan_settings.cc \
	common/android/bluetooth/uuid.cc \

btserviceCommonAidlInclude := \
	packages/modules/Bluetooth/system/service/common \
	frameworks/native/aidl/binder

btserviceDaemonSrc := \
	adapter.cc \
	daemon.cc \
	gatt_client.cc \
	gatt_server.cc \
	gatt_server_old.cc \
	hal/bluetooth_gatt_interface.cc \
	hal/bluetooth_interface.cc \
	ipc/ipc_handler.cc \
	ipc/ipc_manager.cc \
	logging_helpers.cc \
	low_energy_advertiser.cc \
	low_energy_scanner.cc \
	low_energy_client.cc \
	settings.cc

btserviceLinuxSrc := \
	ipc/ipc_handler_linux.cc \
	ipc/linux_ipc_host.cc

btserviceBinderDaemonImplSrc := \
	ipc/binder/bluetooth_binder_server.cc \
	ipc/binder/bluetooth_gatt_client_binder_server.cc \
	ipc/binder/bluetooth_gatt_server_binder_server.cc \
	ipc/binder/bluetooth_le_advertiser_binder_server.cc \
	ipc/binder/bluetooth_le_scanner_binder_server.cc \
	ipc/binder/bluetooth_low_energy_binder_server.cc \
	ipc/binder/interface_with_instances_base.cc \
	ipc/binder/ipc_handler_binder.cc \

btserviceBinderDaemonSrc := \
	$(btserviceCommonBinderSrc) \
	$(btserviceBinderDaemonImplSrc)

btserviceCommonIncludes := \
	$(LOCAL_PATH)/../ \
	$(LOCAL_PATH)/common

# Main unit test sources. These get built for host and target.
# ========================================================
btserviceBaseTestSrc := \
	hal/fake_bluetooth_gatt_interface.cc \
	hal/fake_bluetooth_interface.cc \
	test/adapter_unittest.cc \
	test/advertise_data_unittest.cc \
	test/fake_hal_util.cc \
	test/gatt_client_unittest.cc \
	test/gatt_server_unittest.cc \
	test/low_energy_advertiser_unittest.cc \
	test/low_energy_client_unittest.cc \
	test/low_energy_scanner_unittest.cc \
	test/settings_unittest.cc \
	test/util_unittest.cc \
	test/uuid_unittest.cc

# Native system service for target
# ========================================================
include $(CLEAR_VARS)
LOCAL_CPP_EXTENSION := .cc
LOCAL_SRC_FILES := \
	$(btserviceCommonSrc) \
	$(btserviceBinderDaemonSrc) \
	$(btserviceLinuxSrc) \
	$(btserviceDaemonSrc) \
	main.cc
LOCAL_AIDL_INCLUDES = $(btserviceCommonAidlInclude)
LOCAL_C_INCLUDES := $(btserviceCommonIncludes)
LOCAL_MODULE_TAGS := optional
LOCAL_MODULE := bluetoothtbd
LOCAL_REQUIRED_MODULES := bluetooth.default
LOCAL_STATIC_LIBRARIES := libbtcore
LOCAL_SHARED_LIBRARIES := \
	libbinder \
	libchrome \
	libcutils \
	libhardware \
	liblog \
	libutils
LOCAL_INIT_RC := bluetoothtbd.rc

LOCAL_CFLAGS += $(bluetooth_CFLAGS) $(btservice_orig_TARGET_NDEBUG)
LOCAL_CONLYFLAGS += $(bluetooth_CONLYFLAGS)
LOCAL_CPPFLAGS += $(bluetooth_CPPFLAGS)

include $(BUILD_EXECUTABLE)

# Native system service unit tests for host
# ========================================================
include $(CLEAR_VARS)
LOCAL_CPP_EXTENSION := .cc
LOCAL_SRC_FILES := \
	$(btserviceBaseTestSrc) \
	$(btserviceCommonSrc) \
	$(btserviceDaemonSrc) \
	test/main.cc \
	test/stub_ipc_handler_binder.cc
ifeq ($(HOST_OS),linux)
LOCAL_SRC_FILES += \
	$(btserviceLinuxSrc) \
	test/ipc_linux_unittest.cc
LOCAL_LDLIBS += -lrt
else
LOCAL_SRC_FILES += \
	test/stub_ipc_handler_linux.cc
endif
LOCAL_C_INCLUDES := $(btserviceCommonIncludes)
LOCAL_MODULE_TAGS := debug tests
LOCAL_MODULE := bluetoothtbd-host_test
LOCAL_SHARED_LIBRARIES := libchrome
LOCAL_STATIC_LIBRARIES := libgmock_host libgtest_host liblog

LOCAL_CFLAGS += $(bluetooth_CFLAGS) $(btservice_orig_HOST_NDEBUG)
LOCAL_CONLYFLAGS += $(bluetooth_CONLYFLAGS)
LOCAL_CPPFLAGS += $(bluetooth_CPPFLAGS)

include $(BUILD_HOST_NATIVE_TEST)

# Native system service unit tests for target.
# This includes Binder related tests that can only be run
# on target.
# ========================================================
include $(CLEAR_VARS)
LOCAL_CPP_EXTENSION := .cc
LOCAL_SRC_FILES := \
	$(btserviceBaseTestSrc) \
	$(btserviceCommonSrc) \
	$(btserviceBinderDaemonSrc) \
	$(btserviceDaemonSrc) \
	test/main.cc \
	test/parcelable_unittest.cc \
	test/ParcelableTest.aidl
LOCAL_AIDL_INCLUDES := $(btserviceCommonAidlInclude)
LOCAL_AIDL_INCLUDES += ./
LOCAL_C_INCLUDES := $(btserviceCommonIncludes)
LOCAL_MODULE_TAGS := debug tests
LOCAL_MODULE := bluetoothtbd_test
LOCAL_SHARED_LIBRARIES := \
	libbinder \
	libchrome \
	libutils
LOCAL_STATIC_LIBRARIES := libgmock libgtest liblog

LOCAL_CFLAGS += $(bluetooth_CFLAGS) $(btservice_orig_TARGET_NDEBUG)
LOCAL_CONLYFLAGS += $(bluetooth_CONLYFLAGS)
LOCAL_CPPFLAGS += $(bluetooth_CPPFLAGS)

include $(BUILD_NATIVE_TEST)

# Client library for interacting with Bluetooth daemon
# This is a static library for target.
# ========================================================
include $(CLEAR_VARS)
LOCAL_CPP_EXTENSION := .cc
LOCAL_SRC_FILES := \
	$(btserviceCommonSrc) \
	$(btserviceCommonBinderSrc)
LOCAL_AIDL_INCLUDES := $(btserviceCommonAidlInclude)
LOCAL_C_INCLUDES := $(btserviceCommonIncludes)
LOCAL_EXPORT_C_INCLUDE_DIRS := $(LOCAL_PATH)/common
LOCAL_MODULE := libbluetooth-client
LOCAL_SHARED_LIBRARIES := libbinder libchrome libutils

LOCAL_CFLAGS += $(bluetooth_CFLAGS) $(btservice_orig_TARGET_NDEBUG)
LOCAL_CONLYFLAGS += $(bluetooth_CONLYFLAGS)
LOCAL_CPPFLAGS += $(bluetooth_CPPFLAGS)

include $(BUILD_STATIC_LIBRARY)

# Native system service CLI for target
# ========================================================
include $(CLEAR_VARS)
LOCAL_CPP_EXTENSION := .cc
LOCAL_SRC_FILES := client/main.cc
LOCAL_MODULE_TAGS := optional
LOCAL_MODULE := bluetooth-cli
LOCAL_STATIC_LIBRARIES := libbluetooth-client
LOCAL_SHARED_LIBRARIES := \
	libbinder \
	libchrome \
	libutils

LOCAL_CFLAGS += $(bluetooth_CFLAGS) $(btservice_orig_TARGET_NDEBUG)
LOCAL_CONLYFLAGS += $(bluetooth_CONLYFLAGS)
LOCAL_CPPFLAGS += $(bluetooth_CPPFLAGS)

include $(BUILD_EXECUTABLE)

# Heart Rate GATT service example for target
# ========================================================
# TODO(armansito): Move this into a new makefile under examples/ once we build
# a client static library that the examples can depend on.
include $(CLEAR_VARS)
LOCAL_CPP_EXTENSION := .cc
LOCAL_SRC_FILES := \
	example/heart_rate/heart_rate_server.cc \
	example/heart_rate/server_main.cc
LOCAL_C_INCLUDES := $(LOCAL_PATH)/../
LOCAL_MODULE_TAGS := optional
LOCAL_MODULE := bt-example-hr-server
LOCAL_STATIC_LIBRARIES := libbluetooth-client
LOCAL_SHARED_LIBRARIES := \
	libbinder \
	libchrome \
	libutils

LOCAL_CFLAGS += $(bluetooth_CFLAGS) $(btservice_orig_TARGET_NDEBUG)
LOCAL_CONLYFLAGS += $(bluetooth_CONLYFLAGS)
LOCAL_CPPFLAGS += $(bluetooth_CPPFLAGS)

include $(BUILD_EXECUTABLE)
