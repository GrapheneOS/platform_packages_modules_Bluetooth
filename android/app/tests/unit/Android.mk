LOCAL_PATH:= $(call my-dir)
include $(CLEAR_VARS)

# We only want this apk build for tests.
LOCAL_MODULE_TAGS := tests
LOCAL_CERTIFICATE := platform

LOCAL_JAVA_LIBRARIES := \
    javax.obex \
    android.test.runner \
    telephony-common \
    libprotobuf-java-micro \
    android.test.base \
    android.test.mock

LOCAL_STATIC_JAVA_LIBRARIES :=  \
    com.android.emailcommon \
    androidx.test.rules \
    mockito-target \
    androidx.test.espresso.intents \
    gson-prebuilt-jar \
    bt-androidx-room-migration-nodeps \
    bt-androidx-room-runtime-nodeps \
    bt-androidx-room-testing-nodeps

LOCAL_ASSET_DIR += \
    $(LOCAL_PATH)/src/com/android/bluetooth/btservice/storage/schemas

# Include all test java files.
LOCAL_SRC_FILES := $(call all-java-files-under, src)

LOCAL_PACKAGE_NAME := BluetoothInstrumentationTests
LOCAL_PRIVATE_PLATFORM_APIS := true

LOCAL_COMPATIBILITY_SUITE := device-tests

LOCAL_INSTRUMENTATION_FOR := Bluetooth

include $(BUILD_PACKAGE)

include $(CLEAR_VARS)

ROOM_LIBS_PATH := ../../lib/room

LOCAL_PREBUILT_STATIC_JAVA_LIBRARIES := \
    bt-androidx-room-migration-nodeps:$(ROOM_LIBS_PATH)/room-migration-2.0.0-beta01.jar \
    bt-androidx-room-runtime-nodeps:$(ROOM_LIBS_PATH)/room-runtime-2.0.0-alpha1.aar \
    bt-androidx-room-testing-nodeps:$(ROOM_LIBS_PATH)/room-testing-2.0.0-alpha1.aar

include $(BUILD_MULTI_PREBUILT)
