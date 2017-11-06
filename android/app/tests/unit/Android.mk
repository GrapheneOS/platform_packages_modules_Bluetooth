LOCAL_PATH:= $(call my-dir)
include $(CLEAR_VARS)

# We only want this apk build for tests.
LOCAL_MODULE_TAGS := tests
LOCAL_CERTIFICATE := platform

LOCAL_JAVA_LIBRARIES := \
    javax.obex \
    android.test.runner \
    telephony-common \
    libprotobuf-java-micro

LOCAL_STATIC_JAVA_LIBRARIES :=  \
    com.android.emailcommon \
    android-support-test \
    mockito-target \
    legacy-android-test \
    espresso-intents

# Include all test java files.
LOCAL_SRC_FILES := $(call all-java-files-under, src)

LOCAL_PACKAGE_NAME := BluetoothInstrumentationTests

LOCAL_COMPATIBILITY_SUITE := device-tests

LOCAL_INSTRUMENTATION_FOR := Bluetooth

include $(BUILD_PACKAGE)
