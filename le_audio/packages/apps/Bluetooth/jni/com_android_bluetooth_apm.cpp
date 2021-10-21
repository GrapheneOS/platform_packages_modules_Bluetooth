/*
 * Copyright (c) 2020, The Linux Foundation. All rights reserved.
 * 
 **************************************************************************/

#define LOG_TAG "BluetoothAPM_Jni"

#define LOG_NDEBUG 0

#include "android_runtime/AndroidRuntime.h"
#include "com_android_bluetooth.h"
#include "hardware/bt_apm.h"
#include "utils/Log.h"

#include <string.h>
#include <shared_mutex>

namespace android {
static jmethodID method_onGetActiveprofileCallback;

static const bt_apm_interface_t* sBluetoothApmInterface = nullptr;
static std::shared_timed_mutex interface_mutex;

static jobject mCallbacksObj = nullptr;
static std::shared_timed_mutex callbacks_mutex;


static int btapm_active_profile_callback(const RawAddress& bd_addr, uint16_t audio_type)
{
  ALOGI("%s", __func__);
  std::shared_lock<std::shared_timed_mutex> lock(callbacks_mutex);
  CallbackEnv sCallbackEnv(__func__);
  if (!sCallbackEnv.valid() || mCallbacksObj == nullptr) return -1;

  ScopedLocalRef<jbyteArray> addr(
        sCallbackEnv.get(), sCallbackEnv->NewByteArray(sizeof(RawAddress)));
  if (!addr.get()) {
  ALOGE("%s: Fail to new jbyteArray bd addr", __func__);
  return -1;
  }

  sCallbackEnv->SetByteArrayRegion(
          addr.get(), 0, sizeof(RawAddress),
          reinterpret_cast<const jbyte*>(bd_addr.address));
  return sCallbackEnv->CallIntMethod(mCallbacksObj, method_onGetActiveprofileCallback,
                                                            addr.get(), (jint)audio_type);
}


static btapm_initiator_callbacks_t sBluetoothApmCallbacks = {
        sizeof(sBluetoothApmCallbacks),
        btapm_active_profile_callback
};

static void classInitNative(JNIEnv* env, jclass clazz) {

  ALOGI("%s: succeeds", __func__);
  method_onGetActiveprofileCallback =
     env->GetMethodID(clazz, "getActiveProfile", "([BI)I");
}

static bool initNative(JNIEnv* env, jobject object) {
  std::unique_lock<std::shared_timed_mutex> interface_lock(interface_mutex);
  std::unique_lock<std::shared_timed_mutex> callbacks_lock(callbacks_mutex);

  const bt_interface_t* btInf = getBluetoothInterface();
  if (btInf == nullptr) {
    ALOGE("%s: Bluetooth module is not loaded", __func__);
    return JNI_FALSE;
  }

  if (sBluetoothApmInterface != nullptr) {
    ALOGW("%s: Cleaning up APM Interface before initializing...", __func__);
    sBluetoothApmInterface->cleanup();
    sBluetoothApmInterface = nullptr;
  }

  if (mCallbacksObj != nullptr) {
    ALOGW("%s: Cleaning up APM callback object", __func__);
    env->DeleteGlobalRef(mCallbacksObj);
    mCallbacksObj = nullptr;
  }

  if ((mCallbacksObj = env->NewGlobalRef(object)) == nullptr) {
    ALOGE("%s: Failed to allocate Global Ref for APM Callbacks", __func__);
    return JNI_FALSE;
  }

  sBluetoothApmInterface =
      (bt_apm_interface_t*)btInf->get_profile_interface(
          BT_APM_MODULE_ID);
  if (sBluetoothApmInterface == nullptr) {
    ALOGE("%s: Failed to get Bluetooth APM Interface", __func__);
    return JNI_FALSE;
  }
  bt_status_t status = sBluetoothApmInterface->init(&sBluetoothApmCallbacks);
  if (status != BT_STATUS_SUCCESS) {
    ALOGE("%s: Failed to initialize Bluetooth APM, status: %d", __func__,
          status);
    sBluetoothApmInterface = nullptr;
    return JNI_FALSE;
  }
  return JNI_TRUE;
}

static void cleanupNative(JNIEnv* env, jobject object) {
  std::unique_lock<std::shared_timed_mutex> interface_lock(interface_mutex);
  std::unique_lock<std::shared_timed_mutex> callbacks_lock(callbacks_mutex);

  const bt_interface_t* btInf = getBluetoothInterface();
  if (btInf == nullptr) {
    ALOGE("%s: Bluetooth module is not loaded", __func__);
    return;
  }

  if (sBluetoothApmInterface != nullptr) {
    sBluetoothApmInterface->cleanup();
    sBluetoothApmInterface = nullptr;
  }

  if (mCallbacksObj != nullptr) {
    env->DeleteGlobalRef(mCallbacksObj);
    mCallbacksObj = nullptr;
  }
}

static jboolean activeDeviceUpdateNative(JNIEnv* env, jobject object,
                            jbyteArray address, jint profile, jint audio_type) {
  ALOGI("%s: sBluetoothApmInterface: %p", __func__, sBluetoothApmInterface);
  std::shared_lock<std::shared_timed_mutex> lock(interface_mutex);
  if (!sBluetoothApmInterface) {
    ALOGE("%s: Failed to get the Bluetooth APM Interface", __func__);
    return JNI_FALSE;
  }

  jbyte* addr = env->GetByteArrayElements(address, nullptr);

  RawAddress bd_addr = RawAddress::kEmpty;
  if (addr) {
    bd_addr.FromOctets(reinterpret_cast<const uint8_t*>(addr));
  }
  bt_status_t status = sBluetoothApmInterface->active_device_change(bd_addr, profile, audio_type);
  if (status != BT_STATUS_SUCCESS) {
    ALOGE("%s: Failed APM active_device_change, status: %d", __func__, status);
  }
  env->ReleaseByteArrayElements(address, addr, 0);
  return (status == BT_STATUS_SUCCESS) ? JNI_TRUE : JNI_FALSE;
}

static jboolean setContentControlNative(JNIEnv* env, jobject object,
                                      jint content_control_id, jint profile) {
  ALOGI("%s: sBluetoothApmInterface: %p", __func__, sBluetoothApmInterface);
  std::shared_lock<std::shared_timed_mutex> lock(interface_mutex);
  if (!sBluetoothApmInterface) {
    ALOGE("%s: Failed to get the Bluetooth APM Interface", __func__);
    return JNI_FALSE;
  }

  bt_status_t status = sBluetoothApmInterface->set_content_control_id(content_control_id, profile);
  if (status != BT_STATUS_SUCCESS) {
    ALOGE("%s: Failed APM content control update, status: %d", __func__, status);
  }

  return (status == BT_STATUS_SUCCESS) ? JNI_TRUE : JNI_FALSE;
}

static JNINativeMethod sMethods[] = {
    {"classInitNative", "()V", (void*)classInitNative},
    {"initNative", "()V", (void*)initNative},
    {"cleanupNative", "()V", (void*)cleanupNative},
    {"activeDeviceUpdateNative", "([BII)Z", (void*)activeDeviceUpdateNative},
    {"setContentControlNative", "(II)Z", (void*)setContentControlNative},
};

int register_com_android_bluetooth_apm(JNIEnv* env) {
  return jniRegisterNativeMethods(
      env, "com/android/bluetooth/apm/ApmNativeInterface", sMethods,
      NELEM(sMethods));
}
}
