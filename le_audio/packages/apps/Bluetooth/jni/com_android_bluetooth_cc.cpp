/*
 *Copyright (c) 2020-2021, The Linux Foundation. All rights reserved.

 * Copyright 2012 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#define LOG_TAG "BluetoothCCServiceJni"

#define LOG_NDEBUG 0

#include <base/bind.h>
#include <base/callback.h>
#include <map>
#include <mutex>
#include <shared_mutex>
#include <vector>

#include "android_runtime/AndroidRuntime.h"
#include "base/logging.h"
#include "com_android_bluetooth.h"
#include "hardware/bluetooth.h"
#include "hardware/bluetooth_callcontrol_callbacks.h"
#include "hardware/bluetooth_callcontrol_interface.h"

using bluetooth::call_control::CallControllerCallbacks;
using bluetooth::call_control::CallControllerInterface;
using bluetooth::Uuid;
static CallControllerInterface* sCallControllerInterface = nullptr;

namespace android {
static jmethodID method_CallControlInitializedCallback;
static jmethodID method_OnConnectionStateChanged;
static jmethodID method_CallControlPointChangedRequest;
static std::shared_timed_mutex interface_mutex;
static jobject mCallbacksObj = nullptr;
static std::shared_timed_mutex callbacks_mutex;

class CallControllerCallbacksImpl : public CallControllerCallbacks {
   public:
  ~CallControllerCallbacksImpl() = default;
  void CallControlInitializedCallback(uint8_t state) override {
    LOG(INFO) << __func__;
    std::shared_lock<std::shared_timed_mutex> lock(callbacks_mutex);
    CallbackEnv sCallbackEnv(__func__);
    if (!sCallbackEnv.valid() || mCallbacksObj == nullptr) return;
    sCallbackEnv->CallVoidMethod(mCallbacksObj, method_CallControlInitializedCallback,
                                 (jint)state);
  }
  void ConnectionStateCallback(uint8_t state, const RawAddress& bd_addr) override {
    LOG(INFO) << __func__;
    std::shared_lock<std::shared_timed_mutex> lock(callbacks_mutex);
    CallbackEnv sCallbackEnv(__func__);
    if (!sCallbackEnv.valid() || mCallbacksObj == nullptr) return;
    ScopedLocalRef<jbyteArray> addr(
        sCallbackEnv.get(), sCallbackEnv->NewByteArray(sizeof(RawAddress)));
    if (!addr.get()) {
      LOG(ERROR) << "Failed to new jbyteArray bd addr for connection state";
      return;
    }
    sCallbackEnv->SetByteArrayRegion(addr.get(), 0, sizeof(RawAddress),
                                     (jbyte*)&bd_addr);
    sCallbackEnv->CallVoidMethod(mCallbacksObj, method_OnConnectionStateChanged,
                                 (jint)state, addr.get());
  }

  void CallControlCallback(uint8_t op, std::vector<int32_t> p_indices, int count, std::vector<uint8_t> uri_data, const RawAddress& bd_addr) override {
    LOG(INFO) << __func__;
    std::shared_lock<std::shared_timed_mutex> lock(callbacks_mutex);
    CallbackEnv sCallbackEnv(__func__);
    if (!sCallbackEnv.valid() || mCallbacksObj == nullptr) return;

    ScopedLocalRef<jbyteArray> addr(
        sCallbackEnv.get(), sCallbackEnv->NewByteArray(sizeof(RawAddress)));
    if (!addr.get()) {
      LOG(ERROR) << "Failed to new jbyteArray bd addr for connection state";
      return;
    }
    ScopedLocalRef<jintArray> indices(sCallbackEnv.get(), (jintArray)sCallbackEnv->NewIntArray(count));
    ScopedLocalRef<jbyteArray> originate_uri(
    sCallbackEnv.get(), sCallbackEnv->NewByteArray(uri_data.size()));
    if (!originate_uri.get()) {
        ALOGE("Error while allocation byte array for uri data in %s", __func__);
        return;
    }
    sCallbackEnv->SetByteArrayRegion(originate_uri.get(), 0, uri_data.size(),
           (jbyte*)uri_data.data());

    sCallbackEnv->SetByteArrayRegion(addr.get(), 0, sizeof(RawAddress),
                                     (jbyte*)&bd_addr);
    sCallbackEnv->SetIntArrayRegion(indices.get(), 0, count,(jint*)p_indices.data());
    sCallbackEnv->CallVoidMethod(mCallbacksObj, method_CallControlPointChangedRequest,
                                  (jint)op, indices.get(), (jint)count, originate_uri.get(), addr.get());
  }
};

static CallControllerCallbacksImpl sCallControllerCallbacks;

static void classInitNative(JNIEnv* env, jclass clazz) {
  method_CallControlInitializedCallback =
      env->GetMethodID(clazz, "callControlInitializedCallback", "(I)V");
  method_OnConnectionStateChanged =
      env->GetMethodID(clazz, "onConnectionStateChanged", "(I[B)V");
  method_CallControlPointChangedRequest =
      env->GetMethodID(clazz, "callControlPointChangedRequest", "(I[II[B[B)V");

  LOG(INFO) << __func__ << " : succeeds";
}

static void initializeNative(JNIEnv* env, jobject object, jstring uuid,
                      jint max_ccs_clients, jboolean inband_ringing_enabled) {
  std::unique_lock<std::shared_timed_mutex> interface_lock(interface_mutex);
  std::unique_lock<std::shared_timed_mutex> callbacks_lock(callbacks_mutex);

  const bt_interface_t* btInf = getBluetoothInterface();
  if (!btInf) {
    ALOGE("%s: Bluetooth module is not loaded", __func__);
    jniThrowIOException(env, EINVAL);
    return;
  }

  if (sCallControllerInterface) {
    ALOGI("%s: Cleaning up Bluetooth CallControl Interface before initializing",
          __func__);
    sCallControllerInterface->Cleanup();
    sCallControllerInterface = nullptr;
  }

  if (mCallbacksObj) {
    ALOGI("%s: Cleaning up Bluetooth CallControl callback object", __func__);
    env->DeleteGlobalRef(mCallbacksObj);
    mCallbacksObj = nullptr;
  }

  const char* _uuid = env->GetStringUTFChars(uuid, nullptr);

  sCallControllerInterface =
      (CallControllerInterface*)btInf->get_profile_interface(
          BT_PROFILE_CC_ID);
  if (!sCallControllerInterface) {
    ALOGW("%s: Failed to get Bluetooth CallControl Interface", __func__);
    jniThrowIOException(env, EINVAL);
    return;
  }
  bt_status_t status =
      sCallControllerInterface->Init(&sCallControllerCallbacks,
                                   bluetooth::Uuid::FromString(_uuid), max_ccs_clients, inband_ringing_enabled);
  if (status != BT_STATUS_SUCCESS) {
    ALOGE("%s: Failed to initialize LE audio Call control Interface, status: %d",
          __func__, status);
    sCallControllerInterface = nullptr;
    return;
  }

  env->ReleaseStringUTFChars(uuid, _uuid);
  mCallbacksObj = env->NewGlobalRef(object);
}

static void cleanupNative(JNIEnv* env, jobject object) {
  std::unique_lock<std::shared_timed_mutex> interface_lock(interface_mutex);
  std::unique_lock<std::shared_timed_mutex> callbacks_lock(callbacks_mutex);

  const bt_interface_t* btInf = getBluetoothInterface();
  if (btInf == nullptr) {
    LOG(ERROR) << "Bluetooth module is not loaded";
    return;
  }

  if (sCallControllerInterface != nullptr) {
    sCallControllerInterface->Cleanup();
    sCallControllerInterface = nullptr;
  }

  if (mCallbacksObj != nullptr) {
    env->DeleteGlobalRef(mCallbacksObj);
    mCallbacksObj = nullptr;
  }
}

static jboolean updateBearerNameNative(JNIEnv* env, jobject object,
                                   jstring operator_str) {
  std::shared_lock<std::shared_timed_mutex> lock(interface_mutex);
  if (!sCallControllerInterface) {
    ALOGW("%s: sCallControllerInterface is null", __func__);
    return JNI_FALSE;
  }
  const char* operator_name = env->GetStringUTFChars(operator_str, nullptr);
  bt_status_t status =
      sCallControllerInterface->UpdateBearerName((uint8_t*)operator_name);
  if (status != BT_STATUS_SUCCESS) {
    ALOGE("Failed updateBearerNameNative, status: %d", status);
  }
  env->ReleaseStringUTFChars(operator_str, operator_name);
  return (status == BT_STATUS_SUCCESS) ? JNI_TRUE : JNI_FALSE;
}

static jboolean updateBearerTechnologyNative(JNIEnv* env, jobject object,
                                 jint bearer_tech) {
  std::shared_lock<std::shared_timed_mutex> lock(interface_mutex);
  if (!sCallControllerInterface) {
    ALOGW("%s: sCallControllerInterface is null", __func__);
    return JNI_FALSE;
  }
  bt_status_t status = sCallControllerInterface->UpdateBearerTechnology(bearer_tech);
  if (status != BT_STATUS_SUCCESS) {
    ALOGE("Failed updateBearerTechnologyNative, status: %d", status);
  }
  return (status == BT_STATUS_SUCCESS) ? JNI_TRUE : JNI_FALSE;
}

static jboolean updateSupportedBearerListNative(JNIEnv* env, jobject object,
                                 jstring bearer_list) {
  std::shared_lock<std::shared_timed_mutex> lock(interface_mutex);
  if (!sCallControllerInterface) {
    ALOGW("%s: sCallControllerInterface is null", __func__);
    return JNI_FALSE;
  }
  const char* list_bearer_string = env->GetStringUTFChars(bearer_list, nullptr);
  bt_status_t status = sCallControllerInterface->UpdateSupportedBearerList((uint8_t*)list_bearer_string);
  if (status != BT_STATUS_SUCCESS) {
    ALOGE("Failed updateSupportedBearerListNative, status: %d", status);
  }
  env->ReleaseStringUTFChars(bearer_list, list_bearer_string);
  return (status == BT_STATUS_SUCCESS) ? JNI_TRUE : JNI_FALSE;
}


static jboolean callControlPointOpcodeSupportedNative(JNIEnv* env, jobject object,
                                                 jint feature) {
   std::shared_lock<std::shared_timed_mutex> lock(interface_mutex);
   if (!sCallControllerInterface) {
     ALOGW("%s: sCallControllerInterface is null", __func__);
     return JNI_FALSE;
   }
   bt_status_t status = sCallControllerInterface->CallControlOptionalOpSupported(feature);
   return (status == BT_STATUS_SUCCESS) ? JNI_TRUE : JNI_FALSE;
}

static jboolean updateStatusFlagsNative(JNIEnv* env, jobject object,
                                         jint flags) {
  std::shared_lock<std::shared_timed_mutex> lock(interface_mutex);
  if (!sCallControllerInterface) {
    ALOGW("%s: sCallControllerInterface is null", __func__);
    return JNI_FALSE;
  }
  bt_status_t status = sCallControllerInterface->UpdateStatusFlags(flags);

  return (status == BT_STATUS_SUCCESS) ? JNI_TRUE : JNI_FALSE;
}

static jboolean updateSignalStatusNative(JNIEnv* env, jobject object,
                                          jint signal) {
  std::shared_lock<std::shared_timed_mutex> lock(interface_mutex);
  if (!sCallControllerInterface) {
    ALOGW("%s: sCallControllerInterface is null", __func__);
    return JNI_FALSE;
  }
  bt_status_t status = sCallControllerInterface->UpdateSignalStatus(signal);
  if (status != BT_STATUS_SUCCESS) {
    ALOGE("FAILED updateSignalStatusNative, status: %d", status);
  }
  return (status == BT_STATUS_SUCCESS) ? JNI_TRUE : JNI_FALSE;
}
static jboolean updateIncomingCallNative(JNIEnv* env, jobject object,
                                          jint index, jstring uri_str) {
  std::shared_lock<std::shared_timed_mutex> lock(interface_mutex);
  if (!sCallControllerInterface) {
    ALOGW("%s: sCallControllerInterface is null", __func__);
    return JNI_FALSE;
  }
  const char* uri = env->GetStringUTFChars(uri_str, nullptr);
  sCallControllerInterface->UpdateIncomingCall(index, (uint8_t*)uri);
  env->ReleaseStringUTFChars(uri_str, uri);
  return JNI_TRUE;
}

static jboolean callControlResponseNative(JNIEnv* env, jobject object,
                          jint op, jint index, jint status, jbyteArray address) {
  std::shared_lock<std::shared_timed_mutex> lock(interface_mutex);
  if (!sCallControllerInterface) {
    ALOGW("%s: sCallControllerInterface is null", __func__);
    return JNI_FALSE;
  }
  jbyte* addr = env->GetByteArrayElements(address, nullptr);
  if (!addr) {
   jniThrowIOException(env, EINVAL);
   return JNI_FALSE;
  }
  RawAddress* tmpraw = (RawAddress*)addr;
  bt_status_t ret_status =
      sCallControllerInterface->CallControlResponse(op, index, status, *tmpraw);
  if (ret_status != BT_STATUS_SUCCESS) {
    ALOGE("Failed to send callControlResponseNative, status: %d", ret_status);
  }
  return (ret_status == BT_STATUS_SUCCESS) ? JNI_TRUE : JNI_FALSE;
}

static jboolean setActiveDeviceNative(JNIEnv* env, jobject object,
                                          jint set_id, jbyteArray address) {
  LOG(INFO) << __func__;
  std::shared_lock<std::shared_timed_mutex> lock(interface_mutex);
  if (!sCallControllerInterface) return JNI_FALSE;
  jbyte* addr = env->GetByteArrayElements(address, nullptr);
  if (!addr) {
   jniThrowIOException(env, EINVAL);
   return JNI_FALSE;
  }
  RawAddress* tmpraw = (RawAddress*)addr;
  sCallControllerInterface->SetActiveDevice(*tmpraw, set_id);
  env->ReleaseByteArrayElements(address, addr, 0);

  return JNI_TRUE;
}

static jboolean callStateNative(JNIEnv* env, jobject object, jint len,
                   jbyteArray callList) {
  LOG(INFO) << __func__;
  std::shared_lock<std::shared_timed_mutex> lock(interface_mutex);

  jbyte* cList = env->GetByteArrayElements(callList, NULL);
  if (!cList) {
   jniThrowIOException(env, EINVAL);
   return JNI_FALSE;
  }
  uint16_t array_len = (uint16_t)env->GetArrayLength(callList);

  std::vector<uint8_t> vect_val(cList, cList + array_len);

  if (!sCallControllerInterface) {
    ALOGW("%s: sCallControllerInterface is null", __func__);
    return JNI_FALSE;
  }
  sCallControllerInterface->CallState(len, std::move(vect_val));
  env->ReleaseByteArrayElements(callList, cList, 0);
  return JNI_TRUE;
}

static jboolean contentControlIdNative(JNIEnv* env, jobject object,
                                           jint ccid) {

  LOG(INFO) << __func__;
  std::shared_lock<std::shared_timed_mutex> lock(interface_mutex);
  if (!sCallControllerInterface) return JNI_FALSE;

  sCallControllerInterface->ContentControlId(ccid);
  return JNI_TRUE;
}

static jboolean disconnectNative(JNIEnv* env, jobject object,
                                           jbyteArray address) {

  LOG(INFO) << __func__;
  std::shared_lock<std::shared_timed_mutex> lock(interface_mutex);
  if (!sCallControllerInterface) return JNI_FALSE;

  jbyte* addr = env->GetByteArrayElements(address, nullptr);
  if (!addr) {
   jniThrowIOException(env, EINVAL);
   return JNI_FALSE;
  }
  RawAddress* tmpraw = (RawAddress*)addr;

  sCallControllerInterface->Disconnect(*tmpraw);
  env->ReleaseByteArrayElements(address, addr, 0);
  return JNI_TRUE;
}

static JNINativeMethod sMethods[] = {
    {"classInitNative", "()V", (void*)classInitNative},
    {"initializeNative", "(Ljava/lang/String;IZ)V", (void*)initializeNative},
    {"cleanupNative", "()V", (void*)cleanupNative},
    {"updateBearerNameNative", "(Ljava/lang/String;)Z", (void*)updateBearerNameNative},
    {"updateBearerTechnologyNative", "(I)Z", (void*)updateBearerTechnologyNative},
    {"updateSupportedBearerListNative", "(Ljava/lang/String;)Z", (void*)updateSupportedBearerListNative},
    {"updateSignalStatusNative", "(I)Z", (void*)updateSignalStatusNative},
    {"updateStatusFlagsNative", "(I)Z", (void*)updateStatusFlagsNative},
    {"updateIncomingCallNative", "(ILjava/lang/String;)Z", (void*)updateIncomingCallNative},
    {"callControlResponseNative", "(III[B)Z", (void*)callControlResponseNative},
    {"callStateNative", "(I[B)Z", (void*)callStateNative},
    {"callControlPointOpcodeSupportedNative", "(I)Z", (void*)callControlPointOpcodeSupportedNative},
    {"setActiveDeviceNative", "(I[B)Z", (void*)setActiveDeviceNative},
    {"contentControlIdNative", "(I)Z", (void*)contentControlIdNative},
    {"disconnectNative", "([B)Z", (void*)disconnectNative},
};

int register_com_android_bluetooth_call_controller(JNIEnv* env) {
  return jniRegisterNativeMethods(
      env, "com/android/bluetooth/cc/CCNativeInterface",
      sMethods, NELEM(sMethods));
}
}  // namespace android
