/*
 * Copyright (c) 2020, The Linux Foundation. All rights reserved.

 * Copyright 2018 The Android Open Source Project
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

#define LOG_TAG "BluetoothPacsClienServiceJni"

#define LOG_NDEBUG 0

#include "android_runtime/AndroidRuntime.h"
#include "base/logging.h"
#include "com_android_bluetooth.h"
#include "hardware/bt_pacs_client.h"

#include <string.h>
#include <shared_mutex>

using bluetooth::bap::pacs::ConnectionState;
using bluetooth::bap::pacs::PacsClientInterface;
using bluetooth::bap::pacs::PacsClientCallbacks;

namespace android {

static jmethodID method_OnInitialized;
static jmethodID method_onConnectionStateChanged;
static jmethodID method_OnAudioContextAvailable;
static jmethodID method_onServiceDiscovery;

static struct {
   jclass clazz;
   jmethodID constructor;
   jmethodID getCodecType;
   jmethodID getCodecPriority;
   jmethodID getSampleRate;
   jmethodID getBitsPerSample;
   jmethodID getChannelMode;
   jmethodID getCodecSpecific1;
   jmethodID getCodecSpecific2;
   jmethodID getCodecSpecific3;
   jmethodID getCodecSpecific4;
} android_bluetooth_pacs_record;

static PacsClientInterface* sPacsClientInterface = nullptr;
static std::shared_timed_mutex interface_mutex;

static jobject mCallbacksObj = nullptr;
static std::shared_timed_mutex callbacks_mutex;

class PacsClientCallbacksImpl : public PacsClientCallbacks {
 public:
  ~PacsClientCallbacksImpl() = default;
  void OnInitialized(int status,
                     int client_id) override {
    LOG(INFO) << __func__;

    std::shared_lock<std::shared_timed_mutex> lock(callbacks_mutex);
    CallbackEnv sCallbackEnv(__func__);
    if (!sCallbackEnv.valid() || mCallbacksObj == nullptr) return;

    sCallbackEnv->CallVoidMethod(mCallbacksObj, method_OnInitialized,
                                 (jint)status, (jint)client_id);
  }

  void OnConnectionState(const RawAddress& bd_addr,
                         ConnectionState state) override {
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
    sCallbackEnv->CallVoidMethod(mCallbacksObj, method_onConnectionStateChanged,
                                 addr.get(), (jint)state);
  }

  void OnAudioContextAvailable(const RawAddress& bd_addr,
                        uint32_t available_contexts) override {
    LOG(INFO) << __func__;

    std::shared_lock<std::shared_timed_mutex> lock(callbacks_mutex);
    CallbackEnv sCallbackEnv(__func__);
    if (!sCallbackEnv.valid() || mCallbacksObj == nullptr) return;

    ScopedLocalRef<jbyteArray> addr(
        sCallbackEnv.get(), sCallbackEnv->NewByteArray(sizeof(RawAddress)));
    if (!addr.get()) {
      LOG(ERROR) << "Failed to new jbyteArray bd addr for available audio context";
      return;
    }

    sCallbackEnv->SetByteArrayRegion(addr.get(), 0, sizeof(RawAddress),
                                     (jbyte*)&bd_addr);
    sCallbackEnv->CallVoidMethod(mCallbacksObj, method_OnAudioContextAvailable,
                                 addr.get(), (jint)available_contexts);
  }

   void OnSearchComplete(int status, const RawAddress& address,
                         std::vector<bluetooth::bap::pacs::CodecConfig> sink_pac_records,
                         std::vector<bluetooth::bap::pacs::CodecConfig> src_pac_records,
                         uint32_t sink_locations,
                         uint32_t src_locations,
                         uint32_t available_contexts,
                         uint32_t supported_contexts) override {

    LOG(INFO) << __func__;

    std::shared_lock<std::shared_timed_mutex> lock(callbacks_mutex);
    CallbackEnv sCallbackEnv(__func__);
    if (!sCallbackEnv.valid() || mCallbacksObj == nullptr) return;


    jsize i = 0;
    jobjectArray sink_pac_records_array = sCallbackEnv->NewObjectArray(
        (jsize)sink_pac_records.size(),
        android_bluetooth_pacs_record.clazz, nullptr);
    for (auto const& cap : sink_pac_records) {
      jobject capObj = sCallbackEnv->NewObject(
          android_bluetooth_pacs_record.clazz,
          android_bluetooth_pacs_record.constructor,
          (jint)cap.codec_type, (jint)cap.codec_priority, (jint)cap.sample_rate,
          (jint)cap.bits_per_sample, (jint)cap.channel_mode,
          (jlong)cap.codec_specific_1, (jlong)cap.codec_specific_2,
          (jlong)cap.codec_specific_3, (jlong)cap.codec_specific_4);
      sCallbackEnv->SetObjectArrayElement(sink_pac_records_array, i++, capObj);
      sCallbackEnv->DeleteLocalRef(capObj);
    }

    i = 0;
    jobjectArray src_pac_records_array = sCallbackEnv->NewObjectArray(
        (jsize)src_pac_records.size(),
        android_bluetooth_pacs_record.clazz, nullptr);
    for (auto const& cap : src_pac_records) {
      jobject capObj = sCallbackEnv->NewObject(
          android_bluetooth_pacs_record.clazz,
          android_bluetooth_pacs_record.constructor,
          (jint)cap.codec_type, (jint)cap.codec_priority, (jint)cap.sample_rate,
          (jint)cap.bits_per_sample, (jint)cap.channel_mode,
          (jlong)cap.codec_specific_1, (jlong)cap.codec_specific_2,
          (jlong)cap.codec_specific_3, (jlong)cap.codec_specific_4);
      sCallbackEnv->SetObjectArrayElement(src_pac_records_array, i++,
                                          capObj);
      sCallbackEnv->DeleteLocalRef(capObj);
    }

    ScopedLocalRef<jbyteArray> addr(
        sCallbackEnv.get(), sCallbackEnv->NewByteArray(sizeof(RawAddress)));
    if (!addr.get()) {
      LOG(ERROR) << "Failed to new jbyteArray bd addr";
      return;
    }

    sCallbackEnv->SetByteArrayRegion(addr.get(), 0, sizeof(RawAddress),
                                     (jbyte*)&address);
    sCallbackEnv->CallVoidMethod(mCallbacksObj, method_onServiceDiscovery,
                                 sink_pac_records_array, src_pac_records_array, (jint)sink_locations,
                                 (jint)src_locations, (jint)available_contexts, (jint)supported_contexts,
                                 (jint)status, addr.get());
  }
};

static PacsClientCallbacksImpl sPacsClientCallbacks;

static void classInitNative(JNIEnv* env, jclass clazz) {

  jclass jniBluetoothCodecConfigClass =
      env->FindClass("android/bluetooth/BluetoothCodecConfig");
  android_bluetooth_pacs_record.constructor =
      env->GetMethodID(jniBluetoothCodecConfigClass, "<init>", "(IIIIIJJJJ)V");
  android_bluetooth_pacs_record.getCodecType =
      env->GetMethodID(jniBluetoothCodecConfigClass, "getCodecType", "()I");
  android_bluetooth_pacs_record.getCodecPriority =
      env->GetMethodID(jniBluetoothCodecConfigClass, "getCodecPriority", "()I");
  android_bluetooth_pacs_record.getSampleRate =
      env->GetMethodID(jniBluetoothCodecConfigClass, "getSampleRate", "()I");
  android_bluetooth_pacs_record.getBitsPerSample =
      env->GetMethodID(jniBluetoothCodecConfigClass, "getBitsPerSample", "()I");
  android_bluetooth_pacs_record.getChannelMode =
      env->GetMethodID(jniBluetoothCodecConfigClass, "getChannelMode", "()I");
  android_bluetooth_pacs_record.getCodecSpecific1 = env->GetMethodID(
      jniBluetoothCodecConfigClass, "getCodecSpecific1", "()J");
  android_bluetooth_pacs_record.getCodecSpecific2 = env->GetMethodID(
      jniBluetoothCodecConfigClass, "getCodecSpecific2", "()J");
  android_bluetooth_pacs_record.getCodecSpecific3 = env->GetMethodID(
      jniBluetoothCodecConfigClass, "getCodecSpecific3", "()J");
  android_bluetooth_pacs_record.getCodecSpecific4 = env->GetMethodID(
      jniBluetoothCodecConfigClass, "getCodecSpecific4", "()J");

  method_OnInitialized =
      env->GetMethodID(clazz, "OnInitialized", "(II)V");

  method_onConnectionStateChanged =
      env->GetMethodID(clazz, "onConnectionStateChanged", "([BI)V");

  method_OnAudioContextAvailable =
      env->GetMethodID(clazz, "OnAudioContextAvailable", "([BI)V");

  method_onServiceDiscovery =
      env->GetMethodID(clazz, "onServiceDiscovery", "([Landroid/bluetooth/BluetoothCodecConfig;"
                                                    "[Landroid/bluetooth/BluetoothCodecConfig;"
                                                    "IIIII[B)V");

  LOG(INFO) << __func__ << ": succeeds";
}

static void initNative(JNIEnv* env, jobject object) {
  std::unique_lock<std::shared_timed_mutex> interface_lock(interface_mutex);
  std::unique_lock<std::shared_timed_mutex> callbacks_lock(callbacks_mutex);

  const bt_interface_t* btInf = getBluetoothInterface();
  if (btInf == nullptr) {
    LOG(ERROR) << "Bluetooth module is not loaded";
    return;
  }

  if (sPacsClientInterface != nullptr) {
    LOG(INFO) << "Cleaning up PacsClient Interface before initializing...";
    sPacsClientInterface->Cleanup(0);
    sPacsClientInterface = nullptr;
  }

  if (mCallbacksObj != nullptr) {
    LOG(INFO) << "Cleaning up PacsClient callback object";
    env->DeleteGlobalRef(mCallbacksObj);
    mCallbacksObj = nullptr;
  }

  if ((mCallbacksObj = env->NewGlobalRef(object)) == nullptr) {
    LOG(ERROR) << "Failed to allocate Global Ref for pacs client Callbacks";
    return;
  }

  android_bluetooth_pacs_record.clazz = (jclass)env->NewGlobalRef(
      env->FindClass("android/bluetooth/BluetoothCodecConfig"));
  if (android_bluetooth_pacs_record.clazz == nullptr) {
    ALOGE("%s: Failed to allocate Global Ref for BluetoothCodecConfig class",
          __func__);
    return;
  }

  sPacsClientInterface = (PacsClientInterface*)btInf->get_profile_interface(
      BT_PROFILE_PACS_CLIENT_ID);
  if (sPacsClientInterface == nullptr) {
    LOG(ERROR) << "Failed to get Bluetooth pacs client Interface";
    return;
  }

  sPacsClientInterface->Init(&sPacsClientCallbacks);
}

static void cleanupNative(JNIEnv* env, jobject object, jint client_id) {
  std::unique_lock<std::shared_timed_mutex> interface_lock(interface_mutex);
  std::unique_lock<std::shared_timed_mutex> callbacks_lock(callbacks_mutex);

  const bt_interface_t* btInf = getBluetoothInterface();
  if (btInf == nullptr) {
    LOG(ERROR) << "Bluetooth module is not loaded";
    return;
  }

  if (sPacsClientInterface != nullptr) {
    sPacsClientInterface->Cleanup(client_id);
    sPacsClientInterface = nullptr;
  }

  if (mCallbacksObj != nullptr) {
    env->DeleteGlobalRef(mCallbacksObj);
    mCallbacksObj = nullptr;
  }
  env->DeleteGlobalRef(android_bluetooth_pacs_record.clazz);
  android_bluetooth_pacs_record.clazz = nullptr;
}

static jboolean connectPacsClientNative(JNIEnv* env, jobject object,
                                        jint client_id, jbyteArray address) {
  LOG(INFO) << __func__;
  std::shared_lock<std::shared_timed_mutex> lock(interface_mutex);
  if (!sPacsClientInterface) return JNI_FALSE;

  jbyte* addr = env->GetByteArrayElements(address, nullptr);
  if (!addr) {
    jniThrowIOException(env, EINVAL);
    return JNI_FALSE;
  }

  RawAddress* tmpraw = (RawAddress*)addr;
  sPacsClientInterface->Connect(client_id, *tmpraw);
  env->ReleaseByteArrayElements(address, addr, 0);
  return JNI_TRUE;
}

static jboolean disconnectPacsClientNative(JNIEnv* env, jobject object,
                                           jint client_id, jbyteArray address) {
  LOG(INFO) << __func__;
  std::shared_lock<std::shared_timed_mutex> lock(interface_mutex);
  if (!sPacsClientInterface) return JNI_FALSE;

  jbyte* addr = env->GetByteArrayElements(address, nullptr);
  if (!addr) {
    jniThrowIOException(env, EINVAL);
    return JNI_FALSE;
  }

  RawAddress* tmpraw = (RawAddress*)addr;
  sPacsClientInterface->Disconnect(client_id, *tmpraw);
  env->ReleaseByteArrayElements(address, addr, 0);
  return JNI_TRUE;
}

static jboolean startDiscoveryNative(JNIEnv* env, jobject object,
                                     jint client_id, jbyteArray address) {
  std::shared_lock<std::shared_timed_mutex> lock(interface_mutex);
  if (!sPacsClientInterface) return JNI_FALSE;
  jbyte* addr = env->GetByteArrayElements(address, nullptr);
  if (!addr) {
    jniThrowIOException(env, EINVAL);
    return JNI_FALSE;
  }

  RawAddress* tmpraw = (RawAddress*)addr;
  sPacsClientInterface->StartDiscovery(client_id, *tmpraw);
  env->ReleaseByteArrayElements(address, addr, 0);
  return JNI_TRUE;
}

static void GetAvailableAudioContextsNative(JNIEnv* env, jobject object,
                                      jint client_id, jbyteArray address) {
  std::shared_lock<std::shared_timed_mutex> lock(interface_mutex);
  if (!sPacsClientInterface) return;
  jbyte* addr = env->GetByteArrayElements(address, nullptr);
  if (!addr) {
    jniThrowIOException(env, EINVAL);
    return;
  }

  RawAddress* tmpraw = (RawAddress*)addr;
  sPacsClientInterface->GetAvailableAudioContexts(client_id, *tmpraw);
  env->ReleaseByteArrayElements(address, addr, 0);
}


static JNINativeMethod sMethods[] = {
    {"classInitNative", "()V", (void*)classInitNative},
    {"initNative", "()V", (void*)initNative},
    {"cleanupNative", "(I)V", (void*)cleanupNative},
    {"connectPacsClientNative", "(I[B)Z", (void*)connectPacsClientNative},
    {"disconnectPacsClientNative", "(I[B)Z", (void*)disconnectPacsClientNative},
    {"startDiscoveryNative", "(I[B)Z", (void*)startDiscoveryNative},
    {"GetAvailableAudioContextsNative", "(I[B)Z", (void*)GetAvailableAudioContextsNative},
};

int register_com_android_bluetooth_pacs_client(JNIEnv* env) {
  return jniRegisterNativeMethods(
      env, "com/android/bluetooth/pc/PacsClientNativeInterface",
      sMethods, NELEM(sMethods));
}
}  // namespace android
