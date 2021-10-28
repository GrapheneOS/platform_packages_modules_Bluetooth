/*
 *Copyright (c) 2020, The Linux Foundation. All rights reserved.

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

#define LOG_TAG "BluetoothVCPControllerJni"

#define LOG_NDEBUG 0

#include "android_runtime/AndroidRuntime.h"
#include "base/logging.h"
#include "com_android_bluetooth.h"
#include "hardware/bt_vcp_controller.h"

#include <string.h>
#include <shared_mutex>

using bluetooth::vcp_controller::ConnectionState;
using bluetooth::vcp_controller::VcpControllerCallbacks;
using bluetooth::vcp_controller::VcpControllerInterface;

namespace android {
static jmethodID method_onConnectionStateChanged;
static jmethodID method_onVolumeStateChange;
static jmethodID method_onVolumeFlagsChange;

static VcpControllerInterface* sVcpControllerInterface = nullptr;
static std::shared_timed_mutex interface_mutex;

static jobject mCallbacksObj = nullptr;
static std::shared_timed_mutex callbacks_mutex;

class VcpControllerCallbacksImpl : public VcpControllerCallbacks {
 public:
  ~VcpControllerCallbacksImpl() = default;

  void OnConnectionState(ConnectionState state,
                         const RawAddress& bd_addr) override {
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
                                 (jint)state, addr.get());
  }


  void OnVolumeStateChange(uint8_t volume, uint8_t mute,
                         const RawAddress& bd_addr) override {
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
    sCallbackEnv->CallVoidMethod(mCallbacksObj, method_onVolumeStateChange,
                                 (jint)volume, (jboolean)mute, addr.get());
  }

  void OnVolumeFlagsChange(uint8_t flags,
                         const RawAddress& bd_addr) override {
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
    sCallbackEnv->CallVoidMethod(mCallbacksObj, method_onVolumeFlagsChange,
                                 (jint)flags, addr.get());
  }
};

static VcpControllerCallbacksImpl sVcpControllerCallbacks;

static void classInitNative(JNIEnv* env, jclass clazz) {
  method_onConnectionStateChanged =
      env->GetMethodID(clazz, "onConnectionStateChanged", "(I[B)V");

  method_onVolumeStateChange =
      env->GetMethodID(clazz, "OnVolumeStateChange", "(II[B)V");

  method_onVolumeFlagsChange =
      env->GetMethodID(clazz, "OnVolumeFlagsChange", "(I[B)V");

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

  if (sVcpControllerInterface != nullptr) {
    LOG(INFO) << "Cleaning up VcpController Interface before initializing...";
    sVcpControllerInterface->Cleanup();
    sVcpControllerInterface = nullptr;
  }

  if (mCallbacksObj != nullptr) {
    LOG(INFO) << "Cleaning up VcpController callback object";
    env->DeleteGlobalRef(mCallbacksObj);
    mCallbacksObj = nullptr;
  }

  if ((mCallbacksObj = env->NewGlobalRef(object)) == nullptr) {
    LOG(ERROR) << "Failed to allocate Global Ref for Vcp Controller Callbacks";
    return;
  }

  sVcpControllerInterface = (VcpControllerInterface*)btInf->get_profile_interface(
      BT_PROFILE_VOLUME_CONTROL_ID);
  if (sVcpControllerInterface == nullptr) {
    LOG(ERROR) << "Failed to get Bluetooth Hearing Aid Interface";
    return;
  }

  sVcpControllerInterface->Init(&sVcpControllerCallbacks);
}

static void cleanupNative(JNIEnv* env, jobject object) {
  std::unique_lock<std::shared_timed_mutex> interface_lock(interface_mutex);
  std::unique_lock<std::shared_timed_mutex> callbacks_lock(callbacks_mutex);

  const bt_interface_t* btInf = getBluetoothInterface();
  if (btInf == nullptr) {
    LOG(ERROR) << "Bluetooth module is not loaded";
    return;
  }

  if (sVcpControllerInterface != nullptr) {
    sVcpControllerInterface->Cleanup();
    sVcpControllerInterface = nullptr;
  }

  if (mCallbacksObj != nullptr) {
    env->DeleteGlobalRef(mCallbacksObj);
    mCallbacksObj = nullptr;
  }
}

static jboolean connectVcpNative(JNIEnv* env, jobject object,
                                        jbyteArray address, jboolean isDirect) {
  LOG(INFO) << __func__;
  std::shared_lock<std::shared_timed_mutex> lock(interface_mutex);
  if (!sVcpControllerInterface) return JNI_FALSE;

  jbyte* addr = env->GetByteArrayElements(address, nullptr);
  if (!addr) {
    jniThrowIOException(env, EINVAL);
    return JNI_FALSE;
  }

  RawAddress* tmpraw = (RawAddress*)addr;
  sVcpControllerInterface->Connect(*tmpraw, isDirect);
  env->ReleaseByteArrayElements(address, addr, 0);
  return JNI_TRUE;
}

static jboolean disconnectVcpNative(JNIEnv* env, jobject object,
                                           jbyteArray address) {
  LOG(INFO) << __func__;
  std::shared_lock<std::shared_timed_mutex> lock(interface_mutex);
  if (!sVcpControllerInterface) return JNI_FALSE;

  jbyte* addr = env->GetByteArrayElements(address, nullptr);
  if (!addr) {
    jniThrowIOException(env, EINVAL);
    return JNI_FALSE;
  }

  RawAddress* tmpraw = (RawAddress*)addr;
  sVcpControllerInterface->Disconnect(*tmpraw);
  env->ReleaseByteArrayElements(address, addr, 0);
  return JNI_TRUE;
}

static jboolean setAbsVolumeNative(JNIEnv* env, jobject object,
                                           jint volume, jbyteArray address) {
  LOG(INFO) << __func__;
  std::shared_lock<std::shared_timed_mutex> lock(interface_mutex);
  if (!sVcpControllerInterface) return JNI_FALSE;

  jbyte* addr = env->GetByteArrayElements(address, nullptr);
  if (!addr) {
    jniThrowIOException(env, EINVAL);
    return JNI_FALSE;
  }

  RawAddress* tmpraw = (RawAddress*)addr;
  sVcpControllerInterface->SetAbsVolume(volume, *tmpraw);
  env->ReleaseByteArrayElements(address, addr, 0);
  return JNI_TRUE;
}

static jboolean muteNative(JNIEnv* env, jobject object,
                                           jbyteArray address) {
  LOG(INFO) << __func__;
  std::shared_lock<std::shared_timed_mutex> lock(interface_mutex);
  if (!sVcpControllerInterface) return JNI_FALSE;

  jbyte* addr = env->GetByteArrayElements(address, nullptr);
  if (!addr) {
    jniThrowIOException(env, EINVAL);
    return JNI_FALSE;
  }

  RawAddress* tmpraw = (RawAddress*)addr;
  sVcpControllerInterface->Mute(*tmpraw);
  env->ReleaseByteArrayElements(address, addr, 0);
  return JNI_TRUE;
}

static jboolean unmuteNative(JNIEnv* env, jobject object,
                                           jbyteArray address) {
  LOG(INFO) << __func__;
  std::shared_lock<std::shared_timed_mutex> lock(interface_mutex);
  if (!sVcpControllerInterface) return JNI_FALSE;

  jbyte* addr = env->GetByteArrayElements(address, nullptr);
  if (!addr) {
    jniThrowIOException(env, EINVAL);
    return JNI_FALSE;
  }

  RawAddress* tmpraw = (RawAddress*)addr;
  sVcpControllerInterface->Unmute(*tmpraw);
  env->ReleaseByteArrayElements(address, addr, 0);
  return JNI_TRUE;
}

static JNINativeMethod sMethods[] = {
    {"classInitNative", "()V", (void*)classInitNative},
    {"initNative", "()V", (void*)initNative},
    {"cleanupNative", "()V", (void*)cleanupNative},
    {"connectVcpNative", "([BZ)Z", (void*)connectVcpNative},
    {"disconnectVcpNative", "([B)Z", (void*)disconnectVcpNative},
    {"setAbsVolumeNative", "(I[B)Z", (void*)setAbsVolumeNative},
    {"muteNative", "([B)Z", (void*)muteNative},
    {"unmuteNative", "([B)Z", (void*)unmuteNative},
};

int register_com_android_bluetooth_vcp_controller(JNIEnv* env) {
  return jniRegisterNativeMethods(
      env, "com/android/bluetooth/vcp/VcpControllerNativeInterface",
      sMethods, NELEM(sMethods));
}
}  // namespace android

