/*
 * Copyright 2021 HIMSA II K/S - www.himsa.com.
 * Represented by EHIMA - www.ehima.com
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

#define LOG_TAG "BluetoothVolumeControlServiceJni"

#define LOG_NDEBUG 0

#include <string.h>
#include <shared_mutex>

#include "base/logging.h"
#include "com_android_bluetooth.h"
#include "hardware/bt_vc.h"

using bluetooth::vc::ConnectionState;
using bluetooth::vc::VolumeControlCallbacks;
using bluetooth::vc::VolumeControlInterface;

namespace android {
static jmethodID method_onConnectionStateChanged;
static jmethodID method_onVolumeStateChanged;
static jmethodID method_onGroupVolumeStateChanged;

static VolumeControlInterface* sVolumeControlInterface = nullptr;
static std::shared_timed_mutex interface_mutex;

static jobject mCallbacksObj = nullptr;
static std::shared_timed_mutex callbacks_mutex;

class VolumeControlCallbacksImpl : public VolumeControlCallbacks {
 public:
  ~VolumeControlCallbacksImpl() = default;
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

  void OnVolumeStateChanged(const RawAddress& bd_addr, uint8_t volume,
                            bool mute) override {
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
    sCallbackEnv->CallVoidMethod(mCallbacksObj, method_onVolumeStateChanged,
                                 (jint)volume, (jboolean)mute, addr.get());
  }

  void OnGroupVolumeStateChanged(int group_id, uint8_t volume,
                                 bool mute) override {
    LOG(INFO) << __func__;

    std::shared_lock<std::shared_timed_mutex> lock(callbacks_mutex);
    CallbackEnv sCallbackEnv(__func__);
    if (!sCallbackEnv.valid() || mCallbacksObj == nullptr) return;

    sCallbackEnv->CallVoidMethod(mCallbacksObj,
                                 method_onGroupVolumeStateChanged, (jint)volume,
                                 (jboolean)mute, group_id);
  }
};

static VolumeControlCallbacksImpl sVolumeControlCallbacks;

static void classInitNative(JNIEnv* env, jclass clazz) {
  method_onConnectionStateChanged =
      env->GetMethodID(clazz, "onConnectionStateChanged", "(I[B)V");

  method_onVolumeStateChanged =
      env->GetMethodID(clazz, "onVolumeStateChanged", "(IZ[B)V");

  method_onGroupVolumeStateChanged =
      env->GetMethodID(clazz, "onGroupVolumeStateChanged", "(IZI)V");

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

  if (sVolumeControlInterface != nullptr) {
    LOG(INFO) << "Cleaning up VolumeControl Interface before initializing...";
    sVolumeControlInterface->Cleanup();
    sVolumeControlInterface = nullptr;
  }

  if (mCallbacksObj != nullptr) {
    LOG(INFO) << "Cleaning up VolumeControl callback object";
    env->DeleteGlobalRef(mCallbacksObj);
    mCallbacksObj = nullptr;
  }

  if ((mCallbacksObj = env->NewGlobalRef(object)) == nullptr) {
    LOG(ERROR) << "Failed to allocate Global Ref for Volume control Callbacks";
    return;
  }

  sVolumeControlInterface =
      (VolumeControlInterface*)btInf->get_profile_interface(BT_PROFILE_VC_ID);
  if (sVolumeControlInterface == nullptr) {
    LOG(ERROR) << "Failed to get Bluetooth Volume Control Interface";
    return;
  }

  sVolumeControlInterface->Init(&sVolumeControlCallbacks);
}

static void cleanupNative(JNIEnv* env, jobject object) {
  std::unique_lock<std::shared_timed_mutex> interface_lock(interface_mutex);
  std::unique_lock<std::shared_timed_mutex> callbacks_lock(callbacks_mutex);

  const bt_interface_t* btInf = getBluetoothInterface();
  if (btInf == nullptr) {
    LOG(ERROR) << "Bluetooth module is not loaded";
    return;
  }

  if (sVolumeControlInterface != nullptr) {
    sVolumeControlInterface->Cleanup();
    sVolumeControlInterface = nullptr;
  }

  if (mCallbacksObj != nullptr) {
    env->DeleteGlobalRef(mCallbacksObj);
    mCallbacksObj = nullptr;
  }
}

static jboolean connectVolumeControlNative(JNIEnv* env, jobject object,
                                           jbyteArray address) {
  LOG(INFO) << __func__;
  std::shared_lock<std::shared_timed_mutex> lock(interface_mutex);

  if (!sVolumeControlInterface) {
    LOG(ERROR) << __func__
               << ": Failed to get the Bluetooth Volume Control Interface";
    return JNI_FALSE;
  }

  jbyte* addr = env->GetByteArrayElements(address, nullptr);
  if (!addr) {
    jniThrowIOException(env, EINVAL);
    return JNI_FALSE;
  }

  RawAddress* tmpraw = (RawAddress*)addr;
  sVolumeControlInterface->Connect(*tmpraw);
  env->ReleaseByteArrayElements(address, addr, 0);
  return JNI_TRUE;
}

static jboolean disconnectVolumeControlNative(JNIEnv* env, jobject object,
                                              jbyteArray address) {
  LOG(INFO) << __func__;
  std::shared_lock<std::shared_timed_mutex> lock(interface_mutex);

  if (!sVolumeControlInterface) {
    LOG(ERROR) << __func__
               << ": Failed to get the Bluetooth Volume Control Interface";
    return JNI_FALSE;
  }

  jbyte* addr = env->GetByteArrayElements(address, nullptr);
  if (!addr) {
    jniThrowIOException(env, EINVAL);
    return JNI_FALSE;
  }

  RawAddress* tmpraw = (RawAddress*)addr;
  sVolumeControlInterface->Disconnect(*tmpraw);
  env->ReleaseByteArrayElements(address, addr, 0);
  return JNI_TRUE;
}

static void setVolumeNative(JNIEnv* env, jobject object, jbyteArray address,
                            jint volume) {
  if (!sVolumeControlInterface) {
    LOG(ERROR) << __func__
               << ": Failed to get the Bluetooth Volume Control Interface";
    return;
  }

  jbyte* addr = env->GetByteArrayElements(address, nullptr);
  if (!addr) {
    jniThrowIOException(env, EINVAL);
    return;
  }

  RawAddress* tmpraw = (RawAddress*)addr;
  sVolumeControlInterface->SetVolume(*tmpraw, volume);
  env->ReleaseByteArrayElements(address, addr, 0);
}

static void setVolumeGroupNative(JNIEnv* env, jobject object, jint group_id,
                                 jint volume) {
  if (!sVolumeControlInterface) {
    LOG(ERROR) << __func__
               << ": Failed to get the Bluetooth Volume Control Interface";
    return;
  }

  sVolumeControlInterface->SetVolume(group_id, volume);
}

static JNINativeMethod sMethods[] = {
    {"classInitNative", "()V", (void*)classInitNative},
    {"initNative", "()V", (void*)initNative},
    {"cleanupNative", "()V", (void*)cleanupNative},
    {"connectVolumeControlNative", "([B)Z", (void*)connectVolumeControlNative},
    {"disconnectVolumeControlNative", "([B)Z",
     (void*)disconnectVolumeControlNative},
    {"setVolumeNative", "([BI)V", (void*)setVolumeNative},
    {"setVolumeGroupNative", "(II)V", (void*)setVolumeGroupNative},
};

int register_com_android_bluetooth_vc(JNIEnv* env) {
  return jniRegisterNativeMethods(
      env, "com/android/bluetooth/vc/VolumeControlNativeInterface", sMethods,
      NELEM(sMethods));
}
}  // namespace android
