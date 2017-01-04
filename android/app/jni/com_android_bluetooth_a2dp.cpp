/*
 * Copyright (C) 2012 The Android Open Source Project
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

#define LOG_TAG "BluetoothA2dpServiceJni"

#define LOG_NDEBUG 0

#include "android_runtime/AndroidRuntime.h"
#include "com_android_bluetooth.h"
#include "hardware/bt_av.h"
#include "utils/Log.h"

#include <string.h>

namespace android {
static jmethodID method_onConnectionStateChanged;
static jmethodID method_onAudioStateChanged;
static jmethodID method_onCodecConfigChanged;

static const btav_source_interface_t* sBluetoothA2dpInterface = NULL;
static jobject mCallbacksObj = NULL;

static void bta2dp_connection_state_callback(btav_connection_state_t state,
                                             bt_bdaddr_t* bd_addr) {
  ALOGI("%s", __func__);
  CallbackEnv sCallbackEnv(__func__);
  if (!sCallbackEnv.valid()) return;

  jbyteArray addr = sCallbackEnv->NewByteArray(sizeof(bt_bdaddr_t));
  if (!addr) {
    ALOGE("Fail to new jbyteArray bd addr for connection state");
    return;
  }

  sCallbackEnv->SetByteArrayRegion(addr, 0, sizeof(bt_bdaddr_t),
                                   (jbyte*)bd_addr);
  sCallbackEnv->CallVoidMethod(mCallbacksObj, method_onConnectionStateChanged,
                               (jint)state, addr);
  sCallbackEnv->DeleteLocalRef(addr);
}

static void bta2dp_audio_state_callback(btav_audio_state_t state,
                                        bt_bdaddr_t* bd_addr) {
  ALOGI("%s", __func__);
  CallbackEnv sCallbackEnv(__func__);
  if (!sCallbackEnv.valid()) return;

  jbyteArray addr = sCallbackEnv->NewByteArray(sizeof(bt_bdaddr_t));
  if (!addr) {
    ALOGE("Fail to new jbyteArray bd addr for connection state");
    return;
  }

  sCallbackEnv->SetByteArrayRegion(addr, 0, sizeof(bt_bdaddr_t),
                                   (jbyte*)bd_addr);
  sCallbackEnv->CallVoidMethod(mCallbacksObj, method_onAudioStateChanged,
                               (jint)state, addr);
  sCallbackEnv->DeleteLocalRef(addr);
}

static void bta2dp_audio_config_callback(
    btav_a2dp_codec_config_t codec_config,
    std::vector<btav_a2dp_codec_config_t> codec_capabilities) {
  ALOGI("%s", __func__);
  CallbackEnv sCallbackEnv(__func__);
  if (!sCallbackEnv.valid()) return;

  sCallbackEnv->CallVoidMethod(
      mCallbacksObj, method_onCodecConfigChanged, (jint)codec_config.codec_type,
      (jint)codec_config.codec_priority, (jint)codec_config.sample_rate,
      (jint)codec_config.bits_per_sample, (jint)codec_config.channel_mode,
      (jlong)codec_config.codec_specific_1,
      (jlong)codec_config.codec_specific_2,
      (jlong)codec_config.codec_specific_3,
      (jlong)codec_config.codec_specific_4);
}

static btav_source_callbacks_t sBluetoothA2dpCallbacks = {
    sizeof(sBluetoothA2dpCallbacks), bta2dp_connection_state_callback,
    bta2dp_audio_state_callback, bta2dp_audio_config_callback,
};

static void classInitNative(JNIEnv* env, jclass clazz) {
  method_onConnectionStateChanged =
      env->GetMethodID(clazz, "onConnectionStateChanged", "(I[B)V");

  method_onAudioStateChanged =
      env->GetMethodID(clazz, "onAudioStateChanged", "(I[B)V");

  method_onCodecConfigChanged =
      env->GetMethodID(clazz, "onCodecConfigChanged", "(IIIIIJJJJ)V");

  ALOGI("%s: succeeds", __func__);
}

static void initNative(JNIEnv* env, jobject object) {
  const bt_interface_t* btInf = getBluetoothInterface();
  if (btInf == NULL) {
    ALOGE("Bluetooth module is not loaded");
    return;
  }

  if (sBluetoothA2dpInterface != NULL) {
    ALOGW("Cleaning up A2DP Interface before initializing...");
    sBluetoothA2dpInterface->cleanup();
    sBluetoothA2dpInterface = NULL;
  }

  if (mCallbacksObj != NULL) {
    ALOGW("Cleaning up A2DP callback object");
    env->DeleteGlobalRef(mCallbacksObj);
    mCallbacksObj = NULL;
  }

  if ((mCallbacksObj = env->NewGlobalRef(object)) == NULL) {
    ALOGE("Failed to allocate Global Ref for A2DP Callbacks");
    return;
  }

  sBluetoothA2dpInterface =
      (btav_source_interface_t*)btInf->get_profile_interface(
          BT_PROFILE_ADVANCED_AUDIO_ID);
  if (sBluetoothA2dpInterface == NULL) {
    ALOGE("Failed to get Bluetooth A2DP Interface");
    return;
  }

  bt_status_t status = sBluetoothA2dpInterface->init(&sBluetoothA2dpCallbacks);
  if (status != BT_STATUS_SUCCESS) {
    ALOGE("Failed to initialize Bluetooth A2DP, status: %d", status);
    sBluetoothA2dpInterface = NULL;
    return;
  }
}

static void cleanupNative(JNIEnv* env, jobject object) {
  const bt_interface_t* btInf = getBluetoothInterface();
  if (btInf == NULL) {
    ALOGE("Bluetooth module is not loaded");
    return;
  }

  if (sBluetoothA2dpInterface != NULL) {
    sBluetoothA2dpInterface->cleanup();
    sBluetoothA2dpInterface = NULL;
  }

  if (mCallbacksObj != NULL) {
    env->DeleteGlobalRef(mCallbacksObj);
    mCallbacksObj = NULL;
  }
}

static jboolean connectA2dpNative(JNIEnv* env, jobject object,
                                  jbyteArray address) {
  ALOGI("%s: sBluetoothA2dpInterface: %p", __func__, sBluetoothA2dpInterface);
  if (!sBluetoothA2dpInterface) return JNI_FALSE;

  jbyte* addr = env->GetByteArrayElements(address, NULL);
  if (!addr) {
    jniThrowIOException(env, EINVAL);
    return JNI_FALSE;
  }

  bt_status_t status = sBluetoothA2dpInterface->connect((bt_bdaddr_t*)addr);
  if (status != BT_STATUS_SUCCESS) {
    ALOGE("Failed HF connection, status: %d", status);
  }
  env->ReleaseByteArrayElements(address, addr, 0);
  return (status == BT_STATUS_SUCCESS) ? JNI_TRUE : JNI_FALSE;
}

static jboolean disconnectA2dpNative(JNIEnv* env, jobject object,
                                     jbyteArray address) {
  if (!sBluetoothA2dpInterface) return JNI_FALSE;

  jbyte* addr = env->GetByteArrayElements(address, NULL);
  if (!addr) {
    jniThrowIOException(env, EINVAL);
    return JNI_FALSE;
  }

  bt_status_t status = sBluetoothA2dpInterface->disconnect((bt_bdaddr_t*)addr);
  if (status != BT_STATUS_SUCCESS) {
    ALOGE("Failed HF disconnection, status: %d", status);
  }
  env->ReleaseByteArrayElements(address, addr, 0);
  return (status == BT_STATUS_SUCCESS) ? JNI_TRUE : JNI_FALSE;
}

static jboolean setCodecConfigPreferenceNative(
    JNIEnv* env, jobject object, jint codecType, jint codecPriority,
    jint sampleRate, jint bitsPerSample, jint channelMode, jlong codecSpecific1,
    jlong codecSpecific2, jlong codecSpecific3, jlong codecSpecific4) {
  if (!sBluetoothA2dpInterface) return JNI_FALSE;

  btav_a2dp_codec_config_t codec_config = {
      .codec_type = static_cast<btav_a2dp_codec_index_t>(codecType),
      .codec_priority = static_cast<btav_a2dp_codec_priority_t>(codecPriority),
      .sample_rate = static_cast<btav_a2dp_codec_sample_rate_t>(sampleRate),
      .bits_per_sample =
          static_cast<btav_a2dp_codec_bits_per_sample_t>(bitsPerSample),
      .channel_mode = static_cast<btav_a2dp_codec_channel_mode_t>(channelMode),
      .codec_specific_1 = codecSpecific1,
      .codec_specific_2 = codecSpecific2,
      .codec_specific_3 = codecSpecific3,
      .codec_specific_4 = codecSpecific4};

  std::vector<btav_a2dp_codec_config_t> codec_preferences;
  codec_preferences.push_back(codec_config);

  bt_status_t status = sBluetoothA2dpInterface->config_codec(codec_preferences);
  if (status != BT_STATUS_SUCCESS) {
    ALOGE("Failed codec configuration, status: %d", status);
  }
  return (status == BT_STATUS_SUCCESS) ? JNI_TRUE : JNI_FALSE;
}

static JNINativeMethod sMethods[] = {
    {"classInitNative", "()V", (void*)classInitNative},
    {"initNative", "()V", (void*)initNative},
    {"cleanupNative", "()V", (void*)cleanupNative},
    {"connectA2dpNative", "([B)Z", (void*)connectA2dpNative},
    {"disconnectA2dpNative", "([B)Z", (void*)disconnectA2dpNative},
    {"setCodecConfigPreferenceNative", "(IIIIIJJJJ)Z",
     (void*)setCodecConfigPreferenceNative},
};

int register_com_android_bluetooth_a2dp(JNIEnv* env) {
  return jniRegisterNativeMethods(env,
                                  "com/android/bluetooth/a2dp/A2dpStateMachine",
                                  sMethods, NELEM(sMethods));
}
}
