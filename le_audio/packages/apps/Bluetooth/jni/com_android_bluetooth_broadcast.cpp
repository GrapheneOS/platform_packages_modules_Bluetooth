/*
 * Copyright (c) 2020, The Linux Foundation. All rights reserved.
 */

#define LOG_TAG "BluetoothBapBroadcastServiceJni"

#define LOG_NDEBUG 0

#include "android_runtime/AndroidRuntime.h"
#include "com_android_bluetooth.h"
#include "hardware/bt_av.h"
#include "hardware/bt_bap_ba.h"
#include "utils/Log.h"

#include <string.h>
#include <shared_mutex>

namespace android {
static jmethodID method_onBroadcastStateChanged;
static jmethodID method_onAudioStateChanged;
static jmethodID method_onCodecConfigChanged;
//static jmethodID method_onIsoDataPathChanged;
static jmethodID method_onEncryptionKeyGenerated;
static jmethodID method_onSetupBIG;
static jmethodID method_onBroadcastIdGenerated;
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
} android_bluetooth_BluetoothCodecConfig;

static const btbap_broadcast_interface_t* sBluetoothBapBroadcastInterface = nullptr;
static std::shared_timed_mutex interface_mutex;

static jobject mCallbacksObj = nullptr;
static std::shared_timed_mutex callbacks_mutex;

static void btbap_broadcast_state_callback(jint adv_id, btbap_broadcast_state_t state) {
  ALOGI("%s", __func__);

  std::shared_lock<std::shared_timed_mutex> lock(callbacks_mutex);
  ALOGI("%s: lock acquired", __func__);
  CallbackEnv sCallbackEnv(__func__);
  ALOGI("%s:got callback env", __func__);
  if (!sCallbackEnv.valid() || mCallbacksObj == nullptr) {
    ALOGI("%s:either callback is not valid or callbackobj is null", __func__);
    return;
  }
  ALOGI("%s: calling method to native interface", __func__);
  sCallbackEnv->CallVoidMethod(mCallbacksObj, method_onBroadcastStateChanged, adv_id, (jint)state);
}

static void btbap_broadcast_audio_state_callback(jint big_handle, btbap_broadcast_audio_state_t state) {
  ALOGI("%s", __func__);

  std::shared_lock<std::shared_timed_mutex> lock(callbacks_mutex);
  CallbackEnv sCallbackEnv(__func__);
  if (!sCallbackEnv.valid() || mCallbacksObj == nullptr) return;

  sCallbackEnv->CallVoidMethod(mCallbacksObj, method_onAudioStateChanged, big_handle, (jint)state);
}

static void btbap_broadcast_audio_config_callback(jint adv_id, btav_a2dp_codec_config_t codec_config,
                                                             std::vector<btav_a2dp_codec_config_t> codec_capabilities) {
  ALOGI("%s", __func__);

  std::shared_lock<std::shared_timed_mutex> lock(callbacks_mutex);
  CallbackEnv sCallbackEnv(__func__);
  if (!sCallbackEnv.valid() || mCallbacksObj == nullptr) return;

  jobject codecConfigObj = sCallbackEnv->NewObject(
      android_bluetooth_BluetoothCodecConfig.clazz,
      android_bluetooth_BluetoothCodecConfig.constructor,
      (jint)codec_config.codec_type, (jint)codec_config.codec_priority,
      (jint)codec_config.sample_rate, (jint)codec_config.bits_per_sample,
      (jint)codec_config.channel_mode, (jlong)codec_config.codec_specific_1,
      (jlong)codec_config.codec_specific_2,
      (jlong)codec_config.codec_specific_3,
      (jlong)codec_config.codec_specific_4);

  jsize i = 0;
  jobjectArray local_capabilities_array = sCallbackEnv->NewObjectArray(
      (jsize)codec_capabilities.size(),
      android_bluetooth_BluetoothCodecConfig.clazz, nullptr);
  for (auto const& cap : codec_capabilities) {
    jobject capObj = sCallbackEnv->NewObject(
        android_bluetooth_BluetoothCodecConfig.clazz,
        android_bluetooth_BluetoothCodecConfig.constructor,
        (jint)cap.codec_type, (jint)cap.codec_priority, (jint)cap.sample_rate,
        (jint)cap.bits_per_sample, (jint)cap.channel_mode,
        (jlong)cap.codec_specific_1, (jlong)cap.codec_specific_2,
        (jlong)cap.codec_specific_3, (jlong)cap.codec_specific_4);
    sCallbackEnv->SetObjectArrayElement(local_capabilities_array, i++, capObj);
    sCallbackEnv->DeleteLocalRef(capObj);
  }

  sCallbackEnv->CallVoidMethod(mCallbacksObj, method_onCodecConfigChanged,
                              adv_id, codecConfigObj, local_capabilities_array);
}

/*static void btbap_broadcast_iso_datapath_callback(jint big_handle, jint state) {
  ALOGI("%s", __func__);

  std::shared_lock<std::shared_timed_mutex> lock(callbacks_mutex);
  CallbackEnv sCallbackEnv(__func__);
  if (!sCallbackEnv.valid() || mCallbacksObj == nullptr) return;

  sCallbackEnv->CallVoidMethod(mCallbacksObj, method_onIsoDataPathChanged, big_handle, state);
}*/

static void btbap_broadcast_enckey_callback(std::string pin) {
  ALOGI("%s", __func__);

  std::shared_lock<std::shared_timed_mutex> lock(callbacks_mutex);
  CallbackEnv sCallbackEnv(__func__);
  if (!sCallbackEnv.valid() || mCallbacksObj == nullptr) return;
  /*ScopedLocalRef<jbyteArray> pinkey(
      sCallbackEnv.get(), sCallbackEnv->NewByteArray(sizeof(pin)));
  if (!addr.get()) {
    ALOGE("%s: Fail to new jbyteArray bd addr", __func__);
    return;
  }

  sCallbackEnv->SetByteArrayRegion(
      pinkey.get(), 0, sizeof(pin),
      reinterpret_cast<const jbyte*>(pin));*/

  sCallbackEnv->CallVoidMethod(mCallbacksObj, method_onEncryptionKeyGenerated,
                                     sCallbackEnv->NewStringUTF(pin.c_str()));
}

static void btbap_broadcast_setup_big_callback(jint setup, jint adv_id, jint big_handle,
                                       jint num_bises, std::vector<uint16_t> bis_handles) {
  ALOGI("%s", __func__);
  std::shared_lock<std::shared_timed_mutex> lock(callbacks_mutex);
  CallbackEnv sCallbackEnv(__func__);
  if (!sCallbackEnv.valid() || mCallbacksObj == nullptr) return;
  ScopedLocalRef<jcharArray> jc(sCallbackEnv.get(), sCallbackEnv->NewCharArray(bis_handles.size()));
  sCallbackEnv->SetCharArrayRegion(jc.get(), 0, bis_handles.size(), (jchar*) bis_handles.data());
  sCallbackEnv->CallVoidMethod(mCallbacksObj, method_onSetupBIG, setup, adv_id, big_handle, num_bises, jc.get());
}

static void btbap_broadcast_bid_callback(std::vector<uint8_t> broadcast_id) {
  ALOGI("%s", __func__);

  std::shared_lock<std::shared_timed_mutex> lock(callbacks_mutex);
  CallbackEnv sCallbackEnv(__func__);
  if (!sCallbackEnv.valid() || mCallbacksObj == nullptr) return;
  ALOGI("%s: broadcast_id size = %d",__func__,broadcast_id.size());
  ScopedLocalRef<jbyteArray> jb(sCallbackEnv.get(), sCallbackEnv->NewByteArray(broadcast_id.size()));
  if (!jb.get()) {
      ALOGI("%s:Failed to allocate byte array");
      return;
  }
  sCallbackEnv->SetByteArrayRegion(jb.get(), 0, broadcast_id.size(), (jbyte*) broadcast_id.data());
  sCallbackEnv->CallVoidMethod(mCallbacksObj, method_onBroadcastIdGenerated, jb.get());
}

static btbap_broadcast_callbacks_t sBluetoothBapBroadcastCallbacks = {
    sizeof(sBluetoothBapBroadcastCallbacks),
    btbap_broadcast_state_callback,
    btbap_broadcast_audio_state_callback,
    btbap_broadcast_audio_config_callback,
    //btbap_broadcast_iso_datapath_callback,
    btbap_broadcast_enckey_callback,
    btbap_broadcast_setup_big_callback,
    btbap_broadcast_bid_callback,
};

static void classInitNative(JNIEnv* env, jclass clazz) {
  jclass jniBluetoothCodecConfigClass =
      env->FindClass("android/bluetooth/BluetoothCodecConfig");
  android_bluetooth_BluetoothCodecConfig.constructor =
      env->GetMethodID(jniBluetoothCodecConfigClass, "<init>", "(IIIIIJJJJ)V");
  android_bluetooth_BluetoothCodecConfig.getCodecType =
      env->GetMethodID(jniBluetoothCodecConfigClass, "getCodecType", "()I");
  android_bluetooth_BluetoothCodecConfig.getCodecPriority =
      env->GetMethodID(jniBluetoothCodecConfigClass, "getCodecPriority", "()I");
  android_bluetooth_BluetoothCodecConfig.getSampleRate =
      env->GetMethodID(jniBluetoothCodecConfigClass, "getSampleRate", "()I");
  android_bluetooth_BluetoothCodecConfig.getBitsPerSample =
      env->GetMethodID(jniBluetoothCodecConfigClass, "getBitsPerSample", "()I");
  android_bluetooth_BluetoothCodecConfig.getChannelMode =
      env->GetMethodID(jniBluetoothCodecConfigClass, "getChannelMode", "()I");
  android_bluetooth_BluetoothCodecConfig.getCodecSpecific1 = env->GetMethodID(
      jniBluetoothCodecConfigClass, "getCodecSpecific1", "()J");
  android_bluetooth_BluetoothCodecConfig.getCodecSpecific2 = env->GetMethodID(
      jniBluetoothCodecConfigClass, "getCodecSpecific2", "()J");
  android_bluetooth_BluetoothCodecConfig.getCodecSpecific3 = env->GetMethodID(
      jniBluetoothCodecConfigClass, "getCodecSpecific3", "()J");
  android_bluetooth_BluetoothCodecConfig.getCodecSpecific4 = env->GetMethodID(
      jniBluetoothCodecConfigClass, "getCodecSpecific4", "()J");

  method_onBroadcastStateChanged =
      env->GetMethodID(clazz, "onBroadcastStateChanged", "(II)V");

  method_onAudioStateChanged =
      env->GetMethodID(clazz, "onAudioStateChanged", "(II)V");

  method_onCodecConfigChanged =
      env->GetMethodID(clazz, "onCodecConfigChanged",
                       "(ILandroid/bluetooth/BluetoothCodecConfig;"
                       "[Landroid/bluetooth/BluetoothCodecConfig;)V");

//  method_onIsoDataPathChanged =
//      env->GetMethodID(clazz, "onIsoDataPathChanged","(II)V");
  method_onEncryptionKeyGenerated =
      env->GetMethodID(clazz, "onEncryptionKeyGenerated", "(Ljava/lang/String;)V");

  method_onSetupBIG = env->GetMethodID(clazz, "onSetupBIG", "(IIII[C)V");
  method_onBroadcastIdGenerated = env->GetMethodID(clazz, "onBroadcastIdGenerated", "([B)V");

  ALOGI("%s: succeeds", __func__);
}
static btav_a2dp_codec_config_t prepare_codec_config(
              JNIEnv* env, jobject object,jobject jcodecConfig) {

  /*if (!env->IsInstanceOf(jcodecConfig,
                           android_bluetooth_BluetoothCodecConfig.clazz)) {
      ALOGE("%s: Invalid BluetoothCodecConfig instance", __func__);
      return ((btav_a2dp_codec_config_t)NULL);
  }*/
  jint codecType = env->CallIntMethod(
    jcodecConfig, android_bluetooth_BluetoothCodecConfig.getCodecType);
  jint codecPriority = env->CallIntMethod(
    jcodecConfig, android_bluetooth_BluetoothCodecConfig.getCodecPriority);
  jint sampleRate = env->CallIntMethod(
    jcodecConfig, android_bluetooth_BluetoothCodecConfig.getSampleRate);
  jint bitsPerSample = env->CallIntMethod(
    jcodecConfig, android_bluetooth_BluetoothCodecConfig.getBitsPerSample);
  jint channelMode = env->CallIntMethod(
    jcodecConfig, android_bluetooth_BluetoothCodecConfig.getChannelMode);
  jlong codecSpecific1 = env->CallLongMethod(
    jcodecConfig, android_bluetooth_BluetoothCodecConfig.getCodecSpecific1);
  jlong codecSpecific2 = env->CallLongMethod(
    jcodecConfig, android_bluetooth_BluetoothCodecConfig.getCodecSpecific2);
  jlong codecSpecific3 = env->CallLongMethod(
    jcodecConfig, android_bluetooth_BluetoothCodecConfig.getCodecSpecific3);
  jlong codecSpecific4 = env->CallLongMethod(
    jcodecConfig, android_bluetooth_BluetoothCodecConfig.getCodecSpecific4);

  btav_a2dp_codec_config_t codec_config = {
         .codec_type = static_cast<btav_a2dp_codec_index_t>(codecType),
         .codec_priority =
             static_cast<btav_a2dp_codec_priority_t>(codecPriority),
         .sample_rate = static_cast<btav_a2dp_codec_sample_rate_t>(sampleRate),
         .bits_per_sample =
             static_cast<btav_a2dp_codec_bits_per_sample_t>(bitsPerSample),
         .channel_mode =
             static_cast<btav_a2dp_codec_channel_mode_t>(channelMode),
         .codec_specific_1 = codecSpecific1,
         .codec_specific_2 = codecSpecific2,
         .codec_specific_3 = codecSpecific3,
         .codec_specific_4 = codecSpecific4};
  return codec_config;
}

static void initNative(JNIEnv* env, jobject object,
                       jint maxBroadcast, jobject codecConfig, jint mode) {
  std::unique_lock<std::shared_timed_mutex> interface_lock(interface_mutex);
  std::unique_lock<std::shared_timed_mutex> callbacks_lock(callbacks_mutex);

  const bt_interface_t* btInf = getBluetoothInterface();
  if (btInf == nullptr) {
    ALOGE("%s: Bluetooth module is not loaded", __func__);
    return;
  }

  if (sBluetoothBapBroadcastInterface != nullptr) {
    ALOGW("%s: Cleaning up BapBroadcast Interface before initializing...", __func__);
    sBluetoothBapBroadcastInterface->cleanup();
    sBluetoothBapBroadcastInterface = nullptr;
  }

  if (mCallbacksObj != nullptr) {
    ALOGW("%s: Cleaning up BapBroadcast callback object", __func__);
    env->DeleteGlobalRef(mCallbacksObj);
    mCallbacksObj = nullptr;
  }

  if ((mCallbacksObj = env->NewGlobalRef(object)) == nullptr) {
    ALOGE("%s: Failed to allocate Global Ref for bap broadcast Callbacks", __func__);
    return;
  }

  android_bluetooth_BluetoothCodecConfig.clazz = (jclass)env->NewGlobalRef(
      env->FindClass("android/bluetooth/BluetoothCodecConfig"));
  if (android_bluetooth_BluetoothCodecConfig.clazz == nullptr) {
    ALOGE("%s: Failed to allocate Global Ref for BluetoothCodecConfig class",
          __func__);
    return;
  }

  sBluetoothBapBroadcastInterface =
      (btbap_broadcast_interface_t*)btInf->get_profile_interface(
          BT_PROFILE_BAP_BROADCAST_ID);
  if (sBluetoothBapBroadcastInterface == nullptr) {
    ALOGE("%s: Failed to get Bluetooth BapBroadcast Interface", __func__);
    return;
  }
  btav_a2dp_codec_config_t codec_config =
                 prepare_codec_config(env, object, codecConfig);
  /*if (codec_config == NULL) {
    ALOGE("%s:Invalid codec config",__func__);
    return;
  }*/
  bt_status_t status = sBluetoothBapBroadcastInterface->init(
      &sBluetoothBapBroadcastCallbacks, maxBroadcast, codec_config, mode);
  if (status != BT_STATUS_SUCCESS) {
    ALOGE("%s: Failed to initialize Bluetooth A2DP, status: %d", __func__,
          status);
    sBluetoothBapBroadcastInterface = nullptr;
    return;
  }
}

static void cleanupNative(JNIEnv* env, jobject object) {
  std::unique_lock<std::shared_timed_mutex> interface_lock(interface_mutex);
  std::unique_lock<std::shared_timed_mutex> callbacks_lock(callbacks_mutex);

  const bt_interface_t* btInf = getBluetoothInterface();
  if (btInf == nullptr) {
    ALOGE("%s: Bluetooth module is not loaded", __func__);
    return;
  }

  if (sBluetoothBapBroadcastInterface != nullptr) {
    sBluetoothBapBroadcastInterface->cleanup();
    sBluetoothBapBroadcastInterface = nullptr;
  }

  env->DeleteGlobalRef(android_bluetooth_BluetoothCodecConfig.clazz);
  android_bluetooth_BluetoothCodecConfig.clazz = nullptr;

  if (mCallbacksObj != nullptr) {
    env->DeleteGlobalRef(mCallbacksObj);
    mCallbacksObj = nullptr;
  }
}

static jboolean setActiveDeviceNative(JNIEnv* env, jobject object,
                                         jboolean enable, jint adv_id) {
  ALOGI("%s: sBluetoothBapBroadcastInterface: %p", __func__, sBluetoothBapBroadcastInterface);
  std::shared_lock<std::shared_timed_mutex> lock(interface_mutex);
  if (!sBluetoothBapBroadcastInterface) {
    ALOGE("%s: Failed to get the BapBroadcast Interface", __func__);
    return JNI_FALSE;
  }
  bt_status_t status = sBluetoothBapBroadcastInterface->set_broadcast_active(enable, adv_id);
  return (status == BT_STATUS_SUCCESS) ? JNI_TRUE : JNI_FALSE;
}

static jboolean enableBroadcastNative(JNIEnv* env, jobject object, jobject codecConfig) {
  ALOGI("%s: sBluetoothBapBroadcastInterface: %p", __func__, sBluetoothBapBroadcastInterface);
  btav_a2dp_codec_config_t codec_config =
               prepare_codec_config(env, object, codecConfig);
  std::shared_lock<std::shared_timed_mutex> lock(interface_mutex);
  if (!sBluetoothBapBroadcastInterface) {
    ALOGE("%s: Failed to get the BapBroadcast Interface", __func__);
    return JNI_FALSE;
  }
  bt_status_t status = sBluetoothBapBroadcastInterface->enable_broadcast(codec_config);
  return (status == BT_STATUS_SUCCESS) ? JNI_TRUE : JNI_FALSE;
}

static jboolean disableBroadcastNative(JNIEnv* env, jobject object, jint adv_id) {
  ALOGI("%s: sBluetoothBapBroadcastInterface: %p", __func__, sBluetoothBapBroadcastInterface);
  std::shared_lock<std::shared_timed_mutex> lock(interface_mutex);
  if (!sBluetoothBapBroadcastInterface) {
    ALOGE("%s: Failed to get the BapBroadcast Interface", __func__);
    return JNI_FALSE;
  }
  bt_status_t status = sBluetoothBapBroadcastInterface->disable_broadcast(adv_id);
  return (status == BT_STATUS_SUCCESS) ? JNI_TRUE : JNI_FALSE;
}

static jboolean setupAudioPathNative(JNIEnv* env, jobject object, jboolean enable,jint adv_id,
                                               jint big_handle, jint num_bises, jintArray bises) {
  ALOGI("%s: sBluetoothBapBroadcastInterface: %p", __func__, sBluetoothBapBroadcastInterface);
  std::shared_lock<std::shared_timed_mutex> lock(interface_mutex);
  if (!sBluetoothBapBroadcastInterface) {
    ALOGE("%s: Failed to get the BapBroadcast Interface", __func__);
    return JNI_FALSE;
  }
  jint* bis_handles = env->GetIntArrayElements(bises, NULL);
  bt_status_t status = sBluetoothBapBroadcastInterface->setup_audiopath(enable, adv_id, big_handle, num_bises, bis_handles);
  return (status == BT_STATUS_SUCCESS) ? JNI_TRUE : JNI_FALSE;
}

static jstring getEncryptionKeyNative(JNIEnv* env, jobject object) {
  ALOGI("%s: sBluetoothBapBroadcastInterface: %p", __func__, sBluetoothBapBroadcastInterface);
  std::shared_lock<std::shared_timed_mutex> lock(interface_mutex);
  if (!sBluetoothBapBroadcastInterface) {
    ALOGE("%s: Failed to get the BapBroadcast Interface", __func__);
    return JNI_FALSE;
  }
  std::string stdstr = sBluetoothBapBroadcastInterface->get_encryption_key();
  return env->NewStringUTF(stdstr.c_str());
}

static jboolean setEncryptionKeyNative(JNIEnv* env, jobject object, jboolean enabled, jint length) {
  ALOGI("%s: sBluetoothBapBroadcastInterface: %p", __func__, sBluetoothBapBroadcastInterface);
  std::shared_lock<std::shared_timed_mutex> lock(interface_mutex);
  if (!sBluetoothBapBroadcastInterface) {
    ALOGE("%s: Failed to get the BapBroadcast Interface", __func__);
    return JNI_FALSE;
  }
  bt_status_t status = sBluetoothBapBroadcastInterface->set_encryption(enabled, length);
  return (status == BT_STATUS_SUCCESS) ? JNI_TRUE : JNI_FALSE;
}

static jboolean setCodecConfigPreferenceNative(JNIEnv* env, jobject object,
                                                       jint adv_handle, jobject codecConfig) {
  ALOGI("%s: sBluetoothBapBroadcastInterface: %p", __func__, sBluetoothBapBroadcastInterface);
  std::shared_lock<std::shared_timed_mutex> lock(interface_mutex);
  if (!sBluetoothBapBroadcastInterface) {
    ALOGE("%s: Failed to get the BapBroadcast Interface", __func__);
    return JNI_FALSE;
  }
  btav_a2dp_codec_config_t codec_config =
               prepare_codec_config(env, object, codecConfig);
  bt_status_t status = sBluetoothBapBroadcastInterface->codec_config_change(adv_handle, codec_config);
  return (status == BT_STATUS_SUCCESS) ? JNI_TRUE : JNI_FALSE;
}

static JNINativeMethod sMethods[] = {
    {"classInitNative", "()V", (void*)classInitNative},
    {"initNative", "(ILandroid/bluetooth/BluetoothCodecConfig;I)V",
     (void*)initNative},
    {"cleanupNative", "()V", (void*)cleanupNative},
    {"setActiveDeviceNative", "(ZI)Z", (void*)setActiveDeviceNative},
    {"enableBroadcastNative", "(Landroid/bluetooth/BluetoothCodecConfig;)Z", (void*)enableBroadcastNative},
    {"disableBroadcastNative", "(I)Z", (void*)disableBroadcastNative},
    {"getEncryptionKeyNative", "()Ljava/lang/String;", (void*)getEncryptionKeyNative},
    {"setEncryptionKeyNative", "(ZI)Z", (void*)setEncryptionKeyNative},
    {"setupAudioPathNative", "(ZIII[I)Z", (void*)setupAudioPathNative},
    {"setCodecConfigPreferenceNative",
     "(ILandroid/bluetooth/BluetoothCodecConfig;)Z",
     (void*)setCodecConfigPreferenceNative},
};

int register_com_android_bluetooth_bap_broadcast(JNIEnv* env) {
  return jniRegisterNativeMethods(
      env, "com/android/bluetooth/broadcast/BroadcastNativeInterface", sMethods,
      NELEM(sMethods));
}

}
