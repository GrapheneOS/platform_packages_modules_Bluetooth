/******************************************************************************
 *  Copyright (c) 2020, The Linux Foundation. All rights reserved.
 *
 *****************************************************************************/

#define LOG_TAG "BluetoothAcmServiceJni"

#define LOG_NDEBUG 0

#include "android_runtime/AndroidRuntime.h"
#include "com_android_bluetooth.h"
#include "hardware/bt_acm.h"
#include "utils/Log.h"

#include <string.h>
#include <shared_mutex>

using bluetooth::bap::pacs::CodecIndex;
using bluetooth::bap::pacs::CodecPriority;
using bluetooth::bap::pacs::CodecSampleRate;
using bluetooth::bap::pacs::CodecBPS;
using bluetooth::bap::pacs::CodecChannelMode;

namespace android {
static jmethodID method_onConnectionStateChanged;
static jmethodID method_onAudioStateChanged;
static jmethodID method_onCodecConfigChanged;

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

static const btacm_initiator_interface_t* sBluetoothAcmInterface = nullptr;
static std::shared_timed_mutex interface_mutex;

static jobject mCallbacksObj = nullptr;
static std::shared_timed_mutex callbacks_mutex;

static void btacm_connection_state_callback(const RawAddress& bd_addr,
                                            btacm_connection_state_t state, uint16_t contextType) {
  ALOGI("%s", __func__);

  std::shared_lock<std::shared_timed_mutex> lock(callbacks_mutex);
  CallbackEnv sCallbackEnv(__func__);
  if (!sCallbackEnv.valid() || mCallbacksObj == nullptr) return;

  ScopedLocalRef<jbyteArray> addr(
      sCallbackEnv.get(), sCallbackEnv->NewByteArray(sizeof(RawAddress)));
  if (!addr.get()) {
    ALOGE("%s: Fail to new jbyteArray bd addr", __func__);
    return;
  }

  sCallbackEnv->SetByteArrayRegion(
      addr.get(), 0, sizeof(RawAddress),
      reinterpret_cast<const jbyte*>(bd_addr.address));
  sCallbackEnv->CallVoidMethod(mCallbacksObj, method_onConnectionStateChanged,
                               addr.get(), (jint)state, (jint)contextType);
}

static void btacm_audio_state_callback(const RawAddress& bd_addr,
                                       btacm_audio_state_t state, uint16_t contextType) {
  ALOGI("%s", __func__);

  std::shared_lock<std::shared_timed_mutex> lock(callbacks_mutex);
  CallbackEnv sCallbackEnv(__func__);
  if (!sCallbackEnv.valid() || mCallbacksObj == nullptr) return;

  ScopedLocalRef<jbyteArray> addr(
      sCallbackEnv.get(), sCallbackEnv->NewByteArray(sizeof(RawAddress)));
  if (!addr.get()) {
    ALOGE("%s: Fail to new jbyteArray bd addr", __func__);
    return;
  }

  sCallbackEnv->SetByteArrayRegion(
      addr.get(), 0, sizeof(RawAddress),
      reinterpret_cast<const jbyte*>(bd_addr.address));
  sCallbackEnv->CallVoidMethod(mCallbacksObj, method_onAudioStateChanged,
                               addr.get(), (jint)state, (jint)contextType);
}

static void btacm_audio_config_callback(
    const RawAddress& bd_addr, CodecConfig codec_config,
    std::vector<CodecConfig> codecs_local_capabilities,
    std::vector<CodecConfig> codecs_selectable_capabilities, uint16_t contextType) {
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
      (jsize)codecs_local_capabilities.size(),
      android_bluetooth_BluetoothCodecConfig.clazz, nullptr);
  for (auto const& cap : codecs_local_capabilities) {
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

  i = 0;
  jobjectArray selectable_capabilities_array = sCallbackEnv->NewObjectArray(
      (jsize)codecs_selectable_capabilities.size(),
      android_bluetooth_BluetoothCodecConfig.clazz, nullptr);
  for (auto const& cap : codecs_selectable_capabilities) {
    jobject capObj = sCallbackEnv->NewObject(
        android_bluetooth_BluetoothCodecConfig.clazz,
        android_bluetooth_BluetoothCodecConfig.constructor,
        (jint)cap.codec_type, (jint)cap.codec_priority, (jint)cap.sample_rate,
        (jint)cap.bits_per_sample, (jint)cap.channel_mode,
        (jlong)cap.codec_specific_1, (jlong)cap.codec_specific_2,
        (jlong)cap.codec_specific_3, (jlong)cap.codec_specific_4);
    sCallbackEnv->SetObjectArrayElement(selectable_capabilities_array, i++,
                                        capObj);
    sCallbackEnv->DeleteLocalRef(capObj);
  }

  ScopedLocalRef<jbyteArray> addr(
      sCallbackEnv.get(), sCallbackEnv->NewByteArray(RawAddress::kLength));
  if (!addr.get()) {
    ALOGE("%s: Fail to new jbyteArray bd addr", __func__);
    return;
  }
  sCallbackEnv->SetByteArrayRegion(
      addr.get(), 0, RawAddress::kLength,
      reinterpret_cast<const jbyte*>(bd_addr.address));

  sCallbackEnv->CallVoidMethod(
      mCallbacksObj, method_onCodecConfigChanged, addr.get(), codecConfigObj,
      local_capabilities_array, selectable_capabilities_array, (jint)contextType);
}

static btacm_initiator_callbacks_t sBluetoothAcmCallbacks = {
    sizeof(sBluetoothAcmCallbacks),
    btacm_connection_state_callback,
    btacm_audio_state_callback,
    btacm_audio_config_callback
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

  method_onConnectionStateChanged =
      env->GetMethodID(clazz, "onConnectionStateChanged", "([BII)V");

  method_onAudioStateChanged =
      env->GetMethodID(clazz, "onAudioStateChanged", "([BII)V");

  method_onCodecConfigChanged =
      env->GetMethodID(clazz, "onCodecConfigChanged",
                       "([BLandroid/bluetooth/BluetoothCodecConfig;"
                       "[Landroid/bluetooth/BluetoothCodecConfig;"
                       "[Landroid/bluetooth/BluetoothCodecConfig;I)V");

  ALOGI("%s: succeeds", __func__);
}

static std::vector<CodecConfig> prepareCodecPreferences(
    JNIEnv* env, jobject object, jobjectArray codecConfigArray) {
  std::vector<CodecConfig> codec_preferences;

  int numConfigs = env->GetArrayLength(codecConfigArray);
  for (int i = 0; i < numConfigs; i++) {
    jobject jcodecConfig = env->GetObjectArrayElement(codecConfigArray, i);
    if (jcodecConfig == nullptr) continue;
    if (!env->IsInstanceOf(jcodecConfig,
                           android_bluetooth_BluetoothCodecConfig.clazz)) {
      ALOGE("%s: Invalid BluetoothCodecConfig instance", __func__);
      continue;
    }
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

    CodecConfig codec_config = {
        .codec_type = static_cast<CodecIndex>(codecType),
        .codec_priority =
            static_cast<CodecPriority>(codecPriority),
        .sample_rate = static_cast<CodecSampleRate>(sampleRate),
        .bits_per_sample =
            static_cast<CodecBPS>(bitsPerSample),
        .channel_mode =
            static_cast<CodecChannelMode>(channelMode),
        .codec_specific_1 = codecSpecific1,
        .codec_specific_2 = codecSpecific2,
        .codec_specific_3 = codecSpecific3,
        .codec_specific_4 = codecSpecific4};

    codec_preferences.push_back(codec_config);
  }
  return codec_preferences;
}

static void initNative(JNIEnv* env, jobject object,
                            jint maxConnectedAudioDevices,
                            jobjectArray codecConfigArray) {
  std::unique_lock<std::shared_timed_mutex> interface_lock(interface_mutex);
  std::unique_lock<std::shared_timed_mutex> callbacks_lock(callbacks_mutex);

  const bt_interface_t* btInf = getBluetoothInterface();
  if (btInf == nullptr) {
    ALOGE("%s: Bluetooth module is not loaded", __func__);
    return;
  }

  if (sBluetoothAcmInterface != nullptr) {
    ALOGW("%s: Cleaning up ACM Interface before initializing...", __func__);
    sBluetoothAcmInterface->cleanup();
    sBluetoothAcmInterface = nullptr;
  }

  if (mCallbacksObj != nullptr) {
    ALOGW("%s: Cleaning up ACM callback object", __func__);
    env->DeleteGlobalRef(mCallbacksObj);
    mCallbacksObj = nullptr;
  }

  if ((mCallbacksObj = env->NewGlobalRef(object)) == nullptr) {
    ALOGE("%s: Failed to allocate Global Ref for ACM Callbacks", __func__);
    return;
  }

  android_bluetooth_BluetoothCodecConfig.clazz = (jclass)env->NewGlobalRef(
      env->FindClass("android/bluetooth/BluetoothCodecConfig"));
  if (android_bluetooth_BluetoothCodecConfig.clazz == nullptr) {
    ALOGE("%s: Failed to allocate Global Ref for BluetoothCodecConfig class",
          __func__);
    return;
  }

  sBluetoothAcmInterface =
      (btacm_initiator_interface_t*)btInf->get_profile_interface(
          BT_PROFILE_ACM_ID);
  if (sBluetoothAcmInterface == nullptr) {
    ALOGE("%s: Failed to get Bluetooth ACM Interface", __func__);
    return;
  }

  std::vector<CodecConfig> codec_priorities =
      prepareCodecPreferences(env, object, codecConfigArray);

  bt_status_t status = sBluetoothAcmInterface->init(
      &sBluetoothAcmCallbacks, maxConnectedAudioDevices, codec_priorities);
  if (status != BT_STATUS_SUCCESS) {
    ALOGE("%s: Failed to initialize Bluetooth ACM, status: %d", __func__,
          status);
    sBluetoothAcmInterface = nullptr;
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

  if (sBluetoothAcmInterface != nullptr) {
    sBluetoothAcmInterface->cleanup();
    sBluetoothAcmInterface = nullptr;
  }

  env->DeleteGlobalRef(android_bluetooth_BluetoothCodecConfig.clazz);
  android_bluetooth_BluetoothCodecConfig.clazz = nullptr;

  if (mCallbacksObj != nullptr) {
    env->DeleteGlobalRef(mCallbacksObj);
    mCallbacksObj = nullptr;
  }
}

static jboolean connectAcmNative(JNIEnv* env, jobject object,
                                         jbyteArray address, jint contextType,
                                         jint profileType, jint preferredContext) {
  ALOGI("%s: sBluetoothAcmInterface: %p", __func__, sBluetoothAcmInterface);
  std::shared_lock<std::shared_timed_mutex> lock(interface_mutex);
  if (!sBluetoothAcmInterface) {
    ALOGE("%s: Failed to get the Bluetooth ACM Interface", __func__);
    return JNI_FALSE;
  }

  jbyte* addr = env->GetByteArrayElements(address, nullptr);
  if (!addr) {
    jniThrowIOException(env, EINVAL);
    return JNI_FALSE;
  }

  RawAddress bd_addr;
  bd_addr.FromOctets(reinterpret_cast<const uint8_t*>(addr));
  bt_status_t status = sBluetoothAcmInterface->connect(bd_addr, contextType,
                                                       profileType, preferredContext);
  if (status != BT_STATUS_SUCCESS) {
    ALOGE("%s: Failed ACM connection, status: %d", __func__, status);
  }
  env->ReleaseByteArrayElements(address, addr, 0);
  return (status == BT_STATUS_SUCCESS) ? JNI_TRUE : JNI_FALSE;
}

static jboolean disconnectAcmNative(JNIEnv* env, jobject object,
                                             jbyteArray address, jint contextType) {
  ALOGI("%s: sBluetoothAcmInterface: %p", __func__, sBluetoothAcmInterface);
  std::shared_lock<std::shared_timed_mutex> lock(interface_mutex);
  if (!sBluetoothAcmInterface) {
    ALOGE("%s: Failed to get the Bluetooth ACM Interface", __func__);
    return JNI_FALSE;
  }

  jbyte* addr = env->GetByteArrayElements(address, nullptr);
  if (!addr) {
    jniThrowIOException(env, EINVAL);
    return JNI_FALSE;
  }

  RawAddress bd_addr;
  bd_addr.FromOctets(reinterpret_cast<const uint8_t*>(addr));
  bt_status_t status = sBluetoothAcmInterface->disconnect(bd_addr, contextType);
  if (status != BT_STATUS_SUCCESS) {
    ALOGE("%s: Failed ACM disconnection, status: %d", __func__, status);
  }
  env->ReleaseByteArrayElements(address, addr, 0);
  return (status == BT_STATUS_SUCCESS) ? JNI_TRUE : JNI_FALSE;
}

static jboolean startStreamNative(JNIEnv* env, jobject object,
                                          jbyteArray address, jint contextType) {
  ALOGI("%s: sBluetoothAcmInterface: %p", __func__, sBluetoothAcmInterface);
  std::shared_lock<std::shared_timed_mutex> lock(interface_mutex);
  if (!sBluetoothAcmInterface) {
    ALOGE("%s: Failed to get the Bluetooth ACM Interface", __func__);
    return JNI_FALSE;
  }

  jbyte* addr = env->GetByteArrayElements(address, nullptr);

  RawAddress bd_addr = RawAddress::kEmpty;
  if (addr) {
    bd_addr.FromOctets(reinterpret_cast<const uint8_t*>(addr));
  }
  bt_status_t status = sBluetoothAcmInterface->start_stream(bd_addr, contextType);
  if (status != BT_STATUS_SUCCESS) {
    ALOGE("%s: Failed ACM set_active_device, status: %d", __func__, status);
  }
  env->ReleaseByteArrayElements(address, addr, 0);
  return (status == BT_STATUS_SUCCESS) ? JNI_TRUE : JNI_FALSE;
}

static jboolean stopStreamNative(JNIEnv* env, jobject object,
                                         jbyteArray address, jint contextType) {
  ALOGI("%s: sBluetoothAcmInterface: %p", __func__, sBluetoothAcmInterface);
  std::shared_lock<std::shared_timed_mutex> lock(interface_mutex);
  if (!sBluetoothAcmInterface) {
    ALOGE("%s: Failed to get the Bluetooth ACM Interface", __func__);
    return JNI_FALSE;
  }

  jbyte* addr = env->GetByteArrayElements(address, nullptr);

  RawAddress bd_addr = RawAddress::kEmpty;
  if (addr) {
    bd_addr.FromOctets(reinterpret_cast<const uint8_t*>(addr));
  }
  bt_status_t status = sBluetoothAcmInterface->stop_stream(bd_addr, contextType);
  if (status != BT_STATUS_SUCCESS) {
    ALOGE("%s: Failed ACM set_active_device, status: %d", __func__, status);
  }
  env->ReleaseByteArrayElements(address, addr, 0);
  return (status == BT_STATUS_SUCCESS) ? JNI_TRUE : JNI_FALSE;
}

static jboolean setActiveDeviceNative(JNIEnv* env, jobject object,
                                      jbyteArray address, jint contextType) {
  ALOGI("%s: sBluetoothAcmInterface: %p", __func__, sBluetoothAcmInterface);
  std::shared_lock<std::shared_timed_mutex> lock(interface_mutex);
  if (!sBluetoothAcmInterface) {
    ALOGE("%s: Failed to get the Bluetooth ACM Interface", __func__);
    return JNI_FALSE;
  }

  jbyte* addr = env->GetByteArrayElements(address, nullptr);

  RawAddress bd_addr = RawAddress::kEmpty;
  if (addr) {
    bd_addr.FromOctets(reinterpret_cast<const uint8_t*>(addr));
  }
  bt_status_t status = sBluetoothAcmInterface->set_active_device(bd_addr, contextType);
  if (status != BT_STATUS_SUCCESS) {
    ALOGE("%s: Failed ACM set_active_device, status: %d", __func__, status);
  }
  env->ReleaseByteArrayElements(address, addr, 0);
  return (status == BT_STATUS_SUCCESS) ? JNI_TRUE : JNI_FALSE;
}

static jboolean setCodecConfigPreferenceNative(JNIEnv* env, jobject object,
                                                              jbyteArray address,
                                                              jobjectArray codecConfigArray,
                                                              jint contextType, jint preferredContext) {
  ALOGI("%s: sBluetoothAcmInterface: %p", __func__, sBluetoothAcmInterface);
  std::shared_lock<std::shared_timed_mutex> lock(interface_mutex);
  if (!sBluetoothAcmInterface) {
    ALOGE("%s: Failed to get the Bluetooth ACM Interface", __func__);
    return JNI_FALSE;
  }

  jbyte* addr = env->GetByteArrayElements(address, nullptr);
  if (!addr) {
    jniThrowIOException(env, EINVAL);
    return JNI_FALSE;
  }

  RawAddress bd_addr;
  bd_addr.FromOctets(reinterpret_cast<const uint8_t*>(addr));
  std::vector<CodecConfig> codec_preferences =
      prepareCodecPreferences(env, object, codecConfigArray);

  bt_status_t status =
      sBluetoothAcmInterface->config_codec(bd_addr, codec_preferences, contextType, preferredContext);
  if (status != BT_STATUS_SUCCESS) {
    ALOGE("%s: Failed codec configuration, status: %d", __func__, status);
  }
  env->ReleaseByteArrayElements(address, addr, 0);
  return (status == BT_STATUS_SUCCESS) ? JNI_TRUE : JNI_FALSE;
}

static jboolean ChangeCodecConfigPreferenceNative(JNIEnv* env, jobject object,
                                                  jbyteArray address,
                                                  jstring message) {
  ALOGI("%s: sBluetoothAcmInterface: %p", __func__, sBluetoothAcmInterface);
  std::shared_lock<std::shared_timed_mutex> lock(interface_mutex);
  if (!sBluetoothAcmInterface) {
    ALOGE("%s: Failed to get the Bluetooth ACM Interface", __func__);
    return JNI_FALSE;
  }

  jbyte* addr = env->GetByteArrayElements(address, nullptr);
  if (!addr) {
    jniThrowIOException(env, EINVAL);
    return JNI_FALSE;
  }

  RawAddress bd_addr;
  bd_addr.FromOctets(reinterpret_cast<const uint8_t*>(addr));
  const char* c_msg = env->GetStringUTFChars(message, NULL);
  bt_status_t status =
      sBluetoothAcmInterface->change_config_codec(bd_addr, (char*)c_msg);
  if (status != BT_STATUS_SUCCESS) {
    ALOGE("%s: Failed codec configuration, status: %d", __func__, status);
  }
  env->ReleaseByteArrayElements(address, addr, 0);
  return (status == BT_STATUS_SUCCESS) ? JNI_TRUE : JNI_FALSE;
}

static JNINativeMethod sMethods[] = {
    {"classInitNative", "()V", (void*)classInitNative},
    {"initNative", "(I[Landroid/bluetooth/BluetoothCodecConfig;)V",
     (void*)initNative},
    {"cleanupNative", "()V", (void*)cleanupNative},
    {"connectAcmNative", "([BIII)Z", (void*)connectAcmNative},
    {"disconnectAcmNative", "([BI)Z", (void*)disconnectAcmNative},
    {"startStreamNative", "([BI)Z", (void*)startStreamNative},
    {"stopStreamNative", "([BI)Z", (void*)stopStreamNative},
    {"setActiveDeviceNative", "([BI)Z", (void*)setActiveDeviceNative},
    {"setCodecConfigPreferenceNative",
     "([B[Landroid/bluetooth/BluetoothCodecConfig;II)Z",
     (void*)setCodecConfigPreferenceNative},
    {"ChangeCodecConfigPreferenceNative",
     "([BLjava/lang/String;)Z",
     (void*)ChangeCodecConfigPreferenceNative},
};

int register_com_android_bluetooth_acm(JNIEnv* env) {
  return jniRegisterNativeMethods(
      env, "com/android/bluetooth/acm/AcmNativeInterface", sMethods,
      NELEM(sMethods));
}
}
