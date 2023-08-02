/*
 * Copyright 2020 The Android Open Source Project
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

#define LOG_TAG "BluetoothActivityAttributionJni"

#include <string.h>

#include <shared_mutex>

#include "base/logging.h"
#include "com_android_bluetooth.h"
#include "hardware/bt_activity_attribution.h"

using bluetooth::activity_attribution::ActivityAttributionInterface;

namespace android {
static ActivityAttributionInterface* sActivityAttributionInterface = nullptr;

static void notifyActivityAttributionInfoNative(JNIEnv* env, jobject object,
                                                jint uid, jstring packageName,
                                                jstring deviceAddress) {
  const bt_interface_t* btInf = getBluetoothInterface();
  if (btInf == nullptr) {
    LOG(ERROR) << "Bluetooth module is not loaded";
    return;
  }
  sActivityAttributionInterface =
      (ActivityAttributionInterface*)btInf->get_profile_interface(
          BT_ACTIVITY_ATTRIBUTION_ID);
  if (sActivityAttributionInterface == nullptr) {
    LOG(ERROR) << "Failed to get ActivityAttribution Interface";
    return;
  }

  if (packageName == nullptr || deviceAddress == nullptr) {
    LOG(ERROR) << "Failed to get package name or device address";
    return;
  }
  const char* nativeName = env->GetStringUTFChars(packageName, nullptr);
  const char* nativeAddress = env->GetStringUTFChars(deviceAddress, nullptr);
  sActivityAttributionInterface->NotifyActivityAttributionInfo(uid, nativeName,
                                                               nativeAddress);
  env->ReleaseStringUTFChars(packageName, nativeName);
  env->ReleaseStringUTFChars(deviceAddress, nativeAddress);
}

static JNINativeMethod sMethods[] = {
    {"notifyActivityAttributionInfoNative",
     "(ILjava/lang/String;Ljava/lang/String;)V",
     (void*)notifyActivityAttributionInfoNative},
};

int register_com_android_bluetooth_btservice_activity_attribution(JNIEnv* env) {
  return jniRegisterNativeMethods(
      env,
      "com/android/bluetooth/btservice/activityattribution/"
      "ActivityAttributionNativeInterface",
      sMethods, NELEM(sMethods));
}

}  // namespace android
