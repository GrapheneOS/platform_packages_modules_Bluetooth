/******************************************************************************
 *  Copyright (c) 2020, The Linux Foundation. All rights reserved.
 *
 *****************************************************************************/

#include "android_runtime/AndroidRuntime.h"
#include "com_android_bluetooth_ext.h"

namespace android {

  int register_com_android_bluetooth_adv_audio_profiles(JNIEnv* env) {
    ALOGE("%s", __func__);

    int status = android::register_com_android_bluetooth_csip_client(env);
    if (status < 0) {
      ALOGE("jni csip registration failure: %d", status);
      return JNI_ERR;
    }

    status = android::register_com_android_bluetooth_acm(env);
    if (status < 0) {
      ALOGE("jni acm registration failure: %d", status);
      return JNI_ERR;
    }

    status = android::register_com_android_bluetooth_apm(env);
    if (status < 0) {
      ALOGE("jni APM registration failure: %d", status);
      return JNI_ERR;
    }

    status = android::register_com_android_bluetooth_bap_broadcast(env);
    if (status < 0) {
      ALOGE("jni bap broadcast registration failure: %d", status);
      return JNI_ERR;
    }

    status = android::register_com_android_bluetooth_vcp_controller(env);
    if (status < 0) {
      ALOGE("jni vcp controller registration failure: %d", status);
      return JNI_ERR;
    }

    status = android::register_com_android_bluetooth_pacs_client(env);
    if (status < 0) {
      ALOGE("jni pacs client registration failure: %d", status);
      return JNI_ERR;
    }
    status = android::register_com_android_bluetooth_call_controller(env);
    if (status < 0) {
      ALOGE("jni CC registration failure: %d", status);
      return JNI_ERR;
    }

    status = android::register_com_android_bluetooth_mcp(env);
    if (status < 0) {
      ALOGE("jni mcp registration failure: %d", status);
      return JNI_ERR;
    }
    return JNI_VERSION_1_6;
  }
}
