/******************************************************************************
 *  Copyright (c) 2020, The Linux Foundation. All rights reserved.
 *****************************************************************************/
#ifndef COM_ANDROID_BLUETOOTH_EXT
#define COM_ANDROID_BLUETOOTH_EXT

namespace android {

int register_com_android_bluetooth_bap_broadcast(JNIEnv* env);

int register_com_android_bluetooth_acm(JNIEnv* env);

int register_com_android_bluetooth_apm(JNIEnv* env);

int register_com_android_bluetooth_csip_client(JNIEnv* env);

int register_com_android_bluetooth_adv_audio_profiles(JNIEnv* env);

int register_com_android_bluetooth_vcp_controller(JNIEnv* env);

int register_com_android_bluetooth_pacs_client(JNIEnv* env);

int register_com_android_bluetooth_mcp(JNIEnv* env);

int register_com_android_bluetooth_call_controller(JNIEnv* env);
}

#endif

