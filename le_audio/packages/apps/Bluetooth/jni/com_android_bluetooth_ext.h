/******************************************************************************
 *
 *  Copyright 2021 The Android Open Source Project
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at:
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 ******************************************************************************/

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

