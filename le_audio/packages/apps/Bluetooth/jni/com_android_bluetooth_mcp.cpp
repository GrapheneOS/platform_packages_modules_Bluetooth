/******************************************************************************
 *  Copyright (c) 2020-2021, The Linux Foundation. All rights reserved.
 *
 *****************************************************************************/

#define LOG_TAG "BluetoothMCPService_jni"

#define LOG_NDEBUG 0

#include <base/bind.h>
#include <base/callback.h>
#include <map>
#include <mutex>
#include <shared_mutex>
#include <vector>


#include "android_runtime/AndroidRuntime.h"
#include "base/logging.h"
#include "com_android_bluetooth.h"
#include "hardware/bt_mcp.h"
#include "hardware/bluetooth.h"



using bluetooth::mcp_server::McpServerCallbacks;
using bluetooth::mcp_server::McpServerInterface;
using bluetooth::Uuid;
static McpServerInterface* sMcpServerInterface = nullptr;


namespace android {
static jmethodID method_OnConnectionStateChanged;
static jmethodID method_MediaControlPointChangedRequest;
static jmethodID method_TrackPositionChangedRequest;
static jmethodID method_PlayingOrderChangedRequest;


static std::shared_timed_mutex interface_mutex;

static jobject mCallbacksObj = nullptr;
static std::shared_timed_mutex callbacks_mutex;

class McpServerCallbacksImpl : public McpServerCallbacks {
   public:
  ~McpServerCallbacksImpl() = default;

  void OnConnectionStateChange(int state, const RawAddress& bd_addr) override {
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
    sCallbackEnv->CallVoidMethod(mCallbacksObj, method_OnConnectionStateChanged,
                                 (jint)state, addr.get());
  }


  void MediaControlPointChangeReq(uint8_t state, const RawAddress& bd_addr) override {
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
    sCallbackEnv->CallVoidMethod(mCallbacksObj, method_MediaControlPointChangedRequest,
                                 (jint)state, addr.get());
  }

  void TrackPositionChangeReq(int32_t position) override {
    LOG(INFO) << __func__;

    std::shared_lock<std::shared_timed_mutex> lock(callbacks_mutex);
    CallbackEnv sCallbackEnv(__func__);
    if (!sCallbackEnv.valid() || mCallbacksObj == nullptr) return;

    sCallbackEnv->CallVoidMethod(mCallbacksObj, method_TrackPositionChangedRequest,
                                 (jint)position);
  }

  void PlayingOrderChangeReq(uint32_t order) override {
    LOG(INFO) << __func__;

    std::shared_lock<std::shared_timed_mutex> lock(callbacks_mutex);
    CallbackEnv sCallbackEnv(__func__);
    if (!sCallbackEnv.valid() || mCallbacksObj == nullptr) return;

    sCallbackEnv->CallVoidMethod(mCallbacksObj, method_PlayingOrderChangedRequest,
                                 (jint)order);
  }
};


static McpServerCallbacksImpl sMcpServerCallbacks;

static void classInitNative(JNIEnv* env, jclass clazz) {
  LOG(INFO) << __func__ << ": class init native";
  method_OnConnectionStateChanged =
      env->GetMethodID(clazz, "OnConnectionStateChanged", "(I[B)V");
  LOG(INFO) << __func__ << ": class init native 1";
  method_MediaControlPointChangedRequest =
      env->GetMethodID(clazz, "MediaControlPointChangedRequest", "(I[B)V");
  LOG(INFO) << __func__ << ": class init native 2";
  method_TrackPositionChangedRequest =
      env->GetMethodID(clazz, "TrackPositionChangedRequest", "(I)V");
  method_PlayingOrderChangedRequest =
      env->GetMethodID(clazz, "PlayingOrderChangedRequest", "(I)V");

  LOG(INFO) << __func__ << ": succeeds";
}

//<TBD> uuid not fixed
Uuid uuid = Uuid::FromString("00008fd1-0000-1000-8000-00805F9B34FB");

static void initNative(JNIEnv* env, jobject object) {
  std::unique_lock<std::shared_timed_mutex> interface_lock(interface_mutex);
  std::unique_lock<std::shared_timed_mutex> callbacks_lock(callbacks_mutex);

  const bt_interface_t* btInf = getBluetoothInterface();
  if (btInf == nullptr) {
    LOG(ERROR) << "Bluetooth module is not loaded";
    return;
  }

  if (sMcpServerInterface != nullptr) {
    LOG(INFO) << "Cleaning up McpServer Interface before initializing...";
    sMcpServerInterface->Cleanup();
    sMcpServerInterface = nullptr;
  }

  if (mCallbacksObj != nullptr) {
    LOG(INFO) << "Cleaning up McpServer callback object";
    env->DeleteGlobalRef(mCallbacksObj);
    mCallbacksObj = nullptr;
  }

  if ((mCallbacksObj = env->NewGlobalRef(object)) == nullptr) {
    LOG(ERROR) << "Failed to allocate Global Ref for Mcp Controller Callbacks";
    return;
  }
  LOG(INFO) << "mcs callback initialized";
  sMcpServerInterface = (McpServerInterface* )btInf->get_profile_interface(
      BT_PROFILE_MCP_ID);
  if (sMcpServerInterface == nullptr) {
    LOG(ERROR) << "Failed to get Bluetooth Hearing Aid Interface";
    return;
  }

  sMcpServerInterface->Init(&sMcpServerCallbacks, uuid);
}

static void cleanupNative(JNIEnv* env, jobject object) {
  std::unique_lock<std::shared_timed_mutex> interface_lock(interface_mutex);
  std::unique_lock<std::shared_timed_mutex> callbacks_lock(callbacks_mutex);

  const bt_interface_t* btInf = getBluetoothInterface();
  if (btInf == nullptr) {
    LOG(ERROR) << "Bluetooth module is not loaded";
    return;
  }

  if (sMcpServerInterface != nullptr) {
    sMcpServerInterface->Cleanup();
    sMcpServerInterface = nullptr;
  }

  if (mCallbacksObj != nullptr) {
    env->DeleteGlobalRef(mCallbacksObj);
    mCallbacksObj = nullptr;
  }
}



static jboolean mediaControlPointOpcodeSupportedNative(JNIEnv* env, jobject object,
                                           jint feature) {

  LOG(INFO) << __func__;
  std::shared_lock<std::shared_timed_mutex> lock(interface_mutex);
  if (!sMcpServerInterface) return JNI_FALSE;

  sMcpServerInterface->MediaControlPointOpcodeSupported(feature);
  return JNI_TRUE;
}

static jboolean mediaControlPointNative(JNIEnv* env, jobject object,
                                           jint value) {

  LOG(INFO) << __func__;
  std::shared_lock<std::shared_timed_mutex> lock(interface_mutex);
  if (!sMcpServerInterface) return JNI_FALSE;

  sMcpServerInterface->MediaControlPoint(value);
  return JNI_TRUE;
}

static jboolean mediaStateNative(JNIEnv* env, jobject object,
                                           jint state) {

  LOG(INFO) << __func__;
  std::shared_lock<std::shared_timed_mutex> lock(interface_mutex);
  if (!sMcpServerInterface) return JNI_FALSE;

  sMcpServerInterface->MediaState(state);
  return JNI_TRUE;
}

static jboolean mediaPlayerNameNative(JNIEnv* env, jobject object,
                                           jstring playerName) {

  LOG(INFO) << __func__;
  std::shared_lock<std::shared_timed_mutex> lock(interface_mutex);
  if (!sMcpServerInterface) return JNI_FALSE;


  const char *nativeString = env->GetStringUTFChars(playerName, nullptr);
  if (!nativeString) {
    jniThrowIOException(env, EINVAL);
    return JNI_FALSE;
  }
  sMcpServerInterface->MediaPlayerName((uint8_t*)nativeString);
  env->ReleaseStringUTFChars(playerName, nativeString);
  return JNI_TRUE;
}

static jboolean trackChangedNative(JNIEnv* env, jobject object,
                                           jint status) {

  LOG(INFO) << __func__;
  std::shared_lock<std::shared_timed_mutex> lock(interface_mutex);
  if (!sMcpServerInterface) return JNI_FALSE;

  sMcpServerInterface->TrackChanged((bool)status);
  return JNI_TRUE;
}

static jboolean trackPositionNative(JNIEnv* env, jobject object,
                                           jint playPosition) {
  LOG(INFO) << __func__;
  std::shared_lock<std::shared_timed_mutex> lock(interface_mutex);
  if (!sMcpServerInterface) return JNI_FALSE;


  sMcpServerInterface->TrackPosition(playPosition);
  return JNI_TRUE;
}

static jboolean trackDurationNative(JNIEnv* env, jobject object,
                                           jint duration) {

  LOG(INFO) << __func__;
  std::shared_lock<std::shared_timed_mutex> lock(interface_mutex);
  if (!sMcpServerInterface) return JNI_FALSE;

  sMcpServerInterface->TrackDuration(duration);

  return JNI_TRUE;
}



static jboolean trackTitleNative(JNIEnv* env, jobject object,
                                           jstring title) {

  LOG(INFO) << __func__;
  std::shared_lock<std::shared_timed_mutex> lock(interface_mutex);
  if (!sMcpServerInterface) return JNI_FALSE;

  const char *nativeString = env->GetStringUTFChars(title, nullptr);
  if (!nativeString) {
    jniThrowIOException(env, EINVAL);
    return JNI_FALSE;
  }
  sMcpServerInterface->TrackTitle((uint8_t*)nativeString);
  env->ReleaseStringUTFChars(title, nativeString);
  return JNI_TRUE;
}

static jboolean setActiveDeviceNative(JNIEnv* env, jobject object,
                                         jint profile, jint set_id,
                                         jbyteArray address) {
  LOG(INFO) << __func__;
  std::shared_lock<std::shared_timed_mutex> lock(interface_mutex);
  if (!sMcpServerInterface) return JNI_FALSE;

  jbyte* addr = env->GetByteArrayElements(address, nullptr);
  RawAddress bd_addr = RawAddress::kEmpty;
  if (addr) {
    bd_addr.FromOctets(reinterpret_cast<const uint8_t*>(addr));
  }
  if (bd_addr == RawAddress::kEmpty) {
    LOG(INFO) << __func__ << " active device is null";
  }

  sMcpServerInterface->SetActiveDevice(bd_addr, set_id, profile);
  env->ReleaseByteArrayElements(address, addr, 0);
  return JNI_TRUE;
}

static jboolean bondStateChangeNative(JNIEnv* env, jobject object,
                                          jint state, jbyteArray address) {
  LOG(INFO) << __func__;
  std::shared_lock<std::shared_timed_mutex> lock(interface_mutex);
  if (!sMcpServerInterface) return JNI_FALSE;

  jbyte* addr = env->GetByteArrayElements(address, nullptr);
  if (!addr) {
    jniThrowIOException(env, EINVAL);
    return JNI_FALSE;
  }
  RawAddress* tmpraw = (RawAddress*)addr;

  sMcpServerInterface->BondStateChange(*tmpraw, state);
  env->ReleaseByteArrayElements(address, addr, 0);
  return JNI_TRUE;
}

static jboolean playingOrderSupportedNative(JNIEnv* env, jobject object,
                                           jint order) {

  LOG(INFO) << __func__;
  std::shared_lock<std::shared_timed_mutex> lock(interface_mutex);
  if (!sMcpServerInterface) return JNI_FALSE;

  sMcpServerInterface->PlayingOrderSupported(order);

  return JNI_TRUE;
}

static jboolean playingOrderNative(JNIEnv* env, jobject object,
                                           jint order) {

  LOG(INFO) << __func__;
  std::shared_lock<std::shared_timed_mutex> lock(interface_mutex);
  if (!sMcpServerInterface) return JNI_FALSE;

  sMcpServerInterface->PlayingOrder(order);

  return JNI_TRUE;
}

static jboolean contentControlIdNative(JNIEnv* env, jobject object,
                                           jint ccid) {

  LOG(INFO) << __func__;
  std::shared_lock<std::shared_timed_mutex> lock(interface_mutex);
  if (!sMcpServerInterface) return JNI_FALSE;

  sMcpServerInterface->ContentControlId(ccid);
  return JNI_TRUE;
}

static jboolean disconnectMcpNative(JNIEnv* env, jobject object,
                                           jbyteArray address) {

  LOG(INFO) << __func__;
  std::shared_lock<std::shared_timed_mutex> lock(interface_mutex);
  if (!sMcpServerInterface) return JNI_FALSE;

  jbyte* addr = env->GetByteArrayElements(address, nullptr);
  if (!addr) {
    jniThrowIOException(env, EINVAL);
    return JNI_FALSE;
  }
  RawAddress* tmpraw = (RawAddress*)addr;

  sMcpServerInterface->DisconnectMcp(*tmpraw);
  env->ReleaseByteArrayElements(address, addr, 0);
  return JNI_TRUE;
}

static JNINativeMethod sMethods[] = {
    {"classInitNative", "()V", (void*)classInitNative},
    {"initNative", "()V", (void*)initNative},
    {"cleanupNative", "()V", (void*)cleanupNative},
    {"mediaStateNative", "(I)Z", (void*)mediaStateNative},
    {"mediaPlayerNameNative", "(Ljava/lang/String;)Z", (void*)mediaPlayerNameNative},
    {"mediaControlPointOpcodeSupportedNative", "(I)Z", (void*)mediaControlPointOpcodeSupportedNative},
    {"mediaControlPointNative", "(I)Z", (void*)mediaControlPointNative},
    {"trackChangedNative", "(I)Z", (void*)trackChangedNative},
    {"trackTitleNative", "(Ljava/lang/String;)Z", (void*)trackTitleNative},
    {"trackPositionNative", "(I)Z", (void*)trackPositionNative},
    {"trackDurationNative", "(I)Z", (void*)trackDurationNative},
    {"playingOrderSupportedNative", "(I)Z", (void*)playingOrderSupportedNative},
    {"playingOrderNative", "(I)Z", (void*)playingOrderNative},
    {"setActiveDeviceNative", "(II[B)Z", (void*)setActiveDeviceNative},
    {"contentControlIdNative", "(I)Z", (void*)contentControlIdNative},
    {"disconnectMcpNative", "([B)Z", (void*)disconnectMcpNative},
    {"bondStateChangeNative", "(I[B)Z", (void*)bondStateChangeNative},
};



int register_com_android_bluetooth_mcp(JNIEnv* env) {
  return jniRegisterNativeMethods(
      env, "com/android/bluetooth/mcp/McpNativeInterface",
      sMethods, NELEM(sMethods));
}
}  // namespace android


