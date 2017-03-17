/*
 * Copyright (C) 2017 The Android Open Source Project
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

#include "scoped_bt_addr.h"
#include "utils/Log.h"

namespace android {

ScopedBtAddr::ScopedBtAddr(CallbackEnv* env, const bt_bdaddr_t* bd_addr)
    : mEnv(env) {
  reset(bd_addr);
}

ScopedBtAddr::~ScopedBtAddr() { reset(); }

void ScopedBtAddr::reset(const bt_bdaddr_t* addr /* = NULL */) {
  if (addr == nullptr) {
    if (mAddr != nullptr) {
      (*mEnv)->DeleteLocalRef(mAddr);
      mAddr = nullptr;
    }
    return;
  }
  if (mAddr == nullptr) {
    mAddr = (*mEnv)->NewByteArray(sizeof(bt_bdaddr_t));
    if (mAddr == nullptr) {
      ALOGE("%s: Can't allocate array for bd_addr!", mEnv->method_name());
      return;
    }
  }
  (*mEnv)->SetByteArrayRegion(mAddr, 0, sizeof(bt_bdaddr_t), (jbyte*)addr);
}

jbyteArray ScopedBtAddr::get() { return mAddr; }
}
