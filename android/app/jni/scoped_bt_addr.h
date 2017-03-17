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

#ifndef SCOPED_BT_ADDR_H
#define SCOPED_BT_ADDR_H

#include "com_android_bluetooth.h"

namespace android {

/** Helper class for automatically marshalling and releasing a BT Address.
 * Attempts to be as similar to ScopedLocalRef as possible with automatic
 * copy of a bt_bdaddr_t correctly.
 */
class ScopedBtAddr {
 public:
  ScopedBtAddr(CallbackEnv* env, const bt_bdaddr_t* bd_addr);
  ~ScopedBtAddr();

  // (Re)set the address pointed to, releasing the local reference if necessary.
  void reset(const bt_bdaddr_t* addr = nullptr);

  // Get the pointer to the allocated array, for calling java methods.
  jbyteArray get();

 private:
  CallbackEnv* mEnv;
  jbyteArray mAddr;
};
}

#endif  // SCOPED_BT_ADDR_H
