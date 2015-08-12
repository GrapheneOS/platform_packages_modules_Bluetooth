//
//  Copyright (C) 2015 Google, Inc.
//
//  Licensed under the Apache License, Version 2.0 (the "License");
//  you may not use this file except in compliance with the License.
//  You may obtain a copy of the License at:
//
//  http://www.apache.org/licenses/LICENSE-2.0
//
//  Unless required by applicable law or agreed to in writing, software
//  distributed under the License is distributed on an "AS IS" BASIS,
//  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//  See the License for the specific language governing permissions and
//  limitations under the License.
//

#include <base/logging.h>

#include "service/ipc/binder/IBluetooth.h"

using android::sp;

using ipc::binder::IBluetooth;

// TODO(armansito): Build a REPL into this client so that we make Binder calls
// based on user input. For now this just tests the IsEnabled() method and
// exits.

int main() {
  sp<IBluetooth> bt_iface = IBluetooth::getClientInterface();
  if (!bt_iface.get()) {
    LOG(ERROR) << "Failed to obtain handle on IBluetooth";
    return EXIT_FAILURE;
  }

  bool enabled = bt_iface->IsEnabled();
  LOG(INFO) << "IsEnabled(): " << enabled;

  return EXIT_SUCCESS;
}
