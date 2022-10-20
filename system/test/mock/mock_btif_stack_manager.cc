/*
 * Copyright 2021 The Android Open Source Project
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

/*
 * Generated mock file from original source file
 */

#include "btif/include/core_callbacks.h"
#include "osi/include/future.h"
#include "test/common/core_interface.h"

static future_t* hack_future;

future_t* stack_manager_get_hack_future() { return hack_future; }

namespace {

struct MockCoreInterface : bluetooth::core::CoreInterface {
  void onBluetoothEnabled() override{};
  bt_status_t toggleProfile(tBTA_SERVICE_ID service_id, bool enable) override {
    return BT_STATUS_SUCCESS;
  };
  void removeDeviceFromProfiles(const RawAddress& bd_addr) override{};
  void onLinkDown(const RawAddress& bd_addr) override{};
  MockCoreInterface() : bluetooth::core::CoreInterface{nullptr, nullptr} {};
};

auto interfaceToProfiles = MockCoreInterface{};

}  // namespace

bluetooth::core::CoreInterface* GetInterfaceToProfiles() {
  return &interfaceToProfiles;
}
