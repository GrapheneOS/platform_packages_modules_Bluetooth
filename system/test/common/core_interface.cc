/*
 * Copyright 2022 The Android Open Source Project
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

#include "btif/include/btif_common.h"
#include "btif/include/core_callbacks.h"
#include "btif/include/stack_manager.h"

namespace {

static bluetooth::core::EventCallbacks eventCallbacks = {
    .invoke_adapter_state_changed_cb = invoke_adapter_state_changed_cb,
    .invoke_adapter_properties_cb = invoke_adapter_properties_cb,
    .invoke_remote_device_properties_cb = invoke_remote_device_properties_cb,
    .invoke_device_found_cb = invoke_device_found_cb,
    .invoke_discovery_state_changed_cb = invoke_discovery_state_changed_cb,
    .invoke_pin_request_cb = invoke_pin_request_cb,
    .invoke_ssp_request_cb = invoke_ssp_request_cb,
    .invoke_oob_data_request_cb = invoke_oob_data_request_cb,
    .invoke_bond_state_changed_cb = invoke_bond_state_changed_cb,
    .invoke_address_consolidate_cb = invoke_address_consolidate_cb,
    .invoke_le_address_associate_cb = invoke_le_address_associate_cb,
    .invoke_acl_state_changed_cb = invoke_acl_state_changed_cb,
    .invoke_thread_evt_cb = invoke_thread_evt_cb,
    .invoke_le_test_mode_cb = invoke_le_test_mode_cb,
    .invoke_energy_info_cb = invoke_energy_info_cb,
    .invoke_link_quality_report_cb = invoke_link_quality_report_cb};

struct MockCoreInterface : bluetooth::core::CoreInterface {
  void onBluetoothEnabled() override{};
  bt_status_t toggleProfile(tBTA_SERVICE_ID service_id, bool enable) override {
    return BT_STATUS_SUCCESS;
  };
  void removeDeviceFromProfiles(const RawAddress& bd_addr) override{};
  void onLinkDown(const RawAddress& bd_addr) override{};
  MockCoreInterface()
      : bluetooth::core::CoreInterface{&eventCallbacks, nullptr} {};
};

}  // namespace

void InitializeCoreInterface() {
  static auto mockCoreInterface = MockCoreInterface{};
  stack_manager_get_interface()->init_stack(&mockCoreInterface);
}
