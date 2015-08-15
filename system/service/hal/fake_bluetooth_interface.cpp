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

#include "service/hal/fake_bluetooth_interface.h"

namespace bluetooth {
namespace hal {

namespace {

FakeBluetoothInterface::Manager g_hal_manager;

int FakeHALEnable() {
  return g_hal_manager.enable_succeed ? BT_STATUS_SUCCESS : BT_STATUS_FAIL;
}

int FakeHALDisable() {
  return g_hal_manager.disable_succeed ? BT_STATUS_SUCCESS : BT_STATUS_FAIL;
}

int FakeHALGetAdapterProperties() {
  return BT_STATUS_SUCCESS;
}

int FakeHALSetAdapterProperty(const bt_property_t* /* property */) {
  LOG(INFO) << __func__;
  return (g_hal_manager.set_property_succeed ? BT_STATUS_SUCCESS :
          BT_STATUS_FAIL);
}

bt_interface_t fake_bt_iface = {
  sizeof(bt_interface_t),
  nullptr, /* init */
  FakeHALEnable,
  FakeHALDisable,
  nullptr, /* cleanup */
  FakeHALGetAdapterProperties,
  nullptr, /* get_adapter_property */
  FakeHALSetAdapterProperty,
  nullptr, /* get_remote_device_properties */
  nullptr, /* get_remote_device_property */
  nullptr, /* set_remote_device_property */
  nullptr, /* get_remote_service_record */
  nullptr, /* get_remote_services */
  nullptr, /* start_discovery */
  nullptr, /* cancel_discovery */
  nullptr, /* create_bond */
  nullptr, /* remove_bond */
  nullptr, /* cancel_bond */
  nullptr, /* get_connection_state */
  nullptr, /* pin_reply */
  nullptr, /* ssp_reply */
  nullptr, /* get_profile_interface */
  nullptr, /* dut_mode_configure */
  nullptr, /* dut_more_send */
  nullptr, /* le_test_mode */
  nullptr, /* config_hci_snoop_log */
  nullptr, /* set_os_callouts */
  nullptr, /* read_energy_info */
  nullptr, /* dump */
};

}  // namespace

// static
FakeBluetoothInterface::Manager* FakeBluetoothInterface::GetManager() {
  return &g_hal_manager;
}

FakeBluetoothInterface::Manager::Manager()
    : enable_succeed(false),
      disable_succeed(false),
      set_property_succeed(false) {
}

void FakeBluetoothInterface::NotifyAdapterStateChanged(bt_state_t state) {
  FOR_EACH_OBSERVER(Observer, observers_, AdapterStateChangedCallback(state));
}

void FakeBluetoothInterface::AddObserver(Observer* observer) {
  observers_.AddObserver(observer);
}

void FakeBluetoothInterface::RemoveObserver(Observer* observer) {
  observers_.RemoveObserver(observer);
}

const bt_interface_t* FakeBluetoothInterface::GetHALInterface() const {
  return &fake_bt_iface;
}

const bluetooth_device_t* FakeBluetoothInterface::GetHALAdapter() const {
  // TODO(armansito): Do something meaningful here to simulate test behavior.
  return nullptr;
}

}  // namespace hal
}  // namespace bluetooth
