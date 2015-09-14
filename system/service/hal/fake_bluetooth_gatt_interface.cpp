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

#include "service/hal/fake_bluetooth_gatt_interface.h"

namespace bluetooth {
namespace hal {
namespace {

// The global TestHandler instance. We have to use this since the HAL interface
// methods all have to be global and their signatures don't allow us to pass in
// user_data.
std::shared_ptr<FakeBluetoothGattInterface::TestHandler> g_handler;

bt_status_t FakeRegisterClient(bt_uuid_t* app_uuid) {
  if (g_handler.get())
    return g_handler->RegisterClient(app_uuid);

  return BT_STATUS_FAIL;
}

bt_status_t FakeUnregisterClient(int client_if) {
  if (g_handler.get())
    return g_handler->UnregisterClient(client_if);

  return BT_STATUS_FAIL;
}

btgatt_client_interface_t fake_btgattc_iface = {
  FakeRegisterClient,
  FakeUnregisterClient,
  nullptr, /* scan */
  nullptr, /* connect */
  nullptr, /* disconnect */
  nullptr, /* listen */
  nullptr, /* refresh */
  nullptr, /* search_service */
  nullptr, /* get_included_service */
  nullptr, /* get_characteristic */
  nullptr, /* get_descriptor */
  nullptr, /* read_characteristic */
  nullptr, /* write_characteristic */
  nullptr, /* read_descriptor */
  nullptr, /* write_descriptor */
  nullptr, /* execute_write */
  nullptr, /* register_for_notification */
  nullptr, /* deregister_for_notification */
  nullptr, /* read_remote_rssi */
  nullptr, /* scan_filter_param_setup */
  nullptr, /* scan_filter_add_remove */
  nullptr, /* scan_filter_clear */
  nullptr, /* scan_filter_enable */
  nullptr, /* get_device_type */
  nullptr, /* set_adv_data */
  nullptr, /* configure_mtu */
  nullptr, /* conn_parameter_update */
  nullptr, /* set_scan_parameters */
  nullptr, /* multi_adv_enable */
  nullptr, /* multi_adv_update */
  nullptr, /* multi_adv_inst_data */
  nullptr, /* multi_adv_disable */
  nullptr, /* batchscan_cfg_storate */
  nullptr, /* batchscan_enb_batch_scan */
  nullptr, /* batchscan_dis_batch_scan */
  nullptr, /* batchscan_read_reports */
  nullptr, /* test_command */
};

}  // namespace

FakeBluetoothGattInterface::FakeBluetoothGattInterface(
    std::shared_ptr<TestHandler> handler)
    : handler_(handler) {
  CHECK(!g_handler.get());

  // We allow passing NULL. In this case all calls we fail by default.
  if (handler.get())
    g_handler = handler;
}

FakeBluetoothGattInterface::~FakeBluetoothGattInterface() {
  if (g_handler.get())
    g_handler = nullptr;
}

// The methods below can be used to notify observers with certain events and
// given parameters.
void FakeBluetoothGattInterface::NotifyRegisterClientCallback(
    int status, int client_if,
    const bt_uuid_t& app_uuid) {
  FOR_EACH_OBSERVER(ClientObserver, client_observers_,
                    RegisterClientCallback(status, client_if, app_uuid));
}

void FakeBluetoothGattInterface::AddClientObserver(ClientObserver* observer) {
  CHECK(observer);
  client_observers_.AddObserver(observer);
}

void FakeBluetoothGattInterface::RemoveClientObserver(
    ClientObserver* observer) {
  CHECK(observer);
  client_observers_.RemoveObserver(observer);
}

const btgatt_client_interface_t*
FakeBluetoothGattInterface::GetClientHALInterface() const {
  return &fake_btgattc_iface;
}

}  // namespace hal
}  // namespace bluetooth
