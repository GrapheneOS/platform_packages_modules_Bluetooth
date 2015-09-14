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

#include "service/hal/bluetooth_gatt_interface.h"

#include <mutex>

#include <base/logging.h>
#include <base/observer_list.h>

#include "service/hal/bluetooth_interface.h"

using std::lock_guard;
using std::mutex;

namespace bluetooth {
namespace hal {

namespace {

// The global BluetoothGattInterface instance.
BluetoothGattInterface* g_interface = nullptr;

// Mutex used by callbacks to access |g_interface|.
mutex g_instance_lock;

// Helper for obtaining the client observer list. This is forward declared here
// and defined below since it depends on BluetoothInterfaceImpl.
base::ObserverList<BluetoothGattInterface::ClientObserver>*
    GetClientObservers();

#define FOR_EACH_CLIENT_OBSERVER(func) \
  FOR_EACH_OBSERVER(BluetoothGattInterface::ClientObserver, \
                    *GetClientObservers(), func)

void RegisterClientCallback(int status, int client_if, bt_uuid_t* app_uuid) {
  lock_guard<mutex> lock(g_instance_lock);
  if (!g_interface) {
    LOG(WARNING) << "Callback received after global instance was destroyed";
    return;
  }

  VLOG(2) << "RegisterClientCallback status: " << status
          << " client_if: " << client_if;
  if (!app_uuid) {
    LOG(WARNING) << "|app_uuid| is NULL; ignoring RegisterClientCallback";
    return;
  }

  FOR_EACH_CLIENT_OBSERVER(
      RegisterClientCallback(status, client_if, *app_uuid));
}

// The HAL Bluetooth GATT client interface callbacks. These signal a mixture of
// GATT client-role and GAP events.
const btgatt_client_callbacks_t gatt_client_callbacks = {
    RegisterClientCallback,
    nullptr,  // scan_result_cb
    nullptr,  // open_cb
    nullptr,  // close_cb
    nullptr,  // search_complete_cb
    nullptr,  // search_result_cb
    nullptr,  // get_characteristic_cb
    nullptr,  // get_descriptor_cb
    nullptr,  // get_included_service_cb
    nullptr,  // register_for_notification_cb
    nullptr,  // notify_cb
    nullptr,  // read_characteristic_cb
    nullptr,  // write_characteristic_cb
    nullptr,  // read_descriptor_cb
    nullptr,  // write_descriptor_cb
    nullptr,  // execute_write_cb
    nullptr,  // read_remote_rssi_cb
    nullptr,  // listen_cb
    nullptr,  // configure_mtu_cb
    nullptr,  // scan_filter_cfg_cb
    nullptr,  // scan_filter_param_cb
    nullptr,  // scan_filter_status_cb
    nullptr,  // multi_adv_enable_cb
    nullptr,  // multi_adv_update_cb
    nullptr,  // multi_adv_data_cb
    nullptr,  // multi_adv_disable_cb
    nullptr,  // congestion_cb
    nullptr,  // batchscan_cfg_storage_cb
    nullptr,  // batchscan_enb_disable_cb
    nullptr,  // batchscan_reports_cb
    nullptr,  // batchscan_threshold_cb
    nullptr,  // track_adv_event_cb
    nullptr,  // scan_parameter_setup_completed_cb
};

const btgatt_server_callbacks_t gatt_server_callbacks = {
    nullptr,  // register_server_cb
    nullptr,  // connection_cb
    nullptr,  // service_added_cb,
    nullptr,  // included_service_added_cb,
    nullptr,  // characteristic_added_cb,
    nullptr,  // descriptor_added_cb,
    nullptr,  // service_started_cb,
    nullptr,  // service_stopped_cb,
    nullptr,  // service_deleted_cb,
    nullptr,  // request_read_cb,
    nullptr,  // request_write_cb,
    nullptr,  // request_exec_write_cb,
    nullptr,  // response_confirmation_cb,
    nullptr,  // indication_sent_cb
    nullptr,  // congestion_cb
    nullptr,  // mtu_changed_cb
};

const btgatt_callbacks_t gatt_callbacks = {
  sizeof(btgatt_callbacks_t),
  &gatt_client_callbacks,
  &gatt_server_callbacks
};

}  // namespace

// BluetoothGattInterface implementation for production.
class BluetoothGattInterfaceImpl : public BluetoothGattInterface {
 public:
  BluetoothGattInterfaceImpl() : hal_iface_(nullptr) {
  }

  ~BluetoothGattInterfaceImpl() override {
    CHECK(hal_iface_);
    hal_iface_->cleanup();
  }

  // BluetoothGattInterface overrides:
  void AddClientObserver(ClientObserver* observer) override {
    lock_guard<mutex> lock(g_instance_lock);
    client_observers_.AddObserver(observer);
  }

  void RemoveClientObserver(ClientObserver* observer) override {
    lock_guard<mutex> lock(g_instance_lock);
    client_observers_.RemoveObserver(observer);
  }

  const btgatt_client_interface_t* GetClientHALInterface() const override {
    return hal_iface_->client;
  }

  // Initialize the interface.
  bool Initialize() {
    const bt_interface_t* bt_iface =
        BluetoothInterface::Get()->GetHALInterface();
    CHECK(bt_iface);

    const btgatt_interface_t* gatt_iface =
        reinterpret_cast<const btgatt_interface_t*>(
            bt_iface->get_profile_interface(BT_PROFILE_GATT_ID));
    if (!gatt_iface) {
      LOG(ERROR) << "Failed to obtain HAL GATT interface handle";
      return false;
    }

    bt_status_t status = gatt_iface->init(&gatt_callbacks);
    if (status != BT_STATUS_SUCCESS) {
      LOG(ERROR) << "Failed to initialize HAL GATT interface";
      return false;
    }

    hal_iface_ = gatt_iface;

    return true;
  }

  base::ObserverList<ClientObserver>* client_observers() {
    return &client_observers_;
  }

 private:
  // List of observers that are interested in client notifications from us.
  // We're not using a base::ObserverListThreadSafe, which it posts observer
  // events automatically on the origin threads, as we want to avoid that
  // overhead and simply forward the events to the upper layer.
  base::ObserverList<ClientObserver> client_observers_;

  // The HAL handle obtained from the shared library. We hold a weak reference
  // to this since the actual data resides in the shared Bluetooth library.
  const btgatt_interface_t* hal_iface_;

  DISALLOW_COPY_AND_ASSIGN(BluetoothGattInterfaceImpl);
};

namespace {

base::ObserverList<BluetoothGattInterface::ClientObserver>*
GetClientObservers() {
  CHECK(g_interface);
  return static_cast<BluetoothGattInterfaceImpl*>(
      g_interface)->client_observers();
}

}  // namespace

// Default observer implementations. These are provided so that the methods
// themselves are optional.
void BluetoothGattInterface::ClientObserver::RegisterClientCallback(
    int status, int client_if, const bt_uuid_t& app_uuid) {
  // Do nothing.
}

// static
bool BluetoothGattInterface::Initialize() {
  lock_guard<mutex> lock(g_instance_lock);
  CHECK(!g_interface);

  std::unique_ptr<BluetoothGattInterfaceImpl> impl(
      new BluetoothGattInterfaceImpl());
  if (!impl->Initialize()) {
    LOG(ERROR) << "Failed to initialize BluetoothGattInterface";
    return false;
  }

  g_interface = impl.release();

  return true;
}

// static
void BluetoothGattInterface::CleanUp() {
  lock_guard<mutex> lock(g_instance_lock);
  CHECK(g_interface);

  delete g_interface;
  g_interface = nullptr;
}

// static
bool BluetoothGattInterface::IsInitialized() {
  lock_guard<mutex> lock(g_instance_lock);

  return g_interface != nullptr;
}

// static
BluetoothGattInterface* BluetoothGattInterface::Get() {
  lock_guard<mutex> lock(g_instance_lock);
  CHECK(g_interface);
  return g_interface;
}

// static
void BluetoothGattInterface::InitializeForTesting(
    BluetoothGattInterface* test_instance) {
  lock_guard<mutex> lock(g_instance_lock);
  CHECK(test_instance);
  CHECK(!g_interface);

  g_interface = test_instance;
}

}  // namespace hal
}  // namespace bluetooth
