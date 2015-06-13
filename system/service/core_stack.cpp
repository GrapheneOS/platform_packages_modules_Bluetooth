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
#include "core_stack.h"

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>

#include <condition_variable>
#include <mutex>
#include <string>

#define LOG_TAG "BluetoothBase"
#include "osi/include/log.h"

#include "hardware/bluetooth.h"
#include "hardware/hardware.h"
#include "logging_helpers.h"
#include "osi/include/osi.h"

namespace {

std::mutex mutex;
std::condition_variable synchronize;
bool instantiated = false;

void AdapterStateChangedCallback(bt_state_t state) {
  LOG_INFO("Bluetooth state:%s", BtStateText(state));
  if (state == BT_STATE_ON)
    synchronize.notify_one();
}

void CallbackThreadCallback(bt_cb_thread_evt evt) {
  LOG_INFO("%s: %s", __func__, BtEventText(evt));
}

// TODO(icoolidge): Audit how these os callouts should be
// implemented (or nulled) for systems w/out wakelocks.
bool SetWakeAlarmCallback(uint64_t delay_millis,
                          UNUSED_ATTR bool should_wake,
                          alarm_cb cb,
                          void *data) {
  static timer_t timer;
  static bool timer_created;

  if (!timer_created) {
    struct sigevent sigevent;
    memset(&sigevent, 0, sizeof(sigevent));
    sigevent.sigev_notify = SIGEV_THREAD;
    sigevent.sigev_notify_function = (void (*)(union sigval))cb;
    sigevent.sigev_value.sival_ptr = data;
    timer_create(CLOCK_MONOTONIC, &sigevent, &timer);
    timer_created = true;
  }

  struct itimerspec new_value;
  new_value.it_value.tv_sec = delay_millis / 1000;
  new_value.it_value.tv_nsec = (delay_millis % 1000) * 1000 * 1000;
  new_value.it_interval.tv_sec = 0;
  new_value.it_interval.tv_nsec = 0;
  timer_settime(timer, 0, &new_value, nullptr);

  return true;
}

// Dummy implementation due to no wakelocks.
int AcquireWakeLock(UNUSED_ATTR const char *lock_name) {
  return BT_STATUS_SUCCESS;
}

// Dummy implementation due to no wakelocks.
int ReleaseWakeLock(UNUSED_ATTR const char *lock_name) {
  return BT_STATUS_SUCCESS;
}

void GenericDevicePropertiesCallback(bt_status_t status,
                                     bt_bdaddr_t *remote_address,
                                     int num_properties,
                                     bt_property_t *properties) {
  if (status != BT_STATUS_SUCCESS) {
    LOG_ERROR("%s: %s", __func__, BtStatusText(status));
    return;
  }

  if (!remote_address) {
    LOG_INFO("Local adapter properties:");
  }

  for (int i = 0; i < num_properties; ++i) {
    bt_property_t *prop = &properties[i];
    switch (prop->type) {
      case BT_PROPERTY_BDADDR: {
        std::string text =
            BtAddrString(reinterpret_cast<bt_bdaddr_t *>(prop->val));
        LOG_INFO("%s: %s", BtPropertyText(prop->type), text.c_str());
        break;
      }
      case BT_PROPERTY_ADAPTER_SCAN_MODE: {
        bt_scan_mode_t *mode = reinterpret_cast<bt_scan_mode_t *>(prop->val);
        LOG_INFO("%s: %s", BtPropertyText(prop->type), BtScanModeText(*mode));
        std::lock_guard<std::mutex> lock(mutex);
        synchronize.notify_one();
        break;
      }
      case BT_PROPERTY_BDNAME: {
        bt_bdname_t *name = reinterpret_cast<bt_bdname_t *>(prop->val);
        LOG_INFO("%s: %s", BtPropertyText(prop->type),
                 reinterpret_cast<char *>(name->name));
        std::lock_guard<std::mutex> lock(mutex);
        synchronize.notify_one();
        break;
      }
      default:
        LOG_INFO("%s: %s", __func__, BtPropertyText(prop->type));
        break;
    }
  }
}

void AclStateChangedCallback(bt_status_t status, bt_bdaddr_t *remote_bd_addr,
                             bt_acl_state_t state) {
  if (status != BT_STATUS_SUCCESS) {
    LOG_ERROR("%s: %s", __func__, BtStatusText(status));
    return;
  }

  std::string text = BtAddrString(remote_bd_addr);
  LOG_INFO("%s: %s: %s", __func__, text.c_str(), BtAclText(state));
}

void LocalAdapterPropertiesCallback(bt_status_t status, int num_properties,
                                    bt_property_t *properties) {
  GenericDevicePropertiesCallback(status, nullptr, num_properties, properties);
}

bt_callbacks_t bt_callbacks = {
  sizeof(bt_callbacks_t),
  AdapterStateChangedCallback,
  LocalAdapterPropertiesCallback,
  GenericDevicePropertiesCallback,
  nullptr, /* device_found_cb */
  nullptr, /* discovery_state_changed_cb */
  nullptr, /* pin_request_cb  */
  nullptr, /* ssp_request_cb  */
  nullptr, /* bond_state_changed_cb */
  AclStateChangedCallback,
  CallbackThreadCallback,
  nullptr, /* dut_mode_recv_cb */
  nullptr, /* le_test_mode_cb */
  nullptr  /* energy_info_cb */
};

bt_os_callouts_t callouts = {
  sizeof(bt_os_callouts_t),
  SetWakeAlarmCallback,
  AcquireWakeLock,
  ReleaseWakeLock
};

}  // namespace

namespace bluetooth {

CoreStack::CoreStack() : adapter_(nullptr), hal_(nullptr) {
  std::lock_guard<std::mutex> lock(mutex);
  // TODO(icoolidge): DCHECK(!instantiated);
  instantiated = true;
}

bool CoreStack::Initialize() {
  std::unique_lock<std::mutex> lock(mutex);

  // Load the bluetooth module.
  const hw_module_t *module;
  int status = hw_get_module(BT_HARDWARE_MODULE_ID, &module);
  if (status) {
    LOG_ERROR("Error getting bluetooth module");
    return false;
  }

  // Open the bluetooth device.
  hw_device_t *device;
  status = module->methods->open(module, BT_HARDWARE_MODULE_ID, &device);
  if (status) {
    LOG_ERROR("Error opening bluetooth module");
    return false;
  }

  // TODO(icoolidge): Audit initialization and teardown.
  adapter_ = reinterpret_cast<bluetooth_device_t *>(device);
  hal_ = adapter_->get_bluetooth_interface();

  // Bind module callbacks to local handlers.
  status = hal_->init(&bt_callbacks);
  if (status != BT_STATUS_SUCCESS) {
    LOG_ERROR("Error binding callbacks");
    return false;
  }

  status = hal_->set_os_callouts(&callouts);
  if (status != BT_STATUS_SUCCESS) {
    LOG_ERROR("Error binding OS callbacks");
    return false;
  }

  status = hal_->enable();
  if (status) {
    LOG_ERROR("Enable failed: %d", status);
    return false;
  }

  synchronize.wait(lock);
  LOG_INFO("CoreStack::Initialize success");
  return true;
}

bool CoreStack::SetAdapterName(const std::string &name) {
  bt_bdname_t n;
  snprintf(reinterpret_cast<char *>(n.name), sizeof(n.name), "%s",
           name.c_str());
  bt_property_t prop;
  prop.len = sizeof(n);
  prop.val = &n;
  prop.type = BT_PROPERTY_BDNAME;

  std::unique_lock<std::mutex> lock(mutex);

  int status = hal_->set_adapter_property(&prop);
  if (status) {
    LOG_ERROR("%s: prop change failed: %d", __func__, status);
    return false;
  }

  synchronize.wait(lock);
  return true;
}

bool CoreStack::SetClassicDiscoverable() {
  bt_scan_mode_t mode = BT_SCAN_MODE_CONNECTABLE_DISCOVERABLE;
  bt_property_t disc;
  disc.len = sizeof(mode);
  disc.val = &mode;
  disc.type = BT_PROPERTY_ADAPTER_SCAN_MODE;

  std::unique_lock<std::mutex> lock(mutex);

  int status = hal_->set_adapter_property(&disc);
  if (status) {
    LOG_ERROR("Prop change failed: %d", status);
    return false;
  }

  synchronize.wait(lock);
  return true;
}

const void *CoreStack::GetInterface(const char *profile) {
  std::unique_lock<std::mutex> lock(mutex);
  // Get the interface to the GATT profile.
  const void *interface = hal_->get_profile_interface(profile);
  if (!interface) {
    LOG_ERROR("Error getting %s interface", profile);
    return nullptr;
  }
  return interface;
}

CoreStack::~CoreStack() {
  // TODO(icoolidge): Disable bluetooth hardware, clean up library state.
  std::lock_guard<std::mutex> lock(mutex);
  instantiated = false;
}

}  // namespace bluetooth
