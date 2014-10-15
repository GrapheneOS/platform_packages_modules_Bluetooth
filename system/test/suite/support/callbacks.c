/******************************************************************************
 *
 *  Copyright (C) 2014 Google, Inc.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at:
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 ******************************************************************************/

#include "base.h"
#include "support/callbacks.h"

// Bluetooth callbacks
void acl_state_changed(bt_status_t status, bt_bdaddr_t *remote_bd_addr, bt_acl_state_t state);
void adapter_properties(bt_status_t status, int num_properties, bt_property_t *properties);
void adapter_state_changed(bt_state_t state);
void bond_state_changed(bt_status_t status, bt_bdaddr_t *remote_bd_addr, bt_bond_state_t state);

void device_found(int num_properties, bt_property_t *properties);
void discovery_state_changed(bt_discovery_state_t state);
void remote_device_properties(bt_status_t status, bt_bdaddr_t *bd_addr, int num_properties, bt_property_t *properties);
void ssp_request(bt_bdaddr_t *remote_bd_addr, bt_bdname_t *bd_name, uint32_t cod, bt_ssp_variant_t pairing_variant, uint32_t pass_key);
void thread_evt(bt_cb_thread_evt evt);

// PAN callbacks
void pan_connection_state_changed(btpan_connection_state_t state, bt_status_t error, const bt_bdaddr_t *bd_addr, int local_role, int remote_role);
void pan_control_state_changed(btpan_control_state_t state, int local_role, bt_status_t error, const char *ifname);


static struct {
  const char *name;
  sem_t semaphore;
} callback_data[] = {
  // Adapter callbacks
  { "adapter_state_changed" },
  { "adapter_properties" },
  { "remote_device_properties" },
  { "device_found" },
  { "discovery_state_changed" },
  {},
  { "ssp_request" },
  { "bond_state_changed" },
  { "acl_state_changed" },
  { "thread_evt" },
  {},
  {},

  // PAN callbacks
  { "pan_control_state_changed" },
  { "pan_connection_state_changed" },
};

static bt_callbacks_t bt_callbacks = {
  sizeof(bt_callbacks_t),
  adapter_state_changed,     // adapter_state_changed_callback
  adapter_properties,        // adapter_properties_callback
  remote_device_properties,  // remote_device_properties_callback
  device_found,              // device_found_callback
  discovery_state_changed,   // discovery_state_changed_callback
  NULL,                      // pin_request_callback
  ssp_request,               // ssp_request_callback
  bond_state_changed,        // bond_state_changed_callback
  acl_state_changed,         // acl_state_changed_callback
  thread_evt,                // callback_thread_event
  NULL,                      // dut_mode_recv_callback
  NULL,                      // le_test_mode_callback
  NULL,
};

static btpan_callbacks_t pan_callbacks = {
  sizeof(btpan_callbacks_t),
  pan_control_state_changed,     // btpan_control_state_callback
  pan_connection_state_changed,  // btpan_connection_state_callback
};

void callbacks_init() {
  for (size_t i = 0; i < ARRAY_SIZE(callback_data); ++i) {
    sem_init(&callback_data[i].semaphore, 0, 0);
  }
}

void callbacks_cleanup() {
  for (size_t i = 0; i < ARRAY_SIZE(callback_data); ++i) {
    sem_destroy(&callback_data[i].semaphore);
  }
}

bt_callbacks_t *callbacks_get_adapter_struct() {
  return &bt_callbacks;
}

btpan_callbacks_t *callbacks_get_pan_struct() {
  return &pan_callbacks;
}

sem_t *callbacks_get_semaphore(const char *name) {
  for (size_t i = 0; i < ARRAY_SIZE(callback_data); ++i) {
    if (callback_data[i].name && !strcmp(name, callback_data[i].name)) {
      return &callback_data[i].semaphore;
    }
  }
  return NULL;
}
