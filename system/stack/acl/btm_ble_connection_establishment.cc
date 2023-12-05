/******************************************************************************
 *
 *  Copyright 2019 The Android Open Source Project
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

#include <base/logging.h>
#include <frameworks/proto_logging/stats/enums/bluetooth/enums.pb.h>
#include <frameworks/proto_logging/stats/enums/bluetooth/hci/enums.pb.h>

#include "stack/btm/btm_ble_int.h"
#include "stack/btm/btm_int_types.h"
#include "stack/include/ble_hci_link_interface.h"

extern tBTM_CB btm_cb;

/** LE connection complete. */
void btm_ble_create_ll_conn_complete(tHCI_STATUS status) {
  if (status == HCI_SUCCESS) return;

  LOG(WARNING) << "LE Create Connection attempt failed, status="
               << hci_error_code_text(status);

  if (status == HCI_ERR_COMMAND_DISALLOWED) {
    btm_cb.ble_ctr_cb.set_connection_state_connecting();
    btm_ble_set_topology_mask(BTM_BLE_STATE_INIT_BIT);
    LOG(ERROR) << "LE Create Connection - command disallowed";
  } else {
    btm_cb.ble_ctr_cb.set_connection_state_idle();
    btm_ble_clear_topology_mask(BTM_BLE_STATE_INIT_BIT);
    btm_ble_update_mode_operation(HCI_ROLE_UNKNOWN, NULL, status);
  }
}
