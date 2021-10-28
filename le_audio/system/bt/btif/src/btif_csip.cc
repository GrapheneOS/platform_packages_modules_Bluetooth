/******************************************************************************
 *
 *  Copyright 2021 The Android Open Source Project
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

/*******************************************************************************
 *
 *  Filename:      btif_csip.c
 *
 *  Description:   CSIP client implementation (Set Coordinator)
 *
 ******************************************************************************/

#define LOG_TAG "bt_btif_csip"

#include <base/at_exit.h>
#include <base/bind.h>
#include <base/threading/thread.h>
#include <bluetooth/uuid.h>
#include <errno.h>
#include <hardware/bluetooth.h>
#include <stdlib.h>
#include <string.h>
#include <vector>
#include "device/include/controller.h"
#include "bta_csip_api.h"

#include "btif_api.h"
#include "btif_common.h"
#include "btif_util.h"

#include <hardware/bt_csip.h>

using base::Bind;
using bluetooth::Uuid;

static btcsip_callbacks_t* bt_csip_callbacks = NULL;

void btif_new_set_found_cb(tBTA_CSIP_NEW_SET_FOUND params) {
  HAL_CBACK(bt_csip_callbacks, new_set_found_cb, params.set_id, params.addr,
            params.size, params.sirk, params.including_srvc_uuid,
            params.lock_support);
}

void btif_conn_state_changed_cb(tBTA_CSIP_CONN_STATE_CHANGED params) {
  HAL_CBACK(bt_csip_callbacks, conn_state_cb, params.app_id, params.addr,
            params.state, params.status);
}

void btif_new_set_member_found_cb(tBTA_SET_MEMBER_FOUND params) {
  HAL_CBACK(bt_csip_callbacks, new_set_member_cb, params.set_id, params.addr);
}

void btif_lock_status_changed_cb(tBTA_LOCK_STATUS_CHANGED params) {
  HAL_CBACK(bt_csip_callbacks, lock_status_cb, params.app_id, params.set_id,
            params.value, params.status, params.addr);
}

void btif_lock_available_cb(tBTA_LOCK_AVAILABLE params) {
  HAL_CBACK(bt_csip_callbacks, lock_available_cb, params.app_id, params.set_id,
            params.addr);
}

void btif_set_size_changed_cb (tBTA_CSIP_SET_SIZE_CHANGED params) {
  HAL_CBACK(bt_csip_callbacks, size_changed_cb, params.set_id, params.size,
            params.addr);
}

void btif_set_sirk_changed_cb (tBTA_CSIP_SET_SIRK_CHANGED params) {
  HAL_CBACK(bt_csip_callbacks, sirk_changed_cb, params.set_id, params.sirk,
            params.addr);
}

const char* btif_csip_get_event_name(tBTA_CSIP_EVT event) {
  switch(event) {
    case BTA_CSIP_LOCK_STATUS_CHANGED_EVT:
      return "BTA_CSIP_LOCK_STATUS_CHANGED_EVT";
    case BTA_CSIP_SET_MEMBER_FOUND_EVT:
      return "BTA_CSIP_SET_MEMBER_FOUND_EVT";
    case BTA_CSIP_LOCK_AVAILABLE_EVT:
      return "BTA_CSIP_LOCK_AVAILABLE_EVT";
    case BTA_CSIP_NEW_SET_FOUND_EVT:
      return "BTA_CSIP_NEW_SET_FOUND_EVT";
    case BTA_CSIP_CONN_STATE_CHG_EVT:
      return "BTA_CSIP_CONN_STATE_CHG_EVT";
    case BTA_CSIP_SET_SIZE_CHANGED:
      return "BTA_CSIP_SET_SIZE_CHANGED";
    case BTA_CSIP_SET_SIRK_CHANGED:
      return "BTA_CSIP_SET_SIRK_CHANGED";
    default:
      return "UNKNOWN_EVENT";
  }
}

void btif_csip_evt (tBTA_CSIP_EVT event, tBTA_CSIP_DATA* p_data) {
  BTIF_TRACE_EVENT("%s: Event = %02x (%s)", __func__, event, btif_csip_get_event_name(event));

  switch (event) {
    case BTA_CSIP_LOCK_STATUS_CHANGED_EVT: {
        tBTA_LOCK_STATUS_CHANGED lock_status_params = p_data->lock_status_param;
        do_in_jni_thread(Bind(btif_lock_status_changed_cb, lock_status_params));
      }
      break;

    case BTA_CSIP_LOCK_AVAILABLE_EVT: {
        tBTA_LOCK_AVAILABLE lock_avl_param = p_data->lock_available_param;
        do_in_jni_thread(Bind(btif_lock_available_cb, lock_avl_param));
      }
      break;

    case BTA_CSIP_NEW_SET_FOUND_EVT: {
        tBTA_CSIP_NEW_SET_FOUND new_set_params = p_data->new_set_params;
        memcpy(new_set_params.sirk, p_data->new_set_params.sirk, SIRK_SIZE);
        do_in_jni_thread(Bind(btif_new_set_found_cb, new_set_params));
      }
      break;

    case BTA_CSIP_SET_MEMBER_FOUND_EVT: {
        tBTA_SET_MEMBER_FOUND new_member_params = p_data->set_member_param;
        do_in_jni_thread(Bind(btif_new_set_member_found_cb, new_member_params));
      }
      break;

    case BTA_CSIP_CONN_STATE_CHG_EVT: {
        tBTA_CSIP_CONN_STATE_CHANGED conn_params = p_data->conn_params;
        do_in_jni_thread(Bind(btif_conn_state_changed_cb, conn_params));
      }
      break;

   case BTA_CSIP_SET_SIZE_CHANGED: {
        tBTA_CSIP_SET_SIZE_CHANGED size_chg_param = p_data->size_chg_params;
        do_in_jni_thread(Bind(btif_set_size_changed_cb, size_chg_param));
      }
      break;

   case BTA_CSIP_SET_SIRK_CHANGED: {
          tBTA_CSIP_SET_SIRK_CHANGED sirk_chg_param = p_data->sirk_chg_params;
          do_in_jni_thread(Bind(btif_set_sirk_changed_cb, sirk_chg_param));
      }
      break;

    default:
      BTIF_TRACE_ERROR("%s: Unknown event %d", __func__, event);
  }
}

/* Initialization of CSIP module on BT ON*/
bt_status_t btif_csip_init( btcsip_callbacks_t* callbacks ) {
  bt_csip_callbacks = callbacks;

  do_in_jni_thread(Bind(BTA_CsipEnable, btif_csip_evt));
  btif_register_uuid_srvc_disc(Uuid::FromString("1846"));

  return BT_STATUS_SUCCESS;
}

/* Connect call from upper layer for GATT Connecttion to a given Set Member */
bt_status_t btif_csip_connect (uint8_t app_id, RawAddress *bd_addr) {
  BTIF_TRACE_EVENT("%s: Address: %s", __func__, bd_addr->ToString().c_str());

  do_in_jni_thread(Bind(BTA_CsipConnect, app_id, *bd_addr));

  return BT_STATUS_SUCCESS;
}

/* Call from upper layer to disconnect GATT Connection for given Set Member */
bt_status_t btif_csip_disconnect (uint8_t app_id, RawAddress *bd_addr ) {
  BTIF_TRACE_EVENT("%s", __func__);

  do_in_jni_thread(Bind(BTA_CsipDisconnect, app_id, *bd_addr));

  return BT_STATUS_SUCCESS;
}

/** register app/module with CSIP profile */
bt_status_t btif_csip_app_register (const bluetooth::Uuid& uuid) {
  BTIF_TRACE_EVENT("%s", __func__);
  return do_in_jni_thread(Bind(
    [](const Uuid& uuid) {
      BTA_RegisterCsipApp(
          btif_csip_evt,
          base::Bind(
              [](const Uuid& uuid, uint8_t status, uint8_t app_id) {
                do_in_jni_thread(Bind(
                    [](const Uuid& uuid, uint8_t status, uint8_t app_id) {
                      HAL_CBACK(bt_csip_callbacks, app_registered_cb,
                                status, app_id, uuid);
                    },
                    uuid, status, app_id));
              },
              uuid));
    }, uuid));
}

/** unregister csip App/Module */
bt_status_t btif_csip_app_unregister (uint8_t app_id) {
  BTIF_TRACE_EVENT("%s", __func__);
  return do_in_jni_thread(Bind(BTA_UnregisterCsipApp, app_id));
}

/** change lock value */
bt_status_t btif_csip_set_lock_value (uint8_t app_id, uint8_t set_id, uint8_t lock_value,
                                             std::vector<RawAddress> devices) {
  BTIF_TRACE_EVENT("%s appId = %d setId = %d Lock Value = %02x ", __func__,
                    app_id, set_id, lock_value);
  tBTA_SET_LOCK_PARAMS lock_params = {app_id, set_id, lock_value, devices};
  do_in_jni_thread(Bind(BTA_CsipSetLockValue, lock_params));
  return BT_STATUS_SUCCESS;
}

void  btif_csip_cleanup() {
  BTIF_TRACE_EVENT("%s", __func__);
  do_in_jni_thread(Bind(BTA_CsipDisable));
}

const btcsip_interface_t btcsipInterface = {
    sizeof(btcsipInterface),
    btif_csip_init,
    btif_csip_connect,
    btif_csip_disconnect,
    btif_csip_app_register,
    btif_csip_app_unregister,
    btif_csip_set_lock_value,
    btif_csip_cleanup,
};

/*******************************************************************************
 *
 * Function         btif_csip_get_interface
 *
 * Description      Get the csip callback interface
 *
 * Returns          btcsip_interface_t
 *
 ******************************************************************************/
const btcsip_interface_t* btif_csip_get_interface() {
  BTIF_TRACE_EVENT("%s", __func__);
  return &btcsipInterface;
}
