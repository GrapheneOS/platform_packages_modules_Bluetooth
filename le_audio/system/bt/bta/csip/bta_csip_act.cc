/******************************************************************************

Copyright (c) 2020, The Linux Foundation. All rights reserved.
*
*****************************************************************************/

/******************************************************************************
*

* Copyright 2009-2013 Broadcom Corporation
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at:
*
* http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*
******************************************************************************/

/******************************************************************************
 *
 *  This file contains the CSIP Client action functions.
 *
 ******************************************************************************/

#include <log/log.h>
#include <string.h>
#include <stdlib.h>

#include <base/bind.h>
#include <base/callback.h>
#include <vector>
#include <string>

#include "bta_csip_int.h"
#include "bta_csip_api.h"
#include "bta_gatt_api.h"
#include "bta_gatt_queue.h"
#include "btm_api.h"
#include "btm_ble_api.h"
#include "btm_int.h"
#include "osi/include/osi.h"
#include "osi/include/properties.h"
#include "bta_dm_api.h"
#include "bta_dm_adv_audio.h"

/* CSIS Service UUID */
Uuid CSIS_SERVICE_UUID = Uuid::FromString("1846");
/* CSIS Characteristic UUID's */
Uuid CSIS_SERVICE_SIRK_UUID = Uuid::FromString("2B84");
Uuid CSIS_SERVICE_SIZE_UUID = Uuid::FromString("2B85");
Uuid CSIS_SERVICE_LOCK_UUID = Uuid::FromString("2B86");
Uuid CSIS_SERVICE_RANK_UUID = Uuid::FromString("2B87");

/*******************************************************************************
 *
 * Function         bta_csip_api_enable
 *
 * Description      This function completes tasks to be done on BT ON
 *
 * Parameters:      p_cback - callbacks from btif layer
 *
 ******************************************************************************/
void bta_csip_api_enable(tBTA_CSIP_CBACK *p_cback) {
   APPL_TRACE_DEBUG("%s", __func__);

  bta_csip_cb = tBTA_CSIP_CB();
  bta_csip_cb.p_cback = p_cback;

  // register with GATT CLient interface
  bta_csip_gattc_register();

  bta_csip_load_coordinated_sets_from_storage();
}

/*******************************************************************************
 *
 * Function         bta_csip_api_disable
 *
 * Description      This function completes tasks to be done on BT OFF
 *
 * Parameters:      None
 *
 ******************************************************************************/
void bta_csip_api_disable() {
  std::vector<tBTA_CSIP_DEV_CB> &dev_cb = bta_csip_cb.dev_cb;

  /* close all active GATT Connections */
  for (tBTA_CSIP_DEV_CB& p_cb: dev_cb) {
    if (p_cb.state == BTA_CSIP_CONN_ST) {
      BTA_GATTC_Close(p_cb.conn_id);
    }
  }

  /* Deregister GATT Interface */
  BTA_GATTC_AppDeregister(bta_csip_cb.gatt_if);
}

/*******************************************************************************
 *
 * Function         bta_csip_app_register
 *
 * Description      API used to register App/Module for CSIP callbacks.
 *                  operation
 *
 * Parameters:      app_uuid - Application UUID.
 *                  p_cback - Application callbacks.
 *                  cb - callback after registration.
 ******************************************************************************/
void bta_csip_app_register (const Uuid& app_uuid, tBTA_CSIP_CBACK* p_cback,
                          BtaCsipAppRegisteredCb cb) {
  uint8_t i;
  tBTA_CSIP_STATUS status = BTA_CSIP_FAILURE;

  for (i = 0; i < BTA_CSIP_MAX_SUPPORTED_APPS; i++) {
    if (!bta_csip_cb.app_rcb[i].in_use) {
      bta_csip_cb.app_rcb[i].in_use = true;
      bta_csip_cb.app_rcb[i].app_id = i;
      bta_csip_cb.app_rcb[i].p_cback = p_cback;
      status = BTA_CSIP_SUCCESS;
      break;
    }
  }

  if (status == BTA_CSIP_SUCCESS) {
    LOG(INFO) << "CSIP App Registered Succesfully. App ID: " << +i;
  } else {
    LOG(ERROR) << "CSIP App Registration failed. App Limit reached";
  }

  // Give callback to registering App/Module
  if (!cb.is_null()) cb.Run(status, i);
}

/*******************************************************************************
 *
 * Function         bta_csip_app_unregister
 *
 * Description      API used to unregister App/Module for CSIP callbacks.
 *
 * Parameters:      app_id: ID of the application to be unregistered.
 *
 ******************************************************************************/
void bta_csip_app_unregister(uint8_t app_id) {
  if (app_id >= BTA_CSIP_MAX_SUPPORTED_APPS) {
    LOG(ERROR) << __func__ << " Invalid App ID: " << +app_id;
    return;
  }

  bta_csip_cb.app_rcb[app_id].in_use = false;
  bta_csip_cb.app_rcb[app_id].p_cback = NULL;
}

/*******************************************************************************
 *
 * Function         bta_csip_gattc_callback
 *
 * Description      This is GATT client callback function used in BTA CSIP.
 *
 * Parameters:      event  - received from GATT
 *                  p_data - data associated with the event
 *
 ******************************************************************************/
static void bta_csip_gattc_callback(tBTA_GATTC_EVT event, tBTA_GATTC* p_data) {
  tBTA_CSIP_DEV_CB* p_dev_cb;

  APPL_TRACE_DEBUG("bta_csip_gattc_callback event = %d", event);

  if (p_data == NULL) return;

  switch (event) {
    case BTA_GATTC_OPEN_EVT:
      p_dev_cb = bta_csip_find_dev_cb_by_bda(p_data->open.remote_bda);
      if (p_dev_cb) {
        bta_csip_sm_execute(p_dev_cb, BTA_CSIP_GATT_OPEN_EVT,
                          (tBTA_CSIP_REQ_DATA*)&p_data->open);
      }
      break;

    case BTA_GATTC_CLOSE_EVT:
      p_dev_cb = bta_csip_find_dev_cb_by_bda(p_data->close.remote_bda);
      if (p_dev_cb) {
        APPL_TRACE_DEBUG("BTA_GATTC_CLOSE_EVT state = %d", p_dev_cb->state);
        bta_csip_sm_execute(p_dev_cb, BTA_CSIP_GATT_CLOSE_EVT,
                          (tBTA_CSIP_REQ_DATA*)&p_data->close);
      }
      break;

    case BTA_GATTC_SEARCH_CMPL_EVT: {
        tBTA_GATTC_SEARCH_CMPL* p_srch_data = &p_data->search_cmpl;
        tBTA_CSIP_DISC_SET disc_params = {.conn_id = p_srch_data->conn_id,
                                          .status = p_srch_data->status
                                         };
        p_dev_cb = bta_csip_get_dev_cb_by_cid(p_srch_data->conn_id);
        if (p_dev_cb) {
          disc_params.addr = p_dev_cb->addr;
          p_dev_cb->is_disc_external = true;
        }
        bta_csip_gatt_disc_cmpl_act(&disc_params);
        bta_csip_sm_execute(p_dev_cb, BTA_CSIP_OPEN_CMPL_EVT, NULL);
      }
      break;

    case BTA_GATTC_NOTIF_EVT: {
        bta_csip_handle_notification(&p_data->notify);
      }
      break;

    default:
      break;
  }
}

/*******************************************************************************
 *
 * Function         bta_csip_gattc_register
 *
 * Description      API used to register GATT interface for CSIP operations.
 *
 * Parameters:      None
 *
 ******************************************************************************/
void bta_csip_gattc_register() {
  APPL_TRACE_DEBUG("%s", __func__);

  BTA_GATTC_AppRegister(bta_csip_gattc_callback,
                      base::Bind([](uint8_t client_id, uint8_t status) {
                        tBTA_CSIP_STATUS csip_status = BTA_CSIP_FAILURE;
                        if (status == GATT_SUCCESS) {
                          bta_csip_cb.gatt_if = client_id;
                          csip_status = BTA_CSIP_SUCCESS;
                        } else {
                          bta_csip_cb.gatt_if = BTA_GATTS_INVALID_IF;
                        }

                        /* BTA_GATTC_AppRegister is done */
                        if (bta_csip_cb.p_cback) {
                          LOG(INFO) << "CSIP GATT IF : "
                                    << +bta_csip_cb.gatt_if;
                        }
                      }), true);
}

/*******************************************************************************
 *
 * Function         bta_csip_process_set_lock_act
 *
 * Description      This function processes lock/unlock request.
 *
 * Parameters:      lock_param: params used in LOCK/UNLOCK request.
 *
 ******************************************************************************/
void bta_csip_process_set_lock_act(tBTA_SET_LOCK_PARAMS lock_param) {
  LOG(INFO) << __func__ << ": App ID = " << +lock_param.app_id
                        << ", Set ID = " << +lock_param.set_id
                        << ", Value = " << +lock_param.lock_value;

  tBTA_CSET_CB* cset_cb = bta_csip_get_cset_cb_by_id (lock_param.set_id);
  if (!cset_cb || !bta_csip_is_valid_lock_request(&lock_param)) {
    tBTA_LOCK_STATUS_CHANGED res = {.app_id = lock_param.app_id,
                                    .set_id = lock_param.set_id,
                                    .status = INVALID_REQUEST_PARAMS};
    bta_csip_send_lock_req_cmpl_cb(res);
    return;
  }

  // Add request in the queue if one is already in progress for this set
  if (cset_cb->request_in_progress) {
    cset_cb->lock_req_queue.push(lock_param);
    LOG(INFO) << __func__ << " pending lock requests in queue for Set:"
                          << +lock_param.set_id
                          << " Pending Requests = " << +(int)cset_cb->lock_req_queue.size();
    return;
  }

  bta_csip_form_lock_request(lock_param, cset_cb);
}

/*******************************************************************************
 *
 * Function         bta_csip_process_set_lock_act
 *
 * Description      This function forms request (LOCK/UNLOCK and order of the
 *                  set members).
 *
 * Parameters:      lock_param: params used in LOCK/UNLOCK request.
 *                  cset_cb: current set control block.
 *
 ******************************************************************************/
void bta_csip_form_lock_request(tBTA_SET_LOCK_PARAMS lock_param,
                                       tBTA_CSET_CB* cset_cb) {
  cset_cb->request_in_progress = true;

  std::vector<RawAddress> ordered_members;

  if (lock_param.lock_value == LOCK_VALUE) {
    ordered_members = bta_csip_arrange_set_members_by_order(cset_cb->set_id,
                      lock_param.members_addr, true);
  } else {
    ordered_members = bta_csip_arrange_set_members_by_order(cset_cb->set_id,
                      lock_param.members_addr, false);
  }

  //debug log
  for (int i = 0; i < (int)ordered_members.size(); i++) {
    APPL_TRACE_DEBUG("%s: Member %d = %s", __func__, (i+1),
                     ordered_members[i].ToString().c_str());
  }

  // update current request in CB
  cset_cb->cur_lock_req = {lock_param.app_id, lock_param.set_id, lock_param.lock_value,
                           0, ordered_members};

  // update current response in CB
  cset_cb->cur_lock_res = {};
  cset_cb->cur_lock_res.app_id = lock_param.app_id;
  cset_cb->cur_lock_res.set_id = lock_param.set_id;
  cset_cb->cur_lock_res.value = UNLOCK_VALUE;

  /* LOCK Request */
  if (cset_cb->cur_lock_req.value == LOCK_VALUE) {
    cset_cb->cur_lock_res.status = ALL_LOCKS_ACQUIRED;
    /* check if lock request for this set was denied earlier */
    if (bta_csip_validate_req_for_denied_sm(cset_cb)) {
      bta_csip_get_next_lock_request(cset_cb);

    /* proceed with request otherwise*/
    } else {
      bta_csip_send_lock_req_act(cset_cb);
    }
  /* UNLOCK Request*/
  } else {
    bta_csip_send_unlock_req_act(cset_cb);
  }
}

/*******************************************************************************
 *
 * Function         bta_csip_validate_req_for_denied_sm
 *
 * Description      This function validates request if received for denied set
 *                  member
 *
 * Parameters:      cset_cb: current set control block.
 *
 ******************************************************************************/
bool bta_csip_validate_req_for_denied_sm (tBTA_CSET_CB* cset_cb) {
  bool is_denied = false;
  tBTA_LOCK_REQUEST& lock_req = cset_cb->cur_lock_req;

  for (RawAddress& addr: lock_req.members_addr) {
    tBTA_CSIP_DEV_CB* p_cb = bta_csip_find_dev_cb_by_bda(addr);
    if (!p_cb) {
      APPL_TRACE_ERROR("%s: Device CB not found for %s", __func__,
                       addr.ToString().c_str());
      continue;
    }

    tBTA_CSIS_SRVC_INFO* srvc = bta_csip_get_csis_instance(p_cb, lock_req.set_id);
    if (!srvc) {
      APPL_TRACE_ERROR("%s: CSIS instance not found for %s", __func__,
                       addr.ToString().c_str());
      continue;
    }

    if (!srvc->denied_applist.empty()) {
      is_denied = true;
      // add this app_id in the denied_app_list
      srvc->denied_applist.push_back(lock_req.app_id);
      cset_cb->cur_lock_res.status = LOCK_DENIED;
      cset_cb->cur_lock_res.addr.push_back(addr);
    }
  }

  if (is_denied) {
    bta_csip_send_lock_req_cmpl_cb(cset_cb->cur_lock_res);
  }

  return is_denied;
}

/*******************************************************************************
 *
 * Function         bta_csip_lock_release_by_denial_cb
 *
 * Description      This callback function is called when set member is unlocked
 *                  after unlock request is sent post lock denial.
 *
 * Parameters:      GATT operation callback params.
 *
 ******************************************************************************/
void bta_csip_lock_release_by_denial_cb(uint16_t conn_id, tGATT_STATUS status,
                                                  uint16_t handle, void* data) {
  tBTA_CSET_CB* cset_cb = (tBTA_CSET_CB *)data;
  tBTA_CSIP_DEV_CB* dev_cb = cset_cb->cur_dev_cb;
  tBTA_CSIS_SRVC_INFO* srvc =
          bta_csip_get_csis_instance(cset_cb->cur_dev_cb, cset_cb->cur_lock_req.set_id);

  LOG(INFO) << __func__ << " Released lock for device: " << dev_cb->addr
                        << ", Set ID: " << +cset_cb->set_id;

  if (srvc && status == GATT_SUCCESS) {
    srvc->lock = UNLOCK_VALUE;
    // remove app id from applist
    srvc->lock_applist.erase(std::remove(srvc->lock_applist.begin(), srvc->lock_applist.end(),
        cset_cb->cur_lock_req.app_id), srvc->lock_applist.end());
  }

  // release next set member with lower rank
  bta_csip_handle_lock_denial(cset_cb);
}

/*******************************************************************************
 *
 * Function         bta_csip_handle_lock_denial
 *
 * Description      This function is called when lock has been denied by one of
 *                  the set members.
 *
 * Parameters:      cset_cb: current set control block.
 *
 ******************************************************************************/
void bta_csip_handle_lock_denial(tBTA_CSET_CB* cset_cb) {
    // start lock release procedure for acquired locks
    int8_t cur_idx = cset_cb->cur_lock_req.cur_idx - 1;
    cset_cb->cur_lock_req.cur_idx--;

    if (cur_idx >= 0) {
      RawAddress bd_addr = cset_cb->cur_lock_req.members_addr[cur_idx];
      cset_cb->cur_dev_cb = bta_csip_find_dev_cb_by_bda(bd_addr);
      tBTA_CSIS_SRVC_INFO* srvc =
          bta_csip_get_csis_instance(cset_cb->cur_dev_cb, cset_cb->cur_lock_req.set_id);

      // check if locked by other app
      if (!cset_cb->cur_dev_cb || !srvc ||
          bta_csip_is_locked_by_other_apps(srvc, cset_cb->cur_lock_req.app_id)) {
        LOG(INFO) << "Invalid device or service CB or"
                  << " other apps have locked this set member(" << bd_addr << "). Skip.";
        bta_csip_handle_lock_denial(cset_cb);
        return;
      }

      // Lock value in vector format (one uint8_t size element with )
      std::vector<uint8_t> unlock_value(1, UNLOCK_VALUE);
      BtaGattQueue::WriteCharacteristic(cset_cb->cur_dev_cb->conn_id,
      srvc->lock_handle, unlock_value, GATT_WRITE, bta_csip_lock_release_by_denial_cb, cset_cb);

    } else {
      bta_csip_get_next_lock_request(cset_cb);
    }
}

/*******************************************************************************
 *
 * Function         bta_csip_lock_req_cb
 *
 * Description      This callback function is called when set member is locked
 *                  by remote device after LOCK Request
 *
 * Parameters:      GATT operation callback params.
 *
 ******************************************************************************/
void bta_csip_lock_req_cb(uint16_t conn_id, tGATT_STATUS status, uint16_t handle,
                          void* data) {
  LOG(INFO) << __func__ << " status = " << +status;
  tBTA_CSET_CB* cset_cb = (tBTA_CSET_CB *)data;
  tBTA_CSIP_DEV_CB* dev_cb = bta_csip_get_dev_cb_by_cid(conn_id);
  tBTA_CSIS_SRVC_INFO* srvc =
      bta_csip_get_csis_instance(dev_cb, cset_cb->set_id);

  /* Device control block or corresponding CSIS service instance not found */
  if (!dev_cb || !srvc) {
    APPL_TRACE_ERROR("%s: Device CB not found for conn_id = %d", __func__, conn_id);
    cset_cb->cur_lock_req.cur_idx++;
    alarm_cancel(cset_cb->unresp_timer);
    bta_csip_send_lock_req_act(cset_cb);
    return;
  }

  /*check if this response is received from unresponsive set member */
  if (dev_cb->unresponsive) {
    LOG(INFO) << __func__ << " unresponsive remote: " << dev_cb->addr;
    bta_csip_handle_unresponsive_sm_res(srvc, status);
    dev_cb->unresponsive = false;
    return;
  }
  // cancel alarm (used for unresponsive set member)
  alarm_cancel(cset_cb->unresp_timer);

  if (status == CSIP_LOCK_DENIED) {
      LOG(INFO) << __func__ << " Locked Denied by " << dev_cb->addr;
      srvc->lock = UNLOCK_VALUE;
      cset_cb->cur_lock_res.value = UNLOCK_VALUE;
      cset_cb->cur_lock_res.status = LOCK_DENIED;

      // add member to the response list for which lock is denied and clear others
      cset_cb->cur_lock_res.addr.clear();
      cset_cb->cur_lock_res.addr.push_back(dev_cb->addr);

      // add app_id in the denied applist
      srvc->denied_applist.push_back(cset_cb->cur_lock_req.app_id);
      // Give callback to upper layer that lock is denied
      bta_csip_send_lock_req_cmpl_cb(cset_cb->cur_lock_res);
      // release all the acquired locks till now
      bta_csip_handle_lock_denial(cset_cb);

  /* PTS: Remote responding with invalid value */
  } else if (status == CSIP_INVALID_LOCK_VALUE) {
    LOG(ERROR) << __func__ << " remote " << dev_cb->addr
                          << " responded with INVALID Value";
    /* for PTS to ensure set coordinator is working fine */
    BtaGattQueue::ReadCharacteristic(cset_cb->cur_dev_cb->conn_id,
        srvc->lock_handle, NULL, NULL);

    /* Stop locking remaining set members and inform requesting app */
    bta_csip_send_lock_req_cmpl_cb(cset_cb->cur_lock_res);
    /* Process next lock request from pending queue */
    bta_csip_get_next_lock_request(cset_cb);
  } else {
    if (status == GATT_SUCCESS || status == CSIP_LOCK_ALREADY_GRANTED) {
      LOG(INFO) << __func__ << " successfully locked " << dev_cb->addr;
      cset_cb->cur_lock_res.addr.push_back(dev_cb->addr);
      cset_cb->cur_lock_res.value = LOCK_VALUE;
      srvc->lock = LOCK_VALUE;
      // add app_id against this device entry
      srvc->lock_applist.push_back(cset_cb->cur_lock_req.app_id);
    }

    //proceed with next set member
    cset_cb->cur_lock_req.cur_idx++;
    bta_csip_send_lock_req_act(cset_cb);
  }
}

/*******************************************************************************
 *
 * Function         bta_csip_send_lock_req_act
 *
 * Description      This function is is used to send LOCK request to set member.
 *                  It validates if it is required to send lock request based on
 *                  connection state and current lock value.
 *
 * Parameters:      cset_cb: current set control block.
 *
 ******************************************************************************/
void bta_csip_send_lock_req_act(tBTA_CSET_CB* cset_cb) {
  RawAddress bd_addr;
  uint8_t cur_index = cset_cb->cur_lock_req.cur_idx;

  if (cur_index == (uint8_t)cset_cb->cur_lock_req.members_addr.size()) {
    LOG(INFO) << __func__ << " lock operation completed for all set members";
    bta_csip_send_lock_req_cmpl_cb(cset_cb->cur_lock_res);
    bta_csip_get_next_lock_request(cset_cb);
    return;
  }

  bd_addr = cset_cb->cur_lock_req.members_addr[cur_index];

  // get device control block and corresponding csis service details
  cset_cb->cur_dev_cb = bta_csip_find_dev_cb_by_bda(bd_addr);
  tBTA_CSIS_SRVC_INFO* srvc =
      bta_csip_get_csis_instance(cset_cb->cur_dev_cb, cset_cb->cur_lock_req.set_id);

  // Skip device if it is not in connected state
  if (!cset_cb->cur_dev_cb || !srvc ||
      cset_cb->cur_dev_cb->state != BTA_CSIP_CONN_ST) {
    LOG(INFO) << __func__ << ": Set Member (" << bd_addr.ToString()
              << ") is not connected. Skip this Set member";

    cset_cb->cur_lock_req.cur_idx++;
    cset_cb->cur_lock_res.status = SOME_LOCKS_ACQUIRED_REASON_DISC;
    bta_csip_send_lock_req_act(cset_cb);

  // check if already locked (skip sending write request)
  } else if (srvc->lock == LOCK_VALUE) {
    LOG(INFO) << __func__ << ": Set Member (" << cset_cb->cur_dev_cb->addr
              << ") is already locked. Skip this Set member";
    cset_cb->cur_lock_res.value = LOCK_VALUE;
    // add element in the list
    cset_cb->cur_lock_res.addr.push_back(bd_addr);
    // add appid in the list if locked by different app
    if (!bta_csip_is_member_locked_by_app(cset_cb->cur_lock_req.app_id, srvc)) {
      srvc->lock_applist.push_back(cset_cb->cur_lock_req.app_id);
    }
    cset_cb->cur_lock_req.cur_idx++;
    // process next set member
    bta_csip_send_lock_req_act(cset_cb);

  // send the lock request
  } else {
    // Lock value in vector format (one uint8_t size element with )
    LOG(INFO) << __func__ << " Sending Lock Request to "<< cset_cb->cur_dev_cb->addr
                          << " Conn Id: " << +cset_cb->cur_dev_cb->conn_id;
    std::vector<uint8_t> lock_value = {2};
    BtaGattQueue::WriteCharacteristic(cset_cb->cur_dev_cb->conn_id,
        srvc->lock_handle, lock_value, GATT_WRITE, bta_csip_lock_req_cb, cset_cb);

    // Start set member request timeout alarm
    cset_cb->unresp_timer = alarm_new("csip_unresp_sm_timer");
    alarm_set_on_mloop(cset_cb->unresp_timer, cset_cb->set_member_tout,
                       bta_csip_set_member_lock_timeout, cset_cb);
  }
}

/*******************************************************************************
 *
 * Function         bta_csip_unlock_req_cb
 *
 * Description      This callback function is called when set member is unlocked
 *                  by remote device after UNLOCK Request
 *
 * Parameters:      GATT operation callback params.
 *
 ******************************************************************************/
void bta_csip_unlock_req_cb(uint16_t conn_id, tGATT_STATUS status, uint16_t handle,
                                void* data) {
  LOG(INFO) << __func__ << " status = " << +status;
  tBTA_CSET_CB* cset_cb = (tBTA_CSET_CB *)data;
  tBTA_CSIP_DEV_CB* dev_cb = bta_csip_get_dev_cb_by_cid(conn_id);
  tBTA_CSIS_SRVC_INFO* srvc =
      bta_csip_get_csis_instance(dev_cb, cset_cb->cur_lock_req.set_id);

  /* Device control block or corresponding CSIS service instance not found */
  if (!dev_cb || !srvc) {
    APPL_TRACE_ERROR("%s: Device CB not found for conn_id = %d", __func__, conn_id);
    cset_cb->cur_lock_req.cur_idx++;
    alarm_cancel(cset_cb->unresp_timer);
    bta_csip_send_unlock_req_act(cset_cb);
    return;
  }

  /*check if this response is received from unresponsive set member */
  if (dev_cb->unresponsive) {
    LOG(INFO) << __func__ << " unresponsive remote: " << dev_cb->addr;
    srvc->lock = UNLOCK_VALUE;
    srvc->unrsp_applist.clear();
    dev_cb->unresponsive = false;
    return;
  }

  // cancel alarm (used for unresponsive set member)
  alarm_cancel(cset_cb->unresp_timer);

  /* PTS Test Case: read any characteristic */
  if (status == CSIP_LOCK_RELEASE_NOT_ALLOWED ||
      status == CSIP_INVALID_LOCK_VALUE) {
    /* for PTS to ensure set coordinator is working fine */
    BtaGattQueue::ReadCharacteristic(cset_cb->cur_dev_cb->conn_id,
        srvc->lock_handle, NULL, NULL);

    /* Stop unlocking remaining set members and inform requesting app */
    cset_cb->cur_lock_res.status = status;
    bta_csip_send_lock_req_cmpl_cb(cset_cb->cur_lock_res);
    /* Process next lock request from pending queue */
    bta_csip_get_next_lock_request(cset_cb);
  } else {
    if (status == GATT_SUCCESS) {
      srvc->lock = UNLOCK_VALUE;
      // remove app id from applist
      srvc->lock_applist.erase(std::remove(srvc->lock_applist.begin(),
          srvc->lock_applist.end(), cset_cb->cur_lock_req.app_id),
          srvc->lock_applist.end());
      cset_cb->cur_lock_res.addr.push_back(dev_cb->addr);
    }
    //proceed with next set member
    cset_cb->cur_lock_req.cur_idx++;
    bta_csip_send_unlock_req_act(cset_cb);
  }
}

/*******************************************************************************
 *
 * Function         bta_csip_send_unlock_req_act
 *
 * Description      This function is is used to send UNLOCK request to set member.
 *                  It validates if it is required to send unlock request based on
 *                  connection state and current lock value.
 *
 * Parameters:      cset_cb: current set control block.
 *
 ******************************************************************************/
void bta_csip_send_unlock_req_act(tBTA_CSET_CB* cset_cb) {
  RawAddress bd_addr;
  uint8_t cur_index = cset_cb->cur_lock_req.cur_idx;

  if (cur_index == (uint8_t)cset_cb->cur_lock_req.members_addr.size()) {
    cset_cb->request_in_progress = false;
    bta_csip_send_lock_req_cmpl_cb(cset_cb->cur_lock_res);
    bta_csip_get_next_lock_request(cset_cb);
    LOG(INFO) << __func__ << " Request completed for all set members";
    return;
  }

  bd_addr = cset_cb->cur_lock_req.members_addr[cur_index];

  LOG(INFO) << __func__ << ": Set Member address: " << bd_addr.ToString();

  // get device control block and corresponding csis service details
  cset_cb->cur_dev_cb = bta_csip_find_dev_cb_by_bda(bd_addr);
  tBTA_CSIS_SRVC_INFO* srvc =
      bta_csip_get_csis_instance(cset_cb->cur_dev_cb, cset_cb->cur_lock_req.set_id);

  /* Device control block or corresponding CSIS service instance not found */
  if (!cset_cb->cur_dev_cb || !srvc) {
    APPL_TRACE_ERROR("%s: Device CB not found for %s", __func__,
                       bd_addr.ToString().c_str());
    cset_cb->cur_lock_req.cur_idx++;
    bta_csip_send_unlock_req_act(cset_cb);
    return;
  }

  /* Set member is not locked by requesting app */
  if (!bta_csip_is_member_locked_by_app(cset_cb->cur_lock_req.app_id, srvc)) {
    LOG(INFO) << __func__ << " App "<< +cset_cb->cur_lock_req.app_id
                        << "has not locked this set member (" << srvc->bd_addr
                        << "). Skip this set member";
    cset_cb->cur_lock_req.cur_idx++;
    bta_csip_send_unlock_req_act(cset_cb);
    return;
  }

  // Skip device if it is not in connected state
  if (cset_cb->cur_dev_cb->state != BTA_CSIP_CONN_ST) {
    LOG(INFO) << __func__ << ": Set Member (" << bd_addr.ToString()
              << ") is not connected. Skip this Set member";

    cset_cb->cur_lock_req.cur_idx++;
    // remove app id from applist
    srvc->lock_applist.erase(std::remove(srvc->lock_applist.begin(), srvc->lock_applist.end(),
        cset_cb->cur_lock_req.app_id), srvc->lock_applist.end());
    bta_csip_send_unlock_req_act(cset_cb);

  // check if already unlocked or locked by multiple apps (skip sending write request)
  } else if (srvc->lock == UNLOCK_VALUE ||
             bta_csip_is_locked_by_other_apps(srvc, cset_cb->cur_lock_req.app_id)) {
    LOG(INFO) << __func__ << ": Set Member (" << bd_addr.ToString()
              << ") is already unlocked or locked by other app. Skip this Set member";
    // remove app id from applist
    srvc->lock_applist.erase(std::remove(srvc->lock_applist.begin(), srvc->lock_applist.end(),
        cset_cb->cur_lock_req.app_id), srvc->lock_applist.end());
    cset_cb->cur_lock_req.cur_idx++;
    cset_cb->cur_lock_res.addr.push_back(cset_cb->cur_dev_cb->addr);
    // process next set member
    bta_csip_send_unlock_req_act(cset_cb);

  // send the unlock request
  } else {
    // Unlock value in vector format (one uint8_t size element with unlock value)
    std::vector<uint8_t> lock_value(1, UNLOCK_VALUE);
    BtaGattQueue::WriteCharacteristic(cset_cb->cur_dev_cb->conn_id,
        srvc->lock_handle, lock_value, GATT_WRITE, bta_csip_unlock_req_cb, cset_cb);

    // Start set member request timeout alarm
    cset_cb->unresp_timer = alarm_new("csip_unresp_sm_timer");
    alarm_set_on_mloop(cset_cb->unresp_timer, cset_cb->set_member_tout,
                       bta_csip_set_member_lock_timeout, cset_cb);
  }
}

/*******************************************************************************
 *
 * Function         bta_csip_set_member_lock_timeout
 *
 * Description      This API is called when Set Member has not responded within
 *                  required set member lock timeout.
 *
 * Returns          None
 *
 ******************************************************************************/
void bta_csip_set_member_lock_timeout(void* p_data) {
  tBTA_CSET_CB* cset_cb = (tBTA_CSET_CB *)p_data;
  tBTA_CSIP_DEV_CB* dev_cb = cset_cb->cur_dev_cb;

  APPL_TRACE_DEBUG("%s", __func__);
  // Device not found or disconnected
  if (!dev_cb || dev_cb->state != BTA_CSIP_CONN_ST) {
    LOG(ERROR) << __func__ << " device disconnected.";
    cset_cb->cur_lock_res.status = SOME_LOCKS_ACQUIRED_REASON_DISC;
    cset_cb->cur_lock_req.cur_idx++;
    bta_csip_send_lock_req_act(cset_cb);
    return;
  }

  tBTA_CSIS_SRVC_INFO* srvc =
      bta_csip_get_csis_instance(cset_cb->cur_dev_cb, cset_cb->cur_lock_req.set_id);

  if (!srvc) {
    APPL_TRACE_ERROR("%s: CSIS instance not found.", __func__);
    return;
  }

  dev_cb->unresponsive = true;
  // add app_id in unresponsive set members app list
  srvc->unrsp_applist.push_back(cset_cb->cur_lock_res.app_id);

  if (cset_cb->cur_lock_req.value == LOCK_VALUE) {
    cset_cb->cur_lock_res.status = SOME_LOCKS_ACQUIRED_REASON_TIMEOUT;
    APPL_TRACE_DEBUG("%s: Process next device in the lock request", __func__);
    cset_cb->cur_lock_req.cur_idx++;
    bta_csip_send_lock_req_act(cset_cb);
  } else if (cset_cb->cur_lock_req.value == UNLOCK_VALUE) {
    cset_cb->cur_lock_res.addr.push_back(
    cset_cb->cur_lock_req.members_addr[cset_cb->cur_lock_req.cur_idx]);
    cset_cb->cur_lock_req.cur_idx++;
    bta_csip_send_unlock_req_act(cset_cb);
  }
}

/*******************************************************************************
 *
 * Function         bta_csip_le_encrypt_cback
 *
 * Description      link encryption complete callback.
 *
 * Returns          None
 *
 ******************************************************************************/
void bta_csip_le_encrypt_cback(const RawAddress* bd_addr,
                             UNUSED_ATTR tGATT_TRANSPORT transport,
                             UNUSED_ATTR void* p_ref_data, tBTM_STATUS result) {
  APPL_TRACE_ERROR("%s: status = %d", __func__, result);
  tBTA_CSIP_DEV_CB* p_cb = bta_csip_find_dev_cb_by_bda(*bd_addr);

  if (!p_cb) {
    APPL_TRACE_ERROR("unexpected encryption callback, ignore");
    return;
  }

  /* If encryption fails, disconnect the connection */
  if (result != BTM_SUCCESS) {
    bta_csip_close_csip_conn(p_cb);
    return;
  }

  if (p_cb->state == BTA_CSIP_W4_SEC) {
    bta_csip_sm_execute(p_cb, BTA_CSIP_ENC_CMPL_EVT, NULL);
  }
}

/*******************************************************************************
 *
 * Function         bta_csip_open_act
 *
 * Description      API Call to open CSIP Gatt Connection
 *
 * Returns          None
 *
 ******************************************************************************/
void bta_csip_api_open_act (tBTA_CSIP_DEV_CB* p_cb, tBTA_CSIP_REQ_DATA* p_data) {
  APPL_TRACE_DEBUG("%s: Open GATT connection for CSIP", __func__);

  tBTA_CSIP_API_CONN* p_conn_req = (tBTA_CSIP_API_CONN *)&p_data->conn_param;

  if (!bta_csip_is_app_reg(p_conn_req->app_id)) {
    LOG(ERROR) << __func__ << ": Request from Invalid/Unregistered App: "
                           << +p_conn_req->app_id;
    if (p_cb && (uint8_t)p_cb->conn_applist.size() == 0) {
      p_cb->state = BTA_CSIP_IDLE_ST;
    }
    // No need to send callback to invalid/unregistered app
    return;
  }

  if (btm_sec_is_a_bonded_dev(p_cb->addr) && !bta_csip_is_csis_supported(p_cb)) {
    APPL_TRACE_DEBUG("%s: Remote (%s) doesnt contain any coordinated set", __func__,
                     p_cb->addr.ToString().c_str());
    bta_csip_send_conn_state_changed_cb(p_cb, p_conn_req->app_id,
        BTA_CSIP_DISCONNECTED, BTA_CSIP_COORDINATED_SET_NOT_SUPPORTED);
    return;
  }

  if (!p_cb) {
    LOG(ERROR) << __func__ << ": Insufficient resources. Max"
                              " supported Set members have reached ";
    tBTA_CSIP_DEV_CB invalid_cb = {
        .addr = p_data->conn_param.bd_addr
    };
    bta_csip_send_conn_state_changed_cb(&invalid_cb, p_conn_req->app_id,
        BTA_CSIP_DISCONNECTED, BTA_CSIP_CONN_ESTABLISHMENT_FAILED);
    return;
  }

  // check if connection state is already connected
  if (p_cb->state == BTA_CSIP_CONN_ST) {
    if (!bta_csip_is_app_from_applist(p_cb, p_conn_req->app_id)) {
      bta_csip_add_app_to_applist(p_cb, p_conn_req->app_id);
    }
    bta_csip_send_conn_state_changed_cb(p_cb, p_conn_req->app_id,
        BTA_CSIP_CONNECTED, BTA_CSIP_CONN_ESTABLISHED);
    return;

  // other app has already started connection procedure
  } else if (!bta_csip_is_app_from_applist(p_cb, p_conn_req->app_id)
                && (uint8_t)p_cb->conn_applist.size() > 0
                && p_cb->state != BTA_CSIP_IDLE_ST) {
    LOG(INFO) << __func__ << ": Other app is establishing CSIP Connection."
                          << " Current connection state = " << +p_cb->state;
    bta_csip_add_app_to_applist(p_cb, p_conn_req->app_id);
    /* Note: Callback will given to all apps once connection procedure is completed */
    return;
  }

  p_cb->addr = p_data->conn_param.bd_addr;
  bta_csip_add_app_to_applist(p_cb, p_conn_req->app_id);

  BTA_GATTC_Open(bta_csip_cb.gatt_if, p_cb->addr, true, GATT_TRANSPORT_LE,
                 false);
}

/*******************************************************************************
 *
 * Function         bta_csip_api_close_act
 *
 * Description      API Call to close CSIP Gatt Connection
 *
 * Returns          None
 *
 ******************************************************************************/
void bta_csip_api_close_act (tBTA_CSIP_DEV_CB* p_cb, tBTA_CSIP_REQ_DATA* p_data) {
  if (!p_cb) {
    LOG(ERROR) << __func__ << " Already Closed";
    return;
  }

  tBTA_CSIP_API_CONN* p_req = (tBTA_CSIP_API_CONN *)&p_data->conn_param;

  LOG(INFO) << __func__ << " Disconnect Request from App: " << +p_req->app_id;

  if (!bta_csip_is_app_reg(p_req->app_id)) {
    LOG(ERROR) << __func__ << ": Request from Invalid/Unregistered App: "
                           << +p_req->app_id;
    // No need to send callback to invalid/unregistered app
    return;
  } else if (!bta_csip_is_app_from_applist(p_cb, p_req->app_id)) {
    LOG(ERROR) << __func__ << " App (ID:"<< +p_req->app_id <<") has not connected";
    bta_csip_send_conn_state_changed_cb(p_cb, p_req->app_id,
          BTA_CSIP_DISCONNECTED, BTA_CSIP_DISCONNECT_WITHOUT_CONNECT);
    return;
  }

  // Check if its last disconnecting app
  if ((uint8_t)p_cb->conn_applist.size() > 1) {
    bta_csip_remove_app_from_conn_list(p_cb, p_req->app_id);
    bta_csip_send_conn_state_changed_cb(p_cb, p_req->app_id,
          BTA_CSIP_DISCONNECTED, BTA_CSIP_APP_DISCONNECTED);
    return;
  }

  bta_csip_close_csip_conn(p_cb);
}

/*******************************************************************************
 *
 * Function         bta_csip_gatt_open_act
 *
 * Description      Callback function when GATT Connection is created.
 *
 * Returns          None
 *
 ******************************************************************************/
void bta_csip_gatt_open_act (tBTA_CSIP_DEV_CB* p_cb, tBTA_CSIP_REQ_DATA* p_data) {
  tBTA_GATTC_OPEN* open_param = &p_data->gatt_open_param;
  LOG(INFO) << __func__ << " Remote = " << open_param->remote_bda
                        << " Status = " << open_param->status
                        << " conn_id = " << open_param->conn_id;

  if (open_param->status == GATT_SUCCESS) {
    p_cb->in_use = true;
    p_cb->conn_id = open_param->conn_id;
    BtaGattQueue::Clean(p_cb->conn_id);
    bta_csip_sm_execute(p_cb, BTA_CSIP_START_ENC_EVT, NULL);
  } else {
    /* open failure */
    bta_csip_sm_execute(p_cb, BTA_CSIP_OPEN_FAIL_EVT, p_data);
  }
}

/*******************************************************************************
 *
 * Function         bta_csip_gatt_close_act
 *
 * Description      Callback function when GATT Connection is closed.
 *
 * Returns          None
 *
 ******************************************************************************/
void bta_csip_gatt_close_act (tBTA_CSIP_DEV_CB* p_cb, tBTA_CSIP_REQ_DATA* p_data) {
  tBTA_GATTC_OPEN* open_param = &p_data->gatt_open_param;

  // Give callback to all apps from connection applist
  bta_csip_send_conn_state_changed_cb(p_cb, BTA_CSIP_DISCONNECTED, open_param->status);

  // Clear applist
  p_cb->conn_applist.clear();

  for (int i = 0; i < MAX_SUPPORTED_SETS_PER_DEVICE; i++) {
    tBTA_CSIS_SRVC_INFO* srvc = &p_cb->csis_srvc[i];
    if (srvc->in_use) {
      srvc->lock = UNLOCK_VALUE;
    }
  }

  p_cb->conn_id = 0;
  p_cb->in_use = false;
}

/*******************************************************************************
 *
 * Function         bta_csip_gatt_open_fail_act
 *
 * Description      Callback function when GATT Connection fails to be created.
 *
 * Returns          None
 *
 ******************************************************************************/
void bta_csip_gatt_open_fail_act (tBTA_CSIP_DEV_CB* p_cb,
                                  tBTA_CSIP_REQ_DATA* p_data) {
  LOG(ERROR) << __func__ << " Failed to open GATT Connection";

  tBTA_GATTC_OPEN* open_param = &p_data->gatt_open_param;

  // Give callback to all apps from connection applist waiting for connection
  bta_csip_send_conn_state_changed_cb(p_cb, BTA_CSIP_DISCONNECTED, open_param->status);

  // Clear applist
  p_cb->conn_applist.clear();
  p_cb->in_use = false;
}

/*******************************************************************************
 *
 * Function         bta_csip_open_cmpl_act
 *
 * Description      Tasks needed to be done when connection is established.
 *
 * Returns          None
 *
 ******************************************************************************/
void bta_csip_open_cmpl_act (tBTA_CSIP_DEV_CB* p_cb, tBTA_CSIP_REQ_DATA* p_data) {
  APPL_TRACE_DEBUG("%s", __func__);

  if (!p_cb) {
    LOG(ERROR) << __func__ << " Invalid device contrl block";
    return;
  }

  // Give callback to all apps from connection applist waiting for connection
  bta_csip_send_conn_state_changed_cb(p_cb, BTA_CSIP_CONNECTED,
                                      BTA_CSIP_CONN_ESTABLISHED);

  /* Register for notification of required CSIS characteristic*/
  int i = 0;
  for (i = 0; i < MAX_SUPPORTED_SETS_PER_DEVICE; i++) {
      tBTA_CSIS_SRVC_INFO* srvc = &p_cb->csis_srvc[i];
    if (srvc->in_use) {
      bta_csip_write_cccd(p_cb, srvc->lock_handle, srvc->lock_ccd_handle);
      bta_csip_write_cccd(p_cb, srvc->size_handle, srvc->size_ccd_handle);
      bta_csip_write_cccd(p_cb, srvc->sirk_handle, srvc->sirk_ccd_handle);
    }
  }

}

/*******************************************************************************
 *
 * Function         bta_csip_start_sec_act
 *
 * Description      Tasks needed to be done to check or establish CSIP required
 *                  security.
 *
 * Returns          None
 *
 ******************************************************************************/
void bta_csip_start_sec_act (tBTA_CSIP_DEV_CB* p_cb, tBTA_CSIP_REQ_DATA* p_data) {
  APPL_TRACE_DEBUG("%s", __func__);

  uint8_t sec_flag = 0;

  // Get security flags for the device
  BTM_GetSecurityFlagsByTransport(p_cb->addr, &sec_flag, BT_TRANSPORT_LE);

  // link is already encrypted, send encryption complete callback to csip
  if (sec_flag & BTM_SEC_FLAG_ENCRYPTED) {
    LOG(INFO) << __func__ << " Already Encrypted";
    bta_csip_sm_execute(p_cb, BTA_CSIP_ENC_CMPL_EVT, NULL);
  }
  // device is bonded but link is not encrypted. Start encryption
  else if (sec_flag & BTM_SEC_FLAG_LKEY_KNOWN) {
    sec_flag = BTM_BLE_SEC_ENCRYPT;
    BTM_SetEncryption(p_cb->addr, BTA_TRANSPORT_LE, bta_csip_le_encrypt_cback,
                      NULL, sec_flag);
  }
  // unbonded device. Set MITM Encryption
  else if (p_cb->sec_mask != BTA_SEC_NONE) {
    sec_flag = BTM_BLE_SEC_ENCRYPT_MITM;
    BTM_SetEncryption(p_cb->addr, BTA_TRANSPORT_LE, bta_csip_le_encrypt_cback,
                      NULL, sec_flag);
  }
  // link is already encrypted
  else {
    bta_csip_sm_execute(p_cb, BTA_CSIP_ENC_CMPL_EVT, NULL);
  }
}

/*******************************************************************************
 *
 * Function         bta_csip_start_sec_act
 *
 * Description      Tasks needed to be done to check or establish CSIP required
 *                  security.
 *
 * Returns          None
 *
 ******************************************************************************/
void bta_csip_sec_cmpl_act (tBTA_CSIP_DEV_CB* p_cb, tBTA_CSIP_REQ_DATA* p_data) {
  APPL_TRACE_DEBUG("%s p_cb->csis_srvc[0].in_use = %d, p_cb->csis_srvc[0].sirk_handle = %d",
      __func__, p_cb->csis_srvc[0].in_use, p_cb->csis_srvc[0].sirk_handle);

  if (!p_cb->csis_srvc[0].in_use || !p_cb->csis_srvc[0].sirk_handle) {
    /* Service discovery is triggered from this path when csip connection is opened
     * from 3rd party application */
    LOG(INFO) << __func__ << "Service discovery is pending";
    Uuid pri_srvc = Uuid::From16Bit(UUID_SERVCLASS_CSIS);
    BTA_GATTC_ServiceSearchRequest(p_cb->conn_id, &pri_srvc);
  } else {
    LOG(INFO) << __func__ << "Service discovery is already completed";
    bta_csip_sm_execute(p_cb, BTA_CSIP_OPEN_CMPL_EVT, NULL);
  }
}

/*******************************************************************************
 *
 * Function         bta_csip_close_csip_conn
 *
 * Description      API to close CSIP Connection and remove device from background
 *                  list.
 *
 * Returns          None
 *
 ******************************************************************************/
void bta_csip_close_csip_conn (tBTA_CSIP_DEV_CB* p_cb) {
  LOG(INFO) << __func__;
  if (p_cb->conn_id != GATT_INVALID_CONN_ID) {
    // clear pending GATT Requests
    BtaGattQueue::Clean(p_cb->conn_id);
    p_cb->state = BTA_CSIP_DISCONNECTING_ST;
    // Send Close to GATT Layer
    if (p_cb->state == BTA_CSIP_CONN_ST || p_cb->conn_id) {
      BTA_GATTC_Close(p_cb->conn_id);
    } else {
      BTA_GATTC_CancelOpen(bta_csip_cb.gatt_if, p_cb->addr, true);
      tBTA_GATTC_OPEN open = {.status = GATT_SUCCESS};
      bta_csip_gatt_close_act(p_cb,(tBTA_CSIP_REQ_DATA *)&open);
    }
  }
}

/*******************************************************************************
 *
 * Function         bta_csip_handle_notification
 *
 * Description      This function is called when notification is received on one
 *                  of the characteristic registered for notification.
 *
 * Returns          None
 *
 ******************************************************************************/
void bta_csip_handle_notification(tBTA_GATTC_NOTIFY* ntf) {
  if (!ntf->is_notify) return;
  LOG(INFO) << __func__<< " Set Member: " << ntf->bda << ", handle: " << ntf->handle;

  tBTA_CSIP_DEV_CB* p_cb = bta_csip_find_dev_cb_by_bda(ntf->bda);
  if (!p_cb) {
    LOG(ERROR) << __func__ << " No CSIP GATT Connection for this device";
    return;
  }

  const gatt::Characteristic* p_char =
    BTA_GATTC_GetCharacteristic(p_cb->conn_id, ntf->handle);
  if (p_char == NULL) {
    APPL_TRACE_ERROR(
        "%s: notification received for Unknown Characteristic, conn_id: "
        "0x%04x, handle: 0x%04x",
        __func__, p_cb->conn_id, ntf->handle);
    return;
  }

  if (p_char->uuid == CSIS_SERVICE_LOCK_UUID) {
    bta_csip_handle_lock_value_notif(p_cb, ntf->handle, ntf->value[0]);
  } else if (p_char->uuid == CSIS_SERVICE_SIRK_UUID) {
    //bta_csip_handle_sirk_change();
  } else if (p_char->uuid == CSIS_SERVICE_SIZE_UUID) {
    //bta_csip_handle_size_change();
  }
}

/*******************************************************************************
 *
 * Function         bta_csip_handle_lock_value_notif
 *
 * Description      This function is called when notification is received for
 *                  change in lock value on set member.
 *
 * Returns          None
 *
 ******************************************************************************/
void bta_csip_handle_lock_value_notif(tBTA_CSIP_DEV_CB* p_cb,
                                      uint16_t handle, uint8_t value) {
  tBTA_CSIS_SRVC_INFO* srvc = bta_csip_find_csis_srvc_by_lock_handle(p_cb, handle);
  if (!srvc) {
    LOG(ERROR) << __func__ << " CSIS Service instance not found for this handle";
    return;
  }

  /* LOCK has been released by Set member (by lock timeout) */
  if (value == UNLOCK_VALUE && srvc->lock == LOCK_VALUE) {
    srvc->lock = UNLOCK_VALUE;
    /* Give lock status changed notification to all apps holding
     * lock for this set member */
    LOG(INFO) << __func__ << " Lock released by timeout";
    for (auto i: srvc->lock_applist) {
      tBTA_CSIP_RCB* rcb = bta_csip_get_rcb(i);
      if (rcb && rcb->p_cback) {
        std::vector<RawAddress> sm(1, p_cb->addr);
        tBTA_LOCK_STATUS_CHANGED p_data = {i, srvc->set_id, value,
                                           LOCK_RELEASED_TIMEOUT, sm};
        (*rcb->p_cback) (BTA_CSIP_LOCK_STATUS_CHANGED_EVT, (tBTA_CSIP_DATA *)&p_data);
      }
    }
    srvc->lock_applist.clear();
  }
  /* LOCK held by other set coordinator is released */
  else if (value == UNLOCK_VALUE && srvc->lock == UNLOCK_VALUE) {
    // check if lock was denied for any previous request
    for (auto i: srvc->denied_applist) {
      tBTA_CSIP_RCB* rcb = bta_csip_get_rcb(i);
      if (rcb && rcb->p_cback) {
         tBTA_LOCK_AVAILABLE p_data = {i, srvc->set_id, p_cb->addr};
        (*rcb->p_cback) (BTA_CSIP_LOCK_AVAILABLE_EVT, (tBTA_CSIP_DATA *)&p_data);
      }
    }
    srvc->denied_applist.clear();
  }
  /* Other Set Coordinator acquired the lock */
  else if (value == LOCK_VALUE && srvc->lock == UNLOCK_VALUE) {
    // No action is required to be taken
  }
}

/*******************************************************************************
 *
 * Function         bta_csip_csis_disc_complete_ind
 *
 * Description      This function informas CSIS service discovery has been
 *                  completed to DM layer.
 *
 * Returns          None
 *
 ******************************************************************************/
void bta_csip_csis_disc_complete_ind (RawAddress& addr) {
   tBTA_CSIP_DEV_CB* p_cb = bta_csip_find_dev_cb_by_bda(addr);
   if (p_cb) {
     p_cb->total_instance_disc++;
     LOG(INFO) << __func__ << " discovered = " << +p_cb->total_instance_disc
                           << " Total = " << +p_cb->csis_instance_count;
     if (p_cb->total_instance_disc == p_cb->csis_instance_count
         && !p_cb->is_disc_external) {
       bta_dm_csis_disc_complete(addr, true);
       bta_dm_lea_disc_complete(addr);
     }
   }
}

/*******************************************************************************
 *
 * Function         bta_csip_give_new_set_found_cb
 *
 * Description      Give new coordinate set found callback to upper layer.
 *
 * Returns          None
 *
 ******************************************************************************/
void bta_csip_give_new_set_found_cb (tBTA_CSIS_SRVC_INFO *srvc) {
  /* Check if this remote csis instance is included in another service */
  const std::vector<gatt::Service>* services =
      BTA_GATTC_GetServices(srvc->conn_id);

  if (services) {
    for (const gatt::Service& service : *services) {
      if (service.is_primary) {
        for (const gatt::IncludedService &included_srvc : service.included_services) {
          if (included_srvc.uuid == CSIS_SERVICE_UUID
                  && service.handle == srvc->service_handle) {
            APPL_TRACE_DEBUG("%s: service Uuid of service including CSIS service : %s",
                                    __func__, service.uuid.ToString().c_str());
            srvc->including_srvc_uuid = service.uuid;
          }
        }
      }
    }
  }

  // Given New Set found callback to upper layer
  tBTA_CSIP_NEW_SET_FOUND new_set_params;
  new_set_params.set_id = srvc->set_id;
  memcpy(new_set_params.sirk, srvc->sirk, SIRK_SIZE);
  new_set_params.size = srvc->size;
  new_set_params.including_srvc_uuid = srvc->including_srvc_uuid;
  new_set_params.addr = srvc->bd_addr;
  new_set_params.lock_support = (srvc->lock_handle != 0)? true : false;

  (*bta_csip_cb.p_cback)(BTA_CSIP_NEW_SET_FOUND_EVT, (tBTA_CSIP_DATA *)&new_set_params);
}

bool bta_csip_decrypt_sirk(tBTA_CSIS_SRVC_INFO *srvc, uint8_t *enc_sirk) {
  // Get K from LTK or Link Key based on transport
  Octet16 K = {};
  uint8_t gatt_if, transport = BT_TRANSPORT_LE;
  RawAddress bdaddr;
  GATT_GetConnectionInfor(srvc->conn_id, &gatt_if, bdaddr, &transport);

  char sample_data_prop[6];
  osi_property_get("vendor.bt.pts.sample_csis_data", sample_data_prop, "false");

  if (!strncmp("true", sample_data_prop, 4)) { // comparing prop with "true"
    K = {0x67, 0x6e, 0x1b, 0x9b, 0xd4, 0x48, 0x69, 0x6f,
         0x06, 0x1e, 0xc6, 0x22, 0x3c, 0xe5, 0xce, 0xd9};
  } else if (transport == BT_TRANSPORT_BR_EDR) {
    K = BTM_SecGetDeviceLinkKey(srvc->bd_addr);
  } else if (transport == BT_TRANSPORT_LE) {
    RawAddress pseudo_addr;
    pseudo_addr = bta_get_pseudo_addr_with_id_addr(srvc->bd_addr);
    Octet16 rev_K = BTM_BleGetLTK(pseudo_addr);
    std::reverse_copy(rev_K.begin(), rev_K.end(), K.begin());
  }

  if(is_key_empty(K)) {
    APPL_TRACE_DEBUG("%s Invalid Key received", __func__);
    srvc->discovery_status = BTA_CSIP_INVALID_KEY;
    return false;
  }

  /* compute SALT */
  Octet16 salt = bta_csip_get_salt();

  // Compute T
  Octet16 T = bta_csip_compute_T(salt, K);

  // Compute final result k1
  Octet16 k1 = bta_csip_compute_k1(T);

  // Get decrypted SIRK
  Octet16 r_k1;
  std::reverse_copy(k1.begin(), k1.end(), r_k1.begin());
  bta_csip_get_decrypted_sirk(r_k1, enc_sirk, srvc->sirk);
  return true;
}

/*******************************************************************************
 *
 * Function         bta_sirk_read_cb
 *
 * Description      Callback received when remote device Coordinated Sets SIRK
 *                  is read.
 *
 * Returns          None
 *
 ******************************************************************************/
void bta_sirk_read_cb(uint16_t conn_id, tGATT_STATUS status,
                  uint16_t handle, uint16_t len,
                  uint8_t* value, void* data) {
  APPL_TRACE_DEBUG("%s ", __func__);

  if (status != GATT_SUCCESS) {
    APPL_TRACE_ERROR("%s: SIRK Read failed. conn_id = %d status = %04x",
                        __func__, conn_id, status);
    return;
  }

  tBTA_CSIS_SRVC_INFO *srvc = (tBTA_CSIS_SRVC_INFO *)data;

  uint8_t type = 0xFF;
  LOG(INFO) << __func__ << " SIRK len = " << +len;

  if (len != (SIRK_SIZE + 1)) {
    APPL_TRACE_ERROR("%s : Invalid SIRK length", __func__);
    srvc->discovery_status = BTA_CSIP_INVALID_SIRK_FORMAT;
    bta_csip_csis_disc_complete_ind(srvc->bd_addr);
    return;
  }

  STREAM_TO_UINT8(type, value);
  APPL_TRACE_DEBUG("%s Type Field with SIRK = %d", __func__, type);
  if (type != ENCRYPTED_SIRK && type != PLAINTEXT_SIRK) {
    APPL_TRACE_ERROR("%s : Invalid SIRK Type", __func__);
    srvc->discovery_status = BTA_CSIP_INVALID_KEY_TYPE;
    bta_csip_csis_disc_complete_ind(srvc->bd_addr);
    return;
  }

  if (type == ENCRYPTED_SIRK) {
    uint8_t enc_sirk[SIRK_SIZE] = {};
    STREAM_TO_ARRAY(enc_sirk, value, SIRK_SIZE);
    if (!bta_csip_decrypt_sirk(srvc, enc_sirk)) {
      APPL_TRACE_ERROR("%s : Invalid Empty Key", __func__);
      srvc->discovery_status = BTA_CSIP_INVALID_KEY;
      bta_csip_csis_disc_complete_ind(srvc->bd_addr);
      return;
    }
  } else {
    STREAM_TO_ARRAY(srvc->sirk, value, SIRK_SIZE);
  }
  // check if this set was found earlier
  uint8_t set_id = bta_csip_find_set_id_by_sirk (srvc->sirk);
  tBTA_CSET_CB *cset_cb = NULL;

  /* New Coordinated Set */
  if (set_id == INVALID_SET_ID) {
    cset_cb = bta_csip_get_cset_cb();
    if (!cset_cb) {
      LOG(ERROR) << __func__ << " Insufficient set control blocks available.";
      srvc->discovery_status = BTA_CSIP_RSRC_EXHAUSTED;
      bta_csip_csis_disc_complete_ind(srvc->bd_addr);
      return;
    }
    memcpy(cset_cb->sirk, srvc->sirk, SIRK_SIZE);

    // Create new coordinated set and update in database
    tBTA_CSIP_CSET cset = {};
    cset.set_id = cset_cb->set_id;
    cset.set_members.push_back(srvc->bd_addr);
    cset.total_discovered++;
    cset.lock_support = (srvc->lock_handle != 0 ? true : false);
    LOG(INFO) << __func__ << "New Set. Adding device " << srvc->bd_addr.ToString()
                          << " Set ID: " << +cset.set_id;
    bta_csip_cb.csets.push_back(cset);

    // assign set id in respective control blocks
    srvc->set_id = cset_cb->set_id;

  /* Existing coordinated Set */
  } else {
    LOG(INFO) << __func__ << " Device from existing set (set_id: " << +set_id << " )";
    //bta_csip_csis_disc_complete_ind(srvc->bd_addr);
    srvc->set_id = set_id;
    if (!bta_csip_update_set_member(set_id, srvc->bd_addr)) {
      srvc->discovery_status = BTA_CSIP_ALL_MEMBERS_DISCOVERED;
      bta_csip_csis_disc_complete_ind(srvc->bd_addr);
      return;
    }

    // Give set member found callback
    tBTA_SET_MEMBER_FOUND set_member_params =
        { .set_id = set_id,
          .addr = srvc->bd_addr,
        };

    bta_csip_cb.p_cback (BTA_CSIP_SET_MEMBER_FOUND_EVT, (tBTA_CSIP_DATA *)&set_member_params);
    return;
  }

  /* If size is optional, give callback to upper layer */
  if (!srvc->size_handle) {
    bta_csip_give_new_set_found_cb(srvc);
  }

  if (!srvc->size_handle && !srvc->rank_handle) {
    bta_csip_preserve_cset(srvc);
  }
}

/*******************************************************************************
 *
 * Function         bta_size_read_cb
 *
 * Description      Callback received when remote device Coordinated Sets SIZE
 *                  characteristic is read.
 *
 * Returns          None
 *
 ******************************************************************************/
void bta_size_read_cb(uint16_t conn_id, tGATT_STATUS status,
                  uint16_t handle, uint16_t len,
                  uint8_t* value, void* data) {

  if (status != GATT_SUCCESS) {
    APPL_TRACE_ERROR("%s: SIZE Read failed. conn_id = %d status = %04x",
                        __func__, conn_id, status);
    return;
  }

  tBTA_CSIS_SRVC_INFO *srvc = (tBTA_CSIS_SRVC_INFO *)data;

  if (srvc->discovery_status != BTA_CSIP_DISC_SUCCESS) {
    APPL_TRACE_ERROR("%s: Ignore response (Reason: %d)", __func__, srvc->discovery_status);
    return;
  }

  srvc->size = *value;
  APPL_TRACE_DEBUG("%s size = %d", __func__, srvc->size);

  tBTA_CSIP_CSET* cset = bta_csip_get_or_create_cset(srvc->set_id, true);
  if (cset) cset->size = srvc->size;
  // Give callback only when its a first set member
  uint8_t totalDiscovered = bta_csip_get_coordinated_set(srvc->set_id).set_members.size();
  if (totalDiscovered == 1) {
    bta_csip_give_new_set_found_cb(srvc);
  }

  if (!srvc->rank_handle) {
    bta_csip_preserve_cset(srvc);
  }
}

/*******************************************************************************
 *
 * Function         bta_lock_read_cb
 *
 * Description      Callback received when remote device Coordinated Sets LOCK
 *                  characteristic is read.
 *
 * Returns          None
 *
 ******************************************************************************/
void bta_lock_read_cb(uint16_t conn_id, tGATT_STATUS status,
                  uint16_t handle, uint16_t len,
                  uint8_t* value, void* data) {
  if (status != GATT_SUCCESS) {
    APPL_TRACE_ERROR("%s: LOCK Read failed. conn_id = %d status = %04x",
                        __func__, conn_id, status);
    return;
  }

  APPL_TRACE_DEBUG("%s lock value = %d", __func__, *value);
}

/*******************************************************************************
 *
 * Function         bta_rank_read_cb
 *
 * Description      Callback received when remote device Coordinated Sets RANK
 *                  characteristic is read.
 *
 * Returns          None
 *
 ******************************************************************************/
void bta_rank_read_cb(uint16_t conn_id, tGATT_STATUS status,
                  uint16_t handle, uint16_t len,
                  uint8_t* value, void* data) {
  if (status != GATT_SUCCESS) {
    APPL_TRACE_ERROR("%s: Rank Read failed. conn_id = %d status = %04x",
                        __func__, conn_id, status);
    return;
  }

  tBTA_CSIS_SRVC_INFO *srvc = (tBTA_CSIS_SRVC_INFO *)data;
  if (srvc->discovery_status != BTA_CSIP_DISC_SUCCESS) {
    APPL_TRACE_ERROR("%s: Ignore response (Reason: %d)", __func__, srvc->discovery_status);
    return;
  }

  srvc->rank = *value;
  APPL_TRACE_DEBUG("%s device: %s Rank = %d set_id: %d", __func__,
                   srvc->bd_addr.ToString().c_str(), srvc->rank, srvc->set_id);

  // get coordinated set control block from set_id
  tBTA_CSET_CB *cset_cb = bta_csip_get_cset_cb_by_id(srvc->set_id);
  if (cset_cb) {
    cset_cb->ordered_members.insert({srvc->rank, srvc->bd_addr});
  }

  bta_csip_preserve_cset(srvc);
  bta_csip_csis_disc_complete_ind(srvc->bd_addr);
}

/*******************************************************************************
 *
 * Function         bta_csip_gatt_disc_cmpl_act
 *
 * Description      This APIS is used to serach presence of csis service on
 *                  remote device and initialize CSIS handles in csis service
 *                  control block.
 *
 * Returns          None
 *
 ******************************************************************************/
void bta_csip_gatt_disc_cmpl_act(tBTA_CSIP_DISC_SET *disc_params) {
  uint16_t conn_id = disc_params->conn_id;
  uint8_t status = disc_params->status;
  RawAddress addr = disc_params->addr;

  APPL_TRACE_DEBUG("%s conn_id = %d, status = %d addr: %s", __func__, conn_id,
                   status, addr.ToString().c_str());

  if (status) return;

  // Fetch remote device gatt services from database
  const std::vector<gatt::Service>* services =
      BTA_GATTC_GetServices(conn_id);

  if (!services) {
    LOG(ERROR) << __func__ << " No Services discovered.";
    bta_csip_csis_disc_complete_ind(addr);
    return;
  }

  tBTA_CSIP_DEV_CB* dev_cb = bta_csip_find_dev_cb_by_bda(addr);

  if (!dev_cb) {
    dev_cb = bta_csip_create_dev_cb_for_bda(addr);
  }

  dev_cb->csis_instance_count = 0;

  // Search for CSIS service in the database
  for (const gatt::Service& service : *services) {
    if (service.uuid == CSIS_SERVICE_UUID) {
      dev_cb->csis_instance_count++;
      // Get service control block from service handle (subsequent connection)
      tBTA_CSIS_SRVC_INFO *srvc = bta_csip_get_csis_service_by_handle(dev_cb, service.handle);
      if (!srvc) {
        // create new service cb (if its a first time connection)
        srvc = bta_csip_get_csis_service_cb(dev_cb);
        if (!srvc) {
          APPL_TRACE_ERROR("%s Resources not available for storing CSIS Service.", __func__);
          return;
        }
      }
      srvc->bd_addr = addr;
      srvc->service_handle = service.handle;
      srvc->conn_id = conn_id;
      APPL_TRACE_DEBUG("%s: CSIS service found Uuid: %s service_handle = %d", __func__,
                          service.uuid.ToString().c_str(), srvc->service_handle);

      // Get Characteristic and CCCD handle
      for (const gatt::Characteristic& charac : service.characteristics) {
          Uuid uuid1 = charac.uuid;
          if (uuid1 == CSIS_SERVICE_SIRK_UUID) {
            srvc->sirk_handle = charac.value_handle;
            srvc->sirk_ccd_handle = bta_csip_get_cccd_handle(conn_id, charac.value_handle);
          } else if (uuid1 == CSIS_SERVICE_SIZE_UUID) {
            srvc->size_handle = charac.value_handle;
            srvc->size_ccd_handle = bta_csip_get_cccd_handle(conn_id, charac.value_handle);
          } else if (uuid1 == CSIS_SERVICE_LOCK_UUID) {
            srvc->lock_handle = charac.value_handle;
            srvc->lock_ccd_handle = bta_csip_get_cccd_handle(conn_id, charac.value_handle);
          } else if (uuid1 == CSIS_SERVICE_RANK_UUID) {
            srvc->rank_handle = charac.value_handle;
          }
      }

      /* Skip reading characteristics and Set Discovery procedure if it was done earlier */
      if (srvc->set_id >= 0 && srvc->set_id < BTA_MAX_SUPPORTED_SETS) {
        LOG(INFO) << __func__ << " Coordinated set discovery procedure already completed.";
        continue;
      }

      if (srvc->sirk_handle) {
        BtaGattQueue::ReadCharacteristic(
            conn_id, srvc->sirk_handle, bta_sirk_read_cb, srvc);
      }

      if (srvc->size_handle) {
        BtaGattQueue::ReadCharacteristic(
            conn_id, srvc->size_handle, bta_size_read_cb, srvc);
      }

      if (srvc->lock_handle) {
        BtaGattQueue::ReadCharacteristic(
            conn_id, srvc->lock_handle, bta_lock_read_cb, srvc);
      }

      if (srvc->rank_handle) {
        BtaGattQueue::ReadCharacteristic(
            conn_id, srvc->rank_handle, bta_rank_read_cb, srvc);
      }
    }

  }
}
