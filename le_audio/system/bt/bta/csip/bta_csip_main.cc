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


#include "bt_target.h"
#include "bta_csip_int.h"

#include <string.h>

#include "bt_common.h"

#define LOG_TAG "bt_bta_csip"

/*****************************************************************************
 * Static methods
 ****************************************************************************/
static const char* bta_csip_evt_code(uint16_t evt_code);
static const char* bta_csip_state_code(tBTA_CSIP_STATE evt_code);

/*****************************************************************************
 * Global data
 ****************************************************************************/
tBTA_CSIP_CB bta_csip_cb;

enum {
  BTA_CSIP_OPEN_ACT,
  BTA_CSIP_CLOSE_ACT,
  BTA_CSIP_GATT_OPEN_ACT,
  BTA_CSIP_GATT_CLOSE_ACT,
  BTA_CSIP_GATT_OPEN_FAIL_ACT,
  BTA_CSIP_OPEN_CMPL_ACT,
  BTA_CSIP_START_SEC_ACT,
  BTA_CSIP_SEC_CMPL_ACT,
  BTA_CSIP_IGNORE,
};

/* type for action functions */
typedef void (*tBTA_CSIP_ACTION)(tBTA_CSIP_DEV_CB* p_cb, tBTA_CSIP_REQ_DATA* p_data);

/* action functions */
const tBTA_CSIP_ACTION bta_csip_action[] = {
  bta_csip_api_open_act,
  bta_csip_api_close_act,
  bta_csip_gatt_open_act,
  bta_csip_gatt_close_act,
  bta_csip_gatt_open_fail_act,
  bta_csip_open_cmpl_act,
  bta_csip_start_sec_act,
  bta_csip_sec_cmpl_act,
};

/* state table information */
#define BTA_CSIP_ACTION 0     /* position of action */
#define BTA_CSIP_NEXT_STATE 1 /* position of next state */
#define BTA_CSIP_NUM_COLS 2   /* number of columns */

/* state table in idle state */
const uint8_t bta_csip_st_idle[][BTA_CSIP_NUM_COLS] = {
    /* Event                                 Action              Next state */
    /* BTA_CSIP_API_OPEN_EVT          */ {BTA_CSIP_OPEN_ACT, BTA_CSIP_W4_CONN_ST},
    /* BTA_CSIP_API_CLOSE_EVT         */ {BTA_CSIP_IGNORE,   BTA_CSIP_IDLE_ST},
    /* BTA_CSIP_GATT_OPEN_EVT         */ {BTA_CSIP_IGNORE,   BTA_CSIP_IDLE_ST},
    /* BTA_CSIP_GATT_CLOSE_EVT        */ {BTA_CSIP_IGNORE,   BTA_CSIP_IDLE_ST},
    /* BTA_CSIP_GATT_OPEN_FAIL_ACT    */ {BTA_CSIP_IGNORE,   BTA_CSIP_IDLE_ST},
    /* BTA_CSIP_OPEN_CMPL_EVT         */ {BTA_CSIP_OPEN_CMPL_ACT, BTA_CSIP_CONN_ST},
    /* BTA_CSIP_START_ENC_EVT         */ {BTA_CSIP_IGNORE,   BTA_CSIP_IDLE_ST},
    /* BTA_CSIP_ENC_CMPL_EVT          */ {BTA_CSIP_IGNORE,   BTA_CSIP_IDLE_ST},
};

/* state table in wait for security state */
const uint8_t bta_csip_st_w4_conn[][BTA_CSIP_NUM_COLS] = {
    /* Event                                 Action                       Next state */
    /* BTA_CSIP_API_OPEN_EVT          */ {BTA_CSIP_OPEN_ACT,           BTA_CSIP_W4_CONN_ST},
    /* BTA_CSIP_API_CLOSE_EVT         */ {BTA_CSIP_CLOSE_ACT,          BTA_CSIP_W4_CONN_ST},
    /* BTA_CSIP_GATT_OPEN_EVT         */ {BTA_CSIP_GATT_OPEN_ACT,      BTA_CSIP_W4_CONN_ST},
    /* BTA_CSIP_GATT_CLOSE_EVT        */ {BTA_CSIP_GATT_CLOSE_ACT,     BTA_CSIP_IDLE_ST},
    /* BTA_CSIP_GATT_OPEN_FAIL_ACT    */ {BTA_CSIP_GATT_OPEN_FAIL_ACT, BTA_CSIP_IDLE_ST},
    /* BTA_CSIP_OPEN_CMPL_EVT         */ {BTA_CSIP_OPEN_CMPL_ACT,      BTA_CSIP_CONN_ST},
    /* BTA_CSIP_START_ENC_EVT         */ {BTA_CSIP_START_SEC_ACT,      BTA_CSIP_W4_SEC},
    /* BTA_CSIP_ENC_CMPL_EVT          */ {BTA_CSIP_IGNORE,             BTA_CSIP_W4_CONN_ST},
};

/* state table in wait for connection state */
const uint8_t bta_csip_st_w4_sec[][BTA_CSIP_NUM_COLS] = {
    /* Event                                 Action                       Next state */
    /* BTA_CSIP_API_OPEN_EVT          */ {BTA_CSIP_OPEN_ACT,           BTA_CSIP_W4_SEC},
    /* BTA_CSIP_API_CLOSE_EVT         */ {BTA_CSIP_CLOSE_ACT,          BTA_CSIP_W4_SEC},
    /* BTA_CSIP_GATT_OPEN_EVT         */ {BTA_CSIP_IGNORE,             BTA_CSIP_W4_SEC},
    /* BTA_CSIP_GATT_CLOSE_EVT        */ {BTA_CSIP_GATT_CLOSE_ACT,     BTA_CSIP_IDLE_ST},
    /* BTA_CSIP_GATT_OPEN_FAIL_ACT    */ {BTA_CSIP_GATT_OPEN_FAIL_ACT, BTA_CSIP_IDLE_ST},
    /* BTA_CSIP_OPEN_CMPL_EVT         */ {BTA_CSIP_OPEN_CMPL_ACT,      BTA_CSIP_CONN_ST},
    /* BTA_CSIP_START_ENC_EVT         */ {BTA_CSIP_IGNORE,             BTA_CSIP_W4_SEC},
    /* BTA_CSIP_ENC_CMPL_EVT          */ {BTA_CSIP_SEC_CMPL_ACT,       BTA_CSIP_W4_CONN_ST},
};

/* state table in connection state */
const uint8_t bta_csip_st_connected[][BTA_CSIP_NUM_COLS] = {
    /* Event                                 Action                       Next state */
    /* BTA_CSIP_API_OPEN_EVT          */ {BTA_CSIP_OPEN_ACT,           BTA_CSIP_CONN_ST},
    /* BTA_CSIP_API_CLOSE_EVT         */ {BTA_CSIP_CLOSE_ACT,          BTA_CSIP_CONN_ST},
    /* BTA_CSIP_GATT_OPEN_EVT         */ {BTA_CSIP_IGNORE,             BTA_CSIP_CONN_ST},
    /* BTA_CSIP_GATT_CLOSE_EVT        */ {BTA_CSIP_GATT_CLOSE_ACT,     BTA_CSIP_IDLE_ST},
    /* BTA_CSIP_GATT_OPEN_FAIL_ACT    */ {BTA_CSIP_GATT_OPEN_FAIL_ACT, BTA_CSIP_IDLE_ST},
    /* BTA_CSIP_OPEN_CMPL_EVT         */ {BTA_CSIP_IGNORE,             BTA_CSIP_CONN_ST},
    /* BTA_CSIP_START_ENC_EVT         */ {BTA_CSIP_IGNORE,             BTA_CSIP_CONN_ST},
    /* BTA_CSIP_ENC_CMPL_EVT          */ {BTA_CSIP_IGNORE,             BTA_CSIP_CONN_ST},
};

/* state table in disconnecting state */
const uint8_t bta_csip_st_disconnecting[][BTA_CSIP_NUM_COLS] = {
    /* Event                                 Action                       Next state */
    /* BTA_CSIP_API_OPEN_EVT          */ {BTA_CSIP_IGNORE,          BTA_CSIP_DISCONNECTING_ST},
    /* BTA_CSIP_API_CLOSE_EVT         */ {BTA_CSIP_IGNORE,          BTA_CSIP_DISCONNECTING_ST},
    /* BTA_CSIP_GATT_OPEN_EVT         */ {BTA_CSIP_IGNORE,          BTA_CSIP_DISCONNECTING_ST},
    /* BTA_CSIP_GATT_CLOSE_EVT        */ {BTA_CSIP_GATT_CLOSE_ACT,  BTA_CSIP_IDLE_ST},
    /* BTA_CSIP_GATT_OPEN_FAIL_ACT    */ {BTA_CSIP_IGNORE,          BTA_CSIP_DISCONNECTING_ST},
    /* BTA_CSIP_OPEN_CMPL_EVT         */ {BTA_CSIP_IGNORE,          BTA_CSIP_DISCONNECTING_ST},
    /* BTA_CSIP_START_ENC_EVT         */ {BTA_CSIP_IGNORE,          BTA_CSIP_DISCONNECTING_ST},
    /* BTA_CSIP_ENC_CMPL_EVT          */ {BTA_CSIP_IGNORE,          BTA_CSIP_DISCONNECTING_ST},
};

/* type for state table */
typedef const uint8_t (*tBTA_CSIP_ST_TBL)[BTA_CSIP_NUM_COLS];

/* state table */
tBTA_CSIP_ST_TBL bta_csip_st_tbl[] = {bta_csip_st_idle, bta_csip_st_w4_conn,
                                     bta_csip_st_w4_sec, bta_csip_st_connected,
                                     bta_csip_st_disconnecting};

/*******************************************************************************
 *
 * Function         bta_csip_sm_execute
 *
 * Description      API to execute state operation.
 *
 * Returns          void
 *
 ******************************************************************************/
void bta_csip_sm_execute(tBTA_CSIP_DEV_CB* p_cb, uint16_t event,
                              tBTA_CSIP_REQ_DATA* p_data) {
  tBTA_CSIP_ST_TBL state_table;
  uint8_t action;

  if (!p_cb) {
    APPL_TRACE_ERROR("%s: Device not found. Return.", __func__);
    return;
  }

  state_table = bta_csip_st_tbl[p_cb->state];

  event &= 0xff;

  p_cb->state = state_table[event][BTA_CSIP_NEXT_STATE];
  APPL_TRACE_DEBUG("%s: Next State = %d(%s) event = %04x(%s)", __func__,
                   p_cb->state, bta_csip_state_code(p_cb->state), event,
                   bta_csip_evt_code(event));

  action = state_table[event][BTA_CSIP_ACTION];
  APPL_TRACE_DEBUG("%s: action = %d", __func__, action);
  if (action != BTA_CSIP_IGNORE) {
    (*bta_csip_action[action])(p_cb, p_data);
  }

}

/*******************************************************************************
 *
 * Function         bta_csip_hdl_event
 *
 * Description      CSIP client main event handling function.
 *
 * Returns          void
 *
 ******************************************************************************/
bool bta_csip_hdl_event(BT_HDR* p_msg) {
  tBTA_CSIP_DEV_CB* dev_cb = NULL;

  APPL_TRACE_DEBUG("%s: Event: %04x", __func__, p_msg->event);

  switch (p_msg->event) {
    case BTA_CSIP_API_ENABLE_EVT:
      bta_csip_api_enable(((tBTA_CSIP_ENABLE *)p_msg)->p_cback);
      break;

    case BTA_CSIP_API_DISABLE_EVT:
      bta_csip_api_disable();
      break;

    case BTA_CSIP_DISC_CMPL_EVT:
      bta_csip_gatt_disc_cmpl_act((tBTA_CSIP_DISC_SET *)p_msg);
      break;

    case BTA_CSIP_SET_LOCK_VALUE_EVT:
      bta_csip_process_set_lock_act(((tBTA_CSIP_LOCK_PARAMS*)p_msg)->lock_req);
      break;

    default:
      if (p_msg->event ==  BTA_CSIP_API_OPEN_EVT) {
        RawAddress bd_addr = ((tBTA_CSIP_API_CONN *)p_msg)->bd_addr;
        dev_cb = bta_csip_find_dev_cb_by_bda(bd_addr);
        if (!dev_cb) {
          dev_cb = bta_csip_create_dev_cb_for_bda(bd_addr);
          APPL_TRACE_DEBUG("%s: Created Device CB for device: %s",
                              __func__, bd_addr.ToString().c_str());
        }
      } else if (p_msg->event ==  BTA_CSIP_API_CLOSE_EVT) {
        dev_cb = bta_csip_find_dev_cb_by_bda(((tBTA_CSIP_API_CONN *)p_msg)->bd_addr);
      }

      bta_csip_sm_execute(dev_cb, p_msg->event, (tBTA_CSIP_REQ_DATA*)p_msg);
  }

  return (true);

}

/*******************************************************************************
 *
 * Function         bta_csip_evt_code
 *
 * Description      returns event name in string format
 *
 * Returns          string representation of event code
 *
 ******************************************************************************/
static const char* bta_csip_evt_code(uint16_t evt_code) {
  evt_code = (BTA_ID_GROUP << 8) | evt_code;
  switch (evt_code) {
    case BTA_CSIP_API_OPEN_EVT:
      return "BTA_CSIP_API_OPEN_EVT";
    case BTA_CSIP_API_CLOSE_EVT:
      return "BTA_CSIP_API_CLOSE_EVT";
    case BTA_CSIP_GATT_OPEN_EVT:
      return "BTA_CSIP_GATT_OPEN_EVT";
    case BTA_CSIP_GATT_CLOSE_EVT:
      return "BTA_CSIP_GATT_CLOSE_EVT";
    case BTA_CSIP_OPEN_FAIL_EVT:
      return "BTA_CSIP_OPEN_FAIL_EVT";
    case BTA_CSIP_OPEN_CMPL_EVT:
      return "BTA_CSIP_OPEN_CMPL_EVT";
    case BTA_CSIP_START_ENC_EVT:
      return "BTA_CSIP_START_ENC_EVT";
    case BTA_CSIP_ENC_CMPL_EVT:
      return "BTA_CSIP_ENC_CMPL_EVT";
    case BTA_CSIP_API_ENABLE_EVT:
      return "BTA_CSIP_API_ENABLE_EVT";
    case BTA_CSIP_API_DISABLE_EVT:
      return "BTA_CSIP_API_DISABLE_EVT";
    case BTA_CSIP_SET_LOCK_VALUE_EVT:
      return "BTA_CSIP_SET_LOCK_VALUE_EVT";
    default:
      return "Unknown CSIP event code";
  }
}

/*******************************************************************************
 *
 * Function         bta_csip_state_code
 *
 * Description      returns state name in string format
 *
 * Returns          string representation of connection state
 *
 ******************************************************************************/
static const char* bta_csip_state_code(tBTA_CSIP_STATE state) {
  switch (state) {
    case BTA_CSIP_IDLE_ST:
      return "BTA_CSIP_IDLE_ST";
    case BTA_CSIP_W4_CONN_ST:
      return "BTA_CSIP_W4_CONN_ST";
    case BTA_CSIP_W4_SEC:
      return "BTA_CSIP_W4_SEC";
    case BTA_CSIP_CONN_ST:
      return "BTA_CSIP_CONN_ST";
    case BTA_CSIP_DISCONNECTING_ST:
      return "BTA_CSIP_DISCONNECTING_ST";
    default:
      return "Incorrect State";
  }
}

