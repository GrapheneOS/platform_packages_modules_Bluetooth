/******************************************************************************
 *
 *  Copyright (c) 2014 The Android Open Source Project
 *  Copyright (C) 2003-2012 Broadcom Corporation
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

#include <stdlib.h>
#include <string.h>

#include "bt_utils.h"
#include "bta_api.h"
#include "bta_hf_client_api.h"
#include "bta_hf_client_int.h"
#include "bta_sys.h"
#include "osi/include/osi.h"
#include "osi/include/properties.h"
#include "utl.h"

extern fixed_queue_t* btu_bta_alarm_queue;

static const char* bta_hf_client_evt_str(uint16_t event);
static const char* bta_hf_client_state_str(uint8_t state);

/* control block declaration */
extern tBTA_HF_CLIENT_CB bta_hf_client_cb;

/* state machine states */
enum {
  BTA_HF_CLIENT_INIT_ST,
  BTA_HF_CLIENT_OPENING_ST,
  BTA_HF_CLIENT_OPEN_ST,
  BTA_HF_CLIENT_CLOSING_ST
};

/* state machine action enumeration list */
enum {
  BTA_HF_CLIENT_RFC_DO_CLOSE,
  BTA_HF_CLIENT_START_CLOSE,
  BTA_HF_CLIENT_START_OPEN,
  BTA_HF_CLIENT_RFC_ACP_OPEN,
  BTA_HF_CLIENT_SCO_LISTEN,
  BTA_HF_CLIENT_SCO_CONN_OPEN,
  BTA_HF_CLIENT_SCO_CONN_CLOSE,
  BTA_HF_CLIENT_SCO_OPEN,
  BTA_HF_CLIENT_SCO_CLOSE,
  BTA_HF_CLIENT_FREE_DB,
  BTA_HF_CLIENT_OPEN_FAIL,
  BTA_HF_CLIENT_RFC_OPEN,
  BTA_HF_CLIENT_RFC_FAIL,
  BTA_HF_CLIENT_DISC_INT_RES,
  BTA_HF_CLIENT_RFC_DO_OPEN,
  BTA_HF_CLIENT_DISC_FAIL,
  BTA_HF_CLIENT_RFC_CLOSE,
  BTA_HF_CLIENT_RFC_DATA,
  BTA_HF_CLIENT_DISC_ACP_RES,
  BTA_HF_CLIENT_SVC_CONN_OPEN,
  BTA_HF_CLIENT_SEND_AT_CMD,
  BTA_HF_CLIENT_NUM_ACTIONS,
};

#define BTA_HF_CLIENT_IGNORE BTA_HF_CLIENT_NUM_ACTIONS

/* type for action functions */
typedef void (*tBTA_HF_CLIENT_ACTION)(tBTA_HF_CLIENT_DATA* p_data);

/* action functions table, indexed with action enum */
const tBTA_HF_CLIENT_ACTION bta_hf_client_action[] = {
    /* BTA_HF_CLIENT_RFC_DO_CLOSE */ bta_hf_client_rfc_do_close,
    /* BTA_HF_CLIENT_START_CLOSE */ bta_hf_client_start_close,
    /* BTA_HF_CLIENT_START_OPEN */ bta_hf_client_start_open,
    /* BTA_HF_CLIENT_RFC_ACP_OPEN */ bta_hf_client_rfc_acp_open,
    /* BTA_HF_CLIENT_SCO_LISTEN */ bta_hf_client_sco_listen,
    /* BTA_HF_CLIENT_SCO_CONN_OPEN */ bta_hf_client_sco_conn_open,
    /* BTA_HF_CLIENT_SCO_CONN_CLOSE*/ bta_hf_client_sco_conn_close,
    /* BTA_HF_CLIENT_SCO_OPEN */ bta_hf_client_sco_open,
    /* BTA_HF_CLIENT_SCO_CLOSE */ bta_hf_client_sco_close,
    /* BTA_HF_CLIENT_FREE_DB */ bta_hf_client_free_db,
    /* BTA_HF_CLIENT_OPEN_FAIL */ bta_hf_client_open_fail,
    /* BTA_HF_CLIENT_RFC_OPEN */ bta_hf_client_rfc_open,
    /* BTA_HF_CLIENT_RFC_FAIL */ bta_hf_client_rfc_fail,
    /* BTA_HF_CLIENT_DISC_INT_RES */ bta_hf_client_disc_int_res,
    /* BTA_HF_CLIENT_RFC_DO_OPEN */ bta_hf_client_rfc_do_open,
    /* BTA_HF_CLIENT_DISC_FAIL */ bta_hf_client_disc_fail,
    /* BTA_HF_CLIENT_RFC_CLOSE */ bta_hf_client_rfc_close,
    /* BTA_HF_CLIENT_RFC_DATA */ bta_hf_client_rfc_data,
    /* BTA_HF_CLIENT_DISC_ACP_RES */ bta_hf_client_disc_acp_res,
    /* BTA_HF_CLIENT_SVC_CONN_OPEN */ bta_hf_client_svc_conn_open,
    /* BTA_HF_CLIENT_SEND_AT_CMD */ bta_hf_client_send_at_cmd,
};

/* state table information */
#define BTA_HF_CLIENT_ACTIONS 2    /* number of actions */
#define BTA_HF_CLIENT_NEXT_STATE 2 /* position of next state */
#define BTA_HF_CLIENT_NUM_COLS 3   /* number of columns in state tables */

/* state table for init state */
const uint8_t bta_hf_client_st_init[][BTA_HF_CLIENT_NUM_COLS] = {
    /* Event                    Action 1                       Action 2
       Next state */
    /* API_OPEN_EVT */ {BTA_HF_CLIENT_START_OPEN, BTA_HF_CLIENT_IGNORE,
                        BTA_HF_CLIENT_OPENING_ST},
    /* API_CLOSE_EVT */ {BTA_HF_CLIENT_IGNORE, BTA_HF_CLIENT_IGNORE,
                         BTA_HF_CLIENT_INIT_ST},
    /* API_AUDIO_OPEN_EVT */ {BTA_HF_CLIENT_IGNORE, BTA_HF_CLIENT_IGNORE,
                              BTA_HF_CLIENT_INIT_ST},
    /* API_AUDIO_CLOSE_EVT */ {BTA_HF_CLIENT_IGNORE, BTA_HF_CLIENT_IGNORE,
                               BTA_HF_CLIENT_INIT_ST},
    /* RFC_OPEN_EVT */ {BTA_HF_CLIENT_RFC_ACP_OPEN, BTA_HF_CLIENT_SCO_LISTEN,
                        BTA_HF_CLIENT_OPEN_ST},
    /* RFC_CLOSE_EVT */ {BTA_HF_CLIENT_IGNORE, BTA_HF_CLIENT_IGNORE,
                         BTA_HF_CLIENT_INIT_ST},
    /* RFC_SRV_CLOSE_EVT */ {BTA_HF_CLIENT_IGNORE, BTA_HF_CLIENT_IGNORE,
                             BTA_HF_CLIENT_INIT_ST},
    /* RFC_DATA_EVT */ {BTA_HF_CLIENT_IGNORE, BTA_HF_CLIENT_IGNORE,
                        BTA_HF_CLIENT_INIT_ST},
    /* DISC_ACP_RES_EVT */ {BTA_HF_CLIENT_FREE_DB, BTA_HF_CLIENT_IGNORE,
                            BTA_HF_CLIENT_INIT_ST},
    /* DISC_INT_RES_EVT */ {BTA_HF_CLIENT_IGNORE, BTA_HF_CLIENT_IGNORE,
                            BTA_HF_CLIENT_INIT_ST},
    /* DISC_OK_EVT */ {BTA_HF_CLIENT_IGNORE, BTA_HF_CLIENT_IGNORE,
                       BTA_HF_CLIENT_INIT_ST},
    /* DISC_FAIL_EVT */ {BTA_HF_CLIENT_IGNORE, BTA_HF_CLIENT_IGNORE,
                         BTA_HF_CLIENT_INIT_ST},
    /* SCO_OPEN_EVT */ {BTA_HF_CLIENT_IGNORE, BTA_HF_CLIENT_IGNORE,
                        BTA_HF_CLIENT_INIT_ST},
    /* SCO_CLOSE_EVT */ {BTA_HF_CLIENT_IGNORE, BTA_HF_CLIENT_IGNORE,
                         BTA_HF_CLIENT_INIT_ST},
    /* SEND_AT_CMD_EVT */ {BTA_HF_CLIENT_IGNORE, BTA_HF_CLIENT_IGNORE,
                           BTA_HF_CLIENT_INIT_ST},
};

/* state table for opening state */
const uint8_t bta_hf_client_st_opening[][BTA_HF_CLIENT_NUM_COLS] = {
    /* Event                    Action 1                       Action 2
       Next state */
    /* API_OPEN_EVT */ {BTA_HF_CLIENT_OPEN_FAIL, BTA_HF_CLIENT_IGNORE,
                        BTA_HF_CLIENT_OPENING_ST},
    /* API_CLOSE_EVT */ {BTA_HF_CLIENT_RFC_DO_CLOSE, BTA_HF_CLIENT_IGNORE,
                         BTA_HF_CLIENT_CLOSING_ST},
    /* API_AUDIO_OPEN_EVT */ {BTA_HF_CLIENT_IGNORE, BTA_HF_CLIENT_IGNORE,
                              BTA_HF_CLIENT_OPENING_ST},
    /* API_AUDIO_CLOSE_EVT */ {BTA_HF_CLIENT_IGNORE, BTA_HF_CLIENT_IGNORE,
                               BTA_HF_CLIENT_OPENING_ST},
    /* RFC_OPEN_EVT */ {BTA_HF_CLIENT_RFC_OPEN, BTA_HF_CLIENT_SCO_LISTEN,
                        BTA_HF_CLIENT_OPEN_ST},
    /* RFC_CLOSE_EVT */ {BTA_HF_CLIENT_RFC_FAIL, BTA_HF_CLIENT_IGNORE,
                         BTA_HF_CLIENT_INIT_ST},
    /* RFC_SRV_CLOSE_EVT */ {BTA_HF_CLIENT_IGNORE, BTA_HF_CLIENT_IGNORE,
                             BTA_HF_CLIENT_OPENING_ST},
    /* RFC_DATA_EVT */ {BTA_HF_CLIENT_IGNORE, BTA_HF_CLIENT_IGNORE,
                        BTA_HF_CLIENT_OPENING_ST},
    /* DISC_ACP_RES_EVT */ {BTA_HF_CLIENT_IGNORE, BTA_HF_CLIENT_IGNORE,
                            BTA_HF_CLIENT_OPENING_ST},
    /* DISC_INT_RES_EVT */ {BTA_HF_CLIENT_DISC_INT_RES, BTA_HF_CLIENT_IGNORE,
                            BTA_HF_CLIENT_OPENING_ST},
    /* DISC_OK_EVT */ {BTA_HF_CLIENT_RFC_DO_OPEN, BTA_HF_CLIENT_IGNORE,
                       BTA_HF_CLIENT_OPENING_ST},
    /* DISC_FAIL_EVT */ {BTA_HF_CLIENT_DISC_FAIL, BTA_HF_CLIENT_IGNORE,
                         BTA_HF_CLIENT_INIT_ST},
    /* SCO_OPEN_EVT */ {BTA_HF_CLIENT_IGNORE, BTA_HF_CLIENT_IGNORE,
                        BTA_HF_CLIENT_OPENING_ST},
    /* SCO_CLOSE_EVT */ {BTA_HF_CLIENT_IGNORE, BTA_HF_CLIENT_IGNORE,
                         BTA_HF_CLIENT_OPENING_ST},
    /* SEND_AT_CMD_EVT */ {BTA_HF_CLIENT_IGNORE, BTA_HF_CLIENT_IGNORE,
                           BTA_HF_CLIENT_OPENING_ST},
};

/* state table for open state */
const uint8_t bta_hf_client_st_open[][BTA_HF_CLIENT_NUM_COLS] = {
    /* Event                    Action 1                       Action 2
       Next state */
    /* API_OPEN_EVT */ {BTA_HF_CLIENT_OPEN_FAIL, BTA_HF_CLIENT_IGNORE,
                        BTA_HF_CLIENT_OPEN_ST},
    /* API_CLOSE_EVT */ {BTA_HF_CLIENT_START_CLOSE, BTA_HF_CLIENT_IGNORE,
                         BTA_HF_CLIENT_CLOSING_ST},
    /* API_AUDIO_OPEN_EVT */ {BTA_HF_CLIENT_SCO_OPEN, BTA_HF_CLIENT_IGNORE,
                              BTA_HF_CLIENT_OPEN_ST},
    /* API_AUDIO_CLOSE_EVT */ {BTA_HF_CLIENT_SCO_CLOSE, BTA_HF_CLIENT_IGNORE,
                               BTA_HF_CLIENT_OPEN_ST},
    /* RFC_OPEN_EVT */ {BTA_HF_CLIENT_IGNORE, BTA_HF_CLIENT_IGNORE,
                        BTA_HF_CLIENT_OPEN_ST},
    /* RFC_CLOSE_EVT */ {BTA_HF_CLIENT_RFC_CLOSE, BTA_HF_CLIENT_IGNORE,
                         BTA_HF_CLIENT_INIT_ST},
    /* RFC_SRV_CLOSE_EVT */ {BTA_HF_CLIENT_IGNORE, BTA_HF_CLIENT_IGNORE,
                             BTA_HF_CLIENT_OPEN_ST},
    /* RFC_DATA_EVT */ {BTA_HF_CLIENT_RFC_DATA, BTA_HF_CLIENT_IGNORE,
                        BTA_HF_CLIENT_OPEN_ST},
    /* DISC_ACP_RES_EVT */ {BTA_HF_CLIENT_DISC_ACP_RES, BTA_HF_CLIENT_IGNORE,
                            BTA_HF_CLIENT_OPEN_ST},
    /* DISC_INT_RES_EVT */ {BTA_HF_CLIENT_IGNORE, BTA_HF_CLIENT_IGNORE,
                            BTA_HF_CLIENT_OPEN_ST},
    /* DISC_OK_EVT */ {BTA_HF_CLIENT_IGNORE, BTA_HF_CLIENT_IGNORE,
                       BTA_HF_CLIENT_OPEN_ST},
    /* DISC_FAIL_EVT */ {BTA_HF_CLIENT_IGNORE, BTA_HF_CLIENT_IGNORE,
                         BTA_HF_CLIENT_OPEN_ST},
    /* SCO_OPEN_EVT */ {BTA_HF_CLIENT_SCO_CONN_OPEN, BTA_HF_CLIENT_IGNORE,
                        BTA_HF_CLIENT_OPEN_ST},
    /* SCO_CLOSE_EVT */ {BTA_HF_CLIENT_SCO_CONN_CLOSE, BTA_HF_CLIENT_IGNORE,
                         BTA_HF_CLIENT_OPEN_ST},
    /* SEND_AT_CMD_EVT */ {BTA_HF_CLIENT_SEND_AT_CMD, BTA_HF_CLIENT_IGNORE,
                           BTA_HF_CLIENT_OPEN_ST},
};

/* state table for closing state */
const uint8_t bta_hf_client_st_closing[][BTA_HF_CLIENT_NUM_COLS] = {
    /* Event                    Action 1                       Action 2
       Next state */
    /* API_OPEN_EVT */ {BTA_HF_CLIENT_OPEN_FAIL, BTA_HF_CLIENT_IGNORE,
                        BTA_HF_CLIENT_CLOSING_ST},
    /* API_CLOSE_EVT */ {BTA_HF_CLIENT_IGNORE, BTA_HF_CLIENT_IGNORE,
                         BTA_HF_CLIENT_CLOSING_ST},
    /* API_AUDIO_OPEN_EVT */ {BTA_HF_CLIENT_IGNORE, BTA_HF_CLIENT_IGNORE,
                              BTA_HF_CLIENT_CLOSING_ST},
    /* API_AUDIO_CLOSE_EVT */ {BTA_HF_CLIENT_IGNORE, BTA_HF_CLIENT_IGNORE,
                               BTA_HF_CLIENT_CLOSING_ST},
    /* RFC_OPEN_EVT */ {BTA_HF_CLIENT_IGNORE, BTA_HF_CLIENT_IGNORE,
                        BTA_HF_CLIENT_CLOSING_ST},
    /* RFC_CLOSE_EVT */ {BTA_HF_CLIENT_RFC_CLOSE, BTA_HF_CLIENT_IGNORE,
                         BTA_HF_CLIENT_INIT_ST},
    /* RFC_SRV_CLOSE_EVT */ {BTA_HF_CLIENT_IGNORE, BTA_HF_CLIENT_IGNORE,
                             BTA_HF_CLIENT_CLOSING_ST},
    /* RFC_DATA_EVT */ {BTA_HF_CLIENT_IGNORE, BTA_HF_CLIENT_IGNORE,
                        BTA_HF_CLIENT_CLOSING_ST},
    /* DISC_ACP_RES_EVT */ {BTA_HF_CLIENT_FREE_DB, BTA_HF_CLIENT_IGNORE,
                            BTA_HF_CLIENT_CLOSING_ST},
    /* DISC_INT_RES_EVT */ {BTA_HF_CLIENT_FREE_DB, BTA_HF_CLIENT_IGNORE,
                            BTA_HF_CLIENT_INIT_ST},
    /* DISC_OK_EVT */ {BTA_HF_CLIENT_IGNORE, BTA_HF_CLIENT_IGNORE,
                       BTA_HF_CLIENT_CLOSING_ST},
    /* DISC_FAIL_EVT */ {BTA_HF_CLIENT_IGNORE, BTA_HF_CLIENT_IGNORE,
                         BTA_HF_CLIENT_CLOSING_ST},
    /* SCO_OPEN_EVT */ {BTA_HF_CLIENT_IGNORE, BTA_HF_CLIENT_IGNORE,
                        BTA_HF_CLIENT_CLOSING_ST},
    /* SCO_CLOSE_EVT */ {BTA_HF_CLIENT_IGNORE, BTA_HF_CLIENT_IGNORE,
                         BTA_HF_CLIENT_CLOSING_ST},
    /* SEND_AT_CMD_EVT */ {BTA_HF_CLIENT_IGNORE, BTA_HF_CLIENT_IGNORE,
                           BTA_HF_CLIENT_CLOSING_ST},
};

/* type for state table */
typedef const uint8_t (*tBTA_HF_CLIENT_ST_TBL)[BTA_HF_CLIENT_NUM_COLS];

/* state table */
const tBTA_HF_CLIENT_ST_TBL bta_hf_client_st_tbl[] = {
    bta_hf_client_st_init, bta_hf_client_st_opening, bta_hf_client_st_open,
    bta_hf_client_st_closing};

/* HF Client control block */
tBTA_HF_CLIENT_CB bta_hf_client_cb;

/* Event handler for the state machine */
static const tBTA_SYS_REG bta_hf_client_reg = {bta_hf_client_hdl_event,
                                               BTA_HfClientDisable};

/*******************************************************************************
 *
 * Function         bta_hf_client_scb_init
 *
 * Description      Initialize an HF_Client service control block.
 *
 *
 * Returns          void
 *
 ******************************************************************************/
void bta_hf_client_scb_init(void) {
  APPL_TRACE_DEBUG("%s", __func__);

  alarm_free(bta_hf_client_cb.scb.collision_timer);
  alarm_free(bta_hf_client_cb.scb.at_cb.resp_timer);
  alarm_free(bta_hf_client_cb.scb.at_cb.hold_timer);
  memset(&bta_hf_client_cb.scb, 0, sizeof(tBTA_HF_CLIENT_SCB));
  bta_hf_client_cb.scb.collision_timer =
      alarm_new("bta_hf_client.scb_collision_timer");
  bta_hf_client_cb.scb.sco_idx = BTM_INVALID_SCO_INDEX;
  bta_hf_client_cb.scb.negotiated_codec = BTM_SCO_CODEC_CVSD;
}

/*******************************************************************************
 *
 * Function         bta_hf_client_resume_open
 *
 * Description      Resume opening process.
 *
 *
 * Returns          void
 *
 ******************************************************************************/
void bta_hf_client_resume_open(void) {
  APPL_TRACE_DEBUG("%s", __func__);

  /* resume opening process.  */
  if (bta_hf_client_cb.scb.state == BTA_HF_CLIENT_INIT_ST) {
    bta_hf_client_cb.scb.state = BTA_HF_CLIENT_OPENING_ST;
    tBTA_HF_CLIENT_DATA msg;
    msg.hdr.layer_specific = bta_hf_client_cb.scb.handle;
    bta_hf_client_start_open(&msg);
  }
}

/*******************************************************************************
 *
 * Function         bta_hf_client_collision_timer_cback
 *
 * Description      HF Client connection collision timer callback
 *
 *
 * Returns          void
 *
 ******************************************************************************/
static void bta_hf_client_collision_timer_cback(UNUSED_ATTR void* data) {
  APPL_TRACE_DEBUG("%s", __func__);

  /* If the peer haven't opened connection, restart opening process */
  bta_hf_client_resume_open();
}

/*******************************************************************************
 *
 * Function         bta_hf_client_collision_cback
 *
 * Description      Get notified about collision.
 *
 *
 * Returns          void
 *
 ******************************************************************************/
void bta_hf_client_collision_cback(UNUSED_ATTR tBTA_SYS_CONN_STATUS status,
                                   uint8_t id, UNUSED_ATTR uint8_t app_id,
                                   UNUSED_ATTR BD_ADDR peer_addr) {
  if (bta_hf_client_cb.scb.state == BTA_HF_CLIENT_OPENING_ST) {
    if (id == BTA_ID_SYS) /* ACL collision */
    {
      APPL_TRACE_WARNING("HF Client found collision (ACL) ...");
    } else if (id == BTA_ID_HS) /* RFCOMM collision */
    {
      APPL_TRACE_WARNING("HF Client found collision (RFCOMM) ...");
    } else {
      APPL_TRACE_WARNING("HF Client found collision (\?\?\?) ...");
    }

    bta_hf_client_cb.scb.state = BTA_HF_CLIENT_INIT_ST;

    /* Cancel SDP if it had been started. */
    if (bta_hf_client_cb.scb.p_disc_db) {
      (void)SDP_CancelServiceSearch(bta_hf_client_cb.scb.p_disc_db);
      bta_hf_client_free_db(NULL);
    }

    /* reopen registered server */
    /* Collision may be detected before or after we close servers. */
    bta_hf_client_start_server(&bta_hf_client_cb);

    /* Start timer to handle connection opening restart */
    alarm_set_on_queue(
        bta_hf_client_cb.scb.collision_timer, BTA_HF_CLIENT_COLLISION_TIMER_MS,
        bta_hf_client_collision_timer_cback, NULL, btu_bta_alarm_queue);
  }
}

/*******************************************************************************
 *
 * Function         bta_hf_client_api_enable
 *
 * Description      Handle an API enable event.
 *
 *
 * Returns          void
 *
 ******************************************************************************/
tBTA_STATUS bta_hf_client_api_enable(tBTA_HF_CLIENT_CBACK* p_cback,
                                     tBTA_SEC sec_mask,
                                     tBTA_HF_CLIENT_FEAT features,
                                     const char* p_service_name) {
  /* If already registered then return error */
  if (bta_sys_is_register(BTA_ID_HS)) {
    APPL_TRACE_ERROR("%s: BTA HF Client is already enabled, ignoring ...",
                     __func__);
    return BTA_FAILURE;
  }

  /* register with BTA system manager */
  bta_sys_register(BTA_ID_HS, &bta_hf_client_reg);

  /* zero the control block */
  memset(&bta_hf_client_cb, 0, sizeof(tBTA_HF_CLIENT_CB));

  /* reset the timers and set fields to invalid */
  bta_hf_client_scb_init();

  /* Set control block to be ready to use */
  bta_hf_client_cb.p_cback = p_cback;
  bta_hf_client_cb.scb.handle = BTA_HF_CLIENT_CB_FIRST_HANDLE;
  bta_hf_client_cb.scb.is_allocated = false;
  bta_hf_client_cb.scb.serv_sec_mask = sec_mask;
  bta_hf_client_cb.scb.features = features;
  bta_hf_client_cb.scb.negotiated_codec = BTM_SCO_CODEC_CVSD;

  /* check if mSBC support enabled */
  char value[PROPERTY_VALUE_MAX];
  osi_property_get("ro.bluetooth.hfp.ver", value, "0");
  if (strcmp(value, "1.6") == 0) {
    bta_hf_client_cb.msbc_enabled = true;
  }

  /* set same setting as AG does */
  BTM_WriteVoiceSettings(AG_VOICE_SETTINGS);

  bta_sys_collision_register(BTA_ID_HS, bta_hf_client_collision_cback);

  /* initialize AT control block */
  bta_hf_client_at_init(&bta_hf_client_cb);

  /* create SDP records */
  bta_hf_client_create_record(&bta_hf_client_cb, p_service_name);

  /* Set the Audio service class bit */
  tBTA_UTL_COD cod;
  cod.service = BTM_COD_SERVICE_AUDIO;
  utl_set_device_class(&cod, BTA_UTL_SET_COD_SERVICE_CLASS);

  /* start RFCOMM server */
  bta_hf_client_start_server(&bta_hf_client_cb);

  return BTA_SUCCESS;
}

/*******************************************************************************
 *
 * Function         bta_hf_client_find_cb_by_handle
 *
 * Description      Finds the control block by handle provided
 *
 *                  handle: Handle as obtained from BTA_HfClientOpen call
 *
 *
 * Returns          Control block corresponding to the handle and NULL if
 *                  none exists
 *
 ******************************************************************************/
tBTA_HF_CLIENT_CB* bta_hf_client_find_cb_by_handle(uint16_t handle) {
  // Currently we have only one control block
  if (bta_hf_client_cb.scb.is_allocated &&
      bta_hf_client_cb.scb.handle == handle) {
    return &(bta_hf_client_cb);
  }
  APPL_TRACE_ERROR("%s: block not found for handle %d alloc: %d saved %d",
                   __func__, handle, bta_hf_client_cb.scb.is_allocated,
                   bta_hf_client_cb.scb.handle);
  return NULL;
}

/*******************************************************************************
 *
 * Function         bta_hf_client_find_cb_by_rfc_handle
 *
 * Description      Finds the control block by RFC handle provided.
 *                  RFC handle is either in conn_handle (i.e. RFC handle
 *                  provided by the lower layer, stack/rfc) or in serv_handle
 *                  if the port is an incoming server. In case of incoming
 *                  request a block is allocated.
 *
 *                  handle: RFC handle for either the outgoing connection
 *                  or the server connection
 *
 *
 * Returns          Control block corresponding to the handle and NULL if none
 *                  exists
 *
 ******************************************************************************/
tBTA_HF_CLIENT_CB* bta_hf_client_find_cb_by_rfc_handle(uint16_t handle) {
  // Currently we have only one control block
  bool is_allocated = bta_hf_client_cb.scb.is_allocated;
  uint16_t conn_handle = bta_hf_client_cb.scb.conn_handle;
  uint16_t serv_handle = bta_hf_client_cb.scb.serv_handle;

  APPL_TRACE_DEBUG("%s: cb handle %d alloc %d conn_handle %d serv_handle %d",
                   __func__, handle, is_allocated, conn_handle, serv_handle);

  if (is_allocated && (conn_handle == handle || serv_handle == handle)) {
    return &(bta_hf_client_cb);
  } else if (!is_allocated && serv_handle == handle) {
    uint16_t tmp_handle;
    if (bta_hf_client_allocate_handle(&tmp_handle)) {
      tBTA_HF_CLIENT_CB* client_cb =
          bta_hf_client_find_cb_by_handle(tmp_handle);
      // Allocation for incoming channel happens only on
      // connection request. Also the code uses conn_handle
      // for PORT_{Write/Read}Data. So setting this equal to
      // serv_handle fixes that issue.
      client_cb->scb.conn_handle = client_cb->scb.serv_handle;
      return client_cb;
    }
  } else {
    APPL_TRACE_ERROR("%s: no cb %d alloc %d conn_handle %d serv_handle %d",
                     __func__, handle, is_allocated, conn_handle, serv_handle);
  }
  return NULL;
}

/*******************************************************************************
 *
 * Function         bta_hf_client_find_cb_by_sco_handle
 *
 * Description      Finds the control block by sco handle provided
 *
 *                  handle: sco handle
 *
 *
 * Returns          Control block corresponding to the sco handle and
 *                  none if none exists
 *
 ******************************************************************************/
tBTA_HF_CLIENT_CB* bta_hf_client_find_cb_by_sco_handle(uint16_t handle) {
  // Currently we have only one control block
  if (bta_hf_client_cb.scb.is_allocated &&
      bta_hf_client_cb.scb.sco_idx == handle) {
    return &(bta_hf_client_cb);
  }
  APPL_TRACE_ERROR("%s: block not found for handle %d", __func__, handle);
  return NULL;
}

/*******************************************************************************
 *
 * Function         bta_hf_client_allocate_handle
 *
 * Description      Allocates a handle for the new BD ADDR that needs a new RF
 *                  channel for HF connection. If the channel cannot be created
 *                  for a reason then false is returned
 *
 *                  p_handle: OUT variable to store the outcome of allocate. If
 *                  allocate failed then value is not valid
 *
 *
 * Returns          true if the creation of handle succeeded, false otherwise
 *
 ******************************************************************************/
bool bta_hf_client_allocate_handle(uint16_t* p_handle) {
  /* Check that we do not have a request to for same device in the control
   * blocks */
  if (bta_hf_client_cb.scb.is_allocated) {
    APPL_TRACE_ERROR("%s: all control blocks already used", __func__);
    return false;
  }

  *p_handle = bta_hf_client_cb.scb.handle;
  bta_hf_client_cb.scb.is_allocated = true;
  return true;
}

/*******************************************************************************
 *
 * Function         bta_hf_client_api_disable
 *
 * Description      Handle an API disable event.
 *
 *
 * Returns          void
 *
 ******************************************************************************/
void bta_hf_client_api_disable() {
  if (!bta_sys_is_register(BTA_ID_HS)) {
    APPL_TRACE_WARNING("BTA HF Client is already disabled, ignoring ...");
    return;
  }

  /* Remove the collision handler */
  bta_sys_collision_register(BTA_ID_HS, NULL);

  bta_hf_client_cb.scb.deregister = true;

  /* remove sdp record */
  bta_hf_client_del_record(&bta_hf_client_cb);

  /* remove rfcomm server */
  bta_hf_client_close_server(&bta_hf_client_cb);

  /* reinit the control block */
  bta_hf_client_scb_init();

  /* De-register with BTA system manager */
  bta_sys_deregister(BTA_ID_HS);
}

/*******************************************************************************
 *
 * Function         bta_hf_client_hdl_event
 *
 * Description      Data HF Client main event handling function.
 *
 *
 * Returns          bool
 *
 ******************************************************************************/
bool bta_hf_client_hdl_event(BT_HDR* p_msg) {
  APPL_TRACE_DEBUG("%s: %s (0x%x)", __func__,
                   bta_hf_client_evt_str(p_msg->event), p_msg->event);
  bta_hf_client_sm_execute(p_msg->event, (tBTA_HF_CLIENT_DATA*)p_msg);
  return true;
}

/*******************************************************************************
 *
 * Function         bta_hf_client_sm_execute
 *
 * Description      State machine event handling function for HF Client
 *
 *
 * Returns          void
 *
 ******************************************************************************/
void bta_hf_client_sm_execute(uint16_t event, tBTA_HF_CLIENT_DATA* p_data) {
  tBTA_HF_CLIENT_ST_TBL state_table;
  uint8_t action;
  int i;

  uint16_t in_event = event;
  uint8_t in_state = bta_hf_client_cb.scb.state;

  /* Ignore displaying of AT results when not connected (Ignored in state
   * machine) */
  if (bta_hf_client_cb.scb.state == BTA_HF_CLIENT_OPEN_ST) {
    APPL_TRACE_EVENT("HF Client evt : State %d (%s), Event 0x%04x (%s)",
                     bta_hf_client_cb.scb.state,
                     bta_hf_client_state_str(bta_hf_client_cb.scb.state), event,
                     bta_hf_client_evt_str(event));
  }

  event &= 0x00FF;
  if (event >= (BTA_HF_CLIENT_MAX_EVT & 0x00FF)) {
    APPL_TRACE_ERROR("HF Client evt out of range, ignoring...");
    return;
  }

  /* look up the state table for the current state */
  state_table = bta_hf_client_st_tbl[bta_hf_client_cb.scb.state];

  /* set next state */
  bta_hf_client_cb.scb.state = state_table[event][BTA_HF_CLIENT_NEXT_STATE];

  APPL_TRACE_DEBUG("%s: before alloc %d conn %d serv %d", __func__,
                   bta_hf_client_cb.scb.is_allocated,
                   bta_hf_client_cb.scb.conn_handle,
                   bta_hf_client_cb.scb.serv_handle);

  /* execute action functions */
  for (i = 0; i < BTA_HF_CLIENT_ACTIONS; i++) {
    action = state_table[event][i];
    if (action != BTA_HF_CLIENT_IGNORE) {
      (*bta_hf_client_action[action])(p_data);
    } else {
      break;
    }
  }

  /* if the next state is INIT then release the cb for future use */
  if (bta_hf_client_cb.scb.state == BTA_HF_CLIENT_INIT_ST) {
    bta_hf_client_cb.scb.is_allocated = false;
  }

  APPL_TRACE_DEBUG("%s: after alloc %d conn %d serv %d", __func__,
                   bta_hf_client_cb.scb.is_allocated,
                   bta_hf_client_cb.scb.conn_handle,
                   bta_hf_client_cb.scb.serv_handle);

  if (bta_hf_client_cb.scb.state != in_state) {
    APPL_TRACE_EVENT(
        "BTA HF Client State Change: [%s] -> [%s] after Event [%s]",
        bta_hf_client_state_str(in_state),
        bta_hf_client_state_str(bta_hf_client_cb.scb.state),
        bta_hf_client_evt_str(in_event));
  }
}

static void send_post_slc_cmd(void) {
  bta_hf_client_cb.scb.at_cb.current_cmd = BTA_HF_CLIENT_AT_NONE;

  bta_hf_client_send_at_bia(&bta_hf_client_cb);
  bta_hf_client_send_at_ccwa(&bta_hf_client_cb, true);
  bta_hf_client_send_at_cmee(&bta_hf_client_cb, true);
  bta_hf_client_send_at_cops(&bta_hf_client_cb, false);
  bta_hf_client_send_at_btrh(&bta_hf_client_cb, true, 0);
  bta_hf_client_send_at_clip(&bta_hf_client_cb, true);
}

/*******************************************************************************
 *
 * Function         bta_hf_client_slc_seq
 *
 * Description      Handles AT commands sequence required for SLC creation
 *
 *
 * Returns          void
 *
 ******************************************************************************/
void bta_hf_client_slc_seq(tBTA_HF_CLIENT_CB* client_cb, bool error) {
  APPL_TRACE_DEBUG("bta_hf_client_slc_seq cmd: %u",
                   client_cb->scb.at_cb.current_cmd);

  if (error) {
    /* SLC establishment error, sent close rfcomm event */
    APPL_TRACE_ERROR(
        "HFPClient: Failed to create SLC due to AT error, disconnecting (%u)",
        client_cb->scb.at_cb.current_cmd);

    bta_hf_client_sm_execute(BTA_HF_CLIENT_API_CLOSE_EVT, NULL);
    return;
  }

  if (client_cb->scb.svc_conn) return;

  switch (client_cb->scb.at_cb.current_cmd) {
    case BTA_HF_CLIENT_AT_NONE:
      bta_hf_client_send_at_brsf(&bta_hf_client_cb);
      break;

    case BTA_HF_CLIENT_AT_BRSF:
      if ((client_cb->scb.features & BTA_HF_CLIENT_FEAT_CODEC) &&
          (client_cb->scb.peer_features & BTA_HF_CLIENT_PEER_CODEC)) {
        bta_hf_client_send_at_bac(&bta_hf_client_cb);
        break;
      }

      bta_hf_client_send_at_cind(&bta_hf_client_cb, false);
      break;

    case BTA_HF_CLIENT_AT_BAC:
      bta_hf_client_send_at_cind(&bta_hf_client_cb, false);
      break;

    case BTA_HF_CLIENT_AT_CIND:
      bta_hf_client_send_at_cind(&bta_hf_client_cb, true);
      break;

    case BTA_HF_CLIENT_AT_CIND_STATUS:
      bta_hf_client_send_at_cmer(&bta_hf_client_cb, true);
      break;

    case BTA_HF_CLIENT_AT_CMER:
      if (client_cb->scb.peer_features & BTA_HF_CLIENT_PEER_FEAT_3WAY &&
          client_cb->scb.features & BTA_HF_CLIENT_FEAT_3WAY) {
        bta_hf_client_send_at_chld(&bta_hf_client_cb, '?', 0);
      } else {
        tBTA_HF_CLIENT_DATA msg;
        msg.hdr.layer_specific = bta_hf_client_cb.scb.handle;
        bta_hf_client_svc_conn_open(&msg);
        send_post_slc_cmd();
      }
      break;

    case BTA_HF_CLIENT_AT_CHLD:
      tBTA_HF_CLIENT_DATA msg;
      msg.hdr.layer_specific = bta_hf_client_cb.scb.handle;
      bta_hf_client_svc_conn_open(&msg);
      send_post_slc_cmd();
      break;

    default:
      /* If happen there is a bug in SLC creation procedure... */
      APPL_TRACE_ERROR(
          "HFPClient: Failed to create SLCdue to unexpected AT command, "
          "disconnecting (%u)",
          client_cb->scb.at_cb.current_cmd);

      bta_hf_client_sm_execute(BTA_HF_CLIENT_API_CLOSE_EVT, NULL);
      break;
  }
}

#ifndef CASE_RETURN_STR
#define CASE_RETURN_STR(const) \
  case const:                  \
    return #const;
#endif

static const char* bta_hf_client_evt_str(uint16_t event) {
  switch (event) {
    CASE_RETURN_STR(BTA_HF_CLIENT_API_OPEN_EVT)
    CASE_RETURN_STR(BTA_HF_CLIENT_API_CLOSE_EVT)
    CASE_RETURN_STR(BTA_HF_CLIENT_API_AUDIO_OPEN_EVT)
    CASE_RETURN_STR(BTA_HF_CLIENT_API_AUDIO_CLOSE_EVT)
    CASE_RETURN_STR(BTA_HF_CLIENT_RFC_OPEN_EVT)
    CASE_RETURN_STR(BTA_HF_CLIENT_RFC_CLOSE_EVT)
    CASE_RETURN_STR(BTA_HF_CLIENT_RFC_SRV_CLOSE_EVT)
    CASE_RETURN_STR(BTA_HF_CLIENT_RFC_DATA_EVT)
    CASE_RETURN_STR(BTA_HF_CLIENT_DISC_ACP_RES_EVT)
    CASE_RETURN_STR(BTA_HF_CLIENT_DISC_INT_RES_EVT)
    CASE_RETURN_STR(BTA_HF_CLIENT_DISC_OK_EVT)
    CASE_RETURN_STR(BTA_HF_CLIENT_DISC_FAIL_EVT)
    CASE_RETURN_STR(BTA_HF_CLIENT_API_ENABLE_EVT)
    CASE_RETURN_STR(BTA_HF_CLIENT_API_DISABLE_EVT)
    CASE_RETURN_STR(BTA_HF_CLIENT_SCO_OPEN_EVT)
    CASE_RETURN_STR(BTA_HF_CLIENT_SCO_CLOSE_EVT)
    CASE_RETURN_STR(BTA_HF_CLIENT_SEND_AT_CMD_EVT)
    default:
      return "Unknown HF Client Event";
  }
}

static const char* bta_hf_client_state_str(uint8_t state) {
  switch (state) {
    CASE_RETURN_STR(BTA_HF_CLIENT_INIT_ST)
    CASE_RETURN_STR(BTA_HF_CLIENT_OPENING_ST)
    CASE_RETURN_STR(BTA_HF_CLIENT_OPEN_ST)
    CASE_RETURN_STR(BTA_HF_CLIENT_CLOSING_ST)
    default:
      return "Unknown HF Client State";
  }
}
