/******************************************************************************
 *
 *  Copyright (c) 2014 The Android Open Source Project
 *  Copyright (C) 2004-2012 Broadcom Corporation
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

/******************************************************************************
 *
 *  This file contains the audio gateway functions controlling the RFCOMM
 *  connections.
 *
 ******************************************************************************/

#include <string.h>

#include "bt_utils.h"
#include "bta_api.h"
#include "bta_hf_client_int.h"
#include "osi/include/osi.h"
#include "port_api.h"

/*******************************************************************************
 *
 * Function         bta_hf_client_port_cback
 *
 * Description      RFCOMM Port callback. The handle in this function is
 *                  specified by BTA layer via the PORT_SetEventCallback
 *                  method
 *
 * Returns          void
 *
 ******************************************************************************/
static void bta_hf_client_port_cback(UNUSED_ATTR uint32_t code,
                                     uint16_t port_handle) {
  /* ignore port events for port handles other than connected handle */
  tBTA_HF_CLIENT_CB* client_cb =
      bta_hf_client_find_cb_by_rfc_handle(port_handle);
  if (client_cb == NULL) {
    APPL_TRACE_ERROR("%s: cb not found for handle %d", __func__, port_handle);
    return;
  }

  tBTA_HF_CLIENT_RFC* p_buf =
      (tBTA_HF_CLIENT_RFC*)osi_malloc(sizeof(tBTA_HF_CLIENT_RFC));
  p_buf->hdr.event = BTA_HF_CLIENT_RFC_DATA_EVT;
  p_buf->hdr.layer_specific = client_cb->scb.handle;
  bta_sys_sendmsg(p_buf);
}

/*******************************************************************************
 *
 * Function         bta_hf_client_mgmt_cback
 *
 * Description      RFCOMM management callback
 *
 *
 * Returns          void
 *
 ******************************************************************************/
static void bta_hf_client_mgmt_cback(uint32_t code, uint16_t port_handle) {
  uint16_t event;

  tBTA_HF_CLIENT_CB* client_cb =
      bta_hf_client_find_cb_by_rfc_handle(port_handle);
  if (client_cb == NULL) {
    APPL_TRACE_ERROR("%s: cb not found for handle %d", __func__, port_handle);
    return;
  }

  APPL_TRACE_DEBUG(
      "%s: code = %d, port_handle = %d, conn_handle = "
      "%d, serv_handle = %d",
      __func__, code, port_handle, client_cb->scb.conn_handle,
      client_cb->scb.serv_handle);

  /* ignore close event for port handles other than connected handle */
  if ((code != PORT_SUCCESS) && (port_handle != client_cb->scb.conn_handle)) {
    APPL_TRACE_DEBUG("bta_hf_client_mgmt_cback ignoring handle:%d",
                     port_handle);
    return;
  }

  if (code == PORT_SUCCESS) {
    if ((client_cb->scb.conn_handle &&
         (port_handle ==
          client_cb->scb.conn_handle)) ||            /* outgoing connection */
        (port_handle == client_cb->scb.serv_handle)) /* incoming connection */
    {
      event = BTA_HF_CLIENT_RFC_OPEN_EVT;
    } else {
      APPL_TRACE_ERROR(
          "bta_hf_client_mgmt_cback: PORT_SUCCESS, ignoring handle = %d",
          port_handle);
      return;
    }
  }
  /* distinguish server close events */
  else if (port_handle == client_cb->scb.conn_handle) {
    event = BTA_HF_CLIENT_RFC_CLOSE_EVT;
  } else {
    event = BTA_HF_CLIENT_RFC_SRV_CLOSE_EVT;
  }

  tBTA_HF_CLIENT_RFC* p_buf =
      (tBTA_HF_CLIENT_RFC*)osi_malloc(sizeof(tBTA_HF_CLIENT_RFC));
  p_buf->hdr.event = event;
  p_buf->hdr.layer_specific = client_cb->scb.handle;
  bta_sys_sendmsg(p_buf);
}

/*******************************************************************************
 *
 * Function         bta_hf_client_setup_port
 *
 * Description      Setup RFCOMM port for use by HF Client.
 *
 *
 * Returns          void
 *
 ******************************************************************************/
void bta_hf_client_setup_port(uint16_t handle) {
  PORT_SetEventMask(handle, PORT_EV_RXCHAR);
  PORT_SetEventCallback(handle, bta_hf_client_port_cback);
}

/*******************************************************************************
 *
 * Function         bta_hf_client_start_server
 *
 * Description      Setup RFCOMM server for use by HF Client.
 *
 *
 * Returns          void
 *
 ******************************************************************************/
void bta_hf_client_start_server(tBTA_HF_CLIENT_CB* client_cb) {
  int port_status;

  if (client_cb->scb.serv_handle > 0) {
    APPL_TRACE_DEBUG("%s: already started, handle: %d", __func__,
                     client_cb->scb.serv_handle);
    return;
  }

  BTM_SetSecurityLevel(false, "", BTM_SEC_SERVICE_HF_HANDSFREE,
                       client_cb->scb.serv_sec_mask, BT_PSM_RFCOMM,
                       BTM_SEC_PROTO_RFCOMM, client_cb->scn);

  port_status = RFCOMM_CreateConnection(
      UUID_SERVCLASS_HF_HANDSFREE, client_cb->scn, true, BTA_HF_CLIENT_MTU,
      (uint8_t*)bd_addr_any, &(client_cb->scb.serv_handle),
      bta_hf_client_mgmt_cback);
  APPL_TRACE_DEBUG("%s: started rfcomm server with handle %d", __func__,
                   client_cb->scb.serv_handle);

  if (port_status == PORT_SUCCESS) {
    bta_hf_client_setup_port(client_cb->scb.serv_handle);
  } else {
    APPL_TRACE_DEBUG("%s: RFCOMM_CreateConnection returned error:%d", __func__,
                     port_status);
  }
}

/*******************************************************************************
 *
 * Function         bta_hf_client_close_server
 *
 * Description      Close RFCOMM server port for use by HF Client.
 *
 *
 * Returns          void
 *
 ******************************************************************************/
void bta_hf_client_close_server(tBTA_HF_CLIENT_CB* client_cb) {
  APPL_TRACE_DEBUG("%s: %d", __func__, client_cb->scb.serv_handle);

  if (client_cb->scb.serv_handle == 0) {
    APPL_TRACE_DEBUG("%s: already stopped", __func__);
    return;
  }

  RFCOMM_RemoveServer(client_cb->scb.serv_handle);
  client_cb->scb.serv_handle = 0;
}

/*******************************************************************************
 *
 * Function         bta_hf_client_rfc_do_open
 *
 * Description      Open an RFCOMM connection to the peer device.
 *
 *
 * Returns          void
 *
 ******************************************************************************/
void bta_hf_client_rfc_do_open(tBTA_HF_CLIENT_DATA* p_data) {
  tBTA_HF_CLIENT_CB* client_cb =
      bta_hf_client_find_cb_by_handle(p_data->hdr.layer_specific);
  if (client_cb == NULL) {
    APPL_TRACE_ERROR("%s: cb not found for handle %d", __func__,
                     p_data->hdr.layer_specific);
    return;
  }

  BTM_SetSecurityLevel(true, "", BTM_SEC_SERVICE_HF_HANDSFREE,
                       client_cb->scb.cli_sec_mask, BT_PSM_RFCOMM,
                       BTM_SEC_PROTO_RFCOMM, client_cb->scb.peer_scn);
  if (RFCOMM_CreateConnection(UUID_SERVCLASS_HF_HANDSFREE,
                              client_cb->scb.peer_scn, false, BTA_HF_CLIENT_MTU,
                              client_cb->scb.peer_addr,
                              &(client_cb->scb.conn_handle),
                              bta_hf_client_mgmt_cback) == PORT_SUCCESS) {
    bta_hf_client_setup_port(client_cb->scb.conn_handle);
    APPL_TRACE_DEBUG("bta_hf_client_rfc_do_open : conn_handle = %d",
                     client_cb->scb.conn_handle);
  }
  /* RFCOMM create connection failed; send ourselves RFCOMM close event */
  else {
    bta_hf_client_sm_execute(BTA_HF_CLIENT_RFC_CLOSE_EVT, p_data);
  }
}

/*******************************************************************************
 *
 * Function         bta_hf_client_rfc_do_close
 *
 * Description      Close RFCOMM connection.
 *
 *
 * Returns          void
 *
 ******************************************************************************/
void bta_hf_client_rfc_do_close(UNUSED_ATTR tBTA_HF_CLIENT_DATA* p_data) {
  tBTA_HF_CLIENT_CB* client_cb =
      bta_hf_client_find_cb_by_handle(p_data->hdr.layer_specific);
  if (client_cb == NULL) {
    APPL_TRACE_ERROR("%s: cb not found for handle %d", __func__,
                     p_data->hdr.layer_specific);
    return;
  }

  if (client_cb->scb.conn_handle) {
    RFCOMM_RemoveConnection(client_cb->scb.conn_handle);
  } else {
    /* Close API was called while HF Client is in Opening state.        */
    /* Need to trigger the state machine to send callback to the app    */
    /* and move back to INIT state.                                     */
    tBTA_HF_CLIENT_RFC* p_buf =
        (tBTA_HF_CLIENT_RFC*)osi_malloc(sizeof(tBTA_HF_CLIENT_RFC));
    p_buf->hdr.event = BTA_HF_CLIENT_RFC_CLOSE_EVT;
    bta_sys_sendmsg(p_buf);

    /* Cancel SDP if it had been started. */
    if (client_cb->scb.p_disc_db) {
      (void)SDP_CancelServiceSearch(client_cb->scb.p_disc_db);
      bta_hf_client_free_db(NULL);
    }
  }
}
