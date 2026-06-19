/******************************************************************************
 *
 *  Copyright 2008-2012 Broadcom Corporation
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
 *  this file contains the main ATT functions
 *
 ******************************************************************************/

#include <bluetooth/log.h>
#include <bluetooth/types/address.h>
#include <com_android_bluetooth_flags.h>

#include "btif/include/btif_debug_conn.h"
#include "btif/include/btif_storage.h"
#include "device/include/interop.h"
#include "internal_include/bt_target.h"
#include "osi/include/properties.h"
#include "stack/btm/btm_dev.h"
#include "stack/connection_manager/connection_manager.h"
#include "stack/eatt/eatt.h"
#include "stack/gatt/gatt_int.h"
#include "stack/include/acl_api.h"
#include "stack/include/bt_hdr.h"
#include "stack/include/bt_types.h"
#include "stack/include/btm_client_interface.h"
#include "stack/include/gatt_api.h"
#include "stack/include/hci_error_code.h"
#include "stack/include/l2cap_interface.h"
#include "stack/include/l2cdefs.h"

using bluetooth::eatt::EattExtension;
using namespace bluetooth;

bluetooth::common::TimestampedCircularBuffer<tTCB_STATE_HISTORY> tcb_state_history_(
        100 /*history size*/);

/******************************************************************************/
/*            L O C A L    F U N C T I O N     P R O T O T Y P E S            */
/******************************************************************************/
tGATT_CB gatt_cb;

/*******************************************************************************
 *
 * Function         gatt_init
 *
 * Description      This function is enable the GATT profile on the device.
 *                  It clears out the control blocks, and registers with L2CAP.
 *
 * Returns          void
 *
 ******************************************************************************/
void gatt_init(void) {
  log::verbose("");

  gatt_cb = tGATT_CB();
  connection_manager::reset(true);

  // To catch a potential OOB, 40>31 is used, any valid value (1 to GATT_IF_MAX) is okay.
  gatt_cb.last_gatt_if = static_cast<tGATT_IF>(40);

  gatt_cb.sign_op_queue = fixed_queue_new(SIZE_MAX);
  gatt_cb.srv_chg_clt_q = fixed_queue_new(SIZE_MAX);

  gatt_init_le();

  gatt_cb.over_br_enabled = osi_property_get_bool("bluetooth.gatt.over_bredr.enabled", true);
  if (gatt_cb.over_br_enabled) {
    gatt_init_br();
  }

  gatt_cb.hdl_cfg.gatt_start_hdl = GATT_GATT_START_HANDLE;
  gatt_cb.hdl_cfg.gap_start_hdl = GATT_GAP_START_HANDLE;
  gatt_cb.hdl_cfg.gmcs_start_hdl = GATT_GMCS_START_HANDLE;
  gatt_cb.hdl_cfg.gtbs_start_hdl = GATT_GTBS_START_HANDLE;
  gatt_cb.hdl_cfg.tmas_start_hdl = GATT_TMAS_START_HANDLE;
  gatt_cb.hdl_cfg.gmas_start_hdl = GATT_GMAS_START_HANDLE;
  gatt_cb.hdl_cfg.app_start_hdl = GATT_APP_START_HANDLE;

  gatt_cb.hdl_list_info = new std::list<tGATT_HDL_LIST_ELEM>();
  gatt_cb.srv_list_info = std::make_shared<std::list<tGATT_SRV_LIST_ELEM>>();
  gatt_profile_db_init();

  if (com_android_bluetooth_flags_le_subrate_manager()) {
    gatt_init_subrate_mode_config();
  }

  EattExtension::GetInstance()->Start();

  if (com_android_bluetooth_flags_gatt_offload_api() && !gatt_offload_init()) {
    log::warn("error initializing gatt offload");
  }
}

/*******************************************************************************
 *
 * Function         gatt_free
 *
 * Description      This function frees resources used by the GATT profile.
 *
 * Returns          void
 *
 ******************************************************************************/
void gatt_free(void) {
  int i;
  log::verbose("");

  fixed_queue_free(gatt_cb.sign_op_queue, NULL);
  gatt_cb.sign_op_queue = NULL;
  fixed_queue_free(gatt_cb.srv_chg_clt_q, NULL);
  gatt_cb.srv_chg_clt_q = NULL;
  for (i = 0; i < GATT_MAX_PHY_CHANNEL; i++) {
    gatt_cb.tcb[i].pending_enc_clcb = std::deque<tGATT_CLCB*>();

    gatt_cb.tcb[i].pending_ind_q.clear();
    gatt_cb.tcb[i].pending_notif_q.clear();

    alarm_free(gatt_cb.tcb[i].conf_timer);
    gatt_cb.tcb[i].conf_timer = NULL;

    alarm_free(gatt_cb.tcb[i].ind_ack_timer);
    gatt_cb.tcb[i].ind_ack_timer = NULL;

    fixed_queue_free(gatt_cb.tcb[i].sr_cmd.multi_rsp_q, NULL);
    gatt_cb.tcb[i].sr_cmd.multi_rsp_q = NULL;

    if (gatt_cb.tcb[i].eatt) {
      EattExtension::GetInstance()->FreeGattResources(gatt_cb.tcb[i].peer_bda);
    }
  }

  gatt_cb.hdl_list_info->clear();
  delete gatt_cb.hdl_list_info;
  gatt_cb.hdl_list_info = nullptr;
  gatt_cb.srv_list_info = nullptr;

  EattExtension::GetInstance()->Stop();
}

/*******************************************************************************
 *
 * Function         gatt_force_disconnect
 *
 * Description      This function is called to forcefully disconnect a device.
 *
 * Parameter        p_tcb: pointer to the TCB to disconnect.
 *                  comment: disconnection reason
 *
 ******************************************************************************/
void gatt_force_disconnect(tGATT_TCB* p_tcb, std::string comment) {
  log::verbose("");

  if (!p_tcb) {
    log::warn("Unable to disconnect an unknown device");
    return;
  }

  if (gatt_get_ch_state(p_tcb) == GATT_CH_OPEN) {
    gatt_set_ch_state(p_tcb, GATT_CH_CLOSING);
  }

  auto hci_handle =
          get_btm_client_interface().peer.BTM_GetHCIConnHandle(p_tcb->peer_bda, p_tcb->transport);
  if (hci_handle == HCI_INVALID_HANDLE) {
    log::warn("Unable to disconnect - no handle");
  } else {
    acl_disconnect_from_handle(hci_handle, HCI_ERR_PEER_USER, comment);
  }
}

/*******************************************************************************
 *
 * Function         gatt_disconnect
 *
 * Description      This function is called to disconnect to an ATT device.
 *
 * Parameter        p_tcb: pointer to the TCB to disconnect.
 *
 * Returns          true: if connection found and to be disconnected; otherwise
 *                  return false.
 *
 ******************************************************************************/
bool gatt_disconnect(tGATT_TCB* p_tcb) {
  log::verbose("");

  if (!p_tcb) {
    log::warn("Unable to disconnect an unknown device");
    return false;
  }

  tGATT_CH_STATE ch_state = gatt_get_ch_state(p_tcb);
  if (ch_state == GATT_CH_CLOSING) {
    log::debug("Device already in closing state peer:{}", p_tcb->peer_bda);
    return true;
  }

  if (p_tcb->att_lcid != L2CAP_ATT_CID) {
    return gatt_disconnect_br(p_tcb);
  }

  /* att_lcid == L2CAP_ATT_CID */

  if (ch_state != GATT_CH_OPEN) {
    connection_manager::remove_unconditional(p_tcb->peer_bda);
    gatt_cleanup_upon_disc(p_tcb->peer_bda, GATT_CONN_TERMINATE_LOCAL_HOST, p_tcb->transport);
    return true;
  }

  if (p_tcb->eatt) {
    /* ATT is fixed channel and it is expected to drop ACL.
     * Make sure all EATT channels are disconnected before doing that.
     */
    EattExtension::GetInstance()->Disconnect(p_tcb->peer_bda);
  }

  if (!stack::l2cap::get_interface().L2CA_RemoveFixedChnl(L2CAP_ATT_CID, p_tcb->peer_bda)) {
    log::warn("Unable to remove L2CAP ATT fixed channel peer:{}", p_tcb->peer_bda);
  }

  gatt_set_ch_state(p_tcb, GATT_CH_CLOSING);
  return true;
}

/*******************************************************************************
 *
 * Function         gatt_update_app_hold_link_status
 *
 * Description      Update the application use link status
 *
 * Returns          true if any modifications are made or
 *                  when it already exists, false otherwise.
 *
 ******************************************************************************/
static bool gatt_update_app_hold_link_status(tGATT_IF gatt_if, tGATT_TCB* p_tcb, bool is_add) {
  log::debug("gatt_if={}, is_add={}, peer_bda={}", gatt_if, is_add, p_tcb->peer_bda);
  auto& holders = p_tcb->app_hold_link;

  if (is_add) {
    auto ret = holders.insert(gatt_if);
    if (ret.second) {
      log::info("added gatt_if={}", gatt_if);
    } else {
      log::warn("attempt to add already existing gatt_if={}", gatt_if);
    }

    auto holders_string = gatt_tcb_get_holders_info_string(p_tcb);
    tcb_state_history_.Push({.address = p_tcb->peer_bda,
                             .transport = p_tcb->transport,
                             .state = p_tcb->ch_state,
                             .holders_info = holders_string});
    return true;
  }

  //! is_add
  if (!holders.erase(gatt_if)) {
    log::warn("attempt to remove non-existing gatt_if={}", gatt_if);
    return false;
  }

  log::info("removed gatt_if={}", gatt_if);

  auto holders_string = gatt_tcb_get_holders_info_string(p_tcb);
  tcb_state_history_.Push({.address = p_tcb->peer_bda,
                           .transport = p_tcb->transport,
                           .state = p_tcb->ch_state,
                           .holders_info = holders_string});
  return true;
}

static void gatt_set_idle_timeout(const RawAddress& bd_addr, bool is_active) {
  uint16_t idle_tout = is_active ? GATT_LINK_NO_IDLE_TIMEOUT : GATT_LINK_IDLE_TIMEOUT_WHEN_NO_APP;
  bool status = stack::l2cap::get_interface().L2CA_SetLeGattTimeout(bd_addr, idle_tout);

  if (is_active) {
    status &= stack::l2cap::get_interface().L2CA_MarkLeLinkAsActive(bd_addr);
  } else {
    if (!stack::l2cap::get_interface().L2CA_SetIdleTimeoutByBdAddr(
                bd_addr, GATT_LINK_IDLE_TIMEOUT_WHEN_NO_APP, BT_TRANSPORT_LE)) {
      log::warn("Unable to set L2CAP link idle timeout peer:{} ", bd_addr);
    }
  }

  log::info("idle_timeout={}, is_active={}, status={} (1-OK 0-not performed)", idle_tout, is_active,
            status);
}

/*******************************************************************************
 *
 * Function         gatt_update_app_use_link_flag
 *
 * Description      Update the application use link flag and optional to check
 *                  the acl link if the link is up then set the idle time out
 *                  accordingly
 *
 * Returns          void.
 *
 ******************************************************************************/
void gatt_update_app_use_link_flag(tGATT_IF gatt_if, tGATT_TCB* p_tcb, bool is_add,
                                   bool check_acl_link) {
  log::debug("gatt_if={}, is_add={} chk_link={}", gatt_if, is_add, check_acl_link);

  if (!p_tcb) {
    log::warn("p_tcb is null");
    return;
  }

  // If we make no modification, i.e. kill app that was never connected to a
  // device, skip updating the device state.
  if (!gatt_update_app_hold_link_status(gatt_if, p_tcb, is_add)) {
    log::info("App status is not updated for gatt_if={}", gatt_if);
    return;
  }

  if (!check_acl_link) {
    log::info("check_acl_link is false, no need to check");
    return;
  }

  bool is_valid_handle = (get_btm_client_interface().peer.BTM_GetHCIConnHandle(
                                  p_tcb->peer_bda, p_tcb->transport) != GATT_INVALID_ACL_HANDLE);

  if (is_add) {
    if (p_tcb->att_lcid == L2CAP_ATT_CID && is_valid_handle) {
      log::info("disable link idle timer for {}", p_tcb->peer_bda);
      /* acl link is connected disable the idle timeout */
      gatt_set_idle_timeout(p_tcb->peer_bda, true /* is_active */);
    } else {
      log::info("invalid handle {} or dynamic CID {}", is_valid_handle, p_tcb->att_lcid);
    }
  } else {
    if (p_tcb->app_hold_link.empty()) {
      if (com_android_bluetooth_flags_gatt_offload_api()) {
        gatt_offload_clear_sessions_by_conn_id(gatt_create_conn_id(p_tcb->tcb_idx, gatt_if));
      }
      // acl link is connected but no application needs to use the link
      if (p_tcb->att_lcid == L2CAP_ATT_CID && is_valid_handle) {
        /* Drop EATT before closing ATT */
        EattExtension::GetInstance()->Disconnect(p_tcb->peer_bda);

        /* for fixed channel, set the timeout value to
           GATT_LINK_IDLE_TIMEOUT_WHEN_NO_APP seconds */
        log::info(
                "GATT fixed channel is no longer useful, start link idle timer for "
                "{} seconds",
                GATT_LINK_IDLE_TIMEOUT_WHEN_NO_APP);
        gatt_set_idle_timeout(p_tcb->peer_bda, false /* is_active */);
      } else {
        // disconnect the dynamic channel
        log::info("disconnect GATT dynamic channel");
        gatt_disconnect(p_tcb);
      }
    } else {
      auto holders = gatt_tcb_get_holders_info_string(p_tcb);
      log::info("is_add=false, but some app is still using the ACL link. {}", holders);

      tcb_state_history_.Push({.address = p_tcb->peer_bda,
                               .transport = p_tcb->transport,
                               .state = p_tcb->ch_state,
                               .holders_info = holders});
    }
  }
}

/** This function is called to process the congestion callback from lcb */
void gatt_channel_congestion(tGATT_TCB* p_tcb, bool congested) {
  tCONN_ID conn_id;

  /* if uncongested, check to see if there is any more pending data */
  if (p_tcb != NULL && !congested) {
    gatt_cl_send_next_cmd_inq(*p_tcb);
  }
  /* notifying all applications for the connection up event */
  for (auto& [i, p_reg] : gatt_cb.cl_rcb_map) {
    if (p_reg->in_use && p_reg->app_cb.p_congestion_cb) {
      conn_id = gatt_create_conn_id(p_tcb->tcb_idx, p_reg->gatt_if);
      (*p_reg->app_cb.p_congestion_cb)(conn_id, congested);
    }
  }
}

void gatt_notify_phy_updated(tHCI_STATUS status, uint16_t handle, uint8_t tx_phy, uint8_t rx_phy) {
  const BtmDevice* p_device = btm_find_dev_by_handle(handle);
  if (!p_device) {
    log::warn("No Device Found!");
    return;
  }

  tGATT_TCB* p_tcb = gatt_find_tcb_by_addr(p_device->ble.pseudo_addr, BT_TRANSPORT_LE);
  if (!p_tcb) {
    return;
  }

  // TODO: Clean up this status conversion.
  tGATT_STATUS gatt_status = static_cast<tGATT_STATUS>(status);

  for (auto& [i, p_reg] : gatt_cb.cl_rcb_map) {
    if (p_reg->in_use && p_reg->app_cb.p_phy_update_cb) {
      tCONN_ID conn_id = gatt_create_conn_id(p_tcb->tcb_idx, p_reg->gatt_if);
      (*p_reg->app_cb.p_phy_update_cb)(p_reg->gatt_if, conn_id, tx_phy, rx_phy, gatt_status);
    }
  }
}

void gatt_notify_conn_update(const RawAddress& remote, uint16_t interval, uint16_t latency,
                             uint16_t timeout, tHCI_STATUS status) {
  tGATT_TCB* p_tcb = gatt_find_tcb_by_addr(remote, BT_TRANSPORT_LE);

  if (!p_tcb) {
    return;
  }

  if (com_android_bluetooth_flags_le_subrate_manager()) {
    if (status == HCI_SUCCESS) {
      // call subrate function to adjust subrate parameter
      gatt_handle_conn_parameter_cback_status(remote, interval);
    }
  }

  for (auto& [i, p_reg] : gatt_cb.cl_rcb_map) {
    if (p_reg->in_use && p_reg->app_cb.p_conn_update_cb) {
      tCONN_ID conn_id = gatt_create_conn_id(p_tcb->tcb_idx, p_reg->gatt_if);
      (*p_reg->app_cb.p_conn_update_cb)(p_reg->gatt_if, conn_id, interval, latency, timeout,
                                        static_cast<tGATT_STATUS>(status));
    }
  }
}

void gatt_notify_subrate_change(uint16_t handle, uint16_t subrate_factor, uint16_t latency,
                                uint16_t cont_num, uint16_t timeout, uint8_t status) {
  const BtmDevice* p_device = btm_find_dev_by_handle(handle);
  if (!p_device) {
    log::warn("No Device Found!");
    return;
  }

  tGATT_TCB* p_tcb = gatt_find_tcb_by_addr(p_device->ble.pseudo_addr, BT_TRANSPORT_LE);
  if (!p_tcb) {
    return;
  }

  if (com_android_bluetooth_flags_le_subrate_manager()) {
    if (gatt_handle_subrate_cback_status(p_device->ble.pseudo_addr, subrate_factor, latency,
                                    cont_num, timeout, status)) {
      tGATT_SUBRATE_MODE mode
              = gatt_cb.subrate_info[p_device->ble.pseudo_addr].current_config.mode;
      log::verbose("Subrate event callback mode: {} status: {}", mode, status);
      for (auto& [i, p_reg] : gatt_cb.cl_rcb_map) {
        if (p_reg->in_use && p_reg->app_cb.p_subrate_chg_cb) {
          tCONN_ID conn_id = gatt_create_conn_id(p_tcb->tcb_idx, p_reg->gatt_if);
          (*p_reg->app_cb.p_subrate_chg_cb)(p_reg->gatt_if, conn_id, subrate_factor,
                                            latency, cont_num, timeout,
                                            mode, static_cast<tGATT_STATUS>(status));
        }
      }
    }
  } else {
    for (auto& [i, p_reg] : gatt_cb.cl_rcb_map) {
      if (p_reg->in_use && p_reg->app_cb.p_subrate_chg_cb) {
        tCONN_ID conn_id = gatt_create_conn_id(p_tcb->tcb_idx, p_reg->gatt_if);
        (*p_reg->app_cb.p_subrate_chg_cb)(p_reg->gatt_if, conn_id, subrate_factor,
                                          latency, cont_num, timeout,
                                          GATT_SUBRATE_MODE_OFF, static_cast<tGATT_STATUS>(status));
      }
    }
  }
}

/** Callback used to notify layer above about a connection */
void gatt_send_conn_cback(tGATT_TCB* p_tcb) {
  if (p_tcb->att_lcid == L2CAP_ATT_CID) {
    std::set<tGATT_IF> apps = connection_manager::get_apps_connecting_to(p_tcb->peer_bda);
    for (auto& [i, p_reg] : gatt_cb.cl_rcb_map) {
      if (!p_reg->in_use || !apps.contains(p_reg->gatt_if)) {
        continue;
      }

      gatt_update_app_use_link_flag(p_reg->gatt_if, p_tcb, true, true);
    }

    if (!com_android_bluetooth_flags_move_conn_mgr_callbacks()) {
      /* Remove the direct connection */
      connection_manager::on_connection_complete(p_tcb->peer_bda);
    }

    bool is_active = !p_tcb->app_hold_link.empty();
    gatt_set_idle_timeout(p_tcb->peer_bda, is_active);
  }

  if (gatt_cb.debug_conn_state) {
    gatt_cb.debug_conn_state(p_tcb->peer_bda, true, GATT_CONN_OK);
  }

  /* notifying all applications for the connection up event */
  for (auto& [i, p_reg] : gatt_cb.cl_rcb_map) {
    if (!p_reg->in_use || !p_reg->app_cb.p_conn_cb) {
      continue;
    }

    tCONN_ID conn_id = gatt_create_conn_id(p_tcb->tcb_idx, p_reg->gatt_if);
    (*p_reg->app_cb.p_conn_cb)(p_reg->gatt_if, p_tcb->peer_bda, conn_id, kGattConnected,
                               GATT_CONN_OK, p_tcb->transport);
  }
}

void gatt_consolidate(const RawAddress& identity_addr, const RawAddress& rpa) {
  tGATT_TCB* p_tcb = gatt_find_tcb_by_addr(rpa, BT_TRANSPORT_LE);
  if (p_tcb == NULL) {
    return;
  }

  log::info("consolidate {} -> {}", rpa, identity_addr);
  p_tcb->peer_bda = identity_addr;

  // Address changed, notify GATT clients/servers device is available under new
  // address
  gatt_send_conn_cback(p_tcb);
}
/*******************************************************************************
 *
 * Function         gatt_data_process
 *
 * Description      This function is called when data is received from L2CAP.
 *                  if we are the originator of the connection, we are the ATT
 *                  client, and the received message is queued up for the
 *                  client.
 *
 *                  If we are the destination of the connection, we are the ATT
 *                  server, so the message is passed to the server processing
 *                  function.
 *
 * Returns          void
 *
 ******************************************************************************/
void gatt_data_process(tGATT_TCB& tcb, uint16_t cid, BT_HDR* p_buf) {
  uint8_t* p = (uint8_t*)(p_buf + 1) + p_buf->offset;
  uint8_t op_code, pseudo_op_code;

  if (p_buf->len <= 0) {
    log::error("invalid data length, ignore");
    return;
  }

  uint16_t msg_len = p_buf->len - 1;
  STREAM_TO_UINT8(op_code, p);

  /* remove the two MSBs associated with sign write and write cmd */
  pseudo_op_code = op_code & (~GATT_WRITE_CMD_MASK);

  if (pseudo_op_code >= GATT_OP_CODE_MAX) {
    /* Note: PTS: GATT/SR/UNS/BI-01-C mandates error on unsupported ATT request.
     */
    log::error("ATT - Rcvd L2CAP data, unknown cmd: 0x{:x}", op_code);
    gatt_send_error_rsp(tcb, cid, GATT_REQ_NOT_SUPPORTED, op_code, 0, false);
    return;
  }

  if (op_code == GATT_SIGN_CMD_WRITE) {
    gatt_verify_signature(tcb, cid, p_buf);
  } else {
    /* message from client */
    if ((op_code % 2) == 0) {
      gatt_server_handle_client_req(tcb, cid, op_code, msg_len, p);
    } else {
      gatt_client_handle_server_rsp(tcb, cid, op_code, msg_len, p);
    }
  }
}

/** Add a bonded dev to the service changed client list */
void gatt_add_a_bonded_dev_for_srv_chg(const RawAddress& bda) {
  tGATTS_SRV_CHG_REQ req;
  tGATTS_SRV_CHG srv_chg_clt;

  srv_chg_clt.bda = bda;
  srv_chg_clt.srv_changed = false;
  srv_chg_clt.start_handle = 0xFFFF;
  if (!gatt_add_srv_chg_clt(&srv_chg_clt)) {
    return;
  }

  req.srv_chg.bda = bda;
  req.srv_chg.srv_changed = false;
  req.srv_chg.start_handle = 0xFFFF;
  if (gatt_cb.cb_info.p_srv_chg_callback) {
    (*gatt_cb.cb_info.p_srv_chg_callback)(GATTS_SRV_CHG_CMD_ADD_CLIENT, &req, NULL);
  }
}

/** This function is called to send a service changed indication to the
 * specified bd address */
void gatt_send_srv_chg_ind(const RawAddress& peer_bda, uint16_t start_handle) {
  static const uint16_t sGATT_DEFAULT_START_HANDLE = (uint16_t)osi_property_get_int32(
          "bluetooth.gatt.default_start_handle_for_srvc_change.value", GATT_GATT_START_HANDLE);
  static const uint16_t sGATT_LAST_HANDLE = (uint16_t)osi_property_get_int32(
          "bluetooth.gatt.last_handle_for_srvc_change.value", 0xFFFF);

  log::verbose("");

  if (!gatt_cb.handle_of_h_r) {
    return;
  }

  tCONN_ID conn_id = gatt_profile_find_conn_id_by_bd_addr(peer_bda);
  if (conn_id == GATT_INVALID_CONN_ID) {
    log::error("Unable to find conn_id for {}", peer_bda);
    return;
  }

  uint8_t handle_range[GATT_SIZE_OF_SRV_CHG_HNDL_RANGE];
  uint8_t* p = handle_range;

  if (com_android_bluetooth_flags_gatt_use_better_start_handle_in_service_changed()) {
    UINT16_TO_STREAM(p, start_handle);
  } else {
    UINT16_TO_STREAM(p, sGATT_DEFAULT_START_HANDLE);
  }
  UINT16_TO_STREAM(p, sGATT_LAST_HANDLE);
  if (GATTS_HandleValueIndication(conn_id, gatt_cb.handle_of_h_r, GATT_SIZE_OF_SRV_CHG_HNDL_RANGE,
                                  handle_range) != GATT_SUCCESS) {
    log::warn("Unable to handle GATT service value indication conn_id:{}", conn_id);
  }
}

/** Check sending service changed Indication is required or not if required then
 * send the Indication */
void gatt_chk_srv_chg(tGATTS_SRV_CHG* p_srv_chg_clt) {
  log::verbose("srv_changed={}, start_handle: {:#x}", p_srv_chg_clt->srv_changed,
               p_srv_chg_clt->start_handle);

  if (p_srv_chg_clt->srv_changed) {
    char remote_name[BD_NAME_LEN] = "";

    if (btif_storage_get_stored_remote_name(p_srv_chg_clt->bda, remote_name)) {
      if (interop_match_name(INTEROP_GATTC_NO_SERVICE_CHANGED_IND, remote_name)) {
        log::verbose("discard srv chg - interop matched {}", remote_name);
        p_srv_chg_clt->srv_changed = false;
      }
    }
  }

  if (p_srv_chg_clt->srv_changed) {
    gatt_send_srv_chg_ind(p_srv_chg_clt->bda, p_srv_chg_clt->start_handle);
  }
}

/** This function is used to initialize the service changed attribute value */
void gatt_init_srv_chg(void) {
  tGATTS_SRV_CHG_REQ req;
  tGATTS_SRV_CHG_RSP rsp;
  tGATTS_SRV_CHG srv_chg_clt;

  log::verbose("");
  if (!gatt_cb.cb_info.p_srv_chg_callback) {
    log::verbose("callback not registered yet");
    return;
  }

  bool status =
          (*gatt_cb.cb_info.p_srv_chg_callback)(GATTS_SRV_CHG_CMD_READ_NUM_CLENTS, NULL, &rsp);

  if (!(status && rsp.num_clients)) {
    return;
  }

  log::verbose("num_srv_chg_clt_clients={}", rsp.num_clients);
  uint8_t num_clients = rsp.num_clients;
  uint8_t i = 1; /* use one based index */
  while ((i <= num_clients) && status) {
    req.client_read_index = i;
    status = (*gatt_cb.cb_info.p_srv_chg_callback)(GATTS_SRV_CHG_CMD_READ_CLENT, &req, &rsp);
    if (status) {
      memcpy(&srv_chg_clt, &rsp.srv_chg, sizeof(tGATTS_SRV_CHG));
      if (gatt_add_srv_chg_clt(&srv_chg_clt) == NULL) {
        log::error("Unable to add a service change client");
        status = false;
      }
    }
    i++;
  }
}

/**This function is process the service changed request */
void gatt_proc_srv_chg(uint16_t start_handle) {
  RawAddress bda;
  tBT_TRANSPORT transport;
  uint8_t found_idx;

  log::verbose("");

  if (!gatt_cb.cb_info.p_srv_chg_callback || !gatt_cb.handle_of_h_r) {
    return;
  }

  gatt_set_srv_chg(start_handle);
  uint8_t start_idx = 0;
  while (gatt_find_the_connected_bda(start_idx, bda, &found_idx, &transport)) {
    tGATT_TCB* p_tcb = &gatt_cb.tcb[found_idx];

    bool send_indication = true;

    if (gatt_is_srv_chg_ind_pending(p_tcb)) {
      send_indication = false;
      log::verbose("discard srv chg - already has one in the queue");
    }

    // Some LE GATT clients don't respond to service changed indications.
    char remote_name[BD_NAME_LEN] = "";
    if (send_indication && btif_storage_get_stored_remote_name(bda, remote_name)) {
      if (interop_match_name(INTEROP_GATTC_NO_SERVICE_CHANGED_IND, remote_name)) {
        log::verbose("discard srv chg - interop matched {}", remote_name);
        send_indication = false;
      }
    }

    if (send_indication) {
      gatt_send_srv_chg_ind(bda, start_handle);
    }

    start_idx = ++found_idx;
  }
}

/** This function set the ch_state in tcb */
void gatt_set_ch_state(tGATT_TCB* p_tcb, tGATT_CH_STATE ch_state) {
  if (!p_tcb) {
    return;
  }

  std::string holders_string = gatt_tcb_get_holders_info_string(p_tcb);
  log::verbose("{}, transport: {}, state: {} -> {}, {}", p_tcb->peer_bda,
               bt_transport_text(p_tcb->transport), gatt_channel_state_text(p_tcb->ch_state),
               gatt_channel_state_text(ch_state), holders_string);

  tcb_state_history_.Push({.address = p_tcb->peer_bda,
                           .transport = p_tcb->transport,
                           .state = ch_state,
                           .holders_info = holders_string});

  p_tcb->ch_state = ch_state;
}

/** This function get the ch_state in tcb */
tGATT_CH_STATE gatt_get_ch_state(tGATT_TCB* p_tcb) {
  if (!p_tcb) {
    return GATT_CH_CLOSE;
  }

  log::verbose("{}, transport {},  ch_state={}", p_tcb->peer_bda,
               bt_transport_text(p_tcb->transport), gatt_channel_state_text(p_tcb->ch_state));
  return p_tcb->ch_state;
}
