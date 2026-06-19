/******************************************************************************
 *
 *  Copyright 1999-2012 Broadcom Corporation
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
 *  this file contains GATT interface functions
 *
 ******************************************************************************/
#define LOG_TAG "gatt_api"

#include "stack/include/gatt_api.h"

#include <base/strings/string_number_conversions.h>
#include <bluetooth/log.h>
#include <bluetooth/metrics/bluetooth_event.h>
#include <bluetooth/metrics/os_metrics.h>
#include <bluetooth/types/address.h>
#include <bluetooth/types/bt_transport.h>
#include <bluetooth/types/uuid.h>
#include <com_android_bluetooth_flags.h>
#include <log/log.h>

#include <string>

#include "internal_include/bt_target.h"
#include "os/system_properties.h"
#include "osi/include/allocator.h"
#include "stack/arbiter/acl_arbiter.h"
#include "stack/btm/btm_dev.h"
#include "stack/gatt/gatt_int.h"
#include "stack/include/ais_api.h"
#include "stack/include/bt_hdr.h"
#include "stack/include/bt_psm_types.h"
#include "stack/include/bt_types.h"
#include "stack/include/bt_uuid16.h"
#include "stack/include/btm_client_interface.h"
#include "stack/include/l2cap_interface.h"
#include "stack/include/l2cdefs.h"
#include "stack/include/sdp_api.h"

using namespace bluetooth::legacy::stack::sdp;
using namespace bluetooth;

using bluetooth::Uuid;

/**
 * Add a service handle range to the list in descending order of the start
 * handle. Return reference to the newly added element.
 **/
static tGATT_HDL_LIST_ELEM& gatt_add_an_item_to_list(uint16_t s_handle) {
  auto lst_ptr = gatt_cb.hdl_list_info;
  auto it = lst_ptr->begin();
  for (; it != lst_ptr->end(); it++) {
    if (s_handle > it->asgn_range.s_handle) {
      break;
    }
  }

  auto rit = lst_ptr->emplace(it);
  return *rit;
}

/*****************************************************************************
 *
 *                  GATT SERVER API
 *
 *****************************************************************************/
/*******************************************************************************
 *
 * Function         GATTS_NVRegister
 *
 * Description      Application manager calls this function to register for
 *                  NV save callback function.  There can be one and only one
 *                  NV save callback function.
 *
 * Parameter        p_cb_info : callback information
 *
 * Returns          true if registered OK, else false
 *
 ******************************************************************************/
bool GATTS_NVRegister(tGATT_APPL_INFO* p_cb_info) {
  bool status = false;
  if (p_cb_info) {
    gatt_cb.cb_info = *p_cb_info;
    status = true;
    gatt_init_srv_chg();
  }

  return status;
}

static uint16_t compute_service_size(btgatt_db_element_t* service, int count) {
  int db_size = 0;
  btgatt_db_element_t* el = service;

  for (int i = 0; i < count; i++, el++) {
    if (el->type == BTGATT_DB_PRIMARY_SERVICE || el->type == BTGATT_DB_SECONDARY_SERVICE ||
        el->type == BTGATT_DB_DESCRIPTOR || el->type == BTGATT_DB_INCLUDED_SERVICE) {
      db_size += 1;
    } else if (el->type == BTGATT_DB_CHARACTERISTIC) {
      db_size += 2;

      // if present, Characteristic Extended Properties takes one handle
      if (el->properties & GATT_CHAR_PROP_BIT_EXT_PROP) {
        db_size++;
      }
    } else {
      log::error("Unknown element type: {}", el->type);
    }
  }

  return db_size;
}

static bool is_gatt_attr_type(const Uuid& uuid) {
  if (uuid == Uuid::From16Bit(GATT_UUID_PRI_SERVICE) ||
      uuid == Uuid::From16Bit(GATT_UUID_SEC_SERVICE) ||
      uuid == Uuid::From16Bit(GATT_UUID_INCLUDE_SERVICE) ||
      uuid == Uuid::From16Bit(GATT_UUID_CHAR_DECLARE)) {
    return true;
  }
  return false;
}

/** Update the the last service info for the service list info */
static void gatt_update_last_srv_info() {
  gatt_cb.last_service_handle = 0;

  auto srv_list_info = gatt_cb.srv_list_info;
  if (srv_list_info == nullptr) {
    return;
  }

  for (tGATT_SRV_LIST_ELEM& el : *srv_list_info) {
    gatt_cb.last_service_handle = el.s_hdl;
  }
}

/** Update database hash and client status */
static void gatt_update_for_database_change() {
  auto srv_list_info = gatt_cb.srv_list_info;
  if (srv_list_info == nullptr) {
    return;
  }

  gatt_cb.database_hash = gatts_calculate_database_hash(srv_list_info);

  uint8_t i = 0;
  for (i = 0; i < GATT_MAX_PHY_CHANNEL; i++) {
    tGATT_TCB& tcb = gatt_cb.tcb[i];
    if (tcb.in_use) {
      gatt_sr_update_cl_status(tcb, /* chg_aware= */ false);
    }
  }
}

/*******************************************************************************
 *
 * Function         GATTS_AddService
 *
 * Description      This function is called to add GATT service.
 *
 * Parameter        gatt_if : application if
 *                  service : pseudo-representation of service and it's content
 *                  count   : size of service
 *
 * Returns          on success GATT_SERVICE_STARTED is returned, and
 *                  attribute_handle field inside service elements are filled.
 *                  on error error status is returned.
 *
 ******************************************************************************/
tGATT_STATUS GATTS_AddService(tGATT_IF gatt_if, btgatt_db_element_t* service, int count) {
  uint16_t s_hdl = 0;
  bool save_hdl = false;
  tGATT_REG* p_reg = gatt_get_regcb(gatt_if);

  bool is_pri = (service->type == BTGATT_DB_PRIMARY_SERVICE) ? true : false;
  Uuid svc_uuid = service->uuid;

  log::info("");

  if (!p_reg) {
    log::error("Invalid gatt_if={}", gatt_if);
    return GATT_INTERNAL_ERROR;
  }

  uint16_t num_handles = compute_service_size(service, count);

  if (svc_uuid == Uuid::From16Bit(UUID_SERVCLASS_GATT_SERVER)) {
    s_hdl = gatt_cb.hdl_cfg.gatt_start_hdl;
  } else if (svc_uuid == Uuid::From16Bit(UUID_SERVCLASS_GAP_SERVER)) {
    s_hdl = gatt_cb.hdl_cfg.gap_start_hdl;
  } else if (svc_uuid == Uuid::From16Bit(UUID_SERVCLASS_GMCS_SERVER)) {
    s_hdl = gatt_cb.hdl_cfg.gmcs_start_hdl;
  } else if (svc_uuid == Uuid::From16Bit(UUID_SERVCLASS_GTBS_SERVER)) {
    s_hdl = gatt_cb.hdl_cfg.gtbs_start_hdl;
  } else if (svc_uuid == Uuid::From16Bit(UUID_SERVCLASS_TMAS_SERVER)) {
    s_hdl = gatt_cb.hdl_cfg.tmas_start_hdl;
  } else if (svc_uuid == Uuid::From16Bit(UUID_SERVCLASS_GMAS_SERVER)) {
    s_hdl = gatt_cb.hdl_cfg.gmas_start_hdl;
  } else {
    if (!gatt_cb.hdl_list_info->empty()) {
      s_hdl = gatt_cb.hdl_list_info->front().asgn_range.e_handle + 1;
    }

    if (s_hdl < gatt_cb.hdl_cfg.app_start_hdl) {
      s_hdl = gatt_cb.hdl_cfg.app_start_hdl;
    }

    save_hdl = true;
  }

  /* check for space */
  if (num_handles > (0xFFFF - s_hdl + 1)) {
    log::error("no handles, s_hdl={} needed={}", s_hdl, num_handles);
    return GATT_INTERNAL_ERROR;
  }

  tGATT_HDL_LIST_ELEM& list = gatt_add_an_item_to_list(s_hdl);
  list.asgn_range.app_uuid128 = p_reg->app_uuid128;
  list.asgn_range.svc_uuid = svc_uuid;
  list.asgn_range.s_handle = s_hdl;
  list.asgn_range.e_handle = s_hdl + num_handles - 1;
  list.asgn_range.is_primary = is_pri;

  if (save_hdl) {
    if (gatt_cb.cb_info.p_nv_save_callback) {
      (*gatt_cb.cb_info.p_nv_save_callback)(true, &list.asgn_range);
    }
  }

  gatts_init_service_db(list.svc_db, svc_uuid, is_pri, s_hdl, num_handles);

  log::verbose("handles needed={}, s_hdl=0x{:x}, e_hdl=0x{:x}, uuid={}, is_primary={}", num_handles,
               list.asgn_range.s_handle, list.asgn_range.e_handle, list.asgn_range.svc_uuid,
               list.asgn_range.is_primary);

  service->attribute_handle = s_hdl;

  btgatt_db_element_t* el = service + 1;
  for (int i = 0; i < count - 1; i++, el++) {
    const Uuid& uuid = el->uuid;

    if (el->type == BTGATT_DB_CHARACTERISTIC) {
      /* data validity checking */
      if (((el->properties & GATT_CHAR_PROP_BIT_AUTH) &&
           !(el->permissions & GATT_WRITE_SIGNED_PERM)) ||
          ((el->permissions & GATT_WRITE_SIGNED_PERM) &&
           !(el->properties & GATT_CHAR_PROP_BIT_AUTH))) {
        log::verbose("Invalid configuration property=0x{:x}, perm=0x{:x}", el->properties,
                     el->permissions);
        return GATT_INTERNAL_ERROR;
      }

      if (is_gatt_attr_type(uuid)) {
        log::error(
                "attempt to add characteristic with UUID equal to GATT Attribute "
                "Type {}",
                uuid);
        return GATT_INTERNAL_ERROR;
      }

      el->attribute_handle =
              gatts_add_characteristic(list.svc_db, el->permissions, el->properties, uuid);

      // add characteristic extended properties descriptor if needed
      if (el->properties & GATT_CHAR_PROP_BIT_EXT_PROP) {
        gatts_add_char_ext_prop_descr(list.svc_db, el->extended_properties);
      }

    } else if (el->type == BTGATT_DB_DESCRIPTOR) {
      if (is_gatt_attr_type(uuid)) {
        log::error(
                "attempt to add descriptor with UUID equal to GATT Attribute Type "
                "{}",
                uuid);
        return GATT_INTERNAL_ERROR;
      }

      el->attribute_handle = gatts_add_char_descr(list.svc_db, el->permissions, uuid);
    } else if (el->type == BTGATT_DB_INCLUDED_SERVICE) {
      tGATT_HDL_LIST_ELEM* p_incl_decl;
      p_incl_decl = gatt_find_hdl_buffer_by_handle(el->attribute_handle);
      if (p_incl_decl == nullptr) {
        log::verbose("Included Service not created");
        return GATT_INTERNAL_ERROR;
      }

      el->attribute_handle = gatts_add_included_service(
              list.svc_db, p_incl_decl->asgn_range.s_handle, p_incl_decl->asgn_range.e_handle,
              p_incl_decl->asgn_range.svc_uuid);
    }
  }

  log::info("service parsed correctly, now starting");

  /*this is a new application service start */

  // find a place for this service in the list
  auto lst_ptr = gatt_cb.srv_list_info;
  auto it = lst_ptr->begin();
  for (; it != lst_ptr->end(); it++) {
    if (list.asgn_range.s_handle < it->s_hdl) {
      break;
    }
  }
  auto rit = lst_ptr->emplace(it);

  tGATT_SRV_LIST_ELEM& elem = *rit;
  elem.gatt_if = gatt_if;
  elem.s_hdl = list.asgn_range.s_handle;
  elem.e_hdl = list.asgn_range.e_handle;
  elem.p_db = &list.svc_db;
  elem.is_primary = list.asgn_range.is_primary;

  elem.app_uuid = list.asgn_range.app_uuid128;
  elem.type = list.asgn_range.is_primary ? GATT_UUID_PRI_SERVICE : GATT_UUID_SEC_SERVICE;

  if (elem.type == GATT_UUID_PRI_SERVICE && gatt_cb.over_br_enabled) {
    Uuid* p_uuid = gatts_get_service_uuid(elem.p_db);
    if (*p_uuid != Uuid::From16Bit(UUID_SERVCLASS_GMCS_SERVER) &&
        *p_uuid != Uuid::From16Bit(UUID_SERVCLASS_GTBS_SERVER)) {
      if (*p_uuid == Uuid::From16Bit(UUID_SERVCLASS_RAS) ||
          *p_uuid == ANDROID_INFORMATION_SERVICE_UUID) {
        elem.sdp_handle = 0;
      } else {
        elem.sdp_handle = gatt_add_sdp_record(*p_uuid, elem.s_hdl, elem.e_hdl);
      }
    } else {
      elem.sdp_handle = 0;
    }
  } else {
    elem.sdp_handle = 0;
  }

  gatt_update_last_srv_info();

  log::verbose("allocated el s_hdl=0x{:x}, e_hdl=0x{:x}, type=0x{:x}, sdp_hdl=0x{:x}", elem.s_hdl,
               elem.e_hdl, elem.type, elem.sdp_handle);

  gatt_update_for_database_change();
  gatt_proc_srv_chg(s_hdl);

  return GATT_SERVICE_STARTED;
}

static bool is_active_service(const Uuid& app_uuid128, Uuid* p_svc_uuid, uint16_t start_handle) {
  for (auto& info : *gatt_cb.srv_list_info) {
    Uuid* p_this_uuid = gatts_get_service_uuid(info.p_db);

    if (p_this_uuid && app_uuid128 == info.app_uuid && *p_svc_uuid == *p_this_uuid &&
        (start_handle == info.s_hdl)) {
      log::error("Active Service Found: {}", *p_svc_uuid);
      return true;
    }
  }
  return false;
}

/*******************************************************************************
 *
 * Function         GATTS_DeleteService
 *
 * Description      This function is called to delete a service.
 *
 * Parameter        gatt_if       : application interface
 *                  p_svc_uuid    : service UUID
 *                  start_handle  : start handle of the service
 *
 * Returns          true if the operation succeeded, false if the handle block
 *                  was not found.
 *
 ******************************************************************************/
bool GATTS_DeleteService(tGATT_IF gatt_if, Uuid* p_svc_uuid, uint16_t svc_inst) {
  log::verbose("");

  tGATT_REG* p_reg = gatt_get_regcb(gatt_if);
  if (p_reg == NULL) {
    log::error("Application not found");
    return false;
  }

  auto it = gatt_find_hdl_buffer_by_app_id(p_reg->app_uuid128, p_svc_uuid, svc_inst);
  if (it == gatt_cb.hdl_list_info->end()) {
    log::error("No Service found");
    return false;
  }

  if (is_active_service(p_reg->app_uuid128, p_svc_uuid, svc_inst)) {
    GATTS_StopService(it->asgn_range.s_handle);
  }

  /* Prune any pending notifications/indications for this service */
  for (int i = 0; i < GATT_MAX_PHY_CHANNEL; ++i) {
    tGATT_TCB& tcb = gatt_cb.tcb[i];
    if (!tcb.in_use) {
      continue;
    }

    tcb.pending_ind_q.remove_if([&](const tGATT_VALUE& value) {
      if (value.handle >= it->asgn_range.s_handle && value.handle <= it->asgn_range.e_handle) {
        log::info("Pruning pending indication for handle: 0x{:04x}", value.handle);
        return true;
      }
      return false;
    });

    auto it_notif = tcb.pending_notif_q.begin();
    while (it_notif != tcb.pending_notif_q.end()) {
      bool remove = false;
      if (std::holds_alternative<tGATT_VALUE>(*it_notif)) {
        tGATT_VALUE& notif = std::get<tGATT_VALUE>(*it_notif);
        if (notif.handle >= it->asgn_range.s_handle && notif.handle <= it->asgn_range.e_handle) {
          remove = true;
        }
      } else {
        std::vector<tGATT_VALUE>& multi_notif = std::get<std::vector<tGATT_VALUE>>(*it_notif);
        std::erase_if(multi_notif, [&](const tGATT_VALUE& notif) {
          if (notif.handle >= it->asgn_range.s_handle && notif.handle <= it->asgn_range.e_handle) {
            log::info("Pruning pending multiple notification for handle: 0x{:04x}", notif.handle);
            return true;
          }
          return false;
        });
        remove = multi_notif.empty();
      }

      if (remove) {
        it_notif = tcb.pending_notif_q.erase(it_notif);
      } else {
        ++it_notif;
      }
    }
  }

  gatt_update_for_database_change();
  gatt_proc_srv_chg(svc_inst);

  log::verbose("released handles s_hdl=0x{:x}, e_hdl=0x{:x}", it->asgn_range.s_handle,
               it->asgn_range.e_handle);

  if ((it->asgn_range.s_handle >= gatt_cb.hdl_cfg.app_start_hdl) &&
      gatt_cb.cb_info.p_nv_save_callback) {
    (*gatt_cb.cb_info.p_nv_save_callback)(false, &it->asgn_range);
  }

  gatt_cb.hdl_list_info->erase(it);
  return true;
}

/*******************************************************************************
 *
 * Function         GATTS_StopService
 *
 * Description      This function is called to stop a service
 *
 * Parameter         service_handle : this is the start handle of a service
 *
 * Returns          None.
 *
 ******************************************************************************/
void GATTS_StopService(uint16_t service_handle) {
  log::info("service = 0x{:x}", service_handle);

  auto it = gatt_sr_find_i_rcb_by_handle(service_handle);
  if (it == gatt_cb.srv_list_info->end()) {
    log::error("service_handle=0x{:x} is not in use", service_handle);
    return;
  }

  if (it->sdp_handle) {
    if (!get_legacy_stack_sdp_api()->SDP_DeleteRecord(it->sdp_handle)) {
      log::warn("Unable to delete record handle:{}", it->sdp_handle);
    }
  }

  gatt_cb.srv_list_info->erase(it);
  gatt_update_last_srv_info();
}

/* returns false if security requirements are not met, and operation should be queued */
static bool check_notification_perm(const tGATT_TCB* p_tcb, uint16_t attr_handle) {
  tGATT_SEC_FLAG sec_flag;
  uint8_t key_size;
  gatt_sr_get_sec_info(p_tcb->peer_bda, p_tcb->transport, &sec_flag, &key_size);

  auto it = gatt_sr_find_i_rcb_by_handle(attr_handle);
  if (it == gatt_cb.srv_list_info->end()) {
    log::error("Can't find attribute 0x{:x} to check read permissions", attr_handle);
    return true;
  }

  tGATT_STATUS perm_check = gatts_notify_attr_perm_check(it->p_db, attr_handle, sec_flag, key_size);

  if (perm_check == GATT_INSUF_AUTHENTICATION || perm_check == GATT_INSUF_ENCRYPTION) {
    log::warn("Sending notification/indication, handle: 0x{:04x} bda: {} without proper security",
              attr_handle, p_tcb->peer_bda);

    tBTM_BLE_SEC_ACT btm_ble_sec_act = (perm_check == GATT_INSUF_AUTHENTICATION)
                                               ? BTM_BLE_SEC_ENCRYPT_MITM
                                               : BTM_BLE_SEC_ENCRYPT;
    tBTM_STATUS btm_status = get_security_client_interface().BTM_SetEncryption(
            p_tcb->peer_bda, p_tcb->transport, nullptr, NULL, btm_ble_sec_act);
    if (btm_status != tBTM_STATUS::BTM_SUCCESS && btm_status != tBTM_STATUS::BTM_CMD_STARTED) {
      log::error("BTM_SetEncryption failed btm_status={}", btm_status);
      return true;
    }

    return false;
  }

  return true;
}

/*******************************************************************************
 *
 * Function         GATTs_HandleValueIndication
 *
 * Description      This function sends a handle value indication to a client.
 *
 * Parameter        conn_id: connection identifier.
 *                  attr_handle: Attribute handle of this handle value
 *                               indication.
 *                  val_len: Length of the indicated attribute value.
 *                  p_val: Pointer to the indicated attribute value data.
 *
 * Returns          GATT_SUCCESS if successfully sent or queued; otherwise error
 *                  code.
 *
 ******************************************************************************/
tGATT_STATUS GATTS_HandleValueIndication(tCONN_ID conn_id, uint16_t attr_handle, uint16_t val_len,
                                         uint8_t* p_val) {
  tGATT_IF gatt_if = gatt_get_gatt_if(conn_id);
  uint8_t tcb_idx = gatt_get_tcb_idx(conn_id);
  tGATT_REG* p_reg = gatt_get_regcb(gatt_if);
  tGATT_TCB* p_tcb = gatt_get_tcb_by_idx(tcb_idx);

  log::verbose("");
  if ((p_reg == NULL) || (p_tcb == NULL)) {
    log::error("Unknown  conn_id=0x{:x}", conn_id);
    return GATT_ILLEGAL_PARAMETER;
  }

  if (!GATT_HANDLE_IS_VALID(attr_handle)) {
    return GATT_ILLEGAL_PARAMETER;
  }

  tGATT_VALUE indication;
  indication.conn_id = conn_id;
  indication.handle = attr_handle;
  indication.len = val_len;
  memcpy(indication.value, p_val, val_len);
  indication.auth_req = GATT_AUTH_REQ_NONE;

  if (!check_notification_perm(p_tcb, attr_handle)) {
    gatt_add_pending_ind(p_tcb, &indication);
    return GATT_PENDING;
  }

  uint16_t* indicate_handle_p = NULL;
  uint16_t cid;

  if (!gatt_tcb_get_cid_available_for_indication(p_tcb, p_reg->eatt_support, &indicate_handle_p,
                                                 &cid)) {
    log::verbose("Add a pending indication");
    gatt_add_pending_ind(p_tcb, &indication);
    return GATT_SUCCESS;
  }

  tGATT_SR_MSG gatt_sr_msg;
  gatt_sr_msg.attr_value = indication;

  uint16_t payload_size = gatt_tcb_get_payload_size(*p_tcb, cid);
  BT_HDR* p_msg = attp_build_sr_msg(*p_tcb, GATT_HANDLE_VALUE_IND, &gatt_sr_msg, payload_size);
  if (!p_msg) {
    return GATT_NO_RESOURCES;
  }

  tGATT_STATUS cmd_status = attp_send_sr_msg(*p_tcb, cid, p_msg);
  if (cmd_status == GATT_SUCCESS || cmd_status == GATT_CONGESTED) {
    *indicate_handle_p = indication.handle;
    gatt_start_conf_timer(p_tcb, cid);
  }
  return cmd_status;
}

tGATT_STATUS GATTS_HandleMultipleValueNotification(tCONN_ID conn_id,
                                                   std::vector<tGATT_VALUE> gatt_notif_vector) {
  tGATT_IF app_id = gatt_get_gatt_if(conn_id);
  uint8_t tcb_idx = gatt_get_tcb_idx(conn_id);
  tGATT_REG* p_reg = gatt_get_regcb(app_id);
  tGATT_TCB* p_tcb = gatt_get_tcb_by_idx(tcb_idx);

  log::verbose("");
  if ((p_reg == NULL) || (p_tcb == NULL)) {
    log::error("Unknown  conn_id=0x{:x}", conn_id);
    return GATT_ERROR;
  }

  if (gatt_notif_vector.empty()) {
    return GATT_ILLEGAL_PARAMETER;
  }

  for (auto& notif : gatt_notif_vector) {
    if (!GATT_HANDLE_IS_VALID(notif.handle)) {
      return GATT_ILLEGAL_PARAMETER;
    }
    notif.conn_id = conn_id;
  }

  uint16_t cid = gatt_tcb_get_att_cid(*p_tcb, true /* eatt support */);
  uint16_t payload_size = gatt_tcb_get_payload_size(*p_tcb, cid);

  for (const auto& notif : gatt_notif_vector) {
    if (!check_notification_perm(p_tcb, notif.handle)) {
      gatt_add_pending_multi_notif(p_tcb, &gatt_notif_vector);
      return GATT_PENDING;
    }
  }

  /* TODO Handle too big packet size here. Not needed now for testing. */
  /* Just build the message. */
  BT_HDR* p_buf = (BT_HDR*)osi_malloc(sizeof(BT_HDR) + payload_size + L2CAP_MIN_OFFSET);

  uint8_t* p = (uint8_t*)(p_buf + 1) + L2CAP_MIN_OFFSET;
  UINT8_TO_STREAM(p, GATT_HANDLE_MULTI_VALUE_NOTIF);
  p_buf->offset = L2CAP_MIN_OFFSET;
  p_buf->len = 1;
  for (auto notif : gatt_notif_vector) {
    log::info("Adding handle: 0x{:04x}, val len {}", notif.handle, notif.len);
    UINT16_TO_STREAM(p, notif.handle);
    p_buf->len += 2;
    UINT16_TO_STREAM(p, notif.len);
    p_buf->len += 2;
    ARRAY_TO_STREAM(p, notif.value, notif.len);
    p_buf->len += notif.len;
  }

  log::info("Total len: {}", p_buf->len);

  return attp_send_sr_msg(*p_tcb, cid, p_buf);
}
/*******************************************************************************
 *
 * Function         GATTS_HandleValueNotification
 *
 * Description      This function sends a handle value notification to a client.
 *
 * Parameter        conn_id: connection identifier.
 *                  attr_handle: Attribute handle of this handle value
 *                               indication.
 *                  val_len: Length of the indicated attribute value.
 *                  p_val: Pointer to the indicated attribute value data.
 *
 * Returns          GATT_SUCCESS if successfully sent; otherwise error code.
 *
 ******************************************************************************/
tGATT_STATUS GATTS_HandleValueNotification(tCONN_ID conn_id, uint16_t attr_handle, uint16_t val_len,
                                           uint8_t* p_val) {
  tGATT_VALUE notif;
  tGATT_IF gatt_if = gatt_get_gatt_if(conn_id);
  uint8_t tcb_idx = gatt_get_tcb_idx(conn_id);
  tGATT_REG* p_reg = gatt_get_regcb(gatt_if);
  tGATT_TCB* p_tcb = gatt_get_tcb_by_idx(tcb_idx);
#if (GATT_UPPER_TESTER_MULT_VARIABLE_LENGTH_NOTIF == TRUE)
  static uint8_t cached_tcb_idx = 0xFF;
  static std::vector<tGATT_VALUE> gatt_notif_vector(2);
  tGATT_VALUE* p_gatt_notif;
#endif

  log::verbose("");

  if ((p_reg == NULL) || (p_tcb == NULL)) {
    log::error("Unknown  conn_id: {}", conn_id);
    return GATT_ILLEGAL_PARAMETER;
  }

  if (!GATT_HANDLE_IS_VALID(attr_handle)) {
    return GATT_ILLEGAL_PARAMETER;
  }

#if (GATT_UPPER_TESTER_MULT_VARIABLE_LENGTH_NOTIF == TRUE)
  /* Upper tester for Multiple Value length notifications */
  if (stack_config_get_interface()->get_pts_force_eatt_for_notifications() &&
      gatt_sr_is_cl_multi_variable_len_notif_supported(*p_tcb)) {
    if (cached_tcb_idx == 0xFF) {
      log::info("Storing first notification");
      p_gatt_notif = &gatt_notif_vector[0];

      p_gatt_notif->handle = attr_handle;
      p_gatt_notif->len = val_len;
      std::copy(p_val, p_val + val_len, p_gatt_notif->value);

      notif.auth_req = GATT_AUTH_REQ_NONE;

      cached_tcb_idx = tcb_idx;
      return GATT_SUCCESS;
    }

    if (cached_tcb_idx == tcb_idx) {
      log::info("Storing second notification");
      cached_tcb_idx = 0xFF;
      p_gatt_notif = &gatt_notif_vector[1];

      p_gatt_notif->handle = attr_handle;
      p_gatt_notif->len = val_len;
      std::copy(p_val, p_val + val_len, p_gatt_notif->value);

      notif.auth_req = GATT_AUTH_REQ_NONE;

      return GATTS_HandleMultipleValueNotification(p_tcb, gatt_notif_vector);
    }

    log::error("PTS Mode: Invalid tcb_idx: {}, cached_tcb_idx: {}", tcb_idx, cached_tcb_idx);
  }
#endif

  memset(&notif, 0, sizeof(notif));
  notif.conn_id = conn_id;
  notif.handle = attr_handle;
  notif.len = val_len;
  memcpy(notif.value, p_val, val_len);
  notif.auth_req = GATT_AUTH_REQ_NONE;

  if (!check_notification_perm(p_tcb, attr_handle)) {
    gatt_add_pending_notif(p_tcb, &notif);
    return GATT_PENDING;
  }

  tGATT_STATUS cmd_sent;
  tGATT_SR_MSG gatt_sr_msg;
  gatt_sr_msg.attr_value = notif;

  uint16_t cid = gatt_tcb_get_att_cid(*p_tcb, p_reg->eatt_support);
  uint16_t payload_size = gatt_tcb_get_payload_size(*p_tcb, cid);
  BT_HDR* p_buf = attp_build_sr_msg(*p_tcb, GATT_HANDLE_VALUE_NOTIF, &gatt_sr_msg, payload_size);

  if (p_buf != NULL) {
    cmd_sent = attp_send_sr_msg(*p_tcb, cid, p_buf);
  } else {
    cmd_sent = GATT_NO_RESOURCES;
  }
  return cmd_sent;
}

/*******************************************************************************
 *
 * Function         GATTS_SendRsp
 *
 * Description      This function sends the server response to client.
 *
 * Parameter        conn_id: connection identifier.
 *                  trans_id: transaction id
 *                  status: response status
 *                  p_msg: pointer to message parameters structure.
 *
 * Returns          GATT_SUCCESS if successfully sent; otherwise error code.
 *
 ******************************************************************************/
tGATT_STATUS GATTS_SendRsp(tCONN_ID conn_id, uint32_t trans_id, tGATT_STATUS status,
                           tGATTS_RSP* p_msg) {
  tGATT_IF gatt_if = gatt_get_gatt_if(conn_id);
  uint8_t tcb_idx = gatt_get_tcb_idx(conn_id);
  tGATT_REG* p_reg = gatt_get_regcb(gatt_if);
  tGATT_TCB* p_tcb = gatt_get_tcb_by_idx(tcb_idx);

  log::verbose("conn_id=0x{:x}, trans_id=0x{:x}, status=0x{:x}", conn_id, trans_id,
               static_cast<uint8_t>(status));

  if ((p_reg == NULL) || (p_tcb == NULL)) {
    log::error("Unknown  conn_id=0x{:x}", conn_id);
    return GATT_ILLEGAL_PARAMETER;
  }

  tGATT_SR_CMD* sr_res_p = gatt_sr_get_cmd_by_trans_id(p_tcb, trans_id);

  if (!sr_res_p) {
    log::error("conn_id=0x{:x} waiting for other op_code", conn_id);
    return GATT_WRONG_STATE;
  }

  /* Process App response */
  return gatt_sr_process_app_rsp(*p_tcb, gatt_if, trans_id, sr_res_p->op_code, status, p_msg,
                                 sr_res_p);
}

/*******************************************************************************
 *
 * Function         GATTS_OffloadCharacteristics
 *
 * Description      This function is called to offload characteristics for GATT server.
 *
 * Parameter        conn_id         : connection ID.
 *                  service         : pointer array describing service and characteristics.
 *                  elements_count  : number of elements in the array.
 *                  endpoint_id     : ID of the hub end point.
 *                  hub_id          : ID of the hub to which the end point belongs.
 *                  uid             : UID of the app.
 *                  attribution_tag : attribution tag of the app.
 *                  promise         : object used to signal the completion status.
 *
 ******************************************************************************/
void GATTS_OffloadCharacteristics(tCONN_ID conn_id, btgatt_db_element_t* service,
                                  size_t elements_count, uint64_t endpoint_id, uint64_t hub_id,
                                  int uid, std::string attribution_tag,
                                  std::promise<btgatt_offload_result_t> promise) {
  gatt_offload_characteristics(conn_id, /* is_server */ true, service, elements_count, endpoint_id,
                               hub_id, uid, std::move(attribution_tag), std::move(promise));
}

/*******************************************************************************
 *
 * Function         GATTS_UnoffloadCharacteristics
 *
 * Description      This function is called to unoffload a session for GATT server.
 *
 * Parameter        conn_id         : connection ID.
 *                  session_id      : session ID.
 *
 ******************************************************************************/
void GATTS_UnoffloadCharacteristics(tCONN_ID conn_id, uint16_t session_id) {
  log::info("conn_id: {}, session_id: {}", conn_id, session_id);
  gatt_unoffload_session(conn_id, session_id);
}

std::optional<bluetooth::Uuid> GATTS_LookupServiceUuidByStartHandle(uint16_t start_handle) {
  auto end_it = gatt_cb.hdl_list_info->end();
  for (auto it = gatt_cb.hdl_list_info->begin(); it != end_it; ++it) {
    if (it->asgn_range.s_handle != start_handle) {
      continue;
    }
    return it->asgn_range.svc_uuid;
  }

  // No match found
  return std::nullopt;
}

/******************************************************************************/
/* GATT Profile Srvr Functions */
/******************************************************************************/

/******************************************************************************/
/*                                                                            */
/*                  GATT CLIENT APIs                                          */
/*                                                                            */
/******************************************************************************/

/*******************************************************************************
 *
 * Function         GATTC_ConfigureMTU
 *
 * Description      This function is called to configure the ATT MTU size.
 *
 * Parameters       conn_id: connection identifier.
 *                  mtu    - attribute MTU size..
 *
 * Returns          GATT_SUCCESS if command started successfully.
 *
 ******************************************************************************/
tGATT_STATUS GATTC_ConfigureMTU(tCONN_ID conn_id, uint16_t mtu) {
  tGATT_IF gatt_if = gatt_get_gatt_if(conn_id);
  uint8_t tcb_idx = gatt_get_tcb_idx(conn_id);
  tGATT_TCB* p_tcb = gatt_get_tcb_by_idx(tcb_idx);
  tGATT_REG* p_reg = gatt_get_regcb(gatt_if);

  if ((p_tcb == NULL) || (p_reg == NULL) || (mtu < GATT_DEF_BLE_MTU_SIZE) ||
      (mtu > GATT_MAX_MTU_SIZE)) {
    log::warn(
            "Unable to configure ATT mtu size illegal parameter conn_id:{} mtu:{} "
            "tcb:{} reg:{}",
            conn_id, mtu, (p_tcb == nullptr) ? "BAD" : "ok", (p_reg == nullptr) ? "BAD" : "ok");
    return GATT_ILLEGAL_PARAMETER;
  }

  /* Validate that the link is BLE, not BR/EDR */
  if (p_tcb->transport != BT_TRANSPORT_LE) {
    return GATT_REQ_NOT_SUPPORTED;
  }

  tGATT_CLCB* p_clcb = gatt_clcb_alloc(conn_id);
  if (!p_clcb) {
    log::warn("Unable to allocate connection link control block");
    return GATT_NO_RESOURCES;
  }

  /* For this request only ATT CID is valid */
  p_clcb->cid = L2CAP_ATT_CID;
  p_clcb->operation = GATTC_OPTYPE_CONFIG;
  tGATT_CL_MSG gatt_cl_msg;

  bluetooth::shim::arbiter::GetArbiter().OnOutgoingMtuReq(tcb_idx);

  /* Since GATT MTU Exchange can be done only once, and it is impossible to
   * predict what MTU will be requested by other applications, let's use
   * default MTU in the request. */
  gatt_cl_msg.mtu = gatt_get_local_mtu();

  log::info("Configuring ATT mtu size conn_id:{} mtu:{} user mtu {}", conn_id, gatt_cl_msg.mtu,
            mtu);

  auto result = attp_send_cl_msg(*p_clcb->p_tcb, p_clcb, GATT_REQ_MTU, &gatt_cl_msg);
  if (result == GATT_SUCCESS || result == GATT_CMD_STARTED) {
    p_clcb->p_tcb->pending_user_mtu_exchange_value = mtu;
  }
  return result;
}

/******************************************************************************
 *
 * Function         GATTC_TryMtuRequest
 *
 * Description      This function shall be called before calling
 *                  GATTC_ConfigureMTU in order to check if operation is
 *                  available to do.
 *
 * Parameters        remote_bda : peer device address. (input)
 *                   transport  : physical transport of the GATT connection
 *                                 (BR/EDR or LE) (input)
 *                   conn_id    : connection id  (input)
 *                   current_mtu: current mtu on the link (output)
 *
 * Returns          tGATTC_TryMtuRequestResult:
 *                  - MTU_EXCHANGE_NOT_DONE_YET: There was no MTU Exchange
 *                      procedure on the link. User can call GATTC_ConfigureMTU
 *                      now.
 *                  - MTU_EXCHANGE_NOT_ALLOWED : Not allowed for BR/EDR or if
 *                      link does not exist
 *                  - MTU_EXCHANGE_ALREADY_DONE: MTU Exchange is done. MTU
 *                      should be taken from current_mtu
 *                  - MTU_EXCHANGE_IN_PROGRESS : Other use is doing MTU
 *                      Exchange. Conn_id is stored for result.
 *
 ******************************************************************************/
tGATTC_TryMtuRequestResult GATTC_TryMtuRequest(const RawAddress& remote_bda,
                                               tBT_TRANSPORT transport, tCONN_ID conn_id,
                                               uint16_t* current_mtu) {
  log::info("{} conn_id=0x{:04x}", remote_bda, conn_id);
  *current_mtu = GATT_DEF_BLE_MTU_SIZE;

  if (transport == BT_TRANSPORT_BR_EDR) {
    log::error("Device {} connected over BR/EDR", remote_bda);
    return MTU_EXCHANGE_NOT_ALLOWED;
  }

  tGATT_TCB* p_tcb = gatt_find_tcb_by_addr(remote_bda, transport);
  if (!p_tcb) {
    log::error("Device {} is not connected", remote_bda);
    return MTU_EXCHANGE_DEVICE_DISCONNECTED;
  }

  if (gatt_is_pending_mtu_exchange(p_tcb)) {
    log::debug("Continue MTU pending for other client.");
    /* MTU Exchange is in progress, started by other GATT Client.
     * Wait until it is completed.
     */
    gatt_set_conn_id_waiting_for_mtu_exchange(p_tcb, conn_id);
    return MTU_EXCHANGE_IN_PROGRESS;
  }

  uint16_t mtu = gatt_get_mtu(remote_bda, transport);
  if (mtu == GATT_DEF_BLE_MTU_SIZE || mtu == 0) {
    log::debug("MTU not yet updated for {}", remote_bda);
    return MTU_EXCHANGE_NOT_DONE_YET;
  }

  *current_mtu = mtu;
  return MTU_EXCHANGE_ALREADY_DONE;
}

/*******************************************************************************
 * Function         GATTC_UpdateUserAttMtuIfNeeded
 *
 * Description      This function to be called when user requested MTU after
 *                  MTU Exchange has been already done. This will update data
 *                  length in the controller.
 *
 * Parameters        remote_bda : peer device address. (input)
 *                   transport  : physical transport of the GATT connection
 *                                 (BR/EDR or LE) (input)
 *                   user_mtu: user request mtu
 *
 ******************************************************************************/
void GATTC_UpdateUserAttMtuIfNeeded(const RawAddress& remote_bda, tBT_TRANSPORT transport,
                                    uint16_t user_mtu) {
  log::info("{}, mtu={}", remote_bda, user_mtu);
  tGATT_TCB* p_tcb = gatt_find_tcb_by_addr(remote_bda, transport);
  if (!p_tcb) {
    log::warn("Transport control block not found");
    return;
  }

  log::info("{}, current mtu: {}, max_user_mtu:{}, user_mtu: {}", remote_bda, p_tcb->payload_size,
            p_tcb->max_user_mtu, user_mtu);

  if (p_tcb->payload_size < user_mtu) {
    log::info("User requested more than what GATT can handle. Trim it.");
    user_mtu = p_tcb->payload_size;
  }

  if (p_tcb->max_user_mtu >= user_mtu) {
    return;
  }

  p_tcb->max_user_mtu = user_mtu;
  if (get_btm_client_interface().ble.BTM_SetBleDataLength(
              remote_bda, user_mtu, /*is_privileged_client*/ false) != tBTM_STATUS::BTM_SUCCESS) {
    log::warn("Unable to set ble data length peer:{} mtu:{}", remote_bda, user_mtu);
  }
}

std::list<tCONN_ID> GATTC_GetAndRemoveListOfConnIdsWaitingForMtuRequest(
        const RawAddress& remote_bda) {
  std::list result = std::list<tCONN_ID>();

  tGATT_TCB* p_tcb = gatt_find_tcb_by_addr(remote_bda, BT_TRANSPORT_LE);
  if (!p_tcb || p_tcb->conn_ids_waiting_for_mtu_exchange.empty()) {
    return result;
  }

  result.swap(p_tcb->conn_ids_waiting_for_mtu_exchange);
  return result;
}

/*******************************************************************************
 *
 * Function         GATTC_Discover
 *
 * Description      This function is called to do a discovery procedure on ATT
 *                  server.
 *
 * Parameters       conn_id: connection identifier.
 *                  disc_type:discovery type.
 *                  start_handle and end_handle: range of handles for discovery
 *                  uuid: uuid to discovery. set to Uuid::kEmpty for requests
 *                        that don't need it
 *
 * Returns          GATT_SUCCESS if command received/sent successfully.
 *
 ******************************************************************************/
tGATT_STATUS GATTC_Discover(tCONN_ID conn_id, tGATT_DISC_TYPE disc_type, uint16_t start_handle,
                            uint16_t end_handle, const Uuid& uuid) {
  tGATT_IF gatt_if = gatt_get_gatt_if(conn_id);
  uint8_t tcb_idx = gatt_get_tcb_idx(conn_id);
  tGATT_TCB* p_tcb = gatt_get_tcb_by_idx(tcb_idx);
  tGATT_REG* p_reg = gatt_get_regcb(gatt_if);

  if ((p_tcb == NULL) || (p_reg == NULL) || (disc_type >= GATT_DISC_MAX)) {
    log::error("Illegal param: disc_type={} conn_id=0x{:x}", disc_type, conn_id);
    return GATT_ILLEGAL_PARAMETER;
  }

  if (!GATT_HANDLE_IS_VALID(start_handle) || !GATT_HANDLE_IS_VALID(end_handle) ||
      /* search by type does not have a valid UUID param */
      (disc_type == GATT_DISC_SRVC_BY_UUID && uuid.IsEmpty())) {
    log::warn(
            "Illegal parameter conn_id=0x{:x}, disc_type={}, s_handle=0x{:x}, "
            "e_handle=0x{:x}",
            conn_id, disc_type, start_handle, end_handle);
    return GATT_ILLEGAL_PARAMETER;
  }

  tGATT_CLCB* p_clcb = gatt_clcb_alloc(conn_id);
  if (!p_clcb) {
    log::warn(
            "No resources conn_id=0x{:x}, disc_type={}, s_handle=0x{:x}, "
            "e_handle=0x{:x}",
            conn_id, disc_type, start_handle, end_handle);
    return GATT_NO_RESOURCES;
  }

  p_clcb->operation = GATTC_OPTYPE_DISCOVERY;
  p_clcb->op_subtype = disc_type;
  p_clcb->s_handle = start_handle;
  p_clcb->e_handle = end_handle;
  p_clcb->uuid = uuid;

  log::info("conn_id=0x{:x}, disc_type={}, s_handle=0x{:x}, e_handle=0x{:x}", conn_id, disc_type,
            start_handle, end_handle);

  gatt_act_discovery(p_clcb);
  return GATT_SUCCESS;
}

tGATT_STATUS GATTC_Discover(tCONN_ID conn_id, tGATT_DISC_TYPE disc_type, uint16_t start_handle,
                            uint16_t end_handle) {
  return GATTC_Discover(conn_id, disc_type, start_handle, end_handle, Uuid::kEmpty);
}

/*******************************************************************************
 *
 * Function         GATTC_Read
 *
 * Description      This function is called to read the value of an attribute
 *                  from the server.
 *
 * Parameters       conn_id: connection identifier.
 *                  type    - attribute read type.
 *                  p_read  - read operation parameters.
 *
 * Returns          GATT_SUCCESS if command started successfully.
 *
 ******************************************************************************/
tGATT_STATUS GATTC_Read(tCONN_ID conn_id, tGATT_READ_TYPE type, tGATT_READ_PARAM* p_read) {
  tGATT_IF gatt_if = gatt_get_gatt_if(conn_id);
  uint8_t tcb_idx = gatt_get_tcb_idx(conn_id);
  tGATT_TCB* p_tcb = gatt_get_tcb_by_idx(tcb_idx);
  tGATT_REG* p_reg = gatt_get_regcb(gatt_if);
#if (GATT_UPPER_TESTER_MULT_VARIABLE_LENGTH_READ == TRUE)
  static uint16_t cached_read_handle;
  static int cached_tcb_idx = -1;
#endif

  log::verbose("conn_id=0x{:x}, type=0x{:x}", conn_id, type);

  if ((p_tcb == NULL) || (p_reg == NULL) || (p_read == NULL) ||
      ((type >= GATT_READ_MAX) || (type == 0))) {
    log::error("illegal param: conn_id=0x{:x}, type=0x{:x}", conn_id, type);
    return GATT_ILLEGAL_PARAMETER;
  }

  tGATT_CLCB* p_clcb = gatt_clcb_alloc(conn_id);
  if (!p_clcb) {
    return GATT_NO_RESOURCES;
  }

  p_clcb->operation = GATTC_OPTYPE_READ;
  p_clcb->op_subtype = type;
  p_clcb->auth_req = p_read->by_handle.auth_req;
  p_clcb->counter = 0;
  p_clcb->read_req_current_mtu = gatt_tcb_get_payload_size(*p_tcb, p_clcb->cid);

  switch (type) {
    case GATT_READ_BY_TYPE:
    case GATT_READ_CHAR_VALUE:
      p_clcb->s_handle = p_read->service.s_handle;
      p_clcb->e_handle = p_read->service.e_handle;
      p_clcb->uuid = p_read->service.uuid;
      break;
    case GATT_READ_MULTIPLE:
    case GATT_READ_MULTIPLE_VAR_LEN: {
      p_clcb->s_handle = 0;
      /* copy multiple handles in CB */
      tGATT_READ_MULTI* p_read_multi = (tGATT_READ_MULTI*)osi_malloc(sizeof(tGATT_READ_MULTI));
      if (!p_read_multi) {
        log::error("Unable to allocate read multiple buffer");
        return GATT_NO_RESOURCES;
      }
      p_clcb->p_attr_buf = (uint8_t*)p_read_multi;
      memcpy(p_read_multi, &p_read->read_multiple, sizeof(tGATT_READ_MULTI));
      break;
    }
    case GATT_READ_BY_HANDLE:
#if (GATT_UPPER_TESTER_MULT_VARIABLE_LENGTH_READ == TRUE)
      log::info("Upper tester: Handle read 0x{:04x}", p_read->by_handle.handle);
      /* This is upper tester for the  Multi Read stuff as this is mandatory for
       * EATT, even Android is not making use of this operation :/ */
      if (cached_tcb_idx < 0) {
        cached_tcb_idx = tcb_idx;
        log::info("Upper tester: Read multiple  - first read");
        cached_read_handle = p_read->by_handle.handle;
      } else if (cached_tcb_idx == tcb_idx) {
        log::info("Upper tester: Read multiple  - second read");
        cached_tcb_idx = -1;
        tGATT_READ_MULTI* p_read_multi = (tGATT_READ_MULTI*)osi_malloc(sizeof(tGATT_READ_MULTI));
        p_read_multi->num_handles = 2;
        p_read_multi->handles[0] = cached_read_handle;
        p_read_multi->handles[1] = p_read->by_handle.handle;
        p_read_multi->variable_len = true;

        p_clcb->s_handle = 0;
        p_clcb->op_subtype = GATT_READ_MULTIPLE_VAR_LEN;
        p_clcb->p_attr_buf = (uint8_t*)p_read_multi;
        p_clcb->cid = gatt_tcb_get_att_cid(*p_tcb, true /* eatt support */);

        break;
      }

      FALLTHROUGH_INTENDED;
#endif
    case GATT_READ_PARTIAL:
      p_clcb->uuid = Uuid::kEmpty;
      p_clcb->s_handle = p_read->by_handle.handle;

      if (type == GATT_READ_PARTIAL) {
        p_clcb->counter = p_read->partial.offset;
      }

      break;
    default:
      break;
  }

  /* start security check */
  if (gatt_security_check_start(p_clcb)) {
    p_tcb->pending_enc_clcb.push_back(p_clcb);
  }
  return GATT_SUCCESS;
}

/*******************************************************************************
 *
 * Function         GATTC_Write
 *
 * Description      This function is called to write the value of an attribute
 *                  to the server.
 *
 * Parameters       conn_id: connection identifier.
 *                  type    - attribute write type.
 *                  p_write  - write operation parameters.
 *
 * Returns          GATT_SUCCESS if command started successfully.
 *
 ******************************************************************************/
tGATT_STATUS GATTC_Write(tCONN_ID conn_id, tGATT_WRITE_TYPE type, tGATT_VALUE* p_write) {
  tGATT_IF gatt_if = gatt_get_gatt_if(conn_id);
  uint8_t tcb_idx = gatt_get_tcb_idx(conn_id);
  tGATT_TCB* p_tcb = gatt_get_tcb_by_idx(tcb_idx);
  tGATT_REG* p_reg = gatt_get_regcb(gatt_if);

  if ((p_tcb == NULL) || (p_reg == NULL) || (p_write == NULL) ||
      ((type != GATT_WRITE) && (type != GATT_WRITE_PREPARE) && (type != GATT_WRITE_NO_RSP))) {
    log::error("Illegal param: conn_id=0x{:x}, type=0x{:x}", conn_id, type);
    return GATT_ILLEGAL_PARAMETER;
  }

  tGATT_CLCB* p_clcb = gatt_clcb_alloc(conn_id);
  if (!p_clcb) {
    return GATT_NO_RESOURCES;
  }

  p_clcb->operation = GATTC_OPTYPE_WRITE;
  p_clcb->op_subtype = type;
  p_clcb->auth_req = p_write->auth_req;

  p_clcb->p_attr_buf = (uint8_t*)osi_malloc(sizeof(tGATT_VALUE));
  memcpy(p_clcb->p_attr_buf, (void*)p_write, sizeof(tGATT_VALUE));

  tGATT_VALUE* p = (tGATT_VALUE*)p_clcb->p_attr_buf;
  if (type == GATT_WRITE_PREPARE) {
    p_clcb->start_offset = p_write->offset;
    p->offset = 0;
  }

  if (gatt_security_check_start(p_clcb)) {
    p_tcb->pending_enc_clcb.push_back(p_clcb);
  }
  return GATT_SUCCESS;
}

/*******************************************************************************
 *
 * Function         GATTC_ExecuteWrite
 *
 * Description      This function is called to send an Execute write request to
 *                  the server.
 *
 * Parameters       conn_id: connection identifier.
 *                  is_execute - to execute or cancel the prepared write
 *                               request(s)
 *
 * Returns          GATT_SUCCESS if command started successfully.
 *
 ******************************************************************************/
tGATT_STATUS GATTC_ExecuteWrite(tCONN_ID conn_id, bool is_execute) {
  tGATT_IF gatt_if = gatt_get_gatt_if(conn_id);
  uint8_t tcb_idx = gatt_get_tcb_idx(conn_id);
  tGATT_TCB* p_tcb = gatt_get_tcb_by_idx(tcb_idx);
  tGATT_REG* p_reg = gatt_get_regcb(gatt_if);

  log::verbose("conn_id=0x{:x}, is_execute={}", conn_id, is_execute);

  if ((p_tcb == NULL) || (p_reg == NULL)) {
    log::error("Illegal param: conn_id=0x{:x}", conn_id);
    return GATT_ILLEGAL_PARAMETER;
  }

  tGATT_CLCB* p_clcb = gatt_clcb_alloc(conn_id);
  if (!p_clcb) {
    return GATT_NO_RESOURCES;
  }

  p_clcb->operation = GATTC_OPTYPE_EXE_WRITE;
  tGATT_EXEC_FLAG flag = is_execute ? GATT_PREP_WRITE_EXEC : GATT_PREP_WRITE_CANCEL;
  gatt_send_queue_write_cancel(*p_clcb->p_tcb, p_clcb, flag);
  return GATT_SUCCESS;
}

/*******************************************************************************
 *
 * Function         GATTC_SendHandleValueConfirm
 *
 * Description      This function is called to send a handle value confirmation
 *                  as response to a handle value notification from server.
 *
 * Parameters       conn_id: connection identifier.
 *                  cid: channel id.
 *
 * Returns          GATT_SUCCESS if command started successfully.
 *
 ******************************************************************************/
tGATT_STATUS GATTC_SendHandleValueConfirm(tCONN_ID conn_id, uint16_t cid) {
  log::info("conn_id=0x{:04x} , cid=0x{:04x}", conn_id, cid);

  tGATT_TCB* p_tcb = gatt_get_tcb_by_idx(gatt_get_tcb_idx(conn_id));
  if (!p_tcb) {
    log::error("Unknown conn_id=0x{:x}", conn_id);
    return GATT_ILLEGAL_PARAMETER;
  }

  if (p_tcb->ind_count == 0) {
    log::info("conn_id: 0x{:04x} ignored not waiting for indication ack", conn_id);
    return GATT_SUCCESS;
  }

  log::info("Received confirmation, ind_count= {}, sending confirmation", p_tcb->ind_count);

  /* Just wait for first confirmation.*/
  p_tcb->ind_count = 0;
  gatt_stop_ind_ack_timer(p_tcb, cid);

  /* send confirmation now */
  return attp_send_cl_confirmation_msg(*p_tcb, cid);
}

/*******************************************************************************
 *
 * Function         GATTC_OffloadCharacteristics
 *
 * Description      This function is called to offload characteristics for GATT client.
 *
 * Parameter        conn_id         : connection ID.
 *                  service         : pointer array describing service and characteristics.
 *                  elements_count  : number of elements in the service array.
 *                  endpoint_id     : ID of the hub end point.
 *                  hub_id          : ID of the hub to which the end point belongs.
 *                  uid             : UID of the app.
 *                  attribution_tag : attribution tag of the app.
 *                  promise         : object used to signal the completion status.
 *
 ******************************************************************************/
void GATTC_OffloadCharacteristics(tCONN_ID conn_id, btgatt_db_element_t* service,
                                  size_t elements_count, uint64_t endpoint_id, uint64_t hub_id,
                                  int uid, std::string attribution_tag,
                                  std::promise<btgatt_offload_result_t> promise) {
  gatt_offload_characteristics(conn_id, /* is_server */ false, service, elements_count, endpoint_id,
                               hub_id, uid, std::move(attribution_tag), std::move(promise));
}

/*******************************************************************************
 *
 * Function         GATTC_UnoffloadCharacteristics
 *
 * Description      This function is called to unoffload characteristics for GATT client.
 *
 * Parameter        conn_id         : connection ID.
 *                  session_id      : session ID.
 *
 ******************************************************************************/
void GATTC_UnoffloadCharacteristics(tCONN_ID conn_id, uint16_t session_id) {
  log::info("conn_id: {}, session_id: {}", conn_id, session_id);
  gatt_unoffload_session(conn_id, session_id);
}

/*******************************************************************************
 *
 * Function         GATTC_InformNotificationHandle
 *
 * Description      This function is called to inform the registered notification handle for GATT
 *client.
 *
 * Parameter        remote_bda    : peer device address. (input)
 *                  handle        : notification handle
 *
 ******************************************************************************/
void GATTC_InformNotificationHandle(const RawAddress& remote_bda, uint16_t handle) {
  tGATT_TCB* p_tcb = gatt_find_tcb_by_addr(remote_bda, BT_TRANSPORT_LE);
  if (!p_tcb) {
    log::info("Unknown remote_bda: {}", remote_bda);
    return;
  }
  gattc_inform_notification_handle(p_tcb, handle);
}

/*******************************************************************************
 *
 * Function         GATTC_InformServiceChangedIndication
 *
 * Description      This function is called to inform the service changed indication for GATT
 *client.
 *
 * Parameter        remote_bda    : peer device address. (input)
 *
 ******************************************************************************/
void GATTC_InformServiceChangedIndication(const RawAddress& remote_bda) {
  tGATT_TCB* p_tcb = gatt_find_tcb_by_addr(remote_bda, BT_TRANSPORT_LE);
  if (!p_tcb) {
    log::info("Unknown remote_bda: {}", remote_bda);
    return;
  }
  gattc_offload_handle_service_changed_indication(p_tcb);
}

/*******************************************************************************
 *
 * Function         GATTC_SetDefaultMtu
 *
 * Description      Set the default MTU for ATT bearer associated with remote device.
 *
 * Parameter        remote_bda    : peer device address. (input)
 *
 ******************************************************************************/
void GATTC_SetDefaultMtu(const RawAddress& remote_bda) {
  tGATT_TCB* p_tcb = gatt_find_tcb_by_addr(remote_bda, BT_TRANSPORT_LE);
  if (!p_tcb) {
    log::info("Unknown remote_bda: {}", remote_bda);
    return;
  }

  for (auto& [i, p_reg] : gatt_cb.cl_rcb_map) {
    if (!p_reg->in_use) {
      continue;
    }
    auto mtu_pref = p_reg->auto_mtu_enabled.find(remote_bda);
    if (mtu_pref != p_reg->auto_mtu_enabled.cend() && mtu_pref->second) {
      tCONN_ID conn_id = gatt_create_conn_id(p_tcb->tcb_idx, p_reg->gatt_if);
      tGATT_STATUS status = GATTC_ConfigureMTU(conn_id, gatt_get_local_mtu());
      log::verbose("set default MTU for the app: {}, status: {}", p_reg->gatt_if, status);
      break;
    }
  }
}

/******************************************************************************/
/*                                                                            */
/*                  GATT  APIs                                                */
/*                                                                            */
/******************************************************************************/

/*******************************************************************************
 *
 * Function         GATT_BR_Connect
 *
 * Description      This function initiate a connection to a remote device on
 *                  GATT channel.
 *
 * Parameters       gatt_if: application interface
 *                  bd_addr: peer device address.
 *
 * Returns          true if connection started; false if connection start
 *                  failure.
 *
 ******************************************************************************/
bool GATT_BR_Connect(tGATT_IF gatt_if, const RawAddress& bd_addr) {
  /* Make sure app is registered */
  tGATT_REG* p_reg = gatt_get_regcb(gatt_if);
  if (!p_reg) {
    log::error("Unable to find registered app gatt_if={}", gatt_if);
    return false;
  }

  if (bd_addr == RawAddress::kEmpty) {
    log::error("Unsupported empty address, gatt_if={}", gatt_if);
    return false;
  }

  tGATT_TCB* p_tcb = gatt_find_tcb_by_addr(bd_addr, BT_TRANSPORT_BR_EDR);
  if (p_tcb != NULL) {
    uint8_t st = gatt_get_ch_state(p_tcb);
    if (st == GATT_CH_CLOSING) {
      log::info("Must finish disconnection before new connection");
      /* need to complete the closing first */
      return false;
    }
    log::debug("Already connected, reusing BR/EDR gatt_if={} address={}", gatt_if, bd_addr);
    gatt_update_app_use_link_flag(p_reg->gatt_if, p_tcb, true, false);
    return true;
  }

  log::debug("Starting BR/EDR connection gatt_if={} address={}", gatt_if, bd_addr);
  p_tcb = gatt_allocate_tcb_by_bdaddr(bd_addr, BT_TRANSPORT_BR_EDR);
  if (!p_tcb) {
    log::error("Max TCB for gatt_if [ {}] reached.", p_reg->gatt_if);
    return false;
  }

  gatt_set_ch_state(p_tcb, GATT_CH_CONN);
  p_tcb->att_lcid = stack::l2cap::get_interface().L2CA_ConnectReqWithSecurity(BT_PSM_ATT, bd_addr,
                                                                              BTM_SEC_NONE);
  if (p_tcb->att_lcid == 0) {
    log::error("gatt_connect failed");
    alarm_free(p_tcb->conf_timer);
    alarm_free(p_tcb->ind_ack_timer);
    *p_tcb = tGATT_TCB();
    return false;
  }

  gatt_update_app_use_link_flag(p_reg->gatt_if, p_tcb, true, false);
  return true;
}

/*******************************************************************************
 *
 * Function         GATT_Disconnect
 *
 * Description      This function disconnects the GATT channel for this
 *                  registered application.
 *
 * Parameters       conn_id: connection identifier.
 *
 * Returns          GATT_SUCCESS if disconnected.
 *
 ******************************************************************************/
tGATT_STATUS GATT_Disconnect(tCONN_ID conn_id) {
  uint8_t tcb_idx = gatt_get_tcb_idx(conn_id);
  tGATT_TCB* p_tcb = gatt_get_tcb_by_idx(tcb_idx);
  if (!p_tcb) {
    log::warn("Cannot find TCB for connection {}", conn_id);
    return GATT_ILLEGAL_PARAMETER;
  }

  tGATT_IF gatt_if = gatt_get_gatt_if(conn_id);

  log::info("gatt_if={}, remote_bda={}, transport={}", gatt_if, p_tcb->peer_bda, p_tcb->transport);

  gatt_update_app_use_link_flag(gatt_if, p_tcb, false, true);

  if (p_tcb->transport == BT_TRANSPORT_LE && p_tcb->app_hold_link.empty()) {
    bluetooth::metrics::LogMetricLeConnectionLifecycle(p_tcb->peer_bda, false /* is_connect */,
                                                       false /* is_direct */);
  }
  return GATT_SUCCESS;
}

/*******************************************************************************
 *
 * Function         GATT_GetConnectionInfor
 *
 * Description      This function uses conn_id to find its associated BD address
 *                  and application interface
 *
 * Parameters        conn_id: connection id  (input)
 *                   p_gatt_if: application interface (output)
 *                   bd_addr: peer device address. (output)
 *
 * Returns          true the logical link information is found for conn_id
 *
 ******************************************************************************/
bool GATT_GetConnectionInfor(tCONN_ID conn_id, tGATT_IF* p_gatt_if, RawAddress& bd_addr,
                             tBT_TRANSPORT* p_transport) {
  tGATT_IF gatt_if = gatt_get_gatt_if(conn_id);
  tGATT_REG* p_reg = gatt_get_regcb(gatt_if);
  uint8_t tcb_idx = gatt_get_tcb_idx(conn_id);
  tGATT_TCB* p_tcb = gatt_get_tcb_by_idx(tcb_idx);

  log::verbose("conn_id=0x{:x}", conn_id);

  if (!p_tcb || !p_reg) {
    return false;
  }

  bd_addr = p_tcb->peer_bda;
  *p_gatt_if = gatt_if;
  *p_transport = p_tcb->transport;
  return true;
}

/*******************************************************************************
 *
 * Function         GATT_GetConnIdIfConnected
 *
 * Description      This function finds the conn_id if the logical link for BD
 *                  address and application interface is connected
 *
 * Parameters        gatt_if: application interface (input)
 *                   bd_addr: peer device address. (input)
 *                   p_conn_id: connection id  (output)
 *                   transport: transport option
 *
 * Returns          true the logical link is connected
 *
 ******************************************************************************/
bool GATT_GetConnIdIfConnected(tGATT_IF gatt_if, const RawAddress& bd_addr, tCONN_ID* p_conn_id,
                               tBT_TRANSPORT transport) {
  tGATT_REG* p_reg = gatt_get_regcb(gatt_if);
  tGATT_TCB* p_tcb = gatt_find_tcb_by_addr(bd_addr, transport);
  bool status = false;

  if (p_reg && p_tcb && (gatt_get_ch_state(p_tcb) == GATT_CH_OPEN)) {
    *p_conn_id = gatt_create_conn_id(p_tcb->tcb_idx, gatt_if);
    status = true;
  }

  log::debug("status={}", status);
  return status;
}

static void gatt_bonded_check_add_address(const RawAddress& bda) {
  if (!gatt_is_bda_in_the_srv_chg_clt_list(bda)) {
    gatt_add_a_bonded_dev_for_srv_chg(bda);
  }
}

namespace bluetooth::legacy::testing {
std::optional<bool> OVERRIDE_GATT_LOAD_BONDED = std::nullopt;
}  // namespace bluetooth::legacy::testing

static bool gatt_load_bonded_is_enabled() {
  static const bool sGATT_LOAD_BONDED =
          bluetooth::os::GetSystemPropertyBool("bluetooth.gatt.load_bonded.enabled", false);
  if (bluetooth::legacy::testing::OVERRIDE_GATT_LOAD_BONDED.has_value()) {
    return bluetooth::legacy::testing::OVERRIDE_GATT_LOAD_BONDED.value();
  }
  return sGATT_LOAD_BONDED;
}

/* Initialize GATTS list of bonded device service change updates.
 *
 * Addresses for bonded devices (public for BR/EDR or pseudo for BLE) are added
 * to GATTS service change control list so that updates are sent to bonded
 * devices on next connect after any handles for GATTS services change due to
 * services added/removed.
 */
void gatt_load_bonded(void) {
  const bool load_bonded = gatt_load_bonded_is_enabled();
  log::info("load bonded: {}", load_bonded ? "True" : "False");
  if (!load_bonded) {
    return;
  }
  for (BtmDevice* p_device : btm_get_sec_dev_rec()) {
    if (p_device->sec_rec.is_link_key_known()) {
      log::verbose("Add bonded BR/EDR transport {}", p_device->bd_addr);
      gatt_bonded_check_add_address(p_device->bd_addr);
    }
    if (p_device->sec_rec.is_le_link_key_known()) {
      log::verbose("Add bonded BLE {}", p_device->ble.pseudo_addr);
      gatt_bonded_check_add_address(p_device->ble.pseudo_addr);
    }
  }
}
