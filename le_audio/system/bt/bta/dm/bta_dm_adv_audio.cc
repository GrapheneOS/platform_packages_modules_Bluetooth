/******************************************************************************
 *  Copyright (c) 2020, The Linux Foundation. All rights reserved.
 *
 *****************************************************************************/

#define LOG_TAG "bt_bta_dm_adv_audio"

#include <base/bind.h>
#include <base/callback.h>
#include <base/logging.h>
#include <string.h>

#include "bt_common.h"
#include "bt_target.h"
#include "bt_types.h"
#include "bta_api.h"
#include "bta_dm_api.h"
#include "bta_dm_co.h"
#include "bta/dm/bta_dm_int.h"
#include "bta_csip_api.h"
#include "bta_sys.h"
#include "btif/include/btif_storage.h"
#include "btm_api.h"
#include "btm_int.h"
#include "btu.h"
#include "gap_api.h" /* For GAP_BleReadPeerPrefConnParams */
#include "l2c_api.h"
#include "osi/include/log.h"
#include "osi/include/osi.h"
#include "sdp_api.h"
#include "bta_sdp_api.h"
#include "stack/gatt/connection_manager.h"
#include "stack/include/gatt_api.h"
#include "utl.h"
#include "device/include/interop_config.h"
#include "device/include/profile_config.h"
#include "device/include/interop.h"
#include "stack/sdp/sdpint.h"
#include <inttypes.h>
#include "btif/include/btif_config.h"
#include "device/include/device_iot_config.h"
#include <btcommon_interface_defs.h>
#include <controller.h>
#include "bta_gatt_queue.h"
#include "bta_dm_adv_audio.h"
#include "btif/include/btif_dm_adv_audio.h"

#if (GAP_INCLUDED == TRUE)
#include "gap_api.h"
#endif

using bluetooth::Uuid;

#define ADV_AUDIO_VOICE_ROLE_BIT 2
#define ADV_AUDIO_MEDIA_ROLE_BIT 8
#define CONN_LESS_MEDIA_SINK_ROLE_BIT 32
#define CONN_LESS_ASSIST_ROLE_BIT 64
#define CONN_LESS_DELEGATE_ROLE_BIT 128
#define PACS_CT_SUPPORT_VALUE 2
#define PACS_UMR_SUPPORT_VALUE 4
#define PACS_CONVERSATIONAL_ROLE_VALUE 2
#define PACS_MEDIA_ROLE_VALUE 4

#define BTA_DM_ADV_AUDIO_GATT_CLOSE_DELAY_TOUT 5000

Uuid UUID_SERVCLASS_WMCP = Uuid::FromString
                             ("2587db3c-ce70-4fc9-935f-777ab4188fd7");

std::vector<bluetooth::Uuid> uuid_srv_disc_search;
tBTA_LE_AUDIO_DEV_CB bta_le_audio_dev_cb;
tBTA_LEA_PAIRING_DB bta_lea_pairing_cb;
extern void bta_dm_proc_open_evt(tBTA_GATTC_OPEN* p_data);
bool is_adv_audio_unicast_supported(RawAddress rem_bda, int conn_id);


/***************************************************************************
 *
 * Function         bta_get_lea_ctrl_cb
 *
 * Description      Gets the control block of LE audio device
 *
 * Parameters:      tBTA_LE_AUDIO_DEV_INFO*
 *
 ****************************************************************************/

tBTA_LE_AUDIO_DEV_INFO* bta_get_lea_ctrl_cb(RawAddress peer_addr) {
  tBTA_LE_AUDIO_DEV_INFO *p_lea_cb = NULL;
  p_lea_cb = &bta_le_audio_dev_cb.bta_lea_dev_info[0];

  for (int i = 0; i < MAX_LEA_DEVICES ; i++) {
      if (p_lea_cb[i].in_use &&
        (p_lea_cb[i].peer_address == peer_addr)) {
        APPL_TRACE_DEBUG(" %s Control block Found for addr %s",
          __func__, peer_addr.ToString().c_str());
        return &p_lea_cb[i];
      }
  }
  APPL_TRACE_DEBUG(" %s Control block Not Found for addr %s",
          __func__, peer_addr.ToString().c_str());
  return NULL;
}

/* Callback received when remote device Coordinated Sets SIRK is read */
void bta_gap_gatt_read_cb(uint16_t conn_id, tGATT_STATUS status,
                  uint16_t handle, uint16_t len,
                  uint8_t* value, void* data) {

  tBTA_LE_AUDIO_DEV_INFO *p_lea_cb =
    bta_get_lea_ctrl_cb(bta_le_audio_dev_cb.gatt_op_addr);
  uint32_t role = 0;
  uint8_t *p_val = value;

  STREAM_TO_ARRAY(&role, p_val, len);

  if (p_lea_cb) {
    APPL_TRACE_DEBUG("%s Addr %s ", __func__,
      p_lea_cb->peer_address.ToString().c_str());
    if (status == GATT_SUCCESS) {
      if (p_lea_cb->t_role_handle == handle) {
        LOG(INFO) << __func__ << " Role derived by T_ADV_AUDIO "
          << +role;
        if (role != 0)  {
          if (role & ADV_AUDIO_VOICE_ROLE_BIT)
            p_lea_cb->uuids.push_back(Uuid::From16Bit
                (UUID_SERVCLASS_T_ADV_AUDIO_VOICE));
          if (role & ADV_AUDIO_MEDIA_ROLE_BIT)
            p_lea_cb->uuids.push_back(Uuid::From16Bit
                (UUID_SERVCLASS_T_ADV_AUDIO_MEDIA_SINK));
          if (role & CONN_LESS_MEDIA_SINK_ROLE_BIT)
            p_lea_cb->uuids.push_back(Uuid::From16Bit
                (UUID_SERVCLASS_T_ADV_AUDIO_CONN_LESS_MEDIA_SINK));
          if (role & CONN_LESS_ASSIST_ROLE_BIT)
            p_lea_cb->uuids.push_back(Uuid::From16Bit
                (UUID_SERVCLASS_T_ADV_AUDIO_ASSIST));
          if (role & CONN_LESS_DELEGATE_ROLE_BIT)
            p_lea_cb->uuids.push_back(Uuid::From16Bit
                (UUID_SERVCLASS_T_ADV_AUDIO_DELEGATE));
        }
        p_lea_cb->disc_progress--;
      } else if(handle == p_lea_cb->pacs_char_handle) {
        LOG(INFO) << __func__ << " derived by PACS " << +role;
        if (role == 0) {
          LOG(INFO) << __func__ << " Invalid Information ";
        } else {
          if (is_adv_audio_unicast_supported(bta_le_audio_dev_cb.gatt_op_addr, conn_id)) {
            LOG(INFO) << __func__ << " ASCS Supported by the remote ";
            if ((role & PACS_CONVERSATIONAL_ROLE_VALUE) == PACS_CT_SUPPORT_VALUE)
              p_lea_cb->uuids.push_back(Uuid::From16Bit(UUID_SERVCLASS_PACS_CT_SUPPORT));
            if ((role & PACS_MEDIA_ROLE_VALUE) == PACS_UMR_SUPPORT_VALUE)
              p_lea_cb->uuids.push_back(Uuid::From16Bit(UUID_SERVCLASS_PACS_UMR_SUPPORT));
          }
          //TODO LEA_DBG Call API which will be provided by BAP
        }
        p_lea_cb->disc_progress--;
      } else {
        LOG(INFO) << __func__ << " Invalid Handle for LE AUDIO";
      }
    } else {
      p_lea_cb->disc_progress--;
      LOG(INFO) << __func__ << " GATT READ FAILED" ;
    }

    if (p_lea_cb->disc_progress <= 0) {
      bta_dm_lea_disc_complete(p_lea_cb->peer_address);
    }
  } else {
    LOG(INFO) << __func__ << " INVALID CONTROL BLOCK" ;
  }

}


/*******************************************************************************
 *
 * Function         bta_get_adv_audio_role
 *
 * Description      This API gets role for LE Audio Device after all services
 *                  discovered
 *
 * Parameters:      none
 *
 ******************************************************************************/
void bta_get_adv_audio_role(RawAddress peer_address, uint16_t conn_id,
                                  tGATT_STATUS status) {
  tBTA_LE_AUDIO_DEV_INFO *p_lea_cb = bta_get_lea_ctrl_cb(peer_address);

  bta_le_audio_dev_cb.gatt_op_addr = peer_address;

  if (p_lea_cb == NULL) {
    APPL_TRACE_ERROR(" %s Control block didnt find for peer address %s", __func__,
        peer_address.ToString().c_str());
    return;
  }

  // Fetch remote device gatt services from database
  const std::vector<gatt::Service>* services = BTA_GATTC_GetServices(conn_id);

  if (services) {
    APPL_TRACE_DEBUG(" bta_get_adv_audio_role SIZE %d addr %s conn_id %d",
      (*services).size(),bta_le_audio_dev_cb.gatt_op_addr.ToString().c_str(),
      conn_id);

    // Search for CSIS service in the database
    for (const gatt::Service& service : *services) {
      APPL_TRACE_DEBUG("%s: SERVICES IN REMOTE DEVICE %s ", __func__,
              service.uuid.ToString().c_str())
      if (is_le_audio_service(service.uuid)) {
        size_t len = service.uuid.GetShortestRepresentationSize();
        uint16_t uuid_val = 0;
        if (len == Uuid::kNumBytes16) {
          uuid_val = service.uuid.As16Bit();
        } else if(len == Uuid::kNumBytes128) {
          if (service.uuid == UUID_SERVCLASS_WMCP) {
            APPL_TRACE_DEBUG("%s: WMCP Service UUId found", __func__);
            std::vector<bluetooth::Uuid>::iterator itr;
            itr = std::find(p_lea_cb->uuids.begin(), p_lea_cb->uuids.end(),
                UUID_SERVCLASS_WMCP);
            if (itr == p_lea_cb->uuids.end()) {
              p_lea_cb->uuids.push_back(UUID_SERVCLASS_WMCP);
            }
          }
        }

        switch (uuid_val) {
          case UUID_SERVCLASS_CSIS:
          {
            APPL_TRACE_DEBUG("%s:CSIS service found Uuid: %s ", __func__,
                              service.uuid.ToString().c_str());

            p_lea_cb->is_csip_support = true;
            bta_dm_csis_disc_complete(bta_dm_search_cb.peer_bdaddr, false);
            // Get Characteristic and CCCD handle
            for (const gatt::Characteristic& charac : service.characteristics) {
              Uuid lock_uuid = charac.uuid;
              if (lock_uuid.As16Bit() == UUID_SERVCLASS_CSIS_LOCK) {
                APPL_TRACE_DEBUG("%s: CSIS rank found Uuid: %s ", __func__,
                    lock_uuid.ToString().c_str());
                if (p_lea_cb != NULL) {
                  Uuid csip_lock_uuid = Uuid::FromString("6AD8");
                  std::vector<bluetooth::Uuid>::iterator itr;
                  itr = std::find(p_lea_cb->uuids.begin(), p_lea_cb->uuids.end(),
                    csip_lock_uuid);
                  if (itr == p_lea_cb->uuids.end()) {
                    p_lea_cb->uuids.push_back(csip_lock_uuid);
                  }
                } else {
                  APPL_TRACE_DEBUG(" %s No Control Block", __func__);
                }
              }
            }
          }
          break;
          case UUID_SERVCLASS_T_ADV_AUDIO:
          {
            if (!p_lea_cb->is_has_found) {
              APPL_TRACE_DEBUG("%s: T_ADV_AUDIO service found Uuid: %s ", __func__,
                service.uuid.ToString().c_str());
              std::vector<bluetooth::Uuid>::iterator itr;
              itr = std::find(p_lea_cb->uuids.begin(), p_lea_cb->uuids.end(),
                service.uuid);
              if (itr == p_lea_cb->uuids.end()) {
                p_lea_cb->uuids.push_back(service.uuid);
              }
              // Get Characteristic and CCCD handle
              for (const gatt::Characteristic& charac : service.characteristics) {
                Uuid role_uuid = charac.uuid;
                if (role_uuid.As16Bit() == UUID_SERVCLASS_T_ADV_AUDIO_ROLE_CHAR) {
                  APPL_TRACE_DEBUG("%s:T_ADV_AUDIO ROLE CHAR found Uuid: %s ", __func__,
                      role_uuid.ToString().c_str());
                  if (p_lea_cb != NULL) {
                    p_lea_cb->is_t_audio_srvc_found = true;
                    p_lea_cb->disc_progress++;
                    p_lea_cb->t_role_handle = charac.value_handle;
                  } else {
                    APPL_TRACE_DEBUG(" %s No Control Block", __func__);
                  }
                }
              }
              if (p_lea_cb->t_role_handle) {
                APPL_TRACE_DEBUG("%s t_role_handle %d", __func__,
                  p_lea_cb->t_role_handle);
                BtaGattQueue::ReadCharacteristic(conn_id, p_lea_cb->t_role_handle,
                  bta_gap_gatt_read_cb, NULL);
              }
            }
          }
          break;
          case UUID_SERVCLASS_HAS:
            if (!p_lea_cb->is_t_audio_srvc_found) {
              p_lea_cb->is_has_found = true;
              APPL_TRACE_DEBUG("%s: HAS service found Uuid: %s ", __func__,
                service.uuid.ToString().c_str());
              std::vector<bluetooth::Uuid>::iterator itr;
              itr = std::find(p_lea_cb->uuids.begin(), p_lea_cb->uuids.end(),
                service.uuid);
              if (itr == p_lea_cb->uuids.end()) {
                p_lea_cb->uuids.push_back(service.uuid);
              }
            }
            FALLTHROUGH_INTENDED; /* FALLTHROUGH */
          case UUID_SERVCLASS_PACS:
          {
            if ((!p_lea_cb->pacs_char_handle) &&
              ((!p_lea_cb->is_t_audio_srvc_found))) {
              APPL_TRACE_DEBUG("%s:PACS service found Uuid: %s ", __func__,
                service.uuid.ToString().c_str());

              std::vector<bluetooth::Uuid>::iterator itr;
              itr = std::find(p_lea_cb->uuids.begin(), p_lea_cb->uuids.end(),
                service.uuid);
              if (itr == p_lea_cb->uuids.end()) {
                p_lea_cb->uuids.push_back(service.uuid);
              }
              // Get Characteristic and CCCD handle
              for (const gatt::Characteristic& charac : service.characteristics) {
                Uuid role_uuid = charac.uuid;
                if (role_uuid.As16Bit() == UUID_SERVCLASS_SOURCE_CONTEXT) {
                  APPL_TRACE_DEBUG("%s: PACS Source context CHAR found Uuid: %s ",
                    __func__, role_uuid.ToString().c_str());
                  if (p_lea_cb != NULL) {
                    p_lea_cb->disc_progress++;
                    p_lea_cb->pacs_char_handle = charac.value_handle;
                  } else {
                    APPL_TRACE_DEBUG(" %s No Control Block", __func__);
                  }
                }
              }
              if (p_lea_cb->pacs_char_handle) {
                BtaGattQueue::ReadCharacteristic(conn_id, p_lea_cb->pacs_char_handle,
                  bta_gap_gatt_read_cb, NULL);
              }
            }
          }
          break;
          default:
            APPL_TRACE_DEBUG(" Not a LE AUDIO SERVICE-- IGNORE %s ",
              service.uuid.ToString().c_str());
        }
      }
    }
  }

  if (p_lea_cb->disc_progress == 0) {
    bta_dm_lea_disc_complete(peer_address);
  }
}

/*****************************************************************************
 *
 * Function         bta_dm_csis_disc_complete
 *
 * Description      This API updates csis discovery complete status
 *
 * Parameters:      none
 *****************************************************************************/
void bta_dm_csis_disc_complete(RawAddress p_bd_addr, bool status) {
  tBTA_LE_AUDIO_DEV_INFO *p_lea_cb = bta_get_lea_ctrl_cb(p_bd_addr);
  APPL_TRACE_DEBUG("%s %s %d", __func__, p_bd_addr.ToString().c_str(),
      status);

  if (p_lea_cb) {
    p_lea_cb->csip_disc_progress = status;
  } else {
    RawAddress pseudo_addr = bta_get_pseudo_addr_with_id_addr(p_bd_addr);
    if (pseudo_addr != RawAddress::kEmpty) {
      p_lea_cb = bta_get_lea_ctrl_cb(pseudo_addr);
      if (p_lea_cb) {
        p_lea_cb->csip_disc_progress = status;
        APPL_TRACE_DEBUG(" %s Pseudo addr disc_progress resetted", __func__);
      } else {
        APPL_TRACE_DEBUG(" %s No Control Block for pseudo addr", __func__);
      }
    } else {
      APPL_TRACE_DEBUG(" %s No Control Block", __func__);
    }
  }
}

/*****************************************************************************
 *
 * Function         bta_dm_lea_disc_complete
 *
 * Description      This API sends the event to upper layer that LE audio
 *                  gatt operations are complete.
 *
 * Parameters:      none
 *
 ****************************************************************************/
void bta_dm_lea_disc_complete(RawAddress p_bd_addr) {
  tBTA_DM_SEARCH result;
  tBTA_LE_AUDIO_DEV_INFO *p_lea_cb = bta_get_lea_ctrl_cb(p_bd_addr);
  APPL_TRACE_DEBUG("%s %s", __func__, p_bd_addr.ToString().c_str());

  if (p_lea_cb == NULL) {
    RawAddress pseudo_addr = bta_get_pseudo_addr_with_id_addr(p_bd_addr);
    p_lea_cb = bta_get_lea_ctrl_cb(pseudo_addr);
    p_bd_addr = pseudo_addr;
  }

  if (p_lea_cb) {
  APPL_TRACE_DEBUG("csip_disc_progress %d", p_lea_cb->csip_disc_progress);
    if ((p_lea_cb->disc_progress == 0) &&
        (p_lea_cb->csip_disc_progress)) { //Add CSIS check also
      result.adv_audio_disc_cmpl.num_uuids = 0;
      for (uint16_t i = 0; i < p_lea_cb->uuids.size(); i++) {
        result.adv_audio_disc_cmpl.adv_audio_uuids[i] = p_lea_cb->uuids[i];
        result.adv_audio_disc_cmpl.num_uuids++;
      }

      result.adv_audio_disc_cmpl.bd_addr = p_bd_addr;
      APPL_TRACE_DEBUG("Sending Call back with  no of uuids's"
        "p_lea_cb->uuids.size() %d", p_lea_cb->uuids.size());
      bta_dm_search_cb.p_search_cback(BTA_DM_LE_AUDIO_SEARCH_CMPL_EVT, &result);
    } else {
      APPL_TRACE_DEBUG("%s Discovery in progress", __func__);
    }
  } else {
    APPL_TRACE_DEBUG(" %s No Control Block", __func__);
  }
}


/*****************************************************************************
 *
 * Function         bta_add_adv_audio_uuid
 *
 * Description      This is GATT client callback function used in DM.
 *
 * Parameters:
 *
 ******************************************************************************/
void bta_add_adv_audio_uuid(RawAddress peer_address,
                               tBTA_GATT_ID srvc_uuid) {
  auto itr = find(uuid_srv_disc_search.begin(),
                  uuid_srv_disc_search.end(), srvc_uuid.uuid);

  if(itr != uuid_srv_disc_search.end()) {
    tBTA_LE_AUDIO_DEV_INFO *p_lea_cb = bta_get_lea_ctrl_cb(peer_address);
    if (p_lea_cb != NULL) {
      APPL_TRACE_DEBUG(" %s Control Block Found", __func__);

      std::vector<bluetooth::Uuid>::iterator itr;
      itr = std::find(p_lea_cb->uuids.begin(), p_lea_cb->uuids.end(), srvc_uuid.uuid);
      if (itr == p_lea_cb->uuids.end()) {
        p_lea_cb->uuids.push_back(srvc_uuid.uuid);
      }
    } else {
      APPL_TRACE_DEBUG(" %s No Control Block", __func__);
    }
  }
}




/*******************************************************************************
 *
 * Function         bta_set_lea_ctrl_cb
 *
 * Description      This is GATT client callback function used in DM.
 *
 * Parameters:
 *
 ******************************************************************************/

tBTA_LE_AUDIO_DEV_INFO* bta_set_lea_ctrl_cb(RawAddress peer_addr) {
  tBTA_LE_AUDIO_DEV_INFO *p_lea_cb = NULL;

  p_lea_cb = bta_get_lea_ctrl_cb(peer_addr);

  if (p_lea_cb == NULL) {
    APPL_TRACE_DEBUG("%s Control block create ", __func__);

    for (int i = 0; i < MAX_LEA_DEVICES ; i++) {
      if (!bta_le_audio_dev_cb.bta_lea_dev_info[i].in_use) {
        bta_le_audio_dev_cb.bta_lea_dev_info[i].peer_address = peer_addr;
        bta_le_audio_dev_cb.bta_lea_dev_info[i].in_use = true;
        bta_le_audio_dev_cb.bta_lea_dev_info[i].csip_disc_progress = true;
        bta_le_audio_dev_cb.bta_lea_dev_info[i].is_csip_support = false;
        bta_le_audio_dev_cb.bta_lea_dev_info[i].gatt_disc_progress = true;
        bta_le_audio_dev_cb.num_lea_devices++;
        return (&(bta_le_audio_dev_cb.bta_lea_dev_info[i]));
      }
    }
  } else {
    return p_lea_cb;
  }
  return NULL;
}

/*******************************************************************************
 *
 * Function         bta_dm_reset_adv_audio_dev_info
 *
 * Description      This is GATT client callback function used in DM.
 *
 * Parameters:
 *
 ******************************************************************************/
void bta_dm_reset_adv_audio_dev_info(RawAddress p_addr) {
  tBTA_LE_AUDIO_DEV_INFO *p_lea_cb = bta_get_lea_ctrl_cb(p_addr);

  if (p_lea_cb != NULL) {
    p_lea_cb->peer_address = RawAddress::kEmpty;
    p_lea_cb->disc_progress = 0;
    p_lea_cb->conn_id = 0;
    p_lea_cb->transport = 0;
    p_lea_cb->in_use = false;
    p_lea_cb->t_role_handle = 0;
    p_lea_cb->is_has_found = false;
    p_lea_cb->is_t_audio_srvc_found = false;
    p_lea_cb->pacs_char_handle = 0;
    p_lea_cb->using_bredr_bonding = 0;
    p_lea_cb->gatt_disc_progress = false;
    p_lea_cb->uuids.clear();
    bta_le_audio_dev_cb.gatt_op_addr = RawAddress::kEmpty;
    bta_le_audio_dev_cb.pending_peer_addr = RawAddress::kEmpty;
    bta_le_audio_dev_cb.num_lea_devices--;
    bta_le_audio_dev_cb.bond_progress = false;
    APPL_TRACE_DEBUG("bta_dm_reset_adv_audio_dev_info %s  transport %d ",
      p_lea_cb->peer_address.ToString().c_str(), p_lea_cb->transport);
  }
}

/*******************************************************************************
 *
 * Function         bta_dm_set_adv_audio_dev_info
 *
 * Description      This is GATT client callback function used in DM.
 *
 * Parameters:
 *
 ******************************************************************************/
void bta_dm_set_adv_audio_dev_info(tBTA_GATTC_OPEN* p_data) {
  tBTA_LE_AUDIO_DEV_INFO *p_lea_cb = bta_set_lea_ctrl_cb(p_data->remote_bda);

  if (p_lea_cb != NULL) {
    p_lea_cb->peer_address = p_data->remote_bda;
    p_lea_cb->disc_progress = 0;
    p_lea_cb->conn_id = p_data->conn_id;
    p_lea_cb->transport = p_data->transport;//BTM_UseLeLink(p_data->remote_bda);
    APPL_TRACE_DEBUG("bta_dm_set_adv_audio_dev_info %s  transport %d ",
      p_lea_cb->peer_address.ToString().c_str(), p_lea_cb->transport);
  }
}

/*******************************************************************************
 *
 * Function         is_adv_audio_unicast_supported
 *
 * Description      This function checks whether unicast support is there or not on
 *                  remote side
 *
 * Parameters:
 *
 ******************************************************************************/

bool is_adv_audio_unicast_supported(RawAddress rem_bda, int conn_id) {
  const std::vector<gatt::Service>* services = BTA_GATTC_GetServices(conn_id);

  if (services) {
    for (const gatt::Service& service : *services) {
      uint16_t uuid_val = service.uuid.As16Bit();
      if (uuid_val == UUID_SERVCLASS_ASCS)
        return true;
    }
  }

  return false;
}

/*******************************************************************************
 *
 * Function         is_adv_audio_group_supported
 *
 * Description      This function checks whether csip support is there or not on
 *                  remote side
 *
 * Parameters:
 *
 ******************************************************************************/

bool is_adv_audio_group_supported(RawAddress rem_bda, int conn_id) {
  const std::vector<gatt::Service>* services = BTA_GATTC_GetServices(conn_id);

  if (services) {
    for (const gatt::Service& service : *services) {
      if (is_le_audio_service(service.uuid)) {
        uint16_t uuid_val = service.uuid.As16Bit();
        if (uuid_val == UUID_SERVCLASS_CSIS)
          return true;
      }
    }
  }

  return false;
}

/*******************************************************************************
 *
 * Function         bta_dm_lea_gattc_callback
 *
 * Description      This is GATT client callback function used in DM.
 *
 * Parameters:
 *
 ******************************************************************************/

void bta_dm_lea_gattc_callback(tBTA_GATTC_EVT event, tBTA_GATTC* p_data) {
  APPL_TRACE_DEBUG("bta_dm_lea_gattc_callback event = %d", event);

  switch (event) {
    case BTA_GATTC_OPEN_EVT:
      if (p_data->status != GATT_SUCCESS) {
        btif_dm_release_action_uuid(bta_le_audio_dev_cb.pending_peer_addr);
      } else {
        if (is_remote_support_adv_audio(bta_le_audio_dev_cb.pending_peer_addr)) {
          bta_dm_set_adv_audio_dev_info(&p_data->open);
        }
        bta_dm_proc_open_evt(&p_data->open);
      }
      break;

    case BTA_GATTC_SEARCH_RES_EVT:
      if (is_remote_support_adv_audio(bta_le_audio_dev_cb.pending_peer_addr)) {
        bta_add_adv_audio_uuid(bta_le_audio_dev_cb.pending_peer_addr,
                           p_data->srvc_res.service_uuid);
      }
      break;

    case BTA_GATTC_SEARCH_CMPL_EVT:
      if (is_remote_support_adv_audio(bta_le_audio_dev_cb.pending_peer_addr)) {
        bta_get_adv_audio_role(bta_le_audio_dev_cb.pending_peer_addr,
            p_data->search_cmpl.conn_id,
            p_data->search_cmpl.status);
        if (is_adv_audio_group_supported(bta_le_audio_dev_cb.pending_peer_addr,
             p_data->search_cmpl.conn_id)) {
          RawAddress p_id_addr =
            bta_get_rem_dev_id_addr(bta_le_audio_dev_cb.pending_peer_addr);
          if (p_id_addr != RawAddress::kEmpty) {
            BTA_CsipFindCsisInstance(p_data->search_cmpl.conn_id,
                p_data->search_cmpl.status,
                p_id_addr);
          } else {
            BTA_CsipFindCsisInstance(p_data->search_cmpl.conn_id,
                p_data->search_cmpl.status,
                bta_le_audio_dev_cb.pending_peer_addr);
          }
        }
      }
      break;

    case BTA_GATTC_CLOSE_EVT:
      APPL_TRACE_DEBUG("BTA_GATTC_CLOSE_EVT reason = %d, data conn_id %d,"
          "search conn_id %d", p_data->close.reason, p_data->close.conn_id,
          bta_dm_search_cb.conn_id);

      if (is_remote_support_adv_audio(bta_le_audio_dev_cb.pending_peer_addr)) {
        bta_dm_reset_adv_audio_dev_info(bta_le_audio_dev_cb.pending_peer_addr);
      }
      break;

    default:
      break;
  }
}

/******************************************************************************
 *
 * Function         bta_dm_adv_audio_gatt_conn
 *
 * Description      This API opens the gatt conn after finding sdp record
 *                  during BREDR Discovery
 *
 * Parameters:      none
 *
 ******************************************************************************/
void bta_dm_adv_audio_gatt_conn(RawAddress p_bd_addr) {
  APPL_TRACE_DEBUG("bta_dm_adv_audio_gatt_conn ");

  bta_le_audio_dev_cb.pending_peer_addr = p_bd_addr;

  tBTA_LE_AUDIO_DEV_INFO *tmp_lea_cb = bta_get_lea_ctrl_cb(p_bd_addr);
  if (tmp_lea_cb && tmp_lea_cb->in_use) {
    APPL_TRACE_DEBUG("bta_dm_adv_audio_gatt_conn Already exists %d",
      tmp_lea_cb->conn_id);
    return;
  }

  BTA_GATTC_AppRegister(bta_dm_lea_gattc_callback,
      base::Bind([](uint8_t client_id, uint8_t status) {
        if (status == GATT_SUCCESS) {
          tBTA_LE_AUDIO_DEV_INFO *p_lea_cb =
            bta_set_lea_ctrl_cb(bta_le_audio_dev_cb.pending_peer_addr);
            if (p_lea_cb) {
              APPL_TRACE_DEBUG("bta_dm_adv_audio_gatt_conn Client Id: %d",
                  client_id);
              p_lea_cb->gatt_if = client_id;
              p_lea_cb->using_bredr_bonding = true;
              BTA_GATTC_Open(client_id, bta_le_audio_dev_cb.pending_peer_addr,
                  true, GATT_TRANSPORT_LE, false);
            }
        }
        }), false);

}

/******************************************************************************
 *
 * Function         bta_dm_adv_audio_close
 *
 * Description      This API closes the gatt conn with was opened by dm layer
 *                  for service discovery (or) opened after finding sdp record
 *                  during BREDR Discovery
 *
 * Parameters:      none
 *
 ******************************************************************************/
void bta_dm_adv_audio_close(RawAddress p_bd_addr) {
  tBTA_LE_AUDIO_DEV_INFO *p_lea_cb = bta_get_lea_ctrl_cb(p_bd_addr);
  APPL_TRACE_DEBUG("%s", __func__);

  if (p_lea_cb) {
    APPL_TRACE_DEBUG("%s %d", __func__, p_lea_cb->gatt_if);
    if (p_lea_cb->using_bredr_bonding) {
      APPL_TRACE_DEBUG("%s closing LE conn est due to bredr bonding  %d", __func__,
          p_lea_cb->gatt_if);
      BTA_GATTC_AppDeregister(p_lea_cb->gatt_if);
    } else {
      bta_sys_start_timer(bta_dm_search_cb.gatt_close_timer,
          BTA_DM_ADV_AUDIO_GATT_CLOSE_DELAY_TOUT,
          BTA_DM_DISC_CLOSE_TOUT_EVT, 0);
    }
  }
}

/*******************************************************************************
 *
 * Function         bta_get_lea_ctrl_cb
 *
 * Description      This API returns pairing control block of LE AUDIO DEVICE
 *
 * Parameters:      tBTA_DEV_PAIRING_CB
 *
 ******************************************************************************/
tBTA_DEV_PAIRING_CB* bta_get_lea_pair_cb(RawAddress peer_addr) {
  tBTA_DEV_PAIRING_CB *p_lea_pair_cb = NULL;
  p_lea_pair_cb = &bta_lea_pairing_cb.bta_dev_pair_db[0];
  APPL_TRACE_DEBUG("%s %s ", __func__, peer_addr.ToString().c_str());

  for (int i = 0; i < MAX_LEA_DEVICES; i++) {
      if ((p_lea_pair_cb[i].in_use) &&
        (p_lea_pair_cb[i].p_addr == peer_addr)) {
        APPL_TRACE_DEBUG("%s Found %s index i %d ", __func__,
          p_lea_pair_cb[i].p_addr.ToString().c_str(), i);
        return &p_lea_pair_cb[i];
      }
    }
  return NULL;
}



/*******************************************************************************
 *
 * Function         bta_set_lea_ctrl_cb
 *
 * Description      This is GATT client callback function used in DM.
 *
 * Parameters:
 *
 ******************************************************************************/

tBTA_DEV_PAIRING_CB* bta_set_lea_pair_cb(RawAddress peer_addr) {
  tBTA_DEV_PAIRING_CB *p_lea_pair_cb = NULL;
  APPL_TRACE_DEBUG("bta_set_lea_ctrl_cb %s", peer_addr.ToString().c_str());

  p_lea_pair_cb = bta_get_lea_pair_cb(peer_addr);

  if (p_lea_pair_cb == NULL) {
    APPL_TRACE_DEBUG("bta_set_lea_ctrl_cb Control block create ");

    for (int i = 0; i < MAX_LEA_DEVICES ; i++) {
      if (!bta_lea_pairing_cb.bta_dev_pair_db[i].in_use) {
        bta_lea_pairing_cb.bta_dev_pair_db[i].p_addr = peer_addr;
        bta_lea_pairing_cb.bta_dev_pair_db[i].in_use = true;
        bta_lea_pairing_cb.is_pairing_progress = true;
        bta_lea_pairing_cb.num_devices++;
        return (&(bta_lea_pairing_cb.bta_dev_pair_db[i]));
      }
    }
  } else {
    return p_lea_pair_cb;
  }
  return NULL;
}

/*******************************************************************************
 *
 * Function         bta_dm_reset_adv_audio_dev_info
 *
 * Description      This API resets all the pairing information related to le
 *                  audio remote device.
 * Parameters:      none
 *
 ******************************************************************************/
void bta_dm_reset_lea_pairing_info(RawAddress p_addr) {

  APPL_TRACE_DEBUG("%s Addr %s", __func__, p_addr.ToString().c_str());

  auto itr = bta_lea_pairing_cb.dev_addr_map.find(p_addr);
  if (itr != bta_lea_pairing_cb.dev_addr_map.end()) {
    bta_lea_pairing_cb.dev_addr_map.erase(p_addr);
  }

  itr = bta_lea_pairing_cb.dev_rand_addr_map.find(p_addr);
  if (itr != bta_lea_pairing_cb.dev_rand_addr_map.end()) {
    bta_lea_pairing_cb.dev_rand_addr_map.erase(p_addr);
  }

  tBTA_DEV_PAIRING_CB *p_lea_pair_cb = NULL;
  p_lea_pair_cb = bta_get_lea_pair_cb(p_addr);
  if (p_lea_pair_cb) {
    APPL_TRACE_DEBUG("%s RESETTING VALUES", __func__);
    p_lea_pair_cb->in_use = false;
    p_lea_pair_cb->is_dumo_device = false;
    p_lea_pair_cb->is_le_pairing = false;
    p_lea_pair_cb->dev_type = 0;
    if (p_lea_pair_cb->p_id_addr != RawAddress::kEmpty) {
      itr = bta_lea_pairing_cb.dev_addr_map.find(p_lea_pair_cb->p_id_addr);
      APPL_TRACE_DEBUG("%s RESETTING Addr %s", __func__,
        p_lea_pair_cb->p_id_addr.ToString().c_str());
      if (itr != bta_lea_pairing_cb.dev_addr_map.end()) {
        APPL_TRACE_DEBUG("%s Clearing INSIDE LEA ADDR DB MAP",
          __func__);
        bta_lea_pairing_cb.dev_addr_map.erase(p_lea_pair_cb->p_id_addr);
      }
      p_lea_pair_cb->p_id_addr = RawAddress::kEmpty;
      p_lea_pair_cb->transport = 0;
      p_lea_pair_cb->p_addr = RawAddress::kEmpty;
    }
    bta_lea_pairing_cb.is_pairing_progress = false;
    bta_lea_pairing_cb.num_devices--;
    bta_lea_pairing_cb.is_sdp_discover = true;
  } else {
    APPL_TRACE_DEBUG("%s INVALID CONTROL BLOCK", __func__);
  }
}

/*****************************************************************************
 *
 * Function        bta_dm_ble_adv_audio_idaddr_map
 *
 * Description     storing the identity address information in the device
 *                 control block. It will used for DUMO devices
 *
 * Returns         none
 *
 *****************************************************************************/
void bta_dm_ble_adv_audio_idaddr_map(RawAddress p_bd_addr,
  RawAddress p_id_addr) {
  APPL_TRACE_DEBUG("%s p_bd_addr %s id_addr %s ", __func__,
    p_bd_addr.ToString().c_str(), p_id_addr.ToString().c_str());
  if (is_remote_support_adv_audio(p_bd_addr)) {
    bta_lea_pairing_cb.dev_addr_map[p_id_addr] = p_bd_addr;
    bta_lea_pairing_cb.dev_rand_addr_map[p_bd_addr] = p_id_addr;

    tBTA_DEV_PAIRING_CB *p_lea_pair_cb = NULL;
    p_lea_pair_cb = bta_get_lea_pair_cb(p_bd_addr);
    if (p_lea_pair_cb) {
      if (p_id_addr != p_bd_addr) {
        APPL_TRACE_DEBUG("%s is_dumo_device %s", __func__,
          p_id_addr.ToString().c_str());
        p_lea_pair_cb->p_id_addr = p_id_addr;
        p_lea_pair_cb->is_dumo_device = true;
      }
    }
  }
}

bool bta_remote_dev_identity_addr_match(RawAddress p_addr) {
  APPL_TRACE_DEBUG("%s ", __func__);

  auto itr = bta_lea_pairing_cb.dev_addr_map.find(p_addr);

  if (itr != bta_lea_pairing_cb.dev_addr_map.end()) {
    APPL_TRACE_DEBUG("%s Identity BD_ADDR %s", __func__,
      p_addr.ToString().c_str());
      return true;
  }
  return false;
}

bool bta_is_bredr_primary_transport(RawAddress p_bd_addr) {

  tBTA_DEV_PAIRING_CB *p_lea_pair_cb = NULL;

  p_lea_pair_cb = bta_get_lea_pair_cb(p_bd_addr);
  APPL_TRACE_DEBUG("%s ", __func__);
  if (p_lea_pair_cb) {
    APPL_TRACE_DEBUG("%s Transport %d ", __func__, p_lea_pair_cb->transport);
    if (p_lea_pair_cb->transport == BT_TRANSPORT_BR_EDR) {
      return true;
    }
  }

  return false;
}

bool bta_remote_device_is_dumo(RawAddress p_bd_addr) {

  auto itr = bta_lea_pairing_cb.dev_addr_map.find(p_bd_addr);
  APPL_TRACE_DEBUG("%s Addr %s", __func__, p_bd_addr.ToString().c_str());

  if (itr != bta_lea_pairing_cb.dev_addr_map.end()) {
    APPL_TRACE_DEBUG("%s DUMO DEVICE Identity BD_ADDR %s", __func__,
      p_bd_addr.ToString().c_str());
      return true;
  }

  auto itr2 = bta_lea_pairing_cb.dev_rand_addr_map.find(p_bd_addr);
  if (itr2 != bta_lea_pairing_cb.dev_rand_addr_map.end()) {
    APPL_TRACE_DEBUG("%s Dumo addressed %s %s ", __func__,
      itr2->first.ToString().c_str(), itr2->second.ToString().c_str());
    return true;
  }
  return false;
}

RawAddress bta_get_rem_dev_id_addr(RawAddress p_bd_addr) {
  tBTA_DEV_PAIRING_CB *p_lea_pair_cb = NULL;
  APPL_TRACE_DEBUG("%s ", __func__);

  p_lea_pair_cb = bta_get_lea_pair_cb(p_bd_addr);
  if (p_lea_pair_cb) {
    APPL_TRACE_DEBUG("%s %s", __func__,
      p_lea_pair_cb->p_id_addr.ToString().c_str());
    return p_lea_pair_cb->p_id_addr;
  }
  return RawAddress::kEmpty;
}

/*****************************************************************************
 *
 * Function        bta_adv_audio_update_bond_db
 *
 * Description     Updates pairing control block of the device and the bonding
 *                 is initiated using LE transport or not.
 *
 * Returns         void
 *
 *****************************************************************************/
void bta_adv_audio_update_bond_db(RawAddress p_bd_addr, uint8_t transport) {
  tBTA_DEV_PAIRING_CB *p_dev_pair_cb = bta_set_lea_pair_cb(p_bd_addr);

  APPL_TRACE_DEBUG("%s", __func__);
  if (p_dev_pair_cb) {
    APPL_TRACE_DEBUG("%s Addr %s Transport %d", __func__,
      p_bd_addr.ToString().c_str(),  transport);
    p_dev_pair_cb->p_addr = p_bd_addr;
    p_dev_pair_cb->transport = transport;
    if (transport == BT_TRANSPORT_LE) {
      if (is_remote_support_adv_audio(p_dev_pair_cb->p_addr))
        p_dev_pair_cb->is_le_pairing = true;
      else
        p_dev_pair_cb->is_le_pairing = false;
    } else
      p_dev_pair_cb->is_le_pairing = false;
  }
}

/*****************************************************************************
 *
 * Function        is_le_audio_service
 *
 * Description     It checks whether the given service is related to the LE
 *                 Audio service or not.
 *
 * Returns         true for LE Audio service which are registered.
                   false by default
 *
 *****************************************************************************/
bool is_le_audio_service(Uuid uuid) {

  uint16_t uuid_val = 0;
  bool status = false;

  size_t len = uuid.GetShortestRepresentationSize();
  if (len == Uuid::kNumBytes16) {
    uuid_val = uuid.As16Bit();
    APPL_TRACE_DEBUG("is_le_audio_service : 0x%X  0x%X ", uuid.As16Bit(), uuid_val);
    //TODO check the service contains any LE AUDIO service or not
    switch (uuid_val) {
      case UUID_SERVCLASS_CSIS:
        FALLTHROUGH_INTENDED; /* FALLTHROUGH */
      case UUID_SERVCLASS_BASS:
        FALLTHROUGH_INTENDED; /* FALLTHROUGH */
      case UUID_SERVCLASS_T_ADV_AUDIO:
        FALLTHROUGH_INTENDED; /* FALLTHROUGH */
      case UUID_SERVCLASS_ASCS:
        FALLTHROUGH_INTENDED; /* FALLTHROUGH */
      case UUID_SERVCLASS_BAAS:
        FALLTHROUGH_INTENDED; /* FALLTHROUGH */
      case UUID_SERVCLASS_PACS:
        {
          auto itr = find(uuid_srv_disc_search.begin(),
              uuid_srv_disc_search.end(), uuid);
          if (itr != uuid_srv_disc_search.end())
            status = true;
        }
        break;
      default:
        APPL_TRACE_DEBUG("%s : Not a LEA service ", __func__);
    }
  } else if(len == Uuid::kNumBytes128) {
    if (uuid == UUID_SERVCLASS_WMCP) {
      APPL_TRACE_DEBUG("%s: WMCP Service UUId found", __func__);
      auto itr = find(uuid_srv_disc_search.begin(),
          uuid_srv_disc_search.end(), uuid);
      if (itr != uuid_srv_disc_search.end())
        status = true;
    }
  }

  return status;
}

/*****************************************************************************
 *
 * Function        bta_is_adv_audio_valid_bdaddr
 *
 * Description     This API is used for DUMO device. If the device contains
 *                 two address (random and public), it checks for valid
 *                 address.
 *
 * Returns         0 - for random address in dumo device
 *                 1 - for public address in dumo device
 *
 ****************************************************************************/
int bta_is_adv_audio_valid_bdaddr(RawAddress p_bd_addr) {
  tBTA_DEV_PAIRING_CB *p_lea_pair_cb = NULL;
  p_lea_pair_cb = bta_get_lea_pair_cb(p_bd_addr);

  if (p_lea_pair_cb) {
    APPL_TRACE_DEBUG("%s p_lea_pair_cb %s", __func__,
      p_lea_pair_cb->p_addr.ToString().c_str());
    auto itr = bta_lea_pairing_cb.dev_addr_map.find(p_bd_addr);
    if (itr == bta_lea_pairing_cb.dev_addr_map.end() &&
        (p_lea_pair_cb->is_dumo_device)) {
      APPL_TRACE_DEBUG("%s Ignore BD_ADDR because of ID %s", __func__,
        p_lea_pair_cb->p_id_addr.ToString().c_str());
        return 0;
    }
  }
  return 1;
}

/*****************************************************************************
 *
 * Function        devclass2uint
 *
 * Description     This API is to derive the class of device based of dev_class
 *
 * Returns         uint32_t - class of device
 *
 ****************************************************************************/
static uint32_t devclass2uint(DEV_CLASS dev_class) {
  uint32_t cod = 0;

  if (dev_class != NULL) {
    /* if COD is 0, irrespective of the device type set it to Unclassified
     * device */
    cod = (dev_class[2]) | (dev_class[1] << 8) | (dev_class[0] << 16);
  }
  return cod;
}

/*****************************************************************************
 *
 * Function        bta_is_remote_support_lea
 *
 * Description     This API is to check the remote device contains LEA service
 *                 or not. It checks in Inquiry database initially.
 *                 If the address is Public identity address then it will
 *                 check in the pairing database of that remote device.
 *
 * Returns         true - if remote device inquiry db contains LEA service
 *
 ****************************************************************************/
bool bta_is_remote_support_lea(RawAddress p_addr) {
  tBTM_INQ_INFO* p_inq_info;

  p_inq_info = BTM_InqDbRead(p_addr);
  if (p_inq_info != NULL) {
    uint32_t cod = devclass2uint(p_inq_info->results.dev_class);
    BTIF_TRACE_DEBUG("%s cod is 0x%06x", __func__, cod);
    if ((cod & MAJOR_LE_AUDIO_VENDOR_COD)
          == MAJOR_LE_AUDIO_VENDOR_COD) {
      return true;
    }
  }

  /* check the address is public identity address and its related to random
   * address which supports to LEA then that Public ID address should return
   * true.
   */
  auto itr = bta_lea_pairing_cb.dev_addr_map.find(p_addr);
  if (itr != bta_lea_pairing_cb.dev_addr_map.end()) {
    BTIF_TRACE_DEBUG("%s Idenity address mapping", __func__);
    return true;
  }

  return false;
}

void bta_find_adv_audio_group_instance(uint16_t conn_id, tGATT_STATUS status,
    RawAddress p_addr) {
  RawAddress p_id_addr =
    bta_get_rem_dev_id_addr(p_addr);
  if (p_id_addr != RawAddress::kEmpty) {
    BTA_CsipFindCsisInstance(conn_id, status, p_id_addr);
  } else {
    BTA_CsipFindCsisInstance(conn_id, status, p_addr);
  }
}

/*******************************************************************************
 *
 * Function         is_gatt_srvc_disc_pending
 *
 * Description      This function checks whether gatt_srvc_disc is processing
 *                  or not
 *
 * Parameters:
 *
 ******************************************************************************/
bool is_gatt_srvc_disc_pending(RawAddress rem_bda) {
  tBTA_LE_AUDIO_DEV_INFO *p_lea_cb = bta_get_lea_ctrl_cb(rem_bda);

  APPL_TRACE_DEBUG("%s ", __func__);
  if (p_lea_cb == NULL) {
    return false;
  } else {
    APPL_TRACE_DEBUG("%s gatt_disc_progress %d ", __func__,
        p_lea_cb->gatt_disc_progress);
    return p_lea_cb->gatt_disc_progress;
  }
}

/******************************************************************************
 *
 * Function         bta_get_pseudo_addr_with_id_addr
 *
 * Description      This function returns the mapping id_addr(if present) to
 *                  pseudo addr
 *
 * Parameters:
 *
 *****************************************************************************/
RawAddress bta_get_pseudo_addr_with_id_addr(RawAddress p_addr) {
  auto itr = bta_lea_pairing_cb.dev_addr_map.find(p_addr);

  APPL_TRACE_DEBUG("%s p_addr %s ", __func__, p_addr.ToString().c_str());
  if (itr != bta_lea_pairing_cb.dev_addr_map.end()) {
    APPL_TRACE_DEBUG("%s addr is mapped to %s ", __func__,
        itr->second.ToString().c_str());
    if (itr->second != RawAddress::kEmpty) {
      return itr->second;
    }
  }
  return p_addr;
}
