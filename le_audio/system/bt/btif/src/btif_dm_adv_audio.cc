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

#define LOG_TAG "bt_btif_dm"

#include "btif_dm.h"

#include <base/bind.h>
#include <base/logging.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>
#include <iterator>
#include <map>

#include <mutex>

#include <bluetooth/uuid.h>
#include "hardware/vendor.h"

#include <hardware/bluetooth.h>
#include <hardware/bt_hearing_aid.h>

#include "advertise_data_parser.h"
#include "bt_common.h"
#include "bta_closure_api.h"
#include "bta_csip_api.h"
#include "bta_gatt_api.h"
#include "btif_api.h"
#include "btif_bqr.h"
#include "btif_config.h"
#include "btif_dm.h"
#include "btif_hh.h"
#include "btif_sdp.h"
#include "btif_storage.h"
#include "btif_util.h"
#include "btu.h"
#include "bta/include/bta_dm_api.h"
#include "device/include/controller.h"
#include "device/include/interop.h"
#include "internal_include/stack_config.h"
#include "osi/include/allocator.h"
#include "osi/include/log.h"
#include "osi/include/metrics.h"
#include "osi/include/osi.h"
#include "osi/include/properties.h"
#include "stack/btm/btm_int.h"
#include "stack_config.h"
#include "stack/sdp/sdpint.h"
#include "btif_tws_plus.h"
#include "device/include/device_iot_config.h"
#include "btif_bap_config.h"
#include "bta_dm_adv_audio.h"
#include "btif_dm_adv_audio.h"

using bluetooth::Uuid;

/******************************************************************************
 *  Constants & Macros
 *****************************************************************************/
#define BTIF_DM_GET_REMOTE_PROP(b,t,v,l,p) \
      {p.type=t;p.val=v;p.len=l;btif_storage_get_remote_device_property(b,&p);}

extern std::vector<bluetooth::Uuid> uuid_srv_disc_search;
std::unordered_map<RawAddress, uint32_t> adv_audio_device_db;
extern void bta_dm_adv_audio_gatt_conn(RawAddress p_bd_addr);
extern void bta_dm_adv_audio_close(RawAddress p_bd_addr);
extern bool btif_has_ble_keys(const char* bdstr);
bt_status_t btif_storage_get_remote_device_property(
        const RawAddress* remote_bd_addr, bt_property_t* property);
extern tBTA_LEA_PAIRING_DB bta_lea_pairing_cb;
extern void search_services_copy_cb(uint16_t event, char* p_dest, char* p_src);

extern void bond_state_changed(bt_status_t status, const RawAddress& bd_addr,
                               bt_bond_state_t state);

#define BTIF_STORAGE_GET_REMOTE_PROP(b, t, v, l, p)     \
    do {                                                  \
          (p).type = (t);                                     \
          (p).val = (v);                                      \
          (p).len = (l);                                      \
          btif_storage_get_remote_device_property((b), &(p)); \
        } while (0)

extern bool check_adv_audio_cod(uint32_t cod);
extern bool is_remote_support_adv_audio(const RawAddress remote_bdaddr);
extern bool is_le_audio_service(Uuid uuid);
extern void bta_adv_audio_update_bond_db(RawAddress p_bd_addr, uint8_t transport);

#define BTIF_DM_MAX_SDP_ATTEMPTS_AFTER_PAIRING 2


tBTA_TRANSPORT btif_dm_get_adv_audio_transport(const RawAddress& bd_addr) {
  tBTM_INQ_INFO* p_inq_info;

  p_inq_info = BTM_InqDbRead(bd_addr);
  if (p_inq_info != NULL) {
    BTIF_TRACE_DEBUG("%s, inq_result_type %x",
        __func__, p_inq_info->results.inq_result_type);
    if (p_inq_info->results.inq_result_type & BTM_INQ_RESULT_BLE) {
      return BT_TRANSPORT_LE;
    }
  }
  return BT_TRANSPORT_BR_EDR;
}

/*******************************************************************************
 *
 * Function         btif_set_remote_device_uuid_property
 *
 * Description      Store the remote LEA services in config file
 *
 * Returns          void
 *
 ******************************************************************************/
static void btif_set_remote_device_uuid_property(RawAddress p_addr,
                                                 int num_uuids,
                                                 bluetooth::Uuid *new_uuids) {

  Uuid remote_uuids[BT_MAX_NUM_UUIDS];
  bt_property_t prop;

  for (int j = 0; j < num_uuids; j++) {
    remote_uuids[j] = new_uuids[j];
    BTIF_TRACE_EVENT("%s: UUID %s index %d ", __func__,
      remote_uuids[j].ToString().c_str(), j);
  }
  prop.type = (bt_property_type_t)BT_PROPERTY_ADV_AUDIO_UUIDS;
  prop.val = &remote_uuids[0];
  prop.len = (num_uuids) * (Uuid::kNumBytes128);
  Uuid* tmp = (Uuid*)(prop.val);
  BTIF_TRACE_EVENT("%s: Checking it %s", __func__, tmp->ToString().c_str());
  int ret = btif_storage_set_remote_device_property(&p_addr, &prop);
  ASSERTC(ret == BT_STATUS_SUCCESS, "storing remote services failed",
          ret);
}

/*******************************************************************************
 *
 * Function         btif_dm_lea_search_services_evt
 *
 * Description      Executes search services event in btif context
 *
 * Returns          void
 *
 ******************************************************************************/
void btif_dm_lea_search_services_evt(uint16_t event, char* p_param) {
  tBTA_DM_SEARCH* p_data = (tBTA_DM_SEARCH*)p_param;

  bt_bond_state_t pairing_state = BT_BOND_STATE_NONE;
  uint8_t sdp_attempts = 0;
  RawAddress pairing_bd_addr;
  RawAddress static_bd_addr;
  btif_get_pairing_cb_info(&pairing_state, &sdp_attempts,
    &pairing_bd_addr, &static_bd_addr);

  BTIF_TRACE_EVENT("%s:  event = %d", __func__, event);
  switch (event) {
    case BTA_DM_DISC_RES_EVT: {
      uint32_t i = 0, j = 0;
      bt_property_t prop[2];
      int num_properties = 0;
      bt_status_t ret;
      Uuid remote_uuids[BT_MAX_NUM_UUIDS];
      Uuid missed_remote_uuids[BT_MAX_NUM_UUIDS];
      uint8_t missing_uuids_len = 0;
      bt_property_t remote_uuid_prop;

      RawAddress& bd_addr = p_data->disc_res.bd_addr;

      BTIF_TRACE_DEBUG("%s:(result=0x%x, services 0x%x)", __func__,
                       p_data->disc_res.result, p_data->disc_res.services);

      /* retry sdp service search, if sdp fails for pairing bd address,
      ** report sdp results to APP immediately for non pairing addresses
      */
      if ((p_data->disc_res.result != BTA_SUCCESS) &&
          (pairing_state == BT_BOND_STATE_BONDED) &&
          ((p_data->disc_res.bd_addr == pairing_bd_addr) ||
          (p_data->disc_res.bd_addr == static_bd_addr)) &&
          (sdp_attempts > 0)) {
        if (sdp_attempts < BTIF_DM_MAX_SDP_ATTEMPTS_AFTER_PAIRING) {
          BTIF_TRACE_WARNING("%s:SDP failed after bonding re-attempting",

                           __func__);
          btif_inc_sdp_attempts();
          btif_dm_get_remote_services_by_transport(&bd_addr, BT_TRANSPORT_BR_EDR);
          return;
        } else {
          BTIF_TRACE_WARNING(
            "%s: SDP reached to maximum attempts, sending bond fail to upper layers",
            __func__);
          btif_reset_sdp_attempts();
          if (bta_remote_device_is_dumo(bd_addr)) {
            auto itr = bta_lea_pairing_cb.dev_addr_map.find(bd_addr);
            if (itr != bta_lea_pairing_cb.dev_addr_map.end()) {
              if ((itr->first != itr->second)) {
                bta_lea_pairing_cb.is_sdp_discover = false;
                bond_state_changed(BT_STATUS_FAIL,
                  bd_addr, BT_BOND_STATE_NONE);
              } else {
                btif_reset_pairing_cb();
                BTIF_TRACE_WARNING("%s: Skipping BOND_NONE for %s", __func__,
                  bd_addr.ToString().c_str());
              }
            } else {
              BTIF_TRACE_ERROR("%s: SDP shouldnt on random address. Wrong path %s", __func__,
                  bd_addr.ToString().c_str());
              btif_reset_pairing_cb();
              bond_state_changed(BT_STATUS_FAIL,
                  bd_addr, BT_BOND_STATE_NONE);
              btif_storage_remove_bonded_device(&bd_addr);
              BTA_DmRemoveDevice(bd_addr);
            }
            return;
          } else {
            BTIF_TRACE_ERROR("%s: SDP shouldnt called. Wrong path %s", __func__,
                bd_addr.ToString().c_str());
          }
        }
      }
      prop[0].type = BT_PROPERTY_UUIDS;
      prop[0].len = 0;
      if ((p_data->disc_res.result == BTA_SUCCESS) &&
          (p_data->disc_res.num_uuids > 0)) {
        prop[0].val = p_data->disc_res.p_uuid_list;
        prop[0].len = p_data->disc_res.num_uuids * Uuid::kNumBytes128;

        for (i = 0; i < p_data->disc_res.num_uuids; i++) {
          std::string temp = ((p_data->disc_res.p_uuid_list + i))->ToString();
          LOG_INFO(LOG_TAG, "%s index:%d uuid:%s", __func__, i, temp.c_str());
        }
      }

      /* onUuidChanged requires getBondedDevices to be populated.
      ** bond_state_changed needs to be sent prior to remote_device_property
      */
      if ((pairing_state == BT_BOND_STATE_BONDED && sdp_attempts) &&
          (p_data->disc_res.bd_addr == pairing_bd_addr ||
           p_data->disc_res.bd_addr == static_bd_addr)) {
        LOG_INFO(LOG_TAG, "%s: SDP search done for %s", __func__,
                 bd_addr.ToString().c_str());
        btif_reset_sdp_attempts();
        BTA_DmResetPairingflag(bd_addr);
        btif_reset_pairing_cb();

        // Send one empty UUID to Java to unblock pairing intent when SDP failed
        // or no UUID is discovered
        if (p_data->disc_res.result != BTA_SUCCESS ||
            p_data->disc_res.num_uuids == 0) {
          LOG_INFO(LOG_TAG,
                   "%s: SDP failed, send empty UUID to unblock bonding %s",
                   __func__, bd_addr.ToString().c_str());
          bt_property_t prop;

          Uuid uuid = {};
          //Updating in lea_pairing_database
          if (bta_remote_device_is_dumo(bd_addr)) {
            tBTA_DEV_PAIRING_CB *p_lea_pair_cb = NULL;

            p_lea_pair_cb = bta_get_lea_pair_cb(bd_addr);
            if (p_lea_pair_cb) {
              p_lea_pair_cb->sdp_disc_status = false;
            }
          }

          if (btif_dm_get_adv_audio_transport(bd_addr) == BT_TRANSPORT_BR_EDR)
          {
            prop.type = BT_PROPERTY_UUIDS;
          } else {
            prop.type = (bt_property_type_t)BT_PROPERTY_ADV_AUDIO_UUIDS;
          }
          prop.val = &uuid;
          prop.len = Uuid::kNumBytes128;

          /* Send the event to the BTIF */
          HAL_CBACK(bt_hal_cbacks, remote_device_properties_cb,
                    BT_STATUS_SUCCESS, &bd_addr, 1, &prop);
          break;
        }
      }

      // updates extra uuids which are discovered during
      // new sdp search to existing uuid list present in conf file.
      // If conf file has more UUIDs than the sdp search, it will
      // update the conf file UUIDs as the final UUIDs
      BTIF_STORAGE_FILL_PROPERTY(&remote_uuid_prop, BT_PROPERTY_UUIDS,
                                 sizeof(remote_uuids), remote_uuids);
      btif_storage_get_remote_device_property(&bd_addr,
                                        &remote_uuid_prop);
      if(remote_uuid_prop.len && p_data->disc_res.result == BTA_SUCCESS) {
        // compare now
        bool uuid_found = false;
        uint8_t uuid_len = remote_uuid_prop.len / sizeof(Uuid);
        for (i = 0; i < p_data->disc_res.num_uuids; i++) {
          uuid_found = false;
          Uuid* disc_uuid =  reinterpret_cast<Uuid*> (p_data->disc_res.p_uuid_list + i);
          for (j = 0; j < uuid_len; j++) {
            Uuid* base_uuid =  reinterpret_cast<Uuid*> (remote_uuid_prop.val) + j;
            if(*disc_uuid == *base_uuid) {
              uuid_found = true;
              break;
            }
          }
          if(!uuid_found) {
            BTIF_TRACE_WARNING("%s:new uuid found ", __func__);
            memcpy(&missed_remote_uuids[missing_uuids_len++], disc_uuid, sizeof(Uuid));
          }
        }

        // add the missing uuids now
        if(missing_uuids_len) {
          BTIF_TRACE_WARNING("%s :missing_uuids_len = %d ", __func__, missing_uuids_len);
          for (j = 0; j < missing_uuids_len &&
             (unsigned long)remote_uuid_prop.len < BT_MAX_NUM_UUIDS * sizeof(Uuid); j++) {
            memcpy(&remote_uuids[uuid_len + j], &missed_remote_uuids[j], sizeof(Uuid));
            remote_uuid_prop.len += sizeof(Uuid);
          }
        }

        prop[0].type = BT_PROPERTY_UUIDS;
        prop[0].val = remote_uuids;
        prop[0].len = remote_uuid_prop.len;
        ret = btif_storage_set_remote_device_property(&bd_addr, &prop[0]);
        ASSERTC(ret == BT_STATUS_SUCCESS, "storing remote services failed",
                ret);
        //Send the UUID values to upper layer as BT_PROPERTY_ADV_AUDIO_UUIDS
        num_properties++;

        if (bta_is_bredr_primary_transport(bd_addr)) {
          BTIF_TRACE_WARNING("%s: Initiating LE connection ", __func__);
          adv_audio_device_db[bd_addr] = MAJOR_LE_AUDIO_VENDOR_COD;
          bta_le_audio_dev_cb.bond_progress = true;
          bta_dm_adv_audio_gatt_conn(bd_addr);
        }
      } else if (p_data->disc_res.num_uuids != 0) {
        /* Also write this to the NVRAM */
        ret = btif_storage_set_remote_device_property(&bd_addr, &prop[0]);
        ASSERTC(ret == BT_STATUS_SUCCESS, "storing remote services failed",
                ret);
        num_properties++;
      }

      /* Remote name update */
      if (strlen((const char *) p_data->disc_res.bd_name)) {
        prop[1].type = BT_PROPERTY_BDNAME;
        prop[1].val = p_data->disc_res.bd_name;
        prop[1].len = strlen((char *)p_data->disc_res.bd_name);

        ret = btif_storage_set_remote_device_property(&bd_addr, &prop[1]);
        ASSERTC(ret == BT_STATUS_SUCCESS, "failed to save remote device property", ret);
        num_properties++;
      }

      if (num_properties > 0) {
        if (btif_dm_get_adv_audio_transport(bd_addr) == BT_TRANSPORT_BR_EDR)
        {
          prop[0].type = BT_PROPERTY_UUIDS;
        } else {
          prop[0].type = (bt_property_type_t)BT_PROPERTY_ADV_AUDIO_UUIDS;
        }
        /* Send the event to the BTIF */
        HAL_CBACK(bt_hal_cbacks, remote_device_properties_cb, BT_STATUS_SUCCESS,
                  &bd_addr, num_properties, prop);
      }

      int validAddr = 1;
      bt_property_t rem_prop;
      BTIF_STORAGE_GET_REMOTE_PROP(&bd_addr, (bt_property_type_t)BT_PROPERTY_REM_DEViCE_VALID_ADDR,
                                   &validAddr, sizeof(int),
                                   rem_prop);

      if (validAddr != 0) {
        bt_property_t prop_addr;
        int is_valid = bta_is_adv_audio_valid_bdaddr(bd_addr);
        prop_addr.type = (bt_property_type_t)BT_PROPERTY_REM_DEViCE_VALID_ADDR;
        prop_addr.val = (void *)&is_valid;
        prop_addr.len = sizeof(int);
        ret = btif_storage_set_remote_device_property(&bd_addr, &prop_addr);
        ASSERTC(ret == BT_STATUS_SUCCESS, "failed to save remote device property", ret);
      }

      bt_device_type_t dev_type;
      dev_type = (bt_device_type_t)BT_DEVICE_TYPE_DUMO;
      bt_property_t prop_dev;
      BTIF_STORAGE_FILL_PROPERTY(&prop_dev,
                        BT_PROPERTY_TYPE_OF_DEVICE, sizeof(dev_type),
                        &dev_type);
      ret = btif_storage_set_remote_device_property(&bd_addr, &prop_dev);
      ASSERTC(ret == BT_STATUS_SUCCESS, "failed to save remote device type",
        ret);

      HAL_CBACK(bt_hal_cbacks, remote_device_properties_cb, BT_STATUS_SUCCESS,
          &bd_addr, 1, &prop_dev);

      /* If below condition is true, it means LE random advertising
       * has no ADV audio uuids, but identity address contains adv audio bit
       * As per current design, if pairing initiated through non adv audio
       * address then we dont need to fetch ADV audio role and services
       */
      if ((btif_get_is_adv_audio_pair_info(bd_addr) == 0)) {
        prop_dev.type = (bt_property_type_t)BT_PROPERTY_ADV_AUDIO_ACTION_UUID;
        prop_dev.val = (void *)&validAddr;
        prop_dev.len = sizeof(uint8_t);
        HAL_CBACK(bt_hal_cbacks, remote_device_properties_cb, BT_STATUS_SUCCESS,
            &bd_addr, 1, &prop_dev);
      }

    } break;

    case BTA_DM_DISC_CMPL_EVT:
      /* fixme */
      break;

    case BTA_DM_SEARCH_CANCEL_CMPL_EVT:
      /* no-op */
      break;

    case BTA_DM_DISC_BLE_RES_EVT: {
      BTIF_TRACE_DEBUG("%s: service %s", __func__,
                       p_data->disc_ble_res.service.ToString().c_str());
      bt_property_t prop;
      bt_status_t ret;
      RawAddress& bd_addr = p_data->disc_ble_res.bd_addr;
        /* Remote name update */
        if (strnlen((const char*)p_data->disc_ble_res.bd_name, BD_NAME_LEN)) {
          prop.type = BT_PROPERTY_BDNAME;
          prop.val = p_data->disc_ble_res.bd_name;
          prop.len =
              strnlen((char*)p_data->disc_ble_res.bd_name, BD_NAME_LEN);

          ret = btif_storage_set_remote_device_property(&bd_addr, &prop);
          ASSERTC(ret == BT_STATUS_SUCCESS,
                  "failed to save remote device property", ret);
          /* Send the event to the BTIF */
          HAL_CBACK(bt_hal_cbacks, remote_device_properties_cb, BT_STATUS_SUCCESS,
                    &bd_addr, 1, &prop);
        }
    } break;

    case BTA_DM_LE_AUDIO_SEARCH_CMPL_EVT:
    {
      tBTA_DEV_PAIRING_CB *p_lea_pair_cb = NULL;
      p_lea_pair_cb = bta_get_lea_pair_cb(p_data->disc_ble_res.bd_addr);
      if (p_lea_pair_cb != NULL) {
        btif_reset_pairing_cb();
        bt_property_t prop[5], prop_tmp[2];
        RawAddress& bd_addr = p_data->disc_ble_res.bd_addr;
        int num_properties = 0;
        bool id_addr_action_uuid = false;
        RawAddress id_addr = bta_get_rem_dev_id_addr(bd_addr);

        prop[num_properties].type = (bt_property_type_t)BT_PROPERTY_ADV_AUDIO_UUIDS;
        prop[num_properties].val = p_data->adv_audio_disc_cmpl.adv_audio_uuids;
        prop[num_properties].len = p_data->adv_audio_disc_cmpl.num_uuids *
          Uuid::kNumBytes128;
        /* Also write this to the NVRAM */
        bt_property_t cod_prop1;
        uint32_t cod_p;

        BTIF_STORAGE_FILL_PROPERTY(&cod_prop1,
            BT_PROPERTY_CLASS_OF_DEVICE, sizeof(cod_p), &cod_p);
        btif_storage_get_remote_device_property(&bd_addr,
            &cod_prop1);
        int ret;
        cod_p |= MAJOR_LE_AUDIO_VENDOR_COD;
        BTIF_STORAGE_FILL_PROPERTY(&cod_prop1,
            BT_PROPERTY_CLASS_OF_DEVICE, sizeof(cod_p), &cod_p);
        ret = btif_storage_set_remote_device_property(&bd_addr, &cod_prop1);
        ASSERTC(ret == BT_STATUS_SUCCESS,
            "failed to save remote device property", ret);

        if (bta_remote_device_is_dumo(bd_addr)
            && (id_addr != bd_addr) && (bta_lea_pairing_cb.is_sdp_discover == true)) {
          if(id_addr != RawAddress::kEmpty) {
            BTIF_TRACE_DEBUG("%s: Found BT_PROPERTY_ADV_AUDIO_UUIDS %s",
                p_data->adv_audio_disc_cmpl.adv_audio_uuids[0].ToString().c_str(),
                id_addr.ToString().c_str());

            bt_property_t cod_prop;
            uint32_t cod;

            BTIF_STORAGE_FILL_PROPERTY(&cod_prop,
                BT_PROPERTY_CLASS_OF_DEVICE, sizeof(cod), &cod);
            btif_storage_get_remote_device_property(&id_addr,
                &cod_prop);
            BTIF_TRACE_DEBUG("%s: Cod is %x", __func__, cod);
            cod |= MAJOR_LE_AUDIO_VENDOR_COD;
            BTIF_STORAGE_FILL_PROPERTY(&cod_prop,
                BT_PROPERTY_CLASS_OF_DEVICE, sizeof(cod), &cod);
            ret = btif_storage_set_remote_device_property(&id_addr, &cod_prop);
            ASSERTC(ret == BT_STATUS_SUCCESS,
                "failed to save remote device property", ret);
            num_properties++;
            prop[num_properties].type = BT_PROPERTY_CLASS_OF_DEVICE;
            prop[num_properties].val = (void *) &cod;
            prop[num_properties].len = sizeof(cod);

            num_properties ++;

            BTIF_STORAGE_FILL_PROPERTY(&prop[num_properties],
                (bt_property_type_t)BT_PROPERTY_REM_DEV_IDENT_BD_ADDR, sizeof(RawAddress), &bd_addr);
            ret = btif_storage_set_remote_device_property(&id_addr, &prop[num_properties]);
            ASSERTC(ret == BT_STATUS_SUCCESS,
                "failed to save remote device property", ret);

            id_addr_action_uuid = true;
            HAL_CBACK(bt_hal_cbacks, remote_device_properties_cb, BT_STATUS_SUCCESS,
                &id_addr, 3, &prop[0]);
          }
        }
        num_properties = 1;

        BTIF_STORAGE_FILL_PROPERTY(&prop[num_properties],
            (bt_property_type_t)BT_PROPERTY_REM_DEV_IDENT_BD_ADDR, sizeof(RawAddress), &id_addr);

        ret = btif_storage_set_remote_device_property(&bd_addr, &prop[num_properties]);
        ASSERTC(ret == BT_STATUS_SUCCESS,
            "failed to save remote device property", ret);

        HAL_CBACK(bt_hal_cbacks, remote_device_properties_cb, BT_STATUS_SUCCESS,
            &bd_addr, 2, &prop[0]);

        int validAddr = 1;
        bt_property_t rem_prop;
        BTIF_STORAGE_GET_REMOTE_PROP(&bd_addr, (bt_property_type_t)BT_PROPERTY_REM_DEViCE_VALID_ADDR,
            &validAddr, sizeof(int),
            rem_prop);
        validAddr = bta_is_adv_audio_valid_bdaddr(bd_addr);
        BTIF_TRACE_DEBUG("%s: is Valid Address Check value %d bd_addr %s", __func__, validAddr, bd_addr.ToString().c_str());
        prop_tmp[0].type = (bt_property_type_t)BT_PROPERTY_REM_DEViCE_VALID_ADDR;
        prop_tmp[0].val = (void *)&validAddr;
        prop_tmp[0].len = sizeof(int);
        ret = btif_storage_set_remote_device_property(&bd_addr, &prop_tmp[0]);
        ASSERTC(ret == BT_STATUS_SUCCESS, "failed to save remote device property", ret);

        prop_tmp[1].type = (bt_property_type_t)BT_PROPERTY_ADV_AUDIO_ACTION_UUID;
        prop_tmp[1].val = (void *)&validAddr;
        prop_tmp[1].len = sizeof(uint8_t);

        if (id_addr_action_uuid) {
          BTIF_TRACE_DEBUG("%s: IDENTITY ADDR ACTION UUID %s ", __func__,
              id_addr.ToString().c_str());
          HAL_CBACK(bt_hal_cbacks, remote_device_properties_cb, BT_STATUS_SUCCESS,
              &id_addr, 1, &prop_tmp[1]);
        }

        HAL_CBACK(bt_hal_cbacks, remote_device_properties_cb, BT_STATUS_SUCCESS,
            &bd_addr, 2, &prop_tmp[0]);
        if (id_addr_action_uuid) {
          btif_set_remote_device_uuid_property(id_addr,
              p_data->adv_audio_disc_cmpl.num_uuids, &p_data->adv_audio_disc_cmpl.adv_audio_uuids[0]);
        }
        btif_set_remote_device_uuid_property(bd_addr,
            p_data->adv_audio_disc_cmpl.num_uuids, &p_data->adv_audio_disc_cmpl.adv_audio_uuids[0]);

        bta_dm_adv_audio_close(bd_addr);
        bta_dm_reset_lea_pairing_info(bd_addr);
      } else {
        BTIF_TRACE_DEBUG("%s: ONCE AGAIN WRITING IDENTITY", __func__);
      }
    }
    break;
    default: { ASSERTC(0, "unhandled search services event", event); } break;
  }
}

/****************************************************************************
 *
 * Function        btif_register_uuid_srvc_disc
 *
 * Description     Add to UUID to the service search queue
 *
 * Returns         void
 *
 ****************************************************************************/
void btif_register_uuid_srvc_disc(bluetooth::Uuid uuid) {

  uuid_srv_disc_search.push_back(uuid);
  BTIF_TRACE_DEBUG("btif_register_uuid_srvc_disc, no of uuids %d %s",
  uuid_srv_disc_search.size(), uuid.ToString().c_str());
}

void btif_dm_release_action_uuid(RawAddress bd_addr) {

  bt_property_t prop_dev;
  int status = 1;
  prop_dev.type = (bt_property_type_t)BT_PROPERTY_ADV_AUDIO_ACTION_UUID;
  prop_dev.val = (void *)&status;
  prop_dev.len = sizeof(uint8_t);
  HAL_CBACK(bt_hal_cbacks, remote_device_properties_cb, BT_STATUS_SUCCESS,
      &bd_addr, 1, &prop_dev);
}

/****************************************************************************
 *
 * Function        check_adv_audio_cod
 *
 * Description     This API is used to check whether COD contains LE Audio
 *                 COD or not?
 *
 * Returns         bool
 *
 ****************************************************************************/
bool check_adv_audio_cod(uint32_t cod) {

  BTIF_TRACE_DEBUG("check_adv_audio_cod ");

  if (cod & MAJOR_LE_AUDIO_VENDOR_COD) {
    return true;
  }
  return false;
}

/*******************************************************************************
 *
 * Function        is_remote_support_adv_audio
 *
 * Description     is remote device is supporting LE audio or not
 *
 * Returns         bool
 *
 ******************************************************************************/

bool is_remote_support_adv_audio(const RawAddress p_addr) {
  if (adv_audio_device_db.find(p_addr)
          != adv_audio_device_db.end()) {
        BTIF_TRACE_DEBUG("%s  %s LE AUDIO Support ", __func__,
                  p_addr.ToString().c_str());
            return true;
  }

  bool status = bta_is_remote_support_lea(p_addr);
  if (status) return true;

  bt_property_t cod_prop;
  uint32_t cod_p;

  BTIF_STORAGE_FILL_PROPERTY(&cod_prop,
      BT_PROPERTY_CLASS_OF_DEVICE, sizeof(cod_p), &cod_p);
  btif_storage_get_remote_device_property(&p_addr,
      &cod_prop);

  if ((cod_p & MAJOR_LE_AUDIO_VENDOR_COD)
      == MAJOR_LE_AUDIO_VENDOR_COD) {
    BTIF_TRACE_DEBUG("%s ADV AUDIO COD is matched ", __func__);
    return true;
  }

  return false;
}

void bte_dm_adv_audio_search_services_evt(tBTA_DM_SEARCH_EVT event,
    tBTA_DM_SEARCH* p_data) {
  BTIF_TRACE_DEBUG(" %s ", __func__);
  uint16_t param_len = 0;
  if (p_data) param_len += sizeof(tBTA_DM_SEARCH);
  switch (event) {
    case BTA_DM_DISC_RES_EVT: {
                                if ((p_data && p_data->disc_res.result == BTA_SUCCESS) &&
                                    (p_data->disc_res.num_uuids > 0)) {
                                  param_len += (p_data->disc_res.num_uuids * Uuid::kNumBytes128);
                                }
                              } break;
  }
  /* TODO: The only other member that needs a deep copy is the p_raw_data. But
   *    * not sure
   *       * if raw_data is needed. */
  btif_transfer_context(
      btif_dm_lea_search_services_evt, event, (char*)p_data, param_len,
      (param_len > sizeof(tBTA_DM_SEARCH)) ? search_services_copy_cb : NULL);
}

