/******************************************************************************
 *
 *  Copyright (C) 2014  Broadcom Corporation
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

#define LOG_TAG "bt_btm_ble"

#include <base/bind.h>
#include <string.h>

#include "bt_target.h"

#include "bt_types.h"
#include "bt_utils.h"
#include "btm_ble_api.h"
#include "btm_int.h"
#include "btu.h"
#include "device/include/controller.h"
#include "hcidefs.h"
#include "hcimsgs.h"

#define BTM_BLE_ADV_FILT_META_HDR_LENGTH 3
#define BTM_BLE_ADV_FILT_FEAT_SELN_LEN 13
#define BTM_BLE_ADV_FILT_TRACK_NUM 2

#define BTM_BLE_PF_SELECT_NONE 0

/* BLE meta vsc header: 1 bytes of sub_code, 1 byte of PCF action */
#define BTM_BLE_META_HDR_LENGTH 3
#define BTM_BLE_PF_FEAT_SEL_LEN 18
#define BTM_BLE_PCF_ENABLE_LEN 2

#define BTM_BLE_META_ADDR_LEN 7
#define BTM_BLE_META_UUID_LEN 40

#define BTM_BLE_PF_BIT_TO_MASK(x) (uint16_t)(1 << (x))

tBTM_BLE_ADV_FILTER_CB btm_ble_adv_filt_cb;
tBTM_BLE_VSC_CB cmn_ble_vsc_cb;
static const BD_ADDR na_bda = {0};

static uint8_t btm_ble_cs_update_pf_counter(tBTM_BLE_SCAN_COND_OP action,
                                            uint8_t cond_type,
                                            tBLE_BD_ADDR* p_bd_addr,
                                            uint8_t num_available);

#define BTM_BLE_SET_SCAN_PF_OPCODE(x, y) (((x) << 4) | (y))
#define BTM_BLE_GET_SCAN_PF_SUBCODE(x) ((x) >> 4)
#define BTM_BLE_GET_SCAN_PF_ACTION(x) ((x)&0x0f)
#define BTM_BLE_INVALID_COUNTER 0xff

/* length of each multi adv sub command */
#define BTM_BLE_ADV_FILTER_ENB_LEN 3

/* length of each batch scan command */
#define BTM_BLE_ADV_FILTER_CLEAR_LEN 3
#define BTM_BLE_ADV_FILTER_LEN 2

#define BTM_BLE_ADV_FILT_CB_EVT_MASK 0xF0
#define BTM_BLE_ADV_FILT_SUBCODE_MASK 0x0F

/*******************************************************************************
 *
 * Function         btm_ble_obtain_vsc_details
 *
 * Description      This function obtains the VSC details
 *
 * Parameters
 *
 * Returns          status
 *
 ******************************************************************************/
tBTM_STATUS btm_ble_obtain_vsc_details() {
  tBTM_STATUS st = BTM_SUCCESS;

#if (BLE_VND_INCLUDED == TRUE)
  BTM_BleGetVendorCapabilities(&cmn_ble_vsc_cb);
  if (cmn_ble_vsc_cb.filter_support && 0 == cmn_ble_vsc_cb.max_filter) {
    st = BTM_MODE_UNSUPPORTED;
    return st;
  }
#else
  cmn_ble_vsc_cb.max_filter = BTM_BLE_MAX_FILTER_COUNTER;
#endif
  return st;
}

/*******************************************************************************
 *
 * Function         btm_ble_condtype_to_ocf
 *
 * Description      Convert cond_type to OCF
 *
 * Returns          Returns ocf value
 *
 ******************************************************************************/
uint8_t btm_ble_condtype_to_ocf(uint8_t cond_type) {
  uint8_t ocf = 0;

  switch (cond_type) {
    case BTM_BLE_PF_ADDR_FILTER:
      ocf = BTM_BLE_META_PF_ADDR;
      break;
    case BTM_BLE_PF_SRVC_UUID:
      ocf = BTM_BLE_META_PF_UUID;
      break;
    case BTM_BLE_PF_SRVC_SOL_UUID:
      ocf = BTM_BLE_META_PF_SOL_UUID;
      break;
    case BTM_BLE_PF_LOCAL_NAME:
      ocf = BTM_BLE_META_PF_LOCAL_NAME;
      break;
    case BTM_BLE_PF_MANU_DATA:
      ocf = BTM_BLE_META_PF_MANU_DATA;
      break;
    case BTM_BLE_PF_SRVC_DATA_PATTERN:
      ocf = BTM_BLE_META_PF_SRVC_DATA;
      break;
    case BTM_BLE_PF_TYPE_ALL:
      ocf = BTM_BLE_META_PF_ALL;
      break;
    default:
      ocf = BTM_BLE_PF_TYPE_MAX;
      break;
  }
  return ocf;
}

/*******************************************************************************
 *
 * Function         btm_ble_ocf_to_condtype
 *
 * Description      Convert OCF to cond type
 *
 * Returns          Returns condtype value
 *
 ******************************************************************************/
uint8_t btm_ble_ocf_to_condtype(uint8_t ocf) {
  uint8_t cond_type = 0;

  switch (ocf) {
    case BTM_BLE_META_PF_FEAT_SEL:
      cond_type = BTM_BLE_META_PF_FEAT_SEL;
      break;
    case BTM_BLE_META_PF_ADDR:
      cond_type = BTM_BLE_PF_ADDR_FILTER;
      break;
    case BTM_BLE_META_PF_UUID:
      cond_type = BTM_BLE_PF_SRVC_UUID;
      break;
    case BTM_BLE_META_PF_SOL_UUID:
      cond_type = BTM_BLE_PF_SRVC_SOL_UUID;
      break;
    case BTM_BLE_META_PF_LOCAL_NAME:
      cond_type = BTM_BLE_PF_LOCAL_NAME;
      break;
    case BTM_BLE_META_PF_MANU_DATA:
      cond_type = BTM_BLE_PF_MANU_DATA;
      break;
    case BTM_BLE_META_PF_SRVC_DATA:
      cond_type = BTM_BLE_PF_SRVC_DATA_PATTERN;
      break;
    case BTM_BLE_META_PF_ALL:
      cond_type = BTM_BLE_PF_TYPE_ALL;
      break;
    default:
      cond_type = BTM_BLE_PF_TYPE_MAX;
      break;
  }
  return cond_type;
}

void btm_flt_update_cb(uint8_t expected_ocf, tBTM_BLE_PF_CFG_CBACK cb,
                       uint8_t* p, uint16_t evt_len) {
  if (evt_len != 4) {
    BTM_TRACE_ERROR("%s: bad length: %d", __func__, evt_len);
    return;
  }

  uint8_t status, op_subcode, action, num_avail;
  STREAM_TO_UINT8(status, p);
  STREAM_TO_UINT8(op_subcode, p);
  STREAM_TO_UINT8(action, p);
  STREAM_TO_UINT8(num_avail, p);

  if (expected_ocf != op_subcode) {
    BTM_TRACE_ERROR("%s: Incorrect opcode: 0x%02x, expected: 0x%02x", __func__,
                    expected_ocf, op_subcode);
    return;
  }

  if (op_subcode == BTM_BLE_META_PF_FEAT_SEL) {
    cb.Run(num_avail, action, status);
    return;
  }

  uint8_t cond_type = btm_ble_ocf_to_condtype(expected_ocf);
  BTM_TRACE_DEBUG("%s: Recd: %d, %d, %d, %d, %d", __func__, op_subcode,
                  expected_ocf, action, status, num_avail);
  if (HCI_SUCCESS == status) {
    if (memcmp(&btm_ble_adv_filt_cb.cur_filter_target.bda, &na_bda,
               BD_ADDR_LEN) == 0)
      btm_ble_cs_update_pf_counter(action, cond_type, NULL, num_avail);
    else
      btm_ble_cs_update_pf_counter(
          action, cond_type, &btm_ble_adv_filt_cb.cur_filter_target, num_avail);
  }

  /* send ADV PF operation complete */
  btm_ble_adv_filt_cb.op_type = 0;

  cb.Run(num_avail, action, status);
}

/*******************************************************************************
 *
 * Function         btm_ble_find_addr_filter_counter
 *
 * Description      find the per bd address ADV payload filter counter by
 *                  BD_ADDR.
 *
 * Returns          pointer to the counter if found; NULL otherwise.
 *
 ******************************************************************************/
tBTM_BLE_PF_COUNT* btm_ble_find_addr_filter_counter(tBLE_BD_ADDR* p_le_bda) {
  uint8_t i;
  tBTM_BLE_PF_COUNT* p_addr_filter =
      &btm_ble_adv_filt_cb.p_addr_filter_count[1];

  if (p_le_bda == NULL) return &btm_ble_adv_filt_cb.p_addr_filter_count[0];

  for (i = 0; i < cmn_ble_vsc_cb.max_filter; i++, p_addr_filter++) {
    if (p_addr_filter->in_use &&
        memcmp(p_le_bda->bda, p_addr_filter->bd_addr, BD_ADDR_LEN) == 0) {
      return p_addr_filter;
    }
  }
  return NULL;
}

/*******************************************************************************
 *
 * Function         btm_ble_alloc_addr_filter_counter
 *
 * Description      allocate the per device adv payload filter counter.
 *
 * Returns          pointer to the counter if allocation succeed; NULL
 *                  otherwise.
 *
 ******************************************************************************/
tBTM_BLE_PF_COUNT* btm_ble_alloc_addr_filter_counter(BD_ADDR bd_addr) {
  uint8_t i;
  tBTM_BLE_PF_COUNT* p_addr_filter =
      &btm_ble_adv_filt_cb.p_addr_filter_count[1];

  for (i = 0; i < cmn_ble_vsc_cb.max_filter; i++, p_addr_filter++) {
    if (memcmp(na_bda, p_addr_filter->bd_addr, BD_ADDR_LEN) == 0) {
      memcpy(p_addr_filter->bd_addr, bd_addr, BD_ADDR_LEN);
      p_addr_filter->in_use = true;
      return p_addr_filter;
    }
  }
  return NULL;
}
/*******************************************************************************
 *
 * Function         btm_ble_dealloc_addr_filter_counter
 *
 * Description      de-allocate the per device adv payload filter counter.
 *
 * Returns          true if deallocation succeed; false otherwise.
 *
 ******************************************************************************/
bool btm_ble_dealloc_addr_filter_counter(tBLE_BD_ADDR* p_bd_addr,
                                         uint8_t filter_type) {
  uint8_t i;
  tBTM_BLE_PF_COUNT* p_addr_filter =
      &btm_ble_adv_filt_cb.p_addr_filter_count[1];
  bool found = false;

  if (BTM_BLE_PF_TYPE_ALL == filter_type && NULL == p_bd_addr)
    memset(&btm_ble_adv_filt_cb.p_addr_filter_count[0], 0,
           sizeof(tBTM_BLE_PF_COUNT));

  for (i = 0; i < cmn_ble_vsc_cb.max_filter; i++, p_addr_filter++) {
    if ((p_addr_filter->in_use) &&
        (NULL == p_bd_addr ||
         (NULL != p_bd_addr &&
          memcmp(p_bd_addr->bda, p_addr_filter->bd_addr, BD_ADDR_LEN) == 0))) {
      found = true;
      memset(p_addr_filter, 0, sizeof(tBTM_BLE_PF_COUNT));

      if (NULL != p_bd_addr) break;
    }
  }
  return found;
}

/*******************************************************************************
 *
 * Function         btm_ble_update_pf_local_name
 *
 * Description      this function update(add,delete or clear) the adv local
 *                  name filtering condition.
 *
 *
 * Returns          BTM_SUCCESS if sucessful,
 *                  BTM_ILLEGAL_VALUE if paramter is not valid.
 *
 ******************************************************************************/
tBTM_STATUS btm_ble_update_pf_local_name(tBTM_BLE_SCAN_COND_OP action,
                                         tBTM_BLE_PF_FILT_INDEX filt_index,
                                         tBTM_BLE_PF_COND_PARAM* p_cond,
                                         tBTM_BLE_PF_CFG_CBACK cb) {
  tBTM_BLE_PF_LOCAL_NAME_COND* p_local_name =
      (p_cond == NULL) ? NULL : &p_cond->local_name;
  uint8_t param[BTM_BLE_PF_STR_LEN_MAX + BTM_BLE_ADV_FILT_META_HDR_LENGTH],
      *p = param, len = BTM_BLE_ADV_FILT_META_HDR_LENGTH;
  tBTM_STATUS st = BTM_ILLEGAL_VALUE;

  memset(param, 0, BTM_BLE_PF_STR_LEN_MAX + BTM_BLE_ADV_FILT_META_HDR_LENGTH);

  UINT8_TO_STREAM(p, BTM_BLE_META_PF_LOCAL_NAME);
  UINT8_TO_STREAM(p, action);

  /* Filter index */
  UINT8_TO_STREAM(p, filt_index);

  if (BTM_BLE_SCAN_COND_ADD == action || BTM_BLE_SCAN_COND_DELETE == action) {
    if (NULL == p_local_name) return st;

    if (p_local_name->data_len > BTM_BLE_PF_STR_LEN_MAX)
      p_local_name->data_len = BTM_BLE_PF_STR_LEN_MAX;

    ARRAY_TO_STREAM(p, p_local_name->p_data, p_local_name->data_len);
    len += p_local_name->data_len;
  }

  /* send local name filter */
  btu_hcif_send_cmd_with_cb(
      FROM_HERE, HCI_BLE_ADV_FILTER_OCF, param, len,
      base::Bind(&btm_flt_update_cb, BTM_BLE_META_PF_LOCAL_NAME, cb));

  memset(&btm_ble_adv_filt_cb.cur_filter_target, 0, sizeof(tBLE_BD_ADDR));
  return BTM_CMD_STARTED;
}

/*******************************************************************************
 *
 * Function         btm_ble_update_srvc_data_change
 *
 * Description      this function update(add/remove) service data change filter.
 *
 *
 * Returns          BTM_SUCCESS if sucessful,
 *                  BTM_ILLEGAL_VALUE if paramter is not valid.
 *
4
******************************************************************************/
tBTM_STATUS btm_ble_update_srvc_data_change(tBTM_BLE_SCAN_COND_OP action,
                                            tBTM_BLE_PF_FILT_INDEX filt_index,
                                            tBTM_BLE_PF_COND_PARAM* p_cond) {
  tBTM_STATUS st = BTM_ILLEGAL_VALUE;
  tBLE_BD_ADDR* p_bd_addr = p_cond ? &p_cond->target_addr : NULL;
  uint8_t num_avail = (action == BTM_BLE_SCAN_COND_ADD) ? 0 : 1;

  if (btm_ble_cs_update_pf_counter(action, BTM_BLE_PF_SRVC_DATA, p_bd_addr,
                                   num_avail) != BTM_BLE_INVALID_COUNTER)
    st = BTM_SUCCESS;

  return st;
}

/*******************************************************************************
 *
 * Function         btm_ble_update_pf_manu_data
 *
 * Description      this function update(add,delete or clear) the adv
 *                  manufacturer data filtering condition.
 *
 *
 * Returns          BTM_SUCCESS if sucessful,
 *                  BTM_ILLEGAL_VALUE if paramter is not valid.
 *
 ******************************************************************************/
tBTM_STATUS btm_ble_update_pf_manu_data(tBTM_BLE_SCAN_COND_OP action,
                                        tBTM_BLE_PF_FILT_INDEX filt_index,
                                        tBTM_BLE_PF_COND_PARAM* p_data,
                                        tBTM_BLE_PF_COND_TYPE cond_type,
                                        tBTM_BLE_PF_CFG_CBACK cb) {
  if (!p_data) return BTM_ILLEGAL_VALUE;

  tBTM_BLE_PF_MANU_COND* p_manu_data = &p_data->manu_data;
  tBTM_BLE_PF_SRVC_PATTERN_COND* p_srvc_data = &p_data->srvc_data;

  int param_len = BTM_BLE_PF_STR_LEN_MAX + BTM_BLE_PF_STR_LEN_MAX +
                  BTM_BLE_ADV_FILT_META_HDR_LENGTH;
  uint8_t len = BTM_BLE_ADV_FILT_META_HDR_LENGTH;

  uint8_t param[param_len];
  memset(param, 0, param_len);

  uint8_t* p = param;
  if (BTM_BLE_PF_SRVC_DATA_PATTERN == cond_type) {
    UINT8_TO_STREAM(p, BTM_BLE_META_PF_SRVC_DATA);
  } else {
    UINT8_TO_STREAM(p, BTM_BLE_META_PF_MANU_DATA);
  }

  UINT8_TO_STREAM(p, action);
  UINT8_TO_STREAM(p, filt_index);

  if (BTM_BLE_SCAN_COND_ADD == action || BTM_BLE_SCAN_COND_DELETE == action) {
    if (BTM_BLE_PF_SRVC_DATA_PATTERN == cond_type) {
      if (NULL == p_srvc_data) return BTM_ILLEGAL_VALUE;
      if (p_srvc_data->data_len > (BTM_BLE_PF_STR_LEN_MAX - 2))
        p_srvc_data->data_len = (BTM_BLE_PF_STR_LEN_MAX - 2);

      if (p_srvc_data->data_len > 0) {
        ARRAY_TO_STREAM(p, p_srvc_data->p_pattern, p_srvc_data->data_len);
        len += (p_srvc_data->data_len);
        ARRAY_TO_STREAM(p, p_srvc_data->p_pattern_mask, p_srvc_data->data_len);
      }

      len += (p_srvc_data->data_len);
      BTM_TRACE_DEBUG("Service data length: %d", len);
    } else {
      if (NULL == p_manu_data) {
        BTM_TRACE_ERROR("%s: No manuf data", __func__);
        return BTM_ILLEGAL_VALUE;
      }
      BTM_TRACE_EVENT("%s: length: %d", __func__, p_manu_data->data_len);
      if (p_manu_data->data_len > (BTM_BLE_PF_STR_LEN_MAX - 2))
        p_manu_data->data_len = (BTM_BLE_PF_STR_LEN_MAX - 2);

      UINT16_TO_STREAM(p, p_manu_data->company_id);
      if (p_manu_data->data_len > 0 && p_manu_data->p_pattern_mask != NULL) {
        ARRAY_TO_STREAM(p, p_manu_data->p_pattern, p_manu_data->data_len);
        len += (p_manu_data->data_len + 2);
      } else
        len += 2;

      if (p_manu_data->company_id_mask != 0) {
        UINT16_TO_STREAM(p, p_manu_data->company_id_mask);
      } else {
        memset(p, 0xff, 2);
        p += 2;
      }
      len += 2;

      if (p_manu_data->data_len > 0 && p_manu_data->p_pattern_mask != NULL) {
        ARRAY_TO_STREAM(p, p_manu_data->p_pattern_mask, p_manu_data->data_len);
        len += (p_manu_data->data_len);
      }

      BTM_TRACE_DEBUG("Manuf data length: %d", len);
    }
  }

  uint8_t expected_ocf = btm_ble_condtype_to_ocf(cond_type);
  btu_hcif_send_cmd_with_cb(FROM_HERE, HCI_BLE_ADV_FILTER_OCF, param, len,
                            base::Bind(&btm_flt_update_cb, expected_ocf, cb));

  memset(&btm_ble_adv_filt_cb.cur_filter_target, 0, sizeof(tBLE_BD_ADDR));
  return BTM_CMD_STARTED;
}

/*******************************************************************************
 *
 * Function         btm_ble_cs_update_pf_counter
 *
 * Description      this function is to update the adv data payload filter
 *                  counter
 *
 * Returns          current number of the counter; BTM_BLE_INVALID_COUNTER if
 *                  counter update failed.
 *
 ******************************************************************************/
uint8_t btm_ble_cs_update_pf_counter(tBTM_BLE_SCAN_COND_OP action,
                                     uint8_t cond_type, tBLE_BD_ADDR* p_bd_addr,
                                     uint8_t num_available) {
  tBTM_BLE_PF_COUNT* p_addr_filter = NULL;
  uint8_t* p_counter = NULL;

  btm_ble_obtain_vsc_details();

  if (cond_type > BTM_BLE_PF_TYPE_ALL) {
    BTM_TRACE_ERROR("unknown PF filter condition type %d", cond_type);
    return BTM_BLE_INVALID_COUNTER;
  }

  /* for these three types of filter, always generic */
  if (BTM_BLE_PF_ADDR_FILTER == cond_type ||
      BTM_BLE_PF_MANU_DATA == cond_type || BTM_BLE_PF_LOCAL_NAME == cond_type ||
      BTM_BLE_PF_SRVC_DATA_PATTERN == cond_type)
    p_bd_addr = NULL;

  if ((p_addr_filter = btm_ble_find_addr_filter_counter(p_bd_addr)) == NULL &&
      BTM_BLE_SCAN_COND_ADD == action) {
    p_addr_filter = btm_ble_alloc_addr_filter_counter(p_bd_addr->bda);
  }

  if (NULL != p_addr_filter) {
    /* all filter just cleared */
    if ((BTM_BLE_PF_TYPE_ALL == cond_type &&
         BTM_BLE_SCAN_COND_CLEAR == action) ||
        /* or bd address filter been deleted */
        (BTM_BLE_PF_ADDR_FILTER == cond_type &&
         (BTM_BLE_SCAN_COND_DELETE == action ||
          BTM_BLE_SCAN_COND_CLEAR == action))) {
      btm_ble_dealloc_addr_filter_counter(p_bd_addr, cond_type);
    }
    /* if not feature selection, update new addition/reduction of the filter
       counter */
    else if (cond_type != BTM_BLE_PF_TYPE_ALL) {
      p_counter = p_addr_filter->pf_counter;
      if (num_available > 0) p_counter[cond_type] += 1;

      BTM_TRACE_DEBUG("counter = %d, maxfilt = %d, num_avbl=%d",
                      p_counter[cond_type], cmn_ble_vsc_cb.max_filter,
                      num_available);
      return p_counter[cond_type];
    }
  } else {
    BTM_TRACE_ERROR("no matching filter counter found");
  }
  /* no matching filter located and updated */
  return BTM_BLE_INVALID_COUNTER;
}

/*******************************************************************************
 *
 * Function         btm_ble_update_addr_filter
 *
 * Description      this function updates(adds, deletes or clears) the address
 *                  filter of adv.
 *
 *
 * Returns          BTM_CMD_STARTED if sucessful,
 *                  BTM_ILLEGAL_VALUE if paramter is not valid.
 *
 ******************************************************************************/
tBTM_STATUS btm_ble_update_addr_filter(tBTM_BLE_SCAN_COND_OP action,
                                       tBTM_BLE_PF_FILT_INDEX filt_index,
                                       tBTM_BLE_PF_COND_PARAM* p_cond,
                                       tBTM_BLE_PF_CFG_CBACK cb) {
  const uint8_t len = BTM_BLE_ADV_FILT_META_HDR_LENGTH + BTM_BLE_META_ADDR_LEN;
  uint8_t param[len], *p = param;
  tBLE_BD_ADDR* p_addr = (p_cond == NULL) ? NULL : &p_cond->target_addr;

  memset(param, 0, len);

  UINT8_TO_STREAM(p, BTM_BLE_META_PF_ADDR);
  UINT8_TO_STREAM(p, action);

  /* Filter index */
  UINT8_TO_STREAM(p, filt_index);

  if (BTM_BLE_SCAN_COND_ADD == action || BTM_BLE_SCAN_COND_DELETE == action) {
    if (NULL == p_addr) return BTM_ILLEGAL_VALUE;

    BDADDR_TO_STREAM(p, p_addr->bda);
    UINT8_TO_STREAM(p, p_addr->type);
  }

  /* send address filter */
  btu_hcif_send_cmd_with_cb(
      FROM_HERE, HCI_BLE_ADV_FILTER_OCF, param, len,
      base::Bind(&btm_flt_update_cb, BTM_BLE_META_PF_ADDR, cb));

  memset(&btm_ble_adv_filt_cb.cur_filter_target, 0, sizeof(tBLE_BD_ADDR));
  return BTM_CMD_STARTED;
}

/*******************************************************************************
 *
 * Function         btm_ble_update_uuid_filter
 *
 * Description      this function updates(adds, deletes or clears) the service
 *                  UUID filter.
 *
 *
 * Returns          BTM_CMD_STARTED if sucessful,
 *                  BTM_ILLEGAL_VALUE if paramter is not valid.
 *
 ******************************************************************************/
tBTM_STATUS btm_ble_update_uuid_filter(tBTM_BLE_SCAN_COND_OP action,
                                       tBTM_BLE_PF_FILT_INDEX filt_index,
                                       tBTM_BLE_PF_COND_TYPE filter_type,
                                       tBTM_BLE_PF_COND_PARAM* p_cond,
                                       tBTM_BLE_PF_CFG_CBACK cb) {
  uint8_t param[BTM_BLE_META_UUID_LEN + BTM_BLE_ADV_FILT_META_HDR_LENGTH],
      *p = param, len = BTM_BLE_ADV_FILT_META_HDR_LENGTH;
  tBTM_BLE_PF_UUID_COND* p_uuid_cond;
  uint8_t evt_type;

  memset(param, 0, BTM_BLE_META_UUID_LEN + BTM_BLE_ADV_FILT_META_HDR_LENGTH);

  if (BTM_BLE_PF_SRVC_UUID == filter_type) {
    evt_type = BTM_BLE_META_PF_UUID;
    p_uuid_cond = p_cond ? &p_cond->srvc_uuid : NULL;
  } else {
    evt_type = BTM_BLE_META_PF_SOL_UUID;
    p_uuid_cond = p_cond ? &p_cond->solicitate_uuid : NULL;
  }

  if (NULL == p_uuid_cond && action != BTM_BLE_SCAN_COND_CLEAR) {
    BTM_TRACE_ERROR("Illegal param for add/delete UUID filter");
    return BTM_ILLEGAL_VALUE;
  }

  /* need to add address filter first, if adding per bda UUID filter without
   * address filter */
  if (BTM_BLE_SCAN_COND_ADD == action && NULL != p_uuid_cond &&
      p_uuid_cond->p_target_addr &&
      btm_ble_find_addr_filter_counter(p_uuid_cond->p_target_addr) == NULL) {
    UINT8_TO_STREAM(p, BTM_BLE_META_PF_ADDR);
    UINT8_TO_STREAM(p, action);

    /* Filter index */
    UINT8_TO_STREAM(p, filt_index);

    BDADDR_TO_STREAM(p, p_uuid_cond->p_target_addr->bda);
    UINT8_TO_STREAM(p, p_uuid_cond->p_target_addr->type);

    tBTM_BLE_PF_CFG_CBACK fDoNothing;
    /* send address filter */
    btu_hcif_send_cmd_with_cb(
        FROM_HERE, HCI_BLE_ADV_FILTER_OCF, param,
        (uint8_t)(BTM_BLE_ADV_FILT_META_HDR_LENGTH + BTM_BLE_META_ADDR_LEN),
        base::Bind(&btm_flt_update_cb, BTM_BLE_META_PF_ADDR, fDoNothing));
    BTM_TRACE_DEBUG("Updated Address filter");
  }

  p = param;
  UINT8_TO_STREAM(p, evt_type);
  UINT8_TO_STREAM(p, action);

  /* Filter index */
  UINT8_TO_STREAM(p, filt_index);

  if ((BTM_BLE_SCAN_COND_ADD == action || BTM_BLE_SCAN_COND_DELETE == action) &&
      NULL != p_uuid_cond) {
    if (p_uuid_cond->uuid.len == LEN_UUID_16) {
      UINT16_TO_STREAM(p, p_uuid_cond->uuid.uu.uuid16);
      len += LEN_UUID_16;
    } else if (p_uuid_cond->uuid.len == LEN_UUID_32) /*4 bytes */
    {
      UINT32_TO_STREAM(p, p_uuid_cond->uuid.uu.uuid32);
      len += LEN_UUID_32;
    } else if (p_uuid_cond->uuid.len == LEN_UUID_128) {
      ARRAY_TO_STREAM(p, p_uuid_cond->uuid.uu.uuid128, LEN_UUID_128);
      len += LEN_UUID_128;
    } else {
      BTM_TRACE_ERROR("illegal UUID length: %d", p_uuid_cond->uuid.len);
      return BTM_ILLEGAL_VALUE;
    }

    if (NULL != p_uuid_cond->p_uuid_mask) {
      if (p_uuid_cond->uuid.len == LEN_UUID_16) {
        UINT16_TO_STREAM(p, p_uuid_cond->p_uuid_mask->uuid16_mask);
        len += LEN_UUID_16;
      } else if (p_uuid_cond->uuid.len == LEN_UUID_32) /*4 bytes */
      {
        UINT32_TO_STREAM(p, p_uuid_cond->p_uuid_mask->uuid32_mask);
        len += LEN_UUID_32;
      } else if (p_uuid_cond->uuid.len == LEN_UUID_128) {
        ARRAY_TO_STREAM(p, p_uuid_cond->p_uuid_mask->uuid128_mask,
                        LEN_UUID_128);
        len += LEN_UUID_128;
      }
    } else {
      memset(p, 0xff, p_uuid_cond->uuid.len);
      len += p_uuid_cond->uuid.len;
    }
    BTM_TRACE_DEBUG("%s : %d, %d, %d, %d", __func__, filter_type, evt_type,
                    p_uuid_cond->uuid.len, len);
  }

  /* send UUID filter update */
  btu_hcif_send_cmd_with_cb(FROM_HERE, HCI_BLE_ADV_FILTER_OCF, param, len,
                            base::Bind(&btm_flt_update_cb, evt_type, cb));

  if (p_uuid_cond && p_uuid_cond->p_target_addr)
    memcpy(&btm_ble_adv_filt_cb.cur_filter_target, p_uuid_cond->p_target_addr,
           sizeof(tBLE_BD_ADDR));
  else
    memset(&btm_ble_adv_filt_cb.cur_filter_target, 0, sizeof(tBLE_BD_ADDR));

  return BTM_CMD_STARTED;
}

/*******************************************************************************
 *
 * Function         btm_ble_clear_scan_pf_filter
 *
 * Description      clear all adv payload filter by de-selecting all the adv pf
 *                  feature bits
 *
 *
 * Returns          BTM_CMD_STARTED if sucessful,
 *                  BTM_ILLEGAL_VALUE if paramter is not valid.
 *
 ******************************************************************************/
tBTM_STATUS btm_ble_clear_scan_pf_filter(tBTM_BLE_SCAN_COND_OP action,
                                         tBTM_BLE_PF_FILT_INDEX filt_index,
                                         tBTM_BLE_PF_COND_PARAM* p_cond,
                                         tBTM_BLE_PF_CFG_CBACK cb) {
  tBLE_BD_ADDR* p_target = (p_cond == NULL) ? NULL : &p_cond->target_addr;
  tBTM_BLE_PF_COUNT* p_bda_filter;
  uint8_t param[20], *p;

  if (BTM_BLE_SCAN_COND_CLEAR != action) {
    BTM_TRACE_ERROR("unable to perform action:%d for generic adv filter type",
                    action);
    return BTM_ILLEGAL_VALUE;
  }

  p = param;
  memset(param, 0, 20);

  p_bda_filter = btm_ble_find_addr_filter_counter(p_target);

  if (NULL == p_bda_filter ||
      /* not a generic filter */
      (p_target != NULL && p_bda_filter)) {
    BTM_TRACE_ERROR(
        "Error: Can not clear filter, No PF filter has been configured!");
    return BTM_WRONG_MODE;
  }

  tBTM_BLE_PF_CFG_CBACK fDoNothing;

  /* clear the general filter entry */
  if (NULL == p_target) {
    /* clear manufactuer data filter */
    btm_ble_update_pf_manu_data(BTM_BLE_SCAN_COND_CLEAR, filt_index, NULL,
                                BTM_BLE_PF_MANU_DATA, fDoNothing);

    /* clear local name filter */
    btm_ble_update_pf_local_name(BTM_BLE_SCAN_COND_CLEAR, filt_index, NULL,
                                 fDoNothing);

    /* update the counter for service data */
    btm_ble_update_srvc_data_change(BTM_BLE_SCAN_COND_CLEAR, filt_index, NULL);

    /* clear UUID filter */
    btm_ble_update_uuid_filter(BTM_BLE_SCAN_COND_CLEAR, filt_index,
                               BTM_BLE_PF_SRVC_UUID, NULL, fDoNothing);

    btm_ble_update_uuid_filter(BTM_BLE_SCAN_COND_CLEAR, filt_index,
                               BTM_BLE_PF_SRVC_SOL_UUID, NULL, fDoNothing);

    /* clear service data filter */
    btm_ble_update_pf_manu_data(BTM_BLE_SCAN_COND_CLEAR, filt_index, NULL,
                                BTM_BLE_PF_SRVC_DATA_PATTERN, fDoNothing);
  }

  /* select feature based on control block settings */
  UINT8_TO_STREAM(p, BTM_BLE_META_PF_FEAT_SEL);
  UINT8_TO_STREAM(p, BTM_BLE_SCAN_COND_CLEAR);

  /* Filter index */
  UINT8_TO_STREAM(p, filt_index);

  /* set PCF selection */
  UINT32_TO_STREAM(p, BTM_BLE_PF_SELECT_NONE);
  /* set logic condition as OR as default */
  UINT8_TO_STREAM(p, BTM_BLE_PF_LOGIC_OR);

  btu_hcif_send_cmd_with_cb(
      FROM_HERE, HCI_BLE_ADV_FILTER_OCF, param,
      (uint8_t)(BTM_BLE_ADV_FILT_META_HDR_LENGTH + BTM_BLE_PF_FEAT_SEL_LEN),
      base::Bind(&btm_flt_update_cb, BTM_BLE_META_PF_FEAT_SEL, cb));

  if (p_target)
    memcpy(&btm_ble_adv_filt_cb.cur_filter_target, p_target,
           sizeof(tBLE_BD_ADDR));
  else
    memset(&btm_ble_adv_filt_cb.cur_filter_target, 0, sizeof(tBLE_BD_ADDR));
  return BTM_CMD_STARTED;
}

/*******************************************************************************
 *
 * Function         BTM_BleAdvFilterParamSetup
 *
 * Description      This function is called to setup the adv data payload filter
 *                  condition.
 *
 * Parameters       action - Type of action to be performed
 *                       filt_index - Filter index
 *                       p_filt_params - Filter parameters
 *                       cb - Callback
 *
 ******************************************************************************/
void BTM_BleAdvFilterParamSetup(
    int action, tBTM_BLE_PF_FILT_INDEX filt_index,
    std::unique_ptr<btgatt_filt_param_setup_t> p_filt_params,
    tBTM_BLE_PF_PARAM_CB cb) {
  tBTM_BLE_PF_COUNT* p_bda_filter = NULL;
  uint8_t len = BTM_BLE_ADV_FILT_META_HDR_LENGTH +
                BTM_BLE_ADV_FILT_FEAT_SELN_LEN + BTM_BLE_ADV_FILT_TRACK_NUM;
  uint8_t param[len], *p;

  if (BTM_SUCCESS != btm_ble_obtain_vsc_details()) {
    cb.Run(0, BTM_BLE_PF_ENABLE, 1 /* BTA_FAILURE */);
    return;
  }

  p = param;
  memset(param, 0, len);
  BTM_TRACE_EVENT("%s", __func__);

  if (BTM_BLE_SCAN_COND_ADD == action) {
    p_bda_filter = btm_ble_find_addr_filter_counter(nullptr);
    if (NULL == p_bda_filter) {
      BTM_TRACE_ERROR("BD Address not found!");
      cb.Run(0, BTM_BLE_PF_ENABLE, 1 /* BTA_FAILURE */);
      return;
    }

    BTM_TRACE_DEBUG("%s : Feat mask:%d", __func__, p_filt_params->feat_seln);
    /* select feature based on control block settings */
    UINT8_TO_STREAM(p, BTM_BLE_META_PF_FEAT_SEL);
    UINT8_TO_STREAM(p, BTM_BLE_SCAN_COND_ADD);

    /* Filter index */
    UINT8_TO_STREAM(p, filt_index);

    /* set PCF selection */
    UINT16_TO_STREAM(p, p_filt_params->feat_seln);
    /* set logic type */
    UINT16_TO_STREAM(p, p_filt_params->list_logic_type);
    /* set logic condition */
    UINT8_TO_STREAM(p, p_filt_params->filt_logic_type);
    /* set RSSI high threshold */
    UINT8_TO_STREAM(p, p_filt_params->rssi_high_thres);
    /* set delivery mode */
    UINT8_TO_STREAM(p, p_filt_params->dely_mode);

    if (0x01 == p_filt_params->dely_mode) {
      /* set onfound timeout */
      UINT16_TO_STREAM(p, p_filt_params->found_timeout);
      /* set onfound timeout count*/
      UINT8_TO_STREAM(p, p_filt_params->found_timeout_cnt);
      /* set RSSI low threshold */
      UINT8_TO_STREAM(p, p_filt_params->rssi_low_thres);
      /* set onlost timeout */
      UINT16_TO_STREAM(p, p_filt_params->lost_timeout);
      /* set num_of_track_entries for firmware greater than L-release version */
      if (cmn_ble_vsc_cb.version_supported > BTM_VSC_CHIP_CAPABILITY_L_VERSION)
        UINT16_TO_STREAM(p, p_filt_params->num_of_tracking_entries);
    }

    if (cmn_ble_vsc_cb.version_supported == BTM_VSC_CHIP_CAPABILITY_L_VERSION)
      len = BTM_BLE_ADV_FILT_META_HDR_LENGTH + BTM_BLE_ADV_FILT_FEAT_SELN_LEN;
    else
      len = BTM_BLE_ADV_FILT_META_HDR_LENGTH + BTM_BLE_ADV_FILT_FEAT_SELN_LEN +
            BTM_BLE_ADV_FILT_TRACK_NUM;

    btu_hcif_send_cmd_with_cb(
        FROM_HERE, HCI_BLE_ADV_FILTER_OCF, param, len,
        base::Bind(&btm_flt_update_cb, BTM_BLE_META_PF_FEAT_SEL, cb));
  } else if (BTM_BLE_SCAN_COND_DELETE == action) {
    /* select feature based on control block settings */
    UINT8_TO_STREAM(p, BTM_BLE_META_PF_FEAT_SEL);
    UINT8_TO_STREAM(p, BTM_BLE_SCAN_COND_DELETE);
    /* Filter index */
    UINT8_TO_STREAM(p, filt_index);

    btu_hcif_send_cmd_with_cb(
        FROM_HERE, HCI_BLE_ADV_FILTER_OCF, param,
        (uint8_t)(BTM_BLE_ADV_FILT_META_HDR_LENGTH),
        base::Bind(&btm_flt_update_cb, BTM_BLE_META_PF_FEAT_SEL, cb));
  } else if (BTM_BLE_SCAN_COND_CLEAR == action) {
    /* Deallocate all filters here */
    btm_ble_dealloc_addr_filter_counter(NULL, BTM_BLE_PF_TYPE_ALL);

    /* select feature based on control block settings */
    UINT8_TO_STREAM(p, BTM_BLE_META_PF_FEAT_SEL);
    UINT8_TO_STREAM(p, BTM_BLE_SCAN_COND_CLEAR);

    btu_hcif_send_cmd_with_cb(
        FROM_HERE, HCI_BLE_ADV_FILTER_OCF, param,
        (uint8_t)(BTM_BLE_ADV_FILT_META_HDR_LENGTH - 1),
        base::Bind(&btm_flt_update_cb, BTM_BLE_META_PF_FEAT_SEL, cb));
  }
}

void enable_cmpl_cback(tBTM_BLE_PF_STATUS_CBACK p_stat_cback, uint8_t* p,
                       uint16_t evt_len) {
  uint8_t status, op_subcode, action;

  if (evt_len != 3) {
    BTM_TRACE_ERROR("%s: APCF callback length = %d", __func__, evt_len);
    return;
  }

  STREAM_TO_UINT8(status, p);
  STREAM_TO_UINT8(op_subcode, p);
  STREAM_TO_UINT8(action, p);

  if (op_subcode != BTM_BLE_META_PF_ENABLE) {
    BTM_TRACE_ERROR("%s :bad subcode: 0x%02x", __func__, op_subcode);
    return;
  }

  p_stat_cback.Run(action, status);
}

/*******************************************************************************
 *
 * Function         BTM_BleEnableDisableFilterFeature
 *
 * Description      This function is called to enable / disable the APCF feature
 *
 * Parameters       enable: enable or disable the filter condition
 *                  p_stat_cback - Status callback pointer
 *
 ******************************************************************************/
void BTM_BleEnableDisableFilterFeature(uint8_t enable,
                                       tBTM_BLE_PF_STATUS_CBACK p_stat_cback) {
  if (BTM_SUCCESS != btm_ble_obtain_vsc_details()) {
    if (p_stat_cback) p_stat_cback.Run(BTM_BLE_PF_ENABLE, 1 /* BTA_FAILURE */);
    return;
  }

  uint8_t param[20];
  memset(param, 0, 20);

  uint8_t* p = param;
  UINT8_TO_STREAM(p, BTM_BLE_META_PF_ENABLE);
  UINT8_TO_STREAM(p, enable);

  btu_hcif_send_cmd_with_cb(FROM_HERE, HCI_BLE_ADV_FILTER_OCF, param,
                            BTM_BLE_PCF_ENABLE_LEN,
                            base::Bind(&enable_cmpl_cback, p_stat_cback));
}

/*******************************************************************************
 *
 * Function         BTM_BleCfgFilterCondition
 *
 * Description      This function is called to configure the adv data payload
 *                  filter condition.
 *
 * Parameters       action: to read/write/clear
 *                  cond_type: filter condition type.
 *                  filt_index - Filter index
 *                  p_cond: filter condition parameter
 *                  cb  - Config callback
 *
 ******************************************************************************/
void BTM_BleCfgFilterCondition(tBTM_BLE_SCAN_COND_OP action,
                               tBTM_BLE_PF_COND_TYPE cond_type,
                               tBTM_BLE_PF_FILT_INDEX filt_index,
                               tBTM_BLE_PF_COND_PARAM* p_cond,
                               tBTM_BLE_PF_CFG_CBACK cb) {
  BTM_TRACE_EVENT("%s action:%d, cond_type:%d, index:%d", __func__, action,
                  cond_type, filt_index);

  if (BTM_SUCCESS != btm_ble_obtain_vsc_details()) {
    cb.Run(0, BTM_BLE_PF_CONFIG, 1 /*BTA_FAILURE*/);
    return;
  }

  // uint8_t ocf = btm_ble_condtype_to_ocf(cond_type);
  uint8_t st;

  switch (cond_type) {
    /* write service data filter */
    case BTM_BLE_PF_SRVC_DATA_PATTERN:
    /* write manufacturer data filter */
    case BTM_BLE_PF_MANU_DATA:
      st = btm_ble_update_pf_manu_data(action, filt_index, p_cond, cond_type,
                                       cb);
      break;

    /* write local name filter */
    case BTM_BLE_PF_LOCAL_NAME:
      st = btm_ble_update_pf_local_name(action, filt_index, p_cond, cb);
      break;

    /* filter on advertiser address */
    case BTM_BLE_PF_ADDR_FILTER:
      st = btm_ble_update_addr_filter(action, filt_index, p_cond, cb);
      break;

    /* filter on service/solicitated UUID */
    case BTM_BLE_PF_SRVC_UUID:
    case BTM_BLE_PF_SRVC_SOL_UUID:
      st =
          btm_ble_update_uuid_filter(action, filt_index, cond_type, p_cond, cb);
      break;

    case BTM_BLE_PF_SRVC_DATA:
      st = btm_ble_update_srvc_data_change(action, filt_index, p_cond);

      // TODO(jpawlowski): btm_ble_update_srvc_data_change was not scheduling
      // any operation, callback was never called in success case. Must
      // investigeate more if this was bug, or just never used.
      // cb.Run(0, BTM_BLE_PF_CONFIG, 0 /*BTA_SUCCESS */);
      // equivalent of old:
      // ocf = btm_ble_condtype_to_ocf(cond_type);
      // btm_ble_advfilt_enq_op_q(action, ocf, BTM_BLE_FILT_CFG, ref_value,
      //                          p_cmpl_cback, NULL);
      break;

    case BTM_BLE_PF_TYPE_ALL: /* only used to clear filter */
      st = btm_ble_clear_scan_pf_filter(action, filt_index, p_cond, cb);
      break;

    default:
      BTM_TRACE_WARNING("condition type [%d] not supported currently.",
                        cond_type);
      return;
  }

  if (st != BTM_CMD_STARTED) {
    cb.Run(0, BTM_BLE_PF_CONFIG, 1 /*BTA_FAILURE*/);
  }
}

/*******************************************************************************
 *
 * Function         btm_ble_adv_filter_init
 *
 * Description      This function initializes the adv filter control block
 *
 * Parameters
 *
 * Returns          status
 *
 ******************************************************************************/
void btm_ble_adv_filter_init(void) {
  memset(&btm_ble_adv_filt_cb, 0, sizeof(tBTM_BLE_ADV_FILTER_CB));
  if (BTM_SUCCESS != btm_ble_obtain_vsc_details()) return;

  if (cmn_ble_vsc_cb.max_filter > 0) {
    btm_ble_adv_filt_cb.p_addr_filter_count = (tBTM_BLE_PF_COUNT*)osi_malloc(
        sizeof(tBTM_BLE_PF_COUNT) * cmn_ble_vsc_cb.max_filter);
  }
}

/*******************************************************************************
 *
 * Function         btm_ble_adv_filter_cleanup
 *
 * Description      This function de-initializes the adv filter control block
 *
 * Parameters
 *
 * Returns          status
 *
 ******************************************************************************/
void btm_ble_adv_filter_cleanup(void) {
  osi_free_and_reset((void**)&btm_ble_adv_filt_cb.p_addr_filter_count);
}
