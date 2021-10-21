/******************************************************************************
 *  Copyright (c) 2020, The Linux Foundation. All rights reserved.
 *
 *****************************************************************************/

/******************************************************************************
 *
 *  This file contains the CSIP Client supporting functions
 *
 ******************************************************************************/

#include <log/log.h>
#include <string.h>
#include <stdio.h>

#include <vector>

#include "bta_csip_api.h"
#include "bta_csip_int.h"
#include "bta_gatt_queue.h"

#include "osi/include/config.h"
#include "btif/include/btif_config.h"
#include "stack/crypto_toolbox/crypto_toolbox.h"

/* CSIS Characteristic descriptors handles */
#define CSIP_CCCD_UUID_VAL 0x2902
Uuid CSIP_CCCD_UUID = Uuid::From16Bit(CSIP_CCCD_UUID_VAL);

/*******************************************************************************
 *
 * Function         bta_csip_validate_set_params
 *
 * Description      Validates if set id and its members are valid
 *
 * Returns          bool. true - if details are valid otherwise false.
 *
 ******************************************************************************/
bool bta_csip_validate_set_params(tBTA_SET_LOCK_PARAMS* lock_req) {
  std::vector<tBTA_CSIP_CSET> *csets = &bta_csip_cb.csets;
  tBTA_CSIP_CSET cset;
  bool is_valid_set = false;

  std::vector<tBTA_CSIP_CSET>::iterator itr;
  for (itr = csets->begin(); itr != csets->end(); ++itr) {
    if (lock_req->set_id == itr->set_id) {
      cset = *itr;
      is_valid_set = true;
      break;
    }
  }

  if (!is_valid_set) {
    LOG(ERROR) << __func__ << ": Invalid Set ID = " << +lock_req->set_id;
    //TODO: Give Invalid parameters callback
    return (false);
  }

  std::vector<RawAddress> req_members = lock_req->members_addr;
    // TODO: if requested set members size = 0, return true
  if ((int)lock_req->members_addr.size() == 0) {
    LOG(INFO) << __func__<< " Lock of All Set Memebers is requested";
    return (true);
  }

  std::vector<RawAddress> set_members = cset.set_members;
  int members_matched = 0;
  for (int i = 0; i < (int)req_members.size(); i++) {
    for (int j = 0; j < (int)set_members.size(); j++) {
      if (req_members[i] == set_members[j]) {
        members_matched++;
        break;
      }
    }
  }
  LOG(INFO) << "set members matched count = " << +members_matched; //debug
  if (members_matched != (int)req_members.size()) {
    LOG(ERROR) << __func__ << " Incorrect Set members provided";
    return (false);
  }

  return (true);
}

/*******************************************************************************
 *
 * Function         bta_csip_is_valid_lock_request
 *
 * Description      Validates lock request parameters received
 *
 * Returns          bool. true - if details are valid otherwise false.
 *
 ******************************************************************************/
bool bta_csip_is_valid_lock_request(tBTA_SET_LOCK_PARAMS* lock_req) {
  // validate if correct lock value is provided
  if (lock_req->lock_value != UNLOCK_VALUE && lock_req->lock_value != LOCK_VALUE) {
    LOG(ERROR) << __func__ << ": Invalid Lock Value.";
    return (false);
  }

  // validate set id
  if (!bta_csip_validate_set_params(lock_req)) {
    LOG(INFO) << __func__ << " Invalid params";
    return (false);
  }

  return (true);
}

/*******************************************************************************
 *
 * Function         bta_csip_get_cset_cb
 *
 * Description      Finds coordinated set control block by set_id
 *
 * Returns          tBTA_CSET_CB. NULL - if set is not found.
 *
 ******************************************************************************/
tBTA_CSET_CB* bta_csip_get_cset_cb_by_id (uint8_t set_id) {
  int i;
  tBTA_CSET_CB* cset_cb = &bta_csip_cb.csets_cb[0];

  for (i = 0; i < BTA_MAX_SUPPORTED_SETS; i++, cset_cb++) {
    if ((cset_cb->in_use) && (cset_cb->set_id == set_id)) {
      return (cset_cb);
    }
  }

  /* no match found */
  return (NULL);
}

/*******************************************************************************
 *
 * Function         bta_csip_get_cset_cb
 *
 * Description      Creates new coordinated set control block with next available
 *                  set id.
 *
 * Returns          tBTA_CSET_CB. NULL - if no resources are available for set.
 *
 ******************************************************************************/
tBTA_CSET_CB* bta_csip_get_cset_cb () {
  int i;
  tBTA_CSET_CB* cset_cb = &bta_csip_cb.csets_cb[0];

  for (i = 0; i < BTA_MAX_SUPPORTED_SETS; i++, cset_cb++) {
    if (!cset_cb->in_use) {
      cset_cb->set_id = i;
      cset_cb->in_use = true;
      return (cset_cb);
    }
  }

  LOG(ERROR) << __func__ << " No resource available for Coordinated set";
  return (NULL);
}

/********************************************************************************
 *
 * Function         bta_csip_is_app_reg
 *
 * Description      Utility function to check if app_id is valid and registered.
 *
 * Returns          true - if reistered.
 *                  false - if invalid app id or its not registered.
 *
 *******************************************************************************/
bool bta_csip_is_app_reg(uint8_t app_id) {
  if (app_id >= BTA_CSIP_MAX_SUPPORTED_APPS) {
    return (false);
  }

  if (bta_csip_cb.app_rcb[app_id].in_use) {
    return (true);
  }

  return (false);
}

/********************************************************************************
 *
 * Function         bta_csip_get_rcb
 *
 * Description      Utility function to check if app_id is valid and registered.
 *
 * Returns          registration control block. NULL if not in use.
 *
 *******************************************************************************/
tBTA_CSIP_RCB* bta_csip_get_rcb (uint8_t app_id) {
  if (app_id >= BTA_CSIP_MAX_SUPPORTED_APPS) {
    return (NULL);
  }

  if (bta_csip_cb.app_rcb[app_id].in_use) {
    return (&bta_csip_cb.app_rcb[app_id]);
  }

  return (NULL);
}

/*******************************************************************************
 *
 * Function         bta_csip_get_coordinated_set
 *
 * Description      Creates new coordinated set control block
 *
 * Returns          tBTA_CSIP_CSET for valid set_id.
 *                  Empty set with INVALID_SET_ID if not found.
 *
 ******************************************************************************/
tBTA_CSIP_CSET bta_csip_get_coordinated_set (uint8_t set_id) {
  for (tBTA_CSIP_CSET cset: bta_csip_cb.csets) {
    if (cset.set_id == set_id) {
      return cset;
    }
  }

  LOG(ERROR) << __func__ << "Coordinated set not found for set_id: " << +set_id;
  tBTA_CSIP_CSET cset = {.set_id = INVALID_SET_ID,
                         .size = 0
                        };
  return cset;
 }

/******************************************************************************
 *
 * Function         bta_csip_update_set_member
 *
 * Description      Updates set member in the given set.
 *
 * Returns          bool (true, if added successfully. Otherwise, false.)
 *
 ******************************************************************************/
bool bta_csip_update_set_member (uint8_t set_id, RawAddress addr) {
  for (tBTA_CSIP_CSET& cset: bta_csip_cb.csets) {
    if (cset.set_id == set_id) {
      if (cset.set_members.size() == cset.size) {
        LOG(ERROR) << __func__ << " All Set members already discovered.";
        return false;
      }
      cset.set_members.push_back(addr);
      return true;
    }
  }

  LOG(ERROR) << __func__ << "Coordinated set not found for set_id: " << +set_id;
  return false;
}

/*******************************************************************************
 *
 * Function         bta_csip_remove_set_member
 *
 * Description      Removes set member from given coordinated set after unpairing.
 *                  If its the last set member in set, coordinated set is deleted.
 *
 * Returns          void
 *
 ******************************************************************************/
void bta_csip_remove_set_member (RawAddress addr) {
  LOG(INFO) << __func__ << " Device = " << addr.ToString();
  bool is_device_found = false;

  btif_config_remove(addr.ToString().c_str(), "DGroup");
  tBTA_CSIP_DEV_CB* p_cb = bta_csip_find_dev_cb_by_bda(addr);
  if (!p_cb) {
    APPL_TRACE_DEBUG("%s: Set Member not found", __func__);
    return;
  }

  tBTA_CSIS_SRVC_INFO* srvc = &p_cb->csis_srvc[0];
  for (int i = 0; i < MAX_SUPPORTED_SETS_PER_DEVICE && !is_device_found; i++, srvc++) {
    if (!srvc->in_use) continue;
    for (tBTA_CSIP_CSET& cset: bta_csip_cb.csets) {
      if (cset.set_id == srvc->set_id) {
        //std::remove(cset.set_members.begin(), cset.set_members.end(), addr);
        cset.set_members.erase(
          std::remove_if(cset.set_members.begin(), cset.set_members.end(),
                         [&](RawAddress const & bdaddr) {
            return bdaddr == addr;
        }),
        cset.set_members.end());
        is_device_found = true;
        LOG(INFO) << __func__ << " Size = " << +(int)cset.set_members.size();
        if (cset.set_members.empty()) {
          tBTA_CSET_CB* cset_cb = bta_csip_get_cset_cb_by_id(cset.set_id);
          if (cset_cb) {
            LOG(INFO) << __func__ << " Invalidating set. Last member unpaired.";
            cset_cb->in_use = false;
            cset_cb->set_id = INVALID_SET_ID;
            cset.set_members.clear();
            bta_csip_cb.csets.erase(
              std::remove_if(bta_csip_cb.csets.begin(),
                  bta_csip_cb.csets.end(), [&](tBTA_CSIP_CSET& cs) {
                return cs.set_id == srvc->set_id;
            }),
            bta_csip_cb.csets.end());
          }
        }
        break;
      }
    }
  }

  bta_csip_cb.dev_cb.erase(
        std::remove_if(bta_csip_cb.dev_cb.begin(), bta_csip_cb.dev_cb.end(),
                       [&](tBTA_CSIP_DEV_CB const &dev_cb) {
            return dev_cb.addr == addr;
        }),
        bta_csip_cb.dev_cb.end());
}

/*******************************************************************************
 *
 * Function         bta_csip_get_or_create_cset
 *
 * Description      API used to create Coordinated Set Control block.
 *
 * Returns          void
 *
 ******************************************************************************/
tBTA_CSIP_CSET* bta_csip_get_or_create_cset (uint8_t set_id, bool existing) {
  /*std::find_if(bta_csip_cb.csets.begin(), bta_csip_cb.csets.end(),
               [&set_id](const tBTA_CSIP_CSET& set) {
                 return set.set_id == set_id;
               });*/

  for (tBTA_CSIP_CSET& cset: bta_csip_cb.csets) {
    if (cset.set_id == set_id) {
      return &cset;
    }
  }

  if (existing) return NULL;

  /* Create a new set with invalid set_id*/
  tBTA_CSIP_CSET cset = {.set_id = INVALID_SET_ID,
                         .size = 0
                        };
  bta_csip_cb.csets.push_back(cset);
  return &bta_csip_cb.csets.back();
}

/*******************************************************************************
 *
 * Function         bta_csip_find_set_id_by_sirk
 *
 * Description      Finds Coordinated set control block by sirk
 *
 * Returns          set_id if SIRK is found
 *                  otherwise, INVALID_SET_ID
 *
 ******************************************************************************/
uint8_t bta_csip_find_set_id_by_sirk (uint8_t* sirk) {
  int i = 0;
  tBTA_CSET_CB* csets = &bta_csip_cb.csets_cb[0];

  for (i = 0; i < BTA_MAX_SUPPORTED_SETS; i++, csets++) {
    if (csets->in_use) {
      // compare SIRK's
      if (!memcmp(sirk, csets->sirk, SIRK_SIZE)) {
        return csets->set_id;
      }
    }
  }

  return INVALID_SET_ID;
}


/*******************************************************************************
 *
 * Function         bta_csip_get_cset_cb
 *
 * Description      Finds coordinated set control block by set_id
 *
 * Returns          tBTA_CSET_CB. NULL - if set is not found.
 *
 ******************************************************************************/
tBTA_CSIS_SRVC_INFO* bta_csip_get_csis_instance(tBTA_CSIP_DEV_CB* dev_cb,
                                                       uint8_t set_id) {
  int i = 0;

  if (!dev_cb) return NULL;

  tBTA_CSIS_SRVC_INFO* srvc = &dev_cb->csis_srvc[0];

  for (i = 0; i < MAX_SUPPORTED_SETS_PER_DEVICE; i++, srvc++) {
    srvc = &dev_cb->csis_srvc[i];
    if ((srvc->in_use) && (srvc->set_id == set_id)) {
      return (srvc);
    }
  }

  /* no match found */
  return (NULL);
}

/*******************************************************************************
 *
 * Function         bta_csip_get_csis_service_cb
 *
 * Description      Creates new coordinated set control block for a given device
 *
 * Returns          tBTA_CSET_CB. NULL if no resources available.
 *
 ******************************************************************************/
tBTA_CSIS_SRVC_INFO* bta_csip_get_csis_service_cb(tBTA_CSIP_DEV_CB* dev_cb) {
  int i = 0;
  tBTA_CSIS_SRVC_INFO* srvc = &dev_cb->csis_srvc[0];

  for (i = 0; i < MAX_SUPPORTED_SETS_PER_DEVICE; i++, srvc++) {
    if (!srvc->in_use) {
      srvc->in_use = true;
      return srvc;
    }
  }

  /* no match found */
  return (NULL);
}

/*******************************************************************************
 *
 * Function         bta_csip_is_csis_supported
 *
 * Description      checks if remote device supports coordinated set
 *
 * Returns          true if supported, otherwise false.
 *
 ******************************************************************************/
bool bta_csip_is_csis_supported(tBTA_CSIP_DEV_CB* dev_cb) {
  int i = 0;
  tBTA_CSIS_SRVC_INFO* srvc = &dev_cb->csis_srvc[0];

  for (i = 0; i < MAX_SUPPORTED_SETS_PER_DEVICE; i++, srvc++) {
    if (srvc->in_use) {
      return true;
    }
  }

  /* no csis instance found */
  return (false);
}

/*******************************************************************************
 *
 * Function         bta_csip_get_csis_service_by_handle
 *
 * Description      Gives CSIS Service Control block by service handle.
 *
 * Returns          CSIS Service control block. Null if not found.
 *
 ******************************************************************************/
tBTA_CSIS_SRVC_INFO* bta_csip_get_csis_service_by_handle(
    tBTA_CSIP_DEV_CB* dev_cb, uint16_t service_handle) {
  int i = 0;
  tBTA_CSIS_SRVC_INFO* srvc = &dev_cb->csis_srvc[0];

  for (i = 0; i < MAX_SUPPORTED_SETS_PER_DEVICE; i++, srvc++) {
    if (srvc->in_use && srvc->service_handle == service_handle) {
      return srvc;
    }
  }

  /* no match found */
  return (NULL);
}

/*******************************************************************************
 *
 * Function         bta_csip_find_csis_srvc_by_lock_handle
 *
 * Description      Gives CSIS Service Control block by lock handle.
 *
 * Returns          CSIS Service control block. Null if not found.
 *
 ******************************************************************************/
tBTA_CSIS_SRVC_INFO* bta_csip_find_csis_srvc_by_lock_handle(
    tBTA_CSIP_DEV_CB* dev_cb, uint16_t lock_handle) {
  int i = 0;
  tBTA_CSIS_SRVC_INFO* srvc = &dev_cb->csis_srvc[0];

  for (i = 0; i < MAX_SUPPORTED_SETS_PER_DEVICE; i++, srvc++) {
    if (srvc->in_use && srvc->lock_handle == lock_handle) {
      return srvc;
    }
  }

  /* no match found */
  return (NULL);

}

/*******************************************************************************
 *
 * Function         bta_csip_is_locked_by_other_apps
 *
 * Description      Checks if set is locked by app other than mentioned one.
 *
 * Returns          true, if locked by other app otherwise false.
 *
 ******************************************************************************/
bool bta_csip_is_locked_by_other_apps(tBTA_CSIS_SRVC_INFO* srvc, uint8_t app_id) {
  std::vector<uint8_t> &lock_applist = srvc->lock_applist;

  for (auto& it : lock_applist) {
    if (it != app_id) {
      return (true);
    }
  }

  return (false);
}

/*******************************************************************************
 *
 * Function         bta_csip_form_set_lock_order
 *
 * Description      Forms order of set members as per rank.
 *
 * Returns          Ordered Set members.
 *
 ******************************************************************************/
std::vector<RawAddress> bta_csip_form_set_lock_order(tBTA_CSET_CB* cset_cb) {
  std::vector<RawAddress> ordered_members;
  std::vector<RawAddress> req_members = cset_cb->cur_lock_req.members_addr;
  std::map<uint8_t, RawAddress> lock_order_map;

  for (int i = 0; i < (int)req_members.size(); i++) {
    // get device control block and corresponding csis service details
    tBTA_CSIP_DEV_CB* dev_cb = bta_csip_find_dev_cb_by_bda(req_members[i]);
    // null checks required
    tBTA_CSIS_SRVC_INFO* srvc =
      bta_csip_get_csis_instance(dev_cb, cset_cb->cur_lock_req.set_id);
    if (srvc) {
      lock_order_map.insert({srvc->rank, req_members[i]});
    }
  }

  for (auto itr: lock_order_map) {
    ordered_members.push_back(itr.second);
  }

  return ordered_members;
}

/*******************************************************************************
 *
 * Function         bta_csip_arrange_set_members_by_order
 *
 * Description      Forms order of set members for LOCK/UNLOCK request.
 *
 * Returns          Ordered set members in vector.
 *
 ******************************************************************************/
std::vector<RawAddress> bta_csip_arrange_set_members_by_order(
    uint8_t set_id, std::vector<RawAddress>& req_sm, bool ascending) {
  LOG(INFO) << __func__;

  std::vector<RawAddress> ordered_req_sm;
  std::vector<RawAddress> set_members =
          bta_csip_get_set_member_by_order(set_id, ascending);

  // Check if all set members are requested
  if ((uint8_t)req_sm.size() == 0) {
    LOG(INFO) << __func__ << " original size = " << +set_members.size();
    return set_members;
  }

  /* LOCK Request Order*/
  for (int i = 0; i < (int)set_members.size(); i++) {
    for (int j = 0; j < (int)req_sm.size(); j++) {
      if (set_members[i] == req_sm[j]) {
        ordered_req_sm.push_back(set_members[i]);
        if (ordered_req_sm.size() == req_sm.size()) {
          return ordered_req_sm;
        }
      }
    }
  }

  return {};
}

/*******************************************************************************
 *
 * Function         bta_csip_arrange_set_members_by_order
 *
 * Description      Forms order of set members for LOCK/UNLOCK request.
 *
 * Returns          Ordered set members in vector.
 *
 ******************************************************************************/
std::vector<RawAddress> bta_csip_get_set_member_by_order(uint8_t set_id,
                                              bool ascending) {
  std::vector<RawAddress> ordered_members;

  tBTA_CSET_CB* cset_cb = &bta_csip_cb.csets_cb[set_id];
  if (!cset_cb->in_use) {
    LOG(ERROR) << __func__ << " Invalid Set for for Set ID: " << +set_id;
    return {};
  }

  if (ascending) {
    for (auto itr: cset_cb->ordered_members) {
       ordered_members.push_back(itr.second);
    }
  } else {
    for (auto i = cset_cb->ordered_members.rbegin();
         i != cset_cb->ordered_members.rend(); ++i) {
      ordered_members.push_back(i->second);
    }
  }

  return ordered_members;
}


/*******************************************************************************
 *
 * Function         bta_csip_is_member_locked_by_app
 *
 * Description      checks if application (app_id) has locked given set.
 *
 * Returns          void.
 ******************************************************************************/
bool bta_csip_is_member_locked_by_app (uint8_t app_id, tBTA_CSIS_SRVC_INFO* srvc) {
  std::vector<uint8_t>& lock_applist = srvc->lock_applist;

  auto it = std::find(lock_applist.begin(), lock_applist.end(), app_id);
  if (it != lock_applist.end()) {
    LOG(INFO) << __func__ << " App Id found in app list";
    return true;
  }

  LOG(INFO) << __func__ << " App Id not found in app list";
  return false;
}

/*******************************************************************************
 *
 * Function         bta_csip_handle_unresponsive_sm_res
 *
 * Description      sends lock response to earlier requesting app.
 *
 * Returns          void.
 ******************************************************************************/
void bta_csip_handle_unresponsive_sm_res(tBTA_CSIS_SRVC_INFO* srvc,
                                         tGATT_STATUS status) {
  LOG(INFO) << __func__ << " Response from unresponsive remote " << srvc->bd_addr.ToString()
                        << " status: " << +status;
  std::vector<uint8_t>& unres_applist = srvc->unrsp_applist;

  if (status == GATT_SUCCESS) {
    srvc->lock = LOCK_VALUE;
    for (auto& it : unres_applist) {
      LOG(INFO) << __func__ << " Sending GATT_SUCCESS callback to app: " << +it;
      std::vector<RawAddress> sm = {srvc->bd_addr};
      tBTA_LOCK_STATUS_CHANGED res = {.app_id = it, .set_id = srvc->set_id,
                                      .value = 0x02, .addr = sm};
      bta_csip_send_lock_req_cmpl_cb(res);
      // Add app id to the lock applist
      srvc->lock_applist.push_back(it);
    }
  }

  unres_applist.clear();
}

/*******************************************************************************
 *
 * Function         bta_csip_get_next_lock_request
 *
 * Description      Schedules next pending lock request for the given set.
 *
 * Returns          void.
 ******************************************************************************/
void bta_csip_get_next_lock_request(tBTA_CSET_CB* cset_cb) {
  tBTA_SET_LOCK_PARAMS lock_req_params;
  std::queue<tBTA_SET_LOCK_PARAMS>& lock_req_queue = cset_cb->lock_req_queue;

  if  (lock_req_queue.empty()) {
    LOG(INFO) << " No pending Lock Request for Set: " << +cset_cb->set_id;
    cset_cb->request_in_progress = false;
    return;
  }

  lock_req_params = lock_req_queue.front();
  lock_req_queue.pop();

  bta_csip_form_lock_request(lock_req_params, cset_cb);
}

/*******************************************************************************
 *
 * Function         bta_csip_find_dev_cb_by_bda
 *
 * Description      Utility function find a device control block by BD address.
 *
 * Returns          tBTA_CSIP_DEV_CB - device control block for a given remote.
 *                  nullptr, if device control block is not present.
 ******************************************************************************/
tBTA_CSIP_DEV_CB* bta_csip_find_dev_cb_by_bda(const RawAddress& bda) {
  /*auto iter = std::find_if(bta_csip_cb.dev_cb.begin(), bta_csip_cb.dev_cb.end(),
                           [&bda](const tBTA_CSIP_DEV_CB& device) {
                             return device.addr == bda;
                           });

  return (iter == bta_csip_cb.dev_cb.end()) ? nullptr : &(*iter);*/
  for (tBTA_CSIP_DEV_CB& p_cb: bta_csip_cb.dev_cb) {
    if (p_cb.addr == bda) {
      return &p_cb;
    }
  }

  return NULL;
}

/*******************************************************************************
 *
 * Function         bta_csip_get_dev_cb_by_cid
 *
 * Description      Utility function find a device control block by gatt conn id.
 *
 * Returns          tBTA_CSIP_DEV_CB (device control block for a given remote.)
 ******************************************************************************/
tBTA_CSIP_DEV_CB* bta_csip_get_dev_cb_by_cid(uint16_t conn_id) {
  auto iter = std::find_if(bta_csip_cb.dev_cb.begin(), bta_csip_cb.dev_cb.end(),
                           [&conn_id](const tBTA_CSIP_DEV_CB& device) {
                             return device.conn_id == conn_id;
                           });

  return (iter == bta_csip_cb.dev_cb.end()) ? nullptr : &(*iter);
}

/*******************************************************************************
 *
 * Function         bta_csip_create_dev_cb_for_bda
 *
 * Description      Utility function find a device control block by BD address.
 *
 * Returns          tBTA_CSIP_DEV_CB (device control block for a given remote.
 ******************************************************************************/
tBTA_CSIP_DEV_CB* bta_csip_create_dev_cb_for_bda(const RawAddress& bda) {
  tBTA_CSIP_DEV_CB p_dev_cb = {};
  p_dev_cb.addr = bda;
  p_dev_cb.in_use = true;

  bta_csip_cb.dev_cb.push_back(p_dev_cb);

  return &bta_csip_cb.dev_cb.back();
}

/************************************************************************************
 *
 * Function         bta_csip_get_cccd_handle
 *
 * Description      Utility function to fetch cccd handle of a given characteristic.
 *
 * Returns          handle of cccd. 0 if not found.
 ************************************************************************************/
uint16_t bta_csip_get_cccd_handle(uint16_t conn_id, uint16_t char_handle) {
    const gatt::Characteristic* p_char =
        BTA_GATTC_GetCharacteristic(conn_id, char_handle);
    if (!p_char) {
      LOG(WARNING) << __func__ << ": Characteristic not found: " << char_handle;
      return 0;
    }

    for (const gatt::Descriptor& desc : p_char->descriptors) {
      if (desc.uuid == CSIP_CCCD_UUID) {
        LOG(INFO) << __func__ << " desc handle = " << +desc.handle;
        return desc.handle;
      }
    }

    return 0;
}

/************************************************************************************
 *
 * Function         bta_csip_add_app_to_applist
 *
 * Description      Utility function adds app to connection applist of a
 *                  given device control block.
 *
 * Returns          void
 ************************************************************************************/
void bta_csip_add_app_to_applist(tBTA_CSIP_DEV_CB* p_cb, uint8_t app_id) {
  if (p_cb && !bta_csip_is_app_from_applist(p_cb, app_id)) {
    LOG(INFO) << __func__ << ": adding app(" << +app_id
                          << ") to connection applist of " << p_cb->addr;
    p_cb->conn_applist.push_back(app_id);
  }
}

/************************************************************************************
 *
 * Function         bta_csip_is_app_from_applist
 *
 * Description      Utility function checks if app is from connection applist of a
 *                  given device control block.
 *
 * Returns          true if app has already sent connect request for CSIP.
 ************************************************************************************/
bool bta_csip_is_app_from_applist(tBTA_CSIP_DEV_CB* p_cb, uint8_t app_id) {
  for (auto i: p_cb->conn_applist) {
    if (i == app_id) {
      return (true);
    }
  }

  return (false);
}

/************************************************************************************
 *
 * Function         bta_csip_remove_app_from_conn_list
 *
 * Description      Utility function to remove application from connection applist of
 *                  given device control block
 *
 * Returns          void
 ************************************************************************************/
void bta_csip_remove_app_from_conn_list(tBTA_CSIP_DEV_CB* p_cb, uint8_t app_id) {
  p_cb->conn_applist.erase(
      std::remove(p_cb->conn_applist.begin(), p_cb->conn_applist.end(), app_id),
                  p_cb->conn_applist.end());
}

/************************************************************************************
 *
 * Function         bta_csip_send_conn_state_changed_cb
 *
 * Description      Utility function to send connection state changed to all
 *                  registered application in connection app list.
 *
 * Returns          void
 ************************************************************************************/
void bta_csip_send_conn_state_changed_cb(tBTA_CSIP_DEV_CB* p_cb,
                                         uint8_t state, uint8_t status) {
  if (!p_cb) {
    LOG(ERROR) << __func__ << ": Device CB for " << p_cb->addr << " not found";
    return;
  }

  // send connection state change to all apps in conn_applist
  for (auto i: p_cb->conn_applist) {
    tBTA_CSIP_CONN_STATE_CHANGED conn_cb_params = {
        .app_id = i,
        .addr = p_cb->addr,
        .state = state,
        .status =status
    };
    if (bta_csip_cb.app_rcb[i].p_cback) {
      (*bta_csip_cb.app_rcb[i].p_cback)
          (BTA_CSIP_CONN_STATE_CHG_EVT, (tBTA_CSIP_DATA *)&conn_cb_params);
    }
  }
}

/************************************************************************************
 *
 * Function         bta_csip_send_conn_state_changed_cb
 *
 * Description      Utility function to send connection state changed to requesting
 *                  registered application from connection applist.
 *
 * Returns          void
 ************************************************************************************/
void bta_csip_send_conn_state_changed_cb (tBTA_CSIP_DEV_CB* p_cb, uint8_t app_id,
                                          uint8_t state, uint8_t status) {

  tBTA_CSIP_CONN_STATE_CHANGED conn_cb_params = {
      .app_id = app_id,
      .addr = p_cb->addr,
      .state = state,
      .status =status
  };

  // send connection state change to the requested App
  if (bta_csip_cb.app_rcb[app_id].p_cback) {
    (*bta_csip_cb.app_rcb[app_id].p_cback)
        (BTA_CSIP_CONN_STATE_CHG_EVT, (tBTA_CSIP_DATA *)&conn_cb_params);
  }

}

/************************************************************************************
 *
 * Function         bta_csip_process_completed_lock_req
 *
 * Description      Utility function to send lock state changed to requesting
 *                  registered application.
 *
 * Returns          void
 ************************************************************************************/
void bta_csip_send_lock_req_cmpl_cb (tBTA_LOCK_STATUS_CHANGED response) {
  if (response.app_id >= BTA_CSIP_MAX_SUPPORTED_APPS ||
          !bta_csip_cb.app_rcb[response.app_id].in_use) {
    LOG(ERROR) << __func__ << "Invalid or unregistered application: " << +response.app_id;
    return;
  }

  if (bta_csip_cb.app_rcb[response.app_id].p_cback) {
    (*bta_csip_cb.app_rcb[response.app_id].p_cback)
        (BTA_CSIP_LOCK_STATUS_CHANGED_EVT, (tBTA_CSIP_DATA *)&response);
  }
}

/************************************************************************************
 *
 * Function         bta_csip_write_cccd
 *
 * Description      API used to write required characteristic descriptor.
 *
 * Returns          void
 ************************************************************************************/
void bta_csip_write_cccd (tBTA_CSIP_DEV_CB* p_cb, uint16_t char_handle,
                          uint16_t cccd_handle) {
      LOG(INFO) << __func__;
      // Register for LOCK
      if (BTA_GATTC_RegisterForNotifications(
              bta_csip_cb.gatt_if, p_cb->addr, char_handle)) {
        LOG(ERROR) << __func__
                   << " Notification Registration failed for char handle: " << +char_handle;
        return;
      }

      LOG(INFO) << __func__ << " notification registration successful. handle: " << +char_handle;
      std::vector<uint8_t> value(2);
      uint8_t* ptr = value.data();
      UINT16_TO_STREAM(ptr, GATT_CHAR_CLIENT_CONFIG_NOTIFICATION);
      BtaGattQueue::WriteDescriptor(p_cb->conn_id, cccd_handle, value,
                                    GATT_WRITE, nullptr, nullptr);
}

/************************************************************************************
 *
 * Function         bta_csip_load_coordinated_sets_from_storage
 *
 * Description      API used to load coordinated sets from storage on BT ON.
 *
 * Returns          void
 ************************************************************************************/
void bta_csip_load_coordinated_sets_from_storage () {
  LOG(INFO) << __func__;

  static const char* CONFIG_FILE_PATH = "/data/misc/bluedroid/bt_config.conf";
  config_t* config = config_new(CONFIG_FILE_PATH);
  if (!config) {
    LOG(INFO) << __func__ << " file "<< CONFIG_FILE_PATH << " not found";
    return;
  }

  const config_section_node_t* snode = config_section_begin(config);
  while (snode != config_section_end(config)) {

    const char* name = config_section_name(snode);
    if (!RawAddress::IsValidAddress(name)) {
      snode = config_section_next(snode);
      continue;
    }

    const char* key = "DGroup";
    const char* coordinated_sets = config_get_string(config, name, key, "");
    if (!strcmp(coordinated_sets, "")) {
      LOG(INFO) << __func__ << " doesnt support cooedinated set.";
      snode = config_section_next(snode);
      continue;
    }

    RawAddress bdaddr;
    RawAddress::FromString(name, bdaddr);
    tBTA_CSIP_DEV_CB* dev_cb = bta_csip_find_dev_cb_by_bda(bdaddr);
    if (!dev_cb) {
      dev_cb = bta_csip_create_dev_cb_for_bda(bdaddr);
    }

    char *next = NULL;
    char *csets = strdup(coordinated_sets);
    /* Set Level parsing*/
    char *set_details = strtok_r(csets, " ", &next);

    do {
      tBTA_CSIP_CSET *cset = NULL;
      uint8_t set_id = INVALID_SET_ID, size = 0, rank = 0;
      uint16_t srvc_handle = 0;
      bluetooth::Uuid uuid;
      uint8_t sirk[SIRK_SIZE] = {};
      bool lock_support = false;

      char *part;
      char *posn;
      /* separating properties of set*/
      part = strtok_r(set_details, "~", &posn);

      while (part != NULL)
      {
          char *ptr = NULL;
          /* Decode property type and its value*/
          char *prop_details = strtok_r(part, ":", &ptr);

          if (prop_details != NULL) {
            char* prop_val = strtok_r(NULL, ":", &ptr);
            if (prop_val) {
              if (!strcmp(prop_details, "SET_ID")) {
                set_id = (uint8_t)atoi(prop_val);
                cset = bta_csip_get_or_create_cset(set_id, true);
                if (!cset) LOG(INFO) << __func__ << " got cset empty";
                else LOG(INFO) << "valid " << +cset->set_id;
              } else if (!strcmp(prop_details, "SIZE")) {
                size = (uint8_t)atoi(prop_val);
              } else if (!strcmp(prop_details, "SIRK")) {
                hex_string_to_byte_arr(prop_val, sirk, SIRK_SIZE * 2);
              } else if (!strcmp(prop_details, "INCLUDING_SRVC")) {
                uuid = Uuid::FromString(prop_val);
              } else if (!strcmp(prop_details, "LOCK_SUPPORT")) {
                if (!strcmp(prop_val, "true")) lock_support = true;
              } else if (!strcmp(prop_details, "RANK")) {
                rank = (uint8_t)atoi(prop_val);
              } else if (!strcmp(prop_details, "SRVC_HANDLE")) {
                srvc_handle = (uint16_t)atoi(prop_val);
              }
            }
          }

          part = strtok_r(NULL, "~", &posn);
      }

      if (set_id < BTA_MAX_SUPPORTED_SETS) {
        if (!cset) {
          // Create new coordinated set insatnce and device to it
          cset = bta_csip_get_or_create_cset(set_id, false);
          cset->set_id = set_id;
          cset->size = size;
          cset->p_srvc_uuid = uuid;
          cset->total_discovered = 1;
          cset->set_members.push_back(bdaddr);

          // create coordinated set control block
          tBTA_CSET_CB* cset_cb = &bta_csip_cb.csets_cb[set_id];
          cset_cb->set_id = set_id;
          cset_cb->in_use = true;
          memcpy(cset_cb->sirk, sirk, SIRK_SIZE);
          if (rank != 0) {
            cset_cb->ordered_members.insert({rank, bdaddr});
          }

        } else {
          //LOG(INFO) << "Existing set = " << +cset->set_id;
          cset->total_discovered++;
          cset->set_members.push_back(bdaddr);

          tBTA_CSET_CB* cset_cb = &bta_csip_cb.csets_cb[set_id];
          if (rank != 0) {
            cset_cb->ordered_members.insert({rank, bdaddr});
          }
        }

        // assign service properties - set_id and bd_addr
        tBTA_CSIS_SRVC_INFO *srvc = bta_csip_get_csis_service_cb(dev_cb);
        if (srvc) {
          srvc->set_id = set_id;
          srvc->bd_addr = bdaddr;
          srvc->size = size;
          srvc->rank = rank;
          srvc->service_handle = srvc_handle;
          memcpy(srvc->sirk, sirk, SIRK_SIZE);
        }
      }
    } while ((set_details = strtok_r(NULL, " ", &next)) != NULL);

    snode = config_section_next(snode);
  }

  /*LOG(INFO) << "------------------DEBUG----------------------------";
  LOG(INFO) << "printing all loaded coordinated sets";
  for (int i = 0; i < (int)bta_csip_cb.csets.size(); i++) {
    tBTA_CSIP_CSET set = bta_csip_cb.csets[i];
    LOG(INFO) << " Set ID = " << +set.set_id
              << " Size = " << +set.size
              << " total discovered = " << +set.total_discovered;
    for (int j = 0; j < (int)set.set_members.size(); j++) {
      LOG(INFO) << " Member (" << +(j+1) <<") = " << set.set_members[j].ToString();
    }
  }*/
}

/************************************************************************************
 *
 * Function         bta_csip_preserve_cset
 *
 * Description      function used to preserve coordinated set details to storage.
 *
 * Returns          void
 ************************************************************************************/
void bta_csip_preserve_cset (tBTA_CSIS_SRVC_INFO* srvc) {
  tBTA_CSIP_DEV_CB* p_cb = bta_csip_find_dev_cb_by_bda(srvc->bd_addr);

  if (!p_cb) {
    LOG(ERROR) << " Device cb record not found for " << srvc->bd_addr;
    return;
  }

  std::string& set_info = p_cb->set_info;
  if (set_info.size() > 0) {
    set_info += " ";
  }

  set_info += "SET_ID:" + std::to_string(srvc->set_id);

  if (srvc->size_handle) {
    set_info += "~SIZE:" + std::to_string(srvc->size);
  }

  char sirk[SIRK_SIZE * 2 + 1] = {0};
  byte_arr_to_hex_string(srvc->sirk, sirk, SIRK_SIZE);
  set_info += "~SIRK:" + std::string(sirk);

  if (!srvc->including_srvc_uuid.IsEmpty()) {
    set_info += "~INCLUDING_SRVC:" + srvc->including_srvc_uuid.ToString();
  }

  if (srvc->lock_handle) {
    set_info += "~LOCK_SUPPORT:" + std::string((srvc->lock_handle ? "true" : "false"));
  }

  if (srvc->rank_handle) {
    set_info += "~RANK:" + std::to_string(srvc->rank);
  }

  set_info += "~SRVC_HANDLE:" + std::to_string(srvc->service_handle);

  LOG(INFO) << __func__ << " " << set_info;

  btif_config_set_str(p_cb->addr.ToString().c_str(),
      "DGroup", set_info.c_str());
}

/************************************************************************************
 *
 * Function         bta_csip_get_salt
 *
 * Description      function s1: Used to compute SALT.
 *
 * Returns          Octet16 (cipher - SALT)
 ************************************************************************************/
Octet16 bta_csip_get_salt() {
  Octet16 salt = {};
  Octet16 zero = {};
  uint8_t SIRKenc[] = {0x53, 0x49, 0x52, 0x4B, 0x65, 0x6E, 0x63};

  salt = bta_csip_get_aes_cmac_result(zero, SIRKenc, 7);

  return salt;
}

/************************************************************************************
 *
 * Function         bta_csip_compute_T
 *
 * Description      First step of k1 function. Used to compute T from SALT and K.
 *
 * Returns          Octet16 (cipher - T)
 ************************************************************************************/
Octet16 bta_csip_compute_T(Octet16 salt, Octet16 K) {
  Octet16 T = {};

  T = bta_csip_get_aes_cmac_result(salt, K);

  return T;
}

/************************************************************************************
 *
 * Function         bta_csip_get_aes_cmac_result
 *
 * Description      Second step of k1 function. Used to compute k1 from T and "csis".
 *
 * Returns          Octet16 (cipher - k1)
 ************************************************************************************/
Octet16 bta_csip_compute_k1(Octet16 T) {
  Octet16 k1 = {};
  uint8_t csis[] = {0x63,0x73,0x69,0x73};

  k1 = bta_csip_get_aes_cmac_result(T, csis, 4);

  return k1;
}

/************************************************************************************
 *
 * Function         bta_csip_get_aes_cmac_result
 *
 * Description      sdf function. Used to compute SIRK from encrypted SIRK and k1.
 *
 * Returns          Octet16 (SIRK)
 ************************************************************************************/
void  bta_csip_get_decrypted_sirk(Octet16 k1, uint8_t *enc_sirk, uint8_t *sirk) {
  for (int i = 0; i < 16; i++) {
    sirk[i] = k1[i] ^ enc_sirk[i];
  }
}

/************************************************************************************
 *
 * Function         bta_csip_get_aes_cmac_result
 *
 * Description      Used to get aes-cmac result (for 16 byte input and output
 *                  in LSB->MSB order)
 *
 * Returns          Octet16 (cipher)
 ************************************************************************************/
Octet16 bta_csip_get_aes_cmac_result(const Octet16& key, const Octet16& message) {
  Octet16 r_key, r_message, r_result;

  // reverse inputs as required by crypto_toolbox::aes_cmac
  std::reverse_copy(key.begin(), key.end(), r_key.begin());
  std::reverse_copy(message.begin(), message.end(), r_message.begin());

  Octet16 result = crypto_toolbox::aes_cmac(r_key, r_message.data(), r_message.size());

  // reverse the result to get LSB->MSB order
  std::reverse_copy(result.begin(), result.end(), r_result.begin());

  return r_result;
}

/************************************************************************************
 *
 * Function         bta_csip_get_aes_cmac_result
 *
 * Description      Used to get aes-cmac result (for variable input and output
 *                  in LSB->MSB order)
 *
 * Returns          Octet16 (cipher)
 ************************************************************************************/
Octet16 bta_csip_get_aes_cmac_result(const Octet16& key, const uint8_t* input,
                                     uint16_t length) {
  Octet16 r_key, r_result;

  // reverse inputs as required by crypto_toolbox::aes_cmac
  std::reverse_copy(key.begin(), key.end(), r_key.begin());
  uint8_t *input_buf = (uint8_t *)osi_malloc(length);
  for (int i = 0; i < length; i++) {
    input_buf[i] = input[length - 1 - i];
  }

  Octet16 result = crypto_toolbox::aes_cmac(r_key, input_buf, length);

  // reverse the result to get LSB->MSB order
  std::reverse_copy(result.begin(), result.end(), r_result.begin());

  return r_result;
}

/************************************************************************************
 *
 * Function         byte_arr_to_hex_string
 *
 * Description      function used to get hex representation in string format for byte[].
 *
 * Returns          void
 ************************************************************************************/
void byte_arr_to_hex_string(uint8_t* byte_arr, char* str, uint8_t len) {
  int i;
  LOG(INFO) << __func__ << " Convert byte array to hex format string";

  for (i = 0; i < len; i++)
  {
      snprintf(str + (i * 2), (len * 2 + 1), "%02X", byte_arr[i]);
  }
}

/************************************************************************************
 *
 * Function         hex_string_to_byte_arr
 *
 * Description      function used to get byte array from hex format string.
 *
 * Returns          void
 ************************************************************************************/
void hex_string_to_byte_arr(char *str, uint8_t* byte_arr, uint8_t len) {
  for (int length = 0; *str; str += 2, length++)
     sscanf(str, "%02hhx", &byte_arr[length]);
}

/************************************************************************************
 *
 * Function         is_key_empty
 *
 * Description      function used to check if key is 0 intialized.
 *
 * Returns          true, if all elements are 0. Otherwise, false.
 ************************************************************************************/
bool is_key_empty(Octet16& key) {
  for (unsigned int i = 0; i < key.size(); i++) {
    if (key[i] != 0) return false;
  }
  return true;
}
