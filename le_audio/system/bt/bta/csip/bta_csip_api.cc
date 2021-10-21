/******************************************************************************
 *  Copyright (c) 2020, The Linux Foundation. All rights reserved.
 *
 *****************************************************************************/

/******************************************************************************
 *
 *  This file contains the CSIP API in the subsystem of BTA.
 *
 ******************************************************************************/

#define LOG_TAG "bt_bta_csip"

#include <base/bind.h>
#include <base/bind_helpers.h>
#include <base/callback.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "bta_csip_api.h"
#include "bta_csip_int.h"
#include "bta_gatt_queue.h"
#include "osi/include/log.h"
#include "osi/include/osi.h"

/*****************************************************************************
 *  Constants
 ****************************************************************************/
static const tBTA_SYS_REG bta_csip_reg = {bta_csip_hdl_event, BTA_CsipDisable};

/*********************************************************************************
 *
 * Function         BTA_RegisterCsipApp
 *
 * Description      This function is called to register application or module to
 *                  to register with CSIP for using CSIP functionalities.
 *
 * Parameters       p_csip_cb: callback to be received in registering app when
 *                             required CSIP operation is completed.
 *                  reg_cb   : callback when app/module is registered with CSIP.
 *
 * Returns          None
 *
 *********************************************************************************/
void BTA_RegisterCsipApp(tBTA_CSIP_CBACK* p_csip_cb,
                              BtaCsipAppRegisteredCb reg_cb) {
  do_in_bta_thread(FROM_HERE, base::Bind(&bta_csip_app_register, Uuid::GetRandom(),
                                         p_csip_cb, std::move(reg_cb)));
}

/*********************************************************************************
 *
 * Function         BTA_UnregisterCsipApp
 *
 * Description      This function is called to unregister application or module.
 *
 * Parameters       app_id: id of the app/module that needs to be unregistered.
 *
 * Returns          None
 *
 *********************************************************************************/

void BTA_UnregisterCsipApp(uint8_t app_id) {
  do_in_bta_thread(FROM_HERE, base::Bind(&bta_csip_app_unregister, app_id));
}

/*********************************************************************************
 *
 * Function         BTA_CsipSetLockValue
 *
 * Description      This function is called to request or release lock for the
 *                  coordinated set.
 *
 * Parameters       lock_param: parameters to acquire or release lock.
 *                                (tBTA_SET_LOCK_PARAMS).
 *
 * Returns          None
 *
 *********************************************************************************/
void BTA_CsipSetLockValue(tBTA_SET_LOCK_PARAMS lock_params) {
  tBTA_CSIP_LOCK_PARAMS* p_buf =
      (tBTA_CSIP_LOCK_PARAMS*)osi_calloc(sizeof(tBTA_CSIP_LOCK_PARAMS));

  p_buf->hdr.event = BTA_CSIP_SET_LOCK_VALUE_EVT;
  p_buf->lock_req = lock_params;

  bta_sys_sendmsg(p_buf);
}

/*********************************************************************************
 *
 * Function         BTA_CsipGetCoordinatedSet
 *
 * Description      This function is called to fetch details of the coordinated set.
 *
 * Parameters       set_id: identifier of the coordinated set whose details are
 *                          required to be fetched.
 *
 * Returns          tBTA_CSIP_CSET (containing details of coordinated set).
 *
 *********************************************************************************/
tBTA_CSIP_CSET BTA_CsipGetCoordinatedSet(uint8_t set_id) {
  APPL_TRACE_DEBUG("%s: set_id = %d", __func__, set_id);
  return bta_csip_get_coordinated_set(set_id);
}

/*********************************************************************************
 *
 * Function         BTA_CsipSetLockValue
 *
 * Description      This function is called to request or release lock for the
 *                  coordinated set.
 *
 * Parameters       None.
 *
 * Returns          vector<tBTIF_CSIP_CSET>: (all discovered coordinated set)
 *
 *********************************************************************************/
std::vector<tBTA_CSIP_CSET> BTA_CsipGetDiscoveredSets() {
  return bta_csip_cb.csets;
}

/*********************************************************************************
 *
 * Function         BTA_CsipConnect
 *
 * Description      This function is called to establish GATT Connection.
 *
 * Parameters       bd_addr : Address of the remote device.
 *
 * Returns          None.
 *
 *********************************************************************************/
void BTA_CsipConnect (uint8_t app_id, const RawAddress& bd_addr) {
  tBTA_CSIP_API_CONN* p_buf =
    (tBTA_CSIP_API_CONN*)osi_calloc(sizeof(tBTA_CSIP_API_CONN));
  p_buf->hdr.event = BTA_CSIP_API_OPEN_EVT;
  p_buf->bd_addr = bd_addr;
  p_buf->app_id = app_id;

  bta_sys_sendmsg(p_buf);
}

/*********************************************************************************
 *
 * Function         BTA_CsipConnect
 *
 * Description      This function is called to establish GATT Connection.
 *
 * Parameters       bd_addr : Address of the remote device.
 *
 * Returns          None.
 *
 *********************************************************************************/
void BTA_CsipDisconnect (uint8_t app_id, const RawAddress& bd_addr) {
  tBTA_CSIP_API_CONN* p_buf =
    (tBTA_CSIP_API_CONN*)osi_calloc(sizeof(tBTA_CSIP_API_CONN));
  p_buf->hdr.event = BTA_CSIP_API_CLOSE_EVT;
  p_buf->bd_addr = bd_addr;
  p_buf->app_id = app_id;

  bta_sys_sendmsg(p_buf);
}

/*********************************************************************************
 *
 * Function         BTA_CsipFindCsisInstance
 *
 * Description      This function is called to find presence of CSIS service on
 *                  remote device.
 *
 * Parameters       coon_id : Connection ID of the GATT Connection at DM Layer.
 *
 * Returns          None.
 *
 *********************************************************************************/
void BTA_CsipFindCsisInstance(uint16_t conn_id, tGATT_STATUS status,
                              RawAddress& bd_addr) {
  APPL_TRACE_DEBUG("%s ", __func__);

  tBTA_CSIP_DISC_SET* p_buf =
    (tBTA_CSIP_DISC_SET*)osi_calloc(sizeof(tBTA_CSIP_DISC_SET));
  p_buf->hdr.event = BTA_CSIP_DISC_CMPL_EVT;
  p_buf->conn_id = conn_id;
  p_buf->status = status;
  p_buf->addr = bd_addr;

  bta_sys_sendmsg(p_buf);
}

/*********************************************************************************
 *
 * Function         BTA_CsipInit
 *
 * Description      This function is invoked to initialize CSIP in BTA layer.
 *
 * Parameters       None.
 *
 * Returns          None.
 *
 *********************************************************************************/
void BTA_CsipEnable(tBTA_CSIP_CBACK *p_cback) {
  tBTA_CSIP_ENABLE* p_buf =
    (tBTA_CSIP_ENABLE*)osi_calloc(sizeof(tBTA_CSIP_ENABLE));

  /* register with BTA system manager */
  bta_sys_register(BTA_ID_GROUP, &bta_csip_reg);

  p_buf->hdr.event = BTA_CSIP_API_ENABLE_EVT;
  p_buf->p_cback = p_cback;

  bta_sys_sendmsg(p_buf);
}

/*********************************************************************************
 *
 * Function         BTA_CsipDisable
 *
 * Description      This function is called for deinitialization.
 *
 * Parameters       None.
 *
 * Returns          None.
 *
 *********************************************************************************/
void BTA_CsipDisable() {
  tBTA_CSIP_ENABLE* p_buf =
    (tBTA_CSIP_ENABLE*)osi_calloc(sizeof(tBTA_CSIP_ENABLE));

  p_buf->hdr.event = BTA_CSIP_API_DISABLE_EVT;

  bta_sys_sendmsg(p_buf);
}

/*********************************************************************************
 *
 * Function         BTA_CsipRemoveUnpairedSetMember
 *
 * Description      This function is called when a given set member is unpaired.
 *
 * Parameters       addr: BD Address of the set member.
 *
 * Returns          None.
 *
 *********************************************************************************/
void BTA_CsipRemoveUnpairedSetMember(RawAddress addr) {
  do_in_bta_thread(FROM_HERE, base::Bind(&bta_csip_remove_set_member, addr));
}

/*********************************************************************************
 *
 * Function         BTA_CsipGetDeviceSetId
 *
 * Description      This API is used to get set id of the remote device.
 *
 * Parameters       addr: BD Address of the set member.
 *                  uuid: UUID of the service which includes CSIS service.
 *
 * Returns          None.
 *
 *********************************************************************************/
uint8_t BTA_CsipGetDeviceSetId(RawAddress addr, bluetooth::Uuid uuid) {
  for (tBTA_CSIP_CSET cset: bta_csip_cb.csets) {
    for (RawAddress bd_addr: cset.set_members) {
      if (bd_addr == addr && (cset.p_srvc_uuid == uuid)) {
        return cset.set_id;
      }
    }
  }

  return BTA_MAX_SUPPORTED_SETS;
}
