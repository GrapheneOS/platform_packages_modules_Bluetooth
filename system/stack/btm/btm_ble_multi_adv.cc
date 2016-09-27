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

#include <string.h>
#include <queue>
#include <base/bind.h>

#include "bt_target.h"
#include "device/include/controller.h"

#if (BLE_INCLUDED == TRUE)
#include "bt_types.h"
#include "hcimsgs.h"
#include "btu.h"
#include "btm_int.h"
#include "bt_utils.h"
#include "hcidefs.h"
#include "ble_advertiser.h"
#include "btm_ble_api.h"

using base::Bind;
using multiadv_cb = base::Callback<void(uint8_t /* status */)>;

typedef struct
{
    uint8_t                     inst_id;
    bool                        in_use;
    uint8_t                     adv_evt;
    BD_ADDR                     rpa;
    alarm_t                     *adv_raddr_timer;
    tBTM_BLE_MULTI_ADV_CBACK    *p_cback;
    uint8_t                     index;
}tBTM_BLE_MULTI_ADV_INST;

typedef struct
{
    tBTM_BLE_MULTI_ADV_INST *p_adv_inst; /* dynamic array to store adv instance */
}tBTM_BLE_MULTI_ADV_CB;

/************************************************************************************
**  Constants & Macros
************************************************************************************/
/* length of each multi adv sub command */
#define BTM_BLE_MULTI_ADV_ENB_LEN                       3
#define BTM_BLE_MULTI_ADV_SET_PARAM_LEN                 24
#define BTM_BLE_MULTI_ADV_WRITE_DATA_LEN                (BTM_BLE_AD_DATA_LEN + 3)
#define BTM_BLE_MULTI_ADV_SET_RANDOM_ADDR_LEN           8

/************************************************************************************
**  Static variables
************************************************************************************/
tBTM_BLE_MULTI_ADV_CB  btm_multi_adv_cb;
std::queue<std::pair<int, multiadv_cb>> *pending_ops;

/************************************************************************************
**  Externs
************************************************************************************/
extern fixed_queue_t *btu_general_alarm_queue;
//TODO(jpawlowski): get rid of this extern
extern "C" void btm_ble_update_dmt_flag_bits(uint8_t *flag_value,
                                               const uint16_t connect_mode, const uint16_t disc_mode);

void DoNothing(uint8_t) {}

void btm_ble_multi_adv_vsc_cmpl_cback(tBTM_VSC_CMPL *p_params)
{
    uint8_t status, subcode;
    uint8_t *p = p_params->p_param_buf;
    uint16_t len = p_params->param_len;

    if (len  < 2) {
        BTM_TRACE_ERROR("%s: wrong length", __func__);
        return;
    }

    STREAM_TO_UINT8(status, p);
    STREAM_TO_UINT8(subcode, p);

    BTM_TRACE_DEBUG("%s: subcode = %02x, status = %02x",
        __func__, subcode, status);

    auto pending_op = pending_ops->front();
    uint8_t opcode = pending_op.first;
    pending_ops->pop();

    if (opcode != subcode) {
        BTM_TRACE_ERROR("%s: unexpected VSC cmpl, expect: %d get: %d",
                        __func__, subcode, opcode);
        return;
    }

    pending_op.second.Run(status);
}

void btm_ble_multi_adv_configure_rpa(tBTM_BLE_MULTI_ADV_INST *p_inst);

void btm_ble_adv_raddr_timer_timeout(void *data)
{
    if (BTM_BleLocalPrivacyEnabled() &&
        (BTM_BleMaxMultiAdvInstanceCount() > 0)) {
        btm_ble_multi_adv_configure_rpa((tBTM_BLE_MULTI_ADV_INST *)data);
    }
}

/*******************************************************************************
**
** Function         btm_ble_enable_multi_adv
**
** Description      This function enable the customer specific feature in controller
**
** Parameters       enable: enable or disable
**                  inst_id:    adv instance ID, can not be 0
**
** Returns          void
**
*******************************************************************************/
void btm_ble_enable_multi_adv(bool enable, uint8_t inst_id, multiadv_cb cb)
{
    uint8_t         param[BTM_BLE_MULTI_ADV_ENB_LEN], *pp;
    uint8_t         enb = enable ? 1: 0;

    pp = param;
    memset(param, 0, BTM_BLE_MULTI_ADV_ENB_LEN);

    UINT8_TO_STREAM (pp, BTM_BLE_MULTI_ADV_ENB);
    UINT8_TO_STREAM (pp, enb);
    UINT8_TO_STREAM (pp, inst_id);

    BTM_TRACE_EVENT ("%s: enb %d, Inst ID %d", __func__, enb, inst_id);

    BTM_VendorSpecificCommand(HCI_BLE_MULTI_ADV_OCF,
                              BTM_BLE_MULTI_ADV_ENB_LEN,
                              param,
                              btm_ble_multi_adv_vsc_cmpl_cback);
    pending_ops->push(std::make_pair(BTM_BLE_MULTI_ADV_ENB, cb));
}
/*******************************************************************************
**
** Function         btm_ble_map_adv_tx_power
**
** Description      return the actual power in dBm based on the mapping in config file
**
** Parameters       advertise parameters used for this instance.
**
** Returns          tx power in dBm
**
*******************************************************************************/
int btm_ble_tx_power[BTM_BLE_ADV_TX_POWER_MAX + 1] = BTM_BLE_ADV_TX_POWER;
char btm_ble_map_adv_tx_power(int tx_power_index)
{
    if(0 <= tx_power_index && tx_power_index < BTM_BLE_ADV_TX_POWER_MAX)
        return (char)btm_ble_tx_power[tx_power_index];
    return 0;
}
/*******************************************************************************
**
** Function         btm_ble_multi_adv_set_params
**
** Description      This function enable the customer specific feature in controller
**
** Parameters       advertise parameters used for this instance.
**
** Returns          void
**
*******************************************************************************/
void btm_ble_multi_adv_set_params(tBTM_BLE_MULTI_ADV_INST *p_inst,
                                  tBTM_BLE_ADV_PARAMS *p_params,
                                  multiadv_cb cb)
{
    uint8_t         param[BTM_BLE_MULTI_ADV_SET_PARAM_LEN], *pp;
    BD_ADDR         dummy ={0,0,0,0,0,0};

    pp = param;
    memset(param, 0, BTM_BLE_MULTI_ADV_SET_PARAM_LEN);

    UINT8_TO_STREAM(pp, BTM_BLE_MULTI_ADV_SET_PARAM);

    UINT16_TO_STREAM (pp, p_params->adv_int_min);
    UINT16_TO_STREAM (pp, p_params->adv_int_max);
    UINT8_TO_STREAM  (pp, p_params->adv_type);

#if (BLE_PRIVACY_SPT == TRUE)
    if (BTM_BleLocalPrivacyEnabled())
    {
        UINT8_TO_STREAM  (pp, BLE_ADDR_RANDOM);
        BDADDR_TO_STREAM (pp, p_inst->rpa);
    }
    else
#endif
    {
        UINT8_TO_STREAM  (pp, BLE_ADDR_PUBLIC);
        BDADDR_TO_STREAM (pp, controller_get_interface()->get_address()->address);
    }

    BTM_TRACE_EVENT ("%s: Min %d, Max %d,adv_type %d", __func__,
        p_params->adv_int_min,p_params->adv_int_max,p_params->adv_type);

    UINT8_TO_STREAM  (pp, 0);
    BDADDR_TO_STREAM (pp, dummy);

    if (p_params->channel_map == 0 || p_params->channel_map > BTM_BLE_DEFAULT_ADV_CHNL_MAP)
        p_params->channel_map = BTM_BLE_DEFAULT_ADV_CHNL_MAP;
    UINT8_TO_STREAM (pp, p_params->channel_map);

    if (p_params->adv_filter_policy >= AP_SCAN_CONN_POLICY_MAX)
        p_params->adv_filter_policy = AP_SCAN_CONN_ALL;
    UINT8_TO_STREAM (pp, p_params->adv_filter_policy);

    UINT8_TO_STREAM (pp, p_inst->inst_id);

    if (p_params->tx_power > BTM_BLE_ADV_TX_POWER_MAX)
        p_params->tx_power = BTM_BLE_ADV_TX_POWER_MAX;
    UINT8_TO_STREAM (pp, btm_ble_map_adv_tx_power(p_params->tx_power));

    BTM_TRACE_EVENT("set_params:Chnl Map %d,adv_fltr policy %d,ID:%d, TX Power%d",
        p_params->channel_map,p_params->adv_filter_policy,p_inst->inst_id,p_params->tx_power);

    BTM_VendorSpecificCommand(HCI_BLE_MULTI_ADV_OCF,
                              BTM_BLE_MULTI_ADV_SET_PARAM_LEN,
                              param,
                              btm_ble_multi_adv_vsc_cmpl_cback);
    p_inst->adv_evt = p_params->adv_type;
    pending_ops->push(std::make_pair(BTM_BLE_MULTI_ADV_SET_PARAM, cb));
}

/*******************************************************************************
**
** Function         btm_ble_multi_adv_write_rpa
**
** Description      This function write the random address for the adv instance into
**                  controller
**
** Parameters
**
** Returns          void
**
*******************************************************************************/
void btm_ble_multi_adv_write_rpa(tBTM_BLE_MULTI_ADV_INST *p_inst, BD_ADDR random_addr)
{
    uint8_t         param[BTM_BLE_MULTI_ADV_SET_RANDOM_ADDR_LEN], *pp = param;

    BTM_TRACE_EVENT ("%s-BD_ADDR:%02x-%02x-%02x-%02x-%02x-%02x,inst_id:%d",
                      __func__, random_addr[5], random_addr[4], random_addr[3], random_addr[2],
                      random_addr[1], random_addr[0], p_inst->inst_id);

    memset(param, 0, BTM_BLE_MULTI_ADV_SET_RANDOM_ADDR_LEN);

    UINT8_TO_STREAM (pp, BTM_BLE_MULTI_ADV_SET_RANDOM_ADDR);
    BDADDR_TO_STREAM(pp, random_addr);
    UINT8_TO_STREAM(pp,  p_inst->inst_id);

    BTM_VendorSpecificCommand(HCI_BLE_MULTI_ADV_OCF,
                              BTM_BLE_MULTI_ADV_SET_RANDOM_ADDR_LEN,
                              param,
                              btm_ble_multi_adv_vsc_cmpl_cback);

    pending_ops->push(std::make_pair(BTM_BLE_MULTI_ADV_SET_RANDOM_ADDR, Bind(&DoNothing)));
}

std::queue<uint8_t> rand_gen_inst_id;

/* RPA generation completion callback for each adv instance. Will continue write
 * the new RPA into controller. */
void btm_ble_multi_adv_gen_rpa_cmpl(tBTM_RAND_ENC *p)
{
#if (SMP_INCLUDED == TRUE)
    tSMP_ENC    output;
    tBTM_BLE_MULTI_ADV_INST *p_inst = NULL;

     /* Retrieve the index of adv instance from stored Q */
    uint8_t index = rand_gen_inst_id.front();
    rand_gen_inst_id.pop();
    p_inst = &(btm_multi_adv_cb.p_adv_inst[index]);

    BTM_TRACE_EVENT ("%s: inst_id = %d", __func__, p_inst->inst_id);
    if (p)
    {
        p->param_buf[2] &= (~BLE_RESOLVE_ADDR_MASK);
        p->param_buf[2] |= BLE_RESOLVE_ADDR_MSB;

        p_inst->rpa[2] = p->param_buf[0];
        p_inst->rpa[1] = p->param_buf[1];
        p_inst->rpa[0] = p->param_buf[2];

        if (!SMP_Encrypt(btm_cb.devcb.id_keys.irk, BT_OCTET16_LEN, p->param_buf, 3, &output))
        {
            BTM_TRACE_DEBUG("generate random address failed");
        }
        else
        {
            /* set hash to be LSB of rpAddress */
            p_inst->rpa[5] = output.param_buf[0];
            p_inst->rpa[4] = output.param_buf[1];
            p_inst->rpa[3] = output.param_buf[2];
        }

        if (p_inst->inst_id != BTM_BLE_MULTI_ADV_DEFAULT_STD &&
            p_inst->inst_id < BTM_BleMaxMultiAdvInstanceCount())
        {
            /* set it to controller */
            btm_ble_multi_adv_write_rpa(p_inst, p_inst->rpa);
        }
    }
#endif
}

/*******************************************************************************
**
** Function         btm_ble_multi_adv_configure_rpa
**
** Description      This function set the random address for the adv instance
**
** Parameters       advertise parameters used for this instance.
**
** Returns          none
**
*******************************************************************************/
void btm_ble_multi_adv_configure_rpa(tBTM_BLE_MULTI_ADV_INST *p_inst)
{
    rand_gen_inst_id.push(p_inst->inst_id);
    btm_gen_resolvable_private_addr((void *)btm_ble_multi_adv_gen_rpa_cmpl);
}

/*******************************************************************************
**
** Function         btm_ble_multi_adv_reenable
**
** Description      This function re-enable adv instance upon a connection establishment.
**
** Parameters       advertise parameters used for this instance.
**
** Returns          none.
**
*******************************************************************************/
void btm_ble_multi_adv_reenable(uint8_t inst_id)
{
    tBTM_BLE_MULTI_ADV_INST *p_inst = &btm_multi_adv_cb.p_adv_inst[inst_id - 1];

    if (true == p_inst->in_use)
    {
        if (p_inst->adv_evt != BTM_BLE_CONNECT_DIR_EVT)
            btm_ble_enable_multi_adv(true, p_inst->inst_id, Bind(DoNothing));
        else
          /* mark directed adv as disabled if adv has been stopped */
        {
            (p_inst->p_cback)(BTM_BLE_MULTI_ADV_DISABLE_EVT,p_inst->inst_id,0);
             p_inst->in_use = false;
        }
     }
}

void BTM_BleAdvRegister(tBTM_BLE_MULTI_ADV_CBACK *p_cback) {
    tBTM_BLE_VSC_CB cmn_ble_vsc_cb;
    BTM_BleGetVendorCapabilities(&cmn_ble_vsc_cb);
    if (cmn_ble_vsc_cb.adv_inst_max == 0)
    {
        BTM_TRACE_ERROR("%s: multi adv not supported", __func__);
        (p_cback)(BTM_BLE_MULTI_ADV_REG_EVT, 0xFF, BTM_BLE_MULTI_ADV_FAILURE);
        return;
    }

    tBTM_BLE_MULTI_ADV_INST *p_inst = &btm_multi_adv_cb.p_adv_inst[0];
    for (uint8_t i = 0; i <  BTM_BleMaxMultiAdvInstanceCount() - 1; i++, p_inst++) {
        if (!p_inst->in_use) {
            p_inst->in_use = TRUE;

#if (BLE_PRIVACY_SPT == TRUE)
            // configure the address, and set up periodic timer to update it.
            btm_ble_multi_adv_configure_rpa(p_inst);

            if (BTM_BleLocalPrivacyEnabled()) {
                alarm_set_on_queue(p_inst->adv_raddr_timer,
                                   BTM_BLE_PRIVATE_ADDR_INT_MS,
                                   btm_ble_adv_raddr_timer_timeout, p_inst,
                                   btu_general_alarm_queue);
            }
#endif

            p_inst->p_cback = p_cback;
            (p_inst->p_cback)(BTM_BLE_MULTI_ADV_REG_EVT,
                              p_inst->inst_id, BTM_BLE_MULTI_ADV_SUCCESS);
            return;
        }
    }

    BTM_TRACE_WARNING("%s: no free advertiser instance", __func__);
    if (p_cback)
        (p_cback)(BTM_BLE_MULTI_ADV_REG_EVT, 0xFF, BTM_BLE_MULTI_ADV_FAILURE);
}

void BTM_BleAdvEnableCb(bool enable, uint8_t inst_id, uint8_t status) {
    BTM_TRACE_DEBUG("%s: status = %d, inst_id = %d", __func__, status, inst_id);

    tBTM_BLE_MULTI_ADV_INST *p_inst = &btm_multi_adv_cb.p_adv_inst[inst_id - 1];
    if (enable)
        (p_inst->p_cback)(BTM_BLE_MULTI_ADV_ENB_EVT, inst_id, status);
    else
        (p_inst->p_cback)(BTM_BLE_MULTI_ADV_DISABLE_EVT, inst_id, status);
}

/*******************************************************************************
**
** Function         BTM_BleAdvEnable
**
** Description      This function enable a Multi-ADV instance with the specified
**                  adv parameters
**
** Parameters       inst_id: adv instance ID
**                  p_params: pointer to the adv parameter structure, set as default
**                            adv parameter when the instance is enabled.
**
** Returns          status
**
*******************************************************************************/
void BTM_BleAdvEnable(uint8_t inst_id, bool enable)
{
    BTM_TRACE_EVENT("%s: inst_id: %d, enable: %d", __func__, inst_id, enable);

    if (0 == btm_cb.cmn_ble_vsc_cb.adv_inst_max) {
        BTM_TRACE_ERROR("%s: multi adv not supported", __func__);
        return;
    }

    tBTM_BLE_MULTI_ADV_INST *p_inst = &btm_multi_adv_cb.p_adv_inst[inst_id - 1];
    if (!p_inst || !p_inst->in_use) {
        BTM_TRACE_ERROR("%s: Invalid or not active instance", __func__);
        (p_inst->p_cback)(BTM_BLE_MULTI_ADV_ENB_EVT, inst_id, BTM_BLE_MULTI_ADV_FAILURE);
        return;
    }

    btm_ble_enable_multi_adv(enable, p_inst->inst_id,
        Bind(&BTM_BleAdvEnableCb, enable, p_inst->inst_id));
}

void BTM_BleAdvSetParametersCb(uint8_t inst_id, uint8_t status) {
    BTM_TRACE_DEBUG("%s: status = %d, inst_id = %d", __func__, status, inst_id);

    tBTM_BLE_MULTI_ADV_INST *p_inst = &btm_multi_adv_cb.p_adv_inst[inst_id - 1];
    (p_inst->p_cback)(BTM_BLE_MULTI_ADV_PARAM_EVT, inst_id, status);
}

/*******************************************************************************
**
** Function         BTM_BleAdvSetParameters
**
** Description      This function update a Multi-ADV instance with the specified
**                  adv parameters.
**
** Parameters       inst_id: adv instance ID
**                  p_params: pointer to the adv parameter structure.
**
** Returns          status
**
*******************************************************************************/
void BTM_BleAdvSetParameters(uint8_t inst_id, tBTM_BLE_ADV_PARAMS *p_params)
{
    tBTM_BLE_MULTI_ADV_INST *p_inst = &btm_multi_adv_cb.p_adv_inst[inst_id - 1];

    BTM_TRACE_EVENT("BTM_BleUpdateAdvInstParam called with inst_id:%d", inst_id);

    if (0 == btm_cb.cmn_ble_vsc_cb.adv_inst_max) {
        BTM_TRACE_ERROR("%s: multi adv not supported", __func__);
        return;
    }

    if (inst_id > BTM_BleMaxMultiAdvInstanceCount() || inst_id < 0 ||
        inst_id == BTM_BLE_MULTI_ADV_DEFAULT_STD) {
        BTM_TRACE_ERROR("%s: bad instance id %d", __func__, inst_id);
        return;
    }

    if (!p_inst->in_use) {
        BTM_TRACE_ERROR("%s: adv instance %d is not in use", __func__, inst_id);
        (p_inst->p_cback)(BTM_BLE_MULTI_ADV_PARAM_EVT, inst_id, BTM_BLE_MULTI_ADV_FAILURE);
        return;
    }

    //TODO: disable only if was enabled, currently no use scenario needs that,
    // we always set parameters before enabling
    // btm_ble_enable_multi_adv(false, inst_id, NULL);
    btm_ble_multi_adv_set_params(p_inst, p_params,
        Bind(&BTM_BleAdvSetParametersCb, p_inst->inst_id));

    //TODO: re-enable only if it was enabled, properly call BTM_BleAdvSetParametersCb
    // currently no use scenario needs that
    // btm_ble_enable_multi_adv(true, inst_id, BTM_BleUpdateAdvInstParamCb);
}

void BTM_BleAdvSetDataCb(uint8_t inst_id, uint8_t status)
{
    BTM_TRACE_DEBUG("%s: status = %d, inst_id = %d", __func__, status, inst_id);

    tBTM_BLE_MULTI_ADV_INST *p_inst = &btm_multi_adv_cb.p_adv_inst[inst_id - 1];
    (p_inst->p_cback)(BTM_BLE_MULTI_ADV_DATA_EVT, inst_id, status);
}

/*******************************************************************************
**
** Function         BTM_BleAdvSetData
**
** Description      This function configure a Multi-ADV instance with the specified
**                  adv data or scan response data.
**
** Parameters       inst_id: adv instance ID
**                  is_scan_rsp: is this scan response. if no, set as adv data.
**                  data_mask: adv data mask.
**                  p_data: pointer to the adv data structure.
**
** Returns          status
**
*******************************************************************************/
void BTM_BleAdvSetData(uint8_t inst_id, bool is_scan_rsp,
                           tBTM_BLE_AD_MASK data_mask,
                           tBTM_BLE_ADV_DATA *p_data)
{
    BTM_TRACE_DEBUG("%s: inst_id = %d is_scan_rsp = %d",
                    __func__, inst_id, is_scan_rsp);

    uint8_t     param[BTM_BLE_MULTI_ADV_WRITE_DATA_LEN], *pp = param;
    uint8_t     sub_code = (is_scan_rsp) ?
                           BTM_BLE_MULTI_ADV_WRITE_SCAN_RSP_DATA : BTM_BLE_MULTI_ADV_WRITE_ADV_DATA;
    uint8_t     *p_len;
    uint8_t *pp_temp = (uint8_t*)(param + BTM_BLE_MULTI_ADV_WRITE_DATA_LEN -1);
    tBTM_BLE_VSC_CB cmn_ble_vsc_cb;

    BTM_BleGetVendorCapabilities(&cmn_ble_vsc_cb);
    if (0 == cmn_ble_vsc_cb.adv_inst_max) {
        BTM_TRACE_ERROR("%s: multi adv not supported", __func__);
        return;
    }

    btm_ble_update_dmt_flag_bits(&p_data->flag, btm_cb.btm_inq_vars.connectable_mode,
                                        btm_cb.btm_inq_vars.discoverable_mode);

    if (inst_id > BTM_BleMaxMultiAdvInstanceCount() || inst_id < 0 ||
        inst_id == BTM_BLE_MULTI_ADV_DEFAULT_STD) {
        BTM_TRACE_ERROR("%s: bad instance id %d", __func__, inst_id);
        return;
    }

    memset(param, 0, BTM_BLE_MULTI_ADV_WRITE_DATA_LEN);

    UINT8_TO_STREAM(pp, sub_code);
    p_len = pp ++;
    btm_ble_build_adv_data(&data_mask, &pp, p_data);
    *p_len = (uint8_t)(pp - param - 2);
    UINT8_TO_STREAM(pp_temp, inst_id);

    BTM_VendorSpecificCommand(HCI_BLE_MULTI_ADV_OCF,
                              (uint8_t)BTM_BLE_MULTI_ADV_WRITE_DATA_LEN,
                              param,
                              btm_ble_multi_adv_vsc_cmpl_cback);

    pending_ops->push(std::make_pair(sub_code, Bind(BTM_BleAdvSetDataCb, inst_id)));
}

/*******************************************************************************
**
** Function         BTM_BleAdvUnregister
**
** Description      This function unregister a Multi-ADV instance.
**
** Parameters       inst_id: adv instance ID
**
** Returns          status
**
*******************************************************************************/
void BTM_BleAdvUnregister(uint8_t inst_id)
{
    tBTM_BLE_MULTI_ADV_INST *p_inst = &btm_multi_adv_cb.p_adv_inst[inst_id - 1];
    tBTM_BLE_VSC_CB cmn_ble_vsc_cb;

    BTM_TRACE_EVENT("%s: with inst_id:%d", __func__, inst_id);

    BTM_BleGetVendorCapabilities(&cmn_ble_vsc_cb);

    if (0 == cmn_ble_vsc_cb.adv_inst_max) {
        BTM_TRACE_ERROR("%s: multi adv not supported", __func__);
        return;
    }

    if (inst_id > BTM_BleMaxMultiAdvInstanceCount() || inst_id < 0 ||
        inst_id == BTM_BLE_MULTI_ADV_DEFAULT_STD) {
        BTM_TRACE_ERROR("%s: bad instance id %d", __func__, inst_id);
        return;
    }

    //TODO(jpawlowski): only disable when enabled or enabling
    btm_ble_enable_multi_adv(false, inst_id, Bind(DoNothing));

    alarm_cancel(p_inst->adv_raddr_timer);
    p_inst->in_use = false;
}

/*******************************************************************************
**
** Function         btm_ble_multi_adv_vse_cback
**
** Description      VSE callback for multi adv events.
**
** Returns
**
*******************************************************************************/
void btm_ble_multi_adv_vse_cback(uint8_t len, uint8_t *p)
{
    uint8_t sub_event;
    uint8_t adv_inst, idx;
    uint16_t conn_handle;

    /* Check if this is a BLE RSSI vendor specific event */
    STREAM_TO_UINT8(sub_event, p);
    len--;

    BTM_TRACE_EVENT("btm_ble_multi_adv_vse_cback called with event:%d", sub_event);
    if ((sub_event == HCI_VSE_SUBCODE_BLE_MULTI_ADV_ST_CHG) && (len >= 4))
    {
        STREAM_TO_UINT8(adv_inst, p);
        ++p;
        STREAM_TO_UINT16(conn_handle, p);

        if ((idx = btm_handle_to_acl_index(conn_handle)) != MAX_L2CAP_LINKS)
        {
#if (BLE_PRIVACY_SPT == TRUE)
            if (BTM_BleLocalPrivacyEnabled() &&
                adv_inst <= BTM_BLE_MULTI_ADV_MAX && adv_inst !=  BTM_BLE_MULTI_ADV_DEFAULT_STD)
            {
                memcpy(btm_cb.acl_db[idx].conn_addr, btm_multi_adv_cb.p_adv_inst[adv_inst - 1].rpa,
                                BD_ADDR_LEN);
            }
#endif
        }

        if (adv_inst < BTM_BleMaxMultiAdvInstanceCount() &&
            adv_inst !=  BTM_BLE_MULTI_ADV_DEFAULT_STD)
        {
            BTM_TRACE_EVENT("btm_ble_multi_adv_reenable called");
            btm_ble_multi_adv_reenable(adv_inst);
        }
        /* re-enable connectibility */
        else if (adv_inst == BTM_BLE_MULTI_ADV_DEFAULT_STD)
        {
            if (btm_cb.ble_ctr_cb.inq_var.connectable_mode == BTM_BLE_CONNECTABLE)
            {
                btm_ble_set_connectability ( btm_cb.ble_ctr_cb.inq_var.connectable_mode );
            }
        }

    }

}
/*******************************************************************************
**
** Function         btm_ble_multi_adv_init
**
** Description      This function initialize the multi adv control block.
**
** Parameters       None
**
** Returns          void
**
*******************************************************************************/
void btm_ble_multi_adv_init()
{
    uint8_t i = 0;
    memset(&btm_multi_adv_cb, 0, sizeof(tBTM_BLE_MULTI_ADV_CB));

    pending_ops = new std::queue<std::pair<int, multiadv_cb>>();
    if (btm_cb.cmn_ble_vsc_cb.adv_inst_max > 0) {
        btm_multi_adv_cb.p_adv_inst = reinterpret_cast<tBTM_BLE_MULTI_ADV_INST *>(
            osi_calloc(sizeof(tBTM_BLE_MULTI_ADV_INST) *
                       (btm_cb.cmn_ble_vsc_cb.adv_inst_max)));
    }

    /* Initialize adv instance indices and IDs. */
    for (i = 0; i < btm_cb.cmn_ble_vsc_cb.adv_inst_max; i++) {
        btm_multi_adv_cb.p_adv_inst[i].index = i;
        btm_multi_adv_cb.p_adv_inst[i].inst_id = i + 1;
        btm_multi_adv_cb.p_adv_inst[i].adv_raddr_timer =
            alarm_new_periodic("btm_ble.adv_raddr_timer");
    }

    BTM_RegisterForVSEvents(btm_ble_multi_adv_vse_cback, true);
}

/*******************************************************************************
**
** Function         btm_ble_multi_adv_cleanup
**
** Description      This function cleans up multi adv control block.
**
** Parameters
** Returns          void
**
*******************************************************************************/
void btm_ble_multi_adv_cleanup(void)
{
    delete pending_ops;
    pending_ops = nullptr;

    if (btm_multi_adv_cb.p_adv_inst) {
        for (size_t i = 0; i < btm_cb.cmn_ble_vsc_cb.adv_inst_max; i++) {
            alarm_free(btm_multi_adv_cb.p_adv_inst[i].adv_raddr_timer);
        }
        osi_free_and_reset((void **)&btm_multi_adv_cb.p_adv_inst);
    }
}

#endif

