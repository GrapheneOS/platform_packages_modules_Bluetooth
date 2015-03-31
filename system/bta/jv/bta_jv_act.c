/******************************************************************************
 *
 *  Copyright (C) 2006-2012 Broadcom Corporation
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
 *  This file contains action functions for BTA JV APIs.
 *
 ******************************************************************************/
#include <hardware/bluetooth.h>
#include <arpa/inet.h>

#include "bt_types.h"
#include "gki.h"
#include "utl.h"
#include "bta_sys.h"
#include "bta_api.h"
#include "bta_jv_api.h"
#include "bta_jv_int.h"
#include "bta_jv_co.h"
#include "btm_api.h"
#include "btm_int.h"
#include "sdp_api.h"
#include "l2c_api.h"
#include "port_api.h"
#include <string.h>
#include "rfcdefs.h"
#include "avct_api.h"
#include "avdt_api.h"
#include "gap_api.h"


extern void uuid_to_string_legacy(bt_uuid_t *p_uuid, char *str);
static inline void logu(const char* title, const uint8_t * p_uuid)
{
    char uuids[128];
    uuid_to_string_legacy((bt_uuid_t*)p_uuid, uuids);
    APPL_TRACE_DEBUG("%s: %s", title, uuids);
}


static tBTA_JV_PCB * bta_jv_add_rfc_port(tBTA_JV_RFC_CB *p_cb, tBTA_JV_PCB *p_pcb_open);
static tBTA_JV_STATUS bta_jv_free_set_pm_profile_cb(UINT32 jv_handle);
static void bta_jv_pm_conn_busy(tBTA_JV_PM_CB *p_cb);
static void bta_jv_pm_conn_idle(tBTA_JV_PM_CB *p_cb);
static void bta_jv_pm_state_change(tBTA_JV_PM_CB *p_cb, const tBTA_JV_CONN_STATE state);
tBTA_JV_STATUS bta_jv_set_pm_conn_state(tBTA_JV_PM_CB *p_cb, const tBTA_JV_CONN_STATE
        new_st);

/*******************************************************************************
**
** Function     bta_jv_alloc_sec_id
**
** Description  allocate a security id
**
** Returns
**
*******************************************************************************/
UINT8 bta_jv_alloc_sec_id(void)
{
    UINT8 ret = 0;
    int i;
    for(i=0; i<BTA_JV_NUM_SERVICE_ID; i++)
    {
        if(0 == bta_jv_cb.sec_id[i])
        {
            bta_jv_cb.sec_id[i] = BTA_JV_FIRST_SERVICE_ID + i;
            ret = bta_jv_cb.sec_id[i];
            break;
        }
    }
    return ret;

}
static int get_sec_id_used(void)
{
    int i;
    int used = 0;
    for(i=0; i<BTA_JV_NUM_SERVICE_ID; i++)
    {
        if(bta_jv_cb.sec_id[i])
            used++;
    }
    if (used == BTA_JV_NUM_SERVICE_ID)
        APPL_TRACE_ERROR("get_sec_id_used, sec id exceeds the limit:%d",
                BTA_JV_NUM_SERVICE_ID);
    return used;
}
static int get_rfc_cb_used(void)
{
    int i;
    int used = 0;
    for(i=0; i<BTA_JV_MAX_RFC_CONN; i++)
    {
        if(bta_jv_cb.rfc_cb[i].handle )
            used++;
    }
    if (used == BTA_JV_MAX_RFC_CONN)
        APPL_TRACE_ERROR("get_sec_id_used, rfc ctrl block exceeds the limit:%d",
                BTA_JV_MAX_RFC_CONN);
    return used;
}

/*******************************************************************************
**
** Function     bta_jv_free_sec_id
**
** Description  free the given security id
**
** Returns
**
*******************************************************************************/
static void bta_jv_free_sec_id(UINT8 *p_sec_id)
{
    UINT8 sec_id = *p_sec_id;
    *p_sec_id = 0;
    if(sec_id >= BTA_JV_FIRST_SERVICE_ID && sec_id <= BTA_JV_LAST_SERVICE_ID)
    {
        BTM_SecClrService(sec_id);
        bta_jv_cb.sec_id[sec_id - BTA_JV_FIRST_SERVICE_ID] = 0;
    }
}

/*******************************************************************************
**
** Function     bta_jv_alloc_rfc_cb
**
** Description  allocate a control block for the given port handle
**
** Returns
**
*******************************************************************************/
tBTA_JV_RFC_CB * bta_jv_alloc_rfc_cb(UINT16 port_handle, tBTA_JV_PCB **pp_pcb)
{
    tBTA_JV_RFC_CB *p_cb = NULL;
    tBTA_JV_PCB *p_pcb;
    int i, j;
    for(i=0; i<BTA_JV_MAX_RFC_CONN; i++)
    {
        if (0 == bta_jv_cb.rfc_cb[i].handle )
        {
            p_cb = &bta_jv_cb.rfc_cb[i];
            /* mask handle to distinguish it with L2CAP handle */
            p_cb->handle = (i + 1) | BTA_JV_RFCOMM_MASK;

            p_cb->max_sess          = 1;
            p_cb->curr_sess         = 1;
            for (j = 0; j < BTA_JV_MAX_RFC_SR_SESSION; j++)
                p_cb->rfc_hdl[j] = 0;
            p_cb->rfc_hdl[0]        = port_handle;
            APPL_TRACE_DEBUG( "bta_jv_alloc_rfc_cb port_handle:%d handle:0x%2x",
                    port_handle, p_cb->handle);

            p_pcb = &bta_jv_cb.port_cb[port_handle - 1];
            p_pcb->handle = p_cb->handle;
            p_pcb->port_handle = port_handle;
            p_pcb->p_pm_cb = NULL;
            *pp_pcb = p_pcb;
            break;
        }
    }
    if(p_cb == NULL)
    {
        APPL_TRACE_ERROR( "bta_jv_alloc_rfc_cb: port_handle:%d, ctrl block exceeds "
                "limit:%d", port_handle, BTA_JV_MAX_RFC_CONN);
    }
    return p_cb;
}

/*******************************************************************************
**
** Function     bta_jv_rfc_port_to_pcb
**
** Description  find the port control block associated with the given port handle
**
** Returns
**
*******************************************************************************/
tBTA_JV_PCB * bta_jv_rfc_port_to_pcb(UINT16 port_handle)
{
    tBTA_JV_PCB *p_pcb = NULL;

    if ((port_handle > 0) && (port_handle <= MAX_RFC_PORTS)
            && bta_jv_cb.port_cb[port_handle - 1].handle)
    {
        p_pcb = &bta_jv_cb.port_cb[port_handle - 1];
    }

    return p_pcb;
}

/*******************************************************************************
**
** Function     bta_jv_rfc_port_to_cb
**
** Description  find the RFCOMM control block associated with the given port handle
**
** Returns
**
*******************************************************************************/
tBTA_JV_RFC_CB * bta_jv_rfc_port_to_cb(UINT16 port_handle)
{
    tBTA_JV_RFC_CB *p_cb = NULL;
    UINT32 handle;

    if ((port_handle > 0) && (port_handle <= MAX_RFC_PORTS)
            && bta_jv_cb.port_cb[port_handle - 1].handle)
    {
        handle = bta_jv_cb.port_cb[port_handle - 1].handle;
        handle &= BTA_JV_RFC_HDL_MASK;
        handle &= ~BTA_JV_RFCOMM_MASK;
        if (handle)
            p_cb = &bta_jv_cb.rfc_cb[handle - 1];
    }
    else
    {
        APPL_TRACE_WARNING("bta_jv_rfc_port_to_cb(port_handle:0x%x):jv handle:0x%x not"
                " FOUND", port_handle, bta_jv_cb.port_cb[port_handle - 1].handle);
    }
    return p_cb;
}

static tBTA_JV_STATUS bta_jv_free_rfc_cb(tBTA_JV_RFC_CB *p_cb, tBTA_JV_PCB *p_pcb)
{
    tBTA_JV_STATUS status = BTA_JV_SUCCESS;
    BOOLEAN remove_server = FALSE;
    int close_pending = 0;

    if (!p_cb || !p_pcb)
    {
        APPL_TRACE_ERROR("bta_jv_free_sr_rfc_cb, p_cb or p_pcb cannot be null");
        return BTA_JV_FAILURE;
    }
    APPL_TRACE_DEBUG("bta_jv_free_sr_rfc_cb: max_sess:%d, curr_sess:%d, p_pcb:%p, user:"
            "%p, state:%d, jv handle: 0x%x" ,p_cb->max_sess, p_cb->curr_sess, p_pcb,
            p_pcb->user_data, p_pcb->state, p_pcb->handle);

    if (p_cb->curr_sess <= 0)
        return BTA_JV_SUCCESS;

    switch (p_pcb->state)
    {
    case BTA_JV_ST_CL_CLOSING:
    case BTA_JV_ST_SR_CLOSING:
        APPL_TRACE_WARNING("bta_jv_free_sr_rfc_cb: return on closing, port state:%d, "
                "scn:%d, p_pcb:%p, user_data:%p", p_pcb->state, p_cb->scn, p_pcb,
                p_pcb->user_data);
        status = BTA_JV_FAILURE;
        return status;
    case BTA_JV_ST_CL_OPEN:
    case BTA_JV_ST_CL_OPENING:
        APPL_TRACE_DEBUG("bta_jv_free_sr_rfc_cb: state: %d, scn:%d,"
                          " user_data:%p", p_pcb->state, p_cb->scn, p_pcb->user_data);
        p_pcb->state = BTA_JV_ST_CL_CLOSING;
        break;
    case BTA_JV_ST_SR_LISTEN:
        p_pcb->state = BTA_JV_ST_SR_CLOSING;
        remove_server = TRUE;
        APPL_TRACE_DEBUG("bta_jv_free_sr_rfc_cb: state: BTA_JV_ST_SR_LISTEN, scn:%d,"
                " user_data:%p", p_cb->scn, p_pcb->user_data);
        break;
    case BTA_JV_ST_SR_OPEN:
        p_pcb->state = BTA_JV_ST_SR_CLOSING;
        APPL_TRACE_DEBUG("bta_jv_free_sr_rfc_cb: state: BTA_JV_ST_SR_OPEN, scn:%d,"
                " user_data:%p", p_cb->scn, p_pcb->user_data);
        break;
    default:
        APPL_TRACE_WARNING("bta_jv_free_sr_rfc_cb():failed, ignore port state:%d, scn:"
                "%d, p_pcb:%p, jv handle: 0x%x, port_handle: %d, user_data:%p",
                p_pcb->state, p_cb->scn, p_pcb, p_pcb->handle, p_pcb->port_handle,
                p_pcb->user_data);
        status = BTA_JV_FAILURE;
        break;
    }
    if (BTA_JV_SUCCESS == status)
    {
        int port_status;

        if (!remove_server)
            port_status = RFCOMM_RemoveConnection(p_pcb->port_handle);
        else
            port_status = RFCOMM_RemoveServer(p_pcb->port_handle);
        if (port_status != PORT_SUCCESS)
        {
            status = BTA_JV_FAILURE;
            APPL_TRACE_WARNING("bta_jv_free_rfc_cb(jv handle: 0x%x, state %d)::"
                    "port_status: %d, port_handle: %d, close_pending: %d:Remove",
                    p_pcb->handle, p_pcb->state, port_status, p_pcb->port_handle,
                    close_pending);
        }
    }
    if (!close_pending)
    {
        p_pcb->port_handle = 0;
        p_pcb->state = BTA_JV_ST_NONE;
        bta_jv_free_set_pm_profile_cb(p_pcb->handle);

        //Initialize congestion flags
        p_pcb->cong = FALSE;
        p_pcb->user_data = 0;
        int si = BTA_JV_RFC_HDL_TO_SIDX(p_pcb->handle);
        if (0 <= si && si < BTA_JV_MAX_RFC_SR_SESSION)
            p_cb->rfc_hdl[si] = 0;
        p_pcb->handle = 0;
        p_cb->curr_sess--;
        if (p_cb->curr_sess == 0)
        {
            p_cb->scn = 0;
            bta_jv_free_sec_id(&p_cb->sec_id);
            p_cb->p_cback = NULL;
            p_cb->handle = 0;
            p_cb->curr_sess = -1;
        }
    }
    return status;
}

/*******************************************************************************
 **
 ** Function    bta_jv_clear_pm_cb
 **
 ** Description clears jv pm control block and optionally calls bta_sys_conn_close()
 **             In general close_conn should be set to TRUE to remove registering with
 **             dm pm!
 **
 ** WARNING:    Make sure to clear pointer form port or l2c to this control block too!
 **
 *******************************************************************************/
static void bta_jv_clear_pm_cb(tBTA_JV_PM_CB *p_pm_cb, BOOLEAN close_conn)
{
    /* needs to be called if registered with bta pm, otherwise we may run out of dm pm slots! */
    if (close_conn)
        bta_sys_conn_close(BTA_ID_JV, p_pm_cb->app_id, p_pm_cb->peer_bd_addr);
    p_pm_cb->state = BTA_JV_PM_FREE_ST;
    p_pm_cb->app_id = BTA_JV_PM_ALL;
    p_pm_cb->handle = BTA_JV_PM_HANDLE_CLEAR;
    bdcpy(p_pm_cb->peer_bd_addr, bd_addr_null);
}

/*******************************************************************************
 **
 ** Function     bta_jv_free_set_pm_profile_cb
 **
 ** Description  free pm profile control block
 **
 ** Returns     BTA_JV_SUCCESS if cb has been freed correctly,
 **             BTA_JV_FAILURE in case of no profile has been registered or already freed
 **
 *******************************************************************************/
static tBTA_JV_STATUS bta_jv_free_set_pm_profile_cb(UINT32 jv_handle)
{
    tBTA_JV_STATUS status = BTA_JV_FAILURE;
    tBTA_JV_PM_CB  **p_cb;
    int i, j, bd_counter = 0, appid_counter = 0;

    for (i = 0; i < BTA_JV_PM_MAX_NUM; i++)
    {
        p_cb = NULL;
        if ((bta_jv_cb.pm_cb[i].state != BTA_JV_PM_FREE_ST) &&
                (jv_handle == bta_jv_cb.pm_cb[i].handle))
        {
            for (j = 0; j < BTA_JV_PM_MAX_NUM; j++)
            {
                if (bdcmp(bta_jv_cb.pm_cb[j].peer_bd_addr, bta_jv_cb.pm_cb[i].peer_bd_addr) == 0)
                    bd_counter++;
                if (bta_jv_cb.pm_cb[j].app_id == bta_jv_cb.pm_cb[i].app_id)
                    appid_counter++;
            }

            APPL_TRACE_API("bta_jv_free_set_pm_profile_cb(jv_handle: 0x%2x), idx: %d, "
                    "app_id: 0x%x", jv_handle, i, bta_jv_cb.pm_cb[i].app_id);
            APPL_TRACE_API("bta_jv_free_set_pm_profile_cb, bd_counter = %d, "
                    "appid_counter = %d", bd_counter, appid_counter);
            if (bd_counter > 1)
            {
                bta_jv_pm_conn_idle(&bta_jv_cb.pm_cb[i]);
            }

            if (bd_counter <= 1 || (appid_counter <= 1))
            {
                bta_jv_clear_pm_cb(&bta_jv_cb.pm_cb[i], TRUE);
            }
            else
            {
                bta_jv_clear_pm_cb(&bta_jv_cb.pm_cb[i], FALSE);
            }

            if (BTA_JV_RFCOMM_MASK & jv_handle)
            {
                UINT32 hi = ((jv_handle & BTA_JV_RFC_HDL_MASK) & ~BTA_JV_RFCOMM_MASK) - 1;
                UINT32 si = BTA_JV_RFC_HDL_TO_SIDX(jv_handle);
                if (hi < BTA_JV_MAX_RFC_CONN && bta_jv_cb.rfc_cb[hi].p_cback && si
                        < BTA_JV_MAX_RFC_SR_SESSION && bta_jv_cb.rfc_cb[hi].rfc_hdl[si])
                {
                    tBTA_JV_PCB *p_pcb = bta_jv_rfc_port_to_pcb(bta_jv_cb.rfc_cb[hi].rfc_hdl[si]);
                    if (p_pcb)
                    {
                        if (NULL == p_pcb->p_pm_cb)
                            APPL_TRACE_WARNING("bta_jv_free_set_pm_profile_cb(jv_handle:"
                                    " 0x%x):port_handle: 0x%x, p_pm_cb: %d: no link to "
                                    "pm_cb?", jv_handle, p_pcb->port_handle, i);
                        p_cb = &p_pcb->p_pm_cb;
                    }
                }
            }

            if (p_cb)
            {
                *p_cb = NULL;
                status = BTA_JV_SUCCESS;
            }
        }
    }
    return status;
}

/*******************************************************************************
 **
 ** Function    bta_jv_alloc_set_pm_profile_cb
 **
 ** Description set PM profile control block
 **
 ** Returns     pointer to allocated cb or NULL in case of failure
 **
 *******************************************************************************/
static tBTA_JV_PM_CB *bta_jv_alloc_set_pm_profile_cb(UINT32 jv_handle, tBTA_JV_PM_ID app_id)
{
    BOOLEAN bRfcHandle = (jv_handle & BTA_JV_RFCOMM_MASK) != 0;
    BD_ADDR peer_bd_addr;
    int i, j;
    tBTA_JV_PM_CB **pp_cb;

    for (i = 0; i < BTA_JV_PM_MAX_NUM; i++)
    {
        pp_cb = NULL;
        if (bta_jv_cb.pm_cb[i].state == BTA_JV_PM_FREE_ST)
        {
            /* rfc handle bd addr retrieval requires core stack handle */
            if (bRfcHandle)
            {
                UINT32 hi = ((jv_handle & BTA_JV_RFC_HDL_MASK) & ~BTA_JV_RFCOMM_MASK) - 1;
                UINT32 si = BTA_JV_RFC_HDL_TO_SIDX(jv_handle);
                for (j = 0; j < BTA_JV_MAX_RFC_CONN; j++)
                {
                    if (jv_handle == bta_jv_cb.port_cb[j].handle)
                    {
                        pp_cb = &bta_jv_cb.port_cb[j].p_pm_cb;
                        if (PORT_SUCCESS != PORT_CheckConnection(
                                bta_jv_cb.port_cb[j].port_handle, peer_bd_addr, NULL))
                            i = BTA_JV_PM_MAX_NUM;
                        break;
                    }
                }
            }
            APPL_TRACE_API("bta_jv_alloc_set_pm_profile_cb(handle 0x%2x, app_id %d): "
                    "idx: %d, (BTA_JV_PM_MAX_NUM: %d), pp_cb: 0x%x", jv_handle, app_id,
                    i, BTA_JV_PM_MAX_NUM, pp_cb);
            break;
        }
    }

    if ((i != BTA_JV_PM_MAX_NUM) && (NULL != pp_cb))
    {
        *pp_cb = &bta_jv_cb.pm_cb[i];
        bta_jv_cb.pm_cb[i].handle = jv_handle;
        bta_jv_cb.pm_cb[i].app_id = app_id;
        bdcpy(bta_jv_cb.pm_cb[i].peer_bd_addr, peer_bd_addr);
        bta_jv_cb.pm_cb[i].state = BTA_JV_PM_IDLE_ST;
        return &bta_jv_cb.pm_cb[i];
    }
    APPL_TRACE_WARNING("bta_jv_alloc_set_pm_profile_cb(jv_handle: 0x%x, app_id: %d) "
            "return NULL", jv_handle, app_id);
    return (tBTA_JV_PM_CB *)NULL;
}

/*******************************************************************************
**
** Function     bta_jv_enable
**
** Description  Initialises the JAVA I/F
**
** Returns      void
**
*******************************************************************************/
void bta_jv_enable(tBTA_JV_MSG *p_data)
{
    tBTA_JV_STATUS status = BTA_JV_SUCCESS;
    bta_jv_cb.p_dm_cback = p_data->enable.p_cback;
    bta_jv_cb.p_dm_cback(BTA_JV_ENABLE_EVT, (tBTA_JV *)&status, 0);
}

/*******************************************************************************
**
** Function     bta_jv_disable
**
** Description  Disables the BT device manager
**              free the resources used by java
**
** Returns      void
**
*******************************************************************************/
void bta_jv_disable (tBTA_JV_MSG *p_data)
{
    UNUSED(p_data);

    APPL_TRACE_ERROR("bta_jv_disable not used");
}

static inline tBT_UUID shorten_sdp_uuid(const tBT_UUID* u)
{
    static uint8_t bt_base_uuid[] =
       {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x80, 0x00, 0x00, 0x80, 0x5F, 0x9B, 0x34, 0xFB };

    logu("in, uuid:", u->uu.uuid128);
    APPL_TRACE_DEBUG("uuid len:%d", u->len);
    if(u->len == 16)
    {
        if(memcmp(&u->uu.uuid128[4], &bt_base_uuid[4], 12) == 0)
        {
            tBT_UUID su;
            memset(&su, 0, sizeof(su));
            if(u->uu.uuid128[0] == 0 && u->uu.uuid128[1] == 0)
            {
                su.len = 2;
                uint16_t u16;
                memcpy(&u16, &u->uu.uuid128[2], sizeof(u16));
                su.uu.uuid16 = ntohs(u16);
                APPL_TRACE_DEBUG("shorten to 16 bits uuid: %x", su.uu.uuid16);
            }
            else
            {
                su.len = 4;
                uint32_t u32;
                memcpy(&u32, &u->uu.uuid128[0], sizeof(u32));
                su.uu.uuid32 = ntohl(u32);
                APPL_TRACE_DEBUG("shorten to 32 bits uuid: %x", su.uu.uuid32);
            }
            return su;
        }
    }
    APPL_TRACE_DEBUG("cannot shorten none-reserved 128 bits uuid");
    return *u;
}

/*******************************************************************************
**
** Function     bta_jv_start_discovery_cback
**
** Description  Callback for Start Discovery
**
** Returns      void
**
*******************************************************************************/
static void bta_jv_start_discovery_cback(UINT16 result, void * user_data)
{
    tBTA_JV_STATUS status;
    UINT8          old_sdp_act = bta_jv_cb.sdp_active;

    APPL_TRACE_DEBUG("bta_jv_start_discovery_cback res: 0x%x", result);

    bta_jv_cb.sdp_active = BTA_JV_SDP_ACT_NONE;
    if(bta_jv_cb.p_dm_cback)
    {
        tBTA_JV_DISCOVERY_COMP dcomp;
        dcomp.scn = 0;
        status = BTA_JV_FAILURE;
        if (result == SDP_SUCCESS || result == SDP_DB_FULL)
        {
            tSDP_DISC_REC       *p_sdp_rec = NULL;
            tSDP_PROTOCOL_ELEM  pe;
            logu("bta_jv_cb.uuid", bta_jv_cb.uuid.uu.uuid128);
            tBT_UUID su = shorten_sdp_uuid(&bta_jv_cb.uuid);
            logu("shorten uuid:", su.uu.uuid128);
            p_sdp_rec = SDP_FindServiceUUIDInDb(p_bta_jv_cfg->p_sdp_db, &su, p_sdp_rec);
            APPL_TRACE_DEBUG("p_sdp_rec:%p", p_sdp_rec);
            if(p_sdp_rec && SDP_FindProtocolListElemInRec(p_sdp_rec, UUID_PROTOCOL_RFCOMM, &pe))
            {
                dcomp.scn = (UINT8) pe.params[0];
                status = BTA_JV_SUCCESS;
            }
        }

        dcomp.status = status;
        bta_jv_cb.p_dm_cback(BTA_JV_DISCOVERY_COMP_EVT, (tBTA_JV *)&dcomp, user_data);
    }
}

/*******************************************************************************
**
** Function     bta_jv_start_discovery
**
** Description  Discovers services on a remote device
**
** Returns      void
**
*******************************************************************************/
void bta_jv_start_discovery(tBTA_JV_MSG *p_data)
{
    tBTA_JV_STATUS status = BTA_JV_FAILURE;
    APPL_TRACE_DEBUG("bta_jv_start_discovery in, sdp_active:%d", bta_jv_cb.sdp_active);
    if (bta_jv_cb.sdp_active != BTA_JV_SDP_ACT_NONE)
    {
        /* SDP is still in progress */
        status = BTA_JV_BUSY;
        if(bta_jv_cb.p_dm_cback)
            bta_jv_cb.p_dm_cback(BTA_JV_DISCOVERY_COMP_EVT, (tBTA_JV *)&status, p_data->start_discovery.user_data);
        return;
    }

    /* init the database/set up the filter */
    APPL_TRACE_DEBUG("call SDP_InitDiscoveryDb, p_data->start_discovery.num_uuid:%d",
        p_data->start_discovery.num_uuid);
    SDP_InitDiscoveryDb (p_bta_jv_cfg->p_sdp_db, p_bta_jv_cfg->sdp_db_size,
                    p_data->start_discovery.num_uuid, p_data->start_discovery.uuid_list, 0, NULL);

    /* tell SDP to keep the raw data */
    p_bta_jv_cfg->p_sdp_db->raw_data = p_bta_jv_cfg->p_sdp_raw_data;
    p_bta_jv_cfg->p_sdp_db->raw_size = p_bta_jv_cfg->sdp_raw_size;

    bta_jv_cb.p_sel_raw_data     = 0;
    bta_jv_cb.uuid = p_data->start_discovery.uuid_list[0];

    bta_jv_cb.sdp_active = BTA_JV_SDP_ACT_YES;
    if (!SDP_ServiceSearchAttributeRequest2(p_data->start_discovery.bd_addr,
                                   p_bta_jv_cfg->p_sdp_db,
                                   bta_jv_start_discovery_cback, p_data->start_discovery.user_data))
    {
        bta_jv_cb.sdp_active = BTA_JV_SDP_ACT_NONE;
        /* failed to start SDP. report the failure right away */
        if(bta_jv_cb.p_dm_cback)
            bta_jv_cb.p_dm_cback(BTA_JV_DISCOVERY_COMP_EVT, (tBTA_JV *)&status, p_data->start_discovery.user_data);
    }
    /*
    else report the result when the cback is called
    */
}

/*******************************************************************************
**
** Function     bta_jv_create_record
**
** Description  Create an SDP record with the given attributes
**
** Returns      void
**
*******************************************************************************/
void bta_jv_create_record(tBTA_JV_MSG *p_data)
{
    tBTA_JV_API_CREATE_RECORD *cr = &(p_data->create_record);
    tBTA_JV_CREATE_RECORD   evt_data;
    evt_data.status = BTA_JV_SUCCESS;
    if(bta_jv_cb.p_dm_cback)
        //callback user immediately to create his own sdp record in stack thread context
        bta_jv_cb.p_dm_cback(BTA_JV_CREATE_RECORD_EVT, (tBTA_JV *)&evt_data, cr->user_data);
}

/*******************************************************************************
**
** Function     bta_jv_delete_record
**
** Description  Delete an SDP record
**
**
** Returns      void
**
*******************************************************************************/
void bta_jv_delete_record(tBTA_JV_MSG *p_data)
{
    tBTA_JV_API_ADD_ATTRIBUTE *dr = &(p_data->add_attr);
    if(dr->handle)
    {
        /* this is a record created by btif layer*/
        SDP_DeleteRecord(dr->handle);
    }
}

/*******************************************************************************
**
** Function     bta_jv_port_data_co_cback
**
** Description  port data callback function of rfcomm
**              connections
**
** Returns      void
**
*******************************************************************************/
static int bta_jv_port_data_co_cback(UINT16 port_handle, UINT8 *buf, UINT16 len, int type)
{
    tBTA_JV_RFC_CB  *p_cb = bta_jv_rfc_port_to_cb(port_handle);
    tBTA_JV_PCB     *p_pcb = bta_jv_rfc_port_to_pcb(port_handle);
    int ret = 0;
    APPL_TRACE_DEBUG("bta_jv_port_data_co_cback, p_cb:%p, p_pcb:%p, len:%d, type:%d",
                        p_cb, p_pcb, len, type);
    if (p_pcb != NULL)
    {
        switch(type)
        {
            case DATA_CO_CALLBACK_TYPE_INCOMING:
                bta_jv_pm_conn_busy(p_pcb->p_pm_cb);
                ret = bta_co_rfc_data_incoming(p_pcb->user_data, (BT_HDR*)buf);
                bta_jv_pm_conn_idle(p_pcb->p_pm_cb);
                return ret;
            case DATA_CO_CALLBACK_TYPE_OUTGOING_SIZE:
                return bta_co_rfc_data_outgoing_size(p_pcb->user_data, (int*)buf);
            case DATA_CO_CALLBACK_TYPE_OUTGOING:
                return bta_co_rfc_data_outgoing(p_pcb->user_data, buf, len);
            default:
                APPL_TRACE_ERROR("unknown callout type:%d", type);
                break;
        }
    }
    return 0;
}

/*******************************************************************************
**
** Function     bta_jv_port_mgmt_cl_cback
**
** Description  callback for port mamangement function of rfcomm
**              client connections
**
** Returns      void
**
*******************************************************************************/
static void bta_jv_port_mgmt_cl_cback(UINT32 code, UINT16 port_handle)
{
    tBTA_JV_RFC_CB  *p_cb = bta_jv_rfc_port_to_cb(port_handle);
    tBTA_JV_PCB     *p_pcb = bta_jv_rfc_port_to_pcb(port_handle);
    tBTA_JV evt_data;
    BD_ADDR rem_bda;
    UINT16 lcid;
    tBTA_JV_RFCOMM_CBACK *p_cback;  /* the callback function */

    APPL_TRACE_DEBUG( "bta_jv_port_mgmt_cl_cback:code:%d, port_handle%d", code, port_handle);
    if(NULL == p_cb || NULL == p_cb->p_cback)
        return;

    APPL_TRACE_DEBUG( "bta_jv_port_mgmt_cl_cback code=%d port_handle:%d handle:%d",
        code, port_handle, p_cb->handle);

    PORT_CheckConnection(port_handle, rem_bda, &lcid);

    if(code == PORT_SUCCESS)
    {
        evt_data.rfc_open.handle = p_cb->handle;
        evt_data.rfc_open.status = BTA_JV_SUCCESS;
        bdcpy(evt_data.rfc_open.rem_bda, rem_bda);
        p_pcb->state = BTA_JV_ST_CL_OPEN;
        p_cb->p_cback(BTA_JV_RFCOMM_OPEN_EVT, &evt_data, p_pcb->user_data);
    }
    else
    {
        evt_data.rfc_close.handle = p_cb->handle;
        evt_data.rfc_close.status = BTA_JV_FAILURE;
        evt_data.rfc_close.port_status = code;
        evt_data.rfc_close.async = TRUE;
        if (p_pcb->state == BTA_JV_ST_CL_CLOSING)
        {
            evt_data.rfc_close.async = FALSE;
        }
        //p_pcb->state = BTA_JV_ST_NONE;
        //p_pcb->cong = FALSE;
        p_cback = p_cb->p_cback;
        p_cback(BTA_JV_RFCOMM_CLOSE_EVT, &evt_data, p_pcb->user_data);
        //bta_jv_free_rfc_cb(p_cb, p_pcb);
    }

}

/*******************************************************************************
**
** Function     bta_jv_port_event_cl_cback
**
** Description  Callback for RFCOMM client port events
**
** Returns      void
**
*******************************************************************************/
static void bta_jv_port_event_cl_cback(UINT32 code, UINT16 port_handle)
{
    tBTA_JV_RFC_CB  *p_cb = bta_jv_rfc_port_to_cb(port_handle);
    tBTA_JV_PCB     *p_pcb = bta_jv_rfc_port_to_pcb(port_handle);
    tBTA_JV evt_data;

    APPL_TRACE_DEBUG( "bta_jv_port_event_cl_cback:%d", port_handle);
    if(NULL == p_cb || NULL == p_cb->p_cback)
        return;

    APPL_TRACE_DEBUG( "bta_jv_port_event_cl_cback code=x%x port_handle:%d handle:%d",
        code, port_handle, p_cb->handle);
    if (code & PORT_EV_RXCHAR)
    {
        evt_data.data_ind.handle = p_cb->handle;
        p_cb->p_cback(BTA_JV_RFCOMM_DATA_IND_EVT, &evt_data, p_pcb->user_data);
    }

    if (code & PORT_EV_FC)
    {
        p_pcb->cong = (code & PORT_EV_FCS) ? FALSE : TRUE;
        evt_data.rfc_cong.cong = p_pcb->cong;
        evt_data.rfc_cong.handle = p_cb->handle;
        evt_data.rfc_cong.status = BTA_JV_SUCCESS;
        p_cb->p_cback(BTA_JV_RFCOMM_CONG_EVT, &evt_data, p_pcb->user_data);
    }

    if (code & PORT_EV_TXEMPTY)
    {
        bta_jv_pm_conn_idle(p_pcb->p_pm_cb);
    }
}

/*******************************************************************************
**
** Function     bta_jv_rfcomm_connect
**
** Description  Client initiates an RFCOMM connection
**
** Returns      void
**
*******************************************************************************/
void bta_jv_rfcomm_connect(tBTA_JV_MSG *p_data)
{
    UINT16 handle = 0;
    UINT32 event_mask = BTA_JV_RFC_EV_MASK;
    tPORT_STATE port_state;
    UINT8   sec_id = 0;
    tBTA_JV_RFC_CB  *p_cb = NULL;
    tBTA_JV_PCB     *p_pcb;
    tBTA_JV_API_RFCOMM_CONNECT *cc = &(p_data->rfcomm_connect);
    tBTA_JV_RFCOMM_CL_INIT      evt_data = {0};

    /* TODO DM role manager
    L2CA_SetDesireRole(cc->role);
    */

    sec_id = bta_jv_alloc_sec_id();
    evt_data.sec_id = sec_id;
    evt_data.status = BTA_JV_SUCCESS;
    if (0 == sec_id ||
        BTM_SetSecurityLevel(TRUE, "", sec_id,  cc->sec_mask, BT_PSM_RFCOMM,
                BTM_SEC_PROTO_RFCOMM, cc->remote_scn) == FALSE)
    {
        evt_data.status = BTA_JV_FAILURE;
        APPL_TRACE_ERROR("sec_id:%d is zero or BTM_SetSecurityLevel failed, remote_scn:%d", sec_id, cc->remote_scn);
    }

    if (evt_data.status == BTA_JV_SUCCESS &&
        RFCOMM_CreateConnection(UUID_SERVCLASS_SERIAL_PORT, cc->remote_scn, FALSE,
        BTA_JV_DEF_RFC_MTU, cc->peer_bd_addr, &handle, bta_jv_port_mgmt_cl_cback) != PORT_SUCCESS)
    {
        APPL_TRACE_ERROR("bta_jv_rfcomm_connect, RFCOMM_CreateConnection failed");
        evt_data.status = BTA_JV_FAILURE;
    }
    if (evt_data.status == BTA_JV_SUCCESS)
    {
        p_cb = bta_jv_alloc_rfc_cb(handle, &p_pcb);
        if(p_cb)
        {
            p_cb->p_cback = cc->p_cback;
            p_cb->sec_id = sec_id;
            p_cb->scn = 0;
            p_pcb->state = BTA_JV_ST_CL_OPENING;
            p_pcb->user_data = cc->user_data;
            evt_data.use_co = TRUE;

            PORT_SetEventCallback(handle, bta_jv_port_event_cl_cback);
            PORT_SetEventMask(handle, event_mask);
            PORT_SetDataCOCallback (handle, bta_jv_port_data_co_cback);

            PORT_GetState(handle, &port_state);

            port_state.fc_type = (PORT_FC_CTS_ON_INPUT | PORT_FC_CTS_ON_OUTPUT);

            /* coverity[uninit_use_in_call]
               FALSE-POSITIVE: port_state is initialized at PORT_GetState() */
            PORT_SetState(handle, &port_state);

            evt_data.handle = p_cb->handle;
        }
        else
        {
            evt_data.status = BTA_JV_FAILURE;
            APPL_TRACE_ERROR("run out of rfc control block");
        }
    }
    cc->p_cback(BTA_JV_RFCOMM_CL_INIT_EVT, (tBTA_JV *)&evt_data, cc->user_data);
    if(evt_data.status == BTA_JV_FAILURE)
    {
        if(sec_id)
            bta_jv_free_sec_id(&sec_id);
        if(handle)
            RFCOMM_RemoveConnection(handle);
    }
 }

static int find_rfc_pcb(void* user_data, tBTA_JV_RFC_CB **cb, tBTA_JV_PCB **pcb)
{
    *cb = NULL;
    *pcb = NULL;
    int i;
    for (i = 0; i < MAX_RFC_PORTS; i++)
    {
        UINT32 rfc_handle = bta_jv_cb.port_cb[i].handle & BTA_JV_RFC_HDL_MASK;
        rfc_handle &= ~BTA_JV_RFCOMM_MASK;
        if (rfc_handle && bta_jv_cb.port_cb[i].user_data == user_data)
        {
            *pcb = &bta_jv_cb.port_cb[i];
            *cb = &bta_jv_cb.rfc_cb[rfc_handle - 1];
            APPL_TRACE_DEBUG("find_rfc_pcb(): FOUND rfc_cb_handle 0x%x, port.jv_handle:"
                    " 0x%x, state: %d, rfc_cb->handle: 0x%x", rfc_handle, (*pcb)->handle,
                    (*pcb)->state, (*cb)->handle);
            return 1;
        }
    }
    APPL_TRACE_DEBUG("find_rfc_pcb: cannot find rfc_cb from user data:%d", (UINT32)user_data);
    return 0;
}

/*******************************************************************************
**
** Function     bta_jv_rfcomm_close
**
** Description  Close an RFCOMM connection
**
** Returns      void
**
*******************************************************************************/
void bta_jv_rfcomm_close(tBTA_JV_MSG *p_data)
{
    tBTA_JV_API_RFCOMM_CLOSE *cc = &(p_data->rfcomm_close);
    tBTA_JV_RFC_CB           *p_cb = NULL;
    tBTA_JV_PCB              *p_pcb = NULL;
    APPL_TRACE_DEBUG("bta_jv_rfcomm_close, rfc handle:%d", cc->handle);
    if (!cc->handle)
    {
        APPL_TRACE_ERROR("bta_jv_rfcomm_close, rfc handle is null");
        return;
    }

    void* user_data = cc->user_data;
    if (!find_rfc_pcb(user_data, &p_cb, &p_pcb))
        return;
    bta_jv_free_rfc_cb(p_cb, p_pcb);
    APPL_TRACE_DEBUG("bta_jv_rfcomm_close: sec id in use:%d, rfc_cb in use:%d",
                get_sec_id_used(), get_rfc_cb_used());
}

/*******************************************************************************
**
** Function     bta_jv_port_mgmt_sr_cback
**
** Description  callback for port mamangement function of rfcomm
**              server connections
**
** Returns      void
**
*******************************************************************************/
static void bta_jv_port_mgmt_sr_cback(UINT32 code, UINT16 port_handle)
{
    tBTA_JV_PCB     *p_pcb = bta_jv_rfc_port_to_pcb(port_handle);
    tBTA_JV_RFC_CB  *p_cb = bta_jv_rfc_port_to_cb(port_handle);
    tBTA_JV evt_data;
    BD_ADDR rem_bda;
    UINT16 lcid;
    APPL_TRACE_DEBUG("bta_jv_port_mgmt_sr_cback, code:%d, port_handle:%d", code, port_handle);
    if(NULL == p_cb || NULL == p_cb->p_cback)
    {
        APPL_TRACE_ERROR("bta_jv_port_mgmt_sr_cback, p_cb:%p, p_cb->p_cback%p",
                p_cb, p_cb ? p_cb->p_cback : NULL);
        return;
    }
    void *user_data = p_pcb->user_data;
    APPL_TRACE_DEBUG( "bta_jv_port_mgmt_sr_cback code=%d port_handle:0x%x handle:0x%x, p_pcb:%p, user:%d",
        code, port_handle, p_cb->handle, p_pcb, p_pcb->user_data);

    PORT_CheckConnection(port_handle, rem_bda, &lcid);
    int failed = TRUE;
    if (code == PORT_SUCCESS)
    {
        evt_data.rfc_srv_open.handle = p_pcb->handle;
        evt_data.rfc_srv_open.status = BTA_JV_SUCCESS;
        bdcpy(evt_data.rfc_srv_open.rem_bda, rem_bda);
        tBTA_JV_PCB *p_pcb_new_listen  = bta_jv_add_rfc_port(p_cb, p_pcb);
        if (p_pcb_new_listen)
        {
            evt_data.rfc_srv_open.new_listen_handle = p_pcb_new_listen->handle;
            p_pcb_new_listen->user_data = p_cb->p_cback(BTA_JV_RFCOMM_SRV_OPEN_EVT, &evt_data, user_data);
            APPL_TRACE_DEBUG("PORT_SUCCESS: curr_sess:%d, max_sess:%d", p_cb->curr_sess, p_cb->max_sess);
            failed = FALSE;
        }
        else
            APPL_TRACE_ERROR("bta_jv_add_rfc_port failed to create new listen port");
    }
    if (failed)
    {
        evt_data.rfc_close.handle = p_cb->handle;
        evt_data.rfc_close.status = BTA_JV_FAILURE;
        evt_data.rfc_close.async = TRUE;
        evt_data.rfc_close.port_status = code;
        p_pcb->cong = FALSE;

        tBTA_JV_RFCOMM_CBACK    *p_cback = p_cb->p_cback;
        APPL_TRACE_DEBUG("PORT_CLOSED before BTA_JV_RFCOMM_CLOSE_EVT: curr_sess:%d, max_sess:%d",
                            p_cb->curr_sess, p_cb->max_sess);
        if(BTA_JV_ST_SR_CLOSING == p_pcb->state)
        {
            evt_data.rfc_close.async = FALSE;
            evt_data.rfc_close.status = BTA_JV_SUCCESS;
        }
        //p_pcb->state = BTA_JV_ST_NONE;
        p_cback(BTA_JV_RFCOMM_CLOSE_EVT, &evt_data, user_data);
        //bta_jv_free_rfc_cb(p_cb, p_pcb);

        APPL_TRACE_DEBUG("PORT_CLOSED after BTA_JV_RFCOMM_CLOSE_EVT: curr_sess:%d, max_sess:%d",
                p_cb->curr_sess, p_cb->max_sess);
     }
}

/*******************************************************************************
**
** Function     bta_jv_port_event_sr_cback
**
** Description  Callback for RFCOMM server port events
**
** Returns      void
**
*******************************************************************************/
static void bta_jv_port_event_sr_cback(UINT32 code, UINT16 port_handle)
{
    tBTA_JV_PCB     *p_pcb = bta_jv_rfc_port_to_pcb(port_handle);
    tBTA_JV_RFC_CB  *p_cb = bta_jv_rfc_port_to_cb(port_handle);
    tBTA_JV evt_data;

    if(NULL == p_cb || NULL == p_cb->p_cback)
        return;

    APPL_TRACE_DEBUG( "bta_jv_port_event_sr_cback code=x%x port_handle:%d handle:%d",
        code, port_handle, p_cb->handle);

    void *user_data = p_pcb->user_data;
    if (code & PORT_EV_RXCHAR)
    {
        evt_data.data_ind.handle = p_cb->handle;
        p_cb->p_cback(BTA_JV_RFCOMM_DATA_IND_EVT, &evt_data, user_data);
    }

    if (code & PORT_EV_FC)
    {
        p_pcb->cong = (code & PORT_EV_FCS) ? FALSE : TRUE;
        evt_data.rfc_cong.cong = p_pcb->cong;
        evt_data.rfc_cong.handle = p_cb->handle;
        evt_data.rfc_cong.status = BTA_JV_SUCCESS;
        p_cb->p_cback(BTA_JV_RFCOMM_CONG_EVT, &evt_data, user_data);
    }

    if (code & PORT_EV_TXEMPTY)
    {
        bta_jv_pm_conn_idle(p_pcb->p_pm_cb);
    }
}

/*******************************************************************************
**
** Function     bta_jv_add_rfc_port
**
** Description  add a port for server when the existing posts is open
**
** Returns   return a pointer to tBTA_JV_PCB just added
**
*******************************************************************************/
static tBTA_JV_PCB * bta_jv_add_rfc_port(tBTA_JV_RFC_CB *p_cb, tBTA_JV_PCB *p_pcb_open)
{
    UINT8   used = 0, i, listen=0;
    UINT32  si = 0;
    tPORT_STATE port_state;
    UINT32 event_mask = BTA_JV_RFC_EV_MASK;
    tBTA_JV_PCB *p_pcb = NULL;
    if (p_cb->max_sess > 1)
    {
        for (i=0; i < p_cb->max_sess; i++)
        {
            if (p_cb->rfc_hdl[i] != 0)
            {
                p_pcb = &bta_jv_cb.port_cb[p_cb->rfc_hdl[i] - 1];
                if (p_pcb->state == BTA_JV_ST_SR_LISTEN)
                {
                    listen++;
                    if(p_pcb_open == p_pcb)
                    {
                        APPL_TRACE_DEBUG("bta_jv_add_rfc_port, port_handle:%d, change the listen port to open state",
                                              p_pcb->port_handle);
                        p_pcb->state = BTA_JV_ST_SR_OPEN;

                    }
                    else
                    {
                        APPL_TRACE_ERROR("bta_jv_add_rfc_port, open pcb not matching listen one,"
                            "listen count:%d, listen pcb handle:%d, open pcb:%d",
                               listen, p_pcb->port_handle, p_pcb_open->handle);
                        return NULL;
                    }
                }
                used++;
            }
            else if (si == 0)
            {
                si = i + 1;
            }
        }

        APPL_TRACE_DEBUG("bta_jv_add_rfc_port max_sess=%d used:%d curr_sess:%d, listen:%d si:%d",
                    p_cb->max_sess, used, p_cb->curr_sess, listen, si);
        if (used < p_cb->max_sess && listen == 1 && si)
        {
            si--;
            if (RFCOMM_CreateConnection(p_cb->sec_id, p_cb->scn, TRUE,
                BTA_JV_DEF_RFC_MTU, (UINT8 *) bd_addr_any, &(p_cb->rfc_hdl[si]), bta_jv_port_mgmt_sr_cback) == PORT_SUCCESS)
            {
                p_cb->curr_sess++;
                p_pcb = &bta_jv_cb.port_cb[p_cb->rfc_hdl[si] - 1];
                p_pcb->state = BTA_JV_ST_SR_LISTEN;
                p_pcb->port_handle = p_cb->rfc_hdl[si];
                p_pcb->user_data = p_pcb_open->user_data;

                PORT_ClearKeepHandleFlag(p_pcb->port_handle);
                PORT_SetEventCallback(p_pcb->port_handle, bta_jv_port_event_sr_cback);
                PORT_SetDataCOCallback (p_pcb->port_handle, bta_jv_port_data_co_cback);
                PORT_SetEventMask(p_pcb->port_handle, event_mask);
                PORT_GetState(p_pcb->port_handle, &port_state);

                port_state.fc_type = (PORT_FC_CTS_ON_INPUT | PORT_FC_CTS_ON_OUTPUT);

                PORT_SetState(p_pcb->port_handle, &port_state);
                p_pcb->handle = BTA_JV_RFC_H_S_TO_HDL(p_cb->handle, si);
                APPL_TRACE_DEBUG("bta_jv_add_rfc_port: p_pcb->handle:0x%x, curr_sess:%d",
                                    p_pcb->handle, p_cb->curr_sess);
            }
        }
        else
            APPL_TRACE_ERROR("bta_jv_add_rfc_port, cannot create new rfc listen port");
    }
    APPL_TRACE_DEBUG("bta_jv_add_rfc_port: sec id in use:%d, rfc_cb in use:%d",
                get_sec_id_used(), get_rfc_cb_used());
    return p_pcb;
}

/*******************************************************************************
**
** Function     bta_jv_rfcomm_start_server
**
** Description  waits for an RFCOMM client to connect
**
**
** Returns      void
**
*******************************************************************************/
void bta_jv_rfcomm_start_server(tBTA_JV_MSG *p_data)
{
    UINT16 handle = 0;
    UINT32 event_mask = BTA_JV_RFC_EV_MASK;
    tPORT_STATE port_state;
    UINT8   sec_id = 0;
    tBTA_JV_RFC_CB  *p_cb = NULL;
    tBTA_JV_PCB     *p_pcb;
    tBTA_JV_API_RFCOMM_SERVER *rs = &(p_data->rfcomm_server);
    tBTA_JV_RFCOMM_START        evt_data = {0};
    /* TODO DM role manager
    L2CA_SetDesireRole(rs->role);
    */
    evt_data.status = BTA_JV_FAILURE;
    APPL_TRACE_DEBUG("bta_jv_rfcomm_start_server: sec id in use:%d, rfc_cb in use:%d",
                get_sec_id_used(), get_rfc_cb_used());

    do
    {
        sec_id = bta_jv_alloc_sec_id();

        if (0 == sec_id ||
            BTM_SetSecurityLevel(FALSE, "JV PORT", sec_id,  rs->sec_mask,
                BT_PSM_RFCOMM, BTM_SEC_PROTO_RFCOMM, rs->local_scn) == FALSE)
        {
            APPL_TRACE_ERROR("bta_jv_rfcomm_start_server, run out of sec_id");
            break;
        }

        if (RFCOMM_CreateConnection(sec_id, rs->local_scn, TRUE,
            BTA_JV_DEF_RFC_MTU, (UINT8 *) bd_addr_any, &handle, bta_jv_port_mgmt_sr_cback) != PORT_SUCCESS)
        {
            APPL_TRACE_ERROR("bta_jv_rfcomm_start_server, RFCOMM_CreateConnection failed");
            break;
        }


        p_cb = bta_jv_alloc_rfc_cb(handle, &p_pcb);
        if(!p_cb)
        {
            APPL_TRACE_ERROR("bta_jv_rfcomm_start_server, run out of rfc control block");
            break;
        }

        p_cb->max_sess = rs->max_session;
        p_cb->p_cback = rs->p_cback;
        p_cb->sec_id = sec_id;
        p_cb->scn = rs->local_scn;
        p_pcb->state = BTA_JV_ST_SR_LISTEN;
        p_pcb->user_data = rs->user_data;
        evt_data.status = BTA_JV_SUCCESS;
        evt_data.handle = p_cb->handle;
        evt_data.sec_id = sec_id;
        evt_data.use_co = TRUE;

        PORT_ClearKeepHandleFlag(handle);
        PORT_SetEventCallback(handle, bta_jv_port_event_sr_cback);
        PORT_SetEventMask(handle, event_mask);
        PORT_GetState(handle, &port_state);

        port_state.fc_type = (PORT_FC_CTS_ON_INPUT | PORT_FC_CTS_ON_OUTPUT);

        PORT_SetState(handle, &port_state);
    } while (0);

    rs->p_cback(BTA_JV_RFCOMM_START_EVT, (tBTA_JV *)&evt_data, rs->user_data);
    if(evt_data.status == BTA_JV_SUCCESS)
    {
        PORT_SetDataCOCallback (handle, bta_jv_port_data_co_cback);
    }
    else
    {
        if(sec_id)
            bta_jv_free_sec_id(&sec_id);
        if(handle)
            RFCOMM_RemoveConnection(handle);
    }
}

/*******************************************************************************
**
** Function     bta_jv_rfcomm_stop_server
**
** Description  stops an RFCOMM server
**
** Returns      void
**
*******************************************************************************/

void bta_jv_rfcomm_stop_server(tBTA_JV_MSG *p_data)
{
    tBTA_JV_API_RFCOMM_SERVER *ls = &(p_data->rfcomm_server);
    tBTA_JV_RFC_CB           *p_cb = NULL;
    tBTA_JV_PCB              *p_pcb = NULL;
    APPL_TRACE_DEBUG("bta_jv_rfcomm_stop_server");
    if(!ls->handle)
    {
        APPL_TRACE_ERROR("bta_jv_rfcomm_stop_server, jv handle is null");
        return;
    }
    void* user_data = ls->user_data;
    if(!find_rfc_pcb(user_data, &p_cb, &p_pcb))
        return;
    APPL_TRACE_DEBUG("bta_jv_rfcomm_stop_server: p_pcb:%p, p_pcb->port_handle:%d",
                        p_pcb, p_pcb->port_handle);
    bta_jv_free_rfc_cb(p_cb, p_pcb);
    APPL_TRACE_DEBUG("bta_jv_rfcomm_stop_server: sec id in use:%d, rfc_cb in use:%d",
                get_sec_id_used(), get_rfc_cb_used());
}

/*******************************************************************************
**
** Function     bta_jv_rfcomm_read
**
** Description  Read data from an RFCOMM connection
**
** Returns      void
**
*******************************************************************************/
void bta_jv_rfcomm_read(tBTA_JV_MSG *p_data)
{
    tBTA_JV_API_RFCOMM_READ *rc = &(p_data->rfcomm_read);
    tBTA_JV_RFC_CB  *p_cb = rc->p_cb;
    tBTA_JV_PCB     *p_pcb = rc->p_pcb;
    tBTA_JV_RFCOMM_READ    evt_data;

    evt_data.status = BTA_JV_FAILURE;
    evt_data.handle = p_cb->handle;
    evt_data.req_id = rc->req_id;
    evt_data.p_data = rc->p_data;
    if (PORT_ReadData(rc->p_pcb->port_handle, (char *)rc->p_data, rc->len, &evt_data.len) ==
        PORT_SUCCESS)
    {
        evt_data.status = BTA_JV_SUCCESS;
    }

    p_cb->p_cback(BTA_JV_RFCOMM_READ_EVT, (tBTA_JV *)&evt_data, p_pcb->user_data);
}

/*******************************************************************************
**
** Function     bta_jv_rfcomm_write
**
** Description  write data to an RFCOMM connection
**
** Returns      void
**
*******************************************************************************/
void bta_jv_rfcomm_write(tBTA_JV_MSG *p_data)
{
    tBTA_JV_API_RFCOMM_WRITE *wc = &(p_data->rfcomm_write);
    tBTA_JV_RFC_CB  *p_cb = wc->p_cb;
    tBTA_JV_PCB     *p_pcb = wc->p_pcb;
    tBTA_JV_RFCOMM_WRITE    evt_data;

    evt_data.status = BTA_JV_FAILURE;
    evt_data.handle = p_cb->handle;
    evt_data.req_id = wc->req_id;
    evt_data.cong   = p_pcb->cong;
    evt_data.len    = 0;
    bta_jv_pm_conn_busy(p_pcb->p_pm_cb);
    if (!evt_data.cong &&
        PORT_WriteDataCO(p_pcb->port_handle, &evt_data.len) ==
        PORT_SUCCESS)
    {
        evt_data.status = BTA_JV_SUCCESS;
    }
    //update congestion flag
    evt_data.cong   = p_pcb->cong;
    if (p_cb->p_cback)
    {
        p_cb->p_cback(BTA_JV_RFCOMM_WRITE_EVT, (tBTA_JV *)&evt_data, p_pcb->user_data);
    }
    else
    {
        APPL_TRACE_ERROR("bta_jv_rfcomm_write :: WARNING ! No JV callback set");
    }
}

/*******************************************************************************
 **
 ** Function     bta_jv_set_pm_profile
 **
 ** Description  Set or free power mode profile for a JV application
 **
 ** Returns      void
 **
 *******************************************************************************/
void bta_jv_set_pm_profile(tBTA_JV_MSG *p_data)
{
    tBTA_JV_STATUS status;
    tBTA_JV_PM_CB *p_cb;

    APPL_TRACE_API("bta_jv_set_pm_profile(handle: 0x%x, app_id: %d, init_st: %d)",
            p_data->set_pm.handle, p_data->set_pm.app_id, p_data->set_pm.init_st);

    /* clear PM control block */
    if (p_data->set_pm.app_id == BTA_JV_PM_ID_CLEAR)
    {
        status = bta_jv_free_set_pm_profile_cb(p_data->set_pm.handle);

        if (status != BTA_JV_SUCCESS)
        {
            APPL_TRACE_WARNING("bta_jv_set_pm_profile() free pm cb failed: reason %d",
                    status);
        }
    }
    else /* set PM control block */
    {
        p_cb = bta_jv_alloc_set_pm_profile_cb(p_data->set_pm.handle,
                p_data->set_pm.app_id);

        if (NULL != p_cb)
            bta_jv_pm_state_change(p_cb, p_data->set_pm.init_st);
        else
            APPL_TRACE_WARNING("bta_jv_alloc_set_pm_profile_cb() failed");
    }
}

/*******************************************************************************
 **
 ** Function     bta_jv_change_pm_state
 **
 ** Description  change jv pm connect state, used internally
 **
 ** Returns      void
 **
 *******************************************************************************/
void bta_jv_change_pm_state(tBTA_JV_MSG *p_data)
{
    tBTA_JV_API_PM_STATE_CHANGE *p_msg = (tBTA_JV_API_PM_STATE_CHANGE *)p_data;

    if (p_msg->p_cb)
        bta_jv_pm_state_change(p_msg->p_cb, p_msg->state);
}


/*******************************************************************************
 **
 ** Function    bta_jv_set_pm_conn_state
 **
 ** Description Send pm event state change to jv state machine to serialize jv pm changes
 **             in relation to other jv messages. internal API use mainly.
 **
 ** Params:     p_cb: jv pm control block, NULL pointer returns failure
 **             new_state: new PM connections state, setting is forced by action function
 **
 ** Returns     BTA_JV_SUCCESS, BTA_JV_FAILURE (buffer allocation, or NULL ptr!)
 **
 *******************************************************************************/
tBTA_JV_STATUS bta_jv_set_pm_conn_state(tBTA_JV_PM_CB *p_cb, const tBTA_JV_CONN_STATE
        new_st)
{
    tBTA_JV_STATUS status = BTA_JV_FAILURE;
    tBTA_JV_API_PM_STATE_CHANGE *p_msg;

    if (NULL == p_cb)
        return status;

    APPL_TRACE_API("bta_jv_set_pm_conn_state(handle:0x%x, state: %d)", p_cb->handle,
            new_st);
    if ((p_msg = (tBTA_JV_API_PM_STATE_CHANGE *)GKI_getbuf(
            sizeof(tBTA_JV_API_PM_STATE_CHANGE))) != NULL)
    {
        p_msg->hdr.event = BTA_JV_API_PM_STATE_CHANGE_EVT;
        p_msg->p_cb = p_cb;
        p_msg->state = new_st;
        bta_sys_sendmsg(p_msg);
        status = BTA_JV_SUCCESS;
    }
    return (status);
}

/*******************************************************************************
 **
 ** Function    bta_jv_pm_conn_busy
 **
 ** Description set pm connection busy state (input param safe)
 **
 ** Params      p_cb: pm control block of jv connection
 **
 ** Returns     void
 **
 *******************************************************************************/
static void bta_jv_pm_conn_busy(tBTA_JV_PM_CB *p_cb)
{
    if ((NULL != p_cb) && (BTA_JV_PM_IDLE_ST == p_cb->state))
        bta_jv_pm_state_change(p_cb, BTA_JV_CONN_BUSY);
}

/*******************************************************************************
 **
 ** Function    bta_jv_pm_conn_busy
 **
 ** Description set pm connection busy state (input param safe)
 **
 ** Params      p_cb: pm control block of jv connection
 **
 ** Returns     void
 **
 *******************************************************************************/
static void bta_jv_pm_conn_idle(tBTA_JV_PM_CB *p_cb)
{
    if ((NULL != p_cb) && (BTA_JV_PM_IDLE_ST != p_cb->state))
        bta_jv_pm_state_change(p_cb, BTA_JV_CONN_IDLE);
}

/*******************************************************************************
 **
 ** Function     bta_jv_pm_state_change
 **
 ** Description  Notify power manager there is state change
 **
 ** Params      p_cb: must be NONE NULL
 **
 ** Returns      void
 **
 *******************************************************************************/
static void bta_jv_pm_state_change(tBTA_JV_PM_CB *p_cb, const tBTA_JV_CONN_STATE state)
{
    APPL_TRACE_API("bta_jv_pm_state_change(p_cb: 0x%x, handle: 0x%x, busy/idle_state: %d"
            ", app_id: %d, conn_state: %d)", p_cb, p_cb->handle, p_cb->state,
            p_cb->app_id, state);

    switch (state)
    {
    case BTA_JV_CONN_OPEN:
        bta_sys_conn_open(BTA_ID_JV, p_cb->app_id, p_cb->peer_bd_addr);
        break;

    case BTA_JV_CONN_CLOSE:
        bta_sys_conn_close(BTA_ID_JV, p_cb->app_id, p_cb->peer_bd_addr);
        break;

    case BTA_JV_APP_OPEN:
        bta_sys_app_open(BTA_ID_JV, p_cb->app_id, p_cb->peer_bd_addr);
        break;

    case BTA_JV_APP_CLOSE:
        bta_sys_app_close(BTA_ID_JV, p_cb->app_id, p_cb->peer_bd_addr);
        break;

    case BTA_JV_SCO_OPEN:
        bta_sys_sco_open(BTA_ID_JV, p_cb->app_id, p_cb->peer_bd_addr);
        break;

    case BTA_JV_SCO_CLOSE:
        bta_sys_sco_close(BTA_ID_JV, p_cb->app_id, p_cb->peer_bd_addr);
        break;

    case BTA_JV_CONN_IDLE:
        p_cb->state = BTA_JV_PM_IDLE_ST;
        bta_sys_idle(BTA_ID_JV, p_cb->app_id, p_cb->peer_bd_addr);
        break;

    case BTA_JV_CONN_BUSY:
        p_cb->state = BTA_JV_PM_BUSY_ST;
        bta_sys_busy(BTA_ID_JV, p_cb->app_id, p_cb->peer_bd_addr);
        break;

    default:
        APPL_TRACE_WARNING("bta_jv_pm_state_change(state: %d): Invalid state", state);
        break;
    }
}
