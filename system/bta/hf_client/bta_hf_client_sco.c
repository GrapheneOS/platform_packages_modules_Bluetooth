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

#include "bta_hf_client_int.h"
#include <bt_trace.h>
#include <string.h>
#include "bt_utils.h"

#define BTA_HF_CLIENT_NO_EDR_ESCO  (BTM_SCO_PKT_TYPES_MASK_NO_2_EV3 | \
                                    BTM_SCO_PKT_TYPES_MASK_NO_3_EV3 | \
                                    BTM_SCO_PKT_TYPES_MASK_NO_2_EV5 | \
                                    BTM_SCO_PKT_TYPES_MASK_NO_3_EV5)

static const tBTM_ESCO_PARAMS bta_hf_client_esco_params[] = {
        /* SCO CVSD */
        {
                .rx_bw = BTM_64KBITS_RATE,
                .tx_bw = BTM_64KBITS_RATE,
                .max_latency = 10,
                .voice_contfmt = BTM_VOICE_SETTING_CVSD,
                .packet_types = (BTM_SCO_LINK_ONLY_MASK          |
                                 BTM_SCO_PKT_TYPES_MASK_NO_2_EV3 |
                                 BTM_SCO_PKT_TYPES_MASK_NO_3_EV3 |
                                 BTM_SCO_PKT_TYPES_MASK_NO_2_EV5 |
                                 BTM_SCO_PKT_TYPES_MASK_NO_3_EV5),
                 .retrans_effort = BTM_ESCO_RETRANS_POWER,
        },
        /* ESCO CVSD */
        {
                .rx_bw = BTM_64KBITS_RATE,
                .tx_bw = BTM_64KBITS_RATE,
                .max_latency = 10,
                .voice_contfmt = BTM_VOICE_SETTING_CVSD,
                /* Allow controller to use all types available except 5-slot EDR */
                .packet_types = (BTM_SCO_LINK_ALL_PKT_MASK |
                                 BTM_SCO_PKT_TYPES_MASK_NO_2_EV5 |
                                 BTM_SCO_PKT_TYPES_MASK_NO_3_EV5),
                .retrans_effort = BTM_ESCO_RETRANS_POWER,
        },
        /* ESCO mSBC */
        {
                .rx_bw = BTM_64KBITS_RATE,
                .tx_bw = BTM_64KBITS_RATE,
                .max_latency = 13,
                .voice_contfmt = BTM_VOICE_SETTING_TRANS,
                /* Packet Types : EV3 + 2-EV3               */
                .packet_types = (BTM_SCO_PKT_TYPES_MASK_EV3  |
                                 BTM_SCO_PKT_TYPES_MASK_NO_3_EV3 |
                                 BTM_SCO_PKT_TYPES_MASK_NO_2_EV5 |
                                 BTM_SCO_PKT_TYPES_MASK_NO_3_EV5),
                .retrans_effort = BTM_ESCO_RETRANS_QUALITY,
        }
};

enum
{
    BTA_HF_CLIENT_SCO_LISTEN_E,
    BTA_HF_CLIENT_SCO_OPEN_E,          /* open request */
    BTA_HF_CLIENT_SCO_CLOSE_E,         /* close request */
    BTA_HF_CLIENT_SCO_SHUTDOWN_E,      /* shutdown request */
    BTA_HF_CLIENT_SCO_CONN_OPEN_E,     /* sco opened */
    BTA_HF_CLIENT_SCO_CONN_CLOSE_E,    /* sco closed */
};

/*******************************************************************************
**
** Function         bta_hf_client_remove_sco
**
** Description      Removes the specified SCO from the system.
**                  If only_active is true, then SCO is only removed if connected
**
** Returns          bool   - true if Sco removal was started
**
*******************************************************************************/
static bool bta_hf_client_sco_remove(bool only_active)
{
    bool     removed_started = false;
    tBTM_STATUS status;

    APPL_TRACE_DEBUG("%s %d", __func__, only_active);

    if (bta_hf_client_cb.scb.sco_idx != BTM_INVALID_SCO_INDEX)
    {
        status = BTM_RemoveSco(bta_hf_client_cb.scb.sco_idx);

        APPL_TRACE_DEBUG("%s idx 0x%04x, status:0x%x", __func__, bta_hf_client_cb.scb.sco_idx, status);

        if (status == BTM_CMD_STARTED)
        {
            removed_started = true;
        }
        /* If no connection reset the sco handle */
        else if ( (status == BTM_SUCCESS) || (status == BTM_UNKNOWN_ADDR) )
        {
            bta_hf_client_cb.scb.sco_idx = BTM_INVALID_SCO_INDEX;
        }
    }
    return removed_started;
}

/*******************************************************************************
**
** Function         bta_hf_client_cback_sco
**
** Description      Call application callback function with SCO event.
**
**
** Returns          void
**
*******************************************************************************/
void bta_hf_client_cback_sco(uint8_t event)
{
    tBTA_HF_CLIENT    evt;

    memset(&evt, 0, sizeof(evt));

    /* call app cback */
    (*bta_hf_client_cb.p_cback)(event, (tBTA_HF_CLIENT *) &evt);
}

/*******************************************************************************
**
** Function         bta_hf_client_sco_conn_rsp
**
** Description      Process the SCO connection request
**
**
** Returns          void
**
*******************************************************************************/
static void bta_hf_client_sco_conn_rsp(tBTM_ESCO_CONN_REQ_EVT_DATA *p_data)
{
    tBTM_ESCO_PARAMS    resp;
    uint8_t               hci_status = HCI_SUCCESS;

    APPL_TRACE_DEBUG("%s", __func__);

    if (bta_hf_client_cb.scb.sco_state == BTA_HF_CLIENT_SCO_LISTEN_ST)
    {
        if (p_data->link_type == BTM_LINK_TYPE_SCO)
        {
            resp = bta_hf_client_esco_params[0];
        }
        else
        {
            resp = bta_hf_client_esco_params[bta_hf_client_cb.scb.negotiated_codec];
        }

        /* tell sys to stop av if any */
        bta_sys_sco_use(BTA_ID_HS, 1, bta_hf_client_cb.scb.peer_addr);
    }
    else
    {
        hci_status = HCI_ERR_HOST_REJECT_DEVICE;
    }

    BTM_EScoConnRsp(p_data->sco_inx, hci_status, &resp);
}

/*******************************************************************************
**
** Function         bta_hf_client_sco_connreq_cback
**
** Description      BTM eSCO connection requests and eSCO change requests
**                  Only the connection requests are processed by BTA.
**
** Returns          void
**
*******************************************************************************/
static void bta_hf_client_esco_connreq_cback(tBTM_ESCO_EVT event, tBTM_ESCO_EVT_DATA *p_data)
{
    APPL_TRACE_DEBUG("%s %d", __func__, event);

    if (event != BTM_ESCO_CONN_REQ_EVT)
    {
        return;
    }

    /* TODO check remote bdaddr, should allow connect only from device with
     * active SLC  */

    bta_hf_client_cb.scb.sco_idx = p_data->conn_evt.sco_inx;

    bta_hf_client_sco_conn_rsp(&p_data->conn_evt);

    bta_hf_client_cb.scb.sco_state = BTA_HF_CLIENT_SCO_OPENING_ST;
}

/*******************************************************************************
**
** Function         bta_hf_client_sco_conn_cback
**
** Description      BTM SCO connection callback.
**
**
** Returns          void
**
*******************************************************************************/
static void bta_hf_client_sco_conn_cback(uint16_t sco_idx)
{
    uint8_t *rem_bd;

    APPL_TRACE_DEBUG("%s %d", __func__, sco_idx);

    rem_bd = BTM_ReadScoBdAddr(sco_idx);

    if (rem_bd && bdcmp(bta_hf_client_cb.scb.peer_addr, rem_bd) == 0 &&
            bta_hf_client_cb.scb.svc_conn && bta_hf_client_cb.scb.sco_idx == sco_idx)
    {
        BT_HDR *p_buf = (BT_HDR *)osi_malloc(sizeof(BT_HDR));
        p_buf->event = BTA_HF_CLIENT_SCO_OPEN_EVT;
        p_buf->layer_specific = bta_hf_client_cb.scb.conn_handle;
        bta_sys_sendmsg(p_buf);
    }
    /* no match found; disconnect sco, init sco variables */
    else
    {
        /* should not force the sco state to shutdown state here */
        BTM_RemoveSco(sco_idx);
    }
}

/*******************************************************************************
**
** Function         bta_hf_client_sco_disc_cback
**
** Description      BTM SCO disconnection callback.
**
**
** Returns          void
**
*******************************************************************************/
static void bta_hf_client_sco_disc_cback(uint16_t sco_idx)
{
    APPL_TRACE_DEBUG("%s %d", __func__, sco_idx);

    if (bta_hf_client_cb.scb.sco_idx == sco_idx) {
        BT_HDR *p_buf = (BT_HDR *)osi_malloc(sizeof(BT_HDR));
        p_buf->event = BTA_HF_CLIENT_SCO_CLOSE_EVT;
        p_buf->layer_specific = bta_hf_client_cb.scb.conn_handle;;
        bta_sys_sendmsg(p_buf);
    }
}

/*******************************************************************************
**
** Function         bta_hf_client_create_sco
**
** Description
**
**
** Returns          void
**
*******************************************************************************/
static void bta_hf_client_sco_create(bool is_orig)
{
    tBTM_STATUS       status;
    uint8_t            *p_bd_addr = NULL;
    tBTM_ESCO_PARAMS params;

    APPL_TRACE_DEBUG("%s %d", __func__, is_orig);

    /* Make sure this sco handle is not already in use */
    if (bta_hf_client_cb.scb.sco_idx != BTM_INVALID_SCO_INDEX)
    {
        APPL_TRACE_WARNING("%s: Index 0x%04x already in use", __func__,
                            bta_hf_client_cb.scb.sco_idx);
        return;
    }

    params = bta_hf_client_esco_params[1];

    /* if initiating set current scb and peer bd addr */
    if (is_orig)
    {
        /* Attempt to use eSCO if remote host supports HFP >= 1.5 */
        if (bta_hf_client_cb.scb.peer_version >= HFP_VERSION_1_5 && !bta_hf_client_cb.scb.retry_with_sco_only)
        {
            BTM_SetEScoMode(BTM_LINK_TYPE_ESCO, &params);
            /* If ESCO or EDR ESCO, retry with SCO only in case of failure */
            if((params.packet_types & BTM_ESCO_LINK_ONLY_MASK)
               ||!((params.packet_types & ~(BTM_ESCO_LINK_ONLY_MASK | BTM_SCO_LINK_ONLY_MASK)) ^ BTA_HF_CLIENT_NO_EDR_ESCO))
            {
                bta_hf_client_cb.scb.retry_with_sco_only = true;
                APPL_TRACE_API("Setting retry_with_sco_only to true");
            }
        }
        else
        {
            if(bta_hf_client_cb.scb.retry_with_sco_only)
                APPL_TRACE_API("retrying with SCO only");
            bta_hf_client_cb.scb.retry_with_sco_only = false;

            BTM_SetEScoMode(BTM_LINK_TYPE_SCO, &params);
        }

        /* tell sys to stop av if any */
        bta_sys_sco_use(BTA_ID_HS, 1, bta_hf_client_cb.scb.peer_addr);
    }
    else
    {
        bta_hf_client_cb.scb.retry_with_sco_only = false;
    }

    p_bd_addr = bta_hf_client_cb.scb.peer_addr;

    status = BTM_CreateSco(p_bd_addr, is_orig, params.packet_types,
                           &bta_hf_client_cb.scb.sco_idx, bta_hf_client_sco_conn_cback,
                           bta_hf_client_sco_disc_cback);
    if (status == BTM_CMD_STARTED && !is_orig)
    {
        if(!BTM_RegForEScoEvts(bta_hf_client_cb.scb.sco_idx, bta_hf_client_esco_connreq_cback))
            APPL_TRACE_DEBUG("%s SCO registration success", __func__);
    }

    APPL_TRACE_API("%s: orig %d, inx 0x%04x, status 0x%x, pkt types 0x%04x",
                      __func__, is_orig, bta_hf_client_cb.scb.sco_idx,
                      status, params.packet_types);
}


/*******************************************************************************
**
** Function         bta_hf_client_sco_event
**
** Description      Handle SCO events
**
**
** Returns          void
**
*******************************************************************************/
static void bta_hf_client_sco_event(uint8_t event)
{
    APPL_TRACE_DEBUG("%s state: %d event: %d", __func__,
                        bta_hf_client_cb.scb.sco_state, event);

    switch (bta_hf_client_cb.scb.sco_state)
    {
        case BTA_HF_CLIENT_SCO_SHUTDOWN_ST:
            switch (event)
            {
                case BTA_HF_CLIENT_SCO_LISTEN_E:
                    /* create sco listen connection */
                    bta_hf_client_sco_create(false);
                    bta_hf_client_cb.scb.sco_state = BTA_HF_CLIENT_SCO_LISTEN_ST;
                    break;

                default:
                    APPL_TRACE_WARNING("BTA_HF_CLIENT_SCO_SHUTDOWN_ST: Ignoring event %d", event);
                    break;
            }
            break;

        case BTA_HF_CLIENT_SCO_LISTEN_ST:
            switch (event)
            {
                case BTA_HF_CLIENT_SCO_LISTEN_E:
                    /* create sco listen connection (Additional channel) */
                    bta_hf_client_sco_create(false);
                    break;

                case BTA_HF_CLIENT_SCO_OPEN_E:
                    /* remove listening connection */
                    bta_hf_client_sco_remove(false);

                    /* create sco connection to peer */
                    bta_hf_client_sco_create(true);
                    bta_hf_client_cb.scb.sco_state = BTA_HF_CLIENT_SCO_OPENING_ST;
                    break;

                case BTA_HF_CLIENT_SCO_SHUTDOWN_E:
                    /* remove listening connection */
                    bta_hf_client_sco_remove(false);

                    bta_hf_client_cb.scb.sco_state = BTA_HF_CLIENT_SCO_SHUTDOWN_ST;
                    break;

                case BTA_HF_CLIENT_SCO_CLOSE_E:
                    /* remove listening connection */
                    /* Ignore the event. We need to keep listening SCO for the active SLC */
                    APPL_TRACE_WARNING("BTA_HF_CLIENT_SCO_LISTEN_ST: Ignoring event %d", event);
                    break;

                case BTA_HF_CLIENT_SCO_CONN_CLOSE_E:
                    /* sco failed; create sco listen connection */
                    bta_hf_client_sco_create(false);
                    bta_hf_client_cb.scb.sco_state = BTA_HF_CLIENT_SCO_LISTEN_ST;
                    break;

                default:
                    APPL_TRACE_WARNING("BTA_HF_CLIENT_SCO_LISTEN_ST: Ignoring event %d", event);
                    break;
            }
            break;

        case BTA_HF_CLIENT_SCO_OPENING_ST:
            switch (event)
            {
                case BTA_HF_CLIENT_SCO_CLOSE_E:
                    bta_hf_client_cb.scb.sco_state = BTA_HF_CLIENT_SCO_OPEN_CL_ST;
                    break;

                case BTA_HF_CLIENT_SCO_SHUTDOWN_E:
                    bta_hf_client_cb.scb.sco_state = BTA_HF_CLIENT_SCO_SHUTTING_ST;
                    break;

                case BTA_HF_CLIENT_SCO_CONN_OPEN_E:
                    bta_hf_client_cb.scb.sco_state = BTA_HF_CLIENT_SCO_OPEN_ST;
                    break;

                case BTA_HF_CLIENT_SCO_CONN_CLOSE_E:
                    /* sco failed; create sco listen connection */
                    bta_hf_client_sco_create(false);
                    bta_hf_client_cb.scb.sco_state = BTA_HF_CLIENT_SCO_LISTEN_ST;
                    break;

                default:
                    APPL_TRACE_WARNING("BTA_HF_CLIENT_SCO_OPENING_ST: Ignoring event %d", event);
                    break;
            }
            break;

        case BTA_HF_CLIENT_SCO_OPEN_CL_ST:
            switch (event)
            {
                case BTA_HF_CLIENT_SCO_OPEN_E:
                    bta_hf_client_cb.scb.sco_state = BTA_HF_CLIENT_SCO_OPENING_ST;
                    break;

                case BTA_HF_CLIENT_SCO_SHUTDOWN_E:
                    bta_hf_client_cb.scb.sco_state = BTA_HF_CLIENT_SCO_SHUTTING_ST;
                    break;

                case BTA_HF_CLIENT_SCO_CONN_OPEN_E:
                    /* close sco connection */
                    bta_hf_client_sco_remove(true);

                    bta_hf_client_cb.scb.sco_state = BTA_HF_CLIENT_SCO_CLOSING_ST;
                    break;

                case BTA_HF_CLIENT_SCO_CONN_CLOSE_E:
                    /* sco failed; create sco listen connection */

                    bta_hf_client_cb.scb.sco_state = BTA_HF_CLIENT_SCO_LISTEN_ST;
                    break;

                default:
                    APPL_TRACE_WARNING("BTA_HF_CLIENT_SCO_OPEN_CL_ST: Ignoring event %d", event);
                    break;
            }
            break;

        case BTA_HF_CLIENT_SCO_OPEN_ST:
            switch (event)
            {
                case BTA_HF_CLIENT_SCO_CLOSE_E:
                    /* close sco connection if active */
                    if (bta_hf_client_sco_remove(true))
                    {
                        bta_hf_client_cb.scb.sco_state = BTA_HF_CLIENT_SCO_CLOSING_ST;
                    }
                    break;

                case BTA_HF_CLIENT_SCO_SHUTDOWN_E:
                    /* remove all listening connections */
                    bta_hf_client_sco_remove(false);

                    bta_hf_client_cb.scb.sco_state = BTA_HF_CLIENT_SCO_SHUTTING_ST;
                    break;

                case BTA_HF_CLIENT_SCO_CONN_CLOSE_E:
                    /* peer closed sco; create sco listen connection */
                    bta_hf_client_sco_create(false);
                    bta_hf_client_cb.scb.sco_state = BTA_HF_CLIENT_SCO_LISTEN_ST;
                    break;

                default:
                    APPL_TRACE_WARNING("BTA_HF_CLIENT_SCO_OPEN_ST: Ignoring event %d", event);
                    break;
            }
            break;

        case BTA_HF_CLIENT_SCO_CLOSING_ST:
            switch (event)
            {
                case BTA_HF_CLIENT_SCO_OPEN_E:
                    bta_hf_client_cb.scb.sco_state = BTA_HF_CLIENT_SCO_CLOSE_OP_ST;
                    break;

                case BTA_HF_CLIENT_SCO_SHUTDOWN_E:
                    bta_hf_client_cb.scb.sco_state = BTA_HF_CLIENT_SCO_SHUTTING_ST;
                    break;

                case BTA_HF_CLIENT_SCO_CONN_CLOSE_E:
                    /* peer closed sco; create sco listen connection */
                    bta_hf_client_sco_create(false);

                    bta_hf_client_cb.scb.sco_state = BTA_HF_CLIENT_SCO_LISTEN_ST;
                    break;

                default:
                    APPL_TRACE_WARNING("BTA_HF_CLIENT_SCO_CLOSING_ST: Ignoring event %d", event);
                    break;
            }
            break;

        case BTA_HF_CLIENT_SCO_CLOSE_OP_ST:
            switch (event)
            {
                case BTA_HF_CLIENT_SCO_CLOSE_E:
                    bta_hf_client_cb.scb.sco_state = BTA_HF_CLIENT_SCO_CLOSING_ST;
                    break;

                case BTA_HF_CLIENT_SCO_SHUTDOWN_E:
                    bta_hf_client_cb.scb.sco_state = BTA_HF_CLIENT_SCO_SHUTTING_ST;
                    break;

                case BTA_HF_CLIENT_SCO_CONN_CLOSE_E:
                    /* open sco connection */
                    bta_hf_client_sco_create(true);
                    bta_hf_client_cb.scb.sco_state = BTA_HF_CLIENT_SCO_OPENING_ST;
                    break;

                default:
                    APPL_TRACE_WARNING("BTA_HF_CLIENT_SCO_CLOSE_OP_ST: Ignoring event %d", event);
                    break;
            }
            break;

        case BTA_HF_CLIENT_SCO_SHUTTING_ST:
            switch (event)
            {
                case BTA_HF_CLIENT_SCO_CONN_OPEN_E:
                    /* close sco connection; wait for conn close event */
                    bta_hf_client_sco_remove(true);
                    break;

                case BTA_HF_CLIENT_SCO_CONN_CLOSE_E:
                    bta_hf_client_cb.scb.sco_state = BTA_HF_CLIENT_SCO_SHUTDOWN_ST;
                    break;

                case BTA_HF_CLIENT_SCO_SHUTDOWN_E:
                    bta_hf_client_cb.scb.sco_state = BTA_HF_CLIENT_SCO_SHUTDOWN_ST;
                    break;

                default:
                    APPL_TRACE_WARNING("BTA_HF_CLIENT_SCO_SHUTTING_ST: Ignoring event %d", event);
                    break;
            }
            break;

        default:
            break;
    }
}

/*******************************************************************************
**
** Function         bta_hf_client_sco_listen
**
** Description      Initialize SCO listener
**
**
** Returns          void
**
*******************************************************************************/
void bta_hf_client_sco_listen(tBTA_HF_CLIENT_DATA *p_data)
{
    UNUSED(p_data);

    APPL_TRACE_DEBUG("%s", __func__);

    bta_hf_client_sco_event(BTA_HF_CLIENT_SCO_LISTEN_E);
}

/*******************************************************************************
**
** Function         bta_hf_client_sco_shutdown
**
** Description
**
**
** Returns          void
**
*******************************************************************************/
void bta_hf_client_sco_shutdown(tBTA_HF_CLIENT_DATA *p_data)
{
    UNUSED(p_data);

    APPL_TRACE_DEBUG("%s", __func__);

    bta_hf_client_sco_event(BTA_HF_CLIENT_SCO_SHUTDOWN_E);
}

/*******************************************************************************
**
** Function         bta_hf_client_sco_conn_open
**
** Description
**
**
** Returns          void
**
*******************************************************************************/
void bta_hf_client_sco_conn_open(tBTA_HF_CLIENT_DATA *p_data)
{
    UNUSED(p_data);

    APPL_TRACE_DEBUG("%s", __func__);

    bta_hf_client_sco_event(BTA_HF_CLIENT_SCO_CONN_OPEN_E);

    bta_sys_sco_open(BTA_ID_HS, 1, bta_hf_client_cb.scb.peer_addr);

    if (bta_hf_client_cb.scb.negotiated_codec == BTM_SCO_CODEC_MSBC)
    {
        bta_hf_client_cback_sco(BTA_HF_CLIENT_AUDIO_MSBC_OPEN_EVT);
    }
    else
    {
        bta_hf_client_cback_sco(BTA_HF_CLIENT_AUDIO_OPEN_EVT);
    }

    bta_hf_client_cb.scb.retry_with_sco_only = false;
}

/*******************************************************************************
**
** Function         bta_hf_client_sco_conn_close
**
** Description
**
**
** Returns          void
**
*******************************************************************************/
void bta_hf_client_sco_conn_close(tBTA_HF_CLIENT_DATA *p_data)
{
    APPL_TRACE_DEBUG("%s", __func__);

    /* clear current scb */
    bta_hf_client_cb.scb.sco_idx = BTM_INVALID_SCO_INDEX;

    /* retry_with_sco_only, will be set only when initiator
    ** and HFClient is first trying to establish an eSCO connection */
    if (bta_hf_client_cb.scb.retry_with_sco_only && bta_hf_client_cb.scb.svc_conn)
    {
        bta_hf_client_sco_create(true);
    }
    else
    {
        bta_hf_client_sco_event(BTA_HF_CLIENT_SCO_CONN_CLOSE_E);

        bta_sys_sco_close(BTA_ID_HS, 1, bta_hf_client_cb.scb.peer_addr);

        bta_sys_sco_unuse(BTA_ID_HS, 1, bta_hf_client_cb.scb.peer_addr);

        /* call app callback */
        bta_hf_client_cback_sco(BTA_HF_CLIENT_AUDIO_CLOSE_EVT);

        if (bta_hf_client_cb.scb.sco_close_rfc == true)
        {
            bta_hf_client_cb.scb.sco_close_rfc = false;
            bta_hf_client_rfc_do_close(p_data);
        }
    }
    bta_hf_client_cb.scb.retry_with_sco_only = false;
}

/*******************************************************************************
**
** Function         bta_hf_client_sco_open
**
** Description
**
**
** Returns          void
**
*******************************************************************************/
void bta_hf_client_sco_open(tBTA_HF_CLIENT_DATA *p_data)
{
    UNUSED(p_data);

    APPL_TRACE_DEBUG("%s", __func__);

    bta_hf_client_sco_event(BTA_HF_CLIENT_SCO_OPEN_E);
}

/*******************************************************************************
**
** Function         bta_hf_client_sco_close
**
** Description
**
**
** Returns          void
**
*******************************************************************************/
void bta_hf_client_sco_close(tBTA_HF_CLIENT_DATA *p_data)
{
    UNUSED(p_data);

    APPL_TRACE_DEBUG("%s  0x%x", __func__, bta_hf_client_cb.scb.sco_idx);

    if (bta_hf_client_cb.scb.sco_idx != BTM_INVALID_SCO_INDEX)
    {
        bta_hf_client_sco_event(BTA_HF_CLIENT_SCO_CLOSE_E);
    }
}
