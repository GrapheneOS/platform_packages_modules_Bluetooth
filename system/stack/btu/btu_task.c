/******************************************************************************
 *
 *  Copyright (C) 1999-2012 Broadcom Corporation
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
 *  This file contains the main Bluetooth Upper Layer processing loop.
 *  The Broadcom implementations of L2CAP RFCOMM, SDP and the BTIf run as one
 *  GKI task. This btu_task switches between them.
 *
 *  Note that there will always be an L2CAP, but there may or may not be an
 *  RFCOMM or SDP. Whether these layers are present or not is determined by
 *  compile switches.
 *
 ******************************************************************************/

#include <assert.h>

#define LOG_TAG "btu_task"
#include <cutils/log.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "alarm.h"
#include "bt_target.h"
#include "bt_trace.h"
#include "bt_types.h"
#include "bt_utils.h"
#include "btm_api.h"
#include "btm_int.h"
#include "btu.h"
#include "fixed_queue.h"
#include "gki.h"
#include "hash_map.h"
#include "hcimsgs.h"
#include "l2c_int.h"
#include "btu.h"
#include "bt_utils.h"
#include <sys/prctl.h>

#include "sdpint.h"

#if ( defined(RFCOMM_INCLUDED) && RFCOMM_INCLUDED == TRUE )
#include "port_api.h"
#include "port_ext.h"
#endif

#if (defined(EVAL) && EVAL == TRUE)
#include "btu_eval.h"
#endif

#if GAP_INCLUDED == TRUE
#include "gap_int.h"
#endif

#if (defined(OBX_INCLUDED) && OBX_INCLUDED == TRUE)
#include "obx_int.h"

#if (defined(BIP_INCLUDED) && BIP_INCLUDED == TRUE)
#include "bip_int.h"
#endif /* BIP */

#if (BPP_SND_INCLUDED == TRUE ||  BPP_INCLUDED == TRUE)
#include "bpp_int.h"
#endif /* BPP */

#endif /* OBX */

/* BTE application task */
#if APPL_INCLUDED == TRUE
#include "bte_appl.h"
#endif

#if (defined(BNEP_INCLUDED) && BNEP_INCLUDED == TRUE)
#include "bnep_int.h"
#endif

#if (defined(PAN_INCLUDED) && PAN_INCLUDED == TRUE)
#include "pan_int.h"
#endif

#if (defined(SAP_SERVER_INCLUDED) && SAP_SERVER_INCLUDED == TRUE)
#include "sap_int.h"
#endif

#if (defined(HID_DEV_INCLUDED) && HID_DEV_INCLUDED == TRUE )
#include "hidd_int.h"
#endif

#if (defined(HID_HOST_INCLUDED) && HID_HOST_INCLUDED == TRUE )
#include "hidh_int.h"
#endif

#if (defined(AVDT_INCLUDED) && AVDT_INCLUDED == TRUE)
#include "avdt_int.h"
#else
extern void avdt_rcv_sync_info (BT_HDR *p_buf); /* this is for hci_test */
#endif

#if (defined(MCA_INCLUDED) && MCA_INCLUDED == TRUE)
#include "mca_api.h"
#include "mca_defs.h"
#include "mca_int.h"
#endif

#if (defined(BTU_BTA_INCLUDED) && BTU_BTA_INCLUDED == TRUE)
#include "bta_sys.h"
#endif

#if (BLE_INCLUDED == TRUE)
#include "gatt_int.h"
#if (SMP_INCLUDED == TRUE)
#include "smp_int.h"
#endif
#include "btm_ble_int.h"
#endif

#ifdef __cplusplus
extern "C"
{
#endif

BT_API extern void BTE_InitStack(void);

#ifdef __cplusplus
}
#endif

/* Define BTU storage area
*/
#if BTU_DYNAMIC_MEMORY == FALSE
tBTU_CB  btu_cb;
#endif

// Communication queue between btu_task and bta.
extern fixed_queue_t *btu_bta_msg_queue;

// Communication queue between btu_task and hci.
extern fixed_queue_t *btu_hci_msg_queue;

// Timer queue between btu_task and bta.
extern fixed_queue_t *btu_bta_alarm_queue;

// General timer queue.
extern fixed_queue_t *btu_general_alarm_queue;
extern hash_map_t *btu_general_alarm_hash_map;
extern pthread_mutex_t btu_general_alarm_lock;

// Oneshot timer queue.
extern fixed_queue_t *btu_oneshot_alarm_queue;
extern hash_map_t *btu_oneshot_alarm_hash_map;
extern pthread_mutex_t btu_oneshot_alarm_lock;

// l2cap timer queue.
extern fixed_queue_t *btu_l2cap_alarm_queue;
extern hash_map_t *btu_l2cap_alarm_hash_map;
extern pthread_mutex_t btu_l2cap_alarm_lock;

/* Define a function prototype to allow a generic timeout handler */
typedef void (tUSER_TIMEOUT_FUNC) (TIMER_LIST_ENT *p_tle);

static void btu_l2cap_alarm_process(TIMER_LIST_ENT *p_tle);
static void btu_general_alarm_process(TIMER_LIST_ENT *p_tle);

static void btu_hci_msg_process(BT_HDR *p_msg) {
    /* Determine the input message type. */
    switch (p_msg->event & BT_EVT_MASK)
    {
        case BT_EVT_TO_BTU_HCI_ACL:
            /* All Acl Data goes to L2CAP */
            l2c_rcv_acl_data (p_msg);
            break;

        case BT_EVT_TO_BTU_L2C_SEG_XMIT:
            /* L2CAP segment transmit complete */
            l2c_link_segments_xmitted (p_msg);
            break;

        case BT_EVT_TO_BTU_HCI_SCO:
#if BTM_SCO_INCLUDED == TRUE
            btm_route_sco_data (p_msg);
            break;
#endif

        case BT_EVT_TO_BTU_HCI_EVT:
            btu_hcif_process_event ((UINT8)(p_msg->event & BT_SUB_EVT_MASK), p_msg);
            GKI_freebuf(p_msg);

#if (defined(HCILP_INCLUDED) && HCILP_INCLUDED == TRUE)
            /* If host receives events which it doesn't response to, */
            /* host should start idle timer to enter sleep mode.     */
            btu_check_bt_sleep ();
#endif
            break;

        case BT_EVT_TO_BTU_HCI_CMD:
            btu_hcif_send_cmd ((UINT8)(p_msg->event & BT_SUB_EVT_MASK), p_msg);
            break;

#if (defined(OBX_INCLUDED) && OBX_INCLUDED == TRUE)
#if (defined(OBX_SERVER_INCLUDED) && OBX_SERVER_INCLUDED == TRUE)
        case BT_EVT_TO_OBX_SR_MSG:
            obx_sr_proc_evt((tOBX_PORT_EVT *)(p_msg + 1));
            GKI_freebuf (p_msg);
            break;

        case BT_EVT_TO_OBX_SR_L2C_MSG:
            obx_sr_proc_l2c_evt((tOBX_L2C_EVT_MSG *)(p_msg + 1));
            GKI_freebuf (p_msg);
            break;
#endif

#if (defined(OBX_CLIENT_INCLUDED) && OBX_CLIENT_INCLUDED == TRUE)
        case BT_EVT_TO_OBX_CL_MSG:
            obx_cl_proc_evt((tOBX_PORT_EVT *)(p_msg + 1));
            GKI_freebuf (p_msg);
            break;

        case BT_EVT_TO_OBX_CL_L2C_MSG:
            obx_cl_proc_l2c_evt((tOBX_L2C_EVT_MSG *)(p_msg + 1));
            GKI_freebuf (p_msg);
            break;
#endif

#if (defined(BIP_INCLUDED) && BIP_INCLUDED == TRUE)
        case BT_EVT_TO_BIP_CMDS :
            bip_proc_btu_event(p_msg);
            GKI_freebuf (p_msg);
            break;
#endif /* BIP */
#if (BPP_SND_INCLUDED == TRUE || BPP_INCLUDED == TRUE)
        case BT_EVT_TO_BPP_PR_CMDS:
            bpp_pr_proc_event(p_msg);
            GKI_freebuf (p_msg);
            break;
        case BT_EVT_TO_BPP_SND_CMDS:
            bpp_snd_proc_event(p_msg);
            GKI_freebuf (p_msg);
            break;

#endif /* BPP */

#endif /* OBX */

#if (defined(SAP_SERVER_INCLUDED) && SAP_SERVER_INCLUDED == TRUE)
        case BT_EVT_TO_BTU_SAP :
            sap_proc_btu_event(p_msg);
            GKI_freebuf (p_msg);
            break;
#endif /* SAP */
#if (defined(GAP_CONN_INCLUDED) && GAP_CONN_INCLUDED == TRUE && GAP_CONN_POST_EVT_INCLUDED == TRUE)
        case BT_EVT_TO_GAP_MSG :
            gap_proc_btu_event(p_msg);
            GKI_freebuf (p_msg);
            break;
#endif
            // NOTE: The timer calls below may not be sent by HCI.
        case BT_EVT_TO_START_TIMER :
            /* Start free running 1 second timer for list management */
            GKI_start_timer (TIMER_0, GKI_SECS_TO_TICKS (1), TRUE);
            GKI_freebuf (p_msg);
            break;

        case BT_EVT_TO_STOP_TIMER:
            if (GKI_timer_queue_is_empty(&btu_cb.timer_queue)) {
                GKI_stop_timer(TIMER_0);
            }
            GKI_freebuf (p_msg);
            break;

                    case BT_EVT_TO_START_TIMER_ONESHOT:
                        if (!GKI_timer_queue_is_empty(&btu_cb.timer_queue_oneshot)) {
                            TIMER_LIST_ENT *tle = GKI_timer_getfirst(&btu_cb.timer_queue_oneshot);
                            // Start non-repeating timer.
                            GKI_start_timer(TIMER_3, tle->ticks, FALSE);
                        } else {
                            BTM_TRACE_WARNING("Oneshot timer queue empty when received start request");
                        }
                        GKI_freebuf(p_msg);
                        break;

                    case BT_EVT_TO_STOP_TIMER_ONESHOT:
                        if (GKI_timer_queue_is_empty(&btu_cb.timer_queue_oneshot)) {
                            GKI_stop_timer(TIMER_3);
                        } else {
                            BTM_TRACE_WARNING("Oneshot timer queue not empty when received stop request");
                        }
                        GKI_freebuf (p_msg);
                        break;

#if defined(QUICK_TIMER_TICKS_PER_SEC) && (QUICK_TIMER_TICKS_PER_SEC > 0)
        case BT_EVT_TO_START_QUICK_TIMER :
            GKI_start_timer (TIMER_2, QUICK_TIMER_TICKS, TRUE);
            GKI_freebuf (p_msg);
            break;
#endif

        default:;
            int i = 0;
            uint16_t mask = (UINT16) (p_msg->event & BT_EVT_MASK);
            BOOLEAN handled = FALSE;

            for (; !handled && i < BTU_MAX_REG_EVENT; i++)
            {
                if (btu_cb.event_reg[i].event_cb == NULL)
                    continue;

                if (mask == btu_cb.event_reg[i].event_range)
                {
                    if (btu_cb.event_reg[i].event_cb)
                    {
                        btu_cb.event_reg[i].event_cb(p_msg);
                        handled = TRUE;
                    }
                }
            }

            if (handled == FALSE)
                GKI_freebuf (p_msg);

            break;
    }

}

static void btu_bta_alarm_process(TIMER_LIST_ENT *p_tle) {
    /* call timer callback */
    if (p_tle->p_cback) {
        (*p_tle->p_cback)(p_tle);
    } else if (p_tle->event) {
        BT_HDR *p_msg;
        if ((p_msg = (BT_HDR *) GKI_getbuf(sizeof(BT_HDR))) != NULL) {
            p_msg->event = p_tle->event;
            p_msg->layer_specific = 0;
            bta_sys_sendmsg(p_msg);
        }
    }
}

/*******************************************************************************
**
** Function         btu_task
**
** Description      This is the main task of the Bluetooth Upper Layers unit.
**                  It sits in a loop waiting for messages, and dispatches them
**                  to the appropiate handlers.
**
** Returns          should never return
**
*******************************************************************************/
BTU_API void btu_task (UINT32 param)
{
    UINT16           event;
    BT_HDR          *p_msg;
    TIMER_LIST_ENT  *p_tle;
    UINT8            i;
    UINT16           mask;
    BOOLEAN          handled;
    UNUSED(param);

    /* wait an event that HCISU is ready */
    BT_TRACE(TRACE_LAYER_BTU, TRACE_TYPE_API,
                "btu_task pending for preload complete event");

    for (;;)
    {
        event = GKI_wait (0xFFFF, 0);
        if (event & EVENT_MASK(GKI_SHUTDOWN_EVT))
        {
            /* indicates BT ENABLE abort */
            BT_TRACE(TRACE_LAYER_BTU, TRACE_TYPE_WARNING,
                        "btu_task start abort!");
            return;
        }
        else if (event & BT_EVT_PRELOAD_CMPL)
        {
            break;
        }
        else
        {
            BT_TRACE(TRACE_LAYER_BTU, TRACE_TYPE_WARNING,
                "btu_task ignore evt %04x while pending for preload complete",
                event);
        }
    }

    BT_TRACE(TRACE_LAYER_BTU, TRACE_TYPE_API,
                "btu_task received preload complete event");

    /* Initialize the mandatory core stack control blocks
       (BTU, BTM, L2CAP, and SDP)
     */
    btu_init_core();

    /* Initialize any optional stack components */
    BTE_InitStack();

#if (defined(BTU_BTA_INCLUDED) && BTU_BTA_INCLUDED == TRUE)
    bta_sys_init();
#endif

    /* Initialise platform trace levels at this point as BTE_InitStack() and bta_sys_init()
     * reset the control blocks and preset the trace level with XXX_INITIAL_TRACE_LEVEL
     */
#if ( BT_USE_TRACES==TRUE )
    BTE_InitTraceLevels();
#endif

    /* Send a startup evt message to BTIF_TASK to kickstart the init procedure */
    GKI_send_event(BTIF_TASK, BT_EVT_TRIGGER_STACK_INIT);

    raise_priority_a2dp(TASK_HIGH_BTU);

    /* Wait for, and process, events */
    for (;;) {
        event = GKI_wait (0xFFFF, 0);

        // HCI message queue.
        while (!fixed_queue_is_empty(btu_hci_msg_queue)) {
            p_msg = (BT_HDR *)fixed_queue_dequeue(btu_hci_msg_queue);
            btu_hci_msg_process(p_msg);
        }

        // General alarm queue.
        while (!fixed_queue_is_empty(btu_general_alarm_queue)) {
            p_tle = (TIMER_LIST_ENT *)fixed_queue_dequeue(btu_general_alarm_queue);
            btu_general_alarm_process(p_tle);
        }

#if defined(QUICK_TIMER_TICKS_PER_SEC) && (QUICK_TIMER_TICKS_PER_SEC > 0)
        // L2CAP alarm queue.
        while (!fixed_queue_is_empty(btu_l2cap_alarm_queue)) {
            p_tle = (TIMER_LIST_ENT *)fixed_queue_dequeue(btu_l2cap_alarm_queue);
            btu_l2cap_alarm_process(p_tle);
        }
#endif  // QUICK_TIMER

#if (defined(BTU_BTA_INCLUDED) && BTU_BTA_INCLUDED == TRUE)
        // BTA message queue.
        while (!fixed_queue_is_empty(btu_bta_msg_queue)) {
            p_msg = (BT_HDR *)fixed_queue_dequeue(btu_bta_msg_queue);
            bta_sys_event(p_msg);
        }

        // BTA timer queue.
        while (!fixed_queue_is_empty(btu_bta_alarm_queue)) {
            p_tle = (TIMER_LIST_ENT *)fixed_queue_dequeue(btu_bta_alarm_queue);
            btu_bta_alarm_process(p_tle);
        }
#endif  // BTU_BTA_INCLUDED

        while (!fixed_queue_is_empty(btu_oneshot_alarm_queue)) {
            p_tle = (TIMER_LIST_ENT *)fixed_queue_dequeue(btu_oneshot_alarm_queue);
            switch (p_tle->event) {
#if (defined(BLE_INCLUDED) && BLE_INCLUDED == TRUE)
                case BTU_TTYPE_BLE_RANDOM_ADDR:
                    btm_ble_timeout(p_tle);
                    break;
#endif

                case BTU_TTYPE_USER_FUNC:
                    {
                        tUSER_TIMEOUT_FUNC  *p_uf = (tUSER_TIMEOUT_FUNC *)p_tle->param;
                        (*p_uf)(p_tle);
                    }
                    break;

                default:
                    // FAIL
                    BTM_TRACE_WARNING("Received unexpected oneshot timer event:0x%x\n",
                        p_tle->event);
                    break;
            }
        }

        if (event & EVENT_MASK(APPL_EVT_7))
            break;
    }

#if (defined(BTU_BTA_INCLUDED) && BTU_BTA_INCLUDED == TRUE)
    bta_sys_free();
#endif

    btu_free_core();

    return;
}

/*******************************************************************************
**
** Function         btu_start_timer
**
** Description      Start a timer for the specified amount of time.
**                  NOTE: The timeout resolution is in SECONDS! (Even
**                          though the timer structure field is ticks)
**
** Returns          void
**
*******************************************************************************/
static void btu_general_alarm_process(TIMER_LIST_ENT *p_tle) {
    assert(p_tle != NULL);

    switch (p_tle->event) {
        case BTU_TTYPE_BTM_DEV_CTL:
            btm_dev_timeout(p_tle);
            break;

        case BTU_TTYPE_BTM_ACL:
            btm_acl_timeout(p_tle);
            break;

        case BTU_TTYPE_L2CAP_LINK:
        case BTU_TTYPE_L2CAP_CHNL:
        case BTU_TTYPE_L2CAP_HOLD:
        case BTU_TTYPE_L2CAP_INFO:
        case BTU_TTYPE_L2CAP_FCR_ACK:
            l2c_process_timeout (p_tle);
            break;

        case BTU_TTYPE_SDP:
            sdp_conn_timeout ((tCONN_CB *)p_tle->param);
            break;

        case BTU_TTYPE_BTM_RMT_NAME:
            btm_inq_rmt_name_failed();
            break;

#if (defined(RFCOMM_INCLUDED) && RFCOMM_INCLUDED == TRUE)
        case BTU_TTYPE_RFCOMM_MFC:
        case BTU_TTYPE_RFCOMM_PORT:
            rfcomm_process_timeout (p_tle);
            break;

#endif /* If defined(RFCOMM_INCLUDED) && RFCOMM_INCLUDED == TRUE */

#if ((defined(BNEP_INCLUDED) && BNEP_INCLUDED == TRUE))
        case BTU_TTYPE_BNEP:
            bnep_process_timeout(p_tle);
            break;
#endif


#if (defined(AVDT_INCLUDED) && AVDT_INCLUDED == TRUE)
        case BTU_TTYPE_AVDT_CCB_RET:
        case BTU_TTYPE_AVDT_CCB_RSP:
        case BTU_TTYPE_AVDT_CCB_IDLE:
        case BTU_TTYPE_AVDT_SCB_TC:
            avdt_process_timeout(p_tle);
            break;
#endif

#if (defined(OBX_INCLUDED) && OBX_INCLUDED == TRUE)
#if (defined(OBX_CLIENT_INCLUDED) && OBX_CLIENT_INCLUDED == TRUE)
        case BTU_TTYPE_OBX_CLIENT_TO:
            obx_cl_timeout(p_tle);
            break;
#endif
#if (defined(OBX_SERVER_INCLUDED) && OBX_SERVER_INCLUDED == TRUE)
        case BTU_TTYPE_OBX_SERVER_TO:
            obx_sr_timeout(p_tle);
            break;

        case BTU_TTYPE_OBX_SVR_SESS_TO:
            obx_sr_sess_timeout(p_tle);
            break;
#endif
#endif

#if (defined(SAP_SERVER_INCLUDED) && SAP_SERVER_INCLUDED == TRUE)
        case BTU_TTYPE_SAP_TO:
            sap_process_timeout(p_tle);
            break;
#endif

        case BTU_TTYPE_BTU_CMD_CMPL:
            btu_hcif_cmd_timeout((UINT8)(p_tle->event - BTU_TTYPE_BTU_CMD_CMPL));
            break;

#if (defined(HID_HOST_INCLUDED) && HID_HOST_INCLUDED == TRUE)
        case BTU_TTYPE_HID_HOST_REPAGE_TO :
            hidh_proc_repage_timeout(p_tle);
            break;
#endif

#if (defined(BLE_INCLUDED) && BLE_INCLUDED == TRUE)
        case BTU_TTYPE_BLE_INQUIRY:
        case BTU_TTYPE_BLE_GAP_LIM_DISC:
        case BTU_TTYPE_BLE_RANDOM_ADDR:
        case BTU_TTYPE_BLE_GAP_FAST_ADV:
        case BTU_TTYPE_BLE_OBSERVE:
            btm_ble_timeout(p_tle);
            break;

        case BTU_TTYPE_ATT_WAIT_FOR_RSP:
            gatt_rsp_timeout(p_tle);
            break;

        case BTU_TTYPE_ATT_WAIT_FOR_IND_ACK:
            gatt_ind_ack_timeout(p_tle);
            break;
#if (defined(SMP_INCLUDED) && SMP_INCLUDED == TRUE)
        case BTU_TTYPE_SMP_PAIRING_CMD:
            smp_rsp_timeout(p_tle);
            break;
#endif

#endif

#if (MCA_INCLUDED == TRUE)
        case BTU_TTYPE_MCA_CCB_RSP:
            mca_process_timeout(p_tle);
            break;
#endif
        case BTU_TTYPE_USER_FUNC:
            {
                tUSER_TIMEOUT_FUNC  *p_uf = (tUSER_TIMEOUT_FUNC *)p_tle->param;
                (*p_uf)(p_tle);
            }
            break;

        default:;
                int i = 0;
                BOOLEAN handled = FALSE;

                for (; !handled && i < BTU_MAX_REG_TIMER; i++)
                {
                    if (btu_cb.timer_reg[i].timer_cb == NULL)
                        continue;
                    if (btu_cb.timer_reg[i].p_tle == p_tle)
                    {
                        btu_cb.timer_reg[i].timer_cb(p_tle);
                        handled = TRUE;
                    }
                }
                break;
    }
}

void btu_general_alarm_cb(void *data) {
  assert(data != NULL);
  TIMER_LIST_ENT *p_tle = (TIMER_LIST_ENT *)data;

  fixed_queue_enqueue(btu_general_alarm_queue, p_tle);
  GKI_send_event(BTU_TASK, TIMER_0_EVT_MASK);
}

void btu_start_timer(TIMER_LIST_ENT *p_tle, UINT16 type, UINT32 timeout_sec) {
  assert(p_tle != NULL);

  // Get the alarm for the timer list entry.
  pthread_mutex_lock(&btu_general_alarm_lock);
  if (!hash_map_has_key(btu_general_alarm_hash_map, p_tle)) {
    hash_map_set(btu_general_alarm_hash_map, p_tle, alarm_new());
  }
  pthread_mutex_unlock(&btu_general_alarm_lock);

  alarm_t *alarm = hash_map_get(btu_general_alarm_hash_map, p_tle);
  if (alarm == NULL) {
    ALOGE("%s Unable to create alarm\n", __func__);
    return;
  }
  alarm_cancel(alarm);

  p_tle->event = type;
  // NOTE: This value is in seconds but stored in a ticks field.
  p_tle->ticks = timeout_sec;
  alarm_set(alarm, (period_ms_t)(timeout_sec * 1000), btu_general_alarm_cb, (void *)p_tle);
}

/*******************************************************************************
**
** Function         btu_remaining_time
**
** Description      Return amount of time to expire
**
** Returns          time in second
**
*******************************************************************************/
UINT32 btu_remaining_time (TIMER_LIST_ENT *p_tle)
{
    return(GKI_get_remaining_ticks (&btu_cb.timer_queue, p_tle));
}

/*******************************************************************************
**
** Function         btu_stop_timer
**
** Description      Stop a timer.
**
** Returns          void
**
*******************************************************************************/
void btu_stop_timer(TIMER_LIST_ENT *p_tle) {
  assert(p_tle != NULL);

  // Get the alarm for the timer list entry.
  alarm_t *alarm = hash_map_get(btu_general_alarm_hash_map, p_tle);
  if (alarm == NULL) {
    ALOGE("%s Unable to find expected alarm in hashmap\n", __func__);
    return;
  }
  alarm_cancel(alarm);
}

#if defined(QUICK_TIMER_TICKS_PER_SEC) && (QUICK_TIMER_TICKS_PER_SEC > 0)
/*******************************************************************************
**
** Function         btu_start_quick_timer
**
** Description      Start a timer for the specified amount of time in ticks.
**
** Returns          void
**
*******************************************************************************/
static void btu_l2cap_alarm_process(TIMER_LIST_ENT *p_tle) {
  assert(p_tle != NULL);

  switch (p_tle->event) {
    case BTU_TTYPE_L2CAP_CHNL:      /* monitor or retransmission timer */
    case BTU_TTYPE_L2CAP_FCR_ACK:   /* ack timer */
      l2c_process_timeout (p_tle);
      break;

    default:
      break;
  }
}

static void btu_l2cap_alarm_cb(void *data) {
  assert(data != NULL);
  TIMER_LIST_ENT *p_tle = (TIMER_LIST_ENT *)data;

  fixed_queue_enqueue(btu_l2cap_alarm_queue, p_tle);
  GKI_send_event(BTU_TASK, TIMER_2_EVT_MASK);
}

void btu_start_quick_timer(TIMER_LIST_ENT *p_tle, UINT16 type, UINT32 timeout_ticks) {
  assert(p_tle != NULL);

  // Get the alarm for the timer list entry.
  pthread_mutex_lock(&btu_l2cap_alarm_lock);
  if (!hash_map_has_key(btu_l2cap_alarm_hash_map, p_tle)) {
    hash_map_set(btu_l2cap_alarm_hash_map, p_tle, alarm_new());
  }
  pthread_mutex_unlock(&btu_l2cap_alarm_lock);

  alarm_t *alarm = hash_map_get(btu_l2cap_alarm_hash_map, p_tle);
  if (alarm == NULL) {
    ALOGE("%s Unable to create alarm\n", __func__);
    return;
  }
  alarm_cancel(alarm);

  p_tle->event = type;
  p_tle->ticks = timeout_ticks;
  // The quick timer ticks are 100ms long.
  alarm_set(alarm, (period_ms_t)(timeout_ticks * 100), btu_l2cap_alarm_cb, (void *)p_tle);
}

/*******************************************************************************
**
** Function         btu_stop_quick_timer
**
** Description      Stop a timer.
**
** Returns          void
**
*******************************************************************************/
void btu_stop_quick_timer(TIMER_LIST_ENT *p_tle) {
  assert(p_tle != NULL);

  // Get the alarm for the timer list entry.
  alarm_t *alarm = hash_map_get(btu_l2cap_alarm_hash_map, p_tle);
  if (alarm == NULL) {
    ALOGE("%s Unable to find expected alarm in hashmap\n", __func__);
    return;
  }
  alarm_cancel(alarm);
}
#endif /* defined(QUICK_TIMER_TICKS_PER_SEC) && (QUICK_TIMER_TICKS_PER_SEC > 0) */

void btu_oneshot_alarm_cb(void *data) {
  assert(data != NULL);
  TIMER_LIST_ENT *p_tle = (TIMER_LIST_ENT *)data;

  btu_stop_timer_oneshot(p_tle);

  fixed_queue_enqueue(btu_oneshot_alarm_queue, p_tle);
  GKI_send_event(BTU_TASK, TIMER_3_EVT_MASK);
}

/*
 * Starts a oneshot timer with a timeout in seconds.
 */
void btu_start_timer_oneshot(TIMER_LIST_ENT *p_tle, UINT16 type, UINT32 timeout_sec) {
  assert(p_tle != NULL);

  // Get the alarm for the timer list entry.
  pthread_mutex_lock(&btu_oneshot_alarm_lock);
  if (!hash_map_has_key(btu_oneshot_alarm_hash_map, p_tle)) {
    hash_map_set(btu_oneshot_alarm_hash_map, p_tle, alarm_new());
  }
  pthread_mutex_unlock(&btu_oneshot_alarm_lock);

  alarm_t *alarm = hash_map_get(btu_oneshot_alarm_hash_map, p_tle);
  if (alarm == NULL) {
    ALOGE("%s Unable to create alarm\n", __func__);
    return;
  }
  alarm_cancel(alarm);

  p_tle->event = type;
  // NOTE: This value is in seconds but stored in a ticks field.
  p_tle->ticks = timeout_sec;
  alarm_set(alarm, (period_ms_t)(timeout_sec * 1000), btu_oneshot_alarm_cb, (void *)p_tle);
}

void btu_stop_timer_oneshot(TIMER_LIST_ENT *p_tle) {
  assert(p_tle != NULL);

  // Get the alarm for the timer list entry.
  alarm_t *alarm = hash_map_get(btu_oneshot_alarm_hash_map, p_tle);
  if (alarm == NULL) {
    ALOGE("%s Unable to find expected alarm in hashmap\n", __func__);
    return;
  }
  alarm_cancel(alarm);
}

#if (defined(HCILP_INCLUDED) && HCILP_INCLUDED == TRUE)
/*******************************************************************************
**
** Function         btu_check_bt_sleep
**
** Description      This function is called to check if controller can go to sleep.
**
** Returns          void
**
*******************************************************************************/
void btu_check_bt_sleep (void)
{
    if ((GKI_queue_is_empty(&btu_cb.hci_cmd_cb[LOCAL_BR_EDR_CONTROLLER_ID].cmd_cmpl_q)
        && GKI_queue_is_empty(&btu_cb.hci_cmd_cb[LOCAL_BR_EDR_CONTROLLER_ID].cmd_xmit_q)))
    {
        if (l2cb.controller_xmit_window == l2cb.num_lm_acl_bufs)
        {
            /* enable dev to sleep  in the cmd cplt and cmd status only and num cplt packet */
            HCI_LP_ALLOW_BT_DEVICE_SLEEP();
        }
    }
}
#endif
