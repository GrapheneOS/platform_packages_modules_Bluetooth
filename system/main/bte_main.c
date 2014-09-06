/******************************************************************************
 *
 *  Copyright (C) 2009-2012 Broadcom Corporation
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
 *  Filename:      bte_main.c
 *
 *  Description:   Contains BTE core stack initialization and shutdown code
 *
 ******************************************************************************/
#include <assert.h>
#include <cutils/properties.h>
#include <fcntl.h>
#include <hardware/bluetooth.h>
#include <pthread.h>
#include <signal.h>
#include <stdlib.h>
#include <time.h>
#include <utils/Log.h>

#include "alarm.h"
#include "bd.h"
#include "bta_api.h"
#include "bt_hci_bdroid.h"
#include "bte.h"
#include "btu.h"
#include "bt_utils.h"
#include "fixed_queue.h"
#include "gki.h"
#include "hash_functions.h"
#include "hash_map.h"
#include "hci_layer.h"
#include "osi.h"
#include "thread.h"

/*******************************************************************************
**  Constants & Macros
*******************************************************************************/

/* Run-time configuration file */
#ifndef BTE_STACK_CONF_FILE
#define BTE_STACK_CONF_FILE "/etc/bluetooth/bt_stack.conf"
#endif
/* Run-time configuration file for BLE*/
#ifndef BTE_BLE_STACK_CONF_FILE
#define BTE_BLE_STACK_CONF_FILE "/etc/bluetooth/ble_stack.conf"
#endif

/* if not specified in .txt file then use this as default  */
#ifndef HCI_LOGGING_FILENAME
#define HCI_LOGGING_FILENAME  "/data/misc/bluedroid/btsnoop_hci.log"
#endif

/* Stack preload process maximum retry attempts  */
#ifndef PRELOAD_MAX_RETRY_ATTEMPTS
#define PRELOAD_MAX_RETRY_ATTEMPTS 0
#endif

/*******************************************************************************
**  Local type definitions
*******************************************************************************/
/* Preload retry control block */
typedef struct
{
    int     retry_counts;
    alarm_t *alarm;
} bt_preload_retry_cb_t;

/******************************************************************************
**  Variables
******************************************************************************/
BOOLEAN hci_logging_enabled = FALSE;    /* by default, turn hci log off */
BOOLEAN hci_logging_config = FALSE;    /* configured from bluetooth framework */
BOOLEAN hci_save_log = FALSE; /* save a copy of the log before starting again */
char hci_logfile[256] = HCI_LOGGING_FILENAME;

// Communication queue between btu_task and bta.
fixed_queue_t *btu_bta_msg_queue;

// Communication queue between btu_task and hci.
fixed_queue_t *btu_hci_msg_queue;

// General timer queue.
fixed_queue_t *btu_general_alarm_queue;
hash_map_t *btu_general_alarm_hash_map;
pthread_mutex_t btu_general_alarm_lock;
static const size_t BTU_GENERAL_ALARM_HASH_MAP_SIZE = 17;

// Oneshot timer queue.
fixed_queue_t *btu_oneshot_alarm_queue;
hash_map_t *btu_oneshot_alarm_hash_map;
pthread_mutex_t btu_oneshot_alarm_lock;
static const size_t BTU_ONESHOT_ALARM_HASH_MAP_SIZE = 17;

// l2cap timer queue.
fixed_queue_t *btu_l2cap_alarm_queue;
hash_map_t *btu_l2cap_alarm_hash_map;
pthread_mutex_t btu_l2cap_alarm_lock;
static const size_t BTU_L2CAP_ALARM_HASH_MAP_SIZE = 17;

/*******************************************************************************
**  Static variables
*******************************************************************************/
static const hci_interface_t *hci;
static const hci_callbacks_t hci_callbacks;
static const allocator_t buffer_allocator;
static bt_preload_retry_cb_t preload_retry_cb;
// Lock to serialize shutdown requests from upper layer.
static pthread_mutex_t shutdown_lock;

// These are temporary so we can run the new HCI code
// with the old upper stack.
static fixed_queue_t *upbound_data;
static thread_t *dispatch_thread;

/*******************************************************************************
**  Static functions
*******************************************************************************/
static void bte_hci_enable(void);
static void bte_hci_disable(void);
static void preload_start_wait_timer(void);
static void preload_stop_wait_timer(void);
static void dump_upbound_data_to_btu(fixed_queue_t *queue, void *context);

/*******************************************************************************
**  Externs
*******************************************************************************/
void BTE_LoadStack(void);
void BTE_UnloadStack(void);
void scru_flip_bda (BD_ADDR dst, const BD_ADDR src);
void bte_load_conf(const char *p_path);
extern void bte_load_ble_conf(const char *p_path);
bt_bdaddr_t btif_local_bd_addr;

/******************************************************************************
**
** Function         bte_main_boot_entry
**
** Description      BTE MAIN API - Entry point for BTE chip/stack initialization
**
** Returns          None
**
******************************************************************************/
void bte_main_boot_entry(void)
{
    /* initialize OS */
    GKI_init();

    hci = hci_layer_get_interface();
    if (!hci)
      ALOGE("%s could not get hci layer interface.", __func__);

    upbound_data = fixed_queue_new(SIZE_MAX);
    dispatch_thread = thread_new("hci_dispatch");

    fixed_queue_register_dequeue(
      upbound_data,
      thread_get_reactor(dispatch_thread),
      dump_upbound_data_to_btu,
      NULL
    );

    data_dispatcher_register_default(hci->upward_dispatcher, upbound_data);

    memset(&preload_retry_cb, 0, sizeof(bt_preload_retry_cb_t));
    preload_retry_cb.alarm = alarm_new();

    bte_load_conf(BTE_STACK_CONF_FILE);
#if (defined(BLE_INCLUDED) && (BLE_INCLUDED == TRUE))
    bte_load_ble_conf(BTE_BLE_STACK_CONF_FILE);
#endif

#if (BTTRC_INCLUDED == TRUE)
    /* Initialize trace feature */
    BTTRC_TraceInit(MAX_TRACE_RAM_SIZE, &BTE_TraceLogBuf[0], BTTRC_METHOD_RAM);
#endif

    pthread_mutex_init(&shutdown_lock, NULL);

}

/******************************************************************************
**
** Function         bte_main_shutdown
**
** Description      BTE MAIN API - Shutdown code for BTE chip/stack
**
** Returns          None
**
******************************************************************************/
void bte_main_shutdown()
{
    alarm_free(preload_retry_cb.alarm);
    preload_retry_cb.alarm = NULL;

    pthread_mutex_destroy(&shutdown_lock);

    GKI_shutdown();
}

/******************************************************************************
**
** Function         bte_main_enable
**
** Description      BTE MAIN API - Creates all the BTE tasks. Should be called
**                  part of the Bluetooth stack enable sequence
**
** Returns          None
**
******************************************************************************/
void bte_main_enable()
{
    APPL_TRACE_DEBUG("%s", __FUNCTION__);

    btu_bta_msg_queue = fixed_queue_new(SIZE_MAX);
    btu_hci_msg_queue = fixed_queue_new(SIZE_MAX);

    btu_general_alarm_hash_map = hash_map_new(BTU_GENERAL_ALARM_HASH_MAP_SIZE,
            hash_function_knuth, NULL,NULL);
    pthread_mutex_init(&btu_general_alarm_lock, NULL);
    btu_general_alarm_queue = fixed_queue_new(SIZE_MAX);

    btu_oneshot_alarm_hash_map = hash_map_new(BTU_ONESHOT_ALARM_HASH_MAP_SIZE,
            hash_function_knuth, NULL,NULL);
    pthread_mutex_init(&btu_oneshot_alarm_lock, NULL);
    btu_oneshot_alarm_queue = fixed_queue_new(SIZE_MAX);

    btu_l2cap_alarm_hash_map = hash_map_new(BTU_L2CAP_ALARM_HASH_MAP_SIZE,
            hash_function_knuth, NULL,NULL);
    pthread_mutex_init(&btu_l2cap_alarm_lock, NULL);
    btu_l2cap_alarm_queue = fixed_queue_new(SIZE_MAX);

    BTU_StartUp();

    bte_hci_enable();
}

/******************************************************************************
**
** Function         bte_main_disable
**
** Description      BTE MAIN API - Destroys all the BTE tasks. Should be called
**                  part of the Bluetooth stack disable sequence
**
** Returns          None
**
******************************************************************************/
void bte_main_disable(void)
{
    APPL_TRACE_DEBUG("%s", __FUNCTION__);

    preload_stop_wait_timer();
    bte_hci_disable();
    BTU_ShutDown();

    fixed_queue_free(btu_bta_msg_queue, NULL);
    fixed_queue_free(btu_hci_msg_queue, NULL);

    hash_map_free(btu_general_alarm_hash_map);
    pthread_mutex_destroy(&btu_general_alarm_lock);
    fixed_queue_free(btu_general_alarm_queue, NULL);

    hash_map_free(btu_oneshot_alarm_hash_map);
    pthread_mutex_destroy(&btu_oneshot_alarm_lock);
    fixed_queue_free(btu_oneshot_alarm_queue, NULL);

    hash_map_free(btu_l2cap_alarm_hash_map);
    pthread_mutex_destroy(&btu_l2cap_alarm_lock);
    fixed_queue_free(btu_l2cap_alarm_queue, NULL);
}

/******************************************************************************
**
** Function         bte_main_config_hci_logging
**
** Description      enable or disable HIC snoop logging
**
** Returns          None
**
******************************************************************************/
void bte_main_config_hci_logging(BOOLEAN enable, BOOLEAN bt_disabled)
{
    int old = (hci_logging_enabled == TRUE) || (hci_logging_config == TRUE);
    int new;

    hci_logging_config = enable;

    new = (hci_logging_enabled == TRUE) || (hci_logging_config == TRUE);

    if ((old == new) || bt_disabled) {
        return;
    }

    if (new)
      hci->turn_on_logging(hci_logfile);
    else
      hci->turn_off_logging();
}

/******************************************************************************
**
** Function         bte_hci_enable
**
** Description      Enable HCI & Vendor modules
**
** Returns          None
**
******************************************************************************/
static void bte_hci_enable(void)
{
    APPL_TRACE_DEBUG("%s", __FUNCTION__);

    preload_start_wait_timer();

    bool success = hci->start_up(btif_local_bd_addr.address, &buffer_allocator, &hci_callbacks);
    APPL_TRACE_EVENT("libbt-hci start_up returns %d", success);

    assert(success);

    if (hci_logging_enabled == TRUE || hci_logging_config == TRUE)
        hci->turn_on_logging(hci_logfile);

#if (defined (BT_CLEAN_TURN_ON_DISABLED) && BT_CLEAN_TURN_ON_DISABLED == TRUE)
    APPL_TRACE_DEBUG("%s not turning off the chip before turning it on", __FUNCTION__);

    /* Do not power off the chip before powering on  if BT_CLEAN_TURN_ON_DISABLED flag
     is defined and set to TRUE to avoid below mentioned issue.

     Wingray kernel driver maintains a combined  counter to keep track of
     BT-Wifi state. Invoking  set_power(BT_HC_CHIP_PWR_OFF) when the BT is already
     in OFF state causes this counter to be incorrectly decremented and results in undesired
     behavior of the chip.

     This is only a workaround and when the issue is fixed in the kernel this work around
     should be removed. */
#else
    /* toggle chip power to ensure we will reset chip in case
       a previous stack shutdown wasn't completed gracefully */
    hci->set_chip_power_on(false);
#endif
    hci->set_chip_power_on(true);
    hci->do_preload();
}

/******************************************************************************
**
** Function         bte_hci_disable
**
** Description      Disable HCI & Vendor modules
**
** Returns          None
**
******************************************************************************/
static void bte_hci_disable(void)
{
    APPL_TRACE_DEBUG("%s", __FUNCTION__);

    if (!hci)
        return;

    // Shutdown is not thread safe and must be protected.
    pthread_mutex_lock(&shutdown_lock);

    if (hci_logging_enabled == TRUE ||  hci_logging_config == TRUE)
        hci->turn_off_logging();
    hci->shut_down();

    pthread_mutex_unlock(&shutdown_lock);
}

/*******************************************************************************
**
** Function        preload_wait_timeout
**
** Description     Timeout thread of preload watchdog timer
**
** Returns         None
**
*******************************************************************************/
static void preload_wait_timeout(UNUSED_ATTR void *context)
{
    APPL_TRACE_ERROR("...preload_wait_timeout (retried:%d/max-retry:%d)...",
                        preload_retry_cb.retry_counts,
                        PRELOAD_MAX_RETRY_ATTEMPTS);

    if (preload_retry_cb.retry_counts++ < PRELOAD_MAX_RETRY_ATTEMPTS)
    {
        bte_hci_disable();
        GKI_delay(100);
        bte_hci_enable();
    }
    else
    {
        /* Notify BTIF_TASK that the init procedure had failed*/
        GKI_send_event(BTIF_TASK, BT_EVT_HARDWARE_INIT_FAIL);
    }
}

/*******************************************************************************
**
** Function        preload_start_wait_timer
**
** Description     Launch startup watchdog timer
**
** Returns         None
**
*******************************************************************************/
static void preload_start_wait_timer(void)
{
    uint32_t timeout_ms;
    char timeout_prop[PROPERTY_VALUE_MAX];
    if (!property_get("bluetooth.enable_timeout_ms", timeout_prop, "3000") || (timeout_ms = atoi(timeout_prop)) < 100)
        timeout_ms = 3000;

    alarm_set(preload_retry_cb.alarm, timeout_ms, preload_wait_timeout, NULL);
}

/*******************************************************************************
**
** Function        preload_stop_wait_timer
**
** Description     Stop preload watchdog timer
**
** Returns         None
**
*******************************************************************************/
static void preload_stop_wait_timer(void)
{
    alarm_cancel(preload_retry_cb.alarm);
}

/******************************************************************************
**
** Function         bte_main_postload_cfg
**
** Description      BTE MAIN API - Stack postload configuration
**
** Returns          None
**
******************************************************************************/
void bte_main_postload_cfg(void)
{
    hci->do_postload();
}

#if (defined(HCILP_INCLUDED) && HCILP_INCLUDED == TRUE)
/******************************************************************************
**
** Function         bte_main_enable_lpm
**
** Description      BTE MAIN API - Enable/Disable low power mode operation
**
** Returns          None
**
******************************************************************************/
void bte_main_enable_lpm(BOOLEAN enable)
{
    hci->send_low_power_command(enable ? LPM_ENABLE : LPM_DISABLE);
}

/******************************************************************************
**
** Function         bte_main_lpm_allow_bt_device_sleep
**
** Description      BTE MAIN API - Allow BT controller goest to sleep
**
** Returns          None
**
******************************************************************************/
void bte_main_lpm_allow_bt_device_sleep()
{
    hci->send_low_power_command(LPM_WAKE_DEASSERT);
}

/******************************************************************************
**
** Function         bte_main_lpm_wake_bt_device
**
** Description      BTE MAIN API - Wake BT controller up if it is in sleep mode
**
** Returns          None
**
******************************************************************************/
void bte_main_lpm_wake_bt_device()
{
    hci->send_low_power_command(LPM_WAKE_ASSERT);
}
#endif  // HCILP_INCLUDED


/* NOTICE:
 *  Definitions for audio state structure, this type needs to match to
 *  the bt_vendor_op_audio_state_t type defined in bt_vendor_lib.h
 */
typedef struct {
    UINT16  handle;
    UINT16  peer_codec;
    UINT16  state;
} bt_hc_audio_state_t;

struct bt_audio_state_tag {
    BT_HDR hdr;
    bt_hc_audio_state_t audio;
};

/******************************************************************************
**
** Function         set_audio_state
**
** Description      Sets audio state on controller state for SCO (PCM, WBS, FM)
**
** Parameters       handle: codec related handle for SCO: sco cb idx, unused for
**                  codec: BTA_AG_CODEC_MSBC, BTA_AG_CODEC_CSVD or FM codec
**                  state: codec state, eg. BTA_AG_CO_AUD_STATE_SETUP
**                  param: future extensions, e.g. call-in structure/event.
**
** Returns          None
**
******************************************************************************/
int set_audio_state(UINT16 handle, UINT16 codec, UINT8 state, void *param)
{
    struct bt_audio_state_tag *p_msg;
    int result = -1;

    APPL_TRACE_API("set_audio_state(handle: %d, codec: 0x%x, state: %d)", handle,
                    codec, state);
    if (NULL != param)
        APPL_TRACE_WARNING("set_audio_state() non-null param not supported");
    p_msg = (struct bt_audio_state_tag *)GKI_getbuf(sizeof(*p_msg));
    if (!p_msg)
        return result;
    p_msg->audio.handle = handle;
    p_msg->audio.peer_codec = codec;
    p_msg->audio.state = state;

    p_msg->hdr.event = MSG_CTRL_TO_HC_CMD | (MSG_SUB_EVT_MASK & BT_HC_AUDIO_STATE);
    p_msg->hdr.len = sizeof(p_msg->audio);
    p_msg->hdr.offset = 0;
    /* layer_specific shall contain return path event! for BTA events!
     * 0 means no return message is expected. */
    p_msg->hdr.layer_specific = 0;
    hci->transmit_downward(MSG_STACK_TO_HC_HCI_CMD, p_msg);
    return result;
}


/******************************************************************************
**
** Function         bte_main_hci_send
**
** Description      BTE MAIN API - This function is called by the upper stack to
**                  send an HCI message. The function displays a protocol trace
**                  message (if enabled), and then calls the 'transmit' function
**                  associated with the currently selected HCI transport
**
** Returns          None
**
******************************************************************************/
void bte_main_hci_send (BT_HDR *p_msg, UINT16 event)
{
    UINT16 sub_event = event & BT_SUB_EVT_MASK;  /* local controller ID */

    p_msg->event = event;


    if((sub_event == LOCAL_BR_EDR_CONTROLLER_ID) || \
       (sub_event == LOCAL_BLE_CONTROLLER_ID))
    {
        hci->transmit_downward(event, p_msg);
    }
    else
    {
        APPL_TRACE_ERROR("Invalid Controller ID. Discarding message.");
        GKI_freebuf(p_msg);
    }
}

/*****************************************************************************
**
**   libbt-hci Callback Functions
**
*****************************************************************************/

/******************************************************************************
**
** Function         preload_cb
**
** Description      HOST/CONTROLLER LIB CALLBACK API - This function is called
**                  when the libbt-hci completed stack preload process
**
** Returns          None
**
******************************************************************************/
static void preload_cb(bool success)
{
    APPL_TRACE_EVENT("HC preload_cb %d [1:SUCCESS 0:FAIL]", success);

    if (success)
    {
        preload_stop_wait_timer();

        /* notify BTU task that libbt-hci is ready */
        GKI_send_event(BTU_TASK, BT_EVT_PRELOAD_CMPL);
    }
}

/******************************************************************************
**
** Function         alloc
**
** Description      HOST/CONTROLLER LIB CALLOUT API - This function is called
**                  from the libbt-hci to request for data buffer allocation
**
** Returns          NULL / pointer to allocated buffer
**
******************************************************************************/
static void *alloc(size_t size)
{
    /* Requested buffer size cannot exceed GKI_MAX_BUF_SIZE. */
    if (size > GKI_MAX_BUF_SIZE)
    {
         APPL_TRACE_ERROR("HCI DATA SIZE %d greater than MAX %d",
                           size, GKI_MAX_BUF_SIZE);
         return NULL;
    }

    BT_HDR *p_hdr = (BT_HDR *) GKI_getbuf ((UINT16) size);

    if (!p_hdr)
    {
        APPL_TRACE_WARNING("alloc returns NO BUFFER! (sz %d)", size);
    }

    return p_hdr;
}

/******************************************************************************
**
** Function         dealloc
**
** Description      HOST/CONTROLLER LIB CALLOUT API - This function is called
**                  from the libbt-hci to release the data buffer allocated
**                  through the alloc call earlier
**
**                  Bluedroid libbt-hci library uses 'transac' parameter to
**                  pass data-path buffer/packet across bt_hci_lib interface
**                  boundary.
**
******************************************************************************/
static void dealloc(void *buffer)
{
    GKI_freebuf(buffer);
}

static void dump_upbound_data_to_btu(fixed_queue_t *queue, UNUSED_ATTR void *context) {
    fixed_queue_enqueue(btu_hci_msg_queue, fixed_queue_dequeue(queue));
    // Signal the target thread work is ready.
    GKI_send_event(BTU_TASK, (UINT16)EVENT_MASK(BTU_HCI_RCV_MBOX));

}

/******************************************************************************
**
** Function         tx_result
**
** Description      HOST/CONTROLLER LIB CALLBACK API - This function is called
**                  from the libbt-hci once it has processed/sent the prior data
**                  buffer which core stack passed to it through transmit_buf
**                  call earlier.
**
**                  The core stack is responsible for releasing the data buffer
**                  if it has been completedly processed.
**
**                  Bluedroid libbt-hci library uses 'transac' parameter to
**                  pass data-path buffer/packet across bt_hci_lib interface
**                  boundary. The 'p_buf' is not intended to be used here
**                  but might point to data portion in data-path buffer.
**
** Returns          bt_hc_status_t
**
******************************************************************************/
static void tx_result(void *p_buf, bool all_fragments_sent)
{
    if (!all_fragments_sent)
    {
        fixed_queue_enqueue(btu_hci_msg_queue, p_buf);
        // Signal the target thread work is ready.
        GKI_send_event(BTU_TASK, (UINT16)EVENT_MASK(BTU_HCI_RCV_MBOX));
    }
    else
    {
        GKI_freebuf(p_buf);
    }
}

/*****************************************************************************
**   The libbt-hci Callback Functions Table
*****************************************************************************/
static const hci_callbacks_t hci_callbacks = {
    preload_cb,
    tx_result
};

static const allocator_t buffer_allocator = {
    alloc,
    dealloc
};

