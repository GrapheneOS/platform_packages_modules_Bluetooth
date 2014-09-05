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
#include "btif_common.h"
#include "btu.h"
#include "btsnoop.h"
#include "bt_utils.h"
#include "fixed_queue.h"
#include "future.h"
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

/******************************************************************************
**  Variables
******************************************************************************/
BOOLEAN hci_logging_enabled = FALSE;    /* by default, turn hci log off */
BOOLEAN hci_logging_config = FALSE;    /* configured from bluetooth framework */
BOOLEAN hci_save_log = FALSE; /* save a copy of the log before starting again */
char hci_logfile[256] = HCI_LOGGING_FILENAME;

/*******************************************************************************
**  Static variables
*******************************************************************************/
static const hci_t *hci;
static const btsnoop_t *btsnoop;
static const hci_callbacks_t hci_callbacks;
// Lock to serialize shutdown requests from upper layer.
static pthread_mutex_t shutdown_lock;

/*******************************************************************************
**  Static functions
*******************************************************************************/

/*******************************************************************************
**  Externs
*******************************************************************************/
void BTE_LoadStack(void);
void BTE_UnloadStack(void);
void scru_flip_bda (BD_ADDR dst, const BD_ADDR src);
void bte_load_conf(const char *p_path);
extern void bte_load_ble_conf(const char *p_path);
bt_bdaddr_t btif_local_bd_addr;

fixed_queue_t *btu_hci_msg_queue;

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

    btsnoop = btsnoop_get_interface();

    btu_hci_msg_queue = fixed_queue_new(SIZE_MAX);
    if (btu_hci_msg_queue == NULL) {
      ALOGE("%s unable to allocate hci message queue.", __func__);
      return;
    }

    data_dispatcher_register_default(hci->upward_dispatcher, btu_hci_msg_queue);

    bte_load_conf(BTE_STACK_CONF_FILE);
#if (defined(BLE_INCLUDED) && (BLE_INCLUDED == TRUE))
    bte_load_ble_conf(BTE_BLE_STACK_CONF_FILE);
#endif

#if (BTTRC_INCLUDED == TRUE)
    /* Initialize trace feature */
    BTTRC_TraceInit(MAX_TRACE_RAM_SIZE, &BTE_TraceLogBuf[0], BTTRC_METHOD_RAM);
#endif

    pthread_mutex_init(&shutdown_lock, NULL);
    btsnoop->set_logging_path(hci_logfile);
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
    data_dispatcher_register_default(hci_layer_get_interface()->upward_dispatcher, NULL);
    fixed_queue_free(btu_hci_msg_queue, NULL);

    btu_hci_msg_queue = NULL;

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

//    BTU_StartUp();

    btsnoop->set_is_running(hci_logging_enabled || hci_logging_config);
    assert(hci->start_up_async(btif_local_bd_addr.address, &hci_callbacks));
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

    if (hci) {
      // Shutdown is not thread safe and must be protected.
      pthread_mutex_lock(&shutdown_lock);

      btsnoop->set_is_running(false);
      hci->shut_down();

      pthread_mutex_unlock(&shutdown_lock);
    }

    BTU_ShutDown();
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
  hci_logging_config = enable;
  btsnoop->set_is_running((hci_logging_config || hci_logging_enabled) && !bt_disabled);
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
** Function         hci_startup_cb
**
** Description      HOST/CONTROLLER LIB CALLBACK API - This function is called
**                  when the libbt-hci completed stack preload process
**
** Returns          None
**
******************************************************************************/
static void hci_startup_cb(bool success)
{
    APPL_TRACE_EVENT("HC preload_cb %d [1:SUCCESS 0:FAIL]", success);

    if (success) {
        BTU_StartUp();
    } else {
        ALOGE("%s hci startup failed", __func__);
        // TODO(cmanton) Initiate shutdown sequence.
    }
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
** Returns          void
**
******************************************************************************/
static void tx_result(void *p_buf, bool all_fragments_sent) {
    if (!all_fragments_sent)
        fixed_queue_enqueue(btu_hci_msg_queue, p_buf);
    else
        GKI_freebuf(p_buf);
}

/*****************************************************************************
**   The libbt-hci Callback Functions Table
*****************************************************************************/
static const hci_callbacks_t hci_callbacks = {
    hci_startup_cb,
    tx_result
};
