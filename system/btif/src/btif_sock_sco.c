/* vim: set sw=4 : */
/******************************************************************************
 *
 *  Copyright (C) 2013 Google, Inc.
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

/*******************************************************************************
 *
 *  Filename:      btif_sock_sco.c
 *
 *  Description:   Bluetooth SCO socket interface
 *
 *******************************************************************************/


/* Potential future feature work:
 *  - support WBS
 */

#define LOG_TAG "BTIF_SOCK_SCO"

#include <errno.h>
#include <hardware/bluetooth.h>
#include <hardware/bt_sock.h>
#include <stdbool.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>

#include "bta_api.h"
#include "btif_common.h"
#include "btif_sock_thread.h"
#include "btif_sock_util.h"

#include "../../stack/btm/btm_int.h"

// taken from bta_ag_sco.c - I would like to understand these parameters better
static const tBTM_ESCO_PARAMS bta_ag_esco_params = {
    BTM_64KBITS_RATE,                   /* TX Bandwidth (64 kbits/sec)              */
    BTM_64KBITS_RATE,                   /* RX Bandwidth (64 kbits/sec)              */
    0x000a,                             /* 10 ms (HS/HF can use EV3, 2-EV3, 3-EV3)  */
    0x0060,                             /* Inp Linear, Air CVSD, 2s Comp, 16bit     */
    (BTM_SCO_PKT_TYPES_MASK_HV1      +  /* Packet Types                             */
     BTM_SCO_PKT_TYPES_MASK_HV2      +
     BTM_SCO_PKT_TYPES_MASK_HV3      +
     BTM_SCO_PKT_TYPES_MASK_EV3      +
     BTM_SCO_PKT_TYPES_MASK_EV4      +
     BTM_SCO_PKT_TYPES_MASK_EV5      +
     BTM_SCO_PKT_TYPES_MASK_NO_2_EV5 +
     BTM_SCO_PKT_TYPES_MASK_NO_3_EV5),
     BTM_ESCO_RETRANS_POWER       /* Retransmission effort                      */
};


static int thread_handle;

#define INVALID_SLOT (BTM_MAX_SCO_LINKS+1)

UINT16 listen_slot = INVALID_SLOT;
int listen_fds[2] = {-1, -1};


static struct {
    /* fds (ours, theirs) for the data socket */
    int fds[2];
    bool connected;
    bool disconnect_immediately;
} slots[BTM_MAX_SCO_LINKS];

// protect listen_slot, listen_fds & slots
static pthread_mutex_t lock;


static inline void remove_sco(UINT16 sco_inx);
static void connection_request_cb(tBTM_ESCO_EVT event,
        tBTM_ESCO_EVT_DATA *data);


/* Initialize a slot for a SCO connection, including local socket pair(s).
 * NOTE: the slot lock must be held when calling this function.
 */
static bool slot_init(UINT16 sco_inx) {
    if (sco_inx >= BTM_MAX_SCO_LINKS) {
        ALOGE("%s: invalid sco_inx %d", __func__, sco_inx);
        return false;
    }

    if (slots[sco_inx].fds[0] != -1) {
        ALOGE("%s: slot for sco_inx %d already in use", __func__, sco_inx);
        return false;
    }

    // clear state
    slots[sco_inx].connected = false;
    slots[sco_inx].disconnect_immediately = false;

    // create a socketpair in slots[sco_inx].fds
    if (socketpair(AF_LOCAL, SOCK_STREAM, 0, slots[sco_inx].fds)) {
        ALOGE("%s: socketpair failed: %s", __func__, strerror(errno));
        return false;
    }
    return true;
}

/* Release a slot for a SCO connection, closing the socket if needed.
 * NOTE: the slot lock must be held when calling this function.
 */
static void slot_release(UINT16 sco_inx) {
    if (sco_inx >= BTM_MAX_SCO_LINKS) {
        ALOGE("%s: invalid sco_inx %d", __func__, sco_inx);
        return;
    }
    // if slots[sco_inx].fds is still valid
    if (slots[sco_inx].fds[0] != -1) {
        // close our socket
        close(slots[sco_inx].fds[0]);
        slots[sco_inx].fds[0] = -1;
        slots[sco_inx].fds[1] = -1;
    }
    slots[sco_inx].connected = false;
    slots[sco_inx].disconnect_immediately = false;
}

static void listen_connect_cb(UINT16 sco_inx) {
    ALOGI("%s: for sco_inx=%d", __func__, sco_inx);
    lock_slot(&lock);
    slots[sco_inx].connected = true;
    if (slots[sco_inx].disconnect_immediately) {
        remove_sco(sco_inx);
        slots[sco_inx].disconnect_immediately = false;
    }
    unlock_slot(&lock);
}

static void listen_disconnect_cb(UINT16 sco_inx) {
    ALOGI("%s: for sco_inx=%d", __func__, sco_inx);
    lock_slot(&lock);
    slots[sco_inx].connected = false;
    unlock_slot(&lock);
}

static void connect_connect_cb(UINT16 sco_inx) {
    ALOGI("%s: for sco_inx=%d", __func__, sco_inx);
    lock_slot(&lock);
    slots[sco_inx].connected = true;
    if (slots[sco_inx].disconnect_immediately) {
        remove_sco(sco_inx);
        slots[sco_inx].disconnect_immediately = false;
    }
    unlock_slot(&lock);
}

static void connect_disconnect_cb(UINT16 sco_inx) {
    ALOGI("%s: for sco_inx=%d", __func__, sco_inx);
    lock_slot(&lock);
    slots[sco_inx].connected = false;
    unlock_slot(&lock);
}

/* Ask bluedroid to remove SCO connection.
 * NOTE: the slot lock must be held when calling this function.
 */
static inline void remove_sco(UINT16 sco_inx) {
    if (!slots[sco_inx].connected) {
        // Can't actually disconnect until we're connected. Do it later.
        slots[sco_inx].disconnect_immediately = true;
        return;
    }
    int status = BTM_RemoveSco(sco_inx);
    if (status == BTM_SUCCESS) {
        ALOGI("%s: SCO connection removed.", __func__);
    } else if (status == BTM_CMD_STARTED) {
        ALOGI("%s: SCO connection removal started.", __func__);
    } else if (status == BTM_UNKNOWN_ADDR) {
        ALOGW("%s: got BTM_UNKNOWN_ADDR", __func__);
    } else {
        ALOGW("%s: unexpected return from BTM_RemoveSco: %d", __func__,
                status);
    }
}

/* Create a SCO listen socket.
 * NOTE: the slot lock must be held when calling this function.
 */
static inline UINT16 listen_sco() {
    if (listen_fds[0] == -1) {
        // No active listen socket to an app, allocate one.
        if (socketpair(AF_LOCAL, SOCK_STREAM, 0, listen_fds)) {
            ALOGE("%s: socketpair failed: %s", __func__, strerror(errno));
            return BT_STATUS_FAIL;
        }
    }

    UINT16 sco_inx;
    int status = BTM_CreateSco(0, FALSE, bta_ag_esco_params.packet_types,
            &sco_inx, listen_connect_cb, listen_disconnect_cb);
    if (status != BTM_CMD_STARTED) {
        // something bad happened
        ALOGE("%s: BTM_CreateSco failed: %d", __func__, status);
        return INVALID_SLOT;
    }

    // remember the listen slot
    listen_slot = sco_inx;

    // register for events
    BTM_RegForEScoEvts(sco_inx, connection_request_cb);

    // add our fd to the btsock poll loop
    btsock_thread_add_fd(thread_handle, listen_fds[0], BTSOCK_SCO, SOCK_THREAD_FD_EXCEPTION,
            sco_inx);

    return sco_inx;
}

bt_status_t btsock_sco_init(int poll_thread_handle) {
    UINT16 sco_inx;
    ALOGI("%s", __func__);

    thread_handle = poll_thread_handle;

    // mark all socket slots as not in use
    for (sco_inx=0; sco_inx<BTM_MAX_SCO_LINKS; sco_inx++) {
        slots[sco_inx].fds[0] = -1;
        slots[sco_inx].fds[1] = -1;
        slots[sco_inx].connected = false;
        slots[sco_inx].disconnect_immediately = false;
    }

    // mark the listen socket as not in use
    listen_slot = INVALID_SLOT;
    listen_fds[0] = -1;
    listen_fds[1] = -1;

    // initialize the slot lock
    init_slot_lock(&lock);

    return BT_STATUS_SUCCESS;
}

bt_status_t btsock_sco_cleanup() {
    ALOGI("%s", __func__);
    lock_slot(&lock);
    UINT16 sco_inx;
    for (sco_inx=0; sco_inx<BTM_MAX_SCO_LINKS; sco_inx++) {
        slot_release(sco_inx);
    }
    unlock_slot(&lock);
    return BT_STATUS_SUCCESS;
}

static void connection_request_cb(tBTM_ESCO_EVT event,
        tBTM_ESCO_EVT_DATA *data) {
    if (event != BTM_ESCO_CONN_REQ_EVT) {
        // only care about connection requests
        ALOGW("%s: unexpected SCO event: %d", __func__, event);
        return;
    }

    ALOGI("%s: received connection request", __func__);

    // get the connection event data
    tBTM_ESCO_CONN_REQ_EVT_DATA* conn_data = &data->conn_evt;
    UINT16              sco_inx = conn_data->sco_inx;
    tBTM_ESCO_PARAMS    resp;
    UINT8               hci_status = HCI_SUCCESS;

    resp.rx_bw = BTM_64KBITS_RATE;
    resp.tx_bw = BTM_64KBITS_RATE;
    resp.max_latency = 10;
    resp.voice_contfmt = 0x60;
    resp.retrans_effort = BTM_ESCO_RETRANS_POWER;

    lock_slot(&lock);

    ALOGI(" conn_data->link_type == BTM_LINK_TYPE_SCO? %d",
            (conn_data->link_type == BTM_LINK_TYPE_SCO));

    if (sco_inx != listen_slot) {
        ALOGE("%s: not a listening socket", __func__);
        hci_status = HCI_ERR_PEER_USER;
    }

    if (slots[sco_inx].fds[0] != -1) {
        ALOGE("%s: already a connection on this slot", __func__);
        hci_status = HCI_ERR_PEER_USER;
    }

    if (conn_data->link_type == BTM_LINK_TYPE_SCO) {
        resp.packet_types = (BTM_SCO_LINK_ONLY_MASK          |
                             BTM_SCO_PKT_TYPES_MASK_NO_2_EV3 |
                             BTM_SCO_PKT_TYPES_MASK_NO_3_EV3 |
                             BTM_SCO_PKT_TYPES_MASK_NO_2_EV5 |
                             BTM_SCO_PKT_TYPES_MASK_NO_3_EV5);
    }
    else {
        /* Allow controller to use all types available except 5-slot EDR */
        resp.packet_types = (BTM_SCO_LINK_ALL_PKT_MASK |
                             BTM_SCO_PKT_TYPES_MASK_NO_2_EV5 |
                             BTM_SCO_PKT_TYPES_MASK_NO_3_EV5);
    }

    // respond to the request
    BTM_EScoConnRsp(conn_data->sco_inx, hci_status, &resp);

    // if there was an error, nothing else to do
    if (hci_status != HCI_SUCCESS) {
        unlock_slot(&lock);
        return;
    }

    // allocate a slot
    if (!slot_init(conn_data->sco_inx)) {
        ALOGE("%s: slot_init failed", __func__);
        unlock_slot(&lock);
        return;
    }

/*
    typedef struct {
    short size;
    bt_bdaddr_t bd_addr;
    int channel;
    int status;
} __attribute__((packed)) sock_connect_signal_t;
*/
    sock_connect_signal_t cs;
    cs.size = sizeof(cs);
    memcpy(cs.bd_addr.address, conn_data->bd_addr, sizeof(cs.bd_addr.address));
    cs.channel = 0;
    cs.status = 0;

    if(sock_send_fd(listen_fds[0],
                (const uint8_t*)&cs, sizeof(cs),
                slots[sco_inx].fds[1]) == sizeof(cs)) {
        ALOGI("%s: sock_send_fd succeess", __func__);
    } else {
        ALOGE("%s: sock_send_fd failed", __func__);
        unlock_slot(&lock);
        return;
    }

    btsock_thread_add_fd(thread_handle, slots[sco_inx].fds[0], BTSOCK_SCO,
            SOCK_THREAD_FD_EXCEPTION, sco_inx);

    unlock_slot(&lock);
}

bt_status_t btsock_sco_listen(int* sock_fd, int flags) {
    ALOGI("%s", __func__);

    if (sock_fd == NULL) {
        return BT_STATUS_PARM_INVALID;
    }

    lock_slot(&lock);

    if (listen_slot != INVALID_SLOT) {
        ALOGE("%s: Already listening.", __func__);
        unlock_slot(&lock);
        return BT_STATUS_BUSY;
    }

    // create the SCO socket
    UINT16 sco_inx = listen_sco();
    if (sco_inx == INVALID_SLOT) {
        // something bad happened
        ALOGE("%s: listen_sco failed.", __func__);
        unlock_slot(&lock);
        return BT_STATUS_FAIL;
    }

    // give the app its fd
    *sock_fd = listen_fds[1];

    unlock_slot(&lock);

    return BT_STATUS_SUCCESS;
}

bt_status_t btsock_sco_connect(const bt_bdaddr_t *bd_addr, int* sock_fd,
        int flags) {
    int status;

    ALOGI("%s", __func__);

    if ((bd_addr == NULL) || (sock_fd == NULL)) {
        return BT_STATUS_PARM_INVALID;
    }

    // API is not const-correct
    UINT8* address = (UINT8*)bd_addr->address;
    UINT16 sco_inx;
    // create the SCO socket
    status = BTM_CreateSco(address, TRUE, bta_ag_esco_params.packet_types,
            &sco_inx, connect_connect_cb, connect_disconnect_cb);
    if (status != BTM_CMD_STARTED) {
        // something bad happened
        ALOGE("%s: BTM_CreateSco failed: %d", __func__, status);
        return BT_STATUS_FAIL;
    }

    lock_slot(&lock);

    // allocate a slot
    if (!slot_init(sco_inx)) {
        ALOGE("%s: failed to allocate slot %d.", __func__, sco_inx);
        unlock_slot(&lock);
        return BT_STATUS_FAIL;
    }

    // give the app an fd. apps love fds.
    *sock_fd = slots[sco_inx].fds[1];

    // add our fd to the btsock poll loop
    btsock_thread_add_fd(thread_handle, slots[sco_inx].fds[0], BTSOCK_SCO,
            SOCK_THREAD_FD_EXCEPTION, sco_inx);

    unlock_slot(&lock);

    return BT_STATUS_SUCCESS;
}

void btsock_sco_signaled(int fd, int flags, uint32_t sco_inx) {
    ALOGI("%s: fd=%d flags=%d sco_inx=%d", __func__, fd, flags, sco_inx);
    if (fd < 0) {
        ALOGE("%s: invalid fd %d", __func__, fd);
        return;
    }

    if (sco_inx >= BTM_MAX_SCO_LINKS) {
        ALOGE("%s: invalid sco_inx %d", __func__, sco_inx);
        return;
    }

    if (!(flags & SOCK_THREAD_FD_EXCEPTION)) {
        ALOGE("%s: unexpected flags: 0x%X", __func__, flags);
        return;
    }

    lock_slot(&lock);

    if (fd == slots[sco_inx].fds[0]) {
        // A data socket closed - close the SCO connection.
        remove_sco(sco_inx);
        // clear out the fds for the data socket
        slots[sco_inx].fds[0] = -1;
        slots[sco_inx].fds[1] = -1;
        if (sco_inx == listen_slot) {
            // This is an accept slot - listen again.
            listen_sco();
        }
    } else if (fd == listen_fds[0]) {
        // The listen socket closed.
        if (slots[sco_inx].fds[0] == -1) {
          // There is no data connection, close the SCO.
          remove_sco(sco_inx);
        }
        // Clean up the listen state - the socket will already be closed.
        listen_slot = INVALID_SLOT;
        listen_fds[0] = -1;
        listen_fds[1] = -1;
    } else {
        ALOGE("%s: unexpected fd: %d", __func__, fd);
    }
    unlock_slot(&lock);
}
