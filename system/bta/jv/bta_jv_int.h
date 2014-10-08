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
 *  This is the private interface file for the BTA Java I/F
 *
 ******************************************************************************/
#ifndef BTA_JV_INT_H
#define BTA_JV_INT_H

#include "bta_sys.h"
#include "bta_api.h"
#include "bta_jv_api.h"
#include "rfcdefs.h"
#include "port_api.h"

/*****************************************************************************
**  Constants
*****************************************************************************/

enum
{
    /* these events are handled by the state machine */
    BTA_JV_API_ENABLE_EVT = BTA_SYS_EVT_START(BTA_ID_JV),
    BTA_JV_API_DISABLE_EVT,
    BTA_JV_API_START_DISCOVERY_EVT,
    BTA_JV_API_CREATE_RECORD_EVT,
    BTA_JV_API_DELETE_RECORD_EVT,
    BTA_JV_API_RFCOMM_CONNECT_EVT,
    BTA_JV_API_RFCOMM_CLOSE_EVT,
    BTA_JV_API_RFCOMM_START_SERVER_EVT,
    BTA_JV_API_RFCOMM_STOP_SERVER_EVT,
    BTA_JV_API_RFCOMM_READ_EVT,
    BTA_JV_API_RFCOMM_WRITE_EVT,
    BTA_JV_API_SET_PM_PROFILE_EVT,
    BTA_JV_API_PM_STATE_CHANGE_EVT,
    BTA_JV_MAX_INT_EVT
};

#ifndef BTA_JV_RFC_EV_MASK
#define BTA_JV_RFC_EV_MASK (PORT_EV_RXCHAR | PORT_EV_TXEMPTY | PORT_EV_FC | PORT_EV_FCS)
#endif

/* data type for BTA_JV_API_ENABLE_EVT */
typedef struct
{
    BT_HDR          hdr;
    tBTA_JV_DM_CBACK   *p_cback;
} tBTA_JV_API_ENABLE;

/* data type for BTA_JV_API_START_DISCOVERY_EVT */
typedef struct
{
    BT_HDR      hdr;
    BD_ADDR bd_addr;
    UINT16 num_uuid;
    tSDP_UUID uuid_list[BTA_JV_MAX_UUIDS];
    UINT16 num_attr;
    UINT16 attr_list[BTA_JV_MAX_ATTRS];
    void            *user_data;      /* piggyback caller's private data*/
} tBTA_JV_API_START_DISCOVERY;

enum
{
    BTA_JV_PM_FREE_ST = 0, /* empty PM slot */
    BTA_JV_PM_IDLE_ST,
    BTA_JV_PM_BUSY_ST
};

/* BTA JV PM control block */
typedef struct
{
    UINT32          handle;     /* The connection handle */
    UINT8           state;      /* state: see above enum */
    tBTA_JV_PM_ID   app_id;     /* JV app specific id indicating power table to use */
    BD_ADDR         peer_bd_addr;    /* Peer BD address */
} tBTA_JV_PM_CB;

enum
{
    BTA_JV_ST_NONE = 0,
    BTA_JV_ST_CL_OPENING,
    BTA_JV_ST_CL_OPEN,
    BTA_JV_ST_CL_CLOSING,
    BTA_JV_ST_SR_LISTEN,
    BTA_JV_ST_SR_OPEN,
    BTA_JV_ST_SR_CLOSING
} ;
typedef UINT8  tBTA_JV_STATE;
#define BTA_JV_ST_CL_MAX    BTA_JV_ST_CL_CLOSING

#define BTA_JV_RFC_HDL_MASK         0xFF
#define BTA_JV_RFCOMM_MASK          0x80
#define BTA_JV_ALL_APP_ID           0xFF
#define BTA_JV_RFC_HDL_TO_SIDX(r)   (((r)&0xFF00) >> 8)
#define BTA_JV_RFC_H_S_TO_HDL(h, s) ((h)|(s<<8))

/* port control block */
typedef struct
{
    UINT32              handle;     /* the rfcomm session handle at jv */
    UINT16              port_handle; /* port handle */
    tBTA_JV_STATE       state;      /* the state of this control block */
    UINT8               max_sess;   /* max sessions */
    void                *user_data; /* piggyback caller's private data*/
    BOOLEAN             cong;       /* TRUE, if congested */
    tBTA_JV_PM_CB      *p_pm_cb;    /* ptr to pm control block, NULL: unused */
} tBTA_JV_PCB;

/* JV RFCOMM control block */
typedef struct
{
    tBTA_JV_RFCOMM_CBACK *p_cback;  /* the callback function */
    UINT16              rfc_hdl[BTA_JV_MAX_RFC_SR_SESSION];
    tBTA_SERVICE_ID     sec_id;     /* service id */
    UINT8               handle;     /* index: the handle reported to java app */
    UINT8               scn;        /* the scn of the server */
    UINT8               max_sess;   /* max sessions */
    int                 curr_sess;   /* current sessions count*/
} tBTA_JV_RFC_CB;

/* data type for BTA_JV_API_RFCOMM_CONNECT_EVT */
typedef struct
{
    BT_HDR          hdr;
    tBTA_SEC        sec_mask;
    tBTA_JV_ROLE    role;
    UINT8           remote_scn;
    BD_ADDR         peer_bd_addr;
    tBTA_JV_RFCOMM_CBACK *p_cback;
    void            *user_data;
} tBTA_JV_API_RFCOMM_CONNECT;

/* data type for BTA_JV_API_RFCOMM_SERVER_EVT */
typedef struct
{
    BT_HDR          hdr;
    tBTA_SEC        sec_mask;
    tBTA_JV_ROLE    role;
    UINT8           local_scn;
    UINT8           max_session;
    UINT32          handle;
    tBTA_JV_RFCOMM_CBACK *p_cback;
    void            *user_data;
} tBTA_JV_API_RFCOMM_SERVER;

/* data type for BTA_JV_API_RFCOMM_READ_EVT */
typedef struct
{
    BT_HDR          hdr;
    UINT32          handle;
    UINT32          req_id;
    UINT8           *p_data;
    UINT16          len;
    tBTA_JV_RFC_CB  *p_cb;
    tBTA_JV_PCB     *p_pcb;
} tBTA_JV_API_RFCOMM_READ;

/* data type for BTA_JV_API_SET_PM_PROFILE_EVT */
typedef struct
{
    BT_HDR              hdr;
    UINT32              handle;
    tBTA_JV_PM_ID       app_id;
    tBTA_JV_CONN_STATE  init_st;
} tBTA_JV_API_SET_PM_PROFILE;

/* data type for BTA_JV_API_PM_STATE_CHANGE_EVT */
typedef struct
{
    BT_HDR              hdr;
    tBTA_JV_PM_CB       *p_cb;
    tBTA_JV_CONN_STATE  state;
} tBTA_JV_API_PM_STATE_CHANGE;

/* data type for BTA_JV_API_RFCOMM_WRITE_EVT */
typedef struct
{
    BT_HDR          hdr;
    UINT32          handle;
    UINT32          req_id;
    UINT8           *p_data;
    int          len;
    tBTA_JV_RFC_CB  *p_cb;
    tBTA_JV_PCB     *p_pcb;
} tBTA_JV_API_RFCOMM_WRITE;

/* data type for BTA_JV_API_RFCOMM_CLOSE_EVT */
typedef struct
{
    BT_HDR          hdr;
    UINT32          handle;
    tBTA_JV_RFC_CB  *p_cb;
    tBTA_JV_PCB     *p_pcb;
    void        *user_data;
} tBTA_JV_API_RFCOMM_CLOSE;

/* data type for BTA_JV_API_CREATE_RECORD_EVT */
typedef struct
{
    BT_HDR      hdr;
    void        *user_data;
} tBTA_JV_API_CREATE_RECORD;

/* data type for BTA_JV_API_ADD_ATTRIBUTE_EVT */
typedef struct
{
    BT_HDR      hdr;
    UINT32      handle;
    UINT16      attr_id;
    UINT8       *p_value;
    INT32       value_size;
} tBTA_JV_API_ADD_ATTRIBUTE;

/* union of all data types */
typedef union
{
    /* GKI event buffer header */
    BT_HDR                          hdr;
    tBTA_JV_API_ENABLE              enable;
    tBTA_JV_API_START_DISCOVERY     start_discovery;
    tBTA_JV_API_CREATE_RECORD       create_record;
    tBTA_JV_API_ADD_ATTRIBUTE       add_attr;
    tBTA_JV_API_RFCOMM_CONNECT      rfcomm_connect;
    tBTA_JV_API_RFCOMM_READ         rfcomm_read;
    tBTA_JV_API_RFCOMM_WRITE        rfcomm_write;
    tBTA_JV_API_SET_PM_PROFILE      set_pm;
    tBTA_JV_API_PM_STATE_CHANGE     change_pm_state;
    tBTA_JV_API_RFCOMM_CLOSE        rfcomm_close;
    tBTA_JV_API_RFCOMM_SERVER       rfcomm_server;
} tBTA_JV_MSG;

/* JV control block */
typedef struct
{
    /* the SDP handle reported to JV user is the (index + 1) to sdp_handle[].
     * if sdp_handle[i]==0, it's not used.
     * otherwise sdp_handle[i] is the stack SDP handle. */
    UINT32                  sdp_handle[BTA_JV_MAX_SDP_REC]; /* SDP records created */
    UINT8                   *p_sel_raw_data;/* the raw data of last service select */
    tBTA_JV_DM_CBACK        *p_dm_cback;
    tBTA_JV_RFC_CB          rfc_cb[BTA_JV_MAX_RFC_CONN];
    tBTA_JV_PCB             port_cb[MAX_RFC_PORTS];         /* index of this array is the port_handle, */
    UINT8                   sec_id[BTA_JV_NUM_SERVICE_ID];  /* service ID */
    UINT8                   sdp_active;                     /* see BTA_JV_SDP_ACT_* */
    tSDP_UUID               uuid;                           /* current uuid of sdp discovery*/
    tBTA_JV_PM_CB           pm_cb[BTA_JV_PM_MAX_NUM];       /* PM on a per JV handle bases */
} tBTA_JV_CB;

enum
{
    BTA_JV_SDP_ACT_NONE = 0,
    BTA_JV_SDP_ACT_YES,     /* waiting for SDP result */
    BTA_JV_SDP_ACT_CANCEL   /* waiting for cancel complete */
};

/* JV control block */
#if BTA_DYNAMIC_MEMORY == FALSE
extern tBTA_JV_CB bta_jv_cb;
#else
extern tBTA_JV_CB *bta_jv_cb_ptr;
#define bta_jv_cb (*bta_jv_cb_ptr)
#endif

/* config struct */
extern tBTA_JV_CFG *p_bta_jv_cfg;

extern BOOLEAN bta_jv_sm_execute(BT_HDR *p_msg);

extern void bta_jv_enable (tBTA_JV_MSG *p_data);
extern void bta_jv_disable (tBTA_JV_MSG *p_data);
extern void bta_jv_start_discovery (tBTA_JV_MSG *p_data);
extern void bta_jv_create_record (tBTA_JV_MSG *p_data);
extern void bta_jv_delete_record (tBTA_JV_MSG *p_data);
extern void bta_jv_rfcomm_connect (tBTA_JV_MSG *p_data);
extern void bta_jv_rfcomm_close (tBTA_JV_MSG *p_data);
extern void bta_jv_rfcomm_start_server (tBTA_JV_MSG *p_data);
extern void bta_jv_rfcomm_stop_server (tBTA_JV_MSG *p_data);
extern void bta_jv_rfcomm_read (tBTA_JV_MSG *p_data);
extern void bta_jv_rfcomm_write (tBTA_JV_MSG *p_data);
extern void bta_jv_set_pm_profile (tBTA_JV_MSG *p_data);
extern void bta_jv_change_pm_state(tBTA_JV_MSG *p_data);

#endif /* BTA_JV_INT_H */
