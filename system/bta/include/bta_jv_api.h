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
 *  This is the public interface file the BTA Java I/F
 *
 ******************************************************************************/
#ifndef BTA_JV_API_H
#define BTA_JV_API_H

#include "bt_target.h"
#include "bt_types.h"
#include "bta_api.h"
#include "btm_api.h"
/*****************************************************************************
**  Constants and data types
*****************************************************************************/
/* status values */
#define BTA_JV_SUCCESS             0            /* Successful operation. */
#define BTA_JV_FAILURE             1            /* Generic failure. */
#define BTA_JV_BUSY                2            /* Temporarily can not handle this request. */
#define BTA_JV_NO_DATA             3            /* no data. */
#define BTA_JV_NO_RESOURCE         4            /* No more set pm control block */

typedef UINT8 tBTA_JV_STATUS;
#define BTA_JV_INTERNAL_ERR        (-1) /* internal error. */

#define BTA_JV_MAX_UUIDS        SDP_MAX_UUID_FILTERS
#define BTA_JV_MAX_ATTRS        SDP_MAX_ATTR_FILTERS
#define BTA_JV_MAX_SDP_REC      SDP_MAX_RECORDS
#define BTA_JV_MAX_SCN          PORT_MAX_RFC_PORTS /* same as BTM_MAX_SCN (in btm_int.h) */
#define BTA_JV_MAX_RFC_CONN     MAX_RFC_PORTS

#ifndef BTA_JV_DEF_RFC_MTU
#define BTA_JV_DEF_RFC_MTU      (3*330)
#endif

/* */
#ifndef BTA_JV_MAX_RFC_SR_SESSION
#define BTA_JV_MAX_RFC_SR_SESSION   MAX_BD_CONNECTIONS
#endif

/* BTA_JV_MAX_RFC_SR_SESSION can not be bigger than MAX_BD_CONNECTIONS */
#if (BTA_JV_MAX_RFC_SR_SESSION > MAX_BD_CONNECTIONS)
#undef BTA_JV_MAX_RFC_SR_SESSION
#define BTA_JV_MAX_RFC_SR_SESSION   MAX_BD_CONNECTIONS
#endif

#define BTA_JV_FIRST_SERVICE_ID BTA_FIRST_JV_SERVICE_ID
#define BTA_JV_LAST_SERVICE_ID  BTA_LAST_JV_SERVICE_ID
#define BTA_JV_NUM_SERVICE_ID   (BTA_LAST_JV_SERVICE_ID - BTA_FIRST_JV_SERVICE_ID + 1)

/* Discoverable modes */
enum
{
    BTA_JV_DISC_NONE,
    BTA_JV_DISC_LIMITED,
    BTA_JV_DISC_GENERAL
};
typedef UINT16 tBTA_JV_DISC;

#define BTA_JV_ROLE_SLAVE       BTM_ROLE_SLAVE
#define BTA_JV_ROLE_MASTER      BTM_ROLE_MASTER
typedef UINT32 tBTA_JV_ROLE;

#define BTA_JV_SERVICE_LMTD_DISCOVER    BTM_COD_SERVICE_LMTD_DISCOVER   /* 0x0020 */
#define BTA_JV_SERVICE_POSITIONING      BTM_COD_SERVICE_POSITIONING     /* 0x0100 */
#define BTA_JV_SERVICE_NETWORKING       BTM_COD_SERVICE_NETWORKING      /* 0x0200 */
#define BTA_JV_SERVICE_RENDERING        BTM_COD_SERVICE_RENDERING       /* 0x0400 */
#define BTA_JV_SERVICE_CAPTURING        BTM_COD_SERVICE_CAPTURING       /* 0x0800 */
#define BTA_JV_SERVICE_OBJ_TRANSFER     BTM_COD_SERVICE_OBJ_TRANSFER    /* 0x1000 */
#define BTA_JV_SERVICE_AUDIO            BTM_COD_SERVICE_AUDIO           /* 0x2000 */
#define BTA_JV_SERVICE_TELEPHONY        BTM_COD_SERVICE_TELEPHONY       /* 0x4000 */
#define BTA_JV_SERVICE_INFORMATION      BTM_COD_SERVICE_INFORMATION     /* 0x8000 */

/* JV ID type */
#define BTA_JV_PM_ID_1             1    /* PM example profile 1 */
#define BTA_JV_PM_ID_2             2    /* PM example profile 2 */
#define BTA_JV_PM_ID_CLEAR         0    /* Special JV ID used to clear PM profile */
#define BTA_JV_PM_ALL              0xFF /* Generic match all id, see bta_dm_cfg.c */
typedef UINT8 tBTA_JV_PM_ID;

#define BTA_JV_PM_HANDLE_CLEAR     0xFF /* Special JV ID used to clear PM profile  */

/* define maximum number of registered PM entities. should be in sync with bta pm! */
#ifndef BTA_JV_PM_MAX_NUM
#define BTA_JV_PM_MAX_NUM 5
#endif

/* JV pm connection states */
enum
{
    BTA_JV_CONN_OPEN = 0,   /* Connection opened state */
    BTA_JV_CONN_CLOSE,      /* Connection closed state */
    BTA_JV_APP_OPEN,        /* JV Application opened state */
    BTA_JV_APP_CLOSE,       /* JV Application closed state */
    BTA_JV_SCO_OPEN,        /* SCO connection opened state */
    BTA_JV_SCO_CLOSE,       /* SCO connection opened state */
    BTA_JV_CONN_IDLE,       /* Connection idle state */
    BTA_JV_CONN_BUSY,       /* Connection busy state */
    BTA_JV_MAX_CONN_STATE   /* Max number of connection state */
};
typedef UINT8 tBTA_JV_CONN_STATE;

/* Java I/F callback events */
/* events received by tBTA_JV_DM_CBACK */
#define BTA_JV_ENABLE_EVT           0  /* JV enabled */
#define BTA_JV_DISCOVERY_COMP_EVT   8  /* SDP discovery complete */
#define BTA_JV_CREATE_RECORD_EVT    11 /* the result for BTA_JvCreateRecord */

/* events received by tBTA_JV_RFCOMM_CBACK */
#define BTA_JV_RFCOMM_OPEN_EVT      25 /* open status of RFCOMM Client connection */
#define BTA_JV_RFCOMM_CLOSE_EVT     26 /* RFCOMM connection closed */
#define BTA_JV_RFCOMM_START_EVT     27 /* RFCOMM server started */
#define BTA_JV_RFCOMM_CL_INIT_EVT   28 /* RFCOMM client initiated a connection */
#define BTA_JV_RFCOMM_DATA_IND_EVT  29 /* RFCOMM connection received data */
#define BTA_JV_RFCOMM_CONG_EVT      30 /* RFCOMM connection congestion status changed */
#define BTA_JV_RFCOMM_READ_EVT      31 /* the result for BTA_JvRfcommRead */
#define BTA_JV_RFCOMM_WRITE_EVT     32 /* the result for BTA_JvRfcommWrite*/
#define BTA_JV_RFCOMM_SRV_OPEN_EVT  33 /* open status of Server RFCOMM connection */
#define BTA_JV_MAX_EVT              34 /* max number of JV events */

typedef UINT16 tBTA_JV_EVT;

/* data associated with BTA_JV_SET_DISCOVER_EVT */
typedef struct
{
    tBTA_JV_STATUS  status;     /* Whether the operation succeeded or failed. */
    tBTA_JV_DISC    disc_mode;  /* The current discoverable mode */
} tBTA_JV_SET_DISCOVER;

/* data associated with BTA_JV_DISCOVERY_COMP_EVT_ */
typedef struct
{
    tBTA_JV_STATUS  status;     /* Whether the operation succeeded or failed. */
    int scn;                    /* channel # */
} tBTA_JV_DISCOVERY_COMP;

/* data associated with BTA_JV_CREATE_RECORD_EVT */
typedef struct
{
   tBTA_JV_STATUS  status;     /* Whether the operation succeeded or failed. */
} tBTA_JV_CREATE_RECORD;

/* data associated with BTA_JV_RFCOMM_OPEN_EVT */
typedef struct
{
    tBTA_JV_STATUS  status;     /* Whether the operation succeeded or failed. */
    UINT32          handle;     /* The connection handle */
    BD_ADDR         rem_bda;    /* The peer address */
} tBTA_JV_RFCOMM_OPEN;
/* data associated with BTA_JV_RFCOMM_SRV_OPEN_EVT */
typedef struct
{
    tBTA_JV_STATUS  status;             /* Whether the operation succeeded or failed. */
    UINT32          handle;             /* The connection handle */
    UINT32          new_listen_handle;  /* The new listen handle */
    BD_ADDR         rem_bda;            /* The peer address */
} tBTA_JV_RFCOMM_SRV_OPEN;


/* data associated with BTA_JV_RFCOMM_CLOSE_EVT */
typedef struct
{
    tBTA_JV_STATUS  status;      /* Whether the operation succeeded or failed. */
    UINT32          port_status; /* PORT status */
    UINT32          handle;      /* The connection handle */
    BOOLEAN         async;       /* FALSE, if local initiates disconnect */
} tBTA_JV_RFCOMM_CLOSE;

/* data associated with BTA_JV_RFCOMM_START_EVT */
typedef struct
{
    tBTA_JV_STATUS  status;     /* Whether the operation succeeded or failed. */
    UINT32          handle;     /* The connection handle */
    UINT8           sec_id;     /* security ID used by this server */
    BOOLEAN         use_co;     /* TRUE to use co_rfc_data */
} tBTA_JV_RFCOMM_START;

/* data associated with BTA_JV_RFCOMM_CL_INIT_EVT */
typedef struct
{
    tBTA_JV_STATUS  status;     /* Whether the operation succeeded or failed. */
    UINT32          handle;     /* The connection handle */
    UINT8           sec_id;     /* security ID used by this client */
    BOOLEAN         use_co;     /* TRUE to use co_rfc_data */
} tBTA_JV_RFCOMM_CL_INIT;
/*data associated with BTA_JV_L2CAP_DATA_IND_EVT & BTA_JV_RFCOMM_DATA_IND_EVT */
typedef struct
{
    UINT32          handle;     /* The connection handle */
} tBTA_JV_DATA_IND;

/* data associated with BTA_JV_RFCOMM_CONG_EVT */
typedef struct
{
    tBTA_JV_STATUS  status;     /* Whether the operation succeeded or failed. */
    UINT32          handle;     /* The connection handle */
    BOOLEAN         cong;       /* TRUE, congested. FALSE, uncongested */
} tBTA_JV_RFCOMM_CONG;

/* data associated with BTA_JV_RFCOMM_READ_EVT */
typedef struct
{
    tBTA_JV_STATUS  status;     /* Whether the operation succeeded or failed. */
    UINT32          handle;     /* The connection handle */
    UINT32          req_id;     /* The req_id in the associated BTA_JvRfcommRead() */
    UINT8           *p_data;    /* This points the same location as the p_data
                                 * parameter in BTA_JvRfcommRead () */
    UINT16          len;        /* The length of the data read. */
} tBTA_JV_RFCOMM_READ;

/* data associated with BTA_JV_RFCOMM_WRITE_EVT */
typedef struct
{
    tBTA_JV_STATUS  status;     /* Whether the operation succeeded or failed. */
    UINT32          handle;     /* The connection handle */
    UINT32          req_id;     /* The req_id in the associated BTA_JvRfcommWrite() */
    int             len;        /* The length of the data written. */
    BOOLEAN         cong;       /* congestion status */
} tBTA_JV_RFCOMM_WRITE;

/* data associated with BTA_JV_API_SET_PM_PROFILE_EVT */
typedef struct
{
    tBTA_JV_STATUS  status;     /* Status of the operation */
    UINT32          handle;     /* Connection handle */
    tBTA_JV_PM_ID   app_id;      /* JV app ID */
} tBTA_JV_SET_PM_PROFILE;

/* data associated with BTA_JV_API_NOTIFY_PM_STATE_CHANGE_EVT */
typedef struct
{
    UINT32          handle;     /* Connection handle */
    tBTA_JV_CONN_STATE  state;  /* JV connection stata */
} tBTA_JV_NOTIFY_PM_STATE_CHANGE;


/* union of data associated with JV callback */
typedef union
{
    tBTA_JV_STATUS          status;         /* BTA_JV_ENABLE_EVT */
    tBTA_JV_DISCOVERY_COMP  disc_comp;      /* BTA_JV_DISCOVERY_COMP_EVT */
    tBTA_JV_SET_DISCOVER    set_discover;   /* BTA_JV_SET_DISCOVER_EVT */
    tBTA_JV_CREATE_RECORD   create_rec;     /* BTA_JV_CREATE_RECORD_EVT */
    tBTA_JV_RFCOMM_OPEN     rfc_open;       /* BTA_JV_RFCOMM_OPEN_EVT */
    tBTA_JV_RFCOMM_SRV_OPEN rfc_srv_open;   /* BTA_JV_RFCOMM_SRV_OPEN_EVT */
    tBTA_JV_RFCOMM_CLOSE    rfc_close;      /* BTA_JV_RFCOMM_CLOSE_EVT */
    tBTA_JV_RFCOMM_START    rfc_start;      /* BTA_JV_RFCOMM_START_EVT */
    tBTA_JV_RFCOMM_CL_INIT  rfc_cl_init;    /* BTA_JV_RFCOMM_CL_INIT_EVT */
    tBTA_JV_RFCOMM_CONG     rfc_cong;       /* BTA_JV_RFCOMM_CONG_EVT */
    tBTA_JV_RFCOMM_READ     rfc_read;       /* BTA_JV_RFCOMM_READ_EVT */
    tBTA_JV_RFCOMM_WRITE    rfc_write;      /* BTA_JV_RFCOMM_WRITE_EVT */
    tBTA_JV_DATA_IND        data_ind;    /* BTA_JV_L2CAP_DATA_IND_EVT
                                               BTA_JV_RFCOMM_DATA_IND_EVT */
} tBTA_JV;

/* JAVA DM Interface callback */
typedef void (tBTA_JV_DM_CBACK)(tBTA_JV_EVT event, tBTA_JV *p_data, void * user_data);

/* JAVA RFCOMM interface callback */
typedef void* (tBTA_JV_RFCOMM_CBACK)(tBTA_JV_EVT event, tBTA_JV *p_data, void *user_data);

/* JV configuration structure */
typedef struct
{
    UINT16  sdp_raw_size;           /* The size of p_sdp_raw_data */
    UINT16  sdp_db_size;            /* The size of p_sdp_db */
    UINT8   *p_sdp_raw_data;        /* The data buffer to keep raw data */
    tSDP_DISCOVERY_DB   *p_sdp_db;  /* The data buffer to keep SDP database */
} tBTA_JV_CFG;

/*******************************************************************************
**
** Function         BTA_JvEnable
**
** Description      Enable the Java I/F service. When the enable
**                  operation is complete the callback function will be
**                  called with a BTA_JV_ENABLE_EVT. This function must
**                  be called before other functions in the JV API are
**                  called.
**
** Returns          BTA_JV_SUCCESS if successful.
**                  BTA_JV_FAIL if internal failure.
**
*******************************************************************************/
extern tBTA_JV_STATUS BTA_JvEnable(tBTA_JV_DM_CBACK *p_cback);

/*******************************************************************************
**
** Function         BTA_JvDisable
**
** Description      Disable the Java I/F
**
** Returns          void
**
*******************************************************************************/
extern void BTA_JvDisable(void);

/*******************************************************************************
**
** Function         BTA_JvIsEnable
**
** Description      Get the JV registration status.
**
** Returns          TRUE, if registered
**
*******************************************************************************/
extern BOOLEAN BTA_JvIsEnable(void);

/*******************************************************************************
**
** Function         BTA_JvIsEncrypted
**
** Description      This function checks if the link to peer device is encrypted
**
** Returns          TRUE if encrypted.
**                  FALSE if not.
**
*******************************************************************************/
extern BOOLEAN BTA_JvIsEncrypted(BD_ADDR bd_addr);

/*******************************************************************************
**
** Function         BTA_JvStartDiscovery
**
** Description      This function performs service discovery for the services
**                  provided by the given peer device. When the operation is
**                  complete the tBTA_JV_DM_CBACK callback function will be
**                  called with a BTA_JV_DISCOVERY_COMP_EVT.
**
** Returns          BTA_JV_SUCCESS, if the request is being processed.
**                  BTA_JV_FAILURE, otherwise.
**
*******************************************************************************/
extern tBTA_JV_STATUS BTA_JvStartDiscovery(BD_ADDR bd_addr, UINT16 num_uuid,
                                           tSDP_UUID *p_uuid_list, void* user_data);

/*******************************************************************************
**
** Function         BTA_JvCreateRecord
**
** Description      Create a service record in the local SDP database by user in
**                  tBTA_JV_DM_CBACK callback with a BTA_JV_CREATE_RECORD_EVT.
**
** Returns          BTA_JV_SUCCESS, if the request is being processed.
**                  BTA_JV_FAILURE, otherwise.
**
*******************************************************************************/
extern tBTA_JV_STATUS BTA_JvCreateRecordByUser(void* user_data);

/*******************************************************************************
**
** Function         BTA_JvDeleteRecord
**
** Description      Delete a service record in the local SDP database.
**
** Returns          BTA_JV_SUCCESS, if the request is being processed.
**                  BTA_JV_FAILURE, otherwise.
**
*******************************************************************************/
extern tBTA_JV_STATUS BTA_JvDeleteRecord(UINT32 handle);

/*******************************************************************************
**
** Function         BTA_JvRfcommConnect
**
** Description      This function makes an RFCOMM conection to a remote BD
**                  Address.
**                  When the connection is initiated or failed to initiate,
**                  tBTA_JV_RFCOMM_CBACK is called with BTA_JV_RFCOMM_CL_INIT_EVT
**                  When the connection is established or failed,
**                  tBTA_JV_RFCOMM_CBACK is called with BTA_JV_RFCOMM_OPEN_EVT
**
** Returns          BTA_JV_SUCCESS, if the request is being processed.
**                  BTA_JV_FAILURE, otherwise.
**
*******************************************************************************/
extern tBTA_JV_STATUS BTA_JvRfcommConnect(tBTA_SEC sec_mask,
                                          tBTA_JV_ROLE role, UINT8 remote_scn, BD_ADDR peer_bd_addr,
                                          tBTA_JV_RFCOMM_CBACK *p_cback, void *user_data);

/*******************************************************************************
**
** Function         BTA_JvRfcommClose
**
** Description      This function closes an RFCOMM connection
**
** Returns          BTA_JV_SUCCESS, if the request is being processed.
**                  BTA_JV_FAILURE, otherwise.
**
*******************************************************************************/
extern tBTA_JV_STATUS BTA_JvRfcommClose(UINT32 handle, void* user_data);

/*******************************************************************************
**
** Function         BTA_JvRfcommStartServer
**
** Description      This function starts listening for an RFCOMM connection
**                  request from a remote Bluetooth device.  When the server is
**                  started successfully, tBTA_JV_RFCOMM_CBACK is called
**                  with BTA_JV_RFCOMM_START_EVT.
**                  When the connection is established, tBTA_JV_RFCOMM_CBACK
**                  is called with BTA_JV_RFCOMM_OPEN_EVT.
**
** Returns          BTA_JV_SUCCESS, if the request is being processed.
**                  BTA_JV_FAILURE, otherwise.
**
*******************************************************************************/
extern tBTA_JV_STATUS BTA_JvRfcommStartServer(tBTA_SEC sec_mask,
                                              tBTA_JV_ROLE role, UINT8 local_scn, UINT8 max_session,
                                              tBTA_JV_RFCOMM_CBACK *p_cback, void *user_data);

/*******************************************************************************
**
** Function         BTA_JvRfcommStopServer
**
** Description      This function stops the RFCOMM server. If the server has an
**                  active connection, it would be closed.
**
** Returns          BTA_JV_SUCCESS, if the request is being processed.
**                  BTA_JV_FAILURE, otherwise.
**
*******************************************************************************/
extern tBTA_JV_STATUS BTA_JvRfcommStopServer(UINT32 handle, void* user_data);

/*******************************************************************************
**
** Function         BTA_JvRfcommRead
**
** Description      This function reads data from an RFCOMM connection
**                  When the operation is complete, tBTA_JV_RFCOMM_CBACK is
**                  called with BTA_JV_RFCOMM_READ_EVT.
**
** Returns          BTA_JV_SUCCESS, if the request is being processed.
**                  BTA_JV_FAILURE, otherwise.
**
*******************************************************************************/
extern tBTA_JV_STATUS BTA_JvRfcommRead(UINT32 handle, UINT32 req_id,
                                       UINT8 *p_data, UINT16 len);

/*******************************************************************************
**
** Function         BTA_JvRfcommReady
**
** Description      This function determined if there is data to read from
**                  an RFCOMM connection
**
** Returns          BTA_JV_SUCCESS, if data queue size is in *p_data_size.
**                  BTA_JV_FAILURE, if error.
**
*******************************************************************************/
extern tBTA_JV_STATUS BTA_JvRfcommReady(UINT32 handle, UINT32 *p_data_size);

/*******************************************************************************
**
** Function         BTA_JvRfcommWrite
**
** Description      This function writes data to an RFCOMM connection
**                  When the operation is complete, tBTA_JV_RFCOMM_CBACK is
**                  called with BTA_JV_RFCOMM_WRITE_EVT.
**
** Returns          BTA_JV_SUCCESS, if the request is being processed.
**                  BTA_JV_FAILURE, otherwise.
**
*******************************************************************************/
extern tBTA_JV_STATUS BTA_JvRfcommWrite(UINT32 handle, UINT32 req_id);

/*******************************************************************************
 **
 ** Function    BTA_JVSetPmProfile
 **
 ** Description This function set or free power mode profile for different JV application
 **
 ** Parameters:  handle,  JV handle from RFCOMM or L2CAP
 **              app_id:  app specific pm ID, can be BTA_JV_PM_ALL, see bta_dm_cfg.c for details
 **              BTA_JV_PM_ID_CLEAR: removes pm management on the handle. init_st is ignored and
 **              BTA_JV_CONN_CLOSE is called implicitely
 **              init_st:  state after calling this API. typically it should be BTA_JV_CONN_OPEN
 **
 ** Returns      BTA_JV_SUCCESS, if the request is being processed.
 **              BTA_JV_FAILURE, otherwise.
 **
 ** NOTE:        BTA_JV_PM_ID_CLEAR: In general no need to be called as jv pm calls automatically
 **              BTA_JV_CONN_CLOSE to remove in case of connection close!
 **
 *******************************************************************************/
extern tBTA_JV_STATUS BTA_JvSetPmProfile(UINT32 handle, tBTA_JV_PM_ID app_id,
                                         tBTA_JV_CONN_STATE init_st);

/*******************************************************************************
**
** Function         BTA_JvRfcommGetPortHdl
**
** Description    This function fetches the rfcomm port handle
**
** Returns          BTA_JV_SUCCESS, if the request is being processed.
**                  BTA_JV_FAILURE, otherwise.
**
*******************************************************************************/
UINT16 BTA_JvRfcommGetPortHdl(UINT32 handle);

#endif /* BTA_JV_API_H */
