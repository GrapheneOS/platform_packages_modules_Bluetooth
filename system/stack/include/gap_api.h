/******************************************************************************
 *
 *  Copyright (C) 2009-2013 Broadcom Corporation
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

#ifndef GAP_API_H
#define GAP_API_H

/*****************************************************************************
**  Constants
*****************************************************************************/

#ifndef  GAP_PREFER_CONN_INT_MAX
#define  GAP_PREFER_CONN_INT_MAX         BTM_BLE_CONN_INT_MIN
#endif

#ifndef  GAP_PREFER_CONN_INT_MIN
#define  GAP_PREFER_CONN_INT_MIN         BTM_BLE_CONN_INT_MIN
#endif

#ifndef  GAP_PREFER_CONN_LATENCY
#define  GAP_PREFER_CONN_LATENCY         0
#endif

#ifndef  GAP_PREFER_CONN_SP_TOUT
#define  GAP_PREFER_CONN_SP_TOUT         2000
#endif

/*****************************************************************************
**  Type Definitions
*****************************************************************************/

typedef struct
{
    UINT16      int_min;
    UINT16      int_max;
    UINT16      latency;
    UINT16      sp_tout;
}tGAP_BLE_PREF_PARAM;

typedef union
{
    tGAP_BLE_PREF_PARAM     conn_param;
    BD_ADDR                 reconn_bda;
    UINT16                  icon;
    UINT8                   *p_dev_name;
    UINT8                   privacy;

}tGAP_BLE_ATTR_VALUE;

typedef void (tGAP_BLE_DEV_NAME_CBACK)(BOOLEAN status, BD_ADDR addr, UINT16 length, char *p_name);

typedef void (tGAP_BLE_RECONN_ADDR_CBACK)(BOOLEAN status, BD_ADDR addr, BD_ADDR reconn_bda);

/*****************************************************************************
**  External Function Declarations
*****************************************************************************/

/*******************************************************************************
**
** Function         GAP_SetTraceLevel
**
** Description      This function sets the trace level for GAP.  If called with
**                  a value of 0xFF, it simply returns the current trace level.
**
** Returns          The new or current trace level
**
*******************************************************************************/
extern UINT8 GAP_SetTraceLevel (UINT8 new_level);

/*******************************************************************************
**
** Function         GAP_Init
**
** Description      Initializes the control blocks used by GAP.
**                  This routine should not be called except once per
**                      stack invocation.
**
** Returns          Nothing
**
*******************************************************************************/
extern void GAP_Init(void);

#if (BLE_INCLUDED == TRUE)
/*******************************************************************************
**
** Function         GAP_BleAttrDBUpdate
**
** Description      update GAP local BLE attribute database.
**
** Returns          Nothing
**
*******************************************************************************/
extern void GAP_BleAttrDBUpdate(UINT16 attr_uuid, tGAP_BLE_ATTR_VALUE *p_value);


/*******************************************************************************
**
** Function         GAP_BleReadPeerPrefConnParams
**
** Description      Start a process to read a connected peripheral's preferred
**                  connection parameters
**
** Returns          TRUE if read started, else FALSE if GAP is busy
**
*******************************************************************************/
extern BOOLEAN GAP_BleReadPeerPrefConnParams (BD_ADDR peer_bda);

/*******************************************************************************
**
** Function         GAP_BleReadPeerDevName
**
** Description      Start a process to read a connected peripheral's device name.
**
** Returns          TRUE if request accepted
**
*******************************************************************************/
extern BOOLEAN GAP_BleReadPeerDevName (BD_ADDR peer_bda, tGAP_BLE_DEV_NAME_CBACK *p_cback);


/*******************************************************************************
**
** Function         GAP_BleCancelReadPeerDevName
**
** Description      Cancel reading a peripheral's device name.
**
** Returns          TRUE if request accepted
**
*******************************************************************************/
extern BOOLEAN GAP_BleCancelReadPeerDevName (BD_ADDR peer_bda);

/*******************************************************************************
**
** Function         GAP_BleUpdateReconnectAddr
**
** Description      Start a process to udpate the reconnect address if remote devive
**                  has privacy enabled.
**
** Returns          TRUE if read started, else FALSE if GAP is busy
**
*******************************************************************************/
extern BOOLEAN GAP_BleUpdateReconnectAddr (BD_ADDR peer_bda,
                                           BD_ADDR reconn_addr,
                                           tGAP_BLE_RECONN_ADDR_CBACK *p_cback);

#endif

#endif  /* GAP_API_H */
