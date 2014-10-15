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


#ifndef GAP_INT_H
#define GAP_INT_H

#include "bt_target.h"
#include "gap_api.h"
#include "gki.h"
#include "gatt_api.h"

#if BLE_INCLUDED == TRUE
#define GAP_MAX_CHAR_NUM          5

typedef struct
{
    UINT16                  handle;
    UINT16                  uuid;
    tGAP_BLE_ATTR_VALUE     attr_value;
}tGAP_ATTR;
#endif
/**********************************************************************
** M A I N   C O N T R O L   B L O C K
***********************************************************************/

#define GAP_MAX_CL GATT_CL_MAX_LCB

typedef struct
{
    union
    {
        BD_ADDR         reconn_addr;
        UINT8           privacy_flag;
    }                   pending_data;
    UINT8               op;
    void                *p_pending_cback;
}tGAP_BLE_PENDING_OP;

typedef struct
{
    BD_ADDR                 bda;
    BD_ADDR                 reconn_addr;
    void                    * p_cback;
    UINT16                  conn_id;
    UINT16                  cl_op_uuid;
    UINT16                  disc_handle;
    BOOLEAN                 in_use;
    BOOLEAN                 connected;
    UINT8                   privacy_flag;
    BUFFER_Q                pending_op_q;
}tGAP_CLCB;

typedef struct
{
    UINT8            trace_level;

    /* LE GAP attribute database */
#if BLE_INCLUDED == TRUE
    tGAP_ATTR               gatt_attr[GAP_MAX_CHAR_NUM];
    BD_ADDR                 reconn_bda;
    tGAP_CLCB               clcb[GAP_MAX_CL]; /* connection link*/

    tGATT_IF                gatt_if;
#endif
} tGAP_CB;


extern tGAP_CB  gap_cb;

#if (BLE_INCLUDED == TRUE)
    extern void gap_attr_db_init(void);
#endif

#endif
