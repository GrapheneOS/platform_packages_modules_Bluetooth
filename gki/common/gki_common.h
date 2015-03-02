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

#pragma once

#include "gki.h"
#include "dyn_mem.h"

typedef enum {
  TASK_DEAD,
  TASK_READY,
  TASK_WAIT,
  TASK_DELAY,
  TASK_SUSPEND,
} gki_task_state_t;

/********************************************************************
**  Internal Error codes
*********************************************************************/
#define GKI_ERROR_BUF_CORRUPTED         0xFFFF
#define GKI_ERROR_NOT_BUF_OWNER         0xFFFE
#define GKI_ERROR_FREEBUF_BAD_QID       0xFFFD
#define GKI_ERROR_FREEBUF_BUF_LINKED    0xFFFC
#define GKI_ERROR_SEND_MSG_BAD_DEST     0xFFFB
#define GKI_ERROR_SEND_MSG_BUF_LINKED   0xFFFA
#define GKI_ERROR_ENQUEUE_BUF_LINKED    0xFFF9
#define GKI_ERROR_DELETE_POOL_BAD_QID   0xFFF8
#define GKI_ERROR_BUF_SIZE_TOOBIG       0xFFF7
#define GKI_ERROR_BUF_SIZE_ZERO         0xFFF6
#define GKI_ERROR_ADDR_NOT_IN_BUF       0xFFF5
#define GKI_ERROR_OUT_OF_BUFFERS        0xFFF4
#define GKI_ERROR_GETPOOLBUF_BAD_QID    0xFFF3
#define GKI_ERROR_TIMER_LIST_CORRUPTED  0xFFF2

typedef struct _buffer_hdr
{
	struct _buffer_hdr *p_next;   /* next buffer in the queue */
	UINT8   q_id;                 /* id of the queue */
	UINT8   task_id;              /* task which allocated the buffer*/
	UINT8   status;               /* FREE, UNLINKED or QUEUED */
	UINT8   Type;
        UINT16  size;
} BUFFER_HDR_T;

typedef struct _free_queue
{
	BUFFER_HDR_T *_p_first;      /* first buffer in the queue */
	BUFFER_HDR_T *_p_last;       /* last buffer in the queue */
	UINT16		 size;             /* size of the buffers in the pool */
	UINT16		 total;            /* toatal number of buffers */
	UINT16		 cur_cnt;          /* number of  buffers currently allocated */
	UINT16		 max_cnt;          /* maximum number of buffers allocated at any time */
} FREE_QUEUE_T;

/* Put all GKI variables into one control block
*/
typedef struct
{
    const char *task_name[GKI_MAX_TASKS];         /* name of the task */
    gki_task_state_t task_state[GKI_MAX_TASKS];   /* current state of the task */

    UINT16  OSWaitEvt[GKI_MAX_TASKS];       /* events that have to be processed by the task */
    UINT16  OSWaitForEvt[GKI_MAX_TASKS];    /* events the task is waiting for*/

    /* Define the buffer pool management variables
    */
    FREE_QUEUE_T    freeq[GKI_NUM_TOTAL_BUF_POOLS];

    UINT16   pool_buf_size[GKI_NUM_TOTAL_BUF_POOLS];

    /* Define the buffer pool start addresses
    */
    UINT8   *pool_start[GKI_NUM_TOTAL_BUF_POOLS];   /* array of pointers to the start of each buffer pool */
    UINT8   *pool_end[GKI_NUM_TOTAL_BUF_POOLS];     /* array of pointers to the end of each buffer pool */
    UINT16   pool_size[GKI_NUM_TOTAL_BUF_POOLS];    /* actual size of the buffers in a pool */

    /* Define the buffer pool access control variables */
    UINT16      pool_access_mask;                   /* Bits are set if the corresponding buffer pool is a restricted pool */

    BOOLEAN     timer_nesting;                      /* flag to prevent timer interrupt nesting */
} tGKI_COM_CB;

/* Internal GKI function prototypes
*/
BOOLEAN   gki_chk_buf_damage(void *);
void      gki_buffer_init (void);
void      gki_adjust_timer_count (INT32);
void      gki_dealloc_free_queue(void);
