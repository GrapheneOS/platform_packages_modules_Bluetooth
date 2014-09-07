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

/* Task States: (For OSRdyTbl) */
#define TASK_DEAD       0   /* b0000 */
#define TASK_READY      1   /* b0001 */
#define TASK_WAIT       2   /* b0010 */
#define TASK_DELAY      4   /* b0100 */
#define TASK_SUSPEND    8   /* b1000 */


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


/********************************************************************
**  Misc constants
*********************************************************************/

/********************************************************************
**  Buffer Management Data Structures
*********************************************************************/

typedef struct _buffer_hdr
{
	struct _buffer_hdr *p_next;   /* next buffer in the queue */
	UINT8   q_id;                 /* id of the queue */
	UINT8   task_id;              /* task which allocated the buffer*/
	UINT8   status;               /* FREE, UNLINKED or QUEUED */
	UINT8   Type;
#if VALGRIND
        UINT16  size;
#endif
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


/* Buffer related defines
*/
#define ALIGN_POOL(pl_size)  ( (((pl_size) + 3) / sizeof(UINT32)) * sizeof(UINT32))
#define BUFFER_HDR_SIZE     (sizeof(BUFFER_HDR_T))                  /* Offset past header */
#define BUFFER_PADDING_SIZE (sizeof(BUFFER_HDR_T) + sizeof(UINT32)) /* Header + Magic Number */
#define MAX_USER_BUF_SIZE   ((UINT16)0xffff - BUFFER_PADDING_SIZE)  /* pool size must allow for header */
#define MAGIC_NO            0xDDBADDBA

#define BUF_STATUS_FREE     0
#define BUF_STATUS_UNLINKED 1
#define BUF_STATUS_QUEUED   2

/* Exception related structures (Used in debug mode only)
*/
#if (GKI_DEBUG == TRUE)
typedef struct
{
	UINT16  type;
	UINT8   taskid;
	UINT8   msg[GKI_MAX_EXCEPTION_MSGLEN];
} EXCEPTION_T;
#endif


/* Put all GKI variables into one control block
*/
typedef struct
{
    /* Task management variables
    */
    /* The stack and stack size are not used on Windows
    */
/* Definitions for dynamic buffer use */
#if (GKI_NUM_FIXED_BUF_POOLS > 0)
    UINT8 *bufpool0;
#endif

#if (GKI_NUM_FIXED_BUF_POOLS > 1)
    UINT8 *bufpool1;
#endif

#if (GKI_NUM_FIXED_BUF_POOLS > 2)
    UINT8 *bufpool2;
#endif

#if (GKI_NUM_FIXED_BUF_POOLS > 3)
    UINT8 *bufpool3;
#endif

#if (GKI_NUM_FIXED_BUF_POOLS > 4)
    UINT8 *bufpool4;
#endif

#if (GKI_NUM_FIXED_BUF_POOLS > 5)
    UINT8 *bufpool5;
#endif

#if (GKI_NUM_FIXED_BUF_POOLS > 6)
    UINT8 *bufpool6;
#endif

#if (GKI_NUM_FIXED_BUF_POOLS > 7)
    UINT8 *bufpool7;
#endif

#if (GKI_NUM_FIXED_BUF_POOLS > 8)
    UINT8 *bufpool8;
#endif

#if (GKI_NUM_FIXED_BUF_POOLS > 9)
    UINT8 *bufpool9;
#endif

#if (GKI_NUM_FIXED_BUF_POOLS > 10)
    UINT8 *bufpool10;
#endif

#if (GKI_NUM_FIXED_BUF_POOLS > 11)
    UINT8 *bufpool11;
#endif

#if (GKI_NUM_FIXED_BUF_POOLS > 12)
    UINT8 *bufpool12;
#endif

#if (GKI_NUM_FIXED_BUF_POOLS > 13)
    UINT8 *bufpool13;
#endif

#if (GKI_NUM_FIXED_BUF_POOLS > 14)
    UINT8 *bufpool14;
#endif

#if (GKI_NUM_FIXED_BUF_POOLS > 15)
    UINT8 *bufpool15;
#endif

    const char *OSTName[GKI_MAX_TASKS];         /* name of the task */

    UINT8   OSRdyTbl[GKI_MAX_TASKS];        /* current state of the task */
    UINT16  OSWaitEvt[GKI_MAX_TASKS];       /* events that have to be processed by the task */
    UINT16  OSWaitForEvt[GKI_MAX_TASKS];    /* events the task is waiting for*/

    UINT32  OSTicks;                        /* system ticks from start */

    /* Timer related variables
    */
    INT32   OSTicksTilExp;      /* Number of ticks till next timer expires */
    INT32   OSNumOrigTicks;     /* Number of ticks between last timer expiration to the next one */

    INT32   OSWaitTmr   [GKI_MAX_TASKS];  /* ticks the task has to wait, for specific events */

    /* Only take up space timers used in the system (GKI_NUM_TIMERS defined in target.h) */
    INT32   OSTaskTmr[GKI_MAX_TASKS][GKI_NUM_TIMERS];
    INT32   OSTaskTmrR[GKI_MAX_TASKS][GKI_NUM_TIMERS];

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
    UINT8       pool_list[GKI_NUM_TOTAL_BUF_POOLS]; /* buffer pools arranged in the order of size */
    UINT8       curr_total_no_of_pools;             /* number of fixed buf pools + current number of dynamic pools */

    BOOLEAN     timer_nesting;                      /* flag to prevent timer interrupt nesting */

#if (GKI_DEBUG == TRUE)
    UINT16      ExceptionCnt;                       /* number of GKI exceptions that have happened */
    EXCEPTION_T Exception[GKI_MAX_EXCEPTION];
#endif

} tGKI_COM_CB;

/* Internal GKI function prototypes
*/
GKI_API extern BOOLEAN   gki_chk_buf_damage(void *);
extern BOOLEAN   gki_chk_buf_owner(void *);
extern void      gki_buffer_init (void);
extern void      gki_timers_init(void);
extern void      gki_adjust_timer_count (INT32);
extern void      gki_dealloc_free_queue(void);


/* Debug aids
*/
typedef void  (*FP_PRINT)(char *, ...);

#if (GKI_DEBUG == TRUE)

typedef void  (*PKT_PRINT)(UINT8 *, UINT16);

extern void gki_print_task(FP_PRINT);
extern void gki_print_exception(FP_PRINT);
extern void gki_print_timer(FP_PRINT);
extern void gki_print_stack(FP_PRINT);
extern void gki_print_buffer(FP_PRINT);
extern void gki_print_buffer_statistics(FP_PRINT, INT16);
GKI_API extern void gki_print_used_bufs (FP_PRINT, UINT8);
extern void gki_dump(UINT8 *, UINT16, FP_PRINT);
extern void gki_dump2(UINT16 *, UINT16, FP_PRINT);
extern void gki_dump4(UINT32 *, UINT16, FP_PRINT);

#endif
