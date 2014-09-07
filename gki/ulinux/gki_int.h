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

#include <pthread.h>

#include "gki_common.h"

/**********************************************************************
** OS specific definitions
*/

typedef struct
{
    pthread_mutex_t     GKI_mutex;
    pthread_t           thread_id[GKI_MAX_TASKS];
    pthread_mutex_t     thread_evt_mutex[GKI_MAX_TASKS];
    pthread_cond_t      thread_evt_cond[GKI_MAX_TASKS];
#if (GKI_DEBUG == TRUE)
    pthread_mutex_t     GKI_trace_mutex;
#endif
} tGKI_OS;

/* Contains common control block as well as OS specific variables */
typedef struct
{
    tGKI_OS     os;
    tGKI_COM_CB com;
} tGKI_CB;

#if GKI_DYNAMIC_MEMORY == FALSE
tGKI_CB  gki_cb;
#else
tGKI_CB *gki_cb_ptr;
#define gki_cb (*gki_cb_ptr)
#endif
