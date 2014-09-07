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

/****************************************************************************
**
**  Name        gki_linux_pthreads.c
**
**  Function    pthreads version of Linux GKI. This version is used for
**              settop projects that already use pthreads and not pth.
**
*****************************************************************************/
#include "bt_target.h"

#define LOG_TAG "bt_gki"

#include <assert.h>
#include <hardware/bluetooth.h>
#include <sys/prctl.h>
#include <sys/times.h>
#include <utils/Log.h>

#include "alarm.h"
#include "bt_utils.h"
#include "gki_int.h"
#include "osi.h"

/*****************************************************************************
**  Constants & Macros
******************************************************************************/

#define NANOSEC_PER_MILLISEC    (1000000)
#define NSEC_PER_SEC            (1000 * NANOSEC_PER_MILLISEC)
#define USEC_PER_SEC            (1000000)
#define NSEC_PER_USEC           (1000)

#if GKI_DYNAMIC_MEMORY == FALSE
tGKI_CB   gki_cb;
#endif

#ifndef GKI_SHUTDOWN_EVT
#define GKI_SHUTDOWN_EVT    APPL_EVT_7
#endif

/*****************************************************************************
**  Local type definitions
******************************************************************************/

typedef struct
{
    UINT8 task_id;          /* GKI task id */
    TASKPTR task_entry;     /* Task entry function*/
    UINT32 params;          /* Extra params to pass to task entry function */
} gki_pthread_info_t;

/*****************************************************************************
**  Static variables
******************************************************************************/

gki_pthread_info_t gki_pthread_info[GKI_MAX_TASKS];

// Only a single alarm is used to wake bluedroid.
// NOTE: Must be manipulated with the GKI_disable() lock held.
static alarm_t *alarm_timer;
static int32_t alarm_ticks;


/*****************************************************************************
**  Externs
******************************************************************************/

/*****************************************************************************
**  Functions
******************************************************************************/

static void bt_alarm_cb(UNUSED_ATTR void *data) {
    GKI_timer_update(alarm_ticks);
}

// Schedules the next timer with the alarm timer module.
// NOTE: Must be called with GKI_disable() lock held.
void alarm_service_reschedule() {
    alarm_ticks = GKI_ready_to_sleep();

    assert(alarm_ticks >= 0);

    if (alarm_ticks > 0)
        alarm_set(alarm_timer, GKI_TICKS_TO_MS(alarm_ticks), bt_alarm_cb, NULL);
    else
        ALOGV("%s no more alarms.", __func__);
}


/*****************************************************************************
**
** Function        gki_task_entry
**
** Description     GKI pthread callback
**
** Returns         void
**
*******************************************************************************/
static void gki_task_entry(UINT32 params)
{
    gki_pthread_info_t *p_pthread_info = (gki_pthread_info_t *)params;
    gki_cb.os.thread_id[p_pthread_info->task_id] = pthread_self();

    prctl(PR_SET_NAME, (unsigned long)gki_cb.com.OSTName[p_pthread_info->task_id], 0, 0, 0);

    ALOGI("gki_task_entry task_id=%i [%s] starting\n", p_pthread_info->task_id,
                gki_cb.com.OSTName[p_pthread_info->task_id]);

    /* Call the actual thread entry point */
    (p_pthread_info->task_entry)(p_pthread_info->params);

    ALOGI("gki_task task_id=%i [%s] terminating\n", p_pthread_info->task_id,
                gki_cb.com.OSTName[p_pthread_info->task_id]);

    pthread_exit(0);    /* GKI tasks have no return value */
}

/*******************************************************************************
**
** Function         GKI_init
**
** Description      This function is called once at startup to initialize
**                  all the timer structures.
**
** Returns          void
**
*******************************************************************************/

void GKI_init(void)
{
    pthread_mutexattr_t attr;
    tGKI_OS             *p_os;

    memset (&gki_cb, 0, sizeof (gki_cb));

    gki_buffer_init();
    gki_timers_init();
    alarm_timer = alarm_new();

    gki_cb.com.OSTicks = (UINT32) times(0);

    pthread_mutexattr_init(&attr);

#ifndef __CYGWIN__
    pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE_NP);
#endif
    p_os = &gki_cb.os;
    pthread_mutex_init(&p_os->GKI_mutex, &attr);
#if (GKI_DEBUG == TRUE)
    pthread_mutex_init(&p_os->GKI_trace_mutex, NULL);
#endif
}


/*******************************************************************************
**
** Function         GKI_get_os_tick_count
**
** Description      This function is called to retrieve the native OS system tick.
**
** Returns          Tick count of native OS.
**
*******************************************************************************/
UINT32 GKI_get_os_tick_count(void)
{
    return gki_cb.com.OSTicks;
}

/*******************************************************************************
**
** Function         GKI_create_task
**
** Description      This function is called to create a new OSS task.
**
** Parameters:      task_entry  - (input) pointer to the entry function of the task
**                  task_id     - (input) Task id is mapped to priority
**                  taskname    - (input) name given to the task
**
** Returns          GKI_SUCCESS if all OK, GKI_FAILURE if any problem
**
** NOTE             This function take some parameters that may not be needed
**                  by your particular OS. They are here for compatability
**                  of the function prototype.
**
*******************************************************************************/
UINT8 GKI_create_task(TASKPTR task_entry, UINT8 task_id, const char *taskname)
{
    UINT16  i;
    UINT8   *p;
    struct sched_param param;
    int policy, ret = 0;

    GKI_TRACE( "GKI_create_task %x %d %s", (int)task_entry, (int)task_id, taskname);

    if (task_id >= GKI_MAX_TASKS)
    {
        ALOGE("Error! task ID > max task allowed");
        return (GKI_FAILURE);
    }

    gki_cb.com.OSRdyTbl[task_id]    = TASK_READY;
    gki_cb.com.OSTName[task_id]     = taskname;
    gki_cb.com.OSWaitTmr[task_id]   = 0;
    gki_cb.com.OSWaitEvt[task_id]   = 0;

    /* Initialize mutex and condition variable objects for events and timeouts */
    pthread_condattr_t cond_attr;
    pthread_condattr_init(&cond_attr);
    pthread_condattr_setclock(&cond_attr, CLOCK_MONOTONIC);

    pthread_mutex_init(&gki_cb.os.thread_evt_mutex[task_id], NULL);
    pthread_cond_init (&gki_cb.os.thread_evt_cond[task_id], &cond_attr);

    /* On Android, the new tasks starts running before 'gki_cb.os.thread_id[task_id]' is initialized */
    /* Pass task_id to new task so it can initialize gki_cb.os.thread_id[task_id] for it calls GKI_wait */
    gki_pthread_info[task_id].task_id = task_id;
    gki_pthread_info[task_id].task_entry = task_entry;
    gki_pthread_info[task_id].params = 0;

    ret = pthread_create( &gki_cb.os.thread_id[task_id],
              NULL,
              (void *)gki_task_entry,
              &gki_pthread_info[task_id]);

    if (ret != 0)
    {
         ALOGE("pthread_create failed(%d), %s!", ret, taskname);
         return GKI_FAILURE;
    }

    GKI_TRACE( "Leaving GKI_create_task %x %d %x %s\n",
              (int)task_entry,
              (int)task_id,
              (int)gki_cb.os.thread_id[task_id],
              taskname);

    return (GKI_SUCCESS);
}

void GKI_destroy_task(UINT8 task_id)
{
    if (gki_cb.com.OSRdyTbl[task_id] != TASK_DEAD)
    {
        gki_cb.com.OSRdyTbl[task_id] = TASK_DEAD;

        /* paranoi settings, make sure that we do not execute any mailbox events */
        gki_cb.com.OSWaitEvt[task_id] &= ~(TASK_MBOX_0_EVT_MASK|TASK_MBOX_1_EVT_MASK|
                                            TASK_MBOX_2_EVT_MASK|TASK_MBOX_3_EVT_MASK);

        for (int i = 0; i < GKI_NUM_TIMERS; ++i) {
          gki_cb.com.OSTaskTmr[task_id][i] = 0;
          gki_cb.com.OSTaskTmrR[task_id][i] = 0;
        }

        GKI_send_event(task_id, EVENT_MASK(GKI_SHUTDOWN_EVT));

        int result = pthread_join( gki_cb.os.thread_id[task_id], NULL );
        if ( result < 0 )
        {
            ALOGE( "pthread_join() FAILED: result: %d", result );
        }
        GKI_exit_task(task_id);
        ALOGI( "GKI_shutdown(): task [%s] terminated\n", gki_cb.com.OSTName[task_id]);
    }
}


/*******************************************************************************
**
** Function         GKI_task_self_cleanup
**
** Description      This function is used in the case when the calling thread
**                  is exiting itself. The GKI_destroy_task function can not be
**                  used in this case due to the pthread_join call. The function
**                  cleans up GKI control block associated to the terminating
**                  thread.
**
** Parameters:      task_id     - (input) Task id is used for sanity check to
**                                 make sure the calling thread is in the right
**                                 context.
**
** Returns          None
**
*******************************************************************************/
void GKI_task_self_cleanup(UINT8 task_id)
{
    UINT8 my_task_id = GKI_get_taskid();

    if (task_id != my_task_id)
    {
        ALOGE("%s: Wrong context - current task %d is not the given task id %d",\
                      __FUNCTION__, my_task_id, task_id);
        return;
    }

    if (gki_cb.com.OSRdyTbl[task_id] != TASK_DEAD)
    {
        /* paranoi settings, make sure that we do not execute any mailbox events */
        gki_cb.com.OSWaitEvt[task_id] &= ~(TASK_MBOX_0_EVT_MASK|TASK_MBOX_1_EVT_MASK|
                                            TASK_MBOX_2_EVT_MASK|TASK_MBOX_3_EVT_MASK);

        for (int i = 0; i < GKI_NUM_TIMERS; ++i) {
          gki_cb.com.OSTaskTmr[task_id][i] = 0;
          gki_cb.com.OSTaskTmrR[task_id][i] = 0;
        }

        GKI_exit_task(task_id);

        /* Calling pthread_detach here to mark the thread as detached.
           Once the thread terminates, the system can reclaim its resources
           without waiting for another thread to join with.
        */
        pthread_detach(gki_cb.os.thread_id[task_id]);
    }
}

/*******************************************************************************
**
** Function         GKI_shutdown
**
** Description      shutdowns the GKI tasks/threads in from max task id to 0 and frees
**                  pthread resources!
**                  IMPORTANT: in case of join method, GKI_shutdown must be called outside
**                  a GKI thread context!
**
** Returns          void
**
*******************************************************************************/

void GKI_shutdown(void)
{
    UINT8 task_id;

    alarm_free(alarm_timer);
    alarm_timer = NULL;

    gki_dealloc_free_queue();

    /* release threads and set as TASK_DEAD. going from low to high priority fixes
     * GKI_exception problem due to btu->hci sleep request events  */
    for (task_id = GKI_MAX_TASKS; task_id > 0; task_id--)
    {
        if (gki_cb.com.OSRdyTbl[task_id - 1] != TASK_DEAD)
        {
            gki_cb.com.OSRdyTbl[task_id - 1] = TASK_DEAD;

            /* paranoi settings, make sure that we do not execute any mailbox events */
            gki_cb.com.OSWaitEvt[task_id-1] &= ~(TASK_MBOX_0_EVT_MASK|TASK_MBOX_1_EVT_MASK|
                                                TASK_MBOX_2_EVT_MASK|TASK_MBOX_3_EVT_MASK);
            GKI_send_event(task_id - 1, EVENT_MASK(GKI_SHUTDOWN_EVT));

            int result = pthread_join( gki_cb.os.thread_id[task_id-1], NULL );

            if ( result < 0 )
            {
                ALOGE( "pthread_join() FAILED: result: %d", result );
            }
            GKI_exit_task(task_id - 1);
        }
    }

    /* Destroy mutex and condition variable objects */
    pthread_mutex_destroy(&gki_cb.os.GKI_mutex);

#if (GKI_DEBUG == TRUE)
    pthread_mutex_destroy(&gki_cb.os.GKI_trace_mutex);
#endif
}

/*******************************************************************************
**
** Function         GKI_wait
**
** Description      This function is called by tasks to wait for a specific
**                  event or set of events. The task may specify the duration
**                  that it wants to wait for, or 0 if infinite.
**
** Parameters:      flag -    (input) the event or set of events to wait for
**                  timeout - (input) the duration that the task wants to wait
**                                    for the specific events (in system ticks)
**
**
** Returns          the event mask of received events or zero if timeout
**
*******************************************************************************/
UINT16 GKI_wait (UINT16 flag, UINT32 timeout)
{
    UINT16 evt;
    UINT8 rtask;
    struct timespec abstime = { 0, 0 };

    int sec;
    int nano_sec;

    rtask = GKI_get_taskid();

    GKI_TRACE("GKI_wait %d %x %d", (int)rtask, (int)flag, (int)timeout);

    gki_cb.com.OSWaitForEvt[rtask] = flag;

    /* protect OSWaitEvt[rtask] from modification from an other thread */
    pthread_mutex_lock(&gki_cb.os.thread_evt_mutex[rtask]);

    if (!(gki_cb.com.OSWaitEvt[rtask] & flag))
    {
        if (timeout)
        {
            clock_gettime(CLOCK_MONOTONIC, &abstime);

            /* add timeout */
            sec = timeout / 1000;
            nano_sec = (timeout % 1000) * NANOSEC_PER_MILLISEC;
            abstime.tv_nsec += nano_sec;
            if (abstime.tv_nsec > NSEC_PER_SEC)
            {
                abstime.tv_sec += (abstime.tv_nsec / NSEC_PER_SEC);
                abstime.tv_nsec = abstime.tv_nsec % NSEC_PER_SEC;
            }
            abstime.tv_sec += sec;

            pthread_cond_timedwait(&gki_cb.os.thread_evt_cond[rtask],
                    &gki_cb.os.thread_evt_mutex[rtask], &abstime);
        }
        else
        {
            pthread_cond_wait(&gki_cb.os.thread_evt_cond[rtask], &gki_cb.os.thread_evt_mutex[rtask]);
        }

        /* TODO: check, this is probably neither not needed depending on phtread_cond_wait() implmentation,
         e.g. it looks like it is implemented as a counter in which case multiple cond_signal
         should NOT be lost! */

        /* we are waking up after waiting for some events, so refresh variables
           no need to call GKI_disable() here as we know that we will have some events as we've been waking
           up after condition pending or timeout */

        if (gki_cb.com.OSRdyTbl[rtask] == TASK_DEAD)
        {
            gki_cb.com.OSWaitEvt[rtask] = 0;
            /* unlock thread_evt_mutex as pthread_cond_wait() does auto lock when cond is met */
            pthread_mutex_unlock(&gki_cb.os.thread_evt_mutex[rtask]);
            return (EVENT_MASK(GKI_SHUTDOWN_EVT));
        }
    }

    /* Clear the wait for event mask */
    gki_cb.com.OSWaitForEvt[rtask] = 0;

    /* Return only those bits which user wants... */
    evt = gki_cb.com.OSWaitEvt[rtask] & flag;

    /* Clear only those bits which user wants... */
    gki_cb.com.OSWaitEvt[rtask] &= ~flag;

    /* unlock thread_evt_mutex as pthread_cond_wait() does auto lock mutex when cond is met */
    pthread_mutex_unlock(&gki_cb.os.thread_evt_mutex[rtask]);

    GKI_TRACE("GKI_wait %d %x %d %x done", (int)rtask, (int)flag, (int)timeout, (int)evt);
    return (evt);
}


/*******************************************************************************
**
** Function         GKI_delay
**
** Description      This function is called by tasks to sleep unconditionally
**                  for a specified amount of time. The duration is in milliseconds
**
** Parameters:      timeout -    (input) the duration in milliseconds
**
** Returns          void
**
*******************************************************************************/

void GKI_delay (UINT32 timeout)
{
    UINT8 rtask = GKI_get_taskid();
    struct timespec delay;
    int err;

    GKI_TRACE("GKI_delay %d %d", (int)rtask, (int)timeout);

    delay.tv_sec = timeout / 1000;
    delay.tv_nsec = 1000 * 1000 * (timeout%1000);

    /* [u]sleep can't be used because it uses SIGALRM */

    do {
        err = nanosleep(&delay, &delay);
    } while (err < 0 && errno ==EINTR);

    /* Check if task was killed while sleeping */

     /* NOTE : if you do not implement task killing, you do not need this check */

    if (rtask && gki_cb.com.OSRdyTbl[rtask] == TASK_DEAD)
    {
    }

    GKI_TRACE("GKI_delay %d %d done", (int)rtask, (int)timeout);

    return;
}


/*******************************************************************************
**
** Function         GKI_send_event
**
** Description      This function is called by tasks to send events to other
**                  tasks. Tasks can also send events to themselves.
**
** Parameters:      task_id -  (input) The id of the task to which the event has to
**                  be sent
**                  event   -  (input) The event that has to be sent
**
**
** Returns          GKI_SUCCESS if all OK, else GKI_FAILURE
**
*******************************************************************************/

UINT8 GKI_send_event (UINT8 task_id, UINT16 event)
{
    GKI_TRACE("GKI_send_event %d %x", task_id, event);

    if (task_id < GKI_MAX_TASKS)
    {
        /* protect OSWaitEvt[task_id] from manipulation in GKI_wait() */
        pthread_mutex_lock(&gki_cb.os.thread_evt_mutex[task_id]);

        /* Set the event bit */
        gki_cb.com.OSWaitEvt[task_id] |= event;

        pthread_cond_signal(&gki_cb.os.thread_evt_cond[task_id]);

        pthread_mutex_unlock(&gki_cb.os.thread_evt_mutex[task_id]);

        GKI_TRACE("GKI_send_event %d %x done", task_id, event);
        return ( GKI_SUCCESS );
    }
    GKI_TRACE("############## GKI_send_event FAILED!! ##################");
    return (GKI_FAILURE);
}


/*******************************************************************************
**
** Function         GKI_get_taskid
**
** Description      This function gets the currently running task ID.
**
** Returns          task ID
**
** NOTE             The Broadcom upper stack and profiles may run as a single task.
**                  If you only have one GKI task, then you can hard-code this
**                  function to return a '1'. Otherwise, you should have some
**                  OS-specific method to determine the current task.
**
*******************************************************************************/
UINT8 GKI_get_taskid (void)
{
    int i;

    pthread_t thread_id = pthread_self( );

    GKI_TRACE("GKI_get_taskid %x", (int)thread_id);

    for (i = 0; i < GKI_MAX_TASKS; i++) {
        if (gki_cb.os.thread_id[i] == thread_id) {
            //GKI_TRACE("GKI_get_taskid %x %d done", thread_id, i);
            return(i);
        }
    }

    GKI_TRACE("GKI_get_taskid: task id = -1");

    return(-1);
}


/*******************************************************************************
**
** Function         GKI_map_taskname
**
** Description      This function gets the task name of the taskid passed as arg.
**                  If GKI_MAX_TASKS is passed as arg the currently running task
**                  name is returned
**
** Parameters:      task_id -  (input) The id of the task whose name is being
**                  sought. GKI_MAX_TASKS is passed to get the name of the
**                  currently running task.
**
** Returns          pointer to task name
**
** NOTE             this function needs no customization
**
*******************************************************************************/

const char *GKI_map_taskname(UINT8 task_id) {
  assert(task_id <= GKI_MAX_TASKS);

  if (task_id == GKI_MAX_TASKS)
    task_id = GKI_get_taskid();

  return gki_cb.com.OSTName[task_id];
}

/*******************************************************************************
**
** Function         GKI_enable
**
** Description      This function enables interrupts.
**
** Returns          void
**
*******************************************************************************/
void GKI_enable (void)
{
    pthread_mutex_unlock(&gki_cb.os.GKI_mutex);
}


/*******************************************************************************
**
** Function         GKI_disable
**
** Description      This function disables interrupts.
**
** Returns          void
**
*******************************************************************************/

void GKI_disable (void)
{
    pthread_mutex_lock(&gki_cb.os.GKI_mutex);
}


/*******************************************************************************
**
** Function         GKI_exception
**
** Description      This function throws an exception.
**                  This is normally only called for a nonrecoverable error.
**
** Parameters:      code    -  (input) The code for the error
**                  msg     -  (input) The message that has to be logged
**
** Returns          void
**
*******************************************************************************/

void GKI_exception (UINT16 code, char *msg)
{
    UINT8 task_id;
    int i = 0;

    ALOGE( "GKI_exception(): Task State Table");

    for(task_id = 0; task_id < GKI_MAX_TASKS; task_id++)
    {
        ALOGE( "TASK ID [%d] task name [%s] state [%d]",
                         task_id,
                         gki_cb.com.OSTName[task_id],
                         gki_cb.com.OSRdyTbl[task_id]);
    }

    ALOGE("GKI_exception %d %s", code, msg);
    ALOGE( "********************************************************************");
    ALOGE( "* GKI_exception(): %d %s", code, msg);
    ALOGE( "********************************************************************");

#if 0//(GKI_DEBUG == TRUE)
    GKI_disable();

    if (gki_cb.com.ExceptionCnt < GKI_MAX_EXCEPTION)
    {
        EXCEPTION_T *pExp;

        pExp =  &gki_cb.com.Exception[gki_cb.com.ExceptionCnt++];
        pExp->type = code;
        pExp->taskid = GKI_get_taskid();
        strncpy((char *)pExp->msg, msg, GKI_MAX_EXCEPTION_MSGLEN - 1);
    }

    GKI_enable();
#endif

    GKI_TRACE("GKI_exception %d %s done", code, msg);
    return;
}

/*******************************************************************************
**
** Function         GKI_os_malloc
**
** Description      This function allocates memory
**
** Parameters:      size -  (input) The size of the memory that has to be
**                  allocated
**
** Returns          the address of the memory allocated, or NULL if failed
**
** NOTE             This function is called by the Broadcom stack when
**                  dynamic memory allocation is used. (see dyn_mem.h)
**
*******************************************************************************/
void *GKI_os_malloc (UINT32 size)
{
    return malloc(size);
}

/*******************************************************************************
**
** Function         GKI_os_free
**
** Description      This function frees memory
**
** Parameters:      size -  (input) The address of the memory that has to be
**                  freed
**
** Returns          void
**
** NOTE             This function is NOT called by the Broadcom stack and
**                  profiles. It is only called from within GKI if dynamic
**
*******************************************************************************/
void GKI_os_free (void *p_mem)
{
    free(p_mem);
}


/*******************************************************************************
**
** Function         GKI_exit_task
**
** Description      This function is called to stop a GKI task.
**
** Parameters:      task_id  - (input) the id of the task that has to be stopped
**
** Returns          void
**
** NOTE             This function is NOT called by the Broadcom stack and
**                  profiles. If you want to use it in your own implementation,
**                  put specific code here to kill a task.
**
*******************************************************************************/
void GKI_exit_task (UINT8 task_id)
{
    GKI_disable();
    gki_cb.com.OSRdyTbl[task_id] = TASK_DEAD;

    /* Destroy mutex and condition variable objects */
    pthread_mutex_destroy(&gki_cb.os.thread_evt_mutex[task_id]);
    pthread_cond_destroy (&gki_cb.os.thread_evt_cond[task_id]);

    GKI_enable();

    ALOGI("GKI_exit_task %d done", task_id);
    return;
}
