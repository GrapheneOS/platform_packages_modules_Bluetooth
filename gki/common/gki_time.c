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

#include <assert.h>
#include "gki_int.h"
#include "osi/include/log.h"

#define GKI_NO_NEW_TMRS_STARTED (0x7fffffffL)   /* Largest signed positive timer count */

// Used for controlling alarms from AlarmService.
extern void alarm_service_reschedule(void);

/*******************************************************************************
**
** Function         gki_timers_init
**
** Description      This internal function is called once at startup to initialize
**                  all the timer structures.
**
** Returns          void
**
*******************************************************************************/
void gki_timers_init(void)
{
    UINT8   tt;

    gki_cb.com.OSTicksTilExp = 0;       /* Remaining time (of OSTimeCurTimeout) before next timer expires */
    gki_cb.com.OSNumOrigTicks = 0;

    for (tt = 0; tt < GKI_MAX_TASKS; tt++)
    {
        gki_cb.com.OSWaitTmr   [tt] = 0;

        for (int i = 0; i < GKI_NUM_TIMERS; ++i) {
          gki_cb.com.OSTaskTmr[tt][i] = 0;
          gki_cb.com.OSTaskTmrR[tt][i] = 0;
        }
    }

    return;
}

/*******************************************************************************
**
** Function         gki_timers_is_timer_running
**
** Description      This internal function is called to test if any gki timer are running
**
**
** Returns          TRUE if at least one time is running in the system, FALSE else.
**
*******************************************************************************/
BOOLEAN gki_timers_is_timer_running(void) {
  for (int i = 0; i < GKI_MAX_TASKS; ++i)
    for (int j = 0; j < GKI_NUM_TIMERS; ++j)
      if (gki_cb.com.OSTaskTmr[i][j])
        return true;
    return false;
}

/*******************************************************************************
**
** Function         GKI_get_tick_count
**
** Description      This function returns the current system ticks
**
** Returns          The current number of system ticks
**
*******************************************************************************/
UINT32  GKI_get_tick_count(void)
{
    return gki_cb.com.OSTicks;
}


/*******************************************************************************
**
** Function         GKI_ready_to_sleep
**
** Description      This function returns the number of system ticks until the
**                  next timer will expire.  It is typically called by a power
**                  savings manager to find out how long it can have the system
**                  sleep before it needs to service the next entry.
**
** Parameters:      None
**
** Returns          Number of ticks til the next timer expires
**                  Note: the value is a signed  value.  This value should be
**                      compared to x > 0, to avoid misinterpreting negative tick
**                      values.
**
*******************************************************************************/
INT32    GKI_ready_to_sleep (void)
{
    return (gki_cb.com.OSTicksTilExp);
}


/*******************************************************************************
**
** Function         GKI_start_timer
**
** Description      An application can call this function to start one of
**                  it's four general purpose timers. Any of the four timers
**                  can be 1-shot or continuous. If a timer is already running,
**                  it will be reset to the new parameters.
**
** Parameters       tnum            - (input) timer number to be started (TIMER_0,
**                                              TIMER_1, TIMER_2, or TIMER_3)
**                  ticks           - (input) the number of system ticks til the
**                                              timer expires.
**                  is_continuous   - (input) TRUE if timer restarts automatically,
**                                              else FALSE if it is a 'one-shot'.
**
** Returns          void
**
*******************************************************************************/
void GKI_start_timer (UINT8 tnum, INT32 ticks, BOOLEAN is_continuous)
{
    INT32   reload;
    INT32   orig_ticks;
    UINT8   task_id = GKI_get_taskid();

    if (ticks <= 0)
        ticks = 1;

    orig_ticks = ticks;     /* save the ticks in case adjustment is necessary */


    /* If continuous timer, set reload, else set it to 0 */
    if (is_continuous)
        reload = ticks;
    else
        reload = 0;

    GKI_disable();

    /* Add the time since the last task timer update.
    ** Note that this works when no timers are active since
    ** both OSNumOrigTicks and OSTicksTilExp are 0.
    */
    if (INT32_MAX - (gki_cb.com.OSNumOrigTicks - gki_cb.com.OSTicksTilExp) > ticks)
    {
        ticks += gki_cb.com.OSNumOrigTicks - gki_cb.com.OSTicksTilExp;
    }
    else
        ticks = INT32_MAX;

    assert(tnum < GKI_NUM_TIMERS);

    gki_cb.com.OSTaskTmr[task_id][tnum] = ticks;
    gki_cb.com.OSTaskTmrR[task_id][tnum] = reload;

    gki_adjust_timer_count (orig_ticks);
    GKI_enable();
}

/*******************************************************************************
**
** Function         GKI_stop_timer
**
** Description      An application can call this function to stop one of
**                  it's four general purpose timers. There is no harm in
**                  stopping a timer that is already stopped.
**
** Parameters       tnum            - (input) timer number to be started (TIMER_0,
**                                              TIMER_1, TIMER_2, or TIMER_3)
** Returns          void
**
*******************************************************************************/
void GKI_stop_timer(UINT8 tnum) {
  assert(tnum < GKI_NUM_TIMERS);

  UINT8  task_id = GKI_get_taskid();

  gki_cb.com.OSTaskTmr[task_id][tnum] = 0;
  gki_cb.com.OSTaskTmrR[task_id][tnum] = 0;
}


/*******************************************************************************
**
** Function         GKI_timer_update
**
** Description      This function is called by an OS to drive the GKI's timers.
**                  It is typically called at every system tick to
**                  update the timers for all tasks, and check for timeouts.
**
**                  Note: It has been designed to also allow for variable tick updates
**                      so that systems with strict power savings requirements can
**                      have the update occur at variable intervals.
**
** Parameters:      ticks_since_last_update - (input) This is the number of TICKS that have
**                          occurred since the last time GKI_timer_update was called.
**
** Returns          void
**
*******************************************************************************/
void GKI_timer_update (INT32 ticks_since_last_update)
{
    UINT8   task_id;
    long    next_expiration;        /* Holds the next soonest expiration time after this update */

    /* Increment the number of ticks used for time stamps */
    gki_cb.com.OSTicks += ticks_since_last_update;

    /* If any timers are running in any tasks, decrement the remaining time til
     * the timer updates need to take place (next expiration occurs)
     */
    gki_cb.com.OSTicksTilExp -= ticks_since_last_update;

    /* Don't allow timer interrupt nesting */
    if (gki_cb.com.timer_nesting)
        return;

    gki_cb.com.timer_nesting = 1;

    /* No need to update the ticks if no timeout has occurred */
    if (gki_cb.com.OSTicksTilExp > 0)
    {
        // When using alarms from AlarmService we should
        // always have work to be done here.
        LOG_ERROR("%s no work to be done when expected work", __func__);
        gki_cb.com.timer_nesting = 0;
        return;
    }

    next_expiration = GKI_NO_NEW_TMRS_STARTED;

    /* If here then gki_cb.com.OSTicksTilExp <= 0. If negative, then increase gki_cb.com.OSNumOrigTicks
       to account for the difference so timer updates below are decremented by the full number
       of ticks. gki_cb.com.OSNumOrigTicks is reset at the bottom of this function so changing this
       value only affects the timer updates below
     */
    gki_cb.com.OSNumOrigTicks -= gki_cb.com.OSTicksTilExp;

    /* Protect this section because if a GKI_timer_stop happens between:
     *   - gki_cb.com.OSTaskTmr0[task_id] -= gki_cb.com.OSNumOrigTicks;
     *   - gki_cb.com.OSTaskTmr0[task_id] = gki_cb.com.OSTaskTmr0R[task_id];
     * then the timer may appear stopped while it is about to be reloaded.
     */
    GKI_disable();

    /* Check for OS Task Timers */
    for (task_id = 0; task_id < GKI_MAX_TASKS; task_id++)
    {
        if (gki_cb.com.OSWaitTmr[task_id] > 0) /* If timer is running */
        {
            gki_cb.com.OSWaitTmr[task_id] -= gki_cb.com.OSNumOrigTicks;
            if (gki_cb.com.OSWaitTmr[task_id] <= 0)
            {
                /* Timer Expired */
                gki_cb.com.task_state[task_id] = TASK_READY;
            }
        }

        for (int i = 0; i < GKI_NUM_TIMERS; ++i) {
          /* If any timer is running, decrement */
          if (gki_cb.com.OSTaskTmr[task_id][i] > 0)
          {
            gki_cb.com.OSTaskTmr[task_id][i] -= gki_cb.com.OSNumOrigTicks;

            if (gki_cb.com.OSTaskTmr[task_id][i] <= 0)
            {
              /* Reload timer and set timer expired event mask */
              gki_cb.com.OSTaskTmr[task_id][i] = gki_cb.com.OSTaskTmrR[task_id][i];

              // (1 << (i+4)) evaluates to the same value as TIMER_x_EVT_MASK.
              GKI_send_event(task_id, (1 << (i+4)));
            }
          }

          /* Check to see if this timer is the next one to expire */
          if (gki_cb.com.OSTaskTmr[task_id][i] > 0 && gki_cb.com.OSTaskTmr[task_id][i] < next_expiration)
            next_expiration = gki_cb.com.OSTaskTmr[task_id][i];
        }
    }
    /* Set the next timer experation value if there is one to start */
    if (next_expiration < GKI_NO_NEW_TMRS_STARTED)
    {
        gki_cb.com.OSTicksTilExp = gki_cb.com.OSNumOrigTicks = next_expiration;
    }
    else
    {
        gki_cb.com.OSTicksTilExp = gki_cb.com.OSNumOrigTicks = 0;
    }

    // Set alarm service for next alarm.
    alarm_service_reschedule();

    GKI_enable();

    gki_cb.com.timer_nesting = 0;

    return;
}

/* Returns the initial number of ticks for this timer entry. */
INT32 GKI_timer_ticks_getinitial(const TIMER_LIST_ENT *tle) {
    assert(tle != NULL);
    return tle->ticks_initial;
}

/*******************************************************************************
**
** Function         GKI_get_remaining_ticks
**
** Description      This function is called by an application to get remaining
**                  ticks to expire
**
** Parameters       p_timer_listq   - (input) pointer to the timer list queue object
**                  p_target_tle    - (input) pointer to a timer list queue entry
**
** Returns          0 if timer is not used or timer is not in the list
**                  remaining ticks if success
**
*******************************************************************************/
UINT32 GKI_get_remaining_ticks (TIMER_LIST_Q *p_timer_listq, TIMER_LIST_ENT  *p_target_tle)
{
    TIMER_LIST_ENT  *p_tle;
    UINT32           rem_ticks = 0;

    if (p_target_tle->in_use)
    {
        p_tle = p_timer_listq->p_first;

        /* adding up all of ticks in previous entries */
        while ((p_tle)&&(p_tle != p_target_tle))
        {
            rem_ticks += p_tle->ticks;
            p_tle = p_tle->p_next;
        }

        /* if found target entry */
        if (p_tle == p_target_tle)
        {
            rem_ticks += p_tle->ticks;
        }
        else
        {
            return(0);
        }
    }

    return (rem_ticks);
}

/*******************************************************************************
**
** Function         gki_adjust_timer_count
**
** Description      This function is called whenever a new timer or GKI_wait occurs
**                  to adjust (if necessary) the current time til the first expiration.
**                  This only needs to make an adjustment if the new timer (in ticks) is
**                  less than the number of ticks remaining on the current timer.
**
** Parameters:      ticks - (input) number of system ticks of the new timer entry
**
**                  NOTE:  This routine MUST be called while interrupts are disabled to
**                          avoid updates while adjusting the timer variables.
**
** Returns          void
**
*******************************************************************************/
void gki_adjust_timer_count (INT32 ticks)
{
    if (ticks > 0)
    {
        /* See if the new timer expires before the current first expiration */
        if (gki_cb.com.OSNumOrigTicks == 0 || (ticks < gki_cb.com.OSTicksTilExp && gki_cb.com.OSTicksTilExp > 0))
        {
            gki_cb.com.OSNumOrigTicks = (gki_cb.com.OSNumOrigTicks - gki_cb.com.OSTicksTilExp) + ticks;
            gki_cb.com.OSTicksTilExp = ticks;
            alarm_service_reschedule();
        }
    }

    return;
}
