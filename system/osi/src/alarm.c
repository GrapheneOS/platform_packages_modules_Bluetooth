/******************************************************************************
 *
 *  Copyright (C) 2014 Google, Inc.
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

#define LOG_TAG "bt_osi_alarm"

#include "osi/include/alarm.h"

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <malloc.h>
#include <pthread.h>
#include <signal.h>
#include <string.h>
#include <time.h>

#include <hardware/bluetooth.h>

#include "osi/include/allocator.h"
#include "osi/include/list.h"
#include "osi/include/log.h"
#include "osi/include/osi.h"
#include "osi/include/semaphore.h"
#include "osi/include/thread.h"

// Make callbacks run at high thread priority. Some callbacks are used for audio
// related timer tasks as well as re-transmissions etc. Since we at this point
// cannot differentiate what callback we are dealing with, assume high priority
// for now.
// TODO(eisenbach): Determine correct thread priority (from parent?/per alarm?)
static const int CALLBACK_THREAD_PRIORITY_HIGH = -19;

struct alarm_t {
  // The lock is held while the callback for this alarm is being executed.
  // It allows us to release the coarse-grained monitor lock while a potentially
  // long-running callback is executing. |alarm_cancel| uses this lock to provide
  // a guarantee to its caller that the callback will not be in progress when it
  // returns.
  pthread_mutex_t callback_lock;
  period_ms_t creation_time;
  period_ms_t period;
  period_ms_t deadline;
  bool is_periodic;
  alarm_callback_t callback;
  void *data;
};


// If the next wakeup time is less than this threshold, we should acquire
// a wakelock instead of setting a wake alarm so we're not bouncing in
// and out of suspend frequently. This value is externally visible to allow
// unit tests to run faster. It should not be modified by production code.
int64_t TIMER_INTERVAL_FOR_WAKELOCK_IN_MS = 3000;
static const clockid_t CLOCK_ID = CLOCK_BOOTTIME;
static const clockid_t CLOCK_ID_ALARM = CLOCK_BOOTTIME_ALARM;
static const char *WAKE_LOCK_ID = "bluetooth_timer";
static const char *WAKE_LOCK_PATH = "/sys/power/wake_lock";
static const char *WAKE_UNLOCK_PATH = "/sys/power/wake_unlock";
static ssize_t locked_id_len = -1;
static pthread_once_t wake_fds_initialized = PTHREAD_ONCE_INIT;
static int wake_lock_fd = INVALID_FD;
static int wake_unlock_fd = INVALID_FD;

// This mutex ensures that the |alarm_set|, |alarm_cancel|, and alarm callback
// functions execute serially and not concurrently. As a result, this mutex also
// protects the |alarms| list.
static pthread_mutex_t monitor;
static list_t *alarms;
static timer_t timer;
static timer_t wakeup_timer;
static bool timer_set;

// All alarm callbacks are dispatched from |callback_thread|
static thread_t *callback_thread;
static bool callback_thread_active;
static semaphore_t *alarm_expired;

static bool lazy_initialize(void);
static period_ms_t now(void);
static void alarm_set_internal(alarm_t *alarm, period_ms_t deadline, alarm_callback_t cb, void *data, bool is_periodic);
static void schedule_next_instance(alarm_t *alarm, bool force_reschedule);
static void reschedule_root_alarm(void);
static void timer_callback(void *data);
static void callback_dispatch(void *context);
static bool timer_create_internal(const clockid_t clock_id, timer_t *timer);
static void initialize_wake_fds(void);
static bool acquire_wake_lock(void);
static bool release_wake_lock(void);

alarm_t *alarm_new(void) {
  // Make sure we have a list we can insert alarms into.
  if (!alarms && !lazy_initialize()) {
    assert(false); // if initialization failed, we should not continue
    return NULL;
  }

  pthread_mutexattr_t attr;
  pthread_mutexattr_init(&attr);

  alarm_t *ret = osi_calloc(sizeof(alarm_t));
  if (!ret) {
    LOG_ERROR(LOG_TAG, "%s unable to allocate memory for alarm.", __func__);
    goto error;
  }

  // Make this a recursive mutex to make it safe to call |alarm_cancel| from
  // within the callback function of the alarm.
  int error = pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE);
  if (error) {
    LOG_ERROR(LOG_TAG, "%s unable to create a recursive mutex: %s", __func__, strerror(error));
    goto error;
  }

  error = pthread_mutex_init(&ret->callback_lock, &attr);
  if (error) {
    LOG_ERROR(LOG_TAG, "%s unable to initialize mutex: %s", __func__, strerror(error));
    goto error;
  }

  pthread_mutexattr_destroy(&attr);
  return ret;

error:;
  pthread_mutexattr_destroy(&attr);
  osi_free(ret);
  return NULL;
}

void alarm_free(alarm_t *alarm) {
  if (!alarm)
    return;

  alarm_cancel(alarm);
  pthread_mutex_destroy(&alarm->callback_lock);
  osi_free(alarm);
}

period_ms_t alarm_get_remaining_ms(const alarm_t *alarm) {
  assert(alarm != NULL);
  period_ms_t remaining_ms = 0;

  pthread_mutex_lock(&monitor);
  if (alarm->deadline)
    remaining_ms = alarm->deadline - now();
  pthread_mutex_unlock(&monitor);

  return remaining_ms;
}

void alarm_set(alarm_t *alarm, period_ms_t deadline, alarm_callback_t cb, void *data) {
  alarm_set_internal(alarm, deadline, cb, data, false);
}

void alarm_set_periodic(alarm_t *alarm, period_ms_t period, alarm_callback_t cb, void *data) {
  alarm_set_internal(alarm, period, cb, data, true);
}

// Runs in exclusion with alarm_cancel and timer_callback.
static void alarm_set_internal(alarm_t *alarm, period_ms_t period, alarm_callback_t cb, void *data, bool is_periodic) {
  assert(alarms != NULL);
  assert(alarm != NULL);
  assert(cb != NULL);

  pthread_mutex_lock(&monitor);

  alarm->creation_time = now();
  alarm->is_periodic = is_periodic;
  alarm->period = period;
  alarm->callback = cb;
  alarm->data = data;

  schedule_next_instance(alarm, false);

  pthread_mutex_unlock(&monitor);
}

void alarm_cancel(alarm_t *alarm) {
  assert(alarms != NULL);
  assert(alarm != NULL);

  pthread_mutex_lock(&monitor);

  bool needs_reschedule = (!list_is_empty(alarms) && list_front(alarms) == alarm);

  list_remove(alarms, alarm);
  alarm->deadline = 0;
  alarm->callback = NULL;
  alarm->data = NULL;

  if (needs_reschedule)
    reschedule_root_alarm();

  pthread_mutex_unlock(&monitor);

  // If the callback for |alarm| is in progress, wait here until it completes.
  pthread_mutex_lock(&alarm->callback_lock);
  pthread_mutex_unlock(&alarm->callback_lock);
}

void alarm_cleanup(void) {
  // If lazy_initialize never ran there is nothing to do
  if (!alarms)
    return;

  callback_thread_active = false;
  semaphore_post(alarm_expired);
  thread_free(callback_thread);
  callback_thread = NULL;

  semaphore_free(alarm_expired);
  alarm_expired = NULL;
  timer_delete(&timer);
  list_free(alarms);
  alarms = NULL;

  pthread_mutex_destroy(&monitor);
}

static bool lazy_initialize(void) {
  assert(alarms == NULL);

  // timer_t doesn't have an invalid value so we must track whether
  // the |timer| variable is valid ourselves.
  bool timer_initialized = false;
  bool wakeup_timer_initialized = false;

  pthread_mutex_init(&monitor, NULL);

  alarms = list_new(NULL);
  if (!alarms) {
    LOG_ERROR(LOG_TAG, "%s unable to allocate alarm list.", __func__);
    goto error;
  }

  if (!timer_create_internal(CLOCK_ID, &timer))
    goto error;
  timer_initialized = true;

  if (!timer_create_internal(CLOCK_ID_ALARM, &wakeup_timer))
    goto error;
  wakeup_timer_initialized = true;

  alarm_expired = semaphore_new(0);
  if (!alarm_expired) {
    LOG_ERROR(LOG_TAG, "%s unable to create alarm expired semaphore", __func__);
    goto error;
  }

  callback_thread_active = true;
  callback_thread = thread_new("alarm_callbacks");
  if (!callback_thread) {
    LOG_ERROR(LOG_TAG, "%s unable to create alarm callback thread.", __func__);
    goto error;
  }

  thread_set_priority(callback_thread, CALLBACK_THREAD_PRIORITY_HIGH);
  thread_post(callback_thread, callback_dispatch, NULL);
  return true;

error:
  thread_free(callback_thread);
  callback_thread = NULL;

  callback_thread_active = false;

  semaphore_free(alarm_expired);
  alarm_expired = NULL;

  if (wakeup_timer_initialized)
    timer_delete(wakeup_timer);

  if (timer_initialized)
    timer_delete(timer);

  list_free(alarms);
  alarms = NULL;

  pthread_mutex_destroy(&monitor);

  return false;
}

static period_ms_t now(void) {
  assert(alarms != NULL);

  struct timespec ts;
  if (clock_gettime(CLOCK_ID, &ts) == -1) {
    LOG_ERROR(LOG_TAG, "%s unable to get current time: %s", __func__, strerror(errno));
    return 0;
  }

  return (ts.tv_sec * 1000LL) + (ts.tv_nsec / 1000000LL);
}

// Must be called with monitor held
static void schedule_next_instance(alarm_t *alarm, bool force_reschedule) {
  // If the alarm is currently set and it's at the start of the list,
  // we'll need to re-schedule since we've adjusted the earliest deadline.
  bool needs_reschedule = (!list_is_empty(alarms) && list_front(alarms) == alarm);
  if (alarm->callback)
    list_remove(alarms, alarm);

  // Calculate the next deadline for this alarm
  period_ms_t just_now = now();
  period_ms_t ms_into_period = alarm->is_periodic ? ((just_now - alarm->creation_time) % alarm->period) : 0;
  alarm->deadline = just_now + (alarm->period - ms_into_period);

  // Add it into the timer list sorted by deadline (earliest deadline first).
  if (list_is_empty(alarms) || ((alarm_t *)list_front(alarms))->deadline >= alarm->deadline)
    list_prepend(alarms, alarm);
  else
    for (list_node_t *node = list_begin(alarms); node != list_end(alarms); node = list_next(node)) {
      list_node_t *next = list_next(node);
      if (next == list_end(alarms) || ((alarm_t *)list_node(next))->deadline >= alarm->deadline) {
        list_insert_after(alarms, node, alarm);
        break;
      }
    }

  // If the new alarm has the earliest deadline, we need to re-evaluate our schedule.
  if (force_reschedule || needs_reschedule || (!list_is_empty(alarms) && list_front(alarms) == alarm))
    reschedule_root_alarm();
}

// NOTE: must be called with monitor lock.
static void reschedule_root_alarm(void) {
  assert(alarms != NULL);

  const bool timer_was_set = timer_set;

  // If used in a zeroed state, disarms the timer.
  struct itimerspec timer_time;
  memset(&timer_time, 0, sizeof(timer_time));

  if (list_is_empty(alarms))
    goto done;

  const alarm_t *next = list_front(alarms);
  const int64_t next_expiration = next->deadline - now();
  if (next_expiration < TIMER_INTERVAL_FOR_WAKELOCK_IN_MS) {
    if (!timer_set) {
      if (!acquire_wake_lock()) {
        LOG_ERROR(LOG_TAG, "%s unable to acquire wake lock", __func__);
        goto done;
      }
    }

    timer_time.it_value.tv_sec = (next->deadline / 1000);
    timer_time.it_value.tv_nsec = (next->deadline % 1000) * 1000000LL;

    // It is entirely unsafe to call timer_settime(2) with a zeroed timerspec for
    // timers with *_ALARM clock IDs. Although the man page states that the timer
    // would be canceled, the current behavior (as of Linux kernel 3.17) is that
    // the callback is issued immediately. The only way to cancel an *_ALARM timer
    // is to delete the timer. But unfortunately, deleting and re-creating a timer
    // is rather expensive; every timer_create(2) spawns a new thread. So we simply
    // set the timer to fire at the largest possible time.
    //
    // If we've reached this code path, we're going to grab a wake lock and wait for
    // the next timer to fire. In that case, there's no reason to have a pending wakeup
    // timer so we simply cancel it.
    struct itimerspec end_of_time;
    memset(&end_of_time, 0, sizeof(end_of_time));
    end_of_time.it_value.tv_sec = (time_t)(1LL << (sizeof(time_t) * 8 - 2));
    timer_settime(wakeup_timer, TIMER_ABSTIME, &end_of_time, NULL);
  } else {
    // WARNING: do not attempt to use relative timers with *_ALARM clock IDs
    // in kernels before 3.17 unless you have the following patch:
    // https://lkml.org/lkml/2014/7/7/576
    struct itimerspec wakeup_time;
    memset(&wakeup_time, 0, sizeof(wakeup_time));


    wakeup_time.it_value.tv_sec = (next->deadline / 1000);
    wakeup_time.it_value.tv_nsec = (next->deadline % 1000) * 1000000LL;
    if (timer_settime(wakeup_timer, TIMER_ABSTIME, &wakeup_time, NULL) == -1)
      LOG_ERROR(LOG_TAG, "%s unable to set wakeup timer: %s",
                __func__, strerror(errno));
  }

done:
  timer_set = timer_time.it_value.tv_sec != 0 || timer_time.it_value.tv_nsec != 0;
  if (timer_was_set && !timer_set) {
    release_wake_lock();
  }

  if (timer_settime(timer, TIMER_ABSTIME, &timer_time, NULL) == -1)
    LOG_ERROR(LOG_TAG, "%s unable to set timer: %s", __func__, strerror(errno));

  // If next expiration was in the past (e.g. short timer that got context switched)
  // then the timer might have diarmed itself. Detect this case and work around it
  // by manually signalling the |alarm_expired| semaphore.
  //
  // It is possible that the timer was actually super short (a few milliseconds)
  // and the timer expired normally before we called |timer_gettime|. Worst case,
  // |alarm_expired| is signaled twice for that alarm. Nothing bad should happen in
  // that case though since the callback dispatch function checks to make sure the
  // timer at the head of the list actually expired.
  if (timer_set) {
    struct itimerspec time_to_expire;
    timer_gettime(timer, &time_to_expire);
    if (time_to_expire.it_value.tv_sec == 0 && time_to_expire.it_value.tv_nsec == 0) {
      LOG_ERROR(LOG_TAG, "%s alarm expiration too close for posix timers, switching to guns", __func__);
      semaphore_post(alarm_expired);
    }
  }
}

// Callback function for wake alarms and our posix timer
static void timer_callback(UNUSED_ATTR void *ptr) {
  semaphore_post(alarm_expired);
}

// Function running on |callback_thread| that dispatches alarm callbacks upon
// alarm expiration, which is signaled using |alarm_expired|.
static void callback_dispatch(UNUSED_ATTR void *context) {
  while (true) {
    semaphore_wait(alarm_expired);
    if (!callback_thread_active)
      break;

    pthread_mutex_lock(&monitor);
    alarm_t *alarm;

    // Take into account that the alarm may get cancelled before we get to it.
    // We're done here if there are no alarms or the alarm at the front is in
    // the future. Release the monitor lock and exit right away since there's
    // nothing left to do.
    if (list_is_empty(alarms) || (alarm = list_front(alarms))->deadline > now()) {
      reschedule_root_alarm();
      pthread_mutex_unlock(&monitor);
      continue;
    }

    list_remove(alarms, alarm);

    alarm_callback_t callback = alarm->callback;
    void *data = alarm->data;

    if (alarm->is_periodic) {
      schedule_next_instance(alarm, true);
    } else {
      reschedule_root_alarm();

      alarm->deadline = 0;
      alarm->callback = NULL;
      alarm->data = NULL;
    }

    // Downgrade lock.
    pthread_mutex_lock(&alarm->callback_lock);
    pthread_mutex_unlock(&monitor);

    callback(data);

    pthread_mutex_unlock(&alarm->callback_lock);
  }

  LOG_DEBUG(LOG_TAG, "%s Callback thread exited", __func__);
}

static void initialize_wake_fds(void) {
  LOG_DEBUG(LOG_TAG, "%s opening wake locks", __func__);

  wake_lock_fd = open(WAKE_LOCK_PATH, O_RDWR | O_CLOEXEC);
  if (wake_lock_fd == INVALID_FD) {
    LOG_ERROR(LOG_TAG, "%s can't open wake lock %s: %s",
              __func__, WAKE_LOCK_PATH, strerror(errno));
  }

  wake_unlock_fd = open(WAKE_UNLOCK_PATH, O_RDWR | O_CLOEXEC);
  if (wake_unlock_fd == INVALID_FD) {
    LOG_ERROR(LOG_TAG, "%s can't open wake unlock %s: %s",
              __func__, WAKE_UNLOCK_PATH, strerror(errno));
  }
}

static bool acquire_wake_lock(void) {
  pthread_once(&wake_fds_initialized, initialize_wake_fds);

  if (wake_lock_fd == INVALID_FD) {
    LOG_ERROR(LOG_TAG, "%s lock not acquired, invalid fd", __func__);
    return false;
  }

  if (wake_unlock_fd == INVALID_FD) {
    LOG_ERROR(LOG_TAG, "%s not acquiring lock: can't release lock", __func__);
    return false;
  }

  long lock_name_len = strlen(WAKE_LOCK_ID);
  locked_id_len = write(wake_lock_fd, WAKE_LOCK_ID, lock_name_len);
  if (locked_id_len == -1) {
    LOG_ERROR(LOG_TAG, "%s wake lock not acquired: %s",
              __func__, strerror(errno));
    return false;
  } else if (locked_id_len < lock_name_len) {
    // TODO (jamuraa): this is weird. maybe we should release and retry.
    LOG_WARN(LOG_TAG, "%s wake lock truncated to %zd chars",
             __func__, locked_id_len);
  }
  return true;
}

static bool release_wake_lock(void) {
  pthread_once(&wake_fds_initialized, initialize_wake_fds);

  if (wake_unlock_fd == INVALID_FD) {
    LOG_ERROR(LOG_TAG, "%s lock not released, invalid fd", __func__);
    return false;
  }

  ssize_t wrote_name_len = write(wake_unlock_fd, WAKE_LOCK_ID, locked_id_len);
  if (wrote_name_len == -1) {
    LOG_ERROR(LOG_TAG, "%s can't release wake lock: %s",
              __func__, strerror(errno));
  } else if (wrote_name_len < locked_id_len) {
    LOG_ERROR(LOG_TAG, "%s lock release only wrote %zd, assuming released",
              __func__, wrote_name_len);
  }
  return true;
}

static bool timer_create_internal(const clockid_t clock_id, timer_t *timer) {
  assert(timer != NULL);

  struct sigevent sigevent;
  memset(&sigevent, 0, sizeof(sigevent));
  sigevent.sigev_notify = SIGEV_THREAD;
  sigevent.sigev_notify_function = (void (*)(union sigval))timer_callback;
  if (timer_create(clock_id, &sigevent, timer) == -1) {
    LOG_ERROR(LOG_TAG, "%s unable to create timer with clock %d: %s",
              __func__, clock_id, strerror(errno));
    return false;
  }

  return true;
}
