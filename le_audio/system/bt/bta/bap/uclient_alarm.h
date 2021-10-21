/******************************************************************************
 *  Copyright (c) 2020, The Linux Foundation. All rights reserved.
 *
 *****************************************************************************/

#pragma once

#include <stdbool.h>
#include <stdint.h>
#include "osi/include/alarm.h"
#include <raw_address.h>

namespace bluetooth {
namespace bap {
namespace alarm {

class BapAlarmCallbacks {
  public:
    virtual ~BapAlarmCallbacks() = default;

    /** Callback for timer timeout */
    virtual void OnTimeout(void* data) = 0;
};

class BapAlarm {
  public:
    virtual ~BapAlarm() = default;

    static void Initialize(BapAlarmCallbacks* callbacks);
    static void CleanUp();
    static BapAlarm* Get();

    virtual alarm_t* Create(const char* name) = 0;

    virtual void Delete(alarm_t* alarm) = 0;

    virtual void Start(alarm_t* alarm, period_ms_t interval_ms,
                              void* data) = 0;

    virtual void Stop(alarm_t* alarm) = 0;

    virtual bool IsScheduled(const alarm_t* alarm) = 0;

    virtual void Timeout(void* data) = 0;
};

} //alarm
} //bap
} //bluetooth
