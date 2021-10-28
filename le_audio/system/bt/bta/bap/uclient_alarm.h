/******************************************************************************
 *
 *  Copyright 2021 The Android Open Source Project
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
