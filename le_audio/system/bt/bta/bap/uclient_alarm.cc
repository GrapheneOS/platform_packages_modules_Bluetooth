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


#include "uclient_alarm.h"
#include "bt_trace.h"
#define LOG_TAG "uclient_alarm"

namespace bluetooth {
namespace bap {
namespace alarm {

class BapAlarmImpl;
BapAlarmImpl *instance;

static void alarm_handler(void* data);

class BapAlarmImpl : public BapAlarm {
  public:
    BapAlarmImpl(BapAlarmCallbacks* callback):
       callbacks(callback)  { }

    ~BapAlarmImpl() override = default;

    void CleanUp () { }

    alarm_t* Create(const char* name) {
      return alarm_new(name);
    }

    void Delete(alarm_t* alarm) {
      alarm_free(alarm);
    }

    void Start(alarm_t* alarm, period_ms_t interval_ms,
                              void* data) {
      alarm_set_on_mloop(alarm, interval_ms, alarm_handler, data);
    }

    void Stop(alarm_t* alarm) {
      alarm_cancel(alarm);
    }

    bool IsScheduled(const alarm_t* alarm) {
      return alarm_is_scheduled(alarm);
    }

    void Timeout(void* data) {
      if (callbacks)
        callbacks->OnTimeout(data); // Call uclient_main
    }

  private:
    BapAlarmCallbacks *callbacks;
};

void BapAlarm::Initialize(
                   BapAlarmCallbacks* callbacks) {
  if (instance) {
    LOG(ERROR) << "Already initialized!";
  } else {
    instance = new BapAlarmImpl(callbacks);
  }
}

void BapAlarm::CleanUp() {
  BapAlarmImpl* ptr = instance;
  instance = nullptr;
  ptr->CleanUp();
  delete ptr;
}

BapAlarm* BapAlarm::Get() {
  return instance;
}

static void alarm_handler(void* data) {
  if (instance)
    instance->Timeout(data);
}

} //alarm
} //bap
} //bluetooth
