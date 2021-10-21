/******************************************************************************
 *  Copyright (c) 2020, The Linux Foundation. All rights reserved.
 *
 *****************************************************************************/

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
