/******************************************************************************
 *
 *  Copyright (C) 2016 Google, Inc.
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


#define LOG_TAG "bt_osi_metrics"

extern "C" {
#include "osi/include/metrics.h"

#include <errno.h>

#include "osi/include/log.h"
#include "osi/include/osi.h"
}

#include "osi/src/protos/bluetooth.pb.h"

#include <google/protobuf/text_format.h>

using clearcut::connectivity::BluetoothLog;
using clearcut::connectivity::DeviceInfo;
using clearcut::connectivity::DeviceInfo_DeviceType;
using clearcut::connectivity::PairEvent;
using clearcut::connectivity::ScanEvent;
using clearcut::connectivity::ScanEvent_ScanTechnologyType;
using clearcut::connectivity::ScanEvent_ScanEventType;
using clearcut::connectivity::WakeEvent;
using clearcut::connectivity::WakeEvent_WakeEventType;

BluetoothLog *pending;

static void lazy_initialize(void) {
  if (pending == nullptr) {
    pending = BluetoothLog::default_instance().New();
  }
}

void metrics_pair_event(uint32_t disconnect_reason, uint64_t timestamp_ms,
                        uint32_t device_class, device_type_t device_type) {
  lazy_initialize();

  PairEvent *event = pending->add_pair_event();

  DeviceInfo *info = event->mutable_device_paired_with();

  info->set_device_class(device_class);

  DeviceInfo_DeviceType type = DeviceInfo::DEVICE_TYPE_UNKNOWN;

  if (device_type == DEVICE_TYPE_BREDR)
    type = DeviceInfo::DEVICE_TYPE_BREDR;
  if (device_type == DEVICE_TYPE_LE)
    type = DeviceInfo::DEVICE_TYPE_LE;
  if (device_type == DEVICE_TYPE_DUMO)
    type = DeviceInfo::DEVICE_TYPE_DUMO;

  info->set_device_type(type);

  event->set_disconnect_reason(disconnect_reason);

  event->set_event_time_millis(timestamp_ms);

}

void metrics_wake_event(wake_event_type_t type, const char *requestor,
                        const char *name, uint64_t timestamp) {
  lazy_initialize();

  WakeEvent *event = pending->add_wake_event();

  WakeEvent_WakeEventType waketype = WakeEvent::UNKNOWN;

  if (type == WAKE_EVENT_ACQUIRED)
    waketype = WakeEvent::ACQUIRED;
  if (type == WAKE_EVENT_RELEASED)
    waketype = WakeEvent::RELEASED;

  event->set_wake_event_type(waketype);

  if (requestor)
    event->set_requestor(requestor);

  if (name)
    event->set_name(name);

  event->set_event_time_millis(timestamp);
}


void metrics_scan_event(bool start, const char *initator, scan_tech_t type,
                        uint32_t results, uint64_t timestamp_ms) {
  lazy_initialize();

  ScanEvent *event = pending->add_scan_event();

  if (start)
    event->set_scan_event_type(ScanEvent::SCAN_EVENT_START);
  else
    event->set_scan_event_type(ScanEvent::SCAN_EVENT_STOP);

  if (initator)
    event->set_initiator(initator);

  ScanEvent_ScanTechnologyType scantype = ScanEvent::SCAN_TYPE_UNKNOWN;

  if (type == SCAN_TECH_TYPE_LE)
    scantype = ScanEvent::SCAN_TECH_TYPE_LE;
  if (type == SCAN_TECH_TYPE_BREDR)
    scantype = ScanEvent::SCAN_TECH_TYPE_BREDR;
  if (type == SCAN_TECH_TYPE_BOTH)
    scantype = ScanEvent::SCAN_TECH_TYPE_BOTH;

  event->set_scan_technology_type(scantype);

  event->set_number_results(results);

  event->set_event_time_millis(timestamp_ms);
}

void metrics_write(int fd, bool clear) {
  LOG_DEBUG(LOG_TAG, "%s serializing metrics", __func__);
  lazy_initialize();

  std::string serialized;
  if (!pending->SerializeToString(&serialized)) {
    LOG_ERROR(LOG_TAG, "%s: error serializing metrics", __func__);
    return;
  }

  if (write(fd, serialized.c_str(), serialized.size()) == -1) {
    LOG_ERROR(LOG_TAG, "%s: error writing to dumpsys fd: %s (%d)", __func__,
              strerror(errno), errno);
  }

  if (clear) {
    pending->Clear();
  }
}

void metrics_print(int fd, bool clear) {
  LOG_DEBUG(LOG_TAG, "%s printing metrics", __func__);
  lazy_initialize();

  std::string pretty_output;
  google::protobuf::TextFormat::PrintToString(*pending, &pretty_output);

  if (write(fd, pretty_output.c_str(), pretty_output.size()) == -1) {
    LOG_ERROR(LOG_TAG, "%s: error writing to dumpsys fd: %s (%d)", __func__,
              strerror(errno), errno);
  }

  if (clear) {
    pending->Clear();
  }
}
