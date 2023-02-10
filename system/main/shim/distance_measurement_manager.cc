/*
 * Copyright 2022 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "distance_measurement_manager.h"

#include "btif/include/btif_common.h"
#include "gd/os/log.h"
#include "main/shim/entry.h"
#include "main/shim/helpers.h"

class DistanceMeasurementInterfaceImpl : public DistanceMeasurementInterface {
 public:
  ~DistanceMeasurementInterfaceImpl() override{};

  void Init() {
    // Register callback
    // TODO(b/256055210): Implement DistanceMeasurementManager in GD
    // bluetooth::shim::GetDistanceMeasurementManager()
    //     ->RegisterDistanceMeasurementCallbacks(this);
  }

  void RegisterDistanceMeasurementCallbacks(
      ::DistanceMeasurementCallbacks* callbacks) {
    distance_measurement_callbacks_ = callbacks;
  }

  void StartDistanceMeasurement(RawAddress raw_address, uint16_t frequency,
                                uint8_t method) {
    // TODO(b/256055210): Implement DistanceMeasurementManager in GD
    // bluetooth::shim::GetDistanceMeasurementManager()->StartDistanceMeasurement(
    //     bluetooth::ToGdAddress(raw_address), frequency,
    //     static_cast<DistanceMeasurementMethod>(method));
  }

  void StopDistanceMeasurement(RawAddress raw_address, uint8_t method) {
    // TODO(b/256055210): Implement DistanceMeasurementManager in GD
    // bluetooth::shim::GetDistanceMeasurementManager()->StopDistanceMeasurement(
    //     bluetooth::ToGdAddress(raw_address),
    //     static_cast<DistanceMeasurementMethod>(method));
  }

 private:
  ::DistanceMeasurementCallbacks* distance_measurement_callbacks_;
};

DistanceMeasurementInterfaceImpl* distance_measurement_instance = nullptr;

void bluetooth::shim::init_distance_measurement_manager() {
  static_cast<DistanceMeasurementInterfaceImpl*>(
      bluetooth::shim::get_distance_measurement_instance())
      ->Init();
}

DistanceMeasurementInterface*
bluetooth::shim::get_distance_measurement_instance() {
  if (distance_measurement_instance == nullptr) {
    distance_measurement_instance = new DistanceMeasurementInterfaceImpl();
  }
  return distance_measurement_instance;
};
