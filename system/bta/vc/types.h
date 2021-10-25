/*
 * Copyright 2020 HIMSA II K/S - www.himsa.com.
 * Represented by EHIMA - www.ehima.com
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

#pragma once

#include <queue>
#include <vector>

#include "bta/include/bta_groups.h"
#include "osi/include/alarm.h"
#include "raw_address.h"
#include "types/bluetooth/uuid.h"

namespace bluetooth {
namespace vc {
namespace internal {

/* clang-format off */
/* Volume control point opcodes */
static constexpr uint8_t kControlPointOpcodeVolumeDown         = 0x00;
static constexpr uint8_t kControlPointOpcodeVolumeUp           = 0x01;
static constexpr uint8_t kControlPointOpcodeUnmuteVolumeDown   = 0x02;
static constexpr uint8_t kControlPointOpcodeUnmuteVolumeUp     = 0x03;
static constexpr uint8_t kControlPointOpcodeSetAbsoluteVolume  = 0x04;
static constexpr uint8_t kControlPointOpcodeUnmute             = 0x05;
static constexpr uint8_t kControlPointOpcodeMute               = 0x06;

static const Uuid kVolumeControlUuid                  = Uuid::From16Bit(0x1844);
static const Uuid kVolumeControlStateUuid             = Uuid::From16Bit(0x2B7D);
static const Uuid kVolumeControlPointUuid             = Uuid::From16Bit(0x2B7E);
static const Uuid kVolumeFlagsUuid                    = Uuid::From16Bit(0x2B7F);
/* clang-format on */

struct VolumeOperation {
  int operation_id_;
  int group_id_;

  bool started_;

  uint8_t opcode_;
  std::vector<uint8_t> arguments_;

  std::vector<RawAddress> devices_;
  alarm_t* operation_timeout_;

  VolumeOperation(int operation_id, int group_id, uint8_t opcode,
                  std::vector<uint8_t> arguments,
                  std::vector<RawAddress> devices)
      : operation_id_(operation_id),
        group_id_(group_id),
        opcode_(opcode),
        arguments_(arguments),
        devices_(devices) {
    auto name = "operation_timeout_" + std::to_string(operation_id);
    operation_timeout_ = alarm_new(name.c_str());
    started_ = false;
  };

  ~VolumeOperation() {
    if (alarm_is_scheduled(operation_timeout_))
      alarm_cancel(operation_timeout_);

    alarm_free(operation_timeout_);
    operation_timeout_ = nullptr;
  }

  bool IsGroupOperation(void) {
    return (group_id_ != bluetooth::groups::kGroupUnknown);
  }

  bool IsStarted(void) { return started_; };
  void Start(void) { started_ = true; }
};

}  // namespace internal
}  // namespace vc
}  // namespace bluetooth
