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

#include <string>
#include <vector>

#include "stack/include/bt_types.h"
#include <hardware/bt_bap_uclient.h>

namespace bluetooth {
namespace bap {
namespace cis {

using bluetooth::bap::ucast::CISConfig;
using bluetooth::bap::ucast::CIGConfig;

constexpr uint8_t  DIR_TO_AIR    = 0x1 << 0;
constexpr uint8_t  DIR_FROM_AIR  = 0x1 << 1;

typedef uint8_t sdu_interval_t[3];

enum class CisState {
  INVALID = 0,
  READY,
  DESTROYING,
  ESTABLISHING,
  ESTABLISHED
};

enum class CigState {
  INVALID = 0,
  IDLE,
  CREATING,
  CREATED,
  REMOVING
};

enum IsoHciStatus {
  ISO_HCI_SUCCESS = 0,
  ISO_HCI_FAILED,
  ISO_HCI_IN_PROGRESS
};

class CisInterfaceCallbacks {
 public:
  virtual ~CisInterfaceCallbacks() = default;

  /** Callback for connection state change */
  virtual void OnCigState(uint8_t cig_id, CigState state) = 0;

  virtual void OnCisState(uint8_t cig_id, uint8_t cis_id,
                          uint8_t direction, CisState state) = 0;
};

class CisInterface {
 public:
  virtual ~CisInterface() = default;

  static void Initialize(CisInterfaceCallbacks* callbacks);
  static void CleanUp();
  static CisInterface* Get();

  virtual CigState GetCigState(const uint8_t &cig_id);

  virtual CisState GetCisState(const uint8_t &cig_id, uint8_t cis_id);

  virtual uint8_t GetCisCount(const uint8_t &cig_id) = 0;

  virtual IsoHciStatus CreateCig(RawAddress client_peer_bda,
                         bool reconfig,
                         CIGConfig &cig_config,
                         std::vector<CISConfig> &cis_configs) = 0;

  virtual IsoHciStatus RemoveCig(RawAddress peer_bda,
                                 uint8_t cig_id) = 0;

  virtual IsoHciStatus CreateCis(uint8_t cig_id, std::vector<uint8_t> cis_ids,
                                 RawAddress peer_bda) = 0;

  virtual IsoHciStatus DisconnectCis(uint8_t cig_id, uint8_t cis_id,
                                     uint8_t direction) = 0;

  virtual IsoHciStatus SetupDataPath(uint8_t cig_id, uint8_t cis_id,
                                     uint8_t direction,
                                     uint8_t path_id) = 0;

  virtual IsoHciStatus RemoveDataPath(uint8_t cig_id, uint8_t cis_id,
                              uint8_t direction) = 0;
};

}  // namespace ucast
}  // namespace bap
}  // namespace bluetooth
