/*
 * Copyright 2020 HIMSA II K/S - www.himsa.com. Represented by EHIMA
 * - www.ehima.com
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

#include "devices.h"

#include <base/strings/string_number_conversions.h>

#include <map>

#include "bta_gatt_queue.h"
#include "bta_groups.h"
#include "bta_le_audio_api.h"
#include "btm_iso_api.h"
#include "btm_iso_api_types.h"
#include "client_audio.h"
#include "device/include/controller.h"
#include "gd/common/strings.h"
#include "le_audio_set_configuration_provider.h"
#include "metrics_collector.h"
#include "osi/include/log.h"
#include "stack/include/acl_api.h"

using bluetooth::hci::kIsoCigFramingFramed;
using bluetooth::hci::kIsoCigFramingUnframed;
using bluetooth::hci::kIsoCigPackingSequential;
using bluetooth::hci::kIsoCigPhy1M;
using bluetooth::hci::kIsoCigPhy2M;
using bluetooth::hci::iso_manager::kIsoSca0To20Ppm;
using le_audio::AudioSetConfigurationProvider;
using le_audio::set_configurations::CodecCapabilitySetting;
using le_audio::types::ase;
using le_audio::types::AseState;
using le_audio::types::AudioContexts;
using le_audio::types::AudioLocations;
using le_audio::types::AudioStreamDataPathState;
using le_audio::types::BidirectAsesPair;
using le_audio::types::CisType;
using le_audio::types::LeAudioCodecId;
using le_audio::types::LeAudioContextType;
using le_audio::types::LeAudioLc3Config;

namespace le_audio {
/* LeAudioDeviceGroup Class methods implementation */
void LeAudioDeviceGroup::AddNode(
    const std::shared_ptr<LeAudioDevice>& leAudioDevice) {
  leAudioDevice->group_id_ = group_id_;
  leAudioDevices_.push_back(std::weak_ptr<LeAudioDevice>(leAudioDevice));
  MetricsCollector::Get()->OnGroupSizeUpdate(group_id_, leAudioDevices_.size());
}

void LeAudioDeviceGroup::RemoveNode(
    const std::shared_ptr<LeAudioDevice>& leAudioDevice) {
  /* Group information cleaning in the device. */
  leAudioDevice->group_id_ = bluetooth::groups::kGroupUnknown;
  for (auto ase : leAudioDevice->ases_) {
    ase.active = false;
    ase.cis_conn_hdl = 0;
  }

  leAudioDevices_.erase(
      std::remove_if(
          leAudioDevices_.begin(), leAudioDevices_.end(),
          [&leAudioDevice](auto& d) { return d.lock() == leAudioDevice; }),
      leAudioDevices_.end());
  MetricsCollector::Get()->OnGroupSizeUpdate(group_id_, leAudioDevices_.size());
}

bool LeAudioDeviceGroup::IsEmpty(void) { return leAudioDevices_.size() == 0; }

bool LeAudioDeviceGroup::IsAnyDeviceConnected(void) {
  return (NumOfConnected() != 0);
}

int LeAudioDeviceGroup::Size(void) { return leAudioDevices_.size(); }

int LeAudioDeviceGroup::NumOfConnected(types::LeAudioContextType context_type) {
  if (leAudioDevices_.empty()) return 0;

  bool check_context_type = (context_type != LeAudioContextType::RFU);
  AudioContexts type_set = static_cast<uint16_t>(context_type);

  /* return number of connected devices from the set*/
  return std::count_if(
      leAudioDevices_.begin(), leAudioDevices_.end(),
      [type_set, check_context_type](auto& iter) {
        if (iter.expired()) return false;
        if (iter.lock()->conn_id_ == GATT_INVALID_CONN_ID) return false;

        if (!check_context_type) return true;

        return (iter.lock()->GetAvailableContexts() & type_set).any();
      });
}

void LeAudioDeviceGroup::ClearSinksFromConfiguration(void) {
  LOG_INFO("Group %p, group_id %d", this, group_id_);
  stream_conf.sink_streams.clear();
  stream_conf.sink_offloader_streams_target_allocation.clear();
  stream_conf.sink_offloader_streams_current_allocation.clear();
  stream_conf.sink_audio_channel_allocation = 0;
  stream_conf.sink_num_of_channels = 0;
  stream_conf.sink_num_of_devices = 0;
  stream_conf.sink_sample_frequency_hz = 0;
  stream_conf.sink_codec_frames_blocks_per_sdu = 0;
  stream_conf.sink_octets_per_codec_frame = 0;
  stream_conf.sink_frame_duration_us = 0;
}

void LeAudioDeviceGroup::ClearSourcesFromConfiguration(void) {
  LOG_INFO("Group %p, group_id %d", this, group_id_);
  stream_conf.source_streams.clear();
  stream_conf.source_offloader_streams_target_allocation.clear();
  stream_conf.source_offloader_streams_current_allocation.clear();
  stream_conf.source_audio_channel_allocation = 0;
  stream_conf.source_num_of_channels = 0;
  stream_conf.source_num_of_devices = 0;
  stream_conf.source_sample_frequency_hz = 0;
  stream_conf.source_codec_frames_blocks_per_sdu = 0;
  stream_conf.source_octets_per_codec_frame = 0;
  stream_conf.source_frame_duration_us = 0;
}

void LeAudioDeviceGroup::CigClearCis(void) {
  LOG_INFO("group_id: %d", group_id_);
  cises_.clear();
  ClearSinksFromConfiguration();
  ClearSourcesFromConfiguration();
}

void LeAudioDeviceGroup::Cleanup(void) {
  /* Bluetooth is off while streaming - disconnect CISes and remove CIG */
  if (GetState() == AseState::BTA_LE_AUDIO_ASE_STATE_STREAMING) {
    if (!stream_conf.sink_streams.empty()) {
      for (auto [cis_handle, audio_location] : stream_conf.sink_streams) {
        bluetooth::hci::IsoManager::GetInstance()->DisconnectCis(
            cis_handle, HCI_ERR_PEER_USER);

        if (stream_conf.source_streams.empty()) {
          continue;
        }
        uint16_t cis_hdl = cis_handle;
        stream_conf.source_streams.erase(
            std::remove_if(
                stream_conf.source_streams.begin(),
                stream_conf.source_streams.end(),
                [cis_hdl](auto& pair) { return pair.first == cis_hdl; }),
            stream_conf.source_streams.end());
      }
    }

    if (!stream_conf.source_streams.empty()) {
      for (auto [cis_handle, audio_location] : stream_conf.source_streams) {
        bluetooth::hci::IsoManager::GetInstance()->DisconnectCis(
            cis_handle, HCI_ERR_PEER_USER);
      }
    }
  }

  /* Note: CIG will stay in the controller. We cannot remove it here, because
   * Cises are not yet disconnected.
   * When user start Bluetooth, HCI Reset should remove it
   */

  leAudioDevices_.clear();
  this->CigClearCis();
}

void LeAudioDeviceGroup::Deactivate(void) {
  for (auto* leAudioDevice = GetFirstActiveDevice(); leAudioDevice;
       leAudioDevice = GetNextActiveDevice(leAudioDevice)) {
    for (auto* ase = leAudioDevice->GetFirstActiveAse(); ase;
         ase = leAudioDevice->GetNextActiveAse(ase)) {
      ase->active = false;
    }
  }
}

le_audio::types::CigState LeAudioDeviceGroup::GetCigState(void) {
  return cig_state_;
}

void LeAudioDeviceGroup::SetCigState(le_audio::types::CigState state) {
  LOG_VERBOSE("%s -> %s", bluetooth::common::ToString(cig_state_).c_str(),
              bluetooth::common::ToString(state).c_str());
  cig_state_ = state;
}

bool LeAudioDeviceGroup::Activate(LeAudioContextType context_type) {
  bool is_activate = false;
  for (auto leAudioDevice : leAudioDevices_) {
    if (leAudioDevice.expired()) continue;

    bool activated = leAudioDevice.lock()->ActivateConfiguredAses(context_type);
    LOG_INFO("Device %s is %s",
             leAudioDevice.lock().get()->address_.ToString().c_str(),
             activated ? "activated" : " not activated");
    if (activated) {
      if (!CigAssignCisIds(leAudioDevice.lock().get())) {
        return false;
      }
      is_activate = true;
    }
  }
  return is_activate;
}

LeAudioDevice* LeAudioDeviceGroup::GetFirstDevice(void) {
  auto iter = std::find_if(leAudioDevices_.begin(), leAudioDevices_.end(),
                           [](auto& iter) { return !iter.expired(); });

  if (iter == leAudioDevices_.end()) return nullptr;

  return (iter->lock()).get();
}

LeAudioDevice* LeAudioDeviceGroup::GetFirstDeviceWithActiveContext(
    types::LeAudioContextType context_type) {
  AudioContexts type_set = static_cast<uint16_t>(context_type);

  auto iter = std::find_if(
      leAudioDevices_.begin(), leAudioDevices_.end(), [&type_set](auto& iter) {
        if (iter.expired()) return false;
        return (iter.lock()->GetAvailableContexts() & type_set).any();
      });

  if ((iter == leAudioDevices_.end()) || (iter->expired())) return nullptr;

  return (iter->lock()).get();
}

LeAudioDevice* LeAudioDeviceGroup::GetNextDevice(LeAudioDevice* leAudioDevice) {
  auto iter = std::find_if(leAudioDevices_.begin(), leAudioDevices_.end(),
                           [&leAudioDevice](auto& d) {
                             if (d.expired())
                               return false;
                             else
                               return (d.lock()).get() == leAudioDevice;
                           });

  /* If reference device not found */
  if (iter == leAudioDevices_.end()) return nullptr;

  std::advance(iter, 1);
  /* If reference device is last in group */
  if (iter == leAudioDevices_.end()) return nullptr;

  if (iter->expired()) return nullptr;

  return (iter->lock()).get();
}

LeAudioDevice* LeAudioDeviceGroup::GetNextDeviceWithActiveContext(
    LeAudioDevice* leAudioDevice, types::LeAudioContextType context_type) {
  AudioContexts type_set = static_cast<uint16_t>(context_type);

  auto iter = std::find_if(leAudioDevices_.begin(), leAudioDevices_.end(),
                           [&leAudioDevice](auto& d) {
                             if (d.expired())
                               return false;
                             else
                               return (d.lock()).get() == leAudioDevice;
                           });

  /* If reference device not found */
  if (iter == leAudioDevices_.end()) return nullptr;

  std::advance(iter, 1);
  /* If reference device is last in group */
  if (iter == leAudioDevices_.end()) return nullptr;

  iter = std::find_if(iter, leAudioDevices_.end(), [&type_set](auto& d) {
    if (d.expired())
      return false;
    else
      return (d.lock()->GetAvailableContexts() & type_set).any();
    ;
  });

  return (iter == leAudioDevices_.end()) ? nullptr : (iter->lock()).get();
}

bool LeAudioDeviceGroup::IsDeviceInTheGroup(LeAudioDevice* leAudioDevice) {
  auto iter = std::find_if(leAudioDevices_.begin(), leAudioDevices_.end(),
                           [&leAudioDevice](auto& d) {
                             if (d.expired())
                               return false;
                             else
                               return (d.lock()).get() == leAudioDevice;
                           });

  if ((iter == leAudioDevices_.end()) || (iter->expired())) return false;

  return true;
}

bool LeAudioDeviceGroup::HaveAllActiveDevicesAsesTheSameState(AseState state) {
  auto iter = std::find_if(
      leAudioDevices_.begin(), leAudioDevices_.end(), [&state](auto& d) {
        if (d.expired())
          return false;
        else
          return !(((d.lock()).get())->HaveAllActiveAsesSameState(state));
      });

  return iter == leAudioDevices_.end();
}

LeAudioDevice* LeAudioDeviceGroup::GetFirstActiveDevice(void) {
  auto iter =
      std::find_if(leAudioDevices_.begin(), leAudioDevices_.end(), [](auto& d) {
        if (d.expired())
          return false;
        else
          return ((d.lock()).get())->HaveActiveAse();
      });

  if (iter == leAudioDevices_.end() || iter->expired()) return nullptr;

  return (iter->lock()).get();
}

LeAudioDevice* LeAudioDeviceGroup::GetNextActiveDevice(
    LeAudioDevice* leAudioDevice) {
  auto iter = std::find_if(leAudioDevices_.begin(), leAudioDevices_.end(),
                           [&leAudioDevice](auto& d) {
                             if (d.expired())
                               return false;
                             else
                               return (d.lock()).get() == leAudioDevice;
                           });

  if (iter == leAudioDevices_.end() ||
      std::distance(iter, leAudioDevices_.end()) < 1)
    return nullptr;

  iter = std::find_if(std::next(iter, 1), leAudioDevices_.end(), [](auto& d) {
    if (d.expired())
      return false;
    else
      return ((d.lock()).get())->HaveActiveAse();
  });

  return (iter == leAudioDevices_.end()) ? nullptr : (iter->lock()).get();
}

LeAudioDevice* LeAudioDeviceGroup::GetFirstActiveDeviceByDataPathState(
    AudioStreamDataPathState data_path_state) {
  auto iter = std::find_if(leAudioDevices_.begin(), leAudioDevices_.end(),
                           [&data_path_state](auto& d) {
                             if (d.expired()) {
                               return false;
                             }

                             return (((d.lock()).get())
                                         ->GetFirstActiveAseByDataPathState(
                                             data_path_state) != nullptr);
                           });

  if (iter == leAudioDevices_.end()) {
    return nullptr;
  }

  return iter->lock().get();
}

LeAudioDevice* LeAudioDeviceGroup::GetNextActiveDeviceByDataPathState(
    LeAudioDevice* leAudioDevice, AudioStreamDataPathState data_path_state) {
  auto iter = std::find_if(leAudioDevices_.begin(), leAudioDevices_.end(),
                           [&leAudioDevice](auto& d) {
                             if (d.expired()) {
                               return false;
                             }

                             return d.lock().get() == leAudioDevice;
                           });

  if (std::distance(iter, leAudioDevices_.end()) < 1) {
    return nullptr;
  }

  iter = std::find_if(
      std::next(iter, 1), leAudioDevices_.end(), [&data_path_state](auto& d) {
        if (d.expired()) {
          return false;
        }

        return (((d.lock()).get())
                    ->GetFirstActiveAseByDataPathState(data_path_state) !=
                nullptr);
      });

  if (iter == leAudioDevices_.end()) {
    return nullptr;
  }

  return iter->lock().get();
}

bool LeAudioDeviceGroup::SetContextType(LeAudioContextType context_type) {
  /* XXX: group context policy ? / may it disallow to change type ?) */
  context_type_ = context_type;

  return true;
}

LeAudioContextType LeAudioDeviceGroup::GetContextType(void) {
  return context_type_;
}

uint32_t LeAudioDeviceGroup::GetSduInterval(uint8_t direction) {
  for (LeAudioDevice* leAudioDevice = GetFirstActiveDevice();
       leAudioDevice != nullptr;
       leAudioDevice = GetNextActiveDevice(leAudioDevice)) {
    struct ase* ase = leAudioDevice->GetFirstActiveAseByDirection(direction);
    if (!ase) continue;

    return ase->codec_config.GetFrameDurationUs();
  }

  return 0;
}

uint8_t LeAudioDeviceGroup::GetSCA(void) {
  uint8_t sca = kIsoSca0To20Ppm;

  for (const auto& leAudioDevice : leAudioDevices_) {
    uint8_t dev_sca =
        BTM_GetPeerSCA(leAudioDevice.lock()->address_, BT_TRANSPORT_LE);

    /* If we could not read SCA from the peer device or sca is 0,
     * then there is no reason to continue.
     */
    if ((dev_sca == 0xFF) || (dev_sca == 0)) return 0;

    /* The Slaves_Clock_Accuracy parameter shall be the worst-case sleep clock
     *accuracy of all the slaves that will participate in the CIG.
     */
    if (dev_sca < sca) {
      sca = dev_sca;
    }
  }

  return sca;
}

uint8_t LeAudioDeviceGroup::GetPacking(void) {
  /* TODO: Decide about packing */
  return kIsoCigPackingSequential;
}

uint8_t LeAudioDeviceGroup::GetFraming(void) {
  LeAudioDevice* leAudioDevice = GetFirstActiveDevice();
  LOG_ASSERT(leAudioDevice)
      << __func__ << " Shouldn't be called without an active device.";

  do {
    struct ase* ase = leAudioDevice->GetFirstActiveAse();
    if (!ase) continue;

    do {
      if (ase->framing == types::kFramingUnframedPduUnsupported)
        return kIsoCigFramingFramed;
    } while ((ase = leAudioDevice->GetNextActiveAse(ase)));
  } while ((leAudioDevice = GetNextActiveDevice(leAudioDevice)));

  return kIsoCigFramingUnframed;
}

/* TODO: Preferred parameter may be other than minimum */
static uint16_t find_max_transport_latency(LeAudioDeviceGroup* group,
                                           uint8_t direction) {
  uint16_t max_transport_latency = 0;

  for (LeAudioDevice* leAudioDevice = group->GetFirstActiveDevice();
       leAudioDevice != nullptr;
       leAudioDevice = group->GetNextActiveDevice(leAudioDevice)) {
    for (ase* ase = leAudioDevice->GetFirstActiveAseByDirection(direction);
         ase != nullptr;
         ase = leAudioDevice->GetNextActiveAseWithSameDirection(ase)) {
      if (!ase) break;

      if (!max_transport_latency)
        // first assignment
        max_transport_latency = ase->max_transport_latency;
      else if (ase->max_transport_latency < max_transport_latency)
        max_transport_latency = ase->max_transport_latency;
    }
  }

  if (max_transport_latency < types::kMaxTransportLatencyMin)
    max_transport_latency = types::kMaxTransportLatencyMin;
  else if (max_transport_latency > types::kMaxTransportLatencyMax)
    max_transport_latency = types::kMaxTransportLatencyMax;

  return max_transport_latency;
}

uint16_t LeAudioDeviceGroup::GetMaxTransportLatencyStom(void) {
  return find_max_transport_latency(this, types::kLeAudioDirectionSource);
}

uint16_t LeAudioDeviceGroup::GetMaxTransportLatencyMtos(void) {
  return find_max_transport_latency(this, types::kLeAudioDirectionSink);
}

uint32_t LeAudioDeviceGroup::GetTransportLatencyUs(uint8_t direction) {
  if (direction == types::kLeAudioDirectionSink) {
    return transport_latency_mtos_us_;
  } else if (direction == types::kLeAudioDirectionSource) {
    return transport_latency_stom_us_ ;
  } else {
    LOG(ERROR) << __func__ << ", invalid direction";
    return 0;
  }
}

void LeAudioDeviceGroup::SetTransportLatency(uint8_t direction,
                                             uint32_t new_transport_latency_us) {
  uint32_t* transport_latency_us;

  if (direction == types::kLeAudioDirectionSink) {
    transport_latency_us = &transport_latency_mtos_us_;
  } else if (direction == types::kLeAudioDirectionSource) {
    transport_latency_us = &transport_latency_stom_us_;
  } else {
    LOG(ERROR) << __func__ << ", invalid direction";
    return;
  }

  if (*transport_latency_us == new_transport_latency_us) return;

  if ((*transport_latency_us != 0) &&
      (*transport_latency_us != new_transport_latency_us)) {
    LOG(WARNING) << __func__ << ", Different transport latency for group: "
                 << " old: " << static_cast<int>(*transport_latency_us)
                 << " [us], new: " << static_cast<int>(new_transport_latency_us)
                 << " [us]";
    return;
  }

  LOG(INFO) << __func__ << ", updated group " << static_cast<int>(group_id_)
            << " transport latency: " << static_cast<int>(new_transport_latency_us)
            << " [us]";
  *transport_latency_us = new_transport_latency_us;
}

uint8_t LeAudioDeviceGroup::GetRtn(uint8_t direction, uint8_t cis_id) {
  LeAudioDevice* leAudioDevice = GetFirstActiveDevice();
  LOG_ASSERT(leAudioDevice)
      << __func__ << " Shouldn't be called without an active device.";

  do {
    auto ases_pair = leAudioDevice->GetAsesByCisId(cis_id);

    if (ases_pair.sink && direction == types::kLeAudioDirectionSink) {
      return ases_pair.sink->retrans_nb;
    } else if (ases_pair.source &&
               direction == types::kLeAudioDirectionSource) {
      return ases_pair.source->retrans_nb;
    }
  } while ((leAudioDevice = GetNextActiveDevice(leAudioDevice)));

  return 0;
}

uint16_t LeAudioDeviceGroup::GetMaxSduSize(uint8_t direction, uint8_t cis_id) {
  LeAudioDevice* leAudioDevice = GetFirstActiveDevice();
  LOG_ASSERT(leAudioDevice)
      << __func__ << " Shouldn't be called without an active device.";

  do {
    auto ases_pair = leAudioDevice->GetAsesByCisId(cis_id);

    if (ases_pair.sink && direction == types::kLeAudioDirectionSink) {
      return ases_pair.sink->max_sdu_size;
    } else if (ases_pair.source &&
               direction == types::kLeAudioDirectionSource) {
      return ases_pair.source->max_sdu_size;
    }
  } while ((leAudioDevice = GetNextActiveDevice(leAudioDevice)));

  return 0;
}

uint8_t LeAudioDeviceGroup::GetPhyBitmask(uint8_t direction) {
  LeAudioDevice* leAudioDevice = GetFirstActiveDevice();
  LOG_ASSERT(leAudioDevice)
      << __func__ << " Shouldn't be called without an active device.";

  // local supported PHY's
  uint8_t phy_bitfield = kIsoCigPhy1M;
  if (controller_get_interface()->supports_ble_2m_phy())
    phy_bitfield |= kIsoCigPhy2M;

  if (!leAudioDevice) {
    LOG(ERROR) << "No active leaudio device for direction?: " << +direction;
    return phy_bitfield;
  }

  do {
    struct ase* ase = leAudioDevice->GetFirstActiveAseByDirection(direction);
    if (!ase) return phy_bitfield;

    do {
      if (direction == ase->direction) {
        phy_bitfield &= leAudioDevice->GetPhyBitmask();

        // A value of 0x00 denotes no preference
        if (ase->preferred_phy) phy_bitfield &= ase->preferred_phy;
      }
    } while ((ase = leAudioDevice->GetNextActiveAseWithSameDirection(ase)));
  } while ((leAudioDevice = GetNextActiveDevice(leAudioDevice)));

  return phy_bitfield;
}

uint8_t LeAudioDeviceGroup::GetTargetPhy(uint8_t direction) {
  uint8_t phy_bitfield = GetPhyBitmask(direction);

  // prefer to use 2M if supported
  if (phy_bitfield & kIsoCigPhy2M)
    return types::kTargetPhy2M;
  else if (phy_bitfield & kIsoCigPhy1M)
    return types::kTargetPhy1M;
  else
    return 0;
}

bool LeAudioDeviceGroup::GetPresentationDelay(uint32_t* delay,
                                              uint8_t direction) {
  uint32_t delay_min = 0;
  uint32_t delay_max = UINT32_MAX;
  uint32_t preferred_delay_min = delay_min;
  uint32_t preferred_delay_max = delay_max;

  LeAudioDevice* leAudioDevice = GetFirstActiveDevice();
  LOG_ASSERT(leAudioDevice)
      << __func__ << " Shouldn't be called without an active device.";

  do {
    struct ase* ase = leAudioDevice->GetFirstActiveAseByDirection(direction);
    if (!ase) continue;  // device has no active ASEs in this direction

    do {
      /* No common range check */
      if (ase->pres_delay_min > delay_max || ase->pres_delay_max < delay_min)
        return false;

      if (ase->pres_delay_min > delay_min) delay_min = ase->pres_delay_min;
      if (ase->pres_delay_max < delay_max) delay_max = ase->pres_delay_max;
      if (ase->preferred_pres_delay_min > preferred_delay_min)
        preferred_delay_min = ase->preferred_pres_delay_min;
      if (ase->preferred_pres_delay_max < preferred_delay_max &&
          ase->preferred_pres_delay_max != types::kPresDelayNoPreference)
        preferred_delay_max = ase->preferred_pres_delay_max;
    } while ((ase = leAudioDevice->GetNextActiveAseWithSameDirection(ase)));
  } while ((leAudioDevice = GetNextActiveDevice(leAudioDevice)));

  if (preferred_delay_min <= preferred_delay_max &&
      preferred_delay_min > delay_min && preferred_delay_min < delay_max) {
    *delay = preferred_delay_min;
  } else {
    *delay = delay_min;
  }

  return true;
}

uint16_t LeAudioDeviceGroup::GetRemoteDelay(uint8_t direction) {
  uint16_t remote_delay_ms = 0;
  uint32_t presentation_delay;

  if (!GetPresentationDelay(&presentation_delay, direction)) {
    /* This should never happens at stream request time but to be safe return
     * some sample value to not break streaming
     */
    return 100;
  }

  /* us to ms */
  remote_delay_ms = presentation_delay / 1000;
  remote_delay_ms += GetTransportLatencyUs(direction) / 1000;

  return remote_delay_ms;
}

/* This method returns AudioContext value if support for any type has changed */
std::optional<AudioContexts> LeAudioDeviceGroup::UpdateActiveContextsMap(void) {
  LOG_DEBUG(" group id: %d, active contexts: 0x%04lx", group_id_,
            active_contexts_mask_.to_ulong());
  return UpdateActiveContextsMap(active_contexts_mask_);
}

/* This method returns AudioContext value if support for any type has changed */
std::optional<AudioContexts> LeAudioDeviceGroup::UpdateActiveContextsMap(
    AudioContexts update_contexts) {
  AudioContexts contexts = 0x0000;
  bool active_contexts_has_been_modified = false;

  if (update_contexts.none()) {
    LOG_DEBUG("No context updated");
    return contexts;
  }

  for (LeAudioContextType ctx_type : types::kLeAudioContextAllTypesArray) {
    AudioContexts type_set = static_cast<uint16_t>(ctx_type);
    LOG_DEBUG("Taking context: %s, 0x%04lx",
              bluetooth::common::ToString(ctx_type).c_str(),
              update_contexts.to_ulong());
    if ((type_set & update_contexts).none()) {
      LOG_INFO("Configuration not in updated context %s",
               bluetooth::common::ToString(ctx_type).c_str());
      /* Fill context bitset for possible returned value if updated */
      if (active_context_to_configuration_map.count(ctx_type) > 0)
        contexts |= type_set;

      continue;
    }

    auto new_conf = FindFirstSupportedConfiguration(ctx_type);

    bool ctx_previously_not_supported =
        (active_context_to_configuration_map.count(ctx_type) == 0 ||
         active_context_to_configuration_map[ctx_type] == nullptr);
    /* Check if support for context type has changed */
    if (ctx_previously_not_supported) {
      /* Current configuration for context type is empty */
      if (new_conf == nullptr) {
        /* Configuration remains empty */
        continue;
      } else {
        /* Configuration changes from empty to some */
        contexts |= type_set;
        active_contexts_has_been_modified = true;
      }
    } else {
      /* Current configuration for context type is not empty */
      if (new_conf == nullptr) {
        /* Configuration changed to empty */
        contexts &= ~type_set;
        active_contexts_has_been_modified = true;
      } else if (new_conf != active_context_to_configuration_map[ctx_type]) {
        /* Configuration changed to any other */
        contexts |= type_set;
        active_contexts_has_been_modified = true;
      } else {
        /* Configuration is the same */
        contexts |= type_set;
        continue;
      }
    }

    LOG_INFO(
        "updated context: %s, %s -> %s",
        bluetooth::common::ToString(ctx_type).c_str(),
        (ctx_previously_not_supported
             ? "empty"
             : active_context_to_configuration_map[ctx_type]->name.c_str()),
        (new_conf != nullptr ? new_conf->name.c_str() : "empty"));

    active_context_to_configuration_map[ctx_type] = new_conf;
  }

  /* Some contexts have changed, return new active context bitset */
  if (active_contexts_has_been_modified) {
    active_contexts_mask_ = contexts;
    return contexts;
  }

  /* Nothing has changed */
  return std::nullopt;
}

bool LeAudioDeviceGroup::ReloadAudioLocations(void) {
  AudioLocations updated_snk_audio_locations_ =
      codec_spec_conf::kLeAudioLocationNotAllowed;
  AudioLocations updated_src_audio_locations_ =
      codec_spec_conf::kLeAudioLocationNotAllowed;

  for (const auto& device : leAudioDevices_) {
    if (device.expired()) continue;
    updated_snk_audio_locations_ |= device.lock().get()->snk_audio_locations_;
    updated_src_audio_locations_ |= device.lock().get()->src_audio_locations_;
  }

  /* Nothing has changed */
  if ((updated_snk_audio_locations_ == snk_audio_locations_) &&
      (updated_src_audio_locations_ == src_audio_locations_))
    return false;

  snk_audio_locations_ = updated_snk_audio_locations_;
  src_audio_locations_ = updated_src_audio_locations_;

  return true;
}

bool LeAudioDeviceGroup::ReloadAudioDirections(void) {
  uint8_t updated_audio_directions = 0x00;

  for (const auto& device : leAudioDevices_) {
    if (device.expired()) continue;
    updated_audio_directions |= device.lock().get()->audio_directions_;
  }

  /* Nothing has changed */
  if (updated_audio_directions == audio_directions_) return false;

  audio_directions_ = updated_audio_directions;

  return true;
}

bool LeAudioDeviceGroup::IsInTransition(void) {
  return target_state_ != current_state_;
}

bool LeAudioDeviceGroup::IsReleasing(void) {
  return target_state_ == AseState::BTA_LE_AUDIO_ASE_STATE_IDLE;
}

bool LeAudioDeviceGroup::IsGroupStreamReady(void) {
  auto iter =
      std::find_if(leAudioDevices_.begin(), leAudioDevices_.end(), [](auto& d) {
        if (d.expired())
          return false;
        else
          return !(((d.lock()).get())->HaveAllActiveAsesCisEst());
      });

  return iter == leAudioDevices_.end();
}

bool LeAudioDeviceGroup::HaveAllActiveDevicesCisDisc(void) {
  auto iter =
      std::find_if(leAudioDevices_.begin(), leAudioDevices_.end(), [](auto& d) {
        if (d.expired())
          return false;
        else
          return !(((d.lock()).get())->HaveAllAsesCisDisc());
      });

  return iter == leAudioDevices_.end();
}

uint8_t LeAudioDeviceGroup::GetFirstFreeCisId(void) {
  for (uint8_t id = 0; id < UINT8_MAX; id++) {
    auto iter = std::find_if(leAudioDevices_.begin(), leAudioDevices_.end(),
                             [id](auto& d) {
                               if (d.expired())
                                 return false;
                               else
                                 return ((d.lock()).get())->HasCisId(id);
                             });

    if (iter == leAudioDevices_.end()) return id;
  }

  return kInvalidCisId;
}

uint8_t LeAudioDeviceGroup::GetFirstFreeCisId(CisType cis_type) {
  LOG_DEBUG("Group: %p, group_id: %d cis_type: %d", this, group_id_,
            static_cast<int>(cis_type));
  for (size_t id = 0; id < cises_.size(); id++) {
    if (cises_[id].addr.IsEmpty() && cises_[id].type == cis_type) {
      return id;
    }
  }
  return kInvalidCisId;
}

types::LeAudioConfigurationStrategy LeAudioDeviceGroup::GetGroupStrategy(void) {
  /* Simple strategy picker */
  LOG_INFO(" Group %d size %d", group_id_, Size());
  if (Size() > 1) {
    return types::LeAudioConfigurationStrategy::MONO_ONE_CIS_PER_DEVICE;
  }

  LOG_INFO("audio location 0x%04lx", snk_audio_locations_.to_ulong());
  if (!(snk_audio_locations_.to_ulong() &
        codec_spec_conf::kLeAudioLocationAnyLeft) ||
      !(snk_audio_locations_.to_ulong() &
        codec_spec_conf::kLeAudioLocationAnyRight)) {
    return types::LeAudioConfigurationStrategy::MONO_ONE_CIS_PER_DEVICE;
  }

  auto device = GetFirstDevice();
  auto channel_cnt =
      device->GetLc3SupportedChannelCount(types::kLeAudioDirectionSink);
  LOG_INFO("Channel count for group %d is %d (device %s)", group_id_,
           channel_cnt, device->address_.ToString().c_str());
  if (channel_cnt == 1) {
    return types::LeAudioConfigurationStrategy::STEREO_TWO_CISES_PER_DEVICE;
  }

  return types::LeAudioConfigurationStrategy::STEREO_ONE_CIS_PER_DEVICE;
}

int LeAudioDeviceGroup::GetAseCount(uint8_t direction) {
  int result = 0;
  for (const auto& device_iter : leAudioDevices_) {
    result += device_iter.lock()->GetAseCount(direction);
  }

  return result;
}

void LeAudioDeviceGroup::CigGenerateCisIds(
    types::LeAudioContextType context_type) {
  LOG_INFO("Group %p, group_id: %d, context_type: %s", this, group_id_,
           bluetooth::common::ToString(context_type).c_str());

  if (cises_.size() > 0) {
    LOG_INFO("CIS IDs already generated");
    return;
  }

  const set_configurations::AudioSetConfigurations* confs =
      AudioSetConfigurationProvider::Get()->GetConfigurations(context_type);

  uint8_t cis_count_bidir = 0;
  uint8_t cis_count_unidir_sink = 0;
  uint8_t cis_count_unidir_source = 0;
  get_cis_count(confs, GetGroupStrategy(),
                GetAseCount(types::kLeAudioDirectionSink),
                GetAseCount(types::kLeAudioDirectionSource), &cis_count_bidir,
                &cis_count_unidir_sink, &cis_count_unidir_source);

  uint8_t idx = 0;
  while (cis_count_bidir > 0) {
    struct le_audio::types::cis cis_entry = {
        .id = idx,
        .addr = RawAddress::kEmpty,
        .type = CisType::CIS_TYPE_BIDIRECTIONAL,
        .conn_handle = 0,
    };

    cises_.push_back(cis_entry);
    cis_count_bidir--;
    idx++;
  }

  while (cis_count_unidir_sink > 0) {
    struct le_audio::types::cis cis_entry = {
        .id = idx,
        .addr = RawAddress::kEmpty,
        .type = CisType::CIS_TYPE_UNIDIRECTIONAL_SINK,
        .conn_handle = 0,
    };
    cises_.push_back(cis_entry);
    cis_count_unidir_sink--;
    idx++;
  }

  while (cis_count_unidir_source > 0) {
    struct le_audio::types::cis cis_entry = {
        .id = idx,
        .addr = RawAddress::kEmpty,
        .type = CisType::CIS_TYPE_UNIDIRECTIONAL_SOURCE,
        .conn_handle = 0,
    };
    cises_.push_back(cis_entry);
    cis_count_unidir_source--;
    idx++;
  }
}

bool LeAudioDeviceGroup::CigAssignCisIds(LeAudioDevice* leAudioDevice) {
  ASSERT_LOG(leAudioDevice, "invalid device");
  LOG_INFO("device: %s", leAudioDevice->address_.ToString().c_str());

  struct ase* ase = leAudioDevice->GetFirstActiveAse();
  ASSERT_LOG(ase, " Shouldn't be called without an active ASE");

  for (; ase != nullptr; ase = leAudioDevice->GetNextActiveAse(ase)) {
    uint8_t cis_id = kInvalidCisId;
    /* CIS ID already set */
    if (ase->cis_id != kInvalidCisId) {
      LOG_INFO("ASE ID: %d, is already assigned CIS ID: %d, type %d", ase->id,
               ase->cis_id, cises_[ase->cis_id].type);
      if (!cises_[ase->cis_id].addr.IsEmpty()) {
        LOG_INFO("Bidirectional ASE already assigned");
        continue;
      }
      /* Reuse existing CIS ID if available*/
      cis_id = ase->cis_id;
    }

    /* First check if we have bidirectional ASEs. If so, assign same CIS ID.*/
    struct ase* matching_bidir_ase =
        leAudioDevice->GetNextActiveAseWithDifferentDirection(ase);

    if (matching_bidir_ase) {
      if (cis_id == kInvalidCisId) {
        cis_id = GetFirstFreeCisId(CisType::CIS_TYPE_BIDIRECTIONAL);
      }

      if (cis_id == kInvalidCisId) {
        LOG_ERROR(" Unable to get free Bi-Directional CIS ID");
        return false;
      }

      ase->cis_id = cis_id;
      matching_bidir_ase->cis_id = cis_id;
      cises_[cis_id].addr = leAudioDevice->address_;

      LOG_INFO(" ASE ID: %d and ASE ID: %d, assigned Bi-Directional CIS ID: %d",
               +ase->id, +matching_bidir_ase->id, +ase->cis_id);
      continue;
    }

    if (ase->direction == types::kLeAudioDirectionSink) {
      if (cis_id == kInvalidCisId) {
        cis_id = GetFirstFreeCisId(CisType::CIS_TYPE_UNIDIRECTIONAL_SINK);
      }

      if (cis_id == kInvalidCisId) {
        LOG_WARN(
            " Unable to get free Uni-Directional Sink CIS ID - maybe there is "
            "bi-directional available");
        /* This could happen when scenarios for given context type allows for
         * Sink and Source configuration but also only Sink configuration.
         */
        cis_id = GetFirstFreeCisId(CisType::CIS_TYPE_BIDIRECTIONAL);
        if (cis_id == kInvalidCisId) {
          LOG_ERROR("Unable to get free Uni-Directional Sink CIS ID");
          return false;
        }
      }

      ase->cis_id = cis_id;
      cises_[cis_id].addr = leAudioDevice->address_;
      LOG_INFO("ASE ID: %d, assigned Uni-Directional Sink CIS ID: %d", ase->id,
               ase->cis_id);
      continue;
    }

    /* Source direction */
    ASSERT_LOG(ase->direction == types::kLeAudioDirectionSource,
               "Expected Source direction, actual=%d", ase->direction);

    if (cis_id == kInvalidCisId) {
      cis_id = GetFirstFreeCisId(CisType::CIS_TYPE_UNIDIRECTIONAL_SOURCE);
    }

    if (cis_id == kInvalidCisId) {
      /* This could happen when scenarios for given context type allows for
       * Sink and Source configuration but also only Sink configuration.
       */
      LOG_WARN(
          "Unable to get free Uni-Directional Source CIS ID - maybe there "
          "is bi-directional available");
      cis_id = GetFirstFreeCisId(CisType::CIS_TYPE_BIDIRECTIONAL);
      if (cis_id == kInvalidCisId) {
        LOG_ERROR("Unable to get free Uni-Directional Source CIS ID");
        return false;
      }
    }

    ase->cis_id = cis_id;
    cises_[cis_id].addr = leAudioDevice->address_;
    LOG_INFO("ASE ID: %d, assigned Uni-Directional Source CIS ID: %d", ase->id,
             ase->cis_id);
  }

  return true;
}

void LeAudioDeviceGroup::CigAssignCisConnHandles(
    const std::vector<uint16_t>& conn_handles) {
  LOG_INFO("num of cis handles %d", static_cast<int>(conn_handles.size()));
  for (size_t i = 0; i < cises_.size(); i++) {
    cises_[i].conn_handle = conn_handles[i];
    LOG_INFO("assigning cis[%d] conn_handle: %d", cises_[i].id,
             cises_[i].conn_handle);
  }
}

void LeAudioDeviceGroup::CigAssignCisConnHandlesToAses(
    LeAudioDevice* leAudioDevice) {
  ASSERT_LOG(leAudioDevice, "Invalid device");
  LOG_INFO("group: %p, group_id: %d, device: %s", this, group_id_,
           leAudioDevice->address_.ToString().c_str());

  /* Assign all CIS connection handles to ases */
  struct le_audio::types::ase* ase =
      leAudioDevice->GetFirstActiveAseByDataPathState(
          AudioStreamDataPathState::IDLE);
  if (!ase) {
    LOG_WARN("No active ASE with AudioStreamDataPathState IDLE");
    return;
  }

  for (; ase != nullptr; ase = leAudioDevice->GetFirstActiveAseByDataPathState(
                             AudioStreamDataPathState::IDLE)) {
    auto ases_pair = leAudioDevice->GetAsesByCisId(ase->cis_id);

    if (ases_pair.sink && ases_pair.sink->active) {
      ases_pair.sink->cis_conn_hdl = cises_[ase->cis_id].conn_handle;
      ases_pair.sink->data_path_state = AudioStreamDataPathState::CIS_ASSIGNED;
    }
    if (ases_pair.source && ases_pair.source->active) {
      ases_pair.source->cis_conn_hdl = cises_[ase->cis_id].conn_handle;
      ases_pair.source->data_path_state =
          AudioStreamDataPathState::CIS_ASSIGNED;
    }
  }
}

void LeAudioDeviceGroup::CigAssignCisConnHandlesToAses(void) {
  LeAudioDevice* leAudioDevice = GetFirstActiveDevice();
  ASSERT_LOG(leAudioDevice, "Shouldn't be called without an active device.");

  LOG_INFO("Group %p, group_id %d", this, group_id_);

  /* Assign all CIS connection handles to ases */
  for (; leAudioDevice != nullptr;
       leAudioDevice = GetNextActiveDevice(leAudioDevice)) {
    CigAssignCisConnHandlesToAses(leAudioDevice);
  }
}

void LeAudioDeviceGroup::CigUnassignCis(LeAudioDevice* leAudioDevice) {
  ASSERT_LOG(leAudioDevice, "Invalid device");

  LOG_INFO("Group %p, group_id %d, device: %s", this, group_id_,
           leAudioDevice->address_.ToString().c_str());

  for (struct le_audio::types::cis& cis_entry : cises_) {
    if (cis_entry.addr == leAudioDevice->address_) {
      cis_entry.addr = RawAddress::kEmpty;
    }
  }
}

bool CheckIfStrategySupported(types::LeAudioConfigurationStrategy strategy,
                              types::AudioLocations audio_locations,
                              uint8_t requested_channel_count,
                              uint8_t channel_count_mask) {
  DLOG(INFO) << __func__ << " strategy: " << (int)strategy
             << " locations: " << +audio_locations.to_ulong();

  switch (strategy) {
    case types::LeAudioConfigurationStrategy::MONO_ONE_CIS_PER_DEVICE:
      return audio_locations.any();
    case types::LeAudioConfigurationStrategy::STEREO_TWO_CISES_PER_DEVICE:
      if ((audio_locations.to_ulong() &
           codec_spec_conf::kLeAudioLocationAnyLeft) &&
          (audio_locations.to_ulong() &
           codec_spec_conf::kLeAudioLocationAnyRight))
        return true;
      else
        return false;
    case types::LeAudioConfigurationStrategy::STEREO_ONE_CIS_PER_DEVICE:
      if (!(audio_locations.to_ulong() &
            codec_spec_conf::kLeAudioLocationAnyLeft) ||
          !(audio_locations.to_ulong() &
            codec_spec_conf::kLeAudioLocationAnyRight))
        return false;

      DLOG(INFO) << __func__ << " requested chan cnt "
                 << +requested_channel_count
                 << " chan mask: " << loghex(channel_count_mask);

      /* Return true if requested channel count is set in the channel count
       * mask. In the channel_count_mask, bit0 is set when 1 channel is
       * supported.
       */
      return ((1 << (requested_channel_count - 1)) & channel_count_mask);
    default:
      return false;
  }

  return false;
}

/* This method check if group support given audio configuration
 * requirement for connected devices in the group and available ASEs
 * (no matter on the ASE state) and for given context type
 */
bool LeAudioDeviceGroup::IsConfigurationSupported(
    const set_configurations::AudioSetConfiguration* audio_set_conf,
    types::LeAudioContextType context_type) {
  if (!set_configurations::check_if_may_cover_scenario(
          audio_set_conf, NumOfConnected(context_type))) {
    LOG_DEBUG(" cannot cover scenario  %s: size of for context type %d",
              bluetooth::common::ToString(context_type).c_str(),
              +NumOfConnected(context_type));
    return false;
  }

  /* TODO For now: set ase if matching with first pac.
   * 1) We assume as well that devices will match requirements in order
   *    e.g. 1 Device - 1 Requirement, 2 Device - 2 Requirement etc.
   * 2) ASEs should be active only if best (according to priority list) full
   *    scenarion will be covered.
   * 3) ASEs should be filled according to performance profile.
   */
  for (const auto& ent : (*audio_set_conf).confs) {
    LOG_DEBUG(" Looking for configuration: %s - %s",
              audio_set_conf->name.c_str(),
              (ent.direction == types::kLeAudioDirectionSink ? "snk" : "src"));

    uint8_t required_device_cnt = ent.device_cnt;
    uint8_t max_required_ase_per_dev =
        ent.ase_cnt / ent.device_cnt + (ent.ase_cnt % ent.device_cnt);
    uint8_t active_ase_num = 0;
    auto strategy = ent.strategy;

    LOG_DEBUG(
        " Number of devices: %d, number of ASEs: %d,  Max ASE per device: %d "
        "strategy: %d",
        +required_device_cnt, +ent.ase_cnt, +max_required_ase_per_dev,
        static_cast<int>(strategy));

    for (auto* device = GetFirstDeviceWithActiveContext(context_type);
         device != nullptr && required_device_cnt > 0;
         device = GetNextDeviceWithActiveContext(device, context_type)) {
      /* Skip if device has ASE configured in this direction already */

      if (device->ases_.empty()) continue;

      if (!device->GetCodecConfigurationSupportedPac(ent.direction, ent.codec))
        continue;

      int needed_ase = std::min(static_cast<int>(max_required_ase_per_dev),
                                static_cast<int>(ent.ase_cnt - active_ase_num));

      /* If we required more ASEs per device which means we would like to
       * create more CISes to one device, we should also check the allocation
       * if it allows us to do this.
       */

      types::AudioLocations audio_locations = 0;
      /* Check direction and if audio location allows to create more cise */
      if (ent.direction == types::kLeAudioDirectionSink)
        audio_locations = device->snk_audio_locations_;
      else
        audio_locations = device->src_audio_locations_;

      /* TODO Make it no Lc3 specific */
      if (!CheckIfStrategySupported(
              strategy, audio_locations,
              std::get<LeAudioLc3Config>(ent.codec.config).GetChannelCount(),
              device->GetLc3SupportedChannelCount(ent.direction))) {
        LOG_DEBUG(" insufficient device audio allocation: %lu",
                  audio_locations.to_ulong());
        continue;
      }

      for (auto& ase : device->ases_) {
        if (ase.direction != ent.direction) continue;

        active_ase_num++;
        needed_ase--;

        if (needed_ase == 0) break;
      }

      if (needed_ase > 0) {
        LOG_DEBUG("Device has too less ASEs. Still needed ases %d", needed_ase);
        return false;
      }

      required_device_cnt--;
    }

    if (required_device_cnt > 0) {
      /* Don't left any active devices if requirements are not met */
      LOG_DEBUG(" could not configure all the devices");
      return false;
    }
  }

  LOG_DEBUG("Chosen ASE Configuration for group: %d, configuration: %s",
            this->group_id_, audio_set_conf->name.c_str());
  return true;
}

uint32_t GetFirstLeft(const types::AudioLocations audio_locations) {
  uint32_t audio_location_ulong = audio_locations.to_ulong();

  if (audio_location_ulong & codec_spec_conf::kLeAudioLocationFrontLeft)
    return codec_spec_conf::kLeAudioLocationFrontLeft;

  if (audio_location_ulong & codec_spec_conf::kLeAudioLocationBackLeft)
    return codec_spec_conf::kLeAudioLocationBackLeft;

  if (audio_location_ulong & codec_spec_conf::kLeAudioLocationFrontLeftOfCenter)
    return codec_spec_conf::kLeAudioLocationFrontLeftOfCenter;

  if (audio_location_ulong & codec_spec_conf::kLeAudioLocationSideLeft)
    return codec_spec_conf::kLeAudioLocationSideLeft;

  if (audio_location_ulong & codec_spec_conf::kLeAudioLocationTopFrontLeft)
    return codec_spec_conf::kLeAudioLocationTopFrontLeft;

  if (audio_location_ulong & codec_spec_conf::kLeAudioLocationTopBackLeft)
    return codec_spec_conf::kLeAudioLocationTopBackLeft;

  if (audio_location_ulong & codec_spec_conf::kLeAudioLocationTopSideLeft)
    return codec_spec_conf::kLeAudioLocationTopSideLeft;

  if (audio_location_ulong & codec_spec_conf::kLeAudioLocationBottomFrontLeft)
    return codec_spec_conf::kLeAudioLocationBottomFrontLeft;

  if (audio_location_ulong & codec_spec_conf::kLeAudioLocationFrontLeftWide)
    return codec_spec_conf::kLeAudioLocationFrontLeftWide;

  if (audio_location_ulong & codec_spec_conf::kLeAudioLocationLeftSurround)
    return codec_spec_conf::kLeAudioLocationLeftSurround;

  LOG_ASSERT(0) << __func__ << " shall not happen";
  return 0;
}

uint32_t GetFirstRight(const types::AudioLocations audio_locations) {
  uint32_t audio_location_ulong = audio_locations.to_ulong();

  if (audio_location_ulong & codec_spec_conf::kLeAudioLocationFrontRight)
    return codec_spec_conf::kLeAudioLocationFrontRight;

  if (audio_location_ulong & codec_spec_conf::kLeAudioLocationBackRight)
    return codec_spec_conf::kLeAudioLocationBackRight;

  if (audio_location_ulong &
      codec_spec_conf::kLeAudioLocationFrontRightOfCenter)
    return codec_spec_conf::kLeAudioLocationFrontRightOfCenter;

  if (audio_location_ulong & codec_spec_conf::kLeAudioLocationSideRight)
    return codec_spec_conf::kLeAudioLocationSideRight;

  if (audio_location_ulong & codec_spec_conf::kLeAudioLocationTopFrontRight)
    return codec_spec_conf::kLeAudioLocationTopFrontRight;

  if (audio_location_ulong & codec_spec_conf::kLeAudioLocationTopBackRight)
    return codec_spec_conf::kLeAudioLocationTopBackRight;

  if (audio_location_ulong & codec_spec_conf::kLeAudioLocationTopSideRight)
    return codec_spec_conf::kLeAudioLocationTopSideRight;

  if (audio_location_ulong & codec_spec_conf::kLeAudioLocationBottomFrontRight)
    return codec_spec_conf::kLeAudioLocationBottomFrontRight;

  if (audio_location_ulong & codec_spec_conf::kLeAudioLocationFrontRightWide)
    return codec_spec_conf::kLeAudioLocationFrontRightWide;

  if (audio_location_ulong & codec_spec_conf::kLeAudioLocationRightSurround)
    return codec_spec_conf::kLeAudioLocationRightSurround;

  LOG_ASSERT(0) << __func__ << " shall not happen";
  return 0;
}

uint32_t PickAudioLocation(types::LeAudioConfigurationStrategy strategy,
                           types::AudioLocations audio_locations,
                           types::AudioLocations* group_audio_locations) {
  DLOG(INFO) << __func__ << " strategy: " << (int)strategy
             << " locations: " << +audio_locations.to_ulong()
             << " group locations: " << +group_audio_locations->to_ulong();

  switch (strategy) {
    case types::LeAudioConfigurationStrategy::MONO_ONE_CIS_PER_DEVICE:
    case types::LeAudioConfigurationStrategy::STEREO_TWO_CISES_PER_DEVICE:
      if ((audio_locations.to_ulong() &
           codec_spec_conf::kLeAudioLocationAnyLeft) &&
          !(group_audio_locations->to_ulong() &
            codec_spec_conf::kLeAudioLocationAnyLeft)) {
        uint32_t left_location = GetFirstLeft(audio_locations);
        *group_audio_locations |= left_location;
        return left_location;
      }

      if ((audio_locations.to_ulong() &
           codec_spec_conf::kLeAudioLocationAnyRight) &&
          !(group_audio_locations->to_ulong() &
            codec_spec_conf::kLeAudioLocationAnyRight)) {
        uint32_t right_location = GetFirstRight(audio_locations);
        *group_audio_locations |= right_location;
        return right_location;
      }
      break;
    case types::LeAudioConfigurationStrategy::STEREO_ONE_CIS_PER_DEVICE:
      if ((audio_locations.to_ulong() &
           codec_spec_conf::kLeAudioLocationAnyLeft) &&
          (audio_locations.to_ulong() &
           codec_spec_conf::kLeAudioLocationAnyRight)) {
        uint32_t left_location = GetFirstLeft(audio_locations);
        uint32_t right_location = GetFirstRight(audio_locations);
        *group_audio_locations |= left_location | right_location;
        return left_location | right_location;
      }
      break;
    default:
      LOG_ALWAYS_FATAL("%s: Unknown strategy: %hhu", __func__, strategy);
      return 0;
  }

  LOG_ALWAYS_FATAL(
      "%s: Shall never exit switch statement, strategy: %hhu, "
      "locations: %lx, group_locations: %lx",
      __func__, strategy, audio_locations.to_ulong(),
      group_audio_locations->to_ulong());
  return 0;
}

bool LeAudioDevice::ConfigureAses(
    const le_audio::set_configurations::SetConfiguration& ent,
    types::LeAudioContextType context_type,
    uint8_t* number_of_already_active_group_ase,
    types::AudioLocations& group_snk_audio_locations,
    types::AudioLocations& group_src_audio_locations, bool reuse_cis_id,
    AudioContexts metadata_context_type,
    const std::vector<uint8_t>& ccid_list) {
  struct ase* ase = GetFirstInactiveAse(ent.direction, reuse_cis_id);
  if (!ase) return false;

  uint8_t active_ases = *number_of_already_active_group_ase;
  uint8_t max_required_ase_per_dev =
      ent.ase_cnt / ent.device_cnt + (ent.ase_cnt % ent.device_cnt);
  le_audio::types::LeAudioConfigurationStrategy strategy = ent.strategy;

  auto pac = GetCodecConfigurationSupportedPac(ent.direction, ent.codec);
  if (!pac) return false;

  int needed_ase = std::min((int)(max_required_ase_per_dev),
                            (int)(ent.ase_cnt - active_ases));

  types::AudioLocations audio_locations = 0;
  types::AudioLocations* group_audio_locations;
  /* Check direction and if audio location allows to create more cise */
  if (ent.direction == types::kLeAudioDirectionSink) {
    audio_locations = snk_audio_locations_;
    group_audio_locations = &group_snk_audio_locations;
  } else {
    audio_locations = src_audio_locations_;
    group_audio_locations = &group_src_audio_locations;
  }

  for (; needed_ase && ase; needed_ase--) {
    ase->active = true;
    ase->configured_for_context_type = context_type;
    active_ases++;

    if (ase->state == AseState::BTA_LE_AUDIO_ASE_STATE_CODEC_CONFIGURED)
      ase->reconfigure = true;

    ase->target_latency = ent.target_latency;
    ase->codec_id = ent.codec.id;
    /* TODO: find better way to not use LC3 explicitly */
    ase->codec_config = std::get<LeAudioLc3Config>(ent.codec.config);

    /*Let's choose audio channel allocation if not set */
    ase->codec_config.audio_channel_allocation =
        PickAudioLocation(strategy, audio_locations, group_audio_locations);

    /* Get default value if no requirement for specific frame blocks per sdu */
    if (!ase->codec_config.codec_frames_blocks_per_sdu) {
      ase->codec_config.codec_frames_blocks_per_sdu =
          GetMaxCodecFramesPerSduFromPac(pac);
    }
    ase->max_sdu_size = codec_spec_caps::GetAudioChannelCounts(
                            *ase->codec_config.audio_channel_allocation) *
                        *ase->codec_config.octets_per_codec_frame *
                        *ase->codec_config.codec_frames_blocks_per_sdu;

    ase->retrans_nb = ent.qos.retransmission_number;
    ase->max_transport_latency = ent.qos.max_transport_latency;

    ase->metadata = GetMetadata(metadata_context_type, ccid_list);

    DLOG(INFO) << __func__ << " device=" << address_
               << ", activated ASE id=" << +ase->id
               << ", direction=" << +ase->direction
               << ", max_sdu_size=" << +ase->max_sdu_size
               << ", cis_id=" << +ase->cis_id
               << ", target_latency=" << +ent.target_latency;

    ase = GetFirstInactiveAse(ent.direction, reuse_cis_id);
  }

  *number_of_already_active_group_ase = active_ases;
  return true;
}

/* This method should choose aproperiate ASEs to be active and set a cached
 * configuration for codec and qos.
 */
bool LeAudioDeviceGroup::ConfigureAses(
    const set_configurations::AudioSetConfiguration* audio_set_conf,
    types::LeAudioContextType context_type, AudioContexts metadata_context_type,
    const std::vector<uint8_t>& ccid_list) {
  if (!set_configurations::check_if_may_cover_scenario(
          audio_set_conf, NumOfConnected(context_type)))
    return false;

  bool reuse_cis_id =
      GetState() == AseState::BTA_LE_AUDIO_ASE_STATE_CODEC_CONFIGURED;

  /* TODO For now: set ase if matching with first pac.
   * 1) We assume as well that devices will match requirements in order
   *    e.g. 1 Device - 1 Requirement, 2 Device - 2 Requirement etc.
   * 2) ASEs should be active only if best (according to priority list) full
   *    scenarion will be covered.
   * 3) ASEs should be filled according to performance profile.
   */

  types::AudioLocations group_snk_audio_locations = 0;
  types::AudioLocations group_src_audio_locations = 0;

  for (const auto& ent : (*audio_set_conf).confs) {
    DLOG(INFO) << __func__
               << " Looking for requirements: " << audio_set_conf->name << " - "
               << (ent.direction == 1 ? "snk" : "src");

    uint8_t required_device_cnt = ent.device_cnt;
    uint8_t max_required_ase_per_dev =
        ent.ase_cnt / ent.device_cnt + (ent.ase_cnt % ent.device_cnt);
    uint8_t active_ase_num = 0;
    le_audio::types::LeAudioConfigurationStrategy strategy = ent.strategy;

    DLOG(INFO) << __func__ << " Number of devices: " << +required_device_cnt
               << " number of ASEs: " << +ent.ase_cnt
               << " Max ASE per device: " << +max_required_ase_per_dev
               << " strategy: " << (int)strategy;

    for (auto* device = GetFirstDeviceWithActiveContext(context_type);
         device != nullptr && required_device_cnt > 0;
         device = GetNextDeviceWithActiveContext(device, context_type)) {
      /* Skip if device has ASE configured in this direction already */
      if (device->GetFirstActiveAseByDirection(ent.direction)) {
        required_device_cnt--;
        continue;
      }

      /* For the moment, we configure only connected devices. */
      if (device->conn_id_ == GATT_INVALID_CONN_ID) continue;

      if (!device->ConfigureAses(ent, context_type, &active_ase_num,
                                 group_snk_audio_locations,
                                 group_src_audio_locations, reuse_cis_id,
                                 metadata_context_type, ccid_list))
        continue;

      required_device_cnt--;
    }

    if (required_device_cnt > 0) {
      /* Don't left any active devices if requirements are not met */
      LOG(ERROR) << __func__ << " could not configure all the devices";
      Deactivate();
      return false;
    }
  }

  LOG(INFO) << "Choosed ASE Configuration for group: " << this->group_id_
            << " configuration: " << audio_set_conf->name;

  active_context_type_ = context_type;
  metadata_context_type_ = metadata_context_type;
  return true;
}

const set_configurations::AudioSetConfiguration*
LeAudioDeviceGroup::GetActiveConfiguration(void) {
  return active_context_to_configuration_map[active_context_type_];
}
AudioContexts LeAudioDeviceGroup::GetActiveContexts(void) {
  return active_contexts_mask_;
}

std::optional<LeAudioCodecConfiguration>
LeAudioDeviceGroup::GetCodecConfigurationByDirection(
    types::LeAudioContextType group_context_type, uint8_t direction) {
  const set_configurations::AudioSetConfiguration* audio_set_conf =
      active_context_to_configuration_map[group_context_type];
  LeAudioCodecConfiguration group_config = {0, 0, 0, 0};
  if (!audio_set_conf) return std::nullopt;

  for (const auto& conf : audio_set_conf->confs) {
    if (conf.direction != direction) continue;

    if (group_config.sample_rate != 0 &&
        conf.codec.GetConfigSamplingFrequency() != group_config.sample_rate) {
      LOG(WARNING) << __func__
                   << ", stream configuration could not be "
                      "determined (sampling frequency differs) for direction: "
                   << loghex(direction);
      return std::nullopt;
    }
    group_config.sample_rate = conf.codec.GetConfigSamplingFrequency();

    if (group_config.data_interval_us != 0 &&
        conf.codec.GetConfigDataIntervalUs() != group_config.data_interval_us) {
      LOG(WARNING) << __func__
                   << ", stream configuration could not be "
                      "determined (data interval differs) for direction: "
                   << loghex(direction);
      return std::nullopt;
    }
    group_config.data_interval_us = conf.codec.GetConfigDataIntervalUs();

    if (group_config.bits_per_sample != 0 &&
        conf.codec.GetConfigBitsPerSample() != group_config.bits_per_sample) {
      LOG(WARNING) << __func__
                   << ", stream configuration could not be "
                      "determined (bits per sample differs) for direction: "
                   << loghex(direction);
      return std::nullopt;
    }
    group_config.bits_per_sample = conf.codec.GetConfigBitsPerSample();

    group_config.num_channels +=
        conf.codec.GetConfigChannelCount() * conf.device_cnt;
  }

  if (group_config.IsInvalid()) return std::nullopt;

  return group_config;
}

bool LeAudioDeviceGroup::IsContextSupported(
    types::LeAudioContextType group_context_type) {
  auto iter = active_context_to_configuration_map.find(group_context_type);
  if (iter == active_context_to_configuration_map.end()) return false;

  return active_context_to_configuration_map[group_context_type] != nullptr;
}

bool LeAudioDeviceGroup::IsMetadataChanged(
    types::AudioContexts context_type, const std::vector<uint8_t>& ccid_list) {
  for (auto* leAudioDevice = GetFirstActiveDevice(); leAudioDevice;
       leAudioDevice = GetNextActiveDevice(leAudioDevice)) {
    if (leAudioDevice->IsMetadataChanged(context_type, ccid_list)) return true;
  }

  return false;
}

void LeAudioDeviceGroup::StreamOffloaderUpdated(uint8_t direction) {
  if (direction == le_audio::types::kLeAudioDirectionSource) {
    stream_conf.source_is_initial = false;
  } else {
    stream_conf.sink_is_initial = false;
  }
}

void LeAudioDeviceGroup::CreateStreamVectorForOffloader(uint8_t direction) {
  if (CodecManager::GetInstance()->GetCodecLocation() !=
      le_audio::types::CodecLocation::ADSP) {
    return;
  }

  CisType cis_type;
  std::vector<std::pair<uint16_t, uint32_t>>* streams;
  std::vector<std::pair<uint16_t, uint32_t>>*
      offloader_streams_target_allocation;
  std::vector<std::pair<uint16_t, uint32_t>>*
      offloader_streams_current_allocation;
  std::string tag;
  uint32_t available_allocations = 0;
  bool* changed_flag;
  bool* is_initial;
  if (direction == le_audio::types::kLeAudioDirectionSource) {
    changed_flag = &stream_conf.source_offloader_changed;
    is_initial = &stream_conf.source_is_initial;
    cis_type = CisType::CIS_TYPE_UNIDIRECTIONAL_SOURCE;
    streams = &stream_conf.source_streams;
    offloader_streams_target_allocation =
        &stream_conf.source_offloader_streams_target_allocation;
    offloader_streams_current_allocation =
        &stream_conf.source_offloader_streams_current_allocation;
    tag = "Source";
    available_allocations = AdjustAllocationForOffloader(
        stream_conf.source_audio_channel_allocation);
  } else {
    changed_flag = &stream_conf.sink_offloader_changed;
    is_initial = &stream_conf.sink_is_initial;
    cis_type = CisType::CIS_TYPE_UNIDIRECTIONAL_SINK;
    streams = &stream_conf.sink_streams;
    offloader_streams_target_allocation =
        &stream_conf.sink_offloader_streams_target_allocation;
    offloader_streams_current_allocation =
        &stream_conf.sink_offloader_streams_current_allocation;
    tag = "Sink";
    available_allocations =
        AdjustAllocationForOffloader(stream_conf.sink_audio_channel_allocation);
  }

  if (available_allocations == 0) {
    LOG_ERROR("There is no CIS connected");
    return;
  }

  if (offloader_streams_target_allocation->size() == 0) {
    *is_initial = true;
  } else if (*is_initial) {
    // As multiple CISes phone call case, the target_allocation already have the
    // previous data, but the is_initial flag not be cleared. We need to clear
    // here to avoid make duplicated target allocation stream map.
    offloader_streams_target_allocation->clear();
  }

  offloader_streams_current_allocation->clear();
  *changed_flag = true;
  bool not_all_cises_connected = false;
  if (available_allocations != codec_spec_conf::kLeAudioLocationStereo) {
    not_all_cises_connected = true;
  }

  /* If the all cises are connected as stream started, reset changed_flag that
   * the bt stack wouldn't send another audio configuration for the connection
   * status */
  if (*is_initial && !not_all_cises_connected) {
    *changed_flag = false;
  }

  /* Note: For the offloader case we simplify allocation to only Left and Right.
   * If we need 2 CISes and only one is connected, the connected one will have
   * allocation set to stereo (left | right) and other one will have allocation
   * set to 0. Offloader in this case shall mix left and right and send it on
   * connected CIS. If there is only single CIS with stereo allocation, it means
   * that peer device support channel count 2 and offloader shall send two
   * channels in the single CIS.
   */

  for (auto& cis_entry : cises_) {
    if ((cis_entry.type == CisType::CIS_TYPE_BIDIRECTIONAL ||
         cis_entry.type == cis_type) &&
        cis_entry.conn_handle != 0) {
      uint32_t target_allocation = 0;
      uint32_t current_allocation = 0;
      for (const auto& s : *streams) {
        if (s.first == cis_entry.conn_handle) {
          target_allocation = AdjustAllocationForOffloader(s.second);
          current_allocation = target_allocation;
          if (not_all_cises_connected) {
            /* Tell offloader to mix on this CIS.*/
            current_allocation = codec_spec_conf::kLeAudioLocationStereo;
          }
          break;
        }
      }

      if (target_allocation == 0) {
        /* Take missing allocation for that one .*/
        target_allocation =
            codec_spec_conf::kLeAudioLocationStereo & ~available_allocations;
      }

      LOG_INFO(
          "%s: Cis handle 0x%04x, target allocation  0x%08x, current "
          "allocation 0x%08x",
          tag.c_str(), cis_entry.conn_handle, target_allocation,
          current_allocation);
      if (*is_initial) {
        offloader_streams_target_allocation->emplace_back(
            std::make_pair(cis_entry.conn_handle, target_allocation));
      }
      offloader_streams_current_allocation->emplace_back(
          std::make_pair(cis_entry.conn_handle, current_allocation));
    }
  }
}

types::LeAudioContextType LeAudioDeviceGroup::GetCurrentContextType(void) {
  return active_context_type_;
}

bool LeAudioDeviceGroup::IsPendingConfiguration(void) {
  return stream_conf.pending_configuration;
}

void LeAudioDeviceGroup::SetPendingConfiguration(void) {
  stream_conf.pending_configuration = true;
}

void LeAudioDeviceGroup::ClearPendingConfiguration(void) {
  stream_conf.pending_configuration = false;
}

bool LeAudioDeviceGroup::IsConfigurationSupported(
    LeAudioDevice* leAudioDevice,
    const set_configurations::AudioSetConfiguration* audio_set_conf) {
  for (const auto& ent : (*audio_set_conf).confs) {
    LOG_INFO("Looking for requirements: %s - %s", audio_set_conf->name.c_str(),
             (ent.direction == 1 ? "snk" : "src"));
    auto pac = leAudioDevice->GetCodecConfigurationSupportedPac(ent.direction,
                                                                ent.codec);
    if (pac != nullptr) {
      LOG_INFO("Configuration is supported by device %s",
               leAudioDevice->address_.ToString().c_str());
      return true;
    }
  }

  LOG_INFO("Configuration is NOT supported by device %s",
           leAudioDevice->address_.ToString().c_str());
  return false;
}

const set_configurations::AudioSetConfiguration*
LeAudioDeviceGroup::FindFirstSupportedConfiguration(
    LeAudioContextType context_type) {
  const set_configurations::AudioSetConfigurations* confs =
      AudioSetConfigurationProvider::Get()->GetConfigurations(context_type);

  LOG_DEBUG("context type: %s,  number of connected devices: %d",
            bluetooth::common::ToString(context_type).c_str(),
            +NumOfConnected());

  /* Filter out device set for all scenarios */
  if (!set_configurations::check_if_may_cover_scenario(confs,
                                                       NumOfConnected())) {
    LOG_ERROR(", group is unable to cover scenario");
    return nullptr;
  }

  /* Filter out device set for each end every scenario */

  for (const auto& conf : *confs) {
    if (IsConfigurationSupported(conf, context_type)) {
      LOG_DEBUG("found: %s", conf->name.c_str());
      return conf;
    }
  }

  return nullptr;
}

/* This method should choose aproperiate ASEs to be active and set a cached
 * configuration for codec and qos.
 */
bool LeAudioDeviceGroup::Configure(LeAudioContextType context_type,
                                   AudioContexts metadata_context_type,
                                   std::vector<uint8_t> ccid_list) {
  const set_configurations::AudioSetConfiguration* conf =
      active_context_to_configuration_map[context_type];

  DLOG(INFO) << __func__;

  if (!conf) {
    LOG(ERROR) << __func__ << ", requested context type: "
               << loghex(static_cast<uint16_t>(context_type))
               << ", is in mismatch with cached active contexts";
    return false;
  }

  DLOG(INFO) << __func__ << " setting context type: " << int(context_type);

  if (!ConfigureAses(conf, context_type, metadata_context_type, ccid_list)) {
    LOG(ERROR) << __func__ << ", requested pick ASE config context type: "
               << loghex(static_cast<uint16_t>(context_type))
               << ", is in mismatch with cached active contexts";
    return false;
  }

  /* Store selected configuration at once it is chosen.
   * It might happen it will get unavailable in some point of time
   */
  stream_conf.conf = conf;
  return true;
}

LeAudioDeviceGroup::~LeAudioDeviceGroup(void) { this->Cleanup(); }
void LeAudioDeviceGroup::Dump(int fd) {
  std::stringstream stream;
  auto* active_conf = GetActiveConfiguration();

  stream << "    == Group id: " << group_id_ << " == \n"
         << "      state: " << GetState() << "\n"
         << "      target state: " << GetTargetState() << "\n"
         << "      cig state: " << cig_state_ << "\n"
         << "      number of devices: " << Size() << "\n"
         << "      number of connected devices: " << NumOfConnected() << "\n"
         << "      active context types: "
         << loghex(GetActiveContexts().to_ulong()) << "\n"
         << "      current context type: "
         << static_cast<int>(GetCurrentContextType()) << "\n"
         << "      active stream configuration name: "
         << (active_conf ? active_conf->name : " not set") << "\n"
         << "    Last used stream configuration: \n"
         << "      pending_configuration: " << stream_conf.pending_configuration
         << "\n"
         << "      codec id : " << +(stream_conf.id.coding_format) << "\n"
         << "      name: "
         << (stream_conf.conf != nullptr ? stream_conf.conf->name : " null ")
         << "\n"
         << "      number of sinks in the configuration "
         << stream_conf.sink_num_of_devices << "\n"
         << "      number of sink_streams connected: "
         << stream_conf.sink_streams.size() << "\n"
         << "      number of sources in the configuration "
         << stream_conf.source_num_of_devices << "\n"
         << "      number of source_streams connected: "
         << stream_conf.source_streams.size() << "\n"
         << "      allocated CISes: " << static_cast<int>(cises_.size());

  if (cises_.size() > 0) {
    stream << "\n\t === CISes === ";
    for (auto cis : cises_) {
      stream << "\n\t cis id: " << static_cast<int>(cis.id)
             << ", type: " << static_cast<int>(cis.type)
             << ", conn_handle: " << static_cast<int>(cis.conn_handle)
             << ", addr: " << cis.addr;
    }
  }

  if (GetFirstActiveDevice() != nullptr) {
    uint32_t sink_delay;
    stream << "\n      presentation_delay for sink (speaker): ";
    if (GetPresentationDelay(&sink_delay, le_audio::types::kLeAudioDirectionSink)) {
      stream << sink_delay << " us";
    }
    stream << "\n      presentation_delay for source (microphone): ";
    uint32_t source_delay;
    if (GetPresentationDelay(&source_delay, le_audio::types::kLeAudioDirectionSource)) {
      stream << source_delay << " us";
    }
    stream << "\n";
  } else {
    stream << "\n      presentation_delay for sink (speaker):\n"
           << "      presentation_delay for source (microphone): \n";
  }

  stream << "      === devices: ===";

  dprintf(fd, "%s", stream.str().c_str());

  for (const auto& device_iter : leAudioDevices_) {
    device_iter.lock()->Dump(fd);
  }
}

/* LeAudioDevice Class methods implementation */
void LeAudioDevice::ClearPACs(void) {
  snk_pacs_.clear();
  src_pacs_.clear();
}

LeAudioDevice::~LeAudioDevice(void) {
  alarm_free(link_quality_timer);
  this->ClearPACs();
}

void LeAudioDevice::RegisterPACs(
    std::vector<struct types::acs_ac_record>* pac_db,
    std::vector<struct types::acs_ac_record>* pac_recs) {
  /* Clear PAC database for characteristic in case if re-read, indicated */
  if (!pac_db->empty()) {
    DLOG(INFO) << __func__ << ", upgrade PACs for characteristic";
    pac_db->clear();
  }

  /* TODO wrap this logging part with debug flag */
  for (const struct types::acs_ac_record& pac : *pac_recs) {
    LOG(INFO) << "Registering PAC"
              << "\n\tCoding format: " << loghex(pac.codec_id.coding_format)
              << "\n\tVendor codec company ID: "
              << loghex(pac.codec_id.vendor_company_id)
              << "\n\tVendor codec ID: " << loghex(pac.codec_id.vendor_codec_id)
              << "\n\tCodec spec caps:\n"
              << pac.codec_spec_caps.ToString() << "\n\tMetadata: "
              << base::HexEncode(pac.metadata.data(), pac.metadata.size());
  }

  pac_db->insert(pac_db->begin(), pac_recs->begin(), pac_recs->end());
}

struct ase* LeAudioDevice::GetAseByValHandle(uint16_t val_hdl) {
  auto iter = std::find_if(
      ases_.begin(), ases_.end(),
      [&val_hdl](const auto& ase) { return ase.hdls.val_hdl == val_hdl; });

  return (iter == ases_.end()) ? nullptr : &(*iter);
}

int LeAudioDevice::GetAseCount(uint8_t direction) {
  return std::count_if(ases_.begin(), ases_.end(), [direction](const auto& a) {
    return a.direction == direction;
  });
}

struct ase* LeAudioDevice::GetFirstAseWithState(uint8_t direction,
                                                AseState state) {
  auto iter = std::find_if(
      ases_.begin(), ases_.end(), [direction, state](const auto& ase) {
        return ((ase.direction == direction) && (ase.state == state));
      });

  return (iter == ases_.end()) ? nullptr : &(*iter);
}

struct ase* LeAudioDevice::GetFirstActiveAse(void) {
  auto iter = std::find_if(ases_.begin(), ases_.end(),
                           [](const auto& ase) { return ase.active; });

  return (iter == ases_.end()) ? nullptr : &(*iter);
}

struct ase* LeAudioDevice::GetFirstActiveAseByDirection(uint8_t direction) {
  auto iter =
      std::find_if(ases_.begin(), ases_.end(), [direction](const auto& ase) {
        return (ase.active && (ase.direction == direction));
      });

  return (iter == ases_.end()) ? nullptr : &(*iter);
}

struct ase* LeAudioDevice::GetNextActiveAseWithSameDirection(
    struct ase* base_ase) {
  auto iter = std::find_if(ases_.begin(), ases_.end(),
                           [&base_ase](auto& ase) { return base_ase == &ase; });

  /* Invalid ase given */
  if (iter == ases_.end() || std::distance(iter, ases_.end()) < 1)
    return nullptr;

  iter =
      std::find_if(std::next(iter, 1), ases_.end(), [&iter](const auto& ase) {
        return ase.active && (*iter).direction == ase.direction;
      });

  return (iter == ases_.end()) ? nullptr : &(*iter);
}

struct ase* LeAudioDevice::GetNextActiveAseWithDifferentDirection(
    struct ase* base_ase) {
  auto iter = std::find_if(ases_.begin(), ases_.end(),
                           [&base_ase](auto& ase) { return base_ase == &ase; });

  /* Invalid ase given */
  if (std::distance(iter, ases_.end()) < 1) {
    LOG_DEBUG("ASE %d does not use bidirectional CIS", base_ase->id);
    return nullptr;
  }

  iter =
      std::find_if(std::next(iter, 1), ases_.end(), [&iter](const auto& ase) {
        return ase.active && iter->direction != ase.direction;
      });

  if (iter == ases_.end()) {
    return nullptr;
  }

  return &(*iter);
}

struct ase* LeAudioDevice::GetFirstActiveAseByDataPathState(
    types::AudioStreamDataPathState state) {
  auto iter =
      std::find_if(ases_.begin(), ases_.end(), [state](const auto& ase) {
        return (ase.active && (ase.data_path_state == state));
      });

  return (iter == ases_.end()) ? nullptr : &(*iter);
}

struct ase* LeAudioDevice::GetFirstInactiveAse(uint8_t direction,
                                               bool reuse_cis_id) {
  auto iter = std::find_if(ases_.begin(), ases_.end(),
                           [direction, reuse_cis_id](const auto& ase) {
                             if (ase.active || (ase.direction != direction))
                               return false;

                             if (!reuse_cis_id) return true;

                             return (ase.cis_id != kInvalidCisId);
                           });
  /* If ASE is found, return it */
  if (iter != ases_.end()) return &(*iter);

  /* If reuse was not set, that means there is no inactive ASE available. */
  if (!reuse_cis_id) return nullptr;

  /* Since there is no ASE with assigned CIS ID, it means new configuration
   * needs more ASEs then it was configured before.
   * Let's find just inactive one */
  iter = std::find_if(ases_.begin(), ases_.end(),
                      [direction](const auto& ase) {
                        if (ase.active || (ase.direction != direction))
                          return false;
                        return true;
                      });

  return (iter == ases_.end()) ? nullptr : &(*iter);
}

struct ase* LeAudioDevice::GetNextActiveAse(struct ase* base_ase) {
  auto iter = std::find_if(ases_.begin(), ases_.end(),
                           [&base_ase](auto& ase) { return base_ase == &ase; });

  /* Invalid ase given */
  if (iter == ases_.end() || std::distance(iter, ases_.end()) < 1)
    return nullptr;

  iter = std::find_if(std::next(iter, 1), ases_.end(),
                      [](const auto& ase) { return ase.active; });

  return (iter == ases_.end()) ? nullptr : &(*iter);
}

struct ase* LeAudioDevice::GetAseToMatchBidirectionCis(struct ase* base_ase) {
  auto iter = std::find_if(ases_.begin(), ases_.end(), [&base_ase](auto& ase) {
    return (base_ase->cis_conn_hdl == ase.cis_conn_hdl) &&
           (base_ase->direction != ase.direction);
  });
  return (iter == ases_.end()) ? nullptr : &(*iter);
}

BidirectAsesPair LeAudioDevice::GetAsesByCisConnHdl(uint16_t conn_hdl) {
  BidirectAsesPair ases = {nullptr, nullptr};

  for (auto& ase : ases_) {
    if (ase.cis_conn_hdl == conn_hdl) {
      if (ase.direction == types::kLeAudioDirectionSink) {
        ases.sink = &ase;
      } else {
        ases.source = &ase;
      }
    }
  }

  return ases;
}

BidirectAsesPair LeAudioDevice::GetAsesByCisId(uint8_t cis_id) {
  BidirectAsesPair ases = {nullptr, nullptr};

  for (auto& ase : ases_) {
    if (ase.cis_id == cis_id) {
      if (ase.direction == types::kLeAudioDirectionSink) {
        ases.sink = &ase;
      } else {
        ases.source = &ase;
      }
    }
  }

  return ases;
}

bool LeAudioDevice::HaveActiveAse(void) {
  auto iter = std::find_if(ases_.begin(), ases_.end(),
                           [](const auto& ase) { return ase.active; });

  return iter != ases_.end();
}

bool LeAudioDevice::HaveAnyUnconfiguredAses(void) {
  /* In configuring state when active in Idle or Configured and reconfigure */
  auto iter = std::find_if(ases_.begin(), ases_.end(), [](const auto& ase) {
    if (!ase.active) return false;

    if (ase.state == AseState::BTA_LE_AUDIO_ASE_STATE_IDLE ||
        ((ase.state == AseState::BTA_LE_AUDIO_ASE_STATE_CODEC_CONFIGURED) &&
         ase.reconfigure))
      return true;

    return false;
  });

  return iter != ases_.end();
}

bool LeAudioDevice::HaveAllActiveAsesSameState(AseState state) {
  auto iter = std::find_if(
      ases_.begin(), ases_.end(),
      [&state](const auto& ase) { return ase.active && (ase.state != state); });

  return iter == ases_.end();
}

bool LeAudioDevice::IsReadyToCreateStream(void) {
  auto iter = std::find_if(ases_.begin(), ases_.end(), [](const auto& ase) {
    if (!ase.active) return false;

    if (ase.direction == types::kLeAudioDirectionSink &&
        (ase.state != AseState::BTA_LE_AUDIO_ASE_STATE_STREAMING &&
         ase.state != AseState::BTA_LE_AUDIO_ASE_STATE_ENABLING))
      return true;

    if (ase.direction == types::kLeAudioDirectionSource &&
        ase.state != AseState::BTA_LE_AUDIO_ASE_STATE_ENABLING)
      return true;

    return false;
  });

  return iter == ases_.end();
}

bool LeAudioDevice::IsReadyToSuspendStream(void) {
  auto iter = std::find_if(ases_.begin(), ases_.end(), [](const auto& ase) {
    if (!ase.active) return false;

    if (ase.direction == types::kLeAudioDirectionSink &&
        ase.state != AseState::BTA_LE_AUDIO_ASE_STATE_QOS_CONFIGURED)
      return true;

    if (ase.direction == types::kLeAudioDirectionSource &&
        ase.state != AseState::BTA_LE_AUDIO_ASE_STATE_DISABLING)
      return true;

    return false;
  });

  return iter == ases_.end();
}

bool LeAudioDevice::HaveAllActiveAsesCisEst(void) {
  if (ases_.empty()) {
    LOG_WARN("No ases for device %s", address_.ToString().c_str());
    return false;
  }

  auto iter = std::find_if(ases_.begin(), ases_.end(), [](const auto& ase) {
    return ase.active &&
           (ase.data_path_state != AudioStreamDataPathState::CIS_ESTABLISHED);
  });

  return iter == ases_.end();
}

bool LeAudioDevice::HaveAllAsesCisDisc(void) {
  auto iter = std::find_if(ases_.begin(), ases_.end(), [](const auto& ase) {
    return ase.active &&
           (ase.data_path_state != AudioStreamDataPathState::CIS_ASSIGNED);
  });

  return iter == ases_.end();
}

bool LeAudioDevice::HasCisId(uint8_t id) {
  struct ase* ase = GetFirstActiveAse();

  while (ase) {
    if (ase->cis_id == id) return true;
    ase = GetNextActiveAse(ase);
  }

  return false;
}

uint8_t LeAudioDevice::GetMatchingBidirectionCisId(
    const struct types::ase* base_ase) {
  for (auto& ase : ases_) {
    auto& cis = ase.cis_id;
    if (!ase.active) continue;

    int num_cises =
        std::count_if(ases_.begin(), ases_.end(), [&cis](const auto& iter_ase) {
          return iter_ase.active && iter_ase.cis_id == cis;
        });

    /*
     * If there is only one ASE for device with unique CIS ID and opposite to
     * direction - it may be bi-directional/completive.
     */
    if (num_cises == 1 &&
        ((base_ase->direction == types::kLeAudioDirectionSink &&
          ase.direction == types::kLeAudioDirectionSource) ||
         (base_ase->direction == types::kLeAudioDirectionSource &&
          ase.direction == types::kLeAudioDirectionSink))) {
      return ase.cis_id;
    }
  }

  return kInvalidCisId;
}

uint8_t LeAudioDevice::GetLc3SupportedChannelCount(uint8_t direction) {
  auto& pacs =
      direction == types::kLeAudioDirectionSink ? snk_pacs_ : src_pacs_;

  if (pacs.size() == 0) {
    LOG(ERROR) << __func__ << " missing PAC for direction " << +direction;
    return 0;
  }

  for (const auto& pac_tuple : pacs) {
    /* Get PAC records from tuple as second element from tuple */
    auto& pac_recs = std::get<1>(pac_tuple);

    for (const auto pac : pac_recs) {
      if (pac.codec_id.coding_format != types::kLeAudioCodingFormatLC3)
        continue;

      auto supported_channel_count_ltv = pac.codec_spec_caps.Find(
          codec_spec_caps::kLeAudioCodecLC3TypeAudioChannelCounts);

      return VEC_UINT8_TO_UINT8(supported_channel_count_ltv.value());
    };
  }

  return 0;
}

const struct types::acs_ac_record*
LeAudioDevice::GetCodecConfigurationSupportedPac(
    uint8_t direction, const CodecCapabilitySetting& codec_capability_setting) {
  auto& pacs =
      direction == types::kLeAudioDirectionSink ? snk_pacs_ : src_pacs_;

  if (pacs.size() == 0) {
    LOG_ERROR("missing PAC for direction %d", direction);
    return nullptr;
  }

  /* TODO: Validate channel locations */

  for (const auto& pac_tuple : pacs) {
    /* Get PAC records from tuple as second element from tuple */
    auto& pac_recs = std::get<1>(pac_tuple);

    for (const auto& pac : pac_recs) {
      if (!IsCodecCapabilitySettingSupported(pac, codec_capability_setting))
        continue;

      return &pac;
    };
  }

  /* Doesn't match required configuration with any PAC */
  return nullptr;
}

/**
 * Returns supported PHY's bitfield
 */
uint8_t LeAudioDevice::GetPhyBitmask(void) {
  uint8_t phy_bitfield = kIsoCigPhy1M;

  if (BTM_IsPhy2mSupported(address_, BT_TRANSPORT_LE))
    phy_bitfield |= kIsoCigPhy2M;

  return phy_bitfield;
}

void LeAudioDevice::SetSupportedContexts(AudioContexts snk_contexts,
                                         AudioContexts src_contexts) {
  supp_snk_context_ = snk_contexts;
  supp_src_context_ = src_contexts;
}

void LeAudioDevice::Dump(int fd) {
  std::stringstream stream;
  stream << std::boolalpha;
  stream << "\n\taddress: " << address_
         << (conn_id_ == GATT_INVALID_CONN_ID ? "\n\t  Not connected "
                                              : "\n\t  Connected conn_id =")
         << (conn_id_ == GATT_INVALID_CONN_ID ? "" : std::to_string(conn_id_))
         << "\n\t  set member: " << csis_member_
         << "\n\t  known_service_handles_: " << known_service_handles_
         << "\n\t  notify_connected_after_read_: "
         << notify_connected_after_read_
         << "\n\t  removing_device_: " << removing_device_
         << "\n\t  first_connection_: " << first_connection_
         << "\n\t  encrypted_: " << encrypted_
         << "\n\t  connecting_actively_: " << connecting_actively_
         << "\n\t  number of ases_: " << static_cast<int>(ases_.size());

  if (ases_.size() > 0) {
    stream << "\n\t  == ASE == ";
    for (auto& ase : ases_) {
      stream << "\n\t  id: " << static_cast<int>(ase.id)
             << ", active: " << ase.active << ", direction: "
             << (ase.direction == types::kLeAudioDirectionSink ? "sink"
                                                               : "source")
             << ", allocated cis id: " << static_cast<int>(ase.cis_id);
    }
  }

  dprintf(fd, "%s", stream.str().c_str());
}

void LeAudioDevice::DisconnectAcl(void) {
  if (conn_id_ == GATT_INVALID_CONN_ID) return;

  uint16_t acl_handle =
      BTM_GetHCIConnHandle(address_, BT_TRANSPORT_LE);
  if (acl_handle != HCI_INVALID_HANDLE) {
    acl_disconnect_from_handle(acl_handle, HCI_ERR_PEER_USER,
                               "bta::le_audio::client disconnect");
  }
}

AudioContexts LeAudioDevice::GetAvailableContexts(void) {
  return avail_snk_contexts_ | avail_src_contexts_;
}

/* Returns XOR of updated sink and source bitset context types */
AudioContexts LeAudioDevice::SetAvailableContexts(AudioContexts snk_contexts,
                                                  AudioContexts src_contexts) {
  AudioContexts updated_contexts;

  updated_contexts = snk_contexts ^ avail_snk_contexts_;
  updated_contexts |= src_contexts ^ avail_src_contexts_;

  LOG_DEBUG(
      "\n\t avail_snk_contexts_: %s \n\t avail_src_contexts_: %s  \n\t "
      "snk_contexts: %s \n\t src_contexts: %s \n\t updated_contexts: %s",
      avail_snk_contexts_.to_string().c_str(),
      avail_src_contexts_.to_string().c_str(), snk_contexts.to_string().c_str(),
      src_contexts.to_string().c_str(), updated_contexts.to_string().c_str());

  avail_snk_contexts_ = snk_contexts;
  avail_src_contexts_ = src_contexts;

  return updated_contexts;
}

bool LeAudioDevice::ActivateConfiguredAses(LeAudioContextType context_type) {
  if (conn_id_ == GATT_INVALID_CONN_ID) {
    LOG_WARN(" Device %s is not connected ", address_.ToString().c_str());
    return false;
  }

  bool ret = false;

  LOG_INFO(" Configuring device %s", address_.ToString().c_str());
  for (auto& ase : ases_) {
    if (!ase.active &&
        ase.state == AseState::BTA_LE_AUDIO_ASE_STATE_CODEC_CONFIGURED &&
        ase.configured_for_context_type == context_type) {
      LOG_INFO(
          " conn_id: %d, ase id %d, cis id %d, cis_handle 0x%04x is activated.",
          conn_id_, ase.id, ase.cis_id, ase.cis_conn_hdl);
      ase.active = true;
      ret = true;
    }
  }

  return ret;
}

void LeAudioDevice::DeactivateAllAses(void) {
  /* Just clear states and keep previous configuration for use
   * in case device will get reconnected
   */
  for (auto& ase : ases_) {
    if (ase.active) {
      ase.state = AseState::BTA_LE_AUDIO_ASE_STATE_IDLE;
      ase.data_path_state = AudioStreamDataPathState::IDLE;
      ase.active = false;
    }
  }
}

std::vector<uint8_t> LeAudioDevice::GetMetadata(
    AudioContexts context_type, const std::vector<uint8_t>& ccid_list) {
  std::vector<uint8_t> metadata;

  AppendMetadataLtvEntryForStreamingContext(metadata, context_type);
  AppendMetadataLtvEntryForCcidList(metadata, ccid_list);

  return std::move(metadata);
}

bool LeAudioDevice::IsMetadataChanged(AudioContexts context_type,
                                      const std::vector<uint8_t>& ccid_list) {
  for (auto* ase = this->GetFirstActiveAse(); ase;
       ase = this->GetNextActiveAse(ase)) {
    if (this->GetMetadata(context_type, ccid_list) != ase->metadata)
      return true;
  }

  return false;
}

LeAudioDeviceGroup* LeAudioDeviceGroups::Add(int group_id) {
  /* Get first free group id */
  if (FindById(group_id)) {
    LOG(ERROR) << __func__
               << ", group already exists, id: " << loghex(group_id);
    return nullptr;
  }

  return (groups_.emplace_back(std::make_unique<LeAudioDeviceGroup>(group_id)))
      .get();
}

void LeAudioDeviceGroups::Remove(int group_id) {
  auto iter = std::find_if(
      groups_.begin(), groups_.end(),
      [&group_id](auto const& group) { return group->group_id_ == group_id; });

  if (iter == groups_.end()) {
    LOG(ERROR) << __func__ << ", no such group_id: " << group_id;
    return;
  }

  groups_.erase(iter);
}

LeAudioDeviceGroup* LeAudioDeviceGroups::FindById(int group_id) {
  auto iter = std::find_if(
      groups_.begin(), groups_.end(),
      [&group_id](auto const& group) { return group->group_id_ == group_id; });

  return (iter == groups_.end()) ? nullptr : iter->get();
}

void LeAudioDeviceGroups::Cleanup(void) {
  for (auto& g : groups_) {
    g->Cleanup();
  }

  groups_.clear();
}

void LeAudioDeviceGroups::Dump(int fd) {
  for (auto& g : groups_) {
    g->Dump(fd);
  }
}

bool LeAudioDeviceGroups::IsAnyInTransition(void) {
  for (auto& g : groups_) {
    if (g->IsInTransition()) {
      DLOG(INFO) << __func__ << " group: " << g->group_id_
                 << " is in transition";
      return true;
    }
  }
  return false;
}

size_t LeAudioDeviceGroups::Size() { return (groups_.size()); }

std::vector<int> LeAudioDeviceGroups::GetGroupsIds(void) {
  std::vector<int> result;

  for (auto const& group : groups_) {
    result.push_back(group->group_id_);
  }

  return result;
}

/* LeAudioDevices Class methods implementation */
void LeAudioDevices::Add(const RawAddress& address, bool first_connection,
                         int group_id) {
  auto device = FindByAddress(address);
  if (device != nullptr) {
    LOG(ERROR) << __func__ << ", address: " << address
               << " is already assigned to group: " << device->group_id_;
    return;
  }

  leAudioDevices_.emplace_back(
      std::make_shared<LeAudioDevice>(address, first_connection, group_id));
}

void LeAudioDevices::Remove(const RawAddress& address) {
  auto iter = std::find_if(leAudioDevices_.begin(), leAudioDevices_.end(),
                           [&address](auto const& leAudioDevice) {
                             return leAudioDevice->address_ == address;
                           });

  if (iter == leAudioDevices_.end()) {
    LOG(ERROR) << __func__ << ", no such address: " << address;
    return;
  }

  leAudioDevices_.erase(iter);
}

LeAudioDevice* LeAudioDevices::FindByAddress(const RawAddress& address) {
  auto iter = std::find_if(leAudioDevices_.begin(), leAudioDevices_.end(),
                           [&address](auto const& leAudioDevice) {
                             return leAudioDevice->address_ == address;
                           });

  return (iter == leAudioDevices_.end()) ? nullptr : iter->get();
}

std::shared_ptr<LeAudioDevice> LeAudioDevices::GetByAddress(
    const RawAddress& address) {
  auto iter = std::find_if(leAudioDevices_.begin(), leAudioDevices_.end(),
                           [&address](auto const& leAudioDevice) {
                             return leAudioDevice->address_ == address;
                           });

  return (iter == leAudioDevices_.end()) ? nullptr : *iter;
}

LeAudioDevice* LeAudioDevices::FindByConnId(uint16_t conn_id) {
  auto iter = std::find_if(leAudioDevices_.begin(), leAudioDevices_.end(),
                           [&conn_id](auto const& leAudioDevice) {
                             return leAudioDevice->conn_id_ == conn_id;
                           });

  return (iter == leAudioDevices_.end()) ? nullptr : iter->get();
}

LeAudioDevice* LeAudioDevices::FindByCisConnHdl(const uint16_t conn_hdl) {
  auto iter = std::find_if(leAudioDevices_.begin(), leAudioDevices_.end(),
                           [&conn_hdl](auto& d) {
                             LeAudioDevice* dev;
                             BidirectAsesPair ases;

                             dev = d.get();
                             ases = dev->GetAsesByCisConnHdl(conn_hdl);
                             if (ases.sink || ases.source)
                               return true;
                             else
                               return false;
                           });

  if (iter == leAudioDevices_.end()) return nullptr;

  return iter->get();
}

size_t LeAudioDevices::Size() { return (leAudioDevices_.size()); }

void LeAudioDevices::Dump(int fd, int group_id) {
  for (auto const& device : leAudioDevices_) {
    if (device->group_id_ == group_id) {
      device->Dump(fd);
    }
  }
}

void LeAudioDevices::Cleanup(void) {
  for (auto const& device : leAudioDevices_) {
    if (device->conn_id_ != GATT_INVALID_CONN_ID) {
      BtaGattQueue::Clean(device->conn_id_);
      BTA_GATTC_Close(device->conn_id_);
      device->DisconnectAcl();
    }
  }
  leAudioDevices_.clear();
}

}  // namespace le_audio
