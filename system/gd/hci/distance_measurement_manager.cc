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
#include "hci/distance_measurement_manager.h"

#include <math.h>

#include <unordered_map>

#include "common/strings.h"
#include "hci/acl_manager.h"
#include "hci/distance_measurement_interface.h"
#include "hci/event_checkers.h"
#include "hci/hci_layer.h"
#include "module.h"
#include "os/handler.h"
#include "os/log.h"

namespace bluetooth {
namespace hci {

const ModuleFactory DistanceMeasurementManager::Factory =
    ModuleFactory([]() { return new DistanceMeasurementManager(); });
static constexpr uint16_t kIllegalConnectionHandle = 0xffff;
static constexpr uint8_t kTxPowerNotAvailable = 0xfe;
static constexpr int8_t kRSSIDropOffAt1M = 41;
static constexpr uint8_t kCsMaxTxPower = 12;  // 12 dBm
static constexpr CsSyncAntennaSelection kCsSyncAntennaSelection = CsSyncAntennaSelection::ANTENNA_2;
static constexpr uint8_t kConfigId = 0x01;  // Use 0x01 to create config and enable procedure
static constexpr uint8_t kMinMainModeSteps = 0x02;
static constexpr uint8_t kMaxMainModeSteps = 0x05;
static constexpr uint8_t kMainModeRepetition = 0x00;  // No repetition
static constexpr uint8_t kMode0Steps =
    0x03;  // Maximum number of mode-0 steps to increase success subevent rate
static constexpr uint8_t kChannelMapRepetition = 0x01;  // No repetition
static constexpr uint8_t kCh3cJump = 0x03;              // Skip 3 Channels
static constexpr uint16_t kMaxProcedureLen = 0xFFFF;    // 40.959375s
static constexpr uint16_t kMinProcedureInterval = 0x01;
static constexpr uint16_t kMaxProcedureInterval = 0xFF;
static constexpr uint16_t kMaxProcedureCount = 0x01;
static constexpr uint32_t kMinSubeventLen = 0x0004E2;         // 1250us
static constexpr uint32_t kMaxSubeventLen = 0x3d0900;         // 4s
static constexpr uint8_t kToneAntennaConfigSelection = 0x07;  // 2x2
static constexpr uint8_t kTxPwrDelta = 0x00;

struct DistanceMeasurementManager::impl {
  ~impl() {}
  void start(os::Handler* handler, hci::HciLayer* hci_layer, hci::AclManager* acl_manager) {
    handler_ = handler;
    hci_layer_ = hci_layer;
    acl_manager_ = acl_manager;
    hci_layer_->RegisterLeEventHandler(
        hci::SubeventCode::TRANSMIT_POWER_REPORTING,
        handler_->BindOn(this, &impl::on_transmit_power_reporting));
    distance_measurement_interface_ = hci_layer_->GetDistanceMeasurementInterface(
        handler_->BindOn(this, &DistanceMeasurementManager::impl::handle_event));
    distance_measurement_interface_->EnqueueCommand(
        LeCsReadLocalSupportedCapabilitiesBuilder::Create(),
        handler_->BindOnceOn(this, &impl::on_cs_read_local_supported_capabilities));
  }

  void stop() {
    hci_layer_->UnregisterLeEventHandler(hci::SubeventCode::TRANSMIT_POWER_REPORTING);
  }

  void register_distance_measurement_callbacks(DistanceMeasurementCallbacks* callbacks) {
    distance_measurement_callbacks_ = callbacks;
  }

  void start_distance_measurement(
      const Address& address, uint16_t frequency, DistanceMeasurementMethod method) {
    LOG_INFO("Address:%s, method:%d", ADDRESS_TO_LOGGABLE_CSTR(address), method);
    uint16_t connection_handle = acl_manager_->HACK_GetLeHandle(address);

    // Remove this check if we support any connection less method
    if (connection_handle == kIllegalConnectionHandle) {
      LOG_WARN("Can't find any LE connection for %s", ADDRESS_TO_LOGGABLE_CSTR(address));
      distance_measurement_callbacks_->OnDistanceMeasurementStartFail(
          address, REASON_NO_LE_CONNECTION, method);
      return;
    }

    switch (method) {
      case METHOD_AUTO:
      case METHOD_RSSI: {
        if (rssi_trackers.find(address) == rssi_trackers.end()) {
          rssi_trackers[address].handle = connection_handle;
          rssi_trackers[address].frequency = frequency;
          rssi_trackers[address].remote_tx_power = kTxPowerNotAvailable;
          rssi_trackers[address].started = false;
          rssi_trackers[address].alarm = std::make_unique<os::Alarm>(handler_);
          hci_layer_->EnqueueCommand(
              LeReadRemoteTransmitPowerLevelBuilder::Create(
                  acl_manager_->HACK_GetLeHandle(address), 0x01),
              handler_->BindOnceOn(
                  this, &impl::on_read_remote_transmit_power_level_status, address));
        } else {
          rssi_trackers[address].frequency = frequency;
        }
      } break;
      case METHOD_CS: {
        start_distance_measurement_with_cs(address, connection_handle);
      } break;
    }
  }

  void start_distance_measurement_with_cs(
      const Address& cs_remote_address, uint16_t connection_handle) {
    LOG_INFO(
        "connection_handle: %d, address: %s",
        connection_handle,
        ADDRESS_TO_LOGGABLE_CSTR(cs_remote_address));
    if (cs_trackers_.find(connection_handle) != cs_trackers_.end() &&
        cs_trackers_[connection_handle].address != cs_remote_address) {
      LOG_WARN("Remove old tracker for %s ", ADDRESS_TO_LOGGABLE_CSTR(cs_remote_address));
      cs_trackers_.erase(connection_handle);
    }

    if (cs_trackers_.find(connection_handle) == cs_trackers_.end()) {
      // Create a cs tracker with role initiator
      cs_trackers_[connection_handle].address = cs_remote_address;
      // TODO: Check ROLE via CS config. (b/304295768)
      cs_trackers_[connection_handle].role = CsRole::INITIATOR;
    }

    if (!cs_trackers_[connection_handle].setup_complete) {
      send_le_cs_read_remote_supported_capabilities(connection_handle);
      send_le_cs_set_default_settings(connection_handle);
      send_le_cs_security_enable(connection_handle);
    }
  }

  void stop_distance_measurement(const Address& address, DistanceMeasurementMethod method) {
    LOG_INFO("Address:%s, method:%d", ADDRESS_TO_LOGGABLE_CSTR(address), method);
    switch (method) {
      case METHOD_AUTO:
      case METHOD_RSSI: {
        if (rssi_trackers.find(address) == rssi_trackers.end()) {
          LOG_WARN("Can't find rssi tracker for %s ", ADDRESS_TO_LOGGABLE_CSTR(address));
        } else {
          hci_layer_->EnqueueCommand(
              LeSetTransmitPowerReportingEnableBuilder::Create(
                  rssi_trackers[address].handle, 0x00, 0x00),
              handler_->BindOnce(check_complete<LeSetTransmitPowerReportingEnableCompleteView>));
          rssi_trackers[address].alarm->Cancel();
          rssi_trackers[address].alarm.reset();
          rssi_trackers.erase(address);
        }
      } break;
      case METHOD_CS: {
        uint16_t connection_handle = acl_manager_->HACK_GetLeHandle(address);
        if (cs_trackers_.find(connection_handle) == cs_trackers_.end()) {
          LOG_WARN("Can't find CS tracker for %s ", ADDRESS_TO_LOGGABLE_CSTR(address));
        } else {
          cs_trackers_.erase(connection_handle);
        }
      } break;
    }
  }

  void read_rssi_regularly(const Address& address, uint16_t frequency) {
    if (rssi_trackers.find(address) == rssi_trackers.end()) {
      LOG_WARN("Can't find rssi tracker for %s ", ADDRESS_TO_LOGGABLE_CSTR(address));
      return;
    }
    uint16_t connection_handle = acl_manager_->HACK_GetLeHandle(address);
    if (connection_handle == kIllegalConnectionHandle) {
      LOG_WARN("Can't find connection for %s ", ADDRESS_TO_LOGGABLE_CSTR(address));
      if (rssi_trackers.find(address) != rssi_trackers.end()) {
        distance_measurement_callbacks_->OnDistanceMeasurementStopped(
            address, REASON_NO_LE_CONNECTION, METHOD_RSSI);
        rssi_trackers[address].alarm->Cancel();
        rssi_trackers[address].alarm.reset();
        rssi_trackers.erase(address);
      }
      return;
    }

    hci_layer_->EnqueueCommand(
        ReadRssiBuilder::Create(connection_handle),
        handler_->BindOnceOn(this, &impl::on_read_rssi_complete, address));

    rssi_trackers[address].alarm->Schedule(
        common::BindOnce(&impl::read_rssi_regularly, common::Unretained(this), address, frequency),
        std::chrono::milliseconds(rssi_trackers[address].frequency));
  }

  void handle_event(LeMetaEventView event) {
    if (!event.IsValid()) {
      LOG_ERROR("Received invalid LeMetaEventView");
      return;
    }
    switch (event.GetSubeventCode()) {
      case hci::SubeventCode::LE_CS_TEST_END_COMPLETE:
      case hci::SubeventCode::LE_CS_SUBEVENT_RESULT_CONTINUE:
      case hci::SubeventCode::LE_CS_SUBEVENT_RESULT:
      case hci::SubeventCode::LE_CS_READ_REMOTE_FAE_TABLE_COMPLETE: {
        LOG_WARN("Unhandled subevent %s", hci::SubeventCodeText(event.GetSubeventCode()).c_str());
      } break;
      case hci::SubeventCode::LE_CS_PROCEDURE_ENABLE_COMPLETE: {
        on_cs_procedure_enable_complete(LeCsProcedureEnableCompleteView::Create(event));
      } break;
      case hci::SubeventCode::LE_CS_CONFIG_COMPLETE: {
        on_cs_config_complete(LeCsConfigCompleteView::Create(event));
      } break;
      case hci::SubeventCode::LE_CS_SECURITY_ENABLE_COMPLETE: {
        on_cs_security_enable_complete(LeCsSecurityEnableCompleteView::Create(event));
      } break;
      case hci::SubeventCode::LE_CS_READ_REMOTE_SUPPORTED_CAPABILITIES_COMPLETE: {
        on_cs_read_remote_supported_capabilities_complete(
            LeCsReadRemoteSupportedCapabilitiesCompleteView::Create(event));
      } break;
      default:
        LOG_INFO("Unknown subevent %s", hci::SubeventCodeText(event.GetSubeventCode()).c_str());
    }
  }

  void send_le_cs_read_local_supported_capabilities() {
    hci_layer_->EnqueueCommand(
        LeCsReadLocalSupportedCapabilitiesBuilder::Create(),
        handler_->BindOnceOn(this, &impl::on_cs_read_local_supported_capabilities));
  }

  void send_le_cs_read_remote_supported_capabilities(uint16_t connection_handle) {
    hci_layer_->EnqueueCommand(
        LeCsReadRemoteSupportedCapabilitiesBuilder::Create(connection_handle),
        handler_->BindOnce(check_status<LeCsReadRemoteSupportedCapabilitiesStatusView>));
  }

  void send_le_cs_security_enable(uint16_t connection_handle) {
    hci_layer_->EnqueueCommand(
        LeCsSecurityEnableBuilder::Create(connection_handle),
        handler_->BindOnce(check_status<LeCsSecurityEnableStatusView>));
  }

  void send_le_cs_set_default_settings(uint16_t connection_handle) {
    uint8_t role_enable = (1 << (uint8_t)CsRole::INITIATOR) | 1 << ((uint8_t)CsRole::REFLECTOR);
    hci_layer_->EnqueueCommand(
        LeCsSetDefaultSettingsBuilder::Create(
            connection_handle,
            role_enable,
            kCsSyncAntennaSelection,
            kCsMaxTxPower  // max_tx_power
            ),
        handler_->BindOnceOn(this, &impl::on_cs_set_default_settings_complete));
  }

  void send_le_cs_create_config(uint16_t connection_handle) {
    auto channel_vector = common::FromHexString("1FFFFFFFFFFFFC7FFFFC");  // use all 72 Channel
    std::array<uint8_t, 10> channel_map;
    std::copy(channel_vector->begin(), channel_vector->end(), channel_map.begin());
    std::reverse(channel_map.begin(), channel_map.end());
    hci_layer_->EnqueueCommand(
        LeCsCreateConfigBuilder::Create(
            connection_handle,
            kConfigId,
            CsCreateContext::BOTH_LOCAL_AND_REMOTE_CONTROLLER,
            CsMainModeType::MODE_2,
            CsSubModeType::UNUSED,
            kMinMainModeSteps,
            kMaxMainModeSteps,
            kMainModeRepetition,
            kMode0Steps,
            CsRole::INITIATOR,
            CsConfigRttType::RTT_WITH_128_BIT_RANDOM_SEQUENCE,
            CsSyncPhy::LE_1M_PHY,
            channel_map,
            kChannelMapRepetition,
            CsChannelSelectionType::TYPE_3B,
            CsCh3cShape::HAT_SHAPE,
            kCh3cJump,
            Enable::DISABLED),
        handler_->BindOnce(check_status<LeCsCreateConfigStatusView>));
  }

  void send_le_cs_set_procedure_parameters(uint16_t connection_handle) {
    CsPreferredPeerAntenna preferred_peer_antenna;
    hci_layer_->EnqueueCommand(
        LeCsSetProcedureParametersBuilder::Create(
            connection_handle,
            kConfigId,
            kMaxProcedureLen,
            kMinProcedureInterval,
            kMaxProcedureInterval,
            kMaxProcedureCount,
            kMinSubeventLen,
            kMaxSubeventLen,
            kToneAntennaConfigSelection,
            CsPhy::LE_1M_PHY,
            kTxPwrDelta,
            preferred_peer_antenna),
        handler_->BindOnceOn(this, &impl::on_cs_set_procedure_parameters));
  }

  void send_le_cs_procedure_enable(uint16_t connection_handle, Enable enable) {
    hci_layer_->EnqueueCommand(
        LeCsProcedureEnableBuilder::Create(connection_handle, kConfigId, enable),
        handler_->BindOnce(check_status<LeCsProcedureEnableStatusView>));
  }

  void on_cs_read_local_supported_capabilities(CommandCompleteView view) {
    auto complete_view = LeCsReadLocalSupportedCapabilitiesCompleteView::Create(view);
    if (!complete_view.IsValid()) {
      LOG_WARN("Get invalid LeCsReadLocalSupportedCapabilitiesComplete");
      is_channel_sounding_supported_ = false;
      return;
    } else if (complete_view.GetStatus() != ErrorCode::SUCCESS) {
      std::string error_code = ErrorCodeText(complete_view.GetStatus());
      LOG_WARN(
          "Received LeCsReadLocalSupportedCapabilitiesComplete with error code %s",
          error_code.c_str());
      is_channel_sounding_supported_ = false;
      return;
    }
    is_channel_sounding_supported_ = true;
    cs_subfeature_supported_ = complete_view.GetOptionalSubfeaturesSupported();
  }

  void on_cs_read_remote_supported_capabilities_complete(
      LeCsReadRemoteSupportedCapabilitiesCompleteView event_view) {
    if (!event_view.IsValid()) {
      LOG_WARN("Get invalid LeCsReadRemoteSupportedCapabilitiesCompleteView");
      return;
    } else if (event_view.GetStatus() != ErrorCode::SUCCESS) {
      std::string error_code = ErrorCodeText(event_view.GetStatus());
      LOG_WARN(
          "Received LeCsReadRemoteSupportedCapabilitiesCompleteView with error code %s",
          error_code.c_str());
      return;
    }
    uint16_t connection_handle = event_view.GetConnectionHandle();
    if (cs_trackers_.find(connection_handle) == cs_trackers_.end()) {
      // Create a cs tracker with role reflector
      // TODO: Check ROLE via CS config. (b/304295768)
      cs_trackers_[connection_handle].role = CsRole::REFLECTOR;
      send_le_cs_set_default_settings(event_view.GetConnectionHandle());
    }

    if (event_view.GetOptionalSubfeaturesSupported().phase_based_ranging_ == 0x01) {
      cs_trackers_[connection_handle].remote_support_phase_based_ranging = true;
    }
    LOG_INFO(
        "connection_handle:%d, num_antennas_supported:%d, max_antenna_paths_supported:%d, "
        "roles_supported:%s, phase_based_ranging_supported: %d ",
        event_view.GetConnectionHandle(),
        event_view.GetNumAntennasSupported(),
        event_view.GetMaxAntennaPathsSupported(),
        event_view.GetRolesSupported().ToString().c_str(),
        event_view.GetOptionalSubfeaturesSupported().phase_based_ranging_);
  }

  void on_cs_set_default_settings_complete(CommandCompleteView view) {
    auto complete_view = LeCsSetDefaultSettingsCompleteView::Create(view);
    if (!complete_view.IsValid()) {
      LOG_WARN("Get invalid LeCsSetDefaultSettingsComplete");
      return;
    } else if (complete_view.GetStatus() != ErrorCode::SUCCESS) {
      std::string error_code = ErrorCodeText(complete_view.GetStatus());
      LOG_WARN("Received LeCsSetDefaultSettingsComplete with error code %s", error_code.c_str());
      return;
    }
  }

  void on_cs_security_enable_complete(LeCsSecurityEnableCompleteView event_view) {
    if (!event_view.IsValid()) {
      LOG_WARN("Get invalid LeCsSecurityEnableCompleteView");
      return;
    } else if (event_view.GetStatus() != ErrorCode::SUCCESS) {
      std::string error_code = ErrorCodeText(event_view.GetStatus());
      LOG_WARN("Received LeCsSecurityEnableCompleteView with error code %s", error_code.c_str());
      return;
    }
    uint16_t connection_handle = event_view.GetConnectionHandle();
    if (cs_trackers_.find(connection_handle) == cs_trackers_.end()) {
      LOG_WARN("Can't find cs tracker for connection_handle %d", connection_handle);
      return;
    }
    cs_trackers_[connection_handle].setup_complete = true;
    LOG_INFO(
        "Setup phase complete, connection_handle: %d, address: %s",
        connection_handle,
        ADDRESS_TO_LOGGABLE_CSTR(cs_trackers_[connection_handle].address));
    if (cs_trackers_[connection_handle].role == CsRole::INITIATOR) {
      send_le_cs_create_config(connection_handle);
    }
  }

  void on_cs_config_complete(LeCsConfigCompleteView event_view) {
    if (!event_view.IsValid()) {
      LOG_WARN("Get invalid LeCsConfigCompleteView");
      return;
    } else if (event_view.GetStatus() != ErrorCode::SUCCESS) {
      std::string error_code = ErrorCodeText(event_view.GetStatus());
      LOG_WARN("Received LeCsConfigCompleteView with error code %s", error_code.c_str());
      return;
    }
    uint16_t connection_handle = event_view.GetConnectionHandle();
    if (cs_trackers_.find(connection_handle) == cs_trackers_.end()) {
      LOG_WARN("Can't find cs tracker for connection_handle %d", connection_handle);
      return;
    }
    if (event_view.GetAction() == CsAction::CONFIG_REMOVED) {
      return;
    }
    LOG_INFO("Get %s", event_view.ToString().c_str());
    cs_trackers_[connection_handle].role = event_view.GetRole();
    cs_trackers_[connection_handle].config_set = true;
    cs_trackers_[connection_handle].main_mode_type = event_view.GetMainModeType();
    cs_trackers_[connection_handle].sub_mode_type = event_view.GetSubModeType();
    cs_trackers_[connection_handle].rtt_type = event_view.GetRttType();

    if (cs_trackers_[connection_handle].role == CsRole::INITIATOR) {
      send_le_cs_set_procedure_parameters(event_view.GetConnectionHandle());
    }
  }

  void on_cs_set_procedure_parameters(CommandCompleteView view) {
    auto complete_view = LeCsSetProcedureParametersCompleteView::Create(view);
    if (!complete_view.IsValid()) {
      LOG_WARN("Get Invalid LeCsSetProcedureParametersCompleteView");
      return;
    } else if (complete_view.GetStatus() != ErrorCode::SUCCESS) {
      std::string error_code = ErrorCodeText(complete_view.GetStatus());
      LOG_WARN(
          "Received LeCsSetProcedureParametersCompleteView with error code %s", error_code.c_str());
      return;
    }
    uint16_t connection_handle = complete_view.GetConnectionHandle();
    if (cs_trackers_.find(connection_handle) == cs_trackers_.end()) {
      LOG_WARN("Can't find cs tracker for connection_handle %d", connection_handle);
      return;
    }

    if (cs_trackers_[connection_handle].role == CsRole::INITIATOR) {
      send_le_cs_procedure_enable(complete_view.GetConnectionHandle(), Enable::ENABLED);
    }
  }

  void on_cs_procedure_enable_complete(LeCsProcedureEnableCompleteView event_view) {
    if (!event_view.IsValid()) {
      LOG_WARN("Get invalid LeCsProcedureEnableCompleteView");
      return;
    } else if (event_view.GetStatus() != ErrorCode::SUCCESS) {
      std::string error_code = ErrorCodeText(event_view.GetStatus());
      LOG_WARN("Received LeCsProcedureEnableCompleteView with error code %s", error_code.c_str());
      return;
    }

    if (event_view.GetState() == Enable::ENABLED) {
      LOG_INFO("Procedure enabled, %s", event_view.ToString().c_str());
    }
  }

  void on_read_remote_transmit_power_level_status(Address address, CommandStatusView view) {
    auto status_view = LeReadRemoteTransmitPowerLevelStatusView::Create(view);
    if (!status_view.IsValid()) {
      LOG_WARN("Invalid LeReadRemoteTransmitPowerLevelStatus event");
      distance_measurement_callbacks_->OnDistanceMeasurementStartFail(
          address, REASON_INTERNAL_ERROR, METHOD_RSSI);
      rssi_trackers.erase(address);
    } else if (status_view.GetStatus() != ErrorCode::SUCCESS) {
      std::string error_code = ErrorCodeText(status_view.GetStatus());
      LOG_WARN(
          "Received LeReadRemoteTransmitPowerLevelStatus with error code %s", error_code.c_str());
      distance_measurement_callbacks_->OnDistanceMeasurementStartFail(
          address, REASON_INTERNAL_ERROR, METHOD_RSSI);
      rssi_trackers.erase(address);
    }
  }

  void on_transmit_power_reporting(LeMetaEventView event) {
    auto event_view = LeTransmitPowerReportingView::Create(event);
    if (!event_view.IsValid()) {
      LOG_WARN("Dropping invalid LeTransmitPowerReporting event");
      return;
    }

    if (event_view.GetReason() == ReportingReason::LOCAL_TRANSMIT_POWER_CHANGED) {
      LOG_WARN("Dropping local LeTransmitPowerReporting event");
      return;
    }

    Address address = Address::kEmpty;
    for (auto& rssi_tracker : rssi_trackers) {
      if (rssi_tracker.second.handle == event_view.GetConnectionHandle()) {
        address = rssi_tracker.first;
      }
    }

    if (address.IsEmpty()) {
      LOG_WARN("Can't find rssi tracker for connection %d", event_view.GetConnectionHandle());
      return;
    }

    auto status = event_view.GetStatus();
    if (status != ErrorCode::SUCCESS) {
      LOG_WARN(
          "Received LeTransmitPowerReporting with error code %s", ErrorCodeText(status).c_str());
    } else {
      rssi_trackers[address].remote_tx_power = event_view.GetTransmitPowerLevel();
    }

    if (event_view.GetReason() == ReportingReason::READ_COMMAND_COMPLETE &&
        !rssi_trackers[address].started) {
      if (status == ErrorCode::SUCCESS) {
        hci_layer_->EnqueueCommand(
            LeSetTransmitPowerReportingEnableBuilder::Create(
                event_view.GetConnectionHandle(), 0x00, 0x01),
            handler_->BindOnceOn(
                this, &impl::on_set_transmit_power_reporting_enable_complete, address));
      } else {
        LOG_WARN("Read remote transmit power level fail");
        distance_measurement_callbacks_->OnDistanceMeasurementStartFail(
            address, REASON_INTERNAL_ERROR, METHOD_RSSI);
        rssi_trackers.erase(address);
      }
    }
  }

  void on_set_transmit_power_reporting_enable_complete(Address address, CommandCompleteView view) {
    auto complete_view = LeSetTransmitPowerReportingEnableCompleteView::Create(view);
    if (!complete_view.IsValid()) {
      LOG_WARN("Invalid LeSetTransmitPowerReportingEnableComplete event");
      distance_measurement_callbacks_->OnDistanceMeasurementStartFail(
          address, REASON_INTERNAL_ERROR, METHOD_RSSI);
      rssi_trackers.erase(address);
      return;
    } else if (complete_view.GetStatus() != ErrorCode::SUCCESS) {
      std::string error_code = ErrorCodeText(complete_view.GetStatus());
      LOG_WARN(
          "Received LeSetTransmitPowerReportingEnableComplete with error code %s",
          error_code.c_str());
      distance_measurement_callbacks_->OnDistanceMeasurementStartFail(
          address, REASON_INTERNAL_ERROR, METHOD_RSSI);
      rssi_trackers.erase(address);
      return;
    }

    if (rssi_trackers.find(address) == rssi_trackers.end()) {
      LOG_WARN("Can't find rssi tracker for %s", ADDRESS_TO_LOGGABLE_CSTR(address));
      distance_measurement_callbacks_->OnDistanceMeasurementStartFail(
          address, REASON_INTERNAL_ERROR, METHOD_RSSI);
      rssi_trackers.erase(address);
    } else {
      LOG_INFO("Track rssi for address %s", ADDRESS_TO_LOGGABLE_CSTR(address));
      rssi_trackers[address].started = true;
      distance_measurement_callbacks_->OnDistanceMeasurementStarted(address, METHOD_RSSI);
      read_rssi_regularly(address, rssi_trackers[address].frequency);
    }
  }

  void on_read_rssi_complete(Address address, CommandCompleteView view) {
    auto complete_view = ReadRssiCompleteView::Create(view);
    if (!complete_view.IsValid()) {
      LOG_WARN("Dropping invalid read RSSI complete event ");
      return;
    }
    if (rssi_trackers.find(address) == rssi_trackers.end()) {
      LOG_WARN("Can't find rssi tracker for %s", ADDRESS_TO_LOGGABLE_CSTR(address));
      return;
    }
    double remote_tx_power = (int8_t)rssi_trackers[address].remote_tx_power;
    int8_t rssi = complete_view.GetRssi();
    double pow_value = (remote_tx_power - rssi - kRSSIDropOffAt1M) / 20.0;
    double distance = pow(10.0, pow_value);
    distance_measurement_callbacks_->OnDistanceMeasurementResult(
        address,
        distance * 100,
        distance * 100,
        -1,
        -1,
        -1,
        -1,
        DistanceMeasurementMethod::METHOD_RSSI);
  }

  struct RSSITracker {
    uint16_t handle;
    uint16_t frequency;
    uint8_t remote_tx_power;
    bool started;
    std::unique_ptr<os::Alarm> alarm;
  };

  struct CsTracker {
    Address address;
    uint16_t local_counter;
    uint16_t remote_counter;
    CsRole role;
    bool setup_complete = false;
    bool config_set = false;
    CsMainModeType main_mode_type;
    CsSubModeType sub_mode_type;
    CsRttType rtt_type;
    bool remote_support_phase_based_ranging = false;
  };

  os::Handler* handler_;
  hci::HciLayer* hci_layer_;
  hci::AclManager* acl_manager_;
  bool is_channel_sounding_supported_ = false;
  hci::DistanceMeasurementInterface* distance_measurement_interface_;
  std::unordered_map<Address, RSSITracker> rssi_trackers;
  std::unordered_map<uint16_t, CsTracker> cs_trackers_;
  DistanceMeasurementCallbacks* distance_measurement_callbacks_;
  CsOptionalSubfeaturesSupported cs_subfeature_supported_;
};

DistanceMeasurementManager::DistanceMeasurementManager() {
  pimpl_ = std::make_unique<impl>();
}

DistanceMeasurementManager::~DistanceMeasurementManager() = default;

void DistanceMeasurementManager::ListDependencies(ModuleList* list) const {
  list->add<hci::HciLayer>();
  list->add<hci::AclManager>();
}

void DistanceMeasurementManager::Start() {
  pimpl_->start(GetHandler(), GetDependency<hci::HciLayer>(), GetDependency<AclManager>());
}

void DistanceMeasurementManager::Stop() {
  pimpl_->stop();
}

std::string DistanceMeasurementManager::ToString() const {
  return "Distance Measurement Manager";
}

void DistanceMeasurementManager::RegisterDistanceMeasurementCallbacks(
    DistanceMeasurementCallbacks* callbacks) {
  CallOn(pimpl_.get(), &impl::register_distance_measurement_callbacks, callbacks);
}

void DistanceMeasurementManager::StartDistanceMeasurement(
    const Address& address, uint16_t frequency, DistanceMeasurementMethod method) {
  CallOn(pimpl_.get(), &impl::start_distance_measurement, address, frequency, method);
}

void DistanceMeasurementManager::StopDistanceMeasurement(
    const Address& address, DistanceMeasurementMethod method) {
  CallOn(pimpl_.get(), &impl::stop_distance_measurement, address, method);
}

}  // namespace hci
}  // namespace bluetooth
