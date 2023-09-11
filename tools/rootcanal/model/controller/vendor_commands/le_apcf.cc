/*
 * Copyright 2023 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License") {

 }
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

#include <cstdint>

#include "model/controller/link_layer_controller.h"
#include "packets/hci_packets.h"

#pragma GCC diagnostic ignored "-Wunused-parameter"

namespace rootcanal {

ErrorCode LinkLayerController::LeApcfEnable(bool apcf_enable) {
  return ErrorCode::INVALID_HCI_COMMAND_PARAMETERS;
}

ErrorCode LinkLayerController::LeApcfSetFilteringParameters(
    bluetooth::hci::ApcfAction apcf_action, uint8_t apcf_filter_index,
    uint16_t apcf_feature_selection, uint16_t apcf_list_logic_type,
    uint8_t apcf_filter_logic_type, uint8_t rssi_high_thresh,
    bluetooth::hci::DeliveryMode delivery_mode, uint16_t onfound_timeout,
    uint8_t onfound_timeout_cnt, uint8_t rssi_low_thresh,
    uint16_t onlost_timeout, uint16_t num_of_tracking_entries,
    uint8_t* apcf_available_spaces) {
  return ErrorCode::INVALID_HCI_COMMAND_PARAMETERS;
}

ErrorCode LinkLayerController::LeApcfBroadcasterAddress(
    bluetooth::hci::ApcfAction apcf_action, uint8_t apcf_filter_index,
    bluetooth::hci::Address apcf_broadcaster_address,
    bluetooth::hci::ApcfApplicationAddressType apcf_application_address_type,
    uint8_t* apcf_available_spaces) {
  return ErrorCode::INVALID_HCI_COMMAND_PARAMETERS;
}

ErrorCode LinkLayerController::LeApcfServiceUuid(
    bluetooth::hci::ApcfAction apcf_action, uint8_t apcf_filter_index,
    std::vector<uint8_t> acpf_uuid_data, uint8_t* apcf_available_spaces) {
  return ErrorCode::INVALID_HCI_COMMAND_PARAMETERS;
}

ErrorCode LinkLayerController::LeApcfServiceSolicitationUuid(
    bluetooth::hci::ApcfAction apcf_action, uint8_t apcf_filter_index,
    std::vector<uint8_t> acpf_uuid_data, uint8_t* apcf_available_spaces) {
  return ErrorCode::INVALID_HCI_COMMAND_PARAMETERS;
}

ErrorCode LinkLayerController::LeApcfLocalName(
    bluetooth::hci::ApcfAction apcf_action, uint8_t apcf_filter_index,
    std::vector<uint8_t> apcf_local_name, uint8_t* apcf_available_spaces) {
  return ErrorCode::INVALID_HCI_COMMAND_PARAMETERS;
}

ErrorCode LinkLayerController::LeApcfManufacturerData(
    bluetooth::hci::ApcfAction apcf_action, uint8_t apcf_filter_index,
    std::vector<uint8_t> apcf_manufacturer_data,
    uint8_t* apcf_available_spaces) {
  return ErrorCode::INVALID_HCI_COMMAND_PARAMETERS;
}

ErrorCode LinkLayerController::LeApcfServiceData(
    bluetooth::hci::ApcfAction apcf_action, uint8_t apcf_filter_index,
    std::vector<uint8_t> apcf_service_data, uint8_t* apcf_available_spaces) {
  return ErrorCode::INVALID_HCI_COMMAND_PARAMETERS;
}

ErrorCode LinkLayerController::LeApcfAdTypeFilter(
    bluetooth::hci::ApcfAction apcf_action, uint8_t apcf_filter_index,
    uint8_t ad_type, std::vector<uint8_t> apcf_ad_data,
    std::vector<uint8_t> apcf_ad_data_mask, uint8_t* apcf_available_spaces) {
  return ErrorCode::INVALID_HCI_COMMAND_PARAMETERS;
}

}  // namespace rootcanal
