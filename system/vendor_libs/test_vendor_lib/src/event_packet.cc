//
// Copyright 2015 The Android Open Source Project
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

#define LOG_TAG "event_packet"

#include "vendor_libs/test_vendor_lib/include/event_packet.h"

extern "C" {
#include "osi/include/log.h"
#include "stack/include/hcidefs.h"
}  // extern "C"

namespace test_vendor_lib {

EventPacket::EventPacket(uint8_t event_code)
    : Packet(DATA_TYPE_EVENT, {event_code}) {}

uint8_t EventPacket::GetEventCode() const {
  return GetHeader()[0];
}

// Bluetooth Core Specification Version 4.2, Volume 2, Part E, Section 7.7.1
std::unique_ptr<EventPacket> EventPacket::CreateInquiryCompleteEvent(
    const uint8_t status) {
  std::unique_ptr<EventPacket> evt_ptr =
      std::unique_ptr<EventPacket>(new EventPacket(HCI_INQUIRY_COMP_EVT));
  CHECK(evt_ptr->AddPayloadOctets1(status));

  return evt_ptr;
}

// Bluetooth Core Specification Version 4.2, Volume 2, Part E, Section 7.7.14
std::unique_ptr<EventPacket> EventPacket::CreateCommandCompleteEvent(
    const uint16_t command_opcode,
    const vector<uint8_t>& event_return_parameters) {
  std::unique_ptr<EventPacket> evt_ptr =
      std::unique_ptr<EventPacket>(new EventPacket(HCI_COMMAND_COMPLETE_EVT));

  CHECK(evt_ptr->AddPayloadOctets1(1));  // num_hci_command_packets
  CHECK(evt_ptr->AddPayloadOctets2(command_opcode));
  CHECK(evt_ptr->AddPayloadOctets(event_return_parameters.size(),
                                  event_return_parameters));

  return evt_ptr;
}

std::unique_ptr<EventPacket> EventPacket::CreateCommandCompleteOnlyStatusEvent(
    const uint16_t command_opcode, const uint8_t status) {
  std::unique_ptr<EventPacket> evt_ptr =
      std::unique_ptr<EventPacket>(new EventPacket(HCI_COMMAND_COMPLETE_EVT));

  CHECK(evt_ptr->AddPayloadOctets1(1));  // num_hci_command_packets
  CHECK(evt_ptr->AddPayloadOctets2(command_opcode));
  CHECK(evt_ptr->AddPayloadOctets1(status));

  return evt_ptr;
}

// Bluetooth Core Specification Version 4.2, Volume 2, Part E, Section 7.7.15
std::unique_ptr<EventPacket> EventPacket::CreateCommandStatusEvent(
    uint8_t status, uint16_t command_opcode) {
  std::unique_ptr<EventPacket> evt_ptr =
      std::unique_ptr<EventPacket>(new EventPacket(HCI_COMMAND_STATUS_EVT));

  CHECK(evt_ptr->AddPayloadOctets1(status));
  CHECK(evt_ptr->AddPayloadOctets1(1));  // num_hci_command_packets
  CHECK(evt_ptr->AddPayloadOctets2(command_opcode));

  return evt_ptr;
}

// Bluetooth Core Specification Version 4.2, Volume 2, Part E, Section 7.3.12
std::unique_ptr<EventPacket> EventPacket::CreateCommandCompleteReadLocalName(
    const uint8_t status, const std::string local_name) {
  std::unique_ptr<EventPacket> evt_ptr =
      EventPacket::CreateCommandCompleteOnlyStatusEvent(HCI_READ_LOCAL_NAME,
                                                        status);

  for (size_t i = 0; i < local_name.length(); i++)
    CHECK(evt_ptr->AddPayloadOctets1(local_name[i]));
  CHECK(evt_ptr->AddPayloadOctets1(0));  // Null terminated
  for (size_t i = 0; i < 248 - local_name.length() - 1; i++)
    CHECK(evt_ptr->AddPayloadOctets1(0xFF));

  return evt_ptr;
}

// Bluetooth Core Specification Version 4.2, Volume 2, Part E, Section 7.4.1
std::unique_ptr<EventPacket>
EventPacket::CreateCommandCompleteReadLocalVersionInformation(
    const uint8_t status,
    const uint8_t hci_version,
    const uint16_t hci_revision,
    const uint8_t lmp_pal_version,
    const uint16_t manufacturer_name,
    const uint16_t lmp_pal_subversion) {
  std::unique_ptr<EventPacket> evt_ptr =
      EventPacket::CreateCommandCompleteOnlyStatusEvent(
          HCI_READ_LOCAL_VERSION_INFO, status);

  CHECK(evt_ptr->AddPayloadOctets1(hci_version));
  CHECK(evt_ptr->AddPayloadOctets2(hci_revision));
  CHECK(evt_ptr->AddPayloadOctets1(lmp_pal_version));
  CHECK(evt_ptr->AddPayloadOctets2(manufacturer_name));
  CHECK(evt_ptr->AddPayloadOctets2(lmp_pal_subversion));

  return evt_ptr;
}

// Bluetooth Core Specification Version 4.2, Volume 2, Part E, Section 7.4.2
std::unique_ptr<EventPacket>
EventPacket::CreateCommandCompleteReadLocalSupportedCommands(
    const uint8_t status, const vector<uint8_t>& supported_commands) {
  std::unique_ptr<EventPacket> evt_ptr =
      EventPacket::CreateCommandCompleteOnlyStatusEvent(
          HCI_READ_LOCAL_SUPPORTED_CMDS, status);

  CHECK(evt_ptr->AddPayloadOctets(64, supported_commands));

  return evt_ptr;
}

// Bluetooth Core Specification Version 4.2, Volume 2, Part E, Section 7.4.4
std::unique_ptr<EventPacket>
EventPacket::CreateCommandCompleteReadLocalExtendedFeatures(
    const uint8_t status,
    const uint8_t page_number,
    const uint8_t maximum_page_number,
    const uint64_t extended_lmp_features) {
  std::unique_ptr<EventPacket> evt_ptr =
      EventPacket::CreateCommandCompleteOnlyStatusEvent(
          HCI_READ_LOCAL_EXT_FEATURES, status);

  CHECK(evt_ptr->AddPayloadOctets1(page_number));
  CHECK(evt_ptr->AddPayloadOctets1(maximum_page_number));
  CHECK(evt_ptr->AddPayloadOctets8(extended_lmp_features));

  return evt_ptr;
}

// Bluetooth Core Specification Version 4.2, Volume 2, Part E, Section 7.4.5
std::unique_ptr<EventPacket> EventPacket::CreateCommandCompleteReadBufferSize(
    const uint8_t status,
    const uint16_t hc_acl_data_packet_length,
    const uint8_t hc_synchronous_data_packet_length,
    const uint16_t hc_total_num_acl_data_packets,
    const uint16_t hc_total_synchronous_data_packets) {
  std::unique_ptr<EventPacket> evt_ptr =
      EventPacket::CreateCommandCompleteOnlyStatusEvent(HCI_READ_BUFFER_SIZE,
                                                        status);

  CHECK(evt_ptr->AddPayloadOctets2(hc_acl_data_packet_length));
  CHECK(evt_ptr->AddPayloadOctets1(hc_synchronous_data_packet_length));
  CHECK(evt_ptr->AddPayloadOctets2(hc_total_num_acl_data_packets));
  CHECK(evt_ptr->AddPayloadOctets2(hc_total_synchronous_data_packets));

  return evt_ptr;
}

// Bluetooth Core Specification Version 4.2, Volume 2, Part E, Section 7.4.6
std::unique_ptr<EventPacket> EventPacket::CreateCommandCompleteReadBdAddr(
    const uint8_t status, const vector<uint8_t>& bd_addr) {
  std::unique_ptr<EventPacket> evt_ptr =
      EventPacket::CreateCommandCompleteOnlyStatusEvent(HCI_READ_BD_ADDR,
                                                        status);

  CHECK(evt_ptr->AddPayloadOctets(6, bd_addr));

  return evt_ptr;
}

// Bluetooth Core Specification Version 4.2, Volume 2, Part E, Section 7.4.8
std::unique_ptr<EventPacket>
EventPacket::CreateCommandCompleteReadLocalSupportedCodecs(
    const uint8_t status,
    const vector<uint8_t>& supported_codecs,
    const vector<uint32_t>& vendor_specific_codecs) {
  std::unique_ptr<EventPacket> evt_ptr =
      EventPacket::CreateCommandCompleteOnlyStatusEvent(
          HCI_READ_LOCAL_SUPPORTED_CODECS, status);

  CHECK(evt_ptr->AddPayloadOctets(supported_codecs.size(), supported_codecs));
  for (size_t i = 0; i < vendor_specific_codecs.size(); i++)
    CHECK(evt_ptr->AddPayloadOctets4(vendor_specific_codecs[i]));

  return evt_ptr;
}

std::unique_ptr<EventPacket> EventPacket::CreateInquiryResultEvent(
    const vector<uint8_t>& bd_address,
    const PageScanRepetitionMode page_scan_repetition_mode,
    const uint32_t class_of_device,
    const uint16_t clock_offset) {
  std::unique_ptr<EventPacket> evt_ptr =
      std::unique_ptr<EventPacket>(new EventPacket(HCI_INQUIRY_RESULT_EVT));

  CHECK(evt_ptr->AddPayloadOctets1(1));  // Start with a single response

  CHECK(evt_ptr->AddPayloadOctets(6, bd_address));
  CHECK(evt_ptr->AddPayloadOctets1(page_scan_repetition_mode));
  CHECK(evt_ptr->AddPayloadOctets2(kReservedZero));
  CHECK(evt_ptr->AddPayloadOctets3(class_of_device));
  CHECK(!(clock_offset & 0x8000));
  CHECK(evt_ptr->AddPayloadOctets2(clock_offset));

  return evt_ptr;
}

void EventPacket::AddInquiryResult(
    const vector<uint8_t>& bd_address,
    const PageScanRepetitionMode page_scan_repetition_mode,
    const uint32_t class_of_device,
    const uint16_t clock_offset) {
  CHECK(GetEventCode() == HCI_INQUIRY_RESULT_EVT);

  CHECK(IncrementPayloadCounter(1));  // Increment the number of responses

  CHECK(AddPayloadOctets(6, bd_address));
  CHECK(AddPayloadOctets1(page_scan_repetition_mode));
  CHECK(AddPayloadOctets2(kReservedZero));
  CHECK(AddPayloadOctets3(class_of_device));
  CHECK(!(clock_offset & 0x8000));
  CHECK(AddPayloadOctets2(clock_offset));
}

std::unique_ptr<EventPacket> EventPacket::CreateExtendedInquiryResultEvent(
    const vector<uint8_t>& bd_address,
    const PageScanRepetitionMode page_scan_repetition_mode,
    const uint32_t class_of_device,
    const uint16_t clock_offset,
    const uint8_t rssi,
    const vector<uint8_t>& extended_inquiry_response) {
  std::unique_ptr<EventPacket> evt_ptr = std::unique_ptr<EventPacket>(
      new EventPacket(HCI_EXTENDED_INQUIRY_RESULT_EVT));

  CHECK(evt_ptr->AddPayloadOctets1(1));  // Always contains a single response

  CHECK(evt_ptr->AddPayloadOctets(6, bd_address));
  CHECK(evt_ptr->AddPayloadOctets1(page_scan_repetition_mode));
  CHECK(evt_ptr->AddPayloadOctets1(kReservedZero));
  CHECK(evt_ptr->AddPayloadOctets3(class_of_device));
  CHECK(!(clock_offset & 0x8000));
  CHECK(evt_ptr->AddPayloadOctets2(clock_offset));
  CHECK(evt_ptr->AddPayloadOctets1(rssi));
  CHECK(evt_ptr->AddPayloadOctets(extended_inquiry_response.size(),
                                  extended_inquiry_response));
  while (evt_ptr->AddPayloadOctets1(0xff))
    ;  // Fill packet
  return evt_ptr;
}

// Bluetooth Core Specification Version 4.2, Volume 2, Part E, Section 7.8.2
std::unique_ptr<EventPacket> EventPacket::CreateCommandCompleteLeReadBufferSize(
    const uint8_t status,
    const uint16_t hc_le_data_packet_length,
    const uint8_t hc_total_num_le_data_packets) {
  std::unique_ptr<EventPacket> evt_ptr =
      EventPacket::CreateCommandCompleteOnlyStatusEvent(
          HCI_BLE_READ_BUFFER_SIZE, status);

  CHECK(evt_ptr->AddPayloadOctets2(hc_le_data_packet_length));
  CHECK(evt_ptr->AddPayloadOctets1(hc_total_num_le_data_packets));

  return evt_ptr;
}

// Bluetooth Core Specification Version 4.2, Volume 2, Part E, Section 7.8.3
std::unique_ptr<EventPacket>
EventPacket::CreateCommandCompleteLeReadLocalSupportedFeatures(
    const uint8_t status, const uint64_t le_features) {
  std::unique_ptr<EventPacket> evt_ptr =
      EventPacket::CreateCommandCompleteOnlyStatusEvent(
          HCI_BLE_READ_LOCAL_SPT_FEAT, status);

  CHECK(evt_ptr->AddPayloadOctets1(status));
  CHECK(evt_ptr->AddPayloadOctets8(le_features));

  return evt_ptr;
}

// Bluetooth Core Specification Version 4.2, Volume 2, Part E, Section 7.8.14
std::unique_ptr<EventPacket>
EventPacket::CreateCommandCompleteLeReadWhiteListSize(
    const uint8_t status, const uint8_t white_list_size) {
  std::unique_ptr<EventPacket> evt_ptr =
      EventPacket::CreateCommandCompleteOnlyStatusEvent(
          HCI_BLE_READ_WHITE_LIST_SIZE, status);

  CHECK(evt_ptr->AddPayloadOctets8(white_list_size));

  return evt_ptr;
}

// Bluetooth Core Specification Version 4.2, Volume 2, Part E, Section 7.8.23
std::unique_ptr<EventPacket> EventPacket::CreateCommandCompleteLeRand(
    const uint8_t status, const uint64_t random_val) {
  std::unique_ptr<EventPacket> evt_ptr =
      EventPacket::CreateCommandCompleteOnlyStatusEvent(HCI_BLE_RAND, status);

  CHECK(evt_ptr->AddPayloadOctets8(random_val));

  return evt_ptr;
}

// Bluetooth Core Specification Version 4.2, Volume 2, Part E, Section 7.8.27
std::unique_ptr<EventPacket>
EventPacket::CreateCommandCompleteLeReadSupportedStates(
    const uint8_t status, const uint64_t le_states) {
  std::unique_ptr<EventPacket> evt_ptr =
      EventPacket::CreateCommandCompleteOnlyStatusEvent(
          HCI_BLE_READ_SUPPORTED_STATES, status);

  CHECK(evt_ptr->AddPayloadOctets8(le_states));

  return evt_ptr;
}

// Vendor-specific commands (see hcidefs.h)

std::unique_ptr<EventPacket> EventPacket::CreateCommandCompleteLeVendorCap(
    const uint8_t status, const vector<uint8_t>& vendor_cap) {
  std::unique_ptr<EventPacket> evt_ptr =
      EventPacket::CreateCommandCompleteOnlyStatusEvent(HCI_BLE_VENDOR_CAP_OCF,
                                                        status);

  CHECK(evt_ptr->AddPayloadOctets(vendor_cap.size(), vendor_cap));

  return evt_ptr;
}

}  // namespace test_vendor_lib
