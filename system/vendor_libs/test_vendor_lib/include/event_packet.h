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

#pragma once

#include <cstdint>
#include <memory>
#include <vector>
using std::vector;

#include "base/logging.h"
#include "vendor_libs/test_vendor_lib/include/packet.h"

namespace test_vendor_lib {

// Event Packets are specified in the Bluetooth Core Specification Version 4.2,
// Volume 2, Part E, Section 5.4.4
class EventPacket : public Packet {
 public:
  virtual ~EventPacket() override = default;

  uint8_t GetEventCode() const;

  // Static functions for creating event packets:

  // Bluetooth Core Specification Version 4.2, Volume 2, Part E, Section 7.7.1
  static std::unique_ptr<EventPacket> CreateInquiryCompleteEvent(
      const uint8_t status);

  // Bluetooth Core Specification Version 4.2, Volume 2, Part E, Section 7.7.14
  // This should only be used for testing to send non-standard packets
  // Most code should use the more specific functions that follow
  static std::unique_ptr<EventPacket> CreateCommandCompleteEvent(
      const uint16_t command_opcode,
      const vector<uint8_t>& event_return_parameters);

  static std::unique_ptr<EventPacket> CreateCommandCompleteOnlyStatusEvent(
      const uint16_t command_opcode, const uint8_t status);

  // Bluetooth Core Specification Version 4.2, Volume 2, Part E, Section 7.7.15
  static std::unique_ptr<EventPacket> CreateCommandStatusEvent(
      const uint8_t status, const uint16_t command_opcode);

  // Bluetooth Core Specification Version 4.2, Volume 2, Part E, Section 7.3.12
  static std::unique_ptr<EventPacket> CreateCommandCompleteReadLocalName(
      const uint8_t status, const std::string local_name);

  // Bluetooth Core Specification Version 4.2, Volume 2, Part E, Section 7.4.1
  static std::unique_ptr<EventPacket>
  CreateCommandCompleteReadLocalVersionInformation(
      const uint8_t status,
      const uint8_t hci_version,
      const uint16_t hci_revision,
      const uint8_t lmp_pal_version,
      const uint16_t manufacturer_name,
      const uint16_t lmp_pal_subversion);

  // Bluetooth Core Specification Version 4.2, Volume 2, Part E, Section 7.4.2
  static std::unique_ptr<EventPacket>
  CreateCommandCompleteReadLocalSupportedCommands(
      const uint8_t status, const vector<uint8_t>& supported_commands);

  // Bluetooth Core Specification Version 4.2, Volume 2, Part E, Section 7.4.4
  static std::unique_ptr<EventPacket>
  CreateCommandCompleteReadLocalExtendedFeatures(
      const uint8_t status,
      const uint8_t page_number,
      const uint8_t maximum_page_number,
      const uint64_t extended_lmp_features);

  // Bluetooth Core Specification Version 4.2, Volume 2, Part E, Section 7.4.5
  static std::unique_ptr<EventPacket> CreateCommandCompleteReadBufferSize(
      const uint8_t status,
      const uint16_t hc_acl_data_packet_length,
      const uint8_t hc_synchronous_data_packet_length,
      const uint16_t hc_total_num_acl_data_packets,
      const uint16_t hc_total_synchronous_data_packets);

  // Bluetooth Core Specification Version 4.2, Volume 2, Part E, Section 7.4.6
  static std::unique_ptr<EventPacket> CreateCommandCompleteReadBdAddr(
      const uint8_t status, const vector<uint8_t>& bd_addr);

  // Bluetooth Core Specification Version 4.2, Volume 2, Part E, Section 7.4.8
  static std::unique_ptr<EventPacket>
  CreateCommandCompleteReadLocalSupportedCodecs(
      const uint8_t status,
      const vector<uint8_t>& supported_codecs,
      const vector<uint32_t>& vendor_specific_codecs);

  // Bluetooth Core Specification Version 4.2, Volume 2, Part E, Section 7.7.2
  enum PageScanRepetitionMode {
    kR0 = 0,
    kR1 = 1,
    kR2 = 2,
  };

  static std::unique_ptr<EventPacket> CreateInquiryResultEvent(
      const vector<uint8_t>& bd_address,
      const PageScanRepetitionMode page_scan_repetition_mode,
      const uint32_t class_of_device,
      const uint16_t clock_offset);

  void AddInquiryResult(const vector<uint8_t>& bd_address,
                        const PageScanRepetitionMode page_scan_repetition_mode,
                        const uint32_t class_of_device,
                        const uint16_t clock_offset);

  // Bluetooth Core Specification Version 4.2, Volume 2, Part E, Section 7.7.38
  static std::unique_ptr<EventPacket> CreateExtendedInquiryResultEvent(
      const vector<uint8_t>& bd_address,
      const PageScanRepetitionMode page_scan_repetition_mode,
      const uint32_t class_of_device,
      const uint16_t clock_offset,
      const uint8_t rssi,
      const vector<uint8_t>& extended_inquiry_response);

  // Bluetooth Core Specification Version 4.2, Volume 2, Part E, Section 7.8.2
  static std::unique_ptr<EventPacket> CreateCommandCompleteLeReadBufferSize(
      const uint8_t status,
      const uint16_t hc_le_data_packet_length,
      const uint8_t hc_total_num_le_data_packets);

  // Bluetooth Core Specification Version 4.2, Volume 2, Part E, Section 7.8.3
  static std::unique_ptr<EventPacket>
  CreateCommandCompleteLeReadLocalSupportedFeatures(const uint8_t status,
                                                    const uint64_t le_features);

  // Bluetooth Core Specification Version 4.2, Volume 2, Part E, Section 7.8.14
  static std::unique_ptr<EventPacket> CreateCommandCompleteLeReadWhiteListSize(
      const uint8_t status, const uint8_t white_list_size);

  // Bluetooth Core Specification Version 4.2, Volume 2, Part E, Section 7.8.23
  static std::unique_ptr<EventPacket> CreateCommandCompleteLeRand(
      const uint8_t status, const uint64_t random_val);

  // Bluetooth Core Specification Version 4.2, Volume 2, Part E, Section 7.8.27
  static std::unique_ptr<EventPacket>
  CreateCommandCompleteLeReadSupportedStates(const uint8_t status,
                                             const uint64_t le_states);

  // Vendor-specific commands (see hcidefs.h)

  static std::unique_ptr<EventPacket> CreateCommandCompleteLeVendorCap(
      const uint8_t status, const vector<uint8_t>& vendor_cap);

  // Size of a data packet header, which consists of a 1 octet event code
  static const size_t kEventHeaderSize = 1;

 private:
  EventPacket(const uint8_t event_code);
  EventPacket(const uint8_t event_code, const vector<uint8_t>& payload);
};

}  // namespace test_vendor_lib
