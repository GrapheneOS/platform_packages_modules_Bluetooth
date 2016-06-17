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
#include <string>
#include <unordered_map>
#include <vector>
using std::vector;

#include "base/json/json_value_converter.h"
#include "base/time/time.h"
#include "vendor_libs/test_vendor_lib/include/command_packet.h"
#include "vendor_libs/test_vendor_lib/include/hci_transport.h"
#include "vendor_libs/test_vendor_lib/include/test_channel_transport.h"

namespace test_vendor_lib {

// Emulates a dual mode BR/EDR + LE controller by maintaining the link layer
// state machine detailed in the Bluetooth Core Specification Version 4.2,
// Volume 6, Part B, Section 1.1 (page 30). Provides methods corresponding to
// commands sent by the HCI. These methods will be registered as callbacks from
// a controller instance with the HciHandler. To implement a new Bluetooth
// command, simply add the method declaration below, with return type void and a
// single const vector<uint8_t>& argument. After implementing the
// method, simply register it with the HciHandler using the SET_HANDLER macro in
// the controller's default constructor. Be sure to name your method after the
// corresponding Bluetooth command in the Core Specification with the prefix
// "Hci" to distinguish it as a controller command.
class DualModeController {
 public:
  class Properties {
   public:
    Properties(const std::string& file_name);

    // Access private configuration data

    // Specification Version 4.2, Volume 2, Part E, Section 7.4.1
    const vector<uint8_t>& GetLocalVersionInformation() const;

    // Specification Version 4.2, Volume 2, Part E, Section 7.4.2
    const vector<uint8_t>& GetLocalSupportedCommands() const {
      return local_supported_commands_;
    }

    // Specification Version 4.2, Volume 2, Part E, Section 7.4.3
    uint64_t GetLocalSupportedFeatures() const {
      return local_extended_features_[0];
    };

    // Specification Version 4.2, Volume 2, Part E, Section 7.4.4
    uint8_t GetLocalExtendedFeaturesMaximumPageNumber() const {
      return local_extended_features_.size() - 1;
    };

    uint64_t GetLocalExtendedFeatures(uint8_t page_number) const {
      CHECK(page_number < local_extended_features_.size());
      return local_extended_features_[page_number];
    };

    // Specification Version 4.2, Volume 2, Part E, Section 7.4.5
    uint16_t GetAclDataPacketSize() const { return acl_data_packet_size_; }

    uint8_t GetSynchronousDataPacketSize() const {
      return sco_data_packet_size_;
    }

    uint16_t GetTotalNumAclDataPackets() const { return num_acl_data_packets_; }

    uint16_t GetTotalNumSynchronousDataPackets() const {
      return num_sco_data_packets_;
    }

    // Specification Version 4.2, Volume 2, Part E, Section 7.4.6
    const vector<uint8_t>& GetBdAddress() const { return bd_address_; }

    // Specification Version 4.2, Volume 2, Part E, Section 7.4.8
    const vector<uint8_t>& GetSupportedCodecs() const {
      return supported_codecs_;
    }

    const vector<uint32_t>& GetVendorSpecificCodecs() const {
      return vendor_specific_codecs_;
    }

    const std::string& GetLocalName() const { return local_name_; }

    uint8_t GetVersion() const { return version_; }

    uint16_t GetRevision() const { return revision_; }

    uint8_t GetLmpPalVersion() const { return lmp_pal_version_; }

    uint16_t GetLmpPalSubversion() const { return lmp_pal_subversion_; }

    uint16_t GetManufacturerName() const { return manufacturer_name_; }

    // Specification Version 4.2, Volume 2, Part E, Section 7.8.2
    uint16_t GetLeDataPacketLength() const { return le_data_packet_length_; }

    uint8_t GetTotalNumLeDataPackets() const { return num_le_data_packets_; }

    // Specification Version 4.2, Volume 2, Part E, Section 7.8.3
    uint64_t GetLeLocalSupportedFeatures() const {
      return le_supported_features_;
    }

    // Specification Version 4.2, Volume 2, Part E, Section 7.8.14
    uint8_t GetLeWhiteListSize() const { return le_white_list_size_; }

    // Specification Version 4.2, Volume 2, Part E, Section 7.8.27
    uint64_t GetLeSupportedStates() const { return le_supported_states_; }

    // Vendor-specific commands (see hcidefs.h)
    const vector<uint8_t>& GetLeVendorCap() const { return le_vendor_cap_; }

    static void RegisterJSONConverter(
        base::JSONValueConverter<Properties>* converter);

   private:
    uint16_t acl_data_packet_size_;
    uint8_t sco_data_packet_size_;
    uint16_t num_acl_data_packets_;
    uint16_t num_sco_data_packets_;
    uint8_t version_;
    uint16_t revision_;
    uint8_t lmp_pal_version_;
    uint16_t manufacturer_name_;
    uint16_t lmp_pal_subversion_;
    vector<uint8_t> supported_codecs_;
    vector<uint32_t> vendor_specific_codecs_;
    vector<uint8_t> local_supported_commands_;
    std::string local_name_;
    vector<uint64_t> local_extended_features_;
    vector<uint8_t> bd_address_;

    uint16_t le_data_packet_length_;
    uint8_t num_le_data_packets_;
    uint8_t le_white_list_size_;
    uint64_t le_supported_features_;
    uint64_t le_supported_states_;
    vector<uint8_t> le_vendor_cap_;
  };

  // Sets all of the methods to be used as callbacks in the HciHandler.
  DualModeController();

  ~DualModeController() = default;

  // Preprocesses the command, primarily checking testh channel hooks. If
  // possible, dispatches the corresponding controller method corresponding to
  // carry out the command.
  void HandleCommand(std::unique_ptr<CommandPacket> command_packet);

  // Dispatches the test channel action corresponding to the command specified
  // by |name|.
  void HandleTestChannelCommand(const std::string& name,
                                const vector<std::string>& args);

  // Sets the controller Handle* methods as callbacks for the transport to call
  // when data is received.
  void RegisterHandlersWithHciTransport(HciTransport& transport);

  // Sets the test channel handler with the transport dedicated to test channel
  // communications.
  void RegisterHandlersWithTestChannelTransport(
      TestChannelTransport& transport);

  // Sets the callback to be used for sending events back to the HCI.
  // TODO(dennischeng): Once PostDelayedTask works, get rid of this and only use
  // |RegisterDelayedEventChannel|.
  void RegisterEventChannel(
      std::function<void(std::unique_ptr<EventPacket>)> send_event);

  void RegisterDelayedEventChannel(
      std::function<void(std::unique_ptr<EventPacket>, base::TimeDelta)>
          send_event);

  // Controller commands. For error codes, see the Bluetooth Core Specification,
  // Version 4.2, Volume 2, Part D (page 370).

  // OGF: 0x0003
  // OCF: 0x0003
  // Bluetooth Core Specification Version 4.2 Volume 2 Part E 7.3.2
  void HciReset(const vector<uint8_t>& args);

  // OGF: 0x0004
  // OGF: 0x0005
  // Bluetooth Core Specification Version 4.2 Volume 2 Part E 7.4.5
  void HciReadBufferSize(const vector<uint8_t>& args);

  // OGF: 0x0003
  // OCF: 0x0033
  // Bluetooth Core Specification Version 4.2 Volume 2 Part E 7.3.39
  void HciHostBufferSize(const vector<uint8_t>& args);

  // OGF: 0x0004
  // OCF: 0x0001
  // Bluetooth Core Specification Version 4.2 Volume 2 Part E 7.4.1
  void HciReadLocalVersionInformation(const vector<uint8_t>& args);

  // OGF: 0x0004
  // OCF: 0x0009
  // Bluetooth Core Specification Version 4.2 Volume 2 Part E 7.4.6
  void HciReadBdAddr(const vector<uint8_t>& args);

  // OGF: 0x0004
  // OCF: 0x0002
  // Bluetooth Core Specification Version 4.2 Volume 2 Part E 7.4.2
  void HciReadLocalSupportedCommands(const vector<uint8_t>& args);

  // OGF: 0x0004
  // OCF: 0x0004
  // Bluetooth Core Specification Version 4.2 Volume 2 Part E 7.4.4
  void HciReadLocalExtendedFeatures(const vector<uint8_t>& args);

  // OGF: 0x0004
  // OCF: 0x000B
  // Bluetooth Core Specification Version 4.2 Volume 2 Part E 7.4.8
  void HciReadLocalSupportedCodecs(const vector<uint8_t>& args);

  // OGF: 0x0003
  // OCF: 0x0056
  // Bluetooth Core Specification Version 4.2 Volume 2 Part E 7.3.59
  void HciWriteSimplePairingMode(const vector<uint8_t>& args);

  // OGF: 0x0003
  // OCF: 0x006D
  // Bluetooth Core Specification Version 4.2 Volume 2 Part E 7.3.79
  void HciWriteLeHostSupport(const vector<uint8_t>& args);

  // OGF: 0x0003
  // OCF: 0x0001
  // Bluetooth Core Specification Version 4.2 Volume 2 Part E 7.3.1
  void HciSetEventMask(const vector<uint8_t>& args);

  // OGF: 0x0003
  // OCF: 0x0045
  // Bluetooth Core Specification Version 4.2 Volume 2 Part E 7.3.50
  void HciWriteInquiryMode(const vector<uint8_t>& args);

  // OGF: 0x0003
  // OCF: 0x0047
  // Bluetooth Core Specification Version 4.2 Volume 2 Part E 7.3.52
  void HciWritePageScanType(const vector<uint8_t>& args);

  // OGF: 0x0003
  // OCF: 0x0043
  // Bluetooth Core Specification Version 4.2 Volume 2 Part E 7.3.48
  void HciWriteInquiryScanType(const vector<uint8_t>& args);

  // OGF: 0x0003
  // OCF: 0x0024
  // Bluetooth Core Specification Version 4.2 Volume 2 Part E 7.3.26
  void HciWriteClassOfDevice(const vector<uint8_t>& args);

  // OGF: 0x0003
  // OCF: 0x0018
  // Bluetooth Core Specification Version 4.2 Volume 2 Part E 7.3.16
  void HciWritePageTimeout(const vector<uint8_t>& args);

  // OGF: 0x0002
  // OCF: 0x000F
  // Bluetooth Core Specification Version 4.2 Volume 2 Part E 7.2.12
  void HciWriteDefaultLinkPolicySettings(const vector<uint8_t>& args);

  // OGF: 0x0003
  // OCF: 0x0014
  // Bluetooth Core Specification Version 4.2 Volume 2 Part E 7.3.12
  void HciReadLocalName(const vector<uint8_t>& args);

  // OGF: 0x0003
  // OCF: 0x0013
  // Bluetooth Core Specification Version 4.2 Volume 2 Part E 7.3.11
  void HciWriteLocalName(const vector<uint8_t>& args);

  // OGF: 0x0003
  // OCF: 0x0052
  // Bluetooth Core Specification Version 4.2 Volume 2 Part E 7.3.56
  void HciWriteExtendedInquiryResponse(const vector<uint8_t>& args);

  // OGF: 0x0003
  // OCF: 0x0026
  // Bluetooth Core Specification Version 4.2 Volume 2 Part E 7.3.28
  void HciWriteVoiceSetting(const vector<uint8_t>& args);

  // OGF: 0x0003
  // OCF: 0x003A
  // Bluetooth Core Specification Version 4.2 Volume 2 Part E 7.3.45
  void HciWriteCurrentIacLap(const vector<uint8_t>& args);

  // OGF: 0x0003
  // OCF: 0x001E
  // Bluetooth Core Specification Version 4.2 Volume 2 Part E 7.3.22
  void HciWriteInquiryScanActivity(const vector<uint8_t>& args);

  // OGF: 0x0003
  // OCF: 0x001A
  // Bluetooth Core Specification Version 4.2 Volume 2 Part E 7.3.18
  void HciWriteScanEnable(const vector<uint8_t>& args);

  // OGF: 0x0003
  // OCF: 0x0005
  // Bluetooth Core Specification Version 4.2 Volume 2 Part E 7.3.3
  void HciSetEventFilter(const vector<uint8_t>& args);

  // OGF: 0x0001
  // OCF: 0x0001
  // Bluetooth Core Specification Version 4.2 Volume 2 Part E 7.1.1
  void HciInquiry(const vector<uint8_t>& args);

  // OGF: 0x0001
  // OCF: 0x0002
  // Bluetooth Core Specification Version 4.2 Volume 2 Part E 7.1.2
  void HciInquiryCancel(const vector<uint8_t>& args);

  // OGF: 0x0003
  // OCF: 0x0012
  // Bluetooth Core Specification Version 4.2 Volume 2 Part E 7.3.10
  void HciDeleteStoredLinkKey(const vector<uint8_t>& args);

  // OGF: 0x0001
  // OCF: 0x0019
  // Bluetooth Core Specification Version 4.2 Volume 2 Part E 7.1.19
  void HciRemoteNameRequest(const vector<uint8_t>& args);

  // LE Controller Commands

  // OGF: 0x0008
  // OCF: 0x0001
  // Bluetooth Core Specification Version 4.2 Volume 2 Part E 7.8.1
  void HciLeSetEventMask(const vector<uint8_t>& args);

  // OGF: 0x0008
  // OCF: 0x0002
  // Bluetooth Core Specification Version 4.2 Volume 2 Part E 7.8.2
  void HciLeReadBufferSize(const vector<uint8_t>& args);

  // OGF: 0x0008
  // OCF: 0x0003
  // Bluetooth Core Specification Version 4.2 Volume 2 Part E 7.8.3
  void HciLeReadLocalSupportedFeatures(const vector<uint8_t>& args);

  // OGF: 0x0008
  // OCF: 0x0005
  // Bluetooth Core Specification Version 4.2 Volume 2 Part E 7.8.4
  void HciLeSetRandomAddress(const vector<uint8_t>& args);

  // OGF: 0x0008
  // OCF: 0x000B
  // Bluetooth Core Specification Version 4.2 Volume 2 Part E 7.8.10
  void HciLeSetScanParameters(const vector<uint8_t>& args);

  // OGF: 0x0008
  // OCF: 0x000C
  // Bluetooth Core Specification Version 4.2 Volume 2 Part E 7.8.11
  void HciLeSetScanEnable(const vector<uint8_t>& args);

  // OGF: 0x0008
  // OCF: 0x000F
  // Bluetooth Core Specification Version 4.2 Volume 2 Part E 7.8.14
  void HciLeReadWhiteListSize(const vector<uint8_t>& args);

  // OGF: 0x0008
  // OCF: 0x0018
  // Bluetooth Core Specification Version 4.2 Volume 2 Part E 7.8.23
  void HciLeRand(const vector<uint8_t>& args);

  // OGF: 0x0008
  // OCF: 0x001C
  // Bluetooth Core Specification Version 4.2 Volume 2 Part E 7.8.27
  void HciLeReadSupportedStates(const vector<uint8_t>& args);

  // Vendor-specific commands (see hcidefs.h)

  // OGF: 0x00FC
  // OCF: 0x0027
  void HciBleVendorSleepMode(const vector<uint8_t>& args);

  // OGF: 0x00FC
  // OCF: 0x0153
  void HciBleVendorCap(const vector<uint8_t>& args);

  // OGF: 0x00FC
  // OCF: 0x0154
  void HciBleVendorMultiAdv(const vector<uint8_t>& args);

  // OGF: 0x00FC
  // OCF: 0x0155
  void HciBleVendor155(const vector<uint8_t>& args);

  // OGF: 0x00FC
  // OCF: 0x0157
  void HciBleVendor157(const vector<uint8_t>& args);

  // OGF: 0x00FC
  // OCF: 0x0159
  void HciBleEnergyInfo(const vector<uint8_t>& args);

  // OGF: 0x00FC
  // OCF: 0x015A
  void HciBleExtendedScanParams(const vector<uint8_t>& args);

  // Test Channel commands:

  // Clears all test channel modifications.
  void TestChannelClear(const vector<std::string>& args);

  // Sets the response delay for events to 0.
  void TestChannelClearEventDelay(const vector<std::string>& args);

  // Discovers a fake device.
  void TestChannelDiscover(const vector<std::string>& args);

  // Causes events to be sent after a delay.
  void TestChannelSetEventDelay(const vector<std::string>& args);

  // Causes all future HCI commands to timeout.
  void TestChannelTimeoutAll(const vector<std::string>& args);

 private:
  // Current link layer state of the controller.
  enum State {
    kStandby,  // Not receiving/transmitting any packets from/to other devices.
    kInquiry,  // The controller is discovering other nearby devices.
  };

  enum TestChannelState {
    kNone,             // The controller is running normally.
    kTimeoutAll,       // All commands should time out, i.e. send no response.
    kDelayedResponse,  // Event responses are sent after a delay.
  };

  // Creates a command complete event and sends it back to the HCI.
  void SendCommandComplete(const uint16_t command_opcode,
                           const vector<uint8_t>& return_parameters) const;

  // Sends a command complete event with no return parameters. This event is
  // typically sent for commands that can be completed immediately.
  void SendCommandCompleteSuccess(const uint16_t command_opcode) const;

  // Sends a command complete event with no return parameters. This event is
  // typically sent for commands that can be completed immediately.
  void SendCommandCompleteOnlyStatus(const uint16_t command_opcode,
                                     const uint8_t status) const;

  // Creates a command status event and sends it back to the HCI.
  void SendCommandStatus(uint8_t status, uint16_t command_opcode) const;

  // Sends a command status event with default event parameters.
  void SendCommandStatusSuccess(uint16_t command_opcode) const;

  void SetEventDelay(int64_t delay);

  // Callback provided to send events from the controller back to the HCI.
  std::function<void(std::unique_ptr<EventPacket>)> send_event_;

  std::function<void(std::unique_ptr<EventPacket>, base::TimeDelta)>
      send_delayed_event_;

  // Maintains the commands to be registered and used in the HciHandler object.
  // Keys are command opcodes and values are the callbacks to handle each
  // command.
  std::unordered_map<uint16_t, std::function<void(const vector<uint8_t>&)>>
      active_hci_commands_;

  std::unordered_map<std::string,
                     std::function<void(const vector<std::string>&)>>
      active_test_channel_commands_;

  // Specifies the format of Inquiry Result events to be returned during the
  // Inquiry command.
  // 0x00: Standard Inquiry Result event format (default).
  // 0x01: Inquiry Result format with RSSI.
  // 0x02 Inquiry Result with RSSI format or Extended Inquiry Result format.
  // 0x03-0xFF: Reserved.
  uint8_t inquiry_mode_;

  vector<uint8_t> le_event_mask_;

  vector<uint8_t> le_random_address_;

  uint8_t le_scan_type_;
  uint16_t le_scan_interval_;
  uint16_t le_scan_window_;
  uint8_t own_address_type_;
  uint8_t scanning_filter_policy_;

  uint8_t le_scan_enable_;
  uint8_t filter_duplicates_;

  State state_;

  Properties properties_;

  TestChannelState test_channel_state_;

  DISALLOW_COPY_AND_ASSIGN(DualModeController);
};

}  // namespace test_vendor_lib
