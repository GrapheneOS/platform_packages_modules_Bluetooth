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
#include <vector>
#include <unordered_map>

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
// single const std::vector<std::uint8_t>& argument. After implementing the
// method, simply register it with the HciHandler using the SET_HANDLER macro in
// the controller's default constructor. Be sure to name your method after the
// corresponding Bluetooth command in the Core Specification with the prefix
// "Hci" to distinguish it as a controller command.
class DualModeController {
 public:
  class Properties {
   public:
    // TODO(dennischeng): Add default initialization and use that to instantiate
    // a default configured controller if the config file is invalid or not
    // provided.
    Properties(const std::string& file_name);

    // Aggregates and returns the result for the Read Buffer Size command. This
    // result consists of the |acl_data_packet_size_|, |sco_data_packet_size_|,
    // |num_acl_data_packets_|, and |num_sco_data_packets_| properties. See the
    // Bluetooth Core Specification Version 4.2, Volume 2, Part E, Section 7.4.5
    // (page 794).
    const std::vector<std::uint8_t> GetBufferSize();

    // Aggregates and returns the Read Local Version Information result. This
    // consists of the |version_|, |revision_|, |lmp_pal_version_|,
    // |manufacturer_name_|, and |lmp_pal_subversion_|. See the Bluetooth Core
    // Specification Version 4.2, Volume 2, Part E, Section 7.4.1 (page 788).
    const std::vector<std::uint8_t> GetLocalVersionInformation();

    // Aggregates and returns the result for the Read Local Extended Features
    // command. This result contains the |maximum_page_number_| property (among
    // other things not in the Properties object). See the Bluetooth Core
    // Specification Version 4.2, Volume 2, Part E, Section 7.4.4 (page 792).
    const std::vector<std::uint8_t> GetBdAddress();

    // Returns the result for the Read BD_ADDR command. This result is the
    // |bd_address_| property. See the Bluetooth Core Specification Version
    // 4.2, Volume 2, Part E, Section 7.4.6 (page 796).
    const std::vector<std::uint8_t> GetLocalExtendedFeatures(
        std::uint8_t page_number);

    static void RegisterJSONConverter(
        base::JSONValueConverter<Properties>* converter);

   private:
    std::uint16_t acl_data_packet_size_;
    std::uint8_t sco_data_packet_size_;
    std::uint16_t num_acl_data_packets_;
    std::uint16_t num_sco_data_packets_;
    std::uint8_t version_;
    std::uint16_t revision_;
    std::uint8_t lmp_pal_version_;
    std::uint16_t manufacturer_name_;
    std::uint16_t lmp_pal_subversion_;
    std::uint8_t maximum_page_number_;
    std::vector<std::uint8_t> bd_address_;
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
                                const std::vector<std::string>& args);

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

  // Resets the controller. For now, this just generates and sends a command
  // complete event back to the HCI.
  // OGF: 0x0003
  // OCF: 0x0003
  // Command parameters: none.
  // Command response:
  //   Status (1 octet)
  //     0x00: Success.
  //     0x01-0xFF: Failed. Check error codes.
  void HciReset(const std::vector<std::uint8_t>& args);

  // Reads the max size of the payload for ACL/SCO data packets sent from the
  // host to the controller. Also reads the number of ACL/SCO data packets
  // that can be stored in the controller's data buffer.
  // OGF: 0x0004
  // OGF: 0x0005
  // Command parameters: none.
  void HciReadBufferSize(const std::vector<std::uint8_t>& args);

  // Notifies the controller about the max payload size for ACL/SCO data
  // packets sent from the controller to the host. Also notifies the controller
  // about the number of ACL/SCO data packets that can be stored in the host's
  // data buffers.
  // OGF: 0x0003
  // OCF: 0x0033
  // Command parameters: none.
  void HciHostBufferSize(const std::vector<std::uint8_t>& args);

  // Gives the host the controller's version information.
  // OGF: 0x0004
  // OCF: 0x0001
  // Command parameters: none.
  void HciReadLocalVersionInformation(const std::vector<std::uint8_t>& args);

  // Gives the host the controller's address. See the Bluetooth Core
  // Specification, Version 4.2, Volume 2, Part B (page 58) for more details
  // about how the address is used.
  // OGF: 0x0004
  // OCF: 0x0009
  // Command parameters: none.
  void HciReadBdAddr(const std::vector<std::uint8_t>& args);

  // Reads the list of HCI commands the controller supports.
  // OGF: 0x0004
  // OCF: 0x0002
  // Command parameters: none.
  void HciReadLocalSupportedCommands(const std::vector<std::uint8_t>& args);

  // Returns the requested page of extended LMP features.
  // OGF: 0x0004
  // OCF: 0x0004
  // Command parameters:
  //   Page Number (1 octet)
  //     0x00: Requests the normal LMP features as returned
  //     by HciReadLocalSupportedCommands().
  //     0x01-0xFF: Returns the
  //     corresponding page of features.
  void HciReadLocalExtendedFeatures(const std::vector<std::uint8_t>& args);

  // Toggles simple pairing mode.
  // OGF: 0x0003
  // OCF: 0x0056
  // Command parameters:
  //   Simple Pairing Mode (1 octet)
  //     0x00: Disables simple pairing.
  //     0x01: Enables simple pairing.
  //     0x02-0xFF: Reserved.
  void HciWriteSimplePairingMode(const std::vector<std::uint8_t>& args);

  // Used to set the LE Supported and Simultaneous LE and BREDR to Same Device
  // Capable Link Manager Protocol feature bits.
  // OGF: 0x0003
  // OCF: 0x006D
  // Command parameters:
  //   LE supported host (1 octet)
  //     0x00: LE Supported disabled.
  //     0x01: LE Supported enabled.
  //     0x02-0xFF: Reserved.
  //   Simultaneous LE Host (1 octet)
  //     0x00: Simultaneous LE and BREDR to Same Device Capable disabled.
  //     0x01-0xFF Reserved.
  void HciWriteLeHostSupport(const std::vector<std::uint8_t>& args);

  // Used to control which events are generated by the HCI for the host.
  // OGF: 0x0003
  // OCF: 0x0001
  // Command parameters:
  //   Event Mask (8 octets)
  //     See the Bluetooth Core Specification, Version 4.2, Volume 2, Section
  //     7.3.1 (page 642) for details about the event mask.
  void HciSetEventMask(const std::vector<std::uint8_t>& args);

  // Writes the inquiry mode configuration parameter of the local controller.
  // OGF: 0x0003
  // OCF: 0x0045
  // Command parameters:
  //   Inquiry Mode (1 octet)
  //     0x00: Standard inquiry result event format.
  //     0x01: Inquiry result format with RSSI.
  //     0x02: Inquiry result with RSSI format or extended inquiry result
  //     format.
  //     0x03-0xFF: Reserved.
  void HciWriteInquiryMode(const std::vector<std::uint8_t>& args);

  // Writes the Page Scan Type configuration parameter of the local controller.
  // OGF: 0x0003
  // OCF: 0x0047
  // Command parameters:
  //   Page Scan Type (1 octet)
  //     0x00: Standard scan.
  //     0x01: Interlaced scan.
  //     0x02-0xFF: Reserved.
  void HciWritePageScanType(const std::vector<std::uint8_t>& args);

  // Writes the Inquiry Scan Type configuration parameter of the local
  // controller.
  // OGF: 0x0003
  // OCF: 0x0043
  // Command parameters:
  //   Scan Type (1 octet)
  //     0x00: Standard scan.
  //     0x01: Interlaced scan.
  //     0x02-0xFF: Reserved.
  void HciWriteInquiryScanType(const std::vector<std::uint8_t>& args);

  // Write the value for the class of device parameter.
  // OGF: 0x0003
  // OCF: 0x0024
  // Command parameters:
  //   Class of Device (3 octets)
  void HciWriteClassOfDevice(const std::vector<std::uint8_t>& args);

  // Writes the value that defines the maximum time the local link manager shall
  // wait for a baseband page response from the remote device at a locally
  // initiated connection attempt.
  // OGF: 0x0003
  // OCF: 0x0018
  // Command parameters:
  //   Page Timeout (2 octets)
  //     0: Illegal page timeout, must be larger than 0.
  //     0xXXXX: Page timeout measured in number of baseband slots.
  void HciWritePageTimeout(const std::vector<std::uint8_t>& args);

  // Writes the default link policy configuration value which determines the
  // initial value of the link policy settings for all new BR/EDR connections.
  // OGF: 0x0002
  // OCF: 0x000F
  // Command parameters:
  //   Default Link Policy Settings (2 octets)
  //     0x0000: Disable all LM modes default.
  //     0x0001: Enable role switch.
  //     0x0002: Enable hold mode.
  //     0x0004: Enable sniff mode.
  //     0x0008: Enable park state.
  //     0x0010-0x8000: Reserved.
  void HciWriteDefaultLinkPolicySettings(const std::vector<std::uint8_t>& args);

  // Reads the stored user-friendly name for the controller.
  // OGF: 0x0003
  // OCF: 0x0014
  // Command parameters: none.
  void HciReadLocalName(const std::vector<std::uint8_t>& args);

  // Reads the stored user-friendly name for the controller.
  // OGF: 0x0003
  // OCF: 0x0013
  // Command parameters:
  //   Local Name (248 octets)
  void HciWriteLocalName(const std::vector<std::uint8_t>& args);

  // Writes the extended inquiry response to be sent during the extended inquiry
  // ersponse procedure.
  // OGF: 0x0003
  // OCF: 0x0052
  // Command parameters:
  //   FEC Required (1 octet)
  //     0x00: FEC is not required.
  //     0x01: FEC is required.
  //     0x02-0xFF: Reserved.
  void HciWriteExtendedInquiryResponse(const std::vector<std::uint8_t>& args);

  // Writes the values for the voice setting configuration paramter.
  // OGF: 0x0003
  // OCF: 0x0026
  // Command parameters:
  //   Voice setting (2 octets, 10 bits meaningful)
  //     See Section 6.12 (page 482).
  void HciWriteVoiceSetting(const std::vector<std::uint8_t>& args);

  // Writes the LAP(s) used to create the Inquiry Access Codes that the local
  // controller is simultaneously scanning for during Inquiry Scans.
  // OGF: 0x0003
  // OCF: 0x003A
  // Command parameters:
  //   Num Current IAC (1 octet)
  //     0xXX: Specifies the number of IACs which are currently in use.
  //   IAC LAP (3 octets * Num Current IAC)
  //     0xXXXXXX: LAP(s) used to create IAC. Ranges from 0x9E8B00-0x9E8B3F.
  void HciWriteCurrentIacLap(const std::vector<std::uint8_t>& args);

  // Writes the values for the inquiry scan interval and inquiry scan window
  // configuration parameters.
  // OGF: 0x0003
  // OCF: 0x001E
  // Command parameters:
  //   Inquiry Scan Interval (2 octets)
  //     See Section 6.2 (page 478).
  //   Inquiry Scan Window (2 octets)
  //     See Section 6.2 (page 479).
  void HciWriteInquiryScanActivity(const std::vector<std::uint8_t>& args);

  // Writes the value for the scan enable configuration parameter.
  // OGF: 0x0003
  // OCF: 0x001A
  // Command parameters:
  //   Scan Enable (1 octet)
  //     0x00: No scans enabled (default).
  //     0x01: Inquiry scan enabled. Page scan disabled.
  //     0x02: Inquiry scan disable. Page scan enabled.
  //     0x03: Inquiry scan enabled. Page scan enabled.
  //     0x04-0xFF: Reserved.
  void HciWriteScanEnable(const std::vector<std::uint8_t>& args);

  // Used by the host to specify different event filters.
  // OGF: 0x0003
  // OCF: 0x0005
  // Command parameters:
  //   Filter Type (1 octet)
  //     0x00: Clear all filters.
  //     0x01: Inquiry result.
  //     0x02: Connection setup.
  //     0x03-0xFF: Reserved.
  //   Filter Condition Type (1 octet)
  //     0x00: Return responses from all devices during the inquiry response.
  //     0x01: A device with a specific class of device responded to the inquiry
  //           process.
  //     0x02: A device with a specific BD Address responded to the inquiry
  //           process.
  //     0x03-0xFF: Reserved.
  //   Condition (1 octet)
  //     0x00: Allow connections from all devices.
  //     0x01: Allow connections from a device with a specific class of device.
  //     0x02: Allow connections from a device with a specific BD Address.
  //     0x03-0xFF: Reserved.
  void HciSetEventFilter(const std::vector<std::uint8_t>& args);

  // Causes the BREDR Controller to enter inquiry mode where other nearby
  // controllers can be discovered.
  // OGF: 0x0001
  // OCF: 0x0001
  // Command parameters:
  //   LAP (3 octets)
  //     0x9E8B00-0x9E8B3F: LAP from which the inquiry access code should be
  //     derived when the inquiry procedure is made.
  //   Inquiry Length (1 octet)
  //     0xXX: Maximum amount of time specified before the inquiry is halted.
  //   Num Responses (1 octet)
  //     0x00: Unlimited number of responses.
  //     0xXX: Maximum number of responses from the inquiry before the inquiry
  //           is halted.
  void HciInquiry(const std::vector<std::uint8_t>& args);

  // Test Channel commands:

  // Clears all test channel modifications.
  void TestChannelClear(const std::vector<std::string>& args);

  // Sets the response delay for events to 0.
  void TestChannelClearEventDelay(const std::vector<std::string>& args);

  // Discovers a fake device.
  void TestChannelDiscover(const std::vector<std::string>& args);

  // Causes events to be sent after a delay.
  void TestChannelSetEventDelay(const std::vector<std::string>& args);

  // Causes all future HCI commands to timeout.
  void TestChannelTimeoutAll(const std::vector<std::string>& args);

 private:
  // Current link layer state of the controller.
  enum State {
    kStandby,  // Not receiving/transmitting any packets from/to other devices.
    kAdvertising,  // Transmitting advertising packets.
    kScanning,  // Listening for advertising packets.
    kInitiating,  // Listening for advertising packets from a specific device.
    kConnection,  // In a connection.
  };

  enum TestChannelState {
    kNone,  // The controller is running normally.
    kTimeoutAll,  // All commands should time out, i.e. send no response.
    kDelayedResponse,  // Event responses are sent after a delay.
  };

  // Creates a command complete event and sends it back to the HCI.
  void SendCommandComplete(uint16_t command_opcode,
                           const std::vector<uint8_t>& return_parameters) const;

  // Sends a command complete event with no return parameters. This event is
  // typically sent for commands that can be completed immediately.
  void SendCommandCompleteSuccess(uint16_t command_opcode) const;

  // Creates a command status event and sends it back to the HCI.
  void SendCommandStatus(uint16_t command_opcode) const;

  // Sends a command status event with default event parameters.
  void SendCommandStatusSuccess(uint16_t command_opcode) const;

  // Sends an inquiry response for a fake device.
  void SendInquiryResult() const;

  // Sends an extended inquiry response for a fake device.
  void SendExtendedInquiryResult(const std::string& name,
                                 const std::string& address) const;

  void SetEventDelay(std::int64_t delay);

  // Callback provided to send events from the controller back to the HCI.
  std::function<void(std::unique_ptr<EventPacket>)> send_event_;

  std::function<void(std::unique_ptr<EventPacket>, base::TimeDelta)>
      send_delayed_event_;

  // Maintains the commands to be registered and used in the HciHandler object.
  // Keys are command opcodes and values are the callbacks to handle each
  // command.
  std::unordered_map<std::uint16_t,
                     std::function<void(const std::vector<std::uint8_t>&)>>
      active_hci_commands_;

  std::unordered_map<std::string,
                     std::function<void(const std::vector<std::string>&)>>
      active_test_channel_commands_;

  // Specifies the format of Inquiry Result events to be returned during the
  // Inquiry command.
  // 0x00: Standard Inquiry Result event format (default).
  // 0x01: Inquiry Result format with RSSI.
  // 0x02 Inquiry Result with RSSI format or Extended Inquiry Result format.
  // 0x03-0xFF: Reserved.
  std::uint8_t inquiry_mode_;

  State state_;

  Properties properties_;

  TestChannelState test_channel_state_;

  DISALLOW_COPY_AND_ASSIGN(DualModeController);
};

}  // namespace test_vendor_lib
