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

#define LOG_TAG "dual_mode_controller"

#include "vendor_libs/test_vendor_lib/include/dual_mode_controller.h"

#include "base/logging.h"
#include "vendor_libs/test_vendor_lib/include/event_packet.h"
#include "vendor_libs/test_vendor_lib/include/hci_handler.h"
#include "vendor_libs/test_vendor_lib/include/hci_transport.h"

extern "C" {
#include "stack/include/hcidefs.h"
#include "osi/include/log.h"
}  // extern "C"

namespace {

// Controller constants and packaged command return parameters.
// All page numbers refer to the Bluetooth Core Specification, Version 4.2,
// Volume 2, Part E, Secion 7.1.
// TODO(dennischeng): Move this into member variables so the controller is
// configurable.

// Included in certain events to indicate the successful completion of the
// associated command.
const uint8_t kReturnStatusSuccess = 0;

// The default number encoded in event packets to indicate to the HCI how many
// command packets it can send to the controller.
const uint8_t kNumHciCommandPackets = 1;

// Command: Read Buffer Size (page 794).
// Tells the host size information for data packets.
// Opcode: HCI_READ_BUFFER_SIZE.
// Maximum length in octets of the data portion of each HCI ACL/SCO data packet
// that the controller can accept.
const uint16_t kHciAclDataPacketSize = 1024;
const uint8_t kHciScoDataPacketSize = 255;

// Total number of HCI ACL/SCO data packets that can be stored in the data
// buffers of the controller.
const uint16_t kHciTotalNumAclDataPackets = 10;
const uint16_t kHciTotalNumScoDataPackets = 10;
const std::vector<uint8_t> kBufferSize = {kReturnStatusSuccess,
                                          kHciAclDataPacketSize,
                                          0,
                                          kHciScoDataPacketSize,
                                          kHciTotalNumAclDataPackets,
                                          0,
                                          kHciTotalNumScoDataPackets,
                                          0};

// Command: Read Local Version Information (page 788).
// The values for the version information for the controller.
// Opcode: HCI_READ_LOCAL_VERSION_INFO.
const uint8_t kHciVersion = 0;
const uint16_t kHciRevision = 0;
const uint8_t kLmpPalVersion = 0;
const uint16_t kManufacturerName = 0;
const uint16_t kLmpPalSubversion = 0;
const std::vector<uint8_t> kLocalVersionInformation = {
    kReturnStatusSuccess, kHciVersion, kHciRevision,      0, kLmpPalVersion,
    kManufacturerName,    0,           kLmpPalSubversion, 0};

// Command: Read Local Extended Features (page 792).
// The requested page of extended LMP features.
// Opcode: HCI_READ_LOCAL_EXT_FEATURES.
const uint8_t kPageNumber = 0;
const uint8_t kMaximumPageNumber = 0;
const std::vector<uint8_t> kLocalExtendedFeatures = {kReturnStatusSuccess,
                                                     kPageNumber,
                                                     kMaximumPageNumber,
                                                     0xFF,
                                                     0xFF,
                                                     0xFF,
                                                     0xFF,
                                                     0xFF,
                                                     0xFF,
                                                     0xFF,
                                                     0xFF};
// Command: Read BR_ADDR (page 796).
// The Bluetooth Controller address.
// Opcode: HCI_READ_BD_ADDR.
const std::vector<uint8_t> kBdAddress = {
    kReturnStatusSuccess, 1, 2, 3, 4, 5, 6};

// Inquiry modes for specifiying inquiry result formats.
const uint8_t kStandardInquiry = 0x00;
const uint8_t kRssiInquiry = 0x01;
const uint8_t kExtendedOrRssiInquiry = 0x02;

// The (fake) bd address of another device.
const std::vector<uint8_t> kOtherDeviceBdAddress = {6, 5, 4, 3, 2, 1};

// Fake inquiry response for a fake device.
const std::vector<uint8_t> kPageScanRepetitionMode = {0};
const std::vector<uint8_t> kPageScanPeriodMode = {0};
const std::vector<uint8_t> kPageScanMode = {0};
const std::vector<uint8_t> kClassOfDevice = {1, 2, 3};
const std::vector<uint8_t> kClockOffset = {1, 2};

void LogCommand(const char* command) {
  LOG_INFO(LOG_TAG, "Controller performing command: %s", command);
}

}  // namespace

namespace test_vendor_lib {

void DualModeController::SendCommandComplete(
    uint16_t command_opcode,
    const std::vector<uint8_t>& return_parameters) const {
  std::unique_ptr<EventPacket> command_complete =
      EventPacket::CreateCommandCompleteEvent(
          kNumHciCommandPackets, command_opcode, return_parameters);
  send_event_(std::move(command_complete));
}

void DualModeController::SendCommandCompleteSuccess(
    uint16_t command_opcode) const {
  SendCommandComplete(command_opcode, {kReturnStatusSuccess});
}

void DualModeController::SendCommandStatus(uint16_t command_opcode) const {
  std::unique_ptr<EventPacket> command_status =
      EventPacket::CreateCommandStatusEvent(kNumHciCommandPackets,
                                            command_opcode);
  send_event_(std::move(command_status));
}

void DualModeController::SendCommandStatusSuccess(
    uint16_t command_opcode) const {
  SendCommandComplete(command_opcode, {kReturnStatusSuccess});
}

void DualModeController::SendInquiryResult() const {
  std::unique_ptr<EventPacket> inquiry_result =
      EventPacket::CreateInquiryResultEvent(
          1, kOtherDeviceBdAddress, kPageScanRepetitionMode,
          kPageScanPeriodMode, kPageScanMode, kClassOfDevice, kClockOffset);
  send_event_(std::move(inquiry_result));
}

void DualModeController::SendExtendedInquiryResult() const {
  std::vector<uint8_t> rssi = {0};
  std::vector<uint8_t> extended_inquiry_data = {7, 0x09,
                                                'F', 'o', 'o', 'B', 'a', 'r'};
  // TODO(dennischeng): Use constants for parameter sizes, here and elsewhere.
  while (extended_inquiry_data.size() < 240) {
    extended_inquiry_data.push_back(0);
  }
  std::unique_ptr<EventPacket> extended_inquiry_result =
      EventPacket::CreateExtendedInquiryResultEvent(
          kOtherDeviceBdAddress, kPageScanRepetitionMode, kPageScanPeriodMode,
          kClassOfDevice, kClockOffset, rssi, extended_inquiry_data);
  send_event_(std::move(extended_inquiry_result));
}

DualModeController::DualModeController() : state_(kStandby) {
#define SET_HANDLER(opcode, method) \
  active_commands_[opcode] =        \
      std::bind(&DualModeController::method, this, std::placeholders::_1);
  SET_HANDLER(HCI_RESET, HciReset);
  SET_HANDLER(HCI_READ_BUFFER_SIZE, HciReadBufferSize);
  SET_HANDLER(HCI_HOST_BUFFER_SIZE, HciHostBufferSize);
  SET_HANDLER(HCI_READ_LOCAL_VERSION_INFO, HciReadLocalVersionInformation);
  SET_HANDLER(HCI_READ_BD_ADDR, HciReadBdAddr);
  SET_HANDLER(HCI_READ_LOCAL_SUPPORTED_CMDS, HciReadLocalSupportedCommands);
  SET_HANDLER(HCI_READ_LOCAL_EXT_FEATURES, HciReadLocalExtendedFeatures);
  SET_HANDLER(HCI_WRITE_SIMPLE_PAIRING_MODE, HciWriteSimplePairingMode);
  SET_HANDLER(HCI_WRITE_LE_HOST_SUPPORT, HciWriteLeHostSupport);
  SET_HANDLER(HCI_SET_EVENT_MASK, HciSetEventMask);
  SET_HANDLER(HCI_WRITE_INQUIRY_MODE, HciWriteInquiryMode);
  SET_HANDLER(HCI_WRITE_PAGESCAN_TYPE, HciWritePageScanType);
  SET_HANDLER(HCI_WRITE_INQSCAN_TYPE, HciWriteInquiryScanType);
  SET_HANDLER(HCI_WRITE_CLASS_OF_DEVICE, HciWriteClassOfDevice);
  SET_HANDLER(HCI_WRITE_PAGE_TOUT, HciWritePageTimeout);
  SET_HANDLER(HCI_WRITE_DEF_POLICY_SETTINGS, HciWriteDefaultLinkPolicySettings);
  SET_HANDLER(HCI_READ_LOCAL_NAME, HciReadLocalName);
  SET_HANDLER(HCI_CHANGE_LOCAL_NAME, HciWriteLocalName);
  SET_HANDLER(HCI_WRITE_EXT_INQ_RESPONSE, HciWriteExtendedInquiryResponse);
  SET_HANDLER(HCI_WRITE_VOICE_SETTINGS, HciWriteVoiceSetting);
  SET_HANDLER(HCI_WRITE_CURRENT_IAC_LAP, HciWriteCurrentIacLap);
  SET_HANDLER(HCI_WRITE_INQUIRYSCAN_CFG, HciWriteInquiryScanActivity);
  SET_HANDLER(HCI_WRITE_SCAN_ENABLE, HciWriteScanEnable);
  SET_HANDLER(HCI_SET_EVENT_FILTER, HciSetEventFilter);
  SET_HANDLER(HCI_INQUIRY, HciInquiry);
#undef SET_HANDLER

#define SET_TEST_HANDLER(command_name, method)  \
  test_channel_active_commands_[command_name] = \
      std::bind(&DualModeController::method, this, std::placeholders::_1);
  SET_TEST_HANDLER("TimeoutAll", UciTimeoutAll);
#undef SET_TEST_HANDLER
}

void DualModeController::RegisterCommandsWithHandler(HciHandler& handler) {
  for (auto it = active_commands_.begin(); it != active_commands_.end(); ++it) {
    handler.RegisterControllerCommand(it->first, it->second);
  }
}

void DualModeController::RegisterCommandsWithTestChannelHandler(
    TestChannelHandler& handler) {
  for (auto it = test_channel_active_commands_.begin();
       it != test_channel_active_commands_.end(); ++it) {
    handler.RegisterControllerCommand(it->first, it->second);
  }
}

void DualModeController::RegisterEventChannel(
    std::function<void(std::unique_ptr<EventPacket>)> callback) {
  send_event_ = callback;
}

void DualModeController::UciTimeoutAll(const std::vector<std::uint8_t>& args) {
  LogCommand("Uci Timeout All");
}

// TODO(dennischeng): Store relevant arguments from commands as attributes of
// the controller.

void DualModeController::HciReset(const std::vector<uint8_t>& /* args */) {
  LogCommand("Reset");
  state_ = kStandby;
  SendCommandCompleteSuccess(HCI_RESET);
}

void DualModeController::HciReadBufferSize(
    const std::vector<uint8_t>& /* args */) {
  LogCommand("Read Buffer Size");
  SendCommandComplete(HCI_READ_BUFFER_SIZE, kBufferSize);
}

void DualModeController::HciHostBufferSize(
    const std::vector<uint8_t>& /* args */) {
  LogCommand("Host Buffer Size");
  SendCommandCompleteSuccess(HCI_HOST_BUFFER_SIZE);
}

void DualModeController::HciReadLocalVersionInformation(
                 const std::vector<uint8_t>& /* args */) {
  LogCommand("Read Local Version Information");
  SendCommandComplete(HCI_READ_LOCAL_VERSION_INFO, kLocalVersionInformation);
}

void DualModeController::HciReadBdAddr(const std::vector<uint8_t>& /* args */) {
  LogCommand("Read Bd Addr");
  SendCommandComplete(HCI_READ_BD_ADDR, kBdAddress);
}

void DualModeController::HciReadLocalSupportedCommands(
    const std::vector<uint8_t>& /* args */) {
  LogCommand("Read Local Supported Commands");
  std::vector<uint8_t> return_parameters;
  return_parameters.reserve(65);
  return_parameters.push_back(kReturnStatusSuccess);
  for (int i = 0; i < 64; ++i) {
    return_parameters.push_back(0xFF);
  }
  SendCommandComplete(HCI_READ_LOCAL_SUPPORTED_CMDS, return_parameters);
}

void DualModeController::HciReadLocalExtendedFeatures(
    const std::vector<uint8_t>& /* args */) {
  LogCommand("Read Local Extended Features");
  SendCommandComplete(HCI_READ_LOCAL_EXT_FEATURES, kLocalExtendedFeatures);
}

void DualModeController::HciWriteSimplePairingMode(
    const std::vector<uint8_t>& /* args */) {
  LogCommand("Write Simple Pairing Mode");
  SendCommandCompleteSuccess(HCI_WRITE_SIMPLE_PAIRING_MODE);
}

void DualModeController::HciWriteLeHostSupport(
    const std::vector<uint8_t>& /* args */) {
  LogCommand("Write Le Host Support");
  SendCommandCompleteSuccess(HCI_WRITE_LE_HOST_SUPPORT);
}

void DualModeController::HciSetEventMask(
    const std::vector<uint8_t>& /* args */) {
  LogCommand("Set Event Mask");
  SendCommandCompleteSuccess(HCI_SET_EVENT_MASK);
}

void DualModeController::HciWriteInquiryMode(const std::vector<uint8_t>& args) {
  LogCommand("Write Inquiry Mode");
  CHECK(args.size() == 1);
  inquiry_mode_ = args[0];
  SendCommandCompleteSuccess(HCI_WRITE_INQUIRY_MODE);
}

void DualModeController::HciWritePageScanType(
    const std::vector<uint8_t>& /* args */) {
  LogCommand("Write Page Scan Type");
  SendCommandCompleteSuccess(HCI_WRITE_PAGESCAN_TYPE);
}

void DualModeController::HciWriteInquiryScanType(
    const std::vector<uint8_t>& /* args */) {
  LogCommand("Write Inquiry Scan Type");
  SendCommandCompleteSuccess(HCI_WRITE_INQSCAN_TYPE);
}

void DualModeController::HciWriteClassOfDevice(
    const std::vector<uint8_t>& /* args */) {
  LogCommand("Write Class Of Device");
  SendCommandCompleteSuccess(HCI_WRITE_CLASS_OF_DEVICE);
}

void DualModeController::HciWritePageTimeout(
    const std::vector<uint8_t>& /* args */) {
  LogCommand("Write Page Timeout");
  SendCommandCompleteSuccess(HCI_WRITE_PAGE_TOUT);
}

void DualModeController::HciWriteDefaultLinkPolicySettings(
    const std::vector<uint8_t>& /* args */) {
  LogCommand("Write Default Link Policy Settings");
  SendCommandCompleteSuccess(HCI_WRITE_DEF_POLICY_SETTINGS);
}

void DualModeController::HciReadLocalName(
    const std::vector<uint8_t>& /* args */) {
  LogCommand("Get Local Name");
  std::vector<uint8_t> return_parameters;
  return_parameters.reserve(249);
  return_parameters.push_back(kReturnStatusSuccess);
  for (int i = 0; i < 249; ++i) {
    return_parameters.push_back(0xFF);
  }
  SendCommandComplete(HCI_READ_LOCAL_NAME, return_parameters);
}

void DualModeController::HciWriteLocalName(
    const std::vector<uint8_t>& /* args */) {
  LogCommand("Write Local Name");
  SendCommandCompleteSuccess(HCI_CHANGE_LOCAL_NAME);
}

void DualModeController::HciWriteExtendedInquiryResponse(
    const std::vector<uint8_t>& /* args */) {
  LogCommand("Write Extended Inquiry Response");
  SendCommandCompleteSuccess(HCI_WRITE_EXT_INQ_RESPONSE);
}

void DualModeController::HciWriteVoiceSetting(
    const std::vector<uint8_t>& /* args */) {
  LogCommand("Write Voice Setting");
  SendCommandCompleteSuccess(HCI_WRITE_VOICE_SETTINGS);
}

void DualModeController::HciWriteCurrentIacLap(
    const std::vector<uint8_t>& /* args */) {
  LogCommand("Write Current IAC LAP");
  SendCommandCompleteSuccess(HCI_WRITE_CURRENT_IAC_LAP);
}

void DualModeController::HciWriteInquiryScanActivity(
    const std::vector<uint8_t>& /* args */) {
  LogCommand("Write Inquiry Scan Activity");
  SendCommandCompleteSuccess(HCI_WRITE_INQUIRYSCAN_CFG);
}

void DualModeController::HciWriteScanEnable(
    const std::vector<uint8_t>& /* args */) {
  LogCommand("Write Scan Enable");
  state_ = kScanning;
  SendCommandCompleteSuccess(HCI_WRITE_SCAN_ENABLE);
}

void DualModeController::HciSetEventFilter(
    const std::vector<uint8_t>& /* args */) {
  LogCommand("Set Event Filter");
  SendCommandCompleteSuccess(HCI_SET_EVENT_FILTER);
}

void DualModeController::HciInquiry(const std::vector<uint8_t>& /* args */) {
  LogCommand("Inquiry");
  SendCommandStatusSuccess(HCI_INQUIRY);
  switch (inquiry_mode_) {
    case (kStandardInquiry):
      SendInquiryResult();
      break;

    case (kRssiInquiry):
      LOG_INFO(LOG_TAG, "RSSI Inquiry Mode currently not supported.");
      break;

    case (kExtendedOrRssiInquiry):
      SendExtendedInquiryResult();
      break;
  }
}

}  // namespace test_vendor_lib
