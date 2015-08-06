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

#define LOG_TAG "bredr_controller"

#include "vendor_libs/test_vendor_lib/include/bredr_controller.h"

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

// Creates a command complete event and sends it back to the HCI.
void SendCommandComplete(uint16_t command_opcode,
                         const std::vector<uint8_t>& return_parameters) {
  std::unique_ptr<test_vendor_lib::EventPacket> command_complete =
      test_vendor_lib::EventPacket::CreateCommandCompleteEvent(
          kNumHciCommandPackets, command_opcode, return_parameters);
  // TODO(dennischeng): Should this dependency on HciTransport be removed?
  test_vendor_lib::HciTransport::Get()->SendEvent(std::move(command_complete));
}

// Sends a command complete event with no return parameters. This event is
// typically sent for commands that can be completed immediately.
void SendEmptySuccessCommandComplete(uint16_t command_opcode) {
  SendCommandComplete(command_opcode, {kReturnStatusSuccess});
}

// Creates a command status event and sends it back to the HCI.
void SendCommandStatus(uint16_t command_opcode) {
  std::unique_ptr<test_vendor_lib::EventPacket> command_status =
      test_vendor_lib::EventPacket::CreateCommandStatusEvent(
          kNumHciCommandPackets, command_opcode);
  // TODO(dennischeng): Should this dependency on HciTransport be removed?
  test_vendor_lib::HciTransport::Get()->SendEvent(std::move(command_status));
}

void SendEmptySuccessCommandStatus(uint16_t command_opcode) {
  SendCommandComplete(command_opcode, {kReturnStatusSuccess});
}

// Sends an inquiry response for a fake device.
void SendInquiryResult() {
  std::unique_ptr<test_vendor_lib::EventPacket> inquiry_result =
      test_vendor_lib::EventPacket::CreateInquiryResultEvent(
          1, kOtherDeviceBdAddress, kPageScanRepetitionMode,
          kPageScanPeriodMode, kPageScanMode, kClassOfDevice, kClockOffset);
  // TODO(dennischeng): Should this dependency on HciTransport be removed?
  test_vendor_lib::HciTransport::Get()->SendEvent(std::move(inquiry_result));
}

// Sends an extended inquiry response for a fake device.
void SendExtendedInquiryResult() {
  std::vector<uint8_t> rssi = {0};
  std::vector<uint8_t> extended_inquiry_data = {7, 0x09,
                                                'F', 'o', 'o', 'B', 'a', 'r'};
  // TODO(dennischeng): Use constants for parameter sizes, here and elsewhere.
  while (extended_inquiry_data.size() < 240) {
    extended_inquiry_data.push_back(0);
  }
  std::unique_ptr<test_vendor_lib::EventPacket> extended_inquiry_result =
      test_vendor_lib::EventPacket::CreateExtendedInquiryResultEvent(
          kOtherDeviceBdAddress, kPageScanRepetitionMode, kPageScanPeriodMode,
          kClassOfDevice, kClockOffset, rssi, extended_inquiry_data);
  // TODO(dennischeng): Should this dependency on HciTransport be removed?
  test_vendor_lib::HciTransport::Get()->SendEvent(
      std::move(extended_inquiry_result));
}

void LogCommand(const char* command) {
  LOG_INFO(LOG_TAG, "Controller performing command: %s", command);
}

}  // namespace

namespace test_vendor_lib {

// Global controller instance used in the vendor library.
// TODO(dennischeng): Should this be moved to an unnamed namespace?
BREDRController* g_controller = nullptr;

// static
BREDRController* BREDRController::Get() {
  // Initialize should have been called already.
  CHECK(g_controller);
  return g_controller;
}

// static
void BREDRController::Initialize() {
  // Multiple calls to Initialize should not be made.
  CHECK(!g_controller);
  g_controller = new BREDRController();
}

// static
void BREDRController::CleanUp() {
  delete g_controller;
  g_controller = nullptr;
}

BREDRController::BREDRController() {
#define SET_HANDLER(opcode, command) \
  active_commands_[opcode] =         \
      std::bind(&BREDRController::command, this, std::placeholders::_1);
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
}

void BREDRController::RegisterHandlerCallbacks() {
  HciHandler* handler = HciHandler::Get();
  for (auto it = active_commands_.begin(); it != active_commands_.end(); ++it) {
    handler->RegisterControllerCallback(it->first, it->second);
  }
}

// TODO(dennischeng): Store relevant arguments from commands as attributes of
// the controller.

void BREDRController::HciReset(const std::vector<uint8_t>& /* args */) {
  LogCommand("Reset");
  SendEmptySuccessCommandComplete(HCI_RESET);
}

void BREDRController::HciReadBufferSize(
    const std::vector<uint8_t>& /* args */) {
  LogCommand("Read Buffer Size");
  SendCommandComplete(HCI_READ_BUFFER_SIZE, kBufferSize);
}

void BREDRController::HciHostBufferSize(
    const std::vector<uint8_t>& /* args */) {
  LogCommand("Host Buffer Size");
  SendEmptySuccessCommandComplete(HCI_HOST_BUFFER_SIZE);
}

void BREDRController::HciReadLocalVersionInformation(
                 const std::vector<uint8_t>& /* args */) {
  LogCommand("Read Local Version Information");
  SendCommandComplete(HCI_READ_LOCAL_VERSION_INFO, kLocalVersionInformation);
}

void BREDRController::HciReadBdAddr(const std::vector<uint8_t>& /* args */) {
  LogCommand("Read Bd Addr");
  SendCommandComplete(HCI_READ_BD_ADDR, kBdAddress);
}

void BREDRController::HciReadLocalSupportedCommands(
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

void BREDRController::HciReadLocalExtendedFeatures(
    const std::vector<uint8_t>& /* args */) {
  LogCommand("Read Local Extended Features");
  SendCommandComplete(HCI_READ_LOCAL_EXT_FEATURES, kLocalExtendedFeatures);
}

void BREDRController::HciWriteSimplePairingMode(
    const std::vector<uint8_t>& /* args */) {
  LogCommand("Write Simple Pairing Mode");
  SendEmptySuccessCommandComplete(HCI_WRITE_SIMPLE_PAIRING_MODE);
}

void BREDRController::HciWriteLeHostSupport(
    const std::vector<uint8_t>& /* args */) {
  LogCommand("Write Le Host Support");
  SendEmptySuccessCommandComplete(HCI_WRITE_LE_HOST_SUPPORT);
}

void BREDRController::HciSetEventMask(const std::vector<uint8_t>& /* args */) {
  LogCommand("Set Event Mask");
  SendEmptySuccessCommandComplete(HCI_SET_EVENT_MASK);
}

void BREDRController::HciWriteInquiryMode(const std::vector<uint8_t>& args) {
  LogCommand("Write Inquiry Mode");
  CHECK(args.size() == 1);
  inquiry_mode_ = args[0];
  SendEmptySuccessCommandComplete(HCI_WRITE_INQUIRY_MODE);
}

void BREDRController::HciWritePageScanType(
    const std::vector<uint8_t>& /* args */) {
  LogCommand("Write Page Scan Type");
  SendEmptySuccessCommandComplete(HCI_WRITE_PAGESCAN_TYPE);
}

void BREDRController::HciWriteInquiryScanType(
    const std::vector<uint8_t>& /* args */) {
  LogCommand("Write Inquiry Scan Type");
  SendEmptySuccessCommandComplete(HCI_WRITE_INQSCAN_TYPE);
}

void BREDRController::HciWriteClassOfDevice(
    const std::vector<uint8_t>& /* args */) {
  LogCommand("Write Class Of Device");
  SendEmptySuccessCommandComplete(HCI_WRITE_CLASS_OF_DEVICE);
}

void BREDRController::HciWritePageTimeout(
    const std::vector<uint8_t>& /* args */) {
  LogCommand("Write Page Timeout");
  SendEmptySuccessCommandComplete(HCI_WRITE_PAGE_TOUT);
}

void BREDRController::HciWriteDefaultLinkPolicySettings(
    const std::vector<uint8_t>& /* args */) {
  LogCommand("Write Default Link Policy Settings");
  SendEmptySuccessCommandComplete(HCI_WRITE_DEF_POLICY_SETTINGS);
}

void BREDRController::HciReadLocalName(const std::vector<uint8_t>& /* args */) {
  LogCommand("Get Local Name");
  std::vector<uint8_t> return_parameters;
  return_parameters.reserve(249);
  return_parameters.push_back(kReturnStatusSuccess);
  for (int i = 0; i < 249; ++i) {
    return_parameters.push_back(0xFF);
  }
  SendCommandComplete(HCI_READ_LOCAL_NAME, return_parameters);
}

void BREDRController::HciWriteLocalName(
    const std::vector<uint8_t>& /* args */) {
  LogCommand("Write Local Name");
  SendEmptySuccessCommandComplete(HCI_CHANGE_LOCAL_NAME);
}

void BREDRController::HciWriteExtendedInquiryResponse(
    const std::vector<uint8_t>& /* args */) {
  LogCommand("Write Extended Inquiry Response");
  SendEmptySuccessCommandComplete(HCI_WRITE_EXT_INQ_RESPONSE);
}

void BREDRController::HciWriteVoiceSetting(
    const std::vector<uint8_t>& /* args */) {
  LogCommand("Write Voice Setting");
  SendEmptySuccessCommandComplete(HCI_WRITE_VOICE_SETTINGS);
}

void BREDRController::HciWriteCurrentIacLap(
    const std::vector<uint8_t>& /* args */) {
  LogCommand("Write Current IAC LAP");
  SendEmptySuccessCommandComplete(HCI_WRITE_CURRENT_IAC_LAP);
}

void BREDRController::HciWriteInquiryScanActivity(
    const std::vector<uint8_t>& /* args */) {
  LogCommand("Write Inquiry Scan Activity");
  SendEmptySuccessCommandComplete(HCI_WRITE_INQUIRYSCAN_CFG);
}

void BREDRController::HciWriteScanEnable(
    const std::vector<uint8_t>& /* args */) {
  LogCommand("Write Scan Enable");
  SendEmptySuccessCommandComplete(HCI_WRITE_SCAN_ENABLE);
}

void BREDRController::HciSetEventFilter(
    const std::vector<uint8_t>& /* args */) {
  LogCommand("Set Event Filter");
  SendEmptySuccessCommandComplete(HCI_SET_EVENT_FILTER);
}

void BREDRController::HciInquiry(const std::vector<uint8_t>& /* args */) {
  LogCommand("Inquiry");
  SendEmptySuccessCommandStatus(HCI_INQUIRY);
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
