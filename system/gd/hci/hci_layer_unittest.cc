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

#include "hci/hci_layer.h"

#include <gtest/gtest.h>

#include <chrono>
#include <future>

#include "common/bind.h"
#include "common/init_flags.h"
#include "common/testing/log_capture.h"
#include "hal/hci_hal.h"
#include "hci/address.h"
#include "hci/address_with_type.h"
#include "hci/class_of_device.h"
#include "hci/controller.h"
#include "module.h"
#include "os/fake_timer/fake_timerfd.h"
#include "os/handler.h"
#include "os/thread.h"
#include "packet/raw_builder.h"

using namespace std::chrono_literals;

namespace {
constexpr size_t kBufSize = 512;
constexpr char kOurAclEventHandlerWasInvoked[] = "Our ACL event handler was invoked.";
constexpr char kOurCommandCompleteHandlerWasInvoked[] = "Our command complete handler was invoked.";
constexpr char kOurCommandStatusHandlerWasInvoked[] = "Our command status handler was invoked.";
constexpr char kOurDisconnectHandlerWasInvoked[] = "Our disconnect handler was invoked.";
constexpr char kOurEventHandlerWasInvoked[] = "Our event handler was invoked.";
constexpr char kOurLeAclEventHandlerWasInvoked[] = "Our LE ACL event handler was invoked.";
constexpr char kOurLeAdvertisementEventHandlerWasInvoked[] = "Our LE advertisement event handler was invoked.";
constexpr char kOurLeDisconnectHandlerWasInvoked[] = "Our LE disconnect handler was invoked.";
constexpr char kOurLeEventHandlerWasInvoked[] = "Our LE event handler was invoked.";
constexpr char kOurLeIsoEventHandlerWasInvoked[] = "Our LE ISO event handler was invoked.";
constexpr char kOurLeReadRemoteVersionHandlerWasInvoked[] = "Our Read Remote Version complete handler was invoked.";
constexpr char kOurLeScanningEventHandlerWasInvoked[] = "Our LE scanning event handler was invoked.";
constexpr char kOurReadRemoteVersionHandlerWasInvoked[] = "Our Read Remote Version complete handler was invoked.";
constexpr char kOurLeSecurityEventHandlerWasInvoked[] = "Our LE security event handler was invoked.";
constexpr char kOurSecurityEventHandlerWasInvoked[] = "Our security event handler was invoked.";
constexpr std::chrono::milliseconds kDelay = std::chrono::milliseconds(100);
}  // namespace

namespace bluetooth {
namespace hci {

using common::BidiQueue;
using common::BidiQueueEnd;
using common::InitFlags;
using os::fake_timer::fake_timerfd_advance;
using packet::kLittleEndian;
using packet::PacketView;
using packet::RawBuilder;
using testing::LogCapture;

std::vector<uint8_t> GetPacketBytes(std::unique_ptr<packet::BasePacketBuilder> packet) {
  std::vector<uint8_t> bytes;
  BitInserter i(bytes);
  bytes.reserve(packet->size());
  packet->Serialize(i);
  return bytes;
}

std::unique_ptr<packet::BasePacketBuilder> CreatePayload(std::vector<uint8_t> payload) {
  auto raw_builder = std::make_unique<packet::RawBuilder>();
  raw_builder->AddOctets(payload);
  return raw_builder;
}

class TestHciHal : public hal::HciHal {
 public:
  TestHciHal() : hal::HciHal() {}

  ~TestHciHal() {
    ASSERT(callbacks == nullptr);
  }

  void registerIncomingPacketCallback(hal::HciHalCallbacks* callback) override {
    callbacks = callback;
  }

  void unregisterIncomingPacketCallback() override {
    callbacks = nullptr;
  }

  void sendHciCommand(hal::HciPacket command) override {
    outgoing_commands_.push_back(std::move(command));
    sent_commands_++;
    LOG_DEBUG("Enqueued HCI command %d in HAL.", sent_commands_);
  }

  void sendScoData(hal::HciPacket data) override {}
  void sendIsoData(hal::HciPacket data) override {}
  void sendAclData(hal::HciPacket data) override {}

  hal::HciHalCallbacks* callbacks = nullptr;

  PacketView<kLittleEndian> GetPacketView(hal::HciPacket data) {
    auto shared = std::make_shared<std::vector<uint8_t>>(data);
    return PacketView<kLittleEndian>(shared);
  }

  CommandView GetSentCommand() {
    auto packetview = GetPacketView(std::move(outgoing_commands_.front()));
    outgoing_commands_.pop_front();
    return CommandView::Create(packetview);
  }

  bool IsOutgoingCommandsEmpty() const {
    return outgoing_commands_.empty();
  }

  void Start() override {}

  void Stop() override {}

  void ListDependencies(ModuleList*) const override {}

  int GetPendingCommands() {
    return outgoing_commands_.size();
  }

  std::string ToString() const override {
    return std::string("TestHciHal");
  }

  void InjectResetCompleteEventWithCode(ErrorCode code) {
    auto reset_complete = ResetCompleteBuilder::Create(0x01, code);
    InjectEvent(std::move(reset_complete));
  }

  void InjectEvent(std::unique_ptr<packet::BasePacketBuilder> packet) {
    callbacks->hciEventReceived(GetPacketBytes(std::move(packet)));
  }
  static const ModuleFactory Factory;

 private:
  std::list<hal::HciPacket> outgoing_commands_;
  std::unique_ptr<std::promise<void>> sent_command_promise_;
  int sent_commands_{0};
};

const ModuleFactory TestHciHal::Factory = ModuleFactory([]() { return new TestHciHal(); });

class HciLayerTest : public ::testing::Test {
 protected:
  void SetUp() override {
    log_capture_ = std::make_unique<LogCapture>();
    hal_ = new TestHciHal();
    fake_registry_.InjectTestModule(&hal::HciHal::Factory, hal_);
    fake_registry_.Start<HciLayer>(&fake_registry_.GetTestThread());
    hci_ = static_cast<HciLayer*>(fake_registry_.GetModuleUnderTest(&HciLayer::Factory));
    hci_handler_ = fake_registry_.GetTestModuleHandler(&HciLayer::Factory);
    ASSERT_TRUE(fake_registry_.IsStarted<HciLayer>());
    ::testing::FLAGS_gtest_death_test_style = "threadsafe";
    InitFlags::SetAllForTesting();
    sync_handler();
  }

  void TearDown() override {
    fake_registry_.SynchronizeModuleHandler(&HciLayer::Factory, std::chrono::milliseconds(20));
    fake_registry_.StopAll();
  }

  void FakeTimerAdvance(uint64_t ms) {
    hci_handler_->Post(common::BindOnce(fake_timerfd_advance, ms));
  }

  void FailIfResetNotSent() {
    hci_handler_->BindOnceOn(this, &HciLayerTest::fail_if_reset_not_sent).Invoke();
    sync_handler();
  }

  void fail_if_reset_not_sent() {
    std::promise<void> promise;
    log_capture_->WaitUntilLogContains(&promise, "Enqueued HCI command 1 in HAL.");
    auto sent_command = hal_->GetSentCommand();
    auto reset_view = ResetView::Create(CommandView::Create(sent_command));
    ASSERT_TRUE(reset_view.IsValid());
  }

  void sync_handler(const std::chrono::milliseconds delay = std::chrono::milliseconds(0)) {
    std::promise<void> promise;
    auto future = promise.get_future();
    hci_handler_->BindOnceOn(&promise, &std::promise<void>::set_value).Invoke();
    ASSERT_EQ(std::future_status::ready, future.wait_for(2s));
    std::promise<void> promise2;
    auto future2 = promise2.get_future();
    ASSERT_EQ(std::future_status::timeout, future2.wait_for(delay));
  }

  TestHciHal* hal_ = nullptr;
  HciLayer* hci_ = nullptr;
  os::Handler* hci_handler_ = nullptr;
  TestModuleRegistry fake_registry_;
  std::unique_ptr<LogCapture> log_capture_;
};

TEST_F(HciLayerTest, setup_teardown) {}

// b/260915548
TEST_F(HciLayerTest, DISABLED_reset_command_sent_on_start) {
  FailIfResetNotSent();
}

// b/260915548
TEST_F(HciLayerTest, DISABLED_controller_debug_info_requested_on_hci_timeout) {
  FailIfResetNotSent();
  FakeTimerAdvance(HciLayer::kHciTimeoutMs.count());

  sync_handler();

  std::promise<void> promise;
  log_capture_->WaitUntilLogContains(&promise, "Enqueued HCI command 2 in HAL.");
  ASSERT_FALSE(hal_->IsOutgoingCommandsEmpty());

  auto sent_command = hal_->GetSentCommand();
  auto debug_info_view = ControllerDebugInfoView::Create(VendorCommandView::Create(sent_command));
  ASSERT_TRUE(debug_info_view.IsValid());
}

// b/260915548
TEST_F(HciLayerTest, DISABLED_abort_after_hci_restart_timeout) {
  FailIfResetNotSent();
  FakeTimerAdvance(HciLayer::kHciTimeoutMs.count());

  sync_handler();

  std::promise<void> promise;
  log_capture_->WaitUntilLogContains(&promise, "Enqueued HCI command 2 in HAL.");
  ASSERT_FALSE(hal_->IsOutgoingCommandsEmpty());

  auto sent_command = hal_->GetSentCommand();
  auto debug_info_view = ControllerDebugInfoView::Create(VendorCommandView::Create(sent_command));
  ASSERT_TRUE(debug_info_view.IsValid());

  sync_handler();

  ASSERT_DEATH(
      {
        FakeTimerAdvance(HciLayer::kHciTimeoutRestartMs.count());
        std::promise<void> promise;
        log_capture_->WaitUntilLogContains(&promise, "Done waiting for debug information after HCI timeout");
        sync_handler();
      },
      "");
}

// b/260915548
TEST_F(HciLayerTest, DISABLED_abort_on_root_inflammation_event) {
  FailIfResetNotSent();

  auto payload = CreatePayload({'0'});
  auto root_inflammation_event = BqrRootInflammationEventBuilder::Create(0x01, 0x01, std::move(payload));
  hal_->InjectEvent(std::move(root_inflammation_event));
  std::promise<void> promise;
  log_capture_->WaitUntilLogContains(&promise, "Received a Root Inflammation Event");

  sync_handler();

  ASSERT_DEATH(
      {
        FakeTimerAdvance(HciLayer::kHciTimeoutRestartMs.count());
        std::promise<void> promise;
        log_capture_->WaitUntilLogContains(&promise, "Root inflammation with reason");
        sync_handler();
      },
      "");
}

// b/260915548
TEST_F(HciLayerTest, DISABLED_successful_reset) {
  FailIfResetNotSent();
  auto error_code = ErrorCode::SUCCESS;
  hal_->InjectResetCompleteEventWithCode(error_code);
  std::promise<void> promise;
  auto buf = std::make_unique<char[]>(kBufSize);
  std::snprintf(buf.get(), kBufSize, "Reset completed with status: %s", ErrorCodeText(error_code).c_str());
  log_capture_->WaitUntilLogContains(&promise, buf.get());
}

// b/260915548
TEST_F(HciLayerTest, DISABLED_abort_if_reset_complete_returns_error) {
  ASSERT_DEATH(
      {
        FailIfResetNotSent();
        auto error_code = ErrorCode::UNSPECIFIED_ERROR;
        hal_->InjectResetCompleteEventWithCode(error_code);
        sync_handler();
        auto buf = std::make_unique<char[]>(kBufSize);
        std::snprintf(buf.get(), kBufSize, "Reset completed with status: %s", ErrorCodeText(error_code).c_str());
        std::promise<void> promise;
        log_capture_->WaitUntilLogContains(&promise, buf.get());
        sync_handler();
      },
      "");
}

// b/260915548
TEST_F(HciLayerTest, DISABLED_event_handler_is_invoked) {
  FailIfResetNotSent();
  hci_->UnregisterEventHandler(EventCode::COMMAND_COMPLETE);
  hci_->RegisterEventHandler(EventCode::COMMAND_COMPLETE, hci_handler_->Bind([](EventView view) {
    LOG_DEBUG("%s", kOurEventHandlerWasInvoked);
  }));
  auto error_code = ErrorCode::SUCCESS;
  hal_->InjectResetCompleteEventWithCode(error_code);
  std::promise<void> promise;
  log_capture_->WaitUntilLogContains(&promise, kOurEventHandlerWasInvoked);
}

// b/260915548
TEST_F(HciLayerTest, DISABLED_le_event_handler_is_invoked) {
  FailIfResetNotSent();
  hci_->RegisterLeEventHandler(SubeventCode::ENHANCED_CONNECTION_COMPLETE, hci_handler_->Bind([](LeMetaEventView view) {
    LOG_DEBUG("%s", kOurLeEventHandlerWasInvoked);
  }));
  hci::Address remote_address;
  Address::FromString("D0:05:04:03:02:01", remote_address);
  hal_->InjectEvent(LeEnhancedConnectionCompleteBuilder::Create(
      ErrorCode::SUCCESS,
      0x0041,
      Role::PERIPHERAL,
      AddressType::PUBLIC_DEVICE_ADDRESS,
      remote_address,
      Address::kEmpty,
      Address::kEmpty,
      0x0024,
      0x0000,
      0x0011,
      ClockAccuracy::PPM_30));
  std::promise<void> promise;
  log_capture_->WaitUntilLogContains(&promise, kOurLeEventHandlerWasInvoked);
}

// b/260915548
TEST_F(HciLayerTest, DISABLED_abort_on_second_register_event_handler) {
  ASSERT_DEATH(
      {
        FailIfResetNotSent();
        hci_->RegisterEventHandler(EventCode::COMMAND_COMPLETE, hci_handler_->Bind([](EventView view) {}));
        std::promise<void> promise;
        log_capture_->WaitUntilLogContains(&promise, "Can not register a second handler for");
        sync_handler();
      },
      "");
}

// b/260915548
TEST_F(HciLayerTest, DISABLED_abort_on_second_register_le_event_handler) {
  ASSERT_DEATH(
      {
        FailIfResetNotSent();
        hci_->RegisterLeEventHandler(
            SubeventCode::ENHANCED_CONNECTION_COMPLETE, hci_handler_->Bind([](LeMetaEventView view) {}));
        hci_->RegisterLeEventHandler(
            SubeventCode::ENHANCED_CONNECTION_COMPLETE, hci_handler_->Bind([](LeMetaEventView view) {}));
        std::promise<void> promise;
        log_capture_->WaitUntilLogContains(&promise, "Can not register a second handler for");
        sync_handler();
      },
      "");
}

// b/260915548
TEST_F(HciLayerTest, DISABLED_our_acl_event_callback_is_invoked) {
  FailIfResetNotSent();
  hci_->GetAclConnectionInterface(
      hci_handler_->Bind([](EventView view) { LOG_DEBUG("%s", kOurAclEventHandlerWasInvoked); }),
      hci_handler_->Bind([](uint16_t handle, ErrorCode reason) {}),
      hci_handler_->Bind([](hci::ErrorCode hci_status,
                            uint16_t handle,
                            uint8_t version,
                            uint16_t manufacturer_name,
                            uint16_t sub_version) {}));
  hal_->InjectEvent(ReadClockOffsetCompleteBuilder::Create(ErrorCode::SUCCESS, 0x0001, 0x0123));
  std::promise<void> promise;
  log_capture_->WaitUntilLogContains(&promise, kOurAclEventHandlerWasInvoked);
}

// b/260915548
TEST_F(HciLayerTest, DISABLED_our_disconnect_callback_is_invoked) {
  FailIfResetNotSent();
  hci_->GetAclConnectionInterface(
      hci_handler_->Bind([](EventView view) {}),
      hci_handler_->Bind([](uint16_t handle, ErrorCode reason) { LOG_DEBUG("%s", kOurDisconnectHandlerWasInvoked); }),
      hci_handler_->Bind([](hci::ErrorCode hci_status,
                            uint16_t handle,
                            uint8_t version,
                            uint16_t manufacturer_name,
                            uint16_t sub_version) {}));
  hal_->InjectEvent(
      DisconnectionCompleteBuilder::Create(ErrorCode::SUCCESS, 0x0001, ErrorCode::REMOTE_USER_TERMINATED_CONNECTION));
  std::promise<void> promise;
  log_capture_->WaitUntilLogContains(&promise, kOurDisconnectHandlerWasInvoked);
}

// b/260915548
TEST_F(HciLayerTest, DISABLED_our_read_remote_version_callback_is_invoked) {
  FailIfResetNotSent();
  hci_->GetAclConnectionInterface(
      hci_handler_->Bind([](EventView view) {}),
      hci_handler_->Bind([](uint16_t handle, ErrorCode reason) {}),
      hci_handler_->Bind([](hci::ErrorCode hci_status,
                            uint16_t handle,
                            uint8_t version,
                            uint16_t manufacturer_name,
                            uint16_t sub_version) { LOG_DEBUG("%s", kOurReadRemoteVersionHandlerWasInvoked); }));
  hal_->InjectEvent(
      ReadRemoteVersionInformationCompleteBuilder::Create(ErrorCode::SUCCESS, 0x0001, 0x0b, 0x000f, 0x0000));
  std::promise<void> promise;
  log_capture_->WaitUntilLogContains(&promise, kOurReadRemoteVersionHandlerWasInvoked);
}

// b/260915548
TEST_F(HciLayerTest, DISABLED_our_le_acl_event_callback_is_invoked) {
  FailIfResetNotSent();
  hci_->GetLeAclConnectionInterface(
      hci_handler_->Bind([](LeMetaEventView view) { LOG_DEBUG("%s", kOurLeAclEventHandlerWasInvoked); }),
      hci_handler_->Bind([](uint16_t handle, ErrorCode reason) {}),
      hci_handler_->Bind([](hci::ErrorCode hci_status,
                            uint16_t handle,
                            uint8_t version,
                            uint16_t manufacturer_name,
                            uint16_t sub_version) {}));
  hal_->InjectEvent(LeDataLengthChangeBuilder::Create(0x0001, 0x001B, 0x0148, 0x001B, 0x0148));
  std::promise<void> promise;
  log_capture_->WaitUntilLogContains(&promise, kOurLeAclEventHandlerWasInvoked);
}

// b/260915548
TEST_F(HciLayerTest, DISABLED_our_le_disconnect_callback_is_invoked) {
  FailIfResetNotSent();
  hci_->GetLeAclConnectionInterface(
      hci_handler_->Bind([](LeMetaEventView view) {}),
      hci_handler_->Bind([](uint16_t handle, ErrorCode reason) { LOG_DEBUG("%s", kOurLeDisconnectHandlerWasInvoked); }),
      hci_handler_->Bind([](hci::ErrorCode hci_status,
                            uint16_t handle,
                            uint8_t version,
                            uint16_t manufacturer_name,
                            uint16_t sub_version) {}));
  hal_->InjectEvent(
      DisconnectionCompleteBuilder::Create(ErrorCode::SUCCESS, 0x0001, ErrorCode::REMOTE_USER_TERMINATED_CONNECTION));
  std::promise<void> promise;
  log_capture_->WaitUntilLogContains(&promise, kOurLeDisconnectHandlerWasInvoked);
}

// b/260915548
TEST_F(HciLayerTest, DISABLED_our_le_read_remote_version_callback_is_invoked) {
  FailIfResetNotSent();
  hci_->GetLeAclConnectionInterface(
      hci_handler_->Bind([](LeMetaEventView view) {}),
      hci_handler_->Bind([](uint16_t handle, ErrorCode reason) {}),
      hci_handler_->Bind([](hci::ErrorCode hci_status,
                            uint16_t handle,
                            uint8_t version,
                            uint16_t manufacturer_name,
                            uint16_t sub_version) { LOG_DEBUG("%s", kOurLeReadRemoteVersionHandlerWasInvoked); }));
  hal_->InjectEvent(
      ReadRemoteVersionInformationCompleteBuilder::Create(ErrorCode::SUCCESS, 0x0001, 0x0b, 0x000f, 0x0000));
  std::promise<void> promise;
  log_capture_->WaitUntilLogContains(&promise, kOurLeReadRemoteVersionHandlerWasInvoked);
}

// b/260915548
TEST_F(HciLayerTest, DISABLED_our_security_callback_is_invoked) {
  FailIfResetNotSent();
  hci_->GetSecurityInterface(
      hci_handler_->Bind([](EventView view) { LOG_DEBUG("%s", kOurSecurityEventHandlerWasInvoked); }));
  hal_->InjectEvent(EncryptionChangeBuilder::Create(ErrorCode::SUCCESS, 0x0001, bluetooth::hci::EncryptionEnabled::ON));
  std::promise<void> promise;
  log_capture_->WaitUntilLogContains(&promise, kOurSecurityEventHandlerWasInvoked);
}

// b/260915548
TEST_F(HciLayerTest, DISABLED_our_le_security_callback_is_invoked) {
  FailIfResetNotSent();
  hci_->GetLeSecurityInterface(
      hci_handler_->Bind([](LeMetaEventView view) { LOG_DEBUG("%s", kOurLeSecurityEventHandlerWasInvoked); }));
  hal_->InjectEvent(LeLongTermKeyRequestBuilder::Create(0x0001, {0, 0, 0, 0, 0, 0, 0, 0}, 0));
  std::promise<void> promise;
  log_capture_->WaitUntilLogContains(&promise, kOurLeSecurityEventHandlerWasInvoked);
}

// b/260915548
TEST_F(HciLayerTest, DISABLED_our_le_advertising_callback_is_invoked) {
  FailIfResetNotSent();
  hci_->GetLeAdvertisingInterface(
      hci_handler_->Bind([](LeMetaEventView view) { LOG_DEBUG("%s", kOurLeAdvertisementEventHandlerWasInvoked); }));
  hal_->InjectEvent(LeAdvertisingSetTerminatedBuilder::Create(ErrorCode::SUCCESS, 0x01, 0x001, 0x01));
  std::promise<void> promise;
  log_capture_->WaitUntilLogContains(&promise, kOurLeAdvertisementEventHandlerWasInvoked);
}

// b/260915548
TEST_F(HciLayerTest, DISABLED_our_le_scanning_callback_is_invoked) {
  FailIfResetNotSent();
  hci_->GetLeScanningInterface(
      hci_handler_->Bind([](LeMetaEventView view) { LOG_DEBUG("%s", kOurLeScanningEventHandlerWasInvoked); }));
  hal_->InjectEvent(LeScanTimeoutBuilder::Create());
  std::promise<void> promise;
  log_capture_->WaitUntilLogContains(&promise, kOurLeScanningEventHandlerWasInvoked);
}

// b/260915548
TEST_F(HciLayerTest, DISABLED_our_le_iso_callback_is_invoked) {
  FailIfResetNotSent();
  hci_->GetLeIsoInterface(
      hci_handler_->Bind([](LeMetaEventView view) { LOG_DEBUG("%s", kOurLeIsoEventHandlerWasInvoked); }));
  hal_->InjectEvent(LeCisRequestBuilder::Create(0x0001, 0x0001, 0x01, 0x01));
  std::promise<void> promise;
  log_capture_->WaitUntilLogContains(&promise, kOurLeIsoEventHandlerWasInvoked);
}

// b/260915548
TEST_F(HciLayerTest, DISABLED_our_command_complete_callback_is_invoked) {
  FailIfResetNotSent();
  auto error_code = ErrorCode::SUCCESS;
  hal_->InjectResetCompleteEventWithCode(error_code);
  hci_->EnqueueCommand(ResetBuilder::Create(), hci_handler_->BindOnce([](CommandCompleteView view) {
    LOG_DEBUG("%s", kOurCommandCompleteHandlerWasInvoked);
  }));
  hal_->InjectResetCompleteEventWithCode(error_code);
  std::promise<void> promise;
  log_capture_->WaitUntilLogContains(&promise, kOurCommandCompleteHandlerWasInvoked);
}

// b/260915548
TEST_F(HciLayerTest, DISABLED_our_command_status_callback_is_invoked) {
  FailIfResetNotSent();
  auto error_code = ErrorCode::SUCCESS;
  hal_->InjectResetCompleteEventWithCode(error_code);
  hci_->EnqueueCommand(ReadClockOffsetBuilder::Create(0x001), hci_handler_->BindOnce([](CommandStatusView view) {
    LOG_DEBUG("%s", kOurCommandStatusHandlerWasInvoked);
  }));
  hal_->InjectEvent(ReadClockOffsetStatusBuilder::Create(ErrorCode::SUCCESS, 1));
  std::promise<void> promise;
  log_capture_->WaitUntilLogContains(&promise, kOurCommandStatusHandlerWasInvoked);
}

// b/260915548
TEST_F(HciLayerTest, DISABLED_command_complete_callback_is_invoked_with_an_opcode_that_does_not_match_command_queue) {
  ASSERT_DEATH(
      {
        FailIfResetNotSent();
        hci_->EnqueueCommand(
            ReadClockOffsetBuilder::Create(0x001), hci_handler_->BindOnce([](CommandCompleteView view) {}));
        hal_->InjectEvent(ReadClockOffsetStatusBuilder::Create(ErrorCode::SUCCESS, 1));
        std::promise<void> promise;
        log_capture_->WaitUntilLogContains(&promise, "Waiting for 0x0c03 (RESET)");
        sync_handler(kDelay);
      },
      "");
}

// b/260915548
TEST_F(HciLayerTest, DISABLED_command_status_callback_is_invoked_with_an_opcode_that_does_not_match_command_queue) {
  ASSERT_DEATH(
      {
        FailIfResetNotSent();
        hci_->EnqueueCommand(
            ReadClockOffsetBuilder::Create(0x001), hci_handler_->BindOnce([](CommandStatusView view) {}));
        hal_->InjectEvent(ReadClockOffsetStatusBuilder::Create(ErrorCode::SUCCESS, 1));
        std::promise<void> promise;
        log_capture_->WaitUntilLogContains(&promise, "Waiting for 0x0c03 (RESET)");
        sync_handler();
      },
      "");
}

// b/260915548
TEST_F(HciLayerTest, DISABLED_command_complete_callback_is_invoked_but_command_queue_empty) {
  ASSERT_DEATH(
      {
        FailIfResetNotSent();
        auto error_code = ErrorCode::SUCCESS;
        hal_->InjectResetCompleteEventWithCode(error_code);
        hal_->InjectResetCompleteEventWithCode(error_code);
        std::promise<void> promise;
        log_capture_->WaitUntilLogContains(&promise, "Unexpected event complete with opcode:0x0c3");
        sync_handler(kDelay);
      },
      "");
}

// b/260915548
TEST_F(HciLayerTest, DISABLED_command_status_callback_is_invoked_but_command_queue_empty) {
  ASSERT_DEATH(
      {
        FailIfResetNotSent();
        auto error_code = ErrorCode::SUCCESS;
        hal_->InjectResetCompleteEventWithCode(error_code);
        hal_->InjectEvent(ReadClockOffsetStatusBuilder::Create(ErrorCode::SUCCESS, 1));
        std::promise<void> promise;
        log_capture_->WaitUntilLogContains(&promise, "Unexpected event status with opcode:0x41f");
        sync_handler(kDelay);
      },
      "");
}

// b/260915548
TEST_F(HciLayerTest, DISABLED_command_status_callback_is_invoked_with_failure_status) {
  FailIfResetNotSent();
  auto error_code = ErrorCode::SUCCESS;
  hal_->InjectResetCompleteEventWithCode(error_code);
  hci_->EnqueueCommand(ReadClockOffsetBuilder::Create(0x001), hci_handler_->BindOnce([](CommandStatusView view) {}));
  hal_->InjectEvent(ReadClockOffsetStatusBuilder::Create(ErrorCode::HARDWARE_FAILURE, 1));
  std::promise<void> promise;
  log_capture_->WaitUntilLogContains(
      &promise, "Received UNEXPECTED command status:HARDWARE_FAILURE opcode:0x41f (READ_CLOCK_OFFSET)");
  sync_handler();
}

}  // namespace hci
}  // namespace bluetooth
