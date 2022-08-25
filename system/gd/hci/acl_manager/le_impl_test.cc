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

#include "hci/acl_manager/le_impl.h"

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <chrono>

#include "common/bidi_queue.h"
#include "common/callback.h"
#include "hci/acl_manager.h"
#include "hci/acl_manager/le_connection_management_callbacks.h"
#include "hci/address_with_type.h"
#include "hci/controller.h"
#include "hci/hci_packets.h"
#include "os/handler.h"
#include "os/log.h"
#include "packet/raw_builder.h"

using namespace std::chrono_literals;

using ::bluetooth::common::BidiQueue;
using ::bluetooth::common::Callback;
using ::bluetooth::os::Handler;
using ::bluetooth::os::Thread;

namespace bluetooth {
namespace hci {
namespace acl_manager {

PacketView<kLittleEndian> GetPacketView(std::unique_ptr<packet::BasePacketBuilder> packet) {
  auto bytes = std::make_shared<std::vector<uint8_t>>();
  BitInserter i(*bytes);
  bytes->reserve(packet->size());
  packet->Serialize(i);
  return packet::PacketView<packet::kLittleEndian>(bytes);
}

class TestController : public Controller {
 public:
  bool IsSupported(OpCode op_code) const override {
    LOG_INFO("IsSupported");
    return supported_opcodes_.count(op_code) == 1;
  }

  void AddSupported(OpCode op_code) {
    LOG_INFO("AddSupported");
    supported_opcodes_.insert(op_code);
  }

  uint16_t GetNumAclPacketBuffers() const {
    return max_acl_packet_credits_;
  }

  uint16_t GetAclPacketLength() const {
    return hci_mtu_;
  }

  LeBufferSize GetLeBufferSize() const {
    LeBufferSize le_buffer_size;
    le_buffer_size.le_data_packet_length_ = le_hci_mtu_;
    le_buffer_size.total_num_le_packets_ = le_max_acl_packet_credits_;
    return le_buffer_size;
  }

  void RegisterCompletedAclPacketsCallback(CompletedAclPacketsCallback cb) {
    acl_credits_callback_ = cb;
  }

  void SendCompletedAclPacketsCallback(uint16_t handle, uint16_t credits) {
    acl_credits_callback_.Invoke(handle, credits);
  }

  void UnregisterCompletedAclPacketsCallback() {
    acl_credits_callback_ = {};
  }

  const uint16_t max_acl_packet_credits_ = 10;
  const uint16_t hci_mtu_ = 1024;
  const uint16_t le_max_acl_packet_credits_ = 15;
  const uint16_t le_hci_mtu_ = 27;

 private:
  CompletedAclPacketsCallback acl_credits_callback_;
  std::set<OpCode> supported_opcodes_{};
};

class TestHciLayer : public HciLayer {
  template <typename T>
  class CommandInterfaceImpl : public CommandInterface<T> {
   public:
    explicit CommandInterfaceImpl(HciLayer& hci) : hci_(hci) {}
    ~CommandInterfaceImpl() = default;

    void EnqueueCommand(
        std::unique_ptr<T> command, common::ContextualOnceCallback<void(CommandCompleteView)> on_complete) override {
      hci_.EnqueueCommand(move(command), std::move(on_complete));
    }

    void EnqueueCommand(
        std::unique_ptr<T> command, common::ContextualOnceCallback<void(CommandStatusView)> on_status) override {
      hci_.EnqueueCommand(move(command), std::move(on_status));
    }
    HciLayer& hci_;
  };

  void EnqueueCommand(
      std::unique_ptr<CommandBuilder> command,
      common::ContextualOnceCallback<void(CommandStatusView)> on_status) override {
    command_queue_.push(std::move(command));
    command_status_callbacks.push_back(std::move(on_status));
    if (command_promise_ != nullptr) {
      command_promise_->set_value();
      command_promise_.reset();
    }
  }

  void EnqueueCommand(
      std::unique_ptr<CommandBuilder> command,
      common::ContextualOnceCallback<void(CommandCompleteView)> on_complete) override {
    command_queue_.push(std::move(command));
    command_complete_callbacks.push_back(std::move(on_complete));
    if (command_promise_ != nullptr) {
      command_promise_->set_value();
      command_promise_.reset();
    }
  }

 public:
  void SetCommandFuture() {
    ASSERT_LOG(command_promise_ == nullptr, "Promises, Promises, ... Only one at a time.");
    command_promise_ = std::make_unique<std::promise<void>>();
    command_future_ = std::make_unique<std::future<void>>(command_promise_->get_future());
  }

  CommandView GetLastCommand() {
    if (command_queue_.empty()) {
      return CommandView::Create(PacketView<kLittleEndian>(std::make_shared<std::vector<uint8_t>>()));
    }
    auto last = std::move(command_queue_.front());
    command_queue_.pop();
    return CommandView::Create(GetPacketView(std::move(last)));
  }

  CommandView GetCommand(OpCode op_code) {
    if (!command_queue_.empty()) {
      std::lock_guard<std::mutex> lock(mutex_);
      if (command_future_ != nullptr) {
        command_future_.reset();
        command_promise_.reset();
      }
    } else if (command_future_ != nullptr) {
      auto result = command_future_->wait_for(std::chrono::milliseconds(1000));
      EXPECT_NE(std::future_status::timeout, result);
    }
    std::lock_guard<std::mutex> lock(mutex_);
    ASSERT_LOG(
        !command_queue_.empty(), "Expecting command %s but command queue was empty", OpCodeText(op_code).c_str());
    CommandView command_packet_view = GetLastCommand();
    EXPECT_TRUE(command_packet_view.IsValid());
    EXPECT_EQ(command_packet_view.GetOpCode(), op_code);
    return command_packet_view;
  }

  void CommandCompleteCallback(std::unique_ptr<EventBuilder> event_builder) {
    auto event = EventView::Create(GetPacketView(std::move(event_builder)));
    CommandCompleteView complete_view = CommandCompleteView::Create(event);
    ASSERT_TRUE(complete_view.IsValid());
    ASSERT_NE((uint16_t)command_complete_callbacks.size(), 0);
    std::move(command_complete_callbacks.front()).Invoke(complete_view);
    command_complete_callbacks.pop_front();
  }

  void CommandStatusCallback(std::unique_ptr<EventBuilder> event_builder) {
    auto event = EventView::Create(GetPacketView(std::move(event_builder)));
    CommandStatusView status_view = CommandStatusView::Create(event);
    ASSERT_TRUE(status_view.IsValid());
    ASSERT_NE((uint16_t)command_status_callbacks.size(), 0);
    std::move(command_status_callbacks.front()).Invoke(status_view);
    command_status_callbacks.pop_front();
  }

  void IncomingLeMetaEvent(std::unique_ptr<LeMetaEventBuilder> event_builder) {
    auto packet = GetPacketView(std::move(event_builder));
    EventView event = EventView::Create(packet);
    LeMetaEventView meta_event_view = LeMetaEventView::Create(event);
    EXPECT_TRUE(meta_event_view.IsValid());
    le_event_handler_.Invoke(meta_event_view);
  }

  LeAclConnectionInterface* GetLeAclConnectionInterface(
      common::ContextualCallback<void(LeMetaEventView)> event_handler,
      common::ContextualCallback<void(uint16_t, ErrorCode)> on_disconnect,
      common::ContextualCallback<
          void(hci::ErrorCode hci_status, uint16_t, uint8_t version, uint16_t manufacturer_name, uint16_t sub_version)>
          on_read_remote_version) override {
    disconnect_handlers_.push_back(on_disconnect);
    read_remote_version_handlers_.push_back(on_read_remote_version);
    le_event_handler_ = event_handler;
    return &le_acl_connection_manager_interface_;
  }

  void PutLeAclConnectionInterface() override {}

 private:
  std::list<common::ContextualOnceCallback<void(CommandCompleteView)>> command_complete_callbacks;
  std::list<common::ContextualOnceCallback<void(CommandStatusView)>> command_status_callbacks;
  common::ContextualCallback<void(LeMetaEventView)> le_event_handler_;
  std::queue<std::unique_ptr<CommandBuilder>> command_queue_;
  std::unique_ptr<std::promise<void>> command_promise_;
  std::unique_ptr<std::future<void>> command_future_;
  mutable std::mutex mutex_;
  CommandInterfaceImpl<AclCommandBuilder> le_acl_connection_manager_interface_{*this};
};

class LeImplTest : public ::testing::Test {
 public:
  void SetUp() override {
    thread_ = new Thread("thread", Thread::Priority::NORMAL);
    handler_ = new Handler(thread_);
    controller_ = new TestController();
    hci_layer_ = new TestHciLayer();

    round_robin_scheduler_ = new RoundRobinScheduler(handler_, controller_, hci_queue_.GetUpEnd());
    hci_queue_.GetDownEnd()->RegisterDequeue(
        handler_, common::Bind(&LeImplTest::HciDownEndDequeue, common::Unretained(this)));
    le_impl_ = new le_impl(hci_layer_, controller_, handler_, round_robin_scheduler_, true);
    le_impl_->handle_register_le_callbacks(&mock_le_connection_callbacks_, handler_);

    // Set address policy
    hci_layer_->SetCommandFuture();
    hci::Address address;
    Address::FromString("D0:05:04:03:02:01", address);
    hci::AddressWithType address_with_type(address, hci::AddressType::RANDOM_DEVICE_ADDRESS);
    crypto_toolbox::Octet16 rotation_irk{};
    auto minimum_rotation_time = std::chrono::milliseconds(7 * 60 * 1000);
    auto maximum_rotation_time = std::chrono::milliseconds(15 * 60 * 1000);
    le_impl_->set_privacy_policy_for_initiator_address(
        LeAddressManager::AddressPolicy::USE_STATIC_ADDRESS,
        address_with_type,
        rotation_irk,
        minimum_rotation_time,
        maximum_rotation_time);
    hci_layer_->GetCommand(OpCode::LE_SET_RANDOM_ADDRESS);
    hci_layer_->CommandCompleteCallback(LeSetRandomAddressCompleteBuilder::Create(0x01, ErrorCode::SUCCESS));
  }

  void TearDown() override {
    sync_handler();
    delete le_impl_;

    hci_queue_.GetDownEnd()->UnregisterDequeue();

    delete hci_layer_;
    delete round_robin_scheduler_;
    delete controller_;

    handler_->Clear();
    delete handler_;
    delete thread_;
  }

  void sync_handler() {
    std::promise<void> promise;
    auto future = promise.get_future();
    handler_->BindOnceOn(&promise, &std::promise<void>::set_value).Invoke();
    auto status = future.wait_for(10ms);
    ASSERT_EQ(status, std::future_status::ready);
  }

  void HciDownEndDequeue() {
    auto packet = hci_queue_.GetDownEnd()->TryDequeue();
    // Convert from a Builder to a View
    auto bytes = std::make_shared<std::vector<uint8_t>>();
    bluetooth::packet::BitInserter i(*bytes);
    bytes->reserve(packet->size());
    packet->Serialize(i);
    auto packet_view = bluetooth::packet::PacketView<bluetooth::packet::kLittleEndian>(bytes);
    AclView acl_packet_view = AclView::Create(packet_view);
    ASSERT_TRUE(acl_packet_view.IsValid());
    PacketView<true> count_view = acl_packet_view.GetPayload();
    sent_acl_packets_.push(acl_packet_view);

    packet_count_--;
    if (packet_count_ == 0) {
      packet_promise_->set_value();
      packet_promise_ = nullptr;
    }
  }

  class MockLeConnectionCallbacks : public LeConnectionCallbacks {
   public:
    MOCK_METHOD(
        void,
        OnLeConnectSuccess,
        (AddressWithType address_with_type, std::unique_ptr<LeAclConnection> connection),
        (override));
    MOCK_METHOD(void, OnLeConnectFail, (AddressWithType, ErrorCode reason), (override));
  } mock_le_connection_callbacks_;

  uint16_t packet_count_;
  std::unique_ptr<std::promise<void>> packet_promise_;
  std::unique_ptr<std::future<void>> packet_future_;
  std::queue<AclView> sent_acl_packets_;

  BidiQueue<AclView, AclBuilder> hci_queue_{3};

  Thread* thread_;
  Handler* handler_;
  TestHciLayer* hci_layer_{nullptr};
  TestController* controller_;
  RoundRobinScheduler* round_robin_scheduler_{nullptr};

  struct le_impl* le_impl_;
};

TEST_F(LeImplTest, nop) {}

TEST_F(LeImplTest, add_device_to_connect_list) {
  le_impl_->add_device_to_connect_list({{0x01, 0x02, 0x03, 0x04, 0x05, 0x06}, AddressType::PUBLIC_DEVICE_ADDRESS});
  ASSERT_EQ(1UL, le_impl_->connect_list.size());

  le_impl_->add_device_to_connect_list({{0x11, 0x12, 0x13, 0x14, 0x15, 0x16}, AddressType::PUBLIC_DEVICE_ADDRESS});
  ASSERT_EQ(2UL, le_impl_->connect_list.size());

  le_impl_->add_device_to_connect_list({{0x01, 0x02, 0x03, 0x04, 0x05, 0x06}, AddressType::PUBLIC_DEVICE_ADDRESS});
  ASSERT_EQ(2UL, le_impl_->connect_list.size());

  le_impl_->add_device_to_connect_list({{0x11, 0x12, 0x13, 0x14, 0x15, 0x16}, AddressType::PUBLIC_DEVICE_ADDRESS});
  ASSERT_EQ(2UL, le_impl_->connect_list.size());
}

TEST_F(LeImplTest, remove_device_from_connect_list) {
  le_impl_->add_device_to_connect_list({{0x01, 0x02, 0x03, 0x04, 0x05, 0x06}, AddressType::PUBLIC_DEVICE_ADDRESS});
  le_impl_->add_device_to_connect_list({{0x11, 0x12, 0x13, 0x14, 0x15, 0x16}, AddressType::PUBLIC_DEVICE_ADDRESS});
  le_impl_->add_device_to_connect_list({{0x21, 0x22, 0x23, 0x24, 0x25, 0x26}, AddressType::PUBLIC_DEVICE_ADDRESS});
  le_impl_->add_device_to_connect_list({{0x31, 0x32, 0x33, 0x34, 0x35, 0x36}, AddressType::PUBLIC_DEVICE_ADDRESS});
  ASSERT_EQ(4UL, le_impl_->connect_list.size());

  le_impl_->remove_device_from_connect_list({{0x01, 0x02, 0x03, 0x04, 0x05, 0x06}, AddressType::PUBLIC_DEVICE_ADDRESS});
  ASSERT_EQ(3UL, le_impl_->connect_list.size());

  le_impl_->remove_device_from_connect_list({{0x11, 0x12, 0x13, 0x14, 0x15, 0x16}, AddressType::PUBLIC_DEVICE_ADDRESS});
  ASSERT_EQ(2UL, le_impl_->connect_list.size());

  le_impl_->remove_device_from_connect_list({{0x11, 0x12, 0x13, 0x14, 0x15, 0x16}, AddressType::PUBLIC_DEVICE_ADDRESS});
  ASSERT_EQ(2UL, le_impl_->connect_list.size());

  le_impl_->remove_device_from_connect_list({Address::kEmpty, AddressType::PUBLIC_DEVICE_ADDRESS});
  ASSERT_EQ(2UL, le_impl_->connect_list.size());

  le_impl_->remove_device_from_connect_list({{0x21, 0x22, 0x23, 0x24, 0x25, 0x26}, AddressType::PUBLIC_DEVICE_ADDRESS});
  le_impl_->remove_device_from_connect_list({{0x31, 0x32, 0x33, 0x34, 0x35, 0x36}, AddressType::PUBLIC_DEVICE_ADDRESS});
  ASSERT_EQ(0UL, le_impl_->connect_list.size());
}

TEST_F(LeImplTest, connection_complete_with_periperal_role) {
  // Create connection
  hci_layer_->SetCommandFuture();
  le_impl_->create_le_connection(
      {{0x21, 0x22, 0x23, 0x24, 0x25, 0x26}, AddressType::PUBLIC_DEVICE_ADDRESS}, true, false);
  hci_layer_->GetCommand(OpCode::LE_ADD_DEVICE_TO_FILTER_ACCEPT_LIST);
  hci_layer_->SetCommandFuture();
  hci_layer_->CommandCompleteCallback(LeAddDeviceToFilterAcceptListCompleteBuilder::Create(0x01, ErrorCode::SUCCESS));
  hci_layer_->GetCommand(OpCode::LE_CREATE_CONNECTION);
  hci_layer_->CommandStatusCallback(LeCreateConnectionStatusBuilder::Create(ErrorCode::SUCCESS, 0x01));
  sync_handler();

  // Check state is ARMED
  ASSERT_EQ(ConnectabilityState::ARMED, le_impl_->connectability_state_);

  // Receive connection complete of incoming connection (Role::PERIPHERAL)
  hci::Address remote_address;
  Address::FromString("D0:05:04:03:02:01", remote_address);
  hci::AddressWithType address_with_type(remote_address, hci::AddressType::PUBLIC_DEVICE_ADDRESS);
  EXPECT_CALL(mock_le_connection_callbacks_, OnLeConnectSuccess(address_with_type, testing::_));
  hci_layer_->IncomingLeMetaEvent(LeConnectionCompleteBuilder::Create(
      ErrorCode::SUCCESS,
      0x0041,
      Role::PERIPHERAL,
      AddressType::PUBLIC_DEVICE_ADDRESS,
      remote_address,
      0x0024,
      0x0000,
      0x0011,
      ClockAccuracy::PPM_30));
  sync_handler();

  // Check state is still ARMED
  ASSERT_EQ(ConnectabilityState::ARMED, le_impl_->connectability_state_);
}

TEST_F(LeImplTest, enhanced_connection_complete_with_periperal_role) {
  controller_->AddSupported(OpCode::LE_EXTENDED_CREATE_CONNECTION);
  // Create connection
  hci_layer_->SetCommandFuture();
  le_impl_->create_le_connection(
      {{0x21, 0x22, 0x23, 0x24, 0x25, 0x26}, AddressType::PUBLIC_DEVICE_ADDRESS}, true, false);
  hci_layer_->GetCommand(OpCode::LE_ADD_DEVICE_TO_FILTER_ACCEPT_LIST);
  hci_layer_->SetCommandFuture();
  hci_layer_->CommandCompleteCallback(LeAddDeviceToFilterAcceptListCompleteBuilder::Create(0x01, ErrorCode::SUCCESS));
  hci_layer_->GetCommand(OpCode::LE_EXTENDED_CREATE_CONNECTION);
  hci_layer_->CommandStatusCallback(LeExtendedCreateConnectionStatusBuilder::Create(ErrorCode::SUCCESS, 0x01));
  sync_handler();

  // Check state is ARMED
  ASSERT_EQ(ConnectabilityState::ARMED, le_impl_->connectability_state_);

  // Receive connection complete of incoming connection (Role::PERIPHERAL)
  hci::Address remote_address;
  Address::FromString("D0:05:04:03:02:01", remote_address);
  hci::AddressWithType address_with_type(remote_address, hci::AddressType::PUBLIC_DEVICE_ADDRESS);
  EXPECT_CALL(mock_le_connection_callbacks_, OnLeConnectSuccess(address_with_type, testing::_));
  hci_layer_->IncomingLeMetaEvent(LeEnhancedConnectionCompleteBuilder::Create(
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
  sync_handler();

  // Check state is still ARMED
  ASSERT_EQ(ConnectabilityState::ARMED, le_impl_->connectability_state_);
}

TEST_F(LeImplTest, connection_complete_with_central_role) {
  hci::Address remote_address;
  Address::FromString("D0:05:04:03:02:01", remote_address);
  hci::AddressWithType address_with_type(remote_address, hci::AddressType::PUBLIC_DEVICE_ADDRESS);
  // Create connection
  hci_layer_->SetCommandFuture();
  le_impl_->create_le_connection(address_with_type, true, false);
  hci_layer_->GetCommand(OpCode::LE_ADD_DEVICE_TO_FILTER_ACCEPT_LIST);
  hci_layer_->SetCommandFuture();
  hci_layer_->CommandCompleteCallback(LeAddDeviceToFilterAcceptListCompleteBuilder::Create(0x01, ErrorCode::SUCCESS));
  hci_layer_->GetCommand(OpCode::LE_CREATE_CONNECTION);
  hci_layer_->CommandStatusCallback(LeCreateConnectionStatusBuilder::Create(ErrorCode::SUCCESS, 0x01));
  sync_handler();

  // Check state is ARMED
  ASSERT_EQ(ConnectabilityState::ARMED, le_impl_->connectability_state_);

  // Receive connection complete of outgoing connection (Role::CENTRAL)
  EXPECT_CALL(mock_le_connection_callbacks_, OnLeConnectSuccess(address_with_type, testing::_));
  hci_layer_->IncomingLeMetaEvent(LeConnectionCompleteBuilder::Create(
      ErrorCode::SUCCESS,
      0x0041,
      Role::CENTRAL,
      AddressType::PUBLIC_DEVICE_ADDRESS,
      remote_address,
      0x0024,
      0x0000,
      0x0011,
      ClockAccuracy::PPM_30));
  sync_handler();

  // Check state is DISARMED
  ASSERT_EQ(ConnectabilityState::DISARMED, le_impl_->connectability_state_);
}

TEST_F(LeImplTest, enhanced_connection_complete_with_central_role) {
  controller_->AddSupported(OpCode::LE_EXTENDED_CREATE_CONNECTION);
  hci::Address remote_address;
  Address::FromString("D0:05:04:03:02:01", remote_address);
  hci::AddressWithType address_with_type(remote_address, hci::AddressType::PUBLIC_DEVICE_ADDRESS);
  // Create connection
  hci_layer_->SetCommandFuture();
  le_impl_->create_le_connection(address_with_type, true, false);
  hci_layer_->GetCommand(OpCode::LE_ADD_DEVICE_TO_FILTER_ACCEPT_LIST);
  hci_layer_->SetCommandFuture();
  hci_layer_->CommandCompleteCallback(LeAddDeviceToFilterAcceptListCompleteBuilder::Create(0x01, ErrorCode::SUCCESS));
  hci_layer_->GetCommand(OpCode::LE_EXTENDED_CREATE_CONNECTION);
  hci_layer_->CommandStatusCallback(LeExtendedCreateConnectionStatusBuilder::Create(ErrorCode::SUCCESS, 0x01));
  sync_handler();

  // Check state is ARMED
  ASSERT_EQ(ConnectabilityState::ARMED, le_impl_->connectability_state_);

  // Receive connection complete of outgoing connection (Role::CENTRAL)
  EXPECT_CALL(mock_le_connection_callbacks_, OnLeConnectSuccess(address_with_type, testing::_));
  hci_layer_->IncomingLeMetaEvent(LeEnhancedConnectionCompleteBuilder::Create(
      ErrorCode::SUCCESS,
      0x0041,
      Role::CENTRAL,
      AddressType::PUBLIC_DEVICE_ADDRESS,
      remote_address,
      Address::kEmpty,
      Address::kEmpty,
      0x0024,
      0x0000,
      0x0011,
      ClockAccuracy::PPM_30));
  sync_handler();

  // Check state is DISARMED
  ASSERT_EQ(ConnectabilityState::DISARMED, le_impl_->connectability_state_);
}

}  // namespace acl_manager
}  // namespace hci
}  // namespace bluetooth
