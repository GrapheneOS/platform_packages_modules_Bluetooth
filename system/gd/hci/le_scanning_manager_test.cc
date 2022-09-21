/*
 * Copyright 2019 The Android Open Source Project
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

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <algorithm>
#include <chrono>
#include <future>
#include <map>

#include "common/bind.h"
#include "hci/acl_manager.h"
#include "hci/address.h"
#include "hci/controller.h"
#include "hci/hci_layer.h"
#include "hci/le_scanning_manager.h"
#include "os/thread.h"
#include "packet/raw_builder.h"

using ::testing::_;
using ::testing::Eq;

namespace bluetooth {
namespace hci {
namespace {

using packet::kLittleEndian;
using packet::PacketView;
using packet::RawBuilder;

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
    return supported_opcodes_.count(op_code) == 1;
  }

  void AddSupported(OpCode op_code) {
    supported_opcodes_.insert(op_code);
  }

 protected:
  void Start() override {}
  void Stop() override {}
  void ListDependencies(ModuleList* list) const {}

 private:
  std::set<OpCode> supported_opcodes_{};
};

class TestHciLayer : public HciLayer {
 public:
  void EnqueueCommand(
      std::unique_ptr<CommandBuilder> command,
      common::ContextualOnceCallback<void(CommandStatusView)> on_status) override {
    command_queue_.push(std::move(command));
    command_status_callbacks.push_back(std::move(on_status));
    command_count_--;
    if (command_promise_ != nullptr && command_count_ == 0) {
      command_promise_->set_value();
      command_promise_.reset();
    }
  }

  void EnqueueCommand(
      std::unique_ptr<CommandBuilder> command,
      common::ContextualOnceCallback<void(CommandCompleteView)> on_complete) override {
    command_queue_.push(std::move(command));
    command_complete_callbacks.push_back(std::move(on_complete));
    command_count_--;
    if (command_promise_ != nullptr && command_count_ == 0) {
      command_promise_->set_value();
      command_promise_.reset();
    }
  }

  // Set command future for 'num_command' commands are expected
  void SetCommandFuture(uint16_t num_command) {
    ASSERT_TRUE(command_promise_ == nullptr) << "Promises, Promises, ... Only one at a time.";
    command_count_ = num_command;
    command_promise_ = std::make_unique<std::promise<void>>();
    command_future_ = std::make_unique<std::future<void>>(command_promise_->get_future());
  }

  CommandView GetLastCommand() {
    if (command_queue_.size() == 0) {
      return empty_command_view_;
    }
    auto last = std::move(command_queue_.front());
    command_queue_.pop();
    return CommandView::Create(GetPacketView(std::move(last)));
  }

  CommandView GetCommand() {
    if (!command_queue_.empty()) {
      std::lock_guard<std::mutex> lock(mutex_);
      if (command_future_ != nullptr) {
        command_future_.reset();
        command_promise_.reset();
      }
    } else if (command_future_ != nullptr) {
      command_future_->wait_for(std::chrono::milliseconds(1000));
    }
    std::lock_guard<std::mutex> lock(mutex_);
    if (command_queue_.empty()) {
      LOG_ERROR("Command queue is empty");
      return empty_command_view_;
    }
    CommandView command_packet_view = GetLastCommand();
    if (!command_packet_view.IsValid()) {
      LOG_ERROR("Got invalid command");
      return empty_command_view_;
    }
    return command_packet_view;
  }

  void RegisterEventHandler(EventCode event_code, common::ContextualCallback<void(EventView)> event_handler) override {
    registered_events_[event_code] = event_handler;
  }

  void UnregisterEventHandler(EventCode event_code) override {
    registered_events_.erase(event_code);
  }

  void RegisterLeEventHandler(
      SubeventCode subevent_code, common::ContextualCallback<void(LeMetaEventView)> event_handler) override {
    registered_le_events_[subevent_code] = event_handler;
  }

  void UnregisterLeEventHandler(SubeventCode subevent_code) override {
    registered_le_events_.erase(subevent_code);
  }

  void IncomingEvent(std::unique_ptr<EventBuilder> event_builder) {
    auto packet = GetPacketView(std::move(event_builder));
    EventView event = EventView::Create(packet);
    ASSERT_TRUE(event.IsValid());
    EventCode event_code = event.GetEventCode();
    ASSERT_NE(registered_events_.find(event_code), registered_events_.end()) << EventCodeText(event_code);
    registered_events_[event_code].Invoke(event);
  }

  void IncomingLeMetaEvent(std::unique_ptr<LeMetaEventBuilder> event_builder) {
    auto packet = GetPacketView(std::move(event_builder));
    EventView event = EventView::Create(packet);
    LeMetaEventView meta_event_view = LeMetaEventView::Create(event);
    ASSERT_TRUE(meta_event_view.IsValid());
    SubeventCode subevent_code = meta_event_view.GetSubeventCode();
    ASSERT_TRUE(registered_le_events_.find(subevent_code) != registered_le_events_.end());
    registered_le_events_[subevent_code].Invoke(meta_event_view);
  }

  void CommandCompleteCallback(EventView event) {
    CommandCompleteView complete_view = CommandCompleteView::Create(event);
    ASSERT_TRUE(complete_view.IsValid());
    std::move(command_complete_callbacks.front()).Invoke(complete_view);
    command_complete_callbacks.pop_front();
  }

  void CommandStatusCallback(EventView event) {
    CommandStatusView status_view = CommandStatusView::Create(event);
    ASSERT_TRUE(status_view.IsValid());
    std::move(command_status_callbacks.front()).Invoke(status_view);
    command_status_callbacks.pop_front();
  }

  void InitEmptyCommand() {
    auto payload = std::make_unique<bluetooth::packet::RawBuilder>();
    auto command_builder = CommandBuilder::Create(OpCode::NONE, std::move(payload));
    empty_command_view_ = CommandView::Create(GetPacketView(std::move(command_builder)));
    ASSERT_TRUE(empty_command_view_.IsValid());
  }

  void ListDependencies(ModuleList* list) const {}
  void Start() override {
    InitEmptyCommand();
    RegisterEventHandler(
        EventCode::COMMAND_COMPLETE, GetHandler()->BindOn(this, &TestHciLayer::CommandCompleteCallback));
    RegisterEventHandler(EventCode::COMMAND_STATUS, GetHandler()->BindOn(this, &TestHciLayer::CommandStatusCallback));
  }
  void Stop() override {}

 private:
  std::map<EventCode, common::ContextualCallback<void(EventView)>> registered_events_;
  std::map<SubeventCode, common::ContextualCallback<void(LeMetaEventView)>> registered_le_events_;
  std::list<common::ContextualOnceCallback<void(CommandCompleteView)>> command_complete_callbacks;
  std::list<common::ContextualOnceCallback<void(CommandStatusView)>> command_status_callbacks;
  std::queue<std::unique_ptr<CommandBuilder>> command_queue_;
  std::unique_ptr<std::promise<void>> command_promise_;
  std::unique_ptr<std::future<void>> command_future_;
  mutable std::mutex mutex_;
  uint16_t command_count_ = 0;
  CommandView empty_command_view_ =
      CommandView::Create(PacketView<kLittleEndian>(std::make_shared<std::vector<uint8_t>>()));
};

class TestLeAddressManager : public LeAddressManager {
 public:
  TestLeAddressManager(
      common::Callback<void(std::unique_ptr<CommandBuilder>)> enqueue_command,
      os::Handler* handler,
      Address public_address,
      uint8_t connect_list_size,
      uint8_t resolving_list_size)
      : LeAddressManager(enqueue_command, handler, public_address, connect_list_size, resolving_list_size) {}

  AddressPolicy Register(LeAddressManagerCallback* callback) override {
    return AddressPolicy::USE_STATIC_ADDRESS;
  }

  void Unregister(LeAddressManagerCallback* callback) override {}
};

class TestAclManager : public AclManager {
 public:
  LeAddressManager* GetLeAddressManager() override {
    return test_le_address_manager_;
  }

 protected:
  void Start() override {
    thread_ = new os::Thread("thread", os::Thread::Priority::NORMAL);
    handler_ = new os::Handler(thread_);
    Address address({0x01, 0x02, 0x03, 0x04, 0x05, 0x06});
    test_le_address_manager_ = new TestLeAddressManager(
        common::Bind(&TestAclManager::enqueue_command, common::Unretained(this)), handler_, address, 0x3F, 0x3F);
  }

  void Stop() override {
    delete test_le_address_manager_;
    handler_->Clear();
    delete handler_;
    delete thread_;
  }

  void ListDependencies(ModuleList* list) const {}

  void SetRandomAddress(Address address) {}

  void enqueue_command(std::unique_ptr<CommandBuilder> command_packet){};

  os::Thread* thread_;
  os::Handler* handler_;
  TestLeAddressManager* test_le_address_manager_;
};

class LeScanningManagerTest : public ::testing::Test {
 protected:
  void SetUp() override {
    test_hci_layer_ = new TestHciLayer;  // Ownership is transferred to registry
    test_controller_ = new TestController;
    test_controller_->AddSupported(param_opcode_);
    if (is_filter_support_) {
      test_controller_->AddSupported(OpCode::LE_ADV_FILTER);
    }
    if (is_batch_scan_support_) {
      test_controller_->AddSupported(OpCode::LE_BATCH_SCAN);
    }
    test_acl_manager_ = new TestAclManager;
    fake_registry_.InjectTestModule(&HciLayer::Factory, test_hci_layer_);
    fake_registry_.InjectTestModule(&Controller::Factory, test_controller_);
    fake_registry_.InjectTestModule(&AclManager::Factory, test_acl_manager_);
    client_handler_ = fake_registry_.GetTestModuleHandler(&HciLayer::Factory);
    ASSERT_NE(client_handler_, nullptr);
    test_hci_layer_->SetCommandFuture(1);
    // configure_scan will be trigger by impl.start() and enqueue set scan parameter command
    fake_registry_.Start<LeScanningManager>(&thread_);
    le_scanning_manager =
        static_cast<LeScanningManager*>(fake_registry_.GetModuleUnderTest(&LeScanningManager::Factory));
    HandleConfiguration();
    le_scanning_manager->RegisterScanningCallback(&mock_callbacks_);
  }

  void TearDown() override {
    fake_registry_.SynchronizeModuleHandler(&LeScanningManager::Factory, std::chrono::milliseconds(20));
    fake_registry_.StopAll();
  }

  virtual void HandleConfiguration() {
    ASSERT_EQ(param_opcode_, test_hci_layer_->GetCommand().GetOpCode());
    test_hci_layer_->IncomingEvent(LeSetScanParametersCompleteBuilder::Create(1, ErrorCode::SUCCESS));
  }

  void sync_client_handler() {
    std::promise<void> promise;
    auto future = promise.get_future();
    client_handler_->Post(common::BindOnce(&std::promise<void>::set_value, common::Unretained(&promise)));
    auto future_status = future.wait_for(std::chrono::seconds(1));
    ASSERT_EQ(future_status, std::future_status::ready);
  }

  TestModuleRegistry fake_registry_;
  TestHciLayer* test_hci_layer_ = nullptr;
  TestController* test_controller_ = nullptr;
  TestAclManager* test_acl_manager_ = nullptr;
  os::Thread& thread_ = fake_registry_.GetTestThread();
  LeScanningManager* le_scanning_manager = nullptr;
  os::Handler* client_handler_ = nullptr;

  class MockCallbacks : public bluetooth::hci::ScanningCallback {
   public:
    MOCK_METHOD(
        void,
        OnScannerRegistered,
        (const bluetooth::hci::Uuid app_uuid, ScannerId scanner_id, ScanningStatus status),
        (override));
    MOCK_METHOD(void, OnSetScannerParameterComplete, (ScannerId scanner_id, ScanningStatus status), (override));
    MOCK_METHOD(
        void,
        OnScanResult,
        (uint16_t event_type,
         uint8_t address_type,
         Address address,
         uint8_t primary_phy,
         uint8_t secondary_phy,
         uint8_t advertising_sid,
         int8_t tx_power,
         int8_t rssi,
         uint16_t periodic_advertising_interval,
         std::vector<uint8_t> advertising_data),
        (override));
    MOCK_METHOD(
        void,
        OnTrackAdvFoundLost,
        (bluetooth::hci::AdvertisingFilterOnFoundOnLostInfo on_found_on_lost_info),
        (override));
    MOCK_METHOD(
        void,
        OnBatchScanReports,
        (int client_if, int status, int report_format, int num_records, std::vector<uint8_t> data),
        (override));
    MOCK_METHOD(void, OnBatchScanThresholdCrossed, (int client_if), (override));
    MOCK_METHOD(void, OnTimeout, (), (override));
    MOCK_METHOD(void, OnFilterEnable, (Enable enable, uint8_t status), (override));
    MOCK_METHOD(void, OnFilterParamSetup, (uint8_t available_spaces, ApcfAction action, uint8_t status), (override));
    MOCK_METHOD(
        void,
        OnFilterConfigCallback,
        (ApcfFilterType filter_type, uint8_t available_spaces, ApcfAction action, uint8_t status),
        (override));
    MOCK_METHOD(void, OnPeriodicSyncStarted, (int, uint8_t, uint16_t, uint8_t, AddressWithType, uint8_t, uint16_t));
    MOCK_METHOD(void, OnPeriodicSyncReport, (uint16_t, int8_t, int8_t, uint8_t, std::vector<uint8_t>));
    MOCK_METHOD(void, OnPeriodicSyncLost, (uint16_t));
    MOCK_METHOD(void, OnPeriodicSyncTransferred, (int, uint8_t, Address));
  } mock_callbacks_;

  OpCode param_opcode_{OpCode::LE_SET_SCAN_PARAMETERS};
  OpCode enable_opcode_{OpCode::LE_SET_SCAN_ENABLE};
  bool is_filter_support_ = false;
  bool is_batch_scan_support_ = false;
};

class LeAndroidHciScanningManagerTest : public LeScanningManagerTest {
 protected:
  void SetUp() override {
    param_opcode_ = OpCode::LE_EXTENDED_SCAN_PARAMS;
    is_filter_support_ = true;
    is_batch_scan_support_ = true;
    LeScanningManagerTest::SetUp();
  }

  void HandleConfiguration() override {
    ASSERT_EQ(param_opcode_, test_hci_layer_->GetCommand().GetOpCode());
    test_hci_layer_->IncomingEvent(LeExtendedScanParamsCompleteBuilder::Create(1, ErrorCode::SUCCESS));
  }
};

class LeExtendedScanningManagerTest : public LeScanningManagerTest {
 protected:
  void SetUp() override {
    param_opcode_ = OpCode::LE_SET_EXTENDED_SCAN_PARAMETERS;
    enable_opcode_ = OpCode::LE_SET_EXTENDED_SCAN_ENABLE;
    LeScanningManagerTest::SetUp();
  }

  void HandleConfiguration() override {
    ASSERT_EQ(param_opcode_, test_hci_layer_->GetCommand().GetOpCode());
    test_hci_layer_->IncomingEvent(LeSetExtendedScanParametersCompleteBuilder::Create(1, ErrorCode::SUCCESS));
  }
};

TEST_F(LeScanningManagerTest, startup_teardown) {}

TEST_F(LeScanningManagerTest, start_scan_test) {
  // Enable scan
  test_hci_layer_->SetCommandFuture(2);
  le_scanning_manager->Scan(true);
  ASSERT_EQ(param_opcode_, test_hci_layer_->GetCommand().GetOpCode());
  test_hci_layer_->IncomingEvent(LeSetScanParametersCompleteBuilder::Create(uint8_t{1}, ErrorCode::SUCCESS));
  ASSERT_EQ(enable_opcode_, test_hci_layer_->GetCommand().GetOpCode());
  test_hci_layer_->IncomingEvent(LeSetScanEnableCompleteBuilder::Create(uint8_t{1}, ErrorCode::SUCCESS));

  LeAdvertisingResponse report{};
  report.event_type_ = AdvertisingEventType::ADV_DIRECT_IND;
  report.address_type_ = AddressType::PUBLIC_DEVICE_ADDRESS;
  Address::FromString("12:34:56:78:9a:bc", report.address_);
  std::vector<LengthAndData> adv_data{};
  LengthAndData data_item{};
  data_item.data_.push_back(static_cast<uint8_t>(GapDataType::FLAGS));
  data_item.data_.push_back(0x34);
  adv_data.push_back(data_item);
  data_item.data_.push_back(static_cast<uint8_t>(GapDataType::COMPLETE_LOCAL_NAME));
  for (auto octet : {'r', 'a', 'n', 'd', 'o', 'm', ' ', 'd', 'e', 'v', 'i', 'c', 'e'}) {
    data_item.data_.push_back(octet);
  }
  adv_data.push_back(data_item);
  report.advertising_data_ = adv_data;

  EXPECT_CALL(mock_callbacks_, OnScanResult);

  test_hci_layer_->IncomingLeMetaEvent(LeAdvertisingReportBuilder::Create({report}));
}

TEST_F(LeAndroidHciScanningManagerTest, startup_teardown) {}

TEST_F(LeAndroidHciScanningManagerTest, start_scan_test) {
  // Enable scan
  test_hci_layer_->SetCommandFuture(2);
  le_scanning_manager->Scan(true);
  ASSERT_EQ(param_opcode_, test_hci_layer_->GetCommand().GetOpCode());
  test_hci_layer_->IncomingEvent(LeSetScanParametersCompleteBuilder::Create(uint8_t{1}, ErrorCode::SUCCESS));
  ASSERT_EQ(enable_opcode_, test_hci_layer_->GetCommand().GetOpCode());
  test_hci_layer_->IncomingEvent(LeSetScanEnableCompleteBuilder::Create(uint8_t{1}, ErrorCode::SUCCESS));

  LeAdvertisingResponse report{};
  report.event_type_ = AdvertisingEventType::ADV_DIRECT_IND;
  report.address_type_ = AddressType::PUBLIC_DEVICE_ADDRESS;
  Address::FromString("12:34:56:78:9a:bc", report.address_);
  std::vector<LengthAndData> adv_data{};
  LengthAndData data_item{};
  data_item.data_.push_back(static_cast<uint8_t>(GapDataType::FLAGS));
  data_item.data_.push_back(0x34);
  adv_data.push_back(data_item);
  data_item.data_.push_back(static_cast<uint8_t>(GapDataType::COMPLETE_LOCAL_NAME));
  for (auto octet : {'r', 'a', 'n', 'd', 'o', 'm', ' ', 'd', 'e', 'v', 'i', 'c', 'e'}) {
    data_item.data_.push_back(octet);
  }
  adv_data.push_back(data_item);
  report.advertising_data_ = adv_data;

  EXPECT_CALL(mock_callbacks_, OnScanResult);

  test_hci_layer_->IncomingLeMetaEvent(LeAdvertisingReportBuilder::Create({report}));
}

TEST_F(LeAndroidHciScanningManagerTest, scan_filter_enable_test) {
  test_hci_layer_->SetCommandFuture(1);
  le_scanning_manager->ScanFilterEnable(true);
  auto commandView = test_hci_layer_->GetCommand();
  ASSERT_EQ(OpCode::LE_ADV_FILTER, commandView.GetOpCode());
  auto filter_command_view =
      LeAdvFilterEnableView::Create(LeAdvFilterView::Create(LeScanningCommandView::Create(commandView)));
  ASSERT_TRUE(filter_command_view.IsValid());
  ASSERT_EQ(filter_command_view.GetApcfOpcode(), ApcfOpcode::ENABLE);

  EXPECT_CALL(mock_callbacks_, OnFilterEnable);
  test_hci_layer_->IncomingEvent(
      LeAdvFilterEnableCompleteBuilder::Create(uint8_t{1}, ErrorCode::SUCCESS, Enable::ENABLED));
}

TEST_F(LeAndroidHciScanningManagerTest, scan_filter_parameter_test) {
  test_hci_layer_->SetCommandFuture(1);
  AdvertisingFilterParameter advertising_filter_parameter{};
  advertising_filter_parameter.delivery_mode = DeliveryMode::IMMEDIATE;
  le_scanning_manager->ScanFilterParameterSetup(ApcfAction::ADD, 0x01, advertising_filter_parameter);
  auto commandView = test_hci_layer_->GetCommand();
  ASSERT_EQ(OpCode::LE_ADV_FILTER, commandView.GetOpCode());
  auto filter_command_view = LeAdvFilterSetFilteringParametersView::Create(
      LeAdvFilterView::Create(LeScanningCommandView::Create(commandView)));
  ASSERT_TRUE(filter_command_view.IsValid());
  ASSERT_EQ(filter_command_view.GetApcfOpcode(), ApcfOpcode::SET_FILTERING_PARAMETERS);

  EXPECT_CALL(mock_callbacks_, OnFilterParamSetup);
  test_hci_layer_->IncomingEvent(
      LeAdvFilterSetFilteringParametersCompleteBuilder::Create(uint8_t{1}, ErrorCode::SUCCESS, ApcfAction::ADD, 0x0a));
}

TEST_F(LeAndroidHciScanningManagerTest, scan_filter_add_broadcaster_address_test) {
  test_hci_layer_->SetCommandFuture(1);
  std::vector<AdvertisingPacketContentFilterCommand> filters = {};
  AdvertisingPacketContentFilterCommand filter{};
  filter.filter_type = ApcfFilterType::BROADCASTER_ADDRESS;
  filter.address = Address::kEmpty;
  filter.application_address_type = ApcfApplicationAddressType::RANDOM;
  filters.push_back(filter);
  le_scanning_manager->ScanFilterAdd(0x01, filters);
  auto commandView = test_hci_layer_->GetCommand();
  ASSERT_EQ(OpCode::LE_ADV_FILTER, commandView.GetOpCode());
  auto filter_command_view =
      LeAdvFilterBroadcasterAddressView::Create(LeAdvFilterView::Create(LeScanningCommandView::Create(commandView)));
  ASSERT_TRUE(filter_command_view.IsValid());
  ASSERT_EQ(filter_command_view.GetApcfOpcode(), ApcfOpcode::BROADCASTER_ADDRESS);

  EXPECT_CALL(mock_callbacks_, OnFilterConfigCallback);
  test_hci_layer_->IncomingEvent(
      LeAdvFilterBroadcasterAddressCompleteBuilder::Create(uint8_t{1}, ErrorCode::SUCCESS, ApcfAction::ADD, 0x0a));
}

TEST_F(LeAndroidHciScanningManagerTest, scan_filter_add_service_uuid_test) {
  test_hci_layer_->SetCommandFuture(1);
  std::vector<AdvertisingPacketContentFilterCommand> filters = {};
  AdvertisingPacketContentFilterCommand filter{};
  filter.filter_type = ApcfFilterType::SERVICE_UUID;
  filter.uuid = Uuid::From32Bit(0x12345678);
  filter.uuid_mask = Uuid::From32Bit(0xffffffff);
  filters.push_back(filter);
  le_scanning_manager->ScanFilterAdd(0x01, filters);
  auto commandView = test_hci_layer_->GetCommand();
  ASSERT_EQ(OpCode::LE_ADV_FILTER, commandView.GetOpCode());
  auto filter_command_view =
      LeAdvFilterServiceUuidView::Create(LeAdvFilterView::Create(LeScanningCommandView::Create(commandView)));
  ASSERT_TRUE(filter_command_view.IsValid());
  ASSERT_EQ(filter_command_view.GetApcfOpcode(), ApcfOpcode::SERVICE_UUID);

  EXPECT_CALL(mock_callbacks_, OnFilterConfigCallback);
  test_hci_layer_->IncomingEvent(
      LeAdvFilterServiceUuidCompleteBuilder::Create(uint8_t{1}, ErrorCode::SUCCESS, ApcfAction::ADD, 0x0a));
}

TEST_F(LeAndroidHciScanningManagerTest, scan_filter_add_local_name_test) {
  test_hci_layer_->SetCommandFuture(1);
  std::vector<AdvertisingPacketContentFilterCommand> filters = {};
  AdvertisingPacketContentFilterCommand filter{};
  filter.filter_type = ApcfFilterType::LOCAL_NAME;
  filter.name = {0x01, 0x02, 0x03};
  filters.push_back(filter);
  le_scanning_manager->ScanFilterAdd(0x01, filters);
  auto commandView = test_hci_layer_->GetCommand();
  ASSERT_EQ(OpCode::LE_ADV_FILTER, commandView.GetOpCode());
  auto filter_command_view =
      LeAdvFilterLocalNameView::Create(LeAdvFilterView::Create(LeScanningCommandView::Create(commandView)));
  ASSERT_TRUE(filter_command_view.IsValid());
  ASSERT_EQ(filter_command_view.GetApcfOpcode(), ApcfOpcode::LOCAL_NAME);

  EXPECT_CALL(mock_callbacks_, OnFilterConfigCallback);
  test_hci_layer_->IncomingEvent(
      LeAdvFilterLocalNameCompleteBuilder::Create(uint8_t{1}, ErrorCode::SUCCESS, ApcfAction::ADD, 0x0a));
}

TEST_F(LeAndroidHciScanningManagerTest, scan_filter_add_manufacturer_data_test) {
  test_hci_layer_->SetCommandFuture(1);
  std::vector<AdvertisingPacketContentFilterCommand> filters = {};
  AdvertisingPacketContentFilterCommand filter{};
  filter.filter_type = ApcfFilterType::MANUFACTURER_DATA;
  filter.company = 0x12;
  filter.company_mask = 0xff;
  filter.data = {0x12, 0x34, 0x56, 0x78};
  filter.data_mask = {0xff, 0xff, 0xff, 0xff};
  filters.push_back(filter);
  le_scanning_manager->ScanFilterAdd(0x01, filters);
  auto commandView = test_hci_layer_->GetCommand();
  ASSERT_EQ(OpCode::LE_ADV_FILTER, commandView.GetOpCode());
  auto filter_command_view =
      LeAdvFilterManufacturerDataView::Create(LeAdvFilterView::Create(LeScanningCommandView::Create(commandView)));
  ASSERT_TRUE(filter_command_view.IsValid());
  ASSERT_EQ(filter_command_view.GetApcfOpcode(), ApcfOpcode::MANUFACTURER_DATA);

  EXPECT_CALL(mock_callbacks_, OnFilterConfigCallback);
  test_hci_layer_->IncomingEvent(
      LeAdvFilterManufacturerDataCompleteBuilder::Create(uint8_t{1}, ErrorCode::SUCCESS, ApcfAction::ADD, 0x0a));
}

TEST_F(LeAndroidHciScanningManagerTest, scan_filter_add_service_data_test) {
  test_hci_layer_->SetCommandFuture(1);
  std::vector<AdvertisingPacketContentFilterCommand> filters = {};
  AdvertisingPacketContentFilterCommand filter{};
  filter.filter_type = ApcfFilterType::SERVICE_DATA;
  filter.data = {0x12, 0x34, 0x56, 0x78};
  filter.data_mask = {0xff, 0xff, 0xff, 0xff};
  filters.push_back(filter);
  le_scanning_manager->ScanFilterAdd(0x01, filters);
  auto commandView = test_hci_layer_->GetCommand();
  ASSERT_EQ(OpCode::LE_ADV_FILTER, commandView.GetOpCode());
  auto filter_command_view =
      LeAdvFilterServiceDataView::Create(LeAdvFilterView::Create(LeScanningCommandView::Create(commandView)));
  ASSERT_TRUE(filter_command_view.IsValid());
  ASSERT_EQ(filter_command_view.GetApcfOpcode(), ApcfOpcode::SERVICE_DATA);

  EXPECT_CALL(mock_callbacks_, OnFilterConfigCallback);
  test_hci_layer_->IncomingEvent(
      LeAdvFilterServiceDataCompleteBuilder::Create(uint8_t{1}, ErrorCode::SUCCESS, ApcfAction::ADD, 0x0a));
}

TEST_F(LeAndroidHciScanningManagerTest, scan_filter_add_ad_type_test) {
  test_hci_layer_->SetCommandFuture(1);
  std::vector<AdvertisingPacketContentFilterCommand> filters = {};
  AdvertisingPacketContentFilterCommand filter{};
  filter.filter_type = ApcfFilterType::AD_TYPE;
  filter.ad_type = 0x09;
  filter.data = {0x12, 0x34, 0x56, 0x78};
  filter.data_mask = {0xff, 0xff, 0xff, 0xff};
  filters.push_back(filter);
  le_scanning_manager->ScanFilterAdd(0x01, filters);
  auto commandView = test_hci_layer_->GetCommand();
  ASSERT_EQ(OpCode::LE_ADV_FILTER, commandView.GetOpCode());
  auto filter_command_view =
      LeAdvFilterADTypeView::Create(LeAdvFilterView::Create(LeScanningCommandView::Create(commandView)));
  ASSERT_TRUE(filter_command_view.IsValid());
  ASSERT_EQ(filter_command_view.GetApcfOpcode(), ApcfOpcode::AD_TYPE);

  EXPECT_CALL(mock_callbacks_, OnFilterConfigCallback);
  test_hci_layer_->IncomingEvent(
      LeAdvFilterADTypeCompleteBuilder::Create(uint8_t{1}, ErrorCode::SUCCESS, ApcfAction::ADD, 0x0a));
}

TEST_F(LeAndroidHciScanningManagerTest, read_batch_scan_result) {
  // Enable batch scan feature
  test_hci_layer_->SetCommandFuture(2);
  le_scanning_manager->BatchScanConifgStorage(100, 0, 95, 0x00);
  ASSERT_EQ(OpCode::LE_BATCH_SCAN, test_hci_layer_->GetCommand().GetOpCode());
  test_hci_layer_->IncomingEvent(LeBatchScanEnableCompleteBuilder::Create(uint8_t{1}, ErrorCode::SUCCESS));
  ASSERT_EQ(OpCode::LE_BATCH_SCAN, test_hci_layer_->GetCommand().GetOpCode());
  test_hci_layer_->IncomingEvent(
      LeBatchScanSetStorageParametersCompleteBuilder::Create(uint8_t{1}, ErrorCode::SUCCESS));

  // Enable batch scan
  test_hci_layer_->SetCommandFuture(1);
  le_scanning_manager->BatchScanEnable(BatchScanMode::FULL, 2400, 2400, BatchScanDiscardRule::OLDEST);
  ASSERT_EQ(OpCode::LE_BATCH_SCAN, test_hci_layer_->GetCommand().GetOpCode());
  test_hci_layer_->IncomingEvent(LeBatchScanEnableCompleteBuilder::Create(uint8_t{1}, ErrorCode::SUCCESS));

  // Read batch scan data
  test_hci_layer_->SetCommandFuture(1);
  le_scanning_manager->BatchScanReadReport(0x01, BatchScanMode::FULL);
  ASSERT_EQ(OpCode::LE_BATCH_SCAN, test_hci_layer_->GetCommand().GetOpCode());

  // We will send read command while num_of_record != 0
  std::vector<uint8_t> raw_data = {0x5c, 0x1f, 0xa2, 0xc3, 0x63, 0x5d, 0x01, 0xf5, 0xb3, 0x5e, 0x00, 0x0c, 0x02,
                                   0x01, 0x02, 0x05, 0x09, 0x6d, 0x76, 0x38, 0x76, 0x02, 0x0a, 0xf5, 0x00};
  test_hci_layer_->SetCommandFuture(1);
  test_hci_layer_->IncomingEvent(LeBatchScanReadResultParametersCompleteRawBuilder::Create(
      uint8_t{1}, ErrorCode::SUCCESS, BatchScanDataRead::FULL_MODE_DATA, 1, raw_data));
  ASSERT_EQ(OpCode::LE_BATCH_SCAN, test_hci_layer_->GetCommand().GetOpCode());

  // OnBatchScanReports will be trigger when num_of_record == 0
  EXPECT_CALL(mock_callbacks_, OnBatchScanReports);
  test_hci_layer_->IncomingEvent(LeBatchScanReadResultParametersCompleteRawBuilder::Create(
      uint8_t{1}, ErrorCode::SUCCESS, BatchScanDataRead::FULL_MODE_DATA, 0, {}));
}

TEST_F(LeExtendedScanningManagerTest, startup_teardown) {}

TEST_F(LeExtendedScanningManagerTest, start_scan_test) {
  // Enable scan
  test_hci_layer_->SetCommandFuture(2);
  le_scanning_manager->Scan(true);
  ASSERT_EQ(param_opcode_, test_hci_layer_->GetCommand().GetOpCode());
  test_hci_layer_->IncomingEvent(LeSetExtendedScanParametersCompleteBuilder::Create(uint8_t{1}, ErrorCode::SUCCESS));
  ASSERT_EQ(enable_opcode_, test_hci_layer_->GetCommand().GetOpCode());
  test_hci_layer_->IncomingEvent(LeSetExtendedScanEnableCompleteBuilder::Create(uint8_t{1}, ErrorCode::SUCCESS));
  LeExtendedAdvertisingResponse report{};
  report.connectable_ = 1;
  report.scannable_ = 0;
  report.address_type_ = DirectAdvertisingAddressType::PUBLIC_DEVICE_ADDRESS;
  Address::FromString("12:34:56:78:9a:bc", report.address_);
  std::vector<LengthAndData> adv_data{};
  LengthAndData data_item{};
  data_item.data_.push_back(static_cast<uint8_t>(GapDataType::FLAGS));
  data_item.data_.push_back(0x34);
  adv_data.push_back(data_item);
  data_item.data_.push_back(static_cast<uint8_t>(GapDataType::COMPLETE_LOCAL_NAME));
  for (auto octet : {'r', 'a', 'n', 'd', 'o', 'm', ' ', 'd', 'e', 'v', 'i', 'c', 'e'}) {
    data_item.data_.push_back(octet);
  }
  adv_data.push_back(data_item);

  report.advertising_data_ = adv_data;

  EXPECT_CALL(mock_callbacks_, OnScanResult);

  test_hci_layer_->IncomingLeMetaEvent(LeExtendedAdvertisingReportBuilder::Create({report}));
}

TEST_F(LeExtendedScanningManagerTest, drop_insignificant_bytes_test) {
  // Enable scan
  test_hci_layer_->SetCommandFuture(2);
  le_scanning_manager->Scan(true);
  ASSERT_EQ(param_opcode_, test_hci_layer_->GetCommand().GetOpCode());
  test_hci_layer_->IncomingEvent(LeSetExtendedScanParametersCompleteBuilder::Create(uint8_t{1}, ErrorCode::SUCCESS));
  ASSERT_EQ(enable_opcode_, test_hci_layer_->GetCommand().GetOpCode());
  test_hci_layer_->IncomingEvent(LeSetExtendedScanEnableCompleteBuilder::Create(uint8_t{1}, ErrorCode::SUCCESS));

  // Prepare advertisement report
  LeExtendedAdvertisingResponse advertisement_report{};
  advertisement_report.connectable_ = 1;
  advertisement_report.scannable_ = 1;
  advertisement_report.address_type_ = DirectAdvertisingAddressType::PUBLIC_DEVICE_ADDRESS;
  Address::FromString("12:34:56:78:9a:bc", advertisement_report.address_);
  std::vector<LengthAndData> adv_data{};
  LengthAndData flags_data{};
  flags_data.data_.push_back(static_cast<uint8_t>(GapDataType::FLAGS));
  flags_data.data_.push_back(0x34);
  adv_data.push_back(flags_data);
  LengthAndData name_data{};
  name_data.data_.push_back(static_cast<uint8_t>(GapDataType::COMPLETE_LOCAL_NAME));
  for (auto octet : "random device") {
    name_data.data_.push_back(octet);
  }
  adv_data.push_back(name_data);
  for (int i = 0; i != 5; ++i) {
    adv_data.push_back({});  // pad with a few insigificant zeros
  }
  advertisement_report.advertising_data_ = adv_data;

  // Prepare scan response report
  auto scan_response_report = advertisement_report;
  scan_response_report.scan_response_ = true;
  LengthAndData extra_data{};
  extra_data.data_.push_back(static_cast<uint8_t>(GapDataType::MANUFACTURER_SPECIFIC_DATA));
  for (auto octet : "manufacturer specific") {
    extra_data.data_.push_back(octet);
  }
  adv_data = {extra_data};
  for (int i = 0; i != 5; ++i) {
    adv_data.push_back({});  // pad with a few insigificant zeros
  }
  scan_response_report.advertising_data_ = adv_data;

  // We expect the two reports to be concatenated, excluding the zero-padding
  auto result = std::vector<uint8_t>();
  packet::BitInserter it(result);
  flags_data.Serialize(it);
  name_data.Serialize(it);
  extra_data.Serialize(it);
  EXPECT_CALL(mock_callbacks_, OnScanResult(_, _, _, _, _, _, _, _, _, result));

  // Send both reports
  test_hci_layer_->IncomingLeMetaEvent(LeExtendedAdvertisingReportBuilder::Create({advertisement_report}));
  test_hci_layer_->IncomingLeMetaEvent(LeExtendedAdvertisingReportBuilder::Create({scan_response_report}));
}

}  // namespace
}  // namespace hci
}  // namespace bluetooth
