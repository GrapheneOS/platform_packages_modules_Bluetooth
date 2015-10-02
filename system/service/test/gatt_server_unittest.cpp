//
//  Copyright (C) 2015 Google, Inc.
//
//  Licensed under the Apache License, Version 2.0 (the "License");
//  you may not use this file except in compliance with the License.
//  You may obtain a copy of the License at:
//
//  http://www.apache.org/licenses/LICENSE-2.0
//
//  Unless required by applicable law or agreed to in writing, software
//  distributed under the License is distributed on an "AS IS" BASIS,
//  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//  See the License for the specific language governing permissions and
//  limitations under the License.
//

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "service/gatt_server.h"
#include "service/hal/fake_bluetooth_gatt_interface.h"

using ::testing::_;
using ::testing::Return;

namespace bluetooth {
namespace {

class MockGattHandler
    : public hal::FakeBluetoothGattInterface::TestServerHandler {
 public:
  MockGattHandler() = default;
  ~MockGattHandler() override = default;

  MOCK_METHOD1(RegisterServer, bt_status_t(bt_uuid_t*));
  MOCK_METHOD1(UnregisterServer, bt_status_t(int));

 private:
  DISALLOW_COPY_AND_ASSIGN(MockGattHandler);
};

class GattServerTest : public ::testing::Test {
 public:
  GattServerTest() = default;
  ~GattServerTest() override = default;

  void SetUp() override {
    mock_handler_.reset(new MockGattHandler());
    fake_hal_gatt_iface_ = new hal::FakeBluetoothGattInterface(
        nullptr,
        std::static_pointer_cast<
            hal::FakeBluetoothGattInterface::TestServerHandler>(mock_handler_));

    hal::BluetoothGattInterface::InitializeForTesting(fake_hal_gatt_iface_);
    factory_.reset(new GattServerFactory());
  }

  void TearDown() override {
    factory_.reset();
    hal::BluetoothGattInterface::CleanUp();
  }

 protected:
  hal::FakeBluetoothGattInterface* fake_hal_gatt_iface_;
  std::shared_ptr<MockGattHandler> mock_handler_;
  std::unique_ptr<GattServerFactory> factory_;

 private:
  DISALLOW_COPY_AND_ASSIGN(GattServerTest);
};

TEST_F(GattServerTest, RegisterServer) {
  EXPECT_CALL(*mock_handler_, RegisterServer(_))
      .Times(2)
      .WillOnce(Return(BT_STATUS_FAIL))
      .WillOnce(Return(BT_STATUS_SUCCESS));

  // These will be asynchronously populate with a result when the callback
  // executes.
  BLEStatus status = BLE_STATUS_SUCCESS;
  UUID cb_uuid;
  std::unique_ptr<GattServer> server;
  int callback_count = 0;

  auto callback = [&](BLEStatus in_status, const UUID& uuid,
                      std::unique_ptr<BluetoothClientInstance> in_server) {
    status = in_status;
    cb_uuid = uuid;
    server = std::unique_ptr<GattServer>(
        static_cast<GattServer*>(in_server.release()));
    callback_count++;
  };

  UUID uuid0 = UUID::GetRandom();

  // HAL returns failure.
  EXPECT_FALSE(factory_->RegisterClient(uuid0, callback));
  EXPECT_EQ(0, callback_count);

  // HAL returns success.
  EXPECT_TRUE(factory_->RegisterClient(uuid0, callback));
  EXPECT_EQ(0, callback_count);

  // Calling twice with the same UUID should fail with no additional calls into
  // the stack.
  EXPECT_FALSE(factory_->RegisterClient(uuid0, callback));

  testing::Mock::VerifyAndClearExpectations(mock_handler_.get());

  // Call with a different UUID while one is pending.
  UUID uuid1 = UUID::GetRandom();
  EXPECT_CALL(*mock_handler_, RegisterServer(_))
      .Times(1)
      .WillOnce(Return(BT_STATUS_SUCCESS));
  EXPECT_TRUE(factory_->RegisterClient(uuid1, callback));

  // Trigger callback with an unknown UUID. This should get ignored.
  UUID uuid2 = UUID::GetRandom();
  bt_uuid_t hal_uuid = uuid2.GetBlueDroid();
  fake_hal_gatt_iface_->NotifyRegisterServerCallback(0, 0, hal_uuid);
  EXPECT_EQ(0, callback_count);

  // |uuid0| succeeds.
  int server_if0 = 2;  // Pick something that's not 0.
  hal_uuid = uuid0.GetBlueDroid();
  fake_hal_gatt_iface_->NotifyRegisterServerCallback(
      BT_STATUS_SUCCESS, server_if0, hal_uuid);

  EXPECT_EQ(1, callback_count);
  ASSERT_TRUE(server.get() != nullptr);  // Assert to terminate in case of error
  EXPECT_EQ(BLE_STATUS_SUCCESS, status);
  EXPECT_EQ(server_if0, server->GetClientId());
  EXPECT_EQ(uuid0, server->GetAppIdentifier());
  EXPECT_EQ(uuid0, cb_uuid);

  // The server should unregister itself when deleted.
  EXPECT_CALL(*mock_handler_, UnregisterServer(server_if0))
      .Times(1)
      .WillOnce(Return(BT_STATUS_SUCCESS));
  server.reset();

  testing::Mock::VerifyAndClearExpectations(mock_handler_.get());

  // |uuid1| fails.
  int server_if1 = 3;
  hal_uuid = uuid1.GetBlueDroid();
  fake_hal_gatt_iface_->NotifyRegisterServerCallback(
      BT_STATUS_FAIL, server_if1, hal_uuid);

  EXPECT_EQ(2, callback_count);
  ASSERT_TRUE(server.get() == nullptr);  // Assert to terminate in case of error
  EXPECT_EQ(BLE_STATUS_FAILURE, status);
  EXPECT_EQ(uuid1, cb_uuid);
}

}  // namespace
}  // namespace bluetooth
