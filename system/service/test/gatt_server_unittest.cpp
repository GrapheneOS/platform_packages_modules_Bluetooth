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
#include "service/hal/gatt_helpers.h"

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
  MOCK_METHOD3(AddService, bt_status_t(int, btgatt_srvc_id_t*, int));
  MOCK_METHOD5(AddCharacteristic, bt_status_t(int, int, bt_uuid_t*, int, int));
  MOCK_METHOD4(AddDescriptor, bt_status_t(int, int, bt_uuid_t*, int));
  MOCK_METHOD3(StartService, bt_status_t(int, int, int));
  MOCK_METHOD2(DeleteService, bt_status_t(int, int));
  MOCK_METHOD4(SendResponse, bt_status_t(int, int, int, btgatt_response_t*));

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

const int kDefaultServerId = 4;

class GattServerPostRegisterTest : public GattServerTest {
 public:
  GattServerPostRegisterTest() = default;
  ~GattServerPostRegisterTest() override = default;

  void SetUp() override {
    GattServerTest::SetUp();
    UUID uuid = UUID::GetRandom();
    auto callback = [&](BLEStatus status, const UUID& in_uuid,
                        std::unique_ptr<BluetoothClientInstance> in_client) {
      CHECK(in_uuid == uuid);
      CHECK(in_client.get());
      CHECK(status == BLE_STATUS_SUCCESS);

      gatt_server_ = std::unique_ptr<GattServer>(
          static_cast<GattServer*>(in_client.release()));
    };

    EXPECT_CALL(*mock_handler_, RegisterServer(_))
        .Times(1)
        .WillOnce(Return(BT_STATUS_SUCCESS));

    factory_->RegisterClient(uuid, callback);

    bt_uuid_t hal_uuid = uuid.GetBlueDroid();
    fake_hal_gatt_iface_->NotifyRegisterServerCallback(
        BT_STATUS_SUCCESS,
        kDefaultServerId,
        hal_uuid);
  }

  void TearDown() override {
    EXPECT_CALL(*mock_handler_, UnregisterServer(_))
        .Times(1)
        .WillOnce(Return(BT_STATUS_SUCCESS));
    gatt_server_ = nullptr;
    GattServerTest::TearDown();
  }

 protected:
  std::unique_ptr<GattServer> gatt_server_;

 private:
  DISALLOW_COPY_AND_ASSIGN(GattServerPostRegisterTest);
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

TEST_F(GattServerPostRegisterTest, SimpleServiceTest) {
  // Setup a service callback.
  GattIdentifier cb_id;
  BLEStatus cb_status = BLE_STATUS_SUCCESS;
  int cb_count = 0;
  auto callback = [&](BLEStatus in_status, const GattIdentifier& in_id) {
    cb_id = in_id;
    cb_status = in_status;
    cb_count++;
  };

  // Service declaration not started.
  EXPECT_FALSE(gatt_server_->EndServiceDeclaration(callback));

  const UUID uuid = UUID::GetRandom();
  auto service_id = gatt_server_->BeginServiceDeclaration(uuid, true);
  EXPECT_TRUE(service_id != nullptr);
  EXPECT_TRUE(service_id->IsService());

  // Already started.
  EXPECT_FALSE(gatt_server_->BeginServiceDeclaration(uuid, false));

  // Callback is NULL.
  EXPECT_FALSE(
      gatt_server_->EndServiceDeclaration(GattServer::ResultCallback()));

  // We should get a call for a service with one handle.
  EXPECT_CALL(*mock_handler_, AddService(gatt_server_->GetClientId(), _, 1))
      .Times(2)
      .WillOnce(Return(BT_STATUS_FAIL))
      .WillOnce(Return(BT_STATUS_SUCCESS));

  // Stack returns failure. This will cause the entire service declaration to
  // end and needs to be restarted.
  EXPECT_FALSE(gatt_server_->EndServiceDeclaration(callback));

  service_id = gatt_server_->BeginServiceDeclaration(uuid, true);
  EXPECT_TRUE(service_id != nullptr);
  EXPECT_TRUE(service_id->IsService());

  // Stack returns success.
  EXPECT_TRUE(gatt_server_->EndServiceDeclaration(callback));

  // EndServiceDeclaration already in progress.
  EXPECT_FALSE(gatt_server_->EndServiceDeclaration(callback));

  EXPECT_EQ(0, cb_count);

  btgatt_srvc_id_t hal_id;
  hal::GetHALServiceId(*service_id, &hal_id);
  int srvc_handle = 0x0001;

  // Report success for AddService but for wrong server. Should be ignored.
  fake_hal_gatt_iface_->NotifyServiceAddedCallback(
      BT_STATUS_SUCCESS, kDefaultServerId + 1, hal_id, srvc_handle);
  EXPECT_EQ(0, cb_count);

  // Report success for AddService.
  EXPECT_CALL(*mock_handler_, StartService(kDefaultServerId, srvc_handle, _))
      .Times(1)
      .WillOnce(Return(BT_STATUS_SUCCESS));

  fake_hal_gatt_iface_->NotifyServiceAddedCallback(
      BT_STATUS_SUCCESS, kDefaultServerId, hal_id, srvc_handle);
  EXPECT_EQ(0, cb_count);

  // Report success for StartService but for wrong server. Should be ignored.
  fake_hal_gatt_iface_->NotifyServiceStartedCallback(
      BT_STATUS_SUCCESS, kDefaultServerId + 1, srvc_handle);
  EXPECT_EQ(0, cb_count);

  // Report success for StartService.
  fake_hal_gatt_iface_->NotifyServiceStartedCallback(
      BT_STATUS_SUCCESS, kDefaultServerId, srvc_handle);
  EXPECT_EQ(1, cb_count);
  EXPECT_EQ(BLE_STATUS_SUCCESS, cb_status);
  EXPECT_TRUE(cb_id == *service_id);

  // Start new service declaration with same UUID. We should get a different ID.
  auto service_id1 = gatt_server_->BeginServiceDeclaration(uuid, true);
  EXPECT_TRUE(service_id1 != nullptr);
  EXPECT_TRUE(service_id1->IsService());
  EXPECT_TRUE(*service_id != *service_id1);
}

TEST_F(GattServerPostRegisterTest, AddServiceFailures) {
  // Setup a service callback.
  GattIdentifier cb_id;
  BLEStatus cb_status = BLE_STATUS_SUCCESS;
  int cb_count = 0;
  auto callback = [&](BLEStatus in_status, const GattIdentifier& in_id) {
    cb_id = in_id;
    cb_status = in_status;
    cb_count++;
  };

  const UUID uuid = UUID::GetRandom();
  auto service_id = gatt_server_->BeginServiceDeclaration(uuid, true);
  btgatt_srvc_id_t hal_id;
  hal::GetHALServiceId(*service_id, &hal_id);
  int srvc_handle = 0x0001;

  EXPECT_CALL(*mock_handler_, AddService(gatt_server_->GetClientId(), _, 1))
      .Times(3)
      .WillRepeatedly(Return(BT_STATUS_SUCCESS));
  EXPECT_TRUE(gatt_server_->EndServiceDeclaration(callback));

  // Report failure for AddService.
  fake_hal_gatt_iface_->NotifyServiceAddedCallback(
      BT_STATUS_FAIL, kDefaultServerId, hal_id, srvc_handle);
  EXPECT_EQ(1, cb_count);
  EXPECT_NE(BLE_STATUS_SUCCESS, cb_status);
  EXPECT_TRUE(cb_id == *service_id);

  // Restart. We should get the same ID back.
  auto service_id1 = gatt_server_->BeginServiceDeclaration(uuid, true);
  EXPECT_TRUE(*service_id1 == *service_id);
  EXPECT_TRUE(gatt_server_->EndServiceDeclaration(callback));

  // Report success for AddService but return failure from StartService.
  EXPECT_CALL(*mock_handler_, StartService(gatt_server_->GetClientId(), 1, _))
      .Times(2)
      .WillOnce(Return(BT_STATUS_FAIL))
      .WillOnce(Return(BT_STATUS_SUCCESS));

  fake_hal_gatt_iface_->NotifyServiceAddedCallback(
      BT_STATUS_SUCCESS, kDefaultServerId, hal_id, srvc_handle);
  EXPECT_EQ(2, cb_count);
  EXPECT_NE(BLE_STATUS_SUCCESS, cb_status);
  EXPECT_TRUE(cb_id == *service_id);

  // Restart.
  service_id = gatt_server_->BeginServiceDeclaration(uuid, true);
  EXPECT_TRUE(gatt_server_->EndServiceDeclaration(callback));

  // Report success for AddService, return success from StartService.
  fake_hal_gatt_iface_->NotifyServiceAddedCallback(
      BT_STATUS_SUCCESS, kDefaultServerId, hal_id, srvc_handle);
  EXPECT_EQ(2, cb_count);

  // Report failure for StartService. Added service data should get deleted.
  EXPECT_CALL(*mock_handler_,
              DeleteService(gatt_server_->GetClientId(), srvc_handle))
      .Times(1)
      .WillOnce(Return(BT_STATUS_SUCCESS));
  fake_hal_gatt_iface_->NotifyServiceStartedCallback(
      BT_STATUS_FAIL, kDefaultServerId, srvc_handle);
  EXPECT_EQ(3, cb_count);
  EXPECT_NE(BLE_STATUS_SUCCESS, cb_status);
  EXPECT_TRUE(cb_id == *service_id);
}

TEST_F(GattServerPostRegisterTest, AddCharacteristic) {
  // Just pick some values.
  const int props = bluetooth::kCharacteristicPropertyRead |
      bluetooth::kCharacteristicPropertyNotify;
  const int perms = kAttributePermissionReadEncrypted;
  const UUID char_uuid = UUID::GetRandom();
  bt_uuid_t hal_char_uuid = char_uuid.GetBlueDroid();

  // Declaration not started.
  EXPECT_EQ(nullptr, gatt_server_->AddCharacteristic(char_uuid, props, perms));

  // Start a service declaration.
  const UUID service_uuid = UUID::GetRandom();
  auto service_id = gatt_server_->BeginServiceDeclaration(service_uuid, true);
  EXPECT_TRUE(service_id != nullptr);
  btgatt_srvc_id_t hal_id;
  hal::GetHALServiceId(*service_id, &hal_id);

  // Add two characteristics with the same UUID.
  auto char_id0 = gatt_server_->AddCharacteristic(char_uuid, props, perms);
  auto char_id1 = gatt_server_->AddCharacteristic(char_uuid, props, perms);

  EXPECT_TRUE(char_id0 != nullptr);
  EXPECT_TRUE(char_id1 != nullptr);
  EXPECT_TRUE(char_id0 != char_id1);
  EXPECT_TRUE(char_id0->IsCharacteristic());
  EXPECT_TRUE(char_id1->IsCharacteristic());
  EXPECT_TRUE(*char_id0->GetOwningServiceId() == *service_id);
  EXPECT_TRUE(*char_id1->GetOwningServiceId() == *service_id);

  // Expect calls for 5 handles in total as we have 2 characteristics.
  EXPECT_CALL(*mock_handler_, AddService(kDefaultServerId, _, 5))
      .WillRepeatedly(Return(BT_STATUS_SUCCESS));

  GattIdentifier cb_id;
  BLEStatus cb_status;
  int cb_count = 0;
  auto callback = [&](BLEStatus in_status, const GattIdentifier& in_id) {
    cb_id = in_id;
    cb_status = in_status;
    cb_count++;
  };

  int srvc_handle = 0x0001;
  int char_handle0 = 0x0002;
  int char_handle1 = 0x0004;
  EXPECT_TRUE(gatt_server_->EndServiceDeclaration(callback));

  // Cannot add any more characteristics while EndServiceDeclaration is in
  // progress.
  EXPECT_EQ(nullptr, gatt_server_->AddCharacteristic(char_uuid, props, perms));

  EXPECT_CALL(*mock_handler_, AddCharacteristic(_, _, _, _, _))
      .Times(8)
      .WillOnce(Return(BT_STATUS_FAIL))      // char_id0 - try 1
      .WillOnce(Return(BT_STATUS_SUCCESS))   // char_id0 - try 2
      .WillOnce(Return(BT_STATUS_SUCCESS))   // char_id0 - try 3
      .WillOnce(Return(BT_STATUS_FAIL))      // char_id1 - try 3
      .WillOnce(Return(BT_STATUS_SUCCESS))   // char_id0 - try 4
      .WillOnce(Return(BT_STATUS_SUCCESS))   // char_id1 - try 4
      .WillOnce(Return(BT_STATUS_SUCCESS))   // char_id0 - try 5
      .WillOnce(Return(BT_STATUS_SUCCESS));  // char_id1 - try 5

  // First AddCharacteristic call will fail.
  fake_hal_gatt_iface_->NotifyServiceAddedCallback(
      BT_STATUS_SUCCESS, kDefaultServerId, hal_id, srvc_handle);
  EXPECT_EQ(1, cb_count);
  EXPECT_NE(BLE_STATUS_SUCCESS, cb_status);
  EXPECT_TRUE(cb_id == *service_id);

  // Restart. (try 2)
  service_id = gatt_server_->BeginServiceDeclaration(service_uuid, true);
  char_id0 = gatt_server_->AddCharacteristic(char_uuid, props, perms);
  char_id1 = gatt_server_->AddCharacteristic(char_uuid, props, perms);
  hal::GetHALServiceId(*service_id, &hal_id);
  EXPECT_TRUE(gatt_server_->EndServiceDeclaration(callback));

  fake_hal_gatt_iface_->NotifyServiceAddedCallback(
      BT_STATUS_SUCCESS, kDefaultServerId, hal_id, srvc_handle);
  EXPECT_EQ(1, cb_count);

  // Report failure for pending AddCharacteristic.
  fake_hal_gatt_iface_->NotifyCharacteristicAddedCallback(
      BT_STATUS_FAIL, kDefaultServerId, hal_char_uuid,
      srvc_handle, char_handle0);
  EXPECT_EQ(2, cb_count);
  EXPECT_NE(BLE_STATUS_SUCCESS, cb_status);
  EXPECT_TRUE(cb_id == *service_id);

  // Restart. (try 3)
  service_id = gatt_server_->BeginServiceDeclaration(service_uuid, true);
  char_id0 = gatt_server_->AddCharacteristic(char_uuid, props, perms);
  char_id1 = gatt_server_->AddCharacteristic(char_uuid, props, perms);
  hal::GetHALServiceId(*service_id, &hal_id);
  EXPECT_TRUE(gatt_server_->EndServiceDeclaration(callback));

  fake_hal_gatt_iface_->NotifyServiceAddedCallback(
      BT_STATUS_SUCCESS, kDefaultServerId, hal_id, srvc_handle);
  EXPECT_EQ(2, cb_count);

  // Report success for pending AddCharacteristic we should receive a call for
  // the second characteristic which will fail.
  fake_hal_gatt_iface_->NotifyCharacteristicAddedCallback(
      BT_STATUS_SUCCESS, kDefaultServerId, hal_char_uuid,
      srvc_handle, char_handle0);
  EXPECT_EQ(3, cb_count);
  EXPECT_NE(BLE_STATUS_SUCCESS, cb_status);
  EXPECT_TRUE(cb_id == *service_id);

  // Restart. (try 4)
  service_id = gatt_server_->BeginServiceDeclaration(service_uuid, true);
  char_id0 = gatt_server_->AddCharacteristic(char_uuid, props, perms);
  char_id1 = gatt_server_->AddCharacteristic(char_uuid, props, perms);
  hal::GetHALServiceId(*service_id, &hal_id);
  EXPECT_TRUE(gatt_server_->EndServiceDeclaration(callback));

  fake_hal_gatt_iface_->NotifyServiceAddedCallback(
      BT_STATUS_SUCCESS, kDefaultServerId, hal_id, srvc_handle);
  EXPECT_EQ(3, cb_count);

  // Report success for pending AddCharacteristic. Second characteristic call
  // will start normally. We shouldn't receive any new callback.
  fake_hal_gatt_iface_->NotifyCharacteristicAddedCallback(
      BT_STATUS_SUCCESS, kDefaultServerId, hal_char_uuid,
      srvc_handle, char_handle0);
  EXPECT_EQ(3, cb_count);

  // Report failure for pending AddCharacteristic call for second
  // characteristic.
  fake_hal_gatt_iface_->NotifyCharacteristicAddedCallback(
      BT_STATUS_FAIL, kDefaultServerId, hal_char_uuid,
      srvc_handle, char_handle1);
  EXPECT_EQ(4, cb_count);
  EXPECT_NE(BLE_STATUS_SUCCESS, cb_status);
  EXPECT_TRUE(cb_id == *service_id);

  // Restart. (try 5)
  service_id = gatt_server_->BeginServiceDeclaration(service_uuid, true);
  char_id0 = gatt_server_->AddCharacteristic(char_uuid, props, perms);
  char_id1 = gatt_server_->AddCharacteristic(char_uuid, props, perms);
  hal::GetHALServiceId(*service_id, &hal_id);
  EXPECT_TRUE(gatt_server_->EndServiceDeclaration(callback));

  fake_hal_gatt_iface_->NotifyServiceAddedCallback(
      BT_STATUS_SUCCESS, kDefaultServerId, hal_id, srvc_handle);
  EXPECT_EQ(4, cb_count);

  // Report success for pending AddCharacteristic. Second characteristic call
  // will start normally. We shouldn't receive any new callback.
  fake_hal_gatt_iface_->NotifyCharacteristicAddedCallback(
      BT_STATUS_SUCCESS, kDefaultServerId, hal_char_uuid,
      srvc_handle, char_handle0);
  EXPECT_EQ(4, cb_count);

  // Report success for pending AddCharacteristic call for second
  // characteristic. We shouldn't receive any new callback but we'll get a call
  // to StartService.
  EXPECT_CALL(*mock_handler_, StartService(kDefaultServerId, srvc_handle, _))
      .Times(1)
      .WillOnce(Return(BT_STATUS_SUCCESS));
  fake_hal_gatt_iface_->NotifyCharacteristicAddedCallback(
      BT_STATUS_SUCCESS, kDefaultServerId, hal_char_uuid,
      srvc_handle, char_handle1);
  EXPECT_EQ(4, cb_count);
}

TEST_F(GattServerPostRegisterTest, AddDescriptor) {
  // Set up some values for UUIDs, permissions, and properties.
  const UUID service_uuid = UUID::GetRandom();
  const UUID char_uuid0 = UUID::GetRandom();
  const UUID char_uuid1 = UUID::GetRandom();
  const UUID desc_uuid = UUID::GetRandom();
  bt_uuid_t hal_char_uuid0 = char_uuid0.GetBlueDroid();
  bt_uuid_t hal_char_uuid1 = char_uuid1.GetBlueDroid();
  bt_uuid_t hal_desc_uuid = desc_uuid.GetBlueDroid();
  const int props = bluetooth::kCharacteristicPropertyRead |
      bluetooth::kCharacteristicPropertyNotify;
  const int perms = kAttributePermissionReadEncrypted;

  // Service declaration not started.
  EXPECT_EQ(nullptr, gatt_server_->AddDescriptor(desc_uuid, perms));

  // Start a service declaration.
  auto service_id = gatt_server_->BeginServiceDeclaration(service_uuid, true);
  btgatt_srvc_id_t hal_id;
  hal::GetHALServiceId(*service_id, &hal_id);

  // No characteristic was inserted.
  EXPECT_EQ(nullptr, gatt_server_->AddDescriptor(desc_uuid, perms));

  // Add two characeristics.
  auto char_id0 = gatt_server_->AddCharacteristic(char_uuid0, props, perms);
  auto char_id1 = gatt_server_->AddCharacteristic(char_uuid1, props, perms);

  // Add a descriptor.
  auto desc_id = gatt_server_->AddDescriptor(desc_uuid, perms);
  EXPECT_NE(nullptr, desc_id);
  EXPECT_TRUE(desc_id->IsDescriptor());
  EXPECT_TRUE(*desc_id->GetOwningCharacteristicId() == *char_id1);
  EXPECT_TRUE(*desc_id->GetOwningServiceId() == *service_id);

  // Add a second descriptor with the same UUID.
  auto desc_id1 = gatt_server_->AddDescriptor(desc_uuid, perms);
  EXPECT_NE(nullptr, desc_id1);
  EXPECT_TRUE(*desc_id1 != *desc_id);
  EXPECT_TRUE(desc_id1->IsDescriptor());
  EXPECT_TRUE(*desc_id1->GetOwningCharacteristicId() == *char_id1);
  EXPECT_TRUE(*desc_id1->GetOwningServiceId() == *service_id);

  // Expect calls for 7 handles.
  EXPECT_CALL(*mock_handler_, AddService(kDefaultServerId, _, 7))
      .WillRepeatedly(Return(BT_STATUS_SUCCESS));
  EXPECT_CALL(*mock_handler_, AddCharacteristic(_, _, _, _, _))
      .WillRepeatedly(Return(BT_STATUS_SUCCESS));

  GattIdentifier cb_id;
  BLEStatus cb_status;
  int cb_count = 0;
  auto callback = [&](BLEStatus in_status, const GattIdentifier& in_id) {
    cb_id = in_id;
    cb_status = in_status;
    cb_count++;
  };

  int srvc_handle = 0x0001;
  int char_handle0 = 0x0002;
  int char_handle1 = 0x0004;
  int desc_handle0 = 0x0005;
  int desc_handle1 = 0x0006;

  EXPECT_TRUE(gatt_server_->EndServiceDeclaration(callback));

  // Cannot add any more descriptors while EndServiceDeclaration is in progress.
  EXPECT_EQ(nullptr, gatt_server_->AddDescriptor(desc_uuid, perms));

  fake_hal_gatt_iface_->NotifyServiceAddedCallback(
      BT_STATUS_SUCCESS, kDefaultServerId, hal_id, srvc_handle);
  EXPECT_EQ(0, cb_count);

  EXPECT_CALL(*mock_handler_, AddDescriptor(_, _, _, _))
      .Times(8)
      .WillOnce(Return(BT_STATUS_FAIL))      // desc_id0 - try 1
      .WillOnce(Return(BT_STATUS_SUCCESS))   // desc_id0 - try 2
      .WillOnce(Return(BT_STATUS_SUCCESS))   // desc_id0 - try 3
      .WillOnce(Return(BT_STATUS_FAIL))      // desc_id1 - try 3
      .WillOnce(Return(BT_STATUS_SUCCESS))   // desc_id0 - try 4
      .WillOnce(Return(BT_STATUS_SUCCESS))   // desc_id1 - try 4
      .WillOnce(Return(BT_STATUS_SUCCESS))   // desc_id0 - try 5
      .WillOnce(Return(BT_STATUS_SUCCESS));  // desc_id1 - try 5

  // Notify success for both characteristics. First descriptor call will fail.
  fake_hal_gatt_iface_->NotifyCharacteristicAddedCallback(
      BT_STATUS_SUCCESS, kDefaultServerId, hal_char_uuid0,
      srvc_handle, char_handle0);
  EXPECT_EQ(0, cb_count);
  fake_hal_gatt_iface_->NotifyCharacteristicAddedCallback(
      BT_STATUS_SUCCESS, kDefaultServerId, hal_char_uuid1,
      srvc_handle, char_handle1);
  EXPECT_EQ(1, cb_count);
  EXPECT_NE(BLE_STATUS_SUCCESS, cb_status);
  EXPECT_TRUE(cb_id == *service_id);

  // Restart (try 2)
  cb_count = 0;
  service_id = gatt_server_->BeginServiceDeclaration(service_uuid, true);
  hal::GetHALServiceId(*service_id, &hal_id);
  char_id0 = gatt_server_->AddCharacteristic(char_uuid0, props, perms);
  char_id1 = gatt_server_->AddCharacteristic(char_uuid1, props, perms);
  desc_id = gatt_server_->AddDescriptor(desc_uuid, perms);
  ASSERT_NE(nullptr, desc_id);
  desc_id1 = gatt_server_->AddDescriptor(desc_uuid, perms);
  ASSERT_NE(nullptr, desc_id1);
  EXPECT_TRUE(gatt_server_->EndServiceDeclaration(callback));

  fake_hal_gatt_iface_->NotifyServiceAddedCallback(
      BT_STATUS_SUCCESS, kDefaultServerId, hal_id, srvc_handle);
  EXPECT_EQ(0, cb_count);
  fake_hal_gatt_iface_->NotifyCharacteristicAddedCallback(
      BT_STATUS_SUCCESS, kDefaultServerId, hal_char_uuid0,
      srvc_handle, char_handle0);
  EXPECT_EQ(0, cb_count);
  fake_hal_gatt_iface_->NotifyCharacteristicAddedCallback(
      BT_STATUS_SUCCESS, kDefaultServerId, hal_char_uuid1,
      srvc_handle, char_handle1);
  EXPECT_EQ(0, cb_count);

  // Notify failure for first descriptor.
  fake_hal_gatt_iface_->NotifyDescriptorAddedCallback(
      BT_STATUS_FAIL, kDefaultServerId, hal_desc_uuid,
      srvc_handle, desc_handle0);
  EXPECT_EQ(1, cb_count);
  EXPECT_NE(BLE_STATUS_SUCCESS, cb_status);
  EXPECT_TRUE(cb_id == *service_id);

  // Restart (try 3)
  cb_count = 0;
  service_id = gatt_server_->BeginServiceDeclaration(service_uuid, true);
  hal::GetHALServiceId(*service_id, &hal_id);
  char_id0 = gatt_server_->AddCharacteristic(char_uuid0, props, perms);
  char_id1 = gatt_server_->AddCharacteristic(char_uuid1, props, perms);
  desc_id = gatt_server_->AddDescriptor(desc_uuid, perms);
  ASSERT_NE(nullptr, desc_id);
  desc_id1 = gatt_server_->AddDescriptor(desc_uuid, perms);
  ASSERT_NE(nullptr, desc_id1);
  EXPECT_TRUE(gatt_server_->EndServiceDeclaration(callback));

  fake_hal_gatt_iface_->NotifyServiceAddedCallback(
      BT_STATUS_SUCCESS, kDefaultServerId, hal_id, srvc_handle);
  EXPECT_EQ(0, cb_count);
  fake_hal_gatt_iface_->NotifyCharacteristicAddedCallback(
      BT_STATUS_SUCCESS, kDefaultServerId, hal_char_uuid0,
      srvc_handle, char_handle0);
  EXPECT_EQ(0, cb_count);
  fake_hal_gatt_iface_->NotifyCharacteristicAddedCallback(
      BT_STATUS_SUCCESS, kDefaultServerId, hal_char_uuid1,
      srvc_handle, char_handle1);
  EXPECT_EQ(0, cb_count);

  // Notify success for first descriptor; the second descriptor will fail
  // immediately.
  fake_hal_gatt_iface_->NotifyDescriptorAddedCallback(
      BT_STATUS_SUCCESS, kDefaultServerId, hal_desc_uuid,
      srvc_handle, desc_handle0);
  EXPECT_EQ(1, cb_count);
  EXPECT_NE(BLE_STATUS_SUCCESS, cb_status);
  EXPECT_TRUE(cb_id == *service_id);

  // Restart (try 4)
  cb_count = 0;
  service_id = gatt_server_->BeginServiceDeclaration(service_uuid, true);
  hal::GetHALServiceId(*service_id, &hal_id);
  char_id0 = gatt_server_->AddCharacteristic(char_uuid0, props, perms);
  char_id1 = gatt_server_->AddCharacteristic(char_uuid1, props, perms);
  desc_id = gatt_server_->AddDescriptor(desc_uuid, perms);
  ASSERT_NE(nullptr, desc_id);
  desc_id1 = gatt_server_->AddDescriptor(desc_uuid, perms);
  ASSERT_NE(nullptr, desc_id1);
  EXPECT_TRUE(gatt_server_->EndServiceDeclaration(callback));

  fake_hal_gatt_iface_->NotifyServiceAddedCallback(
      BT_STATUS_SUCCESS, kDefaultServerId, hal_id, srvc_handle);
  EXPECT_EQ(0, cb_count);
  fake_hal_gatt_iface_->NotifyCharacteristicAddedCallback(
      BT_STATUS_SUCCESS, kDefaultServerId, hal_char_uuid0,
      srvc_handle, char_handle0);
  EXPECT_EQ(0, cb_count);
  fake_hal_gatt_iface_->NotifyCharacteristicAddedCallback(
      BT_STATUS_SUCCESS, kDefaultServerId, hal_char_uuid1,
      srvc_handle, char_handle1);
  EXPECT_EQ(0, cb_count);

  // Notify success for first first descriptor and failure for second
  // descriptor.
  fake_hal_gatt_iface_->NotifyDescriptorAddedCallback(
      BT_STATUS_SUCCESS, kDefaultServerId, hal_desc_uuid,
      srvc_handle, desc_handle0);
  EXPECT_EQ(0, cb_count);

  fake_hal_gatt_iface_->NotifyDescriptorAddedCallback(
      BT_STATUS_FAIL, kDefaultServerId, hal_desc_uuid,
      srvc_handle, desc_handle1);
  EXPECT_EQ(1, cb_count);
  EXPECT_NE(BLE_STATUS_SUCCESS, cb_status);
  EXPECT_TRUE(cb_id == *service_id);

  // Restart (try 5)
  cb_count = 0;
  service_id = gatt_server_->BeginServiceDeclaration(service_uuid, true);
  hal::GetHALServiceId(*service_id, &hal_id);
  char_id0 = gatt_server_->AddCharacteristic(char_uuid0, props, perms);
  char_id1 = gatt_server_->AddCharacteristic(char_uuid1, props, perms);
  desc_id = gatt_server_->AddDescriptor(desc_uuid, perms);
  ASSERT_NE(nullptr, desc_id);
  desc_id1 = gatt_server_->AddDescriptor(desc_uuid, perms);
  ASSERT_NE(nullptr, desc_id1);
  EXPECT_TRUE(gatt_server_->EndServiceDeclaration(callback));

  fake_hal_gatt_iface_->NotifyServiceAddedCallback(
      BT_STATUS_SUCCESS, kDefaultServerId, hal_id, srvc_handle);
  EXPECT_EQ(0, cb_count);
  fake_hal_gatt_iface_->NotifyCharacteristicAddedCallback(
      BT_STATUS_SUCCESS, kDefaultServerId, hal_char_uuid0,
      srvc_handle, char_handle0);
  EXPECT_EQ(0, cb_count);
  fake_hal_gatt_iface_->NotifyCharacteristicAddedCallback(
      BT_STATUS_SUCCESS, kDefaultServerId, hal_char_uuid1,
      srvc_handle, char_handle1);
  EXPECT_EQ(0, cb_count);

  // Notify success for both descriptors.
  fake_hal_gatt_iface_->NotifyDescriptorAddedCallback(
      BT_STATUS_SUCCESS, kDefaultServerId, hal_desc_uuid,
      srvc_handle, desc_handle0);
  EXPECT_EQ(0, cb_count);

  // The second descriptor callback should trigger the end routine.
  EXPECT_CALL(*mock_handler_, StartService(kDefaultServerId, srvc_handle, _))
      .Times(1)
      .WillOnce(Return(BT_STATUS_SUCCESS));
  fake_hal_gatt_iface_->NotifyDescriptorAddedCallback(
      BT_STATUS_SUCCESS, kDefaultServerId, hal_desc_uuid,
      srvc_handle, desc_handle1);
  EXPECT_EQ(0, cb_count);
}

}  // namespace
}  // namespace bluetooth
