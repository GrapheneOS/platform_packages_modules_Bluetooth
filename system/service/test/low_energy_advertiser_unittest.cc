//
//  Copyright (C) 2016 Google, Inc.
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

#include <base/macros.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "service/adapter.h"
#include "service/hal/fake_bluetooth_gatt_interface.h"
#include "service/low_energy_advertiser.h"
#include "stack/include/bt_types.h"
#include "stack/include/hcidefs.h"
#include "test/mock_adapter.h"

using ::testing::_;
using ::testing::Return;
using ::testing::Pointee;
using ::testing::DoAll;
using ::testing::Invoke;

namespace bluetooth {
namespace {

class MockAdvertiserHandler
    : public hal::FakeBluetoothGattInterface::TestAdvertiserHandler {
 public:
  MockAdvertiserHandler() {
  }
  ~MockAdvertiserHandler() override = default;

  MOCK_METHOD1(RegisterAdvertiser, bt_status_t(bt_uuid_t*));
  MOCK_METHOD1(UnregisterAdvertiser, bt_status_t(int));
  MOCK_METHOD7(MultiAdvEnable, bt_status_t(int, int, int, int, int, int, int));
  MOCK_METHOD7(
      MultiAdvSetInstDataMock,
      bt_status_t(bool, bool, bool, int, vector<uint8_t>, vector<uint8_t>,
                  vector<uint8_t>));
  MOCK_METHOD1(MultiAdvDisable, bt_status_t(int));

  // GMock has macros for up to 10 arguments (11 is really just too many...).
  // For now we forward this call to a 10 argument mock, omitting the
  // |client_if| argument.
  bt_status_t MultiAdvSetInstData(
      int /* client_if */,
      bool set_scan_rsp, bool include_name,
      bool incl_txpower, int appearance,
      vector<uint8_t> manufacturer_data,
      vector<uint8_t> service_data,
      vector<uint8_t> service_uuid) override {
    return MultiAdvSetInstDataMock(
        set_scan_rsp, include_name, incl_txpower, appearance,
        manufacturer_data, service_data, service_uuid);
  }

 private:
  DISALLOW_COPY_AND_ASSIGN(MockAdvertiserHandler);
};

// Created this class for testing Advertising Data Setting
// It provides a work around in order to verify the arguments
// in the arrays passed to MultiAdvSetInstData due to mocks
// not having an easy way to verify entire arrays
class AdvertiseDataHandler : public MockAdvertiserHandler {
 public:
  AdvertiseDataHandler() : call_count_(0) {}
  ~AdvertiseDataHandler() override = default;

  bt_status_t MultiAdvSetInstData(
      int /* client_if */,
      bool set_scan_rsp, bool include_name,
      bool incl_txpower, int appearance,
      vector<uint8_t> manufacturer_data,
      vector<uint8_t> service_data,
      vector<uint8_t> service_uuid) override {
    call_count_++;
    service_data_ = std::move(service_data);
    manufacturer_data_ = std::move(manufacturer_data);
    uuid_data_ = std::move(service_uuid);
    return BT_STATUS_SUCCESS;
  }

  const std::vector<uint8_t>& manufacturer_data() const {
    return manufacturer_data_;
  }
  const std::vector<uint8_t>& service_data() const { return service_data_; }
  const std::vector<uint8_t>& uuid_data() const { return uuid_data_; }
  int call_count() const { return call_count_; }

 private:
  int call_count_;
  std::vector<uint8_t> manufacturer_data_;
  std::vector<uint8_t> service_data_;
  std::vector<uint8_t> uuid_data_;
};

class LowEnergyAdvertiserTest : public ::testing::Test {
 public:
  LowEnergyAdvertiserTest() = default;
  ~LowEnergyAdvertiserTest() override = default;

  void SetUp() override {
    // Only set |mock_handler_| if a test hasn't set it.
    if (!mock_handler_)
        mock_handler_.reset(new MockAdvertiserHandler());
    fake_hal_gatt_iface_ = new hal::FakeBluetoothGattInterface(
        std::static_pointer_cast<
            hal::FakeBluetoothGattInterface::TestAdvertiserHandler>(mock_handler_),
        nullptr,
        nullptr);
    hal::BluetoothGattInterface::InitializeForTesting(fake_hal_gatt_iface_);
    ble_factory_.reset(new LowEnergyAdvertiserFactory());
  }

  void TearDown() override {
    ble_factory_.reset();
    hal::BluetoothGattInterface::CleanUp();
  }

 protected:
  hal::FakeBluetoothGattInterface* fake_hal_gatt_iface_;
  std::shared_ptr<MockAdvertiserHandler> mock_handler_;
  std::unique_ptr<LowEnergyAdvertiserFactory> ble_factory_;

 private:
  DISALLOW_COPY_AND_ASSIGN(LowEnergyAdvertiserTest);
};

// Used for tests that operate on a pre-registered advertiser.
class LowEnergyAdvertiserPostRegisterTest : public LowEnergyAdvertiserTest {
 public:
  LowEnergyAdvertiserPostRegisterTest() : next_client_id_(0) {
  }
  ~LowEnergyAdvertiserPostRegisterTest() override = default;

  void SetUp() override {
    LowEnergyAdvertiserTest::SetUp();
    auto callback = [&](std::unique_ptr<LowEnergyAdvertiser> advertiser) {
      le_advertiser_ = std::move(advertiser);
    };
    RegisterTestAdvertiser(callback);
  }

  void TearDown() override {
    EXPECT_CALL(*mock_handler_, MultiAdvDisable(_))
        .Times(1)
        .WillOnce(Return(BT_STATUS_SUCCESS));
    EXPECT_CALL(*mock_handler_, UnregisterAdvertiser(_))
        .Times(1)
        .WillOnce(Return(BT_STATUS_SUCCESS));
    le_advertiser_.reset();
    LowEnergyAdvertiserTest::TearDown();
  }

  void RegisterTestAdvertiser(
      const std::function<void(std::unique_ptr<LowEnergyAdvertiser> advertiser)>
          callback) {
    UUID uuid = UUID::GetRandom();
    auto api_callback = [&](BLEStatus status, const UUID& in_uuid,
                        std::unique_ptr<BluetoothInstance> in_client) {
      CHECK(in_uuid == uuid);
      CHECK(in_client.get());
      CHECK(status == BLE_STATUS_SUCCESS);

      callback(std::unique_ptr<LowEnergyAdvertiser>(
          static_cast<LowEnergyAdvertiser*>(in_client.release())));
    };

    EXPECT_CALL(*mock_handler_, RegisterAdvertiser(_))
        .Times(1)
        .WillOnce(Return(BT_STATUS_SUCCESS));

    ble_factory_->RegisterInstance(uuid, api_callback);

    bt_uuid_t hal_uuid = uuid.GetBlueDroid();
    fake_hal_gatt_iface_->NotifyRegisterAdvertiserCallback(
        0, next_client_id_++, hal_uuid);
    ::testing::Mock::VerifyAndClearExpectations(mock_handler_.get());
  }

  void StartAdvertising() {
    ASSERT_FALSE(le_advertiser_->IsAdvertisingStarted());
    ASSERT_FALSE(le_advertiser_->IsStartingAdvertising());
    ASSERT_FALSE(le_advertiser_->IsStoppingAdvertising());

    EXPECT_CALL(*mock_handler_, MultiAdvEnable(_, _, _, _, _, _, _))
        .Times(1)
        .WillOnce(Return(BT_STATUS_SUCCESS));
    EXPECT_CALL(*mock_handler_,
                MultiAdvSetInstDataMock(_, _, _, _, _, _, _))
        .Times(1)
        .WillOnce(Return(BT_STATUS_SUCCESS));

    AdvertiseSettings settings;
    AdvertiseData adv, scan_rsp;
    ASSERT_TRUE(le_advertiser_->StartAdvertising(
        settings, adv, scan_rsp, LowEnergyAdvertiser::StatusCallback()));
    ASSERT_TRUE(le_advertiser_->IsStartingAdvertising());

    fake_hal_gatt_iface_->NotifyMultiAdvEnableCallback(
        le_advertiser_->GetInstanceId(), BT_STATUS_SUCCESS);
    fake_hal_gatt_iface_->NotifyMultiAdvDataCallback(
        le_advertiser_->GetInstanceId(), BT_STATUS_SUCCESS);

    ASSERT_TRUE(le_advertiser_->IsAdvertisingStarted());
    ASSERT_FALSE(le_advertiser_->IsStartingAdvertising());
    ASSERT_FALSE(le_advertiser_->IsStoppingAdvertising());
  }

  void AdvertiseDataTestHelper(AdvertiseData data, std::function<void(BLEStatus)> callback) {
    AdvertiseSettings settings;
    EXPECT_TRUE(le_advertiser_->StartAdvertising(
        settings, data, AdvertiseData(), callback));
    fake_hal_gatt_iface_->NotifyMultiAdvEnableCallback(
        le_advertiser_->GetInstanceId(), BT_STATUS_SUCCESS);
    fake_hal_gatt_iface_->NotifyMultiAdvDataCallback(
        le_advertiser_->GetInstanceId(), BT_STATUS_SUCCESS);
    EXPECT_TRUE(le_advertiser_->StopAdvertising(LowEnergyAdvertiser::StatusCallback()));
    fake_hal_gatt_iface_->NotifyMultiAdvDisableCallback(
        le_advertiser_->GetInstanceId(), BT_STATUS_SUCCESS);
  }

 protected:
  std::unique_ptr<LowEnergyAdvertiser> le_advertiser_;

 private:
  int next_client_id_;

  DISALLOW_COPY_AND_ASSIGN(LowEnergyAdvertiserPostRegisterTest);
};

TEST_F(LowEnergyAdvertiserTest, RegisterInstance) {
  EXPECT_CALL(*mock_handler_, RegisterAdvertiser(_))
      .Times(2)
      .WillOnce(Return(BT_STATUS_FAIL))
      .WillOnce(Return(BT_STATUS_SUCCESS));

  // These will be asynchronously populated with a result when the callback
  // executes.
  BLEStatus status = BLE_STATUS_SUCCESS;
  UUID cb_uuid;
  std::unique_ptr<LowEnergyAdvertiser> advertiser;
  int callback_count = 0;

  auto callback = [&](BLEStatus in_status, const UUID& uuid,
                      std::unique_ptr<BluetoothInstance> in_client) {
        status = in_status;
        cb_uuid = uuid;
        advertiser = std::unique_ptr<LowEnergyAdvertiser>(
            static_cast<LowEnergyAdvertiser*>(in_client.release()));
        callback_count++;
      };

  UUID uuid0 = UUID::GetRandom();

  // HAL returns failure.
  EXPECT_FALSE(ble_factory_->RegisterInstance(uuid0, callback));
  EXPECT_EQ(0, callback_count);

  // HAL returns success.
  EXPECT_TRUE(ble_factory_->RegisterInstance(uuid0, callback));
  EXPECT_EQ(0, callback_count);

  // Calling twice with the same UUID should fail with no additional call into
  // the stack.
  EXPECT_FALSE(ble_factory_->RegisterInstance(uuid0, callback));

  ::testing::Mock::VerifyAndClearExpectations(mock_handler_.get());

  // Call with a different UUID while one is pending.
  UUID uuid1 = UUID::GetRandom();
  EXPECT_CALL(*mock_handler_, RegisterAdvertiser(_))
      .Times(1)
      .WillOnce(Return(BT_STATUS_SUCCESS));
  EXPECT_TRUE(ble_factory_->RegisterInstance(uuid1, callback));

  // Trigger callback with an unknown UUID. This should get ignored.
  UUID uuid2 = UUID::GetRandom();
  bt_uuid_t hal_uuid = uuid2.GetBlueDroid();
  fake_hal_gatt_iface_->NotifyRegisterAdvertiserCallback(0, 0, hal_uuid);
  EXPECT_EQ(0, callback_count);

  // |uuid0| succeeds.
  int client_if0 = 2;  // Pick something that's not 0.
  hal_uuid = uuid0.GetBlueDroid();
  fake_hal_gatt_iface_->NotifyRegisterAdvertiserCallback(
      BT_STATUS_SUCCESS, client_if0, hal_uuid);

  EXPECT_EQ(1, callback_count);
  ASSERT_TRUE(advertiser.get() != nullptr);  // Assert to terminate in case of error
  EXPECT_EQ(BLE_STATUS_SUCCESS, status);
  EXPECT_EQ(client_if0, advertiser->GetInstanceId());
  EXPECT_EQ(uuid0, advertiser->GetAppIdentifier());
  EXPECT_EQ(uuid0, cb_uuid);

  // The advertiser should unregister itself when deleted.
  EXPECT_CALL(*mock_handler_, MultiAdvDisable(client_if0))
      .Times(1)
      .WillOnce(Return(BT_STATUS_SUCCESS));
  EXPECT_CALL(*mock_handler_, UnregisterAdvertiser(client_if0))
      .Times(1)
      .WillOnce(Return(BT_STATUS_SUCCESS));
  advertiser.reset();
  ::testing::Mock::VerifyAndClearExpectations(mock_handler_.get());

  // |uuid1| fails.
  int client_if1 = 3;
  hal_uuid = uuid1.GetBlueDroid();
  fake_hal_gatt_iface_->NotifyRegisterAdvertiserCallback(
      BT_STATUS_FAIL, client_if1, hal_uuid);

  EXPECT_EQ(2, callback_count);
  ASSERT_TRUE(advertiser.get() == nullptr);  // Assert to terminate in case of error
  EXPECT_EQ(BLE_STATUS_FAILURE, status);
  EXPECT_EQ(uuid1, cb_uuid);
}

TEST_F(LowEnergyAdvertiserPostRegisterTest, StartAdvertisingBasic) {
  EXPECT_FALSE(le_advertiser_->IsAdvertisingStarted());
  EXPECT_FALSE(le_advertiser_->IsStartingAdvertising());
  EXPECT_FALSE(le_advertiser_->IsStoppingAdvertising());

  // Use default advertising settings and data.
  AdvertiseSettings settings;
  AdvertiseData adv_data, scan_rsp;
  int callback_count = 0;
  BLEStatus last_status = BLE_STATUS_FAILURE;
  auto callback = [&](BLEStatus status) {
    last_status = status;
    callback_count++;
  };

  EXPECT_CALL(*mock_handler_, MultiAdvEnable(_, _, _, _, _, _, _))
      .Times(5)
      .WillOnce(Return(BT_STATUS_FAIL))
      .WillRepeatedly(Return(BT_STATUS_SUCCESS));

  // Stack call returns failure.
  EXPECT_FALSE(le_advertiser_->StartAdvertising(
      settings, adv_data, scan_rsp, callback));
  EXPECT_FALSE(le_advertiser_->IsAdvertisingStarted());
  EXPECT_FALSE(le_advertiser_->IsStartingAdvertising());
  EXPECT_FALSE(le_advertiser_->IsStoppingAdvertising());
  EXPECT_EQ(0, callback_count);

  // Stack call returns success.
  EXPECT_TRUE(le_advertiser_->StartAdvertising(
      settings, adv_data, scan_rsp, callback));
  EXPECT_FALSE(le_advertiser_->IsAdvertisingStarted());
  EXPECT_TRUE(le_advertiser_->IsStartingAdvertising());
  EXPECT_FALSE(le_advertiser_->IsStoppingAdvertising());
  EXPECT_EQ(0, callback_count);

  // Already starting.
  EXPECT_FALSE(le_advertiser_->StartAdvertising(
      settings, adv_data, scan_rsp, callback));

  // Notify failure.
  fake_hal_gatt_iface_->NotifyMultiAdvEnableCallback(
      le_advertiser_->GetInstanceId(), BT_STATUS_FAIL);
  EXPECT_FALSE(le_advertiser_->IsAdvertisingStarted());
  EXPECT_FALSE(le_advertiser_->IsStartingAdvertising());
  EXPECT_FALSE(le_advertiser_->IsStoppingAdvertising());
  EXPECT_EQ(1, callback_count);
  EXPECT_EQ(BLE_STATUS_FAILURE, last_status);

  // Try again.
  EXPECT_TRUE(le_advertiser_->StartAdvertising(
      settings, adv_data, scan_rsp, callback));
  EXPECT_FALSE(le_advertiser_->IsAdvertisingStarted());
  EXPECT_TRUE(le_advertiser_->IsStartingAdvertising());
  EXPECT_FALSE(le_advertiser_->IsStoppingAdvertising());
  EXPECT_EQ(1, callback_count);

  // Success notification should trigger advertise data update.
  EXPECT_CALL(*mock_handler_,
              MultiAdvSetInstDataMock(
                  false,  // set_scan_rsp
                  false,  // include_name
                  false,  // incl_txpower
                  _, _, _, _))
      .Times(3)
      .WillOnce(Return(BT_STATUS_FAIL))
      .WillRepeatedly(Return(BT_STATUS_SUCCESS));

  // Notify success for enable. The procedure will fail since setting data will
  // fail.
  fake_hal_gatt_iface_->NotifyMultiAdvEnableCallback(
      le_advertiser_->GetInstanceId(), BT_STATUS_SUCCESS);
  EXPECT_FALSE(le_advertiser_->IsAdvertisingStarted());
  EXPECT_FALSE(le_advertiser_->IsStartingAdvertising());
  EXPECT_FALSE(le_advertiser_->IsStoppingAdvertising());
  EXPECT_EQ(2, callback_count);
  EXPECT_EQ(BLE_STATUS_FAILURE, last_status);

  // Try again.
  EXPECT_TRUE(le_advertiser_->StartAdvertising(
      settings, adv_data, scan_rsp, callback));
  EXPECT_FALSE(le_advertiser_->IsAdvertisingStarted());
  EXPECT_TRUE(le_advertiser_->IsStartingAdvertising());
  EXPECT_FALSE(le_advertiser_->IsStoppingAdvertising());
  EXPECT_EQ(2, callback_count);

  // Notify success for enable. the advertise data call should succeed but
  // operation will remain pending.
  fake_hal_gatt_iface_->NotifyMultiAdvEnableCallback(
      le_advertiser_->GetInstanceId(), BT_STATUS_SUCCESS);
  EXPECT_FALSE(le_advertiser_->IsAdvertisingStarted());
  EXPECT_TRUE(le_advertiser_->IsStartingAdvertising());
  EXPECT_FALSE(le_advertiser_->IsStoppingAdvertising());
  EXPECT_EQ(2, callback_count);

  // Notify failure from advertising call.
  fake_hal_gatt_iface_->NotifyMultiAdvDataCallback(
      le_advertiser_->GetInstanceId(), BT_STATUS_FAIL);
  EXPECT_FALSE(le_advertiser_->IsAdvertisingStarted());
  EXPECT_FALSE(le_advertiser_->IsStartingAdvertising());
  EXPECT_FALSE(le_advertiser_->IsStoppingAdvertising());
  EXPECT_EQ(3, callback_count);
  EXPECT_EQ(BLE_STATUS_FAILURE, last_status);

  // Try again. Make everything succeed.
  EXPECT_TRUE(le_advertiser_->StartAdvertising(
      settings, adv_data, scan_rsp, callback));
  EXPECT_FALSE(le_advertiser_->IsAdvertisingStarted());
  EXPECT_TRUE(le_advertiser_->IsStartingAdvertising());
  EXPECT_FALSE(le_advertiser_->IsStoppingAdvertising());
  EXPECT_EQ(3, callback_count);

  fake_hal_gatt_iface_->NotifyMultiAdvEnableCallback(
      le_advertiser_->GetInstanceId(), BT_STATUS_SUCCESS);
  fake_hal_gatt_iface_->NotifyMultiAdvDataCallback(
      le_advertiser_->GetInstanceId(), BT_STATUS_SUCCESS);
  EXPECT_TRUE(le_advertiser_->IsAdvertisingStarted());
  EXPECT_FALSE(le_advertiser_->IsStartingAdvertising());
  EXPECT_FALSE(le_advertiser_->IsStoppingAdvertising());
  EXPECT_EQ(4, callback_count);
  EXPECT_EQ(BLE_STATUS_SUCCESS, last_status);

  // Already started.
  EXPECT_FALSE(le_advertiser_->StartAdvertising(
      settings, adv_data, scan_rsp, callback));
}

TEST_F(LowEnergyAdvertiserPostRegisterTest, StopAdvertisingBasic) {
  AdvertiseSettings settings;

  // Not enabled.
  EXPECT_FALSE(le_advertiser_->IsAdvertisingStarted());
  EXPECT_FALSE(le_advertiser_->StopAdvertising(LowEnergyAdvertiser::StatusCallback()));

  // Start advertising for testing.
  StartAdvertising();

  int callback_count = 0;
  BLEStatus last_status = BLE_STATUS_FAILURE;
  auto callback = [&](BLEStatus status) {
    last_status = status;
    callback_count++;
  };

  EXPECT_CALL(*mock_handler_, MultiAdvDisable(_))
      .Times(3)
      .WillOnce(Return(BT_STATUS_FAIL))
      .WillRepeatedly(Return(BT_STATUS_SUCCESS));

  // Stack call returns failure.
  EXPECT_FALSE(le_advertiser_->StopAdvertising(callback));
  EXPECT_TRUE(le_advertiser_->IsAdvertisingStarted());
  EXPECT_FALSE(le_advertiser_->IsStartingAdvertising());
  EXPECT_FALSE(le_advertiser_->IsStoppingAdvertising());
  EXPECT_EQ(0, callback_count);

  // Stack returns success.
  EXPECT_TRUE(le_advertiser_->StopAdvertising(callback));
  EXPECT_TRUE(le_advertiser_->IsAdvertisingStarted());
  EXPECT_FALSE(le_advertiser_->IsStartingAdvertising());
  EXPECT_TRUE(le_advertiser_->IsStoppingAdvertising());
  EXPECT_EQ(0, callback_count);

  // Already disabling.
  EXPECT_FALSE(le_advertiser_->StopAdvertising(callback));
  EXPECT_TRUE(le_advertiser_->IsAdvertisingStarted());
  EXPECT_FALSE(le_advertiser_->IsStartingAdvertising());
  EXPECT_TRUE(le_advertiser_->IsStoppingAdvertising());
  EXPECT_EQ(0, callback_count);

  // Notify failure.
  fake_hal_gatt_iface_->NotifyMultiAdvDisableCallback(
      le_advertiser_->GetInstanceId(), BT_STATUS_FAIL);
  EXPECT_TRUE(le_advertiser_->IsAdvertisingStarted());
  EXPECT_FALSE(le_advertiser_->IsStartingAdvertising());
  EXPECT_FALSE(le_advertiser_->IsStoppingAdvertising());
  EXPECT_EQ(1, callback_count);
  EXPECT_EQ(BLE_STATUS_FAILURE, last_status);

  // Try again.
  EXPECT_TRUE(le_advertiser_->StopAdvertising(callback));
  EXPECT_TRUE(le_advertiser_->IsAdvertisingStarted());
  EXPECT_FALSE(le_advertiser_->IsStartingAdvertising());
  EXPECT_TRUE(le_advertiser_->IsStoppingAdvertising());
  EXPECT_EQ(1, callback_count);

  // Notify success.
  fake_hal_gatt_iface_->NotifyMultiAdvDisableCallback(
      le_advertiser_->GetInstanceId(), BT_STATUS_SUCCESS);
  EXPECT_FALSE(le_advertiser_->IsAdvertisingStarted());
  EXPECT_FALSE(le_advertiser_->IsStartingAdvertising());
  EXPECT_FALSE(le_advertiser_->IsStoppingAdvertising());
  EXPECT_EQ(2, callback_count);
  EXPECT_EQ(BLE_STATUS_SUCCESS, last_status);

  // Already stopped.
  EXPECT_FALSE(le_advertiser_->StopAdvertising(callback));
}

TEST_F(LowEnergyAdvertiserPostRegisterTest, InvalidAdvertiseData) {
  const std::vector<uint8_t> data0{ 0x02, HCI_EIR_FLAGS_TYPE, 0x00 };
  const std::vector<uint8_t> data1{
      0x04, HCI_EIR_MANUFACTURER_SPECIFIC_TYPE, 0x01, 0x02, 0x00
  };
  AdvertiseData invalid_adv(data0);
  AdvertiseData valid_adv(data1);

  AdvertiseSettings settings;

  EXPECT_FALSE(le_advertiser_->StartAdvertising(
      settings, valid_adv, invalid_adv, LowEnergyAdvertiser::StatusCallback()));
  EXPECT_FALSE(le_advertiser_->StartAdvertising(
      settings, invalid_adv, valid_adv, LowEnergyAdvertiser::StatusCallback()));

  // Manufacturer data not correctly formatted according to spec. We let the
  // stack handle this case.
  const std::vector<uint8_t> data2{ 0x01, HCI_EIR_MANUFACTURER_SPECIFIC_TYPE };
  AdvertiseData invalid_mfc(data2);

  EXPECT_CALL(*mock_handler_, MultiAdvEnable(_, _, _, _, _, _, _))
      .Times(1)
      .WillOnce(Return(BT_STATUS_SUCCESS));
  EXPECT_TRUE(le_advertiser_->StartAdvertising(
      settings, invalid_mfc, valid_adv, LowEnergyAdvertiser::StatusCallback()));
}

TEST_F(LowEnergyAdvertiserPostRegisterTest, ScanResponse) {
  EXPECT_FALSE(le_advertiser_->IsAdvertisingStarted());
  EXPECT_FALSE(le_advertiser_->IsStartingAdvertising());
  EXPECT_FALSE(le_advertiser_->IsStoppingAdvertising());

  AdvertiseSettings settings(
      AdvertiseSettings::MODE_LOW_POWER,
      base::TimeDelta::FromMilliseconds(300),
      AdvertiseSettings::TX_POWER_LEVEL_MEDIUM,
      false /* connectable */);

  const std::vector<uint8_t> data0;
  const std::vector<uint8_t> data1{
      0x04, HCI_EIR_MANUFACTURER_SPECIFIC_TYPE, 0x01, 0x02, 0x00
  };

  int callback_count = 0;
  BLEStatus last_status = BLE_STATUS_FAILURE;
  auto callback = [&](BLEStatus status) {
    last_status = status;
    callback_count++;
  };

  AdvertiseData adv0(data0);
  adv0.set_include_tx_power_level(true);

  AdvertiseData adv1(data1);
  adv1.set_include_device_name(true);

  EXPECT_CALL(*mock_handler_,
              MultiAdvEnable(le_advertiser_->GetInstanceId(), _, _,
                             kAdvertisingEventTypeScannable,
                             _, _, _))
      .Times(2)
      .WillRepeatedly(Return(BT_STATUS_SUCCESS));
  EXPECT_CALL(
      *mock_handler_,
      MultiAdvSetInstDataMock(
          false,  // set_scan_rsp
          false,  // include_name
          true,  // incl_txpower,
          _,
          // 0,  // 0 bytes
          _,
          _, _))
      .Times(2)
      .WillRepeatedly(Return(BT_STATUS_SUCCESS));
  EXPECT_CALL(
      *mock_handler_,
      MultiAdvSetInstDataMock(
          true,  // set_scan_rsp
          true,  // include_name
          false,  // incl_txpower,
          _,
          // data1.size() - 2,  // Mfc. Specific data field bytes.
          _,
          _, _))
      .Times(2)
      .WillRepeatedly(Return(BT_STATUS_SUCCESS));

  // Enable success; Adv. data success; Scan rsp. fail.
  EXPECT_TRUE(le_advertiser_->StartAdvertising(settings, adv0, adv1, callback));
  fake_hal_gatt_iface_->NotifyMultiAdvEnableCallback(
      le_advertiser_->GetInstanceId(), BT_STATUS_SUCCESS);
  fake_hal_gatt_iface_->NotifyMultiAdvDataCallback(
      le_advertiser_->GetInstanceId(), BT_STATUS_SUCCESS);
  fake_hal_gatt_iface_->NotifyMultiAdvDataCallback(
      le_advertiser_->GetInstanceId(), BT_STATUS_FAIL);

  EXPECT_EQ(1, callback_count);
  EXPECT_EQ(BLE_STATUS_FAILURE, last_status);
  EXPECT_FALSE(le_advertiser_->IsAdvertisingStarted());

  // Second time everything succeeds.
  EXPECT_TRUE(le_advertiser_->StartAdvertising(settings, adv0, adv1, callback));
  fake_hal_gatt_iface_->NotifyMultiAdvEnableCallback(
      le_advertiser_->GetInstanceId(), BT_STATUS_SUCCESS);
  fake_hal_gatt_iface_->NotifyMultiAdvDataCallback(
      le_advertiser_->GetInstanceId(), BT_STATUS_SUCCESS);
  fake_hal_gatt_iface_->NotifyMultiAdvDataCallback(
      le_advertiser_->GetInstanceId(), BT_STATUS_SUCCESS);

  EXPECT_EQ(2, callback_count);
  EXPECT_EQ(BLE_STATUS_SUCCESS, last_status);
  EXPECT_TRUE(le_advertiser_->IsAdvertisingStarted());
}

TEST_F(LowEnergyAdvertiserPostRegisterTest, AdvertiseDataParsing) {
  // Re-initialize the test with our own custom handler.
  TearDown();
  std::shared_ptr<AdvertiseDataHandler> adv_handler(new AdvertiseDataHandler());
  mock_handler_ = std::static_pointer_cast<MockAdvertiserHandler>(adv_handler);
  SetUp();

  const std::vector<uint8_t> kUUID16BitData{
    0x03, HCI_EIR_COMPLETE_16BITS_UUID_TYPE, 0xDE, 0xAD,
  };

  const std::vector<uint8_t> kUUID32BitData{
    0x05, HCI_EIR_COMPLETE_32BITS_UUID_TYPE, 0xDE, 0xAD, 0x01, 0x02
  };

  const std::vector<uint8_t> kUUID128BitData{
    0x11, HCI_EIR_COMPLETE_128BITS_UUID_TYPE,
    0xDE, 0xAD, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
    0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E
  };

  const std::vector<uint8_t> kMultiUUIDData{
    0x11, HCI_EIR_COMPLETE_128BITS_UUID_TYPE,
    0xDE, 0xAD, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
    0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
    0x05, HCI_EIR_COMPLETE_32BITS_UUID_TYPE, 0xDE, 0xAD, 0xBE, 0xEF
  };

  const std::vector<uint8_t> kServiceData16Bit{
    0x05, HCI_EIR_SERVICE_DATA_16BITS_UUID_TYPE, 0xDE, 0xAD, 0xBE, 0xEF
  };

  const std::vector<uint8_t> kServiceData32Bit{
    0x07, HCI_EIR_SERVICE_DATA_32BITS_UUID_TYPE, 0xDE, 0xAD, 0x01, 0x02, 0xBE, 0xEF
  };

  const std::vector<uint8_t> kServiceData128Bit{
    0x13, HCI_EIR_SERVICE_DATA_128BITS_UUID_TYPE,
    0xDE, 0xAD, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
    0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0xBE, 0xEF
  };

  const std::vector<uint8_t> kMultiServiceData{
    0x13, HCI_EIR_SERVICE_DATA_128BITS_UUID_TYPE,
    0xDE, 0xAD, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0xBE, 0xEF,
    0xDE, 0xAD, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
    0x05, HCI_EIR_SERVICE_DATA_16BITS_UUID_TYPE, 0xDE, 0xAD, 0xBE, 0xEF
  };

  const std::vector<uint8_t> kServiceUUIDMatch{
    0x05, HCI_EIR_COMPLETE_32BITS_UUID_TYPE, 0xDE, 0xAD, 0x01, 0x02,
    0x07, HCI_EIR_SERVICE_DATA_32BITS_UUID_TYPE, 0xDE, 0xAD, 0x01, 0x02, 0xBE, 0xEF
  };

  const std::vector<uint8_t> kServiceUUIDMismatch{
    0x05, HCI_EIR_COMPLETE_32BITS_UUID_TYPE, 0xDE, 0xAD, 0x01, 0x01,
    0x07, HCI_EIR_SERVICE_DATA_32BITS_UUID_TYPE, 0xDE, 0xAD, 0x01, 0x02, 0xBE, 0xEF
  };

  AdvertiseData uuid_16bit_adv(kUUID16BitData);
  AdvertiseData uuid_32bit_adv(kUUID32BitData);
  AdvertiseData uuid_128bit_adv(kUUID128BitData);
  AdvertiseData multi_uuid_adv(kMultiUUIDData);

  AdvertiseData service_16bit_adv(kServiceData16Bit);
  AdvertiseData service_32bit_adv(kServiceData32Bit);
  AdvertiseData service_128bit_adv(kServiceData128Bit);
  AdvertiseData multi_service_adv(kMultiServiceData);

  AdvertiseData service_uuid_match(kServiceUUIDMatch);
  AdvertiseData service_uuid_mismatch(kServiceUUIDMismatch);

  AdvertiseSettings settings;

  int callback_count = 0;
  BLEStatus last_status = BLE_STATUS_FAILURE;
  auto callback = [&](BLEStatus status) {
    last_status = status;
    callback_count++;
  };

  EXPECT_CALL(*mock_handler_, MultiAdvEnable(_, _, _, _, _, _, _))
      .WillRepeatedly(Return(BT_STATUS_SUCCESS));
  EXPECT_CALL(*mock_handler_, MultiAdvDisable(_))
      .WillRepeatedly(Return(BT_STATUS_SUCCESS));

  // Multiple UUID test, should fail due to only one UUID allowed
  EXPECT_TRUE(le_advertiser_->StartAdvertising(
              settings, multi_uuid_adv, AdvertiseData(), callback));
  fake_hal_gatt_iface_->NotifyMultiAdvEnableCallback(
          le_advertiser_->GetInstanceId(), BT_STATUS_SUCCESS);
  EXPECT_EQ(1, callback_count);
  EXPECT_EQ(0, adv_handler->call_count());
  EXPECT_EQ(BLE_STATUS_FAILURE, last_status);

  // Multiple Service Data test, should fail due to only one service data allowed
  EXPECT_TRUE(le_advertiser_->StartAdvertising(
              settings, multi_uuid_adv, AdvertiseData(), callback));
  fake_hal_gatt_iface_->NotifyMultiAdvEnableCallback(
          le_advertiser_->GetInstanceId(), BT_STATUS_SUCCESS);
  EXPECT_EQ(2, callback_count);
  EXPECT_EQ(0, adv_handler->call_count());
  EXPECT_EQ(BLE_STATUS_FAILURE, last_status);

  // 16bit uuid test, should succeed with correctly parsed uuid in little-endian
  // 128-bit format.
  AdvertiseDataTestHelper(uuid_16bit_adv, callback);
  EXPECT_EQ(3, callback_count);
  EXPECT_EQ(1, adv_handler->call_count());
  const std::vector<uint8_t> uuid_16bit_canonical{
    0xFB, 0x34, 0x9b, 0x5F, 0x80, 0x00, 0x00, 0x80, 0x00, 0x10, 0x00, 0x00,
    0xDE, 0xAD, 0x00, 0x00
  };
  EXPECT_EQ(uuid_16bit_canonical, adv_handler->uuid_data());

  // 32bit uuid test, should succeed with correctly parsed uuid
  AdvertiseDataTestHelper(uuid_32bit_adv, callback);
  EXPECT_EQ(4, callback_count);
  EXPECT_EQ(2, adv_handler->call_count());
  const std::vector<uint8_t> uuid_32bit_canonical{
    0xFB, 0x34, 0x9b, 0x5F, 0x80, 0x00, 0x00, 0x80, 0x00, 0x10, 0x00, 0x00,
    0xDE, 0xAD, 0x01, 0x02
  };
  EXPECT_EQ(uuid_32bit_canonical, adv_handler->uuid_data());

  // 128bit uuid test, should succeed with correctly parsed uuid
  AdvertiseDataTestHelper(uuid_128bit_adv, callback);
  EXPECT_EQ(5, callback_count);
  EXPECT_EQ(3, adv_handler->call_count());
  const std::vector<uint8_t> uuid_128bit{
    0xDE, 0xAD, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
    0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E
  };
  EXPECT_EQ(uuid_128bit, adv_handler->uuid_data());

  const std::vector<uint8_t> service_data{ 0xBE, 0xEF };

  // Service data with 16bit uuid included, should succeed with
  // uuid and service data parsed out
  AdvertiseDataTestHelper(service_16bit_adv, callback);
  EXPECT_EQ(6, callback_count);
  EXPECT_EQ(4, adv_handler->call_count());
  EXPECT_EQ(service_data, adv_handler->service_data());
  EXPECT_EQ(uuid_16bit_canonical, adv_handler->uuid_data());

  // Service data with 32bit uuid included, should succeed with
  // uuid and service data parsed out
  AdvertiseDataTestHelper(service_32bit_adv, callback);
  EXPECT_EQ(7, callback_count);
  EXPECT_EQ(5, adv_handler->call_count());
  EXPECT_EQ(service_data, adv_handler->service_data());
  EXPECT_EQ(uuid_32bit_canonical, adv_handler->uuid_data());

  // Service data with 128bit uuid included, should succeed with
  // uuid and service data parsed out
  AdvertiseDataTestHelper(service_128bit_adv, callback);
  EXPECT_EQ(8, callback_count);
  EXPECT_EQ(6, adv_handler->call_count());
  EXPECT_EQ(service_data, adv_handler->service_data());
  EXPECT_EQ(uuid_128bit, adv_handler->uuid_data());

  // Service data and UUID where the UUID for both match, should succeed.
  AdvertiseDataTestHelper(service_uuid_match, callback);
  EXPECT_EQ(9, callback_count);
  EXPECT_EQ(7, adv_handler->call_count());
  EXPECT_EQ(service_data, adv_handler->service_data());
  EXPECT_EQ(uuid_32bit_canonical, adv_handler->uuid_data());

  // Service data and UUID where the UUID for dont match, should fail
  EXPECT_TRUE(le_advertiser_->StartAdvertising(
              settings, service_uuid_mismatch, AdvertiseData(), callback));
  fake_hal_gatt_iface_->NotifyMultiAdvEnableCallback(
      le_advertiser_->GetInstanceId(), BT_STATUS_SUCCESS);
  EXPECT_EQ(10, callback_count);
  EXPECT_EQ(7, adv_handler->call_count());
  EXPECT_EQ(BLE_STATUS_FAILURE, last_status);
}

MATCHER_P(BitEq, x, std::string(negation ? "isn't" : "is") +
                        " bitwise equal to " + ::testing::PrintToString(x)) {
  static_assert(sizeof(x) == sizeof(arg), "Size mismatch");
  return std::memcmp(&arg, &x, sizeof(x)) == 0;
}


}  // namespace
}  // namespace bluetooth
