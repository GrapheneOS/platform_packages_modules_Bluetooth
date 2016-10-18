/******************************************************************************
 *
 *  Copyright (C) 2016 The Android Open Source Project
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at:
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 ******************************************************************************/

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "device/include/controller.h"
#include "stack/btm/ble_advertiser_hci_interface.h"
#include "stack/include/ble_advertiser.h"

using ::testing::_;
using ::testing::Args;
using ::testing::ElementsAreArray;
using ::testing::Exactly;
using ::testing::IsEmpty;
using ::testing::SaveArg;
using status_cb = BleAdvertiserHciInterface::status_cb;

const int num_adv_instances = 16;

/* Below are methods that must be implemented if we don't want to compile the
 * whole stack. They will be removed, or changed into mocks one by one in the
 * future, as the refactoring progresses */
bool BTM_BleLocalPrivacyEnabled() { return true; }
uint16_t BTM_ReadConnectability(uint16_t *p_window, uint16_t *p_interval) {
  return true;
}
uint16_t BTM_ReadDiscoverability(uint16_t *p_window, uint16_t *p_interval) {
  return true;
}
bool SMP_Encrypt(uint8_t *key, uint8_t key_len, uint8_t *plain_text,
                 uint8_t pt_len, tSMP_ENC *p_out) {
  return true;
}
void BTM_GetDeviceIDRoot(BT_OCTET16 irk) {}
tBTM_STATUS btm_ble_set_connectability(uint16_t combined_mode) { return 0; }
void btm_ble_update_dmt_flag_bits(uint8_t *flag_value,
                                  const uint16_t connect_mode,
                                  const uint16_t disc_mode) {}
void btm_acl_update_conn_addr(uint8_t conn_handle, BD_ADDR address) {}

void btm_gen_resolvable_private_addr(void *p_cmd_cplt_cback) {
  // TODO(jpawlowski): should call p_cmd_cplt_cback();
}
void alarm_set_on_queue(alarm_t *alarm, period_ms_t interval_ms,
                        alarm_callback_t cb, void *data, fixed_queue_t *queue) {
}
void alarm_cancel(alarm_t *alarm) {}
alarm_t *alarm_new_periodic(const char *name) { return nullptr; }
alarm_t *alarm_new(const char *name) { return nullptr; }
void alarm_free(alarm_t *alarm) {}
const controller_t *controller_get_interface() { return nullptr; }
fixed_queue_t *btu_general_alarm_queue = nullptr;

namespace {

class AdvertiserHciMock : public BleAdvertiserHciInterface {
 public:
  AdvertiserHciMock() = default;
  ~AdvertiserHciMock() override = default;

  MOCK_METHOD1(ReadInstanceCount, void(base::Callback<void(uint8_t /* inst_cnt*/)>));
  MOCK_METHOD4(SetAdvertisingData,
               void(uint8_t, uint8_t *, uint8_t, status_cb));
  MOCK_METHOD4(SetScanResponseData,
               void(uint8_t, uint8_t *, uint8_t, status_cb));
  MOCK_METHOD3(SetRandomAddress, void(BD_ADDR, uint8_t, status_cb));
  MOCK_METHOD3(Enable, void(uint8_t, uint8_t, status_cb));

  MOCK_METHOD6(SetParameters1,
               void(uint8_t, uint8_t, uint8_t, uint8_t, BD_ADDR, uint8_t));
  MOCK_METHOD6(SetParameters2,
               void(BD_ADDR, uint8_t, uint8_t, uint8_t, uint8_t, status_cb));

  void SetParameters(uint8_t adv_int_min, uint8_t adv_int_max,
                     uint8_t advertising_type, uint8_t own_address_type,
                     BD_ADDR own_address, uint8_t direct_address_type,
                     BD_ADDR direct_address, uint8_t channel_map,
                     uint8_t filter_policy, uint8_t instance, uint8_t tx_power,
                     status_cb cmd_complete) override {
    SetParameters1(adv_int_min, adv_int_max, advertising_type, own_address_type,
                   own_address, direct_address_type);
    SetParameters2(direct_address, channel_map, filter_policy, instance,
                   tx_power, cmd_complete);
  };

 private:
  DISALLOW_COPY_AND_ASSIGN(AdvertiserHciMock);
};

}  // namespace

class BleAdvertisingManagerTest : public testing::Test {
 protected:
  int reg_inst_id = -1;
  int reg_status = -1;
  int set_params_status = -1;
  int set_data_status = -1;
  int enable_status = -1;
  std::unique_ptr<AdvertiserHciMock> hci_mock;

  virtual void SetUp() {
    hci_mock.reset(new AdvertiserHciMock());

    base::Callback<void(uint8_t)> inst_cnt_Cb;
    EXPECT_CALL(*hci_mock, ReadInstanceCount(_))
      .Times(Exactly(1))
      .WillOnce(SaveArg<0>(&inst_cnt_Cb));

    BleAdvertisingManager::Initialize(hci_mock.get());

    // we are a truly gracious fake controller, let the command succeed!
    inst_cnt_Cb.Run(num_adv_instances);
    ::testing::Mock::VerifyAndClearExpectations(hci_mock.get());
  }

  virtual void TearDown() {
    BleAdvertisingManager::CleanUp();
    hci_mock.reset();
  }

 public:
  void RegistrationCb(uint8_t inst_id, uint8_t status) {
    reg_inst_id = inst_id;
    reg_status = status;
  }

  void SetParametersCb(uint8_t status) { set_params_status = status; }
  void SetDataCb(uint8_t status) { set_data_status = status; }
  void EnableCb(uint8_t status) { enable_status = status; }
};

TEST_F(BleAdvertisingManagerTest, test_registration) {
  for (int i = 1; i < num_adv_instances; i++) {
    BleAdvertisingManager::Get()->RegisterAdvertiser(base::Bind(
        &BleAdvertisingManagerTest::RegistrationCb, base::Unretained(this)));
    EXPECT_EQ(BTM_BLE_MULTI_ADV_SUCCESS, reg_status);
    EXPECT_EQ(i, reg_inst_id);
  }

  // This call should return an error - no more advertisers left.
  BleAdvertisingManager::Get()->RegisterAdvertiser(base::Bind(
      &BleAdvertisingManagerTest::RegistrationCb, base::Unretained(this)));
  EXPECT_EQ(BTM_BLE_MULTI_ADV_FAILURE, reg_status);
  // Don't bother checking inst_id, it doesn't matter

  // This will currently trigger a mock message about a call to Enable(). This
  // should be fixed in the future- we shouldn't disable non-enabled scan.
  BleAdvertisingManager::Get()->Unregister(5);

  // One advertiser was freed, so should be able to register one now
  BleAdvertisingManager::Get()->RegisterAdvertiser(base::Bind(
      &BleAdvertisingManagerTest::RegistrationCb, base::Unretained(this)));
  EXPECT_EQ(BTM_BLE_MULTI_ADV_SUCCESS, reg_status);
  EXPECT_EQ(5, reg_inst_id);
}

/* This test verifies that the only flow that is currently used on Android, is
 * working correctly. This flow is : register, set parameters, set data, enable,
 * ... (advertise) ..., unregister*/
TEST_F(BleAdvertisingManagerTest, test_android_flow) {
  BleAdvertisingManager::Get()->RegisterAdvertiser(base::Bind(
      &BleAdvertisingManagerTest::RegistrationCb, base::Unretained(this)));
  EXPECT_EQ(BTM_BLE_MULTI_ADV_SUCCESS, reg_status);
  int advertiser_id = reg_inst_id;

  status_cb set_params_cb;
  tBTM_BLE_ADV_PARAMS params;
  EXPECT_CALL(*hci_mock, SetParameters1(_, _, _, _, _, _)).Times(1);
  EXPECT_CALL(*hci_mock, SetParameters2(_, _, _, advertiser_id, _, _))
      .Times(1)
      .WillOnce(SaveArg<5>(&set_params_cb));
  BleAdvertisingManager::Get()->SetParameters(
      advertiser_id, &params,
      base::Bind(&BleAdvertisingManagerTest::SetParametersCb,
                 base::Unretained(this)));

  // we are a truly gracious fake controller, let the command succeed!
  set_params_cb.Run(0);
  EXPECT_EQ(BTM_BLE_MULTI_ADV_SUCCESS, set_params_status);
  ::testing::Mock::VerifyAndClearExpectations(hci_mock.get());

  status_cb set_data_cb;
  EXPECT_CALL(*hci_mock, SetAdvertisingData(_, _, advertiser_id, _))
      .Times(1)
      .WillOnce(SaveArg<3>(&set_data_cb));
  BleAdvertisingManager::Get()->SetData(
      advertiser_id, false, std::vector<uint8_t>(),
      base::Bind(&BleAdvertisingManagerTest::SetDataCb,
                 base::Unretained(this)));
  set_data_cb.Run(0);
  EXPECT_EQ(BTM_BLE_MULTI_ADV_SUCCESS, set_data_status);
  ::testing::Mock::VerifyAndClearExpectations(hci_mock.get());

  status_cb enable_cb;
  EXPECT_CALL(*hci_mock, Enable(0x01 /* enable */, advertiser_id, _))
      .Times(1)
      .WillOnce(SaveArg<2>(&enable_cb));
  BleAdvertisingManager::Get()->Enable(
      advertiser_id, true,
      base::Bind(&BleAdvertisingManagerTest::EnableCb, base::Unretained(this)),
      0, base::Callback<void(uint8_t)>());
  enable_cb.Run(0);
  EXPECT_EQ(BTM_BLE_MULTI_ADV_SUCCESS, enable_status);
  ::testing::Mock::VerifyAndClearExpectations(hci_mock.get());

  /* fake controller should be advertising */

  EXPECT_CALL(*hci_mock, Enable(0x00 /* disable */, advertiser_id, _))
      .Times(1)
      .WillOnce(SaveArg<2>(&enable_cb));
  BleAdvertisingManager::Get()->Unregister(advertiser_id);
  enable_cb.Run(0);
  EXPECT_EQ(BTM_BLE_MULTI_ADV_SUCCESS, enable_status);
  ::testing::Mock::VerifyAndClearExpectations(hci_mock.get());
}

/* This test verifies that when advertising data is set, tx power and flags will
 * be properly filled. */
TEST_F(BleAdvertisingManagerTest, test_adv_data_filling) {
  BleAdvertisingManager::Get()->RegisterAdvertiser(base::Bind(
      &BleAdvertisingManagerTest::RegistrationCb, base::Unretained(this)));
  EXPECT_EQ(BTM_BLE_MULTI_ADV_SUCCESS, reg_status);
  int advertiser_id = reg_inst_id;

  status_cb set_params_cb;
  tBTM_BLE_ADV_PARAMS params;
  params.adv_type = BTM_BLE_CONNECT_EVT;
  params.tx_power = -15;
  EXPECT_CALL(*hci_mock, SetParameters1(_, _, _, _, _, _)).Times(1);
  EXPECT_CALL(*hci_mock, SetParameters2(_, _, _, advertiser_id,
                                        (uint8_t)params.tx_power, _))
      .Times(1)
      .WillOnce(SaveArg<5>(&set_params_cb));
  BleAdvertisingManager::Get()->SetParameters(
      advertiser_id, &params,
      base::Bind(&BleAdvertisingManagerTest::SetParametersCb,
                 base::Unretained(this)));

  // let the set parameters command succeed!
  set_params_cb.Run(0);
  EXPECT_EQ(BTM_BLE_MULTI_ADV_SUCCESS, set_params_status);
  ::testing::Mock::VerifyAndClearExpectations(hci_mock.get());

  status_cb set_data_cb;
  /* verify that flags will be added, and tx power filled, if call to SetData
   * contained only tx power, and the advertisement is connectable */
  uint8_t expected_adv_data[] = {0x02 /* len */,         0x01 /* flags */,
                                 0x02 /* flags value */, 0x02 /* len */,
                                 0x0A /* tx_power */,    params.tx_power};
  EXPECT_CALL(*hci_mock, SetAdvertisingData(_, _, advertiser_id, _))
      .With(Args<1, 0>(ElementsAreArray(expected_adv_data)))
      .Times(1)
      .WillOnce(SaveArg<3>(&set_data_cb));
  BleAdvertisingManager::Get()->SetData(
      advertiser_id, false,
      std::vector<uint8_t>({0x02 /* len */, 0x0A /* tx_power */, 0x00}),
      base::Bind(&BleAdvertisingManagerTest::SetDataCb,
                 base::Unretained(this)));
  set_data_cb.Run(0);
  EXPECT_EQ(BTM_BLE_MULTI_ADV_SUCCESS, set_data_status);
  ::testing::Mock::VerifyAndClearExpectations(hci_mock.get());
}

/* This test verifies that when advertising is non-connectable, flags will not
 * be added. */
TEST_F(BleAdvertisingManagerTest, test_adv_data_not_filling) {
  BleAdvertisingManager::Get()->RegisterAdvertiser(base::Bind(
      &BleAdvertisingManagerTest::RegistrationCb, base::Unretained(this)));
  EXPECT_EQ(BTM_BLE_MULTI_ADV_SUCCESS, reg_status);
  int advertiser_id = reg_inst_id;

  status_cb set_params_cb;
  tBTM_BLE_ADV_PARAMS params;
  params.adv_type = BTM_BLE_NON_CONNECT_EVT;
  params.tx_power = -15;
  EXPECT_CALL(*hci_mock, SetParameters1(_, _, _, _, _, _)).Times(1);
  EXPECT_CALL(*hci_mock, SetParameters2(_, _, _, advertiser_id,
                                        (uint8_t)params.tx_power, _))
      .Times(1)
      .WillOnce(SaveArg<5>(&set_params_cb));
  BleAdvertisingManager::Get()->SetParameters(
      advertiser_id, &params,
      base::Bind(&BleAdvertisingManagerTest::SetParametersCb,
                 base::Unretained(this)));

  // let the set parameters command succeed!
  set_params_cb.Run(0);
  EXPECT_EQ(BTM_BLE_MULTI_ADV_SUCCESS, set_params_status);
  ::testing::Mock::VerifyAndClearExpectations(hci_mock.get());

  status_cb set_data_cb;
  /* verify that flags will not be added */
  uint8_t expected_adv_data[] = {
      0x02 /* len */, 0xFF /* manufacturer specific */, 0x01 /* data */};
  EXPECT_CALL(*hci_mock, SetAdvertisingData(_, _, advertiser_id, _))
      .With(Args<1, 0>(ElementsAreArray(expected_adv_data)))
      .Times(1)
      .WillOnce(SaveArg<3>(&set_data_cb));
  BleAdvertisingManager::Get()->SetData(
      advertiser_id, false, std::vector<uint8_t>({0x02 /* len */, 0xFF, 0x01}),
      base::Bind(&BleAdvertisingManagerTest::SetDataCb,
                 base::Unretained(this)));
  set_data_cb.Run(0);
  EXPECT_EQ(BTM_BLE_MULTI_ADV_SUCCESS, set_data_status);
  ::testing::Mock::VerifyAndClearExpectations(hci_mock.get());
}
