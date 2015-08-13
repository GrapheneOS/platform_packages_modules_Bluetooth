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

#include <base/macros.h>
#include <gtest/gtest.h>

#include "service/adapter.h"
#include "service/test/fake_hal_bluetooth_interface.h"

namespace bluetooth {
namespace {

// A Fake HAL Bluetooth interface. This is kept as a global singleton as the
// Bluetooth HAL doesn't support anything otherwise.
struct FakeHALManager {
  FakeHALManager()
      : enable_succeed(false),
        disable_succeed(false),
        set_property_succeed(false) {
  }

  // Values that should be returned from bt_interface_t methods.
  bool enable_succeed;
  bool disable_succeed;
  bool set_property_succeed;
};
FakeHALManager g_hal_manager;

int FakeHALEnable() {
  return g_hal_manager.enable_succeed ? BT_STATUS_SUCCESS : BT_STATUS_FAIL;
}

int FakeHALDisable() {
  return g_hal_manager.disable_succeed ? BT_STATUS_SUCCESS : BT_STATUS_FAIL;
}

int FakeHALSetAdapterProperty(const bt_property_t* /* property */) {
  LOG(INFO) << __func__;
  return (g_hal_manager.set_property_succeed ? BT_STATUS_SUCCESS :
          BT_STATUS_FAIL);
}

bt_interface_t fake_bt_iface = {
  sizeof(bt_interface_t),
  nullptr, /* init */
  FakeHALEnable,
  FakeHALDisable,
  nullptr, /* cleanup */
  nullptr, /* get_adapter_properties */
  nullptr, /* get_adapter_property */
  FakeHALSetAdapterProperty,
  nullptr, /* get_remote_device_properties */
  nullptr, /* get_remote_device_property */
  nullptr, /* set_remote_device_property */
  nullptr, /* get_remote_service_record */
  nullptr, /* get_remote_services */
  nullptr, /* start_discovery */
  nullptr, /* cancel_discovery */
  nullptr, /* create_bond */
  nullptr, /* remove_bond */
  nullptr, /* cancel_bond */
  nullptr, /* get_connection_state */
  nullptr, /* pin_reply */
  nullptr, /* ssp_reply */
  nullptr, /* get_profile_interface */
  nullptr, /* dut_mode_configure */
  nullptr, /* dut_more_send */
  nullptr, /* le_test_mode */
  nullptr, /* config_hci_snoop_log */
  nullptr, /* set_os_callouts */
  nullptr, /* read_energy_info */
  nullptr, /* dump */
};

class AdapterTest : public ::testing::Test {
 public:
  AdapterTest() = default;
  ~AdapterTest() override = default;

  void SetUp() override {
    fake_hal_iface_ = new testing::FakeHALBluetoothInterface(&fake_bt_iface);
    hal::BluetoothInterface::InitializeForTesting(fake_hal_iface_);

    adapter_.reset(new Adapter());
  }

  void TearDown() override {
    adapter_.reset();
    hal::BluetoothInterface::CleanUp();
  }

 protected:
  testing::FakeHALBluetoothInterface* fake_hal_iface_;
  std::unique_ptr<Adapter> adapter_;

 private:
  DISALLOW_COPY_AND_ASSIGN(AdapterTest);
};

TEST_F(AdapterTest, IsEnabled) {
  EXPECT_FALSE(adapter_->IsEnabled());

  fake_hal_iface_->NotifyAdapterStateChanged(BT_STATE_ON);
  EXPECT_TRUE(adapter_->IsEnabled());

  fake_hal_iface_->NotifyAdapterStateChanged(BT_STATE_OFF);
  EXPECT_FALSE(adapter_->IsEnabled());
}

TEST_F(AdapterTest, Enable) {
  EXPECT_FALSE(adapter_->IsEnabled());
  EXPECT_FALSE(adapter_->Enable());

  g_hal_manager.enable_succeed = true;
  EXPECT_TRUE(adapter_->Enable());

  fake_hal_iface_->NotifyAdapterStateChanged(BT_STATE_ON);
  EXPECT_FALSE(adapter_->Enable());
}

TEST_F(AdapterTest, Disable) {
  g_hal_manager.disable_succeed = true;
  EXPECT_FALSE(adapter_->IsEnabled());
  EXPECT_FALSE(adapter_->Disable());

  fake_hal_iface_->NotifyAdapterStateChanged(BT_STATE_ON);
  EXPECT_TRUE(adapter_->Disable());

  g_hal_manager.disable_succeed = false;
  EXPECT_FALSE(adapter_->Disable());
}

TEST_F(AdapterTest, SetName) {
  bt_bdname_t hal_name;

  // Name too large.
  EXPECT_FALSE(adapter_->SetName(std::string(sizeof(hal_name.name), 'a')));

  // Valid length.
  EXPECT_FALSE(adapter_->SetName("Test Name"));
  g_hal_manager.set_property_succeed = true;
  EXPECT_TRUE(adapter_->SetName("Test Name"));
}

}  // namespace
}  // namespace bluetooth
