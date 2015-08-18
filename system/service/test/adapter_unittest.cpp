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
#include "service/hal/fake_bluetooth_interface.h"

namespace bluetooth {
namespace {

class AdapterTest : public ::testing::Test {
 public:
  AdapterTest() = default;
  ~AdapterTest() override = default;

  void SetUp() override {
    fake_hal_manager_ = hal::FakeBluetoothInterface::GetManager();
    fake_hal_iface_ = new hal::FakeBluetoothInterface();
    hal::BluetoothInterface::InitializeForTesting(fake_hal_iface_);

    adapter_.reset(new Adapter());
  }

  void TearDown() override {
    adapter_.reset();
    hal::BluetoothInterface::CleanUp();
  }

 protected:
  hal::FakeBluetoothInterface* fake_hal_iface_;
  hal::FakeBluetoothInterface::Manager* fake_hal_manager_;
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
  EXPECT_EQ(bluetooth::ADAPTER_STATE_OFF, adapter_->GetState());

  // Enable fails at HAL level
  EXPECT_FALSE(adapter_->Enable());
  EXPECT_EQ(bluetooth::ADAPTER_STATE_OFF, adapter_->GetState());

  // Enable success
  fake_hal_manager_->enable_succeed = true;
  EXPECT_TRUE(adapter_->Enable());

  // Enable fails because not disabled
  EXPECT_EQ(bluetooth::ADAPTER_STATE_TURNING_ON, adapter_->GetState());
  EXPECT_FALSE(adapter_->Enable());

  // Adapter state updates properly
  fake_hal_iface_->NotifyAdapterStateChanged(BT_STATE_ON);
  EXPECT_EQ(bluetooth::ADAPTER_STATE_ON, adapter_->GetState());

  // Enable fails because already enabled
  EXPECT_FALSE(adapter_->Enable());
}

TEST_F(AdapterTest, Disable) {
  fake_hal_manager_->disable_succeed = true;
  EXPECT_FALSE(adapter_->IsEnabled());
  EXPECT_EQ(bluetooth::ADAPTER_STATE_OFF, adapter_->GetState());

  // Disable fails because already disabled
  EXPECT_FALSE(adapter_->Disable());
  EXPECT_EQ(bluetooth::ADAPTER_STATE_OFF, adapter_->GetState());

  // Disable success
  fake_hal_iface_->NotifyAdapterStateChanged(BT_STATE_ON);
  EXPECT_TRUE(adapter_->Disable());

  // Disable fails because not enabled
  EXPECT_EQ(bluetooth::ADAPTER_STATE_TURNING_OFF, adapter_->GetState());
  EXPECT_FALSE(adapter_->Disable());

  fake_hal_iface_->NotifyAdapterStateChanged(BT_STATE_ON);
  EXPECT_EQ(bluetooth::ADAPTER_STATE_ON, adapter_->GetState());

  // Disable fails at HAL level
  fake_hal_manager_->disable_succeed = false;
  EXPECT_FALSE(adapter_->Disable());
}

TEST_F(AdapterTest, GetName) {
  EXPECT_EQ(bluetooth::Adapter::kDefaultName, adapter_->GetName());

  const char kTestAdapterName[] = "Test Adapter Name";

  fake_hal_iface_->NotifyAdapterNamePropertyChanged(kTestAdapterName);
  EXPECT_EQ(kTestAdapterName, adapter_->GetName());
}

TEST_F(AdapterTest, SetName) {
  bt_bdname_t hal_name;

  // Name too large.
  EXPECT_FALSE(adapter_->SetName(std::string(sizeof(hal_name.name), 'a')));

  // Valid length.
  EXPECT_FALSE(adapter_->SetName("Test Name"));
  fake_hal_manager_->set_property_succeed = true;
  EXPECT_TRUE(adapter_->SetName("Test Name"));
}

TEST_F(AdapterTest, GetAddress) {
  EXPECT_EQ(bluetooth::Adapter::kDefaultAddress, adapter_->GetAddress());

  const bt_bdaddr_t kTestAdapterInput = {
    { 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc }
  };
  const char kTestAdapterAddressOutput[] = "12:34:56:78:9A:BC";

  fake_hal_iface_->NotifyAdapterAddressPropertyChanged(&kTestAdapterInput);
  EXPECT_EQ(kTestAdapterAddressOutput, adapter_->GetAddress());
}

}  // namespace
}  // namespace bluetooth
