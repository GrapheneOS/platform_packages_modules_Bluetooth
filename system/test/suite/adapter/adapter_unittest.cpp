/******************************************************************************
 *
 *  Copyright (C) 2015 Google, Inc.
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

#include "adapter/bluetooth_test.h"

extern "C" {
#include "btcore/include/property.h"
}

namespace {

// Each iteration of the test takes about 2 seconds to run, so choose a value
// that matches your time constraints. For example, 5 iterations would take
// about 10 seconds to run
const int kTestRepeatCount = 5;

}  // namespace

namespace bttest {

TEST_F(BluetoothTest, AdapterEnableDisable) {
  EXPECT_EQ(GetState(), BT_STATE_OFF) <<
    "Test should be run with Adapter disabled";

  EXPECT_EQ(bt_interface()->enable(), BT_STATUS_SUCCESS);
  semaphore_wait(adapter_state_changed_callback_sem_);
  EXPECT_EQ(GetState(), BT_STATE_ON) <<  "Adapter did not turn on.";

  EXPECT_EQ(bt_interface()->disable(), BT_STATUS_SUCCESS);
  semaphore_wait(adapter_state_changed_callback_sem_);
  EXPECT_EQ(GetState(), BT_STATE_OFF) << "Adapter did not turn off.";
}

TEST_F(BluetoothTest, AdapterRepeatedEnableDisable) {
  EXPECT_EQ(GetState(), BT_STATE_OFF)
    << "Test should be run with Adapter disabled";

  for (int i = 0; i < kTestRepeatCount; ++i) {
    EXPECT_EQ(bt_interface()->enable(), BT_STATUS_SUCCESS);
    semaphore_wait(adapter_state_changed_callback_sem_);
    EXPECT_EQ(GetState(), BT_STATE_ON) <<  "Adapter did not turn on.";

    EXPECT_EQ(bt_interface()->disable(), BT_STATUS_SUCCESS);
    semaphore_wait(adapter_state_changed_callback_sem_);
    EXPECT_EQ(GetState(), BT_STATE_OFF) << "Adapter did not turn off.";
  }
}

TEST_F(BluetoothTest, AdapterSetGetName) {
  bt_property_t *new_name = property_new_name("BluetoothTestName1");

  EXPECT_EQ(bt_interface()->enable(), BT_STATUS_SUCCESS);
  semaphore_wait(adapter_state_changed_callback_sem_);
  EXPECT_EQ(GetState(), BT_STATE_ON)
    << "Test should be run with Adapter enabled";

  // Enabling the interface will call the properties callback twice before
  // ever reaching this point.
  ClearSemaphore(adapter_properties_callback_sem_);

  EXPECT_EQ(bt_interface()->get_adapter_property(BT_PROPERTY_BDNAME),
      BT_STATUS_SUCCESS);
  semaphore_wait(adapter_properties_callback_sem_);
  EXPECT_GT(GetPropertiesChangedCount(), 0)
    << "Expected at least one adapter property to change";
  bt_property_t *old_name = GetProperty(BT_PROPERTY_BDNAME);
  EXPECT_NE(old_name, nullptr);
  if (property_equals(old_name, new_name)) {
    property_free(new_name);
    new_name = property_new_name("BluetoothTestName2");
  }

  EXPECT_EQ(bt_interface()->set_adapter_property(new_name), BT_STATUS_SUCCESS);
  semaphore_wait(adapter_properties_callback_sem_);
  EXPECT_GT(GetPropertiesChangedCount(), 0)
    << "Expected at least one adapter property to change";
  EXPECT_TRUE(GetProperty(BT_PROPERTY_BDNAME))
    << "The Bluetooth name property did not change.";
  EXPECT_TRUE(property_equals(GetProperty(BT_PROPERTY_BDNAME), new_name))
    << "Bluetooth name "
    << property_as_name(GetProperty(BT_PROPERTY_BDNAME))->name
    << " does not match test value " << property_as_name(new_name)->name;


  EXPECT_EQ(bt_interface()->set_adapter_property(old_name), BT_STATUS_SUCCESS);
  semaphore_wait(adapter_properties_callback_sem_);
  EXPECT_TRUE(property_equals(GetProperty(BT_PROPERTY_BDNAME), old_name))
    << "Bluetooth name "
    << property_as_name(GetProperty(BT_PROPERTY_BDNAME))->name
    << " does not match original name" << property_as_name(old_name)->name;

  EXPECT_EQ(bt_interface()->disable(), BT_STATUS_SUCCESS);
  semaphore_wait(adapter_state_changed_callback_sem_);
  EXPECT_EQ(GetState(), BT_STATE_OFF) << "Adapter did not turn off.";
  property_free(new_name);
}

TEST_F(BluetoothTest, AdapterStartDiscovery) {
  EXPECT_EQ(bt_interface()->enable(), BT_STATUS_SUCCESS);
  semaphore_wait(adapter_state_changed_callback_sem_);
  EXPECT_EQ(GetState(), BT_STATE_ON)
    << "Test should be run with Adapter enabled";

  EXPECT_EQ(bt_interface()->start_discovery(), BT_STATUS_SUCCESS);
  semaphore_wait(discovery_state_changed_callback_sem_);
  EXPECT_EQ(GetDiscoveryState(), BT_DISCOVERY_STARTED)
    << "Unable to start discovery.";

  EXPECT_EQ(bt_interface()->disable(), BT_STATUS_SUCCESS);
  semaphore_wait(adapter_state_changed_callback_sem_);
  EXPECT_EQ(GetState(), BT_STATE_OFF) << "Adapter did not turn off.";
}

TEST_F(BluetoothTest, AdapterCancelDiscovery) {
  EXPECT_EQ(bt_interface()->enable(), BT_STATUS_SUCCESS);
  semaphore_wait(adapter_state_changed_callback_sem_);
  EXPECT_EQ(GetState(), BT_STATE_ON)
    << "Test should be run with Adapter enabled";

  EXPECT_EQ(bt_interface()->start_discovery(), BT_STATUS_SUCCESS);
  semaphore_wait(discovery_state_changed_callback_sem_);
  EXPECT_EQ(bt_interface()->cancel_discovery(), BT_STATUS_SUCCESS);
  semaphore_wait(discovery_state_changed_callback_sem_);

  EXPECT_EQ(GetDiscoveryState(), BT_DISCOVERY_STOPPED)
    << "Unable to stop discovery.";

  EXPECT_EQ(bt_interface()->disable(), BT_STATUS_SUCCESS);
  semaphore_wait(adapter_state_changed_callback_sem_);
  EXPECT_EQ(GetState(), BT_STATE_OFF) << "Adapter did not turn off.";
}

}  // bttest
