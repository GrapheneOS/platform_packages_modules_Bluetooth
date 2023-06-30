/*
 * Copyright 2023 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "le_audio_health_status.h"

#include <base/functional/callback.h>
#include <base/functional/callback_forward.h>
#include <base/functional/callback_helpers.h>
#include <base/logging.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "bta/include/bta_groups.h"
#include "gd/common/init_flags.h"
#include "test/common/mock_functions.h"
#include "types/bluetooth/uuid.h"
#include "types/raw_address.h"

using bluetooth::groups::kGroupUnknown;
using bluetooth::le_audio::LeAudioHealthBasedAction;
using le_audio::LeAudioHealthDeviceStatType;
using le_audio::LeAudioHealthGroupStatType;
using le_audio::LeAudioHealthStatus;

const char* test_flags[] = {
    "INIT_logging_debug_enabled_for_all=true",
    nullptr,
};

LeAudioHealthBasedAction recommentation_in_callback =
    LeAudioHealthBasedAction::NONE;
RawAddress address_in_callback = RawAddress::kEmpty;
int group_id_in_callback = kGroupUnknown;

static void healthCallback(const RawAddress& address, int group_id,
                           LeAudioHealthBasedAction recommendation) {
  address_in_callback = address;
  group_id_in_callback = group_id;
  recommentation_in_callback = recommendation;
}

class LeAudioHealthStatusTest : public ::testing::Test {
 protected:
  void SetUp() override {
    reset_mock_function_count_map();

    bluetooth::common::InitFlags::Load(test_flags);
    le_audio_health_status_instance_ = LeAudioHealthStatus::Get();
    le_audio_health_status_instance_->RegisterCallback(
        base::BindRepeating(healthCallback));
  }

  void TearDown() override {
    le_audio_health_status_instance_->Cleanup();
    recommentation_in_callback = LeAudioHealthBasedAction::NONE;
    address_in_callback = RawAddress::kEmpty;
  }

  LeAudioHealthStatus* le_audio_health_status_instance_;
};

RawAddress GetTestAddress(uint8_t index) {
  CHECK_LT(index, UINT8_MAX);
  RawAddress result = {{0xC0, 0xDE, 0xC0, 0xDE, 0x00, index}};
  return result;
}

TEST_F(LeAudioHealthStatusTest, test_initialize) {
  ASSERT_TRUE(le_audio_health_status_instance_ != nullptr);
}

TEST_F(LeAudioHealthStatusTest, test_invalid_db) {
  const RawAddress test_address0 = GetTestAddress(0);
  le_audio_health_status_instance_->AddStatisticForDevice(
      test_address0, LeAudioHealthDeviceStatType::INVALID_DB);
  ASSERT_TRUE(address_in_callback == test_address0);
  ASSERT_TRUE(recommentation_in_callback == LeAudioHealthBasedAction::DISABLE);
}

TEST_F(LeAudioHealthStatusTest, test_invalid_csis_member) {
  const RawAddress test_address0 = GetTestAddress(0);
  le_audio_health_status_instance_->AddStatisticForDevice(
      test_address0, LeAudioHealthDeviceStatType::INVALID_CSIS);
  ASSERT_TRUE(address_in_callback == test_address0);
  ASSERT_TRUE(recommentation_in_callback == LeAudioHealthBasedAction::DISABLE);
}

TEST_F(LeAudioHealthStatusTest, test_remove_statistic) {
  const RawAddress test_address0 = GetTestAddress(0);
  int group_id = 1;

  le_audio_health_status_instance_->AddStatisticForDevice(
      test_address0, LeAudioHealthDeviceStatType::INVALID_CSIS);
  le_audio_health_status_instance_->AddStatisticForGroup(
      group_id, LeAudioHealthGroupStatType::STREAM_CREATE_SUCCESS);
  le_audio_health_status_instance_->RemoveStatistics(test_address0, group_id);
}

TEST_F(LeAudioHealthStatusTest, test_all_is_good) {
  int group_id = 1;

  for (int i = 0; i < 100; i++) {
    le_audio_health_status_instance_->AddStatisticForGroup(
        group_id, LeAudioHealthGroupStatType::STREAM_CREATE_SUCCESS);
  }

  ASSERT_TRUE(address_in_callback == RawAddress::kEmpty);
  ASSERT_TRUE(group_id_in_callback == kGroupUnknown);
}

TEST_F(LeAudioHealthStatusTest, test_disable_cis_no_stream_creation) {
  int group_id = 1;

  for (int i = 0; i < 3; i++) {
    le_audio_health_status_instance_->AddStatisticForGroup(
        group_id, LeAudioHealthGroupStatType::STREAM_CREATE_CIS_FAILED);
  }
  ASSERT_TRUE(address_in_callback == RawAddress::kEmpty);
  ASSERT_TRUE(group_id_in_callback == group_id);
  ;
  ASSERT_TRUE(recommentation_in_callback == LeAudioHealthBasedAction::DISABLE);
}

TEST_F(LeAudioHealthStatusTest, test_disable_signaling_no_stream_creation) {
  int group_id = 1;

  for (int i = 0; i < 3; i++) {
    le_audio_health_status_instance_->AddStatisticForGroup(
        group_id, LeAudioHealthGroupStatType::STREAM_CREATE_SIGNALING_FAILED);
  }
  /* No recommendation shall be sent */
  ASSERT_TRUE(address_in_callback == RawAddress::kEmpty);
  ASSERT_TRUE(group_id_in_callback == group_id);
  ASSERT_TRUE(recommentation_in_callback == LeAudioHealthBasedAction::DISABLE);
}

TEST_F(LeAudioHealthStatusTest, test_disable_signaling_cis_no_stream_creation) {
  int group_id = 1;

  for (int i = 0; i < 2; i++) {
    le_audio_health_status_instance_->AddStatisticForGroup(
        group_id, LeAudioHealthGroupStatType::STREAM_CREATE_SIGNALING_FAILED);
  }
  le_audio_health_status_instance_->AddStatisticForGroup(
      group_id, LeAudioHealthGroupStatType::STREAM_CREATE_CIS_FAILED);

  /* No recommendation shall be sent */
  ASSERT_TRUE(address_in_callback == RawAddress::kEmpty);
  ASSERT_TRUE(group_id_in_callback == group_id);
  ASSERT_TRUE(recommentation_in_callback == LeAudioHealthBasedAction::DISABLE);
}

TEST_F(LeAudioHealthStatusTest, test_consider_disabling) {
  int group_id = 1;

  for (int i = 0; i < 10; i++) {
    le_audio_health_status_instance_->AddStatisticForGroup(
        group_id, LeAudioHealthGroupStatType::STREAM_CREATE_SUCCESS);
  }

  for (int i = 0; i < 2; i++) {
    le_audio_health_status_instance_->AddStatisticForGroup(
        group_id, LeAudioHealthGroupStatType::STREAM_CREATE_CIS_FAILED);
  }

  ASSERT_TRUE(address_in_callback == RawAddress::kEmpty);

  for (int i = 0; i < 2; i++) {
    le_audio_health_status_instance_->AddStatisticForGroup(
        group_id, LeAudioHealthGroupStatType::STREAM_CREATE_SIGNALING_FAILED);
  }

  ASSERT_TRUE(address_in_callback == RawAddress::kEmpty);

  for (int i = 0; i < 3; i++) {
    le_audio_health_status_instance_->AddStatisticForGroup(
        group_id, LeAudioHealthGroupStatType::STREAM_CREATE_CIS_FAILED);
  }

  ASSERT_TRUE(address_in_callback == RawAddress::kEmpty);
  ASSERT_TRUE(group_id_in_callback == group_id);
  ASSERT_TRUE(recommentation_in_callback ==
              LeAudioHealthBasedAction::CONSIDER_DISABLING);
}