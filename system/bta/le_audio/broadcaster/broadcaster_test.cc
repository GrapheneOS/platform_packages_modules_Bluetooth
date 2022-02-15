/*
 * Copyright 2021 HIMSA II K/S - www.himsa.com.
 * Represented by EHIMA - www.ehima.com
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

#include <chrono>

#include "device/include/controller.h"
#include "bta/include/bta_le_audio_api.h"
#include "bta/include/bta_le_audio_broadcaster_api.h"
#include "bta/test/common/mock_controller.h"
#include "bta/le_audio/mock_iso_manager.h"
#include "bta/le_audio/mock_le_audio_client_audio.h"
#include "bta/le_audio/broadcaster/mock_state_machine.h"
#include "stack/include/btm_iso_api.h"

using testing::_;
using testing::AtLeast;
using testing::DoAll;
using testing::Mock;
using testing::NotNull;
using testing::Return;
using testing::SaveArg;
using testing::Test;

using namespace bluetooth::le_audio;

std::map<std::string, int> mock_function_count_map;

// Disables most likely false-positives from base::SplitString()
extern "C" const char* __asan_default_options() {
  return "detect_container_overflow=0";
}

static base::Callback<void(BT_OCTET8)> generator_cb;

void btsnd_hcic_ble_rand(base::Callback<void(BT_OCTET8)> cb) {
  generator_cb = cb;
}

std::ostream& operator<<(
    std::ostream& os,
    const le_audio::broadcaster::BroadcastStateMachine& machine) {
  return os;
}

namespace le_audio {
namespace broadcaster {
namespace {
static constexpr LeAudioBroadcaster::AudioProfile default_profile =
    LeAudioBroadcaster::AudioProfile::SONIFICATION;
static constexpr LeAudioBroadcaster::Code default_code = {
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10};
static const std::vector<uint8_t> default_metadata = {0x03, 0x02, 0x01, 0x00};

class MockLeAudioBroadcasterCallbacks
    : public bluetooth::le_audio::LeAudioBroadcasterCallbacks {
 public:
  MOCK_METHOD((void), OnBroadcastCreated, (uint8_t instance_id, bool success),
              (override));
  MOCK_METHOD((void), OnBroadcastDestroyed, (uint8_t instance_id), (override));
  MOCK_METHOD((void), OnBroadcastStateChanged,
              (uint8_t instance_id, bluetooth::le_audio::BroadcastState state),
              (override));
  MOCK_METHOD((void), OnBroadcastId,
              (uint8_t instance_id,
               const bluetooth::le_audio::BroadcastId& broadcast_id),
              (override));
};

class BroadcasterTest : public Test {
 protected:
  void SetUp() override {
    mock_function_count_map.clear();
    ON_CALL(controller_interface_, SupportsBleIsochronousBroadcaster)
        .WillByDefault(Return(true));

    controller::SetMockControllerInterface(&controller_interface_);
    iso_manager_ = bluetooth::hci::IsoManager::GetInstance();
    ASSERT_NE(iso_manager_, nullptr);
    iso_manager_->Start();

    ON_CALL(mock_audio_source_, Start).WillByDefault(Return(true));
    MockLeAudioClientAudioSource::SetMockInstanceForTesting(
        &mock_audio_source_);

    is_audio_hal_acquired = false;
    ON_CALL(mock_audio_source_, Acquire).WillByDefault([this]() -> void* {
      if (!is_audio_hal_acquired) {
        is_audio_hal_acquired = true;
        return &mock_audio_source_;
      }

      return nullptr;
    });

    ON_CALL(mock_audio_source_, Release)
        .WillByDefault([this](const void* inst) -> void {
          if (is_audio_hal_acquired) {
            is_audio_hal_acquired = false;
          }
        });

    ASSERT_FALSE(LeAudioBroadcaster::IsLeAudioBroadcasterRunning());
    LeAudioBroadcaster::Initialize(&mock_broadcaster_callbacks_,
                                   base::Bind([]() -> bool { return true; }));

    /* Simulate random generator */
    uint8_t random[] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
    generator_cb.Run(random);
  }

  void TearDown() override {
    // This is required since Stop() and Cleanup() may trigger some callbacks.
    Mock::VerifyAndClearExpectations(&mock_broadcaster_callbacks_);

    LeAudioBroadcaster::Stop();
    LeAudioBroadcaster::Cleanup();
    ASSERT_FALSE(LeAudioBroadcaster::IsLeAudioBroadcasterRunning());

    iso_manager_->Stop();

    controller::SetMockControllerInterface(nullptr);
    MockLeAudioClientAudioSource::SetMockInstanceForTesting(nullptr);
  }

  uint8_t InstantiateBroadcast(
      LeAudioBroadcaster::AudioProfile profile = default_profile,
      std::vector<uint8_t> metadata = default_metadata,
      LeAudioBroadcaster::Code code = default_code) {
    uint8_t instance_id = LeAudioBroadcaster::kInstanceIdUndefined;
    EXPECT_CALL(mock_broadcaster_callbacks_, OnBroadcastCreated(_, true))
        .WillOnce(SaveArg<0>(&instance_id));
    LeAudioBroadcaster::Get()->CreateAudioBroadcast(metadata, profile, code);

    return instance_id;
  }

 protected:
  MockLeAudioClientAudioSource mock_audio_source_;
  MockLeAudioBroadcasterCallbacks mock_broadcaster_callbacks_;
  controller::MockControllerInterface controller_interface_;
  bluetooth::hci::IsoManager* iso_manager_;
  bool is_audio_hal_acquired;
};

TEST_F(BroadcasterTest, Initialize) {
  ASSERT_NE(LeAudioBroadcaster::Get(), nullptr);
  ASSERT_TRUE(LeAudioBroadcaster::IsLeAudioBroadcasterRunning());
}

TEST_F(BroadcasterTest, GetNumRetransmit) {
  LeAudioBroadcaster::Get()->SetNumRetransmit(8);
  ASSERT_EQ(LeAudioBroadcaster::Get()->GetNumRetransmit(), 8);
  LeAudioBroadcaster::Get()->SetNumRetransmit(12);
  ASSERT_EQ(LeAudioBroadcaster::Get()->GetNumRetransmit(), 12);
}

TEST_F(BroadcasterTest, GetStreamingPhy) {
  LeAudioBroadcaster::Get()->SetStreamingPhy(1);
  ASSERT_EQ(LeAudioBroadcaster::Get()->GetStreamingPhy(), 1);
  LeAudioBroadcaster::Get()->SetStreamingPhy(2);
  ASSERT_EQ(LeAudioBroadcaster::Get()->GetStreamingPhy(), 2);
}

TEST_F(BroadcasterTest, CreateAudioBroadcast) {
  uint8_t instance_id = InstantiateBroadcast();
  ASSERT_NE(instance_id, LeAudioBroadcaster::kInstanceIdUndefined);
  ASSERT_EQ(instance_id,
            MockBroadcastStateMachine::GetLastInstance()->GetInstanceId());

  auto& instance_config = MockBroadcastStateMachine::GetLastInstance()->cfg;
  ASSERT_EQ(instance_config.broadcast_code, default_code);
  for (auto& subgroup : instance_config.announcement.subgroup_configs) {
    ASSERT_EQ(subgroup.metadata, default_metadata);
  }
  // Note: There shall be a separate test to verify audio parameters
}

TEST_F(BroadcasterTest, SuspendAudioBroadcast) {
  uint8_t instance_id = InstantiateBroadcast();
  LeAudioBroadcaster::Get()->StartAudioBroadcast(instance_id);

  EXPECT_CALL(mock_broadcaster_callbacks_,
              OnBroadcastStateChanged(instance_id, BroadcastState::CONFIGURED))
      .Times(1);

  EXPECT_CALL(mock_audio_source_, Stop).Times(AtLeast(1));
  LeAudioBroadcaster::Get()->SuspendAudioBroadcast(instance_id);
}

TEST_F(BroadcasterTest, StartAudioBroadcast) {
  uint8_t instance_id = InstantiateBroadcast();
  LeAudioBroadcaster::Get()->StopAudioBroadcast(instance_id);

  EXPECT_CALL(mock_broadcaster_callbacks_,
              OnBroadcastStateChanged(instance_id, BroadcastState::STREAMING))
      .Times(1);

  LeAudioClientAudioSinkReceiver* audio_receiver;
  EXPECT_CALL(mock_audio_source_, Start)
      .WillOnce(DoAll(SaveArg<1>(&audio_receiver), Return(true)));

  LeAudioBroadcaster::Get()->StartAudioBroadcast(instance_id);
  ASSERT_NE(audio_receiver, nullptr);

  // NOTICE: This is really an implementation specific part, we fake the BIG
  //         config as the mocked state machine does not even call the
  //         IsoManager to prepare one (and that's good since IsoManager is also
  //         a mocked one).
  BigConfig big_cfg;
  big_cfg.big_id =
      MockBroadcastStateMachine::GetLastInstance()->GetInstanceId();
  big_cfg.connection_handles = {0x10, 0x12};
  big_cfg.max_pdu = 128;
  MockBroadcastStateMachine::GetLastInstance()->SetExpectedBigConfig(big_cfg);

  // Inject the audio and verify call on the Iso manager side.
  EXPECT_CALL(*MockIsoManager::GetInstance(), SendIsoData).Times(1);
  std::vector<uint8_t> sample_data(320, 0);
  audio_receiver->OnAudioDataReady(sample_data);
}

TEST_F(BroadcasterTest, StartAudioBroadcastMedia) {
  uint8_t instance_id =
      InstantiateBroadcast(LeAudioBroadcaster::AudioProfile::MEDIA);
  LeAudioBroadcaster::Get()->StopAudioBroadcast(instance_id);

  EXPECT_CALL(mock_broadcaster_callbacks_,
              OnBroadcastStateChanged(instance_id, BroadcastState::STREAMING))
      .Times(1);

  LeAudioClientAudioSinkReceiver* audio_receiver;
  EXPECT_CALL(mock_audio_source_, Start)
      .WillOnce(DoAll(SaveArg<1>(&audio_receiver), Return(true)));

  LeAudioBroadcaster::Get()->StartAudioBroadcast(instance_id);
  ASSERT_NE(audio_receiver, nullptr);

  // NOTICE: This is really an implementation specific part, we fake the BIG
  //         config as the mocked state machine does not even call the
  //         IsoManager to prepare one (and that's good since IsoManager is also
  //         a mocked one).
  BigConfig big_cfg;
  big_cfg.big_id =
      MockBroadcastStateMachine::GetLastInstance()->GetInstanceId();
  big_cfg.connection_handles = {0x10, 0x12};
  big_cfg.max_pdu = 128;
  MockBroadcastStateMachine::GetLastInstance()->SetExpectedBigConfig(big_cfg);

  // Inject the audio and verify call on the Iso manager side.
  EXPECT_CALL(*MockIsoManager::GetInstance(), SendIsoData).Times(2);
  std::vector<uint8_t> sample_data(1920, 0);
  audio_receiver->OnAudioDataReady(sample_data);
}

TEST_F(BroadcasterTest, StopAudioBroadcast) {
  uint8_t instance_id = InstantiateBroadcast();
  LeAudioBroadcaster::Get()->StartAudioBroadcast(instance_id);

  EXPECT_CALL(mock_broadcaster_callbacks_,
              OnBroadcastStateChanged(instance_id, BroadcastState::STOPPED))
      .Times(1);

  EXPECT_CALL(mock_audio_source_, Stop).Times(AtLeast(1));
  LeAudioBroadcaster::Get()->StopAudioBroadcast(instance_id);
}

TEST_F(BroadcasterTest, DestroyAudioBroadcast) {
  uint8_t instance_id = InstantiateBroadcast();

  EXPECT_CALL(mock_broadcaster_callbacks_, OnBroadcastDestroyed(instance_id))
      .Times(1);
  LeAudioBroadcaster::Get()->DestroyAudioBroadcast(instance_id);

  // Expect not being able to interact with this Broadcast
  EXPECT_CALL(mock_broadcaster_callbacks_,
              OnBroadcastStateChanged(instance_id, _))
      .Times(0);

  EXPECT_CALL(mock_audio_source_, Stop).Times(0);
  LeAudioBroadcaster::Get()->StopAudioBroadcast(instance_id);

  EXPECT_CALL(mock_audio_source_, Start).Times(0);
  LeAudioBroadcaster::Get()->StartAudioBroadcast(instance_id);

  EXPECT_CALL(mock_audio_source_, Stop).Times(0);
  LeAudioBroadcaster::Get()->SuspendAudioBroadcast(instance_id);
}

TEST_F(BroadcasterTest, GetBroadcastId) {
  uint8_t instance_id = InstantiateBroadcast();

  EXPECT_CALL(mock_broadcaster_callbacks_, OnBroadcastId(instance_id, _))
      .Times(1);
  LeAudioBroadcaster::Get()->GetBroadcastId(instance_id);
}

TEST_F(BroadcasterTest, GetBroadcastAllStates) {
  uint8_t instance_id = InstantiateBroadcast();
  uint8_t instance_id2 = InstantiateBroadcast();
  ASSERT_NE(instance_id, LeAudioBroadcaster::kInstanceIdUndefined);
  ASSERT_NE(instance_id2, LeAudioBroadcaster::kInstanceIdUndefined);
  ASSERT_NE(instance_id, instance_id2);

  /* In the current implementation state machine switches to the correct state
   * on itself, therefore here when we use mocked state machine this is not
   * being verified.
   */
  EXPECT_CALL(mock_broadcaster_callbacks_,
              OnBroadcastStateChanged(instance_id, _))
      .Times(1);
  EXPECT_CALL(mock_broadcaster_callbacks_,
              OnBroadcastStateChanged(instance_id2, _))
      .Times(1);

  LeAudioBroadcaster::Get()->GetAllBroadcastStates();
}

TEST_F(BroadcasterTest, UpdateMetadata) {
  uint8_t instance_id = InstantiateBroadcast();

  EXPECT_CALL(*MockBroadcastStateMachine::GetLastInstance(),
              UpdateBroadcastAnnouncement)
      .Times(1);
  LeAudioBroadcaster::Get()->UpdateMetadata(instance_id,
                                            std::vector<uint8_t>({0x02, 0x01}));
}

TEST_F(BroadcasterTest, SetNumRetransmit) {
  uint8_t instance_id = InstantiateBroadcast();
  LeAudioBroadcaster::Get()->SetNumRetransmit(9);
  ASSERT_EQ(MockBroadcastStateMachine::GetLastInstance()->cb->GetNumRetransmit(
                instance_id),
            9);
  ASSERT_EQ(LeAudioBroadcaster::Get()->GetNumRetransmit(), 9);
}

TEST_F(BroadcasterTest, SetStreamingPhy) {
  LeAudioBroadcaster::Get()->SetStreamingPhy(2);
  // From now on new streams should be using Phy = 2.
  uint8_t instance_id = InstantiateBroadcast();
  ASSERT_EQ(MockBroadcastStateMachine::GetLastInstance()->cfg.streaming_phy, 2);

  // From now on new streams should be using Phy = 1.
  LeAudioBroadcaster::Get()->SetStreamingPhy(1);
  instance_id = InstantiateBroadcast();
  ASSERT_EQ(MockBroadcastStateMachine::GetLastInstance()->cfg.streaming_phy, 1);
  ASSERT_EQ(LeAudioBroadcaster::Get()->GetStreamingPhy(), 1);
}

TEST_F(BroadcasterTest, StreamParamsSonification) {
  uint8_t expected_channels = 1u;

  InstantiateBroadcast(LeAudioBroadcaster::AudioProfile::SONIFICATION);
  auto config = MockBroadcastStateMachine::GetLastInstance()->cfg;

  // Check audio configuration
  ASSERT_EQ(config.codec_wrapper.GetNumChannels(), expected_channels);
  // Matches number of bises in the announcement
  ASSERT_EQ(config.announcement.subgroup_configs[0].bis_configs.size(),
            expected_channels);
  // Note: Num of bises at IsoManager level is verified by state machine tests
}

TEST_F(BroadcasterTest, StreamParamsMedia) {
  uint8_t expected_channels = 2u;

  InstantiateBroadcast(LeAudioBroadcaster::AudioProfile::MEDIA);
  auto config = MockBroadcastStateMachine::GetLastInstance()->cfg;

  // Check audio configuration
  ASSERT_EQ(config.codec_wrapper.GetNumChannels(), expected_channels);
  // Matches number of bises in the announcement
  ASSERT_EQ(config.announcement.subgroup_configs[0].bis_configs.size(),
            expected_channels);
  // Note: Num of bises at IsoManager level is verified by state machine tests
}

}  // namespace
}  // namespace broadcaster
}  // namespace le_audio
