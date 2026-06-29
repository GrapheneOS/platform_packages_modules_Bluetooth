/*
 * Copyright (C) 2020 The Android Open Source Project
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

#include "hal/snoop_logger.h"

#include <arpa/inet.h>
#include <bluetooth/log.h>
#include <com_android_bluetooth_flags.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <future>
#include <unordered_map>

#include "hal/snoop_logger_common.h"
#include "hal/snoop_logger_file.h"
#include "hal/syscall_wrapper_impl.h"
#include "os/fake_timer/fake_timerfd.h"
#include "os/files.h"
#include "os/parameter_provider.h"
#include "os/system_properties.h"
#include "os/utils.h"

namespace bluetooth::hal {

using os::fake_timer::fake_timerfd_advance;
using os::fake_timer::fake_timerfd_reset;
using namespace std::chrono_literals;

// Matcher for a byte array.
// Unsafe since the actual size of the argument is unchecked.
MATCHER_P2(MemEq, bytes, size, "") {
  char const* c_bytes = reinterpret_cast<char const*>(bytes);
  char const* c_arg = reinterpret_cast<char const*>(arg);
  for (unsigned i = 0; i < (unsigned)size; i++) {
    if (c_bytes[i] != c_arg[i]) {
      *result_listener << std::format("arg[{}] ({:#x}) != expected[{}] ({:#x})", i, c_arg[i], i,
                                      c_bytes[i]);
      return false;
    }
  }
  return true;
}

namespace {
static const std::vector<uint8_t> kInformationRequest = {
        0xfe, 0x2e, 0x0a, 0x00, 0x06, 0x00, 0x01, 0x00, 0x0a, 0x02, 0x02, 0x00, 0x02, 0x00,
};

static const std::vector<uint8_t> kSdpConnectionRequest = {0x08, 0x20, 0x0c, 0x00, 0x08, 0x00,
                                                           0x01, 0x00, 0x02, 0x0c, 0x04, 0x00,
                                                           0x01, 0x00, 0x44, 0x00};

static const std::vector<uint8_t> kAvdtpSuspend = {0x02, 0x02, 0x00, 0x07, 0x00, 0x03,
                                                   0x00, 0x8d, 0x00, 0x90, 0x09, 0x04};

static const std::vector<uint8_t> kHfpAtNrec0 = {0x02, 0x02, 0x20, 0x13, 0x00, 0x0f, 0x00, 0x41,
                                                 0x00, 0x09, 0xff, 0x15, 0x01, 0x41, 0x54, 0x2b,
                                                 0x4e, 0x52, 0x45, 0x43, 0x3d, 0x30, 0x0d, 0x5c};

static const std::vector<uint8_t> kQualcommConnectionRequest = {
        0xdc, 0x2e, 0x54, 0x00, 0x50, 0x00, 0xff, 0x00, 0x00, 0x0a,
        0x0f, 0x09, 0x01, 0x00, 0x5c, 0x93, 0x01, 0x00, 0x42, 0x00};

static const std::vector<uint8_t> kA2dpMediaPacket = {
        0x0b, 0x20, 0x3a, 0x00, 0x36, 0x00, 0x40, 0xa0, 0x80, 0xe0, 0x07, 0x7f, 0x00,
        0x1e, 0x08, 0x00, 0x00, 0x00, 0x00, 0x02, 0x47, 0xfc, 0x00, 0x00, 0xb0, 0x90,
        0x80, 0x03, 0x00, 0x20, 0x21, 0x11, 0x45, 0x00, 0x14, 0x50, 0x01, 0x46, 0xf0,
        0x81, 0x0a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a,
        0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5e,
};

static const std::vector<bluetooth::hal::HciPacket> kTestData = {
        {0x02, 0x20, 0x11, 0x00, 0x0d, 0x00, 0x41, 0x00, 0x9d, 0xef, 0x35,
         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
        {0x02, 0x00, 0x12, 0x00, 0x0e, 0x00, 0x40, 0x00, 0x9f, 0xff, 0x3f,
         0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
        {0x02, 0x20, 0x11, 0x00, 0x0d, 0x00, 0x41, 0x00, 0x9d, 0xef, 0x85,
         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
        {0x02, 0x00, 0x12, 0x00, 0x0e, 0x00, 0x40, 0x00, 0x9f, 0xff, 0x1f,
         0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
        {0x02, 0x20, 0x11, 0x00, 0x0d, 0x00, 0x41, 0x00, 0x9d, 0xef, 0x99,
         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
        {0x02, 0x00, 0x13, 0x00, 0x0f, 0x00, 0x40, 0x00, 0x9f, 0xff, 0xc6, 0x01,
         0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
        {0x02, 0x20, 0x11, 0x00, 0x0d, 0x00, 0x41, 0x00, 0x9d, 0xef, 0x99,
         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
        {0x02, 0x00, 0x12, 0x00, 0x0e, 0x00, 0x40, 0x00, 0x9f, 0xff, 0x1f,
         0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
        {0x02, 0x20, 0x12, 0x00, 0x0e, 0x00, 0x41, 0x00, 0x9d, 0xff, 0x01,
         0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
        {0x02, 0x00, 0x12, 0x00, 0x0e, 0x00, 0x40, 0x00, 0x9f, 0xff, 0x8f,
         0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
        {0x02, 0x20, 0x11, 0x00, 0x0d, 0x00, 0x41, 0x00, 0x9d, 0xef, 0x89,
         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
        {0x02, 0x00, 0x12, 0x00, 0x0e, 0x00, 0x40, 0x00, 0x9f, 0xff, 0x1f,
         0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
        {0x02, 0x20, 0x11, 0x00, 0x0d, 0x00, 0x41, 0x00, 0x9d, 0xef, 0x43,
         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
        {0x02, 0x00, 0x12, 0x00, 0x0e, 0x00, 0x40, 0x00, 0x9f, 0xff, 0x11,
         0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
        // Short packet (incoming) - L2CAP CID: 0x0041 (local_cid)
        {0x02, 0x20, 0x04, 0x00, 0x00, 0x00, 0x41, 0x00},
        // Short packet (outgoing) - L2CAP CID: 0x0040 (remote_cid)
        {0x02, 0x00, 0x04, 0x00, 0x00, 0x00, 0x40, 0x00}};

}  // namespace

class MockSnoopLoggerSocket : public SnoopLoggerSocketInterface {
public:
  MOCK_METHOD(void, Write, (const void*, size_t), (override));
};

class SnoopLoggerTest : public testing::Test {
protected:
  void SetUp() override {
    thread_ = new os::Thread("test_thread", bluetooth::os::Thread::Priority::NORMAL);
    shared_handler_ = new os::Handler(thread_);

    const testing::TestInfo* const test_info =
            testing::UnitTest::GetInstance()->current_test_info();

    log::debug("Setup for test {} in test suite {}.", test_info->name(),
               test_info->test_suite_name());
    temp_dir_ = std::filesystem::temp_directory_path();
    test_name_ = test_info->name();
    std::replace(test_name_.begin(), test_name_.end(), '/', '_');

    temp_snoop_log_ = temp_dir_ / "btsnoop_hci.log";
    temp_snoop_log_last_ = temp_dir_ / "btsnoop_hci.log.last";
    temp_snooz_log_ = temp_dir_ / "btsnooz_hci.log";
    temp_snooz_log_last_ = temp_dir_ / "btsnooz_hci.log.last";
    temp_snoop_log_filtered_ = temp_dir_ / "btsnoop_hci.log.filtered";
    temp_snoop_log_filtered_last_ = temp_dir_ / "btsnoop_hci.log.filtered.last";

    // TODO: this step is not necessary, temp_dir points to a newly created temporary folder.
    DeleteSnoopLogFiles();

    ASSERT_FALSE(std::filesystem::exists(temp_snoop_log_));
    ASSERT_FALSE(std::filesystem::exists(temp_snoop_log_last_));
    ASSERT_FALSE(std::filesystem::exists(temp_snoop_log_filtered_));
    ASSERT_FALSE(std::filesystem::exists(temp_snoop_log_filtered_last_));
    ASSERT_FALSE(std::filesystem::exists(temp_snooz_log_));
    ASSERT_FALSE(std::filesystem::exists(temp_snooz_log_last_));
  }

  void TearDown() override {
    shared_handler_->Clear();
    shared_handler_->WaitUntilStopped(200ms);
    delete shared_handler_;

    thread_->Stop();
    delete thread_;

    com_android_bluetooth_flags_reset_flags();
    DeleteSnoopLogFiles();
    fake_timerfd_reset();

    const testing::TestInfo* const test_info =
            testing::UnitTest::GetInstance()->current_test_info();
    log::debug("TearDown for test {} in test suite {}.", test_info->name(),
               test_info->test_suite_name());
  }

  static uint32_t GetL2capHeaderSize() { return SnoopLogger::L2CAP_HEADER_SIZE; }
  static size_t GetMaxFilteredSize() {
    return SnoopLogger::MAX_HCI_ACL_LEN - SnoopLogger::PACKET_TYPE_LENGTH;
  }

  std::unique_ptr<SnoopLogger> NewSnoopLogger(
          size_t max_packets_per_file, const std::string& btsnoop_mode,
          bool qualcomm_debug_log_enabled, bool snoop_log_persists,
          std::unique_ptr<SnoopLoggerSocketInterface> socket = nullptr) {
    return std::unique_ptr<SnoopLogger>(
            new SnoopLogger(shared_handler_, std::move(socket), temp_dir_, max_packets_per_file,
                            SnoopLogger::GetMaxPacketsPerBuffer(), btsnoop_mode,
                            qualcomm_debug_log_enabled, 20ms, 5ms, snoop_log_persists));
  }

  void DeleteSnoopLogFiles() {
    if (std::filesystem::exists(temp_snoop_log_)) {
      ASSERT_TRUE(std::filesystem::remove(temp_snoop_log_));
    }
    if (std::filesystem::exists(temp_snoop_log_last_)) {
      ASSERT_TRUE(std::filesystem::remove(temp_snoop_log_last_));
    }
    if (std::filesystem::exists(temp_snoop_log_filtered_)) {
      ASSERT_TRUE(std::filesystem::remove(temp_snoop_log_filtered_));
    }
    if (std::filesystem::exists(temp_snoop_log_filtered_last_)) {
      ASSERT_TRUE(std::filesystem::remove(temp_snoop_log_filtered_last_));
    }
    if (std::filesystem::exists(temp_snooz_log_)) {
      ASSERT_TRUE(std::filesystem::remove(temp_snooz_log_));
    }
    if (std::filesystem::exists(temp_snooz_log_last_)) {
      ASSERT_TRUE(std::filesystem::remove(temp_snooz_log_last_));
    }
  }

  os::Thread* thread_ = nullptr;
  os::Handler* shared_handler_ = nullptr;  // Not necessarily used, depending on flags.
  std::filesystem::path temp_dir_;
  std::filesystem::path temp_snoop_log_;
  std::filesystem::path temp_snoop_log_last_;
  std::filesystem::path temp_snooz_log_;
  std::filesystem::path temp_snooz_log_last_;
  std::filesystem::path temp_snoop_log_filtered_;
  std::filesystem::path temp_snoop_log_filtered_last_;
  std::string test_name_;
};

TEST_F(SnoopLoggerTest, empty_snoop_log_test) {
  // Actual test
  NewSnoopLogger(10, SnoopLogger::kBtSnoopLogModeDisabled, false, false).reset();
  auto snoop_logger = NewSnoopLogger(10, SnoopLogger::kBtSnoopLogModeFull, false, false);
  snoop_logger.reset();

  // Verify states after test
  ASSERT_TRUE(std::filesystem::exists(temp_snoop_log_));
  ASSERT_FALSE(std::filesystem::exists(temp_snoop_log_last_));
  ASSERT_EQ(std::filesystem::file_size(temp_snoop_log_), sizeof(SnoopLoggerCommon::FileHeaderType));
}

TEST_F(SnoopLoggerTest, disable_snoop_log_test) {
  // Actual test
  auto snoop_logger = NewSnoopLogger(10, SnoopLogger::kBtSnoopLogModeDisabled, false, false);
  snoop_logger.reset();

  // Verify states after test
  ASSERT_FALSE(std::filesystem::exists(temp_snoop_log_));
  ASSERT_FALSE(std::filesystem::exists(temp_snoop_log_last_));
  ASSERT_FALSE(std::filesystem::exists(temp_snooz_log_));
}

TEST_F(SnoopLoggerTest, capture_one_packet_test) {
  // Actual test
  auto snoop_logger = NewSnoopLogger(10, SnoopLogger::kBtSnoopLogModeFull, false, false);
  snoop_logger->Capture(kInformationRequest, SnoopLogger::Direction::OUTGOING,
                        SnoopLogger::PacketType::CMD);
  snoop_logger.reset();

  // Verify states after test
  ASSERT_TRUE(std::filesystem::exists(temp_snoop_log_));
  ASSERT_FALSE(std::filesystem::exists(temp_snoop_log_last_));
  ASSERT_EQ(std::filesystem::file_size(temp_snoop_log_),
            sizeof(SnoopLoggerCommon::FileHeaderType) + sizeof(SnoopLoggerFile::PacketHeaderType) +
                    kInformationRequest.size());
}

TEST_F(SnoopLoggerTest, capture_hci_cmd_btsnooz_test) {
  // Actual test
  auto snoop_logger = NewSnoopLogger(10, SnoopLogger::kBtSnoopLogModeDisabled, false, false);
  snoop_logger->Capture(kInformationRequest, SnoopLogger::Direction::OUTGOING,
                        SnoopLogger::PacketType::CMD);
  snoop_logger->DumpSnoozLogToFile();

  ASSERT_TRUE(std::filesystem::exists(temp_snooz_log_));
  ASSERT_EQ(std::filesystem::file_size(temp_snooz_log_),
            sizeof(SnoopLoggerCommon::FileHeaderType) + sizeof(SnoopLoggerFile::PacketHeaderType) +
                    kInformationRequest.size());
  snoop_logger.reset();

  // Verify states after test
  ASSERT_FALSE(std::filesystem::exists(temp_snoop_log_));
  ASSERT_FALSE(std::filesystem::exists(temp_snoop_log_last_));
  ASSERT_FALSE(std::filesystem::exists(temp_snooz_log_));
}

TEST_F(SnoopLoggerTest, capture_l2cap_signal_packet_btsnooz_test) {
  // Actual test
  auto snoop_logger = NewSnoopLogger(10, SnoopLogger::kBtSnoopLogModeDisabled, false, false);
  snoop_logger->Capture(kSdpConnectionRequest, SnoopLogger::Direction::OUTGOING,
                        SnoopLogger::PacketType::ACL);
  snoop_logger->DumpSnoozLogToFile();

  ASSERT_TRUE(std::filesystem::exists(temp_snooz_log_));
  ASSERT_EQ(std::filesystem::file_size(temp_snooz_log_),
            sizeof(SnoopLoggerCommon::FileHeaderType) + sizeof(SnoopLoggerFile::PacketHeaderType) +
                    kSdpConnectionRequest.size());

  snoop_logger.reset();

  // Verify states after test
  ASSERT_FALSE(std::filesystem::exists(temp_snoop_log_));
  ASSERT_FALSE(std::filesystem::exists(temp_snoop_log_last_));
  ASSERT_FALSE(std::filesystem::exists(temp_snooz_log_));
}

TEST_F(SnoopLoggerTest, capture_l2cap_short_data_packet_btsnooz_test) {
  // Actual test
  auto snoop_logger = NewSnoopLogger(10, SnoopLogger::kBtSnoopLogModeDisabled, false, false);
  snoop_logger->Capture(kAvdtpSuspend, SnoopLogger::Direction::OUTGOING,
                        SnoopLogger::PacketType::ACL);
  snoop_logger->DumpSnoozLogToFile();

  ASSERT_TRUE(std::filesystem::exists(temp_snooz_log_));
  ASSERT_EQ(std::filesystem::file_size(temp_snooz_log_),
            sizeof(SnoopLoggerCommon::FileHeaderType) + sizeof(SnoopLoggerFile::PacketHeaderType) +
                    kAvdtpSuspend.size());

  snoop_logger.reset();

  // Verify states after test
  ASSERT_FALSE(std::filesystem::exists(temp_snoop_log_));
  ASSERT_FALSE(std::filesystem::exists(temp_snoop_log_last_));
  ASSERT_FALSE(std::filesystem::exists(temp_snooz_log_));
}

TEST_F(SnoopLoggerTest, capture_l2cap_long_data_packet_btsnooz_test) {
  // Actual test
  auto snoop_logger = NewSnoopLogger(10, SnoopLogger::kBtSnoopLogModeDisabled, false, false);
  snoop_logger->Capture(kHfpAtNrec0, SnoopLogger::Direction::OUTGOING,
                        SnoopLogger::PacketType::ACL);
  snoop_logger->DumpSnoozLogToFile();

  ASSERT_TRUE(std::filesystem::exists(temp_snooz_log_));
  ASSERT_EQ(std::filesystem::file_size(temp_snooz_log_),
            sizeof(SnoopLoggerCommon::FileHeaderType) + sizeof(SnoopLoggerFile::PacketHeaderType) +
                    14);

  snoop_logger.reset();

  // Verify states after test
  ASSERT_FALSE(std::filesystem::exists(temp_snoop_log_));
  ASSERT_FALSE(std::filesystem::exists(temp_snoop_log_last_));
  ASSERT_FALSE(std::filesystem::exists(temp_snooz_log_));
}

TEST_F(SnoopLoggerTest, snoop_log_persists) {
  // Actual test
  auto snoop_logger = NewSnoopLogger(10, SnoopLogger::kBtSnoopLogModeDisabled, false, true);
  snoop_logger->Capture(kHfpAtNrec0, SnoopLogger::Direction::OUTGOING,
                        SnoopLogger::PacketType::ACL);
  snoop_logger->DumpSnoozLogToFile();

  ASSERT_TRUE(std::filesystem::exists(temp_snooz_log_));
  ASSERT_EQ(std::filesystem::file_size(temp_snooz_log_),
            sizeof(SnoopLoggerCommon::FileHeaderType) + sizeof(SnoopLoggerFile::PacketHeaderType) +
                    14);

  snoop_logger.reset();
  ASSERT_TRUE(std::filesystem::exists(temp_snooz_log_));
}

static void sync_handler(bluetooth::os::Handler* handler) {
  std::promise<void> promise;
  auto future = promise.get_future();
  handler->Post(bluetooth::common::BindOnce(&std::promise<void>::set_value,
                                            bluetooth::common::Unretained(&promise)));
  auto future_status = future.wait_for(std::chrono::seconds(1));
  ASSERT_EQ(future_status, std::future_status::ready);
}

TEST_F(SnoopLoggerTest, delete_old_snooz_log_files) {
  // Actual test
  auto snoop_logger = NewSnoopLogger(10, SnoopLogger::kBtSnoopLogModeDisabled, false, false);

  std::filesystem::create_directories(temp_snooz_log_.parent_path());
  os::WriteToFile(temp_snooz_log_.string(), "");

  ASSERT_TRUE(std::filesystem::exists(temp_snooz_log_));
  snoop_logger->GetHandler()->Post(bluetooth::common::BindOnce(fake_timerfd_advance, 10));
  ASSERT_TRUE(std::filesystem::exists(temp_snooz_log_));
  snoop_logger->GetHandler()->Post(bluetooth::common::BindOnce(fake_timerfd_advance, 15));
  sync_handler(snoop_logger->GetHandler());
  snoop_logger->GetHandler()->Post(bluetooth::common::BindOnce(
          [](std::filesystem::path path) {
            log::info("path: {}", path.string());
            ASSERT_FALSE(std::filesystem::exists(path));
          },
          temp_snooz_log_));
  sync_handler(snoop_logger->GetHandler());

  snoop_logger.reset();
  ASSERT_FALSE(std::filesystem::exists(temp_snooz_log_));
}

TEST_F(SnoopLoggerTest, rotate_file_at_new_session_test) {
  // Start once
  {
    auto snoop_logger = NewSnoopLogger(10, SnoopLogger::kBtSnoopLogModeFull, false, false);
    snoop_logger->Capture(kInformationRequest, SnoopLogger::Direction::OUTGOING,
                          SnoopLogger::PacketType::CMD);
    snoop_logger.reset();
  }

  // Verify states after test
  ASSERT_TRUE(std::filesystem::exists(temp_snoop_log_));
  ASSERT_FALSE(std::filesystem::exists(temp_snoop_log_last_));
  ASSERT_EQ(std::filesystem::file_size(temp_snoop_log_),
            sizeof(SnoopLoggerCommon::FileHeaderType) + sizeof(SnoopLoggerFile::PacketHeaderType) +
                    kInformationRequest.size());

  // Start again
  {
    auto snoop_logger = NewSnoopLogger(10, SnoopLogger::kBtSnoopLogModeFull, false, false);
    snoop_logger->Capture(kInformationRequest, SnoopLogger::Direction::OUTGOING,
                          SnoopLogger::PacketType::CMD);
    snoop_logger->Capture(kInformationRequest, SnoopLogger::Direction::OUTGOING,
                          SnoopLogger::PacketType::CMD);
    snoop_logger.reset();
  }

  // Verify states after test
  ASSERT_TRUE(std::filesystem::exists(temp_snoop_log_));
  ASSERT_TRUE(std::filesystem::exists(temp_snoop_log_last_));
  ASSERT_EQ(std::filesystem::file_size(temp_snoop_log_),
            sizeof(SnoopLoggerCommon::FileHeaderType) +
                    (sizeof(SnoopLoggerFile::PacketHeaderType) + kInformationRequest.size()) * 2);
  ASSERT_EQ(std::filesystem::file_size(temp_snoop_log_last_),
            sizeof(SnoopLoggerCommon::FileHeaderType) + sizeof(SnoopLoggerFile::PacketHeaderType) +
                    kInformationRequest.size());
}

TEST_F(SnoopLoggerTest, rotate_file_after_full_test) {
  // Actual test
  auto snoop_logger = NewSnoopLogger(10, SnoopLogger::kBtSnoopLogModeFull, false, false);

  for (int i = 0; i < 11; i++) {
    snoop_logger->Capture(kInformationRequest, SnoopLogger::Direction::OUTGOING,
                          SnoopLogger::PacketType::CMD);
  }

  snoop_logger.reset();

  // Verify states after test
  ASSERT_TRUE(std::filesystem::exists(temp_snoop_log_));
  ASSERT_TRUE(std::filesystem::exists(temp_snoop_log_last_));
  ASSERT_EQ(std::filesystem::file_size(temp_snoop_log_),
            sizeof(SnoopLoggerCommon::FileHeaderType) +
                    (sizeof(SnoopLoggerFile::PacketHeaderType) + kInformationRequest.size()) * 1);
  ASSERT_EQ(std::filesystem::file_size(temp_snoop_log_last_),
            sizeof(SnoopLoggerCommon::FileHeaderType) +
                    (sizeof(SnoopLoggerFile::PacketHeaderType) + kInformationRequest.size()) * 10);
}

TEST_F(SnoopLoggerTest, qualcomm_debug_log_test) {
  auto snoop_logger = NewSnoopLogger(10, SnoopLogger::kBtSnoopLogModeDisabled, true, false);
  snoop_logger->Capture(kQualcommConnectionRequest, SnoopLogger::Direction::OUTGOING,
                        SnoopLogger::PacketType::ACL);
  snoop_logger->DumpSnoozLogToFile();

  ASSERT_TRUE(std::filesystem::exists(temp_snooz_log_));
  ASSERT_EQ(std::filesystem::file_size(temp_snooz_log_),
            sizeof(SnoopLoggerCommon::FileHeaderType) + sizeof(SnoopLoggerFile::PacketHeaderType) +
                    kQualcommConnectionRequest.size());

  snoop_logger.reset();

  // Verify states after test
  ASSERT_FALSE(std::filesystem::exists(temp_snoop_log_));
  ASSERT_FALSE(std::filesystem::exists(temp_snoop_log_last_));
  ASSERT_FALSE(std::filesystem::exists(temp_snooz_log_));
}

TEST_F(SnoopLoggerTest, qualcomm_debug_log_regression_test) {
  {
    auto snoop_logger = NewSnoopLogger(10, SnoopLogger::kBtSnoopLogModeDisabled, true, false);
    snoop_logger->Capture(kHfpAtNrec0, SnoopLogger::Direction::OUTGOING,
                          SnoopLogger::PacketType::ACL);
    snoop_logger->DumpSnoozLogToFile();

    ASSERT_TRUE(std::filesystem::exists(temp_snooz_log_));
    ASSERT_EQ(std::filesystem::file_size(temp_snooz_log_),
              sizeof(SnoopLoggerCommon::FileHeaderType) +
                      sizeof(SnoopLoggerFile::PacketHeaderType) + 14);
    snoop_logger.reset();
  }

  // Verify states after test
  ASSERT_FALSE(std::filesystem::exists(temp_snoop_log_));
  ASSERT_FALSE(std::filesystem::exists(temp_snoop_log_last_));
  ASSERT_FALSE(std::filesystem::exists(temp_snooz_log_));

  {
    auto snoop_logger = NewSnoopLogger(10, SnoopLogger::kBtSnoopLogModeDisabled, false, false);
    snoop_logger->Capture(kQualcommConnectionRequest, SnoopLogger::Direction::OUTGOING,
                          SnoopLogger::PacketType::ACL);
    snoop_logger->DumpSnoozLogToFile();

    ASSERT_TRUE(std::filesystem::exists(temp_snooz_log_));
    ASSERT_EQ(std::filesystem::file_size(temp_snooz_log_),
              sizeof(SnoopLoggerCommon::FileHeaderType) +
                      sizeof(SnoopLoggerFile::PacketHeaderType) + 14);
    snoop_logger.reset();
  }

  // Verify states after test
  ASSERT_FALSE(std::filesystem::exists(temp_snoop_log_));
  ASSERT_FALSE(std::filesystem::exists(temp_snoop_log_last_));
  ASSERT_FALSE(std::filesystem::exists(temp_snooz_log_));
}

TEST_F(SnoopLoggerTest, filter_tracker_test) {
  std::unordered_map<uint16_t, bluetooth::hal::FilterTracker> filter_list;
  uint16_t handle = 1;
  uint16_t local_cid = 0x40;
  uint16_t remote_cid = 0x41;
  uint8_t dlci = 0x02;

  filter_list[handle].AddL2capCid(local_cid, remote_cid);
  ASSERT_TRUE(filter_list[handle].IsAcceptlistedL2cap(true, local_cid));
  ASSERT_TRUE(filter_list[handle].IsAcceptlistedL2cap(false, remote_cid));

  filter_list[handle].RemoveL2capCid(local_cid, remote_cid);
  ASSERT_FALSE(filter_list[handle].IsAcceptlistedL2cap(true, local_cid));
  ASSERT_FALSE(filter_list[handle].IsAcceptlistedL2cap(false, remote_cid));

  filter_list[handle].AddRfcommDlci(dlci);
  ASSERT_TRUE(filter_list[handle].IsAcceptlistedDlci(dlci));

  filter_list[handle].SetRfcommCid(local_cid, remote_cid);
  ASSERT_TRUE(filter_list[handle].IsRfcommChannel(true, local_cid));
  ASSERT_TRUE(filter_list[handle].IsRfcommChannel(false, remote_cid));

  filter_list[handle].RemoveL2capCid(local_cid, remote_cid);
  ASSERT_FALSE(filter_list[handle].IsAcceptlistedL2cap(true, local_cid));
  ASSERT_FALSE(filter_list[handle].IsAcceptlistedL2cap(false, remote_cid));
  ASSERT_FALSE(filter_list[handle].IsAcceptlistedDlci(dlci));
}

TEST_F(SnoopLoggerTest, a2dp_packets_filtered_test) {
  // Actual test
  uint16_t conn_handle = 0x000b;
  uint16_t local_cid = 0x0001;
  uint16_t remote_cid = 0xa040;

  ASSERT_TRUE(bluetooth::os::SetSystemProperty(SnoopLogger::kBtSnoopLogFilterProfileA2dpProperty,
                                               "true"));
  auto filter_a2dp_property =
          bluetooth::os::GetSystemProperty(SnoopLogger::kBtSnoopLogFilterProfileA2dpProperty);
  ASSERT_TRUE(filter_a2dp_property && filter_a2dp_property.value() == "true");

  auto snoop_logger = NewSnoopLogger(10, SnoopLogger::kBtSnoopLogModeFiltered, false, false);

  // Simulate A2dp Media channel setup
  snoop_logger->AddA2dpMediaChannel(conn_handle, local_cid, remote_cid);

  snoop_logger->Capture(kA2dpMediaPacket, SnoopLogger::Direction::OUTGOING,
                        SnoopLogger::PacketType::ACL);

  ASSERT_TRUE(std::filesystem::exists(temp_snoop_log_filtered_));

  snoop_logger.reset();

  ASSERT_TRUE(bluetooth::os::SetSystemProperty(SnoopLogger::kBtSnoopLogFilterProfileA2dpProperty,
                                               "false"));

  // Verify states after test
  ASSERT_TRUE(std::filesystem::exists(temp_snoop_log_filtered_));
  // Should filter packet
  ASSERT_EQ(std::filesystem::file_size(temp_snoop_log_filtered_),
            sizeof(SnoopLoggerCommon::FileHeaderType));
  ASSERT_TRUE(std::filesystem::remove(temp_snoop_log_filtered_));
}

TEST_F(SnoopLoggerTest, a2dp_packets_filtered_negative_test) {
  // Actual test
  uint16_t conn_handle = 0x000b;
  uint16_t local_cid = 0x0001;
  uint16_t remote_cid = 0xa040;

  ASSERT_TRUE(bluetooth::os::SetSystemProperty(SnoopLogger::kBtSnoopLogFilterProfileA2dpProperty,
                                               "true"));
  auto filter_a2dp_property =
          bluetooth::os::GetSystemProperty(SnoopLogger::kBtSnoopLogFilterProfileA2dpProperty);
  ASSERT_TRUE(filter_a2dp_property && filter_a2dp_property.value() == "true");

  auto snoop_logger = NewSnoopLogger(10, SnoopLogger::kBtSnoopLogModeFiltered, false, false);

  // Simulate A2dp Media channel setup
  snoop_logger->AddA2dpMediaChannel(conn_handle, local_cid, remote_cid);
  snoop_logger->RemoveA2dpMediaChannel(conn_handle, local_cid);

  snoop_logger->Capture(kA2dpMediaPacket, SnoopLogger::Direction::OUTGOING,
                        SnoopLogger::PacketType::ACL);

  ASSERT_TRUE(std::filesystem::exists(temp_snoop_log_filtered_));

  snoop_logger.reset();

  ASSERT_TRUE(bluetooth::os::SetSystemProperty(SnoopLogger::kBtSnoopLogFilterProfileA2dpProperty,
                                               "false"));

  // Verify states after test
  ASSERT_TRUE(std::filesystem::exists(temp_snoop_log_filtered_));
  // Should not filter
  ASSERT_EQ(std::filesystem::file_size(temp_snoop_log_filtered_),
            sizeof(SnoopLoggerCommon::FileHeaderType) + sizeof(SnoopLoggerFile::PacketHeaderType) +
                    kA2dpMediaPacket.size());
  ASSERT_TRUE(std::filesystem::remove(temp_snoop_log_filtered_));
}

TEST_F(SnoopLoggerTest, headers_filtered_test) {
  ASSERT_TRUE(
          bluetooth::os::SetSystemProperty(SnoopLogger::kBtSnoopLogFilterHeadersProperty, "true"));
  auto filter_headers_property =
          bluetooth::os::GetSystemProperty(SnoopLogger::kBtSnoopLogFilterHeadersProperty);
  ASSERT_TRUE(filter_headers_property && filter_headers_property.value() == "true");

  auto snoop_logger = NewSnoopLogger(10, SnoopLogger::kBtSnoopLogModeFiltered, false, false);

  std::vector<uint8_t> kAclPacket = {
          0x0b, 0x20, 0x18, 0x00, 0x14, 0x00, 0x44, 0x00, 0x1b, 0x2f, 0x21, 0x41, 0x54, 0x2b,
          0x43, 0x4d, 0x45, 0x52, 0x3d, 0x33, 0x2c, 0x30, 0x2c, 0x30, 0x2c, 0x31, 0x0d, 0x8f,
  };

  snoop_logger->Capture(kAclPacket, SnoopLogger::Direction::INCOMING, SnoopLogger::PacketType::ACL);

  ASSERT_TRUE(std::filesystem::exists(temp_snoop_log_filtered_));

  snoop_logger.reset();

  ASSERT_TRUE(
          bluetooth::os::SetSystemProperty(SnoopLogger::kBtSnoopLogFilterHeadersProperty, "false"));

  // Verify states after test
  ASSERT_TRUE(std::filesystem::exists(temp_snoop_log_filtered_));
  log::info("const size: {}", (int)(sizeof(SnoopLoggerCommon::FileHeaderType) +
                                    sizeof(SnoopLoggerFile::PacketHeaderType)));

  // Packet should be filtered
  const size_t file_size = (size_t)std::filesystem::file_size(temp_snoop_log_filtered_);
  const size_t expected_file_size = sizeof(SnoopLoggerCommon::FileHeaderType) +
                                    sizeof(SnoopLoggerFile::PacketHeaderType) +
                                    GetMaxFilteredSize();
  ASSERT_EQ(file_size, expected_file_size);
  ASSERT_TRUE(std::filesystem::remove(temp_snoop_log_filtered_));
}

TEST_F(SnoopLoggerTest, rfcomm_channel_filtered_sabme_ua_test) {
  // Actual test
  uint16_t conn_handle = 0x000b;
  uint16_t local_cid = 0x0044;
  uint16_t remote_cid = 0x3040;

  ASSERT_TRUE(bluetooth::os::SetSystemProperty(SnoopLogger::kBtSnoopLogFilterProfileRfcommProperty,
                                               "true"));
  auto filter_rfcomm_property =
          bluetooth::os::GetSystemProperty(SnoopLogger::kBtSnoopLogFilterProfileRfcommProperty);
  ASSERT_TRUE(filter_rfcomm_property);
  ASSERT_EQ("true", filter_rfcomm_property.value());

  auto snoop_logger = NewSnoopLogger(10, SnoopLogger::kBtSnoopLogModeFiltered, false, false);

  // Simulate Rfcomm channel
  snoop_logger->AddRfcommL2capChannel(conn_handle, local_cid, remote_cid);
  std::vector<uint8_t> kRfcommSabme = {
          0x0b, 0x20, 0x18, 0x00, 0x14, 0x00, 0x44, 0x00, 0x1b, 0x2f, 0x21, 0x41, 0x54, 0x2b,
          0x43, 0x4d, 0x45, 0x52, 0x3d, 0x33, 0x2c, 0x30, 0x2c, 0x30, 0x2c, 0x31, 0x0d, 0x8f,
  };
  std::vector<uint8_t> kRfcommUa = {
          0x0b, 0x20, 0x18, 0x00, 0x14, 0x00, 0x44, 0x00, 0x1b, 0x63, 0x21, 0x41, 0x54, 0x2b,
          0x43, 0x4d, 0x45, 0x52, 0x3d, 0x33, 0x2c, 0x30, 0x2c, 0x30, 0x2c, 0x31, 0x0d, 0x8f,
  };

  snoop_logger->Capture(kRfcommSabme, SnoopLogger::Direction::INCOMING,
                        SnoopLogger::PacketType::ACL);
  snoop_logger->Capture(kRfcommUa, SnoopLogger::Direction::INCOMING, SnoopLogger::PacketType::ACL);
  snoop_logger->ClearL2capAcceptlist(conn_handle, local_cid, remote_cid);
  ASSERT_TRUE(std::filesystem::exists(temp_snoop_log_filtered_));

  snoop_logger.reset();

  ASSERT_TRUE(bluetooth::os::SetSystemProperty(SnoopLogger::kBtSnoopLogFilterProfileRfcommProperty,
                                               "false"));

  // Verify states after test
  ASSERT_TRUE(std::filesystem::exists(temp_snoop_log_filtered_));

  // Packets should not be filtered because because they are SAMBE and UA events.
  ASSERT_EQ(std::filesystem::file_size(temp_snoop_log_filtered_),
            sizeof(SnoopLoggerCommon::FileHeaderType) +
                    2 * sizeof(SnoopLoggerFile::PacketHeaderType) + kRfcommSabme.size() +
                    kRfcommUa.size());
  ASSERT_TRUE(std::filesystem::remove(temp_snoop_log_filtered_));
}

TEST_F(SnoopLoggerTest, rfcomm_channel_filtered_acceptlisted_dlci_test) {
  // Actual test
  uint16_t conn_handle = 0x000b;
  uint16_t local_cid = 0x0041;
  uint16_t remote_cid = 0x3040;
  uint8_t dlci = 0x04;
  uint8_t dlci_byte = dlci << 2;

  ASSERT_TRUE(bluetooth::os::SetSystemProperty(SnoopLogger::kBtSnoopLogFilterProfileRfcommProperty,
                                               "true"));
  auto filter_rfcomm_property =
          bluetooth::os::GetSystemProperty(SnoopLogger::kBtSnoopLogFilterProfileRfcommProperty);
  ASSERT_TRUE(filter_rfcomm_property);
  ASSERT_EQ("true", filter_rfcomm_property.value());

  auto snoop_logger = NewSnoopLogger(10, SnoopLogger::kBtSnoopLogModeFiltered, false, false);

  // Simulate Rfcomm channel
  snoop_logger->AddRfcommL2capChannel(conn_handle, local_cid, remote_cid);
  snoop_logger->AcceptlistRfcommDlci(conn_handle, local_cid, dlci);

  std::vector<uint8_t> kRfcommDlci = {
          0x0b, 0x20, 0x12, 0x00, 0x0e, 0x00, 0x41, 0x00, dlci_byte, 0xef, 0x15,
          0x83, 0x11, 0x06, 0xf0, 0x07, 0x00, 0x9d, 0x02, 0x00,      0x07, 0x70,
  };

  snoop_logger->Capture(kRfcommDlci, SnoopLogger::Direction::INCOMING,
                        SnoopLogger::PacketType::ACL);
  snoop_logger->ClearL2capAcceptlist(conn_handle, local_cid, remote_cid);
  ASSERT_TRUE(std::filesystem::exists(temp_snoop_log_filtered_));

  snoop_logger.reset();

  ASSERT_TRUE(bluetooth::os::SetSystemProperty(SnoopLogger::kBtSnoopLogFilterProfileRfcommProperty,
                                               "false"));

  // Verify states after test
  ASSERT_TRUE(std::filesystem::exists(temp_snoop_log_filtered_));

  // Packet should not be filtered because DLCI acceptlisted
  ASSERT_EQ(std::filesystem::file_size(temp_snoop_log_filtered_),
            sizeof(SnoopLoggerCommon::FileHeaderType) + sizeof(SnoopLoggerFile::PacketHeaderType) +
                    kRfcommDlci.size());
  ASSERT_TRUE(std::filesystem::remove(temp_snoop_log_filtered_));
}

TEST_F(SnoopLoggerTest, rfcomm_channel_filtered_not_acceptlisted_dlci_test) {
  // Actual test
  uint16_t conn_handle = 0x000b;
  uint16_t local_cid = 0x0041;
  uint16_t remote_cid = 0x3040;
  uint8_t dlci = 0x04;
  uint8_t dlci_byte = dlci << 2;

  ASSERT_TRUE(bluetooth::os::SetSystemProperty(SnoopLogger::kBtSnoopLogFilterProfileRfcommProperty,
                                               "true"));
  auto filter_rfcomm_property =
          bluetooth::os::GetSystemProperty(SnoopLogger::kBtSnoopLogFilterProfileRfcommProperty);
  ASSERT_TRUE(filter_rfcomm_property);
  ASSERT_EQ("true", filter_rfcomm_property.value());

  auto snoop_logger = NewSnoopLogger(10, SnoopLogger::kBtSnoopLogModeFiltered, false, false);

  // Simulate Rfcomm channel
  snoop_logger->AddRfcommL2capChannel(conn_handle, local_cid, remote_cid);

  std::vector<uint8_t> kRfcommDlci = {
          0x0b, 0x20, 0x12, 0x00, 0x0e, 0x00, 0x41, 0x00, dlci_byte, 0xef, 0x15,
          0x83, 0x11, 0x06, 0xf0, 0x07, 0x00, 0x9d, 0x02, 0x00,      0x07, 0x70,
  };

  snoop_logger->Capture(kRfcommDlci, SnoopLogger::Direction::INCOMING,
                        SnoopLogger::PacketType::ACL);
  snoop_logger->ClearL2capAcceptlist(conn_handle, local_cid, remote_cid);

  ASSERT_TRUE(std::filesystem::exists(temp_snoop_log_filtered_));

  snoop_logger.reset();

  ASSERT_TRUE(bluetooth::os::SetSystemProperty(SnoopLogger::kBtSnoopLogFilterProfileRfcommProperty,
                                               "false"));

  // Verify states after test
  ASSERT_TRUE(std::filesystem::exists(temp_snoop_log_filtered_));

  // Packet should be filtered because DLCI not acceptlisted
  ASSERT_EQ(std::filesystem::file_size(temp_snoop_log_filtered_),
            sizeof(SnoopLoggerCommon::FileHeaderType) + sizeof(SnoopLoggerFile::PacketHeaderType) +
                    GetL2capHeaderSize());
  ASSERT_TRUE(std::filesystem::remove(temp_snoop_log_filtered_));
}

TEST_F(SnoopLoggerTest, rfcomm_channel_filtered_not_acceptlisted_l2cap_channel_test) {
  // Actual test
  uint16_t conn_handle = 0x000b;
  uint16_t local_cid = 0x0041;
  uint16_t remote_cid = 0x3040;

  ASSERT_TRUE(bluetooth::os::SetSystemProperty(SnoopLogger::kBtSnoopLogFilterProfileRfcommProperty,
                                               "true"));
  auto filter_rfcomm_property =
          bluetooth::os::GetSystemProperty(SnoopLogger::kBtSnoopLogFilterProfileRfcommProperty);
  ASSERT_TRUE(filter_rfcomm_property);
  ASSERT_EQ("true", filter_rfcomm_property.value());

  auto snoop_logger = NewSnoopLogger(10, SnoopLogger::kBtSnoopLogModeFiltered, false, false);

  std::vector<uint8_t> kRfcommL2capChannel = {
          0x0b, 0x20, 0x12, 0x00, 0x0e, 0x00, 0x41, 0x00, 0x00, 0xef, 0x15,
          0x83, 0x11, 0x06, 0xf0, 0x07, 0x00, 0x9d, 0x02, 0x00, 0x07, 0x70,
  };

  snoop_logger->Capture(kRfcommL2capChannel, SnoopLogger::Direction::INCOMING,
                        SnoopLogger::PacketType::ACL);
  snoop_logger->ClearL2capAcceptlist(conn_handle, local_cid, remote_cid);

  ASSERT_TRUE(std::filesystem::exists(temp_snoop_log_filtered_));

  snoop_logger.reset();

  ASSERT_TRUE(bluetooth::os::SetSystemProperty(SnoopLogger::kBtSnoopLogFilterProfileRfcommProperty,
                                               "false"));

  // Verify states after test
  ASSERT_TRUE(std::filesystem::exists(temp_snoop_log_filtered_));

  // Packet should be filtered because L2CAP channel not acceptlisted
  ASSERT_EQ(std::filesystem::file_size(temp_snoop_log_filtered_),
            sizeof(SnoopLoggerCommon::FileHeaderType) + sizeof(SnoopLoggerFile::PacketHeaderType) +
                    GetL2capHeaderSize());
  ASSERT_TRUE(std::filesystem::remove(temp_snoop_log_filtered_));
}

TEST_F(SnoopLoggerTest, rfcomm_channel_filtered_acceptlisted_l2cap_channel_test) {
  // Actual test
  uint16_t conn_handle = 0x000b;
  uint16_t local_cid = 0x0041;
  uint16_t remote_cid = 0x3040;

  ASSERT_TRUE(bluetooth::os::SetSystemProperty(SnoopLogger::kBtSnoopLogFilterProfileRfcommProperty,
                                               "true"));
  auto filter_rfcomm_property =
          bluetooth::os::GetSystemProperty(SnoopLogger::kBtSnoopLogFilterProfileRfcommProperty);
  ASSERT_TRUE(filter_rfcomm_property);
  ASSERT_EQ("true", filter_rfcomm_property.value());

  auto snoop_logger = NewSnoopLogger(10, SnoopLogger::kBtSnoopLogModeFiltered, false, false);

  snoop_logger->AcceptlistL2capChannel(conn_handle, local_cid, remote_cid);

  std::vector<uint8_t> kRfcommL2capChannel = {
          0x0b, 0x20, 0x12, 0x00, 0x0e, 0x00, 0x41, 0x00, 0x00, 0xef, 0x15,
          0x83, 0x11, 0x06, 0xf0, 0x07, 0x00, 0x9d, 0x02, 0x00, 0x07, 0x70,
  };

  snoop_logger->Capture(kRfcommL2capChannel, SnoopLogger::Direction::INCOMING,
                        SnoopLogger::PacketType::ACL);
  snoop_logger->ClearL2capAcceptlist(conn_handle, local_cid, remote_cid);

  ASSERT_TRUE(std::filesystem::exists(temp_snoop_log_filtered_));

  snoop_logger.reset();

  ASSERT_TRUE(bluetooth::os::SetSystemProperty(SnoopLogger::kBtSnoopLogFilterProfileRfcommProperty,
                                               "false"));

  // Verify states after test
  ASSERT_TRUE(std::filesystem::exists(temp_snoop_log_filtered_));

  // Packet should not be filtered because L2CAP channel acceptlisted
  ASSERT_EQ(std::filesystem::file_size(temp_snoop_log_filtered_),
            sizeof(SnoopLoggerCommon::FileHeaderType) + sizeof(SnoopLoggerFile::PacketHeaderType) +
                    kRfcommL2capChannel.size());
  ASSERT_TRUE(std::filesystem::remove(temp_snoop_log_filtered_));
}

TEST_F(SnoopLoggerTest, profiles_filtered_hfp_hf_test) {
  // Actual test
  uint16_t conn_handle = 0x000b;
  uint16_t local_cid = 0x0043;
  uint16_t remote_cid = 0x3040;
  uint8_t dlci = 0x06;
  uint16_t psm = 0x0003;
  uint16_t profile_uuid_hfp_hf = 0x111f;
  bool flow = true;

  const std::string clcc_pattern = "\x0d\x0a+CLCC:";
  const uint16_t HEADER_SIZE = 12;

  // Set pbap and map filtering modes
  ASSERT_TRUE(
          bluetooth::os::SetSystemProperty(SnoopLogger::kBtSnoopLogFilterProfilePbapModeProperty,
                                           SnoopLogger::kBtSnoopLogFilterProfileModeMagic));
  auto filterPbapModeProperty =
          bluetooth::os::GetSystemProperty(SnoopLogger::kBtSnoopLogFilterProfilePbapModeProperty);
  ASSERT_TRUE(filterPbapModeProperty &&
              (filterPbapModeProperty->find(SnoopLogger::kBtSnoopLogFilterProfileModeMagic) !=
               std::string::npos));
  ASSERT_TRUE(bluetooth::os::SetSystemProperty(SnoopLogger::kBtSnoopLogFilterProfileMapModeProperty,
                                               SnoopLogger::kBtSnoopLogFilterProfileModeMagic));
  auto filterMapModeProperty =
          bluetooth::os::GetSystemProperty(SnoopLogger::kBtSnoopLogFilterProfileMapModeProperty);
  ASSERT_TRUE(filterMapModeProperty &&
              (filterMapModeProperty->find(SnoopLogger::kBtSnoopLogFilterProfileModeMagic) !=
               std::string::npos));

  auto snoop_logger = NewSnoopLogger(10, SnoopLogger::kBtSnoopLogModeFiltered, false, false);

  snoop_logger->SetL2capChannelOpen(conn_handle, local_cid, remote_cid, psm, false);
  snoop_logger->SetRfcommPortOpen(conn_handle, local_cid, dlci, profile_uuid_hfp_hf, flow);

  std::vector<uint8_t> kPhoneNumber = {
          0x0b, 0x00, 0x30, 0x00, 0x2c, 0x00, 0x40, 0x30, 0x19, 0xff, 0x4f, 0x01, 0x0d,
          0x0a, 0x2b, 0x43, 0x4c, 0x43, 0x43, 0x3a, 0x20, 0x31, 0x2c, 0x31, 0x2c, 0x34,
          0x2c, 0x30, 0x2c, 0x30, 0x2c, 0x22, 0x2b, 0x39, 0x39, 0x31, 0x32, 0x33, 0x34,
          0x35, 0x36, 0x37, 0x38, 0x39, 0x22, 0x2c, 0x31, 0x34, 0x35, 0x0d, 0x0a, 0x49,
  };

  snoop_logger->Capture(kPhoneNumber, SnoopLogger::Direction::OUTGOING,
                        SnoopLogger::PacketType::ACL);
  snoop_logger->SetL2capChannelClose(conn_handle, local_cid, remote_cid);
  snoop_logger->SetRfcommPortClose(conn_handle, local_cid, dlci, profile_uuid_hfp_hf);

  ASSERT_TRUE(std::filesystem::exists(temp_snoop_log_filtered_));

  snoop_logger.reset();

  ASSERT_TRUE(bluetooth::os::SetSystemProperty(SnoopLogger::kBtSnoopLogFilterProfileMapModeProperty,
                                               SnoopLogger::kBtSnoopLogFilterProfileModeDisabled));
  ASSERT_TRUE(
          bluetooth::os::SetSystemProperty(SnoopLogger::kBtSnoopLogFilterProfilePbapModeProperty,
                                           SnoopLogger::kBtSnoopLogFilterProfileModeDisabled));

  // Verify states after test
  ASSERT_TRUE(std::filesystem::exists(temp_snoop_log_filtered_));

  // Packet should be filtered
  ASSERT_EQ(std::filesystem::file_size(temp_snoop_log_filtered_),
            sizeof(SnoopLoggerCommon::FileHeaderType) + sizeof(SnoopLoggerFile::PacketHeaderType) +
                    HEADER_SIZE + strlen(clcc_pattern.c_str()));
  ASSERT_TRUE(std::filesystem::remove(temp_snoop_log_filtered_));
}

TEST_F(SnoopLoggerTest, profiles_filtered_pbap_magic_test) {
  // Actual test
  constexpr uint16_t PROFILE_PSM_PBAP = 0x1025;
  constexpr uint16_t PROFILE_UUID_PBAP = 0x112f;
  uint16_t conn_handle = 0x0002;
  uint16_t local_cid = 0x0041;
  uint16_t remote_cid = 0x0040;
  uint8_t dlci = 0x27;
  uint16_t psm = PROFILE_PSM_PBAP;
  uint16_t profile_uuid_pbap = PROFILE_UUID_PBAP;
  bool flow = true;
  const std::string magic_string = "PROHIBITED";
  const uint16_t HEADER_SIZE = 8;

  // Set pbap and map filtering modes
  ASSERT_TRUE(
          bluetooth::os::SetSystemProperty(SnoopLogger::kBtSnoopLogFilterProfilePbapModeProperty,
                                           SnoopLogger::kBtSnoopLogFilterProfileModeMagic));
  auto filterPbapModeProperty =
          bluetooth::os::GetSystemProperty(SnoopLogger::kBtSnoopLogFilterProfilePbapModeProperty);
  ASSERT_TRUE(filterPbapModeProperty &&
              (filterPbapModeProperty->find(SnoopLogger::kBtSnoopLogFilterProfileModeMagic) !=
               std::string::npos));
  ASSERT_TRUE(bluetooth::os::SetSystemProperty(SnoopLogger::kBtSnoopLogFilterProfileMapModeProperty,
                                               SnoopLogger::kBtSnoopLogFilterProfileModeMagic));
  auto filterMapModeProperty =
          bluetooth::os::GetSystemProperty(SnoopLogger::kBtSnoopLogFilterProfileMapModeProperty);
  ASSERT_TRUE(filterMapModeProperty &&
              (filterMapModeProperty->find(SnoopLogger::kBtSnoopLogFilterProfileModeMagic) !=
               std::string::npos));

  auto snoop_logger = NewSnoopLogger(20, SnoopLogger::kBtSnoopLogModeFiltered, false, false);

  snoop_logger->SetL2capChannelOpen(conn_handle, local_cid, remote_cid, psm, false);
  snoop_logger->SetRfcommPortOpen(conn_handle, local_cid, dlci, profile_uuid_pbap, flow);

  for (int i = 0; i < (int)kTestData.size(); i++) {
    snoop_logger->Capture(kTestData[i], (SnoopLogger::Direction)(i % 2),
                          SnoopLogger::PacketType::ACL);
  }

  snoop_logger->SetL2capChannelClose(conn_handle, local_cid, remote_cid);
  snoop_logger->SetRfcommPortClose(conn_handle, local_cid, dlci, profile_uuid_pbap);

  ASSERT_TRUE(std::filesystem::exists(temp_snoop_log_filtered_));

  snoop_logger.reset();

  ASSERT_TRUE(bluetooth::os::SetSystemProperty(SnoopLogger::kBtSnoopLogFilterProfileMapModeProperty,
                                               SnoopLogger::kBtSnoopLogFilterProfileModeDisabled));
  ASSERT_TRUE(
          bluetooth::os::SetSystemProperty(SnoopLogger::kBtSnoopLogFilterProfilePbapModeProperty,
                                           SnoopLogger::kBtSnoopLogFilterProfileModeDisabled));

  // Verify states after test
  ASSERT_TRUE(std::filesystem::exists(temp_snoop_log_filtered_));

  // Packets should be filtered
  ASSERT_EQ(std::filesystem::file_size(temp_snoop_log_filtered_),
            sizeof(SnoopLoggerCommon::FileHeaderType) +
                    (int)kTestData.size() * (sizeof(SnoopLoggerFile::PacketHeaderType) +
                                             HEADER_SIZE + strlen(magic_string.c_str())));

  ASSERT_TRUE(std::filesystem::remove(temp_snoop_log_filtered_));
}

TEST_F(SnoopLoggerTest, profiles_filtered_pbap_header_test) {
  // Actual test
  constexpr uint16_t PROFILE_PSM_PBAP = 0x1025;
  constexpr uint16_t PROFILE_UUID_PBAP = 0x112f;
  uint16_t conn_handle = 0x0002;
  uint16_t local_cid = 0x0041;
  uint16_t remote_cid = 0x0040;
  uint8_t dlci = 0x27;
  uint16_t psm = PROFILE_PSM_PBAP;
  uint16_t profile_uuid_pbap = PROFILE_UUID_PBAP;
  bool flow = true;
  const uint16_t HEADER_SIZE = 8;

  // Set pbap and map filtering modes
  ASSERT_TRUE(
          bluetooth::os::SetSystemProperty(SnoopLogger::kBtSnoopLogFilterProfilePbapModeProperty,
                                           SnoopLogger::kBtSnoopLogFilterProfileModeHeader));
  auto filterPbapModeProperty =
          bluetooth::os::GetSystemProperty(SnoopLogger::kBtSnoopLogFilterProfilePbapModeProperty);
  ASSERT_TRUE(filterPbapModeProperty &&
              (filterPbapModeProperty->find(SnoopLogger::kBtSnoopLogFilterProfileModeHeader) !=
               std::string::npos));
  ASSERT_TRUE(bluetooth::os::SetSystemProperty(SnoopLogger::kBtSnoopLogFilterProfileMapModeProperty,
                                               SnoopLogger::kBtSnoopLogFilterProfileModeHeader));
  auto filterMapModeProperty =
          bluetooth::os::GetSystemProperty(SnoopLogger::kBtSnoopLogFilterProfileMapModeProperty);
  ASSERT_TRUE(filterMapModeProperty &&
              (filterMapModeProperty->find(SnoopLogger::kBtSnoopLogFilterProfileModeHeader) !=
               std::string::npos));

  auto snoop_logger = NewSnoopLogger(20, SnoopLogger::kBtSnoopLogModeFiltered, false, false);

  snoop_logger->SetL2capChannelOpen(conn_handle, local_cid, remote_cid, psm, false);
  snoop_logger->SetRfcommPortOpen(conn_handle, local_cid, dlci, profile_uuid_pbap, flow);

  for (int i = 0; i < (int)kTestData.size(); i++) {
    snoop_logger->Capture(kTestData[i], (SnoopLogger::Direction)(i % 2),
                          SnoopLogger::PacketType::ACL);
  }

  snoop_logger->SetL2capChannelClose(conn_handle, local_cid, remote_cid);
  snoop_logger->SetRfcommPortClose(conn_handle, local_cid, dlci, profile_uuid_pbap);

  ASSERT_TRUE(std::filesystem::exists(temp_snoop_log_filtered_));

  snoop_logger.reset();

  ASSERT_TRUE(bluetooth::os::SetSystemProperty(SnoopLogger::kBtSnoopLogFilterProfileMapModeProperty,
                                               SnoopLogger::kBtSnoopLogFilterProfileModeDisabled));
  ASSERT_TRUE(
          bluetooth::os::SetSystemProperty(SnoopLogger::kBtSnoopLogFilterProfilePbapModeProperty,
                                           SnoopLogger::kBtSnoopLogFilterProfileModeDisabled));

  // Verify states after test
  ASSERT_TRUE(std::filesystem::exists(temp_snoop_log_filtered_));

  // Packets should be filtered
  ASSERT_EQ(std::filesystem::file_size(temp_snoop_log_filtered_),
            sizeof(SnoopLoggerCommon::FileHeaderType) +
                    (int)kTestData.size() *
                            (sizeof(SnoopLoggerFile::PacketHeaderType) + HEADER_SIZE));

  ASSERT_TRUE(std::filesystem::remove(temp_snoop_log_filtered_));
}

TEST_F(SnoopLoggerTest, profiles_filtered_pbap_fullfilter_test) {
  // Actual test
  constexpr uint16_t PROFILE_PSM_PBAP = 0x1025;
  constexpr uint16_t PROFILE_UUID_PBAP = 0x112f;
  uint16_t conn_handle = 0x0002;
  uint16_t local_cid = 0x0041;
  uint16_t remote_cid = 0x0040;
  uint8_t dlci = 0x27;
  uint16_t psm = PROFILE_PSM_PBAP;
  uint16_t profile_uuid_pbap = PROFILE_UUID_PBAP;
  bool flow = true;

  // Set pbap and map filtering modes
  ASSERT_TRUE(
          bluetooth::os::SetSystemProperty(SnoopLogger::kBtSnoopLogFilterProfilePbapModeProperty,
                                           SnoopLogger::kBtSnoopLogFilterProfileModeFullfillter));
  auto filterPbapModeProperty =
          bluetooth::os::GetSystemProperty(SnoopLogger::kBtSnoopLogFilterProfilePbapModeProperty);
  ASSERT_TRUE(filterPbapModeProperty &&
              (filterPbapModeProperty->find(SnoopLogger::kBtSnoopLogFilterProfileModeFullfillter) !=
               std::string::npos));
  ASSERT_TRUE(
          bluetooth::os::SetSystemProperty(SnoopLogger::kBtSnoopLogFilterProfileMapModeProperty,
                                           SnoopLogger::kBtSnoopLogFilterProfileModeFullfillter));
  auto filterMapModeProperty =
          bluetooth::os::GetSystemProperty(SnoopLogger::kBtSnoopLogFilterProfileMapModeProperty);
  ASSERT_TRUE(filterMapModeProperty &&
              (filterMapModeProperty->find(SnoopLogger::kBtSnoopLogFilterProfileModeFullfillter) !=
               std::string::npos));

  auto snoop_logger = NewSnoopLogger(20, SnoopLogger::kBtSnoopLogModeFiltered, false, false);

  snoop_logger->SetL2capChannelOpen(conn_handle, local_cid, remote_cid, psm, false);
  snoop_logger->SetRfcommPortOpen(conn_handle, local_cid, dlci, profile_uuid_pbap, flow);

  for (int i = 0; i < (int)kTestData.size(); i++) {
    snoop_logger->Capture(kTestData[i], (SnoopLogger::Direction)(i % 2),
                          SnoopLogger::PacketType::ACL);
  }

  snoop_logger->SetL2capChannelClose(conn_handle, local_cid, remote_cid);
  snoop_logger->SetRfcommPortClose(conn_handle, local_cid, dlci, profile_uuid_pbap);

  ASSERT_TRUE(std::filesystem::exists(temp_snoop_log_filtered_));

  snoop_logger.reset();

  ASSERT_TRUE(bluetooth::os::SetSystemProperty(SnoopLogger::kBtSnoopLogFilterProfileMapModeProperty,
                                               SnoopLogger::kBtSnoopLogFilterProfileModeDisabled));
  ASSERT_TRUE(
          bluetooth::os::SetSystemProperty(SnoopLogger::kBtSnoopLogFilterProfilePbapModeProperty,
                                           SnoopLogger::kBtSnoopLogFilterProfileModeDisabled));

  // Verify states after test
  ASSERT_TRUE(std::filesystem::exists(temp_snoop_log_filtered_));

  // Packets should be filtered
  ASSERT_EQ(std::filesystem::file_size(temp_snoop_log_filtered_),
            sizeof(SnoopLoggerCommon::FileHeaderType));

  ASSERT_TRUE(std::filesystem::remove(temp_snoop_log_filtered_));
}

static constexpr int INVALID_FD = -1;

TEST_F(SnoopLoggerTest, default_socket_enabled_capture_recv_test) {
  auto* socket = new MockSnoopLoggerSocket();

  // The packet header has fields with variable value.
  // Match the first two fields and the total header length.
  const SnoopLoggerFile::PacketHeaderType packet_header{
          .length_original = htonl(static_cast<uint32_t>(1 + kHfpAtNrec0.size())),
          .length_captured = htonl(static_cast<uint32_t>(1 + kHfpAtNrec0.size())),
  };

  EXPECT_CALL(*socket, Write(MemEq(&packet_header, 8), sizeof(packet_header)));
  EXPECT_CALL(*socket, Write(MemEq(kHfpAtNrec0.data(), kHfpAtNrec0.size()), kHfpAtNrec0.size()));

  auto snoop_logger = NewSnoopLogger(10, SnoopLogger::kBtSnoopLogModeFull, true, false,
                                     std::unique_ptr<SnoopLoggerSocketInterface>(socket));
  snoop_logger->Capture(kHfpAtNrec0, SnoopLogger::Direction::OUTGOING,
                        SnoopLogger::PacketType::ACL);
}

TEST_F(SnoopLoggerTest, custom_socket_profiles_filtered_hfp_hf_test) {
  uint16_t conn_handle = 0x000b;
  uint16_t local_cid = 0x0043;
  uint16_t remote_cid = 0x3040;
  uint8_t dlci = 0x02;
  uint16_t psm = 0x0003;
  uint16_t profile_uuid_hfp_hf = 0x111f;
  bool flow = true;
  const std::string clcc_pattern = "\x0d\x0a+CLCC:";
  const uint16_t HEADER_SIZE = 12;
  size_t expected_data_size = HEADER_SIZE + strlen(clcc_pattern.c_str());

  std::vector<uint8_t> kPhoneNumber = {
          0x0b, 0x00, 0x30, 0x00,  // ACL Header (Handle: 0x000b, PB flag: 0x00, Length: 48)
          0x2c, 0x00, 0x40, 0x30,  // L2CAP Header (Length: 44, CID: 0x3040)
          0x0b, 0xff, 0x4f, 0x01,  // RFCOMM
          // "\r\n+CLCC: 1,1,4,0,0,"+99123456789",145\r\n"
          0x0d, 0x0a, 0x2b, 0x43, 0x4c, 0x43, 0x43, 0x3a, 0x20, 0x31, 0x2c, 0x31, 0x2c, 0x34, 0x2c,
          0x30, 0x2c, 0x30, 0x2c, 0x22, 0x2b, 0x39, 0x39, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
          0x38, 0x39, 0x22, 0x2c, 0x31, 0x34, 0x35, 0x0d, 0x0a,
          0x86  // RFCOMM
  };

  std::vector<uint8_t> kExpectedPhoneNumber = {
          0x0b, 0x00, 0x10, 0x00,  // ACL Header (Handle: 0x000b, PB flag: 0x00, Length: 16)
          0x0c, 0x00, 0x40, 0x30,  // L2CAP Header (Length: 12, CID: 0x3040)
          0x0b, 0xff, 0x4f, 0x01,  // RFCOMM
          // "\r\n+CLCC:"
          0x0d, 0x0a, 0x2b, 0x43, 0x4c, 0x43, 0x43, 0x3a};

  // Set pbap and map filtering modes
  ASSERT_TRUE(
          bluetooth::os::SetSystemProperty(SnoopLogger::kBtSnoopLogFilterProfilePbapModeProperty,
                                           SnoopLogger::kBtSnoopLogFilterProfileModeMagic));
  auto filterPbapModeProperty =
          bluetooth::os::GetSystemProperty(SnoopLogger::kBtSnoopLogFilterProfilePbapModeProperty);
  ASSERT_TRUE(filterPbapModeProperty &&
              (filterPbapModeProperty->find(SnoopLogger::kBtSnoopLogFilterProfileModeMagic) !=
               std::string::npos));
  ASSERT_TRUE(bluetooth::os::SetSystemProperty(SnoopLogger::kBtSnoopLogFilterProfileMapModeProperty,
                                               SnoopLogger::kBtSnoopLogFilterProfileModeMagic));
  auto filterMapModeProperty =
          bluetooth::os::GetSystemProperty(SnoopLogger::kBtSnoopLogFilterProfileMapModeProperty);
  ASSERT_TRUE(filterMapModeProperty &&
              (filterMapModeProperty->find(SnoopLogger::kBtSnoopLogFilterProfileModeMagic) !=
               std::string::npos));

  auto* socket = new MockSnoopLoggerSocket();

  // The packet header has fields with variable value.
  // Match the first two fields and the total header length.
  const SnoopLoggerFile::PacketHeaderType packet_header{
          .length_original = htonl(static_cast<uint32_t>(1 + kPhoneNumber.size())),
          .length_captured = htonl(static_cast<uint32_t>(1 + kExpectedPhoneNumber.size())),
  };

  EXPECT_CALL(*socket, Write(MemEq(&packet_header, 8), sizeof(packet_header)));
  EXPECT_CALL(*socket, Write(MemEq(kExpectedPhoneNumber.data(), kExpectedPhoneNumber.size()),
                             kExpectedPhoneNumber.size()));

  auto snoop_logger = NewSnoopLogger(10, SnoopLogger::kBtSnoopLogModeFiltered, false, false,
                                     std::unique_ptr<SnoopLoggerSocketInterface>(socket));

  snoop_logger->SetL2capChannelOpen(conn_handle, local_cid, remote_cid, psm, false);
  snoop_logger->SetRfcommPortOpen(conn_handle, local_cid, dlci, profile_uuid_hfp_hf, flow);

  snoop_logger->Capture(kPhoneNumber, SnoopLogger::Direction::OUTGOING,
                        SnoopLogger::PacketType::ACL);

  snoop_logger->SetL2capChannelClose(conn_handle, local_cid, remote_cid);
  snoop_logger->SetRfcommPortClose(conn_handle, local_cid, dlci, profile_uuid_hfp_hf);

  ASSERT_TRUE(bluetooth::os::SetSystemProperty(SnoopLogger::kBtSnoopLogFilterProfileMapModeProperty,
                                               SnoopLogger::kBtSnoopLogFilterProfileModeDisabled));
  ASSERT_TRUE(
          bluetooth::os::SetSystemProperty(SnoopLogger::kBtSnoopLogFilterProfilePbapModeProperty,
                                           SnoopLogger::kBtSnoopLogFilterProfileModeDisabled));
}

#ifdef __ANDROID__
TEST_F(SnoopLoggerTest, recreate_log_directory_when_enabled_test) {
  temp_dir_ = os::ParameterProvider::SnoopLogDirPath();

  // Override the paths used for the test. The feature tested here relies on the actual
  // snoop path on Android to work.
  temp_snoop_log_ = temp_dir_ / "btsnoop_hci.log";
  temp_snoop_log_last_ = temp_dir_ / "btsnoop_hci.log.last";
  temp_snooz_log_ = temp_dir_ / "btsnooz_hci.log";
  temp_snooz_log_last_ = temp_dir_ / "btsnooz_hci.log.last";
  temp_snoop_log_filtered_ = temp_dir_ / "btsnoop_hci.log.filtered";
  temp_snoop_log_filtered_last_ = temp_dir_ / "btsnoop_hci.log.filtered.last";
  DeleteSnoopLogFiles();
  std::filesystem::remove_all(temp_dir_);

  ASSERT_FALSE(std::filesystem::exists(temp_dir_));

  auto snoop_logger = NewSnoopLogger(10, SnoopLogger::kBtSnoopLogModeFull, false, false);

  ASSERT_TRUE(std::filesystem::exists(temp_dir_));

  snoop_logger.reset();

  // btsnoop file should exist, but btsnooz should be removed as snoop_log_persist is false.
  ASSERT_TRUE(std::filesystem::exists(temp_snoop_log_));
  ASSERT_FALSE(std::filesystem::exists(temp_snooz_log_));
}

TEST_F(SnoopLoggerTest, recreate_log_directory_when_filtered_test) {
  temp_dir_ = os::ParameterProvider::SnoopLogDirPath();

  // Override the paths used for the test. The feature tested here relies on the actual
  // snoop path on Android to work.
  temp_snoop_log_ = temp_dir_ / "btsnoop_hci.log";
  temp_snoop_log_last_ = temp_dir_ / "btsnoop_hci.log.last";
  temp_snooz_log_ = temp_dir_ / "btsnooz_hci.log";
  temp_snooz_log_last_ = temp_dir_ / "btsnooz_hci.log.last";
  temp_snoop_log_filtered_ = temp_dir_ / "btsnoop_hci.log.filtered";
  temp_snoop_log_filtered_last_ = temp_dir_ / "btsnoop_hci.log.filtered.last";
  DeleteSnoopLogFiles();
  std::filesystem::remove_all(temp_dir_);

  ASSERT_FALSE(std::filesystem::exists(temp_dir_));

  auto snoop_logger = NewSnoopLogger(10, SnoopLogger::kBtSnoopLogModeFiltered, false, false);

  ASSERT_TRUE(std::filesystem::exists(temp_dir_));

  snoop_logger.reset();

  // btsnoop file should exist.
  ASSERT_TRUE(std::filesystem::exists(temp_snoop_log_filtered_));
}

// Test that DumpSnoozLogToFile recreates the log directory if it has been
// removed. This is particularly relevant for snooz (disabled mode), where the
// directory is not created at startup but only when the snooz log is dumped.
TEST_F(SnoopLoggerTest, recreate_log_directory_on_dump_test) {
  // Clean up any previous logs and ensure the directory does not exist.
  std::filesystem::remove_all(temp_dir_);
  ASSERT_FALSE(std::filesystem::exists(temp_dir_));

  auto snoop_logger = NewSnoopLogger(10, SnoopLogger::kBtSnoopLogModeDisabled, false, false);
  snoop_logger->Capture(kInformationRequest, SnoopLogger::Direction::OUTGOING,
                        SnoopLogger::PacketType::CMD);

  // The directory should not have been created by the constructor in disabled mode
  ASSERT_FALSE(std::filesystem::exists(temp_dir_));

  snoop_logger->DumpSnoozLogToFile();

  // The directory should be created by DumpSnoozLogToFile
  ASSERT_TRUE(std::filesystem::exists(temp_dir_));
  ASSERT_TRUE(std::filesystem::exists(temp_snooz_log_));

  snoop_logger.reset();
}
#endif  // __ANDROID__

}  // namespace bluetooth::hal
