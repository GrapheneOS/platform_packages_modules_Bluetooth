/*
 * Copyright 2020 The Android Open Source Project
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

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include <future>

#include "common/init_flags.h"
#include "hal/snoop_logger_common.h"
#include "hal/syscall_wrapper_impl.h"
#include "os/fake_timer/fake_timerfd.h"
#include "os/utils.h"

namespace testing {

using bluetooth::hal::SnoopLoggerCommon;
using bluetooth::hal::SnoopLoggerSocket;
using bluetooth::hal::SnoopLoggerSocketInterface;
using bluetooth::hal::SnoopLoggerSocketThread;
using bluetooth::hal::SyscallWrapperImpl;
using bluetooth::os::fake_timer::fake_timerfd_advance;
using bluetooth::os::fake_timer::fake_timerfd_reset;

namespace {
std::vector<uint8_t> kInformationRequest = {
    0xfe,
    0x2e,
    0x0a,
    0x00,
    0x06,
    0x00,
    0x01,
    0x00,
    0x0a,
    0x02,
    0x02,
    0x00,
    0x02,
    0x00,
};

std::vector<uint8_t> kSdpConnectionRequest = {
    0x08, 0x20, 0x0c, 0x00, 0x08, 0x00, 0x01, 0x00, 0x02, 0x0c, 0x04, 0x00, 0x01, 0x00, 0x44, 0x00};

std::vector<uint8_t> kAvdtpSuspend = {0x02, 0x02, 0x00, 0x07, 0x00, 0x03, 0x00, 0x8d, 0x00, 0x90, 0x09, 0x04};

std::vector<uint8_t> kHfpAtNrec0 = {0x02, 0x02, 0x20, 0x13, 0x00, 0x0f, 0x00, 0x41, 0x00, 0x09, 0xff, 0x15,
                                    0x01, 0x41, 0x54, 0x2b, 0x4e, 0x52, 0x45, 0x43, 0x3d, 0x30, 0x0d, 0x5c};

std::vector<uint8_t> kQualcommConnectionRequest = {0xdc, 0x2e, 0x54, 0x00, 0x50, 0x00, 0xff, 0x00, 0x00, 0x0a,
                                                   0x0f, 0x09, 0x01, 0x00, 0x5c, 0x93, 0x01, 0x00, 0x42, 0x00};

}  // namespace

using bluetooth::TestModuleRegistry;
using bluetooth::hal::SnoopLogger;
using namespace std::chrono_literals;

const char* test_flags[] = {
    "INIT_logging_debug_enabled_for_all=true",
    "INIT_gd_hal_snoop_logger_socket=true",
    nullptr,
};

// Expose protected constructor for test
class TestSnoopLoggerModule : public SnoopLogger {
 public:
  TestSnoopLoggerModule(
      std::string snoop_log_path,
      std::string snooz_log_path,
      size_t max_packets_per_file,
      const std::string& btsnoop_mode,
      bool qualcomm_debug_log_enabled,
      bool snoop_log_persists)
      : SnoopLogger(
            std::move(snoop_log_path),
            std::move(snooz_log_path),
            max_packets_per_file,
            SnoopLogger::GetMaxPacketsPerBuffer(),
            btsnoop_mode,
            qualcomm_debug_log_enabled,
            20ms,
            5ms,
            snoop_log_persists) {}

  std::string ToString() const override {
    return std::string("TestSnoopLoggerModule");
  }

  void CallGetDumpsysData(flatbuffers::FlatBufferBuilder* builder) {
    GetDumpsysData(builder);
  }

  SnoopLoggerSocketThread* GetSocketThread() {
    return snoop_logger_socket_thread_.get();
  }
};

class SnoopLoggerModuleTest : public Test {
 public:
  flatbuffers::FlatBufferBuilder* builder_;
  TestModuleRegistry* test_registry;

 protected:
  void SetUp() override {
    temp_dir_ = std::filesystem::temp_directory_path();
    temp_snoop_log_ = temp_dir_ / "btsnoop_hci.log";
    temp_snoop_log_last_ = temp_dir_ / "btsnoop_hci.log.last";
    temp_snooz_log_ = temp_dir_ / "btsnooz_hci.log";
    temp_snooz_log_last_ = temp_dir_ / "btsnooz_hci.log.last";
    builder_ = new flatbuffers::FlatBufferBuilder();

    DeleteSnoopLogFiles();
    ASSERT_FALSE(std::filesystem::exists(temp_snoop_log_));
    ASSERT_FALSE(std::filesystem::exists(temp_snoop_log_last_));
    ASSERT_FALSE(std::filesystem::exists(temp_snooz_log_));
    ASSERT_FALSE(std::filesystem::exists(temp_snooz_log_last_));

    test_registry = new TestModuleRegistry();

    bluetooth::common::InitFlags::Load(test_flags);
  }

  void TearDown() override {
    DeleteSnoopLogFiles();
    delete builder_;
    fake_timerfd_reset();
    test_registry->StopAll();
    delete test_registry;
  }

  void DeleteSnoopLogFiles() {
    if (std::filesystem::exists(temp_snoop_log_)) {
      ASSERT_TRUE(std::filesystem::remove(temp_snoop_log_));
    }
    if (std::filesystem::exists(temp_snoop_log_last_)) {
      ASSERT_TRUE(std::filesystem::remove(temp_snoop_log_last_));
    }
    if (std::filesystem::exists(temp_snooz_log_)) {
      ASSERT_TRUE(std::filesystem::remove(temp_snooz_log_));
    }
    if (std::filesystem::exists(temp_snooz_log_last_)) {
      ASSERT_TRUE(std::filesystem::remove(temp_snooz_log_last_));
    }
  }

  std::filesystem::path temp_dir_;
  std::filesystem::path temp_snoop_log_;
  std::filesystem::path temp_snoop_log_last_;
  std::filesystem::path temp_snooz_log_;
  std::filesystem::path temp_snooz_log_last_;
};

TEST_F(SnoopLoggerModuleTest, empty_snoop_log_test) {
  // Actual test
  auto* snoop_logger = new TestSnoopLoggerModule(
      temp_snoop_log_.string(),
      temp_snooz_log_.string(),
      10,
      SnoopLogger::kBtSnoopLogModeFull,
      false,
      false);
  test_registry->InjectTestModule(&SnoopLogger::Factory, snoop_logger);
  test_registry->StopAll();

  // Verify states after test
  ASSERT_TRUE(std::filesystem::exists(temp_snoop_log_));
  ASSERT_FALSE(std::filesystem::exists(temp_snoop_log_last_));
  ASSERT_EQ(std::filesystem::file_size(temp_snoop_log_), sizeof(SnoopLoggerCommon::FileHeaderType));
}

TEST_F(SnoopLoggerModuleTest, disable_snoop_log_test) {
  // Actual test
  auto* snoop_logger = new TestSnoopLoggerModule(
      temp_snoop_log_.string(),
      temp_snooz_log_.string(),
      10,
      SnoopLogger::kBtSnoopLogModeDisabled,
      false,
      false);
  test_registry->InjectTestModule(&SnoopLogger::Factory, snoop_logger);
  test_registry->StopAll();

  // Verify states after test
  ASSERT_FALSE(std::filesystem::exists(temp_snoop_log_));
  ASSERT_FALSE(std::filesystem::exists(temp_snoop_log_last_));
  ASSERT_FALSE(std::filesystem::exists(temp_snooz_log_));
}

TEST_F(SnoopLoggerModuleTest, capture_one_packet_test) {
  // Actual test
  auto* snoop_logger = new TestSnoopLoggerModule(
      temp_snoop_log_.string(),
      temp_snooz_log_.string(),
      10,
      SnoopLogger::kBtSnoopLogModeFull,
      false,
      false);
  test_registry->InjectTestModule(&SnoopLogger::Factory, snoop_logger);

  snoop_logger->Capture(kInformationRequest, SnoopLogger::Direction::OUTGOING, SnoopLogger::PacketType::CMD);

  test_registry->StopAll();

  // Verify states after test
  ASSERT_TRUE(std::filesystem::exists(temp_snoop_log_));
  ASSERT_FALSE(std::filesystem::exists(temp_snoop_log_last_));
  ASSERT_EQ(
      std::filesystem::file_size(temp_snoop_log_),
      sizeof(SnoopLoggerCommon::FileHeaderType) + sizeof(SnoopLogger::PacketHeaderType) + kInformationRequest.size());
}

TEST_F(SnoopLoggerModuleTest, capture_hci_cmd_btsnooz_test) {
  // Actual test
  auto* snoop_logger = new TestSnoopLoggerModule(
      temp_snoop_log_.string(),
      temp_snooz_log_.string(),
      10,
      SnoopLogger::kBtSnoopLogModeDisabled,
      false,
      false);
  test_registry->InjectTestModule(&SnoopLogger::Factory, snoop_logger);

  snoop_logger->Capture(kInformationRequest, SnoopLogger::Direction::OUTGOING, SnoopLogger::PacketType::CMD);
  snoop_logger->CallGetDumpsysData(builder_);

  ASSERT_TRUE(std::filesystem::exists(temp_snooz_log_));
  ASSERT_EQ(
      std::filesystem::file_size(temp_snooz_log_),
      sizeof(SnoopLoggerCommon::FileHeaderType) + sizeof(SnoopLogger::PacketHeaderType) + kInformationRequest.size());

  test_registry->StopAll();

  // Verify states after test
  ASSERT_FALSE(std::filesystem::exists(temp_snoop_log_));
  ASSERT_FALSE(std::filesystem::exists(temp_snoop_log_last_));
  ASSERT_FALSE(std::filesystem::exists(temp_snooz_log_));
}

TEST_F(SnoopLoggerModuleTest, capture_l2cap_signal_packet_btsnooz_test) {
  // Actual test
  auto* snoop_logger = new TestSnoopLoggerModule(
      temp_snoop_log_.string(),
      temp_snooz_log_.string(),
      10,
      SnoopLogger::kBtSnoopLogModeDisabled,
      false,
      false);
  test_registry->InjectTestModule(&SnoopLogger::Factory, snoop_logger);

  snoop_logger->Capture(kSdpConnectionRequest, SnoopLogger::Direction::OUTGOING, SnoopLogger::PacketType::ACL);
  snoop_logger->CallGetDumpsysData(builder_);

  ASSERT_TRUE(std::filesystem::exists(temp_snooz_log_));
  ASSERT_EQ(
      std::filesystem::file_size(temp_snooz_log_),
      sizeof(SnoopLoggerCommon::FileHeaderType) + sizeof(SnoopLogger::PacketHeaderType) + kSdpConnectionRequest.size());

  test_registry->StopAll();

  // Verify states after test
  ASSERT_FALSE(std::filesystem::exists(temp_snoop_log_));
  ASSERT_FALSE(std::filesystem::exists(temp_snoop_log_last_));
  ASSERT_FALSE(std::filesystem::exists(temp_snooz_log_));
}

TEST_F(SnoopLoggerModuleTest, capture_l2cap_short_data_packet_btsnooz_test) {
  // Actual test
  auto* snoop_logger = new TestSnoopLoggerModule(
      temp_snoop_log_.string(),
      temp_snooz_log_.string(),
      10,
      SnoopLogger::kBtSnoopLogModeDisabled,
      false,
      false);
  test_registry->InjectTestModule(&SnoopLogger::Factory, snoop_logger);

  snoop_logger->Capture(kAvdtpSuspend, SnoopLogger::Direction::OUTGOING, SnoopLogger::PacketType::ACL);
  snoop_logger->CallGetDumpsysData(builder_);

  ASSERT_TRUE(std::filesystem::exists(temp_snooz_log_));
  ASSERT_EQ(
      std::filesystem::file_size(temp_snooz_log_),
      sizeof(SnoopLoggerCommon::FileHeaderType) + sizeof(SnoopLogger::PacketHeaderType) + kAvdtpSuspend.size());

  test_registry->StopAll();

  // Verify states after test
  ASSERT_FALSE(std::filesystem::exists(temp_snoop_log_));
  ASSERT_FALSE(std::filesystem::exists(temp_snoop_log_last_));
  ASSERT_FALSE(std::filesystem::exists(temp_snooz_log_));
}

TEST_F(SnoopLoggerModuleTest, capture_l2cap_long_data_packet_btsnooz_test) {
  // Actual test
  auto* snoop_logger = new TestSnoopLoggerModule(
      temp_snoop_log_.string(),
      temp_snooz_log_.string(),
      10,
      SnoopLogger::kBtSnoopLogModeDisabled,
      false,
      false);
  test_registry->InjectTestModule(&SnoopLogger::Factory, snoop_logger);

  snoop_logger->Capture(kHfpAtNrec0, SnoopLogger::Direction::OUTGOING, SnoopLogger::PacketType::ACL);
  snoop_logger->CallGetDumpsysData(builder_);

  ASSERT_TRUE(std::filesystem::exists(temp_snooz_log_));
  ASSERT_EQ(
      std::filesystem::file_size(temp_snooz_log_),
      sizeof(SnoopLoggerCommon::FileHeaderType) + sizeof(SnoopLogger::PacketHeaderType) + 14);

  test_registry->StopAll();

  // Verify states after test
  ASSERT_FALSE(std::filesystem::exists(temp_snoop_log_));
  ASSERT_FALSE(std::filesystem::exists(temp_snoop_log_last_));
  ASSERT_FALSE(std::filesystem::exists(temp_snooz_log_));
}

TEST_F(SnoopLoggerModuleTest, snoop_log_persists) {
  // Actual test
  auto* snoop_logger = new TestSnoopLoggerModule(
      temp_snoop_log_.string(),
      temp_snooz_log_.string(),
      10,
      SnoopLogger::kBtSnoopLogModeDisabled,
      false,
      true);
  test_registry->InjectTestModule(&SnoopLogger::Factory, snoop_logger);

  snoop_logger->Capture(
      kHfpAtNrec0, SnoopLogger::Direction::OUTGOING, SnoopLogger::PacketType::ACL);
  snoop_logger->CallGetDumpsysData(builder_);

  ASSERT_TRUE(std::filesystem::exists(temp_snooz_log_));
  ASSERT_EQ(
      std::filesystem::file_size(temp_snooz_log_),
      sizeof(SnoopLoggerCommon::FileHeaderType) + sizeof(SnoopLogger::PacketHeaderType) + 14);

  test_registry->StopAll();
  ASSERT_TRUE(std::filesystem::exists(temp_snooz_log_));
}

TEST_F(SnoopLoggerModuleTest, delete_old_snooz_log_files) {
  // Actual test
  auto* snoop_logger = new TestSnoopLoggerModule(
      temp_snoop_log_.string(),
      temp_snooz_log_.string(),
      10,
      SnoopLogger::kBtSnoopLogModeDisabled,
      false,
      false);
  test_registry->InjectTestModule(&SnoopLogger::Factory, snoop_logger);

  std::filesystem::create_directories(temp_snooz_log_);

  auto* handler = test_registry->GetTestModuleHandler(&SnoopLogger::Factory);
  ASSERT_TRUE(std::filesystem::exists(temp_snooz_log_));
  handler->Post(bluetooth::common::BindOnce(fake_timerfd_advance, 10));
  ASSERT_TRUE(std::filesystem::exists(temp_snooz_log_));
  handler->Post(bluetooth::common::BindOnce(fake_timerfd_advance, 15));
  handler->Post(bluetooth::common::BindOnce(
      [](std::filesystem::path path) { ASSERT_FALSE(std::filesystem::exists(path)); }, temp_snooz_log_));
  test_registry->StopAll();
}

TEST_F(SnoopLoggerModuleTest, rotate_file_at_new_session_test) {
  // Start once
  {
    auto* snoop_logger = new TestSnoopLoggerModule(
        temp_snoop_log_.string(),
        temp_snooz_log_.string(),
        10,
        SnoopLogger::kBtSnoopLogModeFull,
        false,
        false);
    test_registry->InjectTestModule(&SnoopLogger::Factory, snoop_logger);
    snoop_logger->Capture(
        kInformationRequest, SnoopLogger::Direction::OUTGOING, SnoopLogger::PacketType::CMD);
    test_registry->StopAll();
  }

  // Verify states after test
  ASSERT_TRUE(std::filesystem::exists(temp_snoop_log_));
  ASSERT_FALSE(std::filesystem::exists(temp_snoop_log_last_));
  ASSERT_EQ(
      std::filesystem::file_size(temp_snoop_log_),
      sizeof(SnoopLoggerCommon::FileHeaderType) + sizeof(SnoopLogger::PacketHeaderType) + kInformationRequest.size());

  // Start again
  {
    auto* snoop_logger = new TestSnoopLoggerModule(
        temp_snoop_log_.string(),
        temp_snooz_log_.string(),
        10,
        SnoopLogger::kBtSnoopLogModeFull,
        false,
        false);
    test_registry->InjectTestModule(&SnoopLogger::Factory, snoop_logger);
    snoop_logger->Capture(
        kInformationRequest, SnoopLogger::Direction::OUTGOING, SnoopLogger::PacketType::CMD);
    snoop_logger->Capture(
        kInformationRequest, SnoopLogger::Direction::OUTGOING, SnoopLogger::PacketType::CMD);
    test_registry->StopAll();
  }

  // Verify states after test
  ASSERT_TRUE(std::filesystem::exists(temp_snoop_log_));
  ASSERT_TRUE(std::filesystem::exists(temp_snoop_log_last_));
  ASSERT_EQ(
      std::filesystem::file_size(temp_snoop_log_),
      sizeof(SnoopLoggerCommon::FileHeaderType) +
          (sizeof(SnoopLogger::PacketHeaderType) + kInformationRequest.size()) * 2);
  ASSERT_EQ(
      std::filesystem::file_size(temp_snoop_log_last_),
      sizeof(SnoopLoggerCommon::FileHeaderType) + sizeof(SnoopLogger::PacketHeaderType) + kInformationRequest.size());
}

TEST_F(SnoopLoggerModuleTest, rotate_file_after_full_test) {
  // Actual test
  auto* snoop_logger = new TestSnoopLoggerModule(
      temp_snoop_log_.string(),
      temp_snooz_log_.string(),
      10,
      SnoopLogger::kBtSnoopLogModeFull,
      false,
      false);
  test_registry->InjectTestModule(&SnoopLogger::Factory, snoop_logger);

  for (int i = 0; i < 11; i++) {
    snoop_logger->Capture(kInformationRequest, SnoopLogger::Direction::OUTGOING, SnoopLogger::PacketType::CMD);
  }

  test_registry->StopAll();

  // Verify states after test
  ASSERT_TRUE(std::filesystem::exists(temp_snoop_log_));
  ASSERT_TRUE(std::filesystem::exists(temp_snoop_log_last_));
  ASSERT_EQ(
      std::filesystem::file_size(temp_snoop_log_),
      sizeof(SnoopLoggerCommon::FileHeaderType) +
          (sizeof(SnoopLogger::PacketHeaderType) + kInformationRequest.size()) * 1);
  ASSERT_EQ(
      std::filesystem::file_size(temp_snoop_log_last_),
      sizeof(SnoopLoggerCommon::FileHeaderType) +
          (sizeof(SnoopLogger::PacketHeaderType) + kInformationRequest.size()) * 10);
}

TEST_F(SnoopLoggerModuleTest, qualcomm_debug_log_test) {
  auto* snoop_logger = new TestSnoopLoggerModule(
      temp_snoop_log_.string(),
      temp_snooz_log_.string(),
      10,
      SnoopLogger::kBtSnoopLogModeDisabled,
      true,
      false);
  test_registry->InjectTestModule(&SnoopLogger::Factory, snoop_logger);
  snoop_logger->Capture(
      kQualcommConnectionRequest, SnoopLogger::Direction::OUTGOING, SnoopLogger::PacketType::ACL);
  snoop_logger->CallGetDumpsysData(builder_);

  ASSERT_TRUE(std::filesystem::exists(temp_snooz_log_));
  ASSERT_EQ(
      std::filesystem::file_size(temp_snooz_log_),
      sizeof(SnoopLoggerCommon::FileHeaderType) + sizeof(SnoopLogger::PacketHeaderType) +
          kQualcommConnectionRequest.size());

  test_registry->StopAll();

  // Verify states after test
  ASSERT_FALSE(std::filesystem::exists(temp_snoop_log_));
  ASSERT_FALSE(std::filesystem::exists(temp_snoop_log_last_));
  ASSERT_FALSE(std::filesystem::exists(temp_snooz_log_));
}

TEST_F(SnoopLoggerModuleTest, qualcomm_debug_log_regression_test) {
  {
    auto* snoop_logger = new TestSnoopLoggerModule(
        temp_snoop_log_.string(),
        temp_snooz_log_.string(),
        10,
        SnoopLogger::kBtSnoopLogModeDisabled,
        true,
        false);
    test_registry->InjectTestModule(&SnoopLogger::Factory, snoop_logger);
    snoop_logger->Capture(
        kHfpAtNrec0, SnoopLogger::Direction::OUTGOING, SnoopLogger::PacketType::ACL);
    snoop_logger->CallGetDumpsysData(builder_);

    ASSERT_TRUE(std::filesystem::exists(temp_snooz_log_));
    ASSERT_EQ(
        std::filesystem::file_size(temp_snooz_log_),
        sizeof(SnoopLoggerCommon::FileHeaderType) + sizeof(SnoopLogger::PacketHeaderType) + 14);
    test_registry->StopAll();
  }

  // Verify states after test
  ASSERT_FALSE(std::filesystem::exists(temp_snoop_log_));
  ASSERT_FALSE(std::filesystem::exists(temp_snoop_log_last_));
  ASSERT_FALSE(std::filesystem::exists(temp_snooz_log_));

  {
    auto* snoop_logger = new TestSnoopLoggerModule(
        temp_snoop_log_.string(),
        temp_snooz_log_.string(),
        10,
        SnoopLogger::kBtSnoopLogModeDisabled,
        false,
        false);
    test_registry->InjectTestModule(&SnoopLogger::Factory, snoop_logger);
    snoop_logger->Capture(
        kQualcommConnectionRequest, SnoopLogger::Direction::OUTGOING, SnoopLogger::PacketType::ACL);
    snoop_logger->CallGetDumpsysData(builder_);

    ASSERT_TRUE(std::filesystem::exists(temp_snooz_log_));
    ASSERT_EQ(
        std::filesystem::file_size(temp_snooz_log_),
        sizeof(SnoopLoggerCommon::FileHeaderType) + sizeof(SnoopLogger::PacketHeaderType) + 14);
    test_registry->StopAll();
  }

  // Verify states after test
  ASSERT_FALSE(std::filesystem::exists(temp_snoop_log_));
  ASSERT_FALSE(std::filesystem::exists(temp_snoop_log_last_));
  ASSERT_FALSE(std::filesystem::exists(temp_snooz_log_));
}

static constexpr int INVALID_FD = -1;

TEST_F(SnoopLoggerModuleTest, socket_disabled_connect_fail_test) {
  auto* snoop_logger = new TestSnoopLoggerModule(
      temp_snoop_log_.string(),
      temp_snooz_log_.string(),
      10,
      SnoopLogger::kBtSnoopLogModeDisabled,
      true,
      false);
  test_registry->InjectTestModule(&SnoopLogger::Factory, snoop_logger);

  // // Create a TCP socket file descriptor
  int socket_fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, IPPROTO_TCP);
  ASSERT_TRUE(socket_fd != INVALID_FD);

  struct sockaddr_in addr;
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = htonl(SnoopLoggerSocket::DEFAULT_LOCALHOST_);
  addr.sin_port = htons(SnoopLoggerSocket::DEFAULT_LISTEN_PORT_);

  int ret;

  // Connect to snoop logger socket
  RUN_NO_INTR(ret = connect(socket_fd, (struct sockaddr*)&addr, sizeof(addr)));
  ASSERT_TRUE(ret != 0);

  test_registry->StopAll();
}

TEST_F(SnoopLoggerModuleTest, default_socket_enabled_capture_recv_test) {
  int ret;
  auto* snoop_logger = new TestSnoopLoggerModule(
      temp_snoop_log_.string(),
      temp_snooz_log_.string(),
      10,
      SnoopLogger::kBtSnoopLogModeFull,
      true,
      false);
  test_registry->InjectTestModule(&SnoopLogger::Factory, snoop_logger);

  // // Create a TCP socket file descriptor
  int socket_fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, IPPROTO_TCP);
  ASSERT_TRUE(socket_fd != INVALID_FD);

  struct sockaddr_in addr;
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = htonl(SnoopLoggerSocket::DEFAULT_LOCALHOST_);
  addr.sin_port = htons(SnoopLoggerSocket::DEFAULT_LISTEN_PORT_);

  // Connect to snoop logger socket
  RUN_NO_INTR(ret = connect(socket_fd, (struct sockaddr*)&addr, sizeof(addr)));
  ASSERT_TRUE(ret == 0);

  char recv_buf1[sizeof(SnoopLoggerCommon::FileHeaderType)];
  char recv_buf2[sizeof(SnoopLogger::PacketHeaderType)];
  char recv_buf3[99];
  int bytes_read = -1;

  auto a = std::async(std::launch::async, [&] {
    recv(socket_fd, recv_buf1, sizeof(recv_buf1), 0);
    recv(socket_fd, recv_buf2, sizeof(recv_buf2), 0);
    return recv(socket_fd, recv_buf3, sizeof(recv_buf3), 0);
  });

  snoop_logger->GetSocketThread()->GetSocket()->WaitForClientSocketConnected();

  snoop_logger->Capture(kHfpAtNrec0, SnoopLogger::Direction::OUTGOING, SnoopLogger::PacketType::ACL);

  a.wait();
  bytes_read = a.get();

  ASSERT_TRUE(std::memcmp(recv_buf1, &SnoopLoggerCommon::kBtSnoopFileHeader, sizeof(recv_buf1)) == 0);
  ASSERT_EQ(bytes_read, static_cast<int>(kHfpAtNrec0.size()));
  ASSERT_TRUE(std::memcmp(recv_buf3, kHfpAtNrec0.data(), kHfpAtNrec0.size()) == 0);

  test_registry->StopAll();
}

TEST_F(SnoopLoggerModuleTest, custom_socket_register_enabled_capture_recv_test) {
  auto* snoop_logger = new TestSnoopLoggerModule(
      temp_snoop_log_.string(),
      temp_snooz_log_.string(),
      10,
      SnoopLogger::kBtSnoopLogModeFull,
      true,
      false);
  test_registry->InjectTestModule(&SnoopLogger::Factory, snoop_logger);

  int new_port = 8873;
  SyscallWrapperImpl syscall_if;
  auto sls = std::make_unique<SnoopLoggerSocket>(&syscall_if, SnoopLoggerSocket::DEFAULT_LOCALHOST_, new_port);
  SnoopLoggerSocketThread slsThread(std::move(sls));
  auto thread_start_future = slsThread.Start();
  thread_start_future.wait();
  ASSERT_TRUE(thread_start_future.get());

  snoop_logger->RegisterSocket(&slsThread);

  // // Create a TCP socket file descriptor
  int socket_fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, IPPROTO_TCP);
  ASSERT_TRUE(socket_fd != INVALID_FD);

  struct sockaddr_in addr;
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = htonl(SnoopLoggerSocket::DEFAULT_LOCALHOST_);
  addr.sin_port = htons(new_port);

  int ret = 0;
  // Connect to snoop logger socket
  RUN_NO_INTR(ret = connect(socket_fd, (struct sockaddr*)&addr, sizeof(addr)));
  ASSERT_TRUE(ret == 0);

  char recv_buf1[sizeof(SnoopLoggerCommon::FileHeaderType)];
  char recv_buf2[sizeof(SnoopLogger::PacketHeaderType)];
  char recv_buf3[99];
  int bytes_read = -1;

  auto a = std::async(std::launch::async, [socket_fd, &recv_buf1, &recv_buf2, &recv_buf3] {
    recv(socket_fd, recv_buf1, sizeof(recv_buf1), 0);
    recv(socket_fd, recv_buf2, sizeof(recv_buf2), 0);
    return recv(socket_fd, recv_buf3, sizeof(recv_buf3), 0);
  });

  slsThread.GetSocket()->WaitForClientSocketConnected();

  snoop_logger->Capture(kHfpAtNrec0, SnoopLogger::Direction::OUTGOING, SnoopLogger::PacketType::ACL);

  a.wait();
  bytes_read = a.get();

  ASSERT_TRUE(std::memcmp(recv_buf1, &SnoopLoggerCommon::kBtSnoopFileHeader, sizeof(recv_buf1)) == 0);
  ASSERT_EQ(bytes_read, static_cast<int>(kHfpAtNrec0.size()));
  ASSERT_TRUE(std::memcmp(recv_buf3, kHfpAtNrec0.data(), kHfpAtNrec0.size()) == 0);

  test_registry->StopAll();
}

TEST_F(SnoopLoggerModuleTest, custom_socket_interface_register_logging_disabled_test) {
  auto* snoop_logger = new TestSnoopLoggerModule(
      temp_snoop_log_.string(),
      temp_snooz_log_.string(),
      10,
      SnoopLogger::kBtSnoopLogModeDisabled,
      true,
      false);
  test_registry->InjectTestModule(&SnoopLogger::Factory, snoop_logger);

  class SnoopLoggerSocketMock : public SnoopLoggerSocketInterface {
   public:
    bool write_called;
    SnoopLoggerSocketMock() {
      write_called = false;
    }
    virtual void Write(const void* data, size_t length) {
      write_called = true;
    }
  };

  SnoopLoggerSocketMock mock;

  snoop_logger->RegisterSocket(&mock);
  snoop_logger->Capture(kQualcommConnectionRequest, SnoopLogger::Direction::OUTGOING, SnoopLogger::PacketType::ACL);

  ASSERT_FALSE(mock.write_called);

  test_registry->StopAll();
}

TEST_F(SnoopLoggerModuleTest, custom_socket_interface_register_logging_enabled_test) {
  auto* snoop_logger = new TestSnoopLoggerModule(
      temp_snoop_log_.string(),
      temp_snooz_log_.string(),
      10,
      SnoopLogger::kBtSnoopLogModeFull,
      true,
      false);
  test_registry->InjectTestModule(&SnoopLogger::Factory, snoop_logger);

  class SnoopLoggerSocketMock : public SnoopLoggerSocketInterface {
   public:
    bool write_called;
    SnoopLoggerSocketMock() {
      write_called = false;
    }
    virtual void Write(const void* data, size_t length) {
      write_called = true;
    }
  };

  SnoopLoggerSocketMock mock;

  snoop_logger->RegisterSocket(&mock);
  snoop_logger->Capture(kQualcommConnectionRequest, SnoopLogger::Direction::OUTGOING, SnoopLogger::PacketType::ACL);

  ASSERT_TRUE(mock.write_called);

  test_registry->StopAll();
}
}  // namespace testing
