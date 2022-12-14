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

#include <errno.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include <future>

#include "common/init_flags.h"
#include "hal/snoop_logger_common.h"
#include "hal/snoop_logger_socket_thread.h"
#include "hal/syscall_wrapper_impl.h"
#include "hal/syscall_wrapper_mock.h"
#include "os/utils.h"

static const char* test_flags[] = {
    "INIT_logging_debug_enabled_for_all=true",
    nullptr,
};

namespace testing {

using bluetooth::hal::SnoopLoggerCommon;
using bluetooth::hal::SnoopLoggerSocket;
using bluetooth::hal::SyscallWrapperImpl;
using bluetooth::hal::SyscallWrapperMock;

static constexpr int INVALID_FD = -1;

class SnoopLoggerSocketModuleTest : public Test {
 protected:
  void SetUp() override {
    bluetooth::common::InitFlags::Load(test_flags);
  }

  void TearDown() override {}
};

TEST_F(SnoopLoggerSocketModuleTest, test_Constructor_GetSyscallWrapperInterface) {
  SyscallWrapperMock mock;

  SnoopLoggerSocket sls(&mock);

  ASSERT_EQ(sls.GetSyscallWrapperInterface(), &mock);
}

TEST_F(SnoopLoggerSocketModuleTest, test_Destructor_implicit_cleanup) {
  SyscallWrapperMock mock;

  {
    SnoopLoggerSocket sls(&mock);

    EXPECT_CALL(mock, Close).Times(0);
  }
}

TEST_F(SnoopLoggerSocketModuleTest, test_Cleanup_explicit) {
  SyscallWrapperMock mock;

  SnoopLoggerSocket sls(&mock);

  EXPECT_CALL(mock, Close).Times(0);
  sls.Cleanup();
}

TEST_F(SnoopLoggerSocketModuleTest, test_CreateSocket_fail_on_Socket) {
  SyscallWrapperMock mock;

  SnoopLoggerSocket sls(&mock);

  ON_CALL(mock, Socket(_, _, _)).WillByDefault((Return(-1)));

  EXPECT_CALL(mock, Socket).Times(1);
  EXPECT_CALL(mock, Close).Times(0);
  ASSERT_EQ(sls.CreateSocket(), INVALID_FD);
}

TEST_F(SnoopLoggerSocketModuleTest, test_CreateSocket_fail_on_Setsockopt) {
  SyscallWrapperMock mock;

  SnoopLoggerSocket sls(&mock);
  int fd = 10;

  ON_CALL(mock, Socket(_, _, _)).WillByDefault((Return(fd)));
  ON_CALL(mock, Setsockopt(_, _, _, _, _)).WillByDefault((Return(-1)));

  EXPECT_CALL(mock, Socket).Times(1);
  EXPECT_CALL(mock, Setsockopt).Times(1);
  EXPECT_CALL(mock, Close).Times(1);
  ASSERT_EQ(sls.CreateSocket(), INVALID_FD);
}

TEST_F(SnoopLoggerSocketModuleTest, test_CreateSocket_fail_on_Bind) {
  SyscallWrapperMock mock;

  SnoopLoggerSocket sls(&mock);
  int fd = 10;

  ON_CALL(mock, Socket(_, _, _)).WillByDefault((Return(fd)));
  ON_CALL(mock, Setsockopt(_, _, _, _, _)).WillByDefault((Return(0)));
  ON_CALL(mock, Bind(_, _, _)).WillByDefault((Return(-1)));

  EXPECT_CALL(mock, Socket).Times(1);
  EXPECT_CALL(mock, Setsockopt).Times(1);
  EXPECT_CALL(mock, Bind).Times(1);
  EXPECT_CALL(mock, Close).Times(1);
  ASSERT_EQ(sls.CreateSocket(), INVALID_FD);
}

TEST_F(SnoopLoggerSocketModuleTest, test_CreateSocket_fail_on_Listen) {
  SyscallWrapperMock mock;

  SnoopLoggerSocket sls(&mock);
  int fd = 10;

  ON_CALL(mock, Socket(_, _, _)).WillByDefault((Return(fd)));
  ON_CALL(mock, Setsockopt(_, _, _, _, _)).WillByDefault((Return(0)));
  ON_CALL(mock, Bind(_, _, _)).WillByDefault((Return(0)));
  ON_CALL(mock, Listen(_, _)).WillByDefault((Return(-1)));

  EXPECT_CALL(mock, Socket).Times(1);
  EXPECT_CALL(mock, Setsockopt).Times(1);
  EXPECT_CALL(mock, Bind).Times(1);
  EXPECT_CALL(mock, Listen).Times(1);
  EXPECT_CALL(mock, Close).Times(1);
  ASSERT_EQ(sls.CreateSocket(), INVALID_FD);
}

TEST_F(SnoopLoggerSocketModuleTest, test_CreateSocket_success) {
  SyscallWrapperMock mock;

  SnoopLoggerSocket sls(&mock);
  int fd = 10;

  ON_CALL(mock, Socket(_, _, _)).WillByDefault((Return(fd)));
  ON_CALL(mock, Setsockopt(_, _, _, _, _)).WillByDefault((Return(0)));
  ON_CALL(mock, Bind(_, _, _)).WillByDefault((Return(0)));
  ON_CALL(mock, Listen(_, _)).WillByDefault((Return(0)));

  EXPECT_CALL(mock, Socket).Times(1);
  EXPECT_CALL(mock, Setsockopt).Times(1);
  EXPECT_CALL(mock, Bind).Times(1);
  EXPECT_CALL(mock, Listen).Times(1);
  EXPECT_CALL(mock, Close).Times(0);
  ASSERT_EQ(sls.CreateSocket(), fd);
}

TEST_F(SnoopLoggerSocketModuleTest, test_Write_fd_invalid_fd) {
  SyscallWrapperMock mock;
  SnoopLoggerSocket sls(&mock);
  int fd = INVALID_FD;

  EXPECT_CALL(mock, Send).Times(0);
  EXPECT_CALL(mock, Close).Times(0);

  sls.Write(fd, NULL, 0);
}

TEST_F(SnoopLoggerSocketModuleTest, test_Write_fd_fail_on_Send_ECONNRESET) {
  SyscallWrapperMock mock;
  SnoopLoggerSocket sls(&mock);
  int fd = 10;
  char data[10];

  ON_CALL(mock, Send(_, _, _, _)).WillByDefault((Return(-1)));
  ON_CALL(mock, GetErrno()).WillByDefault((Return(ECONNRESET)));

  EXPECT_CALL(mock, Send(Eq(fd), Eq(data), Eq(sizeof(data)), _)).Times(1);
  EXPECT_CALL(mock, Close(Eq(fd))).Times(1);

  sls.Write(fd, data, sizeof(data));
}

TEST_F(SnoopLoggerSocketModuleTest, test_Write_fd_fail_on_Send_EINVAL) {
  SyscallWrapperMock mock;
  SnoopLoggerSocket sls(&mock);
  int fd = 10;
  char data[10];

  ON_CALL(mock, Send(_, _, _, _)).WillByDefault((Return(-1)));
  ON_CALL(mock, GetErrno()).WillByDefault((Return(EINVAL)));

  EXPECT_CALL(mock, Send(Eq(fd), Eq(data), Eq(sizeof(data)), _)).Times(1);
  EXPECT_CALL(mock, Close(Eq(fd))).Times(0);

  sls.Write(fd, data, sizeof(data));
}

TEST_F(SnoopLoggerSocketModuleTest, test_Write_fd_success) {
  SyscallWrapperMock mock;
  SnoopLoggerSocket sls(&mock);
  int client_fd = 33;
  char data[10];

  EXPECT_CALL(mock, Send(client_fd, _, _, _)).Times(1);

  sls.Write(client_fd, data, sizeof(data));
}

TEST_F(SnoopLoggerSocketModuleTest, test_Write_fail_no_client) {
  SyscallWrapperMock mock;
  SnoopLoggerSocket sls(&mock);
  char data[10];

  EXPECT_CALL(mock, Send).Times(0);
  EXPECT_CALL(mock, Close).Times(0);

  sls.Write(data, sizeof(data));
}

TEST_F(SnoopLoggerSocketModuleTest, test_Write_success) {
  SyscallWrapperMock mock;
  SnoopLoggerSocket sls(&mock);
  int client_fd = 33;
  char data[10];

  EXPECT_CALL(mock, Send(client_fd, _, _, _)).Times(1);
  EXPECT_CALL(mock, Close(client_fd)).Times(1);

  sls.ClientSocketConnected(client_fd);

  sls.Write(data, sizeof(data));
}

TEST_F(SnoopLoggerSocketModuleTest, test_Write_fd_fail_on_Send_EINTR) {
  SyscallWrapperMock mock;
  SnoopLoggerSocket sls(&mock);
  int fd = 10;
  char data[10];
  int intr_count = 5;

  ON_CALL(mock, Send).WillByDefault(Invoke([&](int fd, const void* buf, size_t n, int flags) {
    if (intr_count > 0) {
      intr_count--;
      errno = EINTR;
      return -1;
    }
    errno = 0;
    return 0;
  }));

  EXPECT_CALL(mock, Send(Eq(fd), Eq(data), Eq(sizeof(data)), _)).Times(intr_count + 1);
  EXPECT_CALL(mock, Close(Eq(fd))).Times(0);

  sls.Write(fd, data, sizeof(data));
}

TEST_F(SnoopLoggerSocketModuleTest, test_ClientSocketConnected) {
  SyscallWrapperMock mock;
  SnoopLoggerSocket sls(&mock);
  int fd = 10;

  ASSERT_FALSE(sls.IsClientSocketConnected());

  EXPECT_CALL(mock, Close(Eq(fd))).Times(1);
  EXPECT_CALL(mock, Close(Eq(fd + 1))).Times(1);

  sls.ClientSocketConnected(fd);

  ASSERT_TRUE(sls.IsClientSocketConnected());

  sls.ClientSocketConnected(fd + 1);

  ASSERT_TRUE(sls.IsClientSocketConnected());
}

TEST_F(SnoopLoggerSocketModuleTest, test_WaitForClientSocketConnected) {
  SyscallWrapperMock mock;
  SnoopLoggerSocket sls(&mock);
  int fd = 10;

  ASSERT_FALSE(sls.IsClientSocketConnected());

  sls.ClientSocketConnected(fd);

  ASSERT_TRUE(sls.IsClientSocketConnected());

  ASSERT_TRUE(sls.WaitForClientSocketConnected());
}

TEST_F(SnoopLoggerSocketModuleTest, test_InitializeClientSocket) {
  SyscallWrapperMock mock;
  SnoopLoggerSocket sls(&mock);
  int client_fd = 10;

  EXPECT_CALL(mock, Send(client_fd, _, _, _)).Times(1);

  sls.InitializeClientSocket(client_fd);
}

TEST_F(SnoopLoggerSocketModuleTest, test_AcceptIncomingConnection_fail_on_accept_EINVAL) {
  SyscallWrapperMock mock;
  SnoopLoggerSocket sls(&mock);
  int fd = 10;
  int client_fd = 0;

  ON_CALL(mock, Accept(Eq(fd), _, _, _)).WillByDefault(Return(INVALID_FD));
  ON_CALL(mock, GetErrno()).WillByDefault(Return(EINVAL));

  ASSERT_EQ(sls.AcceptIncomingConnection(fd, client_fd), EINVAL);
}

TEST_F(SnoopLoggerSocketModuleTest, test_AcceptIncomingConnection_fail_on_accept_EBADF) {
  SyscallWrapperMock mock;
  SnoopLoggerSocket sls(&mock);
  int fd = 10;
  int client_fd = 0;

  ON_CALL(mock, Accept(Eq(fd), _, _, _)).WillByDefault(Return(INVALID_FD));
  ON_CALL(mock, GetErrno()).WillByDefault(Return(EBADF));

  ASSERT_EQ(sls.AcceptIncomingConnection(fd, client_fd), EBADF);
}

TEST_F(SnoopLoggerSocketModuleTest, test_AcceptIncomingConnection_fail_on_accept_EINTR) {
  SyscallWrapperMock mock;
  SnoopLoggerSocket sls(&mock);
  int fd = 10;
  int client_fd = 0;
  int intr_count = 5;

  ON_CALL(mock, Accept(Eq(fd), _, _, _))
      .WillByDefault(Invoke([&](int fd, struct sockaddr* addr, socklen_t* addr_len, int flags) {
        if (intr_count > 0) {
          intr_count--;
          errno = EINTR;
          return -1;
        }
        errno = 0;
        return client_fd;
      }));

  ASSERT_EQ(sls.AcceptIncomingConnection(fd, client_fd), 0);
}

TEST_F(SnoopLoggerSocketModuleTest, test_AcceptIncomingConnection_fail_on_accept_other_errors) {
  SyscallWrapperMock mock;
  SnoopLoggerSocket sls(&mock);
  int fd = 10;
  int client_fd = 0;

  ON_CALL(mock, Accept(Eq(fd), _, _, _)).WillByDefault(Return(INVALID_FD));
  ON_CALL(mock, GetErrno()).WillByDefault(Return(EAGAIN));

  ASSERT_EQ(sls.AcceptIncomingConnection(fd, client_fd), 0);
  ASSERT_EQ(client_fd, -1);
}

TEST_F(SnoopLoggerSocketModuleTest, test_AcceptIncomingConnection_success) {
  SyscallWrapperMock mock;
  SnoopLoggerSocket sls(&mock);
  int fd = 10;
  int client_fd = 13;
  int client_fd_out = 0;

  ON_CALL(mock, Accept(Eq(fd), _, _, _)).WillByDefault(Return(client_fd));
  ON_CALL(mock, GetErrno()).WillByDefault(Return(0));

  ASSERT_EQ(sls.AcceptIncomingConnection(fd, client_fd_out), 0);
  ASSERT_EQ(client_fd, client_fd_out);
}

TEST_F(SnoopLoggerSocketModuleTest, test_InitializeCommunications_fail_on_Pipe2) {
  SyscallWrapperMock mock;
  SnoopLoggerSocket sls(&mock);
  int ret = -9;

  ON_CALL(mock, Pipe2(_, _)).WillByDefault(Invoke([ret](int* fds, int) { return ret; }));

  ASSERT_EQ(sls.InitializeCommunications(), ret);
}

TEST_F(SnoopLoggerSocketModuleTest, test_InitializeCommunications_fail_on_CreateSocket) {
  SyscallWrapperMock mock;
  SnoopLoggerSocket sls(&mock);
  int ret = -9;
  int listen_fd = 66;
  int write_fd = 99;

  ON_CALL(mock, Socket(_, _, _)).WillByDefault(Return(ret));
  ON_CALL(mock, Pipe2).WillByDefault(Invoke([&](int* fds, int) {
    fds[0] = listen_fd;
    fds[1] = write_fd;
    return 0;
  }));

  EXPECT_CALL(mock, FDZero).Times(1);
  EXPECT_CALL(mock, FDSet(listen_fd, _)).Times(1);
  EXPECT_CALL(mock, Close(Eq(listen_fd))).Times(1);
  EXPECT_CALL(mock, Close(Eq(write_fd))).Times(1);

  ASSERT_EQ(sls.InitializeCommunications(), -1);
}

TEST_F(SnoopLoggerSocketModuleTest, test_InitializeCommunications_success) {
  SyscallWrapperMock mock;
  SnoopLoggerSocket sls(&mock);
  int fd = 11;
  int listen_fd = 66;
  int write_fd = 99;

  ON_CALL(mock, Socket(_, _, _)).WillByDefault((Return(fd)));
  ON_CALL(mock, Setsockopt(_, _, _, _, _)).WillByDefault((Return(0)));
  ON_CALL(mock, Bind(_, _, _)).WillByDefault((Return(0)));
  ON_CALL(mock, Listen(_, _)).WillByDefault((Return(0)));
  ON_CALL(mock, Pipe2).WillByDefault(Invoke([&](int* fds, int) {
    fds[0] = listen_fd;
    fds[1] = write_fd;
    return 0;
  }));

  EXPECT_CALL(mock, FDZero).Times(1);
  EXPECT_CALL(mock, FDSet(listen_fd, _)).Times(1);
  EXPECT_CALL(mock, FDSet(fd, _)).Times(1);
  EXPECT_CALL(mock, Socket).Times(1);
  EXPECT_CALL(mock, Setsockopt).Times(1);
  EXPECT_CALL(mock, Bind).Times(1);
  EXPECT_CALL(mock, Listen).Times(1);
  EXPECT_CALL(mock, Pipe2).Times(1);
  EXPECT_CALL(mock, Close(Eq(fd))).Times(1);
  EXPECT_CALL(mock, Close(Eq(listen_fd))).Times(1);
  EXPECT_CALL(mock, Close(Eq(write_fd))).Times(1);

  ASSERT_EQ(sls.InitializeCommunications(), 0);
}

TEST_F(SnoopLoggerSocketModuleTest, test_ProcessIncomingRequest_fail_on_Select_EINTR) {
  SyscallWrapperMock mock;
  SnoopLoggerSocket sls(&mock);

  ON_CALL(mock, Select).WillByDefault((Return(-1)));
  ON_CALL(mock, GetErrno()).WillByDefault((Return(EINTR)));

  ASSERT_TRUE(sls.ProcessIncomingRequest());
}

TEST_F(SnoopLoggerSocketModuleTest, test_ProcessIncomingRequest_fail_on_Select_EINVAL) {
  SyscallWrapperMock mock;
  SnoopLoggerSocket sls(&mock);

  ON_CALL(mock, Select).WillByDefault((Return(-1)));
  ON_CALL(mock, GetErrno()).WillByDefault((Return(EINVAL)));

  ASSERT_FALSE(sls.ProcessIncomingRequest());
}

TEST_F(SnoopLoggerSocketModuleTest, test_ProcessIncomingRequest_no_fds) {
  SyscallWrapperMock mock;
  SnoopLoggerSocket sls(&mock);

  ON_CALL(mock, Select).WillByDefault((Return(0)));

  ASSERT_TRUE(sls.ProcessIncomingRequest());
}

TEST_F(SnoopLoggerSocketModuleTest, test_ProcessIncomingRequest_FDIsSet_false) {
  SyscallWrapperMock mock;
  SnoopLoggerSocket sls(&mock);

  int fd = 11;
  int listen_fd = 66;
  int write_fd = 99;

  ON_CALL(mock, Socket(_, _, _)).WillByDefault((Return(fd)));
  ON_CALL(mock, Setsockopt(_, _, _, _, _)).WillByDefault((Return(0)));
  ON_CALL(mock, Bind(_, _, _)).WillByDefault((Return(0)));
  ON_CALL(mock, Listen(_, _)).WillByDefault((Return(0)));
  ON_CALL(mock, Pipe2).WillByDefault(Invoke([&](int* fds, int) {
    fds[0] = listen_fd;
    fds[1] = write_fd;
    return 0;
  }));

  ON_CALL(mock, Select).WillByDefault((Return(0)));
  ON_CALL(mock, FDIsSet(fd, _)).WillByDefault((Return(false)));
  ON_CALL(mock, FDIsSet(listen_fd, _)).WillByDefault((Return(false)));

  ASSERT_EQ(sls.InitializeCommunications(), 0);
  ASSERT_TRUE(sls.ProcessIncomingRequest());
}

TEST_F(SnoopLoggerSocketModuleTest, test_ProcessIncomingRequest_signal_close) {
  SyscallWrapperMock mock;
  SnoopLoggerSocket sls(&mock);

  int fd = 11;
  int listen_fd = 66;
  int write_fd = 99;

  ON_CALL(mock, Socket(_, _, _)).WillByDefault((Return(fd)));
  ON_CALL(mock, Setsockopt(_, _, _, _, _)).WillByDefault((Return(0)));
  ON_CALL(mock, Bind(_, _, _)).WillByDefault((Return(0)));
  ON_CALL(mock, Listen(_, _)).WillByDefault((Return(0)));
  ON_CALL(mock, Pipe2).WillByDefault(Invoke([&](int* fds, int) {
    fds[0] = listen_fd;
    fds[1] = write_fd;
    return 0;
  }));

  ON_CALL(mock, Select).WillByDefault((Return(0)));
  ON_CALL(mock, FDIsSet(fd, _)).WillByDefault((Return(false)));
  ON_CALL(mock, FDIsSet(listen_fd, _)).WillByDefault((Return(true)));

  ASSERT_EQ(sls.InitializeCommunications(), 0);
  ASSERT_FALSE(sls.ProcessIncomingRequest());
}

TEST_F(SnoopLoggerSocketModuleTest, test_ProcessIncomingRequest_signal_incoming_connection_fail_on_accept_exit) {
  SyscallWrapperMock mock;
  SnoopLoggerSocket sls(&mock);

  int fd = 11;
  int listen_fd = 66;
  int write_fd = 99;

  ON_CALL(mock, Socket(_, _, _)).WillByDefault((Return(fd)));
  ON_CALL(mock, Setsockopt(_, _, _, _, _)).WillByDefault((Return(0)));
  ON_CALL(mock, Bind(_, _, _)).WillByDefault((Return(0)));
  ON_CALL(mock, Listen(_, _)).WillByDefault((Return(0)));
  ON_CALL(mock, Pipe2).WillByDefault(Invoke([&](int* fds, int) {
    fds[0] = listen_fd;
    fds[1] = write_fd;
    return 0;
  }));

  ON_CALL(mock, Select).WillByDefault((Return(0)));
  ON_CALL(mock, FDIsSet(fd, _)).WillByDefault((Return(true)));
  ON_CALL(mock, FDIsSet(listen_fd, _)).WillByDefault((Return(false)));

  ON_CALL(mock, Accept(fd, _, _, _)).WillByDefault(Return(INVALID_FD));
  ON_CALL(mock, GetErrno()).WillByDefault(Return(EINVAL));

  ASSERT_EQ(sls.InitializeCommunications(), 0);
  ASSERT_FALSE(sls.ProcessIncomingRequest());
}

TEST_F(SnoopLoggerSocketModuleTest, test_ProcessIncomingRequest_signal_incoming_connection_fail_on_accept_continue) {
  SyscallWrapperMock mock;
  SnoopLoggerSocket sls(&mock);

  int fd = 11;
  int listen_fd = 66;
  int write_fd = 99;

  ON_CALL(mock, Socket(_, _, _)).WillByDefault((Return(fd)));
  ON_CALL(mock, Setsockopt(_, _, _, _, _)).WillByDefault((Return(0)));
  ON_CALL(mock, Bind(_, _, _)).WillByDefault((Return(0)));
  ON_CALL(mock, Listen(_, _)).WillByDefault((Return(0)));
  ON_CALL(mock, Pipe2).WillByDefault(Invoke([&](int* fds, int) {
    fds[0] = listen_fd;
    fds[1] = write_fd;
    return 0;
  }));

  ON_CALL(mock, Select).WillByDefault((Return(0)));
  ON_CALL(mock, FDIsSet(fd, _)).WillByDefault((Return(true)));
  ON_CALL(mock, FDIsSet(listen_fd, _)).WillByDefault((Return(false)));

  ON_CALL(mock, Accept(fd, _, _, _)).WillByDefault(Return(INVALID_FD));
  ON_CALL(mock, GetErrno()).WillByDefault(Return(ENOMEM));

  ASSERT_EQ(sls.InitializeCommunications(), 0);
  ASSERT_TRUE(sls.ProcessIncomingRequest());
}

TEST_F(SnoopLoggerSocketModuleTest, test_ProcessIncomingRequest_signal_incoming_connection_success) {
  SyscallWrapperMock mock;
  SnoopLoggerSocket sls(&mock);

  int fd = 11;
  int client_fd = 23;
  int listen_fd = 66;
  int write_fd = 99;

  ON_CALL(mock, Socket(_, _, _)).WillByDefault((Return(fd)));
  ON_CALL(mock, Setsockopt(_, _, _, _, _)).WillByDefault((Return(0)));
  ON_CALL(mock, Bind(_, _, _)).WillByDefault((Return(0)));
  ON_CALL(mock, Listen(_, _)).WillByDefault((Return(0)));
  ON_CALL(mock, Pipe2).WillByDefault(Invoke([&](int* fds, int) {
    fds[0] = listen_fd;
    fds[1] = write_fd;
    return 0;
  }));

  ON_CALL(mock, Select).WillByDefault((Return(0)));
  ON_CALL(mock, FDIsSet(fd, _)).WillByDefault((Return(true)));
  ON_CALL(mock, FDIsSet(listen_fd, _)).WillByDefault((Return(false)));

  ON_CALL(mock, Accept(fd, _, _, _)).WillByDefault(Return(client_fd));
  ON_CALL(mock, GetErrno()).WillByDefault(Return(0));

  EXPECT_CALL(mock, Send(client_fd, _, _, _)).Times(1);

  ASSERT_EQ(sls.InitializeCommunications(), 0);
  ASSERT_TRUE(sls.ProcessIncomingRequest());
}

TEST_F(SnoopLoggerSocketModuleTest, test_NotifySocketListener_no_fd) {
  SyscallWrapperMock mock;
  SnoopLoggerSocket sls(&mock);

  ASSERT_EQ(sls.NotifySocketListener(), 0);
}

TEST_F(SnoopLoggerSocketModuleTest, test_NotifySocketListener_fail_on_write) {
  SyscallWrapperMock mock;
  SnoopLoggerSocket sls(&mock);

  int fd = 11;
  int listen_fd = 66;
  int write_fd = 99;

  ON_CALL(mock, Socket(_, _, _)).WillByDefault((Return(fd)));
  ON_CALL(mock, Setsockopt(_, _, _, _, _)).WillByDefault((Return(0)));
  ON_CALL(mock, Bind(_, _, _)).WillByDefault((Return(0)));
  ON_CALL(mock, Listen(_, _)).WillByDefault((Return(0)));
  ON_CALL(mock, Pipe2).WillByDefault(Invoke([&](int* fds, int) {
    fds[0] = listen_fd;
    fds[1] = write_fd;
    return 0;
  }));

  ON_CALL(mock, Write).WillByDefault((Return(-1)));

  EXPECT_CALL(mock, Write(write_fd, _, _)).Times(1);

  ASSERT_EQ(sls.InitializeCommunications(), 0);
  ASSERT_EQ(sls.NotifySocketListener(), -1);
}

TEST_F(SnoopLoggerSocketModuleTest, test_NotifySocketListener_fail_on_write_EINTR_success) {
  SyscallWrapperMock mock;
  SnoopLoggerSocket sls(&mock);
  int fd = 11;
  int listen_fd = 66;
  int write_fd = 99;
  int intr_count = 5;

  ON_CALL(mock, Socket(_, _, _)).WillByDefault((Return(fd)));
  ON_CALL(mock, Setsockopt(_, _, _, _, _)).WillByDefault((Return(0)));
  ON_CALL(mock, Bind(_, _, _)).WillByDefault((Return(0)));
  ON_CALL(mock, Listen(_, _)).WillByDefault((Return(0)));
  ON_CALL(mock, Pipe2).WillByDefault(Invoke([&](int* fds, int) {
    fds[0] = listen_fd;
    fds[1] = write_fd;
    return 0;
  }));

  ON_CALL(mock, Write).WillByDefault(Invoke([&](int, const void*, size_t count) {
    if (intr_count > 0) {
      intr_count--;
      errno = EINTR;
      return (ssize_t)-1;
    }
    errno = 0;
    return (ssize_t)count;
  }));

  EXPECT_CALL(mock, Write(write_fd, _, _)).Times(intr_count + 1);

  ASSERT_EQ(sls.InitializeCommunications(), 0);
  ASSERT_EQ(sls.NotifySocketListener(), 0);
}

TEST_F(SnoopLoggerSocketModuleTest, test_NotifySocketListener_success) {
  SyscallWrapperMock mock;
  SnoopLoggerSocket sls(&mock);

  int fd = 11;
  int listen_fd = 66;
  int write_fd = 99;

  ON_CALL(mock, Socket(_, _, _)).WillByDefault((Return(fd)));
  ON_CALL(mock, Setsockopt(_, _, _, _, _)).WillByDefault((Return(0)));
  ON_CALL(mock, Bind(_, _, _)).WillByDefault((Return(0)));
  ON_CALL(mock, Listen(_, _)).WillByDefault((Return(0)));
  ON_CALL(mock, Pipe2).WillByDefault(Invoke([&](int* fds, int) {
    fds[0] = listen_fd;
    fds[1] = write_fd;
    return 0;
  }));

  ON_CALL(mock, Write).WillByDefault((Return(0)));

  EXPECT_CALL(mock, Write(write_fd, _, _)).Times(1);

  ASSERT_EQ(sls.InitializeCommunications(), 0);
  ASSERT_EQ(sls.NotifySocketListener(), 0);
}

}  // namespace testing
