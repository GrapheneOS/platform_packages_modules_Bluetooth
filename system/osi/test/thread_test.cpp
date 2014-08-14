#include <gtest/gtest.h>

extern "C" {
#include <sys/select.h>
#include <utils/Log.h>

#include "reactor.h"
#include "semaphore.h"
#include "thread.h"
#include "osi.h"
}

typedef struct {
  semaphore_t *wait;
  semaphore_t *read;
} read_wait_pair_t;

TEST(ThreadTest, test_new_simple) {
  thread_t *thread = thread_new("test_thread");
  ASSERT_TRUE(thread != NULL);
  thread_free(thread);
}

TEST(ThreadTest, test_free_simple) {
  thread_t *thread = thread_new("test_thread");
  thread_free(thread);
}

TEST(ThreadTest, test_name) {
  thread_t *thread = thread_new("test_name");
  ASSERT_STREQ(thread_name(thread), "test_name");
  thread_free(thread);
}

TEST(ThreadTest, test_long_name) {
  thread_t *thread = thread_new("0123456789abcdef");
  ASSERT_STREQ("0123456789abcdef", thread_name(thread));
  thread_free(thread);
}

TEST(ThreadTest, test_very_long_name) {
  thread_t *thread = thread_new("0123456789abcdefg");
  ASSERT_STREQ("0123456789abcdef", thread_name(thread));
  thread_free(thread);
}

static void signal_semaphore_when_called(UNUSED_ATTR void *context) {
  read_wait_pair_t *semaphores = (read_wait_pair_t *)context;
  semaphore_wait(semaphores->read);
  semaphore_post(semaphores->wait);
}

TEST(ThreadTest, test_register) {
  read_wait_pair_t semaphores;
  semaphores.wait = semaphore_new(0);
  semaphores.read = semaphore_new(0);

  thread_t *thread = thread_new("test_thread");

  reactor_object_t obj;
  obj.context = &semaphores;
  obj.fd = semaphore_get_fd(semaphores.read);
  obj.interest = REACTOR_INTEREST_READ;
  obj.read_ready = signal_semaphore_when_called;

  thread_register(thread, &obj);

  // See if the reactor picks it up
  semaphore_post(semaphores.read);
  semaphore_wait(semaphores.wait);
  thread_free(thread);
}

TEST(ThreadTest, test_unregister) {
  read_wait_pair_t semaphores;
  semaphores.wait = semaphore_new(0);
  semaphores.read = semaphore_new(0);

  thread_t *thread = thread_new("test_thread");

  reactor_object_t obj;
  obj.context = &semaphores;
  obj.fd = semaphore_get_fd(semaphores.read);
  obj.interest = REACTOR_INTEREST_READ;
  obj.read_ready = signal_semaphore_when_called;

  thread_register(thread, &obj);

  // See if the reactor picks it up
  semaphore_post(semaphores.read);
  semaphore_wait(semaphores.wait);

  thread_unregister(thread, &obj);

  semaphore_post(semaphores.read);

  // Select with a timeout and make sure it times out (should not get data after unregister returns)
  struct timeval timeout;
  timeout.tv_sec = 1;
  timeout.tv_usec = 0;

  int wait_fd = semaphore_get_fd(semaphores.wait);
  fd_set read_fds;

  FD_ZERO(&read_fds);
  FD_SET(wait_fd, &read_fds);

  select(wait_fd + 1, &read_fds, NULL, NULL, &timeout);

  ASSERT_FALSE(FD_ISSET(wait_fd, &read_fds));
  thread_free(thread);
}

static void thread_is_self_fn(void *context) {
  thread_t *thread = (thread_t *)context;
  EXPECT_TRUE(thread_is_self(thread));
}

TEST(ThreadTest, test_thread_is_self) {
  thread_t *thread = thread_new("test_thread");
  thread_post(thread, thread_is_self_fn, thread);
  thread_free(thread);
}

TEST(ThreadTest, test_thread_is_not_self) {
  thread_t *thread = thread_new("test_thread");
  EXPECT_FALSE(thread_is_self(thread));
  thread_free(thread);
}
