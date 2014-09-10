#include <gtest/gtest.h>

#include "AllocationTestHarness.h"

extern "C" {
#include "async_result.h"
#include "osi.h"
#include "thread.h"
}

static const char *pass_back_data = "fancy a sandwich? it's a fancy sandwich";

class AsyncResultTest : public AllocationTestHarness {};

static void post_to_result(void *context) {
  async_result_ready((async_result_t *)context, (void *)pass_back_data);
}

TEST_F(AsyncResultTest, test_new_free_simple) {
  async_result_t *result = async_result_new();
  ASSERT_TRUE(result != NULL);
  async_result_free(result);
}

TEST_F(AsyncResultTest, test_result_simple) {
  async_result_t *result = async_result_new();

  thread_t *worker_thread = thread_new("worker thread");
  thread_post(worker_thread, post_to_result, result);

  void *ret = async_result_wait_for(result);
  EXPECT_EQ(ret, pass_back_data);

  thread_free(worker_thread);
  async_result_free(result);
}
