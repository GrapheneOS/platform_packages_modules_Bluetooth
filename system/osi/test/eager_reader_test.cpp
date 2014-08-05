/******************************************************************************
 *
 *  Copyright (C) 2014 Google, Inc.
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

#include <gtest/gtest.h>

extern "C" {
#include <stdint.h>
#include <unistd.h>
#include <utils/Log.h>

#include "allocator.h"
#include "eager_reader.h"
#include "osi.h"
#include "semaphore.h"
#include "thread.h"
}

#define BUFFER_SIZE 32

static char *small_data = (char *)"white chocolate lindor truffles";

static semaphore_t *done;

class EagerReaderTest : public ::testing::Test {
  protected:
    virtual void SetUp() {
      pipe(pipefd);
      done = semaphore_new(0);
    }

    virtual void TearDown() {
      semaphore_free(done);
    }

    int pipefd[2];
};

static void expect_data(eager_reader_t *reader, void *context) {
  EXPECT_TRUE(eager_reader_has_byte(reader)) << "if we got a callback we expect there to be data";

  char *data = (char *)context;
  int length = strlen(data);
  int i;

  for (i = 0; i < length; i++) {
    EXPECT_EQ(data[i], eager_reader_read_byte(reader));
  }

  semaphore_post(done);
}

TEST_F(EagerReaderTest, test_new_simple) {
  eager_reader_t *reader = eager_reader_new(pipefd[0], &allocator_malloc, BUFFER_SIZE, SIZE_MAX, (char *)"test_thread");
  ASSERT_TRUE(reader != NULL);
}

TEST_F(EagerReaderTest, test_free_simple) {
  eager_reader_t *reader = eager_reader_new(pipefd[0], &allocator_malloc, BUFFER_SIZE, SIZE_MAX, (char *)"test_thread");
  eager_reader_free(reader);
}

TEST_F(EagerReaderTest, test_small_data) {
  eager_reader_t *reader = eager_reader_new(pipefd[0], &allocator_malloc, BUFFER_SIZE, SIZE_MAX, (char *)"test_thread");

  thread_t *read_thread = thread_new("read_thread");
  eager_reader_register(reader, thread_get_reactor(read_thread), expect_data, small_data);

  write(pipefd[1], small_data, strlen(small_data));

  semaphore_wait(done);
  eager_reader_free(reader);
  thread_free(read_thread);
}
