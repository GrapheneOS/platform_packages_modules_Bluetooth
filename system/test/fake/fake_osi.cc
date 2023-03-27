/*
 * Copyright 2023 The Android Open Source Project
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

#include "test/fake/fake_osi.h"

#include "test/mock/mock_osi_alarm.h"
#include "test/mock/mock_osi_allocator.h"

// Must be global to resolve the symbol within the legacy stack
struct alarm_t {
  alarm_t(const char* name){};
  int any_value;
};

namespace test {
namespace fake {

FakeOsi::FakeOsi() {
  test::mock::osi_alarm::alarm_free.body = [](alarm_t* alarm) { delete alarm; };
  test::mock::osi_alarm::alarm_new.body = [](const char* name) -> alarm_t* {
    return new alarm_t(name);
  };
  test::mock::osi_allocator::osi_calloc.body = [](size_t size) {
    return calloc(1UL, size);
  };
  test::mock::osi_allocator::osi_free.body = [](void* ptr) { free(ptr); };
  test::mock::osi_allocator::osi_free_and_reset.body = [](void** ptr) {
    free(*ptr);
    *ptr = nullptr;
  };
  test::mock::osi_allocator::osi_malloc.body = [](size_t size) {
    return malloc(size);
  };
}

FakeOsi::~FakeOsi() {
  test::mock::osi_alarm::alarm_free = {};
  test::mock::osi_alarm::alarm_new = {};

  test::mock::osi_allocator::osi_calloc = {};
  test::mock::osi_allocator::osi_free = {};
  test::mock::osi_allocator::osi_free_and_reset = {};
  test::mock::osi_allocator::osi_malloc = {};
}

}  // namespace fake
}  // namespace test
