//
//  Copyright (C) 2015 Google, Inc.
//
//  Licensed under the Apache License, Version 2.0 (the "License");
//  you may not use this file except in compliance with the License.
//  You may obtain a copy of the License at:
//
//  http://www.apache.org/licenses/LICENSE-2.0
//
//  Unless required by applicable law or agreed to in writing, software
//  distributed under the License is distributed on an "AS IS" BASIS,
//  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//  See the License for the specific language governing permissions and
//  limitations under the License.
//

#pragma once

#include <gmock/gmock.h>

#include "service/core_stack.h"

namespace bluetooth {
namespace testing {

class MockCoreStack : public CoreStack {
 public:
  MockCoreStack() = default;
  ~MockCoreStack() override = default;

  MOCK_METHOD0(Initialize, bool());
  MOCK_METHOD1(SetAdapterName, bool(const std::string&));
  MOCK_METHOD0(SetClassicDiscoverable, bool());
  MOCK_METHOD1(GetInterface, const void*(const char*));

 private:
  DISALLOW_COPY_AND_ASSIGN(MockCoreStack);
};

}  // namespace testing
}  // namespace bluetooth
