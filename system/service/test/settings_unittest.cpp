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

#include <base/at_exit.h>
#include <base/command_line.h>
#include <base/macros.h>
#include <gtest/gtest.h>

#include "service/settings.h"
#include "service/switches.h"

using bluetooth::Settings;
using namespace bluetooth::switches;

namespace {

class SettingsTest : public ::testing::Test {
 public:
  SettingsTest() = default;

  void TearDown() override {
    base::CommandLine::Reset();
  }

 private:
  base::AtExitManager exit_manager;

  DISALLOW_COPY_AND_ASSIGN(SettingsTest);
};

TEST_F(SettingsTest, EmptyCommandLine) {
  const base::CommandLine::CharType* argv[] = { "program" };
  base::CommandLine::Init(arraysize(argv), argv);
  EXPECT_FALSE(Settings::Initialize());
}

TEST_F(SettingsTest, UnexpectedSwitches) {
  const base::CommandLine::CharType* argv[] = {
    "program", "--ipc-socket-path=foobar", "--foobarbaz"
  };
  base::CommandLine::Init(arraysize(argv), argv);
  EXPECT_FALSE(Settings::Initialize());
}

TEST_F(SettingsTest, UnexpectedArguments) {
  const base::CommandLine::CharType* argv[] = {
    "program", "--ipc-socket-path=foobar", "foobarbaz"
  };
  base::CommandLine::Init(arraysize(argv), argv);
  EXPECT_FALSE(Settings::Initialize());
}

TEST_F(SettingsTest, GoodArguments) {
  const base::CommandLine::CharType* argv[] = {
    "program", "--ipc-socket=foobar"
  };
  base::CommandLine::Init(arraysize(argv), argv);
  EXPECT_TRUE(Settings::Initialize());
}

}  // namespace
