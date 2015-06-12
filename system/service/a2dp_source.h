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

#include "hardware/bluetooth.h"
#include "hardware/bt_av.h"

namespace bluetooth {

class CoreStack;

// This class is just experimental to test out BlueDroid A2DP
// interface, capability, and functionality.
class A2dpSource {
 public:
  explicit A2dpSource(CoreStack* bt);

  // Enables the A2DP source profile in the stack.
  // Creates audio Unix sockets. (see audio_a2dp_hw.h)
  int Start();

  // Disables the A2DP source profile in the stack.
  int Stop();

 private:
  const btav_interface_t* av_;
  // Weak reference.
  CoreStack* bt_;
};

}  // namespace bluetooth
