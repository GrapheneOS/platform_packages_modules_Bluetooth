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

#include <base/macros.h>
#include <base/memory/ref_counted.h>

namespace bluetooth {
class CoreStack;
}  // namespace bluetooth

namespace ipc {

// IPCHandler is an interface that classes implementing different IPC mechanisms
// must conform to.
class IPCHandler : public base::RefCountedThreadSafe<IPCHandler> {
 public:
  explicit IPCHandler(bluetooth::CoreStack* core_stack);
  virtual ~IPCHandler();

  // Initializes and runs the IPC mechanis. Returns true on success, false
  // otherwise.
  virtual bool Run() = 0;

 protected:
  // Weak reference to the global CoreStack instance.
  bluetooth::CoreStack* core_stack_;

 private:
  IPCHandler() = default;

  DISALLOW_COPY_AND_ASSIGN(IPCHandler);
};

}  // namespace ipc
