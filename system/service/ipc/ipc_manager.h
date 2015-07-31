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

#include <memory>

#include <base/macros.h>
#include <base/memory/ref_counted.h>

namespace bluetooth {
class CoreStack;
}  // namespace bluetooth

namespace ipc {

class IPCHandler;

// IPCManager is a class for initializing and running supported IPC mechanisms.
// It manages the life-time of different IPC flavors that are available on the
// system. There are two flavors: a plain UNIX domain socket based system and
// one based on the Binder-based android.bluetooth framework.
class IPCManager {
 public:
  // Possible IPC types.
  enum Type {
    TYPE_UNIX,  // IPC based on a UNIX domain socket
    TYPE_BINDER  // IPC based on the Binder
  };

  explicit IPCManager(bluetooth::CoreStack* core_stack);
  ~IPCManager();

  // Initialize the underlying IPC handler based on |type|, if that type has not
  // yet been initialized and returns true on success. Returns false if that
  // type has already been initialized or an error occurs.
  //
  // If TYPE_UNIX is given, the file path to use for the domain socket will be
  // obtained from the global Settings object. Hence, the Settings object must
  // have been initialized before calling this method.
  bool Start(Type type);

  // Returns true if an IPC type has been initialized.
  bool BinderStarted() const;
  bool UnixStarted() const;

 private:
  IPCManager() = default;

  // Pointers to the different IPC handler classes. These are initialized and
  // owned by us.
  scoped_refptr<IPCHandler> binder_handler_;
  scoped_refptr<IPCHandler> unix_handler_;

  // The global CoreStack instance that represents the current Bluetooth
  // adapter.
  bluetooth::CoreStack* core_stack_;

  DISALLOW_COPY_AND_ASSIGN(IPCManager);
};

}  // namespace ipc
