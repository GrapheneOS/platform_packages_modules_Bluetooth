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

#include <poll.h>

#include <memory>
#include <string>
#include <unordered_map>

#include "gatt_server.h"
#include "uuid.h"

namespace bluetooth {

class CoreStack;

// This implements a single threaded event loop which dispatches
// reads from a set of FDs (pfds_) to a set of handlers.
// Reads from the GATT pipe read end will result in a write to
// to the IPC socket, and vise versa.
class Host {
 public:
  // Host owns the passed sockfd.
  Host(int sockfd, CoreStack* bt);
  ~Host();

  // Synchronously handle all events on input FDs.
  bool EventLoop();

 private:
  // Handler for IPC message receives.
  // Decodes protocol and dispatches to another handler.
  bool OnMessage();

  // Handler for GATT characteristic writes.
  // Encodes to protocol and transmits IPC.
  bool OnGattWrite();

  // Applies adapter name changes to stack.
  bool OnSetAdapterName(const std::string& name);

  // Handles service creation.
  bool OnCreateService(const std::string& service_uuid);

  // Handles service destruction.
  bool OnDestroyService(const std::string& service_uuid);

  // Creates a characteristic for a service.
  bool OnAddCharacteristic(const std::string& service_uuid,
                           const std::string& characteristic_uuid,
                           const std::string& control_uuid,
                           const std::string& options);

  // Sets the value of a characetistic.
  bool OnSetCharacteristicValue(const std::string& service_uuid,
                                const std::string& characteristic_uuid,
                                const std::string& value);

  // Applies settings to service advertisement.
  bool OnSetAdvertisement(const std::string& service_uuid,
                          const std::string& advertise_uuids,
                          const std::string& advertise_data,
                          const std::string& transmit_name);

  // Applies settings to scan response.
  bool OnSetScanResponse(const std::string& service_uuid,
                         const std::string& advertise_uuids,
                         const std::string& advertise_data,
                         const std::string& transmit_name);

  // Starts service (advertisement and connections)
  bool OnStartService(const std::string& service_uuid);

  // Stops service.
  bool OnStopService(const std::string& service_uuid);

  // weak reference.
  CoreStack *bt_;

  // File descripters that we will block against.
  std::vector<struct pollfd> pfds_;

  // Container for multiple GATT servers. Currently only one is supported.
  // TODO(icoolidge): support many to one for real.
  std::unordered_map<std::string, std::unique_ptr<gatt::Server>> gatt_servers_;
};

}  // namespace bluetooth
