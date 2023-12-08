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

#pragma once

#include "hci_hal.h"
#include "module.h"

namespace bluetooth::hal {

class NocpIsoHandler {
 public:
  virtual ~NocpIsoHandler() = default;
  virtual void OnEvent(uint32_t timestamp_us, int num_of_completed_packets) = 0;
};

class NocpIsoClocker : public ::bluetooth::Module {
 public:
  static const ModuleFactory Factory;

  void OnHciEvent(const HciPacket& packet);

  static void Register(NocpIsoHandler* handler);
  static void Unregister();

 protected:
  void ListDependencies(ModuleList*) const override{};
  void Start() override{};
  void Stop() override{};

  std::string ToString() const override {
    return std::string("NocpIsoClocker");
  }

  NocpIsoClocker();

 private:
  int cig_id_;
  int cis_handle_;
};

}  // namespace bluetooth::hal
