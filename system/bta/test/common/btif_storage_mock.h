/*
 * Copyright 2021 HIMSA II K/S - www.himsa.com.
 * Represented by EHIMA - www.ehima.com
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

#include <gmock/gmock.h>

#include "types/raw_address.h"

namespace bluetooth {
namespace storage {

class BtifStorageInterface {
 public:
  virtual void AddLeaudioAutoconnect(RawAddress const& addr,
                                     bool autoconnect) = 0;
  virtual void RemoveLeaudio(RawAddress const& addr) = 0;
  virtual ~BtifStorageInterface() = default;
};

class MockBtifStorageInterface : public BtifStorageInterface {
 public:
  MOCK_METHOD((void), AddLeaudioAutoconnect,
              (RawAddress const& addr, bool autoconnect), (override));
  MOCK_METHOD((void), RemoveLeaudio, (RawAddress const& addr), (override));
};

/**
 * Set the {@link MockBifStorageInterface} for testing
 *
 * @param mock_btif_storage_interface pointer to mock btm security
 * internal interface, could be null
 */
void SetMockBtifStorageInterface(
    MockBtifStorageInterface* mock_btif_storage_interface);

}  // namespace storage
}  // namespace bluetooth
