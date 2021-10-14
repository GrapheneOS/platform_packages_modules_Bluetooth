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

#include "btif_storage_mock.h"

#include <base/logging.h>

static bluetooth::storage::MockBtifStorageInterface* btif_storage_interface =
    nullptr;

void bluetooth::storage::SetMockBtifStorageInterface(
    MockBtifStorageInterface* mock_btif_storage_interface) {
  btif_storage_interface = mock_btif_storage_interface;
}

void btif_storage_set_leaudio_autoconnect(RawAddress const& addr,
                                          bool autoconnect) {
  LOG_ASSERT(btif_storage_interface) << "Mock storage module not set!";
  btif_storage_interface->AddLeaudioAutoconnect(addr, autoconnect);
}

void btif_storage_remove_leaudio(RawAddress const& addr) {
  LOG_ASSERT(btif_storage_interface) << "Mock storage module not set!";
  btif_storage_interface->RemoveLeaudio(addr);
}