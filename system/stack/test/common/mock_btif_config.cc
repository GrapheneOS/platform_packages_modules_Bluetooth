/******************************************************************************
 *
 *  Copyright 2022 The Android Open Source Project
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at:
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 ******************************************************************************/

#include "mock_btif_config.h"

static bluetooth::manager::MockBtifConfigInterface* btif_config_interface =
    nullptr;

void bluetooth::manager::SetMockBtifConfigInterface(
    MockBtifConfigInterface* mock_btif_config_interface) {
  btif_config_interface = mock_btif_config_interface;
}

bool btif_config_get_bin(const std::string& section, const std::string& key,
                         uint8_t* value, size_t* length) {
  return btif_config_interface->GetBin(section, key, value, length);
}

size_t btif_config_get_bin_length(const std::string& section,
                                  const std::string& key) {
  return btif_config_interface->GetBinLength(section, key);
}
