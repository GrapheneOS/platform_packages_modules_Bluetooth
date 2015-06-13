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
#include "uuid.h"

#include <algorithm>
#include <array>
#include <stack>
#include <string>

namespace bluetooth {

void Uuid::InitializeDefault() {
  // Initialize to base bluetooth UUID.
  id_ = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00,
         0x80, 0x00, 0x00, 0x80, 0x5f, 0x9b, 0x34, 0xfb};
}

Uuid::Uuid() {
  InitializeDefault();
}

Uuid::Uuid(const std::string& uuid) {
  InitializeDefault();
  const int start_index = uuid.size() == 4 ? 2 : 0;
  const size_t copy_size = std::min(id_.size(), uuid.size() / 2);
  for (size_t i = 0; i < copy_size; ++i) {
    std::string octet_text(uuid, i * 2, 2);
    id_[start_index + i] = std::stoul(octet_text, 0, 16);
  }
}

Uuid::Uuid(const bt_uuid_t& uuid) {
  std::reverse_copy(uuid.uu, uuid.uu + sizeof(uuid.uu), id_.begin());
}

Uuid::Uuid(const Uuid::Uuid16Bit& uuid) {
  InitializeDefault();
  std::copy(uuid.begin(), uuid.end(), id_.begin() + kUuid16Octets);
}

Uuid::Uuid(const Uuid::Uuid32Bit& uuid) {
  InitializeDefault();
  std::copy(uuid.begin(), uuid.end(), id_.begin());
}

Uuid::Uuid(const Uuid::Uuid128Bit& uuid) : id_(uuid) {}

const Uuid::Uuid128Bit Uuid::GetFullBigEndian() const {
  return id_;
}

const Uuid::Uuid128Bit Uuid::GetFullLittleEndian() const {
  Uuid::Uuid128Bit ret;
  std::reverse_copy(id_.begin(), id_.end(), ret.begin());
  return ret;
}

const bt_uuid_t Uuid::GetBlueDroid() const {
  bt_uuid_t ret;
  std::reverse_copy(id_.begin(), id_.end(), ret.uu);
  return ret;
}

bool Uuid::operator<(const Uuid& rhs) const {
  return std::lexicographical_compare(id_.begin(), id_.end(), rhs.id_.begin(),
                                      rhs.id_.end());
}

bool Uuid::operator==(const Uuid& rhs) const {
  return std::equal(id_.begin(), id_.end(), rhs.id_.begin());
}

}  // namespace bluetooth
