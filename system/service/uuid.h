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

#include <array>
#include <string>

#include "hardware/bluetooth.h"

namespace bluetooth {

class UUID {
 public:
  enum Type {
    kUUID128Octets = 16,
    kUUID32Octets = 4,
    kUUID16Octets = 2,
  };

  typedef std::array<uint8_t, UUID::kUUID16Octets> UUID16Bit;
  typedef std::array<uint8_t, UUID::kUUID32Octets> UUID32Bit;
  typedef std::array<uint8_t, UUID::kUUID128Octets> UUID128Bit;

  // Construct a Bluetooth 'base' UUID.
  UUID();

  // BlueDroid constructor.
  explicit UUID(const bt_uuid_t& uuid);

  // String constructor. Only hex ASCII accepted.
  explicit UUID(const std::string& uuid);

  // std::array variants constructors.
  explicit UUID(const UUID::UUID16Bit& uuid);
  explicit UUID(const UUID::UUID32Bit& uuid);
  explicit UUID(const UUID::UUID128Bit& uuid);

  // Provide the full network-byte-ordered blob.
  const UUID128Bit GetFullBigEndian() const;

  // Provide blob in Little endian (BlueDroid expects this).
  const UUID128Bit GetFullLittleEndian() const;

  // Helper for bluedroid LE type.
  const bt_uuid_t GetBlueDroid() const;

  bool operator<(const UUID& rhs) const;
  bool operator==(const UUID& rhs) const;

 private:
  void InitializeDefault();
  // Network-byte-ordered ID.
  UUID128Bit id_;
};

}  // namespace bluetooth
