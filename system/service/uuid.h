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

#include <base/hash.h>

#include "hardware/bluetooth.h"

namespace bluetooth {

class UUID {
 public:
  static constexpr int kNumBytes128 = 16;
  static constexpr int kNumBytes32 = 4;
  static constexpr int kNumBytes16 = 2;

  typedef std::array<uint8_t, kNumBytes16> UUID16Bit;
  typedef std::array<uint8_t, kNumBytes32> UUID32Bit;
  typedef std::array<uint8_t, kNumBytes128> UUID128Bit;

  // Creates and returns a random 128-bit UUID.
  static UUID GetRandom();

  // Construct a Bluetooth 'base' UUID.
  UUID();

  // BlueDroid constructor.
  explicit UUID(const bt_uuid_t& uuid);

  // String constructor. Only hex ASCII accepted.
  explicit UUID(const std::string& uuid);

  // std::array variants constructors.
  explicit UUID(const UUID16Bit& uuid);
  explicit UUID(const UUID32Bit& uuid);
  explicit UUID(const UUID128Bit& uuid);

  // Provide the full network-byte-ordered blob.
  const UUID128Bit GetFullBigEndian() const;

  // Provide blob in Little endian (BlueDroid expects this).
  const UUID128Bit GetFullLittleEndian() const;

  // Helper for bluedroid LE type.
  const bt_uuid_t GetBlueDroid() const;

  // Returns a string representation for the UUID.
  std::string ToString() const;

  bool operator<(const UUID& rhs) const;
  bool operator==(const UUID& rhs) const;

 private:
  void InitializeDefault();
  // Network-byte-ordered ID.
  UUID128Bit id_;
};

}  // namespace bluetooth

// Custom std::hash specialization so that bluetooth::UUID can be used as a key
// in std::unordered_map.
namespace std {

template<>
struct hash<bluetooth::UUID> {
  std::size_t operator()(const bluetooth::UUID& key) const {
    // Compute individual hash values for each byte and then combine them using
    // XOR and bitshifting.
    const auto& uuid_bytes = key.GetFullBigEndian();

    return base::SuperFastHash(reinterpret_cast<const char*>(uuid_bytes.data()),
                               uuid_bytes.size());
  }
};

}  // namespace std
