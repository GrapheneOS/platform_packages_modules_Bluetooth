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

class Uuid {
 public:
  enum Type {
    kUuid128Octets = 16,
    kUuid32Octets = 4,
    kUuid16Octets = 2,
  };

  typedef std::array<uint8_t, Uuid::kUuid16Octets> Uuid16Bit;
  typedef std::array<uint8_t, Uuid::kUuid32Octets> Uuid32Bit;
  typedef std::array<uint8_t, Uuid::kUuid128Octets> Uuid128Bit;

  // Construct a Bluetooth 'base' UUID.
  Uuid();

  // BlueDroid constructor.
  explicit Uuid(const bt_uuid_t& uuid);

  // String constructor. Only hex ASCII accepted.
  explicit Uuid(const std::string& uuid);

  // std::array variants constructors.
  explicit Uuid(const Uuid::Uuid16Bit& uuid);
  explicit Uuid(const Uuid::Uuid32Bit& uuid);
  explicit Uuid(const Uuid::Uuid128Bit& uuid);

  // Provide the full network-byte-ordered blob.
  const Uuid128Bit GetFullBigEndian() const;

  // Provide blob in Little endian (BlueDroid expects this).
  const Uuid128Bit GetFullLittleEndian() const;

  // Helper for bluedroid LE type.
  const bt_uuid_t GetBlueDroid() const;

  bool operator<(const Uuid& rhs) const;
  bool operator==(const Uuid& rhs) const;

 private:
  void InitializeDefault();
  // Network-byte-ordered ID.
  Uuid128Bit id_;
};

}  // namespace bluetooth
