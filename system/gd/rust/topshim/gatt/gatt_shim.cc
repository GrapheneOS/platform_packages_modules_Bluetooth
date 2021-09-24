/*
 * Copyright (C) 2021 The Android Open Source Project
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

#include "gd/rust/topshim/gatt/gatt_shim.h"

#include "base/bind.h"
#include "base/callback.h"
#include "rust/cxx.h"
#include "src/profiles/gatt.rs.h"
#include "types/raw_address.h"

namespace bluetooth {
namespace topshim {
namespace rust {

namespace internal {

static RustRawAddress ToRustAddress(const RawAddress& address) {
  RustRawAddress raddr;
  std::copy(std::begin(address.address), std::end(address.address), std::begin(raddr.address));
  return raddr;
}

static RawAddress FromRustAddress(const RustRawAddress& raddr) {
  RawAddress addr;
  addr.FromOctets(raddr.address.data());
  return addr;
}

void ReadPhyCallback(int client_if, RawAddress address, uint8_t tx_phy, uint8_t rx_phy, uint8_t status) {
  bluetooth::topshim::rust::read_phy_callback(client_if, ToRustAddress(address), tx_phy, rx_phy, status);
}

}  // namespace internal

int GattClientIntf::read_phy(int client_if, RustRawAddress addr) {
  RawAddress address = internal::FromRustAddress(addr);
  return client_intf_->read_phy(address, base::Bind(&internal::ReadPhyCallback, client_if, address));
}

std::unique_ptr<GattClientIntf> GetGattClientProfile(const unsigned char* gatt_intf) {
  return std::make_unique<GattClientIntf>(reinterpret_cast<const btgatt_interface_t*>(gatt_intf)->client);
}

}  // namespace rust
}  // namespace topshim
}  // namespace bluetooth
