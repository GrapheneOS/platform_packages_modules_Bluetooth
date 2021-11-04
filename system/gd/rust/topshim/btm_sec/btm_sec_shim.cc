/*
 * Copyright 2021 The Android Open Source Project
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

#include "gd/rust/topshim/btm_sec/btm_sec_shim.h"

#include <memory>

#include "main/shim/btm_api.h"
#include "src/btm_sec.rs.h"
#include "stack/btm/btm_sec.h"
#include "stack/include/hci_error_code.h"
#include "types/bt_transport.h"

namespace bluetooth {
namespace topshim {
namespace rust {
namespace internal {
static BtmSecIntf* g_btm_sec_intf;
static RawAddress from_rust_address(const RustRawAddress& raddr) {
  RawAddress addr;
  addr.FromOctets(raddr.address.data());
  return addr;
}
}  // namespace internal

BtmSecIntf::BtmSecIntf() {}
BtmSecIntf::~BtmSecIntf() {}

void BtmSecIntf::hci_disconnect(RustRawAddress bt_addr) const {
  uint16_t handle = shim::BTM_GetHCIConnHandle(internal::from_rust_address(bt_addr), BT_TRANSPORT_BR_EDR);
  btm_sec_disconnect(handle, tHCI_STATUS::HCI_ERR_UNDEFINED);
}

std::unique_ptr<BtmSecIntf> GetBtmSecInterface() {
  if (internal::g_btm_sec_intf) std::abort();
  auto btm_sec_intf = std::make_unique<BtmSecIntf>();
  internal::g_btm_sec_intf = btm_sec_intf.get();

  return btm_sec_intf;
}

}  // namespace rust
}  // namespace topshim
}  // namespace bluetooth
