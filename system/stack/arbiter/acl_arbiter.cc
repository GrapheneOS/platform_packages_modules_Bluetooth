/*
 * Copyright 2022 The Android Open Source Project
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

#include "stack/arbiter/acl_arbiter.h"

#include <base/bind.h>

#include "os/log.h"
#include "osi/include/allocator.h"
#include "stack/gatt/gatt_int.h"
#include "stack/include/btu.h"  // do_in_main_thread
#include "stack/include/l2c_api.h"

namespace bluetooth {
namespace shim {
namespace arbiter {

class RustGattAclArbiter {
 public:
  void SendPacketToPeer(uint8_t tcb_idx, ::rust::Vec<uint8_t> buffer) {
    tGATT_TCB* p_tcb = gatt_get_tcb_by_idx(tcb_idx);
    if (p_tcb != nullptr) {
      BT_HDR* p_buf = (BT_HDR*)osi_malloc(sizeof(BT_HDR) + buffer.size() +
                                          L2CAP_MIN_OFFSET);
      if (p_buf == nullptr) {
        LOG_ALWAYS_FATAL("OOM when sending packet");
      }
      auto p = (uint8_t*)(p_buf + 1) + L2CAP_MIN_OFFSET;
      std::copy(buffer.begin(), buffer.end(), p);
      p_buf->offset = L2CAP_MIN_OFFSET;
      p_buf->len = buffer.size();
      L2CA_SendFixedChnlData(L2CAP_ATT_CID, p_tcb->peer_bda, p_buf);
    } else {
      LOG_ERROR("Dropping packet since connection no longer exists");
    }
  }

  static RustGattAclArbiter& Get() {
    static auto singleton = RustGattAclArbiter();
    return singleton;
  }
};

void SendPacketToPeer(uint8_t tcb_idx, ::rust::Vec<uint8_t> buffer) {
  do_in_main_thread(FROM_HERE,
                    base::Bind(&RustGattAclArbiter::SendPacketToPeer,
                               base::Unretained(&RustGattAclArbiter::Get()),
                               tcb_idx, std::move(buffer)));
}

}  // namespace arbiter
}  // namespace shim
}  // namespace bluetooth
