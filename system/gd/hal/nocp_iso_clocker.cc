/*
 * Copyright 2023 The Android Open Source Project
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

#include "hal/nocp_iso_clocker.h"

namespace bluetooth::hal {

static class : public NocpIsoHandler {
  void OnEvent(uint32_t, int) override {}
} g_empty_handler;

static std::atomic<NocpIsoHandler*> g_handler = &g_empty_handler;

NocpIsoClocker::NocpIsoClocker() : cig_id_(-1), cis_handle_(-1) {}

void NocpIsoClocker::OnHciEvent(const HciPacket& packet) {
  const int HCI_CMD_SET_CIG_PARAMETERS = 0x2062;
  const int HCI_EVT_COMMAND_COMPLETE = 0x0e;
  const int HCI_EVT_NUMBER_OF_COMPLETED_PACKETS = 0x13;

  // HCI Event [Core 4.E.5.4.4]
  // |  [0]  Event Code
  // |  [1]  Parameter Total Length
  // | [2+]  Parameters

  if (packet.size() < 2) return;

  const uint8_t* payload = packet.data() + 2;
  size_t payload_length = std::min(size_t(packet[1]), packet.size() - 2);

  switch (packet[0]) {
      // HCI Command Complete Event [Core 4.E.7.7.14]
      // |    [0]  Num_HCI_Command_Packets, Ignored
      // | [1..2]  Command_Opcode, catch `HCI_LE_Set_CIG_Parameters`
      // |   [3+]  Return Parameters

    case HCI_EVT_COMMAND_COMPLETE: {
      if (payload_length < 3) return;

      int cmd_opcode = payload[1] | (payload[2] << 8);
      if (cmd_opcode != HCI_CMD_SET_CIG_PARAMETERS) return;

      const uint8_t* parameters = payload + 3;
      size_t parameters_length = payload_length - 3;

      // HCI LE Set CIG Parameters return parameters [4.E.7.8.97]
      // |    [0]  Status, 0 when OK
      // |    [1]  CIG_ID
      // |    [2]  CIS_Count
      // | [3..4]  Connection_Handle[0]

      if (parameters_length < 3) return;

      int status = parameters[0];
      int cig_id = parameters[1];
      int cis_count = parameters[2];

      if (status != 0) return;

      if (cig_id_ >= 0 && cis_handle_ >= 0 && cig_id_ != cig_id) {
        LOG_WARN("Multiple groups not supported");
        return;
      }

      cig_id_ = -1;
      cis_handle_ = -1;

      if (cis_count > 0 && parameters_length >= 5) {
        cig_id_ = cig_id;
        cis_handle_ = (parameters[3] | (parameters[4] << 8)) & 0xfff;
      }

      break;
    }

      // HCI Number Of Completed Packets event [Core 4.E.7.7.19]
      // | [0]  Num_Handles
      // | FOR each `Num_Handles` connection handles
      // | | [0..1]  Connection_Handle, catch the CIS Handle
      // | | [2..3]  Num_Completed_Packets

    case HCI_EVT_NUMBER_OF_COMPLETED_PACKETS: {
      if (payload_length < 1) return;

      int i, num_handles = payload[0];
      const uint8_t* item = payload + 1;
      if (payload_length < size_t(1 + 4 * num_handles)) return;

      for (i = 0; i < num_handles && ((item[0] | (item[1] << 8)) & 0xfff) != cis_handle_;
           i++, item += 4)
        ;
      if (i >= num_handles) return;

      auto timestamp = std::chrono::system_clock::now().time_since_epoch();
      unsigned timestamp_us =
          std::chrono::duration_cast<std::chrono::microseconds>(timestamp).count();
      int num_of_completed_packets = item[2] | (item[3] << 8);
      (*g_handler).OnEvent(timestamp_us, num_of_completed_packets);

      break;
    }
  }
}

void NocpIsoClocker::Register(NocpIsoHandler* handler) {
  g_handler = handler;
}
void NocpIsoClocker::Unregister() {
  g_handler = &g_empty_handler;
}

const ModuleFactory NocpIsoClocker::Factory = ModuleFactory([]() { return new NocpIsoClocker(); });

}  // namespace bluetooth::hal
