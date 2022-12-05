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

#include <future>
#include <map>

#include "common/bind.h"
#include "hci/address.h"
#include "hci/hci_layer.h"
#include "packet/raw_builder.h"

namespace bluetooth {
namespace hci {

using packet::kLittleEndian;
using packet::PacketView;

PacketView<kLittleEndian> GetPacketView(std::unique_ptr<packet::BasePacketBuilder> packet);

class TestHciLayer : public HciLayer {
 public:
  void EnqueueCommand(
      std::unique_ptr<CommandBuilder> command,
      common::ContextualOnceCallback<void(CommandStatusView)> on_status) override;

  void EnqueueCommand(
      std::unique_ptr<CommandBuilder> command,
      common::ContextualOnceCallback<void(CommandCompleteView)> on_complete) override;

  // Set command future for 'num_command' commands are expected
  void SetCommandFuture(uint16_t num_command);

  CommandView GetCommand();

  void RegisterEventHandler(EventCode event_code, common::ContextualCallback<void(EventView)> event_handler) override;

  void UnregisterEventHandler(EventCode event_code) override;

  void RegisterLeEventHandler(
      SubeventCode subevent_code, common::ContextualCallback<void(LeMetaEventView)> event_handler) override;

  void UnregisterLeEventHandler(SubeventCode subevent_code) override;

  void IncomingEvent(std::unique_ptr<EventBuilder> event_builder);

  void IncomingLeMetaEvent(std::unique_ptr<LeMetaEventBuilder> event_builder);

  void CommandCompleteCallback(EventView event);

  void CommandStatusCallback(EventView event);

  void InitEmptyCommand();

 protected:
  void ListDependencies(ModuleList* list) const override;
  void Start() override;
  void Stop() override;

 private:
  std::map<EventCode, common::ContextualCallback<void(EventView)>> registered_events_;
  std::map<SubeventCode, common::ContextualCallback<void(LeMetaEventView)>> registered_le_events_;
  std::list<common::ContextualOnceCallback<void(CommandCompleteView)>> command_complete_callbacks;
  std::list<common::ContextualOnceCallback<void(CommandStatusView)>> command_status_callbacks;
  std::queue<std::unique_ptr<CommandBuilder>> command_queue_;
  std::unique_ptr<std::promise<void>> command_promise_;
  std::unique_ptr<std::future<void>> command_future_;
  mutable std::mutex mutex_;
  uint16_t command_count_ = 0;
  CommandView empty_command_view_ =
      CommandView::Create(PacketView<packet::kLittleEndian>(std::make_shared<std::vector<uint8_t>>()));
};

}  // namespace hci
}  // namespace bluetooth