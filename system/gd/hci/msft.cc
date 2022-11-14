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
#include "hci/msft.h"

#include "hal/hci_hal.h"
#include "hci/hci_layer.h"
#include "hci/hci_packets.h"
#include "hci/vendor_specific_event_manager.h"

namespace bluetooth {
namespace hci {

// https://learn.microsoft.com/en-us/windows-hardware/drivers/bluetooth/
//         microsoft-defined-bluetooth-hci-commands-and-events
constexpr uint8_t kMsftEventPrefixLengthMax = 0x20;

struct Msft {
  // MSFT opcode needs to be configured from Bluetooth driver.
  std::optional<uint16_t> opcode;
  uint64_t features{0};
  std::vector<uint8_t> prefix;
};

const ModuleFactory MsftExtensionManager::Factory = ModuleFactory([]() { return new MsftExtensionManager(); });

struct MsftExtensionManager::impl {
  impl(Module* module) : module_(module){};

  ~impl() {}

  void start(
      os::Handler* handler,
      hal::HciHal* hal,
      hci::HciLayer* hci_layer,
      hci::VendorSpecificEventManager* vendor_specific_event_manager) {
    LOG_INFO("MsftExtensionManager start()");
    module_handler_ = handler;
    hal_ = hal;
    hci_layer_ = hci_layer;
    vendor_specific_event_manager_ = vendor_specific_event_manager;

    /*
     * The MSFT opcode is assigned by Bluetooth controller vendors.
     * Query the kernel/drivers to derive the MSFT opcode so that
     * we can issue MSFT vendor specific commands.
     */
    if (!supports_msft_extensions()) {
      LOG_INFO("MSFT extension is not supported.");
      return;
    }

    /*
     * The vendor prefix is required to distinguish among the vendor events
     * of different vendor specifications. Read the supported features to
     * derive the vendor prefix as well as other supported features.
     */
    hci_layer_->EnqueueCommand(
        MsftReadSupportedFeaturesBuilder::Create(static_cast<OpCode>(msft_.opcode.value())),
        module_handler_->BindOnceOn(this, &impl::on_msft_read_supported_features_complete));
  }

  void stop() {
    LOG_INFO("MsftExtensionManager stop()");
  }

  void handle_msft_events(VendorSpecificEventView event) {
    // TODO(b/246398494): MSFT events are vendor specific events with an event prefix.

    /* Myles suggested that the structure look like
    auto payload = event.GetPayload();
    for (size_t i = 0; i < msft_.prefix.size(); i++) {
      if (msft_.prefix[i] != payload[i]) {
        // Print a warning and return
      }
    }

    MsftEventPayloadView::Create(payload.GetLittleEndianSubview(msft_.prefix.size(), payload.size()));
    // Assert that it's valid
    // Check the type of event
    // Cast it, and handle it.
    */
  }

  bool supports_msft_extensions() {
    if (msft_.opcode.has_value()) return true;

    uint16_t opcode = hal_->getMsftOpcode();
    if (opcode == 0) return false;

    msft_.opcode = opcode;
    LOG_INFO("MSFT opcode 0x%4.4x", msft_.opcode.value());
    return true;
  }

  /*
   * Get the event prefix from the packet for configuring MSFT's
   * Vendor Specific events. Also get the MSFT supported features.
   */
  void on_msft_read_supported_features_complete(CommandCompleteView view) {
    ASSERT(view.IsValid());
    auto status_view = MsftReadSupportedFeaturesCommandCompleteView::Create(MsftCommandCompleteView::Create(view));
    ASSERT(status_view.IsValid());

    if (status_view.GetStatus() != ErrorCode::SUCCESS) {
      LOG_WARN("MSFT Command complete status %s", ErrorCodeText(status_view.GetStatus()).c_str());
      return;
    }

    MsftSubcommandOpcode sub_opcode = status_view.GetSubcommandOpcode();
    if (sub_opcode != MsftSubcommandOpcode::MSFT_READ_SUPPORTED_FEATURES) {
      LOG_WARN("Wrong MSFT subcommand opcode %hhu returned", sub_opcode);
      return;
    }

    msft_.features = status_view.GetSupportedFeatures();

    // Save the vendor prefix to distinguish upcoming MSFT vendor events.
    auto prefix = status_view.GetPrefix();
    msft_.prefix.assign(prefix.begin(), prefix.end());

    if (prefix.size() > kMsftEventPrefixLengthMax)
      LOG_WARN("The MSFT prefix length %u is too large", (unsigned int)prefix.size());

    LOG_INFO(
        "MSFT features 0x%16.16llx prefix length %u", (unsigned long long)msft_.features, (unsigned int)prefix.size());
  }

  Module* module_;
  os::Handler* module_handler_;
  hal::HciHal* hal_;
  hci::HciLayer* hci_layer_;
  hci::VendorSpecificEventManager* vendor_specific_event_manager_;
  Msft msft_;
};

MsftExtensionManager::MsftExtensionManager() {
  LOG_INFO("MsftExtensionManager()");
  pimpl_ = std::make_unique<impl>(this);
}

void MsftExtensionManager::ListDependencies(ModuleList* list) const {
  list->add<hal::HciHal>();
  list->add<hci::HciLayer>();
  list->add<hci::VendorSpecificEventManager>();
}

void MsftExtensionManager::Start() {
  pimpl_->start(
      GetHandler(),
      GetDependency<hal::HciHal>(),
      GetDependency<hci::HciLayer>(),
      GetDependency<hci::VendorSpecificEventManager>());
}

void MsftExtensionManager::Stop() {
  pimpl_->stop();
}

std::string MsftExtensionManager::ToString() const {
  return "Microsoft Extension Manager";
}

}  // namespace hci
}  // namespace bluetooth
