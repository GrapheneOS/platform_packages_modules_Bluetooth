/*
 * Copyright (C) 2022 The Android Open Source Project
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

#include <bluetooth/log.h>
#include <com_android_bluetooth_flags.h>
#include <hardware/bt_common_types.h>

#include "hci/hci_packets.h"

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

struct MsftExtensionManager::impl {
  impl(os::Handler* handler, hal::HciHal* hal, hci::HciInterface* hci_layer) {
    log::info("MsftExtensionManager start()");
    handler_ = handler;
    hal_ = hal;
    hci_layer_ = hci_layer;

    /*
     * The MSFT opcode is assigned by Bluetooth controller vendors.
     * Query the kernel/drivers to derive the MSFT opcode so that
     * we can issue MSFT vendor specific commands.
     */
    uint16_t opcode = hal_->getMsftOpcode();
    if (opcode == 0) {
      log::info("MSFT extension is not supported.");
      return;
    }
    msft_.opcode = opcode;
    log::info("MSFT opcode 0x{:04x}", msft_.opcode.value());

    /*
     * The vendor prefix is required to distinguish among the vendor events
     * of different vendor specifications. Read the supported features to
     * derive the vendor prefix as well as other supported features.
     */
    hci_layer_->EnqueueCommand(
            MsftReadSupportedFeaturesBuilder::Create(static_cast<OpCode>(msft_.opcode.value())),
            handler_->BindOnceOn(this, &impl::on_msft_read_supported_features_complete));
  }

  ~impl() = default;

  void handle_rssi_event(MsftRssiEventPayloadView /* view */) {
    log::warn("The Microsoft MSFT_RSSI_EVENT is not supported yet.");
  }

  void handle_le_monitor_device_event(MsftLeMonitorDeviceEventPayloadView view) {
    log::assert_that(view.IsValid(), "assert failed: view.IsValid()");

    if (scanning_callbacks_ == nullptr) {
      log::warn("scanning_callbacks_ is null, dropping Microsoft vendor event.");
      return;
    }

    // The monitor state is 0x00 when the controller stops monitoring the device.
    // The monitor state is 0x01 when the controller starts monitoring the device.
    if (view.GetMonitorState() != 0x00 && view.GetMonitorState() != 0x01) {
      log::warn("The Microsoft vendor event monitor state is invalid.");
      return;
    }

    AdvertisingFilterOnFoundOnLostInfo on_found_on_lost_info;
    on_found_on_lost_info.advertiser_address_type = view.GetAddressType();
    on_found_on_lost_info.advertiser_address = view.GetBdAddr();
    on_found_on_lost_info.advertiser_state = view.GetMonitorState();
    on_found_on_lost_info.monitor_handle = view.GetMonitorHandle();

    scanning_callbacks_->OnTrackAdvFoundLost(on_found_on_lost_info);
  }

  void handle_msft_events(VendorSpecificEventView view) {
    auto payload = view.GetPayload();
    for (size_t i = 0; i < msft_.prefix.size() - 1; i++) {
      if (msft_.prefix[i + 1] != payload[i]) {
        log::warn("The Microsoft vendor event prefix does not match.");
        return;
      }
    }

    auto msft_view = MsftEventPayloadView::Create(
            payload.GetLittleEndianSubview(msft_.prefix.size() - 1, payload.size()));
    log::assert_that(msft_view.IsValid(), "assert failed: msft_view.IsValid()");

    MsftEventCode ev_code = msft_view.GetMsftEventCode();
    switch (ev_code) {
      case MsftEventCode::MSFT_RSSI_EVENT:
        handle_rssi_event(MsftRssiEventPayloadView::Create(msft_view));
        break;
      case MsftEventCode::MSFT_LE_MONITOR_DEVICE_EVENT:
        handle_le_monitor_device_event(MsftLeMonitorDeviceEventPayloadView::Create(msft_view));
        break;
      default:
        log::warn("Unknown MSFT event code {}", ev_code);
        break;
    }
  }

  bool supports_msft_extensions() { return msft_.opcode.has_value(); }

  void msft_adv_monitor_add(const MsftAdvMonitor& monitor, MsftAdvMonitorAddCallback cb) {
    if (!supports_msft_extensions()) {
      log::warn("Disallowed as MSFT extension is not supported.");
      return;
    }

    if (com_android_bluetooth_flags_msft_addr_tracking_quirk()) {
      if (monitor.condition_type != MSFT_CONDITION_TYPE_ADDRESS &&
          monitor.condition_type != MSFT_CONDITION_TYPE_PATTERNS) {
        log::warn("Disallowed as MSFT condition type {} is not supported.", monitor.condition_type);
        return;
      }

      if (monitor.condition_type == MSFT_CONDITION_TYPE_ADDRESS) {
        Address addr = monitor.addr_info.bd_addr;
        hci_layer_->EnqueueCommand(
                MsftLeMonitorAdvConditionAddressBuilder::Create(
                        static_cast<OpCode>(msft_.opcode.value()), monitor.rssi_threshold_high,
                        monitor.rssi_threshold_low, monitor.rssi_threshold_low_time_interval,
                        monitor.rssi_sampling_period, monitor.addr_info.addr_type, addr),
                handler_->BindOnceOn(this, &impl::on_msft_adv_monitor_add_complete, std::move(cb)));
        return;
      }
    }

    if (monitor.condition_type == MSFT_CONDITION_TYPE_UUID) {
      if (monitor.uuid_info.uuid.size() == 2) {
        std::array<uint8_t, 2> uuid;
        std::copy(monitor.uuid_info.uuid.begin(), monitor.uuid_info.uuid.begin() + uuid.size(),
                  uuid.begin());
        hci_layer_->EnqueueCommand(
                MsftLeMonitorAdvConditionUuid2Builder::Create(
                        static_cast<OpCode>(msft_.opcode.value()), monitor.rssi_threshold_high,
                        monitor.rssi_threshold_low, monitor.rssi_threshold_low_time_interval,
                        monitor.rssi_sampling_period, uuid),
                handler_->BindOnceOn(this, &impl::on_msft_adv_monitor_add_complete, std::move(cb)));
        return;
      }

      if (monitor.uuid_info.uuid.size() == 4) {
        std::array<uint8_t, 4> uuid;
        std::copy(monitor.uuid_info.uuid.begin(), monitor.uuid_info.uuid.begin() + uuid.size(),
                  uuid.begin());
        hci_layer_->EnqueueCommand(
                MsftLeMonitorAdvConditionUuid4Builder::Create(
                        static_cast<OpCode>(msft_.opcode.value()), monitor.rssi_threshold_high,
                        monitor.rssi_threshold_low, monitor.rssi_threshold_low_time_interval,
                        monitor.rssi_sampling_period, uuid),
                handler_->BindOnceOn(this, &impl::on_msft_adv_monitor_add_complete, std::move(cb)));
        return;
      }

      if (monitor.uuid_info.uuid.size() == 16) {
        std::array<uint8_t, 16> uuid;
        std::copy(monitor.uuid_info.uuid.begin(), monitor.uuid_info.uuid.begin() + uuid.size(),
                  uuid.begin());
        hci_layer_->EnqueueCommand(
                MsftLeMonitorAdvConditionUuid16Builder::Create(
                        static_cast<OpCode>(msft_.opcode.value()), monitor.rssi_threshold_high,
                        monitor.rssi_threshold_low, monitor.rssi_threshold_low_time_interval,
                        monitor.rssi_sampling_period, uuid),
                handler_->BindOnceOn(this, &impl::on_msft_adv_monitor_add_complete, std::move(cb)));
        return;
      }

      log::error("Invalid uuid size {}", monitor.uuid_info.uuid.size());
      return;
    }

    std::vector<MsftLeMonitorAdvConditionPattern> patterns;
    MsftLeMonitorAdvConditionPattern pattern;
    // The Microsoft Extension specifies 1 octet for the number of patterns.
    // However, the max number of patters should not exceed 61.
    // (255 - 1 (packet type) - 2 (OGF/OCF) - 1 (length) - 7 (MSFT command parameters)) /
    // 4 (min size of a pattern) = 61
    if (monitor.patterns.size() > 61) {
      log::error("Number of MSFT patterns {} is too large", monitor.patterns.size());
      return;
    }
    for (auto& p : monitor.patterns) {
      pattern.ad_type_ = p.ad_type;
      pattern.start_of_pattern_ = p.start_byte;
      pattern.pattern_ = p.pattern;
      patterns.push_back(pattern);
    }

    hci_layer_->EnqueueCommand(
            MsftLeMonitorAdvConditionPatternsBuilder::Create(
                    static_cast<OpCode>(msft_.opcode.value()), monitor.rssi_threshold_high,
                    monitor.rssi_threshold_low, monitor.rssi_threshold_low_time_interval,
                    monitor.rssi_sampling_period, patterns),
            handler_->BindOnceOn(this, &impl::on_msft_adv_monitor_add_complete, std::move(cb)));
  }

  void msft_adv_monitor_remove(uint8_t monitor_handle, MsftAdvMonitorRemoveCallback cb) {
    if (!supports_msft_extensions()) {
      log::warn("Disallowed as MSFT extension is not supported.");
      return;
    }

    hci_layer_->EnqueueCommand(
            MsftLeCancelMonitorAdvBuilder::Create(static_cast<OpCode>(msft_.opcode.value()),
                                                  monitor_handle),
            handler_->BindOnceOn(this, &impl::on_msft_adv_monitor_remove_complete, std::move(cb)));
  }

  void msft_adv_monitor_enable(bool enable, MsftAdvMonitorEnableCallback cb) {
    if (!supports_msft_extensions()) {
      log::warn("Disallowed as MSFT extension is not supported.");
      return;
    }

    hci_layer_->EnqueueCommand(
            MsftLeSetAdvFilterEnableBuilder::Create(static_cast<OpCode>(msft_.opcode.value()),
                                                    enable),
            handler_->BindOnceOn(this, &impl::on_msft_adv_monitor_enable_complete, std::move(cb)));
  }

  void set_scanning_callback(ScanningCallback* callbacks) { scanning_callbacks_ = callbacks; }

  /*
   * Get the event prefix from the packet for configuring MSFT's
   * Vendor Specific events. Also get the MSFT supported features.
   */
  void on_msft_read_supported_features_complete(CommandCompleteView view) {
    log::assert_that(view.IsValid(), "assert failed: view.IsValid()");
    auto status_view = MsftReadSupportedFeaturesCommandCompleteView::Create(
            MsftCommandCompleteView::Create(view));
    if (!status_view.IsValid()) {
      log::error("MSFT Read supported features failed");
      msft_.opcode = std::nullopt;
      return;
    }

    if (status_view.GetStatus() != ErrorCode::SUCCESS) {
      log::warn("MSFT Command complete status {}", ErrorCodeText(status_view.GetStatus()));
      return;
    }

    MsftSubcommandOpcode sub_opcode = status_view.GetSubcommandOpcode();
    if (sub_opcode != MsftSubcommandOpcode::MSFT_READ_SUPPORTED_FEATURES) {
      log::warn("Wrong MSFT subcommand opcode {} returned", sub_opcode);
      return;
    }

    msft_.features = status_view.GetSupportedFeatures();

    // Save the vendor prefix to distinguish upcoming MSFT vendor events.
    auto prefix = status_view.GetPrefix();
    msft_.prefix.assign(prefix.begin(), prefix.end());

    if (prefix.size() > kMsftEventPrefixLengthMax) {
      log::warn("The MSFT prefix length {} is too large", (unsigned int)prefix.size());
    }

    log::info("MSFT features 0x{:016x} prefix length {}", msft_.features, prefix.size());

    // We are here because Microsoft Extension is supported. Hence, register the
    // first octet of the vendor prefix so that the vendor specific event manager
    // can dispatch the event correctly.
    // Note: registration of the first octet of the vendor prefix is sufficient
    //       because each vendor controller should ensure that the first octet
    //       is unique within the vendor's events.
    hci_layer_->RegisterVendorSpecificEventHandler(
            static_cast<VseSubeventCode>(msft_.prefix[0]),
            handler_->BindOn(this, &impl::handle_msft_events));
  }

  void on_msft_adv_monitor_add_complete(MsftAdvMonitorAddCallback msft_adv_monitor_add_cb,
                                        CommandCompleteView view) {
    log::assert_that(view.IsValid(), "assert failed: view.IsValid()");
    auto status_view =
            MsftLeMonitorAdvCommandCompleteView::Create(MsftCommandCompleteView::Create(view));
    log::assert_that(status_view.IsValid(), "assert failed: status_view.IsValid()");

    MsftSubcommandOpcode sub_opcode = status_view.GetSubcommandOpcode();
    if (sub_opcode != MsftSubcommandOpcode::MSFT_LE_MONITOR_ADV) {
      log::warn("Wrong MSFT subcommand opcode {} returned", sub_opcode);
      return;
    }

    std::move(msft_adv_monitor_add_cb).Run(status_view.GetMonitorHandle(), status_view.GetStatus());
  }

  void on_msft_adv_monitor_remove_complete(MsftAdvMonitorRemoveCallback msft_adv_monitor_remove_cb,
                                           CommandCompleteView view) {
    log::assert_that(view.IsValid(), "assert failed: view.IsValid()");
    auto status_view = MsftLeCancelMonitorAdvCommandCompleteView::Create(
            MsftCommandCompleteView::Create(view));
    log::assert_that(status_view.IsValid(), "assert failed: status_view.IsValid()");

    MsftSubcommandOpcode sub_opcode = status_view.GetSubcommandOpcode();
    if (sub_opcode != MsftSubcommandOpcode::MSFT_LE_CANCEL_MONITOR_ADV) {
      log::warn("Wrong MSFT subcommand opcode {} returned", sub_opcode);
      return;
    }

    std::move(msft_adv_monitor_remove_cb).Run(status_view.GetStatus());
  }

  void on_msft_adv_monitor_enable_complete(MsftAdvMonitorEnableCallback msft_adv_monitor_enable_cb,
                                           CommandCompleteView view) {
    log::assert_that(view.IsValid(), "assert failed: view.IsValid()");
    auto status_view = MsftLeSetAdvFilterEnableCommandCompleteView::Create(
            MsftCommandCompleteView::Create(view));
    log::assert_that(status_view.IsValid(), "assert failed: status_view.IsValid()");

    MsftSubcommandOpcode sub_opcode = status_view.GetSubcommandOpcode();
    if (sub_opcode != MsftSubcommandOpcode::MSFT_LE_SET_ADV_FILTER_ENABLE) {
      log::warn("Wrong MSFT subcommand opcode {} returned", sub_opcode);
      return;
    }

    std::move(msft_adv_monitor_enable_cb).Run(status_view.GetStatus());
  }

  os::Handler* handler_;
  hal::HciHal* hal_;
  hci::HciInterface* hci_layer_;
  Msft msft_;
  ScanningCallback* scanning_callbacks_{nullptr};
};

MsftExtensionManager::MsftExtensionManager(os::Handler* handler, hal::HciHal* hal,
                                           hci::HciInterface* hci_layer) {
  log::info("MsftExtensionManager()");
  pimpl_ = std::make_unique<impl>(handler, hal, hci_layer);
  log::verbose("module started !!");
}

MsftExtensionManager::~MsftExtensionManager() { log::verbose("module stopped !!"); }

bool MsftExtensionManager::SupportsMsftExtensions() { return pimpl_->supports_msft_extensions(); }

void MsftExtensionManager::MsftAdvMonitorAdd(const MsftAdvMonitor& monitor,
                                             MsftAdvMonitorAddCallback cb) {
  pimpl_->handler_->CallOn(pimpl_.get(), &impl::msft_adv_monitor_add, monitor, std::move(cb));
}

void MsftExtensionManager::MsftAdvMonitorRemove(uint8_t monitor_handle,
                                                MsftAdvMonitorRemoveCallback cb) {
  pimpl_->handler_->CallOn(pimpl_.get(), &impl::msft_adv_monitor_remove, monitor_handle,
                           std::move(cb));
}

void MsftExtensionManager::MsftAdvMonitorEnable(bool enable, MsftAdvMonitorEnableCallback cb) {
  pimpl_->handler_->CallOn(pimpl_.get(), &impl::msft_adv_monitor_enable, enable, std::move(cb));
}

void MsftExtensionManager::SetScanningCallback(ScanningCallback* callbacks) {
  pimpl_->handler_->CallOn(pimpl_.get(), &impl::set_scanning_callback, callbacks);
}

}  // namespace hci
}  // namespace bluetooth
