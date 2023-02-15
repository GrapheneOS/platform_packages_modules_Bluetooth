/*
 * Copyright 2020 The Android Open Source Project
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

#include "common/init_flags.h"

#include "dumpsys/init_flags.h"
#include "init_flags_generated.h"

namespace initFlags = bluetooth::common::init_flags;

// LINT.IfChange
flatbuffers::Offset<bluetooth::common::InitFlagsData> bluetooth::dumpsys::InitFlags::Dump(
    flatbuffers::FlatBufferBuilder* fb_builder) {
  auto title = fb_builder->CreateString("----- Init Flags -----");
  common::InitFlagsDataBuilder builder(*fb_builder);
  builder.add_title(title);
  builder.add_gd_advertising_enabled(true);
  builder.add_gd_scanning_enabled(true);
  builder.add_gd_acl_enabled(true);
  builder.add_gd_hci_enabled(true);
  builder.add_gd_controller_enabled(true);

  builder.add_always_use_private_gatt_for_debugging_is_enabled(
      initFlags::always_use_private_gatt_for_debugging_is_enabled());
  builder.add_asynchronously_start_l2cap_coc_is_enabled(initFlags::asynchronously_start_l2cap_coc_is_enabled());
  builder.add_btaa_hci_is_enabled(initFlags::btaa_hci_is_enabled());
  builder.add_bta_dm_clear_conn_id_on_client_close_is_enabled(
      initFlags::bta_dm_clear_conn_id_on_client_close_is_enabled());
  builder.add_btm_dm_flush_discovery_queue_on_search_cancel_is_enabled(
      initFlags::btm_dm_flush_discovery_queue_on_search_cancel_is_enabled());
  builder.add_device_iot_config_logging_is_enabled(
      initFlags::device_iot_config_logging_is_enabled());
  builder.add_clear_hidd_interrupt_cid_on_disconnect_is_enabled(
      initFlags::clear_hidd_interrupt_cid_on_disconnect_is_enabled());
  builder.add_dynamic_avrcp_version_enhancement_is_enabled(
      initFlags::dynamic_avrcp_version_enhancement_is_enabled());
  builder.add_gd_hal_snoop_logger_filtering_is_enabled(
      bluetooth::common::init_flags::gd_hal_snoop_logger_filtering_is_enabled());
  builder.add_finite_att_timeout_is_enabled(initFlags::finite_att_timeout_is_enabled());
  builder.add_gatt_robust_caching_client_is_enabled(initFlags::gatt_robust_caching_client_is_enabled());
  builder.add_gatt_robust_caching_server_is_enabled(initFlags::gatt_robust_caching_server_is_enabled());
  builder.add_gd_core_is_enabled(initFlags::gd_core_is_enabled());
  builder.add_gd_hal_snoop_logger_socket_is_enabled(
      bluetooth::common::init_flags::gd_hal_snoop_logger_socket_is_enabled());
  builder.add_gd_l2cap_is_enabled(initFlags::gd_l2cap_is_enabled());
  builder.add_gd_link_policy_is_enabled(initFlags::gd_link_policy_is_enabled());
  builder.add_gd_remote_name_request_is_enabled(initFlags::gd_remote_name_request_is_enabled());
  builder.add_gd_rust_is_enabled(initFlags::gd_rust_is_enabled());
  builder.add_gd_security_is_enabled(initFlags::gd_security_is_enabled());
  builder.add_get_hci_adapter(initFlags::get_hci_adapter());
  builder.add_hfp_dynamic_version_is_enabled(initFlags::hfp_dynamic_version_is_enabled());
  builder.add_irk_rotation_is_enabled(initFlags::irk_rotation_is_enabled());
  // is_debug_logging_enabled_for_tag -- skipped in dumpsys
  builder.add_leaudio_targeted_announcement_reconnection_mode_is_enabled(
      initFlags::leaudio_targeted_announcement_reconnection_mode_is_enabled());
  builder.add_logging_debug_enabled_for_all_is_enabled(initFlags::logging_debug_enabled_for_all_is_enabled());
  builder.add_pass_phy_update_callback_is_enabled(initFlags::pass_phy_update_callback_is_enabled());
  builder.add_periodic_advertising_adi_is_enabled(bluetooth::common::init_flags::periodic_advertising_adi_is_enabled());
  builder.add_queue_l2cap_coc_while_encrypting_is_enabled(
      initFlags::queue_l2cap_coc_while_encrypting_is_enabled());
  builder.add_private_gatt_is_enabled(initFlags::private_gatt_is_enabled());
  builder.add_redact_log_is_enabled(initFlags::redact_log_is_enabled());
  builder.add_rust_event_loop_is_enabled(initFlags::rust_event_loop_is_enabled());
  builder.add_sdp_serialization_is_enabled(initFlags::sdp_serialization_is_enabled());
  builder.add_sdp_skip_rnr_if_known_is_enabled(initFlags::sdp_skip_rnr_if_known_is_enabled());
  builder.add_set_min_encryption_is_enabled(bluetooth::common::init_flags::set_min_encryption_is_enabled());
  builder.add_subrating_is_enabled(initFlags::subrating_is_enabled());
  builder.add_trigger_advertising_callbacks_on_first_resume_after_pause_is_enabled(
      initFlags::trigger_advertising_callbacks_on_first_resume_after_pause_is_enabled());

  return builder.Finish();
}
// LINT.ThenChange(/system/gd/rust/common/src/init_flags.rs)
