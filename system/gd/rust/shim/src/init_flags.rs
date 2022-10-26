#[cxx::bridge(namespace = bluetooth::common::init_flags)]
mod ffi {
    extern "Rust" {
        fn load(flags: Vec<String>);
        fn set_all_for_testing();

        fn btaa_hci_is_enabled() -> bool;
        fn finite_att_timeout_is_enabled() -> bool;
        fn gatt_robust_caching_client_is_enabled() -> bool;
        fn gatt_robust_caching_server_is_enabled() -> bool;
        fn gd_core_is_enabled() -> bool;
        fn gd_l2cap_is_enabled() -> bool;
        fn gd_link_policy_is_enabled() -> bool;
        fn gd_remote_name_request_is_enabled() -> bool;
        fn gd_rust_is_enabled() -> bool;
        fn gd_security_is_enabled() -> bool;
        fn get_hci_adapter() -> i32;
        fn irk_rotation_is_enabled() -> bool;
        fn is_debug_logging_enabled_for_tag(tag: &str) -> bool;
        fn logging_debug_enabled_for_all_is_enabled() -> bool;
        fn pass_phy_update_callback_is_enabled() -> bool;
        fn sdp_serialization_is_enabled() -> bool;
    }
}

use bt_common::init_flags::*;
