pub mod iface_bluetooth_manager;

// protoc-rust generates all modules and exports them in mod.rs
// We have to include them all here to make them available for crate export.
include!(concat!(env!("OUT_DIR"), "/proto_out/mod.rs"));
