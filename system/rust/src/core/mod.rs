//! Shared data-types and utility methods go here.

mod ffi;
pub mod uuid;

use std::{rc::Rc, thread};

use bt_common::init_flags::rust_event_loop_is_enabled;

use crate::{gatt::ffi::AttTransportImpl, GlobalModuleRegistry};

fn init() {
    if rust_event_loop_is_enabled() {
        thread::spawn(move || {
            GlobalModuleRegistry::start(Rc::new(AttTransportImpl()));
        });
    }
}
