use crate::btif::BtState;

#[cxx::bridge(namespace = bluetooth::topshim::rust)]
mod ffi {
    unsafe extern "C++" {
        include!("metrics/metrics_shim.h");

        fn adapter_state_changed(state: u32);
    }
}

pub fn adapter_state_changed(state: BtState) {
    ffi::adapter_state_changed(state as u32);
}
