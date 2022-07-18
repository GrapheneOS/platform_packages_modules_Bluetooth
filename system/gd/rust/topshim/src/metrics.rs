use crate::btif::{BtBondState, BtDeviceType, BtState, BtStatus, RawAddress};

#[cxx::bridge(namespace = bluetooth::topshim::rust)]
mod ffi {
    #[derive(Debug, Copy, Clone)]
    pub struct RustRawAddress {
        address: [u8; 6],
    }

    unsafe extern "C++" {
        include!("metrics/metrics_shim.h");

        fn adapter_state_changed(state: u32);
        fn bond_create_attempt(bt_addr: RustRawAddress, device_type: u32);
        fn bond_state_changed(
            bt_addr: RustRawAddress,
            device_type: u32,
            status: u32,
            bond_state: u32,
            fail_reason: i32,
        );
    }
}

impl From<RawAddress> for ffi::RustRawAddress {
    fn from(addr: RawAddress) -> Self {
        ffi::RustRawAddress { address: addr.val }
    }
}

impl Into<RawAddress> for ffi::RustRawAddress {
    fn into(self) -> RawAddress {
        RawAddress { val: self.address }
    }
}

pub fn adapter_state_changed(state: BtState) {
    ffi::adapter_state_changed(state as u32);
}

pub fn bond_create_attempt(addr: RawAddress, device_type: BtDeviceType) {
    ffi::bond_create_attempt(addr.into(), device_type as u32);
}

pub fn bond_state_changed(
    addr: RawAddress,
    device_type: BtDeviceType,
    status: BtStatus,
    bond_state: BtBondState,
    fail_reason: i32,
) {
    ffi::bond_state_changed(
        addr.into(),
        device_type as u32,
        status as u32,
        bond_state as u32,
        fail_reason as i32,
    );
}
