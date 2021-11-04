use crate::btif::RawAddress;

#[cxx::bridge(namespace = bluetooth::topshim::rust)]
mod ffi {
    pub struct RustRawAddress {
        address: [u8; 6],
    }

    unsafe extern "C++" {
        include!("btm_sec/btm_sec_shim.h");

        type BtmSecIntf;

        fn GetBtmSecInterface() -> UniquePtr<BtmSecIntf>;
        fn hci_disconnect(self: &BtmSecIntf, bt_addr: RustRawAddress);
    }
}

pub struct BtmSec {
    internal: cxx::UniquePtr<ffi::BtmSecIntf>,
}

unsafe impl Send for BtmSec {}

impl BtmSec {
    pub fn new() -> BtmSec {
        let btm_sec_intf = ffi::GetBtmSecInterface();
        BtmSec { internal: btm_sec_intf }
    }

    pub fn hci_disconnect(&mut self, address: [u8; 6]) {
        self.internal.hci_disconnect(ffi::RustRawAddress { address });
    }
}
