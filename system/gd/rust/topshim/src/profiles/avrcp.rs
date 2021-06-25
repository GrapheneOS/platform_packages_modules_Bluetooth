use crate::btif::BluetoothInterface;

#[cxx::bridge(namespace = bluetooth::topshim::rust)]
pub mod ffi {
    unsafe extern "C++" {
        include!("btav/btav_shim.h");

        type AvrcpIntf;

        unsafe fn GetAvrcpProfile(btif: *const u8) -> UniquePtr<AvrcpIntf>;

        fn init(self: Pin<&mut AvrcpIntf>);
        fn cleanup(self: Pin<&mut AvrcpIntf>);

    }
    extern "Rust" {}
}

pub struct Avrcp {
    internal: cxx::UniquePtr<ffi::AvrcpIntf>,
    _is_init: bool,
}

// For *const u8 opaque btif
unsafe impl Send for Avrcp {}

impl Avrcp {
    pub fn new(intf: &BluetoothInterface) -> Avrcp {
        let avrcpif: cxx::UniquePtr<ffi::AvrcpIntf>;
        unsafe {
            avrcpif = ffi::GetAvrcpProfile(intf.as_raw_ptr());
        }

        Avrcp { internal: avrcpif, _is_init: false }
    }

    pub fn initialize(&mut self) -> bool {
        self.internal.pin_mut().init();
        true
    }

    pub fn cleanup(&mut self) -> bool {
        self.internal.pin_mut().cleanup();
        true
    }
}
