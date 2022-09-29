use crate::btif::{BluetoothInterface, BtStatus, RawAddress};
use crate::topstack::get_dispatchers;

use std::sync::{Arc, Mutex};
use topshim_macros::cb_variant;

#[cxx::bridge(namespace = bluetooth::topshim::rust)]
pub mod ffi {
    #[derive(Debug, Copy, Clone)]
    pub struct RustRawAddress {
        address: [u8; 6],
    }

    unsafe extern "C++" {
        include!("btav/btav_shim.h");

        type AvrcpIntf;

        unsafe fn GetAvrcpProfile(btif: *const u8) -> UniquePtr<AvrcpIntf>;

        fn init(self: Pin<&mut AvrcpIntf>);
        fn cleanup(self: Pin<&mut AvrcpIntf>);
        fn connect(self: Pin<&mut AvrcpIntf>, bt_addr: RustRawAddress) -> u32;
        fn disconnect(self: Pin<&mut AvrcpIntf>, bt_addr: RustRawAddress) -> u32;
        fn set_volume(self: Pin<&mut AvrcpIntf>, volume: i8);

    }
    extern "Rust" {
        fn avrcp_device_connected(addr: RustRawAddress, absolute_volume_enabled: bool);
        fn avrcp_device_disconnected(addr: RustRawAddress);
        fn avrcp_absolute_volume_update(volume: u8);
        fn avrcp_send_key_event(key: u8, state: u8);
        fn avrcp_set_active_device(addr: RustRawAddress);
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

#[derive(Debug)]
pub enum AvrcpCallbacks {
    /// Emitted when avrcp completes connection.
    /// Params: Device address, Absolute Volume Enabled
    AvrcpDeviceConnected(RawAddress, bool),
    /// Emitted when avrcp device disconnected.
    /// Params: Device address
    AvrcpDeviceDisconnected(RawAddress),
    /// Emitted when the absolute volume of a connected AVRCP device changed
    /// Params: Volume
    AvrcpAbsoluteVolumeUpdate(u8),
    /// Emitted when received a key event from a connected AVRCP device
    /// Params: Key, Value
    AvrcpSendKeyEvent(u8, u8),
    /// Emitted when received request from AVRCP interface to set a device to active
    /// Params: Device address
    AvrcpSetActiveDevice(RawAddress),
}

pub struct AvrcpCallbacksDispatcher {
    pub dispatch: Box<dyn Fn(AvrcpCallbacks) + Send>,
}

type AvrcpCb = Arc<Mutex<AvrcpCallbacksDispatcher>>;

cb_variant!(
    AvrcpCb,
    avrcp_device_connected -> AvrcpCallbacks::AvrcpDeviceConnected,
    ffi::RustRawAddress -> RawAddress, bool, {
        let _0 = _0.into();
});

cb_variant!(
    AvrcpCb,
    avrcp_device_disconnected -> AvrcpCallbacks::AvrcpDeviceDisconnected,
    ffi::RustRawAddress -> RawAddress, {
        let _0 = _0.into();
});

cb_variant!(
    AvrcpCb,
    avrcp_absolute_volume_update -> AvrcpCallbacks::AvrcpAbsoluteVolumeUpdate,
    u8, {}
);

cb_variant!(
    AvrcpCb,
    avrcp_send_key_event -> AvrcpCallbacks::AvrcpSendKeyEvent,
    u8, u8, {}
);

cb_variant!(
    AvrcpCb,
    avrcp_set_active_device -> AvrcpCallbacks::AvrcpSetActiveDevice,
    ffi::RustRawAddress -> RawAddress, {
        let _0 = _0.into();
});

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

    pub fn initialize(&mut self, callbacks: AvrcpCallbacksDispatcher) -> bool {
        if get_dispatchers().lock().unwrap().set::<AvrcpCb>(Arc::new(Mutex::new(callbacks))) {
            panic!("Tried to set dispatcher for Avrcp callbacks while it already exists");
        }
        self.internal.pin_mut().init();
        true
    }

    pub fn cleanup(&mut self) -> bool {
        self.internal.pin_mut().cleanup();
        true
    }

    pub fn connect(&mut self, addr: RawAddress) -> BtStatus {
        BtStatus::from(self.internal.pin_mut().connect(addr.into()))
    }

    pub fn disconnect(&mut self, addr: RawAddress) -> BtStatus {
        BtStatus::from(self.internal.pin_mut().disconnect(addr.into()))
    }

    pub fn set_volume(&mut self, volume: i8) {
        self.internal.pin_mut().set_volume(volume);
    }
}
