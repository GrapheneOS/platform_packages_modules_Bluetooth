use crate::btif::{BluetoothInterface, BtStatus, RawAddress, ToggleableProfile};
use crate::topstack::get_dispatchers;

use std::sync::{Arc, Mutex};
use topshim_macros::{cb_variant, profile_enabled_or};

use log::warn;

#[derive(Debug, Default)]
pub struct PlayerMetadata {
    pub title: String,
    pub artist: String,
    pub album: String,
    pub length_us: i64,
}

#[cxx::bridge(namespace = bluetooth::topshim::rust)]
pub mod ffi {
    unsafe extern "C++" {
        include!("gd/rust/topshim/common/type_alias.h");
        type RawAddress = crate::btif::RawAddress;
    }

    unsafe extern "C++" {
        include!("btav/btav_shim.h");

        type AvrcpIntf;

        unsafe fn GetAvrcpProfile(btif: *const u8) -> UniquePtr<AvrcpIntf>;

        fn init(self: Pin<&mut AvrcpIntf>);
        fn cleanup(self: Pin<&mut AvrcpIntf>);
        fn connect(self: Pin<&mut AvrcpIntf>, bt_addr: RawAddress) -> u32;
        fn disconnect(self: Pin<&mut AvrcpIntf>, bt_addr: RawAddress) -> u32;
        fn set_volume(self: Pin<&mut AvrcpIntf>, volume: i8);
        fn set_playback_status(self: Pin<&mut AvrcpIntf>, status: &String);
        fn set_position(self: Pin<&mut AvrcpIntf>, position_us: i64);
        fn set_metadata(
            self: Pin<&mut AvrcpIntf>,
            title: &String,
            artist: &String,
            album: &String,
            length_us: i64,
        );

    }
    extern "Rust" {
        fn avrcp_device_connected(addr: RawAddress, absolute_volume_enabled: bool);
        fn avrcp_device_disconnected(addr: RawAddress);
        fn avrcp_absolute_volume_update(volume: u8);
        fn avrcp_send_key_event(key: u8, state: u8);
        fn avrcp_set_active_device(addr: RawAddress);
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
    RawAddress, bool);

cb_variant!(
    AvrcpCb,
    avrcp_device_disconnected -> AvrcpCallbacks::AvrcpDeviceDisconnected,
    RawAddress);

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
    RawAddress);

pub struct Avrcp {
    internal: cxx::UniquePtr<ffi::AvrcpIntf>,
    _is_init: bool,
    _is_enabled: bool,
}

// For *const u8 opaque btif
unsafe impl Send for Avrcp {}

impl ToggleableProfile for Avrcp {
    fn is_enabled(&self) -> bool {
        self._is_enabled
    }

    fn enable(&mut self) -> bool {
        self.internal.pin_mut().init();
        self._is_enabled = true;
        true
    }

    #[profile_enabled_or(false)]
    fn disable(&mut self) -> bool {
        self.internal.pin_mut().cleanup();
        self._is_enabled = false;
        true
    }
}

impl Avrcp {
    pub fn new(intf: &BluetoothInterface) -> Avrcp {
        let avrcpif: cxx::UniquePtr<ffi::AvrcpIntf>;
        unsafe {
            avrcpif = ffi::GetAvrcpProfile(intf.as_raw_ptr());
        }

        Avrcp { internal: avrcpif, _is_init: false, _is_enabled: false }
    }

    pub fn is_initialized(&self) -> bool {
        self._is_init
    }

    pub fn initialize(&mut self, callbacks: AvrcpCallbacksDispatcher) -> bool {
        if get_dispatchers().lock().unwrap().set::<AvrcpCb>(Arc::new(Mutex::new(callbacks))) {
            panic!("Tried to set dispatcher for Avrcp callbacks while it already exists");
        }
        self._is_init = true;
        true
    }

    #[profile_enabled_or(BtStatus::NotReady)]
    pub fn connect(&mut self, addr: RawAddress) -> BtStatus {
        BtStatus::from(self.internal.pin_mut().connect(addr.into()))
    }

    #[profile_enabled_or(BtStatus::NotReady)]
    pub fn disconnect(&mut self, addr: RawAddress) -> BtStatus {
        BtStatus::from(self.internal.pin_mut().disconnect(addr.into()))
    }

    #[profile_enabled_or]
    pub fn set_volume(&mut self, volume: i8) {
        self.internal.pin_mut().set_volume(volume);
    }

    #[profile_enabled_or(false)]
    pub fn cleanup(&mut self) -> bool {
        self.internal.pin_mut().cleanup();
        true
    }

    #[profile_enabled_or]
    pub fn set_playback_status(&mut self, status: &String) {
        self.internal.pin_mut().set_playback_status(status);
    }

    #[profile_enabled_or]
    pub fn set_position(&mut self, position_us: i64) {
        self.internal.pin_mut().set_position(position_us);
    }

    #[profile_enabled_or]
    pub fn set_metadata(&mut self, metadata: &PlayerMetadata) {
        self.internal.pin_mut().set_metadata(
            &metadata.title,
            &metadata.artist,
            &metadata.album,
            metadata.length_us,
        );
    }
}
