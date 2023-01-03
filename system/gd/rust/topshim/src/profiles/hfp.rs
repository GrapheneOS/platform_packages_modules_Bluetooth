use crate::btif::{BluetoothInterface, BtStatus, RawAddress, ToggleableProfile};
use crate::topstack::get_dispatchers;

use bitflags::bitflags;
use num_derive::{FromPrimitive, ToPrimitive};
use num_traits::cast::FromPrimitive;
use std::convert::{TryFrom, TryInto};
use std::sync::{Arc, Mutex};
use topshim_macros::{cb_variant, profile_enabled_or};

use log::warn;

#[derive(Debug, FromPrimitive, ToPrimitive, PartialEq, PartialOrd, Clone)]
#[repr(u32)]
pub enum BthfConnectionState {
    Disconnected = 0,
    Connecting,
    Connected,
    SlcConnected,
    Disconnecting,
}

impl From<u32> for BthfConnectionState {
    fn from(item: u32) -> Self {
        BthfConnectionState::from_u32(item).unwrap()
    }
}

#[derive(Debug, FromPrimitive, PartialEq, PartialOrd, Clone)]
#[repr(u32)]
pub enum BthfAudioState {
    Disconnected = 0,
    Connecting,
    Connected,
    Disconnecting,
}

impl From<u32> for BthfAudioState {
    fn from(item: u32) -> Self {
        BthfAudioState::from_u32(item).unwrap()
    }
}

bitflags! {
    #[derive(Default)]
    pub struct HfpCodecCapability: i32 {
        const UNSUPPORTED = 0b00;
        const CVSD = 0b01;
        const MSBC = 0b10;
    }
}

impl TryInto<i32> for HfpCodecCapability {
    type Error = ();
    fn try_into(self) -> Result<i32, Self::Error> {
        Ok(self.bits())
    }
}

impl TryFrom<i32> for HfpCodecCapability {
    type Error = ();
    fn try_from(val: i32) -> Result<Self, Self::Error> {
        Self::from_bits(val).ok_or(())
    }
}

#[cxx::bridge(namespace = bluetooth::topshim::rust)]
pub mod ffi {
    unsafe extern "C++" {
        include!("gd/rust/topshim/common/type_alias.h");
        type RawAddress = crate::btif::RawAddress;
    }

    unsafe extern "C++" {
        include!("hfp/hfp_shim.h");

        type HfpIntf;

        unsafe fn GetHfpProfile(btif: *const u8) -> UniquePtr<HfpIntf>;

        fn init(self: Pin<&mut HfpIntf>) -> i32;
        fn connect(self: Pin<&mut HfpIntf>, bt_addr: RawAddress) -> u32;
        fn connect_audio(
            self: Pin<&mut HfpIntf>,
            bt_addr: RawAddress,
            sco_offload: bool,
            force_cvsd: bool,
        ) -> i32;
        fn set_active_device(self: Pin<&mut HfpIntf>, bt_addr: RawAddress) -> i32;
        fn set_volume(self: Pin<&mut HfpIntf>, volume: i8, bt_addr: RawAddress) -> i32;
        fn disconnect(self: Pin<&mut HfpIntf>, bt_addr: RawAddress) -> u32;
        fn disconnect_audio(self: Pin<&mut HfpIntf>, bt_addr: RawAddress) -> i32;
        fn cleanup(self: Pin<&mut HfpIntf>);

    }
    extern "Rust" {
        fn hfp_connection_state_callback(state: u32, addr: RawAddress);
        fn hfp_audio_state_callback(state: u32, addr: RawAddress);
        fn hfp_volume_update_callback(volume: u8, addr: RawAddress);
        fn hfp_battery_level_update_callback(battery_level: u8, addr: RawAddress);
        fn hfp_caps_update_callback(wbs_supported: bool, addr: RawAddress);
    }
}

#[derive(Clone, Debug)]
pub enum HfpCallbacks {
    ConnectionState(BthfConnectionState, RawAddress),
    AudioState(BthfAudioState, RawAddress),
    VolumeUpdate(u8, RawAddress),
    BatteryLevelUpdate(u8, RawAddress),
    CapsUpdate(bool, RawAddress),
}

pub struct HfpCallbacksDispatcher {
    pub dispatch: Box<dyn Fn(HfpCallbacks) + Send>,
}

type HfpCb = Arc<Mutex<HfpCallbacksDispatcher>>;

cb_variant!(
    HfpCb,
    hfp_connection_state_callback -> HfpCallbacks::ConnectionState,
    u32 -> BthfConnectionState, RawAddress);

cb_variant!(
    HfpCb,
    hfp_audio_state_callback -> HfpCallbacks::AudioState,
    u32 -> BthfAudioState, RawAddress);

cb_variant!(
    HfpCb,
    hfp_volume_update_callback -> HfpCallbacks::VolumeUpdate,
    u8, RawAddress);

cb_variant!(
    HfpCb,
    hfp_battery_level_update_callback -> HfpCallbacks::BatteryLevelUpdate,
    u8, RawAddress);

cb_variant!(
    HfpCb,
    hfp_caps_update_callback -> HfpCallbacks::CapsUpdate,
    bool, RawAddress);

pub struct Hfp {
    internal: cxx::UniquePtr<ffi::HfpIntf>,
    _is_init: bool,
    _is_enabled: bool,
}

// For *const u8 opaque btif
unsafe impl Send for Hfp {}

impl ToggleableProfile for Hfp {
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

impl Hfp {
    pub fn new(intf: &BluetoothInterface) -> Hfp {
        let hfpif: cxx::UniquePtr<ffi::HfpIntf>;
        unsafe {
            hfpif = ffi::GetHfpProfile(intf.as_raw_ptr());
        }

        Hfp { internal: hfpif, _is_init: false, _is_enabled: false }
    }

    pub fn is_initialized(&self) -> bool {
        self._is_init
    }

    pub fn initialize(&mut self, callbacks: HfpCallbacksDispatcher) -> bool {
        if get_dispatchers().lock().unwrap().set::<HfpCb>(Arc::new(Mutex::new(callbacks))) {
            panic!("Tried to set dispatcher for HFP callbacks while it already exists");
        }
        self._is_init = true;
        true
    }

    #[profile_enabled_or(BtStatus::NotReady)]
    pub fn connect(&mut self, addr: RawAddress) -> BtStatus {
        BtStatus::from(self.internal.pin_mut().connect(addr))
    }

    #[profile_enabled_or(BtStatus::NotReady.into())]
    pub fn connect_audio(&mut self, addr: RawAddress, sco_offload: bool, force_cvsd: bool) -> i32 {
        self.internal.pin_mut().connect_audio(addr, sco_offload, force_cvsd)
    }

    #[profile_enabled_or(BtStatus::NotReady.into())]
    pub fn set_active_device(&mut self, addr: RawAddress) -> i32 {
        self.internal.pin_mut().set_active_device(addr)
    }

    #[profile_enabled_or(BtStatus::NotReady.into())]
    pub fn set_volume(&mut self, volume: i8, addr: RawAddress) -> i32 {
        self.internal.pin_mut().set_volume(volume, addr)
    }

    #[profile_enabled_or(BtStatus::NotReady)]
    pub fn disconnect(&mut self, addr: RawAddress) -> BtStatus {
        BtStatus::from(self.internal.pin_mut().disconnect(addr))
    }

    #[profile_enabled_or(BtStatus::NotReady.into())]
    pub fn disconnect_audio(&mut self, addr: RawAddress) -> i32 {
        self.internal.pin_mut().disconnect_audio(addr)
    }

    #[profile_enabled_or(false)]
    pub fn cleanup(&mut self) -> bool {
        self.internal.pin_mut().cleanup();
        true
    }
}
