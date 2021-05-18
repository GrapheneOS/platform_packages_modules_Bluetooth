//! Bluetooth interface shim
//!
//! This is a shim interface for calling the C++ bluetooth interface via Rust.
//!

use crate::bindings::root as bindings;
use crate::topstack::get_dispatchers;
use num_traits::cast::{FromPrimitive, ToPrimitive};
use std::sync::{Arc, Mutex};
use std::vec::Vec;
use topshim_macros::cb_variant;

use crate::profiles::hid_host::HidHost;

#[derive(Debug, FromPrimitive, ToPrimitive, PartialEq, PartialOrd)]
#[repr(u32)]
pub enum BtState {
    Off = 0,
    On,
}

impl From<bindings::bt_state_t> for BtState {
    fn from(item: bindings::bt_state_t) -> Self {
        BtState::from_u32(item).unwrap_or_else(|| BtState::Off)
    }
}

#[derive(Debug, FromPrimitive, ToPrimitive, PartialEq, PartialOrd)]
#[repr(u32)]
pub enum BtTransport {
    Invalid = 0,
    Bredr,
    Le,
}

impl From<i32> for BtTransport {
    fn from(item: i32) -> Self {
        BtTransport::from_i32(item).unwrap_or_else(|| BtTransport::Invalid)
    }
}

impl From<BtTransport> for i32 {
    fn from(item: BtTransport) -> Self {
        item.to_i32().unwrap_or_else(|| 0)
    }
}

#[derive(Debug, FromPrimitive, ToPrimitive, PartialEq, PartialOrd)]
#[repr(u32)]
pub enum BtSspVariant {
    PasskeyConfirmation = 0,
    PasskeyEntry,
    Consent,
    PasskeyNotification,
}

impl From<bindings::bt_ssp_variant_t> for BtSspVariant {
    fn from(item: bindings::bt_ssp_variant_t) -> Self {
        BtSspVariant::from_u32(item).unwrap_or_else(|| BtSspVariant::PasskeyConfirmation)
    }
}

impl From<BtSspVariant> for bindings::bt_ssp_variant_t {
    fn from(item: BtSspVariant) -> Self {
        item.to_u32().unwrap_or_else(|| 0)
    }
}

#[derive(Debug, FromPrimitive, ToPrimitive, PartialEq, PartialOrd)]
#[repr(u32)]
pub enum BtBondState {
    Unknown = 0,
    Bonding,
    Bonded,
}

impl From<bindings::bt_bond_state_t> for BtBondState {
    fn from(item: bindings::bt_bond_state_t) -> Self {
        BtBondState::from_u32(item).unwrap_or_else(|| BtBondState::Unknown)
    }
}

#[derive(Debug, FromPrimitive, ToPrimitive, PartialEq, PartialOrd)]
#[repr(u32)]
pub enum BtAclState {
    Connected = 0,
    Disconnected,
}

impl From<bindings::bt_acl_state_t> for BtAclState {
    fn from(item: bindings::bt_acl_state_t) -> Self {
        BtAclState::from_u32(item).unwrap_or_else(|| BtAclState::Disconnected)
    }
}

#[derive(Debug, FromPrimitive, ToPrimitive, PartialEq, PartialOrd)]
#[repr(u32)]
pub enum BtDeviceType {
    Bredr,
    Ble,
    Dual,
}

#[derive(Clone, Debug, FromPrimitive, ToPrimitive, PartialEq, PartialOrd)]
#[repr(u32)]
pub enum BtPropertyType {
    BdName = 0x1,
    BdAddr,
    Uuids,
    ClassOfDevice,
    TypeOfDevice,
    ServiceRecord,
    AdapterScanMode,
    AdapterBondedDevices,
    AdapterDiscoveryTimeout,
    RemoteFriendlyName,
    RemoteRssi,
    RemoteVersionInfo,
    LocalLeFeatures,
    LocalIoCaps,
    LocalIoCapsBle,
    DynamicAudioBuffer,

    Unknown = 0xFE,
    RemoteDeviceTimestamp = 0xFF,
}

impl From<u32> for BtPropertyType {
    fn from(item: u32) -> Self {
        BtPropertyType::from_u32(item).unwrap_or_else(|| BtPropertyType::Unknown)
    }
}

impl From<BtPropertyType> for u32 {
    fn from(item: BtPropertyType) -> Self {
        item.to_u32().unwrap_or_else(|| 0)
    }
}

#[derive(Debug, FromPrimitive, ToPrimitive, PartialEq, PartialOrd)]
#[repr(i32)]
pub enum BtDiscoveryState {
    Stopped = 0x0,
    Started,
}

impl From<u32> for BtDiscoveryState {
    fn from(item: u32) -> Self {
        BtDiscoveryState::from_u32(item).unwrap_or_else(|| BtDiscoveryState::Stopped)
    }
}

#[derive(Debug, FromPrimitive, ToPrimitive, PartialEq, PartialOrd)]
#[repr(u32)]
pub enum BtStatus {
    Success = 0,
    Fail,
    NotReady,
    NoMemory,
    Busy,
    Done,
    Unsupported,
    InvalidParam,
    Unhandled,
    AuthFailure,
    RemoteDeviceDown,
    AuthRejected,
    JniEnvironmentError,
    JniThreadAttachError,
    WakeLockError,

    // Any statuses that couldn't be cleanly converted
    Unknown = 0xff,
}

impl From<bindings::bt_status_t> for BtStatus {
    fn from(item: bindings::bt_status_t) -> Self {
        match BtStatus::from_u32(item) {
            Some(x) => x,
            _ => BtStatus::Unknown,
        }
    }
}

#[derive(Debug, Clone)]
pub struct BtProperty {
    pub prop_type: BtPropertyType,
    pub len: i32,
    pub val: Vec<u8>,
}

fn convert_properties(count: i32, props: *const bindings::bt_property_t) -> Vec<BtProperty> {
    let mut ret: Vec<BtProperty> = Vec::new();

    for i in 0..isize::from_i32(count).unwrap() {
        let prop: *const bindings::bt_property_t = unsafe { props.offset(i) };
        let converted = BtProperty::from(unsafe { *prop });

        ret.push(converted)
    }

    ret
}

impl From<bindings::bt_property_t> for BtProperty {
    fn from(item: bindings::bt_property_t) -> Self {
        let slice: &[u8] =
            unsafe { std::slice::from_raw_parts(item.val as *mut u8, item.len as usize) };
        let mut val = Vec::new();
        val.extend_from_slice(slice);

        BtProperty { prop_type: BtPropertyType::from(item.type_), len: item.len, val }
    }
}

impl From<BtProperty> for bindings::bt_property_t {
    fn from(item: BtProperty) -> Self {
        // This is probably very unsafe
        let mut foo = item.clone();
        bindings::bt_property_t {
            type_: item.prop_type.to_u32().unwrap(),
            len: foo.val.len() as i32,
            val: foo.val.as_mut_ptr() as *mut std::os::raw::c_void,
        }
    }
}

impl From<bindings::bt_bdname_t> for String {
    fn from(item: bindings::bt_bdname_t) -> Self {
        std::str::from_utf8(&item.name).unwrap().to_string()
    }
}

pub type BtHciErrorCode = u8;

pub type BtPinCode = bindings::bt_pin_code_t;

pub enum SupportedProfiles {
    HidHost,
}

impl From<SupportedProfiles> for Vec<u8> {
    fn from(item: SupportedProfiles) -> Self {
        match item {
            HidHost => "hidhost".bytes().collect::<Vec<u8>>(),
        }
    }
}

#[cxx::bridge(namespace = bluetooth::topshim::rust)]
mod ffi {
    unsafe extern "C++" {
        include!("btif/btif_shim.h");

        // For converting init flags from Vec<String> to const char **
        type InitFlags;

        // Convert flgas into an InitFlags object
        fn ConvertFlags(flags: Vec<String>) -> UniquePtr<InitFlags>;
        fn GetFlagsPtr(self: &InitFlags) -> *mut *const c_char;
    }
}

// Export the raw address type directly from the bindings
pub type RawAddress = bindings::RawAddress;

#[derive(Debug)]
pub enum BaseCallbacks {
    AdapterState(BtState),
    AdapterProperties(BtStatus, i32, Vec<BtProperty>),
    RemoteDeviceProperties(BtStatus, RawAddress, i32, Vec<BtProperty>),
    DeviceFound(i32, Vec<BtProperty>),
    DiscoveryState(BtDiscoveryState),
    PinRequest(RawAddress, String, u32, bool),
    SspRequest(RawAddress, String, u32, BtSspVariant, u32),
    BondState(BtStatus, RawAddress, BtBondState),
    AclState(BtStatus, RawAddress, BtAclState, BtHciErrorCode),
    // Unimplemented so far:
    // thread_evt_cb
    // dut_mode_recv_cb
    // le_test_mode_cb
    // energy_info_cb
    // link_quality_report_cb
    // generate_local_oob_data_cb
}

pub struct BaseCallbacksDispatcher {
    pub dispatch: Box<dyn Fn(BaseCallbacks) + Send>,
}

type BaseCb = Arc<Mutex<BaseCallbacksDispatcher>>;

cb_variant!(BaseCb, adapter_state_cb -> BaseCallbacks::AdapterState, u32 -> BtState);
cb_variant!(BaseCb, adapter_properties_cb -> BaseCallbacks::AdapterProperties,
u32 -> BtStatus, i32, *mut bindings::bt_property_t, {
    let _2 = convert_properties(_1, _2);
});
cb_variant!(BaseCb, remote_device_properties_cb -> BaseCallbacks::RemoteDeviceProperties,
u32 -> BtStatus, *mut RawAddress -> RawAddress, i32, *mut bindings::bt_property_t, {
    let _1 = unsafe {*_1};
    let _3 = convert_properties(_2, _3);
});
cb_variant!(BaseCb, device_found_cb -> BaseCallbacks::DeviceFound,
i32, *mut bindings::bt_property_t, {
    let _1 = convert_properties(_0, _1);
});
cb_variant!(BaseCb, discovery_state_cb -> BaseCallbacks::DiscoveryState,
    bindings::bt_discovery_state_t -> BtDiscoveryState);
cb_variant!(BaseCb, pin_request_cb -> BaseCallbacks::PinRequest,
*mut RawAddress, *mut bindings::bt_bdname_t, u32, bool, {
    let _0 = unsafe { *_0 };
    let _1 = String::from(unsafe{*_1});
});
cb_variant!(BaseCb, ssp_request_cb -> BaseCallbacks::SspRequest,
*mut RawAddress, *mut bindings::bt_bdname_t, u32, bindings::bt_ssp_variant_t -> BtSspVariant, u32, {
    let _0 = unsafe {*_0};
    let _1 = String::from(unsafe{*_1});
});
cb_variant!(BaseCb, bond_state_cb -> BaseCallbacks::BondState,
u32 -> BtStatus, *mut RawAddress, bindings::bt_bond_state_t -> BtBondState, {
    let _1 = unsafe {*_1};
});
cb_variant!(BaseCb, acl_state_cb -> BaseCallbacks::AclState,
u32 -> BtStatus, *mut RawAddress, bindings::bt_acl_state_t -> BtAclState, bindings::bt_hci_error_code_t -> BtHciErrorCode, {
    let _1 = unsafe { *_1 };
});

struct RawInterfaceWrapper {
    pub raw: *const bindings::bt_interface_t,
}

unsafe impl Send for RawInterfaceWrapper {}

pub struct BluetoothInterface {
    internal: RawInterfaceWrapper,
    pub is_init: bool,
    // Need to take ownership of callbacks so it doesn't get freed after init
    callbacks: Option<Box<bindings::bt_callbacks_t>>,
}

#[macro_export]
macro_rules! ccall {
    ($self:ident,$fn_name:ident) => {
        unsafe {
            ((*$self.internal.raw).$fn_name.unwrap())()
        }
    };
    ($self:ident,$fn_name:ident, $($args:expr),*) => {
        unsafe {
            ((*$self.internal.raw).$fn_name.unwrap())($($args),*)
        }
    }
}

impl BluetoothInterface {
    pub fn is_initialized(&self) -> bool {
        self.is_init
    }

    pub fn initialize(
        &mut self,
        callbacks: BaseCallbacksDispatcher,
        init_flags: Vec<String>,
    ) -> bool {
        // Init flags need to be converted from string to null terminated bytes
        let converted: cxx::UniquePtr<ffi::InitFlags> = ffi::ConvertFlags(init_flags);
        let flags = (*converted).GetFlagsPtr();

        if get_dispatchers().lock().unwrap().set::<BaseCb>(Arc::new(Mutex::new(callbacks))) {
            panic!("Tried to set dispatcher for BaseCallbacks but it already existed");
        }

        // Fill up callbacks struct to pass to init function (will be copied so
        // no need to worry about ownership)
        let mut callbacks = Box::new(bindings::bt_callbacks_t {
            size: 16 * 8,
            adapter_state_changed_cb: Some(adapter_state_cb),
            adapter_properties_cb: Some(adapter_properties_cb),
            remote_device_properties_cb: Some(remote_device_properties_cb),
            device_found_cb: Some(device_found_cb),
            discovery_state_changed_cb: Some(discovery_state_cb),
            pin_request_cb: Some(pin_request_cb),
            ssp_request_cb: Some(ssp_request_cb),
            bond_state_changed_cb: Some(bond_state_cb),
            acl_state_changed_cb: Some(acl_state_cb),
            thread_evt_cb: None,
            dut_mode_recv_cb: None,
            le_test_mode_cb: None,
            energy_info_cb: None,
            link_quality_report_cb: None,
            generate_local_oob_data_cb: None,
        });

        let rawcb: *mut bindings::bt_callbacks_t = &mut *callbacks;

        let (guest_mode, is_common_criteria_mode, config_compare_result, is_atv) =
            (false, false, 0, false);

        let init = ccall!(
            self,
            init,
            rawcb,
            guest_mode,
            is_common_criteria_mode,
            config_compare_result,
            flags,
            is_atv
        );

        self.is_init = init == 0;
        self.callbacks = Some(callbacks);

        return self.is_init;
    }

    pub fn cleanup(&self) {
        ccall!(self, cleanup)
    }

    pub fn enable(&self) -> i32 {
        ccall!(self, enable)
    }

    pub fn disable(&self) -> i32 {
        ccall!(self, disable)
    }

    pub fn get_adapter_properties(&self) -> i32 {
        ccall!(self, get_adapter_properties)
    }

    pub fn get_adapter_property(&self, prop: BtPropertyType) -> i32 {
        let converted_type = bindings::bt_property_type_t::from(prop);
        ccall!(self, get_adapter_property, converted_type)
    }

    pub fn set_adapter_property(&self, prop: BtProperty) -> i32 {
        let converted_prop = bindings::bt_property_t::from(prop);
        ccall!(self, set_adapter_property, &converted_prop)
    }

    pub fn get_remote_device_properties(&self, addr: &mut RawAddress) -> i32 {
        ccall!(self, get_remote_device_properties, addr)
    }

    pub fn get_remote_device_property(
        &self,
        addr: &mut RawAddress,
        prop_type: BtPropertyType,
    ) -> i32 {
        let converted_type = bindings::bt_property_type_t::from(prop_type);
        ccall!(self, get_remote_device_property, addr, converted_type)
    }

    pub fn set_remote_device_property(&self, addr: &mut RawAddress, prop: BtProperty) -> i32 {
        let converted_prop = bindings::bt_property_t::from(prop);
        ccall!(self, set_remote_device_property, addr, &converted_prop)
    }

    pub fn start_discovery(&self) -> i32 {
        ccall!(self, start_discovery)
    }

    pub fn cancel_discovery(&self) -> i32 {
        ccall!(self, cancel_discovery)
    }

    pub fn create_bond(&self, addr: &RawAddress, transport: BtTransport) -> i32 {
        let ctransport: i32 = transport.into();
        ccall!(self, create_bond, addr, ctransport)
    }

    pub fn remove_bond(&self, addr: &RawAddress) -> i32 {
        ccall!(self, remove_bond, addr)
    }

    pub fn cancel_bond(&self, addr: &RawAddress) -> i32 {
        ccall!(self, cancel_bond, addr)
    }

    pub fn get_connection_state(&self, addr: &RawAddress) -> i32 {
        ccall!(self, get_connection_state, addr)
    }

    pub fn pin_reply(
        &self,
        addr: &RawAddress,
        accept: u8,
        pin_len: u8,
        pin_code: &mut BtPinCode,
    ) -> i32 {
        ccall!(self, pin_reply, addr, accept, pin_len, pin_code)
    }

    pub fn ssp_reply(
        &self,
        addr: &RawAddress,
        variant: BtSspVariant,
        accept: u8,
        passkey: u32,
    ) -> i32 {
        let cvariant = bindings::bt_ssp_variant_t::from(variant);
        ccall!(self, ssp_reply, addr, cvariant, accept, passkey)
    }

    pub(crate) fn get_profile_interface(
        &self,
        profile: SupportedProfiles,
    ) -> *const std::os::raw::c_void {
        let cprofile = Vec::<u8>::from(profile);
        ccall!(self, get_profile_interface, cprofile.as_slice().as_ptr() as *const i8)
    }
}

pub fn get_btinterface() -> Option<BluetoothInterface> {
    let mut ret: Option<BluetoothInterface> = None;
    let mut ifptr: *const bindings::bt_interface_t = std::ptr::null();

    unsafe {
        if bindings::hal_util_load_bt_library(&mut ifptr) == 0 {
            ret = Some(BluetoothInterface {
                internal: RawInterfaceWrapper { raw: ifptr },
                is_init: false,
                callbacks: None,
            });
        }
    }

    ret
}
