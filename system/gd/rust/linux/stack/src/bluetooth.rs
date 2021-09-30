//! Anything related to the adapter API (IBluetooth).

use bt_topshim::btif::{
    BaseCallbacks, BaseCallbacksDispatcher, BluetoothInterface, BluetoothProperty, BtBondState,
    BtDiscoveryState, BtPropertyType, BtSspVariant, BtState, BtStatus, BtTransport, RawAddress,
    Uuid, Uuid128Bit,
};
use bt_topshim::{
    profiles::hid_host::{HHCallbacksDispatcher, HidHost},
    profiles::sdp::{BtSdpRecord, Sdp, SdpCallbacks, SdpCallbacksDispatcher},
    topstack,
};

use btif_macros::{btif_callback, btif_callbacks_dispatcher};

use log::{debug, warn};
use num_traits::cast::ToPrimitive;
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::Instant;
use tokio::sync::mpsc::Sender;

use crate::bluetooth_media::{BluetoothMedia, IBluetoothMedia};
use crate::{Message, RPCProxy};

/// Defines the adapter API.
pub trait IBluetooth {
    /// Adds a callback from a client who wishes to observe adapter events.
    fn register_callback(&mut self, callback: Box<dyn IBluetoothCallback + Send>);

    /// Enables the adapter.
    ///
    /// Returns true if the request is accepted.
    fn enable(&mut self) -> bool;

    /// Disables the adapter.
    ///
    /// Returns true if the request is accepted.
    fn disable(&mut self) -> bool;

    /// Returns the Bluetooth address of the local adapter.
    fn get_address(&self) -> String;

    /// Gets supported UUIDs by the local adapter.
    fn get_uuids(&self) -> Vec<Uuid128Bit>;

    /// Gets the local adapter name.
    fn get_name(&self) -> String;

    /// Sets the local adapter name.
    fn set_name(&self, name: String) -> bool;

    /// Starts BREDR Inquiry.
    fn start_discovery(&self) -> bool;

    /// Cancels BREDR Inquiry.
    fn cancel_discovery(&self) -> bool;

    /// Checks if discovery is started.
    fn is_discovering(&self) -> bool;

    /// Checks when discovery ends in milliseconds from now.
    fn get_discovery_end_millis(&self) -> u64;

    /// Initiates pairing to a remote device. Triggers connection if not already started.
    fn create_bond(&self, device: BluetoothDevice, transport: BluetoothTransport) -> bool;

    /// Cancels any pending bond attempt on given device.
    fn cancel_bond_process(&self, device: BluetoothDevice) -> bool;

    /// Removes pairing for given device.
    fn remove_bond(&self, device: BluetoothDevice) -> bool;

    /// Returns a list of known bonded devices.
    fn get_bonded_devices(&self) -> Vec<BluetoothDevice>;

    /// Gets the bond state of a single device.
    fn get_bond_state(&self, device: BluetoothDevice) -> u32;

    /// Returns the cached UUIDs of a remote device.
    fn get_remote_uuids(&self, device: BluetoothDevice) -> Vec<Uuid128Bit>;

    /// Triggers SDP to get UUIDs of a remote device.
    fn fetch_remote_uuids(&self, device: BluetoothDevice) -> bool;

    /// Triggers SDP and searches for a specific UUID on a remote device.
    fn sdp_search(&self, device: BluetoothDevice, uuid: Uuid128Bit) -> bool;
}

#[derive(Debug, FromPrimitive, ToPrimitive)]
#[repr(i32)]
pub enum BluetoothTransport {
    Auto = 0,
    Bredr = 1,
    Le = 2,
}

/// Serializable device used in various apis.
#[derive(Clone, Debug, Default)]
pub struct BluetoothDevice {
    pub address: String,
    pub name: String,
}

impl BluetoothDevice {
    pub(crate) fn new(address: String, name: String) -> BluetoothDevice {
        BluetoothDevice { address, name }
    }

    pub(crate) fn from_properties(in_properties: &Vec<BluetoothProperty>) -> BluetoothDevice {
        let mut address = String::from("");
        let mut name = String::from("");

        for prop in in_properties {
            match &prop {
                BluetoothProperty::BdAddr(bdaddr) => {
                    address = bdaddr.to_string();
                }
                BluetoothProperty::BdName(bdname) => {
                    name = bdname.clone();
                }
                _ => {}
            }
        }

        BluetoothDevice::new(address, name)
    }
}

/// Internal data structure that keeps a map of cached properties for a remote device.
struct BluetoothDeviceContext {
    pub bond_state: BtBondState,
    pub info: BluetoothDevice,
    pub properties: HashMap<BtPropertyType, BluetoothProperty>,
}

impl BluetoothDeviceContext {
    pub(crate) fn new(
        bond_state: BtBondState,
        info: BluetoothDevice,
        properties: Vec<BluetoothProperty>,
    ) -> BluetoothDeviceContext {
        let bond_state = BtBondState::NotBonded;
        let mut device = BluetoothDeviceContext { bond_state, info, properties: HashMap::new() };
        device.update_properties(properties);
        device
    }

    pub(crate) fn update_properties(&mut self, in_properties: Vec<BluetoothProperty>) {
        for prop in in_properties {
            match &prop {
                BluetoothProperty::BdAddr(bdaddr) => {
                    self.info.address = bdaddr.to_string();
                }
                BluetoothProperty::BdName(bdname) => {
                    self.info.name = bdname.clone();
                }
                _ => {}
            }

            self.properties.insert(prop.get_type(), prop);
        }
    }
}

/// The interface for adapter callbacks registered through `IBluetooth::register_callback`.
pub trait IBluetoothCallback: RPCProxy {
    /// When any of the adapter local address is changed.
    fn on_address_changed(&self, addr: String);

    /// When a device is found via discovery.
    fn on_device_found(&self, remote_device: BluetoothDevice);

    /// When the discovery state is changed.
    fn on_discovering_changed(&self, discovering: bool);

    /// When there is a pairing/bonding process and requires agent to display the event to UI.
    fn on_ssp_request(
        &self,
        remote_device: BluetoothDevice,
        cod: u32,
        variant: BtSspVariant,
        passkey: u32,
    );

    /// When a bonding attempt has completed.
    fn on_bond_state_changed(&self, status: u32, device_address: String, state: u32);
}

/// Implementation of the adapter API.
pub struct Bluetooth {
    intf: Arc<Mutex<BluetoothInterface>>,

    bonded_devices: HashMap<String, BluetoothDeviceContext>,
    bluetooth_media: Arc<Mutex<Box<BluetoothMedia>>>,
    callbacks: Vec<(u32, Box<dyn IBluetoothCallback + Send>)>,
    callbacks_last_id: u32,
    discovering_started: Instant,
    hh: Option<HidHost>,
    is_discovering: bool,
    local_address: Option<RawAddress>,
    properties: HashMap<BtPropertyType, BluetoothProperty>,
    found_devices: HashMap<String, BluetoothDeviceContext>,
    sdp: Option<Sdp>,
    state: BtState,
    tx: Sender<Message>,
}

impl Bluetooth {
    /// Constructs the IBluetooth implementation.
    pub fn new(
        tx: Sender<Message>,
        intf: Arc<Mutex<BluetoothInterface>>,
        bluetooth_media: Arc<Mutex<Box<BluetoothMedia>>>,
    ) -> Bluetooth {
        Bluetooth {
            bonded_devices: HashMap::new(),
            callbacks: vec![],
            callbacks_last_id: 0,
            hh: None,
            bluetooth_media,
            discovering_started: Instant::now(),
            intf,
            is_discovering: false,
            local_address: None,
            properties: HashMap::new(),
            found_devices: HashMap::new(),
            sdp: None,
            state: BtState::Off,
            tx,
        }
    }

    pub fn init_profiles(&mut self) {
        let hhtx = self.tx.clone();
        self.hh = Some(HidHost::new(&self.intf.lock().unwrap()));
        self.hh.as_mut().unwrap().initialize(HHCallbacksDispatcher {
            dispatch: Box::new(move |cb| {
                let txl = hhtx.clone();
                topstack::get_runtime().spawn(async move {
                    let _ = txl.send(Message::HidHost(cb)).await;
                });
            }),
        });

        let sdptx = self.tx.clone();
        self.sdp = Some(Sdp::new(&self.intf.lock().unwrap()));
        self.sdp.as_mut().unwrap().initialize(SdpCallbacksDispatcher {
            dispatch: Box::new(move |cb| {
                let txl = sdptx.clone();
                topstack::get_runtime().spawn(async move {
                    let _ = txl.send(Message::Sdp(cb)).await;
                });
            }),
        });
    }

    fn update_local_address(&mut self, addr: &RawAddress) {
        self.local_address = Some(*addr);

        self.for_all_callbacks(|callback| {
            callback.on_address_changed(self.local_address.unwrap().to_string());
        });
    }

    fn for_all_callbacks<F: Fn(&Box<dyn IBluetoothCallback + Send>)>(&self, f: F) {
        for callback in &self.callbacks {
            f(&callback.1);
        }
    }

    pub(crate) fn callback_disconnected(&mut self, id: u32) {
        self.callbacks.retain(|x| x.0 != id);
    }
}

#[btif_callbacks_dispatcher(Bluetooth, dispatch_base_callbacks, BaseCallbacks)]
pub(crate) trait BtifBluetoothCallbacks {
    #[btif_callback(AdapterState)]
    fn adapter_state_changed(&mut self, state: BtState);

    #[btif_callback(AdapterProperties)]
    fn adapter_properties_changed(
        &mut self,
        status: BtStatus,
        num_properties: i32,
        properties: Vec<BluetoothProperty>,
    );

    #[btif_callback(DeviceFound)]
    fn device_found(&mut self, n: i32, properties: Vec<BluetoothProperty>);

    #[btif_callback(DiscoveryState)]
    fn discovery_state(&mut self, state: BtDiscoveryState);

    #[btif_callback(SspRequest)]
    fn ssp_request(
        &mut self,
        remote_addr: RawAddress,
        remote_name: String,
        cod: u32,
        variant: BtSspVariant,
        passkey: u32,
    );

    #[btif_callback(BondState)]
    fn bond_state(
        &mut self,
        status: BtStatus,
        addr: RawAddress,
        bond_state: BtBondState,
        fail_reason: i32,
    );

    #[btif_callback(RemoteDeviceProperties)]
    fn remote_device_properties_changed(
        &mut self,
        status: BtStatus,
        addr: RawAddress,
        num_properties: i32,
        properties: Vec<BluetoothProperty>,
    );
}

#[btif_callbacks_dispatcher(Bluetooth, dispatch_sdp_callbacks, SdpCallbacks)]
pub(crate) trait BtifSdpCallbacks {
    #[btif_callback(SdpSearch)]
    fn sdp_search(
        &mut self,
        status: BtStatus,
        address: RawAddress,
        uuid: Uuid,
        count: i32,
        records: Vec<BtSdpRecord>,
    );
}

pub fn get_bt_dispatcher(tx: Sender<Message>) -> BaseCallbacksDispatcher {
    BaseCallbacksDispatcher {
        dispatch: Box::new(move |cb| {
            let txl = tx.clone();
            topstack::get_runtime().spawn(async move {
                let _ = txl.send(Message::Base(cb)).await;
            });
        }),
    }
}

impl BtifBluetoothCallbacks for Bluetooth {
    fn adapter_state_changed(&mut self, state: BtState) {
        let prev_state = self.state.clone();
        self.state = state;

        // If it's the same state as before, no further action
        if self.state == prev_state {
            return;
        }

        if self.state == BtState::On {
            self.bluetooth_media.lock().unwrap().initialize();
        }

        if self.state == BtState::Off {
            self.properties.clear();
        } else {
            // Trigger properties update
            self.intf.lock().unwrap().get_adapter_properties();
        }
    }

    #[allow(unused_variables)]
    fn adapter_properties_changed(
        &mut self,
        status: BtStatus,
        num_properties: i32,
        properties: Vec<BluetoothProperty>,
    ) {
        if status != BtStatus::Success {
            return;
        }

        // Update local property cache
        for prop in properties {
            match &prop {
                BluetoothProperty::BdAddr(bdaddr) => {
                    self.update_local_address(&bdaddr);
                }
                BluetoothProperty::AdapterBondedDevices(bondlist) => {
                    for addr in bondlist.iter() {
                        let address = addr.to_string();

                        // Update bonded state if already in the list. Otherwise create a new
                        // context with empty properties and name.
                        self.bonded_devices
                            .entry(address.clone())
                            .and_modify(|d| d.bond_state = BtBondState::Bonded)
                            .or_insert(BluetoothDeviceContext::new(
                                BtBondState::Bonded,
                                BluetoothDevice::new(address.clone(), "".to_string()),
                                vec![],
                            ));
                    }
                }
                _ => {}
            }

            self.properties.insert(prop.get_type(), prop);
        }
    }

    fn device_found(&mut self, _n: i32, properties: Vec<BluetoothProperty>) {
        let device = BluetoothDevice::from_properties(&properties);
        let address = device.address.clone();

        if let Some(existing) = self.found_devices.get_mut(&address) {
            existing.update_properties(properties);
        } else {
            let device_with_props =
                BluetoothDeviceContext::new(BtBondState::NotBonded, device, properties);
            self.found_devices.insert(address.clone(), device_with_props);
        }

        let device = self.found_devices.get(&address).unwrap();

        self.for_all_callbacks(|callback| {
            callback.on_device_found(device.info.clone());
        });
    }

    fn discovery_state(&mut self, state: BtDiscoveryState) {
        // Clear found devices when discovery session starts
        if !self.is_discovering && &state == &BtDiscoveryState::Started {
            self.found_devices.clear();
        }

        // Cache discovering state
        self.is_discovering = &state == &BtDiscoveryState::Started;
        if self.is_discovering {
            self.discovering_started = Instant::now();
        }

        self.for_all_callbacks(|callback| {
            callback.on_discovering_changed(state == BtDiscoveryState::Started);
        });
    }

    fn ssp_request(
        &mut self,
        remote_addr: RawAddress,
        remote_name: String,
        cod: u32,
        variant: BtSspVariant,
        passkey: u32,
    ) {
        // Currently this supports many agent because we accept many callbacks.
        // TODO: We need a way to select the default agent.
        self.for_all_callbacks(|callback| {
            callback.on_ssp_request(
                BluetoothDevice::new(remote_addr.to_string(), remote_name.clone()),
                cod,
                variant.clone(),
                passkey,
            );
        });
        // Immediately accept the pairing.
        // TODO: Delegate the pairing confirmation to agent.
        self.intf.lock().unwrap().ssp_reply(&remote_addr, variant, 1, passkey);
    }

    fn bond_state(
        &mut self,
        status: BtStatus,
        mut addr: RawAddress,
        bond_state: BtBondState,
        _fail_reason: i32,
    ) {
        if &bond_state == &BtBondState::Bonded {
            // We are assuming that peer is a HID device and automatically connect to that profile.
            // TODO: Only connect to enabled profiles on that device.
            self.hh.as_ref().unwrap().connect(&mut addr);
        }

        let address = addr.to_string();

        // Easy case of not bonded -- we remove the device from the bonded list
        if &bond_state == &BtBondState::NotBonded {
            self.bonded_devices.remove(&address);
        }
        // We will only insert into the bonded list after bonding is complete
        else if &bond_state == &BtBondState::Bonded && !self.bonded_devices.contains_key(&address)
        {
            // We either need to construct a new BluetoothDeviceContext or grab it from the found
            // devices map
            let device = match self.found_devices.remove(&address) {
                Some(mut v) => {
                    v.bond_state = bond_state.clone();
                    v
                }
                None => BluetoothDeviceContext::new(
                    bond_state.clone(),
                    BluetoothDevice::new(address.clone(), "".to_string()),
                    vec![],
                ),
            };

            self.bonded_devices.insert(address.clone(), device);
        } else {
            self.bonded_devices
                .entry(address.clone())
                .and_modify(|d| d.bond_state = bond_state.clone());
        }

        // Send bond state changed notifications
        self.for_all_callbacks(|callback| {
            callback.on_bond_state_changed(
                status.to_u32().unwrap(),
                address.clone(),
                bond_state.to_u32().unwrap(),
            );
        });
    }

    fn remote_device_properties_changed(
        &mut self,
        status: BtStatus,
        addr: RawAddress,
        _num_properties: i32,
        properties: Vec<BluetoothProperty>,
    ) {
        let address = addr.to_string();
        // Device should be in either found devices or bonded devices
        // If it isn't in either, create it and put it found devices.
        let device = if self.bonded_devices.contains_key(&address) {
            self.bonded_devices.get_mut(&address)
        } else if self.found_devices.contains_key(&address) {
            self.found_devices.get_mut(&address)
        } else {
            self.found_devices.insert(
                address.clone(),
                BluetoothDeviceContext::new(
                    BtBondState::NotBonded,
                    BluetoothDevice::new(address.clone(), String::from("")),
                    vec![],
                ),
            );

            self.found_devices.get_mut(&address)
        };

        device.unwrap().update_properties(properties);
    }
}

// TODO: Add unit tests for this implementation
impl IBluetooth for Bluetooth {
    fn register_callback(&mut self, mut callback: Box<dyn IBluetoothCallback + Send>) {
        let tx = self.tx.clone();

        // TODO: Refactor into a separate wrap-around id generator.
        self.callbacks_last_id += 1;
        let id = self.callbacks_last_id;

        callback.register_disconnect(Box::new(move || {
            let tx = tx.clone();
            tokio::spawn(async move {
                let _result = tx.send(Message::BluetoothCallbackDisconnected(id)).await;
            });
        }));

        self.callbacks.push((id, callback))
    }

    fn enable(&mut self) -> bool {
        self.intf.lock().unwrap().enable() == 0
    }

    fn disable(&mut self) -> bool {
        self.intf.lock().unwrap().disable() == 0
    }

    fn get_address(&self) -> String {
        match self.local_address {
            None => String::from(""),
            Some(addr) => addr.to_string(),
        }
    }

    fn get_uuids(&self) -> Vec<Uuid128Bit> {
        match self.properties.get(&BtPropertyType::Uuids) {
            Some(prop) => match prop {
                BluetoothProperty::Uuids(uuids) => {
                    uuids.iter().map(|&x| x.uu.clone()).collect::<Vec<Uuid128Bit>>()
                }
                _ => vec![],
            },
            _ => vec![],
        }
    }

    fn get_name(&self) -> String {
        match self.properties.get(&BtPropertyType::BdName) {
            Some(prop) => match prop {
                BluetoothProperty::BdName(name) => name.clone(),
                _ => String::new(),
            },
            _ => String::new(),
        }
    }

    fn set_name(&self, name: String) -> bool {
        self.intf.lock().unwrap().set_adapter_property(BluetoothProperty::BdName(name)) == 0
    }

    fn start_discovery(&self) -> bool {
        self.intf.lock().unwrap().start_discovery() == 0
    }

    fn cancel_discovery(&self) -> bool {
        self.intf.lock().unwrap().cancel_discovery() == 0
    }

    fn is_discovering(&self) -> bool {
        self.is_discovering
    }

    fn get_discovery_end_millis(&self) -> u64 {
        if !self.is_discovering {
            return 0;
        }

        match self.properties.get(&BtPropertyType::AdapterDiscoveryTimeout) {
            Some(variant) => match variant {
                BluetoothProperty::AdapterDiscoveryTimeout(timeout) => {
                    let seconds: u64 = (*timeout).into();
                    let elapsed = self.discovering_started.elapsed();
                    if elapsed.as_secs() >= seconds {
                        0
                    } else {
                        seconds * 1000 - elapsed.as_millis() as u64
                    }
                }
                _ => 0,
            },
            _ => 0,
        }
    }

    fn create_bond(&self, device: BluetoothDevice, transport: BluetoothTransport) -> bool {
        let addr = RawAddress::from_string(device.address.clone());

        if addr.is_none() {
            warn!("Can't create bond. Address {} is not valid", device.address);
            return false;
        }

        let address = addr.unwrap();
        self.intf
            .lock()
            .unwrap()
            .create_bond(&address, BtTransport::from(transport.to_i32().unwrap()))
            == 0
    }

    fn cancel_bond_process(&self, device: BluetoothDevice) -> bool {
        let addr = RawAddress::from_string(device.address.clone());

        if addr.is_none() {
            warn!("Can't cancel bond. Address {} is not valid.", device.address);
            return false;
        }

        let address = addr.unwrap();
        self.intf.lock().unwrap().cancel_bond(&address) == 0
    }

    fn remove_bond(&self, device: BluetoothDevice) -> bool {
        let addr = RawAddress::from_string(device.address.clone());

        if addr.is_none() {
            warn!("Can't remove bond. Address {} is not valid.", device.address);
            return false;
        }

        let address = addr.unwrap();
        self.intf.lock().unwrap().remove_bond(&address) == 0
    }

    fn get_bonded_devices(&self) -> Vec<BluetoothDevice> {
        let mut devices: Vec<BluetoothDevice> = vec![];

        for (_, device) in self.bonded_devices.iter() {
            devices.push(device.info.clone());
        }

        devices
    }

    fn get_bond_state(&self, device: BluetoothDevice) -> u32 {
        match self.bonded_devices.get(&device.address) {
            Some(device) => device.bond_state.to_u32().unwrap(),
            None => BtBondState::NotBonded.to_u32().unwrap(),
        }
    }

    fn get_remote_uuids(&self, device: BluetoothDevice) -> Vec<Uuid128Bit> {
        // Device must exist in either bonded or found list
        let found = self
            .bonded_devices
            .get(&device.address)
            .or_else(|| self.found_devices.get(&device.address));

        // Extract property from the device
        return found
            .and_then(|d| {
                if let Some(u) = d.properties.get(&BtPropertyType::Uuids) {
                    match u {
                        BluetoothProperty::Uuids(uuids) => {
                            return Some(
                                uuids.iter().map(|&x| x.uu.clone()).collect::<Vec<Uuid128Bit>>(),
                            );
                        }
                        _ => (),
                    }
                }

                None
            })
            .unwrap_or(vec![]);
    }

    fn fetch_remote_uuids(&self, device: BluetoothDevice) -> bool {
        if !self.bonded_devices.contains_key(&device.address)
            && !self.found_devices.contains_key(&device.address)
        {
            warn!("Won't fetch UUIDs on unknown device {}", device.address);
            return false;
        }

        let addr = RawAddress::from_string(device.address.clone());
        if addr.is_none() {
            warn!("Can't fetch UUIDs. Address {} is not valid.", device.address);
            return false;
        }
        self.intf.lock().unwrap().get_remote_services(&mut addr.unwrap(), BtTransport::Auto) == 0
    }

    fn sdp_search(&self, device: BluetoothDevice, uuid: Uuid128Bit) -> bool {
        if self.sdp.is_none() {
            warn!("SDP is not initialized. Can't do SDP search.");
            return false;
        }

        let addr = RawAddress::from_string(device.address.clone());
        if addr.is_none() {
            warn!("Can't SDP search. Address {} is not valid.", device.address);
            return false;
        }

        let uu = Uuid { uu: uuid };
        self.sdp.as_ref().unwrap().sdp_search(&mut addr.unwrap(), &uu) == BtStatus::Success
    }
}

impl BtifSdpCallbacks for Bluetooth {
    fn sdp_search(
        &mut self,
        status: BtStatus,
        address: RawAddress,
        uuid: Uuid,
        _count: i32,
        _records: Vec<BtSdpRecord>,
    ) {
        debug!(
            "Sdp search result found: Status({:?}) Address({:?}) Uuid({:?})",
            status, address, uuid
        );
    }
}
