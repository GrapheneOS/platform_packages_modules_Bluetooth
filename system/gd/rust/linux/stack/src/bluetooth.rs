//! Anything related to the adapter API (IBluetooth).

use bt_topshim::btif::{
    BaseCallbacks, BaseCallbacksDispatcher, BluetoothInterface, BluetoothProperty, BtBondState,
    BtDiscoveryState, BtPropertyType, BtSspVariant, BtState, BtStatus, BtTransport, RawAddress,
};
use bt_topshim::profiles::hid_host::{HHCallbacksDispatcher, HidHost};
use bt_topshim::topstack;

use btif_macros::{btif_callback, btif_callbacks_dispatcher};

use num_traits::cast::ToPrimitive;

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::Mutex;

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

    /// Starts BREDR Inquiry.
    fn start_discovery(&self) -> bool;

    /// Cancels BREDR Inquiry.
    fn cancel_discovery(&self) -> bool;

    /// Initiates pairing to a remote device. Triggers connection if not already started.
    fn create_bond(&self, device: BluetoothDevice, transport: BluetoothTransport) -> bool;
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
struct BluetoothDeviceWithProperties {
    pub info: BluetoothDevice,
    pub properties: HashMap<BtPropertyType, BluetoothProperty>,
}

impl BluetoothDeviceWithProperties {
    pub(crate) fn new(
        info: BluetoothDevice,
        properties: Vec<BluetoothProperty>,
    ) -> BluetoothDeviceWithProperties {
        let mut device = BluetoothDeviceWithProperties { info, properties: HashMap::new() };
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
}

/// Implementation of the adapter API.
pub struct Bluetooth {
    intf: Arc<Mutex<BluetoothInterface>>,

    bluetooth_media: Arc<Mutex<Box<BluetoothMedia>>>,
    callbacks: Vec<(u32, Box<dyn IBluetoothCallback + Send>)>,
    callbacks_last_id: u32,
    hh: Option<HidHost>,
    local_address: Option<RawAddress>,
    properties: HashMap<BtPropertyType, BluetoothProperty>,
    found_devices: HashMap<String, BluetoothDeviceWithProperties>,
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
            callbacks: vec![],
            callbacks_last_id: 0,
            hh: None,
            bluetooth_media,
            intf,
            local_address: None,
            properties: HashMap::new(),
            found_devices: HashMap::new(),
            state: BtState::Off,
            tx,
        }
    }

    pub fn init_profiles(&mut self) {
        self.hh = Some(HidHost::new(&self.intf.lock().unwrap()));
        self.hh.as_mut().unwrap().initialize(HHCallbacksDispatcher {
            dispatch: Box::new(move |_cb| {
                // TODO("Implement the callbacks");
                println!("received HH callback");
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
            let device_with_props = BluetoothDeviceWithProperties::new(device, properties);
            self.found_devices.insert(address.clone(), device_with_props);
        }

        let device = self.found_devices.get(&address).unwrap();

        self.for_all_callbacks(|callback| {
            callback.on_device_found(device.info.clone());
        });
    }

    fn discovery_state(&mut self, state: BtDiscoveryState) {
        // Clear found devices when discovery session ends
        if &state == &BtDiscoveryState::Stopped {
            self.found_devices.clear();
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
        _status: BtStatus,
        mut addr: RawAddress,
        bond_state: BtBondState,
        _fail_reason: i32,
    ) {
        if bond_state == BtBondState::Bonded {
            // We are assuming that peer is a HID device and automatically connect to that profile.
            // TODO: Only connect to enabled profiles on that device.
            self.hh.as_ref().unwrap().connect(&mut addr);
        }
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

    fn start_discovery(&self) -> bool {
        self.intf.lock().unwrap().start_discovery() == 0
    }

    fn cancel_discovery(&self) -> bool {
        self.intf.lock().unwrap().cancel_discovery() == 0
    }

    fn create_bond(&self, device: BluetoothDevice, transport: BluetoothTransport) -> bool {
        let addr = RawAddress::from_string(device.address.clone());

        if addr.is_none() {
            println!("address {} is not valid", device.address);
            return false;
        }

        let address = addr.unwrap();
        self.intf
            .lock()
            .unwrap()
            .create_bond(&address, BtTransport::from(transport.to_i32().unwrap()))
            == 0
    }
}
