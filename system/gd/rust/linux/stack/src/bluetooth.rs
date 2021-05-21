//! Anything related to the adapter API (IBluetooth).

use bt_topshim::btif::{
    BaseCallbacks, BaseCallbacksDispatcher, BluetoothInterface, BtBondState, BtDiscoveryState,
    BtProperty, BtPropertyType, BtSspVariant, BtState, BtStatus, BtTransport, RawAddress,
};
use bt_topshim::profiles::hid_host::{HHCallbacksDispatcher, HidHost};
use bt_topshim::topstack;

use num_traits::cast::ToPrimitive;

use std::sync::Arc;
use std::sync::Mutex;

use tokio::sync::mpsc::Sender;

use crate::{BDAddr, Message, RPCProxy};

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

#[derive(Debug, Default)]
pub struct BluetoothDevice {
    pub address: String,
    pub name: String,
}

impl BluetoothDevice {
    pub(crate) fn from_properties(properties: &Vec<BtProperty>) -> BluetoothDevice {
        let mut address = String::from("");
        let mut name = String::from("");

        for prop in properties {
            match prop.prop_type {
                BtPropertyType::BdAddr => {
                    if let Some(addr) = BDAddr::from_byte_vec(&prop.val) {
                        address = addr.to_string();
                    }
                }
                BtPropertyType::BdName => {
                    name = String::from_utf8(prop.val.clone()).unwrap();
                }
                _ => {}
            }
        }

        BluetoothDevice { address, name }
    }
}

/// The interface for adapter callbacks registered through `IBluetooth::register_callback`.
pub trait IBluetoothCallback: RPCProxy {
    /// When any of the adapter states is changed.
    fn on_bluetooth_state_changed(&self, prev_state: u32, new_state: u32);

    /// When any of the adapter local address is changed.
    fn on_bluetooth_address_changed(&self, addr: String);

    /// When a device is found via discovery.
    fn on_device_found(&self, remote_device: BluetoothDevice);

    /// When the discovery state is changed.
    fn on_discovering_changed(&self, discovering: bool);
}

/// Implementation of the adapter API.
pub struct Bluetooth {
    intf: Arc<Mutex<BluetoothInterface>>,
    state: BtState,
    callbacks: Vec<(u32, Box<dyn IBluetoothCallback + Send>)>,
    callbacks_last_id: u32,
    tx: Sender<Message>,
    local_address: Option<BDAddr>,
    hh: Option<HidHost>,
}

impl Bluetooth {
    /// Constructs the IBluetooth implementation.
    pub fn new(tx: Sender<Message>, intf: Arc<Mutex<BluetoothInterface>>) -> Bluetooth {
        Bluetooth {
            tx,
            intf,
            state: BtState::Off,
            callbacks: vec![],
            callbacks_last_id: 0,
            local_address: None,
            hh: None,
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

    fn update_local_address(&mut self, raw: &Vec<u8>) {
        self.local_address = BDAddr::from_byte_vec(raw);

        self.for_all_callbacks(|callback| {
            callback.on_bluetooth_address_changed(self.local_address.unwrap().to_string());
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

    pub(crate) fn handle_base_callback(&mut self, cb: BaseCallbacks) {
        match cb {
            BaseCallbacks::AdapterState(state) => {
                self.adapter_state_changed(state);
            }

            BaseCallbacks::AdapterProperties(status, num_properties, properties) => {
                self.adapter_properties_changed(status, num_properties, properties);
            }

            BaseCallbacks::DeviceFound(_n, properties) => {
                self.device_found(properties);
            }

            BaseCallbacks::DiscoveryState(state) => {
                self.discovery_state(state);
            }

            BaseCallbacks::SspRequest(remote_addr, remote_name, cod, variant, passkey) => {
                self.ssp_request(remote_addr, remote_name, cod, variant, passkey);
            }

            BaseCallbacks::BondState(status, addr, bond_state) => {
                self.bond_state(status, addr, bond_state);
            }

            _ => println!("Unhandled callback arm {:?}", cb),
        }
    }
}

pub(crate) trait BtifBluetoothCallbacks {
    fn adapter_state_changed(&mut self, state: BtState);

    fn adapter_properties_changed(
        &mut self,
        status: BtStatus,
        num_properties: i32,
        properties: Vec<BtProperty>,
    );

    fn device_found(&mut self, properties: Vec<BtProperty>);

    fn discovery_state(&mut self, state: BtDiscoveryState);

    fn ssp_request(
        &mut self,
        remote_addr: RawAddress,
        remote_name: String,
        cod: u32,
        variant: BtSspVariant,
        passkey: u32,
    );

    fn bond_state(&mut self, status: BtStatus, addr: RawAddress, bond_state: BtBondState);
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
        self.for_all_callbacks(|callback| {
            callback
                .on_bluetooth_state_changed(self.state.to_u32().unwrap(), state.to_u32().unwrap())
        });

        self.state = state;
    }

    #[allow(unused_variables)]
    fn adapter_properties_changed(
        &mut self,
        status: BtStatus,
        num_properties: i32,
        properties: Vec<BtProperty>,
    ) {
        if status != BtStatus::Success {
            return;
        }

        for prop in properties {
            match prop.prop_type {
                BtPropertyType::BdAddr => {
                    self.update_local_address(&prop.val);
                }
                _ => {}
            }
        }
    }

    fn device_found(&mut self, properties: Vec<BtProperty>) {
        self.for_all_callbacks(|callback| {
            callback.on_device_found(BluetoothDevice::from_properties(&properties));
        });
    }

    fn discovery_state(&mut self, state: BtDiscoveryState) {
        self.for_all_callbacks(|callback| {
            callback.on_discovering_changed(state == BtDiscoveryState::Started);
        });
    }

    fn ssp_request(
        &mut self,
        remote_addr: RawAddress,
        _remote_name: String,
        _cod: u32,
        variant: BtSspVariant,
        passkey: u32,
    ) {
        // Immediately accept the pairing.
        // TODO: Delegate the pairing confirmation to agent.
        // TODO: Implement other pairing confirmations (passkey, passcode, etc);
        self.intf.lock().unwrap().ssp_reply(&remote_addr, variant, 1, passkey);
    }

    fn bond_state(&mut self, _status: BtStatus, mut addr: RawAddress, bond_state: BtBondState) {
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
            topstack::get_runtime().spawn(async move {
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
        let addr = BDAddr::from_string(device.address.clone());

        if addr.is_none() {
            println!("address {} is not valid", device.address);
            return false;
        }

        let address = unsafe { RawAddress::new(&addr.unwrap().val) };
        self.intf
            .lock()
            .unwrap()
            .create_bond(&address, BtTransport::from(transport.to_i32().unwrap()))
            == 0
    }
}
