use bt_topshim::btif::BtSspVariant;

use btstack::bluetooth::{BluetoothDevice, BluetoothTransport, IBluetooth, IBluetoothCallback};
use btstack::RPCProxy;

use manager_service::iface_bluetooth_manager::IBluetoothManager;

use num_traits::cast::FromPrimitive;

use std::sync::{Arc, Mutex};

use crate::console_yellow;
use crate::print_info;

struct BtCallback {
    objpath: String,
}

impl IBluetoothCallback for BtCallback {
    fn on_address_changed(&self, addr: String) {
        print_info!("Address changed to {}", addr);
    }

    fn on_device_found(&self, remote_device: BluetoothDevice) {
        print_info!("Found device: {:?}", remote_device);
    }

    fn on_discovering_changed(&self, discovering: bool) {
        print_info!("Discovering: {}", discovering);
    }

    fn on_ssp_request(
        &self,
        remote_device: BluetoothDevice,
        _cod: u32,
        variant: BtSspVariant,
        passkey: u32,
    ) {
        if variant == BtSspVariant::PasskeyNotification {
            print_info!(
                "device {}{} would like to pair, enter passkey on remote device: {:06}",
                remote_device.address.to_string(),
                if remote_device.name.len() > 0 {
                    format!(" ({})", remote_device.name)
                } else {
                    String::from("")
                },
                passkey
            );
        }
    }
}

impl RPCProxy for BtCallback {
    fn register_disconnect(&mut self, _f: Box<dyn Fn() + Send>) {}

    fn get_object_id(&self) -> String {
        self.objpath.clone()
    }
}

/// Handles string command entered from command line.
pub struct CommandHandler<TBluetoothManager: IBluetoothManager, TBluetooth: IBluetooth> {
    bluetooth_manager: Arc<Mutex<Box<TBluetoothManager>>>,
    bluetooth: Arc<Mutex<Box<TBluetooth>>>,

    is_bluetooth_callback_registered: bool,
}

impl<TBluetoothManager: IBluetoothManager, TBluetooth: IBluetooth>
    CommandHandler<TBluetoothManager, TBluetooth>
{
    pub fn new(
        bluetooth_manager: Arc<Mutex<Box<TBluetoothManager>>>,
        bluetooth: Arc<Mutex<Box<TBluetooth>>>,
    ) -> CommandHandler<TBluetoothManager, TBluetooth> {
        CommandHandler { bluetooth_manager, bluetooth, is_bluetooth_callback_registered: false }
    }

    pub fn cmd_enable(&self, _cmd: String) {
        self.bluetooth_manager.lock().unwrap().start(0);
    }

    pub fn cmd_disable(&self, _cmd: String) {
        self.bluetooth_manager.lock().unwrap().stop(0);
    }

    pub fn cmd_get_address(&self, _cmd: String) {
        let addr = self.bluetooth.lock().unwrap().get_address();
        print_info!("Local address = {}", addr);
    }

    pub fn cmd_start_discovery(&mut self, _cmd: String) {
        // TODO: Register the BtCallback when getting a OnStateChangedCallback from btmanagerd.
        if !self.is_bluetooth_callback_registered {
            self.bluetooth.lock().unwrap().register_callback(Box::new(BtCallback {
                objpath: String::from("/org/chromium/bluetooth/client/bluetooth_callback"),
            }));
            self.is_bluetooth_callback_registered = true;
        }

        self.bluetooth.lock().unwrap().start_discovery();
    }

    pub fn cmd_cancel_discovery(&self, _cmd: String) {
        self.bluetooth.lock().unwrap().cancel_discovery();
    }

    pub fn cmd_create_bond(&self, cmd: String) {
        let s = cmd.split(' ').collect::<Vec<&str>>();
        if s.len() < 2 {
            println!("usage: create_bond <addr>");
            return;
        }
        let device = BluetoothDevice { address: String::from(s[1]), name: String::from("") };
        self.bluetooth
            .lock()
            .unwrap()
            .create_bond(device, BluetoothTransport::from_i32(0).unwrap());
    }
}
