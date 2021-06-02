use btstack::bluetooth::{BluetoothDevice, BluetoothTransport, IBluetooth};

use num_traits::cast::FromPrimitive;

use std::sync::{Arc, Mutex};

use crate::console_yellow;
use crate::print_info;

/// Handles string command entered from command line.
pub struct CommandHandler {
    bluetooth: Arc<Mutex<dyn IBluetooth>>,
}

impl CommandHandler {
    pub fn new(bluetooth: Arc<Mutex<dyn IBluetooth>>) -> CommandHandler {
        CommandHandler { bluetooth }
    }

    pub fn cmd_enable(&self, _cmd: String) {
        self.bluetooth.lock().unwrap().enable();
    }

    pub fn cmd_disable(&self, _cmd: String) {
        self.bluetooth.lock().unwrap().disable();
    }

    pub fn cmd_get_address(&self, _cmd: String) {
        let addr = self.bluetooth.lock().unwrap().get_address();
        print_info!("Local address = {}", addr);
    }

    pub fn cmd_start_discovery(&self, _cmd: String) {
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
