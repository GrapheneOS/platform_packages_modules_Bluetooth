extern crate bt_shim;

use bt_topshim::btif::get_btinterface;
use bt_topshim::topstack;
use btstack::bluetooth::{
    get_bt_dispatcher, Bluetooth, BluetoothDevice, IBluetooth, IBluetoothCallback,
};

use btstack::{RPCProxy, Stack};

use std::sync::{Arc, Mutex};

use crate::command_handler::CommandHandler;
use crate::editor::AsyncEditor;

mod command_handler;
mod console;
mod editor;

struct BtCallback {
    disconnect_callbacks: Arc<Mutex<Vec<Box<dyn Fn() + Send>>>>,
}

impl IBluetoothCallback for BtCallback {
    fn on_bluetooth_state_changed(&self, prev_state: u32, new_state: u32) {
        print_info!("Adapter state changed from {} to {}", prev_state, new_state);
    }

    fn on_bluetooth_address_changed(&self, addr: String) {
        print_info!("Address changed to {}", addr);
    }

    fn on_device_found(&self, remote_device: BluetoothDevice) {
        print_info!("Found device: {:?}", remote_device);
    }

    fn on_discovering_changed(&self, discovering: bool) {
        print_info!("Discovering: {}", discovering);
    }
}

impl RPCProxy for BtCallback {
    fn register_disconnect(&mut self, f: Box<dyn Fn() + Send>) {
        self.disconnect_callbacks.lock().unwrap().push(f);
    }
}

struct API {
    bluetooth: Arc<Mutex<dyn IBluetooth>>,
}

fn create_api_embedded() -> API {
    // This creates the API implementations directly embedded to this client.
    // TODO: Add API implementations as proxy over D-Bus.

    let (tx, rx) = Stack::create_channel();

    let intf = Arc::new(Mutex::new(get_btinterface().unwrap()));
    let bluetooth = Arc::new(Mutex::new(Bluetooth::new(tx.clone(), intf.clone())));

    intf.lock().unwrap().initialize(get_bt_dispatcher(tx), vec![]);

    bluetooth.lock().unwrap().init_profiles();

    topstack::get_runtime().spawn(Stack::dispatch(rx, bluetooth.clone()));

    API { bluetooth }
}

/// Runs a command line program that interacts with a Bluetooth stack.
fn main() -> Result<(), Box<dyn std::error::Error>> {
    // TODO: Process command line arguments.

    let api = create_api_embedded();

    let dc_callbacks = Arc::new(Mutex::new(vec![]));
    api.bluetooth
        .lock()
        .unwrap()
        .register_callback(Box::new(BtCallback { disconnect_callbacks: dc_callbacks.clone() }));

    let handler = CommandHandler::new(api.bluetooth.clone());

    let simulate_disconnect = move |_cmd| {
        for callback in &*dc_callbacks.lock().unwrap() {
            callback();
        }
    };

    let handle_cmd = move |cmd: String| match cmd.split(' ').collect::<Vec<&str>>()[0] {
        "enable" => handler.cmd_enable(cmd),
        "disable" => handler.cmd_disable(cmd),
        "get_address" => handler.cmd_get_address(cmd),
        "start_discovery" => handler.cmd_start_discovery(cmd),
        "cancel_discovery" => handler.cmd_cancel_discovery(cmd),
        "create_bond" => handler.cmd_create_bond(cmd),

        // Simulate client disconnection. Only useful in embedded mode. In D-Bus mode there is
        // real D-Bus disconnection.
        "simulate_disconnect" => simulate_disconnect(cmd),

        // Ignore empty commands.
        "" => {}

        // TODO: Print help.
        _ => print_info!("Command \"{}\" not recognized", cmd),
    };

    let editor = AsyncEditor::new();
    topstack::get_runtime().block_on(async move {
        loop {
            let result = editor.readline().await;
            match result {
                Err(_err) => break,
                Ok(line) => {
                    if line.eq("quit") {
                        break;
                    }
                    handle_cmd(line.clone());
                }
            }
        }

        print_info!("Client exiting");

        Result::Ok(())
    })
}
