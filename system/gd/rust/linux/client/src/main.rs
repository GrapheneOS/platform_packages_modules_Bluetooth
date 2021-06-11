use bt_topshim::btif::BtSspVariant;
use bt_topshim::topstack;

use btstack::bluetooth::{BluetoothDevice, IBluetooth, IBluetoothCallback};
use btstack::RPCProxy;

use dbus::channel::MatchingReceiver;

use dbus::message::MatchRule;

use dbus::nonblock::SyncConnection;

use std::sync::{Arc, Mutex};

use crate::command_handler::CommandHandler;
use crate::dbus_iface::BluetoothDBus;
use crate::editor::AsyncEditor;

use dbus_crossroads::Crossroads;

mod command_handler;
mod console;
mod dbus_arg;
mod dbus_iface;
mod editor;

struct BtCallback {
    objpath: String,
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

struct API<T: IBluetooth> {
    bluetooth: Arc<Mutex<Box<T>>>,
}

// This creates the API implementations over D-Bus.
fn create_api_dbus(conn: Arc<SyncConnection>, cr: Arc<Mutex<Crossroads>>) -> API<BluetoothDBus> {
    let bluetooth = Arc::new(Mutex::new(Box::new(BluetoothDBus::new(conn.clone(), cr))));

    API { bluetooth }
}

/// Runs a command line program that interacts with a Bluetooth stack.
fn main() -> Result<(), Box<dyn std::error::Error>> {
    // TODO: Process command line arguments.

    topstack::get_runtime().block_on(async move {
        // Connect to D-Bus system bus.
        let (resource, conn) = dbus_tokio::connection::new_system_sync()?;

        // The `resource` is a task that should be spawned onto a tokio compatible
        // reactor ASAP. If the resource ever finishes, we lost connection to D-Bus.
        tokio::spawn(async {
            let err = resource.await;
            panic!("Lost connection to D-Bus: {}", err);
        });

        // Sets up Crossroads for receiving callbacks.
        let cr = Arc::new(Mutex::new(Crossroads::new()));
        cr.lock().unwrap().set_async_support(Some((
            conn.clone(),
            Box::new(|x| {
                tokio::spawn(x);
            }),
        )));
        let cr_clone = cr.clone();
        conn.start_receive(
            MatchRule::new_method_call(),
            Box::new(move |msg, conn| {
                cr_clone.lock().unwrap().handle_message(msg, conn).unwrap();
                true
            }),
        );

        let api = create_api_dbus(conn, cr);

        api.bluetooth.lock().unwrap().register_callback(Box::new(BtCallback {
            objpath: String::from("/org/chromium/bluetooth/client/bluetooth_callback"),
        }));

        let handler = CommandHandler::<BluetoothDBus>::new(api.bluetooth.clone());

        let handle_cmd = move |cmd: String| match cmd.split(' ').collect::<Vec<&str>>()[0] {
            "enable" => handler.cmd_enable(cmd),
            "disable" => handler.cmd_disable(cmd),
            "get_address" => handler.cmd_get_address(cmd),
            "start_discovery" => handler.cmd_start_discovery(cmd),
            "cancel_discovery" => handler.cmd_cancel_discovery(cmd),
            "create_bond" => handler.cmd_create_bond(cmd),

            // Ignore empty commands.
            "" => {}

            // TODO: Print help.
            _ => print_info!("Command \"{}\" not recognized", cmd),
        };

        let editor = AsyncEditor::new();

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
