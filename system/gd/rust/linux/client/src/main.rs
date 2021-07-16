use bt_topshim::topstack;

use dbus::channel::MatchingReceiver;

use dbus::message::MatchRule;

use dbus::nonblock::SyncConnection;

use manager_service::iface_bluetooth_manager::{IBluetoothManager, IBluetoothManagerCallback};

use std::sync::{Arc, Mutex};

use crate::command_handler::CommandHandler;
use crate::dbus_iface::{BluetoothDBus, BluetoothManagerDBus};
use crate::editor::AsyncEditor;

use dbus_crossroads::Crossroads;

mod command_handler;
mod console;
mod dbus_arg;
mod dbus_iface;
mod editor;

struct BtManagerCallback {
    objpath: String,
}

impl IBluetoothManagerCallback for BtManagerCallback {
    fn on_hci_device_changed(&self, hci_interface: i32, present: bool) {
        print_info!("hci{} present = {}", hci_interface, present);
    }

    fn on_hci_enabled_changed(&self, hci_interface: i32, enabled: bool) {
        print_info!("hci{} enabled = {}", hci_interface, enabled);
    }
}

impl manager_service::RPCProxy for BtManagerCallback {
    fn register_disconnect(&mut self, _f: Box<dyn Fn() + Send>) {}

    fn get_object_id(&self) -> String {
        self.objpath.clone()
    }
}

struct API {
    bluetooth_manager: Arc<Mutex<Box<BluetoothManagerDBus>>>,
    bluetooth: Arc<Mutex<Box<BluetoothDBus>>>,
}

// This creates the API implementations over D-Bus.
fn create_api_dbus(conn: Arc<SyncConnection>, cr: Arc<Mutex<Crossroads>>, idx: i32) -> API {
    let bluetooth_manager =
        Arc::new(Mutex::new(Box::new(BluetoothManagerDBus::new(conn.clone(), cr.clone()))));

    let bluetooth =
        Arc::new(Mutex::new(Box::new(BluetoothDBus::new(conn.clone(), cr.clone(), idx))));

    API { bluetooth_manager, bluetooth }
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

        // We only need hci index 0 for now.
        // TODO: Have a mechanism (e.g. CLI argument or btclient command) to select the hci index.
        let api = create_api_dbus(conn, cr, 0);

        // TODO: Registering the callback should be done when btmanagerd is ready (detect with
        // ObjectManager).
        api.bluetooth_manager.lock().unwrap().register_callback(Box::new(BtManagerCallback {
            objpath: String::from("/org/chromium/bluetooth/client/bluetooth_manager_callback"),
        }));

        // TODO(b/193719802): Refactor this into a dedicated "Help" data structure.
        let commands = vec![
            String::from("help"),
            String::from("enable"),
            String::from("disable"),
            String::from("get_address"),
            String::from("start_discovery"),
            String::from("cancel_discovery"),
            String::from("create_bond"),
        ];

        let mut handler = CommandHandler::new(
            api.bluetooth_manager.clone(),
            api.bluetooth.clone(),
            commands.clone(),
        );

        let mut handle_cmd = move |cmd: String| match cmd.split(' ').collect::<Vec<&str>>()[0] {
            "help" => handler.cmd_help(),

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

        let editor = AsyncEditor::new(commands.clone());

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
