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

        let mut handler = CommandHandler::new(api.bluetooth_manager.clone(), api.bluetooth.clone());

        let args: Vec<String> = std::env::args().collect();

        // Allow command line arguments to be read
        if args.len() > 1 {
            handler.process_cmd_line(&args[1], &args[2..].to_vec());
        } else {
            start_interactive_shell(handler).await;
        }
        return Result::Ok(());
    })
}

async fn start_interactive_shell(mut handler: CommandHandler) {
    let editor = AsyncEditor::new(handler.get_command_list().clone());

    loop {
        let result = editor.readline().await;
        match result {
            Err(_err) => break,
            Ok(line) => {
                let command_vec = line.split(" ").map(|s| String::from(s)).collect::<Vec<String>>();
                let cmd = &command_vec[0];
                if cmd.eq("quit") {
                    break;
                }
                handler.process_cmd_line(
                    &String::from(cmd),
                    &command_vec[1..command_vec.len()].to_vec(),
                );
            }
        }
    }

    print_info!("Client exiting");
}
