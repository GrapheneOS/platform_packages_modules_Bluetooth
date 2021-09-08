use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use dbus::channel::MatchingReceiver;
use dbus::message::MatchRule;
use dbus::nonblock::SyncConnection;
use dbus_crossroads::Crossroads;
use tokio::sync::mpsc;

use crate::command_handler::CommandHandler;
use crate::dbus_iface::{BluetoothDBus, BluetoothManagerDBus};
use crate::editor::AsyncEditor;
use bt_topshim::btif::BtSspVariant;
use bt_topshim::topstack;
use btstack::bluetooth::{BluetoothDevice, IBluetooth, IBluetoothCallback};
use btstack::RPCProxy;
use manager_service::iface_bluetooth_manager::{IBluetoothManager, IBluetoothManagerCallback};

mod command_handler;
mod console;
mod dbus_arg;
mod dbus_iface;
mod editor;

/// Context structure for the client. Used to keep track details about the active adapter and its
/// state.
pub(crate) struct ClientContext {
    /// List of adapters and whether they are enabled.
    pub(crate) adapters: HashMap<i32, bool>,

    // TODO(abps) - Change once we have multi-adapter support.
    /// The default adapter is also the active adapter. Defaults to 0.
    pub(crate) default_adapter: i32,

    /// Current adapter is enabled?
    pub(crate) enabled: bool,

    /// Current adapter is ready to be used?
    pub(crate) adapter_ready: bool,

    /// Proxy for manager interface.
    pub(crate) manager_dbus: BluetoothManagerDBus,

    /// Proxy for adapter interface. Only exists when the default adapter is enabled.
    pub(crate) adapter_dbus: Option<BluetoothDBus>,

    /// Channel to send actions to take in the foreground
    fg: mpsc::Sender<ForegroundActions>,

    /// Internal DBus connection object.
    dbus_connection: Arc<SyncConnection>,

    /// Internal DBus crossroads object.
    dbus_crossroads: Arc<Mutex<Crossroads>>,
}

impl ClientContext {
    pub fn new(
        dbus_connection: Arc<SyncConnection>,
        dbus_crossroads: Arc<Mutex<Crossroads>>,
        tx: mpsc::Sender<ForegroundActions>,
    ) -> ClientContext {
        // Manager interface is always available but adapter interface requires
        // that the specific adapter is enabled.
        let manager_dbus =
            BluetoothManagerDBus::new(dbus_connection.clone(), dbus_crossroads.clone());

        ClientContext {
            adapters: HashMap::new(),
            default_adapter: 0,
            enabled: false,
            adapter_ready: false,
            manager_dbus,
            adapter_dbus: None,
            fg: tx,
            dbus_connection,
            dbus_crossroads,
        }
    }

    // Creates adapter proxy, registers callbacks and initializes address.
    fn create_adapter_proxy(context: Arc<Mutex<ClientContext>>, idx: &i32) {
        let conn = context.lock().unwrap().dbus_connection.clone();
        let cr = context.lock().unwrap().dbus_crossroads.clone();

        let dbus = BluetoothDBus::new(conn, cr, *idx);
        context.lock().unwrap().adapter_dbus = Some(dbus);

        // Trigger callback registration in the foreground
        let fg = context.lock().unwrap().fg.clone();
        tokio::spawn(async move {
            let objpath = String::from("/org/chromium/bluetooth/client/bluetooth_callback");
            let _ = fg.send(ForegroundActions::RegisterAdapterCallback(objpath)).await;
        });
    }
}

/// Actions to take on the foreground loop. This allows us to queue actions in
/// callbacks that get run in the foreground context.
enum ForegroundActions {
    RegisterAdapterCallback(String), // Register callbacks with this objpath
    Readline(rustyline::Result<String>), // Readline result from rustyline
}

/// Callback context for manager interface callbacks.
struct BtManagerCallback {
    objpath: String,
    context: Arc<Mutex<ClientContext>>,
}

impl IBluetoothManagerCallback for BtManagerCallback {
    fn on_hci_device_changed(&self, hci_interface: i32, present: bool) {
        print_info!("hci{} present = {}", hci_interface, present);

        if present {
            self.context.lock().unwrap().adapters.entry(hci_interface).or_insert(false);
        } else {
            self.context.lock().unwrap().adapters.remove(&hci_interface);
        }
    }

    fn on_hci_enabled_changed(&self, hci_interface: i32, enabled: bool) {
        print_info!("hci{} enabled = {}", hci_interface, enabled);

        self.context
            .lock()
            .unwrap()
            .adapters
            .entry(hci_interface)
            .and_modify(|v| *v = enabled)
            .or_insert(enabled);

        // When the default adapter's state is updated, we need to modify a few more things.
        // Only do this if we're not repeating the previous state.
        let prev_enabled = self.context.lock().unwrap().enabled;
        let default_adapter = self.context.lock().unwrap().default_adapter;
        if hci_interface == default_adapter && prev_enabled != enabled {
            self.context.lock().unwrap().enabled = enabled;
            self.context.lock().unwrap().adapter_ready = false;
            if enabled {
                ClientContext::create_adapter_proxy(self.context.clone(), &hci_interface);
            } else {
                self.context.lock().unwrap().adapter_dbus = None;
            }
        }
    }
}

impl manager_service::RPCProxy for BtManagerCallback {
    fn register_disconnect(&mut self, _f: Box<dyn Fn() + Send>) {}

    fn get_object_id(&self) -> String {
        self.objpath.clone()
    }
}

/// Callback container for adapter interface callbacks.
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

        // Accept foreground actions with mpsc
        let (tx, rx) = mpsc::channel::<ForegroundActions>(10);

        // Create the context needed for handling commands
        let context = Arc::new(Mutex::new(ClientContext::new(conn, cr, tx.clone())));

        // TODO: Registering the callback should be done when btmanagerd is ready (detect with
        // ObjectManager).
        context.lock().unwrap().manager_dbus.register_callback(Box::new(BtManagerCallback {
            objpath: String::from("/org/chromium/bluetooth/client/bluetooth_manager_callback"),
            context: context.clone(),
        }));

        let mut handler = CommandHandler::new(context.clone());

        let args: Vec<String> = std::env::args().collect();

        // Allow command line arguments to be read
        if args.len() > 1 {
            handler.process_cmd_line(&args[1], &args[2..].to_vec());
        } else {
            start_interactive_shell(handler, tx, rx, context).await;
        }
        return Result::Ok(());
    })
}

async fn start_interactive_shell(
    mut handler: CommandHandler,
    tx: mpsc::Sender<ForegroundActions>,
    mut rx: mpsc::Receiver<ForegroundActions>,
    context: Arc<Mutex<ClientContext>>,
) {
    let command_list = handler.get_command_list().clone();

    // Async task to keep reading new lines from user
    tokio::spawn(async move {
        let editor = AsyncEditor::new(command_list);

        loop {
            let result = editor.readline().await;
            let _ = tx.send(ForegroundActions::Readline(result)).await;
        }
    });

    loop {
        let m = rx.recv().await;

        if m.is_none() {
            break;
        }

        match m.unwrap() {
            // Once adapter is ready, register callbacks, get the address and mark it as ready
            ForegroundActions::RegisterAdapterCallback(objpath) => {
                context
                    .lock()
                    .unwrap()
                    .adapter_dbus
                    .as_mut()
                    .unwrap()
                    .register_callback(Box::new(BtCallback { objpath }));
                context.lock().unwrap().adapter_ready = true;
            }
            ForegroundActions::Readline(result) => match result {
                Err(_err) => {
                    break;
                }
                Ok(line) => {
                    let command_vec =
                        line.split(" ").map(|s| String::from(s)).collect::<Vec<String>>();
                    let cmd = &command_vec[0];
                    if cmd.eq("quit") {
                        break;
                    }
                    handler.process_cmd_line(
                        &String::from(cmd),
                        &command_vec[1..command_vec.len()].to_vec(),
                    );
                }
            },
        }
    }
    print_info!("Client exiting");
}
