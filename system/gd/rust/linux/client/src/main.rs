use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use dbus::channel::MatchingReceiver;
use dbus::message::MatchRule;
use dbus::nonblock::SyncConnection;
use dbus_crossroads::Crossroads;
use tokio::sync::mpsc;

use crate::callbacks::{BtCallback, BtManagerCallback};
use crate::command_handler::CommandHandler;
use crate::dbus_iface::{BluetoothDBus, BluetoothManagerDBus};
use crate::editor::AsyncEditor;
use bt_topshim::topstack;
use btstack::bluetooth::{BluetoothDevice, IBluetooth};
use manager_service::iface_bluetooth_manager::IBluetoothManager;

mod callbacks;
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

    /// Current adapter address if known.
    pub(crate) adapter_address: Option<String>,

    /// Is adapter discovering?
    pub(crate) discovering_state: bool,

    /// Devices found in current discovery session. List should be cleared when a new discovery
    /// session starts so that previous results don't pollute current search.
    pub(crate) found_devices: HashMap<String, BluetoothDevice>,

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
            adapter_address: None,
            discovering_state: false,
            found_devices: HashMap::new(),
            manager_dbus,
            adapter_dbus: None,
            fg: tx,
            dbus_connection,
            dbus_crossroads,
        }
    }

    // Creates adapter proxy, registers callbacks and initializes address.
    fn create_adapter_proxy(&mut self, idx: i32) {
        let conn = self.dbus_connection.clone();
        let cr = self.dbus_crossroads.clone();

        let dbus = BluetoothDBus::new(conn, cr, idx);
        self.adapter_dbus = Some(dbus);

        // Trigger callback registration in the foreground
        let fg = self.fg.clone();
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
        context.lock().unwrap().manager_dbus.register_callback(Box::new(BtManagerCallback::new(
            String::from("/org/chromium/bluetooth/client/bluetooth_manager_callback"),
            context.clone(),
        )));

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

    let semaphore_fg = Arc::new(tokio::sync::Semaphore::new(1));

    // Async task to keep reading new lines from user
    let semaphore = semaphore_fg.clone();
    tokio::spawn(async move {
        let editor = AsyncEditor::new(command_list);

        loop {
            // Wait until ForegroundAction::Readline finishes its task.
            let permit = semaphore.acquire().await;
            if permit.is_err() {
                break;
            };
            // Let ForegroundAction::Readline decide when it's done.
            permit.unwrap().forget();

            // It's good to do readline now.
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
                    .register_callback(Box::new(BtCallback::new(objpath, context.clone())));
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
                    // Ready to do readline again.
                    semaphore_fg.add_permits(1);
                }
            },
        }
    }

    semaphore_fg.close();

    print_info!("Client exiting");
}
