use bt_topshim::btif::get_btinterface;
use bt_topshim::topstack;

use dbus::channel::MatchingReceiver;
use dbus::message::MatchRule;

use dbus_crossroads::Crossroads;

use dbus_projection::DisconnectWatcher;

use dbus_tokio::connection;

use futures::future;

use btstack::bluetooth::get_bt_dispatcher;
use btstack::bluetooth::{Bluetooth, IBluetooth};
use btstack::bluetooth_gatt::BluetoothGatt;
use btstack::bluetooth_media::BluetoothMedia;
use btstack::Stack;

use std::error::Error;
use std::sync::{Arc, Mutex};

mod dbus_arg;
mod iface_bluetooth;
mod iface_bluetooth_gatt;
mod iface_bluetooth_media;

const DBUS_SERVICE_NAME: &str = "org.chromium.bluetooth";
const OBJECT_BLUETOOTH: &str = "/org/chromium/bluetooth/adapter";
const OBJECT_BLUETOOTH_GATT: &str = "/org/chromium/bluetooth/gatt";
const OBJECT_BLUETOOTH_MEDIA: &str = "/org/chromium/bluetooth/media";

/// Runs the Bluetooth daemon serving D-Bus IPC.
fn main() -> Result<(), Box<dyn Error>> {
    let (tx, rx) = Stack::create_channel();

    let intf = Arc::new(Mutex::new(get_btinterface().unwrap()));
    let bluetooth = Arc::new(Mutex::new(Box::new(Bluetooth::new(tx.clone(), intf.clone()))));
    let bluetooth_gatt = Arc::new(Mutex::new(Box::new(BluetoothGatt::new(intf.clone()))));
    let bluetooth_media =
        Arc::new(Mutex::new(Box::new(BluetoothMedia::new(tx.clone(), intf.clone()))));

    // Args don't include arg[0] which is the binary name
    let all_args = std::env::args().collect::<Vec<String>>();
    let args = all_args[1..].to_vec();
    intf.lock().unwrap().initialize(get_bt_dispatcher(tx), args);

    bluetooth.lock().unwrap().init_profiles();
    bluetooth.lock().unwrap().enable();

    topstack::get_runtime().block_on(async {
        // Connect to D-Bus system bus.
        let (resource, conn) = connection::new_system_sync()?;

        // The `resource` is a task that should be spawned onto a tokio compatible
        // reactor ASAP. If the resource ever finishes, we lost connection to D-Bus.
        tokio::spawn(async {
            let err = resource.await;
            panic!("Lost connection to D-Bus: {}", err);
        });

        // Request a service name and quit if not able to.
        conn.request_name(DBUS_SERVICE_NAME, false, true, false).await?;

        // Prepare D-Bus interfaces.
        let mut cr = Crossroads::new();
        cr.set_async_support(Some((
            conn.clone(),
            Box::new(|x| {
                tokio::spawn(x);
            }),
        )));

        // Run the stack main dispatch loop.
        tokio::spawn(Stack::dispatch(rx, bluetooth.clone()));

        // Set up the disconnect watcher to monitor client disconnects.
        let disconnect_watcher = Arc::new(Mutex::new(DisconnectWatcher::new()));
        disconnect_watcher.lock().unwrap().setup_watch(conn.clone()).await;

        // Register D-Bus method handlers of IBluetooth.
        iface_bluetooth::export_bluetooth_dbus_obj(
            String::from(OBJECT_BLUETOOTH),
            conn.clone(),
            &mut cr,
            bluetooth,
            disconnect_watcher.clone(),
        );
        // Register D-Bus method handlers of IBluetoothGatt.
        iface_bluetooth_gatt::export_bluetooth_gatt_dbus_obj(
            String::from(OBJECT_BLUETOOTH_GATT),
            conn.clone(),
            &mut cr,
            bluetooth_gatt,
            disconnect_watcher.clone(),
        );

        iface_bluetooth_media::export_bluetooth_media_dbus_obj(
            String::from(OBJECT_BLUETOOTH_MEDIA),
            conn.clone(),
            &mut cr,
            bluetooth_media,
            disconnect_watcher.clone(),
        );

        conn.start_receive(
            MatchRule::new_method_call(),
            Box::new(move |msg, conn| {
                cr.handle_message(msg, conn).unwrap();
                true
            }),
        );

        // Serve clients forever.
        future::pending::<()>().await;
        unreachable!()
    })
}
