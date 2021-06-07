//! D-Bus proxy implementations of the APIs.

use btstack::bluetooth::{BluetoothDevice, BluetoothTransport, IBluetooth, IBluetoothCallback};
use btstack::RPCProxy;

use dbus::arg::{AppendAll, RefArg};
use dbus::nonblock::SyncConnection;

use dbus_crossroads::Crossroads;

use dbus_projection::{impl_dbus_arg_enum, DisconnectWatcher};

use dbus_macros::{dbus_method, dbus_propmap, generate_dbus_exporter};

use num_traits::{FromPrimitive, ToPrimitive};

use std::sync::{Arc, Mutex};

use crate::dbus_arg::{DBusArg, DBusArgError, RefArgToRust};

impl_dbus_arg_enum!(BluetoothTransport);

#[dbus_propmap(BluetoothDevice)]
pub struct BluetoothDeviceDBus {
    address: String,
}

pub(crate) struct BluetoothDBus {
    conn: Arc<SyncConnection>,
    cr: Arc<Mutex<Crossroads>>,
}

impl BluetoothDBus {
    pub(crate) fn new(conn: Arc<SyncConnection>, cr: Arc<Mutex<Crossroads>>) -> BluetoothDBus {
        BluetoothDBus { conn: conn.clone(), cr: cr }
    }

    fn create_proxy(&self) -> dbus::nonblock::Proxy<Arc<SyncConnection>> {
        let conn = self.conn.clone();
        // TODO: Adapter path should have hci number, e.g. /org/chromium/bluetooth/adapter/hci0.
        dbus::nonblock::Proxy::new(
            "org.chromium.bluetooth",
            "/org/chromium/bluetooth/adapter",
            std::time::Duration::from_secs(2),
            conn,
        )
    }

    fn method<A: AppendAll, T: 'static + dbus::arg::Arg + for<'z> dbus::arg::Get<'z>>(
        &self,
        member: &str,
        args: A,
    ) -> T {
        let proxy = self.create_proxy();
        // We know that all APIs return immediately, so we can block on it for simplicity.
        let (ret,): (T,) = futures::executor::block_on(async {
            proxy.method_call("org.chromium.bluetooth.Bluetooth", member, args).await
        })
        .unwrap();

        return ret;
    }

    fn method_noreturn<A: AppendAll>(&self, member: &str, args: A) {
        let proxy = self.create_proxy();
        // We know that all APIs return immediately, so we can block on it for simplicity.
        let _: () = futures::executor::block_on(async {
            proxy.method_call("org.chromium.bluetooth.Bluetooth", member, args).await
        })
        .unwrap();
    }
}

#[allow(dead_code)]
struct IBluetoothCallbackDBus {}

impl RPCProxy for IBluetoothCallbackDBus {
    // Dummy implementations just to satisfy impl RPCProxy requirements.
    fn register_disconnect(&mut self, _f: Box<dyn Fn() + Send>) {}
    fn get_object_id(&self) -> String {
        String::from("")
    }
}

#[generate_dbus_exporter(
    export_bluetooth_callback_dbus_obj,
    "org.chromium.bluetooth.BluetoothCallback"
)]
impl IBluetoothCallback for IBluetoothCallbackDBus {
    #[dbus_method("OnBluetoothStateChanged")]
    fn on_bluetooth_state_changed(&self, prev_state: u32, new_state: u32) {}

    #[dbus_method("OnBluetoothAddressChanged")]
    fn on_bluetooth_address_changed(&self, addr: String) {}

    #[dbus_method("OnDeviceFound")]
    fn on_device_found(&self, remote_device: BluetoothDevice) {}

    #[dbus_method("OnDiscoveringChanged")]
    fn on_discovering_changed(&self, discovering: bool) {}
}

// TODO: These are boilerplate codes, consider creating a macro to generate.
impl IBluetooth for BluetoothDBus {
    fn register_callback(&mut self, callback: Box<dyn IBluetoothCallback + Send>) {
        let path_string = callback.get_object_id();
        let path = dbus::Path::new(path_string.clone()).unwrap();
        export_bluetooth_callback_dbus_obj(
            path_string,
            self.conn.clone(),
            &mut self.cr.lock().unwrap(),
            Arc::new(Mutex::new(callback)),
            Arc::new(Mutex::new(DisconnectWatcher::new())),
        );

        self.method_noreturn("RegisterCallback", (path,))
    }

    fn enable(&mut self) -> bool {
        // Not implemented by server
        true
    }

    fn disable(&mut self) -> bool {
        // Not implemented by server
        true
    }

    fn get_address(&self) -> String {
        self.method("GetAddress", ())
    }

    fn start_discovery(&self) -> bool {
        self.method("StartDiscovery", ())
    }

    fn cancel_discovery(&self) -> bool {
        self.method("CancelDiscovery", ())
    }

    fn create_bond(&self, device: BluetoothDevice, transport: BluetoothTransport) -> bool {
        self.method(
            "CreateBond",
            (
                BluetoothDevice::to_dbus(device).unwrap(),
                BluetoothTransport::to_dbus(transport).unwrap(),
            ),
        )
    }
}
