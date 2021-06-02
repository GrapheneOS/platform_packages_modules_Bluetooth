//! D-Bus proxy implementations of the APIs.

use btstack::bluetooth::{BluetoothDevice, BluetoothTransport, IBluetooth, IBluetoothCallback};

use dbus::arg::{AppendAll, RefArg};
use dbus::nonblock::SyncConnection;

use dbus_projection::impl_dbus_arg_enum;

use dbus_macros::dbus_propmap;

use num_traits::{FromPrimitive, ToPrimitive};

use std::sync::Arc;

use crate::dbus_arg::{DBusArg, DBusArgError, RefArgToRust};

impl_dbus_arg_enum!(BluetoothTransport);

#[dbus_propmap(BluetoothDevice)]
pub struct BluetoothDeviceDBus {
    address: String,
}

pub(crate) struct BluetoothDBus {
    conn: Arc<SyncConnection>,
}

impl BluetoothDBus {
    pub(crate) fn new(conn: Arc<SyncConnection>) -> BluetoothDBus {
        BluetoothDBus { conn: conn.clone() }
    }

    fn method<A: AppendAll, T: 'static + dbus::arg::Arg + for<'z> dbus::arg::Get<'z>>(
        &self,
        member: &str,
        args: A,
    ) -> T {
        let conn = self.conn.clone();
        let proxy = dbus::nonblock::Proxy::new(
            "org.chromium.bluetooth",
            "/org/chromium/bluetooth/adapter",
            std::time::Duration::from_secs(2),
            conn,
        );
        // We know that all APIs return immediately, so we can block on it for simplicity.
        let (ret,): (T,) = futures::executor::block_on(async {
            proxy.method_call("org.chromium.bluetooth.Bluetooth", member, args).await
        })
        .unwrap();

        return ret;
    }
}

// TODO: These are boilerplate codes, consider creating a macro to generate.
impl IBluetooth for BluetoothDBus {
    fn register_callback(&mut self, _callback: Box<dyn IBluetoothCallback + Send>) {
        // TODO: Implement callback object export.
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
