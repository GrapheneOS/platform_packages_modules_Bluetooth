//! D-Bus proxy implementations of the APIs.

use bt_topshim::btif::BtSspVariant;

use btstack::bluetooth::{BluetoothDevice, BluetoothTransport, IBluetooth, IBluetoothCallback};

use dbus::arg::{AppendAll, RefArg};
use dbus::nonblock::SyncConnection;

use dbus_crossroads::Crossroads;

use dbus_projection::{impl_dbus_arg_enum, DisconnectWatcher};

use dbus_macros::{dbus_method, dbus_propmap, generate_dbus_exporter};

use manager_service::iface_bluetooth_manager::{IBluetoothManager, IBluetoothManagerCallback};

use num_traits::{FromPrimitive, ToPrimitive};

use std::sync::{Arc, Mutex};

use crate::dbus_arg::{DBusArg, DBusArgError, RefArgToRust};

impl_dbus_arg_enum!(BluetoothTransport);
impl_dbus_arg_enum!(BtSspVariant);

#[dbus_propmap(BluetoothDevice)]
pub struct BluetoothDeviceDBus {
    address: String,
}

struct ClientDBusProxy {
    conn: Arc<SyncConnection>,
    cr: Arc<Mutex<Crossroads>>,
    bus_name: String,
    objpath: dbus::Path<'static>,
    interface: String,
}

impl ClientDBusProxy {
    fn create_proxy(&self) -> dbus::nonblock::Proxy<Arc<SyncConnection>> {
        let conn = self.conn.clone();
        dbus::nonblock::Proxy::new(
            self.bus_name.clone(),
            self.objpath.clone(),
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
            proxy.method_call(self.interface.clone(), member, args).await
        })
        .unwrap();

        return ret;
    }

    fn method_noreturn<A: AppendAll>(&self, member: &str, args: A) {
        let proxy = self.create_proxy();
        // We know that all APIs return immediately, so we can block on it for simplicity.
        let _: () = futures::executor::block_on(async {
            proxy.method_call(self.interface.clone(), member, args).await
        })
        .unwrap();
    }
}

#[allow(dead_code)]
struct IBluetoothCallbackDBus {}

impl btstack::RPCProxy for IBluetoothCallbackDBus {
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
    #[dbus_method("OnAddressChanged")]
    fn on_address_changed(&self, addr: String) {}

    #[dbus_method("OnDeviceFound")]
    fn on_device_found(&self, remote_device: BluetoothDevice) {}

    #[dbus_method("OnDiscoveringChanged")]
    fn on_discovering_changed(&self, discovering: bool) {}

    #[dbus_method("OnSspRequest")]
    fn on_ssp_request(
        &self,
        remote_device: BluetoothDevice,
        cod: u32,
        variant: BtSspVariant,
        passkey: u32,
    ) {
    }
}

pub(crate) struct BluetoothDBus {
    client_proxy: ClientDBusProxy,
}

impl BluetoothDBus {
    pub(crate) fn new(conn: Arc<SyncConnection>, cr: Arc<Mutex<Crossroads>>) -> BluetoothDBus {
        // TODO: Adapter path should have hci number, e.g. /org/chromium/bluetooth/adapter/hci0.
        BluetoothDBus {
            client_proxy: ClientDBusProxy {
                conn: conn.clone(),
                cr: cr,
                bus_name: String::from("org.chromium.bluetooth"),
                objpath: dbus::Path::new("/org/chromium/bluetooth/adapter").unwrap(),
                interface: String::from("org.chromium.bluetooth.Bluetooth"),
            },
        }
    }
}

// TODO: These are boilerplate codes, consider creating a macro to generate.
impl IBluetooth for BluetoothDBus {
    fn register_callback(&mut self, callback: Box<dyn IBluetoothCallback + Send>) {
        let path_string = callback.get_object_id();
        let path = dbus::Path::new(path_string.clone()).unwrap();
        export_bluetooth_callback_dbus_obj(
            path_string,
            self.client_proxy.conn.clone(),
            &mut self.client_proxy.cr.lock().unwrap(),
            Arc::new(Mutex::new(callback)),
            Arc::new(Mutex::new(DisconnectWatcher::new())),
        );

        self.client_proxy.method_noreturn("RegisterCallback", (path,))
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
        self.client_proxy.method("GetAddress", ())
    }

    fn start_discovery(&self) -> bool {
        self.client_proxy.method("StartDiscovery", ())
    }

    fn cancel_discovery(&self) -> bool {
        self.client_proxy.method("CancelDiscovery", ())
    }

    fn create_bond(&self, device: BluetoothDevice, transport: BluetoothTransport) -> bool {
        self.client_proxy.method(
            "CreateBond",
            (
                BluetoothDevice::to_dbus(device).unwrap(),
                BluetoothTransport::to_dbus(transport).unwrap(),
            ),
        )
    }
}

pub(crate) struct BluetoothManagerDBus {
    client_proxy: ClientDBusProxy,
}

impl BluetoothManagerDBus {
    pub(crate) fn new(
        conn: Arc<SyncConnection>,
        cr: Arc<Mutex<Crossroads>>,
    ) -> BluetoothManagerDBus {
        BluetoothManagerDBus {
            client_proxy: ClientDBusProxy {
                conn: conn.clone(),
                cr: cr,
                bus_name: String::from("org.chromium.bluetooth.Manager"),
                objpath: dbus::Path::new("/org/chromium/bluetooth/Manager").unwrap(),
                interface: String::from("org.chromium.bluetooth.Manager"),
            },
        }
    }
}

// TODO: These are boilerplate codes, consider creating a macro to generate.
impl IBluetoothManager for BluetoothManagerDBus {
    fn start(&mut self, hci_interface: i32) {
        self.client_proxy.method_noreturn("Start", (hci_interface,))
    }

    fn stop(&mut self, hci_interface: i32) {
        self.client_proxy.method_noreturn("Stop", (hci_interface,))
    }

    fn get_state(&mut self) -> i32 {
        self.client_proxy.method("GetState", ())
    }

    fn register_callback(&mut self, callback: Box<dyn IBluetoothManagerCallback + Send>) {
        let path_string = callback.get_object_id();
        let path = dbus::Path::new(path_string.clone()).unwrap();
        export_bluetooth_manager_callback_dbus_obj(
            path_string,
            self.client_proxy.conn.clone(),
            &mut self.client_proxy.cr.lock().unwrap(),
            Arc::new(Mutex::new(callback)),
            Arc::new(Mutex::new(DisconnectWatcher::new())),
        );

        self.client_proxy.method_noreturn("RegisterCallback", (path,))
    }

    fn get_floss_enabled(&mut self) -> bool {
        self.client_proxy.method("GetFlossEnabled", ())
    }

    fn set_floss_enabled(&mut self, enabled: bool) {
        self.client_proxy.method_noreturn("SetFlossEnabled", (enabled,))
    }

    fn list_hci_devices(&mut self) -> Vec<i32> {
        self.client_proxy.method("ListHciDevices", ())
    }
}

#[allow(dead_code)]
struct IBluetoothManagerCallbackDBus {}

impl manager_service::RPCProxy for IBluetoothManagerCallbackDBus {
    // Placeholder implementations just to satisfy impl RPCProxy requirements.
    fn register_disconnect(&mut self, _f: Box<dyn Fn() + Send>) {}
    fn get_object_id(&self) -> String {
        String::from("")
    }
}

#[generate_dbus_exporter(
    export_bluetooth_manager_callback_dbus_obj,
    "org.chromium.bluetooth.ManagerCallback"
)]
impl IBluetoothManagerCallback for IBluetoothManagerCallbackDBus {
    #[dbus_method("OnHciDeviceChanged")]
    fn on_hci_device_changed(&self, hci_interface: i32, present: bool) {}
}
