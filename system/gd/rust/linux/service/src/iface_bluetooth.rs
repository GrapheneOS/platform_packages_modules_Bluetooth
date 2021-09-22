extern crate bt_shim;

use bt_topshim::btif::BtSspVariant;

use btstack::bluetooth::{BluetoothDevice, BluetoothTransport, IBluetooth, IBluetoothCallback};
use btstack::RPCProxy;

use dbus::arg::RefArg;

use dbus::nonblock::SyncConnection;
use dbus::strings::Path;

use dbus_macros::{dbus_method, dbus_propmap, dbus_proxy_obj, generate_dbus_exporter};

use dbus_projection::impl_dbus_arg_enum;
use dbus_projection::DisconnectWatcher;

use num_traits::cast::{FromPrimitive, ToPrimitive};

use std::sync::Arc;

use crate::dbus_arg::{DBusArg, DBusArgError, RefArgToRust};

#[dbus_propmap(BluetoothDevice)]
pub struct BluetoothDeviceDBus {
    address: String,
    name: String,
}

#[allow(dead_code)]
struct BluetoothCallbackDBus {}

#[dbus_proxy_obj(BluetoothCallback, "org.chromium.bluetooth.BluetoothCallback")]
impl IBluetoothCallback for BluetoothCallbackDBus {
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
    #[dbus_method("OnBondStateChanged")]
    fn on_bond_state_changed(&self, status: u32, address: String, state: u32) {}
}

impl_dbus_arg_enum!(BluetoothTransport);
impl_dbus_arg_enum!(BtSspVariant);

#[allow(dead_code)]
struct IBluetoothDBus {}

#[generate_dbus_exporter(export_bluetooth_dbus_obj, "org.chromium.bluetooth.Bluetooth")]
impl IBluetooth for IBluetoothDBus {
    #[dbus_method("RegisterCallback")]
    fn register_callback(&mut self, callback: Box<dyn IBluetoothCallback + Send>) {}

    // Not exposed over D-Bus. The stack is automatically enabled when the daemon starts.
    fn enable(&mut self) -> bool {
        false
    }

    // Not exposed over D-Bus. The stack is automatically disabled when the daemon exits.
    // TODO(b/189495858): Handle shutdown properly when SIGTERM is received.
    fn disable(&mut self) -> bool {
        false
    }

    #[dbus_method("GetAddress")]
    fn get_address(&self) -> String {
        String::from("")
    }

    #[dbus_method("StartDiscovery")]
    fn start_discovery(&self) -> bool {
        true
    }

    #[dbus_method("CancelDiscovery")]
    fn cancel_discovery(&self) -> bool {
        true
    }

    #[dbus_method("CreateBond")]
    fn create_bond(&self, _device: BluetoothDevice, _transport: BluetoothTransport) -> bool {
        true
    }

    #[dbus_method("CancelBondProcess")]
    fn cancel_bond_process(&self, _device: BluetoothDevice) -> bool {
        true
    }

    #[dbus_method("RemoveBond")]
    fn remove_bond(&self, _device: BluetoothDevice) -> bool {
        true
    }

    #[dbus_method("GetBondedDevices")]
    fn get_bonded_devices(&self) -> Vec<BluetoothDevice> {
        vec![]
    }

    #[dbus_method("GetBondState")]
    fn get_bond_state(&self, _device: BluetoothDevice) -> u32 {
        0
    }
}
