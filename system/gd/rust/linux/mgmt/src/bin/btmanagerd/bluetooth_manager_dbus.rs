use dbus::nonblock::SyncConnection;
use dbus::strings::Path;

use dbus_macros::{dbus_method, dbus_proxy_obj, generate_dbus_exporter};

use dbus_projection::DisconnectWatcher;

use manager_service::iface_bluetooth_manager::{IBluetoothManager, IBluetoothManagerCallback};
use manager_service::RPCProxy;

use crate::dbus_arg::DBusArg;

/// D-Bus projection of IBluetoothManager.
struct BluetoothManagerDBus {}

#[generate_dbus_exporter(export_bluetooth_manager_dbus_obj, "org.chromium.bluetooth.Manager")]
impl IBluetoothManager for BluetoothManagerDBus {
    #[dbus_method("Start")]
    fn start(&mut self, _hci_interface: i32) {}

    #[dbus_method("Stop")]
    fn stop(&mut self, _hci_interface: i32) {}

    #[dbus_method("GetState")]
    fn get_state(&mut self) -> i32 {
        0
    }

    #[dbus_method("RegisterCallback")]
    fn register_callback(&mut self, _callback: Box<dyn IBluetoothManagerCallback + Send>) {}

    #[dbus_method("GetFlossEnabled")]
    fn get_floss_enabled(&mut self) -> bool {
        false
    }

    #[dbus_method("SetFlossEnabled")]
    fn set_floss_enabled(&mut self, _enabled: bool) {}

    #[dbus_method("ListHciDevices")]
    fn list_hci_devices(&mut self) -> Vec<i32> {
        vec![]
    }
}

/// D-Bus projection of IBluetoothManagerCallback.
struct BluetoothManagerCallbackDBus {}

#[dbus_proxy_obj(BluetoothManagerCallback, "org.chromium.bluetooth.ManagerCallback")]
impl IBluetoothManagerCallback for BluetoothManagerCallbackDBus {
    #[dbus_method("OnHciDeviceChanged")]
    fn on_hci_device_changed(&self, hci_interface: i32, present: bool) {}

    #[dbus_method("OnHciEnabledChanged")]
    fn on_hci_enabled_changed(&self, hci_interface: i32, enabled: bool) {}
}
