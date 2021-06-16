use btstack::bluetooth_media::{IBluetoothMedia, IBluetoothMediaCallback};
use btstack::RPCProxy;

use dbus::nonblock::SyncConnection;
use dbus::strings::Path;

use dbus_macros::{dbus_method, dbus_proxy_obj, generate_dbus_exporter};

use dbus_projection::DisconnectWatcher;

use crate::dbus_arg::DBusArg;

#[allow(dead_code)]
struct BluetoothMediaCallbackDBus {}

#[dbus_proxy_obj(BluetoothMediaCallback, "org.chromium.bluetooth.BluetoothMediaCallback")]
impl IBluetoothMediaCallback for BluetoothMediaCallbackDBus {
    #[dbus_method("OnBluetoothAudioDeviceAdded")]
    fn on_bluetooth_audio_device_added(&self, addr: String) {}

    #[dbus_method("OnBluetoothAudioDeviceRemoved")]
    fn on_bluetooth_audio_device_removed(&self, addr: String) {}
}

#[allow(dead_code)]
struct IBluetoothMediaDBus {}

#[generate_dbus_exporter(export_bluetooth_media_dbus_obj, "org.chromium.bluetooth.BluetoothMedia")]
impl IBluetoothMedia for IBluetoothMediaDBus {
    #[dbus_method("RegisterCallback")]
    fn register_callback(&mut self, callback: Box<dyn IBluetoothMediaCallback + Send>) -> bool {
        true
    }

    #[dbus_method("Initialize")]
    fn initialize(&mut self) -> bool {
        true
    }
}
