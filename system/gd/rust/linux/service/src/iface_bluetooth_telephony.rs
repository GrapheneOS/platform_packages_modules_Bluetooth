use btstack::bluetooth_media::IBluetoothTelephony;

use dbus_macros::{dbus_method, generate_dbus_exporter};

use dbus_projection::dbus_generated;

use crate::dbus_arg::DBusArg;

#[allow(dead_code)]
struct IBluetoothTelephonyDBus {}

#[generate_dbus_exporter(
    export_bluetooth_telephony_dbus_intf,
    "org.chromium.bluetooth.BluetoothTelephony"
)]
impl IBluetoothTelephony for IBluetoothTelephonyDBus {
    #[dbus_method("SetNetworkAvailable")]
    fn set_network_available(&mut self, network_available: bool) {
        dbus_generated!()
    }
    #[dbus_method("SetRoaming")]
    fn set_roaming(&mut self, roaming: bool) {
        dbus_generated!()
    }
    #[dbus_method("SetSignalStrength")]
    fn set_signal_strength(&mut self, signal_strength: i32) -> bool {
        dbus_generated!()
    }
    #[dbus_method("SetBatteryLevel")]
    fn set_battery_level(&mut self, battery_level: i32) -> bool {
        dbus_generated!()
    }
}
