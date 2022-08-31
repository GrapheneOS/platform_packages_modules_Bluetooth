use btstack::battery_manager::{Battery, IBatteryManager, IBatteryManagerCallback};
use btstack::RPCProxy;
use dbus::arg::RefArg;
use dbus::strings::Path;
use dbus_macros::{dbus_method, dbus_propmap, dbus_proxy_obj, generate_dbus_exporter};
use dbus_projection::{dbus_generated, DisconnectWatcher};

use crate::dbus_arg::{DBusArg, DBusArgError, RefArgToRust};

#[dbus_propmap(Battery)]
pub struct BatteryDBus {
    percentage: i32,
    source_info: String,
    variant: String,
}

struct IBatteryManagerCallbackDBus {}

#[dbus_proxy_obj(BatteryManagerCallback, "org.chromium.bluetooth.BatteryManagerCallback")]
impl IBatteryManagerCallback for IBatteryManagerCallbackDBus {
    #[dbus_method("OnBatteryInfoUpdated")]
    fn on_battery_info_updated(&self, remote_address: String, battery: Battery) {
        dbus_generated!()
    }
}

struct IBatteryManagerDBus {}

#[generate_dbus_exporter(export_battery_manager_dbus_intf, "org.chromium.bluetooth.BatteryManager")]
impl IBatteryManager for IBatteryManagerDBus {
    #[dbus_method("GetBatteryInformation")]
    fn get_battery_information(&self, remote_address: String) -> Battery {
        dbus_generated!()
    }

    #[dbus_method("RegisterBatteryCallback")]
    fn register_battery_callback(
        &mut self,
        remote_address: String,
        battery_manager_callback: Box<dyn IBatteryManagerCallback + Send>,
    ) -> i32 {
        dbus_generated!()
    }

    #[dbus_method("UnregisterBatteryCallback")]
    fn unregister_battery_callback(&mut self, callback_id: i32) {
        dbus_generated!()
    }
}
