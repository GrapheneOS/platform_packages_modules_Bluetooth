use btstack::battery_manager::Battery;
use btstack::battery_provider_manager::{
    BatteryProvider, IBatteryProviderCallback, IBatteryProviderManager,
};
use btstack::RPCProxy;
use dbus::arg::RefArg;
use dbus::strings::Path;
use dbus_macros::{dbus_method, dbus_propmap, dbus_proxy_obj, generate_dbus_exporter};
use dbus_projection::{dbus_generated, DisconnectWatcher};

use crate::dbus_arg::{DBusArg, DBusArgError, RefArgToRust};

#[dbus_propmap(BatteryProvider)]
pub struct BatteryProviderDBus {
    source_info: String,
    remote_address: String,
}

struct IBatteryProviderCallbackDBus {}

#[dbus_proxy_obj(BatteryProviderCallback, "org.chromium.bluetooth.BatteryProviderCallback")]
impl IBatteryProviderCallback for IBatteryProviderCallbackDBus {
    #[dbus_method("RefreshBatteryInfo")]
    fn refresh_battery_info(&self) {
        dbus_generated!()
    }
}

struct IBatteryProviderManagerDBus {}

#[generate_dbus_exporter(
    export_battery_provider_manager_dbus_intf,
    "org.chromium.bluetooth.BatteryProviderManager"
)]
impl IBatteryProviderManager for IBatteryProviderManagerDBus {
    #[dbus_method("RegisterBatteryProvider")]
    fn register_battery_provider(
        &mut self,
        battery_provider: BatteryProvider,
        battery_provider_callback: Box<dyn IBatteryProviderCallback + Send>,
    ) -> i32 {
        dbus_generated!()
    }

    #[dbus_method("UnregisterBatteryProvider")]
    fn unregister_battery_provider(&mut self, battery_id: i32) {
        dbus_generated!()
    }

    #[dbus_method("SetBatteryPercentage")]
    fn set_battery_percentage(&mut self, battery_id: i32, battery: Battery) {
        dbus_generated!()
    }
}
