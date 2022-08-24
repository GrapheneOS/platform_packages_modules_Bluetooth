use btstack::bluetooth_admin::{IBluetoothAdmin, PolicyEffect};

use dbus::arg::RefArg;
use dbus_macros::{dbus_method, dbus_propmap, generate_dbus_exporter};

use dbus_projection::dbus_generated;

use crate::dbus_arg::{DBusArg, DBusArgError, RefArgToRust};

use bt_topshim::btif::Uuid128Bit;

use btstack::bluetooth::BluetoothDevice;

struct IBluetoothAdminDBus {}

#[dbus_propmap(PolicyEffect)]
pub struct PolicyEffectDBus {
    pub service_blocked: Vec<Uuid128Bit>,
}

#[generate_dbus_exporter(export_bluetooth_admin_dbus_intf, "org.chromium.bluetooth.BluetoothAdmin")]
impl IBluetoothAdmin for IBluetoothAdminDBus {
    #[dbus_method("IsServiceAllowed")]
    fn is_service_allowed(&self, uuid: Uuid128Bit) -> bool {
        dbus_generated!()
    }

    #[dbus_method("SetAllowedServices")]
    fn set_allowed_services(&mut self, services: Vec<Uuid128Bit>) -> bool {
        dbus_generated!()
    }

    #[dbus_method("GetAllowedServices")]
    fn get_allowed_services(&self) -> Vec<Uuid128Bit> {
        dbus_generated!()
    }

    #[dbus_method("GetDevicePolicyEffect")]
    fn get_device_policy_effect(&self, device: BluetoothDevice) -> Option<PolicyEffect> {
        dbus_generated!()
    }
}
