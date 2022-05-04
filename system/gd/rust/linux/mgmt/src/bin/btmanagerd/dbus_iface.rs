//! D-Bus proxy implementations of the APIs.

use btstack::suspend::{ISuspend, ISuspendCallback, SuspendType};
use btstack::RPCProxy;
use dbus::nonblock::SyncConnection;
use dbus_macros::{dbus_method, generate_dbus_exporter, generate_dbus_interface_client};
use dbus_projection::{impl_dbus_arg_enum, ClientDBusProxy};
use num_traits::{FromPrimitive, ToPrimitive};
use std::sync::Arc;

use crate::dbus_arg::{DBusArg, DBusArgError};

impl_dbus_arg_enum!(SuspendType);

pub struct SuspendDBus {
    client_proxy: ClientDBusProxy,
}

impl SuspendDBus {
    pub(crate) fn new(conn: Arc<SyncConnection>, path: dbus::Path<'static>) -> SuspendDBus {
        SuspendDBus {
            client_proxy: ClientDBusProxy::new(
                conn.clone(),
                String::from("org.chromium.bluetooth"),
                path,
                String::from("org.chromium.bluetooth.Suspend"),
            ),
        }
    }
}

#[generate_dbus_interface_client]
impl ISuspend for SuspendDBus {
    #[dbus_method("RegisterCallback")]
    fn register_callback(&mut self, callback: Box<dyn ISuspendCallback + Send>) -> bool {
        dbus_generated!()
    }

    #[dbus_method("UnregisterCallback")]
    fn unregister_callback(&mut self, callback_id: u32) -> bool {
        dbus_generated!()
    }

    #[dbus_method("Suspend")]
    fn suspend(&self, suspend_type: SuspendType) -> u32 {
        dbus_generated!()
    }

    #[dbus_method("Resume")]
    fn resume(&self) -> bool {
        dbus_generated!()
    }
}

#[allow(dead_code)]
struct ISuspendCallbackDBus {}

impl RPCProxy for ISuspendCallbackDBus {
    // Placeholder implementations just to satisfy impl RPCProxy requirements.
    fn register_disconnect(&mut self, _f: Box<dyn Fn(u32) + Send>) -> u32 {
        0
    }
    fn get_object_id(&self) -> String {
        String::from("")
    }
    fn unregister(&mut self, _id: u32) -> bool {
        false
    }
    fn export_for_rpc(self: Box<Self>) {}
}

#[generate_dbus_exporter(
    export_suspend_callback_dbus_obj,
    "org.chromium.bluetooth.SuspendCallback"
)]
impl ISuspendCallback for ISuspendCallbackDBus {
    #[dbus_method("OnCallbackRegistered")]
    fn on_callback_registered(&self, callback_id: u32) {}
    #[dbus_method("OnSuspendReady")]
    fn on_suspend_ready(&self, suspend_id: u32) {}
    #[dbus_method("OnResumed")]
    fn on_resumed(&self, suspend_id: u32) {}
}
