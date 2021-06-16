use dbus::nonblock::{Proxy, SyncConnection};
use std::sync::Arc;
use std::sync::Mutex;
use std::time::Duration;

#[derive(Clone)]
pub struct DbusCallbackUtil {
    dbus_connection: Arc<SyncConnection>,
    state_change_observers: Arc<Mutex<Vec<String>>>,
    hci_device_change_observer: Arc<Mutex<Vec<String>>>,
}

impl DbusCallbackUtil {
    pub fn new(
        dbus_connection: Arc<SyncConnection>,
        state_change_observers: Arc<Mutex<Vec<String>>>,
        hci_device_change_observer: Arc<Mutex<Vec<String>>>,
    ) -> Self {
        DbusCallbackUtil {
            dbus_connection: dbus_connection,
            state_change_observers: state_change_observers,
            hci_device_change_observer: hci_device_change_observer,
        }
    }

    pub async fn send_hci_device_change_callback(
        &self,
        hci_device: i32,
        present: bool,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let paths = self.hci_device_change_observer.lock().unwrap().clone();
        for path in paths.iter() {
            let proxy = Proxy::new(
                "org.chromium.bluetooth.Manager",
                path,
                Duration::from_secs(2),
                self.dbus_connection.clone(),
            );
            proxy
                .method_call(
                    "org.chromium.bluetooth.Manager",
                    "HciDeviceChangeCallback",
                    (hci_device, present),
                )
                .await?;
        }
        Ok(())
    }

    pub async fn send_adapter_state_change_callback(
        &self,
        hci_device: i32,
        state: i32,
    ) -> Result<(), Box<dyn std::error::Error>> {
        for path in &*self.state_change_observers.lock().unwrap() {
            let proxy = Proxy::new(
                "org.chromium.bluetooth.Manager",
                path,
                Duration::from_secs(2),
                self.dbus_connection.clone(),
            );
            proxy
                .method_call(
                    "org.chromium.bluetooth.Manager",
                    "AdapterStateChangeCallback",
                    (hci_device, state),
                )
                .await?;
        }
        Ok(())
    }
}
