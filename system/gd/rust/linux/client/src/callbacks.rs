use crate::ClientContext;
use crate::{console_yellow, print_info};
use bt_topshim::btif::BtSspVariant;
use btstack::bluetooth::{BluetoothDevice, IBluetoothCallback};
use btstack::RPCProxy;
use manager_service::iface_bluetooth_manager::IBluetoothManagerCallback;
use std::sync::{Arc, Mutex};

/// Callback context for manager interface callbacks.
pub(crate) struct BtManagerCallback {
    objpath: String,
    context: Arc<Mutex<ClientContext>>,
}

impl BtManagerCallback {
    pub(crate) fn new(objpath: String, context: Arc<Mutex<ClientContext>>) -> Self {
        Self { objpath, context }
    }
}

impl IBluetoothManagerCallback for BtManagerCallback {
    fn on_hci_device_changed(&self, hci_interface: i32, present: bool) {
        print_info!("hci{} present = {}", hci_interface, present);

        if present {
            self.context.lock().unwrap().adapters.entry(hci_interface).or_insert(false);
        } else {
            self.context.lock().unwrap().adapters.remove(&hci_interface);
        }
    }

    fn on_hci_enabled_changed(&self, hci_interface: i32, enabled: bool) {
        print_info!("hci{} enabled = {}", hci_interface, enabled);

        self.context
            .lock()
            .unwrap()
            .adapters
            .entry(hci_interface)
            .and_modify(|v| *v = enabled)
            .or_insert(enabled);

        // When the default adapter's state is updated, we need to modify a few more things.
        // Only do this if we're not repeating the previous state.
        let prev_enabled = self.context.lock().unwrap().enabled;
        let default_adapter = self.context.lock().unwrap().default_adapter;
        if hci_interface == default_adapter && prev_enabled != enabled {
            self.context.lock().unwrap().enabled = enabled;
            self.context.lock().unwrap().adapter_ready = false;
            if enabled {
                self.context.lock().unwrap().create_adapter_proxy(hci_interface);
            } else {
                self.context.lock().unwrap().adapter_dbus = None;
            }
        }
    }
}

impl manager_service::RPCProxy for BtManagerCallback {
    fn register_disconnect(&mut self, _f: Box<dyn Fn() + Send>) {}

    fn get_object_id(&self) -> String {
        self.objpath.clone()
    }
}

/// Callback container for adapter interface callbacks.
pub(crate) struct BtCallback {
    objpath: String,
    context: Arc<Mutex<ClientContext>>,
}

impl BtCallback {
    pub(crate) fn new(objpath: String, context: Arc<Mutex<ClientContext>>) -> Self {
        Self { objpath, context }
    }
}

impl IBluetoothCallback for BtCallback {
    fn on_address_changed(&self, addr: String) {
        print_info!("Address changed to {}", &addr);
        self.context.lock().unwrap().adapter_address = Some(addr);
    }

    fn on_device_found(&self, remote_device: BluetoothDevice) {
        self.context
            .lock()
            .unwrap()
            .found_devices
            .entry(remote_device.address.clone())
            .or_insert(remote_device.clone());

        print_info!("Found device: {:?}", remote_device);
    }

    fn on_discovering_changed(&self, discovering: bool) {
        self.context.lock().unwrap().discovering_state = discovering;

        if discovering {
            self.context.lock().unwrap().found_devices.clear();
        }
        print_info!("Discovering: {}", discovering);
    }

    fn on_ssp_request(
        &self,
        remote_device: BluetoothDevice,
        _cod: u32,
        variant: BtSspVariant,
        passkey: u32,
    ) {
        if variant == BtSspVariant::PasskeyNotification {
            print_info!(
                "device {}{} would like to pair, enter passkey on remote device: {:06}",
                remote_device.address.to_string(),
                if remote_device.name.len() > 0 {
                    format!(" ({})", remote_device.name)
                } else {
                    String::from("")
                },
                passkey
            );
        }
    }
}

impl RPCProxy for BtCallback {
    fn register_disconnect(&mut self, _f: Box<dyn Fn() + Send>) {}

    fn get_object_id(&self) -> String {
        self.objpath.clone()
    }
}
