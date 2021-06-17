use log::error;

use manager_service::iface_bluetooth_manager::{IBluetoothManager, IBluetoothManagerCallback};

use std::process::Command;
use std::sync::atomic::Ordering;

use crate::{config_util, state_machine, ManagerContext};

const BLUEZ_INIT_TARGET: &str = "bluetoothd";

/// Implementation of IBluetoothManager.
pub struct BluetoothManager {
    manager_context: ManagerContext,
    callbacks: Vec<Box<dyn IBluetoothManagerCallback + Send>>,
}

impl BluetoothManager {
    pub(crate) fn new(manager_context: ManagerContext) -> BluetoothManager {
        BluetoothManager { manager_context, callbacks: vec![] }
    }

    pub(crate) fn callback_hci_device_change(&self, hci_device: i32, present: bool) {
        for callback in &self.callbacks {
            callback.on_hci_device_changed(hci_device, present);
        }
    }
}

impl IBluetoothManager for BluetoothManager {
    fn start(&mut self, hci_interface: i32) {
        if !config_util::modify_hci_n_enabled(hci_interface, true) {
            error!("Config is not successfully modified");
        }
        self.manager_context.proxy.start_bluetooth(hci_interface);
    }

    fn stop(&mut self, hci_interface: i32) {
        if !config_util::modify_hci_n_enabled(hci_interface, false) {
            error!("Config is not successfully modified");
        }
        self.manager_context.proxy.stop_bluetooth(hci_interface);
    }

    fn get_state(&mut self) -> i32 {
        let proxy = self.manager_context.proxy.clone();
        let state = proxy.get_state();
        let result = state_machine::state_to_i32(state);
        result
    }

    fn register_callback(&mut self, callback: Box<dyn IBluetoothManagerCallback + Send>) {
        // TODO: Handle callback disconnects.
        self.callbacks.push(callback);
    }

    fn get_floss_enabled(&mut self) -> bool {
        let enabled = self.manager_context.floss_enabled.load(Ordering::Relaxed);
        enabled
    }

    fn set_floss_enabled(&mut self, enabled: bool) {
        let prev = self.manager_context.floss_enabled.swap(enabled, Ordering::Relaxed);
        config_util::write_floss_enabled(enabled);
        if prev != enabled && enabled {
            Command::new("initctl")
                .args(&["stop", BLUEZ_INIT_TARGET])
                .output()
                .expect("failed to stop bluetoothd");
            // TODO: Implement multi-hci case
            let default_device = config_util::list_hci_devices()[0];
            if config_util::is_hci_n_enabled(default_device) {
                let _ = self.manager_context.proxy.start_bluetooth(default_device);
            }
        } else if prev != enabled {
            // TODO: Implement multi-hci case
            let default_device = config_util::list_hci_devices()[0];
            self.manager_context.proxy.stop_bluetooth(default_device);
            Command::new("initctl")
                .args(&["start", BLUEZ_INIT_TARGET])
                .output()
                .expect("failed to start bluetoothd");
        }
    }

    fn list_hci_devices(&mut self) -> Vec<i32> {
        let devices = config_util::list_hci_devices();
        devices
    }
}
