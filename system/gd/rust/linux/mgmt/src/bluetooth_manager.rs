use log::{error, info, warn};

use std::collections::HashMap;
use std::process::Command;

use crate::config_util;
use crate::iface_bluetooth_manager::{
    AdapterWithEnabled, IBluetoothManager, IBluetoothManagerCallback,
};
use crate::state_machine::{state_to_enabled, AdapterState, Message, StateMachineProxy};

const BLUEZ_INIT_TARGET: &str = "bluetoothd";

/// Implementation of IBluetoothManager.
pub struct BluetoothManager {
    proxy: StateMachineProxy,
    callbacks: HashMap<u32, Box<dyn IBluetoothManagerCallback + Send>>,
}

impl BluetoothManager {
    pub fn new(proxy: StateMachineProxy) -> BluetoothManager {
        BluetoothManager { proxy, callbacks: HashMap::new() }
    }

    fn is_adapter_enabled(&self, hci_device: i32) -> bool {
        state_to_enabled(self.proxy.get_process_state(hci_device))
    }

    fn is_adapter_present(&self, hci_device: i32) -> bool {
        self.proxy.get_state(hci_device, move |a| Some(a.present)).unwrap_or(false)
    }

    pub(crate) fn callback_hci_device_change(&mut self, hci_device: i32, present: bool) {
        for (_, callback) in &self.callbacks {
            callback.on_hci_device_changed(hci_device, present);
        }
    }

    pub(crate) fn callback_hci_enabled_change(&mut self, hci_device: i32, enabled: bool) {
        if enabled {
            info!("Started {}", hci_device);
        } else {
            info!("Stopped {}", hci_device);
        }

        for (_, callback) in &self.callbacks {
            callback.on_hci_enabled_changed(hci_device, enabled);
        }
    }

    pub(crate) fn callback_disconnected(&mut self, id: u32) {
        self.callbacks.remove(&id);
    }
}

impl IBluetoothManager for BluetoothManager {
    fn start(&mut self, hci_interface: i32) {
        info!("Starting {}", hci_interface);

        if !config_util::modify_hci_n_enabled(hci_interface, true) {
            error!("Config is not successfully modified");
        }

        // Store that this adapter is meant to be started in state machine.
        self.proxy.modify_state(hci_interface, move |a: &mut AdapterState| a.config_enabled = true);

        // Ignore the request if adapter is already enabled or not present.
        if self.is_adapter_enabled(hci_interface) || !self.is_adapter_present(hci_interface) {
            return;
        }

        self.proxy.start_bluetooth(hci_interface);
    }

    fn stop(&mut self, hci_interface: i32) {
        info!("Stopping {}", hci_interface);
        if !config_util::modify_hci_n_enabled(hci_interface, false) {
            error!("Config is not successfully modified");
        }

        // Store that this adapter is meant to be stopped in state machine.
        self.proxy
            .modify_state(hci_interface, move |a: &mut AdapterState| a.config_enabled = false);

        // Ignore the request if adapter is already disabled.
        if !self.is_adapter_enabled(hci_interface) {
            return;
        }

        self.proxy.stop_bluetooth(hci_interface);
    }

    fn get_adapter_enabled(&mut self, hci_interface: i32) -> bool {
        self.is_adapter_enabled(hci_interface)
    }

    fn register_callback(&mut self, mut callback: Box<dyn IBluetoothManagerCallback + Send>) {
        let tx = self.proxy.get_tx();

        let id = callback.register_disconnect(Box::new(move |cb_id| {
            let tx = tx.clone();
            tokio::spawn(async move {
                let _result = tx.send(Message::CallbackDisconnected(cb_id)).await;
            });
        }));

        self.callbacks.insert(id, callback);
    }

    fn get_floss_enabled(&mut self) -> bool {
        self.proxy.get_floss_enabled()
    }

    fn set_floss_enabled(&mut self, enabled: bool) {
        let prev = self.proxy.set_floss_enabled(enabled);
        config_util::write_floss_enabled(enabled);

        if prev != enabled && enabled {
            if let Err(e) = Command::new("initctl").args(&["stop", BLUEZ_INIT_TARGET]).output() {
                warn!("Failed to stop bluetoothd: {}", e);
            }
            for hci in config_util::list_hci_devices() {
                if config_util::is_hci_n_enabled(hci) {
                    let _ = self.proxy.start_bluetooth(hci);
                }
            }
        } else if prev != enabled {
            for hci in config_util::list_hci_devices() {
                if config_util::is_hci_n_enabled(hci) {
                    let _ = self.proxy.stop_bluetooth(hci);
                }
            }
            if let Err(e) = Command::new("initctl").args(&["start", BLUEZ_INIT_TARGET]).output() {
                warn!("Failed to start bluetoothd: {}", e);
            }
        }
    }

    fn get_available_adapters(&mut self) -> Vec<AdapterWithEnabled> {
        self.proxy
            .get_valid_adapters()
            .iter()
            .map(|a| AdapterWithEnabled {
                hci_interface: a.hci,
                enabled: state_to_enabled(a.state),
            })
            .collect::<Vec<AdapterWithEnabled>>()
    }
}
