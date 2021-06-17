use crate::RPCProxy;

/// Bluetooth stack management API.
pub trait IBluetoothManager {
    /// Starts the Bluetooth stack.
    fn start(&mut self, hci_interface: i32);

    /// Stops the Bluetooth stack.
    fn stop(&mut self, hci_interface: i32);

    /// Returns the state of Bluetooth manager.
    /// TODO: Should return an enum.
    fn get_state(&mut self) -> i32;

    /// Registers a callback to the Bluetooth manager state.
    fn register_callback(&mut self, callback: Box<dyn IBluetoothManagerCallback + Send>);

    /// Returns whether Floss is enabled.
    fn get_floss_enabled(&mut self) -> bool;

    /// Enables/disables Floss.
    fn set_floss_enabled(&mut self, enabled: bool);

    /// Returns the list of available HCI devices.
    fn list_hci_devices(&mut self) -> Vec<i32>;
}

/// Interface of Bluetooth Manager callbacks.
pub trait IBluetoothManagerCallback: RPCProxy {
    fn on_hci_device_changed(&self, hci_interface: i32, present: bool);
    // TODO: Add on_state_changed when this is implemented in state machine.
}
