#[derive(Debug, Clone)]
pub struct Battery {
    pub percentage: i32,
    pub source_info: String,
    pub variant: String,
}

pub struct BatteryManager {}

impl BatteryManager {
    pub fn new() -> BatteryManager {
        BatteryManager {}
    }
}

/// Callback for interacting with the BatteryManager.
pub trait IBatteryManagerCallback {
    /// Invoked whenever battery information associated with the given remote changes.
    fn on_battery_info_updated(&self, remote_address: String, battery: Battery);
}

/// Central point for getting battery information that might be sourced from numerous systems.
pub trait IBatteryManager {
    /// Registers a callback for interfacing with the BatteryManager and returns a unique
    /// callback_id for future calls.
    fn register_battery_callback(
        &mut self,
        remote_address: String,
        battery_manager_callback: Box<dyn IBatteryManagerCallback + Send>,
    ) -> i32;

    /// Unregister a callback.
    fn unregister_battery_callback(&mut self, callback_id: i32);

    /// Returns battery information for the remote, sourced from the highest priority origin.
    fn get_battery_information(&self, remote_address: String) -> Battery;
}

impl IBatteryManager for BatteryManager {
    fn register_battery_callback(
        &mut self,
        _remote_address: String,
        _battery_manager_callback: Box<dyn IBatteryManagerCallback + Send>,
    ) -> i32 {
        todo!()
    }

    fn unregister_battery_callback(&mut self, _callback_id: i32) {
        todo!()
    }

    fn get_battery_information(&self, _remote_address: String) -> Battery {
        todo!()
    }
}
