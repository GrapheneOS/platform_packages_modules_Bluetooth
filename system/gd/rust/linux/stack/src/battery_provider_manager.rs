use crate::battery_manager::Battery;

#[derive(Debug, Clone)]
pub struct BatteryProvider {
    pub source_info: String,
    pub remote_address: String,
}

/// Callback for BatteryProvider implementers.
pub trait IBatteryProviderCallback {
    /// Requests that the BatteryProvider send updated battery information.
    fn refresh_battery_info(&self);
}

/// Interface for managing BatteryProvider instances.
pub trait IBatteryProviderManager {
    /// Registers a BatteryProvider and generates a unique batttery ID for future calls.
    fn register_battery_provider(
        &mut self,
        battery_provider: BatteryProvider,
        battery_provider_callback: Box<dyn IBatteryProviderCallback + Send>,
    ) -> i32;

    /// Unregisters a BatteryProvider, potentially removes battery information for the remote
    /// device if there are no other providers.
    fn unregister_battery_provider(&mut self, battery_id: i32);

    /// Updates the battery information for the battery associated with battery_id.
    fn set_battery_percentage(&mut self, battery_id: i32, battery: Battery);
}

pub struct BatteryProviderManager {}

impl BatteryProviderManager {
    pub fn new() -> BatteryProviderManager {
        BatteryProviderManager {}
    }
}

impl IBatteryProviderManager for BatteryProviderManager {
    fn register_battery_provider(
        &mut self,
        _battery_provider: BatteryProvider,
        _battery_provider_callback: Box<dyn IBatteryProviderCallback + Send>,
    ) -> i32 {
        todo!()
    }

    fn unregister_battery_provider(&mut self, _battery_id: i32) {
        todo!()
    }

    fn set_battery_percentage(&mut self, _battery_id: i32, _battery: Battery) {
        todo!()
    }
}
