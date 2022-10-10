/// Bluetooth experimental feature API
pub trait IBluetoothExperimental {
    /// Set LL privacy status
    fn set_ll_privacy(&mut self, enabled: bool);
}
