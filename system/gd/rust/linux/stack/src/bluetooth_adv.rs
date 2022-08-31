//! BLE Advertising types and utilities

use std::collections::HashMap;

use crate::RPCProxy;

/// Advertising parameters for each BLE advertising set.
#[derive(Debug, Default)]
pub struct AdvertisingSetParameters {
    /// Whether the advertisement will be connectable.
    pub connectable: bool,
    /// Whether the advertisement will be scannable.
    pub scannable: bool,
    /// Whether the legacy advertisement will be used.
    pub is_legacy: bool,
    /// Whether the advertisement will be anonymous.
    pub is_anonymous: bool,
    /// Whether the TX Power will be included.
    pub include_tx_power: bool,
    /// Primary advertising phy. Valid values are: 1 (1M), 2 (2M), 3 (Coded).
    pub primary_phy: i32,
    /// Secondary advertising phy. Valid values are: 1 (1M), 2 (2M), 3 (Coded).
    pub secondary_phy: i32,
    /// The advertising interval. Bluetooth LE Advertising interval, in 0.625 ms unit.
    /// The valid range is from 160 (100 ms) to 16777215 (10485.759375 sec).
    /// Recommended values are: 160 (100 ms), 400 (250 ms), 1600 (1 sec).
    pub interval: i32,
    /// Transmission power of Bluetooth LE Advertising, in dBm. The valid range is [-127, 1].
    /// Recommended values are: -21, -15, 7, 1.
    pub tx_power_level: i32,
    /// Own address type for advertising to control public or privacy mode.
    /// The valid types are: -1 (default), 0 (public), 1 (random).
    pub own_address_type: i32,
}

/// Represents the data to be advertised and the scan response data for active scans.
#[derive(Debug, Default)]
pub struct AdvertiseData {
    /// A list of service UUIDs within the advertisement that are used to identify
    /// the Bluetooth GATT services.
    pub service_uuids: Vec<String>,
    /// A list of service solicitation UUIDs within the advertisement that we invite to connect.
    pub solicit_uuids: Vec<String>,
    /// A list of transport discovery data.
    pub transport_discovery_data: Vec<Vec<u8>>,
    /// A collection of manufacturer Id and the corresponding manufacturer specific data.
    pub manufacturer_data: HashMap<i32, Vec<u8>>,
    /// A map of 128-bit UUID and its corresponding service data.
    pub service_data: HashMap<String, Vec<u8>>,
    /// Whether TX Power level will be included in the advertising packet.
    pub include_tx_power_level: bool,
    /// Whether the device name will be included in the advertisement packet.
    pub include_device_name: bool,
}

/// Parameters of the periodic advertising packet for BLE advertising set.
#[derive(Debug, Default)]
pub struct PeriodicAdvertisingParameters {
    /// Whether TX Power level will be included.
    pub include_tx_power: bool,
    /// Periodic advertising interval in 1.25 ms unit. Valid values are from 80 (100 ms) to
    /// 65519 (81.89875 sec). Value from range [interval, interval+20ms] will be picked as
    /// the actual value.
    pub interval: i32,
}

/// Interface for advertiser callbacks to clients, passed to
/// `IBluetoothGatt::start_advertising_set`.
pub trait IAdvertisingSetCallback: RPCProxy {
    /// Callback triggered in response to `start_advertising_set` indicating result of
    /// the operation.
    ///
    /// * `reg_id` - Identifies the advertising set registered by `start_advertising_set`.
    /// * `advertiser_id` - ID for the advertising set. It will be used in other advertising methods
    ///     and callbacks.
    /// * `tx_power` - Transmit power that will be used for this advertising set.
    /// * `status` - Status of this operation.
    fn on_advertising_set_started(
        &self,
        reg_id: i32,
        advertiser_id: i32,
        tx_power: i32,
        status: i32,
    );

    /// Callback triggered in response to `get_own_address` indicating result of the operation.
    fn on_own_address_read(&self, advertiser_id: i32, address_type: i32, address: String);

    /// Callback triggered in response to `stop_advertising_set` indicating the advertising set
    /// is stopped.
    fn on_advertising_set_stopped(&self, advertiser_id: i32);

    /// Callback triggered in response to `enable_advertising_set` indicating result of
    /// the operation.
    fn on_advertising_enabled(&self, advertiser_id: i32, enable: bool, status: i32);

    /// Callback triggered in response to `set_advertising_data` indicating result of the operation.
    fn on_advertising_data_set(&self, advertiser_id: i32, status: i32);

    /// Callback triggered in response to `set_scan_response_data` indicating result of
    /// the operation.
    fn on_scan_response_data_set(&self, advertiser_id: i32, status: i32);

    /// Callback triggered in response to `set_advertising_parameters` indicating result of
    /// the operation.
    fn on_advertising_parameters_updated(&self, advertiser_id: i32, tx_power: i32, status: i32);

    /// Callback triggered in response to `set_periodic_advertising_parameters` indicating result of
    /// the operation.
    fn on_periodic_advertising_parameters_updated(&self, advertiser_id: i32, status: i32);

    /// Callback triggered in response to `set_periodic_advertising_data` indicating result of
    /// the operation.
    fn on_periodic_advertising_data_set(&self, advertiser_id: i32, status: i32);

    /// Callback triggered in response to `set_periodic_advertising_enable` indicating result of
    /// the operation.
    fn on_periodic_advertising_enabled(&self, advertiser_id: i32, enable: bool, status: i32);
}
