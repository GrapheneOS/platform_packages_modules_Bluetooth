use std::collections::HashMap;

use bt_topshim::btif::Uuid;
use bt_topshim::profiles::gatt::LePhy;
use btstack::bluetooth_adv::{AdvertiseData, AdvertiserId, AdvertisingSetParameters};

/// Avertisement parameter and data for a BLE advertising set.
#[derive(Debug, Clone)]
pub(crate) struct AdvSet {
    /// ID for the advertising set if it's being started successfully, None otherwise.
    pub(crate) adv_id: Option<AdvertiserId>,

    /// Advertising parameters.
    pub(crate) params: AdvertisingSetParameters,

    /// Advertising data.
    pub(crate) data: AdvertiseData,
}

impl AdvSet {
    pub(crate) fn new() -> Self {
        let params = AdvertisingSetParameters {
            connectable: false,
            scannable: false,
            is_legacy: true,
            is_anonymous: false,
            include_tx_power: true,
            primary_phy: LePhy::Phy1m,
            secondary_phy: LePhy::Phy1m,
            interval: 100,
            tx_power_level: 0x7f, // no preference
            own_address_type: 1,  // random
        };

        let data = AdvertiseData {
            service_uuids: vec![Uuid::from([
                0x00, 0x00, 0xfe, 0xf3, 0x00, 0x00, 0x10, 0x00, 0x80, 0x00, 0x00, 0x80, 0x5f, 0x9b,
                0x34, 0xfb,
            ])],
            solicit_uuids: Vec::new(),
            transport_discovery_data: Vec::new(),
            manufacturer_data: HashMap::from([(0, vec![0, 1, 2])]),
            service_data: HashMap::from([(
                "0000fef3-0000-1000-8000-00805f9b34fb".to_string(),
                vec![0x0a, 0x0b],
            )]),
            include_tx_power_level: true,
            include_device_name: true,
        };

        AdvSet { adv_id: None, params, data }
    }
}
