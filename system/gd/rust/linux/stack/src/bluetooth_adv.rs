//! BLE Advertising types and utilities

use bt_topshim::profiles::gatt::{Gatt, GattStatus, LePhy};

use log::warn;
use num_traits::clamp;
use std::collections::HashMap;
use std::sync::atomic::{AtomicIsize, Ordering};
use tokio::sync::mpsc::Sender;

use crate::callbacks::Callbacks;
use crate::uuid::parse_uuid_string;
use crate::{Message, RPCProxy};

pub type AdvertiserId = i32;
pub type CallbackId = u32;
pub type RegId = i32;

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
    pub primary_phy: LePhy,
    /// Secondary advertising phy. Valid values are: 1 (1M), 2 (2M), 3 (Coded).
    pub secondary_phy: LePhy,
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
        status: GattStatus,
    );

    /// Callback triggered in response to `get_own_address` indicating result of the operation.
    fn on_own_address_read(&self, advertiser_id: i32, address_type: i32, address: String);

    /// Callback triggered in response to `stop_advertising_set` indicating the advertising set
    /// is stopped.
    fn on_advertising_set_stopped(&self, advertiser_id: i32);

    /// Callback triggered in response to `enable_advertising_set` indicating result of
    /// the operation.
    fn on_advertising_enabled(&self, advertiser_id: i32, enable: bool, status: GattStatus);

    /// Callback triggered in response to `set_advertising_data` indicating result of the operation.
    fn on_advertising_data_set(&self, advertiser_id: i32, status: GattStatus);

    /// Callback triggered in response to `set_scan_response_data` indicating result of
    /// the operation.
    fn on_scan_response_data_set(&self, advertiser_id: i32, status: GattStatus);

    /// Callback triggered in response to `set_advertising_parameters` indicating result of
    /// the operation.
    fn on_advertising_parameters_updated(
        &self,
        advertiser_id: i32,
        tx_power: i32,
        status: GattStatus,
    );

    /// Callback triggered in response to `set_periodic_advertising_parameters` indicating result of
    /// the operation.
    fn on_periodic_advertising_parameters_updated(&self, advertiser_id: i32, status: GattStatus);

    /// Callback triggered in response to `set_periodic_advertising_data` indicating result of
    /// the operation.
    fn on_periodic_advertising_data_set(&self, advertiser_id: i32, status: GattStatus);

    /// Callback triggered in response to `set_periodic_advertising_enable` indicating result of
    /// the operation.
    fn on_periodic_advertising_enabled(&self, advertiser_id: i32, enable: bool, status: GattStatus);
}

// Advertising interval range.
const INTERVAL_MAX: i32 = 0xff_ffff; // 10485.759375 sec
const INTERVAL_MIN: i32 = 160; // 100 ms
const INTERVAL_DELTA: i32 = 50; // 31.25 ms gap between min and max

// Periodic advertising interval range.
const PERIODIC_INTERVAL_MAX: i32 = 65519; // 81.89875 sec
const PERIODIC_INTERVAL_MIN: i32 = 80; // 100 ms
const PERIODIC_INTERVAL_DELTA: i32 = 16; // 20 ms gap between min and max

// Device name length.
const DEVICE_NAME_MAX: usize = 26;

// Advertising data types.
const COMPLETE_LIST_128_BIT_SERVICE_UUIDS: u8 = 0x07;
const SHORTENED_LOCAL_NAME: u8 = 0x08;
const COMPLETE_LOCAL_NAME: u8 = 0x09;
const TX_POWER_LEVEL: u8 = 0x0a;
const LIST_128_BIT_SERVICE_SOLICITATION_UUIDS: u8 = 0x15;
const SERVICE_DATA_128_BIT_UUID: u8 = 0x21;
const TRANSPORT_DISCOVERY_DATA: u8 = 0x26;
const MANUFACTURER_SPECIFIC_DATA: u8 = 0xff;

// Invalid advertising set id.
const INVALID_ADV_ID: i32 = 0xff;

impl Into<bt_topshim::profiles::gatt::AdvertiseParameters> for AdvertisingSetParameters {
    fn into(self) -> bt_topshim::profiles::gatt::AdvertiseParameters {
        let mut props: u16 = 0;
        if self.connectable {
            props |= 0x01;
        }
        if self.scannable {
            props |= 0x02;
        }
        if self.is_legacy {
            props |= 0x10;
        }
        if self.is_anonymous {
            props |= 0x20;
        }
        if self.include_tx_power {
            props |= 0x40;
        }

        let interval = clamp(self.interval, INTERVAL_MIN, INTERVAL_MAX - INTERVAL_DELTA);

        bt_topshim::profiles::gatt::AdvertiseParameters {
            advertising_event_properties: props,
            min_interval: interval as u32,
            max_interval: (interval + INTERVAL_DELTA) as u32,
            channel_map: 0x07 as u8, // all channels
            tx_power: self.tx_power_level as i8,
            primary_advertising_phy: self.primary_phy.into(),
            secondary_advertising_phy: self.secondary_phy.into(),
            scan_request_notification_enable: 0 as u8, // false
            own_address_type: self.own_address_type as i8,
        }
    }
}

impl AdvertiseData {
    fn append_adv_data(dest: &mut Vec<u8>, ad_type: u8, ad_payload: &[u8]) {
        let len = clamp(ad_payload.len(), 0, 254);
        dest.push((len + 1) as u8);
        dest.push(ad_type);
        dest.extend(&ad_payload[..len]);
    }

    /// Creates raw data from the AdvertiseData.
    pub fn make_with(&self, device_name: &String) -> Vec<u8> {
        let mut bytes = Vec::<u8>::new();

        if device_name.len() > 0 && self.include_device_name {
            let mut name: Vec<u8> = device_name.as_bytes().to_vec();
            let mut ad_type = COMPLETE_LOCAL_NAME;
            if name.len() > DEVICE_NAME_MAX {
                ad_type = SHORTENED_LOCAL_NAME;
                name.resize(DEVICE_NAME_MAX, 0);
            }
            name.push(0);
            AdvertiseData::append_adv_data(&mut bytes, ad_type, &name);
        }

        let mut manufacturers: Vec<&i32> = self.manufacturer_data.keys().collect();
        manufacturers.sort();
        for m in manufacturers {
            let len = 2 + self.manufacturer_data[m].len();
            let mut concated = Vec::<u8>::with_capacity(len);
            concated.push((m & 0xff) as u8);
            concated.push((m >> 8 & 0xff) as u8);
            concated.extend(&self.manufacturer_data[m]);
            AdvertiseData::append_adv_data(&mut bytes, MANUFACTURER_SPECIFIC_DATA, &concated);
        }

        if self.include_tx_power_level {
            // Lower layers will fill tx power level.
            AdvertiseData::append_adv_data(&mut bytes, TX_POWER_LEVEL, &[0]);
        }

        let mut uu128_services = Vec::<u8>::new();
        for uuid_str in &self.service_uuids {
            if let Some(uuid) = parse_uuid_string(uuid_str) {
                match uuid.uu.len() {
                    16 => uu128_services.extend(uuid.uu),
                    _ => (),
                };
            }
        }
        if uu128_services.len() > 0 {
            AdvertiseData::append_adv_data(
                &mut bytes,
                COMPLETE_LIST_128_BIT_SERVICE_UUIDS,
                &uu128_services,
            );
        }

        let uuids: Vec<&String> = self.service_data.keys().collect();
        for uuid_str in uuids {
            if let Some(uuid) = parse_uuid_string(uuid_str) {
                let uu_len = uuid.uu.len();
                let len = uu_len + self.service_data[uuid_str].len();
                let mut concated = Vec::<u8>::with_capacity(len);
                concated.extend(uuid.uu);
                concated.extend(&self.service_data[uuid_str]);

                match uu_len {
                    16 => AdvertiseData::append_adv_data(
                        &mut bytes,
                        SERVICE_DATA_128_BIT_UUID,
                        &concated,
                    ),
                    _ => (),
                };
            }
        }

        let mut uu128_solicits = Vec::<u8>::new();
        for uuid_str in &self.solicit_uuids {
            if let Some(uuid) = parse_uuid_string(uuid_str) {
                match uuid.uu.len() {
                    16 => uu128_solicits.extend(uuid.uu),
                    _ => (),
                };
            }
        }
        if uu128_solicits.len() > 0 {
            AdvertiseData::append_adv_data(
                &mut bytes,
                LIST_128_BIT_SERVICE_SOLICITATION_UUIDS,
                &uu128_solicits,
            );
        }

        for tdd in &self.transport_discovery_data {
            if tdd.len() > 0 {
                AdvertiseData::append_adv_data(&mut bytes, TRANSPORT_DISCOVERY_DATA, &tdd);
            }
        }

        bytes
    }
}

impl Into<bt_topshim::profiles::gatt::PeriodicAdvertisingParameters>
    for PeriodicAdvertisingParameters
{
    fn into(self) -> bt_topshim::profiles::gatt::PeriodicAdvertisingParameters {
        let mut p = bt_topshim::profiles::gatt::PeriodicAdvertisingParameters::default();

        let interval = clamp(
            self.interval,
            PERIODIC_INTERVAL_MIN,
            PERIODIC_INTERVAL_MAX - PERIODIC_INTERVAL_DELTA,
        );

        p.enable = 1;
        p.min_interval = interval as u16;
        p.max_interval = p.min_interval + (PERIODIC_INTERVAL_DELTA as u16);
        if self.include_tx_power {
            p.periodic_advertising_properties |= 0x40;
        }

        p
    }
}

/// Monotonically increasing counter for reg_id.
static REG_ID_COUNTER: AtomicIsize = AtomicIsize::new(0);

// Keeps information of an advertising set.
#[derive(Debug, PartialEq, Copy, Clone)]
pub(crate) struct AdvertisingSetInfo {
    /// Identifies the advertising set when it's started successfully.
    pub(crate) advertiser_id: Option<AdvertiserId>,

    /// Identifies callback associated.
    callback_id: CallbackId,

    /// Identifies the advertising set when it's registered.
    reg_id: RegId,
}

impl AdvertisingSetInfo {
    pub(crate) fn new(callback_id: CallbackId) -> Self {
        AdvertisingSetInfo {
            advertiser_id: None,
            callback_id,
            reg_id: REG_ID_COUNTER.fetch_add(1, Ordering::SeqCst) as RegId,
        }
    }

    /// Get advertising set registration ID.
    pub(crate) fn reg_id(&self) -> RegId {
        self.reg_id
    }

    /// Get associated callback ID.
    pub(crate) fn callback_id(&self) -> CallbackId {
        self.callback_id
    }

    /// Get adv_id, which is required for advertising |BleAdvertiserInterface|.
    pub(crate) fn adv_id(&self) -> u8 {
        // As advertiser_id was from topshim originally, type casting is safe.
        self.advertiser_id.unwrap_or(INVALID_ADV_ID) as u8
    }
}

// Manages advertising sets and the callbacks.
pub(crate) struct Advertisers {
    callbacks: Callbacks<dyn IAdvertisingSetCallback + Send>,
    sets: HashMap<RegId, AdvertisingSetInfo>,
}

impl Advertisers {
    pub(crate) fn new(tx: Sender<Message>) -> Self {
        Advertisers {
            callbacks: Callbacks::new(tx, Message::AdvertiserCallbackDisconnected),
            sets: HashMap::new(),
        }
    }

    /// Adds an advertising set.
    pub(crate) fn add(&mut self, s: AdvertisingSetInfo) {
        if let Some(old) = self.sets.insert(s.reg_id(), s) {
            warn!("An advertising set with the same reg_id ({}) exists. Drop it!", old.reg_id);
        }
    }

    fn find_reg_id(&self, advertiser_id: AdvertiserId) -> Option<RegId> {
        for (_, s) in &self.sets {
            if s.advertiser_id == Some(advertiser_id) {
                return Some(s.reg_id());
            }
        }
        return None;
    }

    /// Returns a mutable reference to the advertising set with the reg_id specified.
    pub(crate) fn get_mut_by_reg_id(&mut self, reg_id: RegId) -> Option<&mut AdvertisingSetInfo> {
        self.sets.get_mut(&reg_id)
    }

    /// Returns a reference to the advertising set with the reg_id specified.
    pub(crate) fn get_by_reg_id(&self, reg_id: RegId) -> Option<&AdvertisingSetInfo> {
        self.sets.get(&reg_id)
    }

    /// Returns a reference to the advertising set with the advertiser_id specified.
    pub(crate) fn get_by_advertiser_id(
        &self,
        advertiser_id: AdvertiserId,
    ) -> Option<&AdvertisingSetInfo> {
        if let Some(reg_id) = self.find_reg_id(advertiser_id) {
            return self.get_by_reg_id(reg_id);
        }
        None
    }

    /// Removes the advertising set with the reg_id specified.
    ///
    /// Returns the advertising set if found, None otherwise.
    pub(crate) fn remove_by_reg_id(&mut self, reg_id: RegId) -> Option<AdvertisingSetInfo> {
        self.sets.remove(&reg_id)
    }

    /// Removes the advertising set with the specified advertiser_id.
    ///
    /// Returns the advertising set if found, None otherwise.
    pub(crate) fn remove_by_advertiser_id(
        &mut self,
        advertiser_id: AdvertiserId,
    ) -> Option<AdvertisingSetInfo> {
        if let Some(reg_id) = self.find_reg_id(advertiser_id) {
            return self.remove_by_reg_id(reg_id);
        }
        None
    }

    /// Adds an advertiser callback.
    pub(crate) fn add_callback(
        &mut self,
        callback: Box<dyn IAdvertisingSetCallback + Send>,
    ) -> CallbackId {
        self.callbacks.add_callback(callback)
    }

    /// Returns callback of the advertising set.
    pub(crate) fn get_callback(
        &mut self,
        s: &AdvertisingSetInfo,
    ) -> Option<&mut Box<dyn IAdvertisingSetCallback + Send>> {
        self.callbacks.get_by_id(s.callback_id())
    }

    /// Removes an advertiser callback and unregisters all advertising sets associated with that callback.
    pub(crate) fn remove_callback(&mut self, callback_id: CallbackId, gatt: &mut Gatt) -> bool {
        for (_, s) in self
            .sets
            .iter()
            .filter(|(_, s)| s.callback_id() == callback_id && s.advertiser_id.is_some())
        {
            gatt.advertiser.unregister(s.adv_id());
        }
        self.sets.retain(|_, s| s.callback_id() != callback_id);

        self.callbacks.remove_callback(callback_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;
    use std::iter::FromIterator;

    #[test]
    fn test_append_ad_data_clamped() {
        let mut bytes = Vec::<u8>::new();
        let mut ans = Vec::<u8>::new();
        ans.push(255);
        ans.push(102);
        ans.extend(Vec::<u8>::from_iter(0..254));

        let payload = Vec::<u8>::from_iter(0..255);
        AdvertiseData::append_adv_data(&mut bytes, 102, &payload);
        assert_eq!(bytes, ans);
    }

    #[test]
    fn test_append_ad_data_multiple() {
        let mut bytes = Vec::<u8>::new();

        let payload = vec![0 as u8, 1, 2, 3, 4];
        AdvertiseData::append_adv_data(&mut bytes, 100, &payload);
        AdvertiseData::append_adv_data(&mut bytes, 101, &[0]);
        assert_eq!(bytes, vec![6 as u8, 100, 0, 1, 2, 3, 4, 2, 101, 0]);
    }

    #[test]
    fn test_new_advising_set_info() {
        let mut uniq = HashSet::new();
        for callback_id in 0..256 {
            let s = AdvertisingSetInfo::new(callback_id);
            assert_eq!(s.callback_id(), callback_id);
            assert_eq!(uniq.insert(s.reg_id()), true);
        }
    }
}
