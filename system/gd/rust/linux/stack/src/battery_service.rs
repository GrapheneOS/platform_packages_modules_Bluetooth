use crate::bluetooth_gatt::{
    BluetoothGatt, BluetoothGattService, IBluetoothGatt, IBluetoothGattCallback,
};
use crate::callbacks::Callbacks;
use crate::uuid;
use crate::uuid::parse_uuid_string;
use crate::Message;
use crate::RPCProxy;
use bt_topshim::btif::BtTransport;
use bt_topshim::profiles::gatt::{GattStatus, LePhy};
use log::debug;
use std::collections::{HashMap, HashSet};
use std::convert::TryInto;
use std::iter;
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc::Sender;

/// The UUID corresponding to the BatteryLevel characteristic defined
/// by the BatteryService specification.
pub const CHARACTERISTIC_BATTERY_LEVEL: &str = "00002A1900001000800000805F9B34FB";

/// Represents the Floss BatteryService implementation.
pub struct BatteryService {
    gatt: Arc<Mutex<Box<BluetoothGatt>>>,
    /// Sender for callback communication with the main thread.
    tx: Sender<Message>,
    callbacks: Callbacks<dyn IBatteryServiceCallback + Send>,
    /// The GATT client ID needed for GATT calls.
    client_id: Option<i32>,
    /// Cached battery levels keyed by remote device.
    battery_levels: HashMap<String, u32>,
    /// Callback IDs that have enabled notifications.
    notifications_enabled: HashSet<u32>,
    /// Found handles for battery levels. Required for faster
    /// refreshes than initiating another search.
    handles: HashMap<String, i32>,
}

/// Enum for GATT callbacks to relay messages to the main processing
/// thread. Newly supported callbacks should add a corresponding entry
/// here.
pub enum GattBatteryCallbacks {
    /// Params: status, client_id
    OnClientRegistered(GattStatus, i32),
    /// Params: status, client_id, connected, addr
    OnClientConnectionState(GattStatus, i32, bool, String),
    /// Params: addr, services, status
    OnSearchComplete(String, Vec<BluetoothGattService>, GattStatus),
    /// Params: addr, status, handle, value
    OnCharacteristicRead(String, GattStatus, i32, Vec<u8>),
    /// Params: addr, handle, value
    OnNotify(String, i32, Vec<u8>),
}

/// API for Floss implementation of the Bluetooth Battery Service
/// (BAS). BAS is built on GATT and this implementation wraps all of
/// the GATT calls and handles tracking battery information for the
/// client.
pub trait IBatteryService {
    /// Registers a callback for interacting with BatteryService.
    fn register_callback(&mut self, callback: Box<dyn IBatteryServiceCallback + Send>) -> u32;

    /// Unregisters a callback.
    fn unregister_callback(&mut self, callback_id: u32);

    /// Enables notifications for a given callback.
    fn enable_notifications(&mut self, callback_id: u32, enable: bool);

    /// Returns the battery level of the remove device if available in
    /// BatteryService's cache. Call refresh_battery_level at least
    /// once to ensure that BatteryService is tracking the device's
    /// battery information.
    fn get_battery_level(&self, remote_address: String) -> Option<u32>;

    /// Forces an explicit read of the device's battery level,
    /// including initiating battery level tracking if not yet
    /// performed.
    fn refresh_battery_level(&self, remote_address: String) -> bool;
}

/// Callback for interacting with BAS.
pub trait IBatteryServiceCallback: RPCProxy {
    /// Called when the status of BatteryService has changed. Trying
    /// to read from devices that do not support BAS will result in
    /// this method being called with BatteryServiceNotSupported.
    fn on_battery_service_status_updated(
        &self,
        remote_address: String,
        status: BatteryServiceStatus,
    );

    /// Invoked when battery level for a device has been changed due to notification.
    fn on_battery_level_updated(&self, remote_address: String, battery_level: u32);

    /// Invoked whenever an explicit read of a devices battery level completes.
    fn on_battery_level_read(&self, remote_address: String, battery_level: u32);
}

impl BatteryService {
    /// Construct a new BatteryService with callbacks relaying messages through tx.
    pub fn new(gatt: Arc<Mutex<Box<BluetoothGatt>>>, tx: Sender<Message>) -> BatteryService {
        let tx = tx.clone();
        let callbacks = Callbacks::new(tx.clone(), Message::BatteryServiceCallbackDisconnected);
        let client_id = None;
        let battery_levels = HashMap::new();
        let notifications_enabled = HashSet::new();
        let handles = HashMap::new();
        Self { gatt, tx, callbacks, client_id, battery_levels, notifications_enabled, handles }
    }

    /// Must be called after BluetoothGatt's init_profiles method has completed.
    pub fn init(&self) {
        self.gatt.lock().unwrap().register_client(
            // TODO(b/233101174): make dynamic or decide on a static UUID
            String::from("e4d2acffcfaa42198f494606b7412117"),
            Box::new(GattCallback::new(self.tx.clone())),
            false,
        );
    }

    /// Handles all callback messages in a central location to avoid deadlocks.
    pub fn handle_callback(&mut self, callback: GattBatteryCallbacks) {
        match callback {
            GattBatteryCallbacks::OnClientRegistered(_status, client_id) => {
                self.client_id = Some(client_id);
            }

            GattBatteryCallbacks::OnClientConnectionState(_status, _client_id, connected, addr) => {
                if !connected {
                    return;
                }
                let client_id = match self.client_id {
                    Some(id) => id,
                    None => {
                        return;
                    }
                };
                self.gatt.lock().unwrap().discover_services(client_id, addr);
            }

            GattBatteryCallbacks::OnSearchComplete(addr, services, status) => {
                if status != GattStatus::Success {
                    debug!("GATT service discovery for {} failed with status {:?}", addr, status);
                    return;
                }
                let (bas_uuid, battery_level_uuid) = match (
                    parse_uuid_string(uuid::BAS),
                    parse_uuid_string(CHARACTERISTIC_BATTERY_LEVEL),
                ) {
                    (Some(bas_uuid), Some(battery_level_uuid)) => (bas_uuid, battery_level_uuid),
                    _ => return,
                };
                // TODO(b/233101174): handle multiple instances of BAS
                let bas = match services.iter().find(|service| service.uuid == bas_uuid.uu) {
                    Some(bas) => bas,
                    None => {
                        self.callbacks.for_all_callbacks(|callback| {
                            callback.on_battery_service_status_updated(
                                addr.clone(),
                                BatteryServiceStatus::BatteryServiceNotSupported,
                            )
                        });
                        return;
                    }
                };
                let battery_level = match bas
                    .characteristics
                    .iter()
                    .find(|characteristic| characteristic.uuid == battery_level_uuid.uu)
                {
                    Some(battery_level) => battery_level,
                    None => {
                        debug!("Device {} has no BatteryLevel characteristic", addr);
                        return;
                    }
                };
                let client_id = match self.client_id {
                    Some(id) => id,
                    None => return,
                };
                let handle = battery_level.instance_id;
                self.handles.insert(addr.clone(), handle.clone());
                self.gatt.lock().unwrap().register_for_notification(
                    client_id,
                    addr.clone(),
                    handle,
                    true,
                );
                if let None = self.battery_levels.get(&addr) {
                    self.gatt.lock().unwrap().read_characteristic(
                        client_id,
                        addr,
                        battery_level.instance_id,
                        0,
                    );
                }
            }

            GattBatteryCallbacks::OnCharacteristicRead(addr, status, _handle, value) => {
                if status != GattStatus::Success {
                    return;
                }
                let level = self.set_battery_level(addr.clone(), value.clone());
                self.callbacks.for_all_callbacks(|callback| {
                    callback.on_battery_level_read(addr.clone(), level);
                });
            }

            GattBatteryCallbacks::OnNotify(addr, _handle, value) => {
                let level = self.set_battery_level(addr.clone(), value);
                // TODO(b/247551256): expand Callbacks to allow direct
                // filtering/exposing the underlying iter
                let to_notify = self.notifications_enabled.clone();
                to_notify.iter().for_each(|id| match self.callbacks.get_by_id(*id) {
                    Some(callback) => callback.on_battery_level_updated(addr.clone(), level),
                    None => (),
                });
            }
        }
    }

    fn set_battery_level(&mut self, remote_address: String, value: Vec<u8>) -> u32 {
        let level: Vec<_> = value.iter().cloned().chain(iter::repeat(0 as u8)).take(4).collect();
        let level = u32::from_le_bytes(level.try_into().unwrap());
        self.battery_levels.insert(remote_address, level);
        level
    }

    fn init_device(&self, remote_address: String) {
        let client_id = match self.client_id {
            Some(id) => id,
            None => return,
        };
        self.gatt.lock().unwrap().client_connect(
            client_id,
            remote_address,
            false,
            BtTransport::Le,
            false,
            LePhy::Phy1m,
        );
    }

    /// Remove a callback due to disconnection or unregistration.
    pub fn remove_callback(&mut self, callback_id: u32) {
        self.callbacks.remove_callback(callback_id);
    }
}

/// Status enum for relaying the state of BAS or a particular device.
pub enum BatteryServiceStatus {
    /// Device does not report support for BAS.
    BatteryServiceNotSupported,
}

impl IBatteryService for BatteryService {
    fn register_callback(&mut self, callback: Box<dyn IBatteryServiceCallback + Send>) -> u32 {
        self.callbacks.add_callback(callback)
    }

    fn unregister_callback(&mut self, callback_id: u32) {
        self.remove_callback(callback_id);
    }

    fn enable_notifications(&mut self, callback_id: u32, enable: bool) {
        if self.callbacks.get_by_id(callback_id).is_none() {
            return;
        }
        self.notifications_enabled.remove(&callback_id);
        if enable {
            self.notifications_enabled.insert(callback_id);
        }
    }

    fn get_battery_level(&self, remote_address: String) -> Option<u32> {
        self.battery_levels.get(&remote_address).cloned()
    }

    fn refresh_battery_level(&self, remote_address: String) -> bool {
        let client_id = match self.client_id {
            Some(id) => id,
            None => return false,
        };
        let handle = match self.handles.get(&remote_address) {
            Some(id) => *id,
            None => {
                self.init_device(remote_address);
                return true;
            }
        };
        self.gatt.lock().unwrap().read_characteristic(client_id, remote_address.clone(), handle, 0);
        self.gatt.lock().unwrap().register_for_notification(
            client_id,
            remote_address,
            handle,
            true,
        );
        true
    }
}

struct GattCallback {
    tx: Sender<Message>,
}

impl GattCallback {
    fn new(tx: Sender<Message>) -> Self {
        Self { tx }
    }
}

impl IBluetoothGattCallback for GattCallback {
    // All callback methods relay messages through the stack receiver
    // to allow BAS to operate on requests serially. This reduces
    // overall complexity including removing the need to share state
    // data with callbacks.

    fn on_client_registered(&self, status: GattStatus, client_id: i32) {
        let tx = self.tx.clone();
        tokio::spawn(async move {
            let _ = tx
                .send(Message::BatteryServiceCallbacks(GattBatteryCallbacks::OnClientRegistered(
                    status, client_id,
                )))
                .await;
        });
    }

    fn on_client_connection_state(
        &self,
        status: GattStatus,
        client_id: i32,
        connected: bool,
        addr: String,
    ) {
        let tx = self.tx.clone();
        tokio::spawn(async move {
            let _ = tx
                .send(Message::BatteryServiceCallbacks(
                    GattBatteryCallbacks::OnClientConnectionState(
                        status, client_id, connected, addr,
                    ),
                ))
                .await;
        });
    }

    fn on_search_complete(
        &self,
        addr: String,
        services: Vec<BluetoothGattService>,
        status: GattStatus,
    ) {
        let tx = self.tx.clone();
        tokio::spawn(async move {
            let _ = tx
                .send(Message::BatteryServiceCallbacks(GattBatteryCallbacks::OnSearchComplete(
                    addr, services, status,
                )))
                .await;
        });
    }

    fn on_characteristic_read(
        &self,
        addr: String,
        status: GattStatus,
        handle: i32,
        value: Vec<u8>,
    ) {
        let tx = self.tx.clone();
        tokio::spawn(async move {
            let _ = tx
                .send(Message::BatteryServiceCallbacks(GattBatteryCallbacks::OnCharacteristicRead(
                    addr, status, handle, value,
                )))
                .await;
        });
    }

    fn on_notify(&self, addr: String, handle: i32, value: Vec<u8>) {
        let tx = self.tx.clone();
        tokio::spawn(async move {
            let _ = tx
                .send(Message::BatteryServiceCallbacks(GattBatteryCallbacks::OnNotify(
                    addr, handle, value,
                )))
                .await;
        });
    }
}

impl RPCProxy for GattCallback {
    fn get_object_id(&self) -> String {
        "BAS Gatt Callback".to_string()
    }
}
