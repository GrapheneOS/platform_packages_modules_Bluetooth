use crate::battery_service::{
    BatteryService, BatteryServiceStatus, IBatteryService, IBatteryServiceCallback,
};
use crate::callbacks::Callbacks;
use crate::Message;
use crate::RPCProxy;
use std::collections::HashSet;
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc::Sender;

/// The primary representation of battery information for internal
/// passing and external calls.
#[derive(Debug, Clone)]
pub struct Battery {
    pub percentage: u32,
    pub source_info: String,
    pub variant: String,
}

/// Callback for interacting with the BatteryManager.
pub trait IBatteryManagerCallback: RPCProxy {
    /// Invoked whenever battery information associated with the given remote changes.
    fn on_battery_info_updated(&self, remote_address: String, battery: Battery);
}

/// Central point for getting battery information that might be sourced from numerous systems.
pub trait IBatteryManager {
    /// Registers a callback for interfacing with the BatteryManager and returns a unique
    /// callback_id for future calls.
    fn register_battery_callback(
        &mut self,
        battery_manager_callback: Box<dyn IBatteryManagerCallback + Send>,
    ) -> u32;

    /// Unregister a callback.
    fn unregister_battery_callback(&mut self, callback_id: u32);

    /// Enables notifications for a given callback.
    fn enable_notifications(&mut self, callback_id: u32, enable: bool);

    /// Returns battery information for the remote, sourced from the highest priority origin.
    fn get_battery_information(&self, remote_address: String) -> Option<Battery>;
}

/// Repesentation of the BatteryManager.
pub struct BatteryManager {
    bas: Arc<Mutex<Box<BatteryService>>>,
    callbacks: Callbacks<dyn IBatteryManagerCallback + Send>,
    /// List of callback IDs that have enabled notifications.
    notifications_enabled: HashSet<u32>,
}

impl BatteryManager {
    /// Construct a new BatteryManager with callbacks communicating on tx.
    pub fn new(bas: Arc<Mutex<Box<BatteryService>>>, tx: Sender<Message>) -> BatteryManager {
        let callbacks = Callbacks::new(tx.clone(), Message::BatteryManagerCallbackDisconnected);
        let notifications_enabled = HashSet::new();
        Self { bas, callbacks, notifications_enabled }
    }

    /// Invoked after BAS has been initialized.
    pub fn init(&self) {
        self.bas.lock().unwrap().register_callback(Box::new(BasCallback::new()));
    }

    /// Remove a callback due to disconnection or unregistration.
    pub fn remove_callback(&mut self, callback_id: u32) {
        self.callbacks.remove_callback(callback_id);
    }
}

struct BasCallback {}

impl BasCallback {
    pub fn new() -> BasCallback {
        Self {}
    }
}

impl IBatteryServiceCallback for BasCallback {
    fn on_battery_service_status_updated(
        &self,
        _remote_address: String,
        _status: BatteryServiceStatus,
    ) {
        todo!()
    }

    fn on_battery_level_updated(&self, _remote_address: String, _battery_level: u32) {
        todo!()
    }

    fn on_battery_level_read(&self, _remote_address: String, _battery_level: u32) {
        todo!()
    }
}

impl RPCProxy for BasCallback {
    fn get_object_id(&self) -> String {
        "BAS Callback".to_string()
    }
}

impl IBatteryManager for BatteryManager {
    fn register_battery_callback(
        &mut self,
        battery_manager_callback: Box<dyn IBatteryManagerCallback + Send>,
    ) -> u32 {
        self.callbacks.add_callback(battery_manager_callback)
    }

    fn unregister_battery_callback(&mut self, callback_id: u32) {
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

    // TODO(b/233101174): update to use all available sources once
    // BatteryProviderManager is implemented.
    fn get_battery_information(&self, remote_address: String) -> Option<Battery> {
        let battery_level = self.bas.lock().unwrap().get_battery_level(remote_address)?;
        Some(Battery {
            percentage: battery_level,
            source_info: "BAS".to_string(),
            variant: "".to_string(),
        })
    }
}
