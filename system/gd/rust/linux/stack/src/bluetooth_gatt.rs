//! Anything related to the GATT API (IBluetoothGatt).

use btif_macros::{btif_callback, btif_callbacks_dispatcher};

use bt_topshim::bindings::root::bluetooth::Uuid;
use bt_topshim::btif::{BluetoothInterface, RawAddress};
use bt_topshim::profiles::gatt::{
    Gatt, GattClientCallbacks, GattClientCallbacksDispatcher, GattServerCallbacksDispatcher,
};
use bt_topshim::topstack;

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use tokio::sync::mpsc::Sender;

use crate::{Message, RPCProxy};

/// Defines the GATT API.
pub trait IBluetoothGatt {
    fn register_scanner(&self, callback: Box<dyn IScannerCallback + Send>);

    fn unregister_scanner(&self, scanner_id: i32);

    fn start_scan(&self, scanner_id: i32, settings: ScanSettings, filters: Vec<ScanFilter>);
    fn stop_scan(&self, scanner_id: i32);

    /// Registers a GATT Client.
    fn register_client(
        &mut self,
        app_uuid: String,
        callback: Box<dyn IBluetoothGattCallback + Send>,
        eatt_support: bool,
    );

    /// Unregisters a GATT Client.
    fn unregister_client(&self, client_if: i32);
}

/// Callback for GATT Client API.
pub trait IBluetoothGattCallback: RPCProxy {
    /// When the `register_client` request is done.
    fn on_client_registered(&self, status: i32, client_if: i32);
}

/// Interface for scanner callbacks to clients, passed to `IBluetoothGatt::register_scanner`.
pub trait IScannerCallback {
    /// When the `register_scanner` request is done.
    fn on_scanner_registered(&self, status: i32, scanner_id: i32);
}

#[derive(Debug, FromPrimitive, ToPrimitive)]
#[repr(i32)]
/// Scan type configuration.
pub enum ScanType {
    Active = 0,
    Passive = 1,
}

impl Default for ScanType {
    fn default() -> Self {
        ScanType::Active
    }
}

/// Represents RSSI configurations for hardware offloaded scanning.
// TODO: This is still a placeholder struct, not yet complete.
#[derive(Debug, Default)]
pub struct RSSISettings {
    pub low_threshold: i32,
    pub high_threshold: i32,
}

/// Represents scanning configurations to be passed to `IBluetoothGatt::start_scan`.
#[derive(Debug, Default)]
pub struct ScanSettings {
    pub interval: i32,
    pub window: i32,
    pub scan_type: ScanType,
    pub rssi_settings: RSSISettings,
}

/// Represents a scan filter to be passed to `IBluetoothGatt::start_scan`.
#[derive(Debug, Default)]
pub struct ScanFilter {}

type Uuid128Bit = [u8; 16];

/// Implementation of the GATT API (IBluetoothGatt).
pub struct BluetoothGatt {
    intf: Arc<Mutex<BluetoothInterface>>,
    gatt: Option<Gatt>,

    gatt_client_map: HashMap<Uuid128Bit, Box<dyn IBluetoothGattCallback + Send>>,
}

impl BluetoothGatt {
    /// Constructs a new IBluetoothGatt implementation.
    pub fn new(intf: Arc<Mutex<BluetoothInterface>>) -> BluetoothGatt {
        BluetoothGatt { intf: intf, gatt: None, gatt_client_map: HashMap::new() }
    }

    pub fn init_profiles(&mut self, tx: Sender<Message>) {
        self.gatt = Gatt::new(&self.intf.lock().unwrap());
        self.gatt.as_mut().unwrap().initialize(
            GattClientCallbacksDispatcher {
                dispatch: Box::new(move |cb| {
                    let tx_clone = tx.clone();
                    topstack::get_runtime().spawn(async move {
                        let _ = tx_clone.send(Message::GattClient(cb)).await;
                    });
                }),
            },
            GattServerCallbacksDispatcher {
                dispatch: Box::new(move |cb| {
                    // TODO(b/193685149): Implement the callbacks
                    println!("received Gatt server callback: {:?}", cb);
                }),
            },
        );
    }
}

// Temporary util that covers only basic string conversion.
// TODO(b/193685325): Implement more UUID utils by using Uuid from gd/hci/uuid.h with cxx.
fn parse_uuid_string(uuid: String) -> Option<Uuid> {
    if uuid.len() != 32 {
        return None;
    }

    let mut raw = [0; 16];

    for i in 0..16 {
        let byte = u8::from_str_radix(&uuid[i * 2..i * 2 + 2], 16);
        if byte.is_err() {
            return None;
        }
        raw[i] = byte.unwrap();
    }

    Some(Uuid { uu: raw })
}

impl IBluetoothGatt for BluetoothGatt {
    fn register_scanner(&self, _callback: Box<dyn IScannerCallback + Send>) {
        // TODO: implement
    }

    fn unregister_scanner(&self, _scanner_id: i32) {
        // TODO: implement
    }

    fn start_scan(&self, _scanner_id: i32, _settings: ScanSettings, _filters: Vec<ScanFilter>) {
        // TODO: implement
    }

    fn stop_scan(&self, _scanner_id: i32) {
        // TODO: implement
    }

    fn register_client(
        &mut self,
        app_uuid: String,
        callback: Box<dyn IBluetoothGattCallback + Send>,
        eatt_support: bool,
    ) {
        let uuid = parse_uuid_string(app_uuid).unwrap();
        self.gatt_client_map.insert(uuid.uu, callback);
        self.gatt.as_ref().unwrap().client.register_client(&uuid, eatt_support);
    }

    fn unregister_client(&self, _client_if: i32) {
        // TODO(b/193685325): implement
    }
}

#[btif_callbacks_dispatcher(BluetoothGatt, dispatch_gatt_client_callbacks, GattClientCallbacks)]
pub(crate) trait BtifGattClientCallbacks {
    #[btif_callback(RegisterClient)]
    fn register_client_cb(&mut self, status: i32, client_if: i32, app_uuid: Uuid);

    #[btif_callback(Connect)]
    fn connect_cb(&mut self, conn_id: i32, status: i32, client_if: i32, addr: RawAddress);

    // TODO(b/193685325): Define all callbacks.
}

impl BtifGattClientCallbacks for BluetoothGatt {
    fn register_client_cb(&mut self, status: i32, client_if: i32, app_uuid: Uuid) {
        let callback = self.gatt_client_map.get(&app_uuid.uu);
        if callback.is_none() {
            println!("Warning: Callback not registered for UUID {:?}", app_uuid.uu);
            return;
        }

        callback.unwrap().on_client_registered(status, client_if);
    }

    fn connect_cb(&mut self, _conn_id: i32, _status: i32, _client_if: i32, _addr: RawAddress) {
        // TODO(b/193685325): handle;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_uuid_from_string() {
        let uuid = parse_uuid_string(String::from("abcdef"));
        assert!(uuid.is_none());

        let uuid = parse_uuid_string(String::from("0123456789abcdef0123456789abcdef"));
        assert!(uuid.is_some());
        let expected: [u8; 16] = [
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab,
            0xcd, 0xef,
        ];
        assert_eq!(Uuid { uu: expected }, uuid.unwrap());
    }
}
