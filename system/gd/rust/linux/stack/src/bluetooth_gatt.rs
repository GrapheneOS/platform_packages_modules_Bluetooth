//! Anything related to the GATT API (IBluetoothGatt).

use btif_macros::{btif_callback, btif_callbacks_dispatcher};

use bt_topshim::bindings::root::bluetooth::Uuid;
use bt_topshim::btif::{BluetoothInterface, BtStatus, BtTransport, RawAddress, Uuid128Bit};
use bt_topshim::profiles::gatt::{
    BtGattDbElement, BtGattNotifyParams, BtGattReadParams, Gatt, GattAdvCallbacks,
    GattAdvCallbacksDispatcher, GattAdvInbandCallbacksDispatcher, GattClientCallbacks,
    GattClientCallbacksDispatcher, GattScannerCallbacks, GattScannerCallbacksDispatcher,
    GattScannerInbandCallbacks, GattScannerInbandCallbacksDispatcher,
    GattServerCallbacksDispatcher, GattStatus, LePhy,
};
use bt_topshim::topstack;

use crate::bluetooth::{Bluetooth, IBluetooth};
use crate::bluetooth_adv::{
    AdvertiseData, Advertisers, AdvertisingSetInfo, AdvertisingSetParameters,
    IAdvertisingSetCallback, PeriodicAdvertisingParameters,
};
use crate::callbacks::Callbacks;
use crate::uuid::parse_uuid_string;
use crate::{Message, RPCProxy, SuspendMode};
use log::{debug, warn};
use num_traits::cast::{FromPrimitive, ToPrimitive};
use num_traits::clamp;
use rand::rngs::SmallRng;
use rand::{RngCore, SeedableRng};
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc::Sender;

struct Client {
    id: Option<i32>,
    cbid: u32,
    uuid: Uuid128Bit,
    is_congested: bool,

    // Queued on_characteristic_write callback.
    congestion_queue: Vec<(String, GattStatus, i32)>,
}

struct Connection {
    conn_id: i32,
    address: String,
    client_id: i32,
}

struct ContextMap {
    // TODO(b/196635530): Consider using `multimap` for a more efficient implementation of get by
    // multiple keys.
    callbacks: Callbacks<dyn IBluetoothGattCallback + Send>,
    clients: Vec<Client>,
    connections: Vec<Connection>,
}

type GattClientCallback = Box<dyn IBluetoothGattCallback + Send>;

impl ContextMap {
    fn new(tx: Sender<Message>) -> ContextMap {
        ContextMap {
            callbacks: Callbacks::new(tx, Message::GattClientCallbackDisconnected),
            clients: vec![],
            connections: vec![],
        }
    }

    fn get_by_uuid(&self, uuid: &Uuid128Bit) -> Option<&Client> {
        self.clients.iter().find(|client| client.uuid == *uuid)
    }

    fn get_by_client_id(&self, client_id: i32) -> Option<&Client> {
        self.clients.iter().find(|client| client.id.is_some() && client.id.unwrap() == client_id)
    }

    fn get_by_client_id_mut(&mut self, client_id: i32) -> Option<&mut Client> {
        self.clients
            .iter_mut()
            .find(|client| client.id.is_some() && client.id.unwrap() == client_id)
    }

    fn get_by_callback_id(&self, callback_id: u32) -> Option<&Client> {
        self.clients.iter().find(|client| client.cbid == callback_id)
    }

    fn get_address_by_conn_id(&self, conn_id: i32) -> Option<String> {
        match self.connections.iter().find(|conn| conn.conn_id == conn_id) {
            None => None,
            Some(conn) => Some(conn.address.clone()),
        }
    }

    fn get_client_by_conn_id(&self, conn_id: i32) -> Option<&Client> {
        match self.connections.iter().find(|conn| conn.conn_id == conn_id) {
            None => None,
            Some(conn) => self.get_by_client_id(conn.client_id),
        }
    }

    fn get_client_by_conn_id_mut(&mut self, conn_id: i32) -> Option<&mut Client> {
        let client_id = match self.connections.iter().find(|conn| conn.conn_id == conn_id) {
            None => return None,
            Some(conn) => conn.client_id,
        };

        self.get_by_client_id_mut(client_id)
    }

    fn add(&mut self, uuid: &Uuid128Bit, callback: GattClientCallback) {
        if self.get_by_uuid(uuid).is_some() {
            return;
        }

        let cbid = self.callbacks.add_callback(callback);

        self.clients.push(Client {
            id: None,
            cbid,
            uuid: uuid.clone(),
            is_congested: false,
            congestion_queue: vec![],
        });
    }

    fn remove(&mut self, id: i32) {
        // Remove any callbacks
        if let Some(c) = self.get_by_client_id(id) {
            let cbid = c.cbid;
            self.remove_callback(cbid);
        }

        self.clients.retain(|client| !(client.id.is_some() && client.id.unwrap() == id));
    }

    fn remove_callback(&mut self, callback_id: u32) {
        self.callbacks.remove_callback(callback_id);
    }

    fn set_client_id(&mut self, uuid: &Uuid128Bit, id: i32) {
        let client = self.clients.iter_mut().find(|client| client.uuid == *uuid);
        if client.is_none() {
            return;
        }

        client.unwrap().id = Some(id);
    }

    fn add_connection(&mut self, client_id: i32, conn_id: i32, address: &String) {
        if self.get_conn_id_from_address(client_id, address).is_some() {
            return;
        }

        self.connections.push(Connection { conn_id, address: address.clone(), client_id });
    }

    fn remove_connection(&mut self, _client_id: i32, conn_id: i32) {
        self.connections.retain(|conn| conn.conn_id != conn_id);
    }

    fn get_conn_id_from_address(&self, client_id: i32, address: &String) -> Option<i32> {
        match self
            .connections
            .iter()
            .find(|conn| conn.client_id == client_id && conn.address == *address)
        {
            None => None,
            Some(conn) => Some(conn.conn_id),
        }
    }

    fn get_callback_from_callback_id(
        &mut self,
        callback_id: u32,
    ) -> Option<&mut GattClientCallback> {
        self.callbacks.get_by_id(callback_id)
    }
}

/// Defines the GATT API.
// TODO(242083290): Split out interfaces.
pub trait IBluetoothGatt {
    // Scanning

    /// Registers an LE scanner callback.
    ///
    /// Returns the callback id.
    fn register_scanner_callback(&mut self, callback: Box<dyn IScannerCallback + Send>) -> u32;

    /// Unregisters an LE scanner callback identified by the given id.
    fn unregister_scanner_callback(&mut self, callback_id: u32) -> bool;

    /// Registers LE scanner.
    ///
    /// `callback_id`: The callback to receive updates about the scanner state.
    /// Returns the UUID of the registered scanner.
    fn register_scanner(&mut self, callback_id: u32) -> Uuid128Bit;

    /// Unregisters an LE scanner identified by the given scanner id.
    fn unregister_scanner(&mut self, scanner_id: u8) -> bool;

    /// Activate scan of the given scanner id.
    fn start_scan(
        &mut self,
        scanner_id: u8,
        settings: ScanSettings,
        filters: Vec<ScanFilter>,
    ) -> BtStatus;

    /// Deactivate scan of the given scanner id.
    fn stop_scan(&mut self, scanner_id: u8) -> BtStatus;

    /// Returns the current suspend mode.
    fn get_scan_suspend_mode(&self) -> SuspendMode;

    // Advertising

    /// Registers callback for BLE advertising.
    fn register_advertiser_callback(
        &mut self,
        callback: Box<dyn IAdvertisingSetCallback + Send>,
    ) -> u32;

    /// Unregisters callback for BLE advertising.
    fn unregister_advertiser_callback(&mut self, callback_id: u32);

    /// Creates a new BLE advertising set and start advertising.
    ///
    /// Returns the reg_id for the advertising set, which is used in the callback
    /// `on_advertising_set_started` to identify the advertising set started.
    ///
    /// * `parameters` - Advertising set parameters.
    /// * `advertise_data` - Advertisement data to be broadcasted.
    /// * `scan_response` - Scan response.
    /// * `periodic_parameters` - Periodic advertising parameters. If None, periodic advertising
    ///     will not be started.
    /// * `periodic_data` - Periodic advertising data.
    /// * `duration` - Advertising duration, in 10 ms unit. Valid range is from 1 (10 ms) to
    ///     65535 (655.35 sec). 0 means no advertising timeout.
    /// * `max_ext_adv_events` - Maximum number of extended advertising events the controller
    ///     shall attempt to send before terminating the extended advertising, even if the
    ///     duration has not expired. Valid range is from 1 to 255. 0 means event count limitation.
    /// * `callback_id` - Identifies callback registered in register_advertiser_callback.
    fn start_advertising_set(
        &mut self,
        parameters: AdvertisingSetParameters,
        advertise_data: AdvertiseData,
        scan_response: Option<AdvertiseData>,
        periodic_parameters: Option<PeriodicAdvertisingParameters>,
        periodic_data: Option<AdvertiseData>,
        duration: i32,
        max_ext_adv_events: i32,
        callback_id: u32,
    ) -> i32;

    /// Disposes a BLE advertising set.
    fn stop_advertising_set(&mut self, advertiser_id: i32);

    /// Queries address associated with the advertising set.
    fn get_own_address(&mut self, advertiser_id: i32);

    /// Enables or disables an advertising set.
    fn enable_advertising_set(
        &mut self,
        advertiser_id: i32,
        enable: bool,
        duration: i32,
        max_ext_adv_events: i32,
    );

    /// Updates advertisement data of the advertising set.
    fn set_advertising_data(&mut self, advertiser_id: i32, data: AdvertiseData);

    /// Updates scan response of the advertising set.
    fn set_scan_response_data(&mut self, advertiser_id: i32, data: AdvertiseData);

    /// Updates advertising parameters of the advertising set.
    ///
    /// It must be called when advertising is not active.
    fn set_advertising_parameters(
        &mut self,
        advertiser_id: i32,
        parameters: AdvertisingSetParameters,
    );

    /// Updates periodic advertising parameters.
    fn set_periodic_advertising_parameters(
        &mut self,
        advertiser_id: i32,
        parameters: PeriodicAdvertisingParameters,
    );

    /// Updates periodic advertisement data.
    ///
    /// It must be called after `set_periodic_advertising_parameters`, or after
    /// advertising was started with periodic advertising data set.
    fn set_periodic_advertising_data(&mut self, advertiser_id: i32, data: AdvertiseData);

    /// Enables or disables periodic advertising.
    fn set_periodic_advertising_enable(&mut self, advertiser_id: i32, enable: bool);

    // GATT Client

    /// Registers a GATT Client.
    fn register_client(
        &mut self,
        app_uuid: String,
        callback: Box<dyn IBluetoothGattCallback + Send>,
        eatt_support: bool,
    );

    /// Unregisters a GATT Client.
    fn unregister_client(&mut self, client_id: i32);

    /// Initiates a GATT connection to a peer device.
    fn client_connect(
        &self,
        client_id: i32,
        addr: String,
        is_direct: bool,
        transport: BtTransport,
        opportunistic: bool,
        phy: LePhy,
    );

    /// Disconnects a GATT connection.
    fn client_disconnect(&self, client_id: i32, addr: String);

    /// Clears the attribute cache of a device.
    fn refresh_device(&self, client_id: i32, addr: String);

    /// Enumerates all GATT services on a connected device.
    fn discover_services(&self, client_id: i32, addr: String);

    /// Search a GATT service on a connected device based on a UUID.
    fn discover_service_by_uuid(&self, client_id: i32, addr: String, uuid: String);

    /// Reads a characteristic on a remote device.
    fn read_characteristic(&self, client_id: i32, addr: String, handle: i32, auth_req: i32);

    /// Reads a characteristic on a remote device.
    fn read_using_characteristic_uuid(
        &self,
        client_id: i32,
        addr: String,
        uuid: String,
        start_handle: i32,
        end_handle: i32,
        auth_req: i32,
    );

    /// Writes a remote characteristic.
    fn write_characteristic(
        &self,
        client_id: i32,
        addr: String,
        handle: i32,
        write_type: GattWriteType,
        auth_req: i32,
        value: Vec<u8>,
    ) -> GattWriteRequestStatus;

    /// Reads the descriptor for a given characteristic.
    fn read_descriptor(&self, client_id: i32, addr: String, handle: i32, auth_req: i32);

    /// Writes a remote descriptor for a given characteristic.
    fn write_descriptor(
        &self,
        client_id: i32,
        addr: String,
        handle: i32,
        auth_req: i32,
        value: Vec<u8>,
    );

    /// Registers to receive notifications or indications for a given characteristic.
    fn register_for_notification(&self, client_id: i32, addr: String, handle: i32, enable: bool);

    /// Begins reliable write.
    fn begin_reliable_write(&mut self, client_id: i32, addr: String);

    /// Ends reliable write.
    fn end_reliable_write(&mut self, client_id: i32, addr: String, execute: bool);

    /// Requests RSSI for a given remote device.
    fn read_remote_rssi(&self, client_id: i32, addr: String);

    /// Configures the MTU of a given connection.
    fn configure_mtu(&self, client_id: i32, addr: String, mtu: i32);

    /// Requests a connection parameter update.
    fn connection_parameter_update(
        &self,
        client_id: i32,
        addr: String,
        min_interval: i32,
        max_interval: i32,
        latency: i32,
        timeout: i32,
        min_ce_len: u16,
        max_ce_len: u16,
    );

    /// Sets preferred PHY.
    fn client_set_preferred_phy(
        &self,
        client_id: i32,
        addr: String,
        tx_phy: LePhy,
        rx_phy: LePhy,
        phy_options: i32,
    );

    /// Reads the PHY used by a peer.
    fn client_read_phy(&mut self, client_id: i32, addr: String);
}

#[derive(Debug, Default)]
/// Represents a GATT Descriptor.
pub struct BluetoothGattDescriptor {
    pub uuid: Uuid128Bit,
    pub instance_id: i32,
    pub permissions: i32,
}

impl BluetoothGattDescriptor {
    fn new(uuid: Uuid128Bit, instance_id: i32, permissions: i32) -> BluetoothGattDescriptor {
        BluetoothGattDescriptor { uuid, instance_id, permissions }
    }
}

#[derive(Debug, Default)]
/// Represents a GATT Characteristic.
pub struct BluetoothGattCharacteristic {
    pub uuid: Uuid128Bit,
    pub instance_id: i32,
    pub properties: i32,
    pub permissions: i32,
    pub key_size: i32,
    pub write_type: GattWriteType,
    pub descriptors: Vec<BluetoothGattDescriptor>,
}

impl BluetoothGattCharacteristic {
    pub const PROPERTY_BROADCAST: i32 = 0x01;
    pub const PROPERTY_READ: i32 = 0x02;
    pub const PROPERTY_WRITE_NO_RESPONSE: i32 = 0x04;
    pub const PROPERTY_WRITE: i32 = 0x08;
    pub const PROPERTY_NOTIFY: i32 = 0x10;
    pub const PROPERTY_INDICATE: i32 = 0x20;
    pub const PROPERTY_SIGNED_WRITE: i32 = 0x40;
    pub const PROPERTY_EXTENDED_PROPS: i32 = 0x80;

    fn new(
        uuid: Uuid128Bit,
        instance_id: i32,
        properties: i32,
        permissions: i32,
    ) -> BluetoothGattCharacteristic {
        BluetoothGattCharacteristic {
            uuid,
            instance_id,
            properties,
            permissions,
            write_type: if properties & BluetoothGattCharacteristic::PROPERTY_WRITE_NO_RESPONSE != 0
            {
                GattWriteType::WriteNoRsp
            } else {
                GattWriteType::Write
            },
            key_size: 16,
            descriptors: vec![],
        }
    }
}

#[derive(Debug, Default)]
/// Represents a GATT Service.
pub struct BluetoothGattService {
    pub uuid: Uuid128Bit,
    pub instance_id: i32,
    pub service_type: i32,
    pub characteristics: Vec<BluetoothGattCharacteristic>,
    pub included_services: Vec<BluetoothGattService>,
}

impl BluetoothGattService {
    fn new(uuid: Uuid128Bit, instance_id: i32, service_type: i32) -> BluetoothGattService {
        BluetoothGattService {
            uuid,
            instance_id,
            service_type,
            characteristics: vec![],
            included_services: vec![],
        }
    }
}

/// Callback for GATT Client API.
pub trait IBluetoothGattCallback: RPCProxy {
    /// When the `register_client` request is done.
    fn on_client_registered(&self, status: GattStatus, client_id: i32);

    /// When there is a change in the state of a GATT client connection.
    fn on_client_connection_state(
        &self,
        status: GattStatus,
        client_id: i32,
        connected: bool,
        addr: String,
    );

    /// When there is a change of PHY.
    fn on_phy_update(&self, addr: String, tx_phy: LePhy, rx_phy: LePhy, status: GattStatus);

    /// The completion of IBluetoothGatt::read_phy.
    fn on_phy_read(&self, addr: String, tx_phy: LePhy, rx_phy: LePhy, status: GattStatus);

    /// When GATT db is available.
    fn on_search_complete(
        &self,
        addr: String,
        services: Vec<BluetoothGattService>,
        status: GattStatus,
    );

    /// The completion of IBluetoothGatt::read_characteristic.
    fn on_characteristic_read(&self, addr: String, status: GattStatus, handle: i32, value: Vec<u8>);

    /// The completion of IBluetoothGatt::write_characteristic.
    fn on_characteristic_write(&self, addr: String, status: GattStatus, handle: i32);

    /// When a reliable write is completed.
    fn on_execute_write(&self, addr: String, status: GattStatus);

    /// The completion of IBluetoothGatt::read_descriptor.
    fn on_descriptor_read(&self, addr: String, status: GattStatus, handle: i32, value: Vec<u8>);

    /// The completion of IBluetoothGatt::write_descriptor.
    fn on_descriptor_write(&self, addr: String, status: GattStatus, handle: i32);

    /// When notification or indication is received.
    fn on_notify(&self, addr: String, handle: i32, value: Vec<u8>);

    /// The completion of IBluetoothGatt::read_remote_rssi.
    fn on_read_remote_rssi(&self, addr: String, rssi: i32, status: GattStatus);

    /// The completion of IBluetoothGatt::configure_mtu.
    fn on_configure_mtu(&self, addr: String, mtu: i32, status: GattStatus);

    /// When a connection parameter changes.
    fn on_connection_updated(
        &self,
        addr: String,
        interval: i32,
        latency: i32,
        timeout: i32,
        status: GattStatus,
    );

    /// When there is an addition, removal, or change of a GATT service.
    fn on_service_changed(&self, addr: String);
}

/// Interface for scanner callbacks to clients, passed to
/// `IBluetoothGatt::register_scanner_callback`.
pub trait IScannerCallback: RPCProxy {
    /// When the `register_scanner` request is done.
    fn on_scanner_registered(&self, uuid: Uuid128Bit, scanner_id: u8, status: GattStatus);

    /// When an LE advertisement matching aggregate filters is detected. Since this callback is
    /// shared among all scanner callbacks, clients may receive more advertisements than what is
    /// requested to be filtered in.
    fn on_scan_result(&self, scan_result: ScanResult);

    /// When LE Scan module changes suspend mode due to system suspend/resume.
    fn on_suspend_mode_change(&self, suspend_mode: SuspendMode);
}

#[derive(Debug, FromPrimitive, ToPrimitive)]
#[repr(u8)]
/// GATT write type.
enum GattDbElementType {
    PrimaryService = 0,
    SecondaryService = 1,
    IncludedService = 2,
    Characteristic = 3,
    Descriptor = 4,
}

#[derive(Debug, FromPrimitive, ToPrimitive)]
#[repr(u8)]
/// GATT write type.
pub enum GattWriteType {
    Invalid = 0,
    WriteNoRsp = 1,
    Write = 2,
    WritePrepare = 3,
}

impl Default for GattWriteType {
    fn default() -> Self {
        GattWriteType::Write
    }
}

#[derive(Debug, FromPrimitive, ToPrimitive)]
#[repr(u32)]
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
// TODO(b/200066804): This is still a placeholder struct, not yet complete.
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

/// Represents scan result
#[derive(Debug)]
pub struct ScanResult {
    pub address: String,
    pub addr_type: u8,
    pub event_type: u16,
    pub primary_phy: u8,
    pub secondary_phy: u8,
    pub advertising_sid: u8,
    pub tx_power: i8,
    pub rssi: i8,
    pub periodic_adv_int: u16,
    pub adv_data: Vec<u8>,
}

/// Represents a scan filter to be passed to `IBluetoothGatt::start_scan`.
#[derive(Debug, Default)]
pub struct ScanFilter {}

/// Implementation of the GATT API (IBluetoothGatt).
pub struct BluetoothGatt {
    intf: Arc<Mutex<BluetoothInterface>>,
    gatt: Option<Gatt>,
    adapter: Option<Arc<Mutex<Box<Bluetooth>>>>,

    context_map: ContextMap,
    reliable_queue: HashSet<String>,
    scanner_callbacks: Callbacks<dyn IScannerCallback + Send>,
    scanners: HashMap<Uuid, ScannerInfo>,
    advertisers: Advertisers,

    // Used for generating random UUIDs. SmallRng is chosen because it is fast, don't use this for
    // cryptography.
    small_rng: SmallRng,
}

impl BluetoothGatt {
    /// Constructs a new IBluetoothGatt implementation.
    pub fn new(intf: Arc<Mutex<BluetoothInterface>>, tx: Sender<Message>) -> BluetoothGatt {
        BluetoothGatt {
            intf,
            gatt: None,
            adapter: None,
            context_map: ContextMap::new(tx.clone()),
            reliable_queue: HashSet::new(),
            scanner_callbacks: Callbacks::new(tx.clone(), Message::ScannerCallbackDisconnected),
            scanners: HashMap::new(),
            small_rng: SmallRng::from_entropy(),
            advertisers: Advertisers::new(tx.clone()),
        }
    }

    pub fn init_profiles(&mut self, tx: Sender<Message>, adapter: Arc<Mutex<Box<Bluetooth>>>) {
        self.gatt = Gatt::new(&self.intf.lock().unwrap());
        self.adapter = Some(adapter);

        let tx_clone = tx.clone();
        let gatt_client_callbacks_dispatcher = GattClientCallbacksDispatcher {
            dispatch: Box::new(move |cb| {
                let tx_clone = tx_clone.clone();
                topstack::get_runtime().spawn(async move {
                    let _ = tx_clone.send(Message::GattClient(cb)).await;
                });
            }),
        };

        let gatt_server_callbacks_dispatcher = GattServerCallbacksDispatcher {
            dispatch: Box::new(move |cb| {
                // TODO(b/193685149): Implement the callbacks
                debug!("received Gatt server callback: {:?}", cb);
            }),
        };

        let tx_clone = tx.clone();
        let gatt_scanner_callbacks_dispatcher = GattScannerCallbacksDispatcher {
            dispatch: Box::new(move |cb| {
                let tx_clone = tx_clone.clone();
                topstack::get_runtime().spawn(async move {
                    let _ = tx_clone.send(Message::LeScanner(cb)).await;
                });
            }),
        };

        let tx_clone = tx.clone();
        let gatt_scanner_inband_callbacks_dispatcher = GattScannerInbandCallbacksDispatcher {
            dispatch: Box::new(move |cb| {
                let tx_clone = tx_clone.clone();
                topstack::get_runtime().spawn(async move {
                    let _ = tx_clone.send(Message::LeScannerInband(cb)).await;
                });
            }),
        };

        let tx_clone = tx.clone();
        let gatt_adv_inband_callbacks_dispatcher = GattAdvInbandCallbacksDispatcher {
            dispatch: Box::new(move |cb| {
                let tx_clone = tx_clone.clone();
                topstack::get_runtime().spawn(async move {
                    let _ = tx_clone.send(Message::LeAdvInband(cb)).await;
                });
            }),
        };

        let tx_clone = tx.clone();
        let gatt_adv_callbacks_dispatcher = GattAdvCallbacksDispatcher {
            dispatch: Box::new(move |cb| {
                let tx_clone = tx_clone.clone();
                topstack::get_runtime().spawn(async move {
                    let _ = tx_clone.send(Message::LeAdv(cb)).await;
                });
            }),
        };

        self.gatt.as_mut().unwrap().initialize(
            gatt_client_callbacks_dispatcher,
            gatt_server_callbacks_dispatcher,
            gatt_scanner_callbacks_dispatcher,
            gatt_scanner_inband_callbacks_dispatcher,
            gatt_adv_inband_callbacks_dispatcher,
            gatt_adv_callbacks_dispatcher,
        );
    }

    /// Remove a scanner callback and unregisters all scanners associated with that callback.
    pub fn remove_scanner_callback(&mut self, callback_id: u32) -> bool {
        let affected_scanner_ids: Vec<u8> = self
            .scanners
            .iter()
            .filter(|(_uuid, scanner)| scanner.callback_id == callback_id)
            .filter_map(|(_uuid, scanner)| {
                if let Some(scanner_id) = scanner.scanner_id {
                    Some(scanner_id)
                } else {
                    None
                }
            })
            .collect();

        // All scanners associated with the callback must be also unregistered.
        for scanner_id in affected_scanner_ids {
            self.unregister_scanner(scanner_id);
        }

        self.scanner_callbacks.remove_callback(callback_id)
    }

    /// Enters suspend mode for LE Scan.
    ///
    /// This "pauses" all operations managed by this module to prepare for system suspend. A
    /// callback is triggered to let clients know that this module is in suspend mode and some
    /// subsequent API calls will be blocked in this mode.
    pub fn scan_enter_suspend(&mut self) {
        // TODO(b/224603540): Implement
        todo!()
    }

    /// Exits suspend mode for LE Scan.
    ///
    /// To be called after system resume/wake up. This "unpauses" the operations that were "paused"
    /// due to suspend. A callback is triggered to let clients when this module has exited suspend
    /// mode.
    pub fn scan_exit_suspend(&mut self) {
        // TODO(b/224603540): Implement
        todo!()
    }

    // Update the topshim's scan state depending on the states of registered scanners. Scan is
    // enabled if there is at least 1 active registered scanner.
    fn update_scan(&mut self) {
        if self.scanners.values().find(|scanner| scanner.is_active).is_some() {
            self.gatt.as_mut().unwrap().scanner.start_scan();
        } else {
            self.gatt.as_mut().unwrap().scanner.stop_scan();
        }
    }

    fn find_scanner_by_id(&mut self, scanner_id: u8) -> Option<&mut ScannerInfo> {
        self.scanners.values_mut().find(|scanner| scanner.scanner_id == Some(scanner_id))
    }

    /// Remove an advertiser callback and unregisters all advertising sets associated with that callback.
    pub fn remove_adv_callback(&mut self, callback_id: u32) -> bool {
        self.advertisers.remove_callback(callback_id, self.gatt.as_mut().unwrap())
    }

    fn get_adapter_name(&self) -> String {
        if let Some(adapter) = &self.adapter {
            adapter.lock().unwrap().get_name()
        } else {
            String::new()
        }
    }

    pub fn remove_client_callback(&mut self, callback_id: u32) {
        // Unregister client if client id exists.
        if let Some(client) = self.context_map.get_by_callback_id(callback_id) {
            if let Some(id) = client.id {
                self.unregister_client(id);
            }
        }

        // Always remove callback.
        self.context_map.remove_callback(callback_id);
    }
}

#[derive(Debug, FromPrimitive, ToPrimitive)]
#[repr(u8)]
/// Status of WriteCharacteristic methods.
pub enum GattWriteRequestStatus {
    Success = 0,
    Fail = 1,
    Busy = 2,
}

// This structure keeps track of the lifecycle of a scanner.
struct ScannerInfo {
    // The callback to which events about this scanner needs to be sent to.
    // Another purpose of keeping track of the callback id is that when a callback is disconnected
    // or unregistered we need to also unregister all scanners associated with that callback to
    // prevent dangling unowned scanners.
    callback_id: u32,
    // If the scanner is registered successfully, this contains the scanner id, otherwise None.
    scanner_id: Option<u8>,
    // If one of scanners is active, we scan.
    is_active: bool,
}

impl IBluetoothGatt for BluetoothGatt {
    fn register_scanner_callback(&mut self, callback: Box<dyn IScannerCallback + Send>) -> u32 {
        self.scanner_callbacks.add_callback(callback)
    }

    fn unregister_scanner_callback(&mut self, callback_id: u32) -> bool {
        self.remove_scanner_callback(callback_id)
    }

    fn register_scanner(&mut self, callback_id: u32) -> Uuid128Bit {
        let mut bytes: [u8; 16] = [0; 16];
        self.small_rng.fill_bytes(&mut bytes);
        let uuid = Uuid { uu: bytes };

        self.scanners.insert(uuid, ScannerInfo { callback_id, scanner_id: None, is_active: false });

        // libbluetooth's register_scanner takes a UUID of the scanning application. This UUID does
        // not correspond to higher level concept of "application" so we use random UUID that
        // functions as a unique identifier of the scanner.
        self.gatt.as_mut().unwrap().scanner.register_scanner(uuid);

        uuid.uu
    }

    fn unregister_scanner(&mut self, scanner_id: u8) -> bool {
        self.gatt.as_mut().unwrap().scanner.unregister(scanner_id);

        // The unregistered scanner must also be stopped.
        self.stop_scan(scanner_id);

        self.scanners.retain(|_uuid, scanner| scanner.scanner_id != Some(scanner_id));

        true
    }

    fn start_scan(
        &mut self,
        scanner_id: u8,
        _settings: ScanSettings,
        _filters: Vec<ScanFilter>,
    ) -> BtStatus {
        // Multiplexing scanners happens at this layer. The implementations of start_scan
        // and stop_scan maintains the state of all registered scanners and based on the states
        // update the scanning and/or filter states of libbluetooth.
        // TODO(b/217274432): Honor settings and filters.
        if let Some(scanner) = self.find_scanner_by_id(scanner_id) {
            scanner.is_active = true;
        } else {
            log::warn!("Scanner {} not found", scanner_id);
            return BtStatus::Fail;
        }

        self.update_scan();
        BtStatus::Success
    }

    fn stop_scan(&mut self, scanner_id: u8) -> BtStatus {
        if let Some(scanner) = self.find_scanner_by_id(scanner_id) {
            scanner.is_active = false;
        } else {
            log::warn!("Scanner {} not found", scanner_id);
            // Clients can assume success of the removal since the scanner does not exist.
            return BtStatus::Success;
        }

        self.update_scan();
        BtStatus::Success
    }

    fn get_scan_suspend_mode(&self) -> SuspendMode {
        // TODO(b/224603540): Implement.
        return SuspendMode::Normal;
    }

    // Advertising

    fn register_advertiser_callback(
        &mut self,
        callback: Box<dyn IAdvertisingSetCallback + Send>,
    ) -> u32 {
        self.advertisers.add_callback(callback)
    }

    fn unregister_advertiser_callback(&mut self, callback_id: u32) {
        self.advertisers.remove_callback(callback_id, self.gatt.as_mut().unwrap());
    }

    fn start_advertising_set(
        &mut self,
        parameters: AdvertisingSetParameters,
        advertise_data: AdvertiseData,
        scan_response: Option<AdvertiseData>,
        periodic_parameters: Option<PeriodicAdvertisingParameters>,
        periodic_data: Option<AdvertiseData>,
        duration: i32,
        max_ext_adv_events: i32,
        callback_id: u32,
    ) -> i32 {
        let device_name = self.get_adapter_name();
        let params = parameters.into();
        let adv_bytes = advertise_data.make_with(&device_name);
        let scan_bytes =
            if let Some(d) = scan_response { d.make_with(&device_name) } else { Vec::<u8>::new() };
        let periodic_params = if let Some(p) = periodic_parameters {
            p.into()
        } else {
            bt_topshim::profiles::gatt::PeriodicAdvertisingParameters::default()
        };
        let periodic_bytes =
            if let Some(d) = periodic_data { d.make_with(&device_name) } else { Vec::<u8>::new() };
        let adv_timeout = clamp(duration, 0, 0xffff) as u16;
        let adv_events = clamp(max_ext_adv_events, 0, 0xff) as u8;

        let s = AdvertisingSetInfo::new(callback_id);
        let reg_id = s.reg_id();
        self.advertisers.add(s);

        self.gatt.as_mut().unwrap().advertiser.start_advertising_set(
            reg_id,
            params,
            adv_bytes,
            scan_bytes,
            periodic_params,
            periodic_bytes,
            adv_timeout,
            adv_events,
        );
        reg_id
    }

    fn stop_advertising_set(&mut self, advertiser_id: i32) {
        let s = self.advertisers.get_by_advertiser_id(advertiser_id);
        if None == s {
            return;
        }
        let s = s.unwrap().clone();

        self.gatt.as_mut().unwrap().advertiser.unregister(s.adv_id());

        if let Some(cb) = self.advertisers.get_callback(&s) {
            cb.on_advertising_set_stopped(advertiser_id);
        }
        self.advertisers.remove_by_advertiser_id(advertiser_id);
    }

    fn get_own_address(&mut self, advertiser_id: i32) {
        if let Some(s) = self.advertisers.get_by_advertiser_id(advertiser_id) {
            self.gatt.as_mut().unwrap().advertiser.get_own_address(s.adv_id());
        }
    }

    fn enable_advertising_set(
        &mut self,
        advertiser_id: i32,
        enable: bool,
        duration: i32,
        max_ext_adv_events: i32,
    ) {
        let adv_timeout = clamp(duration, 0, 0xffff) as u16;
        let adv_events = clamp(max_ext_adv_events, 0, 0xff) as u8;

        if let Some(s) = self.advertisers.get_by_advertiser_id(advertiser_id) {
            self.gatt.as_mut().unwrap().advertiser.enable(
                s.adv_id(),
                enable,
                adv_timeout,
                adv_events,
            );
        }
    }

    fn set_advertising_data(&mut self, advertiser_id: i32, data: AdvertiseData) {
        let device_name = self.get_adapter_name();
        let bytes = data.make_with(&device_name);

        if let Some(s) = self.advertisers.get_by_advertiser_id(advertiser_id) {
            self.gatt.as_mut().unwrap().advertiser.set_data(s.adv_id(), false, bytes);
        }
    }

    fn set_scan_response_data(&mut self, advertiser_id: i32, data: AdvertiseData) {
        let device_name = self.get_adapter_name();
        let bytes = data.make_with(&device_name);

        if let Some(s) = self.advertisers.get_by_advertiser_id(advertiser_id) {
            self.gatt.as_mut().unwrap().advertiser.set_data(s.adv_id(), true, bytes);
        }
    }

    fn set_advertising_parameters(
        &mut self,
        advertiser_id: i32,
        parameters: AdvertisingSetParameters,
    ) {
        let params = parameters.into();

        if let Some(s) = self.advertisers.get_by_advertiser_id(advertiser_id) {
            self.gatt.as_mut().unwrap().advertiser.set_parameters(s.adv_id(), params);
        }
    }

    fn set_periodic_advertising_parameters(
        &mut self,
        advertiser_id: i32,
        parameters: PeriodicAdvertisingParameters,
    ) {
        let params = parameters.into();

        if let Some(s) = self.advertisers.get_by_advertiser_id(advertiser_id) {
            self.gatt
                .as_mut()
                .unwrap()
                .advertiser
                .set_periodic_advertising_parameters(s.adv_id(), params);
        }
    }

    fn set_periodic_advertising_data(&mut self, advertiser_id: i32, data: AdvertiseData) {
        let device_name = self.get_adapter_name();
        let bytes = data.make_with(&device_name);

        if let Some(s) = self.advertisers.get_by_advertiser_id(advertiser_id) {
            self.gatt.as_mut().unwrap().advertiser.set_periodic_advertising_data(s.adv_id(), bytes);
        }
    }

    fn set_periodic_advertising_enable(&mut self, advertiser_id: i32, enable: bool) {
        if let Some(s) = self.advertisers.get_by_advertiser_id(advertiser_id) {
            self.gatt
                .as_mut()
                .unwrap()
                .advertiser
                .set_periodic_advertising_enable(s.adv_id(), enable);
        }
    }

    fn register_client(
        &mut self,
        app_uuid: String,
        callback: Box<dyn IBluetoothGattCallback + Send>,
        eatt_support: bool,
    ) {
        let uuid = parse_uuid_string(app_uuid).unwrap();
        self.context_map.add(&uuid.uu, callback);
        self.gatt.as_ref().unwrap().client.register_client(&uuid, eatt_support);
    }

    fn unregister_client(&mut self, client_id: i32) {
        self.context_map.remove(client_id);
        self.gatt.as_ref().unwrap().client.unregister_client(client_id);
    }

    fn client_connect(
        &self,
        client_id: i32,
        addr: String,
        is_direct: bool,
        transport: BtTransport,
        opportunistic: bool,
        phy: LePhy,
    ) {
        let address = match RawAddress::from_string(addr.clone()) {
            None => return,
            Some(addr) => addr,
        };

        self.gatt.as_ref().unwrap().client.connect(
            client_id,
            &address,
            is_direct,
            transport.into(),
            opportunistic,
            phy.into(),
        );
    }

    fn client_disconnect(&self, client_id: i32, address: String) {
        let conn_id = self.context_map.get_conn_id_from_address(client_id, &address);
        if conn_id.is_none() {
            return;
        }

        self.gatt.as_ref().unwrap().client.disconnect(
            client_id,
            &RawAddress::from_string(address).unwrap(),
            conn_id.unwrap(),
        );
    }

    fn refresh_device(&self, client_id: i32, addr: String) {
        self.gatt
            .as_ref()
            .unwrap()
            .client
            .refresh(client_id, &RawAddress::from_string(addr).unwrap());
    }

    fn discover_services(&self, client_id: i32, addr: String) {
        let conn_id = self.context_map.get_conn_id_from_address(client_id, &addr);
        if conn_id.is_none() {
            return;
        }

        self.gatt.as_ref().unwrap().client.search_service(conn_id.unwrap(), None);
    }

    fn discover_service_by_uuid(&self, client_id: i32, addr: String, uuid: String) {
        let conn_id = self.context_map.get_conn_id_from_address(client_id, &addr);
        if conn_id.is_none() {
            return;
        }

        let uuid = parse_uuid_string(uuid);
        if uuid.is_none() {
            return;
        }

        self.gatt.as_ref().unwrap().client.search_service(conn_id.unwrap(), uuid);
    }

    fn read_characteristic(&self, client_id: i32, addr: String, handle: i32, auth_req: i32) {
        let conn_id = self.context_map.get_conn_id_from_address(client_id, &addr);
        if conn_id.is_none() {
            return;
        }

        // TODO(b/200065274): Perform check on restricted handles.

        self.gatt.as_ref().unwrap().client.read_characteristic(
            conn_id.unwrap(),
            handle as u16,
            auth_req,
        );
    }

    fn read_using_characteristic_uuid(
        &self,
        client_id: i32,
        addr: String,
        uuid: String,
        start_handle: i32,
        end_handle: i32,
        auth_req: i32,
    ) {
        let conn_id = self.context_map.get_conn_id_from_address(client_id, &addr);
        if conn_id.is_none() {
            return;
        }

        let uuid = parse_uuid_string(uuid);
        if uuid.is_none() {
            return;
        }

        // TODO(b/200065274): Perform check on restricted handles.

        self.gatt.as_ref().unwrap().client.read_using_characteristic_uuid(
            conn_id.unwrap(),
            &uuid.unwrap(),
            start_handle as u16,
            end_handle as u16,
            auth_req,
        );
    }

    fn write_characteristic(
        &self,
        client_id: i32,
        addr: String,
        handle: i32,
        mut write_type: GattWriteType,
        auth_req: i32,
        value: Vec<u8>,
    ) -> GattWriteRequestStatus {
        let conn_id = self.context_map.get_conn_id_from_address(client_id, &addr);
        if conn_id.is_none() {
            return GattWriteRequestStatus::Fail;
        }

        if self.reliable_queue.contains(&addr) {
            write_type = GattWriteType::WritePrepare;
        }

        // TODO(b/200065274): Perform check on restricted handles.

        // TODO(b/200070162): Handle concurrent write characteristic.

        self.gatt.as_ref().unwrap().client.write_characteristic(
            conn_id.unwrap(),
            handle as u16,
            write_type.to_i32().unwrap(),
            auth_req,
            &value,
        );

        return GattWriteRequestStatus::Success;
    }

    fn read_descriptor(&self, client_id: i32, addr: String, handle: i32, auth_req: i32) {
        let conn_id = self.context_map.get_conn_id_from_address(client_id, &addr);
        if conn_id.is_none() {
            return;
        }

        // TODO(b/200065274): Perform check on restricted handles.

        self.gatt.as_ref().unwrap().client.read_descriptor(
            conn_id.unwrap(),
            handle as u16,
            auth_req,
        );
    }

    fn write_descriptor(
        &self,
        client_id: i32,
        addr: String,
        handle: i32,
        auth_req: i32,
        value: Vec<u8>,
    ) {
        let conn_id = self.context_map.get_conn_id_from_address(client_id, &addr);
        if conn_id.is_none() {
            return;
        }

        // TODO(b/200065274): Perform check on restricted handles.

        self.gatt.as_ref().unwrap().client.write_descriptor(
            conn_id.unwrap(),
            handle as u16,
            auth_req,
            &value,
        );
    }

    fn register_for_notification(&self, client_id: i32, addr: String, handle: i32, enable: bool) {
        let conn_id = self.context_map.get_conn_id_from_address(client_id, &addr);
        if conn_id.is_none() {
            return;
        }

        // TODO(b/200065274): Perform check on restricted handles.

        if enable {
            self.gatt.as_ref().unwrap().client.register_for_notification(
                client_id,
                &RawAddress::from_string(addr).unwrap(),
                handle as u16,
            );
        } else {
            self.gatt.as_ref().unwrap().client.deregister_for_notification(
                client_id,
                &RawAddress::from_string(addr).unwrap(),
                handle as u16,
            );
        }
    }

    fn begin_reliable_write(&mut self, _client_id: i32, addr: String) {
        self.reliable_queue.insert(addr);
    }

    fn end_reliable_write(&mut self, client_id: i32, addr: String, execute: bool) {
        self.reliable_queue.remove(&addr);

        let conn_id = self.context_map.get_conn_id_from_address(client_id, &addr);
        if conn_id.is_none() {
            return;
        }

        self.gatt
            .as_ref()
            .unwrap()
            .client
            .execute_write(conn_id.unwrap(), if execute { 1 } else { 0 });
    }

    fn read_remote_rssi(&self, client_id: i32, addr: String) {
        self.gatt
            .as_ref()
            .unwrap()
            .client
            .read_remote_rssi(client_id, &RawAddress::from_string(addr).unwrap());
    }

    fn configure_mtu(&self, client_id: i32, addr: String, mtu: i32) {
        let conn_id = self.context_map.get_conn_id_from_address(client_id, &addr);
        if conn_id.is_none() {
            return;
        }

        self.gatt.as_ref().unwrap().client.configure_mtu(conn_id.unwrap(), mtu);
    }

    fn connection_parameter_update(
        &self,
        _client_id: i32,
        addr: String,
        min_interval: i32,
        max_interval: i32,
        latency: i32,
        timeout: i32,
        min_ce_len: u16,
        max_ce_len: u16,
    ) {
        self.gatt.as_ref().unwrap().client.conn_parameter_update(
            &RawAddress::from_string(addr).unwrap(),
            min_interval,
            max_interval,
            latency,
            timeout,
            min_ce_len,
            max_ce_len,
        );
    }

    fn client_set_preferred_phy(
        &self,
        client_id: i32,
        address: String,
        tx_phy: LePhy,
        rx_phy: LePhy,
        phy_options: i32,
    ) {
        let conn_id = self.context_map.get_conn_id_from_address(client_id, &address);
        if conn_id.is_none() {
            return;
        }

        self.gatt.as_ref().unwrap().client.set_preferred_phy(
            &RawAddress::from_string(address).unwrap(),
            tx_phy.to_u8().unwrap(),
            rx_phy.to_u8().unwrap(),
            phy_options as u16,
        );
    }

    fn client_read_phy(&mut self, client_id: i32, addr: String) {
        let address = match RawAddress::from_string(addr.clone()) {
            None => return,
            Some(addr) => addr,
        };

        self.gatt.as_mut().unwrap().client.read_phy(client_id, &address);
    }
}

#[btif_callbacks_dispatcher(BluetoothGatt, dispatch_gatt_client_callbacks, GattClientCallbacks)]
pub(crate) trait BtifGattClientCallbacks {
    #[btif_callback(RegisterClient)]
    fn register_client_cb(&mut self, status: GattStatus, client_id: i32, app_uuid: Uuid);

    #[btif_callback(Connect)]
    fn connect_cb(&mut self, conn_id: i32, status: GattStatus, client_id: i32, addr: RawAddress);

    #[btif_callback(Disconnect)]
    fn disconnect_cb(&mut self, conn_id: i32, status: GattStatus, client_id: i32, addr: RawAddress);

    #[btif_callback(SearchComplete)]
    fn search_complete_cb(&mut self, conn_id: i32, status: GattStatus);

    #[btif_callback(RegisterForNotification)]
    fn register_for_notification_cb(
        &mut self,
        conn_id: i32,
        registered: i32,
        status: GattStatus,
        handle: u16,
    );

    #[btif_callback(Notify)]
    fn notify_cb(&mut self, conn_id: i32, data: BtGattNotifyParams);

    #[btif_callback(ReadCharacteristic)]
    fn read_characteristic_cb(&mut self, conn_id: i32, status: GattStatus, data: BtGattReadParams);

    #[btif_callback(WriteCharacteristic)]
    fn write_characteristic_cb(
        &mut self,
        conn_id: i32,
        status: GattStatus,
        handle: u16,
        len: u16,
        value: *const u8,
    );

    #[btif_callback(ReadDescriptor)]
    fn read_descriptor_cb(&mut self, conn_id: i32, status: GattStatus, data: BtGattReadParams);

    #[btif_callback(WriteDescriptor)]
    fn write_descriptor_cb(
        &mut self,
        conn_id: i32,
        status: GattStatus,
        handle: u16,
        len: u16,
        value: *const u8,
    );

    #[btif_callback(ExecuteWrite)]
    fn execute_write_cb(&mut self, conn_id: i32, status: GattStatus);

    #[btif_callback(ReadRemoteRssi)]
    fn read_remote_rssi_cb(
        &mut self,
        client_id: i32,
        addr: RawAddress,
        rssi: i32,
        status: GattStatus,
    );

    #[btif_callback(ConfigureMtu)]
    fn configure_mtu_cb(&mut self, conn_id: i32, status: GattStatus, mtu: i32);

    #[btif_callback(Congestion)]
    fn congestion_cb(&mut self, conn_id: i32, congested: bool);

    #[btif_callback(GetGattDb)]
    fn get_gatt_db_cb(&mut self, conn_id: i32, elements: Vec<BtGattDbElement>, count: i32);

    #[btif_callback(PhyUpdated)]
    fn phy_updated_cb(&mut self, conn_id: i32, tx_phy: u8, rx_phy: u8, status: GattStatus);

    #[btif_callback(ConnUpdated)]
    fn conn_updated_cb(
        &mut self,
        conn_id: i32,
        interval: u16,
        latency: u16,
        timeout: u16,
        status: GattStatus,
    );

    #[btif_callback(ServiceChanged)]
    fn service_changed_cb(&mut self, conn_id: i32);

    #[btif_callback(ReadPhy)]
    fn read_phy_cb(
        &mut self,
        client_id: i32,
        addr: RawAddress,
        tx_phy: u8,
        rx_phy: u8,
        status: GattStatus,
    );
}

impl BtifGattClientCallbacks for BluetoothGatt {
    fn register_client_cb(&mut self, status: GattStatus, client_id: i32, app_uuid: Uuid) {
        self.context_map.set_client_id(&app_uuid.uu, client_id);

        let client = self.context_map.get_by_uuid(&app_uuid.uu);
        match client {
            Some(c) => {
                let cbid = c.cbid;
                self.context_map.get_callback_from_callback_id(cbid).and_then(
                    |cb: &mut GattClientCallback| {
                        cb.on_client_registered(status, client_id);
                        Some(())
                    },
                );
            }
            None => {
                warn!("Warning: Client not registered for UUID {}", app_uuid);
            }
        }
    }

    fn connect_cb(&mut self, conn_id: i32, status: GattStatus, client_id: i32, addr: RawAddress) {
        if status == GattStatus::Success {
            self.context_map.add_connection(client_id, conn_id, &addr.to_string());
        }

        let client = self.context_map.get_by_client_id(client_id);
        if let Some(c) = client {
            let cbid = c.cbid;
            self.context_map.get_callback_from_callback_id(cbid).and_then(
                |cb: &mut GattClientCallback| {
                    cb.on_client_connection_state(
                        status,
                        client_id,
                        status == GattStatus::Success,
                        addr.to_string(),
                    );
                    Some(())
                },
            );
        }
    }

    fn disconnect_cb(
        &mut self,
        conn_id: i32,
        status: GattStatus,
        client_id: i32,
        addr: RawAddress,
    ) {
        self.context_map.remove_connection(client_id, conn_id);
        let client = self.context_map.get_by_client_id(client_id);
        if let Some(c) = client {
            let cbid = c.cbid;
            self.context_map.get_callback_from_callback_id(cbid).and_then(
                |cb: &mut GattClientCallback| {
                    cb.on_client_connection_state(
                        status,
                        client_id,
                        status == GattStatus::Success,
                        addr.to_string(),
                    );
                    Some(())
                },
            );
        }
    }

    fn search_complete_cb(&mut self, conn_id: i32, _status: GattStatus) {
        // Gatt DB is ready!
        self.gatt.as_ref().unwrap().client.get_gatt_db(conn_id);
    }

    fn register_for_notification_cb(
        &mut self,
        _conn_id: i32,
        _registered: i32,
        _status: GattStatus,
        _handle: u16,
    ) {
        // No-op.
    }

    fn notify_cb(&mut self, conn_id: i32, data: BtGattNotifyParams) {
        let client = self.context_map.get_client_by_conn_id(conn_id);
        if let Some(c) = client {
            let cbid = c.cbid;
            self.context_map.get_callback_from_callback_id(cbid).and_then(
                |cb: &mut GattClientCallback| {
                    cb.on_notify(
                        RawAddress { val: data.bda.address }.to_string(),
                        data.handle as i32,
                        data.value[0..data.len as usize].to_vec(),
                    );
                    Some(())
                },
            );
        }
    }

    fn read_characteristic_cb(&mut self, conn_id: i32, status: GattStatus, data: BtGattReadParams) {
        let address = self.context_map.get_address_by_conn_id(conn_id);
        if address.is_none() {
            return;
        }

        let client = self.context_map.get_client_by_conn_id(conn_id);
        if let Some(c) = client {
            let cbid = c.cbid;
            self.context_map.get_callback_from_callback_id(cbid).and_then(
                |cb: &mut GattClientCallback| {
                    cb.on_characteristic_read(
                        address.unwrap().to_string(),
                        status,
                        data.handle as i32,
                        data.value.value[0..data.value.len as usize].to_vec(),
                    );
                    Some(())
                },
            );
        }
    }

    fn write_characteristic_cb(
        &mut self,
        conn_id: i32,
        mut status: GattStatus,
        handle: u16,
        _len: u16,
        _value: *const u8,
    ) {
        let address = self.context_map.get_address_by_conn_id(conn_id);
        if address.is_none() {
            return;
        }

        // TODO(b/200070162): Design how to handle concurrent write characteristic to the same
        // peer.

        let client = self.context_map.get_client_by_conn_id_mut(conn_id);
        if client.is_none() {
            return;
        }

        match (client, address) {
            (Some(c), Some(addr)) => {
                if c.is_congested {
                    if status == GattStatus::Congested {
                        status = GattStatus::Success;
                    }

                    c.congestion_queue.push((addr.to_string(), status, handle as i32));
                    return;
                }

                let cbid = c.cbid;
                self.context_map.get_callback_from_callback_id(cbid).and_then(
                    |cb: &mut GattClientCallback| {
                        cb.on_characteristic_write(addr.to_string(), status, handle as i32);
                        Some(())
                    },
                );
            }
            _ => (),
        };
    }

    fn read_descriptor_cb(&mut self, conn_id: i32, status: GattStatus, data: BtGattReadParams) {
        let address = self.context_map.get_address_by_conn_id(conn_id);
        if address.is_none() {
            return;
        }

        let client = self.context_map.get_client_by_conn_id(conn_id);
        if let Some(c) = client {
            let cbid = c.cbid;
            self.context_map.get_callback_from_callback_id(cbid).and_then(
                |cb: &mut GattClientCallback| {
                    cb.on_descriptor_read(
                        address.unwrap().to_string(),
                        status,
                        data.handle as i32,
                        data.value.value[0..data.value.len as usize].to_vec(),
                    );
                    Some(())
                },
            );
        }
    }

    fn write_descriptor_cb(
        &mut self,
        conn_id: i32,
        status: GattStatus,
        handle: u16,
        _len: u16,
        _value: *const u8,
    ) {
        let address = self.context_map.get_address_by_conn_id(conn_id);
        if address.is_none() {
            return;
        }

        let client = self.context_map.get_client_by_conn_id(conn_id);
        if let Some(c) = client {
            let cbid = c.cbid;
            self.context_map.get_callback_from_callback_id(cbid).and_then(
                |cb: &mut GattClientCallback| {
                    cb.on_descriptor_write(address.unwrap().to_string(), status, handle as i32);
                    Some(())
                },
            );
        }
    }

    fn execute_write_cb(&mut self, conn_id: i32, status: GattStatus) {
        let address = self.context_map.get_address_by_conn_id(conn_id);
        if address.is_none() {
            return;
        }

        let client = self.context_map.get_client_by_conn_id(conn_id);
        if let Some(c) = client {
            let cbid = c.cbid;
            self.context_map.get_callback_from_callback_id(cbid).and_then(
                |cb: &mut GattClientCallback| {
                    cb.on_execute_write(address.unwrap().to_string(), status);
                    Some(())
                },
            );
        }
    }

    fn read_remote_rssi_cb(
        &mut self,
        client_id: i32,
        addr: RawAddress,
        rssi: i32,
        status: GattStatus,
    ) {
        let client = self.context_map.get_by_client_id(client_id);
        if let Some(c) = client {
            let cbid = c.cbid;
            self.context_map.get_callback_from_callback_id(cbid).and_then(
                |cb: &mut GattClientCallback| {
                    cb.on_read_remote_rssi(addr.to_string(), rssi, status);
                    Some(())
                },
            );
        }
    }

    fn configure_mtu_cb(&mut self, conn_id: i32, status: GattStatus, mtu: i32) {
        let client = self.context_map.get_client_by_conn_id(conn_id);
        let addr = self.context_map.get_address_by_conn_id(conn_id);

        match (client, addr) {
            (Some(c), Some(addr)) => {
                let cbid = c.cbid;
                self.context_map.get_callback_from_callback_id(cbid).and_then(
                    |cb: &mut GattClientCallback| {
                        cb.on_configure_mtu(addr, mtu, status);
                        Some(())
                    },
                );
            }
            _ => (),
        };
    }

    fn congestion_cb(&mut self, conn_id: i32, congested: bool) {
        if let Some(mut client) = self.context_map.get_client_by_conn_id_mut(conn_id) {
            client.is_congested = congested;
            if !client.is_congested {
                let cbid = client.cbid;
                let mut congestion_queue: Vec<(String, GattStatus, i32)> = vec![];
                client.congestion_queue.retain(|v| {
                    congestion_queue.push(v.clone());
                    false
                });

                self.context_map.get_callback_from_callback_id(cbid).and_then(
                    |cb: &mut GattClientCallback| {
                        for callback in congestion_queue.iter() {
                            cb.on_characteristic_write(callback.0.clone(), callback.1, callback.2);
                        }
                        Some(())
                    },
                );
            }
        }
    }

    fn get_gatt_db_cb(&mut self, conn_id: i32, elements: Vec<BtGattDbElement>, _count: i32) {
        let address = self.context_map.get_address_by_conn_id(conn_id);
        if address.is_none() {
            return;
        }

        let client = self.context_map.get_client_by_conn_id(conn_id);
        if client.is_none() {
            return;
        }

        let mut db_out: Vec<BluetoothGattService> = vec![];

        for elem in elements {
            match GattDbElementType::from_u32(elem.type_).unwrap() {
                GattDbElementType::PrimaryService | GattDbElementType::SecondaryService => {
                    db_out.push(BluetoothGattService::new(
                        elem.uuid.uu,
                        elem.id as i32,
                        elem.type_ as i32,
                    ));
                    // TODO(b/200065274): Mark restricted services.
                }

                GattDbElementType::Characteristic => {
                    match db_out.last_mut() {
                        Some(s) => s.characteristics.push(BluetoothGattCharacteristic::new(
                            elem.uuid.uu,
                            elem.id as i32,
                            elem.properties as i32,
                            0,
                        )),
                        None => {
                            // TODO(b/193685325): Log error.
                        }
                    }
                    // TODO(b/200065274): Mark restricted characteristics.
                }

                GattDbElementType::Descriptor => {
                    match db_out.last_mut() {
                        Some(s) => match s.characteristics.last_mut() {
                            Some(c) => c.descriptors.push(BluetoothGattDescriptor::new(
                                elem.uuid.uu,
                                elem.id as i32,
                                0,
                            )),
                            None => {
                                // TODO(b/193685325): Log error.
                            }
                        },
                        None => {
                            // TODO(b/193685325): Log error.
                        }
                    }
                    // TODO(b/200065274): Mark restricted descriptors.
                }

                GattDbElementType::IncludedService => {
                    match db_out.last_mut() {
                        Some(s) => {
                            s.included_services.push(BluetoothGattService::new(
                                elem.uuid.uu,
                                elem.id as i32,
                                elem.type_ as i32,
                            ));
                        }
                        None => {
                            // TODO(b/193685325): Log error.
                        }
                    }
                }
            }
        }

        match (client, address) {
            (Some(c), Some(addr)) => {
                let cbid = c.cbid;
                self.context_map.get_callback_from_callback_id(cbid).and_then(
                    |cb: &mut GattClientCallback| {
                        cb.on_search_complete(addr.to_string(), db_out, GattStatus::Success);
                        Some(())
                    },
                );
            }
            _ => (),
        };
    }

    fn phy_updated_cb(&mut self, conn_id: i32, tx_phy: u8, rx_phy: u8, status: GattStatus) {
        let client = self.context_map.get_client_by_conn_id(conn_id);
        if client.is_none() {
            return;
        }

        let address = self.context_map.get_address_by_conn_id(conn_id);
        if address.is_none() {
            return;
        }
        match (client, address) {
            (Some(c), Some(addr)) => {
                let cbid = c.cbid;
                self.context_map.get_callback_from_callback_id(cbid).and_then(
                    |cb: &mut GattClientCallback| {
                        cb.on_phy_update(
                            addr,
                            LePhy::from_u8(tx_phy).unwrap(),
                            LePhy::from_u8(rx_phy).unwrap(),
                            status,
                        );
                        Some(())
                    },
                );
            }
            _ => (),
        };
    }

    fn read_phy_cb(
        &mut self,
        client_id: i32,
        addr: RawAddress,
        tx_phy: u8,
        rx_phy: u8,
        status: GattStatus,
    ) {
        let client = self.context_map.get_by_client_id(client_id);
        if client.is_none() {
            return;
        }

        if let Some(c) = client {
            let cbid = c.cbid;
            self.context_map.get_callback_from_callback_id(cbid).and_then(
                |cb: &mut GattClientCallback| {
                    cb.on_phy_read(
                        addr.to_string(),
                        LePhy::from_u8(tx_phy).unwrap(),
                        LePhy::from_u8(rx_phy).unwrap(),
                        status,
                    );
                    Some(())
                },
            );
        }
    }

    fn conn_updated_cb(
        &mut self,
        conn_id: i32,
        interval: u16,
        latency: u16,
        timeout: u16,
        status: GattStatus,
    ) {
        let client = self.context_map.get_client_by_conn_id(conn_id);
        if client.is_none() {
            return;
        }

        let address = self.context_map.get_address_by_conn_id(conn_id);
        if address.is_none() {
            return;
        }

        match (client, address) {
            (Some(c), Some(addr)) => {
                let cbid = c.cbid;
                self.context_map.get_callback_from_callback_id(cbid).and_then(
                    |cb: &mut GattClientCallback| {
                        cb.on_connection_updated(
                            addr,
                            interval as i32,
                            latency as i32,
                            timeout as i32,
                            status,
                        );
                        Some(())
                    },
                );
            }
            _ => (),
        };
    }

    fn service_changed_cb(&mut self, conn_id: i32) {
        let address = self.context_map.get_address_by_conn_id(conn_id);
        if address.is_none() {
            return;
        }

        let client = self.context_map.get_client_by_conn_id(conn_id);
        if client.is_none() {
            return;
        }

        match (client, address) {
            (Some(c), Some(addr)) => {
                let cbid = c.cbid;
                self.context_map.get_callback_from_callback_id(cbid).and_then(
                    |cb: &mut GattClientCallback| {
                        cb.on_service_changed(addr);
                        Some(())
                    },
                );
            }
            _ => (),
        };
    }
}

#[btif_callbacks_dispatcher(BluetoothGatt, dispatch_le_scanner_callbacks, GattScannerCallbacks)]
pub(crate) trait BtifGattScannerCallbacks {
    #[btif_callback(OnScannerRegistered)]
    fn on_scanner_registered(&mut self, uuid: Uuid, scanner_id: u8, status: GattStatus);

    #[btif_callback(OnScanResult)]
    fn on_scan_result(
        &mut self,
        event_type: u16,
        addr_type: u8,
        bda: RawAddress,
        primary_phy: u8,
        secondary_phy: u8,
        advertising_sid: u8,
        tx_power: i8,
        rssi: i8,
        periodic_adv_int: u16,
        adv_data: Vec<u8>,
    );
}

#[btif_callbacks_dispatcher(
    BluetoothGatt,
    dispatch_le_scanner_inband_callbacks,
    GattScannerInbandCallbacks
)]
pub(crate) trait BtifGattScannerInbandCallbacks {
    #[btif_callback(RegisterCallback)]
    fn inband_register_callback(&mut self, app_uuid: Uuid, scanner_id: u8, btm_status: u8);

    #[btif_callback(StatusCallback)]
    fn inband_status_callback(&mut self, scanner_id: u8, btm_status: u8);

    #[btif_callback(EnableCallback)]
    fn inband_enable_callback(&mut self, action: u8, btm_status: u8);

    #[btif_callback(FilterParamSetupCallback)]
    fn inband_filter_param_setup_callback(
        &mut self,
        scanner_id: u8,
        available_space: u8,
        action_type: u8,
        btm_status: u8,
    );

    #[btif_callback(FilterConfigCallback)]
    fn inband_filter_config_callback(
        &mut self,
        filter_index: u8,
        filter_type: u8,
        available_space: u8,
        action: u8,
        btm_status: u8,
    );

    #[btif_callback(StartSyncCallback)]
    fn inband_start_sync_callback(
        &mut self,
        status: u8,
        sync_handle: u16,
        advertising_sid: u8,
        address_type: u8,
        address: RawAddress,
        phy: u8,
        interval: u16,
    );

    #[btif_callback(SyncReportCallback)]
    fn inband_sync_report_callback(
        &mut self,
        sync_handle: u16,
        tx_power: i8,
        rssi: i8,
        status: u8,
        data: Vec<u8>,
    );

    #[btif_callback(SyncLostCallback)]
    fn inband_sync_lost_callback(&mut self, sync_handle: u16);

    #[btif_callback(SyncTransferCallback)]
    fn inband_sync_transfer_callback(&mut self, status: u8, address: RawAddress);
}

impl BtifGattScannerInbandCallbacks for BluetoothGatt {
    fn inband_register_callback(&mut self, app_uuid: Uuid, scanner_id: u8, btm_status: u8) {
        log::debug!(
            "Callback received: {:#?}",
            GattScannerInbandCallbacks::RegisterCallback(app_uuid, scanner_id, btm_status)
        );
    }

    fn inband_status_callback(&mut self, scanner_id: u8, btm_status: u8) {
        log::debug!(
            "Callback received: {:#?}",
            GattScannerInbandCallbacks::StatusCallback(scanner_id, btm_status)
        );
    }

    fn inband_enable_callback(&mut self, action: u8, btm_status: u8) {
        log::debug!(
            "Callback received: {:#?}",
            GattScannerInbandCallbacks::EnableCallback(action, btm_status)
        );
    }

    fn inband_filter_param_setup_callback(
        &mut self,
        scanner_id: u8,
        available_space: u8,
        action_type: u8,
        btm_status: u8,
    ) {
        log::debug!(
            "Callback received: {:#?}",
            GattScannerInbandCallbacks::FilterParamSetupCallback(
                scanner_id,
                available_space,
                action_type,
                btm_status
            )
        );
    }

    fn inband_filter_config_callback(
        &mut self,
        filter_index: u8,
        filter_type: u8,
        available_space: u8,
        action: u8,
        btm_status: u8,
    ) {
        log::debug!(
            "Callback received: {:#?}",
            GattScannerInbandCallbacks::FilterConfigCallback(
                filter_index,
                filter_type,
                available_space,
                action,
                btm_status,
            )
        );
    }

    fn inband_start_sync_callback(
        &mut self,
        status: u8,
        sync_handle: u16,
        advertising_sid: u8,
        address_type: u8,
        address: RawAddress,
        phy: u8,
        interval: u16,
    ) {
        log::debug!(
            "Callback received: {:#?}",
            GattScannerInbandCallbacks::StartSyncCallback(
                status,
                sync_handle,
                advertising_sid,
                address_type,
                address,
                phy,
                interval,
            )
        );
    }

    fn inband_sync_report_callback(
        &mut self,
        sync_handle: u16,
        tx_power: i8,
        rssi: i8,
        status: u8,
        data: Vec<u8>,
    ) {
        log::debug!(
            "Callback received: {:#?}",
            GattScannerInbandCallbacks::SyncReportCallback(
                sync_handle,
                tx_power,
                rssi,
                status,
                data
            )
        );
    }

    fn inband_sync_lost_callback(&mut self, sync_handle: u16) {
        log::debug!(
            "Callback received: {:#?}",
            GattScannerInbandCallbacks::SyncLostCallback(sync_handle,)
        );
    }

    fn inband_sync_transfer_callback(&mut self, status: u8, address: RawAddress) {
        log::debug!(
            "Callback received: {:#?}",
            GattScannerInbandCallbacks::SyncTransferCallback(status, address)
        );
    }
}

impl BtifGattScannerCallbacks for BluetoothGatt {
    fn on_scanner_registered(&mut self, uuid: Uuid, scanner_id: u8, status: GattStatus) {
        log::debug!(
            "on_scanner_registered UUID = {}, scanner_id = {}, status = {}",
            uuid,
            scanner_id,
            status
        );

        if status != GattStatus::Success {
            log::error!("Error registering scanner UUID {}", uuid);
            self.scanners.remove(&uuid);
            return;
        }

        let scanner_info = self.scanners.get_mut(&uuid);

        if let Some(info) = scanner_info {
            info.scanner_id = Some(scanner_id);
            let callback = self.scanner_callbacks.get_by_id(info.callback_id);
            if let Some(cb) = callback {
                cb.on_scanner_registered(uuid.uu, scanner_id, status);
            } else {
                log::warn!("There is no callback for scanner UUID {}", uuid);
            }
        } else {
            log::warn!(
                "Scanner registered callback for non-existent scanner info, UUID = {}",
                uuid
            );
        }
    }

    fn on_scan_result(
        &mut self,
        event_type: u16,
        addr_type: u8,
        address: RawAddress,
        primary_phy: u8,
        secondary_phy: u8,
        advertising_sid: u8,
        tx_power: i8,
        rssi: i8,
        periodic_adv_int: u16,
        adv_data: Vec<u8>,
    ) {
        self.scanner_callbacks.for_all_callbacks(|callback| {
            callback.on_scan_result(ScanResult {
                address: address.to_string(),
                addr_type,
                event_type,
                primary_phy,
                secondary_phy,
                advertising_sid,
                tx_power,
                rssi,
                periodic_adv_int,
                adv_data: adv_data.clone(),
            });
        });
    }
}

#[btif_callbacks_dispatcher(BluetoothGatt, dispatch_le_adv_callbacks, GattAdvCallbacks)]
pub(crate) trait BtifGattAdvCallbacks {
    #[btif_callback(OnAdvertisingSetStarted)]
    fn on_advertising_set_started(
        &mut self,
        reg_id: i32,
        advertiser_id: u8,
        tx_power: i8,
        status: GattStatus,
    );

    #[btif_callback(OnAdvertisingEnabled)]
    fn on_advertising_enabled(&mut self, adv_id: u8, enabled: bool, status: GattStatus);

    #[btif_callback(OnAdvertisingDataSet)]
    fn on_advertising_data_set(&mut self, adv_id: u8, status: GattStatus);

    #[btif_callback(OnScanResponseDataSet)]
    fn on_scan_response_data_set(&mut self, adv_id: u8, status: GattStatus);

    #[btif_callback(OnAdvertisingParametersUpdated)]
    fn on_advertising_parameters_updated(&mut self, adv_id: u8, tx_power: i8, status: GattStatus);

    #[btif_callback(OnPeriodicAdvertisingParametersUpdated)]
    fn on_periodic_advertising_parameters_updated(&mut self, adv_id: u8, status: GattStatus);

    #[btif_callback(OnPeriodicAdvertisingDataSet)]
    fn on_periodic_advertising_data_set(&mut self, adv_id: u8, status: GattStatus);

    #[btif_callback(OnPeriodicAdvertisingEnabled)]
    fn on_periodic_advertising_enabled(&mut self, adv_id: u8, enabled: bool, status: GattStatus);

    #[btif_callback(OnOwnAddressRead)]
    fn on_own_address_read(&mut self, adv_id: u8, addr_type: u8, address: RawAddress);
}

impl BtifGattAdvCallbacks for BluetoothGatt {
    fn on_advertising_set_started(
        &mut self,
        reg_id: i32,
        advertiser_id: u8,
        tx_power: i8,
        status: GattStatus,
    ) {
        debug!(
            "on_advertising_set_started(): reg_id = {}, advertiser_id = {}, tx_power = {}, status = {:?}",
            reg_id, advertiser_id, tx_power, status
        );

        if let Some(s) = self.advertisers.get_mut_by_reg_id(reg_id) {
            s.advertiser_id = Some(advertiser_id.into());
        } else {
            return;
        }
        let s = self.advertisers.get_mut_by_reg_id(reg_id).unwrap().clone();

        if let Some(cb) = self.advertisers.get_callback(&s) {
            cb.on_advertising_set_started(reg_id, advertiser_id.into(), tx_power.into(), status);
        }

        if status != GattStatus::Success {
            warn!(
                "on_advertising_set_started(): failed! reg_id = {}, status = {:?}",
                reg_id, status
            );
            self.advertisers.remove_by_reg_id(reg_id);
        }
    }

    fn on_advertising_enabled(&mut self, adv_id: u8, enabled: bool, status: GattStatus) {
        debug!(
            "on_advertising_enabled(): adv_id = {}, enabled = {}, status = {:?}",
            adv_id, enabled, status
        );

        let advertiser_id: i32 = adv_id.into();
        if None == self.advertisers.get_by_advertiser_id(advertiser_id) {
            return;
        }
        let s = self.advertisers.get_by_advertiser_id(advertiser_id).unwrap().clone();

        if let Some(cb) = self.advertisers.get_callback(&s) {
            cb.on_advertising_enabled(advertiser_id, enabled, status);
        }
    }

    fn on_advertising_data_set(&mut self, adv_id: u8, status: GattStatus) {
        debug!("on_advertising_data_set(): adv_id = {}, status = {:?}", adv_id, status);

        let advertiser_id: i32 = adv_id.into();
        if None == self.advertisers.get_by_advertiser_id(advertiser_id) {
            return;
        }
        let s = self.advertisers.get_by_advertiser_id(advertiser_id).unwrap().clone();

        if let Some(cb) = self.advertisers.get_callback(&s) {
            cb.on_advertising_data_set(advertiser_id, status);
        }
    }

    fn on_scan_response_data_set(&mut self, adv_id: u8, status: GattStatus) {
        debug!("on_scan_response_data_set(): adv_id = {}, status = {:?}", adv_id, status);

        let advertiser_id: i32 = adv_id.into();
        if None == self.advertisers.get_by_advertiser_id(advertiser_id) {
            return;
        }
        let s = self.advertisers.get_by_advertiser_id(advertiser_id).unwrap().clone();

        if let Some(cb) = self.advertisers.get_callback(&s) {
            cb.on_scan_response_data_set(advertiser_id, status);
        }
    }

    fn on_advertising_parameters_updated(&mut self, adv_id: u8, tx_power: i8, status: GattStatus) {
        debug!(
            "on_advertising_parameters_updated(): adv_id = {}, tx_power = {}, status = {:?}",
            adv_id, tx_power, status
        );

        let advertiser_id: i32 = adv_id.into();
        if None == self.advertisers.get_by_advertiser_id(advertiser_id) {
            return;
        }
        let s = self.advertisers.get_by_advertiser_id(advertiser_id).unwrap().clone();

        if let Some(cb) = self.advertisers.get_callback(&s) {
            cb.on_advertising_parameters_updated(advertiser_id, tx_power.into(), status);
        }
    }

    fn on_periodic_advertising_parameters_updated(&mut self, adv_id: u8, status: GattStatus) {
        debug!(
            "on_periodic_advertising_parameters_updated(): adv_id = {}, status = {:?}",
            adv_id, status
        );

        let advertiser_id: i32 = adv_id.into();
        if None == self.advertisers.get_by_advertiser_id(advertiser_id) {
            return;
        }
        let s = self.advertisers.get_by_advertiser_id(advertiser_id).unwrap().clone();

        if let Some(cb) = self.advertisers.get_callback(&s) {
            cb.on_periodic_advertising_parameters_updated(advertiser_id, status);
        }
    }

    fn on_periodic_advertising_data_set(&mut self, adv_id: u8, status: GattStatus) {
        debug!("on_periodic_advertising_data_set(): adv_id = {}, status = {:?}", adv_id, status);

        let advertiser_id: i32 = adv_id.into();
        if None == self.advertisers.get_by_advertiser_id(advertiser_id) {
            return;
        }
        let s = self.advertisers.get_by_advertiser_id(advertiser_id).unwrap().clone();

        if let Some(cb) = self.advertisers.get_callback(&s) {
            cb.on_periodic_advertising_data_set(advertiser_id, status);
        }
    }

    fn on_periodic_advertising_enabled(&mut self, adv_id: u8, enabled: bool, status: GattStatus) {
        debug!(
            "on_periodic_advertising_enabled(): adv_id = {}, enabled = {}, status = {:?}",
            adv_id, enabled, status
        );

        let advertiser_id: i32 = adv_id.into();
        if None == self.advertisers.get_by_advertiser_id(advertiser_id) {
            return;
        }
        let s = self.advertisers.get_by_advertiser_id(advertiser_id).unwrap().clone();

        if let Some(cb) = self.advertisers.get_callback(&s) {
            cb.on_periodic_advertising_enabled(advertiser_id, enabled, status);
        }
    }

    fn on_own_address_read(&mut self, adv_id: u8, addr_type: u8, address: RawAddress) {
        debug!(
            "on_own_address_read(): adv_id = {}, addr_type = {}, address = {:?}",
            adv_id, addr_type, address
        );

        let advertiser_id: i32 = adv_id.into();
        if None == self.advertisers.get_by_advertiser_id(advertiser_id) {
            return;
        }
        let s = self.advertisers.get_by_advertiser_id(advertiser_id).unwrap().clone();

        if let Some(cb) = self.advertisers.get_callback(&s) {
            cb.on_own_address_read(advertiser_id, addr_type.into(), address.to_string());
        }
    }
}

#[cfg(test)]
mod tests {
    struct TestBluetoothGattCallback {
        id: String,
    }

    impl TestBluetoothGattCallback {
        fn new(id: String) -> TestBluetoothGattCallback {
            TestBluetoothGattCallback { id }
        }
    }

    impl IBluetoothGattCallback for TestBluetoothGattCallback {
        fn on_client_registered(&self, _status: GattStatus, _client_id: i32) {}
        fn on_client_connection_state(
            &self,
            _status: GattStatus,
            _client_id: i32,
            _connected: bool,
            _addr: String,
        ) {
        }

        fn on_phy_update(
            &self,
            _addr: String,
            _tx_phy: LePhy,
            _rx_phy: LePhy,
            _status: GattStatus,
        ) {
        }

        fn on_phy_read(&self, _addr: String, _tx_phy: LePhy, _rx_phy: LePhy, _status: GattStatus) {}

        fn on_search_complete(
            &self,
            _addr: String,
            _services: Vec<BluetoothGattService>,
            _status: GattStatus,
        ) {
        }

        fn on_characteristic_read(
            &self,
            _addr: String,
            _status: GattStatus,
            _handle: i32,
            _value: Vec<u8>,
        ) {
        }

        fn on_characteristic_write(&self, _addr: String, _status: GattStatus, _handle: i32) {}

        fn on_execute_write(&self, _addr: String, _status: GattStatus) {}

        fn on_descriptor_read(
            &self,
            _addr: String,
            _status: GattStatus,
            _handle: i32,
            _value: Vec<u8>,
        ) {
        }

        fn on_descriptor_write(&self, _addr: String, _status: GattStatus, _handle: i32) {}

        fn on_notify(&self, _addr: String, _handle: i32, _value: Vec<u8>) {}

        fn on_read_remote_rssi(&self, _addr: String, _rssi: i32, _status: GattStatus) {}

        fn on_configure_mtu(&self, _addr: String, _mtu: i32, _status: GattStatus) {}

        fn on_connection_updated(
            &self,
            _addr: String,
            _interval: i32,
            _latency: i32,
            _timeout: i32,
            _status: GattStatus,
        ) {
        }

        fn on_service_changed(&self, _addr: String) {}
    }

    impl RPCProxy for TestBluetoothGattCallback {
        fn get_object_id(&self) -> String {
            self.id.clone()
        }
    }

    use super::*;

    #[test]
    fn test_uuid_from_string() {
        let uuid = parse_uuid_string("abcdef");
        assert!(uuid.is_none());

        let uuid = parse_uuid_string("0123456789abcdef0123456789abcdef");
        assert!(uuid.is_some());
        let expected: [u8; 16] = [
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab,
            0xcd, 0xef,
        ];
        assert_eq!(Uuid { uu: expected }, uuid.unwrap());
    }

    #[test]
    fn test_context_map_clients() {
        let (tx, _rx) = crate::Stack::create_channel();
        let mut map = ContextMap::new(tx.clone());

        // Add client 1.
        let callback1 = Box::new(TestBluetoothGattCallback::new(String::from("Callback 1")));
        let uuid1 = parse_uuid_string("00000000000000000000000000000001").unwrap().uu;
        map.add(&uuid1, callback1);
        let found = map.get_by_uuid(&uuid1);
        assert!(found.is_some());
        assert_eq!(
            "Callback 1",
            match found {
                Some(c) => {
                    let cbid = c.cbid;
                    map.callbacks
                        .get_by_id(cbid)
                        .and_then(|cb| Some(cb.get_object_id()))
                        .unwrap_or(String::new())
                }
                None => String::new(),
            }
        );

        // Add client 2.
        let callback2 = Box::new(TestBluetoothGattCallback::new(String::from("Callback 2")));
        let uuid2 = parse_uuid_string("00000000000000000000000000000002").unwrap().uu;
        map.add(&uuid2, callback2);
        let found = map.get_by_uuid(&uuid2);
        assert!(found.is_some());
        assert_eq!(
            "Callback 2",
            match found {
                Some(c) => {
                    let cbid = c.cbid;
                    map.callbacks
                        .get_by_id(cbid)
                        .and_then(|cb| Some(cb.get_object_id()))
                        .unwrap_or(String::new())
                }
                None => String::new(),
            }
        );

        // Set client ID and get by client ID.
        map.set_client_id(&uuid1, 3);
        let found = map.get_by_client_id(3);
        assert!(found.is_some());

        // Remove client 1.
        map.remove(3);
        let found = map.get_by_uuid(&uuid1);
        assert!(found.is_none());
    }

    #[test]
    fn test_context_map_connections() {
        let (tx, _rx) = crate::Stack::create_channel();
        let mut map = ContextMap::new(tx.clone());
        let client_id = 1;

        map.add_connection(client_id, 3, &String::from("aa:bb:cc:dd:ee:ff"));
        map.add_connection(client_id, 4, &String::from("11:22:33:44:55:66"));

        let found = map.get_conn_id_from_address(client_id, &String::from("aa:bb:cc:dd:ee:ff"));
        assert!(found.is_some());
        assert_eq!(3, found.unwrap());

        let found = map.get_conn_id_from_address(client_id, &String::from("11:22:33:44:55:66"));
        assert!(found.is_some());
        assert_eq!(4, found.unwrap());
    }
}
