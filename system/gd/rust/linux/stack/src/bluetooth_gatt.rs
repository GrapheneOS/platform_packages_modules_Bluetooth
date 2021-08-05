//! Anything related to the GATT API (IBluetoothGatt).

use btif_macros::{btif_callback, btif_callbacks_dispatcher};

use bt_topshim::bindings::root::bluetooth::Uuid;
use bt_topshim::btif::{BluetoothInterface, RawAddress};
use bt_topshim::profiles::gatt::{
    Gatt, GattClientCallbacks, GattClientCallbacksDispatcher, GattServerCallbacksDispatcher,
    GattStatus,
};
use bt_topshim::topstack;

use num_traits::cast::{FromPrimitive, ToPrimitive};

use std::sync::{Arc, Mutex};

use tokio::sync::mpsc::Sender;

use crate::{Message, RPCProxy};

struct Client {
    id: Option<i32>,
    uuid: Uuid128Bit,
    callback: Box<dyn IBluetoothGattCallback + Send>,
}

struct Connection {
    conn_id: i32,
    address: String,
    client_id: i32,
}

struct ContextMap {
    // TODO(b/196635530): Consider using `multimap` for a more efficient implementation of get by
    // multiple keys.
    clients: Vec<Client>,
    connections: Vec<Connection>,
}

impl ContextMap {
    fn new() -> ContextMap {
        ContextMap { clients: vec![], connections: vec![] }
    }

    fn get_by_uuid(&self, uuid: &Uuid128Bit) -> Option<&Client> {
        self.clients.iter().find(|client| client.uuid == *uuid)
    }

    fn get_by_client_id(&self, client_id: i32) -> Option<&Client> {
        self.clients.iter().find(|client| client.id.is_some() && client.id.unwrap() == client_id)
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

    fn add(&mut self, uuid: &Uuid128Bit, callback: Box<dyn IBluetoothGattCallback + Send>) {
        if self.get_by_uuid(uuid).is_some() {
            return;
        }

        self.clients.push(Client { id: None, uuid: uuid.clone(), callback });
    }

    fn remove(&mut self, id: i32) {
        self.clients.retain(|client| !(client.id.is_some() && client.id.unwrap() == id));
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
}

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
    fn unregister_client(&mut self, client_id: i32);

    /// Initiates a GATT connection to a peer device.
    fn client_connect(
        &self,
        client_id: i32,
        addr: String,
        is_direct: bool,
        transport: i32,
        opportunistic: bool,
        phy: i32,
    );

    /// Disconnects a GATT connection.
    fn client_disconnect(&self, client_id: i32, addr: String);

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
        write_type: i32,
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

    /// Requests RSSI for a given remote device.
    fn read_remote_rssi(&self, client_id: i32, addr: String);

    /// Configures the MTU of a given connection.
    fn configure_mtu(&self, client_id: i32, addr: String, mtu: i32);
}

/// Callback for GATT Client API.
pub trait IBluetoothGattCallback: RPCProxy {
    /// When the `register_client` request is done.
    fn on_client_registered(&self, status: i32, client_id: i32);

    /// When there is a change in the state of a GATT client connection.
    fn on_client_connection_state(
        &self,
        status: i32,
        client_id: i32,
        connected: bool,
        addr: String,
    );

    /// When there is a change of PHY.
    fn on_phy_update(&self, addr: String, tx_phy: LePhy, rx_phy: LePhy, status: GattStatus);

    /// The completion of IBluetoothGatt::read_phy.
    fn on_phy_read(&self, addr: String, tx_phy: LePhy, rx_phy: LePhy, status: GattStatus);

    /// The completion of IBluetoothGatt::read_remote_rssi.
    fn on_read_remote_rssi(&self, addr: String, rssi: i32, status: i32);

    /// The completion of IBluetoothGatt::configure_mtu.
    fn on_configure_mtu(&self, addr: String, mtu: i32, status: i32);
}

/// Interface for scanner callbacks to clients, passed to `IBluetoothGatt::register_scanner`.
pub trait IScannerCallback {
    /// When the `register_scanner` request is done.
    fn on_scanner_registered(&self, status: i32, scanner_id: i32);
}

#[derive(Debug, FromPrimitive, ToPrimitive)]
#[repr(u8)]
/// Represents LE PHY.
pub enum LePhy {
    Invalid = 0,
    Phy1m = 1,
    Phy2m = 2,
    PhyCoded = 3,
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

    context_map: ContextMap,
}

impl BluetoothGatt {
    /// Constructs a new IBluetoothGatt implementation.
    pub fn new(intf: Arc<Mutex<BluetoothInterface>>) -> BluetoothGatt {
        BluetoothGatt { intf: intf, gatt: None, context_map: ContextMap::new() }
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
fn parse_uuid_string<T: Into<String>>(uuid: T) -> Option<Uuid> {
    let uuid = uuid.into();

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

#[derive(Debug, FromPrimitive, ToPrimitive)]
#[repr(u8)]
/// Status of WriteCharacteristic methods.
pub enum GattWriteRequestStatus {
    Success = 0,
    Fail = 1,
    Busy = 2,
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
        transport: i32,
        opportunistic: bool,
        phy: i32,
    ) {
        let address = match RawAddress::from_string(addr.clone()) {
            None => return,
            Some(addr) => addr,
        };

        self.gatt.as_ref().unwrap().client.connect(
            client_id,
            &address,
            is_direct,
            transport,
            opportunistic,
            phy,
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

        // TODO(b/193685325): Perform check on restricted handles.

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

        // TODO(b/193685325): Perform check on restricted handles.

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
        write_type: i32,
        auth_req: i32,
        value: Vec<u8>,
    ) -> GattWriteRequestStatus {
        let conn_id = self.context_map.get_conn_id_from_address(client_id, &addr);
        if conn_id.is_none() {
            return GattWriteRequestStatus::Fail;
        }

        // TODO(b/193685325): Check for reliable write type.

        // TODO(b/193685325): Perform check on restricted handles.

        // TODO(b/193685325): Lock the thread until onCharacteristicWrite callback comes back?

        self.gatt.as_ref().unwrap().client.write_characteristic(
            conn_id.unwrap(),
            handle as u16,
            write_type,
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

        // TODO(b/193685325): Perform check on restricted handles.

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

        // TODO(b/193685325): Perform check on restricted handles.

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

        // TODO(b/193685325): Perform check on restricted handles.

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
}

#[btif_callbacks_dispatcher(BluetoothGatt, dispatch_gatt_client_callbacks, GattClientCallbacks)]
pub(crate) trait BtifGattClientCallbacks {
    #[btif_callback(RegisterClient)]
    fn register_client_cb(&mut self, status: i32, client_id: i32, app_uuid: Uuid);

    #[btif_callback(Connect)]
    fn connect_cb(&mut self, conn_id: i32, status: i32, client_id: i32, addr: RawAddress);

    #[btif_callback(ReadRemoteRssi)]
    fn read_remote_rssi_cb(&mut self, client_id: i32, addr: RawAddress, rssi: i32, status: i32);

    #[btif_callback(ConfigureMtu)]
    fn configure_mtu_cb(&mut self, conn_id: i32, status: i32, mtu: i32);

    #[btif_callback(PhyUpdated)]
    fn phy_updated_cb(&mut self, conn_id: i32, tx_phy: u8, rx_phy: u8, status: u8);

    #[btif_callback(ReadPhy)]
    fn read_phy_cb(&mut self, client_id: i32, addr: RawAddress, tx_phy: u8, rx_phy: u8, status: u8);

    // TODO(b/193685325): Define all callbacks.
}

impl BtifGattClientCallbacks for BluetoothGatt {
    fn register_client_cb(&mut self, status: i32, client_id: i32, app_uuid: Uuid) {
        self.context_map.set_client_id(&app_uuid.uu, client_id);

        let client = self.context_map.get_by_uuid(&app_uuid.uu);
        if client.is_none() {
            println!("Warning: Client not registered for UUID {:?}", app_uuid.uu);
            return;
        }

        let callback = &client.unwrap().callback;
        callback.on_client_registered(status, client_id);
    }

    fn connect_cb(&mut self, conn_id: i32, status: i32, client_id: i32, addr: RawAddress) {
        if status == 0 {
            self.context_map.add_connection(client_id, conn_id, &addr.to_string());
        }

        let client = self.context_map.get_by_client_id(client_id);
        if client.is_none() {
            return;
        }

        client.unwrap().callback.on_client_connection_state(
            status,
            client_id,
            match GattStatus::from_i32(status) {
                None => false,
                Some(gatt_status) => gatt_status == GattStatus::Success,
            },
            addr.to_string(),
        );
    }

    fn read_remote_rssi_cb(&mut self, client_id: i32, addr: RawAddress, rssi: i32, status: i32) {
        let client = self.context_map.get_by_client_id(client_id);
        if client.is_none() {
            return;
        }

        client.unwrap().callback.on_read_remote_rssi(addr.to_string(), rssi, status);
    }

    fn configure_mtu_cb(&mut self, conn_id: i32, status: i32, mtu: i32) {
        let client = self.context_map.get_client_by_conn_id(conn_id);
        if client.is_none() {
            return;
        }

        let addr = self.context_map.get_address_by_conn_id(conn_id);
        if addr.is_none() {
            return;
        }

        client.unwrap().callback.on_configure_mtu(addr.unwrap(), mtu, status);
    }

    fn phy_updated_cb(&mut self, conn_id: i32, tx_phy: u8, rx_phy: u8, status: u8) {
        let client = self.context_map.get_client_by_conn_id(conn_id);
        if client.is_none() {
            return;
        }

        let address = self.context_map.get_address_by_conn_id(conn_id);
        if address.is_none() {
            return;
        }

        client.unwrap().callback.on_phy_update(
            address.unwrap(),
            LePhy::from_u8(tx_phy).unwrap(),
            LePhy::from_u8(rx_phy).unwrap(),
            GattStatus::from_u8(status).unwrap(),
        );
    }

    fn read_phy_cb(
        &mut self,
        client_id: i32,
        addr: RawAddress,
        tx_phy: u8,
        rx_phy: u8,
        status: u8,
    ) {
        let client = self.context_map.get_by_client_id(client_id);
        if client.is_none() {
            return;
        }

        client.unwrap().callback.on_phy_read(
            addr.to_string(),
            LePhy::from_u8(tx_phy).unwrap(),
            LePhy::from_u8(rx_phy).unwrap(),
            GattStatus::from_u8(status).unwrap(),
        );
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
        fn on_client_registered(&self, _status: i32, _client_id: i32) {}
        fn on_client_connection_state(
            &self,
            _status: i32,
            _client_id: i32,
            _connected: bool,
            _addr: String,
        ) {
        }
    }

    impl RPCProxy for TestBluetoothGattCallback {
        fn register_disconnect(&mut self, _f: Box<dyn Fn() + Send>) {}

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
        let mut map = ContextMap::new();

        // Add client 1.
        let callback1 = Box::new(TestBluetoothGattCallback::new(String::from("Callback 1")));
        let uuid1 = parse_uuid_string("00000000000000000000000000000001").unwrap().uu;
        map.add(&uuid1, callback1);
        let found = map.get_by_uuid(&uuid1);
        assert!(found.is_some());
        assert_eq!("Callback 1", found.unwrap().callback.get_object_id());

        // Add client 2.
        let callback2 = Box::new(TestBluetoothGattCallback::new(String::from("Callback 2")));
        let uuid2 = parse_uuid_string("00000000000000000000000000000002").unwrap().uu;
        map.add(&uuid2, callback2);
        let found = map.get_by_uuid(&uuid2);
        assert!(found.is_some());
        assert_eq!("Callback 2", found.unwrap().callback.get_object_id());

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
        let mut map = ContextMap::new();
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
