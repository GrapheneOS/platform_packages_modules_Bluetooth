//! D-Bus proxy implementations of the APIs.

use bt_topshim::btif::{BtSspVariant, BtTransport, Uuid128Bit};
use bt_topshim::profiles::gatt::GattStatus;

use btstack::bluetooth::{
    BluetoothDevice, IBluetooth, IBluetoothCallback, IBluetoothConnectionCallback,
};
use btstack::bluetooth_gatt::{
    BluetoothGattCharacteristic, BluetoothGattDescriptor, BluetoothGattService,
    GattWriteRequestStatus, GattWriteType, IBluetoothGatt, IBluetoothGattCallback,
    IScannerCallback, LePhy, ScanFilter, ScanSettings,
};

use dbus::arg::{AppendAll, RefArg};
use dbus::nonblock::SyncConnection;

use dbus_crossroads::Crossroads;

use dbus_projection::{impl_dbus_arg_enum, DisconnectWatcher};

use dbus_macros::{dbus_method, dbus_propmap, generate_dbus_exporter};

use manager_service::iface_bluetooth_manager::{
    AdapterWithEnabled, IBluetoothManager, IBluetoothManagerCallback,
};

use num_traits::{FromPrimitive, ToPrimitive};

use std::convert::TryInto;
use std::sync::{Arc, Mutex};

use crate::dbus_arg::{DBusArg, DBusArgError, RefArgToRust};

fn make_object_path(idx: i32, name: &str) -> dbus::Path {
    dbus::Path::new(format!("/org/chromium/bluetooth/hci{}/{}", idx, name)).unwrap()
}

impl_dbus_arg_enum!(BtTransport);
impl_dbus_arg_enum!(BtSspVariant);
impl_dbus_arg_enum!(GattStatus);
impl_dbus_arg_enum!(GattWriteType);
impl_dbus_arg_enum!(LePhy);

// Represents Uuid128Bit as an array in D-Bus.
impl DBusArg for Uuid128Bit {
    type DBusType = Vec<u8>;

    fn from_dbus(
        data: Vec<u8>,
        _conn: Option<Arc<SyncConnection>>,
        _remote: Option<dbus::strings::BusName<'static>>,
        _disconnect_watcher: Option<Arc<std::sync::Mutex<DisconnectWatcher>>>,
    ) -> Result<[u8; 16], Box<dyn std::error::Error>> {
        return Ok(data.try_into().unwrap());
    }

    fn to_dbus(data: [u8; 16]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        return Ok(data.to_vec());
    }
}

#[dbus_propmap(BluetoothGattDescriptor)]
pub struct BluetoothGattDescriptorDBus {
    uuid: Uuid128Bit,
    instance_id: i32,
    permissions: i32,
}

#[dbus_propmap(BluetoothGattCharacteristic)]
pub struct BluetoothGattCharacteristicDBus {
    uuid: Uuid128Bit,
    instance_id: i32,
    properties: i32,
    permissions: i32,
    key_size: i32,
    write_type: GattWriteType,
    descriptors: Vec<BluetoothGattDescriptor>,
}

#[dbus_propmap(BluetoothGattService)]
pub struct BluetoothGattServiceDBus {
    pub uuid: Uuid128Bit,
    pub instance_id: i32,
    pub service_type: i32,
    pub characteristics: Vec<BluetoothGattCharacteristic>,
    pub included_services: Vec<BluetoothGattService>,
}

#[dbus_propmap(BluetoothDevice)]
pub struct BluetoothDeviceDBus {
    address: String,
    name: String,
}

struct ClientDBusProxy {
    conn: Arc<SyncConnection>,
    cr: Arc<Mutex<Crossroads>>,
    bus_name: String,
    objpath: dbus::Path<'static>,
    interface: String,
}

impl ClientDBusProxy {
    fn create_proxy(&self) -> dbus::nonblock::Proxy<Arc<SyncConnection>> {
        let conn = self.conn.clone();
        dbus::nonblock::Proxy::new(
            self.bus_name.clone(),
            self.objpath.clone(),
            std::time::Duration::from_secs(2),
            conn,
        )
    }

    /// Calls a method and returns the dbus result.
    fn method_withresult<A: AppendAll, T: 'static + dbus::arg::Arg + for<'z> dbus::arg::Get<'z>>(
        &self,
        member: &str,
        args: A,
    ) -> Result<(T,), dbus::Error> {
        let proxy = self.create_proxy();
        // We know that all APIs return immediately, so we can block on it for simplicity.
        return futures::executor::block_on(async {
            proxy.method_call(self.interface.clone(), member, args).await
        });
    }

    fn method<A: AppendAll, T: 'static + dbus::arg::Arg + for<'z> dbus::arg::Get<'z>>(
        &self,
        member: &str,
        args: A,
    ) -> T {
        let (ret,): (T,) = self.method_withresult(member, args).unwrap();
        return ret;
    }

    fn method_noreturn<A: AppendAll>(&self, member: &str, args: A) {
        // The real type should be Result<((),), _> since there is no return value. However, to
        // meet trait constraints, we just use bool and never unwrap the result. This calls the
        // method, waits for the response but doesn't actually attempt to parse the result (on
        // unwrap).
        let _: Result<(bool,), _> = self.method_withresult(member, args);
    }
}

#[allow(dead_code)]
struct IBluetoothCallbackDBus {}

impl btstack::RPCProxy for IBluetoothCallbackDBus {
    // Dummy implementations just to satisfy impl RPCProxy requirements.
    fn register_disconnect(&mut self, _f: Box<dyn Fn(u32) + Send>) -> u32 {
        0
    }
    fn get_object_id(&self) -> String {
        String::from("")
    }
    fn unregister(&mut self, _id: u32) -> bool {
        false
    }
}

#[generate_dbus_exporter(
    export_bluetooth_callback_dbus_obj,
    "org.chromium.bluetooth.BluetoothCallback"
)]
impl IBluetoothCallback for IBluetoothCallbackDBus {
    #[dbus_method("OnAddressChanged")]
    fn on_address_changed(&self, addr: String) {}

    #[dbus_method("OnDeviceFound")]
    fn on_device_found(&self, remote_device: BluetoothDevice) {}

    #[dbus_method("OnDiscoveringChanged")]
    fn on_discovering_changed(&self, discovering: bool) {}

    #[dbus_method("OnSspRequest")]
    fn on_ssp_request(
        &self,
        remote_device: BluetoothDevice,
        cod: u32,
        variant: BtSspVariant,
        passkey: u32,
    ) {
    }

    #[dbus_method("OnBondStateChanged")]
    fn on_bond_state_changed(&self, status: u32, address: String, state: u32) {}
}

#[allow(dead_code)]
struct IBluetoothConnectionCallbackDBus {}

impl btstack::RPCProxy for IBluetoothConnectionCallbackDBus {
    // Dummy implementations just to satisfy impl RPCProxy requirements.
    fn register_disconnect(&mut self, _f: Box<dyn Fn(u32) + Send>) -> u32 {
        0
    }
    fn get_object_id(&self) -> String {
        String::from("")
    }
    fn unregister(&mut self, _id: u32) -> bool {
        false
    }
}

#[generate_dbus_exporter(
    export_bluetooth_connection_callback_dbus_obj,
    "org.chromium.bluetooth.BluetoothConnectionCallback"
)]
impl IBluetoothConnectionCallback for IBluetoothConnectionCallbackDBus {
    #[dbus_method("OnDeviceConnected")]
    fn on_device_connected(&self, remote_device: BluetoothDevice) {}

    #[dbus_method("OnDeviceDisconencted")]
    fn on_device_disconnected(&self, remote_device: BluetoothDevice) {}
}

pub(crate) struct BluetoothDBus {
    client_proxy: ClientDBusProxy,
}

impl BluetoothDBus {
    pub(crate) fn new(
        conn: Arc<SyncConnection>,
        cr: Arc<Mutex<Crossroads>>,
        index: i32,
    ) -> BluetoothDBus {
        BluetoothDBus {
            client_proxy: ClientDBusProxy {
                conn: conn.clone(),
                cr: cr,
                bus_name: String::from("org.chromium.bluetooth"),
                objpath: make_object_path(index, "adapter"),
                interface: String::from("org.chromium.bluetooth.Bluetooth"),
            },
        }
    }
}

// TODO(b/200732080): These are boilerplate codes, consider creating a macro to generate.
impl IBluetooth for BluetoothDBus {
    fn register_callback(&mut self, callback: Box<dyn IBluetoothCallback + Send>) {
        let path_string = callback.get_object_id();
        let path = dbus::Path::new(path_string.clone()).unwrap();
        export_bluetooth_callback_dbus_obj(
            path_string,
            self.client_proxy.conn.clone(),
            &mut self.client_proxy.cr.lock().unwrap(),
            Arc::new(Mutex::new(callback)),
            Arc::new(Mutex::new(DisconnectWatcher::new())),
        );

        self.client_proxy.method_noreturn("RegisterCallback", (path,))
    }

    fn register_connection_callback(
        &mut self,
        callback: Box<dyn IBluetoothConnectionCallback + Send>,
    ) -> u32 {
        let path_string = callback.get_object_id();
        let path = dbus::Path::new(path_string.clone()).unwrap();
        export_bluetooth_connection_callback_dbus_obj(
            path_string,
            self.client_proxy.conn.clone(),
            &mut self.client_proxy.cr.lock().unwrap(),
            Arc::new(Mutex::new(callback)),
            Arc::new(Mutex::new(DisconnectWatcher::new())),
        );

        self.client_proxy.method("RegisterConnectionCallback", (path,))
    }

    fn unregister_connection_callback(&mut self, id: u32) -> bool {
        self.client_proxy.method("UnregisterConnectionCallback", (id,))
    }

    fn enable(&mut self) -> bool {
        // Not implemented by server
        true
    }

    fn disable(&mut self) -> bool {
        // Not implemented by server
        true
    }

    fn get_address(&self) -> String {
        self.client_proxy.method("GetAddress", ())
    }

    fn get_uuids(&self) -> Vec<Uuid128Bit> {
        let result: Vec<Vec<u8>> = self.client_proxy.method("GetUuids", ());
        <Vec<Uuid128Bit> as DBusArg>::from_dbus(result, None, None, None).unwrap()
    }

    fn get_name(&self) -> String {
        self.client_proxy.method("GetName", ())
    }

    fn set_name(&self, name: String) -> bool {
        self.client_proxy.method("SetName", (name,))
    }

    fn start_discovery(&self) -> bool {
        self.client_proxy.method("StartDiscovery", ())
    }

    fn cancel_discovery(&self) -> bool {
        self.client_proxy.method("CancelDiscovery", ())
    }

    fn is_discovering(&self) -> bool {
        self.client_proxy.method("IsDiscovering", ())
    }

    fn get_discovery_end_millis(&self) -> u64 {
        self.client_proxy.method("GetDiscoveryEndMillis", ())
    }

    fn create_bond(&self, device: BluetoothDevice, transport: BtTransport) -> bool {
        self.client_proxy.method(
            "CreateBond",
            (BluetoothDevice::to_dbus(device).unwrap(), BtTransport::to_dbus(transport).unwrap()),
        )
    }

    fn cancel_bond_process(&self, device: BluetoothDevice) -> bool {
        self.client_proxy.method("CancelBondProcess", (BluetoothDevice::to_dbus(device).unwrap(),))
    }

    fn remove_bond(&self, device: BluetoothDevice) -> bool {
        self.client_proxy.method("RemoveBond", (BluetoothDevice::to_dbus(device).unwrap(),))
    }

    fn get_bonded_devices(&self) -> Vec<BluetoothDevice> {
        let props: Vec<dbus::arg::PropMap> = self.client_proxy.method("GetBondedDevices", ());
        <Vec<BluetoothDevice> as DBusArg>::from_dbus(props, None, None, None).unwrap()
    }

    fn get_bond_state(&self, device: BluetoothDevice) -> u32 {
        self.client_proxy.method("GetBondState", (BluetoothDevice::to_dbus(device).unwrap(),))
    }

    fn set_pin(&self, device: BluetoothDevice, accept: bool, len: u32, pin_code: Vec<u8>) -> bool {
        self.client_proxy
            .method("SetPin", (BluetoothDevice::to_dbus(device).unwrap(), accept, len, pin_code))
    }

    fn set_passkey(
        &self,
        device: BluetoothDevice,
        accept: bool,
        len: u32,
        passkey: Vec<u8>,
    ) -> bool {
        self.client_proxy
            .method("SetPasskey", (BluetoothDevice::to_dbus(device).unwrap(), accept, len, passkey))
    }

    fn set_pairing_confirmation(&self, device: BluetoothDevice, accept: bool) -> bool {
        self.client_proxy
            .method("SetPairingConfirmation", (BluetoothDevice::to_dbus(device).unwrap(), accept))
    }

    fn get_connection_state(&self, device: BluetoothDevice) -> u32 {
        self.client_proxy.method("GetConnectionState", (BluetoothDevice::to_dbus(device).unwrap(),))
    }

    fn get_remote_uuids(&self, device: BluetoothDevice) -> Vec<Uuid128Bit> {
        let result: Vec<Vec<u8>> = self
            .client_proxy
            .method("GetRemoteUuids", (BluetoothDevice::to_dbus(device).unwrap(),));
        <Vec<Uuid128Bit> as DBusArg>::from_dbus(result, None, None, None).unwrap()
    }

    fn fetch_remote_uuids(&self, device: BluetoothDevice) -> bool {
        self.client_proxy.method("FetchRemoteUuids", (BluetoothDevice::to_dbus(device).unwrap(),))
    }

    fn sdp_search(&self, device: BluetoothDevice, uuid: Uuid128Bit) -> bool {
        self.client_proxy.method(
            "SdpSearch",
            (BluetoothDevice::to_dbus(device).unwrap(), Uuid128Bit::to_dbus(uuid).unwrap()),
        )
    }

    fn connect_all_enabled_profiles(&self, device: BluetoothDevice) -> bool {
        self.client_proxy
            .method("ConnectAllEnabledProfiles", (BluetoothDevice::to_dbus(device).unwrap(),))
    }

    fn disconnect_all_enabled_profiles(&self, device: BluetoothDevice) -> bool {
        self.client_proxy
            .method("DisconnectAllEnabledProfiles", (BluetoothDevice::to_dbus(device).unwrap(),))
    }
}

#[dbus_propmap(AdapterWithEnabled)]
pub struct AdapterWithEnabledDbus {
    hci_interface: i32,
    enabled: bool,
}

pub(crate) struct BluetoothManagerDBus {
    client_proxy: ClientDBusProxy,
}

impl BluetoothManagerDBus {
    pub(crate) fn new(
        conn: Arc<SyncConnection>,
        cr: Arc<Mutex<Crossroads>>,
    ) -> BluetoothManagerDBus {
        BluetoothManagerDBus {
            client_proxy: ClientDBusProxy {
                conn: conn.clone(),
                cr: cr,
                bus_name: String::from("org.chromium.bluetooth.Manager"),
                objpath: dbus::Path::new("/org/chromium/bluetooth/Manager").unwrap(),
                interface: String::from("org.chromium.bluetooth.Manager"),
            },
        }
    }

    pub(crate) fn is_valid(&self) -> bool {
        let result: Result<(bool,), _> = self.client_proxy.method_withresult("GetFlossEnabled", ());
        return result.is_ok();
    }
}

// TODO: These are boilerplate codes, consider creating a macro to generate.
impl IBluetoothManager for BluetoothManagerDBus {
    fn start(&mut self, hci_interface: i32) {
        self.client_proxy.method_noreturn("Start", (hci_interface,))
    }

    fn stop(&mut self, hci_interface: i32) {
        self.client_proxy.method_noreturn("Stop", (hci_interface,))
    }

    fn get_adapter_enabled(&mut self, hci_interface: i32) -> bool {
        self.client_proxy.method("GetAdapterEnabled", (hci_interface,))
    }

    fn register_callback(&mut self, callback: Box<dyn IBluetoothManagerCallback + Send>) {
        let path_string = callback.get_object_id();
        let path = dbus::Path::new(path_string.clone()).unwrap();
        export_bluetooth_manager_callback_dbus_obj(
            path_string,
            self.client_proxy.conn.clone(),
            &mut self.client_proxy.cr.lock().unwrap(),
            Arc::new(Mutex::new(callback)),
            Arc::new(Mutex::new(DisconnectWatcher::new())),
        );

        self.client_proxy.method_noreturn("RegisterCallback", (path,))
    }

    fn get_floss_enabled(&mut self) -> bool {
        self.client_proxy.method("GetFlossEnabled", ())
    }

    fn set_floss_enabled(&mut self, enabled: bool) {
        self.client_proxy.method_noreturn("SetFlossEnabled", (enabled,))
    }

    fn get_available_adapters(&mut self) -> Vec<AdapterWithEnabled> {
        let props: Vec<dbus::arg::PropMap> = self.client_proxy.method("GetAvailableAdapters", ());
        <Vec<AdapterWithEnabled> as DBusArg>::from_dbus(props, None, None, None).unwrap()
    }
}

#[allow(dead_code)]
struct IBluetoothManagerCallbackDBus {}

impl manager_service::RPCProxy for IBluetoothManagerCallbackDBus {
    // Placeholder implementations just to satisfy impl RPCProxy requirements.
    fn register_disconnect(&mut self, _f: Box<dyn Fn(u32) + Send>) -> u32 {
        0
    }
    fn get_object_id(&self) -> String {
        String::from("")
    }
    fn unregister(&mut self, _id: u32) -> bool {
        false
    }
}

#[generate_dbus_exporter(
    export_bluetooth_manager_callback_dbus_obj,
    "org.chromium.bluetooth.ManagerCallback"
)]
impl IBluetoothManagerCallback for IBluetoothManagerCallbackDBus {
    #[dbus_method("OnHciDeviceChanged")]
    fn on_hci_device_changed(&self, hci_interface: i32, present: bool) {}

    #[dbus_method("OnHciEnabledChanged")]
    fn on_hci_enabled_changed(&self, hci_interface: i32, enabled: bool) {}
}

pub(crate) struct BluetoothGattDBus {
    client_proxy: ClientDBusProxy,
}

impl BluetoothGattDBus {
    pub(crate) fn new(
        conn: Arc<SyncConnection>,
        cr: Arc<Mutex<Crossroads>>,
        index: i32,
    ) -> BluetoothGattDBus {
        BluetoothGattDBus {
            client_proxy: ClientDBusProxy {
                conn: conn.clone(),
                cr: cr,
                bus_name: String::from("org.chromium.bluetooth"),
                objpath: make_object_path(index, "gatt"),
                interface: String::from("org.chromium.bluetooth.BluetoothGatt"),
            },
        }
    }
}

// TODO: These are boilerplate codes, consider creating a macro to generate.
impl IBluetoothGatt for BluetoothGattDBus {
    fn register_scanner(&self, _callback: Box<dyn IScannerCallback + Send>) {
        // TODO(b/200066804): implement
    }

    fn unregister_scanner(&self, _scanner_id: i32) {
        // TODO(b/200066804): implement
    }

    fn start_scan(&self, _scanner_id: i32, _settings: ScanSettings, _filters: Vec<ScanFilter>) {
        // TODO(b/200066804): implement
    }

    fn stop_scan(&self, _scanner_id: i32) {
        // TODO(b/200066804): implement
    }

    fn register_client(
        &mut self,
        app_uuid: String,
        callback: Box<dyn IBluetoothGattCallback + Send>,
        eatt_support: bool,
    ) {
        let path_string = callback.get_object_id();
        let path = dbus::Path::new(path_string.clone()).unwrap();
        export_bluetooth_gatt_callback_dbus_obj(
            path_string,
            self.client_proxy.conn.clone(),
            &mut self.client_proxy.cr.lock().unwrap(),
            Arc::new(Mutex::new(callback)),
            Arc::new(Mutex::new(DisconnectWatcher::new())),
        );

        self.client_proxy.method_noreturn("RegisterClient", (app_uuid, path, eatt_support))
    }

    fn unregister_client(&mut self, client_id: i32) {
        self.client_proxy.method_noreturn("UnregisterClient", (client_id,))
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
        self.client_proxy.method_noreturn(
            "ClientConnect",
            (client_id, addr, is_direct, transport, opportunistic, phy),
        )
    }

    fn client_disconnect(&self, client_id: i32, addr: String) {
        self.client_proxy.method_noreturn("ClientDisconnect", (client_id, addr))
    }

    fn client_set_preferred_phy(
        &self,
        client_id: i32,
        addr: String,
        tx_phy: LePhy,
        rx_phy: LePhy,
        phy_options: i32,
    ) {
        self.client_proxy.method_noreturn(
            "ClientSetPreferredPhy",
            (client_id, addr, tx_phy.to_i32().unwrap(), rx_phy.to_i32().unwrap(), phy_options),
        )
    }

    fn client_read_phy(&mut self, client_id: i32, addr: String) {
        self.client_proxy.method_noreturn("ClientReadPhy", (client_id, addr))
    }

    fn refresh_device(&self, client_id: i32, addr: String) {
        self.client_proxy.method_noreturn("RefreshDevice", (client_id, addr))
    }

    fn discover_services(&self, client_id: i32, addr: String) {
        self.client_proxy.method_noreturn("DiscoverServices", (client_id, addr))
    }

    fn discover_service_by_uuid(&self, client_id: i32, addr: String, uuid: String) {
        self.client_proxy.method_noreturn("DiscoverServiceByUuid", (client_id, addr, uuid))
    }

    fn read_characteristic(&self, client_id: i32, addr: String, handle: i32, auth_req: i32) {
        self.client_proxy.method_noreturn("ReadCharacteristic", (client_id, addr, handle, auth_req))
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
        self.client_proxy.method_noreturn(
            "ReadUsingCharacteristicUuid",
            (client_id, addr, uuid, start_handle, end_handle, auth_req),
        )
    }

    fn write_characteristic(
        &self,
        client_id: i32,
        addr: String,
        handle: i32,
        write_type: GattWriteType,
        auth_req: i32,
        value: Vec<u8>,
    ) -> GattWriteRequestStatus {
        GattWriteRequestStatus::from_i32(self.client_proxy.method(
            "WriteCharacteristic",
            (client_id, addr, handle, write_type.to_i32().unwrap(), auth_req, value),
        ))
        .unwrap()
    }

    fn read_descriptor(&self, client_id: i32, addr: String, handle: i32, auth_req: i32) {
        self.client_proxy.method_noreturn("ReadDescriptor", (client_id, addr, handle, auth_req))
    }

    fn write_descriptor(
        &self,
        client_id: i32,
        addr: String,
        handle: i32,
        auth_req: i32,
        value: Vec<u8>,
    ) {
        self.client_proxy
            .method_noreturn("WriteDescriptor", (client_id, addr, handle, auth_req, value))
    }

    fn register_for_notification(&self, client_id: i32, addr: String, handle: i32, enable: bool) {
        self.client_proxy
            .method_noreturn("RegisterForNotification", (client_id, addr, handle, enable))
    }

    fn begin_reliable_write(&mut self, client_id: i32, addr: String) {
        self.client_proxy.method_noreturn("BeginReliableWrite", (client_id, addr))
    }

    fn end_reliable_write(&mut self, client_id: i32, addr: String, execute: bool) {
        self.client_proxy.method_noreturn("EndReliableWrite", (client_id, addr, execute))
    }

    fn read_remote_rssi(&self, client_id: i32, addr: String) {
        self.client_proxy.method_noreturn("ReadRemoteRssi", (client_id, addr))
    }

    fn configure_mtu(&self, client_id: i32, addr: String, mtu: i32) {
        self.client_proxy.method_noreturn("ConfigureMtu", (client_id, addr, mtu))
    }

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
    ) {
        self.client_proxy.method_noreturn(
            "ConnectionParameterUpdate",
            (client_id, addr, min_interval, max_interval, latency, timeout, min_ce_len, max_ce_len),
        )
    }
}

#[allow(dead_code)]
struct IBluetoothGattCallbackDBus {}

impl btstack::RPCProxy for IBluetoothGattCallbackDBus {
    // Placeholder implementations just to satisfy impl RPCProxy requirements.
    fn register_disconnect(&mut self, _f: Box<dyn Fn(u32) + Send>) -> u32 {
        0
    }
    fn get_object_id(&self) -> String {
        String::from("")
    }
    fn unregister(&mut self, _id: u32) -> bool {
        false
    }
}

#[generate_dbus_exporter(
    export_bluetooth_gatt_callback_dbus_obj,
    "org.chromium.bluetooth.BluetoothGattCallback"
)]
impl IBluetoothGattCallback for IBluetoothGattCallbackDBus {
    #[dbus_method("OnClientRegistered")]
    fn on_client_registered(&self, status: i32, client_id: i32) {}

    #[dbus_method("OnClientConnectionState")]
    fn on_client_connection_state(
        &self,
        status: i32,
        client_id: i32,
        connected: bool,
        addr: String,
    ) {
    }

    #[dbus_method("OnPhyUpdate")]
    fn on_phy_update(&self, addr: String, tx_phy: LePhy, rx_phy: LePhy, status: GattStatus) {}

    #[dbus_method("OnPhyRead")]
    fn on_phy_read(&self, addr: String, tx_phy: LePhy, rx_phy: LePhy, status: GattStatus) {}

    #[dbus_method("OnSearchComplete")]
    fn on_search_complete(&self, addr: String, services: Vec<BluetoothGattService>, status: i32) {}

    #[dbus_method("OnCharacteristicRead")]
    fn on_characteristic_read(&self, addr: String, status: i32, handle: i32, value: Vec<u8>) {}

    #[dbus_method("OnCharacteristicWrite")]
    fn on_characteristic_write(&self, addr: String, status: i32, handle: i32) {}

    #[dbus_method("OnExecuteWrite")]
    fn on_execute_write(&self, addr: String, status: i32) {}

    #[dbus_method("OnDescriptorRead")]
    fn on_descriptor_read(&self, addr: String, status: i32, handle: i32, value: Vec<u8>) {}

    #[dbus_method("OnDescriptorWrite")]
    fn on_descriptor_write(&self, addr: String, status: i32, handle: i32) {}

    #[dbus_method("OnNotify")]
    fn on_notify(&self, addr: String, handle: i32, value: Vec<u8>) {}

    #[dbus_method("OnReadRemoteRssi")]
    fn on_read_remote_rssi(&self, addr: String, rssi: i32, status: i32) {}

    #[dbus_method("OnConfigureMtu")]
    fn on_configure_mtu(&self, addr: String, mtu: i32, status: i32) {}

    #[dbus_method("OnConnectionUpdated")]
    fn on_connection_updated(
        &self,
        addr: String,
        interval: i32,
        latency: i32,
        timeout: i32,
        status: i32,
    ) {
    }

    #[dbus_method("OnServiceChanged")]
    fn on_service_changed(&self, addr: String) {}
}
