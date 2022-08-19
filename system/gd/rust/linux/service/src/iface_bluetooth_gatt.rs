use bt_topshim::{btif::Uuid128Bit, profiles::gatt::GattStatus};

use btstack::bluetooth_gatt::{
    BluetoothGattCharacteristic, BluetoothGattDescriptor, BluetoothGattService,
    GattWriteRequestStatus, GattWriteType, IBluetoothGatt, IBluetoothGattCallback,
    IScannerCallback, LePhy, RSSISettings, ScanFilter, ScanSettings, ScanType,
};
use btstack::RPCProxy;

use dbus::arg::RefArg;

use dbus::nonblock::SyncConnection;
use dbus::strings::Path;

use dbus_macros::{dbus_method, dbus_propmap, dbus_proxy_obj, generate_dbus_exporter};

use dbus_projection::DisconnectWatcher;
use dbus_projection::{dbus_generated, impl_dbus_arg_enum};

use num_traits::cast::{FromPrimitive, ToPrimitive};

use std::convert::TryInto;
use std::sync::Arc;

use crate::dbus_arg::{DBusArg, DBusArgError, RefArgToRust};

#[allow(dead_code)]
struct BluetoothGattCallbackDBus {}

#[dbus_proxy_obj(BluetoothGattCallback, "org.chromium.bluetooth.BluetoothGattCallback")]
impl IBluetoothGattCallback for BluetoothGattCallbackDBus {
    #[dbus_method("OnClientRegistered")]
    fn on_client_registered(&self, status: i32, scanner_id: i32) {
        dbus_generated!()
    }

    #[dbus_method("OnClientConnectionState")]
    fn on_client_connection_state(
        &self,
        status: i32,
        client_id: i32,
        connected: bool,
        addr: String,
    ) {
        dbus_generated!()
    }

    #[dbus_method("OnPhyUpdate")]
    fn on_phy_update(&self, addr: String, tx_phy: LePhy, rx_phy: LePhy, status: GattStatus) {
        dbus_generated!()
    }

    #[dbus_method("OnPhyRead")]
    fn on_phy_read(&self, addr: String, tx_phy: LePhy, rx_phy: LePhy, status: GattStatus) {
        dbus_generated!()
    }

    #[dbus_method("OnSearchComplete")]
    fn on_search_complete(&self, addr: String, services: Vec<BluetoothGattService>, status: i32) {
        dbus_generated!()
    }

    #[dbus_method("OnCharacteristicRead")]
    fn on_characteristic_read(&self, addr: String, status: i32, handle: i32, value: Vec<u8>) {
        dbus_generated!()
    }

    #[dbus_method("OnCharacteristicWrite")]
    fn on_characteristic_write(&self, addr: String, status: i32, handle: i32) {
        dbus_generated!()
    }

    #[dbus_method("OnExecuteWrite")]
    fn on_execute_write(&self, addr: String, status: i32) {
        dbus_generated!()
    }

    #[dbus_method("OnDescriptorRead")]
    fn on_descriptor_read(&self, addr: String, status: i32, handle: i32, value: Vec<u8>) {
        dbus_generated!()
    }

    #[dbus_method("OnDescriptorWrite")]
    fn on_descriptor_write(&self, addr: String, status: i32, handle: i32) {
        dbus_generated!()
    }

    #[dbus_method("OnNotify")]
    fn on_notify(&self, addr: String, handle: i32, value: Vec<u8>) {
        dbus_generated!()
    }

    #[dbus_method("OnReadRemoteRssi")]
    fn on_read_remote_rssi(&self, addr: String, rssi: i32, status: i32) {
        dbus_generated!()
    }

    #[dbus_method("OnConfigureMtu")]
    fn on_configure_mtu(&self, addr: String, mtu: i32, status: i32) {
        dbus_generated!()
    }

    #[dbus_method("OnConnectionUpdated")]
    fn on_connection_updated(
        &self,
        addr: String,
        interval: i32,
        latency: i32,
        timeout: i32,
        status: i32,
    ) {
        dbus_generated!()
    }

    #[dbus_method("OnServiceChanged")]
    fn on_service_changed(&self, addr: String) {
        dbus_generated!()
    }
}

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

#[allow(dead_code)]
struct ScannerCallbackDBus {}

#[dbus_proxy_obj(ScannerCallback, "org.chromium.bluetooth.ScannerCallback")]
impl IScannerCallback for ScannerCallbackDBus {
    #[dbus_method("OnScannerRegistered")]
    fn on_scanner_registered(&self, uuid: Uuid128Bit, scanner_id: u8, status: u8) {
        dbus_generated!()
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
    uuid: Uuid128Bit,
    instance_id: i32,
    service_type: i32,
    characteristics: Vec<BluetoothGattCharacteristic>,
    included_services: Vec<BluetoothGattService>,
}

#[dbus_propmap(RSSISettings)]
pub struct RSSISettingsDBus {
    low_threshold: i32,
    high_threshold: i32,
}

#[dbus_propmap(ScanSettings)]
struct ScanSettingsDBus {
    interval: i32,
    window: i32,
    scan_type: ScanType,
    rssi_settings: RSSISettings,
}

impl_dbus_arg_enum!(GattStatus);
impl_dbus_arg_enum!(GattWriteRequestStatus);
impl_dbus_arg_enum!(GattWriteType);
impl_dbus_arg_enum!(LePhy);
impl_dbus_arg_enum!(ScanType);

#[dbus_propmap(ScanFilter)]
struct ScanFilterDBus {}

#[allow(dead_code)]
struct IBluetoothGattDBus {}

#[generate_dbus_exporter(export_bluetooth_gatt_dbus_intf, "org.chromium.bluetooth.BluetoothGatt")]
impl IBluetoothGatt for IBluetoothGattDBus {
    #[dbus_method("RegisterScannerCallback")]
    fn register_scanner_callback(&mut self, callback: Box<dyn IScannerCallback + Send>) -> u32 {
        dbus_generated!()
    }

    #[dbus_method("UnregisterScannerCallback")]
    fn unregister_scanner_callback(&mut self, callback_id: u32) -> bool {
        dbus_generated!()
    }

    // Advertising
    fn register_advertiser(&self) {
        // TODO(b/233128294): implement
        todo!()
    }

    fn unregister_advertiser(&self) {
        // TODO(b/233128294): implement
        todo!()
    }

    /// Get the address currently being advertised
    fn get_own_address(&self) {
        // TODO(b/233128294): implement
        todo!()
    }

    fn set_parameters(&self) {
        // TODO(b/233128294): implement
        todo!()
    }

    fn set_data(&self) {
        // TODO(b/233128294): implement
        todo!()
    }

    fn advertising_enable(&self) {
        // TODO(b/233128294): implement
        todo!()
    }

    fn advertising_disable(&self) {
        // TODO(b/233128294): implement
        todo!()
    }

    fn set_periodic_advertising_parameters(&self) {
        // TODO(b/233128294): implement
        todo!()
    }

    fn set_periodic_advertising_data(&self) {
        // TODO(b/233128294): implement
        todo!()
    }

    fn set_periodic_advertising_enable(&self) {
        // TODO(b/233128294): implement
        todo!()
    }

    fn start_advertising(&self) {
        // TODO(b/233128294): implement
        todo!()
    }

    fn start_advertising_set(&self) {
        // TODO(b/233128294): implement
        todo!()
    }

    // Scanning
    #[dbus_method("RegisterScanner")]
    fn register_scanner(&mut self, callback_id: u32) -> Uuid128Bit {
        dbus_generated!()
    }

    #[dbus_method("UnregisterScanner")]
    fn unregister_scanner(&mut self, scanner_id: u8) -> bool {
        dbus_generated!()
    }

    #[dbus_method("StartScan")]
    fn start_scan(&self, scanner_id: i32, settings: ScanSettings, filters: Vec<ScanFilter>) {
        dbus_generated!()
    }

    #[dbus_method("StopScan")]
    fn stop_scan(&self, scanner_id: i32) {
        dbus_generated!()
    }

    fn scan_filter_setup(&self) {
        // TODO(b/200066804): implement
        todo!()
    }

    fn scan_filter_add(&self) {
        // TODO(b/200066804): implement
        todo!()
    }

    fn scan_filter_clear(&self) {
        // TODO(b/200066804): implement
        todo!()
    }

    fn scan_filter_enable(&self) {
        // TODO(b/200066804): implement
        todo!()
    }

    fn scan_filter_disable(&self) {
        // TODO(b/200066804): implement
        todo!()
    }

    fn set_scan_parameters(&self) {
        // TODO(b/200066804): implement
        todo!()
    }

    fn batch_scan_config_storage(&self) {
        // TODO(b/200066804): implement
        todo!()
    }

    fn batch_scan_enable(&self) {
        // TODO(b/200066804): implement
        todo!()
    }

    fn batch_scan_disable(&self) {
        // TODO(b/200066804): implement
        todo!()
    }

    fn batch_scan_read_reports(&self) {
        // TODO(b/200066804): implement
        todo!()
    }

    // GATT Client
    fn start_sync(&self) {
        // TODO(b/193686094): implement
        todo!()
    }

    fn stop_sync(&self) {
        // TODO(b/193686094): implement
        todo!()
    }

    fn cancel_create_sync(&self) {
        // TODO(b/193686094): implement
        todo!()
    }

    fn transfer_sync(&self) {
        // TODO(b/193686094): implement
        todo!()
    }

    fn transfer_set_info(&self) {
        // TODO(b/193686094): implement
        todo!()
    }

    fn sync_tx_parameters(&self) {
        // TODO(b/193686094): implement
        todo!()
    }

    #[dbus_method("RegisterClient")]
    fn register_client(
        &mut self,
        app_uuid: String,
        callback: Box<dyn IBluetoothGattCallback + Send>,
        eatt_support: bool,
    ) {
        dbus_generated!()
    }

    #[dbus_method("UnregisterClient")]
    fn unregister_client(&mut self, client_id: i32) {
        dbus_generated!()
    }

    #[dbus_method("ClientConnect")]
    fn client_connect(
        &self,
        client_id: i32,
        addr: String,
        is_direct: bool,
        transport: i32,
        opportunistic: bool,
        phy: i32,
    ) {
        dbus_generated!()
    }

    #[dbus_method("ClientDisconnect")]
    fn client_disconnect(&self, client_id: i32, addr: String) {
        dbus_generated!()
    }

    #[dbus_method("RefreshDevice")]
    fn refresh_device(&self, client_id: i32, addr: String) {
        dbus_generated!()
    }

    #[dbus_method("DiscoverServices")]
    fn discover_services(&self, client_id: i32, addr: String) {
        dbus_generated!()
    }

    #[dbus_method("DiscoverServiceByUuid")]
    fn discover_service_by_uuid(&self, client_id: i32, addr: String, uuid: String) {
        dbus_generated!()
    }

    #[dbus_method("ReadCharacteristic")]
    fn read_characteristic(&self, client_id: i32, addr: String, handle: i32, auth_req: i32) {
        dbus_generated!()
    }

    #[dbus_method("ReadUsingCharacteristicUuid")]
    fn read_using_characteristic_uuid(
        &self,
        client_id: i32,
        addr: String,
        uuid: String,
        start_handle: i32,
        end_handle: i32,
        auth_req: i32,
    ) {
        dbus_generated!()
    }

    #[dbus_method("WriteCharacteristic")]
    fn write_characteristic(
        &self,
        client_id: i32,
        addr: String,
        handle: i32,
        write_type: GattWriteType,
        auth_req: i32,
        value: Vec<u8>,
    ) -> GattWriteRequestStatus {
        dbus_generated!()
    }

    #[dbus_method("ReadDescriptor")]
    fn read_descriptor(&self, client_id: i32, addr: String, handle: i32, auth_req: i32) {
        dbus_generated!()
    }

    #[dbus_method("WriteDescriptor")]
    fn write_descriptor(
        &self,
        client_id: i32,
        addr: String,
        handle: i32,
        auth_req: i32,
        value: Vec<u8>,
    ) {
        dbus_generated!()
    }

    #[dbus_method("RegisterForNotification")]
    fn register_for_notification(&self, client_id: i32, addr: String, handle: i32, enable: bool) {
        dbus_generated!()
    }

    #[dbus_method("BeginReliableWrite")]
    fn begin_reliable_write(&mut self, client_id: i32, addr: String) {
        dbus_generated!()
    }

    #[dbus_method("EndReliableWrite")]
    fn end_reliable_write(&mut self, client_id: i32, addr: String, execute: bool) {
        dbus_generated!()
    }

    #[dbus_method("ReadRemoteRssi")]
    fn read_remote_rssi(&self, client_id: i32, addr: String) {
        dbus_generated!()
    }

    #[dbus_method("ConfigureMtu")]
    fn configure_mtu(&self, client_id: i32, addr: String, mtu: i32) {
        dbus_generated!()
    }

    #[dbus_method("ConnectionParameterUpdate")]
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
        dbus_generated!()
    }

    fn execute_write(&self) {
        // TODO(b/193686094): implement
        todo!()
    }

    fn deregister_for_notification(&self) {
        // TODO(b/193686094): implement
        todo!()
    }

    fn get_device_type(&self) {
        // TODO(b/193686094): implement
        todo!()
    }

    #[dbus_method("ClientSetPreferredPhy")]
    fn client_set_preferred_phy(
        &self,
        client_id: i32,
        addr: String,
        tx_phy: LePhy,
        rx_phy: LePhy,
        phy_options: i32,
    ) {
        dbus_generated!()
    }

    #[dbus_method("ClientReadPhy")]
    fn client_read_phy(&mut self, client_id: i32, addr: String) {
        dbus_generated!()
    }

    fn test_command(&self) {
        // TODO(b/193686094): implement
        todo!()
    }

    fn get_gatt_db(&self) {
        // TODO(b/193686094): implement
        todo!()
    }

    // GATT Server
    fn register_server(&self) {
        // TODO(b/193686564): implement
        todo!()
    }

    fn unregister_server(&self) {
        // TODO(b/193686564): implement
        todo!()
    }

    fn server_connect(&self) {
        // TODO(b/193686564): implement
        todo!()
    }

    fn server_disconnect(&self) {
        // TODO(b/193686564): implement
        todo!()
    }

    fn add_service(&self) {
        // TODO(b/193686564): implement
        todo!()
    }

    fn stop_service(&self) {
        // TODO(b/193686564): implement
        todo!()
    }

    fn delete_service(&self) {
        // TODO(b/193686564): implement
        todo!()
    }

    fn send_indication(&self) {
        // TODO(b/193686564): implement
        todo!()
    }

    fn send_response(&self) {
        // TODO(b/193686564): implement
        todo!()
    }

    fn server_set_preferred_phy(&self) {
        // TODO(b/193686564): implement
        todo!()
    }

    fn server_read_phy(&self) {
        // TODO(b/193686564): implement
        todo!()
    }
}
