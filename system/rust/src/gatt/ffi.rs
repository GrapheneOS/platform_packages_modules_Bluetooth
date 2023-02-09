//! FFI interfaces for the GATT module. Some structs are exported so that
//! core::init can instantiate and pass them into the main loop.

use anyhow::{bail, Result};
use bt_common::init_flags::{
    always_use_private_gatt_for_debugging_is_enabled, rust_event_loop_is_enabled,
};
pub use inner::*;
use log::{error, info, warn};

use crate::{
    do_in_rust_thread,
    packets::{AttBuilder, Serializable, SerializeError},
};

use super::{
    arbiter::{self, with_arbiter},
    channel::AttTransport,
    ids::{AdvertiserId, AttHandle, ConnectionId, ServerId, TransportIndex},
    server::gatt_database::{AttPermissions, GattCharacteristicWithHandle, GattServiceWithHandle},
};

#[cxx::bridge]
#[allow(clippy::needless_lifetimes)]
#[allow(clippy::too_many_arguments)]
#[allow(missing_docs)]
mod inner {
    #[namespace = "bluetooth"]
    extern "C++" {
        include!("bluetooth/uuid.h");
        /// A C++ UUID.
        type Uuid = crate::core::uuid::Uuid;
    }

    /// What action the arbiter should take in response to an incoming packet
    #[namespace = "bluetooth::shim::arbiter"]
    enum InterceptAction {
        /// Forward the packet to the legacy stack
        #[cxx_name = "FORWARD"]
        Forward = 0u32,
        /// Discard the packet (typically because it has been intercepted)
        #[cxx_name = "DROP"]
        Drop = 1u32,
    }

    /// The type of GATT record supplied over FFI
    #[derive(Debug)]
    #[namespace = "bluetooth::gatt"]
    enum GattRecordType {
        PrimaryService,
        SecondaryService,
        IncludedService,
        Characteristic,
        Descriptor,
    }

    /// An entry in a service definition received from JNI. See GattRecordType
    /// for possible types.
    #[namespace = "bluetooth::gatt"]
    struct GattRecord {
        uuid: Uuid,
        record_type: GattRecordType,
        attribute_handle: u16,

        properties: u8,
        extended_properties: u16,

        permissions: u16,
    }

    #[namespace = "bluetooth::shim::arbiter"]
    unsafe extern "C++" {
        include!("stack/arbiter/acl_arbiter.h");
        type InterceptAction;

        /// Register callbacks from C++ into Rust within the Arbiter
        fn StoreCallbacksFromRust(
            on_le_connect: fn(tcb_idx: u8, advertiser: u8),
            on_le_disconnect: fn(tcb_idx: u8),
            intercept_packet: fn(tcb_idx: u8, packet: Vec<u8>) -> InterceptAction,
        );

        /// Send an outgoing packet on the specified tcb_idx
        fn SendPacketToPeer(tcb_idx: u8, packet: Vec<u8>);
    }

    #[namespace = "bluetooth::gatt"]
    extern "Rust" {
        // service management
        fn open_server(server_id: u8);
        fn close_server(server_id: u8);
        fn add_service(server_id: u8, service_records: Vec<GattRecord>);
        fn remove_service(server_id: u8, service_handle: u16);

        // connection
        fn is_connection_isolated(conn_id: u16) -> bool;

        // arbitration
        fn associate_server_with_advertiser(server_id: u8, advertiser_id: u8);
        fn clear_advertiser(advertiser_id: u8);
    }
}

/// Implementation of AttTransport wrapping the corresponding C++ method
pub struct AttTransportImpl();

impl AttTransport for AttTransportImpl {
    fn send_packet(
        &self,
        tcb_idx: TransportIndex,
        packet: AttBuilder,
    ) -> Result<(), SerializeError> {
        SendPacketToPeer(tcb_idx.0, packet.to_vec()?);
        Ok(())
    }
}

fn open_server(server_id: u8) {
    if !rust_event_loop_is_enabled() {
        return;
    }

    let server_id = ServerId(server_id);

    if always_use_private_gatt_for_debugging_is_enabled() {
        with_arbiter(|arbiter| {
            arbiter.associate_server_with_advertiser(server_id, AdvertiserId(0))
        });
    }

    do_in_rust_thread(move |modules| {
        if let Err(err) = modules.gatt_module.open_gatt_server(server_id) {
            error!("{err:?}")
        }
    })
}

fn close_server(server_id: u8) {
    if !rust_event_loop_is_enabled() {
        return;
    }

    let server_id = ServerId(server_id);

    if !always_use_private_gatt_for_debugging_is_enabled() {
        with_arbiter(move |arbiter| arbiter.clear_server(server_id));
    }

    do_in_rust_thread(move |modules| {
        if let Err(err) = modules.gatt_module.close_gatt_server(server_id) {
            error!("{err:?}")
        }
    })
}

fn records_to_service(service_records: &[GattRecord]) -> Result<GattServiceWithHandle> {
    let mut characteristics = vec![];
    let mut service_handle_uuid = None;

    for record in service_records {
        match record.record_type {
            GattRecordType::PrimaryService => {
                if service_handle_uuid.is_some() {
                    bail!("got service registration but with duplicate primary service! {service_records:?}".to_string());
                }
                service_handle_uuid = Some((record.attribute_handle, record.uuid));
            }
            GattRecordType::Characteristic => characteristics.push(GattCharacteristicWithHandle {
                handle: AttHandle(record.attribute_handle),
                type_: record.uuid,
                permissions: AttPermissions {
                    readable: record.properties & 0x02 != 0,
                    writable: record.properties & 0x08 != 0,
                },
            }),
            _ => {
                warn!("ignoring unsupported database entry of type {:?}", record.record_type)
            }
        }
    }

    let Some((handle, uuid)) = service_handle_uuid else {
        bail!("got service registration but with no primary service! {characteristics:?}".to_string())
    };

    Ok(GattServiceWithHandle { handle: AttHandle(handle), type_: uuid, characteristics })
}

fn add_service(server_id: u8, service_records: Vec<GattRecord>) {
    if !rust_event_loop_is_enabled() {
        return;
    }

    // marshal into the form expected by GattModule
    let server_id = ServerId(server_id);

    match records_to_service(&service_records) {
        Ok(service) => {
            let handle = service.handle;
            do_in_rust_thread(move |modules| {
                let ok = modules.gatt_module.register_gatt_service(server_id, service.clone());
                match ok {
                    Ok(_) => info!(
                        "successfully registered service for server {server_id:?} with handle {handle:?} (service={service:?})"
                    ),
                    Err(err) => error!(
                        "failed to register GATT service for server {server_id:?} with error: {err},  (service={service:?})"
                    ),
                }
            });
        }
        Err(err) => {
            error!("failed to register service for server {server_id:?}, err: {err:?}")
        }
    }
}

fn remove_service(server_id: u8, service_handle: u16) {
    if !rust_event_loop_is_enabled() {
        return;
    }

    let server_id = ServerId(server_id);
    let service_handle = AttHandle(service_handle);
    do_in_rust_thread(move |modules| {
        let ok = modules.gatt_module.unregister_gatt_service(server_id, service_handle);
        match ok {
            Ok(_) => info!(
                "successfully removed service {service_handle:?} for server {server_id:?}"
            ),
            Err(err) => error!(
                "failed to remove GATT service {service_handle:?} for server {server_id:?} with error: {err}"
            ),
        }
    })
}

fn is_connection_isolated(conn_id: u16) -> bool {
    if !rust_event_loop_is_enabled() {
        return false;
    }

    with_arbiter(|arbiter| arbiter.is_connection_isolated(ConnectionId(conn_id)))
}

fn associate_server_with_advertiser(server_id: u8, advertiser_id: u8) {
    if !rust_event_loop_is_enabled() {
        return;
    }

    arbiter::with_arbiter(move |arbiter| {
        arbiter.associate_server_with_advertiser(ServerId(server_id), AdvertiserId(advertiser_id))
    })
}

fn clear_advertiser(advertiser_id: u8) {
    if !rust_event_loop_is_enabled() {
        return;
    }

    arbiter::with_arbiter(move |arbiter| arbiter.clear_advertiser(AdvertiserId(advertiser_id)))
}

#[cfg(test)]
mod test {
    use super::*;

    const SERVICE_HANDLE: AttHandle = AttHandle(1);
    const SERVICE_UUID: Uuid = Uuid::new(0x1234);

    const CHARACTERISTIC_HANDLE: AttHandle = AttHandle(2);
    const CHARACTERISTIC_UUID: Uuid = Uuid::new(0x5678);

    const ANOTHER_CHARACTERISTIC_HANDLE: AttHandle = AttHandle(3);
    const ANOTHER_CHARACTERISTIC_UUID: Uuid = Uuid::new(0x9ABC);

    fn make_service_record(uuid: Uuid, handle: AttHandle) -> GattRecord {
        GattRecord {
            uuid,
            record_type: GattRecordType::PrimaryService,
            attribute_handle: handle.0,
            properties: 0,
            extended_properties: 0,
            permissions: 0,
        }
    }

    fn make_characteristic_record(uuid: Uuid, handle: AttHandle, properties: u8) -> GattRecord {
        GattRecord {
            uuid,
            record_type: GattRecordType::Characteristic,
            attribute_handle: handle.0,
            properties,
            extended_properties: 0,
            permissions: 0,
        }
    }

    #[test]
    fn test_empty_records() {
        let res = records_to_service(&[]);
        assert!(res.is_err());
    }

    #[test]
    fn test_primary_service() {
        let service =
            records_to_service(&[make_service_record(SERVICE_UUID, SERVICE_HANDLE)]).unwrap();

        assert_eq!(service.handle, SERVICE_HANDLE);
        assert_eq!(service.type_, SERVICE_UUID);
        assert_eq!(service.characteristics.len(), 0);
    }

    #[test]
    fn test_dupe_primary_service() {
        let res = records_to_service(&[
            make_service_record(SERVICE_UUID, SERVICE_HANDLE),
            make_service_record(SERVICE_UUID, SERVICE_HANDLE),
        ]);

        assert!(res.is_err());
    }

    #[test]
    fn test_service_with_single_characteristic() {
        let service = records_to_service(&[
            make_service_record(SERVICE_UUID, SERVICE_HANDLE),
            make_characteristic_record(CHARACTERISTIC_UUID, CHARACTERISTIC_HANDLE, 0),
        ])
        .unwrap();

        assert_eq!(service.handle, SERVICE_HANDLE);
        assert_eq!(service.type_, SERVICE_UUID);

        assert_eq!(service.characteristics.len(), 1);
        assert_eq!(service.characteristics[0].handle, CHARACTERISTIC_HANDLE);
        assert_eq!(service.characteristics[0].type_, CHARACTERISTIC_UUID);
    }

    #[test]
    fn test_multiple_characteristics() {
        let service = records_to_service(&[
            make_service_record(SERVICE_UUID, SERVICE_HANDLE),
            make_characteristic_record(CHARACTERISTIC_UUID, CHARACTERISTIC_HANDLE, 0),
            make_characteristic_record(
                ANOTHER_CHARACTERISTIC_UUID,
                ANOTHER_CHARACTERISTIC_HANDLE,
                0,
            ),
        ])
        .unwrap();

        assert_eq!(service.characteristics.len(), 2);
        assert_eq!(service.characteristics[0].handle, CHARACTERISTIC_HANDLE);
        assert_eq!(service.characteristics[0].type_, CHARACTERISTIC_UUID);
        assert_eq!(service.characteristics[1].handle, ANOTHER_CHARACTERISTIC_HANDLE);
        assert_eq!(service.characteristics[1].type_, ANOTHER_CHARACTERISTIC_UUID);
    }

    #[test]
    fn test_characteristic_readable_property() {
        let service = records_to_service(&[
            make_service_record(SERVICE_UUID, SERVICE_HANDLE),
            make_characteristic_record(CHARACTERISTIC_UUID, CHARACTERISTIC_HANDLE, 0x02),
        ])
        .unwrap();

        assert_eq!(
            service.characteristics[0].permissions,
            AttPermissions { readable: true, writable: false }
        );
    }

    #[test]
    fn test_characteristic_writable_property() {
        let service = records_to_service(&[
            make_service_record(SERVICE_UUID, SERVICE_HANDLE),
            make_characteristic_record(CHARACTERISTIC_UUID, CHARACTERISTIC_HANDLE, 0x08),
        ])
        .unwrap();

        assert_eq!(
            service.characteristics[0].permissions,
            AttPermissions { readable: false, writable: true }
        );
    }

    #[test]
    fn test_characteristic_readable_and_writable_property() {
        let service = records_to_service(&[
            make_service_record(SERVICE_UUID, SERVICE_HANDLE),
            make_characteristic_record(CHARACTERISTIC_UUID, CHARACTERISTIC_HANDLE, 0x02 | 0x08),
        ])
        .unwrap();

        assert_eq!(
            service.characteristics[0].permissions,
            AttPermissions { readable: true, writable: true }
        );
    }
}
