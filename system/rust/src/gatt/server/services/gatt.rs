//! The GATT service as defined in Core Spec 5.3 Vol 3G Section 7

use std::{cell::RefCell, collections::HashSet, rc::Rc};

use anyhow::Result;
use async_trait::async_trait;
use log::warn;

use crate::{
    core::uuid::Uuid,
    gatt::{
        callbacks::GattDatastore,
        ffi::AttributeBackingType,
        ids::{AttHandle, ConnectionId},
        server::gatt_database::{
            AttPermissions, GattCharacteristicWithHandle, GattDatabase, GattDescriptorWithHandle,
            GattServiceWithHandle,
        },
    },
    packets::{
        AttAttributeDataChild, AttAttributeDataView, AttClientCharacteristicConfigurationBuilder,
        AttClientCharacteristicConfigurationView, AttErrorCode, Packet,
    },
};

#[derive(Default)]
struct GattService {
    // TODO(aryarahul): clear this on disconnect/reconnect
    // TODO(aryarahul): do NOT clear this for bonded devices
    // TODO(aryarahul): actually send this on service change
    clients_watching_for_service_change_indication: RefCell<HashSet<ConnectionId>>,
}

// Must lie in the range specified by GATT_GATT_START_HANDLE from legacy stack
const GATT_SERVICE_HANDLE: AttHandle = AttHandle(1);
const SERVICE_CHANGE_HANDLE: AttHandle = AttHandle(3);
const SERVICE_CHANGE_CCC_DESCRIPTOR_HANDLE: AttHandle = AttHandle(4);

/// The UUID used for the GATT service (Assigned Numbers 3.4.1 Services by Name)
pub const GATT_SERVICE_UUID: Uuid = Uuid::new(0x1801);
/// The UUID used for the Service Changed characteristic (Assigned Numbers 3.8.1 Characteristics by Name)
pub const SERVICE_CHANGE_UUID: Uuid = Uuid::new(0x2A05);
/// The UUID used for the Client Characteristic Configuration descriptor (Assigned Numbers 3.7 Descriptors)
pub const CLIENT_CHARACTERISTIC_CONFIGURATION_UUID: Uuid = Uuid::new(0x2902);

#[async_trait(?Send)]
impl GattDatastore for GattService {
    async fn read(
        &self,
        conn_id: ConnectionId,
        handle: AttHandle,
        _: AttributeBackingType,
    ) -> Result<AttAttributeDataChild, AttErrorCode> {
        if handle == SERVICE_CHANGE_CCC_DESCRIPTOR_HANDLE {
            Ok(AttClientCharacteristicConfigurationBuilder {
                notification: 0,
                indication: self
                    .clients_watching_for_service_change_indication
                    .borrow()
                    .contains(&conn_id)
                    .into(),
            }
            .into())
        } else {
            unreachable!()
        }
    }

    async fn write(
        &self,
        conn_id: ConnectionId,
        handle: AttHandle,
        _: AttributeBackingType,
        data: AttAttributeDataView<'_>,
    ) -> Result<(), AttErrorCode> {
        if handle == SERVICE_CHANGE_CCC_DESCRIPTOR_HANDLE {
            let ccc = AttClientCharacteristicConfigurationView::try_parse(data).map_err(|err| {
                warn!("failed to parse CCC descriptor, got: {err:?}");
                AttErrorCode::APPLICATION_ERROR
            })?;
            if ccc.get_indication() != 0 {
                self.clients_watching_for_service_change_indication.borrow_mut().insert(conn_id);
            } else {
                self.clients_watching_for_service_change_indication.borrow_mut().remove(&conn_id);
            }
            Ok(())
        } else {
            unreachable!()
        }
    }
}

/// Register the GATT service in the provided GATT database.
pub fn register_gatt_service(database: &mut GattDatabase) -> Result<()> {
    database.add_service_with_handles(
        // GATT Service
        GattServiceWithHandle {
            handle: GATT_SERVICE_HANDLE,
            type_: GATT_SERVICE_UUID,
            // Service Changed Characteristic
            characteristics: vec![GattCharacteristicWithHandle {
                handle: SERVICE_CHANGE_HANDLE,
                type_: SERVICE_CHANGE_UUID,
                permissions: AttPermissions::INDICATE,
                descriptors: vec![GattDescriptorWithHandle {
                    handle: SERVICE_CHANGE_CCC_DESCRIPTOR_HANDLE,
                    type_: CLIENT_CHARACTERISTIC_CONFIGURATION_UUID,
                    permissions: AttPermissions::READABLE | AttPermissions::WRITABLE,
                }],
            }],
        },
        Rc::new(GattService::default()),
    )
}
#[cfg(test)]
mod test {
    use super::*;

    use crate::{
        core::shared_box::SharedBox,
        gatt::{
            ids::ConnectionId,
            server::{
                att_database::{
                    AttDatabase, CHARACTERISTIC_UUID, PRIMARY_SERVICE_DECLARATION_UUID,
                },
                gatt_database::GattDatabase,
            },
        },
        utils::{
            packet::{build_att_data, build_view_or_crash},
            task::block_on_locally,
        },
    };

    const CONN_ID: ConnectionId = ConnectionId(1);

    fn init_dbs() -> (SharedBox<GattDatabase>, impl AttDatabase) {
        let mut gatt_database = GattDatabase::new();
        register_gatt_service(&mut gatt_database).unwrap();
        let gatt_database = SharedBox::new(gatt_database);
        let att_database = gatt_database.get_att_database(CONN_ID);
        (gatt_database, att_database)
    }

    #[test]
    fn test_gatt_service_discovery() {
        // arrange
        let (_gatt_db, att_db) = init_dbs();

        // act: discover all services
        let attrs = att_db.list_attributes();

        // assert: 1 service + 1 char decl + 1 char value + 1 char descriptor = 4 attrs
        assert_eq!(attrs.len(), 4);
        // assert: value handles are correct
        assert_eq!(attrs[0].handle, GATT_SERVICE_HANDLE);
        assert_eq!(attrs[2].handle, SERVICE_CHANGE_HANDLE);
        // assert: types are correct
        assert_eq!(attrs[0].type_, PRIMARY_SERVICE_DECLARATION_UUID);
        assert_eq!(attrs[1].type_, CHARACTERISTIC_UUID);
        assert_eq!(attrs[2].type_, SERVICE_CHANGE_UUID);
        assert_eq!(attrs[3].type_, CLIENT_CHARACTERISTIC_CONFIGURATION_UUID);
        // assert: permissions of value attrs are correct
        assert_eq!(attrs[2].permissions, AttPermissions::INDICATE);
        assert_eq!(attrs[3].permissions, AttPermissions::READABLE | AttPermissions::WRITABLE);
    }

    #[test]
    fn test_default_indication_subscription() {
        // arrange
        let (_gatt_db, att_db) = init_dbs();

        // act: try to read the CCC descriptor
        let resp =
            block_on_locally(att_db.read_attribute(SERVICE_CHANGE_CCC_DESCRIPTOR_HANDLE)).unwrap();

        // assert: we are not registered for either indications/notifications
        let AttAttributeDataChild::AttClientCharacteristicConfiguration(configuration) = resp else {
            unreachable!()
        };
        assert_eq!(
            configuration,
            AttClientCharacteristicConfigurationBuilder { notification: 0, indication: 0 }
        );
    }

    #[test]
    fn test_subscribe_to_indication() {
        // arrange
        let (_gatt_db, att_db) = init_dbs();

        // act: register for service change indication
        block_on_locally(
            att_db.write_attribute(
                SERVICE_CHANGE_CCC_DESCRIPTOR_HANDLE,
                build_view_or_crash(build_att_data(AttClientCharacteristicConfigurationBuilder {
                    notification: 0,
                    indication: 1,
                }))
                .view(),
            ),
        )
        .unwrap();
        // read our registration status
        let resp =
            block_on_locally(att_db.read_attribute(SERVICE_CHANGE_CCC_DESCRIPTOR_HANDLE)).unwrap();

        // assert: we are registered for indications
        let AttAttributeDataChild::AttClientCharacteristicConfiguration(configuration) = resp else {
            unreachable!()
        };
        assert_eq!(
            configuration,
            AttClientCharacteristicConfigurationBuilder { notification: 0, indication: 1 }
        );
    }

    #[test]
    fn test_unsubscribe_to_indication() {
        // arrange
        let (_gatt_db, att_db) = init_dbs();

        // act: register for service change indication
        block_on_locally(
            att_db.write_attribute(
                SERVICE_CHANGE_CCC_DESCRIPTOR_HANDLE,
                build_view_or_crash(build_att_data(AttClientCharacteristicConfigurationBuilder {
                    notification: 0,
                    indication: 1,
                }))
                .view(),
            ),
        )
        .unwrap();
        // act: next, unregister from this indication
        block_on_locally(
            att_db.write_attribute(
                SERVICE_CHANGE_CCC_DESCRIPTOR_HANDLE,
                build_view_or_crash(build_att_data(AttClientCharacteristicConfigurationBuilder {
                    notification: 0,
                    indication: 0,
                }))
                .view(),
            ),
        )
        .unwrap();
        // read our registration status
        let resp =
            block_on_locally(att_db.read_attribute(SERVICE_CHANGE_CCC_DESCRIPTOR_HANDLE)).unwrap();

        // assert: we are not registered for indications
        let AttAttributeDataChild::AttClientCharacteristicConfiguration(configuration) = resp else {
            unreachable!()
        };
        assert_eq!(
            configuration,
            AttClientCharacteristicConfigurationBuilder { notification: 0, indication: 0 }
        );
    }
}
