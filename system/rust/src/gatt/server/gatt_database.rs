//! This module converts a GattDatastore to an AttDatabase,
//! by converting a registry of services into a list of attributes, and proxying
//! ATT read/write requests into characteristic reads/writes

use std::{cell::RefCell, collections::BTreeMap, rc::Rc};

use anyhow::{bail, Result};
use async_trait::async_trait;
use log::error;

use crate::{
    core::{
        shared_box::{SharedBox, WeakBox},
        uuid::Uuid,
    },
    gatt::{
        callbacks::GattDatastore,
        ffi::AttributeBackingType,
        ids::{AttHandle, ConnectionId},
    },
    packets::{
        AttAttributeDataChild, AttAttributeDataView, AttErrorCode,
        GattCharacteristicDeclarationValueBuilder, GattCharacteristicPropertiesBuilder,
        GattServiceDeclarationValueBuilder, UuidBuilder,
    },
};

use super::att_database::{
    AttAttribute, AttDatabase, CHARACTERISTIC_UUID, PRIMARY_SERVICE_DECLARATION_UUID,
};

pub use super::att_database::AttPermissions;

/// A GattService (currently, only primary services are supported) has an
/// identifying UUID and a list of contained characteristics, as well as a
/// handle (indicating the attribute where the service declaration will live)
#[derive(Debug, Clone)]
pub struct GattServiceWithHandle {
    /// The handle of the service declaration
    pub handle: AttHandle,
    /// The type of the service
    pub type_: Uuid,
    /// A list of contained characteristics (that must have handles between the
    /// service declaration handle, and that of the next service)
    pub characteristics: Vec<GattCharacteristicWithHandle>,
}

/// A GattCharacteristic consists of a handle (where the value attribute lives),
/// a UUID identifying its type, and permissions indicating what operations can
/// be performed
#[derive(Debug, Clone)]
pub struct GattCharacteristicWithHandle {
    /// The handle of the characteristic value attribute. The characteristic
    /// declaration is one before this handle.
    pub handle: AttHandle,
    /// The UUID representing the type of the characteristic value.
    pub type_: Uuid,
    /// The permissions (read/write) indicate what operations can be performed.
    pub permissions: AttPermissions,
    /// The descriptors associated with this characteristic
    pub descriptors: Vec<GattDescriptorWithHandle>,
}

/// A GattDescriptor consists of a handle, type_, and permissions (similar to a
/// GattCharacteristic) It is guaranteed that the handle of the GattDescriptor
/// is after the handle of the characteristic value attribute, and before the
/// next characteristic/service declaration
#[derive(Debug, Clone)]
pub struct GattDescriptorWithHandle {
    /// The handle of the descriptor.
    pub handle: AttHandle,
    /// The UUID representing the type of the descriptor.
    pub type_: Uuid,
    /// The permissions (read/write) indicate what operations can be performed.
    pub permissions: AttPermissions,
}

/// The GattDatabase implements AttDatabase, and converts attribute reads/writes
/// into GATT operations to be sent to the upper layers
#[derive(Default)]
pub struct GattDatabase<T: ?Sized> {
    datastore: Rc<T>,
    schema: RefCell<GattDatabaseSchema>,
}

#[derive(Default)]
struct GattDatabaseSchema {
    attributes: BTreeMap<AttHandle, AttAttributeWithBackingValue>,
}

#[derive(Clone)]
enum AttAttributeBackingValue {
    Static(AttAttributeDataChild),
    DynamicCharacteristic,
    DynamicDescriptor,
}

#[derive(Clone)]
struct AttAttributeWithBackingValue {
    attribute: AttAttribute,
    value: AttAttributeBackingValue,
}

// TODO(aryarahul) - send srvc_chg indication when the schema is modified
impl<T: GattDatastore + ?Sized> GattDatabase<T> {
    /// Constructor, wrapping a GattDatastore
    pub fn new(datastore: Rc<T>) -> Self {
        Self { datastore, schema: Default::default() }
    }

    /// Add a service with pre-allocated handles (for co-existence with C++)
    /// Assumes that the characteristic DECLARATION handles are one less than
    /// the characteristic handles.
    /// Returns failure if handles overlap with ones already allocated
    pub fn add_service_with_handles(&self, service: GattServiceWithHandle) -> Result<()> {
        let mut attributes = BTreeMap::new();
        let mut attribute_cnt = 0;

        let mut add_attribute = |attribute: AttAttribute, value: AttAttributeBackingValue| {
            attribute_cnt += 1;
            attributes.insert(attribute.handle, AttAttributeWithBackingValue { attribute, value })
        };

        let mut characteristics = vec![];

        // service definition
        add_attribute(
            AttAttribute {
                handle: service.handle,
                type_: PRIMARY_SERVICE_DECLARATION_UUID,
                permissions: AttPermissions::READABLE,
            },
            AttAttributeBackingValue::Static(
                GattServiceDeclarationValueBuilder { uuid: UuidBuilder::from(service.type_) }
                    .into(),
            ),
        );

        // characteristics
        for characteristic in service.characteristics {
            characteristics.push(characteristic.clone());

            // declaration
            // Recall that we assume the declaration handle is one less than the value
            // handle
            let declaration_handle = AttHandle(characteristic.handle.0 - 1);

            add_attribute(
                AttAttribute {
                    handle: declaration_handle,
                    type_: CHARACTERISTIC_UUID,
                    permissions: AttPermissions::READABLE,
                },
                AttAttributeBackingValue::Static(
                    GattCharacteristicDeclarationValueBuilder {
                        properties: GattCharacteristicPropertiesBuilder {
                            broadcast: 0,
                            read: characteristic.permissions.readable().into(),
                            write_without_response: 0,
                            write: characteristic.permissions.writable().into(),
                            notify: 0,
                            indicate: characteristic.permissions.indicate().into(),
                            authenticated_signed_writes: 0,
                            extended_properties: 0,
                        },
                        handle: characteristic.handle.into(),
                        uuid: characteristic.type_.into(),
                    }
                    .into(),
                ),
            );

            // value
            add_attribute(
                AttAttribute {
                    handle: characteristic.handle,
                    type_: characteristic.type_,
                    permissions: characteristic.permissions,
                },
                AttAttributeBackingValue::DynamicCharacteristic,
            );

            // descriptors
            for descriptor in characteristic.descriptors {
                add_attribute(
                    AttAttribute {
                        handle: descriptor.handle,
                        type_: descriptor.type_,
                        permissions: descriptor.permissions,
                    },
                    AttAttributeBackingValue::DynamicDescriptor,
                );
            }
        }

        // validate attributes for overlap
        let mut static_data = self.schema.borrow_mut();

        for handle in attributes.keys() {
            if static_data.attributes.contains_key(handle) {
                bail!("duplicate handle detected");
            }
        }
        if attributes.len() != attribute_cnt {
            bail!("duplicate handle detected");
        }

        // if we made it here, we successfully loaded the new service
        static_data.attributes.extend(attributes.into_iter());
        Ok(())
    }

    /// Remove a previously-added service by service handle
    pub fn remove_service_at_handle(&self, service_handle: AttHandle) -> Result<()> {
        let mut static_data = self.schema.borrow_mut();

        // find next service
        let next_service_handle = static_data
            .attributes
            .values()
            .find(|attribute| {
                attribute.attribute.handle > service_handle
                    && attribute.attribute.type_ == PRIMARY_SERVICE_DECLARATION_UUID
            })
            .map(|service| service.attribute.handle);

        // clear out attributes
        static_data.attributes.retain(|curr_handle, _| {
            !(service_handle <= *curr_handle
                && next_service_handle.map(|x| *curr_handle < x).unwrap_or(true))
        });

        Ok(())
    }
}

impl<T: GattDatastore + ?Sized> SharedBox<GattDatabase<T>> {
    /// Generate an impl AttDatabase from a backing GattDatabase, associated
    /// with a given connection.
    pub fn get_att_database(&self, conn_id: ConnectionId) -> AttDatabaseImpl<T> {
        AttDatabaseImpl { gatt_db: self.downgrade(), conn_id }
    }
}

/// An implementation of AttDatabase wrapping an underlying GattDatabase
pub struct AttDatabaseImpl<T: ?Sized> {
    gatt_db: WeakBox<GattDatabase<T>>,
    conn_id: ConnectionId,
}

#[async_trait(?Send)]
impl<T> AttDatabase for AttDatabaseImpl<T>
where
    T: GattDatastore + ?Sized,
{
    async fn read_attribute(
        &self,
        handle: AttHandle,
    ) -> Result<AttAttributeDataChild, AttErrorCode> {
        let (value, datastore) = self.gatt_db.with(|gatt_db| {
            let Some(gatt_db) = gatt_db else {
                // db must have been closed
                return Err(AttErrorCode::INVALID_HANDLE);
            };
            let services = gatt_db.schema.borrow();
            let Some(attr) = services.attributes.get(&handle) else {
                return Err(AttErrorCode::INVALID_HANDLE);
            };
            if !attr.attribute.permissions.readable() {
                return Err(AttErrorCode::READ_NOT_PERMITTED);
            }
            Ok((attr.value.clone(), gatt_db.datastore.clone()))
        })?;

        match value {
            AttAttributeBackingValue::Static(val) => return Ok(val),
            AttAttributeBackingValue::DynamicCharacteristic => {
                datastore.read(self.conn_id, handle, AttributeBackingType::Characteristic).await
            }
            AttAttributeBackingValue::DynamicDescriptor => {
                datastore.read(self.conn_id, handle, AttributeBackingType::Descriptor).await
            }
        }
    }

    async fn write_attribute(
        &self,
        handle: AttHandle,
        data: AttAttributeDataView<'_>,
    ) -> Result<(), AttErrorCode> {
        let (value, datastore) = self.gatt_db.with(|gatt_db| {
            let Some(gatt_db) = gatt_db else {
                // db must have been closed
                return Err(AttErrorCode::INVALID_HANDLE);
            };
            let services = gatt_db.schema.borrow();
            let Some(attr) = services.attributes.get(&handle) else {
                return Err(AttErrorCode::INVALID_HANDLE);
            };
            if !attr.attribute.permissions.writable() {
                return Err(AttErrorCode::WRITE_NOT_PERMITTED);
            }
            Ok((attr.value.clone(), gatt_db.datastore.clone()))
        })?;

        match value {
            AttAttributeBackingValue::Static(val) => {
                error!("A static attribute {val:?} is marked as writable - ignoring it and rejecting the write...");
                return Err(AttErrorCode::WRITE_NOT_PERMITTED);
            }
            AttAttributeBackingValue::DynamicCharacteristic => {
                datastore
                    .write(self.conn_id, handle, AttributeBackingType::Characteristic, data)
                    .await
            }
            AttAttributeBackingValue::DynamicDescriptor => {
                datastore.write(self.conn_id, handle, AttributeBackingType::Descriptor, data).await
            }
        }
    }

    fn list_attributes(&self) -> Vec<AttAttribute> {
        self.gatt_db.with(|db| {
            db.map(|db| db.schema.borrow().attributes.values().map(|attr| attr.attribute).collect())
                .unwrap_or_default()
        })
    }
}

impl<T: ?Sized> Clone for AttDatabaseImpl<T> {
    fn clone(&self) -> Self {
        Self { gatt_db: self.gatt_db.clone(), conn_id: self.conn_id }
    }
}

#[cfg(test)]
mod test {
    use tokio::{join, task::spawn_local};

    use crate::{
        gatt::mocks::mock_datastore::{MockDatastore, MockDatastoreEvents},
        packets::Packet,
        utils::{
            packet::{build_att_data, build_view_or_crash},
            task::block_on_locally,
        },
    };

    use super::*;

    const SERVICE_HANDLE: AttHandle = AttHandle(1);
    const SERVICE_TYPE: Uuid = Uuid::new(0x1234);

    const CHARACTERISTIC_DECLARATION_HANDLE: AttHandle = AttHandle(2);
    const CHARACTERISTIC_VALUE_HANDLE: AttHandle = AttHandle(3);
    const CHARACTERISTIC_TYPE: Uuid = Uuid::new(0x5678);

    const DESCRIPTOR_HANDLE: AttHandle = AttHandle(4);
    const DESCRIPTOR_TYPE: Uuid = Uuid::new(0x9ABC);

    const CONN_ID: ConnectionId = ConnectionId(1);

    #[test]
    fn test_read_empty_db() {
        let (gatt_datastore, _) = MockDatastore::new();
        let gatt_db = SharedBox::new(GattDatabase::new(gatt_datastore.into()));
        let att_db = gatt_db.get_att_database(CONN_ID);

        let resp = tokio_test::block_on(att_db.read_attribute(AttHandle(1)));

        assert_eq!(resp, Err(AttErrorCode::INVALID_HANDLE))
    }

    #[test]
    fn test_single_service() {
        let (gatt_datastore, _) = MockDatastore::new();
        let gatt_db = SharedBox::new(GattDatabase::new(gatt_datastore.into()));
        gatt_db
            .add_service_with_handles(GattServiceWithHandle {
                handle: SERVICE_HANDLE,
                type_: SERVICE_TYPE,
                characteristics: vec![],
            })
            .unwrap();
        let att_db = gatt_db.get_att_database(CONN_ID);

        let attrs = att_db.list_attributes();
        let service_value = tokio_test::block_on(att_db.read_attribute(SERVICE_HANDLE));

        assert_eq!(
            attrs,
            vec![AttAttribute {
                handle: SERVICE_HANDLE,
                type_: PRIMARY_SERVICE_DECLARATION_UUID,
                permissions: AttPermissions::READABLE
            }]
        );
        assert_eq!(
            service_value,
            Ok(AttAttributeDataChild::GattServiceDeclarationValue(
                GattServiceDeclarationValueBuilder { uuid: SERVICE_TYPE.into() }
            ))
        );
    }

    #[test]
    fn test_service_removal() {
        // arrange three services, each with a single characteristic
        let (gatt_datastore, _) = MockDatastore::new();
        let gatt_db = SharedBox::new(GattDatabase::new(gatt_datastore.into()));

        gatt_db
            .add_service_with_handles(GattServiceWithHandle {
                handle: AttHandle(1),
                type_: SERVICE_TYPE,
                characteristics: vec![GattCharacteristicWithHandle {
                    handle: AttHandle(3),
                    type_: CHARACTERISTIC_TYPE,
                    permissions: AttPermissions::READABLE,
                    descriptors: vec![],
                }],
            })
            .unwrap();
        gatt_db
            .add_service_with_handles(GattServiceWithHandle {
                handle: AttHandle(4),
                type_: SERVICE_TYPE,
                characteristics: vec![GattCharacteristicWithHandle {
                    handle: AttHandle(6),
                    type_: CHARACTERISTIC_TYPE,
                    permissions: AttPermissions::READABLE,
                    descriptors: vec![],
                }],
            })
            .unwrap();
        gatt_db
            .add_service_with_handles(GattServiceWithHandle {
                handle: AttHandle(7),
                type_: SERVICE_TYPE,
                characteristics: vec![GattCharacteristicWithHandle {
                    handle: AttHandle(9),
                    type_: CHARACTERISTIC_TYPE,
                    permissions: AttPermissions::READABLE,
                    descriptors: vec![],
                }],
            })
            .unwrap();
        let att_db = gatt_db.get_att_database(CONN_ID);
        assert_eq!(att_db.list_attributes().len(), 9);

        // act: remove the middle service
        gatt_db.remove_service_at_handle(AttHandle(4)).unwrap();
        let attrs = att_db.list_attributes();

        // assert that the middle service is gone
        assert_eq!(attrs.len(), 6, "{attrs:?}");

        // assert the other two old services are still there
        assert_eq!(
            attrs[0],
            AttAttribute {
                handle: AttHandle(1),
                type_: PRIMARY_SERVICE_DECLARATION_UUID,
                permissions: AttPermissions::READABLE
            }
        );
        assert_eq!(
            attrs[3],
            AttAttribute {
                handle: AttHandle(7),
                type_: PRIMARY_SERVICE_DECLARATION_UUID,
                permissions: AttPermissions::READABLE
            }
        );
    }

    #[test]
    fn test_single_characteristic_declaration() {
        let (gatt_datastore, _) = MockDatastore::new();
        let gatt_db = SharedBox::new(GattDatabase::new(gatt_datastore.into()));
        gatt_db
            .add_service_with_handles(GattServiceWithHandle {
                handle: SERVICE_HANDLE,
                type_: SERVICE_TYPE,
                characteristics: vec![GattCharacteristicWithHandle {
                    handle: CHARACTERISTIC_VALUE_HANDLE,
                    type_: CHARACTERISTIC_TYPE,
                    permissions: AttPermissions::READABLE
                        | AttPermissions::WRITABLE
                        | AttPermissions::INDICATE,
                    descriptors: vec![],
                }],
            })
            .unwrap();
        let att_db = gatt_db.get_att_database(CONN_ID);

        let attrs = att_db.list_attributes();
        let characteristic_decl =
            tokio_test::block_on(att_db.read_attribute(CHARACTERISTIC_DECLARATION_HANDLE));

        assert_eq!(attrs.len(), 3, "{attrs:?}");
        assert_eq!(attrs[0].type_, PRIMARY_SERVICE_DECLARATION_UUID);
        assert_eq!(
            attrs[1],
            AttAttribute {
                handle: CHARACTERISTIC_DECLARATION_HANDLE,
                type_: CHARACTERISTIC_UUID,
                permissions: AttPermissions::READABLE
            }
        );
        assert_eq!(
            attrs[2],
            AttAttribute {
                handle: CHARACTERISTIC_VALUE_HANDLE,
                type_: CHARACTERISTIC_TYPE,
                permissions: AttPermissions::READABLE
                    | AttPermissions::WRITABLE
                    | AttPermissions::INDICATE
            }
        );

        assert_eq!(
            characteristic_decl,
            Ok(AttAttributeDataChild::GattCharacteristicDeclarationValue(
                GattCharacteristicDeclarationValueBuilder {
                    properties: GattCharacteristicPropertiesBuilder {
                        read: 1,
                        broadcast: 0,
                        write_without_response: 0,
                        write: 1,
                        notify: 0,
                        indicate: 1,
                        authenticated_signed_writes: 0,
                        extended_properties: 0,
                    },
                    handle: CHARACTERISTIC_VALUE_HANDLE.into(),
                    uuid: CHARACTERISTIC_TYPE.into()
                }
            ))
        );
    }

    #[test]
    fn test_single_characteristic_value() {
        // arrange: create a database with a single characteristic
        let (gatt_datastore, mut data_evts) = MockDatastore::new();
        let gatt_db = SharedBox::new(GattDatabase::new(gatt_datastore.into()));
        gatt_db
            .add_service_with_handles(GattServiceWithHandle {
                handle: SERVICE_HANDLE,
                type_: SERVICE_TYPE,
                characteristics: vec![GattCharacteristicWithHandle {
                    handle: CHARACTERISTIC_VALUE_HANDLE,
                    type_: CHARACTERISTIC_TYPE,
                    permissions: AttPermissions::READABLE,
                    descriptors: vec![],
                }],
            })
            .unwrap();
        let att_db = gatt_db.get_att_database(CONN_ID);
        let data = AttAttributeDataChild::RawData(Box::new([1, 2]));

        // act: read from the database, and supply a value from the backing datastore
        let characteristic_value = tokio_test::block_on(async {
            join!(
                async {
                    let MockDatastoreEvents::Read(
                    CONN_ID,
                    CHARACTERISTIC_VALUE_HANDLE,
                    AttributeBackingType::Characteristic,
                    reply,
                ) = data_evts.recv().await.unwrap() else {
                    unreachable!()
                };
                    reply.send(Ok(data.clone())).unwrap();
                },
                att_db.read_attribute(CHARACTERISTIC_VALUE_HANDLE)
            )
            .1
        });

        // assert: the supplied value matches what the att datastore returned
        assert_eq!(characteristic_value, Ok(data));
    }

    #[test]
    fn test_unreadable_characteristic() {
        let (gatt_datastore, _) = MockDatastore::new();
        let gatt_db = SharedBox::new(GattDatabase::new(gatt_datastore.into()));
        gatt_db
            .add_service_with_handles(GattServiceWithHandle {
                handle: SERVICE_HANDLE,
                type_: SERVICE_TYPE,
                characteristics: vec![GattCharacteristicWithHandle {
                    handle: CHARACTERISTIC_VALUE_HANDLE,
                    type_: CHARACTERISTIC_TYPE,
                    permissions: AttPermissions::empty(),
                    descriptors: vec![],
                }],
            })
            .unwrap();

        let characteristic_value = tokio_test::block_on(
            gatt_db.get_att_database(CONN_ID).read_attribute(CHARACTERISTIC_VALUE_HANDLE),
        );

        assert_eq!(characteristic_value, Err(AttErrorCode::READ_NOT_PERMITTED));
    }

    #[test]
    fn test_handle_clash() {
        let (gatt_datastore, _) = MockDatastore::new();
        let gatt_db = SharedBox::new(GattDatabase::new(gatt_datastore.into()));

        let result = gatt_db.add_service_with_handles(GattServiceWithHandle {
            handle: SERVICE_HANDLE,
            type_: SERVICE_TYPE,
            characteristics: vec![GattCharacteristicWithHandle {
                handle: SERVICE_HANDLE,
                type_: CHARACTERISTIC_TYPE,
                permissions: AttPermissions::WRITABLE,
                descriptors: vec![],
            }],
        });

        assert!(result.is_err());
    }

    #[test]
    fn test_handle_clash_with_existing() {
        let (gatt_datastore, _) = MockDatastore::new();
        let gatt_db = Rc::new(GattDatabase::new(gatt_datastore.into()));

        gatt_db
            .add_service_with_handles(GattServiceWithHandle {
                handle: SERVICE_HANDLE,
                type_: SERVICE_TYPE,
                characteristics: vec![],
            })
            .unwrap();

        let result = gatt_db.add_service_with_handles(GattServiceWithHandle {
            handle: SERVICE_HANDLE,
            type_: SERVICE_TYPE,
            characteristics: vec![],
        });

        assert!(result.is_err());
    }

    #[test]
    fn test_write_single_characteristic_callback_invoked() {
        // arrange: create a database with a single characteristic
        let (gatt_datastore, mut data_evts) = MockDatastore::new();
        let gatt_db = SharedBox::new(GattDatabase::new(gatt_datastore.into()));
        gatt_db
            .add_service_with_handles(GattServiceWithHandle {
                handle: SERVICE_HANDLE,
                type_: SERVICE_TYPE,
                characteristics: vec![GattCharacteristicWithHandle {
                    handle: CHARACTERISTIC_VALUE_HANDLE,
                    type_: CHARACTERISTIC_TYPE,
                    permissions: AttPermissions::WRITABLE,
                    descriptors: vec![],
                }],
            })
            .unwrap();
        let att_db = gatt_db.get_att_database(CONN_ID);
        let data =
            build_view_or_crash(build_att_data(AttAttributeDataChild::RawData(Box::new([1, 2]))));

        // act: write to the database
        let recv_data = block_on_locally(async {
            // start write task
            let cloned_data = data.view().to_owned_packet();
            spawn_local(async move {
                att_db
                    .write_attribute(CHARACTERISTIC_VALUE_HANDLE, cloned_data.view())
                    .await
                    .unwrap();
            });

            let MockDatastoreEvents::Write(
                CONN_ID,
                CHARACTERISTIC_VALUE_HANDLE,
                AttributeBackingType::Characteristic,
                recv_data,
                _,
            ) = data_evts.recv().await.unwrap() else {
                unreachable!();
            };
            recv_data
        });

        // assert: the received value matches what we supplied
        assert_eq!(
            recv_data.view().get_raw_payload().collect::<Vec<_>>(),
            data.view().get_raw_payload().collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_write_single_characteristic_recv_response() {
        // arrange: create a database with a single characteristic
        let (gatt_datastore, mut data_evts) = MockDatastore::new();
        let gatt_db = SharedBox::new(GattDatabase::new(gatt_datastore.into()));
        gatt_db
            .add_service_with_handles(GattServiceWithHandle {
                handle: SERVICE_HANDLE,
                type_: SERVICE_TYPE,
                characteristics: vec![GattCharacteristicWithHandle {
                    handle: CHARACTERISTIC_VALUE_HANDLE,
                    type_: CHARACTERISTIC_TYPE,
                    permissions: AttPermissions::WRITABLE,
                    descriptors: vec![],
                }],
            })
            .unwrap();
        let att_db = gatt_db.get_att_database(CONN_ID);
        let data =
            build_view_or_crash(build_att_data(AttAttributeDataChild::RawData(Box::new([1, 2]))));

        // act: write to the database
        let res = tokio_test::block_on(async {
            join!(
                async {
                    let MockDatastoreEvents::Write(_,_,_,_,reply) = data_evts.recv().await.unwrap() else {
                        unreachable!();
                    };
                    reply.send(Err(AttErrorCode::UNLIKELY_ERROR)).unwrap();
                },
                att_db.write_attribute(CHARACTERISTIC_VALUE_HANDLE, data.view())
            )
            .1
        });

        // assert: the supplied value matches what the att datastore returned
        assert_eq!(res, Err(AttErrorCode::UNLIKELY_ERROR));
    }

    #[test]
    fn test_unwriteable_characteristic() {
        let (gatt_datastore, _) = MockDatastore::new();
        let gatt_db = SharedBox::new(GattDatabase::new(gatt_datastore.into()));
        gatt_db
            .add_service_with_handles(GattServiceWithHandle {
                handle: SERVICE_HANDLE,
                type_: SERVICE_TYPE,
                characteristics: vec![GattCharacteristicWithHandle {
                    handle: CHARACTERISTIC_VALUE_HANDLE,
                    type_: CHARACTERISTIC_TYPE,
                    permissions: AttPermissions::READABLE,
                    descriptors: vec![],
                }],
            })
            .unwrap();
        let data =
            build_view_or_crash(build_att_data(AttAttributeDataChild::RawData(Box::new([1, 2]))));

        let characteristic_value = tokio_test::block_on(
            gatt_db
                .get_att_database(CONN_ID)
                .write_attribute(CHARACTERISTIC_VALUE_HANDLE, data.view()),
        );

        assert_eq!(characteristic_value, Err(AttErrorCode::WRITE_NOT_PERMITTED));
    }

    #[test]
    fn test_single_descriptor_declaration() {
        let (gatt_datastore, mut data_evts) = MockDatastore::new();
        let gatt_db = SharedBox::new(GattDatabase::new(gatt_datastore.into()));
        gatt_db
            .add_service_with_handles(GattServiceWithHandle {
                handle: SERVICE_HANDLE,
                type_: SERVICE_TYPE,
                characteristics: vec![GattCharacteristicWithHandle {
                    handle: CHARACTERISTIC_VALUE_HANDLE,
                    type_: CHARACTERISTIC_TYPE,
                    permissions: AttPermissions::READABLE,
                    descriptors: vec![GattDescriptorWithHandle {
                        handle: DESCRIPTOR_HANDLE,
                        type_: DESCRIPTOR_TYPE,
                        permissions: AttPermissions::READABLE,
                    }],
                }],
            })
            .unwrap();
        let att_db = gatt_db.get_att_database(CONN_ID);
        let data = AttAttributeDataChild::RawData(Box::new([1, 2]));

        let descriptor_value = block_on_locally(async {
            // start write task
            let pending_read =
                spawn_local(async move { att_db.read_attribute(DESCRIPTOR_HANDLE).await.unwrap() });

            let MockDatastoreEvents::Read(
                CONN_ID,
                DESCRIPTOR_HANDLE,
                AttributeBackingType::Descriptor,
                reply,
            ) = data_evts.recv().await.unwrap() else {
                unreachable!();
            };

            reply.send(Ok(data.clone())).unwrap();

            pending_read.await.unwrap()
        });

        assert_eq!(descriptor_value, data);
    }

    #[test]
    fn test_write_descriptor() {
        // arrange: db with a writable descriptor
        let (gatt_datastore, mut data_evts) = MockDatastore::new();
        let gatt_db = SharedBox::new(GattDatabase::new(gatt_datastore.into()));
        gatt_db
            .add_service_with_handles(GattServiceWithHandle {
                handle: SERVICE_HANDLE,
                type_: SERVICE_TYPE,
                characteristics: vec![GattCharacteristicWithHandle {
                    handle: CHARACTERISTIC_VALUE_HANDLE,
                    type_: CHARACTERISTIC_TYPE,
                    permissions: AttPermissions::READABLE,
                    descriptors: vec![GattDescriptorWithHandle {
                        handle: DESCRIPTOR_HANDLE,
                        type_: DESCRIPTOR_TYPE,
                        permissions: AttPermissions::WRITABLE,
                    }],
                }],
            })
            .unwrap();
        let att_db = gatt_db.get_att_database(CONN_ID);
        let data =
            build_view_or_crash(build_att_data(AttAttributeDataChild::RawData(Box::new([1, 2]))));

        // act: write, and wait for the callback to be invoked
        block_on_locally(async {
            // start write task
            spawn_local(async move {
                att_db.write_attribute(DESCRIPTOR_HANDLE, data.view()).await.unwrap()
            });

            let MockDatastoreEvents::Write(
                CONN_ID,
                DESCRIPTOR_HANDLE,
                AttributeBackingType::Descriptor,
                _,
                _,
            ) = data_evts.recv().await.unwrap() else {
                unreachable!();
            };
        });

        // assert: nothing, if we reach this far we are OK
    }

    #[test]
    fn test_multiple_descriptors() {
        // arrange: a database with some characteristics and descriptors
        let (gatt_datastore, _) = MockDatastore::new();
        let gatt_db = SharedBox::new(GattDatabase::new(gatt_datastore.into()));
        gatt_db
            .add_service_with_handles(GattServiceWithHandle {
                handle: AttHandle(1),
                type_: SERVICE_TYPE,
                characteristics: vec![
                    GattCharacteristicWithHandle {
                        handle: AttHandle(3),
                        type_: CHARACTERISTIC_TYPE,
                        permissions: AttPermissions::READABLE,
                        descriptors: vec![GattDescriptorWithHandle {
                            handle: AttHandle(4),
                            type_: DESCRIPTOR_TYPE,
                            permissions: AttPermissions::READABLE,
                        }],
                    },
                    GattCharacteristicWithHandle {
                        handle: AttHandle(6),
                        type_: CHARACTERISTIC_TYPE,
                        permissions: AttPermissions::READABLE,
                        descriptors: vec![
                            GattDescriptorWithHandle {
                                handle: AttHandle(7),
                                type_: DESCRIPTOR_TYPE,
                                permissions: AttPermissions::WRITABLE,
                            },
                            GattDescriptorWithHandle {
                                handle: AttHandle(8),
                                type_: DESCRIPTOR_TYPE,
                                permissions: AttPermissions::READABLE | AttPermissions::WRITABLE,
                            },
                        ],
                    },
                ],
            })
            .unwrap();

        // act: get the attributes
        let attributes = gatt_db.get_att_database(CONN_ID).list_attributes();

        // assert: check the attributes are in the correct order
        assert_eq!(attributes.len(), 8);
        assert_eq!(attributes[0].type_, PRIMARY_SERVICE_DECLARATION_UUID);
        assert_eq!(attributes[1].type_, CHARACTERISTIC_UUID);
        assert_eq!(attributes[2].type_, CHARACTERISTIC_TYPE);
        assert_eq!(attributes[3].type_, DESCRIPTOR_TYPE);
        assert_eq!(attributes[4].type_, CHARACTERISTIC_UUID);
        assert_eq!(attributes[5].type_, CHARACTERISTIC_TYPE);
        assert_eq!(attributes[6].type_, DESCRIPTOR_TYPE);
        assert_eq!(attributes[7].type_, DESCRIPTOR_TYPE);
        // assert: check the handles of the descriptors are correct
        assert_eq!(attributes[3].handle, AttHandle(4));
        assert_eq!(attributes[6].handle, AttHandle(7));
        assert_eq!(attributes[7].handle, AttHandle(8));
        // assert: check the permissions of the descriptors are correct
        assert_eq!(attributes[3].permissions, AttPermissions::READABLE);
        assert_eq!(attributes[6].permissions, AttPermissions::WRITABLE);
        assert_eq!(attributes[7].permissions, AttPermissions::READABLE | AttPermissions::WRITABLE);
    }
}
