//! This module converts a GattDatastore to an AttDatabase,
//! by converting a registry of services into a list of attributes, and proxying
//! ATT read/write requests into characteristic reads/writes

use std::{cell::RefCell, collections::BTreeMap, rc::Rc};

use anyhow::{anyhow, bail, Result};
use async_trait::async_trait;

use crate::{
    core::uuid::Uuid,
    gatt::ids::AttHandle,
    packets::{
        AttAttributeDataChild, AttCharacteristicPropertiesBuilder, AttErrorCode,
        GattCharacteristicDeclarationValueBuilder, GattServiceDeclarationValueBuilder, UuidBuilder,
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
}

/// The GattDatabase implements AttDatabase, and converts attribute reads/writes
/// into GATT operations to be sent to the upper layers
#[derive(Default)]
pub struct GattDatabase {
    schema: RefCell<GattDatabaseSchema>,
}

#[derive(Default)]
struct GattDatabaseSchema {
    services: Vec<GattServiceWithHandle>,
    attributes: BTreeMap<AttHandle, AttAttributeWithBackingValue>,
}

enum AttAttributeBackingValue {
    Static(AttAttributeDataChild),
    Dynamic,
}

struct AttAttributeWithBackingValue {
    attribute: AttAttribute,
    value: AttAttributeBackingValue,
}

impl GattDatabase {
    /// Constructor
    pub fn new() -> Self {
        Default::default()
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
                permissions: AttPermissions { readable: true, writable: false },
            },
            AttAttributeBackingValue::Static(
                GattServiceDeclarationValueBuilder { uuid: UuidBuilder::from(service.type_) }
                    .into(),
            ),
        );

        // characteristics
        for characteristic in service.characteristics {
            characteristics.push(GattCharacteristicWithHandle {
                handle: characteristic.handle,
                type_: characteristic.type_,
                permissions: characteristic.permissions.clone(),
            });

            // declaration
            // Recall that we assume the declaration handle is one less than the value
            // handle
            let declaration_handle = AttHandle(characteristic.handle.0 - 1);

            add_attribute(
                AttAttribute {
                    handle: declaration_handle,
                    type_: CHARACTERISTIC_UUID,
                    permissions: AttPermissions { readable: true, writable: false },
                },
                AttAttributeBackingValue::Static(
                    GattCharacteristicDeclarationValueBuilder {
                        properties: AttCharacteristicPropertiesBuilder {
                            broadcast: 0,
                            read: characteristic.permissions.readable.into(),
                            write_without_response: 0,
                            write: characteristic.permissions.writable.into(),
                            notify: 0,
                            indicate: 0,
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
                AttAttributeBackingValue::Dynamic,
            );
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
        let service =
            GattServiceWithHandle { handle: service.handle, type_: service.type_, characteristics };
        static_data.services.push(service);
        static_data.attributes.extend(attributes.into_iter());
        Ok(())
    }

    /// Remove a previously-added service by service handle
    pub fn remove_service_at_handle(&self, service_handle: AttHandle) -> Result<()> {
        let mut static_data = self.schema.borrow_mut();

        // remove old service
        static_data
            .services
            .iter()
            .position(|service| service.handle == service_handle)
            .map(|index| static_data.services.remove(index))
            .ok_or_else(|| {
                anyhow!("service at handle {service_handle:?} not found, cannot remove")
            })?;

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

    /// Clear all services
    pub fn clear_all_services(&self) {
        *self.schema.borrow_mut() = Default::default();
    }

    /// Generate an impl AttDatabase from a backing GattDatabase
    pub fn get_att_database(self: &Rc<Self>) -> AttDatabaseImpl {
        AttDatabaseImpl { gatt_db: self.clone() }
    }
}

/// An implementation of AttDatabase wrapping an underlying GattDatabase
pub struct AttDatabaseImpl {
    gatt_db: Rc<GattDatabase>,
}

#[async_trait(?Send)]
impl AttDatabase for AttDatabaseImpl {
    async fn read_attribute(
        &self,
        handle: AttHandle,
    ) -> Result<AttAttributeDataChild, AttErrorCode> {
        {
            let services = self.gatt_db.schema.borrow();
            match services.attributes.get(&handle).map(|attr| &attr.value) {
                Some(AttAttributeBackingValue::Static(val)) => return Ok(val.clone()),
                None => return Err(AttErrorCode::INVALID_HANDLE),
                Some(AttAttributeBackingValue::Dynamic) => { /* fallthrough */ }
            };
        }

        // TODO(aryarahul): read value from upper layers
        Err(AttErrorCode::INVALID_HANDLE)
    }

    fn list_attributes(&self) -> Vec<AttAttribute> {
        self.gatt_db
            .schema
            .borrow()
            .attributes
            .values()
            .map(|attr| attr.attribute.clone())
            .collect()
    }
}

#[cfg(test)]
mod test {
    use super::*;

    const SERVICE_HANDLE: AttHandle = AttHandle(1);
    const SERVICE_TYPE: Uuid = Uuid::new(0x1234);

    const CHARACTERISTIC_DECLARATION_HANDLE: AttHandle = AttHandle(2);
    const CHARACTERISTIC_VALUE_HANDLE: AttHandle = AttHandle(3);
    const CHARACTERISTIC_TYPE: Uuid = Uuid::new(0x5678);

    #[test]
    fn test_read_empty_db() {
        let gatt_db = Rc::new(GattDatabase::new());
        let att_db = gatt_db.get_att_database();

        let resp = tokio_test::block_on(att_db.read_attribute(AttHandle(1)));

        assert_eq!(resp, Err(AttErrorCode::INVALID_HANDLE))
    }

    #[test]
    fn test_single_service() {
        let gatt_db = Rc::new(GattDatabase::new());
        gatt_db
            .add_service_with_handles(GattServiceWithHandle {
                handle: SERVICE_HANDLE,
                type_: SERVICE_TYPE,
                characteristics: vec![],
            })
            .unwrap();
        let att_db = gatt_db.get_att_database();

        let attrs = att_db.list_attributes();
        let service_value = tokio_test::block_on(att_db.read_attribute(SERVICE_HANDLE));

        assert_eq!(
            attrs,
            vec![AttAttribute {
                handle: SERVICE_HANDLE,
                type_: PRIMARY_SERVICE_DECLARATION_UUID,
                permissions: AttPermissions { readable: true, writable: false }
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
        let gatt_db = Rc::new(GattDatabase::new());

        gatt_db
            .add_service_with_handles(GattServiceWithHandle {
                handle: AttHandle(1),
                type_: SERVICE_TYPE,
                characteristics: vec![GattCharacteristicWithHandle {
                    handle: AttHandle(3),
                    type_: CHARACTERISTIC_TYPE,
                    permissions: AttPermissions { readable: true, writable: false },
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
                    permissions: AttPermissions { readable: true, writable: false },
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
                    permissions: AttPermissions { readable: true, writable: false },
                }],
            })
            .unwrap();
        let att_db = gatt_db.get_att_database();
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
                permissions: AttPermissions { readable: true, writable: false }
            }
        );
        assert_eq!(
            attrs[3],
            AttAttribute {
                handle: AttHandle(7),
                type_: PRIMARY_SERVICE_DECLARATION_UUID,
                permissions: AttPermissions { readable: true, writable: false }
            }
        );
    }

    #[test]
    fn test_single_characteristic() {
        let gatt_db = Rc::new(GattDatabase::new());
        gatt_db
            .add_service_with_handles(GattServiceWithHandle {
                handle: SERVICE_HANDLE,
                type_: SERVICE_TYPE,
                characteristics: vec![GattCharacteristicWithHandle {
                    handle: CHARACTERISTIC_VALUE_HANDLE,
                    type_: CHARACTERISTIC_TYPE,
                    permissions: AttPermissions { readable: false, writable: true },
                }],
            })
            .unwrap();
        let att_db = gatt_db.get_att_database();

        let attrs = att_db.list_attributes();
        let characteristic_decl =
            tokio_test::block_on(att_db.read_attribute(CHARACTERISTIC_DECLARATION_HANDLE));
        let characteristic_value =
            tokio_test::block_on(att_db.read_attribute(CHARACTERISTIC_VALUE_HANDLE));

        assert_eq!(attrs.len(), 3, "{attrs:?}");
        assert_eq!(attrs[0].type_, PRIMARY_SERVICE_DECLARATION_UUID);
        assert_eq!(
            attrs[1],
            AttAttribute {
                handle: CHARACTERISTIC_DECLARATION_HANDLE,
                type_: CHARACTERISTIC_UUID,
                permissions: AttPermissions { readable: true, writable: false }
            }
        );
        assert_eq!(
            attrs[2],
            AttAttribute {
                handle: CHARACTERISTIC_VALUE_HANDLE,
                type_: CHARACTERISTIC_TYPE,
                permissions: AttPermissions { readable: false, writable: true }
            }
        );

        assert_eq!(
            characteristic_decl,
            Ok(AttAttributeDataChild::GattCharacteristicDeclarationValue(
                GattCharacteristicDeclarationValueBuilder {
                    properties: AttCharacteristicPropertiesBuilder {
                        read: 0,
                        broadcast: 0,
                        write_without_response: 0,
                        write: 1,
                        notify: 0,
                        indicate: 0,
                        authenticated_signed_writes: 0,
                        extended_properties: 0,
                    },
                    handle: CHARACTERISTIC_VALUE_HANDLE.into(),
                    uuid: CHARACTERISTIC_TYPE.into()
                }
            ))
        );
        // TODO(aryarahul): fix this once attribute value reading works
        assert_eq!(characteristic_value, Err(AttErrorCode::INVALID_HANDLE));
    }

    #[test]
    fn test_handle_clash() {
        let gatt_db = Rc::new(GattDatabase::new());

        let result = gatt_db.add_service_with_handles(GattServiceWithHandle {
            handle: SERVICE_HANDLE,
            type_: SERVICE_TYPE,
            characteristics: vec![GattCharacteristicWithHandle {
                handle: SERVICE_HANDLE,
                type_: CHARACTERISTIC_TYPE,
                permissions: AttPermissions { readable: false, writable: true },
            }],
        });

        assert!(result.is_err());
    }

    #[test]
    fn test_handle_clash_with_existing() {
        let gatt_db = Rc::new(GattDatabase::new());

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
    fn test_clear_all_services() {
        // arrange: db with some services
        let gatt_db = Rc::new(GattDatabase::new());
        gatt_db
            .add_service_with_handles(GattServiceWithHandle {
                handle: SERVICE_HANDLE,
                type_: SERVICE_TYPE,
                characteristics: vec![],
            })
            .unwrap();

        // act: clear services
        gatt_db.clear_all_services();

        // assert: no attributes left, nothing readable
        assert!(gatt_db.get_att_database().list_attributes().is_empty());
        let read_result =
            tokio_test::block_on(gatt_db.get_att_database().read_attribute(SERVICE_HANDLE));
        assert!(read_result.is_err());
    }
}
