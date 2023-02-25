use crate::{
    gatt::{
        ids::AttHandle,
        server::{
            att_database::{AttAttribute, AttDatabase, StableAttDatabase},
            gatt_database::AttPermissions,
        },
    },
    packets::{AttAttributeDataChild, AttAttributeDataView, AttErrorCode},
};

use async_trait::async_trait;
use log::info;
use std::{cell::Cell, collections::BTreeMap};

pub struct TestAttDatabase {
    attributes: BTreeMap<AttHandle, (AttAttribute, Cell<Vec<u8>>)>,
}

impl TestAttDatabase {
    pub fn new(attributes: Vec<(AttAttribute, Vec<u8>)>) -> Self {
        Self {
            attributes: attributes
                .into_iter()
                .map(|(att, data)| (att.handle, (att, Cell::new(data))))
                .collect(),
        }
    }
}

#[async_trait(?Send)]
impl AttDatabase for TestAttDatabase {
    async fn read_attribute(
        &self,
        handle: AttHandle,
    ) -> Result<AttAttributeDataChild, AttErrorCode> {
        info!("reading {handle:?}");
        match self.attributes.get(&handle) {
            Some((AttAttribute { permissions: AttPermissions { readable: false, .. }, .. }, _)) => {
                Err(AttErrorCode::READ_NOT_PERMITTED)
            }
            Some((_, data)) => {
                let contents = data.take();
                data.set(contents.clone());
                Ok(AttAttributeDataChild::RawData(contents.into_boxed_slice()))
            }
            None => Err(AttErrorCode::INVALID_HANDLE),
        }
    }
    async fn write_attribute(
        &self,
        handle: AttHandle,
        data: AttAttributeDataView<'_>,
    ) -> Result<(), AttErrorCode> {
        match self.attributes.get(&handle) {
            Some((AttAttribute { permissions: AttPermissions { writable: false, .. }, .. }, _)) => {
                Err(AttErrorCode::WRITE_NOT_PERMITTED)
            }
            Some((_, data_cell)) => {
                data_cell.replace(data.get_raw_payload().collect());
                Ok(())
            }
            None => Err(AttErrorCode::INVALID_HANDLE),
        }
    }
    fn list_attributes(&self) -> Vec<AttAttribute> {
        self.attributes.values().map(|(att, _)| *att).collect()
    }
}

// We guarantee that the contents of a TestAttDatabase will remain stable
impl StableAttDatabase for TestAttDatabase {}
