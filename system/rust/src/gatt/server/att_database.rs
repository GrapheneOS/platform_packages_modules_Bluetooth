use async_trait::async_trait;

use crate::{
    core::uuid::Uuid,
    gatt::ids::AttHandle,
    packets::{AttAttributeDataChild, AttErrorCode, AttHandleBuilder, AttHandleView},
};

// UUIDs from Bluetooth Assigned Numbers Sec 3.6
pub const PRIMARY_SERVICE_DECLARATION_UUID: Uuid = Uuid::new(0x2800);
pub const CHARACTERISTIC_UUID: Uuid = Uuid::new(0x2803);

impl From<AttHandleView<'_>> for AttHandle {
    fn from(value: AttHandleView) -> Self {
        AttHandle(value.get_handle())
    }
}

impl From<AttHandle> for AttHandleBuilder {
    fn from(value: AttHandle) -> Self {
        AttHandleBuilder { handle: value.0 }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttAttribute {
    pub handle: AttHandle,
    pub type_: Uuid,
    pub permissions: AttPermissions,
}

/// The attribute properties supported by the current GATT server implementation
/// Unimplemented properties will default to false.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttPermissions {
    /// Whether an attribute is readable
    pub readable: bool,
    /// Whether an attribute is writable
    /// (using ATT_WRITE_REQ, so a response is expected)
    pub writable: bool,
}

#[async_trait(?Send)]
pub trait AttDatabase {
    /// Read an attribute by handle
    async fn read_attribute(
        &self,
        handle: AttHandle,
    ) -> Result<AttAttributeDataChild, AttErrorCode>;

    /// List all the attributes in this database.
    ///
    /// Expected to return them in sorted order.
    fn list_attributes(&self) -> Vec<AttAttribute>;

    fn find_attribute(&self, handle: AttHandle) -> Option<AttAttribute> {
        self.list_attributes().into_iter().find(|attr| attr.handle == handle)
    }
}
