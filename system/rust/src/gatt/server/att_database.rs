use crate::{
    gatt::ids::AttHandle,
    packets::{AttHandleBuilder, AttHandleView},
};

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
