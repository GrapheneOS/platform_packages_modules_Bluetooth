//! These are the interfaces between the GattModule and JNI. The synchronous
//! interface is mapped to the asynchronous interface using the
//! CallbackTransactionManager;

mod callback_transaction_manager;

pub use callback_transaction_manager::{CallbackResponseError, CallbackTransactionManager};

use async_trait::async_trait;

use crate::packets::{AttAttributeDataChild, AttAttributeDataView, AttErrorCode};

use super::{
    ffi::AttributeBackingType,
    ids::{AttHandle, ConnectionId, TransactionId},
    server::IndicationError,
};

/// These callbacks are expected to be made available to the GattModule from
/// JNI.
pub trait GattCallbacks {
    /// Invoked when a client tries to read a characteristic/descriptor. Expects
    /// a response using bluetooth::gatt::send_response();
    fn on_server_read(
        &self,
        conn_id: ConnectionId,
        trans_id: TransactionId,
        handle: AttHandle,
        attr_type: AttributeBackingType,
        offset: u32,
        is_long: bool,
    );

    /// Invoked when a client tries to write a characteristic/descriptor.
    /// Expects a response using bluetooth::gatt::send_response();
    #[allow(clippy::too_many_arguments)] // needed to match the C++ interface
    fn on_server_write(
        &self,
        conn_id: ConnectionId,
        trans_id: TransactionId,
        handle: AttHandle,
        attr_type: AttributeBackingType,
        offset: u32,
        need_response: bool,
        is_prepare: bool,
        value: AttAttributeDataView,
    );

    /// Invoked when a handle value indication transaction completes
    /// (either due to an error, link loss, or the peer confirming it)
    fn on_indication_sent_confirmation(
        &self,
        conn_id: ConnectionId,
        result: Result<(), IndicationError>,
    );
}

/// This interface is an "async" version of the above, and is passed directly
/// into the GattModule
#[async_trait(?Send)]
pub trait GattDatastore {
    /// Read a characteristic from the specified connection at the given handle.
    async fn read(
        &self,
        conn_id: ConnectionId,
        handle: AttHandle,
        attr_type: AttributeBackingType,
    ) -> Result<AttAttributeDataChild, AttErrorCode>;

    /// Write data to a given characteristic on the specified connection.
    async fn write(
        &self,
        conn_id: ConnectionId,
        handle: AttHandle,
        attr_type: AttributeBackingType,
        data: AttAttributeDataView<'_>,
    ) -> Result<(), AttErrorCode>;
}
