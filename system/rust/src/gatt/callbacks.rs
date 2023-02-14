//! These are the interfaces between the GattModule and JNI. The synchronous
//! interface is mapped to the asynchronous interface using the
//! CallbackTransactionManager;

mod callback_transaction_manager;

pub use callback_transaction_manager::{CallbackResponseError, CallbackTransactionManager};

use async_trait::async_trait;

use crate::packets::{AttAttributeDataChild, AttAttributeDataView, AttErrorCode};

use super::ids::{AttHandle, ConnectionId, TransactionId};

/// These callbacks are expected to be made available to the GattModule from
/// JNI.
pub trait GattCallbacks {
    /// Invoked when a client tries to read a characteristic. Expects a response
    /// using bluetooth::gatt::send_response();
    fn on_server_read_characteristic(
        &self,
        conn_id: ConnectionId,
        trans_id: TransactionId,
        handle: AttHandle,
        offset: u32,
        is_long: bool,
    );

    /// Invoked when a client tries to write a characteristic. Expects a
    /// response using bluetooth::gatt::send_response();
    #[allow(clippy::too_many_arguments)] // needed to match the C++ interface
    fn on_server_write_characteristic(
        &self,
        conn_id: ConnectionId,
        trans_id: TransactionId,
        handle: AttHandle,
        offset: u32,
        need_response: bool,
        is_prepare: bool,
        value: AttAttributeDataView,
    );
}

/// This interface is an "async" version of the above, and is passed directly
/// into the GattModule
#[async_trait(?Send)]
pub trait GattDatastore {
    /// Invoked to indicate when a new connection should be tracked
    fn add_connection(&self, conn_id: ConnectionId);

    /// Invoked to indicate that a connection has closed and all
    /// pending transactions can be dropped.
    fn remove_connection(&self, conn_id: ConnectionId);

    /// Read a characteristic from the specified connection at the given handle.
    async fn read_characteristic(
        &self,
        conn_id: ConnectionId,
        handle: AttHandle,
    ) -> Result<AttAttributeDataChild, AttErrorCode>;

    /// Write data to a given characteristic on the specified connection.
    async fn write_characteristic(
        &self,
        conn_id: ConnectionId,
        handle: AttHandle,
        data: AttAttributeDataView<'_>,
    ) -> Result<(), AttErrorCode>;
}
