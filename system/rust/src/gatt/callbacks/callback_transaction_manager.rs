use std::{cell::RefCell, collections::HashMap, rc::Rc};

use async_trait::async_trait;
use log::{trace, warn};
use tokio::sync::oneshot;

use crate::{
    gatt::{
        ids::{AttHandle, ConnectionId, TransactionId},
        GattCallbacks,
    },
    packets::{AttAttributeDataChild, AttAttributeDataView, AttErrorCode},
};

use super::GattDatastore;

struct PendingTransaction {
    response: oneshot::Sender<Result<AttAttributeDataChild, AttErrorCode>>,
}

/// This struct converts the asynchronus read/write operations of GattDatastore
/// into the callback-based interface expected by JNI
pub struct CallbackTransactionManager {
    callbacks: Rc<dyn GattCallbacks>,
    pending_transactions: RefCell<PendingTransactionsState>,
}

struct PendingTransactionsState {
    pending_transactions: HashMap<ConnectionId, HashMap<TransactionId, PendingTransaction>>,
    next_transaction_id: u32,
}

/// The cause of a failure to dispatch a call to send_response()
#[derive(Debug, PartialEq, Eq)]
pub enum CallbackResponseError {
    /// The ConnectionId supplied was invalid
    NonExistentConnection(ConnectionId),
    /// The TransactionId supplied was invalid
    NonExistentTransaction(TransactionId),
    /// The TransactionId was valid but has since terminated
    ListenerHungUp(TransactionId),
}

impl CallbackTransactionManager {
    /// Constructor, wrapping a GattCallbacks instance with the GattDatastore
    /// interface
    pub fn new(callbacks: Rc<dyn GattCallbacks>) -> Self {
        Self {
            callbacks,
            pending_transactions: RefCell::new(PendingTransactionsState {
                pending_transactions: HashMap::new(),
                next_transaction_id: 1,
            }),
        }
    }

    /// Invoked from server implementations in response to read/write requests
    pub fn send_response(
        &self,
        conn_id: ConnectionId,
        trans_id: TransactionId,
        value: Result<AttAttributeDataChild, AttErrorCode>,
    ) -> Result<(), CallbackResponseError> {
        let mut pending = self.pending_transactions.borrow_mut();
        if let Some(pending_transactions) = pending.pending_transactions.get_mut(&conn_id) {
            if let Some(transaction) = pending_transactions.remove(&trans_id) {
                if transaction.response.send(value).is_err() {
                    Err(CallbackResponseError::ListenerHungUp(trans_id))
                } else {
                    trace!("got expected response for transaction {trans_id:?}");
                    Ok(())
                }
            } else {
                Err(CallbackResponseError::NonExistentTransaction(trans_id))
            }
        } else {
            Err(CallbackResponseError::NonExistentConnection(conn_id))
        }
    }
}

impl PendingTransactionsState {
    fn start_new_transaction(
        &mut self,
        conn_id: ConnectionId,
    ) -> Result<
        (TransactionId, oneshot::Receiver<Result<AttAttributeDataChild, AttErrorCode>>),
        AttErrorCode,
    > {
        let trans_id = TransactionId(self.next_transaction_id);
        self.next_transaction_id += 1;

        let (tx, rx) = oneshot::channel();
        let pending_transactions = self.pending_transactions.get_mut(&conn_id);

        if let Some(pending_transactions) = pending_transactions {
            trace!("starting transaction {trans_id:?}");
            pending_transactions.insert(trans_id, PendingTransaction { response: tx });
        } else {
            warn!("dropping read request attempt for transaction {trans_id:?} since connection is down - this error code should not be sent to the peer");
            return Err(AttErrorCode::UNLIKELY_ERROR);
        }

        Ok((trans_id, rx))
    }
}

#[async_trait(?Send)]
impl GattDatastore for CallbackTransactionManager {
    fn add_connection(&self, conn_id: ConnectionId) {
        let old_conn = self
            .pending_transactions
            .borrow_mut()
            .pending_transactions
            .insert(conn_id, HashMap::new());
        assert!(old_conn.is_none(), "Connection ID reuse, something has gone wrong")
    }

    fn remove_connection(&self, conn_id: ConnectionId) {
        let old_conn = self.pending_transactions.borrow_mut().pending_transactions.remove(&conn_id);
        assert!(old_conn.is_some(), "Received unexpected connection ID, something has gone wrong")
    }

    async fn read_characteristic(
        &self,
        conn_id: ConnectionId,
        handle: AttHandle,
    ) -> Result<AttAttributeDataChild, AttErrorCode> {
        let (trans_id, rx) =
            self.pending_transactions.borrow_mut().start_new_transaction(conn_id)?;

        self.callbacks.on_server_read_characteristic(conn_id, trans_id, handle, 0, false);

        if let Ok(value) = rx.await {
            value
        } else {
            warn!("sender side of {trans_id:?} dropped while handling request - most likely this response will not be sent over the air");
            Err(AttErrorCode::UNLIKELY_ERROR)
        }
    }

    async fn write_characteristic(
        &self,
        conn_id: ConnectionId,
        handle: AttHandle,
        data: AttAttributeDataView<'_>,
    ) -> Result<(), AttErrorCode> {
        let (trans_id, rx) =
            self.pending_transactions.borrow_mut().start_new_transaction(conn_id)?;

        self.callbacks
            .on_server_write_characteristic(conn_id, trans_id, handle, 0, true, false, data);

        if let Ok(value) = rx.await {
            value.map(|_| ()) // the data passed back is irrelevant for write
                              // requests
        } else {
            warn!("sender side of {trans_id:?} dropped while handling request - most likely this response will not be sent over the air");
            Err(AttErrorCode::UNLIKELY_ERROR)
        }
    }
}
