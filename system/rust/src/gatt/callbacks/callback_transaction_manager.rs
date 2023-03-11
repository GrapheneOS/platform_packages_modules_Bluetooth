use std::{cell::RefCell, collections::HashMap, rc::Rc, time::Duration};

use async_trait::async_trait;
use log::{error, trace, warn};
use tokio::{sync::oneshot, time::timeout};

use crate::{
    gatt::{
        ids::{AttHandle, ConnectionId, TransactionId},
        GattCallbacks,
    },
    packets::{AttAttributeDataChild, AttAttributeDataView, AttErrorCode},
};

use super::{AttributeBackingType, GattDatastore};

struct PendingTransaction {
    response: oneshot::Sender<Result<AttAttributeDataChild, AttErrorCode>>,
}

#[derive(Debug)]
struct PendingTransactionWatcher {
    conn_id: ConnectionId,
    trans_id: TransactionId,
    rx: oneshot::Receiver<Result<AttAttributeDataChild, AttErrorCode>>,
}

enum PendingTransactionError {
    SenderDropped,
    Timeout,
}

impl PendingTransactionWatcher {
    /// Wait for the transaction to resolve, or to hit the timeout. If the
    /// timeout is reached, clean up state related to transaction watching.
    async fn wait(
        self,
        manager: &CallbackTransactionManager,
    ) -> Result<Result<AttAttributeDataChild, AttErrorCode>, PendingTransactionError> {
        match timeout(TIMEOUT, self.rx).await {
            Ok(Ok(result)) => Ok(result),
            Ok(Err(_)) => Err(PendingTransactionError::SenderDropped),
            Err(_) => {
                manager
                    .pending_transactions
                    .borrow_mut()
                    .pending_transactions
                    .remove(&(self.conn_id, self.trans_id));
                Err(PendingTransactionError::Timeout)
            }
        }
    }
}

/// This struct converts the asynchronus read/write operations of GattDatastore
/// into the callback-based interface expected by JNI
pub struct CallbackTransactionManager {
    callbacks: Rc<dyn GattCallbacks>,
    pending_transactions: RefCell<PendingTransactionsState>,
}

struct PendingTransactionsState {
    pending_transactions: HashMap<(ConnectionId, TransactionId), PendingTransaction>,
    next_transaction_id: u32,
}

/// We expect all responses to be provided within this timeout
/// It should be less than 30s, as that is the ATT timeout that causes
/// the client to disconnect.
const TIMEOUT: Duration = Duration::from_secs(15);

/// The cause of a failure to dispatch a call to send_response()
#[derive(Debug, PartialEq, Eq)]
pub enum CallbackResponseError {
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
        if let Some(transaction) = pending.pending_transactions.remove(&(conn_id, trans_id)) {
            if transaction.response.send(value).is_err() {
                Err(CallbackResponseError::ListenerHungUp(trans_id))
            } else {
                trace!("got expected response for transaction {trans_id:?}");
                Ok(())
            }
        } else {
            Err(CallbackResponseError::NonExistentTransaction(trans_id))
        }
    }
}

impl PendingTransactionsState {
    fn start_new_transaction(&mut self, conn_id: ConnectionId) -> PendingTransactionWatcher {
        let trans_id = TransactionId(self.next_transaction_id);
        self.next_transaction_id = self.next_transaction_id.wrapping_add(1);

        let (tx, rx) = oneshot::channel();
        self.pending_transactions.insert((conn_id, trans_id), PendingTransaction { response: tx });
        PendingTransactionWatcher { conn_id, trans_id, rx }
    }
}

#[async_trait(?Send)]
impl GattDatastore for CallbackTransactionManager {
    async fn read(
        &self,
        conn_id: ConnectionId,
        handle: AttHandle,
        attr_type: AttributeBackingType,
    ) -> Result<AttAttributeDataChild, AttErrorCode> {
        let pending_transaction =
            self.pending_transactions.borrow_mut().start_new_transaction(conn_id);
        let trans_id = pending_transaction.trans_id;

        self.callbacks.on_server_read(conn_id, trans_id, handle, attr_type, 0, false);

        match pending_transaction.wait(self).await {
            Ok(value) => value,
            Err(PendingTransactionError::SenderDropped) => {
                warn!("sender side of {trans_id:?} dropped / timed out while handling request - most likely this response will not be sent over the air");
                Err(AttErrorCode::UNLIKELY_ERROR)
            }
            Err(PendingTransactionError::Timeout) => {
                warn!("no response received from Java after timeout - returning UNLIKELY_ERROR");
                Err(AttErrorCode::UNLIKELY_ERROR)
            }
        }
    }

    async fn write(
        &self,
        conn_id: ConnectionId,
        handle: AttHandle,
        attr_type: AttributeBackingType,
        data: AttAttributeDataView<'_>,
    ) -> Result<(), AttErrorCode> {
        let pending_transaction =
            self.pending_transactions.borrow_mut().start_new_transaction(conn_id);
        let trans_id = pending_transaction.trans_id;

        self.callbacks.on_server_write(conn_id, trans_id, handle, attr_type, 0, true, false, data);

        match pending_transaction.wait(self).await {
            Ok(value) => value.map(|_| ()), // the data passed back is irrelevant for write
            // requests
            Err(PendingTransactionError::SenderDropped) => {
                error!("the CallbackTransactionManager dropped the sender TX without sending it");
                Err(AttErrorCode::UNLIKELY_ERROR)
            }
            Err(PendingTransactionError::Timeout) => {
                warn!("no response received from Java after timeout - returning UNLIKELY_ERROR");
                Err(AttErrorCode::UNLIKELY_ERROR)
            }
        }
    }
}
