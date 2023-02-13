//! Mocked implementation of GattCallbacks for use in test

use crate::gatt::{
    ids::{AttHandle, ConnectionId, TransactionId},
    GattCallbacks,
};
use tokio::sync::mpsc::{self, unbounded_channel, UnboundedReceiver};

/// Routes calls to GattCallbacks into a channel of MockCallbackEvents
pub struct MockCallbacks(mpsc::UnboundedSender<MockCallbackEvents>);

impl MockCallbacks {
    /// Constructor. Returns self and the RX side of the associated channel.
    pub fn new() -> (Self, UnboundedReceiver<MockCallbackEvents>) {
        let (tx, rx) = unbounded_channel();
        (Self(tx), rx)
    }
}

/// Events representing calls to GattCallbacks
#[derive(Debug)]
pub enum MockCallbackEvents {
    /// GattCallbacks#on_server_read_characteristic invoked
    OnServerReadCharacteristic(ConnectionId, TransactionId, AttHandle, u32, bool),
}

impl GattCallbacks for MockCallbacks {
    fn on_server_read_characteristic(
        &self,
        conn_id: ConnectionId,
        trans_id: TransactionId,
        handle: AttHandle,
        offset: u32,
        is_long: bool,
    ) {
        self.0
            .send(MockCallbackEvents::OnServerReadCharacteristic(
                conn_id, trans_id, handle, offset, is_long,
            ))
            .unwrap();
    }
}
