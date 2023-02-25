//! Mocked implementation of GattCallbacks for use in test

use crate::{
    gatt::{
        ids::{AttHandle, ConnectionId, TransactionId},
        GattCallbacks,
    },
    packets::{AttAttributeDataView, OwnedAttAttributeDataView, Packet},
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
    /// GattCallbacks#on_server_write_characteristic invoked
    OnServerWriteCharacteristic(
        ConnectionId,
        TransactionId,
        AttHandle,
        u32,
        bool,
        bool,
        OwnedAttAttributeDataView,
    ),
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

    fn on_server_write_characteristic(
        &self,
        conn_id: ConnectionId,
        trans_id: TransactionId,
        handle: AttHandle,
        offset: u32,
        need_response: bool,
        is_prepare: bool,
        value: AttAttributeDataView,
    ) {
        self.0
            .send(MockCallbackEvents::OnServerWriteCharacteristic(
                conn_id,
                trans_id,
                handle,
                offset,
                need_response,
                is_prepare,
                value.to_owned_packet(),
            ))
            .unwrap();
    }
}
