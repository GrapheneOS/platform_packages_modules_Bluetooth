//! Mocked implementation of GattCallbacks for use in test

use crate::{
    gatt::{
        ffi::AttributeBackingType,
        ids::{AttHandle, ConnectionId, TransactionId},
        server::IndicationError,
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
    OnServerRead(ConnectionId, TransactionId, AttHandle, AttributeBackingType, u32, bool),
    /// GattCallbacks#on_server_write_characteristic invoked
    OnServerWrite(
        ConnectionId,
        TransactionId,
        AttHandle,
        AttributeBackingType,
        u32,
        bool,
        bool,
        OwnedAttAttributeDataView,
    ),
    /// GattCallbacks#on_indication_sent_confirmation invoked
    OnIndicationSentConfirmation(ConnectionId, Result<(), IndicationError>),
}

impl GattCallbacks for MockCallbacks {
    fn on_server_read(
        &self,
        conn_id: ConnectionId,
        trans_id: TransactionId,
        handle: AttHandle,
        attr_type: AttributeBackingType,
        offset: u32,
        is_long: bool,
    ) {
        self.0
            .send(MockCallbackEvents::OnServerRead(
                conn_id, trans_id, handle, attr_type, offset, is_long,
            ))
            .unwrap();
    }

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
    ) {
        self.0
            .send(MockCallbackEvents::OnServerWrite(
                conn_id,
                trans_id,
                handle,
                attr_type,
                offset,
                need_response,
                is_prepare,
                value.to_owned_packet(),
            ))
            .unwrap();
    }

    fn on_indication_sent_confirmation(
        &self,
        conn_id: ConnectionId,
        result: Result<(), IndicationError>,
    ) {
        self.0.send(MockCallbackEvents::OnIndicationSentConfirmation(conn_id, result)).unwrap();
    }
}
