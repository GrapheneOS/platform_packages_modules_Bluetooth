//! Mocked implementation of GattDatabaseCallbacks for use in test

use std::ops::RangeInclusive;

use crate::{
    core::shared_box::{WeakBox, WeakBoxRef},
    gatt::{
        ids::{AttHandle, ConnectionId},
        server::{
            att_server_bearer::AttServerBearer,
            gatt_database::{AttDatabaseImpl, GattDatabaseCallbacks},
        },
    },
};
use tokio::sync::mpsc::{self, unbounded_channel, UnboundedReceiver};

/// Routes calls to GattDatabaseCallbacks into a channel of MockCallbackEvents
pub struct MockCallbacks(mpsc::UnboundedSender<MockCallbackEvents>);

impl MockCallbacks {
    /// Constructor. Returns self and the RX side of the associated channel.
    pub fn new() -> (Self, UnboundedReceiver<MockCallbackEvents>) {
        let (tx, rx) = unbounded_channel();
        (Self(tx), rx)
    }
}

/// Events representing calls to GattCallbacks
pub enum MockCallbackEvents {
    /// GattDatabaseCallbacks#on_le_connect invoked
    OnLeConnect(ConnectionId, WeakBox<AttServerBearer<AttDatabaseImpl>>),
    /// GattDatabaseCallbacks#on_le_disconnect invoked
    OnLeDisconnect(ConnectionId),
    /// GattDatabaseCallbacks#on_service_change invoked
    OnServiceChange(RangeInclusive<AttHandle>),
}

impl GattDatabaseCallbacks for MockCallbacks {
    fn on_le_connect(
        &self,
        conn_id: ConnectionId,
        bearer: WeakBoxRef<AttServerBearer<AttDatabaseImpl>>,
    ) {
        self.0.send(MockCallbackEvents::OnLeConnect(conn_id, bearer.downgrade())).ok().unwrap();
    }

    fn on_le_disconnect(&self, conn_id: ConnectionId) {
        self.0.send(MockCallbackEvents::OnLeDisconnect(conn_id)).ok().unwrap();
    }

    fn on_service_change(&self, range: RangeInclusive<AttHandle>) {
        self.0.send(MockCallbackEvents::OnServiceChange(range)).ok().unwrap();
    }
}
