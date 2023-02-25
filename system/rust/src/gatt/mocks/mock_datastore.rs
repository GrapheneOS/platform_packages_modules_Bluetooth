//! Mocked implementation of GattDatastore for use in test

use crate::{
    gatt::{
        callbacks::GattDatastore,
        ids::{AttHandle, ConnectionId},
    },
    packets::{
        AttAttributeDataChild, AttAttributeDataView, AttErrorCode, OwnedAttAttributeDataView,
        Packet,
    },
};
use async_trait::async_trait;
use log::info;
use tokio::sync::{
    mpsc::{self, unbounded_channel, UnboundedReceiver},
    oneshot,
};

/// Routes calls to GattDatastore into a channel of MockDatastoreEvents
pub struct MockDatastore(mpsc::UnboundedSender<MockDatastoreEvents>);

impl MockDatastore {
    /// Constructor. Returns self and the RX side of the associated channel.
    pub fn new() -> (Self, UnboundedReceiver<MockDatastoreEvents>) {
        let (tx, rx) = unbounded_channel();
        (Self(tx), rx)
    }
}

/// Events representing calls to GattDatastore
#[derive(Debug)]
pub enum MockDatastoreEvents {
    /// A new connection was created
    AddConnection(ConnectionId),
    /// A connection was removed
    RemoveConnection(ConnectionId),
    /// A characteristic was read on a given handle. The oneshot is used to
    /// return the value read.
    ReadCharacteristic(
        ConnectionId,
        AttHandle,
        oneshot::Sender<Result<AttAttributeDataChild, AttErrorCode>>,
    ),
    /// A characteristic was written to on a given handle. The oneshot is used
    /// to return whether the write succeeded.
    WriteCharacteristic(
        ConnectionId,
        AttHandle,
        OwnedAttAttributeDataView,
        oneshot::Sender<Result<(), AttErrorCode>>,
    ),
}

#[async_trait(?Send)]
impl GattDatastore for MockDatastore {
    fn add_connection(&self, conn_id: ConnectionId) {
        self.0.send(MockDatastoreEvents::AddConnection(conn_id)).unwrap();
    }

    fn remove_connection(&self, conn_id: ConnectionId) {
        self.0.send(MockDatastoreEvents::RemoveConnection(conn_id)).unwrap();
    }

    async fn read_characteristic(
        &self,
        conn_id: ConnectionId,
        handle: AttHandle,
    ) -> Result<AttAttributeDataChild, AttErrorCode> {
        let (tx, rx) = oneshot::channel();
        self.0.send(MockDatastoreEvents::ReadCharacteristic(conn_id, handle, tx)).unwrap();
        let resp = rx.await.unwrap();
        info!("sending {resp:?} down from upper tester");
        resp
    }

    async fn write_characteristic(
        &self,
        conn_id: ConnectionId,
        handle: AttHandle,
        data: AttAttributeDataView<'_>,
    ) -> Result<(), AttErrorCode> {
        let (tx, rx) = oneshot::channel();
        self.0
            .send(MockDatastoreEvents::WriteCharacteristic(
                conn_id,
                handle,
                data.to_owned_packet(),
                tx,
            ))
            .unwrap();
        rx.await.unwrap()
    }
}
