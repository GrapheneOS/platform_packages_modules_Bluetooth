//! This module handles an individual connection on the ATT fixed channel.
//! It handles ATT transactions and unacknowledged operations, backed by an
//! AttDatabase (that may in turn be backed by an upper-layer protocol)

use std::cell::Cell;

use log::{error, trace, warn};
use tokio::task::spawn_local;

use crate::{
    core::shared_box::WeakBoxRef,
    gatt::ids::AttHandle,
    packets::{
        AttBuilder, AttChild, AttErrorCode, AttErrorResponseBuilder, AttView, Packet,
        SerializeError,
    },
    utils::{owned_handle::OwnedHandle, packet::HACK_child_to_opcode},
};

use super::{att_database::AttDatabase, request_handler::AttRequestHandler};

enum AttRequestState<T: AttDatabase> {
    Idle(AttRequestHandler<T>),
    Pending(Option<OwnedHandle<()>>),
}

const DEFAULT_ATT_MTU: usize = 23;

/// The errors that can occur while trying to send a packet
#[derive(Debug)]
pub enum SendError {
    /// The packet failed to serialize
    SerializeError(SerializeError),
}

/// This represents a single ATT bearer (currently, always the unenhanced fixed
/// channel on LE) The AttRequestState ensures that only one transaction can
/// take place at a time
pub struct AttServerBearer<T: AttDatabase> {
    curr_request: Cell<AttRequestState<T>>,
    send_packet: Box<dyn Fn(AttBuilder) -> Result<(), SerializeError>>,
    mtu: Cell<usize>,
}

impl<T: AttDatabase + 'static> AttServerBearer<T> {
    /// Constructor, wrapping an ATT channel (for outgoing packets) and an
    /// AttDatabase
    pub fn new(
        db: T,
        send_packet: impl Fn(AttBuilder) -> Result<(), SerializeError> + 'static,
    ) -> Self {
        Self {
            curr_request: AttRequestState::Idle(AttRequestHandler::new(db)).into(),
            send_packet: Box::new(send_packet),
            mtu: Cell::new(DEFAULT_ATT_MTU),
        }
    }
}

impl<T: AttDatabase + 'static> WeakBoxRef<'_, AttServerBearer<T>> {
    /// Handle an incoming packet, and send outgoing packets as appropriate
    /// using the owned ATT channel.
    pub fn handle_packet(&self, packet: AttView<'_>) {
        let curr_request = self.curr_request.replace(AttRequestState::Pending(None));
        self.curr_request.replace(match curr_request {
            AttRequestState::Idle(mut request_handler) => {
                // even if the MTU is updated afterwards, 5.3 3F 3.4.2.2 states that the
                // request-time MTU should be used
                let mtu = self.mtu.get();
                let packet = packet.to_owned_packet();
                let this = self.downgrade();
                let task = spawn_local(async move {
                    trace!("starting ATT transaction");
                    let reply = request_handler.process_packet(packet.view(), mtu).await;
                    this.with(|this| {
                    match this {
                        None => {
                            warn!("callback returned after disconnect");
                        }
                        Some(this) => {
                            trace!("sending reply packet");
                            if let Err(err) = this.send_packet(reply) {
                                error!("serializer failure {err:?}, dropping packet and sending failed reply");
                                this.send_packet(AttErrorResponseBuilder {
                                    opcode_in_error: packet.view().get_opcode(),
                                    handle_in_error: AttHandle(0).into(),
                                    error_code: AttErrorCode::UNLIKELY_ERROR,
                                }).expect("packet should never fail to serialize");
                            }
                            // ready for next transaction
                            this.curr_request.replace(AttRequestState::Idle(request_handler));
                        }
                    }
                    })
                });
                AttRequestState::Pending(Some(task.into()))
            }
            AttRequestState::Pending(_) => {
                warn!("multiple ATT operations cannot simultaneously take place, dropping one");
                // TODO(aryarahul) - disconnect connection here;
                curr_request
            }
        });
    }

    fn send_packet(&self, packet: impl Into<AttChild>) -> Result<(), SendError> {
        let child = packet.into();
        let packet = AttBuilder { opcode: HACK_child_to_opcode(&child), _child_: child };
        (self.send_packet)(packet).map_err(SendError::SerializeError)
    }
}

#[cfg(test)]
mod test {
    use std::rc::Rc;

    use tokio::sync::mpsc::{error::TryRecvError, unbounded_channel, UnboundedReceiver};

    use super::*;

    use crate::{
        core::{shared_box::SharedBox, uuid::Uuid},
        gatt::{
            callbacks::GattDatastore,
            ids::ConnectionId,
            mocks::mock_datastore::{MockDatastore, MockDatastoreEvents},
            server::{
                att_database::{AttAttribute, AttPermissions},
                gatt_database::{
                    GattCharacteristicWithHandle, GattDatabase, GattServiceWithHandle,
                },
                test::test_att_db::TestAttDatabase,
            },
        },
        packets::{
            AttAttributeDataChild, AttOpcode, AttReadRequestBuilder, AttReadResponseBuilder,
        },
        utils::{
            packet::{build_att_data, build_att_view_or_crash},
            task::block_on_locally,
        },
    };

    const VALID_HANDLE: AttHandle = AttHandle(3);
    const INVALID_HANDLE: AttHandle = AttHandle(4);
    const ANOTHER_VALID_HANDLE: AttHandle = AttHandle(10);

    const CONN_ID: ConnectionId = ConnectionId(1);

    fn open_connection(
    ) -> (SharedBox<AttServerBearer<TestAttDatabase>>, UnboundedReceiver<AttBuilder>) {
        let db = TestAttDatabase::new(vec![(
            AttAttribute {
                handle: VALID_HANDLE,
                type_: Uuid::new(0x1234),
                permissions: AttPermissions { readable: true, writable: false },
            },
            vec![5, 6],
        )]);
        let (tx, rx) = unbounded_channel();
        let conn = AttServerBearer::new(db, move |packet| {
            tx.send(packet).unwrap();
            Ok(())
        })
        .into();
        (conn, rx)
    }

    #[test]
    fn test_single_transaction() {
        block_on_locally(async {
            let (conn, mut rx) = open_connection();
            conn.as_ref().handle_packet(
                build_att_view_or_crash(AttReadRequestBuilder {
                    attribute_handle: VALID_HANDLE.into(),
                })
                .view(),
            );
            assert_eq!(rx.recv().await.unwrap().opcode, AttOpcode::READ_RESPONSE);
            assert_eq!(rx.try_recv(), Err(TryRecvError::Empty));
        });
    }

    #[test]
    fn test_sequential_transactions() {
        block_on_locally(async {
            let (conn, mut rx) = open_connection();
            conn.as_ref().handle_packet(
                build_att_view_or_crash(AttReadRequestBuilder {
                    attribute_handle: INVALID_HANDLE.into(),
                })
                .view(),
            );
            assert_eq!(rx.recv().await.unwrap().opcode, AttOpcode::ERROR_RESPONSE);
            assert_eq!(rx.try_recv(), Err(TryRecvError::Empty));

            conn.as_ref().handle_packet(
                build_att_view_or_crash(AttReadRequestBuilder {
                    attribute_handle: VALID_HANDLE.into(),
                })
                .view(),
            );
            assert_eq!(rx.recv().await.unwrap().opcode, AttOpcode::READ_RESPONSE);
            assert_eq!(rx.try_recv(), Err(TryRecvError::Empty));
        });
    }

    #[test]
    fn test_concurrent_transaction_failure() {
        // arrange: AttServerBearer linked to a backing datastore and packet queue, with
        // two characteristics in the database
        let (datastore, mut data_rx) = MockDatastore::new();
        let datastore = Rc::new(datastore);
        datastore.add_connection(CONN_ID);
        data_rx.blocking_recv().unwrap(); // ignore AddConnection() event
        let db = SharedBox::new(GattDatabase::new(datastore));
        db.add_service_with_handles(GattServiceWithHandle {
            handle: AttHandle(1),
            type_: Uuid::new(1),
            characteristics: vec![
                GattCharacteristicWithHandle {
                    handle: VALID_HANDLE,
                    type_: Uuid::new(2),
                    permissions: AttPermissions::READONLY,
                },
                GattCharacteristicWithHandle {
                    handle: ANOTHER_VALID_HANDLE,
                    type_: Uuid::new(2),
                    permissions: AttPermissions::READONLY,
                },
            ],
        })
        .unwrap();
        let (tx, mut rx) = unbounded_channel();
        let send_packet = move |packet| {
            tx.send(packet).unwrap();
            Ok(())
        };
        let conn = SharedBox::new(AttServerBearer::new(db.get_att_database(CONN_ID), send_packet));
        let data = AttAttributeDataChild::RawData([1, 2].into());

        // act: send two read requests before replying to either read
        // first request
        block_on_locally(async {
            let req1 = build_att_view_or_crash(AttReadRequestBuilder {
                attribute_handle: VALID_HANDLE.into(),
            });
            conn.as_ref().handle_packet(req1.view());
            // second request
            let req2 = build_att_view_or_crash(AttReadRequestBuilder {
                attribute_handle: ANOTHER_VALID_HANDLE.into(),
            });
            conn.as_ref().handle_packet(req2.view());
            // handle first reply
            let MockDatastoreEvents::ReadCharacteristic(CONN_ID, VALID_HANDLE, data_resp) =
                data_rx.recv().await.unwrap() else {
                    unreachable!();
            };
            data_resp.send(Ok(data.clone())).unwrap();
            trace!("reply sent from upper tester");

            // assert: that the first reply was made
            let resp = rx.recv().await.unwrap();
            assert_eq!(
                resp,
                AttBuilder {
                    opcode: AttOpcode::READ_RESPONSE,
                    _child_: AttReadResponseBuilder { value: build_att_data(data) }.into(),
                }
            );
            // assert no other replies were made
            assert_eq!(rx.try_recv(), Err(TryRecvError::Empty));
            // assert no callbacks are pending
            assert_eq!(data_rx.try_recv().unwrap_err(), TryRecvError::Empty);
        });
    }
}
