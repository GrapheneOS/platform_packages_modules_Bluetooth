//! This module handles an individual connection on the ATT fixed channel.
//! It handles ATT transactions and unacknowledged operations, backed by an
//! AttDatabase (that may in turn be backed by an upper-layer protocol)

use std::{
    cell::Cell,
    rc::{Rc, Weak},
};

use log::{error, info, warn};
use tokio::task::spawn_local;

use crate::{
    gatt::ids::AttHandle,
    packets::{
        AttBuilder, AttChild, AttErrorCode, AttErrorResponseBuilder, AttView, Packet,
        SerializeError,
    },
    utils::{owned_handle::OwnedHandle, packet::HACK_child_to_opcode},
};

use super::{att_database::AttDatabase, transaction_handler::AttTransactionHandler};

enum AttTransaction<T: AttDatabase> {
    Idle(AttTransactionHandler<T>),
    Pending(Option<OwnedHandle<()>>),
}

const DEFAULT_ATT_MTU: usize = 23;

/// This represents a single ATT bearer (currently, always the unenhanced fixed
/// channel on LE) The AttTransaction ensures that only one transaction can take
/// place at a time
pub struct AttServerBearer<T: AttDatabase> {
    curr_operation: Cell<AttTransaction<T>>,
    send_packet: Box<dyn Fn(AttBuilder) -> Result<(), SerializeError>>,
    mtu: Cell<usize>,
}

impl<T: AttDatabase + 'static> AttServerBearer<T> {
    /// Constructor, wrapping an ATT channel (for outgoing packets) and an
    /// AttDatabase
    pub fn new(
        db: T,
        send_packet: impl Fn(AttBuilder) -> Result<(), SerializeError> + 'static,
    ) -> Rc<Self> {
        Self {
            curr_operation: AttTransaction::Idle(AttTransactionHandler::new(db)).into(),
            send_packet: Box::new(send_packet),
            mtu: Cell::new(DEFAULT_ATT_MTU),
        }
        .into()
    }

    /// Handle an incoming packet, and send outgoing packets as appropriate
    /// using the owned ATT channel.
    pub fn handle_packet(self: &Rc<Self>, packet: AttView<'_>) {
        let curr_operation = self.curr_operation.replace(AttTransaction::Pending(None));
        self.clone().curr_operation.replace(match curr_operation {
            AttTransaction::Idle(mut request_handler) => {
                // even if the MTU is updated afterwards, 5.3 3F 3.4.2.2 states that the request-time MTU should be used
                let mtu = self.mtu.get();
                let this = Rc::downgrade(self);
                let packet = packet.to_owned_packet();
                let task = spawn_local(async move {
                    info!("starting ATT transaction");
                    let reply = request_handler.process_packet(packet.view(), mtu).await;
                    match Weak::upgrade(&this) {
                        None => {
                            warn!("callback returned after disconnect");
                        }
                        Some(this) => {
                            info!("sending reply packet");
                            if let Err(err) = this.send_response(reply) {
                                error!("serializer failure {err:?}, dropping packet and sending failed reply");
                                this.send_response(AttErrorResponseBuilder {
                                    opcode_in_error: packet.view().get_opcode(),
                                    handle_in_error: AttHandle(0).into(),
                                    error_code: AttErrorCode::UNLIKELY_ERROR,
                                }).expect("packet should never fail to serialize");
                            }
                            // ready for next transaction
                            this.curr_operation.replace(AttTransaction::Idle(request_handler));
                        }
                    }
                });
                AttTransaction::Pending(Some(task.into()))
            }
            AttTransaction::Pending(_) => {
                warn!("multiple ATT operations cannot simultaneously take place, dropping one");
                // TODO(aryarahul) - disconnect connection here;
                curr_operation
            }
        });
    }

    fn send_response(&self, packet: impl Into<AttChild>) -> Result<(), SerializeError> {
        let child = packet.into();
        let packet = AttBuilder { opcode: HACK_child_to_opcode(&child), _child_: child };
        (self.send_packet)(packet)
    }
}

#[cfg(test)]
mod test {
    use tokio::{
        runtime::Runtime,
        sync::mpsc::{error::TryRecvError, unbounded_channel, UnboundedReceiver},
        task::LocalSet,
    };

    use super::*;

    use crate::{
        core::uuid::Uuid,
        gatt::server::{
            att_database::{AttAttribute, AttPermissions},
            test::test_att_db::TestAttDatabase,
        },
        packets::{AttOpcode, AttReadRequestBuilder},
        utils::packet::build_att_view_or_crash,
    };

    const VALID_HANDLE: AttHandle = AttHandle(3);
    const INVALID_HANDLE: AttHandle = AttHandle(4);

    fn open_connection() -> (Rc<AttServerBearer<TestAttDatabase>>, UnboundedReceiver<AttBuilder>) {
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
        });
        (conn, rx)
    }

    #[test]
    fn test_single_transaction() {
        LocalSet::new().block_on(&Runtime::new().unwrap(), async {
            let (conn, mut rx) = open_connection();
            conn.handle_packet(
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
        LocalSet::new().block_on(&Runtime::new().unwrap(), async {
            let (conn, mut rx) = open_connection();
            conn.handle_packet(
                build_att_view_or_crash(AttReadRequestBuilder {
                    attribute_handle: INVALID_HANDLE.into(),
                })
                .view(),
            );
            assert_eq!(rx.recv().await.unwrap().opcode, AttOpcode::ERROR_RESPONSE);
            assert_eq!(rx.try_recv(), Err(TryRecvError::Empty));

            conn.handle_packet(
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
        // TODO(aryarahul) - Add this test once GATT callbacks are available
    }
}
