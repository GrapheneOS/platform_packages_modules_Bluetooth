use log::warn;

use crate::{
    gatt::ids::AttHandle,
    packets::{
        AttChild, AttErrorCode, AttErrorResponseBuilder, AttOpcode, AttReadRequestView, AttView,
        Packet, ParseError,
    },
};

use super::{att_database::AttDatabase, transactions::read_request::handle_read_request};

/// This struct handles all requests needing ACKs. Only ONE should exist per
/// bearer per database, to ensure serialization.
pub struct AttTransactionHandler<Db: AttDatabase> {
    db: Db,
}

impl<Db: AttDatabase> AttTransactionHandler<Db> {
    pub fn new(db: Db) -> Self {
        Self { db }
    }

    // Runs a task to process an incoming packet. Takes an exclusive reference to
    // ensure that only one request is outstanding at a time (notifications +
    // commands should take a different path)
    pub async fn process_packet(&mut self, packet: AttView<'_>, mtu: usize) -> AttChild {
        match self.try_parse_and_process_packet(packet, mtu).await {
            Ok(result) => result,
            Err(_) => {
                // parse error, assume it's an unsupported request
                AttErrorResponseBuilder {
                    opcode_in_error: packet.get_opcode(),
                    handle_in_error: AttHandle(0).into(),
                    error_code: AttErrorCode::REQUEST_NOT_SUPPORTED,
                }
                .into()
            }
        }
    }

    async fn try_parse_and_process_packet(
        &mut self,
        packet: AttView<'_>,
        mtu: usize,
    ) -> Result<AttChild, ParseError> {
        match packet.get_opcode() {
            AttOpcode::READ_REQUEST => {
                Ok(handle_read_request(AttReadRequestView::try_parse(packet)?, mtu, &self.db).await)
            }
            _ => {
                warn!("Dropping unsupported opcode {:?}", packet.get_opcode());
                Err(ParseError::InvalidEnumValue)
            }
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    use crate::{
        core::uuid::Uuid,
        gatt::server::{
            att_database::{AttAttribute, AttPermissions},
            test::test_att_db::TestAttDatabase,
            transaction_handler::AttTransactionHandler,
        },
        packets::{
            AttAttributeDataChild, AttReadRequestBuilder, AttReadResponseBuilder,
            AttWriteResponseBuilder,
        },
        utils::packet::{build_att_data, build_att_view_or_crash},
    };

    #[test]
    fn test_read_request() {
        // arrange
        let db = TestAttDatabase::new(vec![(
            AttAttribute {
                handle: AttHandle(3),
                type_: Uuid::new(0x1234),
                permissions: AttPermissions { readable: true, writable: false },
            },
            vec![1, 2, 3],
        )]);
        let mut handler = AttTransactionHandler { db };
        let att_view = build_att_view_or_crash(AttReadRequestBuilder {
            attribute_handle: AttHandle(3).into(),
        });

        // act
        let response = tokio_test::block_on(handler.process_packet((&att_view).into(), 31));

        // assert
        assert_eq!(
            response,
            AttChild::AttReadResponse(AttReadResponseBuilder {
                value: build_att_data(AttAttributeDataChild::RawData([1, 2, 3].into()))
            })
        );
    }

    #[test]
    fn test_unsupported_request() {
        // arrange
        let db = TestAttDatabase::new(vec![(
            AttAttribute {
                handle: AttHandle(3),
                type_: Uuid::new(0x1234),
                permissions: AttPermissions { readable: true, writable: false },
            },
            vec![1, 2, 3],
        )]);
        let mut handler = AttTransactionHandler { db };
        let att_view = build_att_view_or_crash(AttWriteResponseBuilder {});

        // act
        let response = tokio_test::block_on(handler.process_packet((&att_view).into(), 31));

        // assert
        assert_eq!(
            response,
            AttChild::AttErrorResponse(AttErrorResponseBuilder {
                opcode_in_error: AttOpcode::WRITE_RESPONSE,
                handle_in_error: AttHandle(0).into(),
                error_code: AttErrorCode::REQUEST_NOT_SUPPORTED
            })
        );
    }
}
