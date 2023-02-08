use std::rc::Rc;

use bluetooth_core::{
    core::uuid::Uuid,
    gatt::{
        self,
        ids::{AttHandle, ConnectionId, ServerId, TransportIndex},
        mocks::mock_transport::MockAttTransport,
        server::{
            gatt_database::{AttPermissions, GattCharacteristicWithHandle, GattServiceWithHandle},
            GattModule,
        },
    },
    packets::{
        AttBuilder, AttErrorCode, AttErrorResponseBuilder, AttOpcode, AttReadRequestBuilder,
        AttReadResponseBuilder, GattServiceDeclarationValueBuilder,
    },
    utils::packet::{build_att_data, build_att_view_or_crash},
};

use tokio::sync::mpsc::UnboundedReceiver;
use utils::start_test;

mod utils;

const TCB_IDX: TransportIndex = TransportIndex(1);
const SERVER_ID: ServerId = ServerId(2);
const CONN_ID: ConnectionId = ConnectionId::new(TCB_IDX, SERVER_ID);
const HANDLE_1: AttHandle = AttHandle(3);
const HANDLE_2: AttHandle = AttHandle(5);
const UUID_1: Uuid = Uuid::new(0x0102);
const UUID_2: Uuid = Uuid::new(0x0103);

fn start_gatt_module() -> (gatt::server::GattModule, UnboundedReceiver<(TransportIndex, AttBuilder)>)
{
    let (transport, transport_rx) = MockAttTransport::new();
    let gatt = GattModule::new(Rc::new(transport));

    (gatt, transport_rx)
}

fn create_server_and_open_connection(gatt: &mut GattModule) {
    gatt.open_gatt_server(SERVER_ID).unwrap();
    gatt.register_gatt_service(
        SERVER_ID,
        GattServiceWithHandle {
            handle: HANDLE_1,
            type_: UUID_1,
            characteristics: vec![GattCharacteristicWithHandle {
                handle: HANDLE_2,
                type_: UUID_2,
                permissions: AttPermissions { readable: true, writable: false },
            }],
        },
    )
    .unwrap();
    gatt.on_le_connect(CONN_ID).unwrap();
}

#[test]
fn test_service_read() {
    start_test(async move {
        // arrange
        let (mut gatt, mut transport_rx) = start_gatt_module();

        create_server_and_open_connection(&mut gatt);

        // act
        gatt.handle_packet(
            CONN_ID,
            build_att_view_or_crash(AttReadRequestBuilder { attribute_handle: HANDLE_1.into() })
                .view(),
        )
        .unwrap();
        let (tcb_idx, resp) = transport_rx.recv().await.unwrap();

        // assert
        assert_eq!(tcb_idx, TCB_IDX);
        assert_eq!(
            resp,
            AttBuilder {
                opcode: AttOpcode::READ_RESPONSE,
                _child_: AttReadResponseBuilder {
                    value: build_att_data(GattServiceDeclarationValueBuilder {
                        uuid: UUID_1.into()
                    })
                }
                .into()
            }
        );
    })
}

#[test]
fn test_server_closed_while_connected() {
    start_test(async move {
        // arrange: set up a connection to a closed server
        let (mut gatt, mut transport_rx) = start_gatt_module();

        // open a server and connect
        create_server_and_open_connection(&mut gatt);
        // close the server but keep the connection up
        gatt.close_gatt_server(SERVER_ID).unwrap();

        // act: read from the closed server
        gatt.handle_packet(
            CONN_ID,
            build_att_view_or_crash(AttReadRequestBuilder { attribute_handle: HANDLE_1.into() })
                .view(),
        )
        .unwrap();
        let (_, resp) = transport_rx.recv().await.unwrap();

        // assert that the read failed, but that a response was provided
        assert_eq!(resp.opcode, AttOpcode::ERROR_RESPONSE);
        assert_eq!(
            resp._child_,
            AttErrorResponseBuilder {
                opcode_in_error: AttOpcode::READ_REQUEST,
                handle_in_error: HANDLE_1.into(),
                error_code: AttErrorCode::INVALID_HANDLE
            }
            .into()
        );
    })
}
