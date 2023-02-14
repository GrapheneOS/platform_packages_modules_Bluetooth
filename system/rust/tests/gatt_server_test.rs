use std::rc::Rc;

use bluetooth_core::{
    core::uuid::Uuid,
    gatt::{
        self,
        ids::{AttHandle, ConnectionId, ServerId, TransportIndex},
        mocks::{
            mock_datastore::{MockDatastore, MockDatastoreEvents},
            mock_transport::MockAttTransport,
        },
        server::{
            gatt_database::{AttPermissions, GattCharacteristicWithHandle, GattServiceWithHandle},
            GattModule,
        },
    },
    packets::{
        AttAttributeDataChild, AttBuilder, AttErrorCode, AttErrorResponseBuilder, AttOpcode,
        AttReadRequestBuilder, AttReadResponseBuilder, AttWriteRequestBuilder,
        AttWriteResponseBuilder, GattServiceDeclarationValueBuilder, Serializable,
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

fn start_gatt_module() -> (
    gatt::server::GattModule,
    UnboundedReceiver<MockDatastoreEvents>,
    UnboundedReceiver<(TransportIndex, AttBuilder)>,
) {
    let (datastore, data_rx) = MockDatastore::new();
    let (transport, transport_rx) = MockAttTransport::new();
    let gatt = GattModule::new(Rc::new(datastore), Rc::new(transport));

    (gatt, data_rx, transport_rx)
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
                permissions: AttPermissions { readable: true, writable: true },
            }],
        },
    )
    .unwrap();
    gatt.on_le_connect(CONN_ID).unwrap();
}

#[test]
fn test_connection_creation() {
    start_test(async move {
        // arrange
        let (mut gatt, mut data_rx, _) = start_gatt_module();

        gatt.open_gatt_server(SERVER_ID).unwrap();
        gatt.register_gatt_service(
            SERVER_ID,
            GattServiceWithHandle { handle: HANDLE_1, type_: UUID_1, characteristics: vec![] },
        )
        .unwrap();

        // act
        gatt.on_le_connect(CONN_ID).unwrap();

        // assert
        assert!(matches!(
            data_rx.recv().await.unwrap(),
            MockDatastoreEvents::AddConnection(CONN_ID)
        ));
    })
}
#[test]
fn test_disconnection() {
    start_test(async move {
        // arrange
        let (mut gatt, mut data_rx, _) = start_gatt_module();

        gatt.open_gatt_server(SERVER_ID).unwrap();
        gatt.register_gatt_service(
            SERVER_ID,
            GattServiceWithHandle { handle: HANDLE_1, type_: UUID_1, characteristics: vec![] },
        )
        .unwrap();
        gatt.on_le_connect(CONN_ID).unwrap();
        data_rx.recv().await.unwrap(); // drop the AddConnection event

        // act
        gatt.on_le_disconnect(CONN_ID);

        // assert
        assert!(matches!(
            data_rx.recv().await.unwrap(),
            MockDatastoreEvents::RemoveConnection(CONN_ID)
        ));
    })
}

#[test]
fn test_service_read() {
    start_test(async move {
        // arrange
        let (mut gatt, mut data_rx, mut transport_rx) = start_gatt_module();

        create_server_and_open_connection(&mut gatt);
        data_rx.recv().await.unwrap();

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
        let (mut gatt, mut data_rx, mut transport_rx) = start_gatt_module();

        // open a server and connect
        create_server_and_open_connection(&mut gatt);
        data_rx.recv().await.unwrap(); // drop the AddConnection message
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
        )
    });
}

#[test]
fn test_characteristic_read() {
    start_test(async move {
        // arrange
        let (mut gatt, mut data_rx, mut transport_rx) = start_gatt_module();

        let data = AttAttributeDataChild::RawData([5, 6, 7, 8].into());

        create_server_and_open_connection(&mut gatt);
        data_rx.recv().await.unwrap();

        // act
        gatt.handle_packet(
            CONN_ID,
            build_att_view_or_crash(AttReadRequestBuilder { attribute_handle: HANDLE_2.into() })
                .view(),
        )
        .unwrap();
        let tx = if let MockDatastoreEvents::ReadCharacteristic(CONN_ID, HANDLE_2, tx) =
            data_rx.recv().await.unwrap()
        {
            tx
        } else {
            unreachable!()
        };
        tx.send(Ok(data.clone())).unwrap();
        let (tcb_idx, resp) = transport_rx.recv().await.unwrap();

        // assert
        assert_eq!(tcb_idx, TCB_IDX);
        assert_eq!(
            resp,
            AttBuilder {
                opcode: AttOpcode::READ_RESPONSE,
                _child_: AttReadResponseBuilder { value: build_att_data(data) }.into()
            }
        );
    })
}

#[test]
fn test_characteristic_write() {
    start_test(async move {
        // arrange
        let (mut gatt, mut data_rx, mut transport_rx) = start_gatt_module();

        let data = AttAttributeDataChild::RawData([5, 6, 7, 8].into());

        create_server_and_open_connection(&mut gatt);
        data_rx.recv().await.unwrap();

        // act
        gatt.handle_packet(
            CONN_ID,
            build_att_view_or_crash(AttWriteRequestBuilder {
                handle: HANDLE_2.into(),
                value: build_att_data(data.clone()),
            })
            .view(),
        )
        .unwrap();
        let (tx, written_data) =
            if let MockDatastoreEvents::WriteCharacteristic(CONN_ID, HANDLE_2, written_data, tx) =
                data_rx.recv().await.unwrap()
            {
                (tx, written_data)
            } else {
                unreachable!()
            };
        tx.send(Ok(())).unwrap();
        let (tcb_idx, resp) = transport_rx.recv().await.unwrap();

        // assert
        assert_eq!(tcb_idx, TCB_IDX);
        assert_eq!(
            resp,
            AttBuilder {
                opcode: AttOpcode::WRITE_RESPONSE,
                _child_: AttWriteResponseBuilder {}.into()
            }
        );
        assert_eq!(
            data.to_vec().unwrap(),
            written_data.view().get_raw_payload().collect::<Vec<_>>()
        )
    })
}
