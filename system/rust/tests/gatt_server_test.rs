use std::rc::Rc;

use bluetooth_core::{
    core::uuid::Uuid,
    gatt::{
        self,
        ffi::AttributeBackingType,
        ids::{AttHandle, ConnectionId, ServerId, TransportIndex},
        mocks::{
            mock_datastore::{MockDatastore, MockDatastoreEvents},
            mock_transport::MockAttTransport,
        },
        server::{
            gatt_database::{
                AttPermissions, GattCharacteristicWithHandle, GattDescriptorWithHandle,
                GattServiceWithHandle,
            },
            services::gap::DEVICE_NAME_UUID,
            GattModule, IndicationError,
        },
    },
    packets::{
        AttAttributeDataChild, AttBuilder, AttChild, AttErrorCode, AttErrorResponseBuilder,
        AttHandleValueConfirmationBuilder, AttHandleValueIndicationBuilder, AttOpcode,
        AttReadByTypeRequestBuilder, AttReadRequestBuilder, AttReadResponseBuilder,
        AttWriteRequestBuilder, AttWriteResponseBuilder, GattServiceDeclarationValueBuilder,
        Serializable,
    },
    utils::packet::{build_att_data, build_att_view_or_crash},
};

use tokio::{sync::mpsc::UnboundedReceiver, task::spawn_local};
use utils::start_test;

mod utils;

const TCB_IDX: TransportIndex = TransportIndex(1);
const SERVER_ID: ServerId = ServerId(2);
const CONN_ID: ConnectionId = ConnectionId::new(TCB_IDX, SERVER_ID);

const ANOTHER_TCB_IDX: TransportIndex = TransportIndex(2);
const ANOTHER_SERVER_ID: ServerId = ServerId(3);
const ANOTHER_CONN_ID: ConnectionId = ConnectionId::new(ANOTHER_TCB_IDX, ANOTHER_SERVER_ID);

const SERVICE_HANDLE: AttHandle = AttHandle(6);
const CHARACTERISTIC_HANDLE: AttHandle = AttHandle(8);
const DESCRIPTOR_HANDLE: AttHandle = AttHandle(9);

const SERVICE_TYPE: Uuid = Uuid::new(0x0102);
const CHARACTERISTIC_TYPE: Uuid = Uuid::new(0x0103);
const DESCRIPTOR_TYPE: Uuid = Uuid::new(0x0104);

const DATA: [u8; 4] = [1, 2, 3, 4];
const ANOTHER_DATA: [u8; 4] = [5, 6, 7, 8];

fn start_gatt_module() -> (gatt::server::GattModule, UnboundedReceiver<(TransportIndex, AttBuilder)>)
{
    let (transport, transport_rx) = MockAttTransport::new();
    let gatt = GattModule::new(Rc::new(transport));

    (gatt, transport_rx)
}

fn create_server_and_open_connection(
    gatt: &mut GattModule,
) -> UnboundedReceiver<MockDatastoreEvents> {
    gatt.open_gatt_server(SERVER_ID).unwrap();
    let (datastore, data_rx) = MockDatastore::new();
    gatt.register_gatt_service(
        SERVER_ID,
        GattServiceWithHandle {
            handle: SERVICE_HANDLE,
            type_: SERVICE_TYPE,
            characteristics: vec![GattCharacteristicWithHandle {
                handle: CHARACTERISTIC_HANDLE,
                type_: CHARACTERISTIC_TYPE,
                permissions: AttPermissions::READABLE
                    | AttPermissions::WRITABLE
                    | AttPermissions::INDICATE,
                descriptors: vec![GattDescriptorWithHandle {
                    handle: DESCRIPTOR_HANDLE,
                    type_: DESCRIPTOR_TYPE,
                    permissions: AttPermissions::READABLE | AttPermissions::WRITABLE,
                }],
            }],
        },
        Rc::new(datastore),
    )
    .unwrap();
    gatt.on_le_connect(CONN_ID).unwrap();
    data_rx
}

#[test]
fn test_service_read() {
    start_test(async move {
        // arrange
        let (mut gatt, mut transport_rx) = start_gatt_module();

        create_server_and_open_connection(&mut gatt);

        // act
        gatt.get_bearer(CONN_ID).unwrap().handle_packet(
            build_att_view_or_crash(AttReadRequestBuilder {
                attribute_handle: SERVICE_HANDLE.into(),
            })
            .view(),
        );
        let (tcb_idx, resp) = transport_rx.recv().await.unwrap();

        // assert
        assert_eq!(tcb_idx, TCB_IDX);
        assert_eq!(
            resp,
            AttBuilder {
                opcode: AttOpcode::READ_RESPONSE,
                _child_: AttReadResponseBuilder {
                    value: build_att_data(GattServiceDeclarationValueBuilder {
                        uuid: SERVICE_TYPE.into()
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
        gatt.close_gatt_server(SERVER_ID).unwrap();

        // act: read from the closed server
        gatt.get_bearer(CONN_ID).unwrap().handle_packet(
            build_att_view_or_crash(AttReadRequestBuilder {
                attribute_handle: SERVICE_HANDLE.into(),
            })
            .view(),
        );
        let (_, resp) = transport_rx.recv().await.unwrap();

        // assert that the read failed, but that a response was provided
        assert_eq!(resp.opcode, AttOpcode::ERROR_RESPONSE);
        assert_eq!(
            resp._child_,
            AttErrorResponseBuilder {
                opcode_in_error: AttOpcode::READ_REQUEST,
                handle_in_error: SERVICE_HANDLE.into(),
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
        let (mut gatt, mut transport_rx) = start_gatt_module();

        let data = AttAttributeDataChild::RawData(DATA.into());

        let mut data_rx = create_server_and_open_connection(&mut gatt);

        // act
        gatt.get_bearer(CONN_ID).unwrap().handle_packet(
            build_att_view_or_crash(AttReadRequestBuilder {
                attribute_handle: CHARACTERISTIC_HANDLE.into(),
            })
            .view(),
        );
        let tx = if let MockDatastoreEvents::Read(
            CONN_ID,
            CHARACTERISTIC_HANDLE,
            AttributeBackingType::Characteristic,
            tx,
        ) = data_rx.recv().await.unwrap()
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
        let (mut gatt, mut transport_rx) = start_gatt_module();

        let data = AttAttributeDataChild::RawData(DATA.into());

        let mut data_rx = create_server_and_open_connection(&mut gatt);

        // act
        gatt.get_bearer(CONN_ID).unwrap().handle_packet(
            build_att_view_or_crash(AttWriteRequestBuilder {
                handle: CHARACTERISTIC_HANDLE.into(),
                value: build_att_data(data.clone()),
            })
            .view(),
        );
        let (tx, written_data) = if let MockDatastoreEvents::Write(
            CONN_ID,
            CHARACTERISTIC_HANDLE,
            AttributeBackingType::Characteristic,
            written_data,
            tx,
        ) = data_rx.recv().await.unwrap()
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

#[test]
fn test_send_indication() {
    start_test(async move {
        // arrange
        let (mut gatt, mut transport_rx) = start_gatt_module();

        let data = AttAttributeDataChild::RawData(DATA.into());

        create_server_and_open_connection(&mut gatt);

        // act
        let pending_indication = spawn_local(
            gatt.get_bearer(CONN_ID).unwrap().send_indication(CHARACTERISTIC_HANDLE, data.clone()),
        );

        let (tcb_idx, resp) = transport_rx.recv().await.unwrap();

        gatt.get_bearer(CONN_ID)
            .unwrap()
            .handle_packet(build_att_view_or_crash(AttHandleValueConfirmationBuilder {}).view());

        // assert
        assert!(matches!(pending_indication.await.unwrap(), Ok(())));
        assert_eq!(tcb_idx, TCB_IDX);
        assert_eq!(
            resp,
            AttBuilder {
                opcode: AttOpcode::HANDLE_VALUE_INDICATION,
                _child_: AttHandleValueIndicationBuilder {
                    handle: CHARACTERISTIC_HANDLE.into(),
                    value: build_att_data(data),
                }
                .into()
            }
        );
    })
}

#[test]
fn test_send_indication_and_disconnect() {
    start_test(async move {
        // arrange
        let (mut gatt, mut transport_rx) = start_gatt_module();

        create_server_and_open_connection(&mut gatt);

        // act: send an indication, then disconnect
        let pending_indication = spawn_local(gatt.get_bearer(CONN_ID).unwrap().send_indication(
            CHARACTERISTIC_HANDLE,
            AttAttributeDataChild::RawData([1, 2, 3, 4].into()),
        ));
        transport_rx.recv().await.unwrap();
        gatt.on_le_disconnect(CONN_ID);

        // assert: the pending indication resolves appropriately
        assert!(matches!(
            pending_indication.await.unwrap(),
            Err(IndicationError::ConnectionDroppedWhileWaitingForConfirmation)
        ));
    })
}

#[test]
fn test_write_to_descriptor() {
    start_test(async move {
        // arrange
        let (mut gatt, mut transport_rx) = start_gatt_module();

        let data = AttAttributeDataChild::RawData(DATA.into());

        let mut data_rx = create_server_and_open_connection(&mut gatt);

        // act
        gatt.get_bearer(CONN_ID).unwrap().handle_packet(
            build_att_view_or_crash(AttWriteRequestBuilder {
                handle: DESCRIPTOR_HANDLE.into(),
                value: build_att_data(data.clone()),
            })
            .view(),
        );
        let (tx, written_data) = if let MockDatastoreEvents::Write(
            CONN_ID,
            DESCRIPTOR_HANDLE,
            AttributeBackingType::Descriptor,
            written_data,
            tx,
        ) = data_rx.recv().await.unwrap()
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

#[test]
fn test_multiple_servers() {
    start_test(async move {
        // arrange
        let (mut gatt, mut transport_rx) = start_gatt_module();
        let data = AttAttributeDataChild::RawData(DATA.into());
        let another_data = AttAttributeDataChild::RawData(ANOTHER_DATA.into());
        // open the default server (SERVER_ID on CONN_ID)
        let mut data_rx_1 = create_server_and_open_connection(&mut gatt);
        // open a second server and connect to it (ANOTHER_SERVER_ID on ANOTHER_CONN_ID)
        let (datastore, mut data_rx_2) = MockDatastore::new();
        gatt.open_gatt_server(ANOTHER_SERVER_ID).unwrap();
        gatt.register_gatt_service(
            ANOTHER_SERVER_ID,
            GattServiceWithHandle {
                handle: SERVICE_HANDLE,
                type_: SERVICE_TYPE,
                characteristics: vec![GattCharacteristicWithHandle {
                    handle: CHARACTERISTIC_HANDLE,
                    type_: CHARACTERISTIC_TYPE,
                    permissions: AttPermissions::READABLE,
                    descriptors: vec![],
                }],
            },
            Rc::new(datastore),
        )
        .unwrap();
        gatt.on_le_connect(ANOTHER_CONN_ID).unwrap();

        // act: read from both connections
        gatt.get_bearer(CONN_ID).unwrap().handle_packet(
            build_att_view_or_crash(AttReadRequestBuilder {
                attribute_handle: CHARACTERISTIC_HANDLE.into(),
            })
            .view(),
        );
        gatt.get_bearer(ANOTHER_CONN_ID).unwrap().handle_packet(
            build_att_view_or_crash(AttReadRequestBuilder {
                attribute_handle: CHARACTERISTIC_HANDLE.into(),
            })
            .view(),
        );
        // service the first read with `data`
        let MockDatastoreEvents::Read(
            CONN_ID,
            _, _,
            tx,
        ) = data_rx_1.recv().await.unwrap() else {
            unreachable!()
        };
        tx.send(Ok(data.clone())).unwrap();
        // and then the second read with `another_data`
        let MockDatastoreEvents::Read(
            ANOTHER_CONN_ID,
            _, _,
            tx,
        ) = data_rx_2.recv().await.unwrap() else {
            unreachable!()
        };
        tx.send(Ok(another_data.clone())).unwrap();

        // receive both response packets
        let (tcb_idx_1, resp_1) = transport_rx.recv().await.unwrap();
        let (tcb_idx_2, resp_2) = transport_rx.recv().await.unwrap();

        // assert: the responses were routed to the correct connections
        assert_eq!(tcb_idx_1, TCB_IDX);
        assert_eq!(resp_1._child_.to_vec().unwrap(), DATA);
        assert_eq!(tcb_idx_2, ANOTHER_TCB_IDX);
        assert_eq!(resp_2._child_.to_vec().unwrap(), ANOTHER_DATA);
    })
}

#[test]
fn test_read_device_name() {
    start_test(async move {
        // arrange
        let (mut gatt, mut transport_rx) = start_gatt_module();
        create_server_and_open_connection(&mut gatt);

        // act: try to read the device name
        gatt.get_bearer(CONN_ID).unwrap().handle_packet(
            build_att_view_or_crash(AttReadByTypeRequestBuilder {
                starting_handle: AttHandle(1).into(),
                ending_handle: AttHandle(0xFFFF).into(),
                attribute_type: DEVICE_NAME_UUID.into(),
            })
            .view(),
        );
        let (tcb_idx, resp) = transport_rx.recv().await.unwrap();

        // assert: the name should not be readable
        assert_eq!(tcb_idx, TCB_IDX);
        let AttChild::AttErrorResponse(resp) = resp._child_ else {
            unreachable!("{resp:?}");
        };
        assert_eq!(resp.error_code, AttErrorCode::INSUFFICIENT_AUTHENTICATION);
    });
}
