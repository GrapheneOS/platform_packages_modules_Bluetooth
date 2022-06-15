//! Implementation of the Socket API (IBluetoothSocketManager).

use crate::bluetooth::BluetoothDevice;
use crate::uuid::UuidHelper;
use bt_topshim::btif::{BluetoothInterface, RawAddress, Uuid};
use bt_topshim::profiles::socket::{BtSocket, SocketType};

use log::warn;
use std::sync::{Arc, Mutex};

pub trait IBluetoothSocketManager {
    /// Connects L2CAP or RFCOMM socket to remote device.
    ///
    /// # Args
    /// `device`: Remote device to connect with.
    /// `sock_type`: Type of socket to open.
    /// `uuid`: Optional service uuid for RFCOMM connections.
    /// `port`: Either channel (RFCOMM) or PSM (L2CAP).
    /// `flags`: Additional flags on the socket. Reserved for now.
    ///
    /// # Returns
    ///
    /// Optional file descriptor if the connection succeeds.
    fn connect_socket(
        &mut self,
        device: BluetoothDevice,
        sock_type: SocketType,
        uuid: Option<Uuid>,
        port: i32,
        flags: i32,
    ) -> Option<std::fs::File>;

    /// Listen to a RFCOMM UUID or L2CAP channel.
    ///
    /// # Args
    /// `sock_type`:
    /// `service_name`:
    /// `uuid`:
    /// `port`:
    /// `flags`:
    ///
    /// # Returns
    ///
    /// Optional file descriptor if listening socket was established successfully.
    fn create_socket_channel(
        &mut self,
        sock_type: SocketType,
        service_name: String,
        uuid: Option<Uuid>,
        port: i32,
        flags: i32,
    ) -> Option<std::fs::File>;

    /// Set the LE Data Length value for this connected peer to the maximum
    /// supported by this BT controller.
    ///
    /// # Args
    /// `device`: Connected remote device to apply this setting against.
    fn request_maximum_tx_data_length(&mut self, device: BluetoothDevice);
}

/// Implementation of the `IBluetoothSocketManager` api.
pub struct BluetoothSocketManager {
    sock: BtSocket,
}

impl BluetoothSocketManager {
    /// Constructs the IBluetooth implementation.
    pub fn new(intf: Arc<Mutex<BluetoothInterface>>) -> Self {
        let sock = BtSocket::new(&intf.lock().unwrap());
        BluetoothSocketManager { sock }
    }

    // TODO(abps) - We need to save information about who the caller is so that
    //              we can pipe it down to the lower levels. This needs to be
    //              provided by the projection layer and is currently missing.
    fn get_caller_uid(&self) -> i32 {
        0
    }
}

impl IBluetoothSocketManager for BluetoothSocketManager {
    fn connect_socket(
        &mut self,
        device: BluetoothDevice,
        sock_type: SocketType,
        uuid: Option<Uuid>,
        port: i32,
        flags: i32,
    ) -> Option<std::fs::File> {
        let addr = match RawAddress::from_string(device.address.clone()) {
            Some(r) => r,
            None => {
                warn!("Invalid address on connect to socket: {}", device.address);
                return None;
            }
        };

        let uu = match uuid {
            Some(v) => Some(v.uu.clone()),
            None => None,
        };

        let (status, result) =
            self.sock.connect(addr, sock_type.clone(), uu, port, flags, self.get_caller_uid());

        match result {
            Ok(fd) => Some(fd),
            Err(_) => {
                warn!(
                    "Failed to connect to socket at [{}]:{}, type={:?}, uuid={}. Status={:?}",
                    device.address,
                    port,
                    sock_type,
                    match uu {
                        Some(u) => UuidHelper::to_string(&u),
                        None => "".to_string(),
                    },
                    status
                );
                None
            }
        }
    }

    fn create_socket_channel(
        &mut self,
        sock_type: SocketType,
        service_name: String,
        uuid: Option<Uuid>,
        port: i32,
        flags: i32,
    ) -> Option<std::fs::File> {
        let uu = match uuid {
            Some(v) => Some(v.uu.clone()),
            None => None,
        };

        let (status, result) = self.sock.listen(
            sock_type.clone(),
            service_name.clone(),
            uu,
            port,
            flags,
            self.get_caller_uid(),
        );

        match result {
            Ok(fd) => Some(fd),
            Err(_) => {
                warn!(
                    "Failed to create socket channel on port {}, type {:?}, name={}, uuid={}. Status={:?}",
                    port, sock_type, service_name, match uu {
                        Some(u) => UuidHelper::to_string(&u),
                        None => "".to_string(),
                    }, status);
                None
            }
        }
    }

    fn request_maximum_tx_data_length(&mut self, device: BluetoothDevice) {
        let addr = match RawAddress::from_string(device.address.clone()) {
            Some(r) => r,
            None => {
                warn!("Invalid address requesting max tx data length: {}", device.address);
                return;
            }
        };

        self.sock.request_max_tx_data_length(addr);
    }
}
