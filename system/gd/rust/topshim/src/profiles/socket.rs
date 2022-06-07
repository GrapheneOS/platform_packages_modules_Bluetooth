use crate::bindings::root as bindings;
use crate::btif::{
    BluetoothInterface, BtStatus, FfiAddress, RawAddress, SupportedProfiles, Uuid, Uuid128Bit,
};
use crate::{cast_to_ffi_address, ccall};

use num_traits::cast::{FromPrimitive, ToPrimitive};
use std::ffi::CString;
use std::fs::File;
use std::os::unix::io::FromRawFd;

#[derive(Clone, Debug, FromPrimitive, ToPrimitive)]
#[repr(u32)]
/// Socket interface type.
pub enum SocketType {
    /// Unknown socket type value.
    Unknown = 0,

    Rfcomm = 1,
    Sco = 2,
    L2cap = 3,
    L2capLe = 4,
}

impl From<bindings::btsock_type_t> for SocketType {
    fn from(item: bindings::btsock_type_t) -> Self {
        SocketType::from_u32(item).unwrap_or(SocketType::Unknown)
    }
}

impl From<SocketType> for bindings::btsock_type_t {
    fn from(item: SocketType) -> Self {
        item.to_u32().unwrap_or(0)
    }
}

/// Represents the standard BT SOCKET interface.
///
/// For parameter documentation, see the type |sock_connect_signal_t|.
pub type SocketConnectSignal = bindings::sock_connect_signal_t;

struct RawBtSockWrapper {
    raw: *const bindings::btsock_interface_t,
}

// Pointers unsafe due to ownership but this is a static pointer so Send is ok.
unsafe impl Send for RawBtSockWrapper {}

/// Bluetooth socket interface wrapper. This allows creation of RFCOMM and L2CAP sockets.
/// For documentation of functions, see definition of |btsock_interface_t|.
pub struct BtSocket {
    internal: RawBtSockWrapper,
}

pub type FdError = &'static str;

fn try_from_fd(fd: i32) -> Result<File, FdError> {
    if fd >= 0 {
        Ok(unsafe { File::from_raw_fd(fd) })
    } else {
        Err("Invalid FD")
    }
}

impl BtSocket {
    pub fn new(intf: &BluetoothInterface) -> Self {
        let r = intf.get_profile_interface(SupportedProfiles::Socket);
        BtSocket { internal: RawBtSockWrapper { raw: r as *const bindings::btsock_interface_t } }
    }

    pub fn listen(
        &self,
        sock_type: SocketType,
        service_name: String,
        service_uuid: Option<Uuid128Bit>,
        channel: i32,
        flags: i32,
        calling_uid: i32,
    ) -> (BtStatus, Result<File, FdError>) {
        let mut sockfd: i32 = -1;
        let uuid = match service_uuid {
            Some(uu) => Some(Uuid { uu }),
            None => None,
        };

        let uuid_ptr = match uuid {
            Some(u) => &u as *const Uuid,
            None => std::ptr::null(),
        };

        let name = CString::new(service_name).expect("Service name has null in it.");
        let status: BtStatus = ccall!(
            self,
            listen,
            sock_type.into(),
            name.as_ptr(),
            uuid_ptr,
            channel,
            &mut sockfd,
            flags,
            calling_uid
        )
        .into();

        (status, try_from_fd(sockfd))
    }

    pub fn connect(
        &self,
        addr: RawAddress,
        sock_type: SocketType,
        service_uuid: Option<Uuid128Bit>,
        channel: i32,
        flags: i32,
        calling_uid: i32,
    ) -> (BtStatus, Result<File, FdError>) {
        let mut sockfd: i32 = -1;
        let uuid = match service_uuid {
            Some(uu) => Some(Uuid { uu }),
            None => None,
        };

        let uuid_ptr = match uuid {
            Some(u) => &u as *const Uuid,
            None => std::ptr::null(),
        };

        let ffi_addr = cast_to_ffi_address!(&addr as *const RawAddress);

        let status: BtStatus = ccall!(
            self,
            connect,
            ffi_addr,
            sock_type.into(),
            uuid_ptr,
            channel,
            &mut sockfd,
            flags,
            calling_uid
        )
        .into();

        (status, try_from_fd(sockfd))
    }

    pub fn request_max_tx_data_length(&self, addr: RawAddress) {
        let ffi_addr = cast_to_ffi_address!(&addr as *const RawAddress);
        ccall!(self, request_max_tx_data_length, ffi_addr);
    }
}
