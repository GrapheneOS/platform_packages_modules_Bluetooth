//! FFI interfaces for the GATT module. Some structs are exported so that
//! core::init can instantiate and pass them into the main loop.

pub use inner::*;

use crate::packets::{AttBuilder, Serializable, SerializeError};

use super::{channel::AttTransport, ids::TransportIndex};

#[cxx::bridge]
#[allow(clippy::needless_lifetimes)]
#[allow(clippy::too_many_arguments)]
#[allow(missing_docs)]
mod inner {
    #[namespace = "bluetooth::shim::arbiter"]
    unsafe extern "C++" {
        include!("stack/arbiter/acl_arbiter.h");
        /// Send an outgoing packet on the specified tcb_idx
        fn SendPacketToPeer(tcb_idx: u8, packet: Vec<u8>);
    }
}

/// Implementation of AttTransport wrapping the corresponding C++ method
pub struct AttTransportImpl();

impl AttTransport for AttTransportImpl {
    fn send_packet(
        &self,
        tcb_idx: TransportIndex,
        packet: AttBuilder,
    ) -> Result<(), SerializeError> {
        SendPacketToPeer(tcb_idx.0, packet.to_vec()?);
        Ok(())
    }
}
