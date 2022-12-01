use bitflags::bitflags;
use bt_topshim::btif::BtTransport;
use bt_topshim::profiles::gatt::LePhy;

bitflags! {
    pub(crate) struct AuthReq: i32 {
        // reference to system/stack/include/gatt_api.h
        const MITM   = 0x01;
        const SIGNED = 0x10;
    }
}

/// User preferenece of GATT operations
pub(crate) struct GattClientContext {
    /// If set, the registered GATT client id. None otherwise.
    pub(crate) client_id: Option<i32>,
    /// Type of authentication requirement
    pub(crate) auth_req: AuthReq,
    /// Is connection going to be directed?
    pub(crate) is_connect_direct: bool,
    /// Transport of connection
    pub(crate) connect_transport: BtTransport,
    /// Is connection going to be opportunistic?
    pub(crate) connect_opportunistic: bool,
    /// Type of connect phy
    pub(crate) connect_phy: LePhy,
}

impl GattClientContext {
    pub(crate) fn new() -> Self {
        GattClientContext {
            client_id: None,
            auth_req: AuthReq::empty(),
            is_connect_direct: false,
            connect_transport: BtTransport::Le,
            connect_opportunistic: false,
            connect_phy: LePhy::Phy1m,
        }
    }

    pub(crate) fn get_auth_req_bits(&self) -> i32 {
        self.auth_req.bits()
    }
}
