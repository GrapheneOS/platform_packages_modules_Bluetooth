//! This module is a simple GATT server that shares the ATT channel with the
//! existing C++ GATT client. See go/private-gatt-in-platform for the design.

pub mod arbiter;
pub mod channel;
pub mod ffi;
pub mod ids;
pub mod mocks;
pub mod server;
