//! This module is a simple GATT server that shares the ATT channel with the
//! existing C++ GATT client.

mod att_database;
pub mod att_server_bearer;
mod transaction_handler;
mod transactions;

#[cfg(test)]
mod test;
mod utils;
