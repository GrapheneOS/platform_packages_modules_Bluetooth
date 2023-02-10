//! This module is a simple GATT server that shares the ATT channel with the
//! existing C++ GATT client.

mod att_database;
pub mod att_server_bearer;
pub mod gatt_database;
mod transaction_handler;
mod transactions;

#[cfg(test)]
mod test;
mod utils;

use std::{collections::HashMap, rc::Rc};

use crate::{
    gatt::{ids::ConnectionId, server::gatt_database::GattDatabase},
    packets::AttView,
};

use self::{
    super::ids::ServerId,
    att_server_bearer::AttServerBearer,
    gatt_database::{AttDatabaseImpl, GattServiceWithHandle},
};

use super::{channel::AttTransport, ids::AttHandle};
use anyhow::{anyhow, bail, Result};
use log::info;

#[allow(missing_docs)]
pub struct GattModule {
    connection_bearers: HashMap<ConnectionId, Rc<AttServerBearer<AttDatabaseImpl>>>,
    databases: HashMap<ServerId, Rc<GattDatabase>>,
    transport: Rc<dyn AttTransport>,
}

impl GattModule {
    /// Constructor.
    pub fn new(transport: Rc<dyn AttTransport>) -> Self {
        Self { connection_bearers: HashMap::new(), databases: HashMap::new(), transport }
    }

    /// Handle LE link connect
    pub fn on_le_connect(&mut self, conn_id: ConnectionId) -> Result<()> {
        info!("connected on conn_id {conn_id:?}");
        let database = self.databases.get(&conn_id.get_server_id());
        let Some(database) = database else {
            bail!(
                "got connection to conn_id {conn_id:?} (server_id {:?}) but this server does not exist!",
                conn_id.get_server_id(),
            );
        };
        let transport = self.transport.clone();
        self.connection_bearers.insert(
            conn_id,
            AttServerBearer::new(database.get_att_database(), move |packet| {
                transport.send_packet(conn_id.get_tcb_idx(), packet)
            }),
        );
        Ok(())
    }

    /// Handle an LE link disconnect
    pub fn on_le_disconnect(&mut self, conn_id: ConnectionId) {
        info!("disconnected conn_id {conn_id:?}");
        self.connection_bearers.remove(&conn_id);
    }

    /// Handle an incoming ATT packet
    pub fn handle_packet(&mut self, conn_id: ConnectionId, packet: AttView<'_>) -> Result<()> {
        self.connection_bearers
            .get(&conn_id)
            .ok_or_else(|| anyhow!("dropping ATT packet for unregistered connection"))?
            .handle_packet(packet);
        Ok(())
    }

    /// Register a new GATT service on a given server
    pub fn register_gatt_service(
        &mut self,
        server_id: ServerId,
        service: GattServiceWithHandle,
    ) -> Result<()> {
        self.databases
            .get(&server_id)
            .ok_or_else(|| anyhow!("server {server_id:?} not opened"))?
            .add_service_with_handles(service)
    }

    /// Unregister an existing GATT service on a given server
    pub fn unregister_gatt_service(
        &mut self,
        server_id: ServerId,
        service_handle: AttHandle,
    ) -> Result<()> {
        self.databases
            .get(&server_id)
            .ok_or_else(|| anyhow!("server {server_id:?} not opened"))?
            .remove_service_at_handle(service_handle)
    }

    /// Open a GATT server
    pub fn open_gatt_server(&mut self, server_id: ServerId) -> Result<()> {
        let old = self.databases.insert(server_id, GattDatabase::new().into());
        if old.is_some() {
            bail!("GATT server {server_id:?} already exists but was re-opened, clobbering old value...")
        }
        Ok(())
    }

    /// Close a GATT server
    pub fn close_gatt_server(&mut self, server_id: ServerId) -> Result<()> {
        let old = self.databases.remove(&server_id);
        let Some(old) = old else {
            bail!("GATT server {server_id:?} did not exist")
        };

        old.clear_all_services();

        Ok(())
    }
}
