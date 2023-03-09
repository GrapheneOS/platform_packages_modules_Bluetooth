//! This module is a simple GATT server that shares the ATT channel with the
//! existing C++ GATT client.

mod att_database;
pub mod att_server_bearer;
pub mod gatt_database;
mod indication_handler;
mod request_handler;
mod transactions;

#[cfg(test)]
mod test;

use std::{collections::HashMap, rc::Rc};

use crate::{
    core::shared_box::{SharedBox, WeakBoxRef},
    gatt::{ids::ConnectionId, server::gatt_database::GattDatabase},
};

use self::{
    super::ids::ServerId,
    att_server_bearer::AttServerBearer,
    gatt_database::{AttDatabaseImpl, GattServiceWithHandle},
};

use super::{callbacks::GattDatastore, channel::AttTransport, ids::AttHandle};
use anyhow::{anyhow, bail, Result};
use log::info;

pub use indication_handler::IndicationError;

#[allow(missing_docs)]
pub struct GattModule {
    connection_bearers:
        HashMap<ConnectionId, SharedBox<AttServerBearer<AttDatabaseImpl<dyn GattDatastore>>>>,
    databases: HashMap<ServerId, SharedBox<GattDatabase<dyn GattDatastore>>>,
    datastore: Rc<dyn GattDatastore>,
    transport: Rc<dyn AttTransport>,
}

impl GattModule {
    /// Constructor. Uses `datastore` to read/write characteristics.
    pub fn new(datastore: Rc<dyn GattDatastore>, transport: Rc<dyn AttTransport>) -> Self {
        Self { connection_bearers: HashMap::new(), databases: HashMap::new(), datastore, transport }
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
            AttServerBearer::new(database.get_att_database(conn_id), move |packet| {
                transport.send_packet(conn_id.get_tcb_idx(), packet)
            })
            .into(),
        );
        Ok(())
    }

    /// Handle an LE link disconnect
    pub fn on_le_disconnect(&mut self, conn_id: ConnectionId) {
        info!("disconnected conn_id {conn_id:?}");
        self.connection_bearers.remove(&conn_id);
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
        let old =
            self.databases.insert(server_id, GattDatabase::new(self.datastore.clone()).into());
        if old.is_some() {
            bail!("GATT server {server_id:?} already exists but was re-opened, clobbering old value...")
        }
        Ok(())
    }

    /// Close a GATT server
    pub fn close_gatt_server(&mut self, server_id: ServerId) -> Result<()> {
        let old = self.databases.remove(&server_id);
        if old.is_none() {
            bail!("GATT server {server_id:?} did not exist")
        };

        Ok(())
    }

    /// Get an ATT bearer for a particular connection
    pub fn get_bearer(
        &self,
        conn_id: ConnectionId,
    ) -> Option<WeakBoxRef<AttServerBearer<AttDatabaseImpl<dyn GattDatastore>>>> {
        self.connection_bearers.get(&conn_id).map(|x| x.as_ref())
    }
}
