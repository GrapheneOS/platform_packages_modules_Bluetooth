//! Anything related to the Admin API (IBluetoothAdmin).

use std::collections::HashSet;
use std::sync::{Arc, Mutex};

use crate::bluetooth::{Bluetooth, BluetoothDevice, IBluetooth};
use bt_topshim::btif::Uuid128Bit;
use log::warn;

/// Defines the Admin API
pub trait IBluetoothAdmin {
    /// Check if the given UUID is in the allowlist
    fn is_service_allowed(&self, service: Uuid128Bit) -> bool;
    /// Overwrite the current settings and store it to a file.
    fn set_allowed_services(&mut self, services: Vec<Uuid128Bit>) -> bool;
    /// Get the allowlist in UUIDs
    fn get_allowed_services(&self) -> Vec<Uuid128Bit>;
    /// Get the PolicyEffect struct of a device
    fn get_device_policy_effect(&self, device: BluetoothDevice) -> Option<PolicyEffect>;
}

/// Information of the effects to a remote device by the admin policies
pub struct PolicyEffect {
    pub service_blocked: Vec<Uuid128Bit>,
}

pub struct BluetoothAdmin {
    adapter: Option<Arc<Mutex<Box<Bluetooth>>>>,
    allowed_services: HashSet<Uuid128Bit>,
}

impl BluetoothAdmin {
    pub fn new() -> BluetoothAdmin {
        // TODO: Load all admin settings from a file.
        BluetoothAdmin {
            adapter: None,
            allowed_services: HashSet::new(), //empty means allowed all services
        }
    }

    pub fn set_adapter(&mut self, adapter: Arc<Mutex<Box<Bluetooth>>>) {
        self.adapter = Some(adapter);
    }

    fn get_blocked_services(&self, remote_uuids: &Vec<Uuid128Bit>) -> Vec<Uuid128Bit> {
        remote_uuids
            .iter()
            .filter(|&s| !self.is_service_allowed(s.clone()))
            .cloned()
            .collect::<Vec<Uuid128Bit>>()
    }
}

impl IBluetoothAdmin for BluetoothAdmin {
    fn is_service_allowed(&self, service: Uuid128Bit) -> bool {
        self.allowed_services.is_empty() || self.allowed_services.contains(&service)
    }

    fn set_allowed_services(&mut self, services: Vec<Uuid128Bit>) -> bool {
        self.allowed_services.clear();

        for service in services.iter() {
            self.allowed_services.insert(service.clone());
        }

        if let Some(adapter) = &self.adapter {
            let allowed_services = self.get_allowed_services();
            adapter.lock().unwrap().toggle_enabled_profiles(&allowed_services);
            return true;
        }

        false
    }

    fn get_allowed_services(&self) -> Vec<Uuid128Bit> {
        self.allowed_services.iter().cloned().collect()
    }

    fn get_device_policy_effect(&self, device: BluetoothDevice) -> Option<PolicyEffect> {
        if let Some(adapter) = &self.adapter {
            let service_blocked =
                self.get_blocked_services(&adapter.lock().unwrap().get_remote_uuids(device));

            if service_blocked.is_empty() {
                None
            } else {
                Some(PolicyEffect { service_blocked })
            }
        } else {
            warn!("Adapter not found");
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::bluetooth_admin::{BluetoothAdmin, IBluetoothAdmin};
    use bt_topshim::btif::Uuid128Bit;

    // A workaround needed for linking. For more details, check the comment in
    // system/gd/rust/topshim/facade/src/main.rs
    #[allow(unused)]
    use bt_shim::*;

    #[test]
    fn test_set_service_allowed() {
        let mut admin = BluetoothAdmin::new();
        let uuid1: Uuid128Bit = [1; 16];
        let uuid2: Uuid128Bit = [2; 16];
        let uuid3: Uuid128Bit = [3; 16];
        let uuids = vec![uuid1.clone(), uuid2.clone(), uuid3.clone()];

        // Default admin allows everything
        assert!(admin.is_service_allowed(uuid1));
        assert!(admin.is_service_allowed(uuid2));
        assert!(admin.is_service_allowed(uuid3));
        assert_eq!(admin.get_blocked_services(&uuids), Vec::<Uuid128Bit>::new());

        admin.set_allowed_services(vec![uuid1.clone(), uuid3.clone()]);

        // Admin disallows uuid2 now
        assert!(admin.is_service_allowed(uuid1));
        assert!(!admin.is_service_allowed(uuid2));
        assert!(admin.is_service_allowed(uuid3));
        assert_eq!(admin.get_blocked_services(&uuids), vec![uuid2.clone()]);

        admin.set_allowed_services(vec![uuid2.clone()]);

        // Allowed services were overwritten.
        assert!(!admin.is_service_allowed(uuid1));
        assert!(admin.is_service_allowed(uuid2));
        assert!(!admin.is_service_allowed(uuid3));
        assert_eq!(admin.get_blocked_services(&uuids), vec![uuid1.clone(), uuid3.clone()]);
    }
}
