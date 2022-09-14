//! Anything related to the Admin API (IBluetoothAdmin).

use std::collections::HashSet;
use std::fs::File;
use std::io::{Read, Result, Write};
use std::sync::{Arc, Mutex};

use crate::bluetooth::{Bluetooth, BluetoothDevice, IBluetooth};
use crate::uuid::UuidHelper;
use bt_topshim::btif::Uuid128Bit;
use log::{info, warn};
use serde_json::{json, Value};

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
    path: String,
    adapter: Option<Arc<Mutex<Box<Bluetooth>>>>,
    allowed_services: HashSet<Uuid128Bit>,
}

impl BluetoothAdmin {
    pub fn new(path: String) -> BluetoothAdmin {
        // default admin settings
        let mut admin = BluetoothAdmin {
            path,
            adapter: None,
            allowed_services: HashSet::new(), //empty means allowed all services
        };

        if admin.load_config().is_err() {
            warn!("Failed to load config file");
        }
        admin
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

    fn load_config(&mut self) -> Result<()> {
        let mut file = File::open(&self.path)?;
        let mut contents = String::new();
        file.read_to_string(&mut contents)?;
        let json = serde_json::from_str::<Value>(contents.as_str()).unwrap();
        if let Some(_res) = self.load_config_from_json(&json) {
            info!("Load settings from {} successfully", &self.path);
        }
        Ok(())
    }

    fn load_config_from_json(&mut self, json: &Value) -> Option<bool> {
        let allowed_services: Vec<Uuid128Bit> = json
            .get("allowed_services")?
            .as_array()?
            .iter()
            .filter_map(|v| UuidHelper::from_string(v.as_str()?))
            .collect();
        self.set_allowed_services(allowed_services);
        Some(true)
    }

    fn write_config(&self) -> Result<()> {
        let mut f = File::create(&self.path)?;
        f.write_all(self.get_config_string().as_bytes()).and_then(|_| {
            info!("Write settings into {} successfully", &self.path);
            Ok(())
        })
    }

    fn get_config_string(&self) -> String {
        serde_json::to_string_pretty(&json!({
            "allowed_services":
                self.get_allowed_services()
                    .iter()
                    .map(UuidHelper::to_string)
                    .collect::<Vec<String>>()
        }))
        .ok()
        .unwrap()
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
            if self.write_config().is_err() {
                warn!("Failed to write config");
            }
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
    use crate::uuid::UuidHelper;
    use bt_topshim::btif::Uuid128Bit;

    // A workaround needed for linking. For more details, check the comment in
    // system/gd/rust/topshim/facade/src/main.rs
    #[allow(unused)]
    use bt_shim::*;
    use serde_json::{json, Value};

    #[test]
    fn test_set_service_allowed() {
        let mut admin = BluetoothAdmin::new(String::from(""));
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

    fn get_sorted_allowed_services_from_config(admin: &BluetoothAdmin) -> Vec<String> {
        let mut v = serde_json::from_str::<Value>(admin.get_config_string().as_str())
            .unwrap()
            .get("allowed_services")
            .unwrap()
            .as_array()
            .unwrap()
            .iter()
            .map(|v| String::from(v.as_str().unwrap()))
            .collect::<Vec<String>>();
        v.sort();
        v
    }

    fn get_sorted_allowed_services(admin: &BluetoothAdmin) -> Vec<Uuid128Bit> {
        let mut v = admin.get_allowed_services();
        v.sort();
        v
    }

    #[test]
    fn test_config() {
        let mut admin = BluetoothAdmin::new(String::from(""));
        let a2dp_sink = "0000110b-0000-1000-8000-00805f9b34fb";
        let a2dp_source = "0000110a-0000-1000-8000-00805f9b34fb";

        let a2dp_sink_uuid128 = UuidHelper::from_string(a2dp_sink).unwrap();
        let a2dp_source_uuid128 = UuidHelper::from_string(a2dp_source).unwrap();

        let mut allowed_services = vec![a2dp_sink, a2dp_source];

        let mut allowed_services_128 = vec![a2dp_sink_uuid128, a2dp_source_uuid128];

        allowed_services.sort();
        allowed_services_128.sort();

        // valid configuration
        assert_eq!(
            admin.load_config_from_json(&json!({
                "allowed_services": allowed_services.clone()
            })),
            Some(true)
        );
        assert_eq!(get_sorted_allowed_services(&admin), allowed_services_128);
        assert_eq!(get_sorted_allowed_services_from_config(&admin), allowed_services);

        // invalid configuration
        assert_eq!(admin.load_config_from_json(&json!({ "allowed_services": a2dp_sink })), None);
        // config should remain unchanged
        assert_eq!(get_sorted_allowed_services(&admin), allowed_services_128);
        assert_eq!(get_sorted_allowed_services_from_config(&admin), allowed_services);
    }
}
