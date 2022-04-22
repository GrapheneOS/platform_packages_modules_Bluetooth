use crate::bridge::ffi::BluetoothKeystoreInterface;
use crate::init_flags::AID_BLUETOOTH;
use cxx::UniquePtr;
use nix::unistd::getuid;
use std::marker::Send;
use std::ptr::null_mut;
use std::string::String;
use std::sync::Mutex;

/// A single ParameterProvider
pub struct ParameterProvider {
    configuration_file_path: String,
    btsnoop_log_file_path: String,
    btsnooz_log_file_path: String,
    common_criteria_mode: bool,
    common_criteria_config_compare_result: i32,
    bt_keystore_interface: *mut BluetoothKeystoreInterface,
    lock: Mutex<i32>,
}

unsafe impl Send for ParameterProvider {}
unsafe impl Send for BluetoothKeystoreInterface {}

impl ParameterProvider {
    /// Construct a new ParameterProvider
    pub fn new(prefix: String) -> Self {
        Self {
            configuration_file_path: prefix.clone() + "bluedroid/bt_config.conf",
            btsnoop_log_file_path: prefix.clone() + "bluetooth/logs/btsnoop_hci.log",
            btsnooz_log_file_path: prefix + "bluetooth/logs/btsnooz_hci.log",
            common_criteria_mode: false,
            common_criteria_config_compare_result: 0b11,
            bt_keystore_interface: null_mut(),
            lock: Mutex::new(0),
        }
    }

    /// Get the config file path
    pub async fn config_file_path(&self) -> String {
        let guard = self.lock.lock().unwrap();
        let path = &self.configuration_file_path;
        drop(guard);
        path.to_string()
    }

    /// Set the config file path
    pub async fn override_config_file_path(&mut self, path: &str) {
        let guard = self.lock.lock().unwrap();
        self.configuration_file_path = path.to_string();
        drop(guard);
    }

    /// Get the snoop file path
    pub async fn snoop_log_file_path(&mut self) -> String {
        let guard = self.lock.lock().unwrap();
        let path = &self.btsnoop_log_file_path;
        drop(guard);
        path.to_string()
    }

    /// Set the snoop file path
    pub async fn override_snoop_file_path(&mut self, path: &str) {
        let guard = self.lock.lock().unwrap();
        self.btsnoop_log_file_path = path.to_string();
        drop(guard);
    }

    /// Get the snooz log file path
    pub async fn snooz_log_file_path(&mut self) -> String {
        let guard = self.lock.lock().unwrap();
        let path = &self.btsnooz_log_file_path;
        drop(guard);
        path.to_string()
    }

    /// Set the snooz file path
    pub async fn override_snooz_file_path(&mut self, path: &str) {
        let guard = self.lock.lock().unwrap();
        self.btsnooz_log_file_path = path.to_string();
        drop(guard);
    }

    /// Get the bluetooth keystore interface
    pub async fn get_bt_keystore_interface(&mut self) -> *mut BluetoothKeystoreInterface {
        let guard = self.lock.lock().unwrap();
        let result = &self.bt_keystore_interface;
        drop(guard);
        *result
    }

    /// Set the bluetooth keystore interface
    pub async fn set_bt_keystore_interface(
        &mut self,
        by_keystore: UniquePtr<BluetoothKeystoreInterface>,
    ) {
        let guard = self.lock.lock().unwrap();
        self.bt_keystore_interface = by_keystore.into_raw();
        drop(guard);
    }

    /// Get the common criteria mode
    pub async fn is_common_criteria_mode(&self) -> bool {
        let guard = self.lock.lock().unwrap();
        let enable = &self.common_criteria_mode;
        drop(guard);
        return (getuid().as_raw() == *(*AID_BLUETOOTH).lock().unwrap()) && *enable;
    }

    /// Set the common criteria mode
    pub async fn set_common_criteria_mode(&mut self, enable: bool) {
        let guard = self.lock.lock().unwrap();
        self.common_criteria_mode = enable;
        drop(guard);
    }

    /// Get the common criteria config compare result
    pub async fn get_common_criteria_config_compare_result(&self) -> i32 {
        let guard = self.lock.lock().unwrap();
        let result = &self.common_criteria_config_compare_result;
        drop(guard);
        *result
    }

    /// Set the common criteria config compare result
    pub async fn set_common_criteria_config_compare_result(&mut self, result: i32) {
        let guard = self.lock.lock().unwrap();
        self.common_criteria_config_compare_result = result;
        drop(guard);
    }
}

#[cfg(test)]
mod tests {
    use crate::bridge::ffi;
    use crate::bridge::ffi::BluetoothKeystoreInterface;
    use crate::bridge::ParameterProvider;
    use crate::init_flags::AID_BLUETOOTH;
    use crate::init_flags::MISC;
    use futures::executor::block_on;
    use nix::unistd::getuid;
    use std::assert_eq;
    use std::i64;
    use std::ptr::null_mut;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use std::sync::Mutex;
    use std::thread;

    #[tokio::test]
    async fn test_config_file_path() {
        let prefix: String = (*(*MISC).lock().unwrap()).clone();
        let param_provider = Arc::new(Mutex::new(ParameterProvider::new(prefix)));
        let origin: String = (*param_provider.lock().unwrap()).config_file_path().await;
        assert_eq!(origin, "/data/misc/bluedroid/bt_config.conf");
        let param_provider1 = Arc::clone(&param_provider);
        let param_provider2 = Arc::clone(&param_provider);
        let choice = Arc::new(Mutex::new("0"));
        let choice1 = Arc::clone(&choice);
        let choice2 = Arc::clone(&choice);
        let handle1 = thread::spawn(move || {
            let mut c1 = choice1.lock().unwrap();
            *c1 = "1";
            block_on((*param_provider1.lock().unwrap()).override_config_file_path(&c1.to_string()));
        });

        let handle2 = thread::spawn(move || {
            let mut c2 = choice2.lock().unwrap();
            *c2 = "2";
            block_on((*param_provider2.lock().unwrap()).override_config_file_path(&c2.to_string()));
        });

        handle1.join().unwrap();
        handle2.join().unwrap();
        let current: String = (*param_provider.lock().unwrap()).config_file_path().await;
        assert_eq!(*choice.lock().unwrap(), &current);
        (*param_provider.lock().unwrap()).override_config_file_path(&origin).await;
        let now: String = (*param_provider.lock().unwrap()).config_file_path().await;
        assert_eq!(now, "/data/misc/bluedroid/bt_config.conf");
    }

    #[tokio::test]
    async fn test_snoop_log_file_path() {
        let prefix: String = (*(*MISC).lock().unwrap()).clone();
        let param_provider = Arc::new(Mutex::new(ParameterProvider::new(prefix)));
        let origin: String = (*param_provider.lock().unwrap()).snoop_log_file_path().await;
        assert_eq!(origin, "/data/misc/bluetooth/logs/btsnoop_hci.log");
        let param_provider1 = Arc::clone(&param_provider);
        let param_provider2 = Arc::clone(&param_provider);
        let choice = Arc::new(Mutex::new("0"));
        let choice1 = Arc::clone(&choice);
        let choice2 = Arc::clone(&choice);
        let handle1 = thread::spawn(move || {
            let mut c1 = choice1.lock().unwrap();
            *c1 = "1";
            block_on((*param_provider1.lock().unwrap()).override_snoop_file_path(&c1.to_string()));
        });

        let handle2 = thread::spawn(move || {
            let mut c2 = choice2.lock().unwrap();
            *c2 = "2";
            block_on((*param_provider2.lock().unwrap()).override_snoop_file_path(&c2.to_string()));
        });

        handle1.join().unwrap();
        handle2.join().unwrap();
        let current: String = (*param_provider.lock().unwrap()).snoop_log_file_path().await;
        assert_eq!(*choice.lock().unwrap(), &current);
        (*param_provider.lock().unwrap()).override_snoop_file_path(&origin).await;
        let now: String = (*param_provider.lock().unwrap()).snoop_log_file_path().await;
        assert_eq!(now, "/data/misc/bluetooth/logs/btsnoop_hci.log");
    }

    #[tokio::test]
    async fn test_snooz_log_file_path() {
        let prefix: String = (*(*MISC).lock().unwrap()).clone();
        let param_provider = Arc::new(Mutex::new(ParameterProvider::new(prefix)));
        let origin: String = (*param_provider.lock().unwrap()).snooz_log_file_path().await;
        assert_eq!(origin, "/data/misc/bluetooth/logs/btsnooz_hci.log");
        let param_provider1 = Arc::clone(&param_provider);
        let param_provider2 = Arc::clone(&param_provider);
        let choice = Arc::new(Mutex::new("0"));
        let choice1 = Arc::clone(&choice);
        let choice2 = Arc::clone(&choice);
        let handle1 = thread::spawn(move || {
            let mut c1 = choice1.lock().unwrap();
            *c1 = "1";
            block_on((*param_provider1.lock().unwrap()).override_snooz_file_path(&c1.to_string()));
        });

        let handle2 = thread::spawn(move || {
            let mut c2 = choice2.lock().unwrap();
            *c2 = "2";
            block_on((*param_provider2.lock().unwrap()).override_snooz_file_path(&c2.to_string()));
        });

        handle1.join().unwrap();
        handle2.join().unwrap();
        let current: String = (*param_provider.lock().unwrap()).snooz_log_file_path().await;
        assert_eq!(*choice.lock().unwrap(), &current);
        (*param_provider.lock().unwrap()).override_snooz_file_path(&origin).await;
        let now: String = (*param_provider.lock().unwrap()).snooz_log_file_path().await;
        assert_eq!(now, "/data/misc/bluetooth/logs/btsnooz_hci.log");
    }

    #[tokio::test]
    async fn test_bt_keystore_interface() {
        let prefix: String = (*(*MISC).lock().unwrap()).clone();
        let param_provider = Arc::new(Mutex::new(ParameterProvider::new(prefix)));
        let origin: *mut BluetoothKeystoreInterface =
            (*param_provider.lock().unwrap()).get_bt_keystore_interface().await;
        assert_eq!(origin, null_mut());
        let param_provider1 = Arc::clone(&param_provider);
        let param_provider2 = Arc::clone(&param_provider);

        let choice_p1: cxx::UniquePtr<ffi::BluetoothKeystoreInterface> =
            ffi::new_bt_keystore_interface();
        let address_p1 = format!("{:p}", &choice_p1);

        let choice_p2: cxx::UniquePtr<ffi::BluetoothKeystoreInterface> =
            ffi::new_bt_keystore_interface();
        let address_p2 = format!("{:p}", &choice_p2);

        let choice = Arc::new(Mutex::new("0"));
        let choice1 = Arc::clone(&choice);
        let choice2 = Arc::clone(&choice);

        let handle1 = thread::spawn(move || {
            let mut c1 = choice1.lock().unwrap();
            *c1 = "1";
            block_on((*param_provider1.lock().unwrap()).set_bt_keystore_interface(choice_p1));
        });

        let handle2 = thread::spawn(move || {
            let mut c2 = choice2.lock().unwrap();
            *c2 = "2";
            block_on((*param_provider2.lock().unwrap()).set_bt_keystore_interface(choice_p2));
        });

        handle1.join().unwrap();
        handle2.join().unwrap();
        let current = (*param_provider.lock().unwrap()).get_bt_keystore_interface().await;
        let address_current = format!("{:p}", &current);
        let address = hex_to_dec(address_current);
        if *choice.lock().unwrap() == "1" {
            let addr1 = hex_to_dec(address_p1);
            assert_eq!(*address, *addr1);
        } else {
            let addr2 = hex_to_dec(address_p2);
            assert_eq!(*address, *addr2);
        }
    }

    #[tokio::test]
    async fn test_common_criteria_mode() {
        let prefix: String = (*(*MISC).lock().unwrap()).clone();
        let param_provider = Arc::new(Mutex::new(ParameterProvider::new(prefix)));
        let origin: bool = (*param_provider.lock().unwrap()).is_common_criteria_mode().await;
        assert!(!origin);
        let param_provider1 = Arc::clone(&param_provider);
        let param_provider2 = Arc::clone(&param_provider);

        let choice = Arc::new(AtomicBool::new(false));
        let choice1 = choice.clone();
        let choice2 = choice.clone();

        let init_bt: u32 = *(*AID_BLUETOOTH).lock().unwrap();
        *(*AID_BLUETOOTH).lock().unwrap() = getuid().as_raw();

        let handle1 = thread::spawn(move || {
            choice1.store(false, Ordering::Relaxed);
            block_on((*param_provider1.lock().unwrap()).set_common_criteria_mode(false));
        });

        let handle2 = thread::spawn(move || {
            choice2.store(true, Ordering::Relaxed);
            block_on((*param_provider2.lock().unwrap()).set_common_criteria_mode(true));
        });

        handle1.join().unwrap();
        handle2.join().unwrap();
        let current: bool = (*param_provider.lock().unwrap()).is_common_criteria_mode().await;
        assert_eq!(choice.load(Ordering::SeqCst), current);
        (*param_provider.lock().unwrap()).set_common_criteria_mode(origin).await;
        let now: bool = (*param_provider.lock().unwrap()).is_common_criteria_mode().await;
        assert!(!now);
        *(*AID_BLUETOOTH).lock().unwrap() = init_bt;
    }

    #[tokio::test]
    async fn test_common_criteria_config_compare_result() {
        let prefix: String = (*(*MISC).lock().unwrap()).clone();
        let param_provider = Arc::new(Mutex::new(ParameterProvider::new(prefix)));
        let origin: i32 =
            (*param_provider.lock().unwrap()).get_common_criteria_config_compare_result().await;
        assert_eq!(origin, 0b11);
        let param_provider1 = Arc::clone(&param_provider);
        let param_provider2 = Arc::clone(&param_provider);
        let counter = Arc::new(Mutex::new(0));
        let counter1 = Arc::clone(&counter);
        let counter2 = Arc::clone(&counter);
        let handle1 = thread::spawn(move || {
            let mut c1 = counter1.lock().unwrap();
            *c1 = 1;
            block_on(
                (*param_provider1.lock().unwrap()).set_common_criteria_config_compare_result(*c1),
            );
        });

        let handle2 = thread::spawn(move || {
            let mut c2 = counter2.lock().unwrap();
            *c2 = 2;
            block_on(
                (*param_provider2.lock().unwrap()).set_common_criteria_config_compare_result(*c2),
            );
        });

        handle1.join().unwrap();
        handle2.join().unwrap();
        let current: i32 =
            (*param_provider.lock().unwrap()).get_common_criteria_config_compare_result().await;
        assert_eq!(*counter.lock().unwrap(), current);
        (*param_provider.lock().unwrap()).set_common_criteria_config_compare_result(origin).await;
        let now: i32 =
            (*param_provider.lock().unwrap()).get_common_criteria_config_compare_result().await;
        assert_eq!(now, 0b11);
    }

    fn hex_to_dec(origin: String) -> &'static i64 {
        let address = unsafe {
            let origin = origin.trim_start_matches("0x");
            &*(usize::from_str_radix(origin, 16).unwrap() as *const i64)
        };
        address
    }
}
