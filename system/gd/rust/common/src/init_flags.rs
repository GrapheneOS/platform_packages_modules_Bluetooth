use log::{error, info, warn};
use paste::paste;
use std::sync::Mutex;

macro_rules! default_value {
    () => {
        false
    };
    ($default:tt) => {
        $default
    };
}

macro_rules! default_flag {
    ($flag:ident) => {
        let $flag = false;
    };
    ($flag:ident = $default:tt) => {
        let $flag = $default;
    };
}

macro_rules! init_flags {
    (flags: { $($flag:ident $(= $default:tt)?,)* }, dependencies: { $($parent:ident => $child:ident),* }) => {
        struct InitFlags {
            $($flag: bool,)*
        }

        impl Default for InitFlags {
            fn default() -> Self {
                $(default_flag!($flag $(= $default)?);)*
                Self { $($flag,)* }
            }
        }

        /// Sets all flags to true, for testing
        pub fn set_all_for_testing() {
            *FLAGS.lock().unwrap() = InitFlags { $($flag: true,)* };
        }

        impl InitFlags {
            fn parse(flags: Vec<String>) -> Self {
                let mut init_flags = Self::default();

                for flag in flags {
                    let values: Vec<&str> = flag.split("=").collect();
                    if values.len() != 2 {
                        error!("Bad flag {}, must be in <FLAG>=<VALUE> format", flag);
                        continue;
                    }

                    match values[0] {
                        $(concat!("INIT_", stringify!($flag)) =>
                            init_flags.$flag = values[1].parse().unwrap_or(default_value!($($default)?)),)*
                        _ => warn!("Unsaved flag: {} = {}", values[0], values[1])
                    }
                }

                init_flags.reconcile()
            }

            fn reconcile(mut self) -> Self {
                // Loop to ensure dependencies can be specified in any order
                loop {
                    let mut any_change = false;
                    $(if self.$parent && !self.$child {
                        self.$child = true;
                        any_change = true;
                    })*

                    if !any_change {
                        break;
                    }
                }

                // TODO: acl should not be off if l2cap is on, but need to reconcile legacy code
                if self.gd_l2cap {
                  // TODO This can never be turned off  self.gd_acl = false;
                }

                self
            }

            fn log(&self) {
                info!(concat!("Flags loaded: ", $(stringify!($flag), "={} ",)*), $(self.$flag,)*);
            }
        }

        paste! {
            $(
                #[allow(missing_docs)]
                pub fn [<$flag _is_enabled>]() -> bool {
                    FLAGS.lock().unwrap().$flag
                }
            )*
        }
    };
}

init_flags!(
    flags: {
        btaa_hci = true,
        gatt_robust_caching_client = true,
        gatt_robust_caching_server,
        gd_core,
        gd_l2cap,
        gd_link_policy,
        gd_rust,
        gd_security,
        irk_rotation,
        sdp_serialization = true,
    },
    dependencies: {
        gd_core => gd_security
    }
);

lazy_static! {
    /// Store some flag values
    static ref FLAGS: Mutex<InitFlags> = Mutex::new(InitFlags::default());
    /// Store the uid of bluetooth
    pub static ref AID_BLUETOOTH: Mutex<u32> = Mutex::new(1002);
    /// Store the prefix for file system
    pub static ref MISC: Mutex<String> = Mutex::new("/data/misc/".to_string());
}

/// Loads the flag values from the passed-in vector of string values
pub fn load(flags: Vec<String>) {
    crate::init_logging();

    let flags = InitFlags::parse(flags);
    flags.log();
    *FLAGS.lock().unwrap() = flags;
}
