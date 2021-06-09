mod config_util;
mod dbus_callback_util;
mod state_machine;

use dbus::channel::MatchingReceiver;
use dbus::message::MatchRule;
use dbus::nonblock::SyncConnection;
use dbus_crossroads::Crossroads;
use dbus_tokio::connection;
use log::{error, info, warn};
use log::{Level, LevelFilter, Metadata, Record, SetLoggerError};
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::sync::Mutex;

struct SimpleLogger;

impl log::Log for SimpleLogger {
    fn enabled(&self, metadata: &Metadata) -> bool {
        true || metadata.level() <= Level::Info
    }

    fn log(&self, record: &Record) {
        if self.enabled(record.metadata()) {
            println!("{} - {}", record.level(), record.args());
        }
    }

    fn flush(&self) {}
}

static LOGGER: SimpleLogger = SimpleLogger;

const BLUEZ_INIT_TARGET: &str = "bluetoothd";

#[derive(Clone)]
struct ManagerContext {
    proxy: state_machine::StateMachineProxy,
    floss_enabled: Arc<AtomicBool>,
    dbus_connection: Arc<SyncConnection>,
    state_change_observer: Arc<Mutex<Vec<String>>>,
    hci_device_change_observer: Arc<Mutex<Vec<String>>>,
}

#[tokio::main]
pub async fn main() -> Result<(), Box<dyn std::error::Error>> {
    log::set_logger(&LOGGER)
        .map(|()| {
            log::set_max_level(
                config_util::get_log_level().unwrap_or(Level::Info).to_level_filter(),
            )
        })
        .unwrap();

    // Initialize config util
    config_util::fix_config_file_format();

    // Connect to the D-Bus system bus (this is blocking, unfortunately).
    let (resource, conn) = connection::new_system_sync()?;

    let context = state_machine::start_new_state_machine_context();
    let proxy = context.get_proxy();
    let state_change_observer = Arc::new(Mutex::new(Vec::new()));
    let hci_device_change_observer = Arc::new(Mutex::new(Vec::new()));
    let manager_context = ManagerContext {
        proxy: proxy,
        floss_enabled: Arc::new(AtomicBool::new(config_util::is_floss_enabled())),
        dbus_connection: conn.clone(),
        state_change_observer: state_change_observer.clone(),
        hci_device_change_observer: hci_device_change_observer.clone(),
    };

    let dbus_callback_util = dbus_callback_util::DbusCallbackUtil::new(
        conn.clone(),
        state_change_observer.clone(),
        hci_device_change_observer.clone(),
    );

    // The resource is a task that should be spawned onto a tokio compatible
    // reactor ASAP. If the resource ever finishes, you lost connection to D-Bus.
    tokio::spawn(async {
        let err = resource.await;
        panic!("Lost connection to D-Bus: {}", err);
    });

    // Let's request a name on the bus, so that clients can find us.
    conn.request_name("org.chromium.bluetooth.Manager", false, true, false).await?;

    // Create a new crossroads instance.
    // The instance is configured so that introspection and properties interfaces
    // are added by default on object path additions.
    let mut cr = Crossroads::new();

    // Enable async support for the crossroads instance.
    cr.set_async_support(Some((
        conn.clone(),
        Box::new(|x| {
            tokio::spawn(x);
        }),
    )));

    let iface_token = cr.register("org.chromium.bluetooth.Manager", |b| {
        b.method_with_cr_async(
            "Start",
            ("hci_interface",),
            (),
            |mut ctx, cr, (hci_interface,): (i32,)| {
                if !config_util::modify_hci_n_enabled(hci_interface, true) {
                    error!("Config is not successfully modified");
                }
                let proxy = cr.data_mut::<ManagerContext>(ctx.path()).unwrap().proxy.clone();
                async move {
                    let result = proxy.start_bluetooth(hci_interface).await;
                    match result {
                        Ok(()) => ctx.reply(Ok(())),
                        Err(_) => ctx.reply(Err(dbus_crossroads::MethodErr::failed(
                            "cannot start Bluetooth",
                        ))),
                    }
                }
            },
        );
        b.method_with_cr_async(
            "Stop",
            ("hci_interface",),
            (),
            |mut ctx, cr, (hci_interface,): (i32,)| {
                let proxy = cr.data_mut::<ManagerContext>(ctx.path()).unwrap().proxy.clone();
                if !config_util::modify_hci_n_enabled(hci_interface, false) {
                    error!("Config is not successfully modified");
                }
                async move {
                    let result = proxy.stop_bluetooth(hci_interface).await;
                    match result {
                        Ok(()) => ctx.reply(Ok(())),
                        Err(_) => ctx.reply(Err(dbus_crossroads::MethodErr::failed(
                            "cannot stop Bluetooth",
                        ))),
                    }
                }
            },
        );
        b.method_with_cr_async("GetState", (), ("result",), |mut ctx, cr, ()| {
            let proxy = cr.data_mut::<ManagerContext>(ctx.path()).unwrap().proxy.clone();
            async move {
                let state = proxy.get_state().await;
                let result = state_machine::state_to_i32(state);
                ctx.reply(Ok((result,)))
            }
        });
        // Register AdapterStateChangeCallback(int hci_device, int state) on specified object_path
        b.method_with_cr_async(
            "RegisterStateChangeObserver",
            ("object_path",),
            (),
            |mut ctx, cr, (object_path,): (String,)| {
                let manager_context = cr.data_mut::<ManagerContext>(ctx.path()).unwrap().clone();
                async move {
                    manager_context.state_change_observer.lock().await.push(object_path.clone());
                    ctx.reply(Ok(()))
                }
            },
        );
        b.method_with_cr_async(
            "UnregisterStateChangeObserver",
            ("object_path",),
            (),
            |mut ctx, cr, (object_path,): (String,)| {
                let manager_context = cr.data_mut::<ManagerContext>(ctx.path()).unwrap().clone();
                async move {
                    let mut observers = manager_context.state_change_observer.lock().await;
                    match observers.iter().position(|x| *x == object_path) {
                        Some(index) => {
                            observers.remove(index);
                            ctx.reply(Ok(()))
                        }
                        _ => ctx.reply(Err(dbus_crossroads::MethodErr::failed(&format!(
                            "cannot unregister {}",
                            object_path
                        )))),
                    }
                }
            },
        );
        b.method_with_cr_async("GetFlossEnabled", (), ("result",), |mut ctx, cr, ()| {
            let enabled = cr
                .data_mut::<ManagerContext>(ctx.path())
                .unwrap()
                .clone()
                .floss_enabled
                .load(Ordering::Relaxed);

            async move { ctx.reply(Ok((enabled,))) }
        });
        b.method_with_cr_async(
            "SetFlossEnabled",
            ("enabled",),
            (),
            |mut ctx, cr, (enabled,): (bool,)| {
                let prev = cr
                    .data_mut::<ManagerContext>(ctx.path())
                    .unwrap()
                    .clone()
                    .floss_enabled
                    .swap(enabled, Ordering::Relaxed);
                config_util::write_floss_enabled(enabled);
                let proxy = cr.data_mut::<ManagerContext>(ctx.path()).unwrap().proxy.clone();

                async move {
                    if prev != enabled && enabled {
                        Command::new("initctl")
                            .args(&["stop", BLUEZ_INIT_TARGET])
                            .output()
                            .expect("failed to stop bluetoothd");
                        // TODO: Implement multi-hci case
                        let default_device = config_util::list_hci_devices()[0];
                        if config_util::is_hci_n_enabled(default_device) {
                            let _ = proxy.start_bluetooth(default_device).await;
                        }
                    } else if prev != enabled {
                        // TODO: Implement multi-hci case
                        let default_device = config_util::list_hci_devices()[0];
                        let _ = proxy.stop_bluetooth(default_device).await;
                        Command::new("initctl")
                            .args(&["start", BLUEZ_INIT_TARGET])
                            .output()
                            .expect("failed to start bluetoothd");
                    }
                    ctx.reply(Ok(()))
                }
            },
        );
        b.method_with_cr_async("ListHciDevices", (), ("devices",), |mut ctx, _cr, ()| {
            let devices = config_util::list_hci_devices();
            async move { ctx.reply(Ok((devices,))) }
        });
        // Register AdapterStateChangeCallback(int hci_device, int state) on specified object_path
        b.method_with_cr_async(
            "RegisterHciDeviceChangeObserver",
            ("object_path",),
            (),
            |mut ctx, cr, (object_path,): (String,)| {
                let manager_context = cr.data_mut::<ManagerContext>(ctx.path()).unwrap().clone();
                async move {
                    manager_context.hci_device_change_observer.lock().await.push(object_path);
                    ctx.reply(Ok(()))
                }
            },
        );
        b.method_with_cr_async(
            "UnregisterHciDeviceChangeObserver",
            ("object_path",),
            (),
            |mut ctx, cr, (object_path,): (String,)| {
                let manager_context = cr.data_mut::<ManagerContext>(ctx.path()).unwrap().clone();
                async move {
                    let mut observers = manager_context.hci_device_change_observer.lock().await;
                    match observers.iter().position(|x| *x == object_path) {
                        Some(index) => {
                            observers.remove(index);
                            ctx.reply(Ok(()))
                        }
                        _ => ctx.reply(Err(dbus_crossroads::MethodErr::failed(&format!(
                            "cannot unregister {}",
                            object_path
                        )))),
                    }
                }
            },
        );
    });

    // Let's add the "/org/chromium/bluetooth/Manager" path, which implements the org.chromium.bluetooth.Manager interface,
    // to the crossroads instance.
    cr.insert("/org/chromium/bluetooth/Manager", &[iface_token], manager_context);

    // We add the Crossroads instance to the connection so that incoming method calls will be handled.
    conn.start_receive(
        MatchRule::new_method_call(),
        Box::new(move |msg, conn| {
            cr.handle_message(msg, conn).unwrap();
            true
        }),
    );

    tokio::spawn(async move {
        state_machine::mainloop(context, dbus_callback_util).await;
    });

    std::future::pending::<()>().await;

    // Run forever.
    unreachable!()
}
