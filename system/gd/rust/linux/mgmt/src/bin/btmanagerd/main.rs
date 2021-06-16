mod config_util;
mod dbus_callback_util;
mod state_machine;

use dbus::channel::MatchingReceiver;
use dbus::message::MatchRule;
use dbus::nonblock::SyncConnection;
use dbus_crossroads::Crossroads;
use dbus_tokio::connection;
use log::error;
use log::{Level, Metadata, Record};
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

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

    // Object manager is necessary for clients (to inform them when Bluetooth is
    // available). Create it at root (/) so subsequent additions generate
    // InterfaceAdded and InterfaceRemoved signals.
    cr.set_object_manager_support(Some(conn.clone()));
    cr.insert("/", &[cr.object_manager()], {});

    let iface_token = cr.register(
        "org.chromium.bluetooth.Manager",
        |b: &mut dbus_crossroads::IfaceBuilder<ManagerContext>| {
            b.method(
                "Start",
                ("hci_interface",),
                (),
                |_ctx, manager_context, (hci_interface,): (i32,)| {
                    if !config_util::modify_hci_n_enabled(hci_interface, true) {
                        error!("Config is not successfully modified");
                    }
                    manager_context.proxy.start_bluetooth(hci_interface);
                    Ok(())
                },
            );
            b.method(
                "Stop",
                ("hci_interface",),
                (),
                |_ctx, manager_context, (hci_interface,): (i32,)| {
                    if !config_util::modify_hci_n_enabled(hci_interface, false) {
                        error!("Config is not successfully modified");
                    }
                    manager_context.proxy.stop_bluetooth(hci_interface);
                    Ok(())
                },
            );
            b.method("GetState", (), ("result",), |_ctx, manager_context, ()| {
                let proxy = manager_context.proxy.clone();
                let state = proxy.get_state();
                let result = state_machine::state_to_i32(state);
                Ok((result,))
            });
            // Register AdapterStateChangeCallback(int hci_device, int state) on specified object_path
            b.method(
                "RegisterStateChangeObserver",
                ("object_path",),
                (),
                |_ctx, manager_context, (object_path,): (String,)| {
                    manager_context.state_change_observer.lock().unwrap().push(object_path.clone());
                    Ok(())
                },
            );
            b.method(
                "UnregisterStateChangeObserver",
                ("object_path",),
                (),
                |_ctx, manager_context, (object_path,): (String,)| {
                    let mut observers = manager_context.state_change_observer.lock().unwrap();
                    match observers.iter().position(|x| *x == object_path) {
                        Some(index) => {
                            observers.remove(index);
                            Ok(())
                        }
                        _ => Err(dbus_crossroads::MethodErr::failed(&format!(
                            "cannot unregister {}",
                            object_path
                        ))),
                    }
                },
            );
            b.method("GetFlossEnabled", (), ("result",), |_ctx, manager_context, ()| {
                let enabled = manager_context.floss_enabled.load(Ordering::Relaxed);

                Ok((enabled,))
            });
            b.method(
                "SetFlossEnabled",
                ("enabled",),
                (),
                |_ctx, manager_context, (enabled,): (bool,)| {
                    let prev = manager_context.floss_enabled.swap(enabled, Ordering::Relaxed);
                    config_util::write_floss_enabled(enabled);
                    if prev != enabled && enabled {
                        Command::new("initctl")
                            .args(&["stop", BLUEZ_INIT_TARGET])
                            .output()
                            .expect("failed to stop bluetoothd");
                        // TODO: Implement multi-hci case
                        let default_device = config_util::list_hci_devices()[0];
                        if config_util::is_hci_n_enabled(default_device) {
                            let _ = manager_context.proxy.start_bluetooth(default_device);
                        }
                    } else if prev != enabled {
                        // TODO: Implement multi-hci case
                        let default_device = config_util::list_hci_devices()[0];
                        manager_context.proxy.stop_bluetooth(default_device);
                        Command::new("initctl")
                            .args(&["start", BLUEZ_INIT_TARGET])
                            .output()
                            .expect("failed to start bluetoothd");
                    }
                    Ok(())
                },
            );
            b.method("ListHciDevices", (), ("devices",), |_ctx, _manager_context, ()| {
                let devices = config_util::list_hci_devices();
                Ok((devices,))
            });
            // Register AdapterStateChangeCallback(int hci_device, int state) on specified object_path
            b.method(
                "RegisterHciDeviceChangeObserver",
                ("object_path",),
                (),
                |_ctx, manager_context, (object_path,): (String,)| {
                    manager_context.hci_device_change_observer.lock().unwrap().push(object_path);
                    Ok(())
                },
            );
            b.method(
                "UnregisterHciDeviceChangeObserver",
                ("object_path",),
                (),
                |_ctx, manager_context, (object_path,): (String,)| {
                    let mut observers = manager_context.hci_device_change_observer.lock().unwrap();
                    match observers.iter().position(|x| *x == object_path) {
                        Some(index) => {
                            observers.remove(index);
                            Ok(())
                        }
                        _ => Err(dbus_crossroads::MethodErr::failed(&format!(
                            "cannot unregister {}",
                            object_path
                        ))),
                    }
                },
            );
        },
    );

    // Let's add the "/org/chromium/bluetooth/Manager" path, which implements
    // the org.chromium.bluetooth.Manager interface, to the crossroads instance.
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
