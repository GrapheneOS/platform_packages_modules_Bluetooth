mod config_util;
mod state_machine;

use dbus::channel::MatchingReceiver;
use dbus::message::MatchRule;
use dbus_crossroads::Crossroads;
use dbus_tokio::connection;
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

const BLUEZ_INIT_TARGET: &str = "bluetoothd";

#[derive(Clone)]
struct ManagerContext {
    proxy: state_machine::StateMachineProxy,
    floss_enabled: Arc<AtomicBool>,
}

#[tokio::main]
pub async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize config util
    config_util::fix_config_file_format();

    let context = state_machine::start_new_state_machine_context();
    let proxy = context.get_proxy();
    let manager_context = ManagerContext {
        proxy: proxy,
        floss_enabled: Arc::new(AtomicBool::new(config_util::is_floss_enabled())),
    };

    // Connect to the D-Bus system bus (this is blocking, unfortunately).
    let (resource, c) = connection::new_system_sync()?;

    // The resource is a task that should be spawned onto a tokio compatible
    // reactor ASAP. If the resource ever finishes, you lost connection to D-Bus.
    tokio::spawn(async {
        let err = resource.await;
        panic!("Lost connection to D-Bus: {}", err);
    });

    // Let's request a name on the bus, so that clients can find us.
    c.request_name("org.chromium.bluetooth.Manager", false, true, false).await?;

    // Create a new crossroads instance.
    // The instance is configured so that introspection and properties interfaces
    // are added by default on object path additions.
    let mut cr = Crossroads::new();

    // Enable async support for the crossroads instance.
    cr.set_async_support(Some((
        c.clone(),
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
                    println!("Config is not successfully modified");
                }
                let proxy = cr.data_mut::<ManagerContext>(ctx.path()).unwrap().proxy.clone();
                println!("Incoming Start call for hci {}!", hci_interface);
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
                    println!("Config is not successfully modified");
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
                let result = match state {
                    state_machine::State::Off => 0,
                    state_machine::State::TurningOn => 1,
                    state_machine::State::On => 2,
                    state_machine::State::TurningOff => 3,
                };
                ctx.reply(Ok((result,)))
            }
        });
        b.method_with_cr_async(
            "RegisterStateChangeObserver",
            ("object_path",),
            (),
            |mut ctx, cr, (object_path,): (String,)| {
                let proxy = cr.data_mut::<ManagerContext>(ctx.path()).unwrap().proxy.clone();
                async move {
                    let result = proxy.register_state_change_observer(object_path.clone()).await;
                    match result {
                        Ok(()) => ctx.reply(Ok(())),
                        Err(_) => ctx.reply(Err(dbus_crossroads::MethodErr::failed(&format!(
                            "cannot register {}",
                            object_path
                        )))),
                    }
                }
            },
        );
        b.method_with_cr_async(
            "UnregisterStateChangeObserver",
            ("object_path",),
            (),
            |mut ctx, cr, (object_path,): (String,)| {
                let proxy = cr.data_mut::<ManagerContext>(ctx.path()).unwrap().proxy.clone();
                async move {
                    let result = proxy.unregister_state_change_observer(object_path.clone()).await;
                    match result {
                        Ok(()) => ctx.reply(Ok(())),
                        Err(_) => ctx.reply(Err(dbus_crossroads::MethodErr::failed(&format!(
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
                        let _ = proxy.start_bluetooth(0).await;
                    } else if prev != enabled {
                        let _ = proxy.stop_bluetooth(0).await;
                        Command::new("initctl")
                            .args(&["start", BLUEZ_INIT_TARGET])
                            .output()
                            .expect("failed to start bluetoothd");
                    }
                    ctx.reply(Ok(()))
                }
            },
        );
    });

    // Let's add the "/org/chromium/bluetooth/Manager" path, which implements the org.chromium.bluetooth.Manager interface,
    // to the crossroads instance.
    cr.insert("/org/chromium/bluetooth/Manager", &[iface_token], manager_context);

    // We add the Crossroads instance to the connection so that incoming method calls will be handled.
    c.start_receive(
        MatchRule::new_method_call(),
        Box::new(move |msg, conn| {
            cr.handle_message(msg, conn).unwrap();
            true
        }),
    );

    tokio::spawn(async move {
        state_machine::mainloop(context).await;
    });

    std::future::pending::<()>().await;

    // Run forever.
    unreachable!()
}
