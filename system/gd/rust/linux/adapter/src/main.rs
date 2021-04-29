use bt_topshim::btif;
use bt_topshim::btif::{BaseCallbacks, BaseCallbacksDispatcher, BluetoothInterface};
use bt_topshim::topstack;
use num_traits::{FromPrimitive, ToPrimitive};
use std::convert::TryFrom;
use std::env;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::sync::mpsc::{Receiver, Sender};
use tokio::time::sleep;

// DO NOT REMOVE
// Required so that bt_shim is linked into the final image
extern crate bt_shim;

struct Context {
    tx: Sender<BaseCallbacks>,
    rx: Receiver<BaseCallbacks>,
    dispatcher: Option<BaseCallbacksDispatcher>,
    intf: BluetoothInterface,
}

fn make_context(intf: BluetoothInterface) -> Context {
    let (tx, rx) = mpsc::channel::<BaseCallbacks>(1);

    let tx1 = tx.clone();
    let dispatcher = btif::BaseCallbacksDispatcher {
        dispatch: Box::new(move |cb| {
            let txl = tx1.clone();
            topstack::get_runtime().spawn(async move {
                txl.send(cb).await;
            });
        }),
    };

    return Context { tx, rx, dispatcher: Some(dispatcher), intf };
}

async fn mainloop(context: &mut Context) {
    'main: while let Some(cb) = context.rx.recv().await {
        match cb {
            BaseCallbacks::AdapterState(state) => {
                println!("Adapter state changed to {}", state.to_u32().unwrap());

                if state == btif::BtState::On {
                    context.intf.get_adapter_properties();
                }
            }
            BaseCallbacks::AdapterProperties(status, _count, properties) => {
                if status != btif::BtStatus::Success {
                    println!("Failed property change: {:?}", status);
                }

                for p in properties {
                    println!("Property {:?} is ({:?})", p.prop_type, p.val);
                }

                // Scan for 5s and then cancel
                println!("Starting discovery");
                context.intf.start_discovery();
            }
            BaseCallbacks::RemoteDeviceProperties(status, address, _count, properties) => {
                if status != btif::BtStatus::Success {
                    println!("Failed remote property change: {:?}", status);
                }

                println!("Properties for {:?}", address.address);

                for p in properties {
                    println!("Property {:?} is ({:?})", p.prop_type, p.val);
                }
            }
            BaseCallbacks::DeviceFound(_count, properties) => {
                print!("Device found: ");

                for p in properties {
                    if p.prop_type == btif::BtPropertyType::BdAddr {
                        print!(" Addr[{:?}]", p.val);
                    } else if p.prop_type == btif::BtPropertyType::BdName {
                        print!(
                            " Name[{:?}]",
                            p.val.iter().map(|u| char::try_from(*u).unwrap()).collect::<String>()
                        );
                    }
                }

                println!("");
            }
            BaseCallbacks::DiscoveryState(state) => {
                if state == btif::BtDiscoveryState::Started {
                    sleep(Duration::from_millis(5000)).await;
                    context.intf.cancel_discovery();

                    break 'main;
                }
            }
            _ => println!("{:?}", cb),
        }
    }
}

fn main() {
    println!("Bluetooth Adapter Daemon");

    // Drop the first arg (which is the binary name)
    let all_args: Vec<String> = env::args().collect();
    let args = all_args[1..].to_vec();

    let intf = btif::get_btinterface().expect("Couldn't get bluetooth interface");
    let mut context = make_context(intf);

    topstack::get_runtime().block_on(async move {
        if let Some(dispatcher) = context.dispatcher {
            if !context.intf.initialize(dispatcher, args) {
                panic!("Couldn't initialize bluetooth interface!");
            }

            context.dispatcher = None;
        }

        println!("Enabling...");
        context.intf.enable();

        println!("Running mainloop now");
        mainloop(&mut context).await;

        println!("Disabling and exiting...");
        context.intf.disable();
    });
}
