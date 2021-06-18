//! Anything related to audio and media API.

use bt_topshim::btif::BluetoothInterface;
use bt_topshim::profiles::a2dp::{A2dp, A2dpCallbacksDispatcher};
use bt_topshim::topstack;

use std::sync::Arc;
use std::sync::Mutex;

use tokio::sync::mpsc::Sender;

use crate::Message;

pub trait IBluetoothMedia {
    ///
    fn register_callback(&mut self, callback: Box<dyn IBluetoothMediaCallback + Send>) -> bool;

    ///
    fn initialize(&mut self) -> bool;
}

pub trait IBluetoothMediaCallback {
    ///
    fn on_bluetooth_audio_device_added(&self, addr: String);

    ///
    fn on_bluetooth_audio_device_removed(&self, addr: String);
}

pub struct BluetoothMedia {
    intf: Arc<Mutex<BluetoothInterface>>,
    initialized: bool,
    callbacks: Vec<(u32, Box<dyn IBluetoothMediaCallback + Send>)>,
    callback_last_id: u32,
    tx: Sender<Message>,
    a2dp: Option<A2dp>,
}

impl BluetoothMedia {
    pub fn new(tx: Sender<Message>, intf: Arc<Mutex<BluetoothInterface>>) -> BluetoothMedia {
        BluetoothMedia {
            intf,
            initialized: false,
            callbacks: vec![],
            callback_last_id: 0,
            tx,
            a2dp: None,
        }
    }
}

fn get_a2dp_dispatcher(tx: Sender<Message>) -> A2dpCallbacksDispatcher {
    A2dpCallbacksDispatcher {
        dispatch: Box::new(move |cb| {
            let txl = tx.clone();
            topstack::get_runtime().spawn(async move {
                let _ = txl.send(Message::A2dp(cb)).await;
            });
        }),
    }
}

impl IBluetoothMedia for BluetoothMedia {
    fn register_callback(&mut self, callback: Box<dyn IBluetoothMediaCallback + Send>) -> bool {
        self.callback_last_id += 1;
        self.callbacks.push((self.callback_last_id, callback));
        true
    }

    fn initialize(&mut self) -> bool {
        self.initialized = true;

        // TEST A2dp
        let a2dp_dispatcher = get_a2dp_dispatcher(self.tx.clone());
        self.a2dp = Some(A2dp::new(&self.intf.lock().unwrap()));
        self.a2dp.as_mut().unwrap().initialize(a2dp_dispatcher);
        true
    }
}
