//! Anything related to audio and media API.

use bt_topshim::btif::{BluetoothInterface, RawAddress};
use bt_topshim::profiles::a2dp::{
    A2dp, A2dpCallbacks, A2dpCallbacksDispatcher, A2dpCodecBitsPerSample, A2dpCodecChannelMode,
    A2dpCodecConfig, A2dpCodecIndex, A2dpCodecSampleRate, BtavConnectionState,
};
use bt_topshim::profiles::avrcp::Avrcp;
use bt_topshim::topstack;

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::Mutex;

use tokio::sync::mpsc::Sender;

use crate::Message;

pub trait IBluetoothMedia {
    ///
    fn register_callback(&mut self, callback: Box<dyn IBluetoothMediaCallback + Send>) -> bool;

    /// initializes media (both A2dp and AVRCP) stack
    fn initialize(&mut self) -> bool;

    /// clean up media stack
    fn cleanup(&mut self) -> bool;

    fn connect(&mut self, device: String);
    fn set_active_device(&mut self, device: String);
    fn disconnect(&mut self, device: String);
    fn set_audio_config(
        &mut self,
        sample_rate: i32,
        bits_per_sample: i32,
        channel_mode: i32,
    ) -> bool;
    fn start_audio_request(&mut self);
    fn stop_audio_request(&mut self);
}

pub trait IBluetoothMediaCallback {
    ///
    fn on_bluetooth_audio_device_added(
        &self,
        addr: String,
        sample_rate: i32,
        bits_per_sample: i32,
        channel_mode: i32,
    );

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
    avrcp: Option<Avrcp>,
    a2dp_states: HashMap<RawAddress, BtavConnectionState>,
    selectable_caps: HashMap<RawAddress, Vec<A2dpCodecConfig>>,
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
            avrcp: None,
            a2dp_states: HashMap::new(),
            selectable_caps: HashMap::new(),
        }
    }

    pub fn dispatch_a2dp_callbacks(&mut self, cb: A2dpCallbacks) {
        match cb {
            A2dpCallbacks::ConnectionState(addr, state) => {
                if !self.a2dp_states.get(&addr).is_none()
                    && state == *self.a2dp_states.get(&addr).unwrap()
                {
                    return;
                }
                match state {
                    BtavConnectionState::Connected => {
                        if let Some(caps) = self.selectable_caps.get(&addr) {
                            for cap in caps {
                                // TODO: support codecs other than SBC.
                                if A2dpCodecIndex::SrcSbc != A2dpCodecIndex::from(cap.codec_type) {
                                    continue;
                                }

                                self.for_all_callbacks(|callback| {
                                    callback.on_bluetooth_audio_device_added(
                                        addr.to_string(),
                                        cap.sample_rate,
                                        cap.bits_per_sample,
                                        cap.channel_mode,
                                    );
                                });
                                return;
                            }
                        }
                    }
                    BtavConnectionState::Connecting => {}
                    BtavConnectionState::Disconnected => {
                        self.for_all_callbacks(|callback| {
                            callback.on_bluetooth_audio_device_removed(addr.to_string());
                        });
                    }
                    BtavConnectionState::Disconnecting => {}
                };
                self.a2dp_states.insert(addr, state);
            }
            A2dpCallbacks::AudioState(_addr, _state) => {}
            A2dpCallbacks::AudioConfig(addr, _config, _local_caps, selectable_caps) => {
                self.selectable_caps.insert(addr, selectable_caps);
            }
            A2dpCallbacks::MandatoryCodecPreferred(_addr) => {}
        }
    }

    fn for_all_callbacks<F: Fn(&Box<dyn IBluetoothMediaCallback + Send>)>(&self, f: F) {
        for callback in &self.callbacks {
            f(&callback.1);
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

        // AVRCP
        self.avrcp = Some(Avrcp::new(&self.intf.lock().unwrap()));
        self.avrcp.as_mut().unwrap().initialize();
        true
    }

    fn connect(&mut self, device: String) {
        self.a2dp.as_mut().unwrap().connect(device);
    }

    fn cleanup(&mut self) -> bool {
        true
    }

    fn set_active_device(&mut self, device: String) {
        self.a2dp.as_mut().unwrap().set_active_device(device);
    }

    fn disconnect(&mut self, device: String) {
        self.a2dp.as_mut().unwrap().disconnect(device);
    }

    fn set_audio_config(
        &mut self,
        sample_rate: i32,
        bits_per_sample: i32,
        channel_mode: i32,
    ) -> bool {
        if !A2dpCodecSampleRate::validate_bits(sample_rate)
            || !A2dpCodecBitsPerSample::validate_bits(bits_per_sample)
            || !A2dpCodecChannelMode::validate_bits(channel_mode)
        {
            return false;
        }
        self.a2dp.as_mut().unwrap().set_audio_config(sample_rate, bits_per_sample, channel_mode);
        true
    }

    fn start_audio_request(&mut self) {
        self.a2dp.as_mut().unwrap().start_audio_request();
    }

    fn stop_audio_request(&mut self) {
        self.a2dp.as_mut().unwrap().stop_audio_request();
    }
}
