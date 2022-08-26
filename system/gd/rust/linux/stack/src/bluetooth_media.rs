//! Anything related to audio and media API.

use bt_topshim::btif::{BluetoothInterface, RawAddress};
use bt_topshim::profiles::a2dp::{
    A2dp, A2dpCallbacks, A2dpCallbacksDispatcher, A2dpCodecBitsPerSample, A2dpCodecChannelMode,
    A2dpCodecConfig, A2dpCodecSampleRate, BtavAudioState, BtavConnectionState,
    PresentationPosition,
};
use bt_topshim::profiles::avrcp::{Avrcp, AvrcpCallbacks, AvrcpCallbacksDispatcher};
use bt_topshim::profiles::hfp::{
    BthfAudioState, BthfConnectionState, Hfp, HfpCallbacks, HfpCallbacksDispatcher,
    HfpCodecCapability,
};

use bt_topshim::topstack;

use log::{info, warn};
use num_traits::cast::ToPrimitive;
use std::collections::HashMap;
use std::convert::TryFrom;
use std::sync::Arc;
use std::sync::Mutex;

use tokio::sync::mpsc::Sender;
use tokio::task::JoinHandle;
use tokio::time::{sleep, Duration};

use crate::bluetooth::{Bluetooth, BluetoothDevice, IBluetooth};
use crate::callbacks::Callbacks;
use crate::{Message, RPCProxy};

// The timeout we have to wait for all supported profiles to connect after we
// receive the first profile connected event. In the worst scenario, we'll have
// 2 * PROFILE_DISCOVERY_TIMEOUT_SEC of waiting time.
const PROFILE_DISCOVERY_TIMEOUT_SEC: u64 = 5;

pub trait IBluetoothMedia {
    ///
    fn register_callback(&mut self, callback: Box<dyn IBluetoothMediaCallback + Send>) -> bool;

    /// initializes media (both A2dp and AVRCP) stack
    fn initialize(&mut self) -> bool;

    /// clean up media stack
    fn cleanup(&mut self) -> bool;

    fn connect(&mut self, address: String);
    fn set_active_device(&mut self, address: String);
    fn disconnect(&mut self, address: String);
    fn set_audio_config(
        &mut self,
        sample_rate: i32,
        bits_per_sample: i32,
        channel_mode: i32,
    ) -> bool;

    // Set the A2DP/AVRCP volume. Valid volume specified by the spec should be
    // in the range of 0-127.
    fn set_volume(&mut self, volume: u8);

    // Set the HFP speaker volume. Valid volume specified by the HFP spec should
    // be in the range of 0-15.
    fn set_hfp_volume(&mut self, volume: u8, address: String);
    fn start_audio_request(&mut self);
    fn stop_audio_request(&mut self);

    /// Returns non-zero value iff A2DP audio has started.
    fn get_a2dp_audio_started(&mut self, address: String) -> u8;

    /// Returns the negotiated codec (CVSD=1, mSBC=2) to use if HFP audio has started.
    /// Returns 0 if HFP audio hasn't started.
    fn get_hfp_audio_started(&mut self, address: String) -> u8;

    fn get_presentation_position(&mut self) -> PresentationPosition;

    fn start_sco_call(&mut self, address: String);
    fn stop_sco_call(&mut self, address: String);
}

pub trait IBluetoothMediaCallback: RPCProxy {
    /// Triggered when a Bluetooth audio device is ready to be used. This should
    /// only be triggered once for a device and send an event to clients. If the
    /// device supports both HFP and A2DP, both should be ready when this is
    /// triggered.
    fn on_bluetooth_audio_device_added(&self, device: BluetoothAudioDevice);

    ///
    fn on_bluetooth_audio_device_removed(&self, addr: String);

    ///
    fn on_absolute_volume_supported_changed(&self, supported: bool);

    /// Triggered when a Bluetooth device triggers an AVRCP/A2DP volume change
    /// event. We need to notify audio client to reflect the change on the audio
    /// stack. The volume should be in the range of 0 to 127.
    fn on_absolute_volume_changed(&self, volume: u8);

    /// Triggered when a Bluetooth device triggers a HFP AT command (AT+VGS) to
    /// notify AG about its speaker volume change. We need to notify audio
    /// client to reflect the change on the audio stack. The volume should be
    /// in the range of 0 to 15.
    fn on_hfp_volume_changed(&self, volume: u8, addr: String);
}

/// Serializable device used in.
#[derive(Debug, Default, Clone)]
pub struct BluetoothAudioDevice {
    pub address: String,
    pub name: String,
    pub a2dp_caps: Vec<A2dpCodecConfig>,
    pub hfp_cap: HfpCodecCapability,
    pub absolute_volume: bool,
}

impl BluetoothAudioDevice {
    pub(crate) fn new(
        address: String,
        name: String,
        a2dp_caps: Vec<A2dpCodecConfig>,
        hfp_cap: HfpCodecCapability,
        absolute_volume: bool,
    ) -> BluetoothAudioDevice {
        BluetoothAudioDevice { address, name, a2dp_caps, hfp_cap, absolute_volume }
    }
}
/// Actions that `BluetoothMedia` can take on behalf of the stack.
pub enum MediaActions {
    Connect(String),
    Disconnect(String),
}

pub struct BluetoothMedia {
    intf: Arc<Mutex<BluetoothInterface>>,
    initialized: bool,
    callbacks: Arc<Mutex<Callbacks<dyn IBluetoothMediaCallback + Send>>>,
    tx: Sender<Message>,
    adapter: Option<Arc<Mutex<Box<Bluetooth>>>>,
    a2dp: Option<A2dp>,
    avrcp: Option<Avrcp>,
    a2dp_states: HashMap<RawAddress, BtavConnectionState>,
    a2dp_audio_state: HashMap<RawAddress, BtavAudioState>,
    hfp: Option<Hfp>,
    hfp_states: HashMap<RawAddress, BthfConnectionState>,
    hfp_audio_state: HashMap<RawAddress, BthfAudioState>,
    selectable_caps: HashMap<RawAddress, Vec<A2dpCodecConfig>>,
    hfp_caps: HashMap<RawAddress, HfpCodecCapability>,
    device_added_tasks: Arc<Mutex<HashMap<RawAddress, Option<JoinHandle<()>>>>>,
    absolute_volume: bool,
}

impl BluetoothMedia {
    pub fn new(tx: Sender<Message>, intf: Arc<Mutex<BluetoothInterface>>) -> BluetoothMedia {
        BluetoothMedia {
            intf,
            initialized: false,
            callbacks: Arc::new(Mutex::new(Callbacks::new(
                tx.clone(),
                Message::MediaCallbackDisconnected,
            ))),
            tx,
            adapter: None,
            a2dp: None,
            avrcp: None,
            a2dp_states: HashMap::new(),
            a2dp_audio_state: HashMap::new(),
            hfp: None,
            hfp_states: HashMap::new(),
            hfp_audio_state: HashMap::new(),
            selectable_caps: HashMap::new(),
            hfp_caps: HashMap::new(),
            device_added_tasks: Arc::new(Mutex::new(HashMap::new())),
            absolute_volume: false,
        }
    }

    pub fn set_adapter(&mut self, adapter: Arc<Mutex<Box<Bluetooth>>>) {
        self.adapter = Some(adapter);
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
                        info!("[{}]: a2dp connected.", addr.to_string());
                        self.notify_media_capability_added(addr);
                        self.a2dp_states.insert(addr, state);
                    }
                    BtavConnectionState::Disconnected => {
                        self.a2dp_audio_state.remove(&addr);
                        match self.a2dp_states.remove(&addr) {
                            Some(_) => self.notify_media_capability_removed(addr),
                            None => {
                                warn!("[{}]: Unknown address a2dp disconnected.", addr.to_string());
                            }
                        }
                    }
                    _ => {
                        self.a2dp_states.insert(addr, state);
                    }
                }
            }
            A2dpCallbacks::AudioState(addr, state) => {
                self.a2dp_audio_state.insert(addr, state);
            }
            A2dpCallbacks::AudioConfig(addr, _config, _local_caps, selectable_caps) => {
                self.selectable_caps.insert(addr, selectable_caps);
            }
            A2dpCallbacks::MandatoryCodecPreferred(_addr) => {}
        }
    }

    pub fn dispatch_avrcp_callbacks(&mut self, cb: AvrcpCallbacks) {
        match cb {
            AvrcpCallbacks::AvrcpDeviceConnected(addr, supported) => {
                if self.absolute_volume == supported {
                    return;
                }

                self.absolute_volume = supported;
                let mut guard = self.device_added_tasks.lock().unwrap();
                if let Some(task) = guard.get(&addr) {
                    match task {
                        // There is a device added event waiting for other
                        // profiles (A2DP or HFP) to connect. We need to cancel
                        // the pending event to update the absolute volume
                        // capability.
                        // This refreshes the timeout waiting for potential
                        // profile connection and makes the worst case total
                        // waiting time to 2 * PROFILE_DISCOVERY_TIMEOUT_SEC.
                        Some(handler) => {
                            handler.abort();
                            guard.remove(&addr);
                            drop(guard);
                            self.notify_media_capability_added(addr);
                        }
                        // This addr has been added so trigger the absolute
                        // volume supported changed callback.
                        None => self.callbacks.lock().unwrap().for_all_callbacks(|callback| {
                            callback.on_absolute_volume_supported_changed(supported);
                        }),
                    }
                } else {
                    info!("[{}]: Device's avrcp connected before a2dp and hfp", addr.to_string());
                }
            }
            AvrcpCallbacks::AvrcpDeviceDisconnected(_addr) => {}
            AvrcpCallbacks::AvrcpAbsoluteVolumeUpdate(volume) => {
                self.callbacks.lock().unwrap().for_all_callbacks(|callback| {
                    callback.on_absolute_volume_changed(volume);
                });
            }
            AvrcpCallbacks::AvrcpSendKeyEvent(_key, _value) => {}
        }
    }

    pub fn dispatch_media_actions(&mut self, action: MediaActions) {
        match action {
            MediaActions::Connect(address) => self.connect(address),
            MediaActions::Disconnect(address) => self.disconnect(address),
        }
    }

    pub fn dispatch_hfp_callbacks(&mut self, cb: HfpCallbacks) {
        match cb {
            HfpCallbacks::ConnectionState(state, addr) => {
                if !self.hfp_states.get(&addr).is_none()
                    && state == *self.hfp_states.get(&addr).unwrap()
                {
                    return;
                }
                match state {
                    BthfConnectionState::Connected => {
                        info!("[{}]: hfp connected.", addr.to_string());
                    }
                    BthfConnectionState::SlcConnected => {
                        info!("[{}]: hfp slc connected.", addr.to_string());
                        // The device may not support codec-negotiation,
                        // in which case we shall assume it supports CVSD at this point.
                        if !self.hfp_caps.contains_key(&addr) {
                            self.hfp_caps.insert(addr, HfpCodecCapability::CVSD);
                        }
                        self.notify_media_capability_added(addr);
                    }
                    BthfConnectionState::Disconnected => {
                        info!("[{}]: hfp disconnected.", addr.to_string());
                        self.hfp_caps.remove(&addr);
                        self.hfp_audio_state.remove(&addr);
                        match self.hfp_states.remove(&addr) {
                            Some(_) => self.notify_media_capability_removed(addr),
                            None => {
                                warn!("[{}] Unknown address hfp disconnected.", addr.to_string())
                            }
                        }
                        return;
                    }
                    BthfConnectionState::Connecting => {
                        info!("[{}]: hfp connecting.", addr.to_string());
                    }
                    BthfConnectionState::Disconnecting => {
                        info!("[{}]: hfp disconnecting.", addr.to_string());
                    }
                }

                self.hfp_states.insert(addr, state);
            }
            HfpCallbacks::AudioState(state, addr) => {
                if self.hfp_states.get(&addr).is_none()
                    || BthfConnectionState::SlcConnected != *self.hfp_states.get(&addr).unwrap()
                {
                    warn!("[{}]: Unknown address hfp or slc not ready", addr.to_string());
                    return;
                }

                match state {
                    BthfAudioState::Connected => {
                        info!("[{}]: hfp audio connected.", addr.to_string());
                    }
                    BthfAudioState::Disconnected => {
                        info!("[{}]: hfp audio disconnected.", addr.to_string());
                    }
                    BthfAudioState::Connecting => {
                        info!("[{}]: hfp audio connecting.", addr.to_string());
                    }
                    BthfAudioState::Disconnecting => {
                        info!("[{}]: hfp audio disconnecting.", addr.to_string());
                    }
                }

                self.hfp_audio_state.insert(addr, state);
            }
            HfpCallbacks::VolumeUpdate(volume, addr) => {
                self.callbacks.lock().unwrap().for_all_callbacks(|callback| {
                    callback.on_hfp_volume_changed(volume, addr.to_string());
                });
            }
            HfpCallbacks::CapsUpdate(wbs_supported, addr) => {
                let hfp_caps = match wbs_supported {
                    true => HfpCodecCapability::CVSD | HfpCodecCapability::MSBC,
                    false => HfpCodecCapability::CVSD,
                };

                self.hfp_caps.insert(addr, hfp_caps);
            }
        }
    }

    pub fn remove_callback(&mut self, id: u32) -> bool {
        self.callbacks.lock().unwrap().remove_callback(id)
    }

    fn notify_media_capability_added(&self, addr: RawAddress) {
        // Return true if the device added message is sent by the call.
        fn dedup_added_cb(
            device_added_tasks: Arc<Mutex<HashMap<RawAddress, Option<JoinHandle<()>>>>>,
            addr: RawAddress,
            callbacks: Arc<Mutex<Callbacks<dyn IBluetoothMediaCallback + Send>>>,
            device: BluetoothAudioDevice,
            is_delayed: bool,
        ) -> bool {
            // Closure used to lock and trigger the device added callbacks.
            let trigger_device_added = || {
                callbacks.lock().unwrap().for_all_callbacks(|callback| {
                    callback.on_bluetooth_audio_device_added(device.clone());
                });
            };
            let mut guard = device_added_tasks.lock().unwrap();
            let task = guard.insert(addr, None);
            match task {
                // None handler means the device has just been added
                Some(handler) if handler.is_none() => {
                    warn!("[{}]: A device with the same address has been added.", addr.to_string());
                    false
                }
                // Not None handler means there is a pending task.
                Some(handler) => {
                    trigger_device_added();

                    // Abort the delayed callback if the caller is not delayed.
                    // Otherwise, it is the delayed callback task itself.
                    // The abort call can be out of the critical section as we
                    // have updated the device_added_tasks and send the message.
                    drop(guard);
                    if !is_delayed {
                        handler.unwrap().abort();
                    }
                    true
                }
                // The delayed callback task has been removed and couldn't be found.
                None if is_delayed => false,
                // No delayed callback and the device hasn't been added.
                None => {
                    trigger_device_added();
                    true
                }
            }
        }

        let cur_a2dp_caps = self.selectable_caps.get(&addr);
        let cur_hfp_cap = self.hfp_caps.get(&addr);
        let name = self.adapter_get_remote_name(addr);
        let absolute_volume = self.absolute_volume;
        match (cur_a2dp_caps, cur_hfp_cap) {
            (None, None) => warn!(
                "[{}]: Try to add a device without a2dp and hfp capability.",
                addr.to_string()
            ),
            (Some(caps), Some(hfp_cap)) => {
                dedup_added_cb(
                    self.device_added_tasks.clone(),
                    addr,
                    self.callbacks.clone(),
                    BluetoothAudioDevice::new(
                        addr.to_string(),
                        name.clone(),
                        caps.to_vec(),
                        *hfp_cap,
                        absolute_volume,
                    ),
                    false,
                );
            }
            (_, _) => {
                let mut guard = self.device_added_tasks.lock().unwrap();
                if guard.get(&addr).is_none() {
                    let callbacks = self.callbacks.clone();
                    let device_added_tasks = self.device_added_tasks.clone();
                    let device = BluetoothAudioDevice::new(
                        addr.to_string(),
                        name.clone(),
                        cur_a2dp_caps.unwrap_or(&Vec::new()).to_vec(),
                        *cur_hfp_cap.unwrap_or(&HfpCodecCapability::UNSUPPORTED),
                        absolute_volume,
                    );
                    let task = topstack::get_runtime().spawn(async move {
                        sleep(Duration::from_secs(PROFILE_DISCOVERY_TIMEOUT_SEC)).await;
                        if dedup_added_cb(device_added_tasks, addr, callbacks, device, true) {
                            warn!(
                                "[{}]: Add a device with only hfp or a2dp capability after timeout.",
                                addr.to_string()
                            );
                        }
                    });
                    guard.insert(addr, Some(task));
                }
            }
        }
    }

    fn notify_media_capability_removed(&self, addr: RawAddress) {
        if let Some(task) = self.device_added_tasks.lock().unwrap().remove(&addr) {
            match task {
                // Abort what is pending
                Some(handler) => handler.abort(),
                // This addr has been added so tell audio server to remove it
                None => self.callbacks.lock().unwrap().for_all_callbacks(|callback| {
                    callback.on_bluetooth_audio_device_removed(addr.to_string());
                }),
            }
        } else {
            warn!("[{}]: Device hasn't been added yet.", addr.to_string());
        }
    }

    fn adapter_get_remote_name(&self, addr: RawAddress) -> String {
        let device = BluetoothDevice::new(
            addr.to_string(),
            // get_remote_name needs a BluetoothDevice just for its address, the
            // name field is unused so construct one with a fake name.
            "Classic Device".to_string(),
        );
        if let Some(adapter) = &self.adapter {
            match adapter.lock().unwrap().get_remote_name(device).as_str() {
                "" => addr.to_string(),
                name => name.into(),
            }
        } else {
            addr.to_string()
        }
    }

    pub fn get_hfp_connection_state(&self) -> u32 {
        for state in self.hfp_states.values() {
            return BthfConnectionState::to_u32(state).unwrap_or(0);
        }
        0
    }

    pub fn get_a2dp_connection_state(&self) -> u32 {
        for state in self.a2dp_states.values() {
            return BtavConnectionState::to_u32(state).unwrap_or(0);
        }
        0
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

fn get_avrcp_dispatcher(tx: Sender<Message>) -> AvrcpCallbacksDispatcher {
    AvrcpCallbacksDispatcher {
        dispatch: Box::new(move |cb| {
            let txl = tx.clone();
            topstack::get_runtime().spawn(async move {
                let _ = txl.send(Message::Avrcp(cb)).await;
            });
        }),
    }
}

fn get_hfp_dispatcher(tx: Sender<Message>) -> HfpCallbacksDispatcher {
    HfpCallbacksDispatcher {
        dispatch: Box::new(move |cb| {
            let txl = tx.clone();
            topstack::get_runtime().spawn(async move {
                let _ = txl.send(Message::Hfp(cb)).await;
            });
        }),
    }
}

impl IBluetoothMedia for BluetoothMedia {
    fn register_callback(&mut self, callback: Box<dyn IBluetoothMediaCallback + Send>) -> bool {
        let _id = self.callbacks.lock().unwrap().add_callback(callback);
        true
    }

    fn initialize(&mut self) -> bool {
        if self.initialized {
            return false;
        }
        self.initialized = true;

        // TEST A2dp
        let a2dp_dispatcher = get_a2dp_dispatcher(self.tx.clone());
        self.a2dp = Some(A2dp::new(&self.intf.lock().unwrap()));
        self.a2dp.as_mut().unwrap().initialize(a2dp_dispatcher);

        // AVRCP
        let avrcp_dispatcher = get_avrcp_dispatcher(self.tx.clone());
        self.avrcp = Some(Avrcp::new(&self.intf.lock().unwrap()));
        self.avrcp.as_mut().unwrap().initialize(avrcp_dispatcher);

        // HFP
        let hfp_dispatcher = get_hfp_dispatcher(self.tx.clone());
        self.hfp = Some(Hfp::new(&self.intf.lock().unwrap()));
        self.hfp.as_mut().unwrap().initialize(hfp_dispatcher);

        true
    }

    fn connect(&mut self, address: String) {
        if let Some(addr) = RawAddress::from_string(address.clone()) {
            self.a2dp.as_mut().unwrap().connect(addr);
            self.hfp.as_mut().unwrap().connect(addr);
        } else {
            warn!("Invalid device string {}", address);
        }
    }

    fn cleanup(&mut self) -> bool {
        true
    }

    fn set_active_device(&mut self, address: String) {
        if let Some(addr) = RawAddress::from_string(address.clone()) {
            self.a2dp.as_mut().unwrap().set_active_device(addr);
        } else {
            warn!("Invalid device string {}", address);
        }
    }

    fn disconnect(&mut self, address: String) {
        if let Some(addr) = RawAddress::from_string(address.clone()) {
            self.a2dp.as_mut().unwrap().disconnect(addr);
            self.hfp.as_mut().unwrap().disconnect(addr);
        } else {
            warn!("Invalid device string {}", address);
        }
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

    fn set_volume(&mut self, volume: u8) {
        // Guard the range 0-127 by the try_from cast from u8 to i8.
        match i8::try_from(volume) {
            Ok(val) => self.avrcp.as_mut().unwrap().set_volume(val),
            _ => warn!("Ignore invalid volume {}", volume),
        }
    }

    fn set_hfp_volume(&mut self, volume: u8, address: String) {
        if let Some(addr) = RawAddress::from_string(address.clone()) {
            if !self.hfp_states.get(&addr).is_none() {
                match i8::try_from(volume) {
                    Ok(val) if val <= 15 => {
                        self.hfp.as_mut().unwrap().set_volume(val, addr);
                    }
                    _ => warn!("[{}]: Ignore invalid volume {}", address, volume),
                }
            } else {
                warn!(
                    "[{}]: Ignore volume event for unconnected or disconnected HFP device",
                    address
                );
            }
        } else {
            warn!("[{}]: Invalid address", address);
        }
    }

    fn start_audio_request(&mut self) {
        self.a2dp.as_mut().unwrap().start_audio_request();
    }

    fn stop_audio_request(&mut self) {
        self.a2dp.as_mut().unwrap().stop_audio_request();
    }

    fn start_sco_call(&mut self, address: String) {
        if let Some(addr) = RawAddress::from_string(address.clone()) {
            info!("Start sco call for {}", address);
            match self.hfp.as_mut().unwrap().connect_audio(addr) {
                0 => {
                    info!("SCO connect_audio status success.");
                }
                x => {
                    warn!("SCO connect_audio status failed: {}", x);
                }
            };
        } else {
            warn!("Can't start sco call with: {}", address);
        }
    }

    fn stop_sco_call(&mut self, address: String) {
        if let Some(addr) = RawAddress::from_string(address.clone()) {
            info!("Stop sco call for {}", address);
            self.hfp.as_mut().unwrap().disconnect_audio(addr);
        } else {
            warn!("Can't stop sco call with: {}", address);
        }
    }

    fn get_a2dp_audio_started(&mut self, address: String) -> u8 {
        if let Some(addr) = RawAddress::from_string(address.clone()) {
            match self.a2dp_audio_state.get(&addr) {
                Some(BtavAudioState::Started) => 1,
                _ => 0,
            }
        } else {
            warn!("Invalid device string {}", address);
            0
        }
    }

    fn get_hfp_audio_started(&mut self, address: String) -> u8 {
        if let Some(addr) = RawAddress::from_string(address.clone()) {
            match self.hfp_audio_state.get(&addr) {
                Some(BthfAudioState::Connected) => match self.hfp_caps.get(&addr) {
                    Some(caps)
                        if (*caps & HfpCodecCapability::MSBC) == HfpCodecCapability::MSBC =>
                    {
                        2
                    }
                    Some(caps)
                        if (*caps & HfpCodecCapability::CVSD) == HfpCodecCapability::CVSD =>
                    {
                        1
                    }
                    _ => {
                        warn!("hfp_caps not found, fallback to CVSD.");
                        1
                    }
                },
                _ => 0,
            }
        } else {
            warn!("Invalid device string {}", address);
            0
        }
    }

    fn get_presentation_position(&mut self) -> PresentationPosition {
        let position = self.a2dp.as_mut().unwrap().get_presentation_position();
        PresentationPosition {
            remote_delay_report_ns: position.remote_delay_report_ns,
            total_bytes_read: position.total_bytes_read,
            data_position_sec: position.data_position_sec,
            data_position_nsec: position.data_position_nsec,
        }
    }
}
