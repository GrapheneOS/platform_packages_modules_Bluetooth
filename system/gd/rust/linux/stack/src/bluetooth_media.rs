//! Anything related to audio and media API.

use bt_topshim::btif::{
    BluetoothInterface, BtConnectionDirection, BtStatus, RawAddress, ToggleableProfile,
};
use bt_topshim::profiles::a2dp::{
    A2dp, A2dpCallbacks, A2dpCallbacksDispatcher, A2dpCodecBitsPerSample, A2dpCodecChannelMode,
    A2dpCodecConfig, A2dpCodecSampleRate, BtavAudioState, BtavConnectionState,
    PresentationPosition,
};
use bt_topshim::profiles::avrcp::{
    Avrcp, AvrcpCallbacks, AvrcpCallbacksDispatcher, PlayerMetadata,
};
use bt_topshim::profiles::hfp::{
    BthfAudioState, BthfConnectionState, Hfp, HfpCallbacks, HfpCallbacksDispatcher,
    HfpCodecCapability,
};
use bt_topshim::profiles::ProfileConnectionState;
use bt_topshim::{metrics, topstack};
use bt_utils::uinput::UInput;

use log::{debug, info, warn};
use std::collections::{HashMap, HashSet};
use std::convert::TryFrom;
use std::sync::Arc;
use std::sync::Mutex;

use tokio::sync::mpsc::Sender;
use tokio::task::JoinHandle;
use tokio::time::{sleep, Duration, Instant};

use crate::battery_manager::{Battery, BatterySet};
use crate::battery_provider_manager::{
    BatteryProviderManager, IBatteryProviderCallback, IBatteryProviderManager,
};
use crate::bluetooth::{Bluetooth, BluetoothDevice, IBluetooth};
use crate::callbacks::Callbacks;
use crate::uuid;
use crate::uuid::Profile;
use crate::{Message, RPCProxy};

// The timeout we have to wait for all supported profiles to connect after we
// receive the first profile connected event.
const PROFILE_DISCOVERY_TIMEOUT_SEC: u64 = 5;
// The timeout we have to wait for the initiator peer device to complete the
// initial profile connection. After this many seconds, we will begin to
// connect the missing profiles.
const ACCEPTOR_CONNECT_MISSING_PROFILES_TIMEOUT_SEC: u64 = 2;

pub trait IBluetoothMedia {
    ///
    fn register_callback(&mut self, callback: Box<dyn IBluetoothMediaCallback + Send>) -> bool;

    /// initializes media (both A2dp and AVRCP) stack
    fn initialize(&mut self) -> bool;

    /// clean up media stack
    fn cleanup(&mut self) -> bool;

    /// connect to available but missing media profiles
    fn connect(&mut self, address: String);
    fn disconnect(&mut self, address: String);

    // Set the device as the active A2DP device
    fn set_active_device(&mut self, address: String);

    // Set the device as the active HFP device
    fn set_hfp_active_device(&mut self, address: String);

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
    fn start_audio_request(&mut self) -> bool;
    fn stop_audio_request(&mut self);

    /// Returns true iff A2DP audio has started.
    fn get_a2dp_audio_started(&mut self, address: String) -> bool;

    /// Returns the negotiated codec (CVSD=1, mSBC=2) to use if HFP audio has started.
    /// Returns 0 if HFP audio hasn't started.
    fn get_hfp_audio_final_codecs(&mut self, address: String) -> u8;

    fn get_presentation_position(&mut self) -> PresentationPosition;

    /// Start the SCO setup to connect audio
    fn start_sco_call(&mut self, address: String, sco_offload: bool, force_cvsd: bool) -> bool;
    fn stop_sco_call(&mut self, address: String);

    /// Set the current playback status: e.g., playing, paused, stopped, etc. The method is a copy
    /// of the existing CRAS API, hence not following Floss API conventions.
    fn set_player_playback_status(&mut self, status: String);
    /// Set the position of the current media in microseconds. The method is a copy of the existing
    /// CRAS API, hence not following Floss API conventions.
    fn set_player_position(&mut self, position: i64);
    /// Set the media metadata, including title, artist, album, and length. The method is a
    /// copy of the existing CRAS API, hence not following Floss API conventions. PlayerMetadata is
    /// a custom data type that requires special handlng.
    fn set_player_metadata(&mut self, metadata: PlayerMetadata);
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

    /// Triggered when HFP audio is disconnected, in which case it could be
    /// waiting for the audio client to issue a reconnection request. We need
    /// to notify audio client of this event for it to do appropriate handling.
    fn on_hfp_audio_disconnected(&self, addr: String);
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
    battery_provider_manager: Arc<Mutex<Box<BatteryProviderManager>>>,
    battery_provider_id: u32,
    initialized: bool,
    callbacks: Arc<Mutex<Callbacks<dyn IBluetoothMediaCallback + Send>>>,
    tx: Sender<Message>,
    adapter: Option<Arc<Mutex<Box<Bluetooth>>>>,
    a2dp: Option<A2dp>,
    avrcp: Option<Avrcp>,
    avrcp_direction: BtConnectionDirection,
    a2dp_states: HashMap<RawAddress, BtavConnectionState>,
    a2dp_audio_state: HashMap<RawAddress, BtavAudioState>,
    hfp: Option<Hfp>,
    hfp_states: HashMap<RawAddress, BthfConnectionState>,
    hfp_audio_state: HashMap<RawAddress, BthfAudioState>,
    a2dp_caps: HashMap<RawAddress, Vec<A2dpCodecConfig>>,
    hfp_cap: HashMap<RawAddress, HfpCodecCapability>,
    device_added_tasks: Arc<Mutex<HashMap<RawAddress, Option<(JoinHandle<()>, Instant)>>>>,
    absolute_volume: bool,
    uinput: UInput,
    delay_enable_profiles: HashSet<uuid::Profile>,
    connected_profiles: HashMap<RawAddress, HashSet<uuid::Profile>>,
    disconnecting_devices: HashSet<RawAddress>,
}

impl BluetoothMedia {
    pub fn new(
        tx: Sender<Message>,
        intf: Arc<Mutex<BluetoothInterface>>,
        battery_provider_manager: Arc<Mutex<Box<BatteryProviderManager>>>,
    ) -> BluetoothMedia {
        let battery_provider_id = battery_provider_manager
            .lock()
            .unwrap()
            .register_battery_provider(Box::new(BatteryProviderCallback::new()));
        BluetoothMedia {
            intf,
            battery_provider_manager,
            battery_provider_id,
            initialized: false,
            callbacks: Arc::new(Mutex::new(Callbacks::new(
                tx.clone(),
                Message::MediaCallbackDisconnected,
            ))),
            tx,
            adapter: None,
            a2dp: None,
            avrcp: None,
            avrcp_direction: BtConnectionDirection::Unknown,
            a2dp_states: HashMap::new(),
            a2dp_audio_state: HashMap::new(),
            hfp: None,
            hfp_states: HashMap::new(),
            hfp_audio_state: HashMap::new(),
            a2dp_caps: HashMap::new(),
            hfp_cap: HashMap::new(),
            device_added_tasks: Arc::new(Mutex::new(HashMap::new())),
            absolute_volume: false,
            uinput: UInput::new(),
            delay_enable_profiles: HashSet::new(),
            connected_profiles: HashMap::new(),
            disconnecting_devices: HashSet::new(),
        }
    }

    fn is_profile_connected(&self, addr: RawAddress, profile: uuid::Profile) -> bool {
        if let Some(connected_profiles) = self.connected_profiles.get(&addr) {
            return connected_profiles.contains(&profile);
        }
        return false;
    }

    fn add_connected_profile(&mut self, addr: RawAddress, profile: uuid::Profile) {
        if self.is_profile_connected(addr, profile) {
            warn!("[{}]: profile is already connected", addr.to_string());
            return;
        }

        self.connected_profiles.entry(addr).or_insert_with(HashSet::new).insert(profile);

        self.notify_media_capability_updated(addr);
    }

    fn rm_connected_profile(
        &mut self,
        addr: RawAddress,
        profile: uuid::Profile,
        is_profile_critical: bool,
    ) {
        if !self.is_profile_connected(addr, profile) {
            warn!("[{}]: profile is already disconnected", addr.to_string());
            return;
        }

        self.connected_profiles.entry(addr).or_insert_with(HashSet::new).remove(&profile);

        if is_profile_critical {
            self.notify_critical_profile_disconnected(addr);
        }

        self.notify_media_capability_updated(addr);
    }

    pub fn set_adapter(&mut self, adapter: Arc<Mutex<Box<Bluetooth>>>) {
        self.adapter = Some(adapter);
    }

    pub fn enable_profile(&mut self, profile: &Profile) {
        match profile {
            &Profile::A2dpSource => {
                if let Some(a2dp) = &mut self.a2dp {
                    a2dp.enable();
                }
            }
            &Profile::AvrcpTarget => {
                if let Some(avrcp) = &mut self.avrcp {
                    avrcp.enable();
                }
            }
            &Profile::Hfp => {
                if let Some(hfp) = &mut self.hfp {
                    hfp.enable();
                }
            }
            _ => {
                warn!("Tried to enable {} in bluetooth_media", profile);
                return;
            }
        }

        if self.is_profile_enabled(profile).unwrap() {
            self.delay_enable_profiles.remove(profile);
        } else {
            self.delay_enable_profiles.insert(profile.clone());
        }
    }

    pub fn disable_profile(&mut self, profile: &Profile) {
        match profile {
            &Profile::A2dpSource => {
                if let Some(a2dp) = &mut self.a2dp {
                    a2dp.disable();
                }
            }
            &Profile::AvrcpTarget => {
                if let Some(avrcp) = &mut self.avrcp {
                    avrcp.disable();
                }
            }
            &Profile::Hfp => {
                if let Some(hfp) = &mut self.hfp {
                    hfp.disable();
                }
            }
            _ => {
                warn!("Tried to disable {} in bluetooth_media", profile);
                return;
            }
        }

        self.delay_enable_profiles.remove(profile);
    }

    pub fn is_profile_enabled(&self, profile: &Profile) -> Option<bool> {
        match profile {
            &Profile::A2dpSource => {
                Some(self.a2dp.as_ref().map_or(false, |a2dp| a2dp.is_enabled()))
            }
            &Profile::AvrcpTarget => {
                Some(self.avrcp.as_ref().map_or(false, |avrcp| avrcp.is_enabled()))
            }
            &Profile::Hfp => Some(self.hfp.as_ref().map_or(false, |hfp| hfp.is_enabled())),
            _ => {
                warn!("Tried to query enablement status of {} in bluetooth_media", profile);
                None
            }
        }
    }

    pub fn dispatch_a2dp_callbacks(&mut self, cb: A2dpCallbacks) {
        match cb {
            A2dpCallbacks::ConnectionState(addr, state, error) => {
                if !self.a2dp_states.get(&addr).is_none()
                    && state == *self.a2dp_states.get(&addr).unwrap()
                {
                    return;
                }
                metrics::profile_connection_state_changed(
                    addr,
                    Profile::A2dpSink as u32,
                    error.status,
                    state.clone() as u32,
                );
                match state {
                    BtavConnectionState::Connected => {
                        info!("[{}]: a2dp connected.", addr.to_string());
                        self.a2dp_states.insert(addr, state);
                        self.add_connected_profile(addr, uuid::Profile::A2dpSink);
                    }
                    BtavConnectionState::Disconnected => {
                        info!("[{}]: a2dp disconnected.", addr.to_string());
                        self.a2dp_states.remove(&addr);
                        self.a2dp_caps.remove(&addr);
                        self.a2dp_audio_state.remove(&addr);
                        self.rm_connected_profile(addr, uuid::Profile::A2dpSink, true);
                    }
                    _ => {
                        self.a2dp_states.insert(addr, state);
                    }
                }
            }
            A2dpCallbacks::AudioState(addr, state) => {
                self.a2dp_audio_state.insert(addr, state);
            }
            A2dpCallbacks::AudioConfig(addr, _config, _local_caps, a2dp_caps) => {
                // TODO(b/254808917): revert to debug log once fixed
                info!("[{}]: a2dp updated audio config: {:?}", addr.to_string(), a2dp_caps);
                self.a2dp_caps.insert(addr, a2dp_caps);
            }
            A2dpCallbacks::MandatoryCodecPreferred(_addr) => {}
        }
    }

    pub fn dispatch_avrcp_callbacks(&mut self, cb: AvrcpCallbacks) {
        match cb {
            AvrcpCallbacks::AvrcpDeviceConnected(addr, supported) => {
                info!(
                    "[{}]: avrcp connected. Absolute volume support: {}.",
                    addr.to_string(),
                    supported
                );

                match self.uinput.create(self.adapter_get_remote_name(addr), addr.to_string()) {
                    Ok(()) => info!("uinput device created for: {}", addr.to_string()),
                    Err(e) => warn!("{}", e),
                }

                // Notify change via callback if device is added.
                if self.absolute_volume != supported {
                    let guard = self.device_added_tasks.lock().unwrap();
                    if let Some(task) = guard.get(&addr) {
                        if task.is_none() {
                            self.callbacks.lock().unwrap().for_all_callbacks(|callback| {
                                callback.on_absolute_volume_supported_changed(supported);
                            });
                        }
                    }
                }

                self.absolute_volume = supported;

                // If is device initiated the AVRCP connection, emit a fake connecting state as
                // stack don't receive one.
                if self.avrcp_direction != BtConnectionDirection::Outgoing {
                    metrics::profile_connection_state_changed(
                        addr,
                        Profile::AvrcpController as u32,
                        BtStatus::Success,
                        BtavConnectionState::Connecting as u32,
                    );
                }
                metrics::profile_connection_state_changed(
                    addr,
                    Profile::AvrcpController as u32,
                    BtStatus::Success,
                    BtavConnectionState::Connected as u32,
                );
                // Reset direction to unknown.
                self.avrcp_direction = BtConnectionDirection::Unknown;

                self.add_connected_profile(addr, uuid::Profile::AvrcpController);
            }
            AvrcpCallbacks::AvrcpDeviceDisconnected(addr) => {
                info!("[{}]: avrcp disconnected.", addr.to_string());

                self.uinput.close(addr.to_string());

                // TODO: better support for multi-device
                self.absolute_volume = false;

                // This may be considered a critical profile in the extreme case
                // where only AVRCP was connected.
                let is_profile_critical = match self.connected_profiles.get(&addr) {
                    Some(profiles) => *profiles == HashSet::from([uuid::Profile::AvrcpController]),
                    None => false,
                };

                // If the peer device initiated the AVRCP disconnection, emit a fake connecting
                // state as stack don't receive one.
                if self.avrcp_direction != BtConnectionDirection::Outgoing {
                    metrics::profile_connection_state_changed(
                        addr,
                        Profile::AvrcpController as u32,
                        BtStatus::Success,
                        BtavConnectionState::Disconnecting as u32,
                    );
                }
                metrics::profile_connection_state_changed(
                    addr,
                    Profile::AvrcpController as u32,
                    BtStatus::Success,
                    BtavConnectionState::Disconnected as u32,
                );
                // Reset direction to unknown.
                self.avrcp_direction = BtConnectionDirection::Unknown;

                self.rm_connected_profile(
                    addr,
                    uuid::Profile::AvrcpController,
                    is_profile_critical,
                );
            }
            AvrcpCallbacks::AvrcpAbsoluteVolumeUpdate(volume) => {
                self.callbacks.lock().unwrap().for_all_callbacks(|callback| {
                    callback.on_absolute_volume_changed(volume);
                });
            }
            AvrcpCallbacks::AvrcpSendKeyEvent(key, value) => {
                match self.uinput.send_key(key, value) {
                    Ok(()) => (),
                    Err(e) => warn!("{}", e),
                }
            }
            AvrcpCallbacks::AvrcpSetActiveDevice(addr) => {
                self.uinput.set_active_device(addr.to_string());
            }
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
                metrics::profile_connection_state_changed(
                    addr,
                    Profile::Hfp as u32,
                    BtStatus::Success,
                    state.clone() as u32,
                );
                match state {
                    BthfConnectionState::Connected => {
                        info!("[{}]: hfp connected.", addr.to_string());
                    }
                    BthfConnectionState::SlcConnected => {
                        info!("[{}]: hfp slc connected.", addr.to_string());
                        // The device may not support codec-negotiation,
                        // in which case we shall assume it supports CVSD at this point.
                        if !self.hfp_cap.contains_key(&addr) {
                            self.hfp_cap.insert(addr, HfpCodecCapability::CVSD);
                        }
                        self.add_connected_profile(addr, uuid::Profile::Hfp);
                    }
                    BthfConnectionState::Disconnected => {
                        info!("[{}]: hfp disconnected.", addr.to_string());
                        self.hfp_states.remove(&addr);
                        self.hfp_cap.remove(&addr);
                        self.hfp_audio_state.remove(&addr);
                        self.rm_connected_profile(addr, uuid::Profile::Hfp, true);
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

                        self.hfp_audio_state.insert(addr, state);
                    }
                    BthfAudioState::Disconnected => {
                        info!("[{}]: hfp audio disconnected.", addr.to_string());

                        // Ignore disconnected -> disconnected
                        if let Some(BthfAudioState::Connected) =
                            self.hfp_audio_state.insert(addr, state)
                        {
                            self.callbacks.lock().unwrap().for_all_callbacks(|callback| {
                                callback.on_hfp_audio_disconnected(addr.to_string());
                            });
                        }
                    }
                    BthfAudioState::Connecting => {
                        info!("[{}]: hfp audio connecting.", addr.to_string());
                    }
                    BthfAudioState::Disconnecting => {
                        info!("[{}]: hfp audio disconnecting.", addr.to_string());
                    }
                }
            }
            HfpCallbacks::VolumeUpdate(volume, addr) => {
                self.callbacks.lock().unwrap().for_all_callbacks(|callback| {
                    callback.on_hfp_volume_changed(volume, addr.to_string());
                });
            }
            HfpCallbacks::BatteryLevelUpdate(battery_level, addr) => {
                let battery_set = BatterySet::new(
                    addr.to_string(),
                    uuid::HFP.to_string(),
                    "HFP".to_string(),
                    vec![Battery { percentage: battery_level as u32, variant: "".to_string() }],
                );
                self.battery_provider_manager
                    .lock()
                    .unwrap()
                    .set_battery_info(self.battery_provider_id, battery_set);
            }
            HfpCallbacks::CapsUpdate(wbs_supported, addr) => {
                let hfp_cap = match wbs_supported {
                    true => HfpCodecCapability::CVSD | HfpCodecCapability::MSBC,
                    false => HfpCodecCapability::CVSD,
                };

                self.hfp_cap.insert(addr, hfp_cap);
            }
        }
    }

    pub fn remove_callback(&mut self, id: u32) -> bool {
        self.callbacks.lock().unwrap().remove_callback(id)
    }

    fn notify_critical_profile_disconnected(&mut self, addr: RawAddress) {
        if self.disconnecting_devices.insert(addr) {
            let mut guard = self.device_added_tasks.lock().unwrap();
            if let Some(task) = guard.get(&addr) {
                match task {
                    // Abort pending task if it hasn't been notified.
                    Some((handler, _ts)) => {
                        warn!(
                            "[{}]: Device disconnected a critical profile before it was added.",
                            addr.to_string()
                        );
                        handler.abort();
                        guard.insert(addr, None);
                    }
                    // Notify device removal if it has been added.
                    None => {
                        info!(
                            "[{}]: Device disconnected a critical profile, removing the device.",
                            addr.to_string()
                        );
                        self.callbacks.lock().unwrap().for_all_callbacks(|callback| {
                            callback.on_bluetooth_audio_device_removed(addr.to_string());
                        });
                    }
                };
            }
        }
    }

    fn notify_media_capability_updated(&mut self, addr: RawAddress) {
        fn device_added_cb(
            device_added_tasks: Arc<Mutex<HashMap<RawAddress, Option<(JoinHandle<()>, Instant)>>>>,
            addr: RawAddress,
            callbacks: Arc<Mutex<Callbacks<dyn IBluetoothMediaCallback + Send>>>,
            device: BluetoothAudioDevice,
            missing_profiles: HashSet<uuid::Profile>,
        ) {
            // Once it gets here, either it will win the lock and run the task
            // or be aborted and potentially get replaced.
            let mut guard = device_added_tasks.lock().unwrap();
            guard.insert(addr, None);

            if !missing_profiles.is_empty() {
                warn!(
                    "Notify media capability added with missing profiles: {:?}",
                    missing_profiles
                );
            }

            callbacks.lock().unwrap().for_all_callbacks(|callback| {
                callback.on_bluetooth_audio_device_added(device.clone());
            });
        }

        let cur_a2dp_caps = self.a2dp_caps.get(&addr);
        let cur_hfp_cap = self.hfp_cap.get(&addr);
        let name = self.adapter_get_remote_name(addr);
        let absolute_volume = self.absolute_volume;
        let device = BluetoothAudioDevice::new(
            addr.to_string(),
            name.clone(),
            cur_a2dp_caps.unwrap_or(&Vec::new()).to_vec(),
            *cur_hfp_cap.unwrap_or(&HfpCodecCapability::UNSUPPORTED),
            absolute_volume,
        );

        let mut guard = self.device_added_tasks.lock().unwrap();
        let mut first_conn_ts = Instant::now();

        let is_profile_cleared = self.connected_profiles.get(&addr).unwrap().is_empty();
        if is_profile_cleared {
            self.connected_profiles.remove(&addr);
            self.disconnecting_devices.remove(&addr);
        }

        match guard.get(&addr) {
            Some(task) => match task {
                // There is a handler that hasn't fired.
                // Abort the task and later replace it if the device isn't disconnecting.
                Some((handler, ts)) => {
                    handler.abort();
                    first_conn_ts = *ts;
                    if is_profile_cleared {
                        warn!(
                            "[{}]: Device disconnected all profiles before it was added.",
                            addr.to_string()
                        );
                        guard.remove(&addr);
                        return;
                    } else {
                        guard.insert(addr, None);
                    }
                }
                // The handler was fired or aborted (due to critical profile disconnection).
                // Ignore if it's a late "insert" event.
                // Also ignore if it's a "remove" event unless all have been removed.
                None => {
                    if is_profile_cleared {
                        info!("[{}]: Device disconnected all profiles.", addr.to_string());
                        guard.remove(&addr);
                    }
                    return;
                }
            },
            // First update since the last moment with no connection.
            // Note it's possible that a device (e.g., Motorola S10) requests
            // disconnection at start (i.e., when nothing is connected).
            None => {
                if is_profile_cleared {
                    warn!(
                        "[{}]: Trying to remove capability of an unknown device.",
                        addr.to_string()
                    );
                    return;
                }
            }
        }

        // If the device has disconnected a critical profile, wait until all
        // profiles have disconnected and refrain from adding the task.
        if self.disconnecting_devices.contains(&addr) {
            return;
        }

        let available_profiles = self.adapter_get_audio_profiles(addr);
        let connected_profiles = self.connected_profiles.get(&addr).unwrap();
        let missing_profiles =
            available_profiles.difference(&connected_profiles).cloned().collect::<HashSet<_>>();

        let callbacks = self.callbacks.clone();
        let device_added_tasks = self.device_added_tasks.clone();
        let txl = self.tx.clone();
        let task = topstack::get_runtime().spawn(async move {
            if !missing_profiles.is_empty() {
                // When the headset initiates profile connection, it will not share the same
                // path as that of the other way around, and may selectively connect to
                // certain profiles while missing out others.
                // Therefore here we want to connect the missing profiles. However, we must not do
                // so immediately, since by convention the initiating device should be given chance
                // to connect the profiles first. Here we yield for a couple of seconds before
                // attempting to connect the missing profiles.
                sleep(Duration::from_secs(ACCEPTOR_CONNECT_MISSING_PROFILES_TIMEOUT_SEC)).await;
                let _ = txl.send(Message::Media(MediaActions::Connect(addr.to_string()))).await;

                let now_ts = Instant::now();
                let total_wait_duration = Duration::from_secs(PROFILE_DISCOVERY_TIMEOUT_SEC);
                let remaining_wait_duration =
                    (first_conn_ts + total_wait_duration).saturating_duration_since(now_ts);
                sleep(remaining_wait_duration).await;
            }
            device_added_cb(device_added_tasks, addr, callbacks, device, missing_profiles);
        });
        guard.insert(addr, Some((task, first_conn_ts)));
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

    fn adapter_get_audio_profiles(&self, addr: RawAddress) -> HashSet<uuid::Profile> {
        let device = BluetoothDevice::new(addr.to_string(), "".to_string());
        if let Some(adapter) = &self.adapter {
            let audio_profiles =
                vec![uuid::Profile::A2dpSink, uuid::Profile::Hfp, uuid::Profile::AvrcpController];

            adapter
                .lock()
                .unwrap()
                .get_remote_uuids(device)
                .into_iter()
                .map(|u| uuid::UuidHelper::is_known_profile(&u))
                .filter(|u| u.is_some())
                .map(|u| u.unwrap())
                .filter(|u| audio_profiles.contains(&u))
                .collect()
        } else {
            HashSet::new()
        }
    }

    pub fn get_hfp_connection_state(&self) -> ProfileConnectionState {
        if self.hfp_audio_state.values().any(|state| *state == BthfAudioState::Connected) {
            ProfileConnectionState::Active
        } else {
            let mut winning_state = ProfileConnectionState::Disconnected;
            for state in self.hfp_states.values() {
                // Grab any state higher than the current state.
                match state {
                    // Any SLC completed state means the profile is connected.
                    BthfConnectionState::SlcConnected => {
                        winning_state = ProfileConnectionState::Connected;
                    }

                    // Connecting or Connected are both counted as connecting for profile state
                    // since it's not a complete connection.
                    BthfConnectionState::Connecting | BthfConnectionState::Connected
                        if winning_state != ProfileConnectionState::Connected =>
                    {
                        winning_state = ProfileConnectionState::Connecting;
                    }

                    BthfConnectionState::Disconnecting
                        if winning_state == ProfileConnectionState::Disconnected =>
                    {
                        winning_state = ProfileConnectionState::Disconnecting;
                    }

                    _ => (),
                }
            }

            winning_state
        }
    }

    pub fn get_a2dp_connection_state(&self) -> ProfileConnectionState {
        if self.a2dp_audio_state.values().any(|state| *state == BtavAudioState::Started) {
            ProfileConnectionState::Active
        } else {
            let mut winning_state = ProfileConnectionState::Disconnected;
            for state in self.a2dp_states.values() {
                // Grab any state higher than the current state.
                match state {
                    BtavConnectionState::Connected => {
                        winning_state = ProfileConnectionState::Connected;
                    }

                    BtavConnectionState::Connecting
                        if winning_state != ProfileConnectionState::Connected =>
                    {
                        winning_state = ProfileConnectionState::Connecting;
                    }

                    BtavConnectionState::Disconnecting
                        if winning_state == ProfileConnectionState::Disconnected =>
                    {
                        winning_state = ProfileConnectionState::Disconnecting;
                    }

                    _ => (),
                }
            }

            winning_state
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

        // A2DP
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

        for profile in self.delay_enable_profiles.clone() {
            self.enable_profile(&profile);
        }

        // Default to enable AVRCP since btadapterd will crash when connecting a headset while
        // avrcp is disabled.
        // TODO: fix b/251692015
        self.enable_profile(&Profile::AvrcpTarget);
        true
    }

    fn connect(&mut self, address: String) {
        let addr = match RawAddress::from_string(address.clone()) {
            None => {
                warn!("Invalid device address {}", address);
                return;
            }
            Some(addr) => addr,
        };

        let available_profiles = self.adapter_get_audio_profiles(addr);

        info!("[{}]: Connecting to device, available profiles: {:?}.", address, available_profiles);

        let connected_profiles = self.connected_profiles.entry(addr).or_insert_with(HashSet::new);

        let missing_profiles =
            available_profiles.difference(&connected_profiles).collect::<HashSet<_>>();

        for profile in missing_profiles {
            match profile {
                uuid::Profile::A2dpSink => {
                    metrics::profile_connection_state_changed(
                        addr,
                        Profile::A2dpSink as u32,
                        BtStatus::Success,
                        BtavConnectionState::Connecting as u32,
                    );
                    match self.a2dp.as_mut() {
                        Some(a2dp) => {
                            let status: BtStatus = a2dp.connect(addr);
                            if BtStatus::Success != status {
                                metrics::profile_connection_state_changed(
                                    addr,
                                    Profile::A2dpSink as u32,
                                    status,
                                    BtavConnectionState::Disconnected as u32,
                                );
                            }
                        }
                        None => {
                            warn!("Uninitialized A2DP to connect {}", address);
                            metrics::profile_connection_state_changed(
                                addr,
                                Profile::A2dpSink as u32,
                                BtStatus::NotReady,
                                BtavConnectionState::Disconnected as u32,
                            );
                        }
                    };
                }
                uuid::Profile::Hfp => {
                    metrics::profile_connection_state_changed(
                        addr,
                        Profile::Hfp as u32,
                        BtStatus::Success,
                        BtavConnectionState::Connecting as u32,
                    );
                    match self.hfp.as_mut() {
                        Some(hfp) => {
                            let status: BtStatus = hfp.connect(addr);
                            if BtStatus::Success != status {
                                metrics::profile_connection_state_changed(
                                    addr,
                                    Profile::Hfp as u32,
                                    status,
                                    BthfConnectionState::Disconnected as u32,
                                );
                            }
                        }
                        None => {
                            warn!("Uninitialized HFP to connect {}", address);
                            metrics::profile_connection_state_changed(
                                addr,
                                Profile::Hfp as u32,
                                BtStatus::NotReady,
                                BthfConnectionState::Disconnected as u32,
                            );
                        }
                    };
                }
                uuid::Profile::AvrcpController => {
                    metrics::profile_connection_state_changed(
                        addr,
                        Profile::AvrcpController as u32,
                        BtStatus::Success,
                        BtavConnectionState::Connecting as u32,
                    );
                    match self.avrcp.as_mut() {
                        Some(avrcp) => {
                            self.avrcp_direction = BtConnectionDirection::Outgoing;
                            let status: BtStatus = avrcp.connect(addr);
                            if BtStatus::Success != status {
                                // Reset direction to unknown.
                                self.avrcp_direction = BtConnectionDirection::Unknown;
                                metrics::profile_connection_state_changed(
                                    addr,
                                    Profile::AvrcpController as u32,
                                    status,
                                    BtavConnectionState::Disconnected as u32,
                                );
                            }
                        }

                        None => {
                            warn!("Uninitialized AVRCP to connect {}", address);
                            metrics::profile_connection_state_changed(
                                addr,
                                Profile::AvrcpController as u32,
                                BtStatus::NotReady,
                                BtavConnectionState::Disconnected as u32,
                            );
                        }
                    };
                }
                _ => warn!("Unknown profile: {:?}", profile),
            }
        }
    }

    fn cleanup(&mut self) -> bool {
        true
    }

    fn disconnect(&mut self, address: String) {
        let addr = match RawAddress::from_string(address.clone()) {
            None => {
                warn!("Invalid device address {}", address);
                return;
            }
            Some(addr) => addr,
        };

        let connected_profiles = match self.connected_profiles.get(&addr) {
            Some(profiles) => profiles,
            None => {
                warn!(
                    "[{}]: Ignoring disconnection request since there is no connected profile.",
                    address
                );
                return;
            }
        };

        for profile in connected_profiles {
            match profile {
                uuid::Profile::A2dpSink => {
                    metrics::profile_connection_state_changed(
                        addr,
                        Profile::A2dpSink as u32,
                        BtStatus::Success,
                        BtavConnectionState::Disconnecting as u32,
                    );
                    match self.a2dp.as_mut() {
                        Some(a2dp) => {
                            let status: BtStatus = a2dp.disconnect(addr);
                            if BtStatus::Success != status {
                                metrics::profile_connection_state_changed(
                                    addr,
                                    Profile::A2dpSource as u32,
                                    status,
                                    BtavConnectionState::Disconnected as u32,
                                );
                            }
                        }
                        None => {
                            warn!("Uninitialized A2DP to disconnect {}", address);
                            metrics::profile_connection_state_changed(
                                addr,
                                Profile::A2dpSource as u32,
                                BtStatus::NotReady,
                                BtavConnectionState::Disconnected as u32,
                            );
                        }
                    };
                }
                uuid::Profile::Hfp => {
                    metrics::profile_connection_state_changed(
                        addr,
                        Profile::Hfp as u32,
                        BtStatus::Success,
                        BthfConnectionState::Disconnecting as u32,
                    );
                    match self.hfp.as_mut() {
                        Some(hfp) => {
                            let status: BtStatus = hfp.disconnect(addr);
                            if BtStatus::Success != status {
                                metrics::profile_connection_state_changed(
                                    addr,
                                    Profile::Hfp as u32,
                                    status,
                                    BthfConnectionState::Disconnected as u32,
                                );
                            }
                        }
                        None => {
                            warn!("Uninitialized HFP to disconnect {}", address);
                            metrics::profile_connection_state_changed(
                                addr,
                                Profile::Hfp as u32,
                                BtStatus::NotReady,
                                BthfConnectionState::Disconnected as u32,
                            );
                        }
                    };
                }
                uuid::Profile::AvrcpController => {
                    metrics::profile_connection_state_changed(
                        addr,
                        Profile::AvrcpController as u32,
                        BtStatus::Success,
                        BtavConnectionState::Disconnecting as u32,
                    );
                    match self.avrcp.as_mut() {
                        Some(avrcp) => {
                            self.avrcp_direction = BtConnectionDirection::Outgoing;
                            let status: BtStatus = avrcp.disconnect(addr);
                            if BtStatus::Success != status {
                                // Reset direction to unknown.
                                self.avrcp_direction = BtConnectionDirection::Unknown;
                                metrics::profile_connection_state_changed(
                                    addr,
                                    Profile::AvrcpController as u32,
                                    status,
                                    BtavConnectionState::Disconnected as u32,
                                );
                            }
                        }

                        None => {
                            warn!("Uninitialized AVRCP to disconnect {}", address);
                            metrics::profile_connection_state_changed(
                                addr,
                                Profile::AvrcpController as u32,
                                BtStatus::NotReady,
                                BtavConnectionState::Disconnected as u32,
                            );
                        }
                    };
                }
                _ => warn!("Unknown profile: {:?}", profile),
            }
        }
    }

    fn set_active_device(&mut self, address: String) {
        let addr = match RawAddress::from_string(address.clone()) {
            None => {
                warn!("Invalid device address {}", address);
                return;
            }
            Some(addr) => addr,
        };

        match self.a2dp.as_mut() {
            Some(a2dp) => a2dp.set_active_device(addr),
            None => warn!("Uninitialized A2DP to set active device"),
        }
        self.uinput.set_active_device(addr.to_string());
    }

    fn set_hfp_active_device(&mut self, address: String) {
        let addr = match RawAddress::from_string(address.clone()) {
            None => {
                warn!("Invalid device address {}", address);
                return;
            }
            Some(addr) => addr,
        };

        match self.hfp.as_mut() {
            Some(hfp) => {
                hfp.set_active_device(addr);
            }
            None => warn!("Uninitialized HFP to set active device"),
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

        match self.a2dp.as_mut() {
            Some(a2dp) => {
                a2dp.set_audio_config(sample_rate, bits_per_sample, channel_mode);
                true
            }
            None => {
                warn!("Uninitialized A2DP to set audio config");
                false
            }
        }
    }

    fn set_volume(&mut self, volume: u8) {
        // Guard the range 0-127 by the try_from cast from u8 to i8.
        let vol = match i8::try_from(volume) {
            Ok(val) => val,
            _ => {
                warn!("Ignore invalid volume {}", volume);
                return;
            }
        };

        match self.avrcp.as_mut() {
            Some(avrcp) => avrcp.set_volume(vol),
            None => warn!("Uninitialized AVRCP to set volume"),
        };
    }

    fn set_hfp_volume(&mut self, volume: u8, address: String) {
        let addr = match RawAddress::from_string(address.clone()) {
            None => {
                warn!("Invalid device address {}", address);
                return;
            }
            Some(addr) => addr,
        };

        let vol = match i8::try_from(volume) {
            Ok(val) if val <= 15 => val,
            _ => {
                warn!("[{}]: Ignore invalid volume {}", address, volume);
                return;
            }
        };

        if self.hfp_states.get(&addr).is_none() {
            warn!("[{}]: Ignore volume event for unconnected or disconnected HFP device", address);
            return;
        }

        match self.hfp.as_mut() {
            Some(hfp) => {
                hfp.set_volume(vol, addr);
            }
            None => warn!("Uninitialized HFP to set volume"),
        };
    }

    fn start_audio_request(&mut self) -> bool {
        // TODO(b/254808917): revert to debug log once fixed
        info!("Start audio request");

        match self.a2dp.as_mut() {
            Some(a2dp) => a2dp.start_audio_request(),
            None => {
                warn!("Uninitialized A2DP to start audio request");
                false
            }
        }
    }

    fn stop_audio_request(&mut self) {
        if !self.a2dp_audio_state.values().any(|state| *state == BtavAudioState::Started) {
            info!("No active stream on A2DP device, ignoring request to stop audio.");
            return;
        }

        // TODO(b/254808917): revert to debug log once fixed
        info!("Stop audio request");

        match self.a2dp.as_mut() {
            Some(a2dp) => a2dp.stop_audio_request(),
            None => warn!("Uninitialized A2DP to stop audio request"),
        };
    }

    fn start_sco_call(&mut self, address: String, sco_offload: bool, force_cvsd: bool) -> bool {
        let addr = match RawAddress::from_string(address.clone()) {
            None => {
                warn!("Can't start sco call with: {}", address);
                return false;
            }
            Some(addr) => addr,
        };

        info!("Start sco call for {}", address);
        let hfp = match self.hfp.as_mut() {
            None => {
                warn!("Uninitialized HFP to start the sco call");
                return false;
            }
            Some(hfp) => hfp,
        };

        match hfp.connect_audio(addr, sco_offload, force_cvsd) {
            0 => {
                info!("SCO connect_audio status success.");
                true
            }
            x => {
                warn!("SCO connect_audio status failed: {}", x);
                false
            }
        }
    }

    fn stop_sco_call(&mut self, address: String) {
        let addr = match RawAddress::from_string(address.clone()) {
            None => {
                warn!("Can't stop sco call with: {}", address);
                return;
            }
            Some(addr) => addr,
        };

        info!("Stop sco call for {}", address);

        match self.hfp.as_mut() {
            Some(hfp) => {
                hfp.disconnect_audio(addr);
            }
            None => warn!("Uninitialized HFP to stop the sco call"),
        };
    }

    fn get_a2dp_audio_started(&mut self, address: String) -> bool {
        let addr = match RawAddress::from_string(address.clone()) {
            None => {
                warn!("Invalid device address {}", address);
                return false;
            }
            Some(addr) => addr,
        };

        match self.a2dp_audio_state.get(&addr) {
            Some(BtavAudioState::Started) => true,
            _ => false,
        }
    }

    fn get_hfp_audio_final_codecs(&mut self, address: String) -> u8 {
        let addr = match RawAddress::from_string(address.clone()) {
            None => {
                warn!("Invalid device address {}", address);
                return 0;
            }
            Some(addr) => addr,
        };

        match self.hfp_audio_state.get(&addr) {
            Some(BthfAudioState::Connected) => match self.hfp_cap.get(&addr) {
                Some(caps) if (*caps & HfpCodecCapability::MSBC) == HfpCodecCapability::MSBC => 2,
                Some(caps) if (*caps & HfpCodecCapability::CVSD) == HfpCodecCapability::CVSD => 1,
                _ => {
                    warn!("hfp_cap not found, fallback to CVSD.");
                    1
                }
            },
            _ => 0,
        }
    }

    fn get_presentation_position(&mut self) -> PresentationPosition {
        let position = match self.a2dp.as_mut() {
            Some(a2dp) => a2dp.get_presentation_position(),
            None => {
                warn!("Uninitialized A2DP to get presentation position");
                Default::default()
            }
        };
        PresentationPosition {
            remote_delay_report_ns: position.remote_delay_report_ns,
            total_bytes_read: position.total_bytes_read,
            data_position_sec: position.data_position_sec,
            data_position_nsec: position.data_position_nsec,
        }
    }

    fn set_player_playback_status(&mut self, status: String) {
        debug!("AVRCP received player playback status: {}", status);
        match self.avrcp.as_mut() {
            Some(avrcp) => avrcp.set_playback_status(&status),
            None => warn!("Uninitialized AVRCP to set player playback status"),
        };
    }
    fn set_player_position(&mut self, position_us: i64) {
        debug!("AVRCP received player position: {}", position_us);
        match self.avrcp.as_mut() {
            Some(avrcp) => avrcp.set_position(position_us),
            None => warn!("Uninitialized AVRCP to set player position"),
        };
    }
    fn set_player_metadata(&mut self, metadata: PlayerMetadata) {
        debug!("AVRCP received player metadata: {:?}", metadata);
        match self.avrcp.as_mut() {
            Some(avrcp) => avrcp.set_metadata(&metadata),
            None => warn!("Uninitialized AVRCP to set player playback status"),
        };
    }
}

struct BatteryProviderCallback {}

impl BatteryProviderCallback {
    fn new() -> Self {
        Self {}
    }
}

impl IBatteryProviderCallback for BatteryProviderCallback {
    // We do not support refreshing HFP battery information.
    fn refresh_battery_info(&self) {}
}

impl RPCProxy for BatteryProviderCallback {
    fn get_object_id(&self) -> String {
        "HFP BatteryProvider Callback".to_string()
    }
}
