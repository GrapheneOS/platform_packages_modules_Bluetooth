use crate::bluetooth_manager::BluetoothManager;
use crate::config_util;
use bt_common::time::Alarm;
use bt_socket::{BtSocket, HciChannels, MgmtCommand, MgmtCommandResponse, MgmtEvent, HCI_DEV_NONE};

use log::{debug, error, info, warn};
use nix::sys::signal::{self, Signal};
use nix::unistd::Pid;
use regex::Regex;
use std::collections::HashMap;
use std::convert::TryFrom;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use tokio::io::unix::AsyncFd;
use tokio::sync::mpsc;
use tokio::time::{Duration, Instant};

// Directory for Bluetooth pid file
pub const PID_DIR: &str = "/var/run/bluetooth";

#[derive(Debug, PartialEq, Copy, Clone)]
#[repr(u32)]
pub enum ProcessState {
    Off = 0,        // Bluetooth is not running or is not available.
    TurningOn = 1,  // We are not notified that the Bluetooth is running
    On = 2,         // Bluetooth is running
    TurningOff = 3, // We are not notified that the Bluetooth is stopped
}

/// Check whether adapter is enabled by checking internal state.
pub fn state_to_enabled(state: ProcessState) -> bool {
    match state {
        ProcessState::On => true,
        _ => false,
    }
}

/// Adapter state actions
#[derive(Debug)]
pub enum AdapterStateActions {
    StartBluetooth(i32),
    StopBluetooth(i32),
    BluetoothStarted(i32, i32), // PID and HCI
    BluetoothStopped(i32),
    HciDevicePresence(i32, bool),
}

/// Enum of all the messages that state machine handles.
#[derive(Debug)]
pub enum Message {
    AdapterStateChange(AdapterStateActions),
    PidChange(inotify::EventMask, Option<String>),
    CallbackDisconnected(u32),
    CommandTimeout(i32),
}

pub struct StateMachineContext {
    tx: mpsc::Sender<Message>,
    rx: mpsc::Receiver<Message>,
    state_machine: StateMachineInternal,
}

impl StateMachineContext {
    fn new(state_machine: StateMachineInternal) -> StateMachineContext {
        let (tx, rx) = mpsc::channel::<Message>(10);
        StateMachineContext { tx: tx, rx: rx, state_machine: state_machine }
    }

    pub fn get_proxy(&self) -> StateMachineProxy {
        StateMachineProxy {
            floss_enabled: self.state_machine.floss_enabled.clone(),
            state: self.state_machine.state.clone(),
            tx: self.tx.clone(),
        }
    }
}

/// Creates a new state machine.
///
/// # Arguments
/// `invoker` - What type of process manager to use.
/// `floss_enabled` - Whether floss is enabled when the state machine is started.
pub fn create_new_state_machine_context(
    invoker: Invoker,
    floss_enabled: bool,
) -> StateMachineContext {
    match invoker {
        Invoker::NativeInvoker => {
            StateMachineContext::new(StateMachineInternal::new_native(floss_enabled))
        }
        Invoker::SystemdInvoker => {
            StateMachineContext::new(StateMachineInternal::new_systemd(floss_enabled))
        }
        Invoker::UpstartInvoker => {
            StateMachineContext::new(StateMachineInternal::new_upstart(floss_enabled))
        }
    }
}

#[derive(Clone)]
/// Proxy object to give access to certain internals of the state machine.
///
/// Always construct this using |StateMachineContext::get_proxy(&self)|.
pub struct StateMachineProxy {
    floss_enabled: Arc<AtomicBool>,
    state: Arc<Mutex<HashMap<i32, AdapterState>>>,
    tx: mpsc::Sender<Message>,
}

const TX_SEND_TIMEOUT_DURATION: Duration = Duration::from_secs(3);
const COMMAND_TIMEOUT_DURATION: Duration = Duration::from_secs(3);

impl StateMachineProxy {
    pub fn start_bluetooth(&self, hci: i32) {
        let tx = self.tx.clone();
        tokio::spawn(async move {
            let _ = tx
                .send(Message::AdapterStateChange(AdapterStateActions::StartBluetooth(hci)))
                .await;
        });
    }

    pub fn stop_bluetooth(&self, hci: i32) {
        let tx = self.tx.clone();
        tokio::spawn(async move {
            let _ =
                tx.send(Message::AdapterStateChange(AdapterStateActions::StopBluetooth(hci))).await;
        });
    }

    /// Read state for an hci device.
    pub fn get_state<T, F>(&self, hci: i32, call: F) -> Option<T>
    where
        F: Fn(&AdapterState) -> Option<T>,
    {
        match self.state.lock().unwrap().get(&hci) {
            Some(a) => call(&a),
            None => None,
        }
    }

    pub fn get_process_state(&self, hci: i32) -> ProcessState {
        self.get_state(hci, move |a: &AdapterState| Some(a.state)).unwrap_or(ProcessState::Off)
    }

    pub fn modify_state<F>(&mut self, hci: i32, call: F)
    where
        F: Fn(&mut AdapterState),
    {
        call(&mut *self.state.lock().unwrap().entry(hci).or_insert(AdapterState::new(hci)))
    }

    pub fn get_tx(&self) -> mpsc::Sender<Message> {
        self.tx.clone()
    }

    pub fn get_floss_enabled(&self) -> bool {
        self.floss_enabled.load(Ordering::Relaxed)
    }

    /// Sets the |floss_enabled| atomic variable.
    ///
    /// # Returns
    /// Previous value of |floss_enabled|
    pub fn set_floss_enabled(&mut self, enabled: bool) -> bool {
        self.floss_enabled.swap(enabled, Ordering::Relaxed)
    }

    pub fn get_valid_adapters(&self) -> Vec<AdapterState> {
        self.state
            .lock()
            .unwrap()
            .iter()
            // Filter to adapters that are present or enabled.
            .filter(|&(_, a)| a.present || state_to_enabled(a.state))
            .map(|(_, a)| a.clone())
            .collect::<Vec<AdapterState>>()
    }
}

fn pid_inotify_async_fd() -> AsyncFd<inotify::Inotify> {
    let mut pid_detector = inotify::Inotify::init().expect("cannot use inotify");
    pid_detector
        .add_watch(PID_DIR, inotify::WatchMask::CREATE | inotify::WatchMask::DELETE)
        .expect("failed to add watch on pid directory");
    AsyncFd::new(pid_detector).expect("failed to add async fd for pid detector")
}

/// Given an pid path, returns the adapter index for that pid path.
fn get_hci_index_from_pid_path(path: &str) -> Option<i32> {
    let re = Regex::new(r"bluetooth([0-9]+).pid").unwrap();
    re.captures(path)?.get(1)?.as_str().parse().ok()
}

fn event_name_to_string(name: Option<&std::ffi::OsStr>) -> Option<String> {
    if let Some(val) = &name {
        if let Some(strval) = val.to_str() {
            return Some(strval.to_string());
        }
    }

    return None;
}

// List existing pids and then configure inotify on pid dir.
fn configure_pid(pid_tx: mpsc::Sender<Message>) {
    // Configure PID listener.
    tokio::spawn(async move {
        debug!("Spawned pid notify task");

        // Get a list of active pid files to determine initial adapter status
        let files = config_util::list_pid_files(PID_DIR);
        for file in files {
            let _ = pid_tx
                .send_timeout(
                    Message::PidChange(inotify::EventMask::CREATE, Some(file)),
                    TX_SEND_TIMEOUT_DURATION,
                )
                .await
                .unwrap();
        }

        // Set up a PID file listener to emit PID inotify messages
        let mut pid_async_fd = pid_inotify_async_fd();

        loop {
            let r = pid_async_fd.readable_mut();
            let mut fd_ready = r.await.unwrap();
            let mut buffer: [u8; 1024] = [0; 1024];
            debug!("Found new pid inotify entries. Reading them");
            match fd_ready.try_io(|inner| inner.get_mut().read_events(&mut buffer)) {
                Ok(Ok(events)) => {
                    for event in events {
                        debug!("got some events from pid {:?}", event.mask);
                        let _ = pid_tx
                            .send_timeout(
                                Message::PidChange(event.mask, event_name_to_string(event.name)),
                                TX_SEND_TIMEOUT_DURATION,
                            )
                            .await
                            .unwrap();
                    }
                }
                Err(_) | Ok(Err(_)) => panic!("Inotify watcher on {} failed.", PID_DIR),
            }
            fd_ready.clear_ready();
            drop(fd_ready);
        }
    });
}

async fn start_hci_if_floss_enabled(hci: u16, floss_enabled: bool, tx: mpsc::Sender<Message>) {
    // Initialize adapter states based on saved config only if floss is enabled.
    if floss_enabled {
        let is_enabled = config_util::is_hci_n_enabled(hci.into());
        debug!("Start hci {}: floss={}, enabled={}", hci, floss_enabled, is_enabled);

        if is_enabled {
            let _ = tx
                .send_timeout(
                    Message::AdapterStateChange(AdapterStateActions::StartBluetooth(hci.into())),
                    TX_SEND_TIMEOUT_DURATION,
                )
                .await
                .unwrap();
        }
    }
}

// Configure the HCI socket listener and prepare the system to receive mgmt events for index added
// and index removed.
fn configure_hci(hci_tx: mpsc::Sender<Message>, floss_enabled: bool) {
    let mut btsock = BtSocket::new();

    // If the bluetooth socket isn't available, the kernel module is not loaded and we can't
    // actually listen to it for index added/removed events.
    match btsock.open() {
        -1 => {
            panic!(
                "Bluetooth socket unavailable (errno {}). Try loading the kernel module first.",
                std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
            );
        }
        x => debug!("Socket open at fd: {}", x),
    }

    // Bind to control channel (which is used for mgmt commands). We provide
    // HCI_DEV_NONE because we don't actually need a valid HCI dev for some MGMT commands.
    match btsock.bind_channel(HciChannels::Control, HCI_DEV_NONE) {
        -1 => {
            panic!(
                "Failed to bind control channel with errno={}",
                std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
            );
        }
        _ => (),
    };

    tokio::spawn(async move {
        debug!("Spawned hci notify task");

        // Make this into an AsyncFD and start using it for IO
        let mut hci_afd = AsyncFd::new(btsock).expect("Failed to add async fd for BT socket.");

        // Start by first reading the index list
        match hci_afd.writable_mut().await {
            Ok(mut guard) => {
                let _ = guard.try_io(|sock| {
                    let command = MgmtCommand::ReadIndexList;
                    sock.get_mut().write_mgmt_packet(command.into());
                    Ok(())
                });
            }
            Err(e) => debug!("Failed to write to hci socket: {:?}", e),
        };

        // Now listen only for devices that are newly added or removed.
        loop {
            if let Ok(mut guard) = hci_afd.readable_mut().await {
                let result = guard.try_io(|sock| Ok(sock.get_mut().read_mgmt_packet()));
                let packet = match result {
                    Ok(v) => v.unwrap_or(None),
                    Err(_) => None,
                };

                if let Some(p) = packet {
                    debug!("Got a valid packet from btsocket: {:?}", p);

                    if let Ok(ev) = MgmtEvent::try_from(p) {
                        debug!("Got a valid mgmt event: {:?}", ev);

                        match ev {
                            MgmtEvent::CommandComplete { opcode: _, status: _, response } => {
                                if let MgmtCommandResponse::ReadIndexList {
                                    num_intf: _,
                                    interfaces,
                                } = response
                                {
                                    for hci in interfaces {
                                        debug!("IndexList response: {}", hci);

                                        let _ = hci_tx
                                            .send_timeout(
                                                Message::AdapterStateChange(
                                                    AdapterStateActions::HciDevicePresence(
                                                        hci.into(),
                                                        true,
                                                    ),
                                                ),
                                                TX_SEND_TIMEOUT_DURATION,
                                            )
                                            .await
                                            .unwrap();

                                        // With a list of initial hci devices, make sure to
                                        // enable them if they were previously enabled and we
                                        // are using floss.
                                        start_hci_if_floss_enabled(
                                            hci.into(),
                                            floss_enabled,
                                            hci_tx.clone(),
                                        )
                                        .await;
                                    }
                                }
                            }
                            MgmtEvent::IndexAdded(hci) => {
                                let _ = hci_tx
                                    .send_timeout(
                                        Message::AdapterStateChange(
                                            AdapterStateActions::HciDevicePresence(
                                                hci.into(),
                                                true,
                                            ),
                                        ),
                                        TX_SEND_TIMEOUT_DURATION,
                                    )
                                    .await
                                    .unwrap();
                            }
                            MgmtEvent::IndexRemoved(hci) => {
                                let _ = hci_tx
                                    .send_timeout(
                                        Message::AdapterStateChange(
                                            AdapterStateActions::HciDevicePresence(
                                                hci.into(),
                                                false,
                                            ),
                                        ),
                                        TX_SEND_TIMEOUT_DURATION,
                                    )
                                    .await
                                    .unwrap();
                            }
                        }
                    }
                } else {
                    // Got nothing from the previous read so clear the ready bit.
                    guard.clear_ready();
                }
            }
        }
    });
}

/// Handle command timeouts per hci interface.
struct CommandTimeout {
    pub waker: Arc<Alarm>,
    expired: bool,
    per_hci_timeout: HashMap<i32, Instant>,
    duration: Duration,
}

impl CommandTimeout {
    pub fn new() -> Self {
        CommandTimeout {
            waker: Arc::new(Alarm::new()),
            per_hci_timeout: HashMap::new(),
            expired: true,
            duration: COMMAND_TIMEOUT_DURATION,
        }
    }

    /// Set next command timeout. If no waker is active, reset to duration.
    fn set_next(&mut self, hci: i32) {
        let wake = Instant::now() + self.duration;
        self.per_hci_timeout.entry(hci).and_modify(|v| *v = wake).or_insert(wake);

        if self.expired {
            self.waker.reset(self.duration);
            self.expired = false;
        }
    }

    /// Remove command timeout for hci interface.
    fn cancel(&mut self, hci: i32) {
        self.per_hci_timeout.remove(&hci);
    }

    /// Expire entries that are older than now and set next wake.
    /// Returns list of expired hci entries.
    fn expire(&mut self) -> Vec<i32> {
        let now = Instant::now();

        let mut completed: Vec<i32> = Vec::new();
        let mut next_expiry = now + self.duration;

        for (hci, expiry) in &self.per_hci_timeout {
            if *expiry < now {
                completed.push(*hci);
            } else if *expiry < next_expiry {
                next_expiry = *expiry;
            }
        }

        for hci in &completed {
            self.per_hci_timeout.remove(hci);
        }

        // If there are any remaining wakeups, reset the wake.
        if !self.per_hci_timeout.is_empty() {
            let duration: Duration = next_expiry - now;
            self.waker.reset(duration);
            self.expired = false;
        } else {
            self.expired = true;
        }

        completed
    }

    /// Handles a specific timeout action.
    fn handle_timeout_action(&mut self, hci: i32, action: CommandTimeoutAction) {
        match action {
            CommandTimeoutAction::ResetTimer => self.set_next(hci),
            CommandTimeoutAction::CancelTimer => self.cancel(hci),
            CommandTimeoutAction::DoNothing => (),
        }
    }
}

pub async fn mainloop(
    mut context: StateMachineContext,
    bluetooth_manager: Arc<Mutex<Box<BluetoothManager>>>,
) {
    // Set up a command timeout listener to emit timeout messages
    let cmd_timeout = Arc::new(Mutex::new(CommandTimeout::new()));

    let ct = cmd_timeout.clone();
    let timeout_tx = context.tx.clone();

    tokio::spawn(async move {
        let timer = ct.lock().unwrap().waker.clone();
        loop {
            let _expired = timer.expired().await;
            let completed = ct.lock().unwrap().expire();
            for hci in completed {
                let _ = timeout_tx
                    .send_timeout(Message::CommandTimeout(hci), TX_SEND_TIMEOUT_DURATION)
                    .await
                    .unwrap();
            }
        }
    });

    // Set up an HCI device listener to emit HCI device inotify messages.
    // This is also responsible for configuring the initial list of HCI devices available on the
    // system.
    configure_hci(context.tx.clone(), context.get_proxy().get_floss_enabled());
    configure_pid(context.tx.clone());

    // Listen for all messages and act on them
    loop {
        let m = context.rx.recv().await;

        if m.is_none() {
            info!("Exiting manager mainloop");
            break;
        }

        debug!("Message handler: {:?}", m);

        match m.unwrap() {
            // Adapter action has changed
            Message::AdapterStateChange(action) => {
                // Grab previous state from lock and release
                let hci;
                let next_state;
                let prev_state;

                match action {
                    AdapterStateActions::StartBluetooth(i) => {
                        hci = i;
                        prev_state = context.state_machine.get_process_state(hci);
                        next_state = ProcessState::TurningOn;

                        let action = context.state_machine.action_start_bluetooth(i);
                        cmd_timeout.lock().unwrap().handle_timeout_action(hci, action);
                    }
                    AdapterStateActions::StopBluetooth(i) => {
                        hci = i;
                        prev_state = context.state_machine.get_process_state(hci);
                        next_state = ProcessState::TurningOff;

                        let action = context.state_machine.action_stop_bluetooth(i);
                        cmd_timeout.lock().unwrap().handle_timeout_action(hci, action);
                    }
                    AdapterStateActions::BluetoothStarted(pid, i) => {
                        hci = i;
                        prev_state = context.state_machine.get_process_state(hci);
                        next_state = ProcessState::On;

                        let action = context.state_machine.action_on_bluetooth_started(pid, hci);
                        cmd_timeout.lock().unwrap().handle_timeout_action(hci, action);
                    }
                    AdapterStateActions::BluetoothStopped(i) => {
                        hci = i;
                        prev_state = context.state_machine.get_process_state(hci);
                        next_state = ProcessState::Off;

                        let action = context.state_machine.action_on_bluetooth_stopped(hci);
                        cmd_timeout.lock().unwrap().handle_timeout_action(hci, action);
                    }

                    AdapterStateActions::HciDevicePresence(i, presence) => {
                        hci = i;
                        prev_state = context.state_machine.get_process_state(hci);
                        next_state =
                            context.state_machine.action_on_hci_presence_changed(i, presence);

                        bluetooth_manager.lock().unwrap().callback_hci_device_change(hci, presence)
                    }
                };

                debug!(
                    "Took action {:?} with prev_state({:?}) and next_state({:?})",
                    action, prev_state, next_state
                );

                // Only emit enabled event for certain transitions
                if next_state != prev_state
                    && (next_state == ProcessState::On || prev_state == ProcessState::On)
                {
                    bluetooth_manager
                        .lock()
                        .unwrap()
                        .callback_hci_enabled_change(hci, next_state == ProcessState::On);
                }
            }

            // Monitored pid directory has a change
            Message::PidChange(mask, filename) => match (mask, &filename) {
                (inotify::EventMask::CREATE, Some(fname)) => {
                    let path = std::path::Path::new(PID_DIR).join(&fname);
                    match (get_hci_index_from_pid_path(&fname), tokio::fs::read(path).await.ok()) {
                        (Some(hci), Some(s)) => {
                            let pid = String::from_utf8(s)
                                .expect("invalid pid file")
                                .parse::<i32>()
                                .unwrap_or(0);
                            debug!("Sending bluetooth started action for pid={}, hci={}", pid, hci);
                            let _ = context
                                .tx
                                .send_timeout(
                                    Message::AdapterStateChange(
                                        AdapterStateActions::BluetoothStarted(pid, hci),
                                    ),
                                    TX_SEND_TIMEOUT_DURATION,
                                )
                                .await
                                .unwrap();
                        }
                        _ => debug!("Invalid pid path: {}", fname),
                    }
                }
                (inotify::EventMask::DELETE, Some(fname)) => {
                    if let Some(hci) = get_hci_index_from_pid_path(&fname) {
                        debug!("Sending bluetooth stopped action for hci={}", hci);
                        context
                            .tx
                            .send_timeout(
                                Message::AdapterStateChange(AdapterStateActions::BluetoothStopped(
                                    hci,
                                )),
                                TX_SEND_TIMEOUT_DURATION,
                            )
                            .await
                            .unwrap();
                    }
                }
                _ => debug!("Ignored event {:?} - {:?}", mask, &filename),
            },

            // Callback client has disconnected
            Message::CallbackDisconnected(id) => {
                bluetooth_manager.lock().unwrap().callback_disconnected(id);
            }

            // Handle command timeouts
            Message::CommandTimeout(hci) => {
                debug!(
                    "Expired action on hci{:?} state{:?}",
                    hci,
                    context.state_machine.get_process_state(hci)
                );
                let timeout_action = context.state_machine.action_on_command_timeout(hci);
                match timeout_action {
                    StateMachineTimeoutActions::Noop => (),
                    _ => cmd_timeout.lock().unwrap().set_next(hci),
                }
            }
        }
    }
}

pub trait ProcessManager {
    fn start(&mut self, hci: String);
    fn stop(&mut self, hci: String);
}

pub enum Invoker {
    #[allow(dead_code)]
    NativeInvoker,
    SystemdInvoker,
    UpstartInvoker,
}

pub struct NativeInvoker {
    process_container: Option<Child>,
    bluetooth_pid: u32,
}

impl NativeInvoker {
    pub fn new() -> NativeInvoker {
        NativeInvoker { process_container: None, bluetooth_pid: 0 }
    }
}

impl ProcessManager for NativeInvoker {
    fn start(&mut self, hci: String) {
        let new_process = Command::new("/usr/bin/btadapterd")
            .arg(format!("HCI={}", hci))
            .stdout(Stdio::piped())
            .spawn()
            .expect("cannot open");
        self.bluetooth_pid = new_process.id();
        self.process_container = Some(new_process);
    }
    fn stop(&mut self, _hci: String) {
        match self.process_container {
            Some(ref mut _p) => {
                signal::kill(Pid::from_raw(self.bluetooth_pid as i32), Signal::SIGTERM).unwrap();
                self.process_container = None;
            }
            None => {
                warn!("Process doesn't exist");
            }
        }
    }
}

pub struct UpstartInvoker {}

impl UpstartInvoker {
    pub fn new() -> UpstartInvoker {
        UpstartInvoker {}
    }
}

impl ProcessManager for UpstartInvoker {
    fn start(&mut self, hci: String) {
        if let Err(e) = Command::new("initctl")
            .args(&["start", "btadapterd", format!("HCI={}", hci).as_str()])
            .output()
        {
            error!("Failed to start btadapterd: {}", e);
        }
    }

    fn stop(&mut self, hci: String) {
        if let Err(e) = Command::new("initctl")
            .args(&["stop", "btadapterd", format!("HCI={}", hci).as_str()])
            .output()
        {
            error!("Failed to stop btadapterd: {}", e);
        }
    }
}

pub struct SystemdInvoker {}

impl SystemdInvoker {
    pub fn new() -> SystemdInvoker {
        SystemdInvoker {}
    }
}

impl ProcessManager for SystemdInvoker {
    fn start(&mut self, hci: String) {
        Command::new("systemctl")
            .args(&["restart", format!("btadapterd@{}.service", hci).as_str()])
            .output()
            .expect("failed to start bluetooth");
    }

    fn stop(&mut self, hci: String) {
        Command::new("systemctl")
            .args(&["stop", format!("btadapterd@{}.service", hci).as_str()])
            .output()
            .expect("failed to stop bluetooth");
    }
}

/// Stored state of each adapter in the state machine.
#[derive(Clone, Debug)]
pub struct AdapterState {
    /// Current adapter process state.
    pub state: ProcessState,

    /// Hci index for this adapter.
    pub hci: i32,

    /// PID for process using this adapter.
    pub pid: i32,

    /// Whether this hci device is listed as present.
    pub present: bool,

    /// Whether this hci device is configured to be enabled.
    pub config_enabled: bool,

    /// How many times this adapter has attempted to restart without success.
    pub restart_count: i32,
}

impl AdapterState {
    pub fn new(hci: i32) -> Self {
        AdapterState {
            state: ProcessState::Off,
            hci,
            present: false,
            config_enabled: false,
            pid: 0,
            restart_count: 0,
        }
    }
}

// Internal and core implementation of the state machine.
struct StateMachineInternal {
    /// Is Floss currently enabled?
    floss_enabled: Arc<AtomicBool>,

    /// Keep track of per hci state. Key = hci id, Value = State.
    state: Arc<Mutex<HashMap<i32, AdapterState>>>,

    /// Process manager implementation.
    process_manager: Box<dyn ProcessManager + Send>,
}

// Implementations of state machine with various process managers.
impl StateMachineInternal {
    pub fn new_upstart(floss_enabled: bool) -> StateMachineInternal {
        StateMachineInternal::new(Box::new(UpstartInvoker::new()), floss_enabled)
    }

    pub fn new_systemd(floss_enabled: bool) -> StateMachineInternal {
        StateMachineInternal::new(Box::new(SystemdInvoker::new()), floss_enabled)
    }

    pub fn new_native(floss_enabled: bool) -> StateMachineInternal {
        StateMachineInternal::new(Box::new(NativeInvoker::new()), floss_enabled)
    }
}

#[derive(Debug, PartialEq)]
enum StateMachineTimeoutActions {
    RetryStart,
    RetryStop,
    Noop,
}

#[derive(Debug, PartialEq)]
enum CommandTimeoutAction {
    CancelTimer,
    DoNothing,
    ResetTimer,
}

// Core state machine implementations.
impl StateMachineInternal {
    pub fn new(
        process_manager: Box<dyn ProcessManager + Send>,
        floss_enabled: bool,
    ) -> StateMachineInternal {
        StateMachineInternal {
            floss_enabled: Arc::new(AtomicBool::new(floss_enabled)),
            state: Arc::new(Mutex::new(HashMap::new())),
            process_manager: process_manager,
        }
    }

    fn is_known(&self, hci: i32) -> bool {
        self.state.lock().unwrap().contains_key(&hci)
    }

    fn get_floss_enabled(&self) -> bool {
        self.floss_enabled.load(Ordering::Relaxed)
    }

    #[cfg(test)]
    fn set_floss_enabled(&mut self, enabled: bool) -> bool {
        self.floss_enabled.swap(enabled, Ordering::Relaxed)
    }

    fn get_process_state(&self, hci: i32) -> ProcessState {
        self.get_state(hci, move |a: &AdapterState| Some(a.state)).unwrap_or(ProcessState::Off)
    }

    fn get_state<T, F>(&self, hci: i32, call: F) -> Option<T>
    where
        F: Fn(&AdapterState) -> Option<T>,
    {
        match self.state.lock().unwrap().get(&hci) {
            Some(a) => call(a),
            None => None,
        }
    }

    fn modify_state<F>(&mut self, hci: i32, call: F)
    where
        F: Fn(&mut AdapterState),
    {
        call(&mut *self.state.lock().unwrap().entry(hci).or_insert(AdapterState::new(hci)))
    }

    /// Returns true if we are starting bluetooth process.
    pub fn action_start_bluetooth(&mut self, hci: i32) -> CommandTimeoutAction {
        let state = self.get_process_state(hci);
        let present = self.get_state(hci, move |a: &AdapterState| Some(a.present)).unwrap_or(false);
        let floss_enabled = self.get_floss_enabled();

        match state {
            // If adapter is off, we should turn it on when present and floss is enabled.
            // If adapter is turning on and we get another start request, we should just
            // repeat the same action which resets the timeout mechanism.
            ProcessState::Off | ProcessState::TurningOn if present && floss_enabled => {
                self.modify_state(hci, move |s: &mut AdapterState| {
                    s.state = ProcessState::TurningOn
                });
                self.process_manager.start(format!("{}", hci));
                CommandTimeoutAction::ResetTimer
            }
            // Otherwise no op
            _ => CommandTimeoutAction::DoNothing,
        }
    }

    /// Returns true if we are stopping bluetooth process.
    pub fn action_stop_bluetooth(&mut self, hci: i32) -> CommandTimeoutAction {
        if !self.is_known(hci) {
            warn!("Attempting to stop unknown hci{}", hci);
            return CommandTimeoutAction::DoNothing;
        }

        let state = self.get_process_state(hci);
        match state {
            ProcessState::On => {
                self.modify_state(hci, |s: &mut AdapterState| s.state = ProcessState::TurningOff);
                self.process_manager.stop(hci.to_string());
                CommandTimeoutAction::ResetTimer
            }
            ProcessState::TurningOn => {
                self.modify_state(hci, |s: &mut AdapterState| s.state = ProcessState::Off);
                self.process_manager.stop(hci.to_string());
                CommandTimeoutAction::CancelTimer
            }
            // Otherwise no op
            _ => CommandTimeoutAction::DoNothing,
        }
    }

    /// Handles a bluetooth started event. Always returns true even with unknown interfaces.
    pub fn action_on_bluetooth_started(&mut self, pid: i32, hci: i32) -> CommandTimeoutAction {
        if !self.is_known(hci) {
            warn!("Unknown hci{} is started; capturing that process", hci);
            self.modify_state(hci, |s: &mut AdapterState| s.state = ProcessState::Off);
        }

        self.modify_state(hci, |s: &mut AdapterState| {
            s.state = ProcessState::On;
            s.restart_count = 0;
            s.pid = pid;
        });

        CommandTimeoutAction::CancelTimer
    }

    /// Returns true if the event is expected.
    /// If unexpected, Bluetooth probably crashed, returning false and starting the timer for restart timeout.
    pub fn action_on_bluetooth_stopped(&mut self, hci: i32) -> CommandTimeoutAction {
        let state = self.get_process_state(hci);
        let present = self.get_state(hci, move |a: &AdapterState| Some(a.present)).unwrap_or(false);
        let floss_enabled = self.get_floss_enabled();

        match state {
            // Normal shut down behavior.
            ProcessState::TurningOff => {
                self.modify_state(hci, |s: &mut AdapterState| s.state = ProcessState::Off);
                CommandTimeoutAction::CancelTimer
            }
            // Running bluetooth stopped unexpectedly.
            ProcessState::On if present && floss_enabled => {
                warn!("Bluetooth stopped unexpectedly, try restarting");
                self.modify_state(hci, |s: &mut AdapterState| {
                    s.state = ProcessState::TurningOn;
                    s.restart_count = s.restart_count + 1;
                });
                self.process_manager.start(format!("{}", hci));
                CommandTimeoutAction::ResetTimer
            }
            ProcessState::On | ProcessState::TurningOn | ProcessState::Off => {
                warn!(
                    "Bluetooth stopped unexpectedly from {:?}. Adapter present? {}",
                    state, present
                );
                self.modify_state(hci, |s: &mut AdapterState| s.state = ProcessState::Off);
                CommandTimeoutAction::CancelTimer
            }
        }
    }

    /// Triggered on Bluetooth start/stop timeout.  Return the actions that the
    /// state machine has taken, for the external context to reset the timer.
    pub fn action_on_command_timeout(&mut self, hci: i32) -> StateMachineTimeoutActions {
        let state = self.get_process_state(hci);
        let floss_enabled = self.get_floss_enabled();
        let present = self.get_state(hci, |a: &AdapterState| Some(a.present)).unwrap_or(false);

        match state {
            // If Floss is not enabled, just send |Stop| to process manager and end the state
            // machine actions.
            ProcessState::TurningOn if !floss_enabled => {
                info!("Timed out turning on but floss is disabled: {}", hci);
                self.modify_state(hci, |s: &mut AdapterState| s.state = ProcessState::Off);
                self.process_manager.stop(format! {"{}", hci});
                StateMachineTimeoutActions::Noop
            }
            // If turning on and hci is present, restart the process.
            ProcessState::TurningOn if present => {
                info!("Restarting bluetooth {}", hci);
                self.modify_state(hci, |s: &mut AdapterState| s.state = ProcessState::TurningOn);
                self.process_manager.stop(format! {"{}", hci});
                self.process_manager.start(format! {"{}", hci});
                StateMachineTimeoutActions::RetryStart
            }
            // If turning on but hci is not present, mark process as stopped. It will be
            // automatically started (if configured to do so) when it next becomes present.
            ProcessState::TurningOn if !present => {
                info!("Device presence lost while turning on: {}", hci);
                self.modify_state(hci, |s: &mut AdapterState| s.state = ProcessState::Off);
                StateMachineTimeoutActions::Noop
            }
            ProcessState::TurningOff => {
                info!("Killing bluetooth {}", hci);
                self.process_manager.stop(format! {"{}", hci});
                StateMachineTimeoutActions::RetryStop
            }
            _ => StateMachineTimeoutActions::Noop,
        }
    }

    /// Handle when an hci device presence has changed.
    ///
    /// This will start adapters that are configured to be enabled if the presence is newly added.
    ///
    /// # Return
    /// Target process state.
    pub fn action_on_hci_presence_changed(&mut self, hci: i32, present: bool) -> ProcessState {
        let prev_present = self.get_state(hci, |a: &AdapterState| Some(a.present)).unwrap_or(false);
        let prev_state = self.get_process_state(hci);

        // No-op if same as previous present.
        if prev_present == present {
            return prev_state;
        }

        self.modify_state(hci, |a: &mut AdapterState| a.present = present);
        let floss_enabled = self.get_floss_enabled();

        match self.get_state(hci, |a: &AdapterState| Some((a.state, a.config_enabled))) {
            // Start the adapter if present, config is enabled and floss is enabled.
            Some((ProcessState::Off, true)) if floss_enabled && present => {
                self.action_start_bluetooth(hci);
                ProcessState::TurningOn
            }
            _ => prev_state,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;

    #[derive(Debug, PartialEq)]
    enum ExecutedCommand {
        Start,
        Stop,
    }

    struct MockProcessManager {
        last_command: VecDeque<ExecutedCommand>,
        expectations: Vec<bool>,
    }

    impl MockProcessManager {
        fn new() -> MockProcessManager {
            MockProcessManager { last_command: VecDeque::new(), expectations: Vec::new() }
        }

        fn expect_start(&mut self) {
            self.last_command.push_back(ExecutedCommand::Start);
        }

        fn expect_stop(&mut self) {
            self.last_command.push_back(ExecutedCommand::Stop);
        }
    }

    impl ProcessManager for MockProcessManager {
        fn start(&mut self, _: String) {
            self.expectations.push(match self.last_command.pop_front() {
                Some(x) => x == ExecutedCommand::Start,
                None => false,
            });
        }

        fn stop(&mut self, _: String) {
            self.expectations.push(match self.last_command.pop_front() {
                Some(x) => x == ExecutedCommand::Stop,
                None => false,
            });
        }
    }

    impl Drop for MockProcessManager {
        fn drop(&mut self) {
            assert_eq!(self.last_command.len(), 0);
            let exp: &[bool] = &[];
            // Check that we had 0 false expectations.
            assert_eq!(
                self.expectations
                    .iter()
                    .filter(|&v| !*v)
                    .map(|v| *v)
                    .collect::<Vec<bool>>()
                    .as_slice(),
                exp
            );
        }
    }

    #[test]
    fn initial_state_is_off() {
        tokio::runtime::Runtime::new().unwrap().block_on(async {
            let process_manager = MockProcessManager::new();
            let state_machine = StateMachineInternal::new(Box::new(process_manager), true);
            assert_eq!(state_machine.get_process_state(0), ProcessState::Off);
        })
    }

    #[test]
    fn off_turnoff_should_noop() {
        tokio::runtime::Runtime::new().unwrap().block_on(async {
            let process_manager = MockProcessManager::new();
            let mut state_machine = StateMachineInternal::new(Box::new(process_manager), true);
            state_machine.action_stop_bluetooth(0);
            assert_eq!(state_machine.get_process_state(0), ProcessState::Off);
        })
    }

    #[test]
    fn off_turnon_should_turningon() {
        tokio::runtime::Runtime::new().unwrap().block_on(async {
            let mut process_manager = MockProcessManager::new();
            // Expect to send start command
            process_manager.expect_start();
            let mut state_machine = StateMachineInternal::new(Box::new(process_manager), true);
            state_machine.action_on_hci_presence_changed(0, true);
            state_machine.action_start_bluetooth(0);
            assert_eq!(state_machine.get_process_state(0), ProcessState::TurningOn);
        })
    }

    #[test]
    fn turningon_turnon_again_resends_start() {
        tokio::runtime::Runtime::new().unwrap().block_on(async {
            let mut process_manager = MockProcessManager::new();
            // Expect to send start command just once
            process_manager.expect_start();
            process_manager.expect_start();
            let mut state_machine = StateMachineInternal::new(Box::new(process_manager), true);
            state_machine.action_on_hci_presence_changed(0, true);
            state_machine.action_start_bluetooth(0);
            assert_eq!(state_machine.action_start_bluetooth(0), CommandTimeoutAction::ResetTimer);
        })
    }

    #[test]
    fn turningon_bluetooth_started() {
        tokio::runtime::Runtime::new().unwrap().block_on(async {
            let mut process_manager = MockProcessManager::new();
            process_manager.expect_start();
            let mut state_machine = StateMachineInternal::new(Box::new(process_manager), true);
            state_machine.action_on_hci_presence_changed(0, true);
            state_machine.action_start_bluetooth(0);
            state_machine.action_on_bluetooth_started(0, 0);
            assert_eq!(state_machine.get_process_state(0), ProcessState::On);
        })
    }

    #[test]
    fn turningon_bluetooth_different_hci_started() {
        tokio::runtime::Runtime::new().unwrap().block_on(async {
            let mut process_manager = MockProcessManager::new();
            process_manager.expect_start();
            let mut state_machine = StateMachineInternal::new(Box::new(process_manager), true);
            state_machine.action_on_hci_presence_changed(1, true);
            state_machine.action_start_bluetooth(1);
            state_machine.action_on_bluetooth_started(1, 1);
            assert_eq!(state_machine.get_process_state(1), ProcessState::On);
            assert_eq!(state_machine.get_process_state(0), ProcessState::Off);
        })
    }

    #[test]
    fn turningon_timeout() {
        tokio::runtime::Runtime::new().unwrap().block_on(async {
            let mut process_manager = MockProcessManager::new();
            process_manager.expect_start();
            process_manager.expect_stop();
            process_manager.expect_start(); // start bluetooth again
            let mut state_machine = StateMachineInternal::new(Box::new(process_manager), true);
            state_machine.action_on_hci_presence_changed(0, true);
            state_machine.action_start_bluetooth(0);
            assert_eq!(
                state_machine.action_on_command_timeout(0),
                StateMachineTimeoutActions::RetryStart
            );
            assert_eq!(state_machine.get_process_state(0), ProcessState::TurningOn);
        })
    }

    #[test]
    fn turningon_turnoff_should_turningoff_and_send_command() {
        tokio::runtime::Runtime::new().unwrap().block_on(async {
            let mut process_manager = MockProcessManager::new();
            process_manager.expect_start();
            // Expect to send stop command
            process_manager.expect_stop();
            let mut state_machine = StateMachineInternal::new(Box::new(process_manager), true);
            state_machine.action_on_hci_presence_changed(0, true);
            state_machine.action_start_bluetooth(0);
            state_machine.action_stop_bluetooth(0);
            assert_eq!(state_machine.get_process_state(0), ProcessState::Off);
        })
    }

    #[test]
    fn on_turnoff_should_turningoff_and_send_command() {
        tokio::runtime::Runtime::new().unwrap().block_on(async {
            let mut process_manager = MockProcessManager::new();
            process_manager.expect_start();
            // Expect to send stop command
            process_manager.expect_stop();
            let mut state_machine = StateMachineInternal::new(Box::new(process_manager), true);
            state_machine.action_on_hci_presence_changed(0, true);
            state_machine.action_start_bluetooth(0);
            state_machine.action_on_bluetooth_started(0, 0);
            state_machine.action_stop_bluetooth(0);
            assert_eq!(state_machine.get_process_state(0), ProcessState::TurningOff);
        })
    }

    #[test]
    fn on_bluetooth_stopped_multicase() {
        // Normal bluetooth stopped should restart.
        tokio::runtime::Runtime::new().unwrap().block_on(async {
            let mut process_manager = MockProcessManager::new();
            process_manager.expect_start();
            // Expect to start again
            process_manager.expect_start();
            let mut state_machine = StateMachineInternal::new(Box::new(process_manager), true);
            state_machine.action_on_hci_presence_changed(0, true);
            state_machine.action_start_bluetooth(0);
            state_machine.action_on_bluetooth_started(0, 0);
            assert_eq!(
                state_machine.action_on_bluetooth_stopped(0),
                CommandTimeoutAction::ResetTimer
            );
            assert_eq!(state_machine.get_process_state(0), ProcessState::TurningOn);
        });

        // Stopped with no presence shouldn't restart.
        tokio::runtime::Runtime::new().unwrap().block_on(async {
            let mut process_manager = MockProcessManager::new();
            process_manager.expect_start();
            let mut state_machine = StateMachineInternal::new(Box::new(process_manager), true);
            state_machine.action_on_hci_presence_changed(0, true);
            state_machine.action_start_bluetooth(0);
            state_machine.action_on_bluetooth_started(0, 0);
            state_machine.action_on_hci_presence_changed(0, false);
            assert_eq!(
                state_machine.action_on_bluetooth_stopped(0),
                CommandTimeoutAction::CancelTimer
            );
            assert_eq!(state_machine.get_process_state(0), ProcessState::Off);
        });

        // If floss was disabled and we see stopped, we shouldn't restart.
        tokio::runtime::Runtime::new().unwrap().block_on(async {
            let mut process_manager = MockProcessManager::new();
            process_manager.expect_start();
            let mut state_machine = StateMachineInternal::new(Box::new(process_manager), true);
            state_machine.action_on_hci_presence_changed(0, true);
            state_machine.action_start_bluetooth(0);
            state_machine.action_on_bluetooth_started(0, 0);
            state_machine.set_floss_enabled(false);
            assert_eq!(
                state_machine.action_on_bluetooth_stopped(0),
                CommandTimeoutAction::CancelTimer
            );
            assert_eq!(state_machine.get_process_state(0), ProcessState::Off);
        });
    }

    #[test]
    fn turningoff_bluetooth_down_should_off() {
        tokio::runtime::Runtime::new().unwrap().block_on(async {
            let mut process_manager = MockProcessManager::new();
            process_manager.expect_start();
            process_manager.expect_stop();
            let mut state_machine = StateMachineInternal::new(Box::new(process_manager), true);
            state_machine.action_on_hci_presence_changed(0, true);
            state_machine.action_start_bluetooth(0);
            state_machine.action_on_bluetooth_started(0, 0);
            state_machine.action_stop_bluetooth(0);
            state_machine.action_on_bluetooth_stopped(0);
            assert_eq!(state_machine.get_process_state(0), ProcessState::Off);
        })
    }

    #[test]
    fn restart_bluetooth() {
        tokio::runtime::Runtime::new().unwrap().block_on(async {
            let mut process_manager = MockProcessManager::new();
            process_manager.expect_start();
            process_manager.expect_stop();
            process_manager.expect_start();
            let mut state_machine = StateMachineInternal::new(Box::new(process_manager), true);
            state_machine.action_on_hci_presence_changed(0, true);
            state_machine.action_start_bluetooth(0);
            state_machine.action_on_bluetooth_started(0, 0);
            state_machine.action_stop_bluetooth(0);
            state_machine.action_on_bluetooth_stopped(0);
            state_machine.action_start_bluetooth(0);
            state_machine.action_on_bluetooth_started(0, 0);
            assert_eq!(state_machine.get_process_state(0), ProcessState::On);
        })
    }

    #[test]
    fn start_bluetooth_without_device_fails() {
        tokio::runtime::Runtime::new().unwrap().block_on(async {
            let process_manager = MockProcessManager::new();
            let mut state_machine = StateMachineInternal::new(Box::new(process_manager), true);
            state_machine.action_start_bluetooth(0);
            assert_eq!(state_machine.get_process_state(0), ProcessState::Off);
        });
    }

    #[test]
    fn start_bluetooth_without_floss_fails() {
        tokio::runtime::Runtime::new().unwrap().block_on(async {
            let process_manager = MockProcessManager::new();
            let mut state_machine = StateMachineInternal::new(Box::new(process_manager), false);
            state_machine.action_on_hci_presence_changed(0, true);
            state_machine.action_start_bluetooth(0);
            assert_eq!(state_machine.get_process_state(0), ProcessState::Off);
        });
    }

    #[test]
    fn on_timeout_multicase() {
        // If a timeout occurs while turning on or off with floss enabled..
        tokio::runtime::Runtime::new().unwrap().block_on(async {
            let mut process_manager = MockProcessManager::new();
            process_manager.expect_start();
            // Expect a stop and start for timeout.
            process_manager.expect_stop();
            process_manager.expect_start();
            // Expect another stop for stop timeout.
            process_manager.expect_stop();
            process_manager.expect_stop();
            let mut state_machine = StateMachineInternal::new(Box::new(process_manager), true);
            state_machine.action_on_hci_presence_changed(0, true);
            state_machine.action_start_bluetooth(0);
            assert_eq!(state_machine.get_process_state(0), ProcessState::TurningOn);
            assert_eq!(
                state_machine.action_on_command_timeout(0),
                StateMachineTimeoutActions::RetryStart
            );
            assert_eq!(state_machine.get_process_state(0), ProcessState::TurningOn);
            state_machine.action_on_bluetooth_started(0, 0);
            state_machine.action_stop_bluetooth(0);
            assert_eq!(
                state_machine.action_on_command_timeout(0),
                StateMachineTimeoutActions::RetryStop
            );
            assert_eq!(state_machine.get_process_state(0), ProcessState::TurningOff);
        });

        // If a timeout occurs during turning on and floss is disabled, stop the adapter.
        tokio::runtime::Runtime::new().unwrap().block_on(async {
            let mut process_manager = MockProcessManager::new();
            process_manager.expect_start();
            // Expect a stop for timeout since floss is disabled.
            process_manager.expect_stop();
            let mut state_machine = StateMachineInternal::new(Box::new(process_manager), true);
            state_machine.action_on_hci_presence_changed(0, true);
            state_machine.action_start_bluetooth(0);
            assert_eq!(state_machine.get_process_state(0), ProcessState::TurningOn);
            state_machine.set_floss_enabled(false);
            assert_eq!(
                state_machine.action_on_command_timeout(0),
                StateMachineTimeoutActions::Noop
            );
            assert_eq!(state_machine.get_process_state(0), ProcessState::Off);
        });

        // If a timeout occurs during TurningOn phase (present = true, Start, present = false,
        // timeout)
        tokio::runtime::Runtime::new().unwrap().block_on(async {
            let mut process_manager = MockProcessManager::new();
            process_manager.expect_start();
            let mut state_machine = StateMachineInternal::new(Box::new(process_manager), true);
            state_machine.action_on_hci_presence_changed(0, true);
            state_machine.action_start_bluetooth(0);
            assert_eq!(state_machine.get_process_state(0), ProcessState::TurningOn);
            state_machine.action_on_hci_presence_changed(0, false);
            assert_eq!(
                state_machine.action_on_command_timeout(0),
                StateMachineTimeoutActions::Noop
            );
            assert_eq!(state_machine.get_process_state(0), ProcessState::Off);
        });
    }

    #[test]
    fn on_present_after_stopped_restarts() {}

    #[test]
    fn path_to_pid() {
        assert_eq!(get_hci_index_from_pid_path("/var/run/bluetooth/bluetooth0.pid"), Some(0));
        assert_eq!(get_hci_index_from_pid_path("/var/run/bluetooth/bluetooth1.pid"), Some(1));
        assert_eq!(get_hci_index_from_pid_path("/var/run/bluetooth/bluetooth10.pid"), Some(10));
        assert_eq!(get_hci_index_from_pid_path("/var/run/bluetooth/garbage"), None);
    }
}
