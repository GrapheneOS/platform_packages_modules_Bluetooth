use bt_common::time::Alarm;
use nix::sys::signal::{self, Signal};
use nix::unistd::Pid;
use regex::Regex;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::unix::AsyncFd;
use tokio::sync::mpsc::error::SendError;
use tokio::sync::{mpsc, Mutex};

// Directory for Bluetooth pid file
pub const PID_DIR: &str = "/var/run/bluetooth";

#[derive(Debug, PartialEq, Copy, Clone)]
#[repr(i32)]
pub enum State {
    Off = 0,        // Bluetooth is not running
    TurningOn = 1,  // We are not notified that the Bluetooth is running
    On = 2,         // Bluetooth is running
    TurningOff = 3, // We are not notified that the Bluetooth is stopped
}

impl From<State> for i32 {
    fn from(item: State) -> i32 {
        item as i32
    }
}

pub fn state_to_i32(state: State) -> i32 {
    i32::from(state)
}

#[derive(Debug)]
pub enum StateMachineActions {
    StartBluetooth(i32),
    StopBluetooth(i32),
    BluetoothStarted(i32, i32), // PID and HCI
    BluetoothStopped(),
}

pub struct StateMachineContext<PM> {
    tx: mpsc::Sender<StateMachineActions>,
    rx: mpsc::Receiver<StateMachineActions>,
    state_machine: ManagerStateMachine<PM>,
}

impl<PM> StateMachineContext<PM> {
    fn new(state_machine: ManagerStateMachine<PM>) -> StateMachineContext<PM>
    where
        PM: ProcessManager + Send,
    {
        let (tx, rx) = mpsc::channel::<StateMachineActions>(1);
        StateMachineContext { tx: tx, rx: rx, state_machine: state_machine }
    }

    pub fn get_proxy(&self) -> StateMachineProxy {
        StateMachineProxy { tx: self.tx.clone(), state: self.state_machine.state.clone() }
    }
}

pub fn start_new_state_machine_context() -> StateMachineContext<UpstartInvoker> {
    StateMachineContext::new(ManagerStateMachine::new_upstart())
}

#[derive(Clone)]
pub struct StateMachineProxy {
    tx: mpsc::Sender<StateMachineActions>,
    state: Arc<Mutex<State>>,
}

impl StateMachineProxy {
    pub async fn start_bluetooth(
        &self,
        hci_interface: i32,
    ) -> Result<(), SendError<StateMachineActions>> {
        self.tx.send(StateMachineActions::StartBluetooth(hci_interface)).await
    }

    pub async fn stop_bluetooth(
        &self,
        hci_interface: i32,
    ) -> Result<(), SendError<StateMachineActions>> {
        self.tx.send(StateMachineActions::StopBluetooth(hci_interface)).await
    }

    pub async fn get_state(&self) -> State {
        *self.state.lock().await
    }
}

fn pid_inotify_async_fd() -> AsyncFd<inotify::Inotify> {
    let mut pid_detector = inotify::Inotify::init().expect("cannot use inotify");
    pid_detector
        .add_watch(PID_DIR, inotify::WatchMask::CREATE | inotify::WatchMask::DELETE)
        .expect("failed to add watch");
    AsyncFd::new(pid_detector).expect("failed to add async fd")
}

fn get_hci_interface_from_pid_file_name(path: &str) -> Option<i32> {
    let re = Regex::new(r"bluetooth([0-9]+).pid").unwrap();
    re.captures(path)?.get(1)?.as_str().parse().ok()
}

fn hci_devices_inotify_async_fd() -> AsyncFd<inotify::Inotify> {
    let mut detector = inotify::Inotify::init().expect("cannot use inotify");
    detector
        .add_watch(
            crate::config_util::HCI_DEVICES_DIR,
            inotify::WatchMask::CREATE | inotify::WatchMask::DELETE,
        )
        .expect("failed to add watch");
    AsyncFd::new(detector).expect("failed to add async fd")
}

fn get_hci_interface_from_device(path: &str) -> Option<i32> {
    let re = Regex::new(r"hci([0-9]+)").unwrap();
    re.captures(path)?.get(1)?.as_str().parse().ok()
}

pub async fn mainloop<PM>(
    mut context: StateMachineContext<PM>,
    dbus_callback_util: crate::dbus_callback_util::DbusCallbackUtil,
) where
    PM: ProcessManager + Send,
{
    let mut command_timeout = Alarm::new();
    let command_timeout_duration = Duration::from_secs(2);
    let mut pid_async_fd = pid_inotify_async_fd();
    let mut hci_devices_async_fd = hci_devices_inotify_async_fd();
    loop {
        tokio::select! {
            Some(action) = context.rx.recv() => {
              match action {
                StateMachineActions::StartBluetooth(i) => {
                    match context.state_machine.action_start_bluetooth(i) {
                        true => {
                            command_timeout.reset(command_timeout_duration);
                        },
                        false => (),
                    }
                },
                StateMachineActions::StopBluetooth(i) => {
                  match context.state_machine.action_stop_bluetooth(i) {
                      true => command_timeout.reset(command_timeout_duration),
                      false => (),
                  }
                },
                StateMachineActions::BluetoothStarted(pid, hci) => {
                  match context.state_machine.action_on_bluetooth_started(pid, hci) {
                      true => command_timeout.cancel(),
                      false => println!("unexpected BluetoothStarted pid{} hci{}", pid, hci),
                  }
                },
                StateMachineActions::BluetoothStopped() => {
                  match context.state_machine.action_on_bluetooth_stopped() {
                      true => command_timeout.cancel(),
                      false => {
                        println!("BluetoothStopped");
                          command_timeout.reset(command_timeout_duration);
                      }
                  }
                },
              }
            },
            _ = command_timeout.expired() => {
                println!("expired {:?}", *context.state_machine.state.lock().await);
                let timeout_action = context.state_machine.action_on_command_timeout();
                match timeout_action {
                    StateMachineTimeoutActions::Noop => (),
                    _ => command_timeout.reset(command_timeout_duration),
                }
            },
            r = pid_async_fd.readable_mut() => {
                let mut fd_ready = r.unwrap();
                let mut buffer: [u8; 1024] = [0; 1024];
                match fd_ready.try_io(|inner| inner.get_mut().read_events(&mut buffer)) {
                    Ok(Ok(events)) => {
                        println!("got some events");
                        for event in events {
                            match (event.mask, event.name) {
                                (inotify::EventMask::CREATE, Some(oss)) => {
                                    let path = std::path::Path::new(PID_DIR).join(oss);
                                    let file_name = oss.to_str().unwrap_or("invalid file");
                                    match (get_hci_interface_from_pid_file_name(file_name), tokio::fs::read(path).await.ok()) {
                                        (Some(hci), Some(s)) => {
                                            let pid = String::from_utf8(s).expect("invalid pid file").parse::<i32>().unwrap_or(0);
                                            let _ = context.tx.send(StateMachineActions::BluetoothStarted(pid, hci)).await;
                                        },
                                        (hci, s) => println!("invalid file hci={:?} pid_file={:?}", hci, s),
                                    }
                                },
                                (inotify::EventMask::DELETE, Some(oss)) => {
                                    let file_name = oss.to_str().unwrap_or("invalid file");
                                    match get_hci_interface_from_pid_file_name(file_name) {
                                        Some(hci) => {
                                            let _ = context.tx.send(StateMachineActions::BluetoothStopped()).await;
                                        },
                                        _ => (),
                                    }
                                },
                                _ => println!("Ignored event {:?}", event.mask)
                            }
                        }
                    },
                    Err(_) | Ok(Err(_)) => panic!("why can't we read while the asyncfd is ready?"),
                }
                fd_ready.clear_ready();
                drop(fd_ready);
            },
            r = hci_devices_async_fd.readable_mut() => {
                let mut fd_ready = r.unwrap();
                let mut buffer: [u8; 1024] = [0; 1024];
                match fd_ready.try_io(|inner| inner.get_mut().read_events(&mut buffer)) {
                    Ok(Ok(events)) => {
                        for event in events {
                            match (event.mask, event.name) {
                                (inotify::EventMask::CREATE, Some(oss)) => {
                                    match get_hci_interface_from_device(oss.to_str().unwrap_or("invalid hci device")) {
                                        Some(hci) => {
                                            dbus_callback_util.send_hci_device_change_callback(hci, true).await;
                                        },
                                        _ => (),
                                    }
                                },
                                (inotify::EventMask::DELETE, Some(oss)) => {
                                    match get_hci_interface_from_device(oss.to_str().unwrap_or("invalid hci device")) {
                                        Some(hci) => {
                                            dbus_callback_util.send_hci_device_change_callback(hci, false).await;
                                        },
                                        _ => (),
                                    }
                                },
                                _ => println!("Ignored event {:?}", event.mask)
                            }
                        }
                    },
                    Err(_) | Ok(Err(_)) => panic!("why can't we read while the asyncfd is ready?"),
                }
                fd_ready.clear_ready();
                drop(fd_ready);
            },
        }
    }
}

pub trait ProcessManager {
    fn start(&mut self, hci_interface: String);
    fn stop(&mut self, hci_interface: String);
}

pub struct NativeSubprocess {
    process_container: Option<Child>,
    bluetooth_pid: u32,
}

impl NativeSubprocess {
    pub fn new() -> NativeSubprocess {
        NativeSubprocess { process_container: None, bluetooth_pid: 0 }
    }
}

impl ProcessManager for NativeSubprocess {
    fn start(&mut self, hci_interface: String) {
        let new_process = Command::new("/usr/bin/btadapterd")
            .arg(format!("HCI={}", hci_interface))
            .stdout(Stdio::piped())
            .spawn()
            .expect("cannot open");
        self.bluetooth_pid = new_process.id();
        self.process_container = Some(new_process);
    }
    fn stop(&mut self, _hci_interface: String) {
        match self.process_container {
            Some(ref mut _p) => {
                signal::kill(Pid::from_raw(self.bluetooth_pid as i32), Signal::SIGTERM).unwrap();
                self.process_container = None;
            }
            None => {
                println!("Process doesn't exist");
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
    fn start(&mut self, hci_interface: String) {
        Command::new("initctl")
            .args(&["start", "btadapterd", format!("HCI={}", hci_interface).as_str()])
            .output()
            .expect("failed to start bluetooth");
    }

    fn stop(&mut self, hci_interface: String) {
        Command::new("initctl")
            .args(&["stop", "btadapterd", format!("HCI={}", hci_interface).as_str()])
            .output()
            .expect("failed to stop bluetooth");
    }
}

struct ManagerStateMachine<PM> {
    state: Arc<Mutex<State>>,
    process_manager: PM,
    hci_interface: i32,
    bluetooth_pid: i32,
}

impl ManagerStateMachine<NativeSubprocess> {
    pub fn new_native() -> ManagerStateMachine<NativeSubprocess> {
        ManagerStateMachine::new(NativeSubprocess::new())
    }
}

impl ManagerStateMachine<UpstartInvoker> {
    pub fn new_upstart() -> ManagerStateMachine<UpstartInvoker> {
        ManagerStateMachine::new(UpstartInvoker::new())
    }
}

#[derive(Debug, PartialEq)]
enum StateMachineTimeoutActions {
    RetryStart,
    RetryStop,
    Noop,
}

impl<PM> ManagerStateMachine<PM>
where
    PM: ProcessManager + Send,
{
    pub fn new(process_manager: PM) -> ManagerStateMachine<PM> {
        ManagerStateMachine {
            state: Arc::new(Mutex::new(State::Off)),
            process_manager: process_manager,
            hci_interface: 0,
            bluetooth_pid: 0,
        }
    }

    /// Returns true if we are starting bluetooth process.
    pub fn action_start_bluetooth(&mut self, hci_interface: i32) -> bool {
        let mut state = self.state.try_lock().unwrap();
        match *state {
            State::Off => {
                *state = State::TurningOn;
                self.hci_interface = hci_interface;
                self.process_manager.start(format!("{}", hci_interface));
                true
            }
            // Otherwise no op
            _ => false,
        }
    }

    /// Returns true if we are stopping bluetooth process.
    pub fn action_stop_bluetooth(&mut self, hci_interface: i32) -> bool {
        if self.hci_interface != hci_interface {
            println!(
                "We are running hci{} but attempting to stop hci{}",
                self.hci_interface, hci_interface
            );
            return false;
        }

        let mut state = self.state.try_lock().unwrap();
        match *state {
            State::On | State::TurningOn => {
                *state = State::TurningOff;
                self.process_manager.stop(self.hci_interface.to_string());
                true
            }
            // Otherwise no op
            _ => false,
        }
    }

    /// Returns true if the event is expected.
    pub fn action_on_bluetooth_started(&mut self, pid: i32, hci_interface: i32) -> bool {
        let mut state = self.state.try_lock().unwrap();
        if self.hci_interface != hci_interface {
            println!(
                "We should start hci{} but hci{} is started; capturing that process",
                self.hci_interface, hci_interface
            );
            self.hci_interface = hci_interface;
        }
        if *state != State::TurningOn {
            println!("Unexpected Bluetooth started");
        }
        *state = State::On;
        self.bluetooth_pid = pid;
        true
    }

    /// Returns true if the event is expected.
    /// If unexpected, Bluetooth probably crashed;
    /// start the timer for restart timeout
    pub fn action_on_bluetooth_stopped(&mut self) -> bool {
        // Need to check if file exists
        let mut state = self.state.try_lock().unwrap();

        match *state {
            State::TurningOff => {
                *state = State::Off;
                true
            }
            State::On => {
                println!("Bluetooth stopped unexpectedly, try restarting");
                *state = State::TurningOn;
                self.process_manager.start(format!("{}", self.hci_interface));
                false
            }
            State::TurningOn | State::Off => {
                // Unexpected
                panic!("unexpected bluetooth shutdown");
            }
        }
    }

    /// Triggered on Bluetooth start/stop timeout.  Return the actions that the
    /// state machine has taken, for the external context to reset the timer.
    pub fn action_on_command_timeout(&mut self) -> StateMachineTimeoutActions {
        let mut state = self.state.try_lock().unwrap();
        match *state {
            State::TurningOn => {
                println!("Restarting bluetooth");
                *state = State::TurningOn;
                self.process_manager.start(format! {"{}", self.hci_interface});
                StateMachineTimeoutActions::RetryStart
            }
            State::TurningOff => {
                println!("Killing bluetooth");

                *state = State::Off;
                StateMachineTimeoutActions::RetryStop
            }
            _ => panic!("Unexpected timeout on {:?}", *state),
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
    }

    impl MockProcessManager {
        fn new() -> MockProcessManager {
            MockProcessManager { last_command: VecDeque::new() }
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
            let start = self.last_command.pop_front().expect("Should expect start event");
            assert_eq!(start, ExecutedCommand::Start);
        }

        fn stop(&mut self, _: String) {
            let stop = self.last_command.pop_front().expect("Should expect stop event");
            assert_eq!(stop, ExecutedCommand::Stop);
        }
    }

    impl Drop for MockProcessManager {
        fn drop(&mut self) {
            assert_eq!(self.last_command.len(), 0);
        }
    }

    #[test]
    fn initial_state_is_off() {
        let process_manager = MockProcessManager::new();
        let state_machine = ManagerStateMachine::new(process_manager);
        assert_eq!(*state_machine.state.try_lock().unwrap(), State::Off);
    }

    #[test]
    fn off_turnoff_should_noop() {
        let process_manager = MockProcessManager::new();
        let mut state_machine = ManagerStateMachine::new(process_manager);
        state_machine.action_stop_bluetooth(0);
        assert_eq!(*state_machine.state.try_lock().unwrap(), State::Off);
    }

    #[test]
    fn off_turnon_should_turningon() {
        let mut process_manager = MockProcessManager::new();
        // Expect to send start command
        process_manager.expect_start();
        let mut state_machine = ManagerStateMachine::new(process_manager);
        state_machine.action_start_bluetooth(0);
        assert_eq!(*state_machine.state.try_lock().unwrap(), State::TurningOn);
    }

    #[test]
    fn turningon_turnon_again_noop() {
        let mut process_manager = MockProcessManager::new();
        // Expect to send start command just once
        process_manager.expect_start();
        let mut state_machine = ManagerStateMachine::new(process_manager);
        state_machine.action_start_bluetooth(0);
        assert_eq!(state_machine.action_start_bluetooth(0), false);
    }

    #[test]
    fn turningon_bluetooth_started() {
        let mut process_manager = MockProcessManager::new();
        process_manager.expect_start();
        let mut state_machine = ManagerStateMachine::new(process_manager);
        state_machine.action_start_bluetooth(0);
        state_machine.action_on_bluetooth_started(0, 0);
        assert_eq!(*state_machine.state.try_lock().unwrap(), State::On);
    }

    #[test]
    fn turningon_timeout() {
        let mut process_manager = MockProcessManager::new();
        process_manager.expect_start();
        process_manager.expect_start(); // start bluetooth again
        let mut state_machine = ManagerStateMachine::new(process_manager);
        state_machine.action_start_bluetooth(0);
        assert_eq!(
            state_machine.action_on_command_timeout(),
            StateMachineTimeoutActions::RetryStart
        );
        assert_eq!(*state_machine.state.try_lock().unwrap(), State::TurningOn);
    }

    #[test]
    fn turningon_turnoff_should_turningoff_and_send_command() {
        let mut process_manager = MockProcessManager::new();
        process_manager.expect_start();
        // Expect to send stop command
        process_manager.expect_stop();
        let mut state_machine = ManagerStateMachine::new(process_manager);
        state_machine.action_start_bluetooth(0);
        state_machine.action_stop_bluetooth(0);
        assert_eq!(*state_machine.state.try_lock().unwrap(), State::TurningOff);
    }

    #[test]
    fn on_turnoff_should_turningoff_and_send_command() {
        let mut process_manager = MockProcessManager::new();
        process_manager.expect_start();
        // Expect to send stop command
        process_manager.expect_stop();
        let mut state_machine = ManagerStateMachine::new(process_manager);
        state_machine.action_start_bluetooth(0);
        state_machine.action_on_bluetooth_started(0, 0);
        state_machine.action_stop_bluetooth(0);
        assert_eq!(*state_machine.state.try_lock().unwrap(), State::TurningOff);
    }

    #[test]
    fn on_bluetooth_stopped() {
        let mut process_manager = MockProcessManager::new();
        process_manager.expect_start();
        // Expect to start again
        process_manager.expect_start();
        let mut state_machine = ManagerStateMachine::new(process_manager);
        state_machine.action_start_bluetooth(0);
        state_machine.action_on_bluetooth_started(0, 0);
        assert_eq!(state_machine.action_on_bluetooth_stopped(), false);
        assert_eq!(*state_machine.state.try_lock().unwrap(), State::TurningOn);
    }

    #[test]
    fn turningoff_bluetooth_down_should_off() {
        let mut process_manager = MockProcessManager::new();
        process_manager.expect_start();
        process_manager.expect_stop();
        let mut state_machine = ManagerStateMachine::new(process_manager);
        state_machine.action_start_bluetooth(0);
        state_machine.action_on_bluetooth_started(0, 0);
        state_machine.action_stop_bluetooth(0);
        state_machine.action_on_bluetooth_stopped();
        assert_eq!(*state_machine.state.try_lock().unwrap(), State::Off);
    }

    #[test]
    fn restart_bluetooth() {
        let mut process_manager = MockProcessManager::new();
        process_manager.expect_start();
        process_manager.expect_stop();
        process_manager.expect_start();
        let mut state_machine = ManagerStateMachine::new(process_manager);
        state_machine.action_start_bluetooth(0);
        state_machine.action_on_bluetooth_started(0, 0);
        state_machine.action_stop_bluetooth(0);
        state_machine.action_on_bluetooth_stopped();
        state_machine.action_start_bluetooth(0);
        state_machine.action_on_bluetooth_started(0, 0);
        assert_eq!(*state_machine.state.try_lock().unwrap(), State::On);
    }

    #[test]
    fn path_to_hci_interface() {
        assert_eq!(
            get_hci_interface_from_pid_file_name("/var/run/bluetooth/bluetooth0.pid"),
            Some(0)
        );
        assert_eq!(
            get_hci_interface_from_pid_file_name("/var/run/bluetooth/bluetooth1.pid"),
            Some(1)
        );
        assert_eq!(
            get_hci_interface_from_pid_file_name("/var/run/bluetooth/bluetooth10.pid"),
            Some(10)
        );
        assert_eq!(get_hci_interface_from_pid_file_name("/var/run/bluetooth/garbage"), None);

        assert_eq!(get_hci_interface_from_device("/sys/class/bluetooth/hci0"), Some(0));
        assert_eq!(get_hci_interface_from_device("/sys/class/bluetooth/hci1"), Some(1));
        assert_eq!(get_hci_interface_from_device("/sys/class/bluetooth/hci10"), Some(10));
        assert_eq!(get_hci_interface_from_device("/sys/class/bluetooth/eth0"), None);
    }
}
