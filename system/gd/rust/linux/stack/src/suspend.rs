//! Suspend/Resume API.

use crate::callbacks::Callbacks;
use crate::{Message, RPCProxy};
use bt_topshim::btif::BluetoothInterface;
use log::warn;
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc::Sender;

/// Defines the Suspend/Resume API.
///
/// This API is exposed by `btadapterd` and independent of the suspend/resume detection mechanism
/// which depends on the actual operating system the daemon runs on. Possible clients of this API
/// include `btmanagerd` with Chrome OS `powerd` integration, `btmanagerd` with systemd Inhibitor
/// interface, or any script hooked to suspend/resume events.
pub trait ISuspend {
    /// Adds an observer to suspend events.
    ///
    /// Returns true if the callback can be registered.
    fn register_callback(&mut self, callback: Box<dyn ISuspendCallback + Send>) -> bool;

    /// Removes an observer to suspend events.
    ///
    /// Returns true if the callback can be removed, false if `callback_id` is not recognized.
    fn unregister_callback(&mut self, callback_id: u32) -> bool;

    /// Prepares the stack for suspend, identified by `suspend_id`.
    ///
    /// Returns a positive number identifying the suspend if it can be started. If there is already
    /// a suspend, that active suspend id is returned.
    fn suspend(&self, suspend_type: SuspendType) -> u32;

    /// Undoes previous suspend preparation identified by `suspend_id`.
    ///
    /// Returns true if suspend can be resumed, and false if there is no suspend to resume.
    fn resume(&self) -> bool;
}

/// Suspend events.
pub trait ISuspendCallback: RPCProxy {
    /// Triggered when a callback is registered and given an identifier `callback_id`.
    fn on_callback_registered(&self, callback_id: u32);

    /// Triggered when the stack is ready for suspend and tell the observer the id of the suspend.
    fn on_suspend_ready(&self, suspend_id: u32);

    /// Triggered when the stack has resumed the previous suspend.
    fn on_resumed(&self, suspend_id: u32);
}

#[derive(FromPrimitive, ToPrimitive)]
#[repr(u32)]
pub enum SuspendType {
    Disconnected,
    Connected,
    Other,
}

/// Implementation of the suspend API.
pub struct Suspend {
    intf: Arc<Mutex<BluetoothInterface>>,
    tx: Sender<Message>,
    callbacks: Callbacks<dyn ISuspendCallback + Send>,
    is_connected_suspend: bool,
    was_a2dp_connected: bool,
}

impl Suspend {
    pub fn new(intf: Arc<Mutex<BluetoothInterface>>, tx: Sender<Message>) -> Suspend {
        Self {
            intf: intf,
            tx: tx.clone(),
            callbacks: Callbacks::new(tx.clone(), Message::SuspendCallbackDisconnected),
            is_connected_suspend: false,
            was_a2dp_connected: false,
        }
    }

    pub(crate) fn callback_registered(&mut self, id: u32) {
        match self.callbacks.get_by_id(id) {
            Some(callback) => callback.on_callback_registered(id),
            None => warn!("Suspend callback {} does not exist", id),
        }
    }

    pub(crate) fn remove_callback(&mut self, id: u32) -> bool {
        self.callbacks.remove_callback(id)
    }
}

impl ISuspend for Suspend {
    fn register_callback(&mut self, callback: Box<dyn ISuspendCallback + Send>) -> bool {
        let id = self.callbacks.add_callback(callback);

        let tx = self.tx.clone();
        tokio::spawn(async move {
            let _result = tx.send(Message::SuspendCallbackRegistered(id)).await;
        });

        true
    }

    fn unregister_callback(&mut self, callback_id: u32) -> bool {
        self.remove_callback(callback_id)
    }

    fn suspend(&self, suspend_type: SuspendType) -> u32 {
        let suspend_id = 1;
        match suspend_type {
            SuspendType::Connected => {
                // TODO(231345733): API For allowing classic HID only
                // TODO(230604670): check if A2DP is connected
                // TODO(224603198): save all advertiser information
            }
            SuspendType::Disconnected => {
                self.intf.lock().unwrap().clear_event_filter();
                self.intf.lock().unwrap().clear_event_mask();
            }
            SuspendType::Other => {
                // TODO(231438120): Decide what to do about Other suspend type
                // For now perform disconnected suspend flow
                self.intf.lock().unwrap().clear_event_filter();
                self.intf.lock().unwrap().clear_event_mask();
            }
        }
        self.intf.lock().unwrap().clear_filter_accept_list();
        // TODO(231435700): self.intf.lock().unwrap().disconnect_all_acls();
        self.intf.lock().unwrap().le_rand();
        self.callbacks.for_all_callbacks(|callback| {
            callback.on_suspend_ready(suspend_id);
        });
        return 1;
    }

    fn resume(&self) -> bool {
        let suspend_id = 1;
        self.intf.lock().unwrap().set_event_filter_inquiry_result_all_devices();
        self.intf.lock().unwrap().set_default_event_mask();
        if self.is_connected_suspend {
            if self.was_a2dp_connected {
                // TODO(230604670): self.intf.lock().unwrap().restore_filter_accept_list();
                // TODO(230604670): reconnect to a2dp device if connected before
            }
            // TODO(224603198): start all advertising again
        }
        self.intf.lock().unwrap().le_rand();
        self.callbacks.for_all_callbacks(|callback| {
            callback.on_resumed(suspend_id);
        });
        return true;
    }
}
