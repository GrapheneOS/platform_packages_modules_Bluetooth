//! Floss Bluetooth stack.
//!
//! This crate provides the API implementation of the Fluoride/GD Bluetooth
//! stack, independent of any RPC projection.

#[macro_use]
extern crate num_derive;

pub mod battery_manager;
pub mod battery_provider_manager;
pub mod bluetooth;
pub mod bluetooth_adv;
pub mod bluetooth_gatt;
pub mod bluetooth_media;
pub mod callbacks;
pub mod socket_manager;
pub mod suspend;
pub mod uuid;

use log::debug;
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc::channel;
use tokio::sync::mpsc::{Receiver, Sender};

use crate::bluetooth::Bluetooth;
use crate::bluetooth_gatt::BluetoothGatt;
use crate::bluetooth_media::{BluetoothMedia, MediaActions};
use crate::socket_manager::{BluetoothSocketManager, SocketActions};
use crate::suspend::Suspend;
use bt_topshim::{
    btif::BaseCallbacks,
    profiles::{
        a2dp::A2dpCallbacks, avrcp::AvrcpCallbacks, gatt::GattAdvCallbacks,
        gatt::GattAdvInbandCallbacks, gatt::GattClientCallbacks, gatt::GattScannerCallbacks,
        gatt::GattServerCallbacks, hfp::HfpCallbacks, hid_host::HHCallbacks, sdp::SdpCallbacks,
    },
};

/// Message types that are sent to the stack main dispatch loop.
pub enum Message {
    // Callbacks from libbluetooth
    A2dp(A2dpCallbacks),
    Avrcp(AvrcpCallbacks),
    Base(BaseCallbacks),
    GattClient(GattClientCallbacks),
    GattServer(GattServerCallbacks),
    LeScanner(GattScannerCallbacks),
    LeAdvInband(GattAdvInbandCallbacks),
    LeAdv(GattAdvCallbacks),
    HidHost(HHCallbacks),
    Hfp(HfpCallbacks),
    Sdp(SdpCallbacks),

    // Actions within the stack
    Media(MediaActions),
    MediaCallbackDisconnected(u32),

    // Client callback disconnections
    AdapterCallbackDisconnected(u32),
    ConnectionCallbackDisconnected(u32),

    // Update list of found devices and remove old instances.
    DeviceFreshnessCheck,

    // Suspend related
    SuspendCallbackRegistered(u32),
    SuspendCallbackDisconnected(u32),

    // Scanner related
    ScannerCallbackDisconnected(u32),

    // Advertising related
    AdvertiserCallbackDisconnected(u32),

    SocketManagerActions(SocketActions),
    SocketManagerCallbackDisconnected(u32),
}

/// Umbrella class for the Bluetooth stack.
pub struct Stack {}

impl Stack {
    /// Creates an mpsc channel for passing messages to the main dispatch loop.
    pub fn create_channel() -> (Sender<Message>, Receiver<Message>) {
        channel::<Message>(1)
    }

    /// Runs the main dispatch loop.
    pub async fn dispatch(
        mut rx: Receiver<Message>,
        bluetooth: Arc<Mutex<Box<Bluetooth>>>,
        bluetooth_gatt: Arc<Mutex<Box<BluetoothGatt>>>,
        bluetooth_media: Arc<Mutex<Box<BluetoothMedia>>>,
        suspend: Arc<Mutex<Box<Suspend>>>,
        bluetooth_socketmgr: Arc<Mutex<Box<BluetoothSocketManager>>>,
    ) {
        loop {
            let m = rx.recv().await;

            if m.is_none() {
                eprintln!("Message dispatch loop quit");
                break;
            }

            match m.unwrap() {
                Message::A2dp(a) => {
                    bluetooth_media.lock().unwrap().dispatch_a2dp_callbacks(a);
                }

                Message::Avrcp(av) => {
                    bluetooth_media.lock().unwrap().dispatch_avrcp_callbacks(av);
                }

                Message::Base(b) => {
                    bluetooth.lock().unwrap().dispatch_base_callbacks(b);
                }

                Message::GattClient(m) => {
                    bluetooth_gatt.lock().unwrap().dispatch_gatt_client_callbacks(m);
                }

                Message::GattServer(m) => {
                    // TODO(b/193685149): dispatch GATT server callbacks.
                    debug!("Unhandled Message::GattServer: {:?}", m);
                }

                Message::LeScanner(m) => {
                    bluetooth_gatt.lock().unwrap().dispatch_le_scanner_callbacks(m);
                }

                Message::LeAdvInband(m) => {
                    debug!("Received LeAdvInband message: {:?}. This is unexpected!", m);
                }

                Message::LeAdv(m) => {
                    bluetooth_gatt.lock().unwrap().dispatch_le_adv_callbacks(m);
                }

                Message::Hfp(hf) => {
                    bluetooth_media.lock().unwrap().dispatch_hfp_callbacks(hf);
                }

                Message::HidHost(h) => {
                    bluetooth.lock().unwrap().dispatch_hid_host_callbacks(h);
                }

                Message::Sdp(s) => {
                    bluetooth.lock().unwrap().dispatch_sdp_callbacks(s);
                }

                Message::Media(action) => {
                    bluetooth_media.lock().unwrap().dispatch_media_actions(action);
                }

                Message::MediaCallbackDisconnected(cb_id) => {
                    bluetooth_media.lock().unwrap().remove_callback(cb_id);
                }

                Message::AdapterCallbackDisconnected(id) => {
                    bluetooth.lock().unwrap().adapter_callback_disconnected(id);
                }

                Message::ConnectionCallbackDisconnected(id) => {
                    bluetooth.lock().unwrap().connection_callback_disconnected(id);
                }

                Message::DeviceFreshnessCheck => {
                    bluetooth.lock().unwrap().trigger_freshness_check();
                }

                Message::SuspendCallbackRegistered(id) => {
                    suspend.lock().unwrap().callback_registered(id);
                }

                Message::SuspendCallbackDisconnected(id) => {
                    suspend.lock().unwrap().remove_callback(id);
                }

                Message::ScannerCallbackDisconnected(id) => {
                    bluetooth_gatt.lock().unwrap().remove_scanner_callback(id);
                }

                Message::AdvertiserCallbackDisconnected(id) => {
                    bluetooth_gatt.lock().unwrap().remove_adv_callback(id);
                }

                Message::SocketManagerActions(action) => {
                    bluetooth_socketmgr.lock().unwrap().handle_actions(action);
                }
                Message::SocketManagerCallbackDisconnected(id) => {
                    bluetooth_socketmgr.lock().unwrap().remove_callback(id);
                }
            }
        }
    }
}

/// Signifies that the object may be a proxy to a remote RPC object.
///
/// An object that implements RPCProxy trait signifies that the object may be a proxy to a remote
/// RPC object. Therefore the object may be disconnected and thus should implement
/// `register_disconnect` to let others observe the disconnection event.
pub trait RPCProxy {
    /// Registers disconnect observer that will be notified when the remote object is disconnected.
    fn register_disconnect(&mut self, _f: Box<dyn Fn(u32) + Send>) -> u32 {
        0
    }

    /// Returns the ID of the object. For example this would be an object path in D-Bus RPC.
    fn get_object_id(&self) -> String {
        String::from("")
    }

    /// Unregisters callback with this id.
    fn unregister(&mut self, _id: u32) -> bool {
        false
    }

    /// Makes this object available for remote call.
    fn export_for_rpc(self: Box<Self>) {}
}
