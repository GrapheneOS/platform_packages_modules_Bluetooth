//! Fluoride/GD Bluetooth stack.
//!
//! This crate provides the API implementation of the Fluoride/GD Bluetooth stack, independent of
//! any RPC projection.

#[macro_use]
extern crate num_derive;

pub mod bluetooth;
pub mod bluetooth_gatt;

use bt_topshim::btif::BaseCallbacks;

use std::convert::TryInto;
use std::fmt::{Debug, Formatter, Result};
use std::sync::{Arc, Mutex};

use tokio::sync::mpsc::channel;
use tokio::sync::mpsc::{Receiver, Sender};

use crate::bluetooth::Bluetooth;

/// Represents a Bluetooth address.
// TODO: Add support for LE random addresses.
#[derive(Copy, Clone)]
pub struct BDAddr {
    val: [u8; 6],
}

impl Debug for BDAddr {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        f.write_fmt(format_args!(
            "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
            self.val[0], self.val[1], self.val[2], self.val[3], self.val[4], self.val[5]
        ))
    }
}

impl Default for BDAddr {
    fn default() -> Self {
        Self { val: [0; 6] }
    }
}

impl ToString for BDAddr {
    fn to_string(&self) -> String {
        String::from(format!(
            "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
            self.val[0], self.val[1], self.val[2], self.val[3], self.val[4], self.val[5]
        ))
    }
}

impl BDAddr {
    /// Constructs a BDAddr from a vector of 6 bytes.
    fn from_byte_vec(raw_addr: &Vec<u8>) -> Option<BDAddr> {
        if let Ok(val) = raw_addr.clone().try_into() {
            return Some(BDAddr { val });
        }
        None
    }

    fn from_string(addr_str: String) -> Option<BDAddr> {
        let s = addr_str.split(':').collect::<Vec<&str>>();

        if s.len() != 6 {
            return None;
        }

        let mut raw: [u8; 6] = [0; 6];
        for i in 0..s.len() {
            raw[i] = match u8::from_str_radix(s[i], 16) {
                Ok(res) => res,
                Err(_) => {
                    return None;
                }
            };
        }

        Some(BDAddr { val: raw })
    }
}

/// Message types that are sent to the stack main dispatch loop.
pub enum Message {
    Base(BaseCallbacks),
    BluetoothCallbackDisconnected(u32),
}

/// Umbrella class for the Bluetooth stack.
pub struct Stack {}

impl Stack {
    /// Creates an mpsc channel for passing messages to the main dispatch loop.
    pub fn create_channel() -> (Sender<Message>, Receiver<Message>) {
        channel::<Message>(1)
    }

    /// Runs the main dispatch loop.
    pub async fn dispatch(mut rx: Receiver<Message>, bluetooth: Arc<Mutex<Bluetooth>>) {
        loop {
            let m = rx.recv().await;

            if m.is_none() {
                eprintln!("Message dispatch loop quit");
                break;
            }

            match m.unwrap() {
                Message::Base(b) => {
                    bluetooth.lock().unwrap().dispatch_base_callbacks(b);
                }

                Message::BluetoothCallbackDisconnected(id) => {
                    bluetooth.lock().unwrap().callback_disconnected(id);
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
    fn register_disconnect(&mut self, f: Box<dyn Fn() + Send>);
}
