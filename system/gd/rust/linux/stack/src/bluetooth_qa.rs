//! Anything related to the Qualification API (IBluetoothQA).

use crate::Message;
use tokio::sync::mpsc::Sender;

/// Defines the Qualification API
pub trait IBluetoothQA {}

pub struct BluetoothQA {
    _tx: Sender<Message>,
}

impl BluetoothQA {
    pub fn new(tx: Sender<Message>) -> BluetoothQA {
        BluetoothQA { _tx: tx }
    }
}

impl IBluetoothQA for BluetoothQA {}
