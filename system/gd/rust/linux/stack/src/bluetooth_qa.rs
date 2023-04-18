//! Anything related to the Qualification API (IBluetoothQA).

use crate::Message;
use tokio::sync::mpsc::Sender;

/// Defines the Qualification API
pub trait IBluetoothQA {
    fn add_media_player(&self, name: String, browsing_supported: bool);
}

pub struct BluetoothQA {
    tx: Sender<Message>,
}

impl BluetoothQA {
    pub fn new(tx: Sender<Message>) -> BluetoothQA {
        BluetoothQA { tx }
    }
}

impl IBluetoothQA for BluetoothQA {
    fn add_media_player(&self, name: String, browsing_supported: bool) {
        let txl = self.tx.clone();
        tokio::spawn(async move {
            let _ = txl.send(Message::QaAddMediaPlayer(name, browsing_supported)).await;
        });
    }
}
