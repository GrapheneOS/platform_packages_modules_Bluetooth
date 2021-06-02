//! Tools to work with rustyline readline() library.

use futures::Future;

use rustyline::{Config, Editor};

use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use crate::console_blue;

/// A future that does async readline().
///
/// async readline() is implemented by spawning a thread for the blocking readline(). While this
/// readline() thread is blocked, it yields back to executor and will wake the executor up when the
/// blocked thread has proceeded and got input from readline().
pub struct AsyncReadline {
    rl: Arc<Mutex<Editor<()>>>,
    result: Arc<Mutex<Option<rustyline::Result<String>>>>,
}

impl Future for AsyncReadline {
    type Output = rustyline::Result<String>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<rustyline::Result<String>> {
        let option = self.result.lock().unwrap().take();
        if let Some(res) = option {
            return Poll::Ready(res);
        }

        let waker = cx.waker().clone();
        let result_clone = self.result.clone();
        let rl = self.rl.clone();
        std::thread::spawn(move || {
            let readline = rl.lock().unwrap().readline(console_blue!("bluetooth> "));
            *result_clone.lock().unwrap() = Some(readline);
            waker.wake();
        });

        Poll::Pending
    }
}

/// Wrapper of rustyline editor that supports async readline().
pub struct AsyncEditor {
    rl: Arc<Mutex<Editor<()>>>,
}

impl AsyncEditor {
    /// Creates new async rustyline editor.
    pub fn new() -> AsyncEditor {
        let builder = Config::builder().auto_add_history(true).history_ignore_dups(true);
        let config = builder.build();
        let rl = rustyline::Editor::<()>::with_config(config);
        AsyncEditor { rl: Arc::new(Mutex::new(rl)) }
    }

    /// Does async readline().
    ///
    /// Returns a future that will do the readline() when await-ed. This does not block the thread
    /// but rather yields to the executor while waiting for a command to be entered.
    pub fn readline(&self) -> AsyncReadline {
        AsyncReadline { rl: self.rl.clone(), result: Arc::new(Mutex::new(None)) }
    }
}
