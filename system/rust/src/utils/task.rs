//! This module provides utilities relating to async tasks

use std::future::Future;

use tokio::{runtime::Builder, task::LocalSet};

/// Run the supplied future on a single-threaded runtime
pub fn block_on_locally<T>(f: impl Future<Output = T>) -> T {
    LocalSet::new().block_on(&Builder::new_current_thread().build().unwrap(), f)
}
