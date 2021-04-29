//! Stack on top of the Bluetooth interface shim
//!
//! Helpers for dealing with the stack on top of the Bluetooth interface.

use std::any::{Any, TypeId};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tokio::runtime::{Builder, Runtime};

lazy_static! {
    // Shared runtime for topshim handlers. All async tasks will get run by this
    // runtime and this will properly serialize all spawned tasks.
    pub static ref RUNTIME: Arc<Runtime> = Arc::new(
        Builder::new_multi_thread()
            .worker_threads(1)
            .max_blocking_threads(1)
            .enable_all()
            .build()
            .unwrap()
    );
}

pub fn get_runtime() -> Arc<Runtime> {
    RUNTIME.clone()
}

lazy_static! {
    static ref CB_DISPATCHER: Arc<Mutex<DispatchContainer>> =
        Arc::new(Mutex::new(DispatchContainer { instances: HashMap::new() }));
}

type InstanceBox = Box<dyn Any + Send + Sync>;

pub struct DispatchContainer {
    instances: HashMap<TypeId, InstanceBox>,
}

impl DispatchContainer {
    pub fn get<T: 'static + Clone + Send + Sync>(&self) -> Option<T> {
        let typeid = TypeId::of::<T>();

        if let Some(value) = self.instances.get(&typeid) {
            return Some(value.downcast_ref::<T>().unwrap().clone());
        }

        None
    }

    pub fn set<T: 'static + Clone + Send + Sync>(&mut self, obj: T) -> bool {
        self.instances.insert(TypeId::of::<T>(), Box::new(obj)).is_some()
    }
}

pub fn get_dispatchers() -> Arc<Mutex<DispatchContainer>> {
    CB_DISPATCHER.clone()
}
