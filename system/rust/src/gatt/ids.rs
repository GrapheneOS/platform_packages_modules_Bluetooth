//! These are strongly-typed identifiers representing the various objects
//! interacted with, mostly over FFI

/// The handle of a given ATT attribute
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct AttHandle(pub u16);
