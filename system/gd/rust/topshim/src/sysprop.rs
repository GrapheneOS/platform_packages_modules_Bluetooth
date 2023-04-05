//! Shim to provide more structured access to sysprops from Rust.

use crate::bindings::root as bindings;
use crate::utils::LTCheckedPtr;

/// List of properties accessible to Rust. Add new ones here as they become
/// necessary.
pub enum Property {
    // bluetooth.core.le
    LeInquiryScanInterval,
    LeInquiryScanWindow,
}

impl Into<(Vec<u8>, i32)> for Property {
    /// Convert the property into the property key name and a default value.
    fn into(self) -> (Vec<u8>, i32) {
        let (key, default_value) = match self {
            // Inquiry scan interval  = N * 0.625 ms; value of 432 = 270ms
            Property::LeInquiryScanInterval => ("bluetooth.core.le.inquiry_scan_interval", 430),

            //Inquiry scan window  = N * 0.625 ms; value of 216 = 135ms
            Property::LeInquiryScanWindow => ("bluetooth.core.le.inquiry_scan_window", 216),
        };

        (key.bytes().chain("\0".bytes()).collect::<Vec<u8>>(), default_value)
    }
}

/// Get the i32 value for a system property.
pub fn get_i32(prop: Property) -> i32 {
    let (key, default_value) = prop.into();
    let key_cptr = LTCheckedPtr::from(&key);

    unsafe {
        bindings::osi_property_get_int32(
            key_cptr.cast_into::<std::os::raw::c_char>(),
            default_value,
        )
    }
}
