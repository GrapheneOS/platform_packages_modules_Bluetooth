//! This library provides access to Linux uinput.

use libc;
use log::error;
use std::ffi::CString;

// uinput setup constants
const UINPUT_MAX_NAME_SIZE: usize = 80;
const ABS_MAX: usize = 0x3F;
const BUS_BLUETOOTH: u16 = 0x05;

#[repr(C, packed)]
struct UInputId {
    bustype: libc::c_ushort,
    vendor: libc::c_ushort,
    product: libc::c_ushort,
    version: libc::c_ushort,
}

#[repr(C, packed)]
struct UInputDev {
    name: [libc::c_char; UINPUT_MAX_NAME_SIZE],
    id: UInputId,
    ff_effects_max: libc::c_int,
    absmax: [libc::c_int; ABS_MAX + 1],
    absmin: [libc::c_int; ABS_MAX + 1],
    absfuzz: [libc::c_int; ABS_MAX + 1],
    absflat: [libc::c_int; ABS_MAX + 1],
}

/// A struct that holds the uinput object. It consists of a file descriptor fetched from the kernel
/// and a device struct which contains the information required to construct an uinput device.
#[allow(dead_code)]
pub struct UInput {
    fd: i32,
    device: UInputDev,
}

impl Drop for UInput {
    fn drop(&mut self) {
        self.close();
    }
}

impl UInput {
    /// Create a new UInput object.
    pub fn new() -> Self {
        UInput {
            fd: -1,
            device: UInputDev {
                name: [0; UINPUT_MAX_NAME_SIZE],
                id: UInputId { bustype: BUS_BLUETOOTH, vendor: 0, product: 0, version: 0 },
                ff_effects_max: 0,
                absmax: [0; ABS_MAX + 1],
                absmin: [0; ABS_MAX + 1],
                absfuzz: [0; ABS_MAX + 1],
                absflat: [0; ABS_MAX + 1],
            },
        }
    }

    /// Return true if uinput is open and a valid fd is retrieved.
    pub fn is_initialized(&self) -> bool {
        self.fd >= 0
    }

    /// Initialize a uinput device with kernel.
    #[allow(temporary_cstring_as_ptr)]
    pub fn init(&mut self) {
        if self.is_initialized() {
            return;
        }

        let mut fd = -1;

        unsafe {
            for path in ["/dev/uinput", "/dev/input/uinput", "/dev/misc/uinput"] {
                fd = libc::open(CString::new(path).unwrap().as_ptr().cast(), libc::O_RDWR);
                if fd >= 0 {
                    break;
                }
            }
        }

        if fd < -1 {
            error!("Failed to open uinput");
            return;
        }
        self.fd = fd;
    }

    /// Close the uinput device with kernel if there is one.
    pub fn close(&mut self) {
        if self.is_initialized() {
            unsafe {
                libc::close(self.fd);
            }
            self.fd = -1;
        }
    }
}
