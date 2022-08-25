//! This library provides access to Linux uinput.

use libc;
use log::error;
use nix;
use std::ffi::CString;
use std::mem;
use std::slice;

// Supported AVRCP Keys
const AVC_PLAY: u8 = 0x44;
const AVC_STOP: u8 = 0x45;
const AVC_PAUSE: u8 = 0x46;
const AVC_REWIND: u8 = 0x48;
const AVC_FAST_FORWAED: u8 = 0x49;
const AVC_FORWARD: u8 = 0x4B;
const AVC_BACKWARD: u8 = 0x4C;

// Supported uinput keys
const KEY_PLAYPAUSE: libc::c_uint = 164;
const KEY_STOPCD: libc::c_uint = 166;
const KEY_REWIND: libc::c_uint = 168;
const KEY_FASTFORWAED: libc::c_uint = 208;
const KEY_NEXTSONG: libc::c_uint = 163;
const KEY_PREVIOUSSONG: libc::c_uint = 165;

// uinput setup constants
const UINPUT_MAX_NAME_SIZE: usize = 80;
const ABS_MAX: usize = 0x3F;
const BUS_BLUETOOTH: u16 = 0x05;
const UINPUT_IOCTL_BASE: char = 'U';

const EV_SYN: libc::c_int = 0x00;
const EV_KEY: libc::c_int = 0x01;
const EV_REL: libc::c_int = 0x02;
const EV_REP: libc::c_int = 0x14;

const SYN_REPORT: libc::c_int = 0;

const UI_DEV_CREATE: u64 = nix::request_code_none!(UINPUT_IOCTL_BASE, 1);
const UI_DEV_DESTROY: u64 = nix::request_code_none!(UINPUT_IOCTL_BASE, 2);
const UI_SET_EVBIT: u64 =
    nix::request_code_write!(UINPUT_IOCTL_BASE, 100, mem::size_of::<libc::c_int>());
const UI_SET_PHYS: u64 =
    nix::request_code_write!(UINPUT_IOCTL_BASE, 108, mem::size_of::<libc::c_char>());
const UI_SET_KEYBIT: u64 =
    nix::request_code_write!(UINPUT_IOCTL_BASE, 101, mem::size_of::<libc::c_int>());

// Conversion key map from AVRCP keys to uinput keys.
#[allow(dead_code)]
struct KeyMap {
    avc: u8,
    uinput: libc::c_uint,
}

const KEY_MAP: [KeyMap; 7] = [
    KeyMap { avc: AVC_PLAY, uinput: KEY_PLAYPAUSE },
    KeyMap { avc: AVC_STOP, uinput: KEY_STOPCD },
    KeyMap { avc: AVC_PAUSE, uinput: KEY_PLAYPAUSE },
    KeyMap { avc: AVC_REWIND, uinput: KEY_REWIND },
    KeyMap { avc: AVC_FAST_FORWAED, uinput: KEY_FASTFORWAED },
    KeyMap { avc: AVC_FORWARD, uinput: KEY_NEXTSONG },
    KeyMap { avc: AVC_BACKWARD, uinput: KEY_PREVIOUSSONG },
];

#[repr(C, packed)]
struct UInputId {
    bustype: libc::c_ushort,
    vendor: libc::c_ushort,
    product: libc::c_ushort,
    version: libc::c_ushort,
}

impl Default for UInputId {
    fn default() -> Self {
        UInputId { bustype: BUS_BLUETOOTH, vendor: 0, product: 0, version: 0 }
    }
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

impl Default for UInputDev {
    fn default() -> Self {
        UInputDev {
            name: [0; UINPUT_MAX_NAME_SIZE],
            id: UInputId::default(),
            ff_effects_max: 0,
            absmax: [0; ABS_MAX + 1],
            absmin: [0; ABS_MAX + 1],
            absfuzz: [0; ABS_MAX + 1],
            absflat: [0; ABS_MAX + 1],
        }
    }
}

impl UInputDev {
    pub fn serialize(&mut self) -> &[u8] {
        unsafe {
            slice::from_raw_parts(
                (self as *const UInputDev) as *const u8,
                mem::size_of::<UInputDev>(),
            )
        }
    }
}

#[repr(C, packed)]
struct UInputEvent {
    time: libc::timeval,
    event_type: libc::c_ushort,
    code: libc::c_ushort,
    value: libc::c_int,
}

impl UInputEvent {
    pub fn serialize(&mut self) -> &[u8] {
        unsafe {
            slice::from_raw_parts(
                (self as *const UInputEvent) as *const u8,
                mem::size_of::<UInputEvent>(),
            )
        }
    }
}

/// A struct that holds the uinput object. It consists of a file descriptor fetched from the kernel
/// and a device struct which contains the information required to construct an uinput device.
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
        UInput { fd: -1, device: UInputDev::default() }
    }

    /// Return true if uinput is open and a valid fd is retrieved.
    pub fn is_initialized(&self) -> bool {
        self.fd >= 0
    }

    /// Initialize a uinput device with kernel.
    #[allow(temporary_cstring_as_ptr)]
    pub fn init(&mut self, mut name: String, addr: String) {
        if self.is_initialized() {
            return;
        }

        // Truncate the device name if over the max size allowed.
        name.truncate(UINPUT_MAX_NAME_SIZE);
        for (i, ch) in name.chars().enumerate() {
            self.device.name[i] = ch as libc::c_char;
        }

        let mut fd = -1;

        unsafe {
            for path in ["/dev/uinput", "/dev/input/uinput", "/dev/misc/uinput"] {
                fd = libc::open(CString::new(path).unwrap().as_ptr().cast(), libc::O_RDWR);
                if fd >= 0 {
                    break;
                }
            }

            if fd < -1 {
                error!("Failed to open uinput: {}", std::io::Error::last_os_error());
                return;
            }

            if libc::write(
                fd,
                self.device.serialize().as_ptr() as *const libc::c_void,
                mem::size_of::<UInputDev>(),
            ) < 0
            {
                error!("Can't write device information: {}", std::io::Error::last_os_error());
                libc::close(fd);
                return;
            }

            libc::ioctl(fd, UI_SET_EVBIT, EV_KEY);
            libc::ioctl(fd, UI_SET_EVBIT, EV_REL);
            libc::ioctl(fd, UI_SET_EVBIT, EV_REP);
            libc::ioctl(fd, UI_SET_EVBIT, EV_SYN);
            libc::ioctl(fd, UI_SET_PHYS, addr);

            for key_map in KEY_MAP {
                libc::ioctl(fd, UI_SET_KEYBIT, key_map.uinput);
            }

            if libc::ioctl(fd, UI_DEV_CREATE, 0) < 0 {
                error!("Can't create uinput device: {}", std::io::Error::last_os_error());
                libc::close(fd);
                return;
            }
        }

        self.fd = fd;
    }

    /// Close the uinput device with kernel if there is one.
    pub fn close(&mut self) {
        if self.is_initialized() {
            unsafe {
                libc::ioctl(self.fd, UI_DEV_DESTROY, 0);
                libc::close(self.fd);
            }
            self.fd = -1;
            self.device = UInputDev::default();
        }
    }

    fn send_event(
        &mut self,
        event_type: libc::c_ushort,
        code: libc::c_ushort,
        value: libc::c_int,
    ) -> i32 {
        let mut event = UInputEvent {
            time: libc::timeval { tv_sec: 0, tv_usec: 0 },
            event_type: event_type,
            code: code,
            value: value,
        };

        unsafe {
            libc::write(
                self.fd,
                event.serialize().as_ptr() as *const libc::c_void,
                mem::size_of::<UInputDev>(),
            )
            .try_into()
            .unwrap()
        }
    }

    /// Send key event to the uinput if the device is initialized.
    pub fn send_key(&mut self, key: u8, value: u8) -> Result<(), String> {
        let mut uinput_key: libc::c_ushort = 0;

        for key_map in KEY_MAP {
            if key_map.avc == key {
                uinput_key = key_map.uinput.try_into().unwrap();
            }
        }

        if uinput_key == 0 {
            return Err(format!("AVRCP key: {} is not supported", key));
        }

        if self.is_initialized() {
            if self.send_event(EV_KEY.try_into().unwrap(), uinput_key, value.into()) < 0
                || self.send_event(EV_SYN.try_into().unwrap(), SYN_REPORT.try_into().unwrap(), 0)
                    < 0
            {
                return Err(format!(
                    "Failed to send uinput event: {}",
                    std::io::Error::last_os_error()
                ));
            }
            return Ok(());
        }

        Err(format!("uinput is not initialized"))
    }
}
