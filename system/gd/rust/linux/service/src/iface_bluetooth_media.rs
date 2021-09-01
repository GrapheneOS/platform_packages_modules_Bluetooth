use bt_topshim::profiles::a2dp::PresentationPosition;
use btstack::bluetooth_media::{IBluetoothMedia, IBluetoothMediaCallback};
use btstack::RPCProxy;

use dbus::arg::RefArg;
use dbus::strings::Path;

use dbus_macros::{dbus_method, dbus_propmap, dbus_proxy_obj, generate_dbus_exporter};

use dbus_projection::DisconnectWatcher;

use crate::dbus_arg::{DBusArg, DBusArgError, RefArgToRust};

#[allow(dead_code)]
struct BluetoothMediaCallbackDBus {}

#[dbus_proxy_obj(BluetoothMediaCallback, "org.chromium.bluetooth.BluetoothMediaCallback")]
impl IBluetoothMediaCallback for BluetoothMediaCallbackDBus {
    #[dbus_method("OnBluetoothAudioDeviceAdded")]
    fn on_bluetooth_audio_device_added(
        &self,
        addr: String,
        sample_rate: i32,
        bits_per_sample: i32,
        channel_mode: i32,
    ) {
    }

    #[dbus_method("OnBluetoothAudioDeviceRemoved")]
    fn on_bluetooth_audio_device_removed(&self, addr: String) {}

    #[dbus_method("OnAbsoluteVolumeSupportedChanged")]
    fn on_absolute_volume_supported_changed(&self, supported: bool) {}

    #[dbus_method("OnAbsoluteVolumeChanged")]
    fn on_absolute_volume_changed(&self, volume: i32) {}
}

#[allow(dead_code)]
struct IBluetoothMediaDBus {}

#[dbus_propmap(PresentationPosition)]
pub struct PresentationPositionDBus {
    remote_delay_report_ns: u64,
    total_bytes_read: u64,
    data_position_sec: i64,
    data_position_nsec: i32,
}

#[generate_dbus_exporter(export_bluetooth_media_dbus_obj, "org.chromium.bluetooth.BluetoothMedia")]
impl IBluetoothMedia for IBluetoothMediaDBus {
    #[dbus_method("RegisterCallback")]
    fn register_callback(&mut self, callback: Box<dyn IBluetoothMediaCallback + Send>) -> bool {
        true
    }

    #[dbus_method("Initialize")]
    fn initialize(&mut self) -> bool {
        true
    }

    #[dbus_method("Cleanup")]
    fn cleanup(&mut self) -> bool {
        true
    }

    #[dbus_method("Connect")]
    fn connect(&mut self, device: String) {}

    #[dbus_method("SetActiveDevice")]
    fn set_active_device(&mut self, device: String) {}

    #[dbus_method("Disconnect")]
    fn disconnect(&mut self, device: String) {}

    #[dbus_method("SetAudioConfig")]
    fn set_audio_config(
        &mut self,
        sample_rate: i32,
        bits_per_sample: i32,
        channel_mode: i32,
    ) -> bool {
        true
    }

    #[dbus_method("SetVolume")]
    fn set_volume(&mut self, volume: i32) {}

    #[dbus_method("StartAudioRequest")]
    fn start_audio_request(&mut self) {}

    #[dbus_method("StopAudioRequest")]
    fn stop_audio_request(&mut self) {}

    #[dbus_method("GetPresentationPosition")]
    fn get_presentation_position(&mut self) -> PresentationPosition {
        PresentationPosition {
            remote_delay_report_ns: 0,
            total_bytes_read: 0,
            data_position_sec: 0,
            data_position_nsec: 0,
        }
    }
}
