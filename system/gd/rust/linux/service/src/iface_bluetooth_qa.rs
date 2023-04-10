use btstack::bluetooth_qa::IBluetoothQA;

use dbus_macros::generate_dbus_exporter;

struct IBluetoothQADBus {}

#[generate_dbus_exporter(export_bluetooth_qa_dbus_intf, "org.chromium.bluetooth.BluetoothQA")]
impl IBluetoothQA for IBluetoothQADBus {}
