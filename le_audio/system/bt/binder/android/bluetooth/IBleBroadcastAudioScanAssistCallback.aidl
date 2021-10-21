/*
 * Copyright (c) 2020, The Linux Foundation. All rights reserved.
 *
 */

package android.bluetooth;

import android.bluetooth.BluetoothDevice;
import android.bluetooth.BleBroadcastSourceInfo;
import android.bluetooth.BleBroadcastSourceChannel;
import android.bluetooth.le.ScanResult;

/** @hide */
interface IBleBroadcastAudioScanAssistCallback {
    void onBleBroadcastSourceFound(in ScanResult scanres);
    void onBleBroadcastAudioSourceSelected(in BluetoothDevice device,
            in int status,
            in List<BleBroadcastSourceChannel>
            broadcastSourceChannels);

    void onBleBroadcastAudioSourceAdded(in BluetoothDevice rcvr,
                                        in byte srcId,
                                        in int status);
    void onBleBroadcastAudioSourceUpdated(in BluetoothDevice rcvr,
                                          in byte srcId,
                                          in int status);

    void onBleBroadcastPinUpdated(in BluetoothDevice rcvr,
                                  in byte srcId,
                                  in int status);
    void onBleBroadcastAudioSourceRemoved(in BluetoothDevice rcvr,
                                          in byte srcId,
                                          in int status);
}
