/*
 * Copyright (c) 2020, The Linux Foundation. All rights reserved.
 */
package android.bluetooth;

import android.bluetooth.BluetoothDevice;

/**
 * APIs for Bluetooth Broadcast service
 *
 * @hide
 */
interface IBluetoothBroadcast {
    // Public API
    boolean SetBroadcast(in boolean enable, in String packageName);
    boolean SetEncryption(in boolean enable, in int enc_len,
                          in boolean use_existing, in String packageName);
    byte[] GetEncryptionKey(in String packageName);
    int GetBroadcastStatus(in String packageName);
}
