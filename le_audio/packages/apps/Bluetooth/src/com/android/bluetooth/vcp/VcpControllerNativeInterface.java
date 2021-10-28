/*
 *Copyright (c) 2020, The Linux Foundation. All rights reserved.
 */

/*
 * Copyright 2018 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * Defines the native interface that is used by state machine/service to
 * send or receive messages from the native stack. This file is registered
 * for the native methods in the corresponding JNI C++ file.
 */
package com.android.bluetooth.vcp;

import android.bluetooth.BluetoothAdapter;
import android.bluetooth.BluetoothDevice;
import android.util.Log;

import com.android.bluetooth.Utils;
import com.android.internal.annotations.GuardedBy;
import com.android.internal.annotations.VisibleForTesting;

/**
 * Vcp Controller Native Interface to/from JNI.
 */
public class VcpControllerNativeInterface {
    private static final String TAG = "VcpControllerNativeInterface";
    private static final boolean DBG = true;
    private BluetoothAdapter mAdapter;

    @GuardedBy("INSTANCE_LOCK")
    private static VcpControllerNativeInterface sInstance;
    private static final Object INSTANCE_LOCK = new Object();

    static {
        classInitNative();
    }

    private VcpControllerNativeInterface() {
        mAdapter = BluetoothAdapter.getDefaultAdapter();
        if (mAdapter == null) {
            Log.wtfStack(TAG, "No Bluetooth Adapter Available");
        }
    }

    /**
     * Get singleton instance.
     */
    public static VcpControllerNativeInterface getInstance() {
        synchronized (INSTANCE_LOCK) {
            if (sInstance == null) {
                sInstance = new VcpControllerNativeInterface();
            }
            return sInstance;
        }
    }

    /**
     * Initializes the native interface.
     *
     * priorities to configure.
     */
    @VisibleForTesting(visibility = VisibleForTesting.Visibility.PACKAGE)
    public void init() {
        initNative();
    }

    /**
     * Cleanup the native interface.
     */
    @VisibleForTesting(visibility = VisibleForTesting.Visibility.PACKAGE)
    public void cleanup() {
        cleanupNative();
    }

    /**
     * Initiates Vcp connection to a remote device.
     *
     * @param device the remote device
     * @return true on success, otherwise false.
     */
    @VisibleForTesting(visibility = VisibleForTesting.Visibility.PACKAGE)
    public boolean connectVcp(BluetoothDevice device, boolean isDirect) {
        return connectVcpNative(getByteAddress(device), isDirect);
    }

    /**
     * Disconnects Vcp from a remote device.
     *
     * @param device the remote device
     * @return true on success, otherwise false.
     */
    @VisibleForTesting(visibility = VisibleForTesting.Visibility.PACKAGE)
    public boolean disconnectVcp(BluetoothDevice device) {
        return disconnectVcpNative(getByteAddress(device));
    }

    /**
     * Sets the Vcp Abs volume
     * @param volume
     */
    @VisibleForTesting(visibility = VisibleForTesting.Visibility.PACKAGE)
    public boolean setAbsVolume(int volume, BluetoothDevice device) {
        return setAbsVolumeNative(volume, getByteAddress(device));
    }

    @VisibleForTesting(visibility = VisibleForTesting.Visibility.PACKAGE)
    public boolean mute(BluetoothDevice device) {
        return muteNative(getByteAddress(device));
    }

    @VisibleForTesting(visibility = VisibleForTesting.Visibility.PACKAGE)
    public boolean unmute(BluetoothDevice device) {
        return unmuteNative(getByteAddress(device));
    }

    private BluetoothDevice getDevice(byte[] address) {
        return mAdapter.getRemoteDevice(address);
    }

    private byte[] getByteAddress(BluetoothDevice device) {
        if (device == null) {
            return Utils.getBytesFromAddress("00:00:00:00:00:00");
        }
        return Utils.getBytesFromAddress(device.getAddress());
    }

    private void sendMessageToService(VcpStackEvent event) {
        VcpController service = VcpController.getVcpController();
        if (service != null) {
            service.messageFromNative(event);
        } else {
            Log.e(TAG, "Event ignored, service not available: " + event);
        }
    }

    // Callbacks from the native stack back into the Java framework.
    // All callbacks are routed via the Service which will disambiguate which
    // state machine the message should be routed to.
    private void onConnectionStateChanged(int state, byte[] address) {
        VcpStackEvent event =
                new VcpStackEvent(VcpStackEvent.EVENT_TYPE_CONNECTION_STATE_CHANGED);
        event.device = getDevice(address);
        event.valueInt1 = state;

        if (DBG) {
            Log.d(TAG, "onConnectionStateChanged: " + event);
        }
        sendMessageToService(event);
    }

    private void OnVolumeStateChange(int volume, int mute, byte[] address) {
        VcpStackEvent event = new VcpStackEvent(
                VcpStackEvent.EVENT_TYPE_VOLUME_STATE_CHANGED);
        event.device = getDevice(address);
        event.valueInt1 = volume;
        event.valueInt2 = mute;

        if (DBG) {
            Log.d(TAG, "OnVolumeStateChange: " + event);
        }
        sendMessageToService(event);
    }

    private void OnVolumeFlagsChange(int flags, byte[] address) {
        VcpStackEvent event = new VcpStackEvent(
                VcpStackEvent.EVENT_TYPE_VOLUME_FLAGS_CHANGED);
        event.device = getDevice(address);
        event.valueInt1 = flags;

        if (DBG) {
            Log.d(TAG, "OnVolumeFlagsChange: " + event);
        }
        sendMessageToService(event);
    }

    // Native methods that call into the JNI interface
    private static native void classInitNative();
    private native void initNative();
    private native void cleanupNative();
    private native boolean connectVcpNative(byte[] address, boolean isDirect);
    private native boolean disconnectVcpNative(byte[] address);
    private native boolean setAbsVolumeNative(int volume, byte[] address);
    private native boolean muteNative(byte[] address);
    private native boolean unmuteNative(byte[] address);
}

