/*
 * Copyright (c) 2020, The Linux Foundation. All rights reserved.
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
package com.android.bluetooth.pc;

import android.bluetooth.BluetoothAdapter;
import android.bluetooth.BluetoothDevice;
import android.bluetooth.BluetoothCodecConfig;
import android.util.Log;

import com.android.bluetooth.Utils;
import com.android.internal.annotations.GuardedBy;
import com.android.internal.annotations.VisibleForTesting;

/**
 * PacsClient Native Interface to/from JNI.
 */
public class PacsClientNativeInterface {
    private static final String TAG = "PacsClientNativeInterface";
    private static final boolean DBG = true;
    private BluetoothAdapter mAdapter;
    private int pacs_client_id = -1;

    @GuardedBy("INSTANCE_LOCK")
    private static PacsClientNativeInterface sInstance;
    private static final Object INSTANCE_LOCK = new Object();

    static {
        classInitNative();
    }

    private PacsClientNativeInterface() {
        mAdapter = BluetoothAdapter.getDefaultAdapter();
        if (mAdapter == null) {
            Log.wtf(TAG, "No Bluetooth Adapter Available");
        }
    }

    /**
     * Get singleton instance.
     */
    public static PacsClientNativeInterface getInstance() {
        synchronized (INSTANCE_LOCK) {
            if (sInstance == null) {
                sInstance = new PacsClientNativeInterface();
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
        cleanupNative(pacs_client_id);
        pacs_client_id = -1;
    }

    /**
     * Initiates PacsClient connection to a remote device.
     *
     * @param device the remote device
     * @return true on success, otherwise false.
     */
    @VisibleForTesting(visibility = VisibleForTesting.Visibility.PACKAGE)
    public boolean connectPacsClient(BluetoothDevice device) {
        return connectPacsClientNative(pacs_client_id, getByteAddress(device));
    }

    /**
     * Disconnects PacsClient from a remote device.
     *
     * @param device the remote device
     * @return true on success, otherwise false.
     */
    @VisibleForTesting(visibility = VisibleForTesting.Visibility.PACKAGE)
    public boolean disconnectPacsClient(BluetoothDevice device) {
        return disconnectPacsClientNative(pacs_client_id, getByteAddress(device));
    }

    /**
     * Trigger service discovery for pacs
     *
     * @param device the remote device
     * @return true on success, otherwise false.
     */
    @VisibleForTesting(visibility = VisibleForTesting.Visibility.PACKAGE)
    public boolean startDiscoveryNative(BluetoothDevice device) {
        return startDiscoveryNative(pacs_client_id, getByteAddress(device));
    }

    /**
     *  get available audio contexts.
     *
     * @param device the remote device
     * @return true on success, otherwise false.
     */
    @VisibleForTesting(visibility = VisibleForTesting.Visibility.PACKAGE)
    public boolean GetAvailableAudioContexts(BluetoothDevice device) {
        return GetAvailableAudioContextsNative(pacs_client_id, getByteAddress(device));
    }

    private BluetoothDevice getDevice(byte[] address) {
        if (mAdapter != null) {
            return mAdapter.getRemoteDevice(address);
        } else {
            return null;
        }
    }

    private byte[] getByteAddress(BluetoothDevice device) {
        if (device == null) {
            return Utils.getBytesFromAddress("00:00:00:00:00:00");
        }
        return Utils.getBytesFromAddress(device.getAddress());
    }

    private void sendMessageToService(PacsClientStackEvent event) {
        PCService service = PCService.getPCService();
        if (service != null) {
            service.messageFromNative(event);
        } else {
            Log.e(TAG, "Event ignored, service not available: " + event);
        }
    }

    // Callbacks from the native stack back into the Java framework.
    // All callbacks are routed via the Service which will disambiguate which
    // state machine the message should be routed to.

    private void OnInitialized(int state, int client_id) {
        pacs_client_id = client_id;
    }

    private void onConnectionStateChanged(byte[] address, int state) {
        PacsClientStackEvent event =
                new PacsClientStackEvent(PacsClientStackEvent.EVENT_TYPE_CONNECTION_STATE_CHANGED);
        event.device = getDevice(address);
        event.valueInt1 = state;

        if (DBG) {
            Log.d(TAG, "onConnectionStateChanged: " + event);
        }
        sendMessageToService(event);
    }

    private void OnAudioContextAvailable(byte[] address, int available_contexts) {
        PacsClientStackEvent event =
                new PacsClientStackEvent(PacsClientStackEvent.EVENT_TYPE_AUDIO_CONTEXT_AVAIL);
        event.device = getDevice(address);
        event.valueInt1 = available_contexts;

        if (DBG) {
            Log.d(TAG, "OnAudioContextAvailable: " + event);
        }
        sendMessageToService(event);
    }

    private void onServiceDiscovery(BluetoothCodecConfig[] sink_pacs_array,
                                    BluetoothCodecConfig[] src_pacs_array,
                                    int sink_locations, int src_locations,
                                    int available_contexts, int supported_contexts,
                                    int status, byte[] address) {
        if (status != 0) {
            Log.e(TAG, "onServiceDiscovery: Failed" + status);
            return;
        }
        PacsClientStackEvent event = new PacsClientStackEvent(
                PacsClientStackEvent.EVENT_TYPE_SERVICE_DISCOVERY);
        event.device = getDevice(address);
        event.sinkCodecConfig = sink_pacs_array;
        event.srcCodecConfig = src_pacs_array;
        event.valueInt1 = sink_locations;
        event.valueInt2 = src_locations;
        event.valueInt3 = available_contexts;
        event.valueInt4 = supported_contexts;
        if (DBG) {
            Log.d(TAG, "onServiceDiscovery: " + event);
        }
        for (BluetoothCodecConfig codecConfig :
                    sink_pacs_array) {
                Log.d(TAG, "sink_pacs_array: " + codecConfig);
        }
        for (BluetoothCodecConfig codecConfig :
                    src_pacs_array) {
                Log.d(TAG, "src_pacs_array: " + codecConfig);
        }
        if (DBG) {
            Log.d(TAG, "sink locs: " + sink_locations + "src locs:" + src_locations);
            Log.d(TAG, "avail ctxts: " + available_contexts + "supp ctxts: " + supported_contexts);
        }

        sendMessageToService(event);
    }

    // Native methods that call into the JNI interface
    private static native void classInitNative();
    private native void initNative();
    private native void cleanupNative(int client_id);
    private native boolean connectPacsClientNative(int client_id, byte[] address);
    private native boolean disconnectPacsClientNative(int client_id, byte[] address);
    private native boolean startDiscoveryNative(int client_id, byte[] address);
    private native boolean GetAvailableAudioContextsNative(int client_id, byte[] address);
}
