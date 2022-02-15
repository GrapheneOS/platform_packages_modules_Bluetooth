/*
 * Copyright 2021 HIMSA II K/S - www.himsa.com.
 * Represented by EHIMA - www.ehima.com
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
package com.android.bluetooth.le_audio;

import android.bluetooth.BluetoothAdapter;
import android.bluetooth.BluetoothDevice;
import android.util.Log;

import com.android.bluetooth.Utils;
import com.android.internal.annotations.GuardedBy;
import com.android.internal.annotations.VisibleForTesting;

/**
 * LeAudio Native Interface to/from JNI.
 */
public class LeAudioBroadcasterNativeInterface {
    private static final String TAG = "LeAudioBroadcasterNativeInterface";
    private static final boolean DBG = true;
    private BluetoothAdapter mAdapter;

    @GuardedBy("INSTANCE_LOCK")
    private static LeAudioBroadcasterNativeInterface sInstance;
    private static final Object INSTANCE_LOCK = new Object();

    static {
        classInitNative();
    }

    private LeAudioBroadcasterNativeInterface() {
        mAdapter = BluetoothAdapter.getDefaultAdapter();
        if (mAdapter == null) {
            Log.wtf(TAG, "No Bluetooth Adapter Available");
        }
    }

    /**
     * Get singleton instance.
     */
    public static LeAudioBroadcasterNativeInterface getInstance() {
        synchronized (INSTANCE_LOCK) {
            if (sInstance == null) {
                sInstance = new LeAudioBroadcasterNativeInterface();
            }
            return sInstance;
        }
    }

    private void sendMessageToService(LeAudioStackEvent event) {
        LeAudioService service = LeAudioService.getLeAudioService();
        if (service != null) {
            service.messageFromNative(event);
        } else {
            Log.e(TAG, "Event ignored, service not available: " + event);
        }
    }

    @VisibleForTesting
    public BluetoothDevice getDevice(byte[] address) {
        return mAdapter.getRemoteDevice(address);
    }

    // Callbacks from the native stack back into the Java framework.
    @VisibleForTesting
    public void onBroadcastCreated(int instanceId, boolean success) {
        if (DBG) {
            Log.d(TAG, "onBroadcastCreated: instanceId=" + instanceId);
        }
        LeAudioStackEvent event =
                new LeAudioStackEvent(LeAudioStackEvent.EVENT_TYPE_BROADCAST_CREATED);

        event.valueInt1 = instanceId;
        event.valueBool1 = success;
        sendMessageToService(event);
    }

    @VisibleForTesting
    public void onBroadcastDestroyed(int instanceId) {
        if (DBG) {
            Log.d(TAG, "onBroadcastDestroyed: instanceId=" + instanceId);
        }
        LeAudioStackEvent event =
                new LeAudioStackEvent(LeAudioStackEvent.EVENT_TYPE_BROADCAST_DESTROYED);

        event.valueInt1 = instanceId;
        sendMessageToService(event);
    }

    @VisibleForTesting
    public void onBroadcastStateChanged(int instanceId, int state) {
        if (DBG) {
            Log.d(TAG, "onBroadcastStateChanged: instanceId=" + instanceId + " state=" + state);
        }
        LeAudioStackEvent event =
                new LeAudioStackEvent(LeAudioStackEvent.EVENT_TYPE_BROADCAST_STATE);

        /* NOTICE: This is a fake device to satisfy Audio Manager in the upper
         * layers which needs a device instance to route audio streams to the
         * proper module (here it's Bluetooth). Broadcast has no concept of a
         * destination or peer device therefore this fake device was created.
         * For now it's only important that this device is a Bluetooth device.
         */
        event.device = getDevice(Utils.getBytesFromAddress("FF:FF:FF:FF:FF:FF"));
        event.valueInt1 = instanceId;
        event.valueInt2 = state;
        sendMessageToService(event);
    }

    @VisibleForTesting
    public void onBroadcastId(int instanceId, byte[] broadcastId) {
        LeAudioStackEvent event =
                new LeAudioStackEvent(LeAudioStackEvent.EVENT_TYPE_BROADCAST_ID);
        event.valueInt1 = instanceId;
        event.valueByte1 = broadcastId;
        if (DBG) {
            Log.d(TAG, "onBroadcastId: " + event);
        }
        sendMessageToService(event);
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
     * Stop the Broadcast Service.
     */
    @VisibleForTesting(visibility = VisibleForTesting.Visibility.PACKAGE)
    public void stop() {
        stopNative();
    }

    /**
     * Cleanup the native interface.
     */
    @VisibleForTesting(visibility = VisibleForTesting.Visibility.PACKAGE)
    public void cleanup() {
        cleanupNative();
    }

    /**
     * Creates LeAudio Broadcast instance.
     *
     * @param metadata metadata buffer with TLVs
     * @param audioProfile broadcast audio profile
     * @param broadcastCode optional code if broadcast should be encrypted
     */
    @VisibleForTesting(visibility = VisibleForTesting.Visibility.PACKAGE)
    public void createBroadcast(byte[] metadata, int audioProfile, byte[] broadcastCode) {
        createBroadcastNative(metadata, audioProfile, broadcastCode);
    }

    /**
     * Update LeAudio Broadcast instance metadata.
     *
     * @param instanceId broadcast instance identifier
     * @param metadata metadata buffer with TLVs
     */
    @VisibleForTesting(visibility = VisibleForTesting.Visibility.PACKAGE)
    public void updateMetadata(int instanceId, byte[] metadata) {
        updateMetadataNative(instanceId, metadata);
    }

    /**
     * Start LeAudio Broadcast instance.
     *
     * @param instanceId broadcast instance identifier
     */
    @VisibleForTesting(visibility = VisibleForTesting.Visibility.PACKAGE)
    public void startBroadcast(int instanceId) {
        startBroadcastNative(instanceId);
    }

    /**
     * Stop LeAudio Broadcast instance.
     *
     * @param instanceId broadcast instance identifier
     */
    @VisibleForTesting(visibility = VisibleForTesting.Visibility.PACKAGE)
    public void stopBroadcast(int instanceId) {
        stopBroadcastNative(instanceId);
    }

    /**
     * Pause LeAudio Broadcast instance.
     *
     * @param instanceId broadcast instance identifier
     */
    @VisibleForTesting(visibility = VisibleForTesting.Visibility.PACKAGE)
    public void pauseBroadcast(int instanceId) {
        pauseBroadcastNative(instanceId);
    }

    /**
     * Destroy LeAudio Broadcast instance.
     *
     * @param instanceId broadcast instance identifier
     */
    @VisibleForTesting(visibility = VisibleForTesting.Visibility.PACKAGE)
    public void destroyBroadcast(int instanceId) {
        destroyBroadcastNative(instanceId);
    }

    /**
     * Get LeAudio Broadcast instance advertising address.
     *
     * @param instanceId broadcast instance identifier
     */
    @VisibleForTesting(visibility = VisibleForTesting.Visibility.PACKAGE)
    public void getBroadcastId(int instanceId) {
        getBroadcastIdNative(instanceId);
    }

    /**
     * Get all LeAudio Broadcast instance states.
     */
    @VisibleForTesting(visibility = VisibleForTesting.Visibility.PACKAGE)
    public void getAllBroadcastStates() {
        getAllBroadcastStatesNative();
    }

    // Native methods that call into the JNI interface
    private static native void classInitNative();
    private native void initNative();
    private native void stopNative();
    private native void cleanupNative();
    private native void createBroadcastNative(byte[] metadata, int profile, byte[] broadcastCode);
    private native void updateMetadataNative(int instanceId, byte[] metadata);
    private native void startBroadcastNative(int instanceId);
    private native void stopBroadcastNative(int instanceId);
    private native void pauseBroadcastNative(int instanceId);
    private native void destroyBroadcastNative(int instanceId);
    private native void getBroadcastIdNative(int instanceId);
    private native void getAllBroadcastStatesNative();
}
