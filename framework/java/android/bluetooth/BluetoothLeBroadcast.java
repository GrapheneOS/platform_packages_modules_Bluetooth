/*
 * Copyright 2021 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package android.bluetooth;

import android.annotation.CallbackExecutor;
import android.annotation.IntDef;
import android.annotation.NonNull;
import android.annotation.Nullable;
import android.annotation.RequiresPermission;
import android.annotation.SystemApi;
import android.bluetooth.annotations.RequiresBluetoothConnectPermission;
import android.content.Context;
import android.util.Log;

import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.Executor;

/**
 * This class provides the public APIs to control the BAP Broadcast Source profile.
 *
 * <p>BluetoothLeBroadcast is a proxy object for controlling the Bluetooth LE Broadcast Source
 * Service via IPC. Use {@link BluetoothAdapter#getProfileProxy} to get the BluetoothLeBroadcast
 * proxy object.
 *
 * @hide
 */
@SystemApi
public final class BluetoothLeBroadcast implements AutoCloseable, BluetoothProfile {
    private static final String TAG = "BluetoothLeBroadcast";
    private static final boolean DBG = true;

    /**
     * Interface for receiving events related to Broadcast Source
     * @hide
     */
    @SystemApi
    public interface Callback {
        /** @hide */
        @Retention(RetentionPolicy.SOURCE)
        @IntDef(value = {
                BluetoothStatusCodes.ERROR_UNKNOWN,
                BluetoothStatusCodes.REASON_LOCAL_APP_REQUEST,
                BluetoothStatusCodes.REASON_LOCAL_STACK_REQUEST,
                BluetoothStatusCodes.REASON_SYSTEM_POLICY,
                BluetoothStatusCodes.ERROR_HARDWARE_GENERIC,
                BluetoothStatusCodes.ERROR_BAD_PARAMETERS,
                BluetoothStatusCodes.ERROR_LOCAL_NOT_ENOUGH_RESOURCES,
                BluetoothStatusCodes.ERROR_LE_BROADCAST_INVALID_CODE,
                BluetoothStatusCodes.ERROR_LE_BROADCAST_INVALID_BROADCAST_ID,
                BluetoothStatusCodes.ERROR_LE_CONTENT_METADATA_INVALID_PROGRAM_INFO,
                BluetoothStatusCodes.ERROR_LE_CONTENT_METADATA_INVALID_LANGUAGE,
                BluetoothStatusCodes.ERROR_LE_CONTENT_METADATA_INVALID_OTHER,
        })
        @interface Reason {}

        /**
         * Callback invoked when broadcast is started, but audio may not be playing.
         *
         * Caller should wait for
         * {@link #onBroadcastMetadataChanged(int, BluetoothLeBroadcastMetadata)}
         * for the updated metadata
         *
         * @param reason for broadcast start
         * @param broadcastId as defined by the Basic Audio Profile
         * @hide
         */
        @SystemApi
        void onBroadcastStarted(@Reason int reason, int broadcastId);

        /**
         * Callback invoked when broadcast failed to start
         *
         * @param reason for broadcast start failure
         * @hide
         */
        @SystemApi
        void onBroadcastStartFailed(@Reason int reason);

        /**
         * Callback invoked when broadcast is stopped
         *
         * @param reason for broadcast stop
         * @hide
         */
        @SystemApi
        void onBroadcastStopped(@Reason int reason, int broadcastId);

        /**
         * Callback invoked when broadcast failed to stop
         *
         * @param reason for broadcast stop failure
         * @hide
         */
        @SystemApi
        void onBroadcastStopFailed(@Reason int reason);

        /**
         * Callback invoked when broadcast audio is playing
         *
         * @param reason for playback start
         * @param broadcastId as defined by the Basic Audio Profile
         * @hide
         */
        @SystemApi
        void onPlaybackStarted(@Reason int reason, int broadcastId);

        /**
         * Callback invoked when broadcast audio is not playing
         *
         * @param reason for playback stop
         * @param broadcastId as defined by the Basic Audio Profile
         * @hide
         */
        @SystemApi
        void onPlaybackStopped(@Reason int reason, int broadcastId);

        /**
         * Callback invoked when encryption is enabled
         *
         * @param reason for encryption enable
         * @param broadcastId as defined by the Basic Audio Profile
         * @hide
         */
        @SystemApi
        void onBroadcastUpdated(@Reason int reason, int broadcastId);

        /**
         * Callback invoked when Broadcast Source failed to update
         *
         * @param reason for update failure
         * @param broadcastId as defined by the Basic Audio Profile
         * @hide
         */
        @SystemApi
        void onBroadcastUpdateFailed(int reason, int broadcastId);

        /**
         * Callback invoked when Broadcast Source metadata is updated
         *
         * @param metadata updated Broadcast Source metadata
         * @param broadcastId as defined by the Basic Audio Profile
         * @hide
         */
        @SystemApi
        void onBroadcastMetadataChanged(int broadcastId,
                @NonNull BluetoothLeBroadcastMetadata metadata);
    }

    /**
     * Create a BluetoothLeBroadcast proxy object for interacting with the local LE Audio Broadcast
     * Source service.
     *
     * @param context  for to operate this API class
     * @param listener listens for service callbacks across binder
     * @hide
     */
    /*package*/ BluetoothLeBroadcast(Context context, BluetoothProfile.ServiceListener listener) {}

    /**
     * Not supported since LE Audio Broadcasts do not establish a connection.
     *
     * @hide
     */
    @Override
    @RequiresBluetoothConnectPermission
    @RequiresPermission(allOf = {
            android.Manifest.permission.BLUETOOTH_CONNECT,
            android.Manifest.permission.BLUETOOTH_PRIVILEGED,
    })
    public int getConnectionState(@NonNull BluetoothDevice device) {
        throw new UnsupportedOperationException("LE Audio Broadcasts are not connection-oriented.");
    }

    /**
     * Not supported since LE Audio Broadcasts do not establish a connection.
     *
     * @hide
     */
    @Override
    @RequiresBluetoothConnectPermission
    @RequiresPermission(allOf = {
            android.Manifest.permission.BLUETOOTH_CONNECT,
            android.Manifest.permission.BLUETOOTH_PRIVILEGED,
    })
    public @NonNull List<BluetoothDevice> getDevicesMatchingConnectionStates(
            @NonNull int[] states) {
        throw new UnsupportedOperationException("LE Audio Broadcasts are not connection-oriented.");
    }

    /**
     * Not supported since LE Audio Broadcasts do not establish a connection.
     *
     * @hide
     */
    @Override
    @RequiresBluetoothConnectPermission
    @RequiresPermission(allOf = {
            android.Manifest.permission.BLUETOOTH_CONNECT,
            android.Manifest.permission.BLUETOOTH_PRIVILEGED,
    })
    public @NonNull List<BluetoothDevice> getConnectedDevices() {
        throw new UnsupportedOperationException("LE Audio Broadcasts are not connection-oriented.");
    }

    /**
     * Register a {@link Callback} that will be invoked during the operation of this profile.
     *
     * Repeated registration of the same <var>callback</var> object will have no effect after
     * the first call to this method, even when the <var>executor</var> is different. API caller
     * would have to call {@link #unregisterCallback(Callback)} with
     * the same callback object before registering it again.
     *
     * @param executor an {@link Executor} to execute given callback
     * @param callback user implementation of the {@link Callback}
     * @throws IllegalArgumentException if a null executor, sink, or callback is given
     * @hide
     */
    @SystemApi
    @RequiresBluetoothConnectPermission
    @RequiresPermission(allOf = {
            android.Manifest.permission.BLUETOOTH_CONNECT,
            android.Manifest.permission.BLUETOOTH_PRIVILEGED,
    })
    public void registerCallback(@NonNull @CallbackExecutor Executor executor,
            @NonNull Callback callback) {
        if (executor == null) {
            throw new IllegalArgumentException("executor cannot be null");
        }
        if (callback == null) {
            throw new IllegalArgumentException("callback cannot be null");
        }
        log("registerCallback");
        throw new UnsupportedOperationException("Not Implemented");
    }

    /**
     * Unregister the specified {@link Callback}
     * <p>The same {@link Callback} object used when calling
     * {@link #registerCallback(Executor, Callback)} must be used.
     *
     * <p>Callbacks are automatically unregistered when application process goes away
     *
     * @param callback user implementation of the {@link Callback}
     * @throws IllegalArgumentException when callback is null or when no callback is registered
     * @hide
     */
    @SystemApi
    @RequiresBluetoothConnectPermission
    @RequiresPermission(allOf = {
            android.Manifest.permission.BLUETOOTH_CONNECT,
            android.Manifest.permission.BLUETOOTH_PRIVILEGED,
    })
    public void unregisterCallback(@NonNull Callback callback) {
        if (callback == null) {
            throw new IllegalArgumentException("callback cannot be null");
        }
        log("unregisterCallback");
        throw new UnsupportedOperationException("Not Implemented");
    }

    /**
     * Start broadcasting to nearby devices using <var>broadcastCode</var> and
     * <var>contentMetadata</var>
     *
     * Encryption will be enabled when <var>broadcastCode</var> is not null.
     *
     * <p>As defined in Volume 3, Part C, Section 3.2.6 of Bluetooth Core Specification, Version
     * 5.3, Broadcast Code is used to encrypt a broadcast audio stream.
     * <p>It must be a UTF-8 string that has at least 4 octets and should not exceed 16 octets.
     *
     * If the provided <var>broadcastCode</var> is non-null and does not meet the above
     * requirements, encryption will fail to enable with reason code
     * {@link BluetoothStatusCodes#ERROR_LE_BROADCAST_INVALID_CODE}
     *
     * Caller can set content metadata such as program information string in
     * <var>contentMetadata</var>
     *
     * On success, {@link Callback#onBroadcastStarted(int, int)} will be invoked with
     * {@link BluetoothStatusCodes#REASON_LOCAL_APP_REQUEST} reason code.
     * On failure, {@link Callback#onBroadcastStartFailed(int)} will be invoked  with reason code.
     *
     * In particular, when the number of Broadcast Sources reaches
     * {@link #getMaximumNumberOfBroadcast()}, this method will fail with
     * {@link BluetoothStatusCodes#ERROR_LOCAL_NOT_ENOUGH_RESOURCES}
     *
     * After broadcast is started,
     * {@link Callback#onBroadcastMetadataChanged(int, BluetoothLeBroadcastMetadata)}
     * will be invoked to expose the latest Broadcast Group metadata that can be shared out of band
     * to set up Broadcast Sink without scanning.
     *
     * Alternatively, one can also get the latest Broadcast Source meta via
     * {@link #getAllBroadcastMetadata()}
     *
     * @param contentMetadata metadata for the default Broadcast subgroup
     * @param broadcastCode Encryption will be enabled when <var>broadcastCode</var> is not null
     * @throws IllegalArgumentException if <var>contentMetadata</var> is null
     * @throws IllegalStateException if callback was not registered
     * @hide
     */
    @SystemApi
    @RequiresBluetoothConnectPermission
    @RequiresPermission(allOf = {
            android.Manifest.permission.BLUETOOTH_CONNECT,
            android.Manifest.permission.BLUETOOTH_PRIVILEGED,
    })
    public void startBroadcast(@NonNull BluetoothLeAudioContentMetadata contentMetadata,
            @Nullable byte[] broadcastCode) {
        if (DBG) log("startBroadcasting");
    }

    /**
     * Update the broadcast with <var>broadcastId</var> with new <var>contentMetadata</var>
     *
     * On success, {@link Callback#onBroadcastUpdated(int, int)} will be invoked with reason code
     * {@link BluetoothStatusCodes#REASON_LOCAL_APP_REQUEST}.
     * On failure, {@link Callback#onBroadcastUpdateFailed(int, int)} will be invoked with reason
     * code
     *
     * @param broadcastId broadcastId as defined by the Basic Audio Profile
     * @param contentMetadata updated metadata for the default Broadcast subgroup
     * @throws IllegalStateException if callback was not registered
     * @hide
     */
    @SystemApi
    @RequiresBluetoothConnectPermission
    @RequiresPermission(allOf = {
            android.Manifest.permission.BLUETOOTH_CONNECT,
            android.Manifest.permission.BLUETOOTH_PRIVILEGED,
    })
    public void updateBroadcast(int broadcastId,
            @NonNull BluetoothLeAudioContentMetadata contentMetadata) {

    }

    /**
     * Stop broadcasting.
     *
     * On success, {@link Callback#onBroadcastStopped(int, int)} will be invoked with reason code
     * {@link BluetoothStatusCodes#REASON_LOCAL_APP_REQUEST} and the <var>broadcastId</var>
     * On failure, {@link Callback#onBroadcastStopFailed(int)} will be invoked with reason code
     *
     * @param broadcastId as defined by the Basic Audio Profile
     * @throws IllegalStateException if callback was not registered
     * @hide
     */
    @SystemApi
    @RequiresBluetoothConnectPermission
    @RequiresPermission(allOf = {
            android.Manifest.permission.BLUETOOTH_CONNECT,
            android.Manifest.permission.BLUETOOTH_PRIVILEGED,
    })
    public void stopBroadcast(int broadcastId) {
        if (DBG) log("disableBroadcastMode");
    }

    /**
     * Return true if audio is being broadcasted on the Broadcast Source as identified by the
     * <var>broadcastId</var>
     *
     * @param broadcastId as defined in the Basic Audio Profile
     * @return true if audio is being broadcasted
     * @hide
     */
    @SystemApi
    @RequiresBluetoothConnectPermission
    @RequiresPermission(allOf = {
            android.Manifest.permission.BLUETOOTH_CONNECT,
            android.Manifest.permission.BLUETOOTH_PRIVILEGED,
    })
    public boolean isPlaying(int broadcastId) {
        return false;
    }

    /**
     * Get {@link BluetoothLeBroadcastMetadata} for all Broadcast Groups currently running on
     * this device
     *
     * @return list of {@link BluetoothLeBroadcastMetadata}
     * @hide
     */
    @SystemApi
    @RequiresBluetoothConnectPermission
    @RequiresPermission(allOf = {
            android.Manifest.permission.BLUETOOTH_CONNECT,
            android.Manifest.permission.BLUETOOTH_PRIVILEGED,
    })
    public @NonNull List<BluetoothLeBroadcastMetadata> getAllBroadcastMetadata() {
        return Collections.emptyList();
    }

    /**
     * Get the maximum number of broadcast groups supported on this device
     * @return maximum number of broadcast groups supported on this device
     * @hide
     */
    @SystemApi
    @RequiresPermission(android.Manifest.permission.BLUETOOTH_PRIVILEGED)
    public int getMaximumNumberOfBroadcast() {
        return 1;
    }

    /**
     * {@inheritDoc}
     * @hide
     */
    @Override
    public void close() throws Exception {}

    private static void log(String msg) {
        Log.d(TAG, msg);
    }
}
