/******************************************************************************
 *
 *  Copyright 2021 The Android Open Source Project
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at:
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 ******************************************************************************/


package com.android.bluetooth.mcp;

import android.bluetooth.BluetoothAdapter;
import android.bluetooth.BluetoothDevice;
import android.util.Log;

import com.android.bluetooth.Utils;
import com.android.internal.annotations.GuardedBy;
import com.android.internal.annotations.VisibleForTesting;

/**
 * Mcp Native Interface to/from JNI.
 */
public class McpNativeInterface {
    private static final String TAG = "McpNativeInterface";
    private static final boolean DBG = true;
    private BluetoothAdapter mAdapter;
    @GuardedBy("INSTANCE_LOCK")
    private static McpNativeInterface sInstance;
    private static final Object INSTANCE_LOCK = new Object();

    static {
        classInitNative();
    }

    private McpNativeInterface() {
        mAdapter = BluetoothAdapter.getDefaultAdapter();
        if (mAdapter == null) {
            Log.wtfStack(TAG, "No Bluetooth Adapter Available");
        }
    }

    /**
     * Get singleton instance.
     */
    public static McpNativeInterface getInstance() {
        synchronized (INSTANCE_LOCK) {
            if (sInstance == null) {
                sInstance = new McpNativeInterface();
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
     * update MCP media supported feature
     * @param feature
     */
  @VisibleForTesting(visibility = VisibleForTesting.Visibility.PACKAGE)
    public boolean mediaControlPointOpcodeSupported(int feature) {
        return mediaControlPointOpcodeSupportedNative(feature);
    }

    /**
     * update MCP media supported feature current value
     * @param value
     */
  @VisibleForTesting(visibility = VisibleForTesting.Visibility.PACKAGE)
    public boolean mediaControlPoint(int value) {
        return mediaControlPointNative(value);
    }

  /**
     * Sets the Mcp media state
     * @param state
     */
  @VisibleForTesting(visibility = VisibleForTesting.Visibility.PACKAGE)
    public boolean mediaState(int state) {
        return mediaStateNative(state);
    }

  /**
     * update MCP media player name
     * @param player name
     */
  @VisibleForTesting(visibility = VisibleForTesting.Visibility.PACKAGE)
    public boolean mediaPlayerName(String playeName) {
        return mediaPlayerNameNative(playeName);
    }
  /**
     * update track change notification
     * @param track id
     */
  @VisibleForTesting(visibility = VisibleForTesting.Visibility.PACKAGE)
    public boolean trackChanged(int status) {
        return trackChangedNative(status);
    }
  /**
     * update MCP track position
     * @param position
     */
  @VisibleForTesting(visibility = VisibleForTesting.Visibility.PACKAGE)
    public boolean trackPosition(int position) {
        return trackPositionNative(position);
    }

  /**
     * update MCP track duration
     * @param duration
     */
  @VisibleForTesting(visibility = VisibleForTesting.Visibility.PACKAGE)
    public boolean trackDuration(int duration) {
        return trackDurationNative(duration);
    }
  /**
     * update MCP track title
     * @param title
     */
  @VisibleForTesting(visibility = VisibleForTesting.Visibility.PACKAGE)
    public boolean trackTitle(String title) {
        return trackTitleNative(title);
    }
  /**
     * update playing order support of media
     * @param order
     */
  @VisibleForTesting(visibility = VisibleForTesting.Visibility.PACKAGE)
    public boolean playingOrderSupported(int order) {
        return playingOrderSupportedNative(order);
    }
  /**
     * update playing order value of media
     * @param value
     */
  @VisibleForTesting(visibility = VisibleForTesting.Visibility.PACKAGE)
    public boolean playingOrder(int value) {
        return playingOrderNative(value);
    }
  /**
     * update active device
     * @param device
     * @param setId
     */
  @VisibleForTesting(visibility = VisibleForTesting.Visibility.PACKAGE)
    public boolean setActiveDevice(BluetoothDevice device, int setId, int profile) {
        return setActiveDeviceNative(profile, setId, getByteAddress(device));
    }
    /**
     * Sets Mcp media content control id
     * @param ccid
     */
  @VisibleForTesting(visibility = VisibleForTesting.Visibility.PACKAGE)
    public boolean contentControlId(int ccid) {

        return contentControlIdNative(ccid);
    }
    /**
     * Disconnect Mcp disconnect device
     * @param device
     */
  @VisibleForTesting(visibility = VisibleForTesting.Visibility.PACKAGE)
    public boolean disconnectMcp(BluetoothDevice device) {
        return disconnectMcpNative(getByteAddress(device));
    }

    /**
     * Disconnect Mcp disconnect device
     * @param device
     */
  @VisibleForTesting(visibility = VisibleForTesting.Visibility.PACKAGE)
    public boolean bondStateChange(BluetoothDevice device, int state) {
        return bondStateChangeNative(state, getByteAddress(device));
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

    // Callbacks from the native stack back into the Java framework.
    // All callbacks are routed via the Service which will disambiguate which
    private void OnConnectionStateChanged(int state, byte[] address) {
        if (DBG) {
            Log.d(TAG, "OnConnectionStateChanged: " + state);
        }
        BluetoothDevice device = getDevice(address);

        McpService service = McpService.getMcpService();
        if (service != null)
            service.onConnectionStateChanged(device, state);
    }

    private void MediaControlPointChangedRequest(int state, byte[] address) {
        BluetoothDevice device = getDevice(address);
        if (DBG) {
            Log.d(TAG, "MediaControlPointChangedReq: " + state);
        }
        McpService service = McpService.getMcpService();
        if (service != null)
            service.onMediaControlPointChangeReq(device, state);
    }

    private void TrackPositionChangedRequest(int position) {
        if (DBG) {
           Log.d(TAG, "TrackPositionChangedRequest: " + position);
        }
    McpService service = McpService.getMcpService();
    if (service != null)
        service.onTrackPositionChangeReq(position);
    }

    private void PlayingOrderChangedRequest(int order) {
        if (DBG) {
           Log.d(TAG, "PlayingOrderChangedRequest: " + order);
        }
    McpService service = McpService.getMcpService();
    if (service != null)
        service.onPlayingOrderChangeReq(order);
    }

    // Native methods that call into the JNI interface
    private static native void classInitNative();
    private native void initNative();
    private native void cleanupNative();
    private native boolean mediaControlPointOpcodeSupportedNative(int feature);
    private native boolean mediaControlPointNative(int value);
    private native boolean mediaStateNative(int state);
    private native boolean mediaPlayerNameNative(String playerName);
    private native boolean trackChangedNative(int status);
    private native boolean trackPositionNative(int position);
    private native boolean trackDurationNative(int duration);
    private native boolean trackTitleNative(String title);
    private native boolean playingOrderSupportedNative(int order);
    private native boolean playingOrderNative(int value);
    private native boolean setActiveDeviceNative(int profile, int setId, byte[] address);
    private native boolean contentControlIdNative(int ccid);
    private native boolean disconnectMcpNative(byte[] address);
    private native boolean bondStateChangeNative(int state, byte[] address);
}

