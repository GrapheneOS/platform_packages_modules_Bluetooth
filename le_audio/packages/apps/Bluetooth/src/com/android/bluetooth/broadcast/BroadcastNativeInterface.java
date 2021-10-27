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

package com.android.bluetooth.broadcast;

import android.bluetooth.BluetoothBroadcast;
import android.bluetooth.BluetoothAdapter;
import android.bluetooth.BluetoothCodecConfig;
import android.bluetooth.BluetoothCodecStatus;
import android.util.Log;
import java.util.List;

import com.android.bluetooth.Utils;
import com.android.internal.annotations.GuardedBy;
import com.android.internal.annotations.VisibleForTesting;
import java.util.Arrays;

/**
 * Broadcast Native Interface to/from JNI.
 */

public class BroadcastNativeInterface {
    private static final String TAG = "BroadcastNativeInterface";
    private static final boolean DBG = true;
    private BluetoothAdapter mAdapter;
    @GuardedBy("INSTANCE_LOCK")
    private static BroadcastNativeInterface sInstance;
    private static final Object INSTANCE_LOCK = new Object();

    static {
        classInitNative();
    }

    @VisibleForTesting
    private BroadcastNativeInterface() {
        mAdapter = BluetoothAdapter.getDefaultAdapter();
        if (mAdapter == null) {
            Log.wtfStack(TAG, "No Bluetooth Adapter Available");
        }
    }

    /**
     * Get singleton instance.
     */
    public static BroadcastNativeInterface getInstance() {
        synchronized (INSTANCE_LOCK) {
            if (sInstance == null) {
                sInstance = new BroadcastNativeInterface();
            }
            return sInstance;
        }
    }
    /**
     * Initializes the native interface.
     *
     * @param maxConnectedAudioDevices maximum number of A2DP Sink devices that can be connected
     * simultaneously
     * @param codecConfigPriorities an array with the codec configuration
     * priorities to configure.
     */
    public void init(int maxBroadcast, BluetoothCodecConfig codecConfig, int mode) {
        initNative(maxBroadcast, codecConfig, mode);
    }

    /**
     * Cleanup the native interface.
     */
    public void cleanup() {
        cleanupNative();
    }

    /**
     * Sets a connected A2DP remote device as active.
     *
     * @param device the remote device
     * @return true on success, otherwise false.
     */
    public boolean enableBroadcast(BluetoothCodecConfig mCodecConfig) {
        Log.d(TAG, "enableBroadcast");
        return enableBroadcastNative(mCodecConfig);
    }
    //Move SM to IDLE
    public boolean disableBroadcast(int adv_id) {
        Log.d(TAG, "disableBroadcast");
        return disableBroadcastNative(adv_id);
    }
    //Remove ISO Data path for reconfiguration
    public boolean SetupAudioPath(boolean enable, int adv_id, int BIG_handle, int num_bises, int[] bises) {
        Log.d(TAG, "SetupAudioPath for BIG Handle: " + BIG_handle);
        return setupAudioPathNative(enable, adv_id, BIG_handle, num_bises, bises);
    }
    //Star/End Session
    public boolean setActiveDevice(boolean enable, int advID) {
        Log.d(TAG, "SetActiveDevice");
        return setActiveDeviceNative(enable, advID);
    }
    //Retrieve stored encryption key
    public String GetEncryptionKey() {
        Log.d(TAG, "GetEncryptionKey");
        return getEncryptionKeyNative();
    }
    //Set new encyption key
    public boolean SetEncryptionKey(boolean enabled, int length) {
        Log.d(TAG, "SetEncryptionKey");
        return setEncryptionKeyNative(enabled, length);
    }
    /**
     * Sets the codec configuration preferences.
     *
     * @param device the remote Bluetooth device
     * @param codecConfigArray an array with the codec configurations to
     * configure.
     * @return true on success, otherwise false.
     */
    //Restart session with new codec config
    public boolean setCodecConfigPreference(int adv_handle, BluetoothCodecConfig codecConfig) {
        Log.d(TAG, "setCodecConfigPreference");
        return setCodecConfigPreferenceNative(adv_handle, codecConfig);
    }
    private int translate_state_to_app(int event, int state) {
        if (event == BroadcastStackEvent.EVENT_TYPE_BROADCAST_STATE_CHANGED) {
            switch(state) {
                 case BroadcastStackEvent.STATE_IDLE:
                     return BluetoothBroadcast.STATE_DISABLED;
                 case BroadcastStackEvent.STATE_CONFIGURED:
                     return BluetoothBroadcast.STATE_ENABLED;
                 case BroadcastStackEvent.STATE_STREAMING:
                     return BluetoothBroadcast.STATE_STREAMING;
                 default:
                    return BluetoothBroadcast.STATE_DISABLED;
            }
        } else if (event == BroadcastStackEvent.EVENT_TYPE_BROADCAST_AUDIO_STATE_CHANGED) {
             switch(state) {
                 case BroadcastStackEvent.STATE_STOPPED:
                     return BluetoothBroadcast.STATE_NOT_PLAYING;
                 case BroadcastStackEvent.STATE_STARTED:
                     return BluetoothBroadcast.STATE_PLAYING;
                 default:
                     return BluetoothBroadcast.STATE_NOT_PLAYING;
             }
        }
        return BluetoothBroadcast.STATE_DISABLED;
    }
    private void sendMessageToService(BroadcastStackEvent event) {
        BroadcastService service = BroadcastService.getBroadcastService();
        if (service != null) {
            service.messageFromNative(event);
        } else {
            Log.w(TAG, "Event ignored, service not available: " + event);
        }
    }

    private void onBroadcastStateChanged(int adv_handle, int state) {
        BroadcastStackEvent event =
             new BroadcastStackEvent(BroadcastStackEvent.EVENT_TYPE_BROADCAST_STATE_CHANGED);
        event.valueInt = translate_state_to_app(BroadcastStackEvent.EVENT_TYPE_BROADCAST_STATE_CHANGED,state);
        event.advHandle = adv_handle;
        if (DBG) {
            Log.d(TAG, "onBroadcastStateChanged: " + event);
        }
        sendMessageToService(event);
    }

    private void onAudioStateChanged(int adv_handle, int state) {
        BroadcastStackEvent event =
             new BroadcastStackEvent(BroadcastStackEvent.EVENT_TYPE_BROADCAST_AUDIO_STATE_CHANGED);
        event.valueInt = translate_state_to_app(BroadcastStackEvent.EVENT_TYPE_BROADCAST_AUDIO_STATE_CHANGED,state);
        event.advHandle = adv_handle;
        if (DBG) {
            Log.d(TAG, "onAudioStateChanged: " + event);
        }
        sendMessageToService(event);
    }

    private void onEncryptionKeyGenerated(String key) {
        BroadcastStackEvent event =
            new BroadcastStackEvent(BroadcastStackEvent.EVENT_TYPE_ENC_KEY_GENERATED);
        event.key = key;
        if (DBG) {
            Log.d(TAG, "onEncryptionKeyGenerated: " + event);
        }
        sendMessageToService(event);
    }

    private void onCodecConfigChanged(int adv_handle, BluetoothCodecConfig newCodecConfig,
                                                 BluetoothCodecConfig[] codecCapabilities) {
        BroadcastStackEvent event =
               new BroadcastStackEvent(BroadcastStackEvent.EVENT_TYPE_CODEC_CONFIG_CHANGED);
        event.codecStatus = new BluetoothCodecStatus(newCodecConfig, codecCapabilities, codecCapabilities);
        event.advHandle = adv_handle;
        if (DBG) {
            Log.d(TAG, "onCodecConfigChanged: " + event);
        }
        sendMessageToService(event);
    }

    private void onSetupBIG(int setup, int adv_id, int big_handle, int num_bises, char[] bis_handles) {
        BroadcastStackEvent event = new BroadcastStackEvent(BroadcastStackEvent.EVENT_TYPE_SETUP_BIG);
        event.valueInt = setup;
        event.advHandle = adv_id;
        event.bigHandle = big_handle;
        event.NumBises = num_bises;
        if (DBG) {
            Log.d(TAG, "onSetupBIG: " + event);
        }
        sendMessageToService(event);
    }

    private void onBroadcastIdGenerated(byte[] broadcast_id) {
        BroadcastStackEvent event =
            new BroadcastStackEvent(BroadcastStackEvent.EVENT_TYPE_BROADCAST_ID_GENERATED);
        Log.d(TAG,"onBroadcastIdGenerated");
        for(int i = 0; i < 3; i++) {
            event.BroadcastId[i] = broadcast_id[i];
            Log.d(TAG, "BroadcastID ["+i+"]" + " = " + event.BroadcastId[i]);
        }
        if (DBG) {
            Log.d(TAG, "onBroadcastIdGenerated: " + event);
        }
        sendMessageToService(event);
    }

    // Native methods that call into the JNI interface
    private static native void classInitNative();
    private native void initNative(int maxBroadcast, BluetoothCodecConfig codecConfig, int mode);
    private native void cleanupNative();
    private native boolean setActiveDeviceNative(boolean enable, int adv_id);
    private native boolean enableBroadcastNative(BluetoothCodecConfig codecConfig);
    private native boolean disableBroadcastNative(int adv_id);
    private native boolean setupAudioPathNative(boolean enable, int adv_id, int big_handle,
                                                         int num_bises, int[] bises);
    private native String getEncryptionKeyNative();
    private native boolean setEncryptionKeyNative(boolean enabled, int length);
    private native boolean setCodecConfigPreferenceNative(int adv_id, BluetoothCodecConfig codecConfig);

}


