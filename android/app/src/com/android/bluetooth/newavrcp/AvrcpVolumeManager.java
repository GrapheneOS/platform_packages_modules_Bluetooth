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

package com.android.bluetooth.avrcp;

import android.content.Context;
import android.content.SharedPreferences;
import android.media.AudioManager;
import android.util.Log;

import java.util.HashMap;
import java.util.Map;

class AvrcpVolumeManager {
    public static final String TAG = "NewAvrcpVolumeManager";
    public static final boolean DEBUG = true;

    // All volumes are stored at system volume values, not AVRCP values
    public static final String VOLUME_MAP = "bluetooth_volume_map";
    public static final String VOLUME_BLACKLIST = "absolute_volume_blacklist";
    public static final int AVRCP_MAX_VOL = 127;
    public static int sDeviceMaxVolume = 0;
    public static final int STREAM_MUSIC = AudioManager.STREAM_MUSIC;

    Context mContext;
    AudioManager mAudioManager;
    AvrcpNativeInterface mNativeInterface;

    HashMap<String, Boolean> mDeviceMap = new HashMap<String, Boolean>();
    HashMap<String, Integer> mVolumeMap = new HashMap<String, Integer>();
    String mCurrentDeviceAddr = "";
    boolean mAbsoluteVolumeSupported = false;

    static int avrcpToSystemVolume(int avrcpVolume) {
        return (int) Math.floor((double) avrcpVolume * sDeviceMaxVolume / AVRCP_MAX_VOL);
    }

    static int systemToAvrcpVolume(int deviceVolume) {
        int avrcpVolume = (int) Math.floor((double) deviceVolume
                * AVRCP_MAX_VOL / sDeviceMaxVolume);
        if (avrcpVolume > 127) avrcpVolume = 127;
        return avrcpVolume;
    }

    private SharedPreferences getVolumeMap() {
        return mContext.getSharedPreferences(VOLUME_MAP, Context.MODE_PRIVATE);
    }

    private int getVolume(String bdaddr, int defaultValue) {
        if (!mVolumeMap.containsKey(bdaddr)) {
            Log.w(TAG, "getVolume: Couldn't find volume preference for device: " + bdaddr);
            return defaultValue;
        }

        return mVolumeMap.get(bdaddr);
    }

    private void switchVolumeDevice(String bdaddr) {
        // Inform the audio manager that the device has changed
        mAudioManager.avrcpSupportsAbsoluteVolume(bdaddr, mDeviceMap.get(bdaddr));

        // Get the current system volume and try to get the preference volume
        int currVolume = mAudioManager.getStreamVolume(STREAM_MUSIC);
        int savedVolume = getVolume(bdaddr, currVolume);

        // If the preference volume isn't equal to the current stream volume then that means
        // we had a stored preference.
        if (DEBUG) {
            Log.d(TAG, "switchVolumeDevice: currVolume=" + currVolume
                    + " savedVolume=" + savedVolume);
        }
        if (savedVolume != currVolume) {
            Log.i(TAG, "switchVolumeDevice: restoring volume level " + savedVolume);
            mAudioManager.setStreamVolume(AudioManager.STREAM_MUSIC, savedVolume,
                    AudioManager.FLAG_SHOW_UI | AudioManager.FLAG_BLUETOOTH_ABS_VOLUME);
        }

        // If absolute volume for the device is supported, set the volume for the device
        if (mDeviceMap.get(bdaddr)) {
            int avrcpVolume = systemToAvrcpVolume(savedVolume);
            Log.i(TAG, "switchVolumeDevice: Updating device volume: avrcpVolume=" + avrcpVolume);
            mNativeInterface.sendVolumeChanged(avrcpVolume);
        }
    }

    AvrcpVolumeManager(Context context, AudioManager audioManager,
            AvrcpNativeInterface nativeInterface) {
        mContext = context;
        mAudioManager = audioManager;
        mNativeInterface = nativeInterface;
        sDeviceMaxVolume = mAudioManager.getStreamMaxVolume(AudioManager.STREAM_MUSIC);

        // Load the volume map into a hash map since shared preferences are slow to poll and update
        Map<String, ?> allKeys = getVolumeMap().getAll();
        for (Map.Entry<String, ?> entry : allKeys.entrySet()) {
            String key = entry.getKey();
            Object value = entry.getValue();
            if (value instanceof Integer) {
                mVolumeMap.put(key, (Integer) value);
            }
        }
    }

    void storeVolume() {
        SharedPreferences.Editor pref = getVolumeMap().edit();
        int storeVolume =  mAudioManager.getStreamVolume(STREAM_MUSIC);
        Log.i(TAG, "storeVolume: Storing stream volume level for device " + mCurrentDeviceAddr
                + " : " + storeVolume);
        mVolumeMap.put(mCurrentDeviceAddr, storeVolume);
        pref.putInt(mCurrentDeviceAddr, storeVolume);
        pref.apply();
    }

    void deviceConnected(String bdaddr, boolean absoluteVolume) {
        if (DEBUG) {
            Log.d(TAG, "deviceConnected: bdaddr=" + bdaddr + " absoluteVolume=" + absoluteVolume);
        }

        mDeviceMap.put(bdaddr, absoluteVolume);

        // AVRCP features lookup has completed after the device became active. Switch to the new
        // device now.
        if (bdaddr.equals(mCurrentDeviceAddr)) {
            switchVolumeDevice(bdaddr);
        }
    }

    void volumeDeviceSwitched(String bdaddr) {
        if (DEBUG) {
            Log.d(TAG, "volumeDeviceSwitched: mCurrentDeviceAddr=" + mCurrentDeviceAddr
                    + " bdaddr=" + bdaddr);
        }

        if (bdaddr == null || bdaddr.equals(mCurrentDeviceAddr)) {
            return;
        }

        // Store the previous volume if a device was active.
        if (!mCurrentDeviceAddr.isEmpty()) {
            storeVolume();
        }

        // Set the current volume device to the new device.
        mCurrentDeviceAddr = bdaddr;

        // No new active device.
        if (bdaddr.isEmpty()) {
            return;
        }

        // A2DP can sometimes connect and set a device to active before AVRCP has determined if the
        // device supports absolute volume. Defer switching the device until AVRCP returns the
        // info.
        if (!mDeviceMap.containsKey(bdaddr)) {
            Log.w(TAG, "volumeDeviceSwitched: Device isn't connected: " + bdaddr);
            return;
        }

        switchVolumeDevice(bdaddr);
    }

    void deviceDisconnected(String bdaddr) {
        if (DEBUG) {
            Log.d(TAG, "deviceDisconnected: bdaddr=" + bdaddr);
        }
        mDeviceMap.remove(bdaddr);
    }

    public void dump(StringBuilder sb) {
        sb.append("Bluetooth Device Volume Map:\n");
        sb.append("  Device Address    : Volume\n");
        Map<String, ?> allKeys = getVolumeMap().getAll();
        for (Map.Entry<String, ?> entry : allKeys.entrySet()) {
            String key = entry.getKey();
            Object value = entry.getValue();
            if (value instanceof Integer) {
                sb.append("  " + key + " : " + (Integer) value + "\n");
                mVolumeMap.put(key, (Integer) value);
            }
        }
    }
}
