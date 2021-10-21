/*
 * Copyright (c) 2020, The Linux Foundation. All rights reserved.
 *
 **************************************************************************/

package com.android.bluetooth.apm;

import android.bluetooth.BluetoothAdapter;
import android.bluetooth.BluetoothDevice;
import android.util.Log;
import java.util.List;

import com.android.bluetooth.Utils;
import com.android.internal.annotations.GuardedBy;
import com.android.internal.annotations.VisibleForTesting;

/**
 * A2DP Native Interface to/from JNI.
 */
public class ApmNativeInterface {
    private static final String TAG = "ApmNativeInterface";
    private static final boolean DBG = true;

    @GuardedBy("INSTANCE_LOCK")
    private static ApmNativeInterface sInstance;
    private BluetoothAdapter mAdapter;
    private static final Object INSTANCE_LOCK = new Object();

    static {
        classInitNative();
    }

    @VisibleForTesting
    private ApmNativeInterface() {
        mAdapter = BluetoothAdapter.getDefaultAdapter();
        if (mAdapter == null) {
            Log.w(TAG, "No Bluetooth Adapter Available");
        }
    }

    /**
     * Get singleton instance.
     */
    public static ApmNativeInterface getInstance() {
        synchronized (INSTANCE_LOCK) {
            if (sInstance == null) {
                sInstance = new ApmNativeInterface();
            }
            return sInstance;
        }
    }

    /**
     * Initializes the native interface.
     */
    public void init() {
        initNative();
    }

    /**
     * Cleanup the native interface.
     */
    public void cleanup() {
        cleanupNative();
    }

    /**
     * Report new active device to stack.
     *
     * @param device: new active device
     * @param profile: new active profile
     * @return true on success, otherwise false.
     */
    public boolean activeDeviceUpdate(BluetoothDevice device, int profile, int audioType) {
        return activeDeviceUpdateNative(getByteAddress(device), profile, audioType);
    }

    /**
     * Report Content Control ID to stack.
     *
     * @param id: Content Control ID
     * @param profile: content control profile
     * @return true on success, otherwise false.
     */
    public boolean setContentControl(int id, int profile) {
        return setContentControlNative(id, profile);
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

    //Current logic is implemented only for CALL_AUDIO
    //Proper Audio_type needs to be sent to device profile map
    //for other audio features
    private int getActiveProfile(byte[] address, int audio_type) {
        DeviceProfileMap dpm = DeviceProfileMap.getDeviceProfileMapInstance();
        BluetoothDevice device = getDevice(address);
        int profile = dpm.getProfile(device, ApmConst.AudioFeatures.CALL_AUDIO);
        return profile;
    }

    // Native methods that call into the JNI interface
    private static native void classInitNative();
    private native void initNative();
    private native void cleanupNative();
    private native boolean activeDeviceUpdateNative(byte[] address, int profile, int audioType);
    private native boolean setContentControlNative(int id, int profile);
}

