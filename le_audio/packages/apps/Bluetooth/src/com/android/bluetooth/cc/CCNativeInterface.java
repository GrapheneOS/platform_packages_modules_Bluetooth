/*
 *Copyright (c) 2020-2021, The Linux Foundation. All rights reserved.
 */

/*
 * Copyright 2017 The Android Open Source Project
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
package com.android.bluetooth.cc;

import android.bluetooth.BluetoothAdapter;
import android.bluetooth.BluetoothDevice;
import android.util.Log;
import java.util.ArrayList;
import java.util.List;

import com.android.bluetooth.Utils;
import com.android.internal.annotations.GuardedBy;
import com.android.internal.annotations.VisibleForTesting;
import java.nio.charset.StandardCharsets;

/**
 * Ccp Native Interface to/from JNI.
 */
public class CCNativeInterface {
    private static final String TAG = "CCNativeInterface";
    private static final boolean DBG = true;
    private BluetoothAdapter mAdapter;

    @GuardedBy("INSTANCE_LOCK")
    private static CCNativeInterface sInstance;
    private static final Object INSTANCE_LOCK = new Object();

    static {
        classInitNative();
    }

    private CCNativeInterface() {
        mAdapter = BluetoothAdapter.getDefaultAdapter();
        if (mAdapter == null) {
            Log.w(TAG, "No Bluetooth Adapter Available");
        }
    }

     /**
     * This class is a singleton because native library should only be loaded once
     *
     * @return default instance
     */
    public static CCNativeInterface getInstance() {
        synchronized (INSTANCE_LOCK) {
            if (sInstance == null) {
                sInstance = new CCNativeInterface();
            }
            return sInstance;
        }
    }

    /**
     * Initialize native stack
     *
     * @param ccsClients maximum number of CCS clients that can be connected simultaneously
     * @param inbandRingingEnabled whether in-band ringing is enabled on this AG
     */
    @VisibleForTesting
    public void init(int maxCcsClients, boolean inbandRingingEnabled) {
        initializeNative("00008fd1-0000-1000-8000-00805F9B34FB", maxCcsClients, inbandRingingEnabled);
    }

    /**
     * Cleanup the native interface.
     */
    @VisibleForTesting(visibility = VisibleForTesting.Visibility.PACKAGE)
    public void cleanup() {
        cleanupNative();
    }

    /**
     * Disconnects Call control from a remote device.
     *
     * @param device the remote device
     * @return true on success, otherwise false.
     */
    @VisibleForTesting(visibility = VisibleForTesting.Visibility.PACKAGE)
    public boolean disconnect(BluetoothDevice device) {
        return disconnectNative(getByteAddress(device));
    }
    /**
     * update CC optional supported feature
     * @param feature
     */
  @VisibleForTesting(visibility = VisibleForTesting.Visibility.PACKAGE)
    public boolean callControlOptionalFeatures(int feature) {
        return callControlPointOpcodeSupportedNative(feature);
    }

  /**
     * Sets the CC call state
     * @param state
     */
  @VisibleForTesting(visibility = VisibleForTesting.Visibility.PACKAGE)
    public boolean callState(ArrayList<CallControlState> callList) {
        int len = callList.size();
        byte[] cStateListBytes = new byte[len*3];
        for (int i=0; i<len; i++) {
            cStateListBytes[3*i+0] = (byte) callList.get(i).mIndex;
            cStateListBytes[3*i+1] = (byte) CCHalConstants.getCCsCallState(callList.get(i).mState);
            cStateListBytes[3*i+2] = (byte) callList.get(i).mFlags;
        }
        return callStateNative(len, cStateListBytes);
    }

  /**
     * update CC Bearer name
     * @param Bearer name
     */
  @VisibleForTesting(visibility = VisibleForTesting.Visibility.PACKAGE)
    public boolean updateBearerProviderName(String name) {
        return updateBearerNameNative(name);
    }

    /**
     * update CC Bearer  technology type
     * @param Bearer technology
     */
  @VisibleForTesting(visibility = VisibleForTesting.Visibility.PACKAGE)
    public boolean updateBearerTechnology(int tech_type) {
         return updateBearerTechnologyNative(tech_type);

    }

  @VisibleForTesting(visibility = VisibleForTesting.Visibility.PACKAGE)
    public boolean updateStatusFlags(int value) {
        return updateStatusFlagsNative(value);
    }
  @VisibleForTesting(visibility = VisibleForTesting.Visibility.PACKAGE)
    public boolean updateSignalStrength(int signal_value) {
        return updateSignalStatusNative(signal_value);
    }


   @VisibleForTesting(visibility = VisibleForTesting.Visibility.PACKAGE)
   public boolean updateIncomingCall(int index, String uri) {
      updateIncomingCallNative(index, uri);
       return true;
   }

  @VisibleForTesting(visibility = VisibleForTesting.Visibility.PACKAGE)
   public boolean updateSupportedBearerList(String supportedBearers) {
      return  updateSupportedBearerListNative(supportedBearers);
   }

  @VisibleForTesting(visibility = VisibleForTesting.Visibility.PACKAGE)
    public boolean callControlResponse(int op, int index, int status, BluetoothDevice device) {
        return callControlResponseNative(op, index, status,  getByteAddress(device));
    }

  /**
     * update active device
     * @param device
       * @param setId
     */
  @VisibleForTesting(visibility = VisibleForTesting.Visibility.PACKAGE)
    public boolean setActiveDevice(BluetoothDevice device, int setId) {
        return setActiveDeviceNative(setId, getByteAddress(device));
    }
    /**
     * Sets call content control id
     * @param ccid
     */
  @VisibleForTesting(visibility = VisibleForTesting.Visibility.PACKAGE)
    public boolean contentControlId(int ccid) {

        return contentControlIdNative(ccid);
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
    private void callControlInitializedCallback(int state) {
        if (DBG) {
            Log.d(TAG, "CallControlInitializedCallback: " + state);
        }

        CCService service = CCService.getCCService();
        if (service != null) {
            service.onCallControlInitialized(state);
        }
    }

    private void onConnectionStateChanged(int state, byte[] address) {
        if (DBG) {
            Log.d(TAG, "OnConnectionStateChanged: " + state);
        }
        BluetoothDevice device = getDevice(address);

        CCService service = CCService.getCCService();
        if (service != null)
            service.onConnectionStateChanged(device, state);
    }

    private void callControlPointChangedRequest(int op, int[]call_indices, int count, byte[] dialNumber, byte[] address) {
        BluetoothDevice device = getDevice(address);
        String dialUri = new String(dialNumber, StandardCharsets.UTF_8);
        if (DBG) {
            Log.d(TAG, "CallControlPointChangedRequest: " + op + "dialNumber: " + dialUri);
        }
        CCService service = CCService.getCCService();
        if (service != null)
            service.onCallControlPointChangedRequest(op, call_indices, count, dialUri, device);
    }

    // Native methods that call into the JNI interface
    private static native void classInitNative();
    private native void initializeNative(String uuid, int max_ccs_clients, boolean inbandRingingEnabled);
    private native void cleanupNative();
    private native boolean callControlPointOpcodeSupportedNative(int feature);
    private native boolean callStateNative(int len, byte[] callStateList);
    private native boolean updateBearerNameNative(String providerName);
    private native boolean updateBearerTechnologyNative(int tech_type);
    private native boolean updateSignalStatusNative(int signal);
    private native boolean updateStatusFlagsNative(int value);
    private native boolean setActiveDeviceNative(int setId, byte[] address);
    private native boolean contentControlIdNative(int ccid);
    private native boolean disconnectNative(byte[] address);
    private native boolean callControlResponseNative(int op, int index, int status, byte[] address);
    private native boolean updateSupportedBearerListNative(String supportedBearers);
    private native boolean updateIncomingCallNative(int index, String uri);
}
