/*
 * Copyright (c) 2020 The Linux Foundation. All rights reserved.

 * Copyright (C) 2018 The Android Open Source Project
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
 * limitations under the License
 */

package com.android.settingslib.bluetooth;

import android.bluetooth.BluetoothAdapter;
import android.bluetooth.BluetoothClass;
import android.bluetooth.BluetoothDevice;
import android.bluetooth.BluetoothSyncHelper;
import android.bluetooth.BluetoothProfile;
import android.content.Context;
import android.util.Log;
import android.os.ParcelUuid;
import android.bluetooth.BleBroadcastAudioScanAssistManager;
import android.bluetooth.BleBroadcastAudioScanAssistCallback;
import android.content.Intent;
import android.bluetooth.BleBroadcastSourceInfo;

import com.android.settingslib.R;
import android.os.SystemProperties;
import android.os.Handler;

import androidx.annotation.Keep;
import java.util.ArrayList;
import java.util.List;

@Keep
public class BCProfile implements LocalBluetoothProfile {
    private static final String TAG = "BCProfile";
    private static boolean V = true;

    private Context mContext;

    private BluetoothSyncHelper mService;
    private boolean mIsProfileReady;

    private final CachedBluetoothDeviceManager mDeviceManager;

    static final String NAME = "BCProfile";
    private final LocalBluetoothProfileManager mProfileManager;

    // Order of this profile in device profiles list
    private static final int ORDINAL = 1;

    // These callbacks run on the main thread.
    private final class BassclientServiceListener
            implements BluetoothProfile.ServiceListener {

        public void onServiceConnected(int profile, BluetoothProfile proxy) {
            Log.d(TAG, "BassclientService connected");
            mService = (BluetoothSyncHelper) proxy;
            // We just bound to the service, so refresh the UI for any connected Bassclient devices.
            //List<BluetoothDevice> deviceList = mService.getConnectedDevices();
            mIsProfileReady=true;//BassService connected
            mProfileManager.callServiceConnectedListeners();
        }

        public void onServiceDisconnected(int profile) {
            Log.d(TAG, "BassclientService disconnected");
            mIsProfileReady=false;
        }
    }

    public boolean isProfileReady() {
        return mIsProfileReady;
    }

    @Override
    public int getProfileId() {
        return BluetoothProfile.BC_PROFILE;
    }

    @Override
    public boolean setEnabled(BluetoothDevice device, boolean enabled) {
        boolean isEnabled = false;
        if (mService == null) {
            return false;
        }
        if (enabled) {
            Log.d(TAG, "BCProfile: " + device + ":" + enabled);
            if (mService.getConnectionPolicy(device) < BluetoothProfile.CONNECTION_POLICY_ALLOWED) {
                isEnabled = mService.setConnectionPolicy(device, BluetoothProfile.CONNECTION_POLICY_ALLOWED);
            }
        } else {
            isEnabled = mService.setConnectionPolicy(device, BluetoothProfile.CONNECTION_POLICY_FORBIDDEN);
        }

        return isEnabled;
    }

    @Override
    public boolean isEnabled(BluetoothDevice device) {
        if (mService == null) {
            return false;
        }
        return mService.getConnectionPolicy(device) > BluetoothProfile.CONNECTION_POLICY_FORBIDDEN;

    }

   @Override
    public int getConnectionPolicy(BluetoothDevice device) {
        return BluetoothProfile.CONNECTION_POLICY_ALLOWED;
    }

    BCProfile(Context context, CachedBluetoothDeviceManager deviceManager,
            LocalBluetoothProfileManager profileManager) {
        mContext = context;
        mDeviceManager = deviceManager;
        mProfileManager = profileManager;
        BluetoothAdapter.getDefaultAdapter().getProfileProxy(context,
                new BassclientServiceListener(), BluetoothProfile.BC_PROFILE);
    }

    public boolean accessProfileEnabled() {
        //return true for BASS always so that
        //It shows the profile preference in device details
        return true;
    }

    public boolean isAutoConnectable() {
        if (mService == null) return false;
        Log.d(TAG, "isAutoConnectable return false");
        return false;
    }

    /**
     * Get Scan delegator devices matching connection states{
     * @code BluetoothProfile.STATE_CONNECTED,
     * @code BluetoothProfile.STATE_CONNECTING,
     * @code BluetoothProfile.STATE_DISCONNECTING}
     *
     * @return Matching device list
     */
    public List<BluetoothDevice> getConnectedDevices() {
        return getDevicesByStates(new int[] {
                BluetoothProfile.STATE_CONNECTED,
                BluetoothProfile.STATE_CONNECTING,
                BluetoothProfile.STATE_DISCONNECTING});
    }

    /**
     * Get Scan delegator  devices matching connection states{
     * @code BluetoothProfile.STATE_DISCONNECTED,
     * @code BluetoothProfile.STATE_CONNECTED,
     * @code BluetoothProfile.STATE_CONNECTING,
     * @code BluetoothProfile.STATE_DISCONNECTING}
     *
     * @return Matching device list
     */
    public List<BluetoothDevice> getConnectableDevices() {
        return getDevicesByStates(new int[] {
                BluetoothProfile.STATE_DISCONNECTED,
                BluetoothProfile.STATE_CONNECTED,
                BluetoothProfile.STATE_CONNECTING,
                BluetoothProfile.STATE_DISCONNECTING});
    }

    private List<BluetoothDevice> getDevicesByStates(int[] states) {
        if (mService == null) {
            return new ArrayList<BluetoothDevice>(0);
        }
        return mService.getDevicesMatchingConnectionStates(states);
    }

    public boolean connect(BluetoothDevice device) {
        Log.d(TAG, "BCProfile Connect to  device: " + device);
        if (mService == null) return false;
        return mService.connect(device);
    }

    public boolean disconnect(BluetoothDevice device) {
        Log.d(TAG, "BCProfile disonnect to  device: " + device);
        if (mService == null) return false;
        // Downgrade priority as user is disconnecting the Bassclient.
        if (mService.getConnectionPolicy(device) > BluetoothProfile.PRIORITY_ON){
            mService.setConnectionPolicy(device, BluetoothProfile.PRIORITY_ON);
        }
        return mService.disconnect(device);
    }

    public int getConnectionStatus(BluetoothDevice device) {
        if (mService == null) {
            return BluetoothProfile.STATE_DISCONNECTED;
        }
        return mService.getConnectionState(device);
    }

    public int getPreferred(BluetoothDevice device) {
        if (mService == null) return BluetoothProfile.CONNECTION_POLICY_UNKNOWN;
        return mService.getConnectionPolicy(device);
    }

    public void setPreferred(BluetoothDevice device, boolean preferred) {
        if (mService == null) return;
        if (preferred) {
            if (mService.getConnectionPolicy(device) !=
                       BluetoothProfile.CONNECTION_POLICY_ALLOWED) {
                mService.setConnectionPolicy(device,
                       BluetoothProfile.CONNECTION_POLICY_ALLOWED);
            }
        } else {
            mService.setConnectionPolicy(device, BluetoothProfile.CONNECTION_POLICY_UNKNOWN);
        }
    }

    public String toString() {
        return NAME;
    }

    public int getOrdinal() {
        return ORDINAL;
    }

    public int getNameResource(BluetoothDevice device) {
        return R.string.bluetooth_profile_bc;
    }

    public BleBroadcastAudioScanAssistManager getBSAManager(BluetoothDevice device,
                                                  BleBroadcastAudioScanAssistCallback callback) {
        if (mService == null) {
            Log.d(TAG, "getBroadcastAudioScanAssistManager: service is null");
            return null;
        }
        return mService.getBleBroadcastAudioScanAssistManager(device, callback);
    }

    public int getSummaryResourceForDevice(BluetoothDevice device) {
        int state = getConnectionStatus(device);
        switch (state) {
            case BluetoothProfile.STATE_DISCONNECTED:
                return R.string.bluetooth_bc_profile_summary_use_for;

            case BluetoothProfile.STATE_CONNECTED:
                return R.string.bluetooth_bc_profile_summary_connected;

            default:
                return BluetoothUtils.getConnectionStateSummary(state);
        }
    }

    public int getDrawableResource(BluetoothClass btClass) {
        return com.android.internal.R.drawable.ic_bt_hearing_aid;
    }

    protected void finalize() {
        Log.d(TAG, "finalize()");
        if (mService != null) {
            try {
                BluetoothAdapter.getDefaultAdapter().closeProfileProxy(BluetoothProfile.BC_PROFILE,
                                                                       mService);
                mService = null;
            }catch (Throwable t) {
                Log.w(TAG, "Error cleaning up BAss client proxy", t);
            }
        }
    }

    static boolean isBCSupported() {
        boolean isBCSupported = SystemProperties.getBoolean("persist.vendor.service.bt.bc", true);
        Log.d(TAG, "BassClientProfile: isBCSupported returns " + isBCSupported);
        return isBCSupported;
    }

    static public boolean isBASeeker(BluetoothDevice device) {
       //always send true
       boolean isSeeker = SystemProperties.getBoolean("persist.vendor.service.bt.baseeker", false);
       ParcelUuid[] uuids = null;
       if (device != null) {
          uuids = device.getUuids();
       }
       ParcelUuid sd = ParcelUuid.fromString("0000184F-0000-1000-8000-00805F9B34FB");
       if (isBCSupported()) {
           if (uuids != null) {
               for (ParcelUuid uid : uuids) {
                  if (uid.equals(sd)) {
                        Log.d(TAG, "SD uuid present");
                      isSeeker = true;
                  }
               }
           }
       }
       Log.d(TAG,"isBASeeker returns:" + isSeeker);
       return isSeeker;
    }

}
