/*
 * Copyright (C) 2008 The Android Open Source Project
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

package com.android.settingslib.bluetooth;

import android.bluetooth.BluetoothAdapter;
import android.bluetooth.BluetoothClass;
import android.bluetooth.BluetoothDevice;
import android.bluetooth.BluetoothHearingAid;
import android.bluetooth.BleBroadcastSourceInfo;
import android.bluetooth.BleBroadcastSourceChannel;
import android.bluetooth.BluetoothProfile;
import android.bluetooth.BleBroadcastAudioScanAssistManager;
import android.bluetooth.BleBroadcastAudioScanAssistCallback;
import android.bluetooth.le.ScanResult;
import android.bluetooth.BluetoothUuid;
import android.os.ParcelUuid;
import android.content.Context;
import android.content.SharedPreferences;
import java.util.IdentityHashMap;
import android.os.Handler;
import android.os.Looper;
import android.os.Message;
import android.os.ParcelUuid;
import android.os.SystemClock;
import java.util.HashMap;
import java.util.Map;
import java.util.List;
import android.text.TextUtils;
import android.util.EventLog;
import android.util.Log;
import java.lang.Integer;

import android.os.SystemProperties;
import androidx.annotation.VisibleForTesting;

import com.android.internal.util.ArrayUtils;
import com.android.settingslib.R;
import com.android.settingslib.Utils;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * VendorCachedBluetoothDevice represents a remote Bluetooth device. It contains
 * attributes of the device (such as the address, name, RSSI, etc.) and
 * functionality that can be performed on the device (connect, pair, disconnect,
 * etc.).
 */
public class VendorCachedBluetoothDevice extends CachedBluetoothDevice {
    private static final String TAG = "VendorCachedBluetoothDevice";
    private static final boolean V = Log.isLoggable(TAG, Log.VERBOSE);
    private ScanResult mScanRes = null;
    private BleBroadcastAudioScanAssistManager mScanAssistManager;
    static private Map<Integer, BleBroadcastSourceInfo> mBleBroadcastReceiverStates
        = new HashMap<Integer, BleBroadcastSourceInfo>();
    private LocalBluetoothProfileManager mProfileManager = null;
    static private Map<CachedBluetoothDevice,
                 VendorCachedBluetoothDevice> mVcbdEntries = new IdentityHashMap<CachedBluetoothDevice, VendorCachedBluetoothDevice>();

    public static VendorCachedBluetoothDevice getVendorCachedBluetoothDevice(
                     CachedBluetoothDevice cachedDevice,
                     LocalBluetoothProfileManager profileManager) {
        VendorCachedBluetoothDevice vCbd = null;
        if (mVcbdEntries != null) {
            vCbd = mVcbdEntries.get(cachedDevice);
        }
        //dont create new instance if profileMgr is null
        if (vCbd == null && profileManager != null) {
            vCbd = new VendorCachedBluetoothDevice(cachedDevice,
                                                  profileManager);
            Log.d(TAG, "getVendorCachedBluetoothDevice: created new Instance");
            mVcbdEntries.put(cachedDevice, vCbd);
        }
        return vCbd;
    }

    VendorCachedBluetoothDevice(CachedBluetoothDevice cachedDevice,LocalBluetoothProfileManager profileManager) {
        super(cachedDevice);
        mProfileManager = profileManager;
        mBleBroadcastReceiverStates = new HashMap<Integer, BleBroadcastSourceInfo>();
        InitializeSAManager();
    }

    VendorCachedBluetoothDevice(Context context, LocalBluetoothProfileManager profileManager,
            BluetoothDevice device) {
         super(context, profileManager, device);
        mProfileManager = profileManager;
        mBleBroadcastReceiverStates = new HashMap<Integer, BleBroadcastSourceInfo>();
        InitializeSAManager();
    }

    /**
     * Describes the current device and profile for logging.
     *
     * @param profile Profile to describe
     * @return Description of the device and profile
     */
    private String describe(LocalBluetoothProfile profile) {
        StringBuilder sb = new StringBuilder();
        sb.append("Address:").append(mDevice);
        if (profile != null) {
            sb.append(" Profile:").append(profile);
        }

        return sb.toString();
    }

    void onProfileStateChanged(LocalBluetoothProfile profile, int newProfileState) {
        if (V) {
            Log.d(TAG, "onProfileStateChanged: profile " + profile + ", device=" + mDevice
                    + ", newProfileState " + newProfileState);
        }
        if (profile instanceof BCProfile
                 && newProfileState == BluetoothProfile.STATE_DISCONNECTED) {
           cleanUpSAMananger();
           super.dispatchAttributesChanged();
       }
    }

    private BleBroadcastAudioScanAssistCallback mScanAssistCallback = new BleBroadcastAudioScanAssistCallback() {
        public void onBleBroadcastSourceFound(ScanResult res) {
            if (V) {
                Log.d(TAG, "onBleBroadcastSourceFound" + res.getDevice());
            }
            setScanResult(res);
        };

        public void onBleBroadcastAudioSourceAdded(BluetoothDevice rcvr,
                                                byte srcId,
                                                int status) {
        };

        public void onBleBroadcastSourceSelected( int status,
            List<BleBroadcastSourceChannel> broadcastSourceIndicies) {
        };

        public void onBleBroadcastAudioSourceUpdated(BluetoothDevice rcvr,
                                             byte srcId,
                                             int status) {
        };

        public void onBleBroadcastPinUpdated(BluetoothDevice rcvr,
                                                byte srcId,
                                                int status) {
        };
        public void onBleBroadcastAudioSourceRemoved(BluetoothDevice rcvr,
                                             byte srcId,
                                             int status) {
        };
    };

    public BleBroadcastAudioScanAssistManager getScanAssistManager()
    {   InitializeSAManager();
        return mScanAssistManager;
    }

    void InitializeSAManager() {
        BCProfile bcProfile = (BCProfile)mProfileManager.getBCProfile();
        mScanAssistManager = bcProfile.getBSAManager(
                                  mDevice, mScanAssistCallback);
    }

    void cleanUpSAMananger() {
        mScanAssistManager = null;
        if (mBleBroadcastReceiverStates != null) {
            mBleBroadcastReceiverStates.clear();
        }
    }

    void updateBroadcastreceiverStates(BleBroadcastSourceInfo srcInfo, int index,
                                       int maxSourceInfosNum) {
        BleBroadcastSourceInfo entry = mBleBroadcastReceiverStates.get(index);
        if (entry != null) {
            Log.d(TAG, "updateBroadcastreceiverStates: Replacing receiver State Information");
            mBleBroadcastReceiverStates.replace(index, srcInfo);
        } else {
            mBleBroadcastReceiverStates.put(index, srcInfo);
        }
        super.dispatchAttributesChanged();
    }

    public int getNumberOfBleBroadcastReceiverStates() {
        int ret = 0;
        if (mScanAssistManager == null) {
            InitializeSAManager();
            if (mScanAssistManager == null) {
                return ret;
            }
        }
        List<BleBroadcastSourceInfo> srcInfo = mScanAssistManager.getAllBroadcastSourceInformation();
        if (srcInfo != null) {
            ret = srcInfo.size();
        }
        if (V) {
            Log.d(TAG, "getNumberOfBleBroadcastReceiverStates:"+ ret);
        }
        return ret;
    }

    public Map<Integer, BleBroadcastSourceInfo> getAllBleBroadcastreceiverStates() {
        if (mScanAssistManager == null) {
            InitializeSAManager();
            if (mScanAssistManager == null) {
                Log.e(TAG, "SA Manager cant be initialized");
                return null;
            }
        }
        List<BleBroadcastSourceInfo> srcInfos = mScanAssistManager.getAllBroadcastSourceInformation();
        if (srcInfos == null) {
             Log.e(TAG, "getAllBleBroadcastreceiverStates: no src Info");
             return null;
        }
        for (int i=0; i<srcInfos.size(); i++) {
            BleBroadcastSourceInfo sI = srcInfos.get(i);
            mBleBroadcastReceiverStates.put((int)sI.getSourceId(), sI);
        }
        return  mBleBroadcastReceiverStates;
    }

    void onBroadcastReceiverStateChanged (BleBroadcastSourceInfo srcInfo, int index,
                                          int maxSourceInfoNum) {
       updateBroadcastreceiverStates(srcInfo, index, maxSourceInfoNum);
    }

    public void setScanResult(ScanResult res) {
        mScanRes = res;
    }

    public ScanResult getScanResult() {
        return mScanRes;
    }

    @androidx.annotation.Keep
    public boolean isBroadcastAudioSynced() {
        if (mScanAssistManager == null) {
            InitializeSAManager();
            if (mScanAssistManager == null) {
                Log.e(TAG, "SA Manager cant be initialized");
                return false;
            }
        }
        List<BleBroadcastSourceInfo> srcInfos = mScanAssistManager.getAllBroadcastSourceInformation();
        if (srcInfos == null) {
             Log.e(TAG, "isBroadcastAudioSynced: no src Info");
             return false;
        }
        for (int i=0; i<srcInfos.size(); i++) {
            BleBroadcastSourceInfo sI = srcInfos.get(i);
            if (sI.getAudioSyncState() ==
                    BleBroadcastSourceInfo.BROADCAST_ASSIST_AUDIO_SYNC_STATE_SYNCHRONIZED) {
                return true;
            }
        }
        Log.d(TAG,"isAudioSynced: false");
        return false;
    }
}
