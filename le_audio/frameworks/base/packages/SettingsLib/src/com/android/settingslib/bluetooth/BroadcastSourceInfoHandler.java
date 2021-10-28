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


package com.android.settingslib.bluetooth;

import android.bluetooth.BluetoothAdapter;
import android.bluetooth.BluetoothDevice;
import android.content.Context;
import android.util.Log;
import android.bluetooth.BleBroadcastAudioScanAssistManager;
import com.android.settingslib.bluetooth.CachedBluetoothDeviceManager;
import android.content.Intent;
import android.bluetooth.BleBroadcastSourceInfo;
import android.os.Handler;

public class BroadcastSourceInfoHandler implements BluetoothEventManager.Handler {
        private static final String TAG = "BroadcastSourceInfoHandler";
        private static final boolean V = Log.isLoggable(TAG, Log.VERBOSE);
        private final CachedBluetoothDeviceManager mDeviceManager;
        BroadcastSourceInfoHandler(CachedBluetoothDeviceManager deviceManager
            ) {
            mDeviceManager = deviceManager;
        }
        @Override
        public void onReceive(Context context, Intent intent, BluetoothDevice device) {
            if (device == null) {
                Log.w(TAG, "BroadcastSourceInfoHandler: device is null");
                return;
            }

            final String action = intent.getAction();
            if (action == null) {
                Log.w(TAG, "BroadcastSourceInfoHandler: action is null");
                return;
            }
            BleBroadcastSourceInfo sourceInfo = intent.getParcelableExtra(
                              BleBroadcastSourceInfo.EXTRA_SOURCE_INFO);

            int sourceInfoIdx = intent.getIntExtra(
                              BleBroadcastSourceInfo.EXTRA_SOURCE_INFO_INDEX,
                              BluetoothAdapter.ERROR);

            int maxNumOfsrcInfo = intent.getIntExtra(
                              BleBroadcastSourceInfo.EXTRA_MAX_NUM_SOURCE_INFOS,
                              BluetoothAdapter.ERROR);
            if (V) {
                Log.d(TAG, "Rcved :BCAST_RECEIVER_STATE Intent for : " + device);
                Log.d(TAG, "Rcvd BroadcastSourceInfo index=" + sourceInfoIdx);
                Log.d(TAG, "Rcvd max num of source Info=" + maxNumOfsrcInfo);
                Log.d(TAG, "Rcvd BroadcastSourceInfo=" + sourceInfo);
            }
            CachedBluetoothDevice cachedDevice = mDeviceManager.findDevice(device);
            VendorCachedBluetoothDevice vDevice =
            VendorCachedBluetoothDevice.getVendorCachedBluetoothDevice(cachedDevice, null);
            if (vDevice != null) {
                vDevice.onBroadcastReceiverStateChanged(sourceInfo,
                                     sourceInfoIdx, maxNumOfsrcInfo);
                cachedDevice.dispatchAttributesChanged();
            } else {
                Log.e(TAG, "No vCachedDevice created for this Device");
            }
        }
};
