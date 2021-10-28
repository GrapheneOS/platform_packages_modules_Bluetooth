/*
 *Copyright (c) 2018, The Linux Foundation. All rights reserved.
 * 
 * Copyright (C) 2017 The Android Open Source Project
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
package com.android.settings.bluetooth;

import android.bluetooth.BluetoothDevice;
import android.bluetooth.BleBroadcastSourceInfo;
import android.content.Context;
import android.util.Log;

import androidx.preference.Preference;

import com.android.settings.bluetooth.BleBroadcastSourceInfoPreferenceCallback;
import com.android.settings.dashboard.DashboardFragment;
import com.android.settingslib.bluetooth.CachedBluetoothDevice;

/**
 * Maintain and update saved bluetooth devices(bonded but not connected)
 */
public class BluetoothBroadcastSourceInfoEntries extends BleBroadcastSourceInfoUpdater
        implements Preference.OnPreferenceClickListener {
    private static final String TAG = "BluetoothBroadcastSourceInfoEntries";


    public BluetoothBroadcastSourceInfoEntries(Context context, DashboardFragment fragment,
            BleBroadcastSourceInfoPreferenceCallback bleBroadcastSourceInfoPreferenceCallback,
            CachedBluetoothDevice device) {
        super(context, fragment, bleBroadcastSourceInfoPreferenceCallback, device);
    }

    @Override
    public boolean onPreferenceClick(Preference preference) {
        final BleBroadcastSourceInfo srcInfo = ((BleBroadcastSourceInfoPreference) preference)
                .getBleBroadcastSourceInfo();
        BroadcastScanAssistanceUtils.debug(TAG, "onPreferenceClick: " + srcInfo);
        return true;
    }
}
