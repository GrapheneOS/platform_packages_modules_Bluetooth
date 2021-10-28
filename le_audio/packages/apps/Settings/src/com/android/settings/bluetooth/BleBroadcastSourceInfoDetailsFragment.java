/*
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

import static android.os.UserManager.DISALLOW_CONFIG_BLUETOOTH;

import android.app.settings.SettingsEnums;
import android.bluetooth.BluetoothDevice;
import android.bluetooth.BleBroadcastSourceInfo;
import android.content.Context;
import android.os.Bundle;
import android.provider.DeviceConfig;
import android.util.Log;
import android.view.Menu;
import android.view.MenuInflater;
import android.view.MenuItem;


import com.android.settings.R;
import com.android.settings.core.SettingsUIDeviceConfig;
import com.android.settings.dashboard.RestrictedDashboardFragment;
import com.android.settings.overlay.FeatureFactory;
import com.android.settings.slices.BlockingSlicePrefController;
import com.android.settingslib.bluetooth.CachedBluetoothDevice;
import com.android.settingslib.bluetooth.LocalBluetoothManager;
import com.android.settingslib.core.AbstractPreferenceController;
import com.android.settingslib.core.lifecycle.Lifecycle;

import java.util.ArrayList;
import java.util.List;

public class BleBroadcastSourceInfoDetailsFragment extends RestrictedDashboardFragment {
    public static final String KEY_DEVICE_ADDRESS = "device_address";
    public static final String KEY_SOURCE_INFO = "broadcast_source_info";
    public static final String KEY_SOURCE_INFO_INDEX = "broadcast_source_index";
    private static final String TAG = "SourceInfoDetailsFrg";
    private Context mContext;

    String mDeviceAddress;
    CachedBluetoothDevice mCachedDevice;
    LocalBluetoothManager mManager;
    BleBroadcastSourceInfo mBleBroadcastSourceInfo;
    Integer mSourceInfoIndex = -1;

    public BleBroadcastSourceInfoDetailsFragment() {
        super(DISALLOW_CONFIG_BLUETOOTH);
    }

    CachedBluetoothDevice getCachedDevice(String deviceAddress) {
        BluetoothDevice remoteDevice =
                 mManager.getBluetoothAdapter().getRemoteDevice(deviceAddress);
        return mManager.getCachedDeviceManager().findDevice(remoteDevice);
     }

    public static BleBroadcastSourceInfoDetailsFragment newInstance(String deviceAddress) {
        Bundle args = new Bundle(1);
        args.putString(KEY_DEVICE_ADDRESS, deviceAddress);
        BleBroadcastSourceInfoDetailsFragment fragment = new BleBroadcastSourceInfoDetailsFragment();
        fragment.setArguments(args);
        return fragment;
    }

    @Override
    public void onAttach(Context context) {
        mDeviceAddress = getArguments().getString(KEY_DEVICE_ADDRESS);
        mManager = Utils.getLocalBtManager(context);
        mBleBroadcastSourceInfo = getArguments().getParcelable(KEY_SOURCE_INFO);
        mCachedDevice = getCachedDevice(mDeviceAddress);
        mSourceInfoIndex = getArguments().getInt(KEY_SOURCE_INFO_INDEX);
        super.onAttach(context);
        if (mCachedDevice == null) {
            // Close this page if device is null with invalid device mac address
            Log.w(TAG, "onAttach() CachedDevice is null!");
            finish();
            return;
        }
        if (mBleBroadcastSourceInfo == null) {
            Log.w(TAG, "onAttach()  mBleBroadcastSourceInfo null!");
            finish();
            return;
        }
        if (mSourceInfoIndex == null) {
            Log.w(TAG, "onAttach()  mSourceInfoIndex null!");
            finish();
            return;
        }
    }

    @Override
    public int getMetricsCategory() {
        return SettingsEnums.BLUETOOTH_DEVICE_DETAILS;
    }

    @Override
    protected String getLogTag() {
        return TAG;
    }

    @Override
    protected int getPreferenceScreenResId() {
        return R.xml.bcast_source_info_details_fragment;
    }

    @Override
    protected List<AbstractPreferenceController> createPreferenceControllers(Context context) {
        ArrayList<AbstractPreferenceController> controllers = new ArrayList<>();

        if (mCachedDevice != null && mBleBroadcastSourceInfo != null) {
            Lifecycle lifecycle = getSettingsLifecycle();
            controllers.add(new BleBroadcastSourceInfoDetailsController(context, this, mBleBroadcastSourceInfo,
                    mCachedDevice, mSourceInfoIndex, lifecycle));
        }
        return controllers;
    }
}
