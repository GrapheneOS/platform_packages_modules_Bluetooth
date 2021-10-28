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

import android.content.Context;

import androidx.preference.PreferenceFragmentCompat;
import androidx.preference.PreferenceScreen;

import com.android.settings.R;
import com.android.settingslib.bluetooth.CachedBluetoothDevice;
import com.android.settingslib.core.lifecycle.Lifecycle;
import com.android.settingslib.widget.ActionButtonsPreference;
import com.android.settingslib.bluetooth.BCProfile;
import com.android.settingslib.bluetooth.LocalBluetoothProfileManager;
import com.android.settingslib.bluetooth.LocalBluetoothManager;
import android.util.Log;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.FutureTask;
import com.android.settings.core.SubSettingLauncher;
import android.app.settings.SettingsEnums;
import android.os.Bundle;
import android.bluetooth.BluetoothProfile;
/**
 * This class adds two buttons: one to connect/disconnect from a device (depending on the current
 * connected state), and one to "Search for LE audio Broadcast sources" around.
 */
public class BluetoothDetailsAddSourceButtonController extends BluetoothDetailsController
                                    implements CachedBluetoothDevice.Callback {
    private static final String KEY_ACTION_BUTTONS = "sync_helper_buttons";
    private static final String TAG = "BluetoothDetailsAddSourceButtonController";
    private boolean mIsConnected = false;

    private ActionButtonsPreference mActionButtons;
    protected LocalBluetoothProfileManager mProfileManager;
    private LocalBluetoothManager mLocalBluetoothManager;
    private  BCProfile mBCProfile = null;


    public BluetoothDetailsAddSourceButtonController(Context context, PreferenceFragmentCompat fragment,
            CachedBluetoothDevice device, Lifecycle lifecycle) {
        super(context, fragment, device, lifecycle);
        device.registerCallback(this);

    }

    private void onAddLESourcePressed() {
         final Bundle args = new Bundle();
         args.putString(BluetoothSADetail.KEY_DEVICE_ADDRESS,
                 mCachedDevice.getDevice().getAddress());
         args.putShort(BluetoothSADetail.KEY_GROUP_OP,
                 (short)0);

        new SubSettingLauncher(mContext)
                .setDestination(BluetoothSADetail.class.getName())
                .setArguments(args)
                .setTitleRes(R.string.bluetooth_search_broadcasters)
                .setSourceMetricsCategory(SettingsEnums.BLUETOOTH_DEVICE_PICKER)
                 .launch();
    }

    @Override
    public void onDeviceAttributesChanged() {
        refresh();
    }

    @Override
    protected void init(PreferenceScreen screen) {
        BroadcastScanAssistanceUtils.debug(TAG, "init");
        mLocalBluetoothManager = Utils.getLocalBtManager(mContext);
        mProfileManager = mLocalBluetoothManager.getProfileManager();
        mBCProfile = (BCProfile)mProfileManager.getBCProfile();

        mActionButtons = ((ActionButtonsPreference) screen.findPreference(
                getPreferenceKey()))
                .setButton1Text(R.string.add_source_button_text)
                .setButton1Icon(R.drawable.ic_add_24dp)
                .setButton1OnClickListener((view) -> onAddLESourcePressed())
                .setButton1Enabled(false)
                ;
    }

    @Override
    protected void refresh() {
        BroadcastScanAssistanceUtils.debug(TAG, "refresh");
        if (mBCProfile != null) {
            mIsConnected = mBCProfile.getConnectionStatus(mCachedDevice.getDevice()) == BluetoothProfile.STATE_CONNECTED;
        }
        if (mIsConnected) {
            mActionButtons
                   .setButton1Enabled(true);
        } else {
             BroadcastScanAssistanceUtils.debug(TAG, "Bass is not connected for thsi device>>");
             mActionButtons
                    .setButton1Enabled(false);
        }
    }

    @Override
    public String getPreferenceKey() {
        return KEY_ACTION_BUTTONS;
    }

}
