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
package com.android.settings.bluetooth;

import android.content.Context;
import android.content.pm.PackageManager;

import androidx.annotation.VisibleForTesting;
import androidx.preference.Preference;
import androidx.preference.PreferenceGroup;
import androidx.preference.PreferenceScreen;

import com.android.settingslib.bluetooth.CachedBluetoothDevice;
import com.android.settings.bluetooth.BluetoothDeviceUpdater;
import com.android.settings.bluetooth.SavedBluetoothDeviceUpdater;
import com.android.settings.connecteddevice.dock.DockUpdater;
import com.android.settings.connecteddevice.DevicePreferenceCallback;
import com.android.settings.core.BasePreferenceController;
import com.android.settings.dashboard.DashboardFragment;
import com.android.settings.overlay.FeatureFactory;
import com.android.settingslib.core.lifecycle.LifecycleObserver;
import com.android.settingslib.core.lifecycle.Lifecycle;
import com.android.settingslib.core.lifecycle.events.OnStart;
import com.android.settingslib.core.lifecycle.events.OnStop;
import android.util.Log;
import androidx.annotation.Keep;

@Keep
public class BADevicePreferenceController extends BasePreferenceController
        implements LifecycleObserver, OnStart, OnStop, BleBroadcastSourceInfoPreferenceCallback {

    private static final String TAG = "BADevicePreferenceController";
    //Up to 3 Elements can be viewed here
    private static final int MAX_DEVICE_NUM = 3;

    private PreferenceGroup mPreferenceGroup;
    private BluetoothBroadcastSourceInfoEntries mBleSourceInfoUpdater;
    private int mPreferenceSize;
    private CachedBluetoothDevice mCachedDevice;

    public BADevicePreferenceController(Context context, Lifecycle lifecycle, String preferenceKey) {
        super(context, preferenceKey);

        lifecycle.addObserver(this);
        BroadcastScanAssistanceUtils.debug(TAG, "constructor: KEY" + preferenceKey);
    }

    @Override
    public int getAvailabilityStatus() {
        return (mContext.getPackageManager().hasSystemFeature(PackageManager.FEATURE_BLUETOOTH)
                )
                ? AVAILABLE
                : CONDITIONALLY_UNAVAILABLE;
    }

    @Override
    public String getPreferenceKey() {
        return new String("added_sources");
    }

    @Override
    public void displayPreference(PreferenceScreen screen) {
        BroadcastScanAssistanceUtils.debug(TAG, "displayPreference");
        super.displayPreference(screen);
        mPreferenceGroup = screen.findPreference(getPreferenceKey());
        mPreferenceGroup.setVisible(false);

        if (isAvailable()) {
            BroadcastScanAssistanceUtils.debug(TAG, "registering wth BleSrcInfo updaters");
            final Context context = screen.getContext();
            if (mBleSourceInfoUpdater != null) {
                mBleSourceInfoUpdater.setPrefContext(context);
            }
        }
    }

    @Override
    public void onStart() {
        if (mBleSourceInfoUpdater != null) {
            mBleSourceInfoUpdater.registerCallback();
        }
    }

    @Override
    public void onStop() {
        if (mBleSourceInfoUpdater != null) {
            mBleSourceInfoUpdater.unregisterCallback();
        }
    }

    public void init(DashboardFragment fragment, CachedBluetoothDevice device) {
        BroadcastScanAssistanceUtils.debug(TAG, "Init");
        mCachedDevice = device;
        mBleSourceInfoUpdater = new BluetoothBroadcastSourceInfoEntries(fragment.getContext(),
                fragment, BADevicePreferenceController.this,
                device);
        mPreferenceSize = 0;
    }

    @Override
    public void onBroadcastSourceInfoAdded(Preference preference) {
        BroadcastScanAssistanceUtils.debug(TAG, "onBroadcastSourceInfoAdded");

        if (mPreferenceSize < MAX_DEVICE_NUM) {
            boolean ret = mPreferenceGroup.addPreference(preference);
            BroadcastScanAssistanceUtils.debug(TAG, "addPreference returns" + ret);
            mPreferenceSize++;
        }
        updatePreferenceVisiblity();
    }

    @Override
    public void onBroadcastSourceInfoRemoved(Preference preference) {
         BroadcastScanAssistanceUtils.debug(TAG, "onBroadcastSourceInfoRemoved");
        mPreferenceSize--;
        boolean ret = mPreferenceGroup.removePreference(preference);
        BroadcastScanAssistanceUtils.debug(TAG, "removePreference returns " + ret);
        updatePreferenceVisiblity();
    }

    @VisibleForTesting
    void setPreferenceGroup(PreferenceGroup preferenceGroup) {
        mPreferenceGroup = preferenceGroup;
    }

    @VisibleForTesting
    void updatePreferenceVisiblity() {
        BroadcastScanAssistanceUtils.debug(TAG, "updatePreferenceVisiblity:"  + mPreferenceSize);
        mPreferenceGroup.setVisible(mPreferenceSize > 0);
    }
}
