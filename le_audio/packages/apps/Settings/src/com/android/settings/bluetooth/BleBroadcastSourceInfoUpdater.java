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

import android.bluetooth.BluetoothAdapter;
import android.bluetooth.BluetoothDevice;
import android.bluetooth.BleBroadcastSourceInfo;
import android.content.Context;
import java.util.Iterator;
import android.os.Bundle;
import android.util.Log;

import androidx.preference.Preference;

import com.android.settings.R;
import com.android.settings.connecteddevice.DevicePreferenceCallback;
import com.android.settings.core.SubSettingLauncher;
import com.android.settings.dashboard.DashboardFragment;
import com.android.settings.widget.GearPreference;
import com.android.settingslib.bluetooth.BluetoothCallback;
import com.android.settingslib.bluetooth.BluetoothDeviceFilter;
import com.android.settingslib.bluetooth.CachedBluetoothDevice;
import com.android.settingslib.bluetooth.VendorCachedBluetoothDevice;
import com.android.settingslib.bluetooth.LocalBluetoothProfileManager;
import com.android.settingslib.bluetooth.LocalBluetoothManager;

import java.util.Collection;
import java.util.HashMap;
import java.util.Map;
import java.lang.Integer;

/**
 * Update the Ble broadcast source Info preference entries. It retrieves the Bluetooth broadcast source
 * information using CachedBluetoothDevice object from setting library
 * {@link BluetoothCallback}. It notifies the upper level whether to add/remove the preference
 * through {@link BleBroadcastSourceInfoPreferenceCallback}
 *
 * In {@link BleBroadcastSourceInfoUpdater}, it uses {@link BluetoothDeviceFilter.Filter} to detect
 * whether the {@link CachedBluetoothDevice} is relevant.
 */
public abstract class BleBroadcastSourceInfoUpdater implements CachedBluetoothDevice.Callback,
                                                             BluetoothCallback {
    private static final String TAG = "BleBroadcastSourceInfoUpdater";
    private static final boolean DBG = false;

    protected final BleBroadcastSourceInfoPreferenceCallback mBleSourceInfoPreferenceCallback;
    protected final Map<Integer, Preference> mPreferenceMap;
    protected Context mPrefContext;
    protected DashboardFragment mFragment;
    protected final CachedBluetoothDevice mCachedDevice;
    protected final VendorCachedBluetoothDevice mVendorCachedDevice;
    private LocalBluetoothManager mLocalManager;

    final GearPreference.OnGearClickListener mSourceInfoEntryListener = pref -> {
        launchSourceInfoDetails(pref);
    };

    public BleBroadcastSourceInfoUpdater(Context context, DashboardFragment fragment,
            BleBroadcastSourceInfoPreferenceCallback aBleSourceInfoPreferenceCallback,
            CachedBluetoothDevice device) {
        this(fragment, aBleSourceInfoPreferenceCallback ,device);
    }

    BleBroadcastSourceInfoUpdater(DashboardFragment fragment,
            BleBroadcastSourceInfoPreferenceCallback aBleSourceInfoPreferenceCallback,
            CachedBluetoothDevice device) {
        mCachedDevice = device;
        LocalBluetoothManager mgr = Utils.getLocalBtManager(mPrefContext);
        LocalBluetoothProfileManager profileManager = mgr.getProfileManager();
        mVendorCachedDevice = VendorCachedBluetoothDevice.getVendorCachedBluetoothDevice(device, profileManager);
        mFragment = fragment;
        mBleSourceInfoPreferenceCallback = aBleSourceInfoPreferenceCallback;
        mPreferenceMap = new HashMap<Integer, Preference>();
        mLocalManager = Utils.getLocalBtManager(mPrefContext);
        mLocalManager.getEventManager().registerCallback(this);
    }

    /**
     * Register the bluetooth event callback and update the list
     */
    public void registerCallback() {
        mCachedDevice.registerCallback(this);
        forceUpdate();
    }

    /**
     * Unregister the bluetooth event callback
     */
    public void unregisterCallback() {
        mCachedDevice.unregisterCallback(this);
    }

    @Override
    public void onBluetoothStateChanged(int bluetoothState) {
        BroadcastScanAssistanceUtils.debug(TAG, "onBluetoothStateChanged");
        if (bluetoothState == BluetoothAdapter.STATE_OFF) {
            removeAllBleBroadcastSourceInfosFromPreference();
        }
        //forceUpdate();
    }

    /**
     * Force to update the list of bluetooth devices
     */
    public void forceUpdate() {
        if (mCachedDevice != null &&
              mVendorCachedDevice.getNumberOfBleBroadcastReceiverStates() > 0) {
            final Map<Integer, BleBroadcastSourceInfo> srcInfos =
                    mVendorCachedDevice.getAllBleBroadcastreceiverStates();
            if (srcInfos == null) {
                Log.e(TAG, "srcInfos is null");
                return;
            }
            for (Map.Entry<Integer, BleBroadcastSourceInfo> entry: srcInfos.entrySet()) {
                update(entry.getKey(), entry.getValue());
            }
        } else {
          BroadcastScanAssistanceUtils.debug(TAG, "remove all the preferences as there are no rcvr states");
          removeAllBleBroadcastSourceInfosFromPreference();
        }
    }

    public void removeAllBleBroadcastSourceInfosFromPreference() {
        Iterator<Map.Entry<Integer, Preference>> entries = mPreferenceMap.entrySet().iterator();
        while (entries.hasNext())  {
        //for (Map.Entry<Integer, Preference> entry: mPreferenceMap.entrySet()) {
            Map.Entry<Integer, Preference> entry = entries.next();
            //removePreference(entry.getKey(), entry.getValue());
            mBleSourceInfoPreferenceCallback.onBroadcastSourceInfoRemoved(entry.getValue());
        }
        mPreferenceMap.clear();
    }

     @Override
     public void onDeviceAttributesChanged() {
         BroadcastScanAssistanceUtils.debug(TAG, "onDeviceAttributesChanged");
         forceUpdate();
     }

    /**
     * Set the context to generate the {@link Preference}, so it could get the correct theme.
     */
    public void setPrefContext(Context context) {
        mPrefContext = context;
    }

    /**
     * Update whether to show {@link CachedBluetoothDevice} in the list.
     */
    protected void update(Integer index, BleBroadcastSourceInfo sourceInfo) {
        addPreference(index, sourceInfo);
    }

    /**
     * Add the {@link Preference} that represents the {@code cachedDevice}
     */
    protected void addPreference(Integer index, BleBroadcastSourceInfo sourceInfo) {
        final BluetoothDevice device = sourceInfo.getSourceDevice();
        final byte sourceId = sourceInfo.getSourceId();
        if (mPreferenceMap.containsKey(index) == false) {
            BroadcastScanAssistanceUtils.debug(TAG, "source info addition");
            BleBroadcastSourceInfoPreference sourceInfoPreference =
                    new BleBroadcastSourceInfoPreference(mPrefContext,
                            mCachedDevice,
                            sourceInfo,
                            index,
                            BleBroadcastSourceInfoPreference.SortType.TYPE_DEFAULT);
            sourceInfoPreference.setOnGearClickListener(mSourceInfoEntryListener);
            if (this instanceof Preference.OnPreferenceClickListener) {
                sourceInfoPreference.setOnPreferenceClickListener(
                        (Preference.OnPreferenceClickListener)this);
            }
            BroadcastScanAssistanceUtils.debug(TAG, "source info newly added: " + index);
            mPreferenceMap.put(index, sourceInfoPreference);
            mBleSourceInfoPreferenceCallback.onBroadcastSourceInfoAdded(sourceInfoPreference);
        } else {
            BleBroadcastSourceInfoPreference pref = (BleBroadcastSourceInfoPreference)mPreferenceMap.get(index);
            BleBroadcastSourceInfo currentSi = pref.getBleBroadcastSourceInfo();
            if (currentSi != null && currentSi.equals(sourceInfo)) {
                BroadcastScanAssistanceUtils.debug(TAG, "No change in SI" + index);
            } else {
                BroadcastScanAssistanceUtils.debug(TAG, "source info Updated: " + index);
                pref.setBleBroadcastSourceInfo (sourceInfo);

                /*mBleSourceInfoPreferenceCallback.onBroadcastSourceInfoRemoved(mPreferenceMap.get(index));
                mPreferenceMap.remove(index);

                BleBroadcastSourceInfoPreference sourceInfoPreference =
                    new BleBroadcastSourceInfoPreference(mPrefContext,
                            mCachedDevice,
                            sourceInfo,
                            index,
                            BleBroadcastSourceInfoPreference.SortType.TYPE_DEFAULT);
                sourceInfoPreference.setOnGearClickListener(mSourceInfoEntryListener);
                if (this instanceof Preference.OnPreferenceClickListener) {
                    sourceInfoPreference.setOnPreferenceClickListener(
                        (Preference.OnPreferenceClickListener)this);
                }
                BroadcastScanAssistanceUtils.debug(TAG, "source info added again: " + index);
                mPreferenceMap.put(index, sourceInfoPreference);
                mBleSourceInfoPreferenceCallback.onBroadcastSourceInfoAdded(sourceInfoPreference);*/
            }
        }
    }

    /**
     * Remove the {@link Preference} that represents the {@code cachedDevice}
     */
    protected void removePreference(int index, Preference pref) {
        if (mPreferenceMap.containsKey(index)) {
            mBleSourceInfoPreferenceCallback.onBroadcastSourceInfoRemoved(mPreferenceMap.get(index));
            mPreferenceMap.remove(index);
        }
    }

    /**
     * Get {@link CachedBluetoothDevice} from {@link Preference} and it is used to init
     * {@link SubSettingLauncher} to launch {@link BluetoothDeviceDetailsFragment}
     */
    protected void launchSourceInfoDetails(Preference preference) {
        final BleBroadcastSourceInfo srcInfo =
                ((BleBroadcastSourceInfoPreference) preference).getBleBroadcastSourceInfo();
        if (srcInfo == null) {
            return;
        }
        final int index = ((BleBroadcastSourceInfoPreference) preference).getSourceInfoIndex();
        final Bundle args = new Bundle();
        args.putString(BleBroadcastSourceInfoDetailsFragment.KEY_DEVICE_ADDRESS,
                mCachedDevice.getAddress());
        args.putParcelable(BleBroadcastSourceInfoDetailsFragment.KEY_SOURCE_INFO,
                srcInfo);
        args.putInt(BleBroadcastSourceInfoDetailsFragment.KEY_SOURCE_INFO_INDEX,
                      index);

        new SubSettingLauncher(mFragment.getContext())
                .setDestination(BleBroadcastSourceInfoDetailsFragment.class.getName())
                .setArguments(args)
                .setTitleRes(R.string.source_info_details_title)
                .setSourceMetricsCategory(mFragment.getMetricsCategory())
                .launch();
    }
}
