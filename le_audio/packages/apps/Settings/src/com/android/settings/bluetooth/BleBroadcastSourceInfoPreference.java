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

package com.android.settings.bluetooth;

import static android.os.UserManager.DISALLOW_CONFIG_BLUETOOTH;

import android.app.settings.SettingsEnums;
import android.bluetooth.BluetoothDevice;
import android.bluetooth.BluetoothAdapter;
import android.bluetooth.BleBroadcastSourceInfo;
import android.content.Context;
import android.content.DialogInterface;
import android.content.res.Resources;
import android.graphics.drawable.Drawable;
import android.os.UserManager;
import android.text.Html;
import android.text.TextUtils;
import android.util.Pair;
import android.util.TypedValue;
import android.view.View;
import android.widget.ImageView;
import android.util.Log;

import androidx.annotation.IntDef;
import androidx.annotation.VisibleForTesting;
import androidx.appcompat.app.AlertDialog;
import androidx.preference.Preference;
import androidx.preference.PreferenceViewHolder;

import com.android.settings.R;
import com.android.settings.overlay.FeatureFactory;
import com.android.settings.widget.GearPreference;
import com.android.settingslib.bluetooth.BluetoothUtils;
import com.android.settingslib.bluetooth.CachedBluetoothDevice;
import com.android.settingslib.core.instrumentation.MetricsFeatureProvider;

import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.Integer;
import java.lang.String;
/**
 * BleBroadcastSourceInfoPreference is the preference type used to display each
 * Broadcast Source information stored in the Remote Scan delegator.
 */
public final class BleBroadcastSourceInfoPreference extends GearPreference implements
        CachedBluetoothDevice.Callback {
    private static final String TAG = "BleBroadcastSourceInfoPreference";

    private static String EMPTY_BD_ADDR = "00:00:00:00:00:00";

    @Retention(RetentionPolicy.SOURCE)
    @IntDef({SortType.TYPE_DEFAULT,
            SortType.TYPE_FIFO})
    public @interface SortType {
        int TYPE_DEFAULT = 1;
        int TYPE_FIFO = 2;
    }

    private final CachedBluetoothDevice mCachedDevice;
    private BleBroadcastSourceInfo mBleSourceInfo;
    private final Integer mIndex;
    private final long mCurrentTime;
    private final int mType;

    ///private String contentDescription = null;
    //@VisibleForTesting
    //boolean mNeedNotifyHierarchyChanged = false;
    /* Talk-back descriptions for various BT icons */
    Resources mResources;

    public BleBroadcastSourceInfoPreference(Context context, CachedBluetoothDevice device,
            BleBroadcastSourceInfo sourceInfo,
            Integer index, @SortType int type) {
        super(context, null);
        mResources = getContext().getResources();
        mIndex = index;

        mCachedDevice = device;
        mBleSourceInfo = sourceInfo;
        mCachedDevice.registerCallback(this);
        mCurrentTime = System.currentTimeMillis();
        mType = type;

        onDeviceAttributesChanged();
    }


    @Override
    protected boolean shouldHideSecondTarget() {
        return (mBleSourceInfo == null);
    }

    @Override
    protected int getSecondTargetResId() {
        return R.layout.preference_widget_gear;
    }

    CachedBluetoothDevice getCachedDevice() {
        return mCachedDevice;
    }

    public BleBroadcastSourceInfo getBleBroadcastSourceInfo() {
        return mBleSourceInfo;
    }

    public void setBleBroadcastSourceInfo(BleBroadcastSourceInfo srcInfo) {
        mBleSourceInfo = srcInfo;
        //refresh
        onDeviceAttributesChanged();
    }

    Integer getSourceInfoIndex() {
        return mIndex;
    }

    @Override
    protected void onPrepareForRemoval() {
        super.onPrepareForRemoval();
        mCachedDevice.unregisterCallback(this);
    }

    String formSyncSummaryString(BleBroadcastSourceInfo srcInfo) {
        String metadataStatus = "Metadata Synced";
        String audioSyncStatus = "Audio Synced";

        if (srcInfo.getMetadataSyncState() == BleBroadcastSourceInfo.BROADCAST_ASSIST_PA_SYNC_STATE_IN_SYNC) {
            metadataStatus = "Metadata Synced";
        } else {
            metadataStatus = "Metadata not synced";
        }

        if (srcInfo.getAudioSyncState() == BleBroadcastSourceInfo.BROADCAST_ASSIST_AUDIO_SYNC_STATE_SYNCHRONIZED) {
            audioSyncStatus = "Audio Synced";
        } else {
            audioSyncStatus = "Audio not synced";
        }
        return metadataStatus + ", " + audioSyncStatus;
    }

    public void onDeviceAttributesChanged() {
        BluetoothDevice dev = mBleSourceInfo.getSourceDevice();
        BluetoothAdapter adapter = BluetoothAdapter.getDefaultAdapter();
        String s = null;
        if (dev != null && adapter != null) {
            if (adapter.getAddress().equals(dev.getAddress()))
            {
               s = adapter.getName() + "(Self)";
            } else {
               s = dev.getAlias();
            }
            if (s == null) {
                s = String.valueOf(dev.getAddress());
            }
        }
        if (s == null || s.equals(EMPTY_BD_ADDR)) {
            BroadcastScanAssistanceUtils.debug(TAG, "seem to be an entry source Info");
            s = "EMPTY ENTRY";
        }
        setTitle(s);
        setIcon(R.drawable.ic_media_stream);
        if (!mBleSourceInfo.isEmptyEntry()) {
            //Show the status only If it is not an Empty Entry
            setSummary(formSyncSummaryString(mBleSourceInfo));
        } else {
            setSummary("");
        }
        setVisible(true);

        // This could affect ordering, so notify that
        notifyHierarchyChanged();
    }



    @Override
    public boolean equals(Object o) {
        if ((o == null) || !(o instanceof BleBroadcastSourceInfoPreference)) {
            BroadcastScanAssistanceUtils.debug(TAG, "Not an Instance of BleBroadcastSourceInfoPreference:");
            return false;
        }
        BleBroadcastSourceInfo otherSrc = ((BleBroadcastSourceInfoPreference) o).mBleSourceInfo;
        BroadcastScanAssistanceUtils.debug(TAG, "Comparing: " + mBleSourceInfo);
        BroadcastScanAssistanceUtils.debug(TAG, "TO: " + otherSrc);
        boolean ret = (mBleSourceInfo.getSourceId() == otherSrc.getSourceId());
        BroadcastScanAssistanceUtils.debug(TAG, "equals returns: " + ret);

        return ret;
    }

    @Override
    public int hashCode() {
        return mBleSourceInfo.hashCode();
    }

    @Override
    public int compareTo(Preference another) {
        if (!(another instanceof BleBroadcastSourceInfoPreference)) {
            // Rely on default sort
            return super.compareTo(another);
        }

        switch (mType) {
            case SortType.TYPE_DEFAULT:
                BroadcastScanAssistanceUtils.debug(TAG, ">>compareTo");
                return mIndex > ((BleBroadcastSourceInfoPreference) another).getSourceInfoIndex() ? 1 : -1;
            case SortType.TYPE_FIFO:
                return mCurrentTime > ((BleBroadcastSourceInfoPreference) another).mCurrentTime ? 1 : -1;
            default:
                return super.compareTo(another);
        }
    }

    void onClicked() {
        Context context = getContext();

        final MetricsFeatureProvider metricsFeatureProvider =
                FeatureFactory.getFactory(context).getMetricsFeatureProvider();

    }
}
