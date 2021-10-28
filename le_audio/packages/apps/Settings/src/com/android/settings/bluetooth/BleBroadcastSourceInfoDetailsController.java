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

import android.bluetooth.BluetoothDevice;
import android.bluetooth.BluetoothProfile;
import android.bluetooth.BluetoothAdapter;
import android.bluetooth.BleBroadcastSourceInfo;
import android.bluetooth.BleBroadcastAudioScanAssistManager;
import android.bluetooth.BleBroadcastSourceChannel;
import android.bluetooth.BleBroadcastSourceChannel;

import android.content.Context;
import android.text.TextUtils;
import android.util.Log;
import java.lang.String;
import androidx.annotation.VisibleForTesting;
import androidx.preference.Preference;
import androidx.preference.PreferenceCategory;
import androidx.preference.PreferenceFragmentCompat;
import androidx.preference.PreferenceScreen;
import androidx.preference.SwitchPreference;
import androidx.preference.EditTextPreference;
import androidx.preference.MultiSelectListPreference;
import com.android.settingslib.widget.ActionButtonsPreference;

import com.android.settingslib.bluetooth.A2dpProfile;
import com.android.settingslib.bluetooth.CachedBluetoothDevice;
import com.android.settingslib.bluetooth.VendorCachedBluetoothDevice;
import com.android.settingslib.bluetooth.LocalBluetoothProfile;
import com.android.settingslib.bluetooth.LocalBluetoothProfileManager;
import com.android.settingslib.bluetooth.LocalBluetoothManager;
import com.android.settingslib.bluetooth.MapProfile;
import com.android.settingslib.bluetooth.PanProfile;
import com.android.settingslib.bluetooth.PbapServerProfile;
import com.android.settingslib.core.lifecycle.Lifecycle;
import androidx.appcompat.app.AlertDialog;
import android.text.Html;
import android.text.TextUtils;
import android.content.DialogInterface;
import android.widget.Toast;

import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.HashSet;
import java.util.Arrays;
import java.util.Iterator;
import com.android.settings.R;
import java.util.Map;

/**
 * This class Broadcast Source Info details of the given Scan delegator
 */
public class BleBroadcastSourceInfoDetailsController extends BluetoothDetailsController
        implements Preference.OnPreferenceClickListener,
         Preference.OnPreferenceChangeListener, CachedBluetoothDevice.Callback {
    private static final String TAG = "BleBroadcastSourceInfoDetailsController";
    private final String EMPTY_BD_ADDRESS = "00:00:00:00:00:00";

    //Display controls
    private static final String KEY_SOURCE_INFO_GROUP = "broadcast_source_details_category";
    private static final String KEY_SOURCE_ID = "broadcast_si_sourceId";
    private static final String KEY_SOURCE_DEVICE = "broadcast_si_source_address";
    private static final String KEY_SOURCE_ENC_STATUS = "broadcast_si_encryption_state";
    private static final String KEY_SOURCE_METADATA = "broadcast_si_metadata";
    private static final String KEY_SOURCE_METADATA_STATE = "broadcast_si_metadata_state";
    private static final String KEY_SOURCE_AUDIO_STATE = "broadcast_si_audio_state";

    //Input Controls
    private static final String KEY_SOURCE_METADATA_SWITCH = "broadcast_si_enable_metadata_sync";
    private static final String KEY_SOURCE_AUDIOSYNC_SWITCH = "broadcast_si_enable_audio_sync";
    private static final String KEY_UPDATE_BCAST_CODE = "update_broadcast_code";
    private static final String KEY_UPDATE_SOURCE_INFO = "bcast_si_update_button";
    private static final String KEY_REMOVE_SOURCE_INFO = "bcast_si_remove_button";

    private CachedBluetoothDevice mCachedDevice;
    private VendorCachedBluetoothDevice mVendorCachedDevice;
    private PreferenceCategory mSourceInfoContainer;

    private Preference mSourceIdPref;
    private Preference mSourceDevicePref;
    private Preference mSourceEncStatusPref;
    private Preference mSourceMetadataPref;
    private Preference mSourceMetadataSyncStatusPref;
    private MultiSelectListPreference mSourceAudioSyncStatusPref;
    private SwitchPreference mSourceMetadataSyncSwitchPref;
    private SwitchPreference mSourceAudioSyncSwitchPref;
    private EditTextPreference mSourceUpdateBcastCodePref;
    private ActionButtonsPreference mSourceUpdateSourceInfoPref;
    private ActionButtonsPreference mSourceRemoveSourceInfoPref;
    private boolean mIsValueChanged = false;
    private BleBroadcastSourceInfo mBleBroadcastSourceInfo;
    private BleBroadcastAudioScanAssistManager mScanAssistanceMgr;
    private boolean isBroadcastPINUpdated = false;
    private String mBroadcastCode;
    private int mSourceInfoIndex;
    private String EMPTY_ENTRY = "EMPTY ENTRY";
    private int mMetadataSyncState;
    private int mAudioSyncState;
    private boolean mIsButtonRefreshOnly = false;
    private boolean mGroupOp = false;
    private AlertDialog mScanAssistGroupOpDialog = null;
    private List<BleBroadcastSourceChannel> mBisIndicies;
    private boolean mPAsyncCtrlNeeded = false;

    public BleBroadcastSourceInfoDetailsController(Context context,
            PreferenceFragmentCompat fragment,
            BleBroadcastSourceInfo bleSourceInfo, CachedBluetoothDevice device,
            int sourceInfoIndex, Lifecycle lifecycle) {
        super(context, fragment, device, lifecycle);
        Context mContext = context;
        mBleBroadcastSourceInfo = bleSourceInfo;
        mCachedDevice = device;
        LocalBluetoothManager mgr = Utils.getLocalBtManager(context);
        LocalBluetoothProfileManager profileManager = mgr.getProfileManager();
        mVendorCachedDevice = VendorCachedBluetoothDevice.getVendorCachedBluetoothDevice(device, profileManager);
        mScanAssistanceMgr = mVendorCachedDevice.getScanAssistManager();
        lifecycle.addObserver(this);
        mSourceInfoIndex = sourceInfoIndex;
        clearInputs();
        mPAsyncCtrlNeeded = false;
    }

    private void clearInputs()
    {    //Keep the  default state of Metadata as ON always
         mMetadataSyncState =
               BleBroadcastSourceInfo.BROADCAST_ASSIST_PA_SYNC_STATE_IN_SYNC;
         mAudioSyncState =
               BleBroadcastSourceInfo.BROADCAST_ASSIST_AUDIO_SYNC_STATE_INVALID;
         mBroadcastCode = null;
         isBroadcastPINUpdated = false;
    }

    private void triggerRemoveBroadcastSource() {
        if (mScanAssistanceMgr != null) {
            mScanAssistanceMgr.removeBroadcastSource(
            mBleBroadcastSourceInfo.getSourceId(), mGroupOp);
        }
    }

    private void onRemoveBroadcastSourceInfoPressed() {
        BroadcastScanAssistanceUtils.debug(TAG, mSourceInfoIndex  + ":onRemoveBroadcastSourceInfoPressed:" +
                                        mBleBroadcastSourceInfo);

        ///*_CSIP
        if (mCachedDevice.isGroupDevice()) {
            String name = mCachedDevice.getName();
            if (TextUtils.isEmpty(name)) {
                name = mContext.getString(R.string.bluetooth_device);
            }
            String message = mContext.getString(R.string.group_remove_source_message, name);
            String title = mContext.getString(R.string.group_remove_source_title);

            DialogInterface.OnClickListener groupOpListener = new DialogInterface.OnClickListener() {
                public void onClick(DialogInterface dialog, int which) {
                    if (mScanAssistGroupOpDialog != null) {
                        mScanAssistGroupOpDialog.dismiss();
                    }
                    mGroupOp = true;
                    triggerRemoveBroadcastSource();
                }
            };
            DialogInterface.OnClickListener nonGroupOpListener = new DialogInterface.OnClickListener() {
                public void onClick(DialogInterface dialog, int which) {
                    if (mScanAssistGroupOpDialog != null) {
                        mScanAssistGroupOpDialog.dismiss();
                    }

                    mGroupOp = false;
                    triggerRemoveBroadcastSource();
                }
            };
            mGroupOp = false;
            mScanAssistGroupOpDialog = BroadcastScanAssistanceUtils.showAssistanceGroupOptionsDialog(mContext,
                mScanAssistGroupOpDialog, groupOpListener, nonGroupOpListener, title, Html.fromHtml(message));
        } else {
        //_CSIP*/
            mGroupOp = false;
            triggerRemoveBroadcastSource();
        ///*_CSIP
        }
        //_CSIP*/
    }

    private int getSyncState(int metadataSyncState, int audioSyncState) {

        if (audioSyncState == BleBroadcastSourceInfo.BROADCAST_ASSIST_AUDIO_SYNC_STATE_SYNCHRONIZED &&
            metadataSyncState == BleBroadcastSourceInfo.BROADCAST_ASSIST_PA_SYNC_STATE_IN_SYNC) {
            return BleBroadcastAudioScanAssistManager.SYNC_METADATA_AUDIO;
        }

        if (audioSyncState == BleBroadcastSourceInfo.BROADCAST_ASSIST_AUDIO_SYNC_STATE_SYNCHRONIZED &&
            metadataSyncState != BleBroadcastSourceInfo.BROADCAST_ASSIST_PA_SYNC_STATE_IN_SYNC) {
            return BleBroadcastAudioScanAssistManager.SYNC_AUDIO;
        }
        if (audioSyncState != BleBroadcastSourceInfo.BROADCAST_ASSIST_AUDIO_SYNC_STATE_SYNCHRONIZED &&
            metadataSyncState == BleBroadcastSourceInfo.BROADCAST_ASSIST_PA_SYNC_STATE_IN_SYNC) {
            return BleBroadcastAudioScanAssistManager.SYNC_METADATA;
        }

        return -1;
    }

     private void triggerUpdateBroadcastSource() {
         if (mScanAssistanceMgr != null) {
              if (mIsValueChanged == true) {
                  int syncState = getSyncState(mMetadataSyncState, mAudioSyncState);
                if (syncState == -1) {
                    Log.e(TAG, "triggerUpdateBroadcastSource: Invalid sync Input, Ignore");
                    return;
                }
                  mScanAssistanceMgr.updateBroadcastSource(
                      mBleBroadcastSourceInfo.getSourceId(),
                      getSyncState(mMetadataSyncState, mAudioSyncState),
                      mBisIndicies, mGroupOp);
                  mIsValueChanged = false;
              }
              if (isBroadcastPINUpdated) {
                  mScanAssistanceMgr.setBroadcastCode(
                      mBleBroadcastSourceInfo.getSourceId(),mBroadcastCode, mGroupOp);
                  isBroadcastPINUpdated = false;
              }
              clearInputs();
          }
    }

    private void onUpdateBroadcastSourceInfoPressed() {
        BroadcastScanAssistanceUtils.debug(TAG, mSourceInfoIndex  +
               "onUpdateBroadcastSourceInfoPressed:" + mBleBroadcastSourceInfo);

        ///*_CSIP
        if (mCachedDevice.isGroupDevice()) {
            String name = mCachedDevice.getName();
            if (TextUtils.isEmpty(name)) {
                name = mContext.getString(R.string.bluetooth_device);
            }
            String message = mContext.getString(R.string.group_update_source_message, name);
            String title = mContext.getString(R.string.group_update_source_title);

            DialogInterface.OnClickListener groupOpListener = new DialogInterface.OnClickListener() {
                public void onClick(DialogInterface dialog, int which) {
                    mGroupOp = true;
                    triggerUpdateBroadcastSource();
                }
            };
            DialogInterface.OnClickListener nonGroupOpListener = new DialogInterface.OnClickListener() {
                public void onClick(DialogInterface dialog, int which) {
                    mGroupOp = false;
                    triggerUpdateBroadcastSource();
                }
            };
            mGroupOp = false;
            mScanAssistGroupOpDialog = BroadcastScanAssistanceUtils.showAssistanceGroupOptionsDialog(mContext,
                mScanAssistGroupOpDialog, groupOpListener, nonGroupOpListener, title, Html.fromHtml(message));
        } else {
        //_CSIP*/
            mGroupOp = false;
            triggerUpdateBroadcastSource();
        ///*_CSIP
        }
        //_CSIP*/
    }

    @Override
    protected void init(PreferenceScreen screen) {
        mSourceInfoContainer =
                 (PreferenceCategory)screen.findPreference(getPreferenceKey());
        mSourceIdPref = (Preference)mSourceInfoContainer.findPreference(
                         KEY_SOURCE_ID);
        mSourceDevicePref = (Preference)mSourceInfoContainer.findPreference(
                         KEY_SOURCE_DEVICE);
        mSourceEncStatusPref = (Preference)mSourceInfoContainer.findPreference(
                         KEY_SOURCE_ENC_STATUS);
        mSourceMetadataPref = (Preference)mSourceInfoContainer.findPreference(
                         KEY_SOURCE_METADATA);
        mSourceMetadataSyncStatusPref = (Preference)mSourceInfoContainer.findPreference(
                         KEY_SOURCE_METADATA_STATE);
        if (mPAsyncCtrlNeeded) {
            mSourceMetadataSyncSwitchPref = (SwitchPreference)mSourceInfoContainer.findPreference(
                         KEY_SOURCE_METADATA_SWITCH);

            if (mSourceMetadataSyncSwitchPref != null) {
                mSourceMetadataSyncSwitchPref.setOnPreferenceClickListener(this);
            }
        }
        mSourceAudioSyncStatusPref = (MultiSelectListPreference)mSourceInfoContainer.findPreference(
                         KEY_SOURCE_AUDIO_STATE);
        if (mSourceAudioSyncStatusPref != null) {
            mSourceAudioSyncStatusPref.setOnPreferenceChangeListener(this);
        }

        mSourceAudioSyncSwitchPref = (SwitchPreference)mSourceInfoContainer.findPreference(
                         KEY_SOURCE_AUDIOSYNC_SWITCH);
        if (mSourceAudioSyncSwitchPref != null) {
            mSourceAudioSyncSwitchPref.setOnPreferenceClickListener(this);
        }
        mSourceUpdateBcastCodePref =
                     (EditTextPreference)mSourceInfoContainer.findPreference(
                         KEY_UPDATE_BCAST_CODE);
        if (mSourceUpdateBcastCodePref != null) {
            mSourceUpdateBcastCodePref.setOnPreferenceClickListener(this);
            mSourceUpdateBcastCodePref.setOnPreferenceChangeListener(this);
        }
        mSourceUpdateSourceInfoPref =
                     ((ActionButtonsPreference)mSourceInfoContainer.findPreference(
                         KEY_UPDATE_SOURCE_INFO))
                         .setButton1Text(R.string.update_sourceinfo_btn_txt)
                         .setButton1Enabled(false)
                         .setButton1OnClickListener((view)->onUpdateBroadcastSourceInfoPressed())
                         .setButton2Text(R.string.remove_sourceinfo_btn_txt)
                         .setButton2Icon(R.drawable.ic_settings_close)
                         .setButton2Enabled(false)
                         .setButton2OnClickListener((view)->onRemoveBroadcastSourceInfoPressed());
        refresh();
    }

    @Override
    public void onDeviceAttributesChanged() {
        //update the Local variable If the receiverState is
        //updated with some values
        final Map<Integer, BleBroadcastSourceInfo>  srcInfos =
                    mVendorCachedDevice.getAllBleBroadcastreceiverStates();
        if (srcInfos == null) {
            return;
        }
        for (Map.Entry<Integer, BleBroadcastSourceInfo> entry: srcInfos.entrySet()) {
            Integer index = entry.getKey();
            BleBroadcastSourceInfo sourceInfo = entry.getValue();
            String toastString = null;
            if (index == mSourceInfoIndex) {
                BroadcastScanAssistanceUtils.debug(TAG, mSourceInfoIndex  + ":matching source Info");
                if (sourceInfo.isEmptyEntry()) {
                    BroadcastScanAssistanceUtils.debug(TAG, mSourceInfoIndex  + ":source info seem to be removed");
                    toastString = "Source Info Removal";
                    mBleBroadcastSourceInfo = sourceInfo;
                }
                else if (sourceInfo.equals(mBleBroadcastSourceInfo) != true) {
                    //toast Message
                    mBleBroadcastSourceInfo = sourceInfo;
                    BroadcastScanAssistanceUtils.debug(TAG, mSourceInfoIndex  + ":Update in Broadcast Source Information");
                    toastString = "Source Info Update";
                } else {
                    BroadcastScanAssistanceUtils.debug(TAG, mSourceInfoIndex  + ":No Update to Source Information values");
                }
            } else {
                BroadcastScanAssistanceUtils.debug(TAG, mSourceInfoIndex  + ":Ignore this case");
            }
            if (toastString != null) {
                Toast toast = Toast.makeText(mContext, toastString, Toast.LENGTH_SHORT);
                toast.show();
            }
        }
        refresh();
    }
    @Override
    public boolean onPreferenceChange(Preference preference, Object newValue) {
        String key = preference.getKey();
        BroadcastScanAssistanceUtils.debug(TAG, mSourceInfoIndex  + ":onPreferenceChange" + newValue);
        if (key.equals(KEY_UPDATE_BCAST_CODE)) {
            EditTextPreference pref = (EditTextPreference)preference;
            String code = (String)newValue;
            //Use different flag for Broadcast pin
            isBroadcastPINUpdated = true;
            mBroadcastCode = (String)newValue;
        } else if (key.equals(KEY_SOURCE_AUDIO_STATE)) {
            BroadcastScanAssistanceUtils.debug(TAG, ">>Checked:" +newValue);
            CharSequence[] getEntriesSeqence =
                ((MultiSelectListPreference)preference).getEntries();
            Set<String> valueSet = ((MultiSelectListPreference)preference).getValues();

            String[] selectedStrings = new String[((Set<String>) newValue).size()];

             //noinspection unchecked
             int j =0;
             for (String value : (Set<String>) newValue) {
                 selectedStrings[j] = value;
                 for (int i=0; i<mBisIndicies.size(); i++) {
                     if (value.equals(mBisIndicies.get(i).getDescription())) {
                        BroadcastScanAssistanceUtils.debug(TAG, "Selected: value["+ i + "]- " + value);
                        if (mBisIndicies.get(i).getStatus() == true) {
                            mBisIndicies.get(i).setStatus(false);
                        } else {
                            mBisIndicies.get(i).setStatus(true);
                        }
                    }
                 }
                 BroadcastScanAssistanceUtils.debug(TAG, "value["+ j++ + "]- " + value);
             }
             mIsValueChanged = true;
        }
        mIsButtonRefreshOnly = true;
        refresh();
        return true;
    }

   /**
     * When the pref for a ble broadcast source info details is clicked on, necessary action will be
     * taken and updateBroadcastSourceInfo would be called as needed
     */
    @Override
    public boolean onPreferenceClick(Preference preference) {
        String key = preference.getKey();
        BroadcastScanAssistanceUtils.debug(TAG, mSourceInfoIndex  + ":onPreferenceClick");
        mIsValueChanged = true;
        if (mPAsyncCtrlNeeded) {
            if (key.equals(KEY_SOURCE_METADATA_SWITCH)) {
                SwitchPreference pref = (SwitchPreference)preference;
                BroadcastScanAssistanceUtils.debug(TAG, mSourceInfoIndex  + ":Meta data sync state: " + pref.isChecked());
                if (pref.isChecked()) mMetadataSyncState = BleBroadcastSourceInfo.BROADCAST_ASSIST_PA_SYNC_STATE_IN_SYNC;
                else mMetadataSyncState = BleBroadcastSourceInfo.BROADCAST_ASSIST_PA_SYNC_STATE_IDLE;

                //Update the audio sync state as well
                if (mSourceAudioSyncSwitchPref != null) {
                    if (mSourceAudioSyncSwitchPref.isChecked()) {
                        mAudioSyncState = BleBroadcastSourceInfo.BROADCAST_ASSIST_AUDIO_SYNC_STATE_SYNCHRONIZED;
                    }
                    else {
                        mAudioSyncState = BleBroadcastSourceInfo.BROADCAST_ASSIST_AUDIO_SYNC_STATE_NOT_SYNCHRONIZED;
                    }
                }
            }
        }
        if (key.equals(KEY_SOURCE_AUDIOSYNC_SWITCH)) {
            SwitchPreference pref = (SwitchPreference)preference;
            BroadcastScanAssistanceUtils.debug(TAG, mSourceInfoIndex  + ":Audio sync state:  " + pref.isChecked());

            if (pref.isChecked()) mAudioSyncState = BleBroadcastSourceInfo.BROADCAST_ASSIST_AUDIO_SYNC_STATE_SYNCHRONIZED;
            else mAudioSyncState = BleBroadcastSourceInfo.BROADCAST_ASSIST_AUDIO_SYNC_STATE_NOT_SYNCHRONIZED;

            if (mPAsyncCtrlNeeded) {
                //Update the metadata sync state as well
                if (mSourceMetadataSyncSwitchPref != null) {
                    if (mSourceMetadataSyncSwitchPref.isChecked()) {
                        mMetadataSyncState = BleBroadcastSourceInfo.BROADCAST_ASSIST_AUDIO_SYNC_STATE_SYNCHRONIZED;
                    }
                    else {
                        mMetadataSyncState = BleBroadcastSourceInfo.BROADCAST_ASSIST_AUDIO_SYNC_STATE_NOT_SYNCHRONIZED;
                    }
                }
            }
        } else if (key.equals(KEY_UPDATE_BCAST_CODE)) {
            EditTextPreference pref = (EditTextPreference)preference;
            BroadcastScanAssistanceUtils.debug(TAG, mSourceInfoIndex  + ":>>Pin code updated:  " + pref.getText());
            //Use different flag for Broadcast pin
            mIsValueChanged = false;
            isBroadcastPINUpdated = true;
            mBroadcastCode = pref.getText();
        } else {
            BroadcastScanAssistanceUtils.debug(TAG, mSourceInfoIndex  + ":unhandled preference");
            mIsValueChanged = false;
        }
        BroadcastScanAssistanceUtils.debug(TAG, mSourceInfoIndex  + ":onPreferenceClick" + mBleBroadcastSourceInfo);
        mIsButtonRefreshOnly = true;
        refresh();
        return true;
    }

    @Override
    public void onPause() {
        super.onPause();
        mCachedDevice.unregisterCallback(this);
    }

    @Override
    public void onResume() {
        super.onResume();
        mCachedDevice.registerCallback(this);
    }

    String getEncryptionStatusString(int encryptionStatus) {

        switch(encryptionStatus) {
            case BleBroadcastSourceInfo.BROADCAST_ASSIST_ENC_STATE_INVALID:
                return "ENCRYPTION STATE UNKNOWN";
            case BleBroadcastSourceInfo.BROADCAST_ASSIST_ENC_STATE_UNENCRYPTED:
                return "UNENCRYPTED STREAMING";
            case BleBroadcastSourceInfo.BROADCAST_ASSIST_ENC_STATE_PIN_NEEDED:
                return "PIN UPDATE NEEDED";
            case BleBroadcastSourceInfo.BROADCAST_ASSIST_ENC_STATE_DECRYPTING:
                return "DECRYPTING SUCCESSFULLY";
            case BleBroadcastSourceInfo.BROADCAST_ASSIST_ENC_STATE_BADCODE:
                return "INCORRECT BROADCAST PIN";
        }
        return "ENCRYPTION STATE UNKNOWN";
    }

     String getMetadataSyncStatusString(int metadataSyncStatus) {

        switch(metadataSyncStatus) {
            case BleBroadcastSourceInfo.BROADCAST_ASSIST_PA_SYNC_STATE_IDLE:
                return "IDLE";
            case BleBroadcastSourceInfo.BROADCAST_ASSIST_PA_SYNC_STATE_INVALID:
                return "UNKNOWN";
            case BleBroadcastSourceInfo.BROADCAST_ASSIST_PA_SYNC_STATE_IN_SYNC:
                return "IN SYNC";
            case BleBroadcastSourceInfo.BROADCAST_ASSIST_PA_SYNC_STATE_NO_PAST:
                return "NO PAST";
            case BleBroadcastSourceInfo.BROADCAST_ASSIST_PA_SYNC_STATE_SYNCINFO_REQ:
                return "SYNCINFO NEEDED";
            case BleBroadcastSourceInfo.BROADCAST_ASSIST_PA_SYNC_STATE_SYNC_FAIL:
                return "SYNC FAIL";
        }
        return "UNKNOWN";
    }

     String getAudioSyncStatusString(int audioSyncStatus) {

        switch(audioSyncStatus) {
            case BleBroadcastSourceInfo.BROADCAST_ASSIST_AUDIO_SYNC_STATE_INVALID:
                return "UNKNOWN";
            case BleBroadcastSourceInfo.BROADCAST_ASSIST_AUDIO_SYNC_STATE_NOT_SYNCHRONIZED:
                return "NOT IN SYNC";
            case BleBroadcastSourceInfo.BROADCAST_ASSIST_AUDIO_SYNC_STATE_SYNCHRONIZED:
                return "IN SYNC";
        }
        return "UNKNOWN";
    }

    private boolean isPinUpdatedNeeded() {
        boolean ret = false;

        if (BroadcastScanAssistanceUtils.isLocalDevice(mBleBroadcastSourceInfo.getSourceDevice())) {
            BroadcastScanAssistanceUtils.debug(TAG, "Local Device, Dont allow User to update PWD");
            return false;
        }
        if (mBleBroadcastSourceInfo.getEncryptionStatus()
           == BleBroadcastSourceInfo.BROADCAST_ASSIST_ENC_STATE_PIN_NEEDED) {
            ret = true;
        }

        BroadcastScanAssistanceUtils.debug(TAG, "isPinUpdatedNeeded return" + ret);
        return ret;
    }

    /**
     * Refreshes the state of the switches for all profiles, possibly adding or removing switches as
     * needed.
     */
    @Override
    protected void refresh() {
        BroadcastScanAssistanceUtils.debug(TAG, mSourceInfoIndex  + ":refresh: " + mBleBroadcastSourceInfo + " mSourceIndex" + mSourceInfoIndex);
        mSourceIdPref.setSummary(
                 String.valueOf(mBleBroadcastSourceInfo.getSourceId()));

        BluetoothDevice dev = mBleBroadcastSourceInfo.getSourceDevice();
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
        if (s == null || s.equals(EMPTY_BD_ADDRESS)) {
            BroadcastScanAssistanceUtils.debug(TAG, mSourceInfoIndex  + ":NULL source device");
            s = "EMPTY_ENTRY";
        }
        mSourceDevicePref.setSummary(s);
        mSourceEncStatusPref.setSummary(
                getEncryptionStatusString(
                          mBleBroadcastSourceInfo.getEncryptionStatus())
                          );

        if (mBleBroadcastSourceInfo.isEmptyEntry()) {
            BroadcastScanAssistanceUtils.debug(TAG, mSourceInfoIndex  + ":Source Information seem to be Empty");
            if (mPAsyncCtrlNeeded) {
                mSourceMetadataSyncSwitchPref.setEnabled(false);
            }
            mSourceAudioSyncSwitchPref.setEnabled(false);
            mSourceUpdateBcastCodePref.setEnabled(false);
            //Disable 'remove and update source Info' if It is empty entry
            mSourceUpdateSourceInfoPref.setButton1Enabled(false);
            mSourceUpdateSourceInfoPref.setButton2Enabled(false);
            mSourceAudioSyncStatusPref.setEnabled(false);
            mIsValueChanged = false;
        } else {
            //enable the Input controls
            if (mPAsyncCtrlNeeded) {
                mSourceMetadataSyncSwitchPref.setEnabled(true);
            }
            mSourceAudioSyncSwitchPref.setEnabled(true);
            mSourceUpdateBcastCodePref.setEnabled(isPinUpdatedNeeded());

            if (mIsButtonRefreshOnly != true) {
                mSourceMetadataSyncStatusPref.setSummary(
                     getMetadataSyncStatusString(mBleBroadcastSourceInfo.getMetadataSyncState())
                       );
                   mSourceAudioSyncStatusPref.setSummary(
                     getAudioSyncStatusString(mBleBroadcastSourceInfo.getAudioSyncState())
                       );
                   mBisIndicies = mBleBroadcastSourceInfo.getBroadcastChannelsSyncStatus();
                   if (mBisIndicies != null) {
                       String[] bisNames = new String[mBisIndicies.size()];
                       boolean[] bisStatuses = new boolean[mBisIndicies.size()];
                       Set<String> hashSet = new HashSet<String>();
                       for (int i=0; i<mBisIndicies.size(); i++) {
                              bisNames[i] = mBisIndicies.get(i).getDescription();
                           bisStatuses[i] = mBisIndicies.get(i).getStatus();
                       }
                       hashSet.addAll(Arrays.asList(bisNames));
                       mSourceAudioSyncStatusPref.setEntries(bisNames);
                       mSourceAudioSyncStatusPref.setEntryValues(bisNames);
                       mSourceAudioSyncStatusPref.setValues(hashSet);
                   }

                //Reflect the controls based on the status
                if (mPAsyncCtrlNeeded) {
                    mSourceMetadataSyncSwitchPref.setChecked(mBleBroadcastSourceInfo.getMetadataSyncState() ==
                        BleBroadcastSourceInfo.BROADCAST_ASSIST_PA_SYNC_STATE_IN_SYNC);
                }
                mSourceAudioSyncSwitchPref.setChecked(mBleBroadcastSourceInfo.getAudioSyncState() ==
                    BleBroadcastSourceInfo.BROADCAST_ASSIST_AUDIO_SYNC_STATE_SYNCHRONIZED);

                int getFirstSyncedBisIndex = -1;
                if (mBisIndicies != null) {
                    for (int i=0; i<mBisIndicies.size(); i++) {
                        if (mBisIndicies.get(i).getStatus() == true) {
                            getFirstSyncedBisIndex = i;
                            break;
                        }
                    }
                }
                byte[] metadata = null;
                if (getFirstSyncedBisIndex != -1) {
                    metadata = mBisIndicies.get(getFirstSyncedBisIndex).getMetadata();
                }
                if (metadata != null) {
                    String metaDataStr = new String(metadata);
                    BroadcastScanAssistanceUtils.debug(TAG, mSourceInfoIndex  + ":Metadata:" + metaDataStr);
                    mSourceMetadataPref.setSummary(metaDataStr);
                } else {
                    mSourceMetadataPref.setSummary("NONE");
                }
                if (mBleBroadcastSourceInfo != null &&
                    (mBleBroadcastSourceInfo.getMetadataSyncState() != BleBroadcastSourceInfo.BROADCAST_ASSIST_PA_SYNC_STATE_IN_SYNC &&
                    mBleBroadcastSourceInfo.getAudioSyncState() != BleBroadcastSourceInfo.BROADCAST_ASSIST_AUDIO_SYNC_STATE_SYNCHRONIZED)) {
                    //Remove source Info button
                    mSourceUpdateSourceInfoPref.setButton2Enabled(true);
                } else {
                    mSourceUpdateSourceInfoPref.setButton2Enabled(false);
                }
            }
            //User can update OR remove only if the Source info is not an Empty Entry
            if (mIsValueChanged || isBroadcastPINUpdated) {
                //User can Update only if any of the entries are modified by user action
                mSourceUpdateSourceInfoPref.setButton1Enabled(true);
            } else {
                mSourceUpdateSourceInfoPref.setButton1Enabled(false);
            }
            mIsButtonRefreshOnly = false;
        }
    }

    @Override
    public String getPreferenceKey() {
        return KEY_SOURCE_INFO_GROUP;
    }
}
