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
import android.bluetooth.BluetoothAdapter;
import android.bluetooth.BluetoothDevice;
import android.content.Context;
import android.os.Bundle;
import android.util.Log;
import android.widget.Toast;
import android.text.Html;
import android.widget.EditText;
import android.widget.RadioButton;
import android.view.View;
import android.widget.RadioGroup;
import android.bluetooth.le.ScanResult;
import android.bluetooth.IBluetoothManager;
import java.util.Arrays;
import java.util.Map;
import java.util.List;
import android.bluetooth.le.ScanRecord;
import android.app.Activity;

import androidx.appcompat.app.AlertDialog;
import android.content.DialogInterface;
import android.text.TextUtils;

import com.android.settings.R;
import com.android.settingslib.bluetooth.BluetoothDeviceFilter;
import com.android.settingslib.bluetooth.CachedBluetoothDevice;
import com.android.settingslib.bluetooth.VendorCachedBluetoothDevice;
import com.android.settingslib.bluetooth.LocalBluetoothProfileManager;
import com.android.settingslib.bluetooth.BCProfile;

import android.bluetooth.BleBroadcastAudioScanAssistManager;
import android.bluetooth.BleBroadcastAudioScanAssistCallback;
import android.bluetooth.BleBroadcastSourceInfo;
import android.bluetooth.BleBroadcastSourceChannel;

import com.android.settingslib.search.Indexable;
import com.android.settingslib.widget.FooterPreference;
import androidx.preference.Preference;
import android.widget.ListView;
import android.text.BidiFormatter;
import android.widget.ArrayAdapter;
import android.widget.AdapterView;
import android.widget.CheckedTextView;

/**
 * BluetoothSADetail is a page to scan bluetooth devices and pair them.
 */
public class BluetoothSADetail extends DeviceListPreferenceFragment implements
        Indexable {
    private static final String TAG = "BluetoothSADetail";
    private static final boolean DBG = true;

    public static final String KEY_DEVICE_ADDRESS = "device_address";
    public static final String KEY_GROUP_OP = "group_op";
    static final String KEY_AVAIL_LE_AUDIO_SOURCES = "available_audio_sources";
    static final String KEY_FOOTER_PREF = "footer_preference";
    static final String SCAN_DEL_NAME = "Scan Delegator";

    BluetoothProgressCategory mAvailableDevicesCategory;
    FooterPreference mFooterPreference;

    private AlertDialog mScanAssistDetailsDialog;
    private boolean mInitialScanStarted;
    private CachedBluetoothDevice mCachedDevice;
    Preference mScanDelegatorName;
    String mSyncState;
    BleBroadcastAudioScanAssistManager mScanAssistManager;
    protected LocalBluetoothProfileManager mProfileManager;
    String mBroadcastCode;
    Context mContext;
    CachedBluetoothDevice clickedDevice = null;
    String mBroadcastPinCode = null;
    boolean mScanning = true;
    boolean mGroupOperation = false;
    AlertDialog mCommonMsgDialog = null;

    private String getBluetoothName(BluetoothDevice dev) {
        String aliasName = null;
        if (dev == null) {
            aliasName = SCAN_DEL_NAME;
        } else {
            aliasName = dev.getAlias();
            aliasName = TextUtils.isEmpty(aliasName) ? dev.getAddress() : aliasName;
            if (aliasName == null) {
                aliasName = SCAN_DEL_NAME;
            }
        }
        BroadcastScanAssistanceUtils.debug(TAG, "getBluetoothName returns" + aliasName);
        return aliasName;
    }

    private int getSourceSelectionErrMessage(int status) {
        int errorMessage = R.string.bluetooth_source_selection_error_message;
        switch (status) {
            case BleBroadcastAudioScanAssistCallback.BASS_STATUS_COLOCATED_SRC_UNAVAILABLE:
            case BleBroadcastAudioScanAssistCallback.BASS_STATUS_SOURCE_UNAVAILABLE:
                errorMessage = R.string.bluetooth_source_selection_error_src_unavail_message;
                break;
            case BleBroadcastAudioScanAssistCallback.BASS_STATUS_INVALID_SOURCE_SELECTED:
            case BleBroadcastAudioScanAssistCallback.BASS_STATUS_INVALID_SOURCE_ID:
                errorMessage = R.string.bluetooth_source_selection_error_message;
                break;
            case BleBroadcastAudioScanAssistCallback.BASS_STATUS_DUPLICATE_ADDITION :
                errorMessage = R.string.bluetooth_source_dup_addition_error_message;
                break;
            case BleBroadcastAudioScanAssistCallback.BASS_STATUS_NO_EMPTY_SLOT :
                errorMessage = R.string.bluetooth_source_no_empty_slot_error_message;
                break;
        }
        return errorMessage;
    }

    private int getSourceAdditionErrMessage(int status) {
        int errorMessage = R.string.bluetooth_source_addition_error_message;
        switch (status) {
            case BleBroadcastAudioScanAssistCallback.BASS_STATUS_DUPLICATE_ADDITION :
                errorMessage = R.string.bluetooth_source_dup_addition_error_message;
                break;
            case BleBroadcastAudioScanAssistCallback.BASS_STATUS_NO_EMPTY_SLOT :
                errorMessage = R.string.bluetooth_source_no_empty_slot_error_message;
                break;
        }
        return errorMessage;
    }

    private int getSourceRemovalErrMessage(int status) {
        int errorMessage = R.string.bluetooth_source_removal_error_message;
        switch (status) {
            case BleBroadcastAudioScanAssistCallback.BASS_STATUS_FATAL :
                errorMessage = R.string.bluetooth_source_removal_error_message;
                break;
            case BleBroadcastAudioScanAssistCallback.BASS_STATUS_INVALID_GROUP_OP :
                errorMessage = R.string.bluetooth_source_remove_invalid_group_op;
                break;
            case BleBroadcastAudioScanAssistCallback.BASS_STATUS_INVALID_SOURCE_ID :
                errorMessage = R.string.bluetooth_source_remove_invalid_src_id;
                break;
        }
        return errorMessage;
    }

    private int getSourceUpdateErrMessage(int status) {
        int errorMessage = R.string.bluetooth_source_update_error_message;
        switch (status) {
            case BleBroadcastAudioScanAssistCallback.BASS_STATUS_FATAL :
                errorMessage = R.string.bluetooth_source_update_error_message;
                break;
            case BleBroadcastAudioScanAssistCallback.BASS_STATUS_INVALID_GROUP_OP :
                errorMessage = R.string.bluetooth_source_update_invalid_group_op;
                break;
            case BleBroadcastAudioScanAssistCallback.BASS_STATUS_INVALID_SOURCE_ID :
                errorMessage = R.string.bluetooth_source_update_invalid_src_id;
                break;
        }
        return errorMessage;
    }

    BleBroadcastAudioScanAssistCallback mScanAssistCallback = new BleBroadcastAudioScanAssistCallback() {
        DialogInterface.OnClickListener commonMessageListener = new DialogInterface.OnClickListener() {
             public void onClick(DialogInterface dialog, int which) {
                 BroadcastScanAssistanceUtils.debug(TAG, ">>OK clicked");
                 if (mCommonMsgDialog != null) {
                     mCommonMsgDialog.dismiss();
                 }
                 finish();
             }
        };
        public void onBleBroadcastSourceFound(ScanResult res) {
            BroadcastScanAssistanceUtils.debug(TAG, "onBleBroadcastSourceFound" + res.getDevice());

            CachedBluetoothDevice cachedDevice = mLocalManager.getCachedDeviceManager().findDevice(res.getDevice());

            if (cachedDevice != null) {
                BroadcastScanAssistanceUtils.debug(TAG, "seems like CachedDevice entry already present for this device");
            } else     {
                //Create a Device entry for this,
                //If this is randon Address, there would new CachedDevice Entry for this random address Instance
                //However this wont have the name
                cachedDevice  = mLocalManager.getCachedDeviceManager().addDevice(res.getDevice());
                //udate the Name for this device from ADV: HACK
                BluetoothAdapter adapter = BluetoothAdapter.getDefaultAdapter();
                if (res.getDevice().getAddress().equals(adapter.getAddress())) {
                    BroadcastScanAssistanceUtils.debug(TAG, "Self DEVICE:");
                } else {
                    ScanRecord rec = res.getScanRecord();
                    if (rec != null && rec.getDeviceName() != null) {
                        String  s = rec.getDeviceName();
                        BroadcastScanAssistanceUtils.debug(TAG,"setting name as " + s);
                        cachedDevice.setName(s);
                    }
                }
            }

            BluetoothDevicePreference pref = mDevicePreferenceMap.get(cachedDevice);
            if (pref != null) {
                //If the Prefernce alread Created, just update the
                //Scan Result
                //pref.SetScanResult(res);
                 BroadcastScanAssistanceUtils.debug(TAG, "Preference is already present" + res.getDevice());
                return;
            }
            // Prevent updates while the list shows one of the state messages
            if (mBluetoothAdapter.getState() != BluetoothAdapter.STATE_ON) return;
            //if (mFilter.matches(cachedDevice.getDevice())) {
               createDevicePreference(cachedDevice);
            //}
            //
            VendorCachedBluetoothDevice vDev = VendorCachedBluetoothDevice.getVendorCachedBluetoothDevice(cachedDevice, mProfileManager);
            vDev.setScanResult(res);
        };

        public void onBleBroadcastSourceSelected(BluetoothDevice rcvr, int status,
                                List<BleBroadcastSourceChannel> broadcastSourceIndicies) {
            BroadcastScanAssistanceUtils.debug(TAG, "onBleBroadcastSourceSelected" + status + "sel indicies:" +  broadcastSourceIndicies);
            if (status == BleBroadcastAudioScanAssistCallback.BASS_STATUS_SUCCESS) {
                launchSyncAndBroadcastIndexOptions(broadcastSourceIndicies);
            } else {
                String aliasName = getBluetoothName(rcvr);
                mCommonMsgDialog = BroadcastScanAssistanceUtils.showScanAssistError(mContext, rcvr.getName(),
                    getSourceSelectionErrMessage(status), commonMessageListener);

            }
        };

        public void onBleBroadcastAudioSourceAdded(BluetoothDevice rcvr,
                                                byte srcId,
                                                int status) {

             BroadcastScanAssistanceUtils.debug(TAG, "onBleBroadcastAudioSourceAdded: rcvr:" + rcvr +
                "status:" + status + "srcId" + srcId);
            if (status == BleBroadcastAudioScanAssistCallback.BASS_STATUS_SUCCESS) {
                //Show Dialog
                if (mGroupOperation) {
                    String aliasName = getBluetoothName(rcvr);
                     mCommonMsgDialog = BroadcastScanAssistanceUtils.showScanAssistError(mContext, aliasName,
                        R.string.bluetooth_source_added_message, commonMessageListener);
                }
                if(mBroadcastPinCode != null) {
                    if (status == BleBroadcastAudioScanAssistCallback.BASS_STATUS_SUCCESS
                        && mScanAssistManager != null) {
                        mScanAssistManager.setBroadcastCode(srcId,mBroadcastPinCode, mGroupOperation);
                    }
                    mBroadcastPinCode = null;
                }
                finish();
            } else {
                String aliasName = getBluetoothName(rcvr);
                mCommonMsgDialog = BroadcastScanAssistanceUtils.showScanAssistError(mContext, aliasName,
                    getSourceAdditionErrMessage(status), commonMessageListener);
            }
        };

        public void onBleBroadcastAudioSourceUpdated(BluetoothDevice rcvr,
                                             byte srcId,
                                             int status) {
              BroadcastScanAssistanceUtils.debug(TAG, "onBleBroadcastAudioSourceUpdated: rcvr:" + rcvr +
                "status:" + status + "srcId" + srcId);
             if (status != BleBroadcastAudioScanAssistCallback.BASS_STATUS_SUCCESS) {
                 String aliasName = getBluetoothName(rcvr);
                 mCommonMsgDialog = BroadcastScanAssistanceUtils.showScanAssistError(mContext, aliasName,
                    getSourceUpdateErrMessage(status), commonMessageListener);
             }
        };

        public void onBleBroadcastPinUpdated(BluetoothDevice rcvr,
                                                byte srcId,
                                                int status) {

              BroadcastScanAssistanceUtils.debug(TAG, "onBleBroadcastPinUpdated: rcvr:" + rcvr +
                "status:" + status + "srcId" + srcId);
             if (status != BleBroadcastAudioScanAssistCallback.BASS_STATUS_SUCCESS) {
                  String aliasName = getBluetoothName(rcvr);
                 mCommonMsgDialog = BroadcastScanAssistanceUtils.showScanAssistError(mContext, aliasName,
                    R.string.bluetooth_source_setpin_error_message, commonMessageListener);
             }
        };
        public void onBleBroadcastAudioSourceRemoved(BluetoothDevice rcvr,
                                             byte srcId,
                                             int status) {
              BroadcastScanAssistanceUtils.debug(TAG, "onBleBroadcastAudioSourceRemoved: rcvr:" + rcvr +
                "status:" + status + "srcId" + srcId);
             if (status != BleBroadcastAudioScanAssistCallback.BASS_STATUS_SUCCESS) {
                  String aliasName = getBluetoothName(rcvr);
                 mCommonMsgDialog = BroadcastScanAssistanceUtils.showScanAssistError(mContext, aliasName,
                    getSourceRemovalErrMessage(status), commonMessageListener);
             }
        };
    };


    public BluetoothSADetail() {
        super(DISALLOW_CONFIG_BLUETOOTH);
    }

    void createDevicePreference(CachedBluetoothDevice cachedDevice) {
        if (mDeviceListGroup == null) {
            Log.w(TAG, "Trying to create a device preference before the list group/category "
                    + "exists!");
            return;
        }

        String key = cachedDevice.getDevice().getAddress();
        BluetoothDevicePreference preference = (BluetoothDevicePreference) getCachedPreference(key);

        if (preference == null) {
            preference = new BluetoothDevicePreference(getPrefContext(), cachedDevice,
                    true/*mShowDevicesWithoutNames*/, BluetoothDevicePreference.SortType.TYPE_FIFO);
            preference.setKey(key);
            //Set hideSecondTarget is true if it's bonded device.
            //preference.hideSecondTarget(true);
            mDeviceListGroup.addPreference(preference);
        }

        initDevicePreference(preference);
        Log.w(TAG, "adding" + cachedDevice + "to the Pref map");
        mDevicePreferenceMap.put(cachedDevice, preference);
    }

    @Override
    public void onActivityCreated(Bundle savedInstanceState) {
        super.onActivityCreated(savedInstanceState);
        mInitialScanStarted = false;
    }

    @Override
    public void onDeviceAdded(CachedBluetoothDevice cachedDevice) {
        //Do nothing
    }

    @Override
    public void onStart() {
        BroadcastScanAssistanceUtils.debug(TAG, "OnStart Called");
        super.onStart();
        if (mLocalManager == null){
            Log.e(TAG, "Bluetooth is not supported on this device");
            return;
        }
        updateContent(mBluetoothAdapter.getState());
        mAvailableDevicesCategory.setProgress(mBluetoothAdapter.isDiscovering());
        if (mScanAssistManager == null) {
            if (mProfileManager == null) {
                mProfileManager = mLocalManager.getProfileManager();
            }
            BCProfile bcProfile = (BCProfile)mProfileManager.getBCProfile();
            mScanAssistManager = bcProfile.getBSAManager(
                                  mCachedDevice.getDevice(), mScanAssistCallback);
            if (mScanAssistManager == null) {
                Log.e(TAG, "On Start: not able to instantiate scanAssistManager");
                //return;
            }
        }
    }

    @Override
    public void onAttach(Context context) {
        BroadcastScanAssistanceUtils.debug(TAG, "OnAttach Called");
        super.onAttach(context);
        mContext = context;
        String deviceAddress = getArguments().getString(KEY_DEVICE_ADDRESS);
        mGroupOperation = getArguments().getShort(KEY_GROUP_OP) == (short)1;
        BluetoothDevice remoteDevice = BluetoothAdapter.getDefaultAdapter().getRemoteDevice(
                deviceAddress);
        if (mLocalManager == null) {
            Log.e(TAG, "Local mgr is NULL");
            mLocalManager = Utils.getLocalBtManager(getActivity());
            if (mLocalManager == null) {
               Log.e(TAG, "Bluetooth is not supported on this device");
               return;
            }
        }
        mCachedDevice = mLocalManager.getCachedDeviceManager().findDevice(remoteDevice);
        if (mCachedDevice == null) {
            //goBack();
            return;
        } else {
            mProfileManager = mLocalManager.getProfileManager();
            BCProfile bcProfile = (BCProfile)mProfileManager.getBCProfile();
            mScanAssistManager = bcProfile.getBSAManager(
                                  mCachedDevice.getDevice(), mScanAssistCallback);
            if (mScanAssistManager == null) {
                Log.e(TAG, "not able to instantiate scanAssistManager");
                //return;
            }
        }
    }


    @Override
    public void onStop() {
        super.onStop();
        if (mLocalManager == null){
            Log.e(TAG, "Bluetooth is not supported on this device");
            return;
        }
        // Make the device only visible to connected devices.
        disableScanning();
        //clear the preference map onStop
        mDevicePreferenceMap.clear();
        mScanAssistManager = null;
    }

    @Override
    void initPreferencesFromPreferenceScreen() {
        mScanDelegatorName = findPreference("bt_bcast_rcvr_device");
        mScanDelegatorName.setSelectable(false);
        if (mCachedDevice == null) {
            mScanDelegatorName.setSummary(SCAN_DEL_NAME);
        } else {
            mScanDelegatorName.setSummary(getBluetoothName(mCachedDevice.getDevice()));
        }
        mAvailableDevicesCategory = (BluetoothProgressCategory) findPreference(KEY_AVAIL_LE_AUDIO_SOURCES);
        mFooterPreference = (FooterPreference) findPreference(KEY_FOOTER_PREF);
        mFooterPreference.setSelectable(false);
    }

    @Override
    public int getMetricsCategory() {
        return SettingsEnums.BLUETOOTH_PAIRING;
    }

    @Override
    void enableScanning() {
        // Clear all device states before first scan
        if (!mInitialScanStarted) {
            if (mAvailableDevicesCategory != null) {
                removeAllDevices();
            }
            mLocalManager.getCachedDeviceManager().clearNonBondedDevices();
            mInitialScanStarted = true;
        }
        //Call to Scan for LE Audio Sources
        if (mScanAssistManager != null) {
            BroadcastScanAssistanceUtils.debug(TAG, "call searchforLeAudioBroadcasters");
            mScanAssistManager.searchforLeAudioBroadcasters();
        }
    }

    @Override
    void disableScanning() {
        if (mScanAssistManager != null && mScanning == true) {
            BroadcastScanAssistanceUtils.debug(TAG, "call stopSearchforLeAudioBroadcasters");
            mScanAssistManager.stopSearchforLeAudioBroadcasters();
            mScanning = false;
        }
    }

    private int getSyncStateFromSelection (String s) {
        int ret = -1;
        if (s == null) {
            BroadcastScanAssistanceUtils.debug(TAG, "getSyncStateFromSelection:Invalid Input");
        } else {
            if (mSyncState.equals("Sync Metadata")) {
                ret = BleBroadcastAudioScanAssistManager.SYNC_METADATA;
            } else {
                ret = BleBroadcastAudioScanAssistManager.SYNC_METADATA_AUDIO;
            }
        }
        return ret;
    }

    void launchSyncAndBroadcastIndexOptions(List<BleBroadcastSourceChannel> broadcastSourceIndicies) {
         Context context = getContext();

         final View dialogView;
         String title, message;
         Activity activity = getActivity();
         if (isAdded() && activity != null) {
             dialogView = getLayoutInflater().inflate(R.layout.select_source_prompt, null);
             String name = null;
             if (clickedDevice != null) {
                 name = clickedDevice.getName();
             }
             if (TextUtils.isEmpty(name)) {
                 name = context.getString(R.string.bluetooth_device);
             }
             if (mGroupOperation) {
                 message = context.getString(R.string.bluetooth_grp_source_selection_options_detail, name);
             } else {
                 message = context.getString(R.string.bluetooth_source_selection_options_detail, name);
             }
             title = context.getString(R.string.bluetooth_source_selection_options_detail_title);

             /*
             //BIS Selection choice
             ListView bisSelectionList;
             bisSelectionList = dialogView.findViewById(R.id.lv);
             bisSelectionList.setChoiceMode(ListView.CHOICE_MODE_MULTIPLE);
             ArrayAdapter<BleBroadcastSourceChannel> arrayAdapter =
             new ArrayAdapter<BleBroadcastSourceChannel>(context, android.R.layout.simple_list_item_multiple_choice , broadcastSourceIndicies);

             bisSelectionList.setAdapter(arrayAdapter);

             bisSelectionList.setOnItemClickListener(new AdapterView.OnItemClickListener() {
                @Override
                public void onItemClick(AdapterView<?> parent, View view, int position, long id) {
                    BroadcastScanAssistanceUtils.debug(TAG, "onItemClick: " +position);
                    CheckedTextView v = (CheckedTextView) view;
                    boolean currentCheck = v.isChecked();
                    BleBroadcastSourceChannel bisIndex = (BleBroadcastSourceChannel) bisSelectionList.getItemAtPosition(position);
                    bisIndex.setStatus(currentCheck);
                }
            });
            */
             DialogInterface.OnClickListener cancelAddSourceListener = new DialogInterface.OnClickListener() {
             public void onClick(DialogInterface dialog, int which) {
                 BroadcastScanAssistanceUtils.debug(TAG, ">>Cancel clicked");
                finish();
             }
             };

             DialogInterface.OnClickListener addSourceListener = new DialogInterface.OnClickListener() {
             public void onClick(DialogInterface dialog, int which) {
                 /*
                 Radio Buttons
                 final RadioGroup group = dialogView.findViewById(R.id.syncStateOptions);
                 int selectedId = group.getCheckedRadioButtonId();
                 RadioButton radioSelectedButton = (RadioButton) dialogView.findViewById(selectedId);
                 mSyncState = radioSelectedButton.getText().toString();
                 BroadcastScanAssistanceUtils.debug(TAG, "mSyncState: " +  mSyncState);
                 */
                if (clickedDevice == null) {
                    Log.w(TAG, "Ignore as there is no clicked device");
                }
                if (clickedDevice.getAddress().equals(mBluetoothAdapter.getAddress())) {
                    BroadcastScanAssistanceUtils.debug(TAG, ">>Local Adapter");
                    mBroadcastPinCode = null;
                } else {
                    EditText broadcastPIN = dialogView.findViewById(R.id.broadcastPINcode);
                    mBroadcastPinCode = broadcastPIN.getText().toString();
                    BroadcastScanAssistanceUtils.debug(TAG, "broadcastPinCode: " + mBroadcastPinCode);
                    if (TextUtils.isEmpty(mBroadcastPinCode)) {
                        BroadcastScanAssistanceUtils.debug(TAG, "Empty broacast PinCode");
                        mBroadcastPinCode = null;
                    }
                }
                if (mScanAssistManager != null && clickedDevice != null) {
                     mScanAssistManager.addBroadcastSource(clickedDevice.getDevice(),
                                                           /*getSyncStateFromSelection(mSyncState)*/
                                                           BleBroadcastAudioScanAssistManager.SYNC_METADATA_AUDIO,
                                                           broadcastSourceIndicies, mGroupOperation);
                }
             }
             };
             EditText broadcastPIN = dialogView.findViewById(R.id.broadcastPINcode);
             if (clickedDevice != null && clickedDevice.getAddress().equals(mBluetoothAdapter.getAddress())) {
                 BroadcastScanAssistanceUtils.debug(TAG, "Local Adapter");
                 mBroadcastPinCode = null;
                 broadcastPIN.setVisibility(View.INVISIBLE);
                 if (mGroupOperation) {
                     message = context.getString(R.string.bluetooth_col_grp_source_selection_options_detail, name);
                 } else {
                     message = context.getString(R.string.bluetooth_col_source_selection_options_detail, name);
                 }
             }
             mScanAssistDetailsDialog = BroadcastScanAssistanceUtils.showScanAssistDetailsDialog(context,
                 mScanAssistDetailsDialog, addSourceListener, cancelAddSourceListener, title,
                 Html.fromHtml(message), dialogView);
         }
    }

    @Override
    void onDevicePreferenceClick(BluetoothDevicePreference btPreference) {
        disableScanning();
        clickedDevice = btPreference.getBluetoothDevice();
		VendorCachedBluetoothDevice vDevice = VendorCachedBluetoothDevice.getVendorCachedBluetoothDevice(clickedDevice, mProfileManager);
        if (mScanAssistManager != null) {
            BroadcastScanAssistanceUtils.debug(TAG, "calling selectAudioSource");
            mScanAssistManager.selectBroadcastSource(vDevice.getScanResult(), mGroupOperation);
        }
    }
    void updateContent(int bluetoothState) {
        switch (bluetoothState) {
            case BluetoothAdapter.STATE_ON:
                mDevicePreferenceMap.clear();
                //mBluetoothAdapter.enable();

                addDeviceCategory(mAvailableDevicesCategory,
                        R.string.bluetooth_preference_found_media_devices,
                        BluetoothDeviceFilter.ALL_FILTER, false);
                updateFooterPreference(mFooterPreference);
                //mAlwaysDiscoverable.start();
                enableScanning();
                break;

            case BluetoothAdapter.STATE_OFF:
                finish();
                break;
        }
    }

    @Override
    void updateFooterPreference(Preference myDevicePreference) {
        final BidiFormatter bidiFormatter = BidiFormatter.getInstance();
        myDevicePreference.setTitle(getString(
                R.string.bluetooth_footer_mac_message,
                bidiFormatter.unicodeWrap(mCachedDevice.getAddress())));
    }

    @Override
    public void onBluetoothStateChanged(int bluetoothState) {
        super.onBluetoothStateChanged(bluetoothState);
        updateContent(bluetoothState);
        if (bluetoothState == BluetoothAdapter.STATE_ON) {
            showBluetoothTurnedOnToast();
        }
    }



    @Override
    public int getHelpResource() {
        return R.string.help_url_bluetooth;
    }

    @Override
    protected String getLogTag() {
        return TAG;
    }

    @Override
    protected int getPreferenceScreenResId() {
        return R.xml.bluetooth_search_bcast_sources;
    }

    @Override
    public String getDeviceListKey() {
        return KEY_AVAIL_LE_AUDIO_SOURCES;
    }

    void showBluetoothTurnedOnToast() {
        Toast.makeText(getContext(), R.string.connected_device_bluetooth_turned_on_toast,
                Toast.LENGTH_SHORT).show();
    }
}
