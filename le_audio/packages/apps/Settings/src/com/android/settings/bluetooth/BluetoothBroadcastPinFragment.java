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



package com.android.settings.bluetooth;

import android.app.Dialog;
import android.content.Context;
import android.content.DialogInterface;
import android.content.res.Configuration;
import android.os.Bundle;
import android.text.Editable;
import android.text.InputFilter;
import android.text.TextUtils;
import android.text.TextWatcher;
import android.view.KeyEvent;
import android.view.LayoutInflater;
import android.util.Log;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.TextView;
import android.widget.RadioButton;
import android.widget.RadioGroup;

import androidx.annotation.VisibleForTesting;
import androidx.appcompat.app.AlertDialog;
import androidx.fragment.app.Fragment;
import androidx.fragment.app.FragmentActivity;
import androidx.fragment.app.FragmentManager;
import androidx.fragment.app.DialogFragment;

import android.app.settings.SettingsEnums;
import com.android.settings.R;
import com.android.settings.core.instrumentation.InstrumentedDialogFragment;
import com.android.settings.bluetooth.BluetoothBroadcastEnableController;
import com.android.settingslib.bluetooth.BluetoothUtils;
import com.android.settingslib.bluetooth.BroadcastProfile;
import com.android.settingslib.bluetooth.LocalBluetoothProfile;
import com.android.settingslib.bluetooth.LocalBluetoothManager;
import com.android.settingslib.bluetooth.LocalBluetoothProfileManager;
import java.util.ArrayList;
import java.util.List;


/**
 * Dialog fragment for renaming a Bluetooth device.
 */
public class BluetoothBroadcastPinFragment extends InstrumentedDialogFragment
        implements RadioGroup.OnCheckedChangeListener {

    public static BluetoothBroadcastPinFragment newInstance() {
        Log.d(TAG, "newInstance");
        BluetoothBroadcastPinFragment frag = new BluetoothBroadcastPinFragment();
        return frag;
    }

    public static final String TAG = "BluetoothBroadcastPinFragment";

    private Context mContext;
    @VisibleForTesting
    AlertDialog mAlertDialog = null;
    private Dialog mDialog = null;
    private Button mOkButton = null;
    private TextView mCurrentPinView;

    private String mCurrentPin = "4308";
    private int mUserSelectedPinConfiguration = -1;

    private List<Integer> mRadioButtonIds = new ArrayList<>();
    private List<String> mRadioButtonStrings = new ArrayList<>();

    private int getDialogTitle() {
       return R.string.bluetooth_broadcast_pin_configure_dialog;
    }

    private void updatePinConfiguration() {
        Log.d(TAG, "updatePinConfiguration with " + Integer.toString(mUserSelectedPinConfiguration));
        if (mUserSelectedPinConfiguration == -1) {
          Log.e(TAG, "no pin selected");
          return;
        }
        // Call lower layer to generate new pin
        LocalBluetoothManager mManager = Utils.getLocalBtManager(mContext);
        LocalBluetoothProfileManager profileManager = mManager.getProfileManager();
        BroadcastProfile bapProfile = (BroadcastProfile) profileManager.getBroadcastProfile();
        if (mUserSelectedPinConfiguration != 0)
           bapProfile.setEncryption(true, mUserSelectedPinConfiguration, false);
        else
           bapProfile.setEncryption(false, mUserSelectedPinConfiguration, false);
    }

    @Override
    public void onAttach(Context context) {
        Log.d(TAG, "onAttach");
        super.onAttach(context);
        mContext = context;
    }

    @Override
    public void onCreate(Bundle savedInstanceState) {
        Log.d(TAG, "onCreate");
        super.onCreate(savedInstanceState);
    }

    @Override
    public void onActivityCreated(Bundle savedInstanceState) {
        Log.d(TAG, "onActivityCreated");
        super.onActivityCreated(savedInstanceState);
        //Dialog mDialog = onCreateDialog(new Bundle());
        //this.show(this.getActivity().getSupportFragmentManager(), "PinFragment");
    }

    /*
    public void show() {
        Log.e(TAG, "show");
        this.show(this.getActivity().getSupportFragmentManager(), "PinFragment");
    }
    */

    @Override
    public Dialog onCreateDialog(Bundle savedInstanceState) {
        //String deviceName = getDeviceName();
        Log.d(TAG, "onCreateDialog - enter");
        if (savedInstanceState != null) {
            Log.e(TAG, "savedInstanceState != null");
        }
        AlertDialog.Builder builder = new AlertDialog.Builder(getActivity())
                .setTitle(getDialogTitle())
                .setView(createDialogView())
                .setPositiveButton(R.string.okay, (dialog, which) -> {
                    //setDeviceName(mDeviceNameView.getText().toString().trim());
                    updatePinConfiguration();
                })
                .setNegativeButton(android.R.string.cancel, null);
        mAlertDialog = builder.create();
        Log.d(TAG, "onCreateDialog - exit");
        return mAlertDialog;
    }

    @Override
    public int getMetricsCategory() {
        return SettingsEnums.BLUETOOTH_FRAGMENT;
    }

    @Override
    public void onSaveInstanceState(Bundle outState) {
        Log.d(TAG, "onSaveInstanceState");
    }

    private int getRadioButtonGroupId() {
        return R.id.bluetooth_broadcast_pin_config_radio_group;
    }

    private void setCurrentPin(String pin) {
        mCurrentPin = pin;
    }

    private String getCurrentPin() {
        return mCurrentPin;
    }

    @Override
    public void onCheckedChanged(RadioGroup group, int checkedId) {
        Log.d(TAG, "Index changed to " + checkedId);
        // radioButton = (RadioButton) view.findViewById(checkedId);
        int index = mRadioButtonIds.indexOf(checkedId);
        Log.d(TAG, "index");
        String[] stringArrayValues = getContext().getResources().getStringArray(
                R.array.bluetooth_broadcast_pin_config_values);
        mUserSelectedPinConfiguration = Integer.parseInt(stringArrayValues[index]);
        Log.d(TAG, "Selected Pin Configuration " + Integer.toString(mUserSelectedPinConfiguration));
    }

    private View createDialogView() {
        Log.d(TAG, "onCreateDialogView - enter");
        final LayoutInflater layoutInflater = (LayoutInflater)getActivity()
            .getSystemService(Context.LAYOUT_INFLATER_SERVICE);
        View view = layoutInflater.inflate(R.xml.bluetooth_broadcast_pin_config, null);

        final RadioGroup radioGroup = (RadioGroup) view.findViewById(getRadioButtonGroupId());
        if (radioGroup == null) {
            Log.e (TAG, "Not able to find RadioGroup");
            return null;
        }
        radioGroup.clearCheck();
        radioGroup.setOnCheckedChangeListener(this);

        // Fill up the Radio Group
        mRadioButtonIds.add(R.id.bluetooth_broadcast_pin_unencrypted);
        mRadioButtonIds.add(R.id.bluetooth_broadcast_pin_4);
        mRadioButtonIds.add(R.id.bluetooth_broadcast_pin_16);
        String[] stringArray = getContext().getResources().getStringArray(
                R.array.bluetooth_broadcast_pin_config_titles);
        for (int i = 0; i < stringArray.length; i++) {
            mRadioButtonStrings.add(stringArray[i]);
        }
        RadioButton radioButton;
        for (int i = 0; i < mRadioButtonStrings.size(); i++) {
            radioButton = (RadioButton) view.findViewById(mRadioButtonIds.get(i));
            if (radioButton == null) {
                Log.e(TAG, "Unable to show dialog by no radio button:" + mRadioButtonIds.get(i));
                return null;
            }
            radioButton.setText(mRadioButtonStrings.get(i));
            radioButton.setEnabled(true);
        }

        mCurrentPinView = (TextView) view.findViewById(R.id.bluetooth_broadcast_current_pin);
        //mCurrentPinView.setText("Current Pin is " + getCurrentPin());
        Log.d(TAG, "onCreateDialogView - exit");
        return view;
    }

    @Override
    public void onDestroy() {
        super.onDestroy();
        Log.d(TAG, "onDestroy");
        mAlertDialog = null;
        mOkButton = null;
        mCurrentPinView = null;
        mRadioButtonIds = new ArrayList<>();
        mRadioButtonStrings = new ArrayList<>();
        mUserSelectedPinConfiguration = -1;
    }

    @Override
    public void onResume() {
        super.onResume();
        Log.d(TAG, "onResume");
        if (mOkButton == null) {
            if (mAlertDialog != null) {
                mOkButton = mAlertDialog.getButton(DialogInterface.BUTTON_POSITIVE);
                mOkButton.setEnabled(true);
            } else {
                Log.d(TAG, "onResume: mAlertDialog is null");
            }
        }
    }
}
