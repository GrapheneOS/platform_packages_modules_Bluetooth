/*
 * Copyright (c) 2020, The Linux Foundation. All rights reserved.
 *
 */

package com.android.settings.bluetooth;

import android.bluetooth.BluetoothAdapter;
import android.bluetooth.BluetoothBroadcast;
import android.content.Context;
import android.util.Log;
import android.os.SystemProperties;
import android.os.Handler;
import android.os.Message;

import androidx.preference.PreferenceScreen;
import androidx.preference.SwitchPreference;
import com.android.settingslib.RestrictedSwitchPreference;
import com.android.settings.core.TogglePreferenceController;
import com.android.settingslib.bluetooth.BluetoothCallback;
import com.android.settingslib.bluetooth.BluetoothUtils;
import com.android.settingslib.bluetooth.BroadcastProfile;
import com.android.settingslib.bluetooth.LocalBluetoothProfile;
import com.android.settingslib.bluetooth.LocalBluetoothProfileManager;
import com.android.settingslib.core.lifecycle.LifecycleObserver;
import com.android.settingslib.core.lifecycle.events.OnPause;
import com.android.settingslib.core.lifecycle.events.OnResume;
import com.android.settingslib.core.lifecycle.events.OnDestroy;
import com.android.settings.connecteddevice.BluetoothDashboardFragment;
import com.android.settingslib.bluetooth.LocalBluetoothManager;
import androidx.annotation.Keep;

@Keep
public class BluetoothBroadcastEnableController extends TogglePreferenceController
    implements LifecycleObserver, OnResume, OnPause, OnDestroy, BluetoothCallback {

    public static final String TAG = "BluetoothBroadcastEnableController";
    public static final int BROADCAST_AUDIO_MASK = 0x04;
    public static final String BLUETOOTH_LE_AUDIO_MASK_PROP = "persist.vendor.service.bt.adv_audio_mask";
    public static final String KEY_BROADCAST_ENABLE = "bluetooth_screen_broadcast_enable";
    private RestrictedSwitchPreference mPreference = null;
    private BluetoothAdapter mBluetoothAdapter;
    private boolean mState = false;
    private boolean reset_pending = false;
    private Context mContext;
    private BroadcastProfile mBapBroadcastProfile = null;
    private boolean isBluetoothLeBroadcastAudioSupported = false;
    private boolean mCallbacksRegistered = false;
    private LocalBluetoothManager mManager = null;
    public BluetoothBroadcastEnableController(Context context, String key) {
        super(context, key);
        Log.d(TAG, "Constructor() with key");
        Init(context);
    }

    private void Init(Context context) {
        mContext = context;
        int leAudioMask = SystemProperties.getInt(BLUETOOTH_LE_AUDIO_MASK_PROP, 0);
        isBluetoothLeBroadcastAudioSupported = ((leAudioMask & BROADCAST_AUDIO_MASK) == BROADCAST_AUDIO_MASK);
        if(isBluetoothLeBroadcastAudioSupported){
           mManager = Utils.getLocalBtManager(context);
           mBapBroadcastProfile = (BroadcastProfile) mManager.getProfileManager().getBroadcastProfile();
           if (!mCallbacksRegistered) {
               Log.d(TAG, "Registering EventManager callbacks");
               mCallbacksRegistered = true;
               mManager.getEventManager().registerCallback(this);
           }
        }
        Log.d(TAG, "Init done");
    }

    private void updateState(boolean newState) {
        Log.d(TAG, "updateState req " + Boolean.toString(newState));
        if (newState != mState) {
             if (mPreference != null) mPreference.setEnabled(false);
             Log.d(TAG, "updateState to " + Boolean.toString(newState));
             mBapBroadcastProfile.setBroadcastMode(newState);
        }
    }

    private void onStateChanged(boolean newState) {
        Log.d(TAG, "onStateChanged " + Boolean.toString(newState));
        mState = newState;
        if (mPreference != null) mPreference.setChecked(mState);
        if (mState == false && reset_pending == true) {
            reset_pending = false;
            updateState(true);
        }
    }

    private final Handler mHandler = new Handler() {
        @Override
        public void handleMessage(Message msg) {
            Log.d(TAG, "BT state, msg = " + Integer.toString(msg.what));
            switch (msg.what) {
            case BluetoothAdapter.STATE_ON:
                if (mPreference != null) mPreference.setEnabled(true);
                mBapBroadcastProfile = (BroadcastProfile) mManager.getProfileManager().getBroadcastProfile();
                break;
            case BluetoothAdapter.STATE_TURNING_ON:
            case BluetoothAdapter.STATE_OFF:
            case BluetoothAdapter.STATE_TURNING_OFF:
                reset_pending = false;
                onStateChanged(false);
                mBapBroadcastProfile = null;
                if (mPreference != null) mPreference.setEnabled(false);
                break;
            }
        }
    };

    @Override
    public void onBluetoothStateChanged(int newBtState) {
        Log.d(TAG, "onBluetoothStateChanged" + Integer.toString(newBtState));

        switch (newBtState) {
            case BluetoothAdapter.STATE_ON:
                mHandler.sendMessageDelayed(mHandler.obtainMessage(newBtState), 200);
                break;
            case BluetoothAdapter.STATE_TURNING_ON:
            case BluetoothAdapter.STATE_OFF:
            case BluetoothAdapter.STATE_TURNING_OFF:
                mHandler.sendMessage(mHandler.obtainMessage(newBtState));
                break;
        }
    }

    @Override
    public void onBroadcastStateChanged(int newBapState) {
        Log.d(TAG, "onBroadcastStateChanged" + Integer.toString(newBapState));

        switch (newBapState) {
            case BluetoothBroadcast.STATE_ENABLED:
                if (mPreference != null) mPreference.setEnabled(true);
                onStateChanged(true);
                break;
            case BluetoothBroadcast.STATE_DISABLED:
                if (mPreference != null) mPreference.setEnabled(true);
                onStateChanged(false);
                break;
        }
    }

    @Override
    public void onBroadcastKeyGenerated() {
         Log.d(TAG, "onBroadcastKeyGenerated");
         // Encryption key got updated. Reset BAP?
         if (mState == true) {
             reset_pending = true;
             updateState(false);
         }
    }

    @Override
    public String getPreferenceKey() {
        Log.d(TAG, "getPreferenceKey");
        return KEY_BROADCAST_ENABLE;
    }

    @Override
    public void displayPreference(PreferenceScreen screen) {
        super.displayPreference(screen);
        Log.d(TAG, "displayPreference");
        mPreference = screen.findPreference(getPreferenceKey());
        if(isBluetoothLeBroadcastAudioSupported) {
          mBluetoothAdapter = BluetoothAdapter.getDefaultAdapter();
          onBluetoothStateChanged(mBluetoothAdapter.getState());
          if ((mBluetoothAdapter.getState() == BluetoothAdapter.STATE_ON) &&
              (mBapBroadcastProfile.isProfileReady())) {
            int bapState = mBapBroadcastProfile.getBroadcastStatus();
            Log.d(TAG, "get status done");
            if ((bapState == BluetoothBroadcast.STATE_ENABLED) ||
                 (bapState == BluetoothBroadcast.STATE_STREAMING))
                onStateChanged(true);
            else
                onStateChanged(false);
          }
        } else {
          mPreference.setVisible(false);
        }
    }

    @Override
    public boolean isChecked() {
        return mState;
    }

    @Override
    public boolean setChecked(boolean isChecked) {
        updateState(isChecked);
        return true;
    }

    @Override
    public int getAvailabilityStatus() {
        Log.d(TAG, "getAvailabilityStatus");
        if(isBluetoothLeBroadcastAudioSupported) {
            return AVAILABLE;
        } else {
            return UNSUPPORTED_ON_DEVICE;
        }
    }

    @Override
    public boolean hasAsyncUpdate() {
        Log.d(TAG, "hasAsyncUpdate");
        return true;
    }

    @Override
    public boolean isPublicSlice() {
        Log.d(TAG, "isPublicSlice");
        return true;
    }

    @Override
    public void onResume() {
        Log.d(TAG, "onResume");
    }

    @Override
    public void onPause() {
        Log.d(TAG, "onPause");
    }

    @Override
    public void onDestroy() {
        Log.d(TAG, "onDestory");
        mCallbacksRegistered = false;
        if (mManager != null)
            mManager.getEventManager().unregisterCallback(this);
    }
}
