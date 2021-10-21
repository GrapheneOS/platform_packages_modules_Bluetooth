/*
 * Copyright (c) 2020, The Linux Foundation. All rights reserved.
 *
 */


package com.android.settings.bluetooth;

import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

import android.app.settings.SettingsEnums;
import android.bluetooth.BluetoothBroadcast;
import android.content.Context;
import android.content.pm.PackageManager;
import android.util.Log;
import android.view.View;
import android.view.LayoutInflater;
import android.text.TextUtils;
import android.widget.TextView;
import android.bluetooth.BluetoothAdapter;
import android.os.Handler;
import android.os.SystemProperties;

import androidx.annotation.VisibleForTesting;
import androidx.preference.Preference;
import androidx.preference.PreferenceFragmentCompat;
import androidx.fragment.app.Fragment;
import androidx.preference.PreferenceScreen;

import com.android.settingslib.bluetooth.BluetoothCallback;
import com.android.settingslib.bluetooth.BluetoothUtils;
import com.android.settingslib.bluetooth.BroadcastProfile;
import com.android.settingslib.bluetooth.LocalBluetoothProfile;
import com.android.settingslib.bluetooth.LocalBluetoothProfileManager;
import com.android.settingslib.RestrictedPreference;
import com.android.settings.core.BasePreferenceController;
import com.android.settings.core.PreferenceControllerMixin;
import com.android.settings.overlay.FeatureFactory;
import com.android.settingslib.core.instrumentation.MetricsFeatureProvider;
import com.android.settingslib.core.lifecycle.events.OnDestroy;
import com.android.settingslib.widget.LayoutPreference;
import com.android.settingslib.bluetooth.LocalBluetoothManager;
import com.android.settings.R;
import com.android.settings.core.instrumentation.InstrumentedDialogFragment;
import androidx.annotation.Keep;

/**
 * Controller that shows Pin for BLE Broadcast Audio
 */
@Keep
public class BluetoothBroadcastPinController extends BasePreferenceController
    implements OnDestroy, BluetoothCallback {
    public static final String TAG = "BluetoothBroadcastPinController";
    public static final int BROADCAST_AUDIO_MASK = 0x04;
    public static final String BLUETOOTH_LE_AUDIO_MASK_PROP = "persist.vendor.service.bt.adv_audio_mask";
    public static final String KEY_BROADCAST_AUDIO_PIN = "bluetooth_screen_broadcast_pin_configure";

    private BluetoothAdapter mBluetoothAdapter;
    private Fragment mFragment = null;
    private MetricsFeatureProvider mMetricsFeatureProvider;
    @VisibleForTesting
    RestrictedPreference mPreference;
    private Context mContext;

    private boolean isBluetoothLeBroadcastAudioSupported = false;
    private boolean mCallbacksRegistered = false;
    private LocalBluetoothManager mManager = null;
    private Handler mHandler;
    private Runnable mRunnable = new Runnable() {
        @Override
        public void run() {
            onBroadcastKeyGenerated();
        }
    };

    public BluetoothBroadcastPinController(Context context) {
        super(context, KEY_BROADCAST_AUDIO_PIN);
        int leAudioMask = SystemProperties.getInt(BLUETOOTH_LE_AUDIO_MASK_PROP, 0);
        isBluetoothLeBroadcastAudioSupported = ((leAudioMask & BROADCAST_AUDIO_MASK) == BROADCAST_AUDIO_MASK);
        Log.d(TAG, "Constructor()");
        mContext = context;
        mHandler = new Handler();
        mBluetoothAdapter = BluetoothAdapter.getDefaultAdapter();
        if(isBluetoothLeBroadcastAudioSupported) {
          mManager = Utils.getLocalBtManager(context);
          if (!mCallbacksRegistered) {
              Log.d(TAG, "Registering EventManager callbacks");
              mCallbacksRegistered = true;
              mManager.getEventManager().registerCallback(this);
          }
        }
    }

    public BluetoothBroadcastPinController(Context context, PreferenceFragmentCompat fragment, String prefKey) {
        super(context, KEY_BROADCAST_AUDIO_PIN);
        Log.d(TAG, "PinController()" + prefKey);
        mFragment = fragment;
        mMetricsFeatureProvider = FeatureFactory.getFactory(context).getMetricsFeatureProvider();
    }

    @VisibleForTesting
    public void setFragment(Fragment fragment) {
        Log.d(TAG, "setFragment");
        mFragment = fragment;
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
    public String getPreferenceKey() {
        return KEY_BROADCAST_AUDIO_PIN;
    }

    @Override
    public void displayPreference(PreferenceScreen screen) {
        super.displayPreference(screen);
        Log.d(TAG, "displayPreference");
        mPreference = screen.findPreference(getPreferenceKey());
        if(isBluetoothLeBroadcastAudioSupported) {
          onBroadcastKeyGenerated();
        } else {
          mPreference.setVisible(false);
        }
    }

    @Override
    public boolean handlePreferenceTreeClick(Preference preference) {
        Log.d(TAG, "PinController: handlePreferenceTreeClick");
        if (KEY_BROADCAST_AUDIO_PIN.equals(preference.getKey())) {
            Log.d(TAG, "PinController: handlePreferenceTreeClick true");
            new BluetoothBroadcastPinFragment()
		.show(mFragment.getFragmentManager(), "PinFragment");
            return true;
        }

        return false;
    }

    @Override
    public void onBluetoothStateChanged(int newBtState) {
        Log.d(TAG, "onBluetoothStateChanged" + Integer.toString(newBtState));
        int delay = 0;
        switch (newBtState) {
            case BluetoothAdapter.STATE_ON:
              delay = 200;
            case BluetoothAdapter.STATE_OFF:
              mHandler.postDelayed(mRunnable, delay);
            break;
        }
    }

    private String convertBytesToString(byte[] pin) {
        if (pin.length != 16) {
           Log.e (TAG, "Not 16 bytes ++++++++++++");
           return "";
        }
        byte[] temp = new byte[16];
        int i = 0, j = 0;
        // Reverse the pin and discard the padding
        for (i = 0; i < 16; i++) {
            if (pin[15-i] == 0) break;
            temp[j++] = pin[15-i];
        }
        String str;
        if (j == 0)
           str = new String(""); // unencrypted
        else
           str = new String(Arrays.copyOfRange(temp,0,j), StandardCharsets.UTF_8);
        Log.d(TAG, "Pin: " + str);
        return str;
    }

    @Override
    public void onBroadcastKeyGenerated() {
        Log.d(TAG, "onBroadcastKeyGenerated");
        String summary = "Broadcast code: ";
        String keyStr = "Unavailable";

        mBluetoothAdapter = BluetoothAdapter.getDefaultAdapter();
        LocalBluetoothProfileManager profileManager = mManager.getProfileManager();
        BroadcastProfile bapProfile = (BroadcastProfile) profileManager.getBroadcastProfile();
        if ((mBluetoothAdapter.getState() == BluetoothAdapter.STATE_ON) &&
            (bapProfile.isProfileReady())) {
          byte[] key = bapProfile.getEncryptionKey();
          // Key can only be 16 byte long
          if (key.length == 16) {
              for(int i = 0; i<key.length; i++) {
                  Log.d(TAG, "pin(" + Integer.toString(i) + "): " + String.format("%02X", key[i]));
              }
              keyStr = convertBytesToString(key);
          }
          if (keyStr.equals("")) summary = "No Broadcast code";
          mPreference.setSummary(summary + keyStr);
          mPreference.setVisible(true);
          if (keyStr.equals("Unavailable")) {
            mPreference.setEnabled(false);
          } else {
            mPreference.setEnabled(true);
          }
        } else {
          mPreference.setSummary(summary + keyStr);
          mPreference.setEnabled(false);
        }
    }

    @Override
    public void onDestroy() {
        Log.d(TAG, "onDestory");
        mCallbacksRegistered = false;
        if (mManager != null)
            mManager.getEventManager().unregisterCallback(this);
    }
}
