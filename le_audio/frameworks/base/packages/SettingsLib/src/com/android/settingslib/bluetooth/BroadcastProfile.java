/*
*Copyright (c) 2020, The Linux Foundation. All rights reserved.
*
*/

package com.android.settingslib.bluetooth;

import android.bluetooth.BluetoothAdapter;
import android.bluetooth.BluetoothClass;
import android.bluetooth.BluetoothDevice;
import android.bluetooth.BluetoothBroadcast;
import android.bluetooth.BluetoothProfile;
import android.content.Context;
import android.util.Log;
import static android.bluetooth.BluetoothProfile.CONNECTION_POLICY_FORBIDDEN;
import static android.bluetooth.BluetoothProfile.CONNECTION_POLICY_ALLOWED;
import com.android.settingslib.R;
import androidx.annotation.Keep;

/**
 * BroadcastProfile handles Bluetooth Broadcast profile.
 */
@Keep
public final class BroadcastProfile implements LocalBluetoothProfile {
    private static final String TAG = "BroadcastProfile";
    private static boolean V = true;

    private BluetoothBroadcast mService;
    private boolean mIsProfileReady = false;

    static final String NAME = "Broadcast";

    // Order of this profile in device profiles list
    private static final int ORDINAL = 0;

    // These callbacks run on the main thread.
    private final class BroadcastListener
            implements BluetoothProfile.ServiceListener {

        public void onServiceConnected(int profile, BluetoothProfile proxy) {
            if (profile == BluetoothProfile.BROADCAST) {
              if (V) Log.d(TAG,"Bluetooth Broadcast service connected");
              mService = (BluetoothBroadcast) proxy;
              mIsProfileReady = true;
            }
        }

        public void onServiceDisconnected(int profile) {
            if (profile == BluetoothProfile.BROADCAST) {
              if (V) Log.d(TAG,"Bluetooth Broadcast service disconnected");
              mIsProfileReady = false;
            }
        }
    }

    public boolean isProfileReady() {
        Log.d(TAG,"isProfileReady = " + mIsProfileReady);
        return mIsProfileReady;
    }

    @Override
    public int getProfileId() {
        Log.d(TAG,"getProfileId");
        return BluetoothProfile.BROADCAST;
    }

    BroadcastProfile(Context context) {
        Log.d(TAG,"BroadcastProfile constructor");
        BluetoothAdapter.getDefaultAdapter().getProfileProxy(context,
                new BroadcastListener(), BluetoothProfile.BROADCAST);
    }

    public boolean accessProfileEnabled() {
        Log.d(TAG,"accessProfileEnabled");
        return false;
    }

    public boolean isAutoConnectable() {
        return false;
    }

    public boolean connect(BluetoothDevice device) {
        return false;
    }

    public boolean disconnect(BluetoothDevice device) {
        return false;
    }

    public int getConnectionStatus(BluetoothDevice device) {
        return BluetoothProfile.STATE_DISCONNECTED;
    }

    public boolean isEnabled(BluetoothDevice device) {
        return false;
    }

    public int getConnectionPolicy(BluetoothDevice device) {
        return CONNECTION_POLICY_FORBIDDEN;     
    }

    public boolean setEnabled(BluetoothDevice device, boolean enabled) {
        return false;//CONNECTION_POLICY_ALLOWED;
    }
     
    public void setPreferred(BluetoothDevice device, boolean preferred) {
    }
    public int getPreferred(BluetoothDevice device) {
        return BluetoothProfile.PRIORITY_OFF;
    }
    public boolean isPreferred(BluetoothDevice device) {
        return false;
    }
    public String toString() {
        return NAME;
    }

    public int getOrdinal() {
        return ORDINAL;
    }

    public int getNameResource(BluetoothDevice device) {
        return R.string.bluetooth_profile_broadcast;
    }

    public int getSummaryResourceForDevice(BluetoothDevice device) {
        return 0;
    }

    public int getDrawableResource(BluetoothClass btClass) {
        return 0;
    }

    public boolean setEncryption(boolean enable, int enc_len, boolean use_existing) {
      Log.d(TAG,"setEncryption");
      return mService.SetEncryption(enable, enc_len, use_existing);
    }

    public byte[] getEncryptionKey() {
      Log.d(TAG,"getEncryptionKey");
      return mService.GetEncryptionKey();
    }

    public int getBroadcastStatus() {
      Log.d(TAG,"getBroadcastStatus");
      return mService.GetBroadcastStatus();
    }

    public boolean setBroadcastMode(boolean enable) {
      Log.d(TAG,"setBroadcastMode");
      return mService.SetBroadcastMode(enable);
    }

    protected void finalize() {
        if (V) Log.d(TAG, "finalize()");
        if (mService != null) {
            try {
                BluetoothAdapter.getDefaultAdapter().closeProfileProxy
                                    (BluetoothProfile.BROADCAST, mService);
                mService = null;
            } catch (Throwable t) {
                Log.w(TAG, "Error cleaning up Broadcast proxy", t);
            }
        }
    }
}
