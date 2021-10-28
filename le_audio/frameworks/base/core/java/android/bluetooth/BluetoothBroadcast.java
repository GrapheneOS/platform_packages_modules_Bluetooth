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

package android.bluetooth;

import android.Manifest;
import android.annotation.Nullable;
import android.annotation.RequiresPermission;
import android.annotation.SdkConstant;
import android.annotation.SdkConstant.SdkConstantType;
import android.content.Context;
import android.os.Binder;
import android.os.Build;
import android.os.IBinder;
import android.os.ParcelUuid;
import android.os.RemoteException;
import android.util.Log;
import android.app.ActivityThread;
import java.util.ArrayList;
import java.util.List;

/**
 * This class provides the public APIs to control the Bluetooth Broadcast
 * profile.
 *
 * <p>BluetoothBroadcast is a proxy object for controlling the Bluetooth
 * Broadcast Service via IPC. Use {@link BluetoothAdapter#getProfileProxy}
 * to get the BluetoothBroadcast proxy object.
 *
 * @hide
 */

public final class BluetoothBroadcast implements BluetoothProfile{
    private static final String TAG = "BluetoothBroadcast";
    private static final boolean DBG = true;
    private static final boolean VDBG = false;

    /**
     * Intent used to broadcast the change in broadcast state.
     *
     * <p>This intent will have 3 extras:
     * <ul>
     * <li> {@link #EXTRA_STATE} - The current state of the profile. </li>
     * <li> {@link #EXTRA_PREVIOUS_STATE}- The previous state of the profile.</li>
     * </ul>
     *
     * <p>{@link #EXTRA_STATE} or {@link #EXTRA_PREVIOUS_STATE} can be any of
     * {@link #STATE_Disabled}, {@link #Enabling},
     * {@link #STATE_ENABLED}, {@link #STATE_DISABLING}.
     *
     * <p>Requires {@link android.Manifest.permission#BLUETOOTH} permission to
     * receive.
     * @hide
     */
    @SdkConstant(SdkConstantType.BROADCAST_INTENT_ACTION)
    public static final String ACTION_BROADCAST_STATE_CHANGED =
            "android.bluetooth.broadcast.profile.action.BROADCAST_STATE_CHANGED";

    /**
     * Intent used to broadcast the change in broadcast audio state.
     *
     * <p>This intent will have 3 extras:
     * <ul>
     * <li> {@link #EXTRA_STATE} - The current audio state . </li>
     * <li> {@link #EXTRA_PREVIOUS_STATE}- The previous audio state.</li>
     * </ul>
     *
     * <p>{@link #EXTRA_STATE} or {@link #EXTRA_PREVIOUS_STATE} can be any of
     * {@link #STATE_PLAYING}, {@link #STATE_NOT_PLAYING},
     *
     * <p>Requires {@link android.Manifest.permission#BLUETOOTH} permission to
     * receive.
     * @hide
     */
    @SdkConstant(SdkConstantType.BROADCAST_INTENT_ACTION)
    public static final String ACTION_BROADCAST_AUDIO_STATE_CHANGED =
            "android.bluetooth.broadcast.profile.action.BROADCAST_AUDIO_STATE_CHANGED";

    /**
     * Intent used to broadcast encryption key generation status.
     *
     * <p>This intent will have 2 extras:
     * <ul>
     * <li> {@link #EXTRA_STATE} - The current audio state . </li>
     * </ul>
     *
     * <p>{@link #EXTRA_STATE} can be any of
     * {@link #TRUE}, {@link #FALSE},
     *
     * <p>Requires {@link android.Manifest.permission#BLUETOOTH} permission to
     * receive.
     * @hide
     */
    @SdkConstant(SdkConstantType.BROADCAST_INTENT_ACTION)
    public static final String ACTION_BROADCAST_ENCRYPTION_KEY_GENERATED =
            "android.bluetooth.broadcast.profile.action.BROADCAST_ENCRYPTION_KEY_GENERATED";

    public static final int STATE_DISABLED = 10;
    public static final int STATE_ENABLING = 11;
    public static final int STATE_ENABLED = 12;
    public static final int STATE_DISABLING = 13;
    public static final int STATE_STREAMING = 14;
    public static final int STATE_PLAYING = 10;
    public static final int STATE_NOT_PLAYING = 11;

    private BluetoothAdapter mAdapter;
    private final BluetoothProfileConnector<IBluetoothBroadcast> mProfileConnector =
            new BluetoothProfileConnector(this, BluetoothProfile.BROADCAST, "BluetoothBroadcast",
                    IBluetoothBroadcast.class.getName()) {
                @Override
                public IBluetoothBroadcast getServiceInterface(IBinder service) {
                    return IBluetoothBroadcast.Stub.asInterface(Binder.allowBlocking(service));
                }
    };
    /**
     * Create a BluetoothBroadcast proxy object for interacting with the local
     * Bluetooth Broadcast service.
     * @hide
     */
    /*package*/ BluetoothBroadcast(Context context, ServiceListener listener) {
        mAdapter = BluetoothAdapter.getDefaultAdapter();
        mProfileConnector.connect(context, listener);
    }

    /*
     * @hide
    */
    //@UnsupportedAppUsage
    /*package*/ void close() {
        mProfileConnector.disconnect();
    }

    /*
     * @hide
    */
    private IBluetoothBroadcast getService() {
        return mProfileConnector.getService();
    }

    @Override
    public void finalize() {
        // The empty finalize needs to be kept or the
        // cts signature tests would fail.
    }
    /*
     * @hide
    */
    //@UnsupportedAppUsage
    public boolean SetBroadcastMode(boolean enable) {
        if (DBG) log("EnableBroadcast");
        String packageName = ActivityThread.currentPackageName();
        try {
            final IBluetoothBroadcast service = getService();
            if (service != null && isEnabled()) {
                return service.SetBroadcast(enable, packageName);
            }
            if (service == null) Log.w(TAG, "Proxy not attached to service");
            return false;
        } catch (RemoteException e) {
            Log.e(TAG, "Stack:" + Log.getStackTraceString(new Throwable()));
            return false;
        }
    }
    /**
     * Not supported - please use {@link BluetoothManager#getConnectedDevices(int)}
     * with {@link BluetoothProfile#GATT} as argument
     *
     * @throws UnsupportedOperationException
     */
    @Override
    public int getConnectionState(BluetoothDevice device) {
        throw new UnsupportedOperationException(
                   "Use BluetoothManager#getConnectedDevices instead.");
    }
    /**
     * Not supported - please use {@link BluetoothManager#getConnectedDevices(int)}
     * with {@link BluetoothProfile#GATT} as argument
     *
     * @throws UnsupportedOperationException
     */
    @Override
    public List<BluetoothDevice> getDevicesMatchingConnectionStates(int[] states) {
        throw new UnsupportedOperationException(
                   "Use BluetoothManager#getConnectedDevices instead.");
    }
    /**
     * Not supported - please use {@link BluetoothManager#getConnectedDevices(int)}
     * with {@link BluetoothProfile#GATT} as argument
     *
     * @throws UnsupportedOperationException
     */
    @Override
    public List<BluetoothDevice> getConnectedDevices() {
        throw new UnsupportedOperationException(
                   "Use BluetoothManager#getConnectedDevices instead.");
    }

    /*
     * @hide
    */
    public boolean SetEncryption(boolean enable, int enc_len/*4bytes,16bytes*/, boolean use_existing) {
        if (DBG) log("SetEncryption");
        String packageName = ActivityThread.currentPackageName();
        try {
            final IBluetoothBroadcast service = getService();
            if (service != null && isEnabled()) {
                return service.SetEncryption(enable, enc_len, use_existing, packageName);
            }
            if (service == null) Log.w(TAG, "Proxy not attached to service");
            return false;
        } catch (RemoteException e) {
            Log.e(TAG, "Stack:" + Log.getStackTraceString(new Throwable()));
            return false;
        }
    }
    /*
     * @hide
    */
    public byte[] GetEncryptionKey() {
        if (DBG) log("GetBroadcastEncryptionKey");
        String packageName = ActivityThread.currentPackageName();
        try {
            final IBluetoothBroadcast service = getService();
            if (service != null && isEnabled()) {
                return service.GetEncryptionKey(packageName);
            }
            if (service == null) Log.w(TAG, "Proxy not attached to service");
            return null;
        } catch (RemoteException e) {
            Log.e(TAG, "Stack:" + Log.getStackTraceString(new Throwable()));
            return null;
        }
    }
    /*
     * @hide
    */
    public int GetBroadcastStatus() {
        if (DBG) log("GetBroadcastStatus");
        String packageName = ActivityThread.currentPackageName();
        try {
            final IBluetoothBroadcast service = getService();
            if (service != null && isEnabled()) {
                return service.GetBroadcastStatus(packageName);
            }
            if (service == null) Log.w(TAG, "Proxy not attached to service");
            return STATE_DISABLED;
        } catch (RemoteException e) {
            Log.e(TAG, "Stack:" + Log.getStackTraceString(new Throwable()));
            return STATE_DISABLED;
        }
    }
    //@UnsupportedAppUsage
//    public @Nullable BluetoothCodecStatus getCodecStatus(BluetoothDevice device) {return null;}

    private boolean isEnabled() {
        if (mAdapter.getState() == BluetoothAdapter.STATE_ON) return true;
        return false;
    }

    private static void log(String msg) {
        Log.d(TAG, msg);
    }
}


