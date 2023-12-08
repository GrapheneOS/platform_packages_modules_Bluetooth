/*
 * Copyright 2019 The Android Open Source Project
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

package android.bluetooth;

import android.annotation.SuppressLint;
import android.content.ComponentName;
import android.os.Handler;
import android.os.IBinder;
import android.os.Looper;
import android.os.Message;
import android.os.RemoteException;
import android.util.CloseGuard;
import android.util.Log;

import java.util.Objects;

/**
 * Connector for Bluetooth profile proxies to bind manager service and profile services
 *
 * @hide
 */
@SuppressLint("AndroidFrameworkBluetoothPermission")
public final class BluetoothProfileConnector extends Handler {
    private static final String TAG = BluetoothProfileConnector.class.getSimpleName();
    private final CloseGuard mCloseGuard = new CloseGuard();
    private final int mProfileId;
    private BluetoothProfile.ServiceListener mServiceListener;
    private final BluetoothProfile mProfileProxy;
    private String mPackageName;
    private final IBluetoothManager mBluetoothManager;
    private boolean mBound = false;

    private static final int MESSAGE_SERVICE_CONNECTED = 100;
    private static final int MESSAGE_SERVICE_DISCONNECTED = 101;

    private final IBluetoothStateChangeCallback mBluetoothStateChangeCallback =
            new IBluetoothStateChangeCallback.Stub() {
                public void onBluetoothStateChange(boolean up) {
                    if (up) {
                        doBind();
                    } else {
                        doUnbind();
                    }
                }
            };

    private final IBluetoothProfileServiceConnection mConnection =
            new IBluetoothProfileServiceConnection.Stub() {
                @Override
                public void onServiceConnected(ComponentName className, IBinder service) {
                    Log.d(
                            TAG,
                            "Proxy object connected for "
                                    + BluetoothProfile.getProfileName(mProfileId));
                    mProfileProxy.onServiceConnected(service);
                    sendEmptyMessage(MESSAGE_SERVICE_CONNECTED);
                }

                @Override
                public void onServiceDisconnected(ComponentName className) {
                    Log.d(
                            TAG,
                            "Proxy object disconnected for "
                                    + BluetoothProfile.getProfileName(mProfileId));
                    boolean bound = mBound;
                    doUnbind();
                    if (bound) {
                        sendEmptyMessage(MESSAGE_SERVICE_DISCONNECTED);
                    }
                }
            };

    /** @hide */
    public BluetoothProfileConnector(
            Looper looper,
            BluetoothProfile profile,
            int profileId,
            IBluetoothManager bluetoothManager) {
        super(looper);
        mProfileId = profileId;
        mProfileProxy = profile;
        mBluetoothManager = Objects.requireNonNull(bluetoothManager);
    }

    BluetoothProfileConnector(BluetoothProfile profile, int profileId) {
        this(
                Looper.getMainLooper(),
                profile,
                profileId,
                BluetoothAdapter.getDefaultAdapter().getBluetoothManager());
    }

    /** @hide */
    @Override
    @SuppressWarnings("Finalize") // TODO(b/314811467)
    public void finalize() {
        mCloseGuard.warnIfOpen();
        doUnbind();
    }

    private void doBind() {
        synchronized (mConnection) {
            if (!mBound) {
                Log.d(
                        TAG,
                        "Binding service "
                                + BluetoothProfile.getProfileName(mProfileId)
                                + " for "
                                + mPackageName);
                mCloseGuard.open("doUnbind");
                try {
                    mBluetoothManager.bindBluetoothProfileService(mProfileId, mConnection);
                    mBound = true;
                } catch (RemoteException re) {
                    Log.e(
                            TAG,
                            "Failed to bind service. "
                                    + BluetoothProfile.getProfileName(mProfileId),
                            re);
                }
            }
        }
    }

    private void doUnbind() {
        synchronized (mConnection) {
            if (mBound) {
                Log.d(
                        TAG,
                        "Unbinding service "
                                + BluetoothProfile.getProfileName(mProfileId)
                                + " for "
                                + mPackageName);
                mCloseGuard.close();
                try {
                    mBluetoothManager.unbindBluetoothProfileService(mProfileId, mConnection);
                    mBound = false;
                } catch (RemoteException re) {
                    Log.e(
                            TAG,
                            "Unable to unbind service "
                                    + BluetoothProfile.getProfileName(mProfileId),
                            re);
                } finally {
                    mProfileProxy.onServiceDisconnected();
                }
            }
        }
    }

    /** @hide */
    public void connect(String packageName, BluetoothProfile.ServiceListener listener) {
        mPackageName = packageName;
        mServiceListener = listener;

        try {
            mBluetoothManager.registerStateChangeCallback(mBluetoothStateChangeCallback);
        } catch (RemoteException re) {
            Log.e(TAG, "Failed to register state change callback.", re);
        }
    }

    /** @hide */
    public void disconnect() {
        if (mServiceListener != null) {
            BluetoothProfile.ServiceListener listener = mServiceListener;
            mServiceListener = null;
            listener.onServiceDisconnected(mProfileId);
        }
        try {
            mBluetoothManager.unregisterStateChangeCallback(mBluetoothStateChangeCallback);
        } catch (RemoteException re) {
            Log.e(TAG, "Failed to unregister state change callback", re);
        }
    }

    @Override
    public void handleMessage(Message msg) {
        switch (msg.what) {
            case MESSAGE_SERVICE_CONNECTED:
                if (mServiceListener != null) {
                    mServiceListener.onServiceConnected(mProfileId, mProfileProxy);
                }
                break;
            case MESSAGE_SERVICE_DISCONNECTED:
                if (mServiceListener != null) {
                    mServiceListener.onServiceDisconnected(mProfileId);
                }
                break;
        }
    }
}
