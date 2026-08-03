/*
 * Copyright (C) 2014 Samsung System LSI
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

package com.android.bluetooth.map;

import static android.Manifest.permission.BLUETOOTH_CONNECT;
import static android.bluetooth.BluetoothProfile.CONNECTION_POLICY_FORBIDDEN;
import static android.bluetooth.BluetoothProfile.STATE_CONNECTED;
import static android.bluetooth.BluetoothProfile.STATE_DISCONNECTED;

import static java.util.Objects.requireNonNull;

import android.app.Activity;
import android.app.AlarmManager;
import android.app.PendingIntent;
import android.bluetooth.BluetoothDevice;
import android.bluetooth.BluetoothMap;
import android.bluetooth.BluetoothProfile;
import android.bluetooth.BluetoothUuid;
import android.bluetooth.SdpMnsRecord;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.IntentFilter.MalformedMimeTypeException;
import android.os.Handler;
import android.os.HandlerThread;
import android.os.Looper;
import android.os.Message;
import android.os.ParcelUuid;
import android.os.Parcelable;
import android.os.PowerManager;
import android.os.RemoteException;
import android.os.SystemProperties;
import android.sysprop.BluetoothProperties;
import android.telephony.TelephonyManager;
import android.util.Log;
import android.util.SparseArray;

import com.android.bluetooth.R;
import com.android.bluetooth.Util;
import com.android.bluetooth.Utils;
import com.android.bluetooth.btservice.AdapterService;
import com.android.bluetooth.profile.ConnectableProfile;
import com.android.internal.annotations.VisibleForTesting;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

public class BluetoothMapService extends ConnectableProfile {
    private static final String TAG = BluetoothMapService.class.getSimpleName();

    /**
     * To enable MAP DEBUG/VERBOSE logging - run below cmd in adb shell, and restart
     * com.android.bluetooth process. only enable DEBUG log: "setprop log.tag.BluetoothMapService
     * DEBUG"; enable both VERBOSE and DEBUG log: "setprop log.tag.BluetoothMapService VERBOSE"
     */

    /** The component names for the owned provider and activity */
    private static final String MAP_FILE_PROVIDER = MmsFileProvider.class.getCanonicalName();

    /** Intent indicating timeout for user confirmation, which is sent to BluetoothMapActivity */
    public static final String USER_CONFIRM_TIMEOUT_ACTION =
            "com.android.bluetooth.map.USER_CONFIRM_TIMEOUT";

    private static final int USER_CONFIRM_TIMEOUT_VALUE = 25000;

    static final int MSG_SERVERSESSION_CLOSE = 5000;
    static final int MSG_SESSION_ESTABLISHED = 5001;
    static final int MSG_SESSION_DISCONNECTED = 5002;
    static final int MSG_MAS_CONNECT = 5003; // Send at MAS connect, including the MAS_ID
    static final int MSG_MAS_CONNECT_CANCEL = 5004; // Send at auth. declined
    static final int MSG_ACQUIRE_WAKE_LOCK = 5005;
    static final int MSG_RELEASE_WAKE_LOCK = 5006;
    static final int MSG_MNS_SDP_SEARCH = 5007;
    static final int MSG_OBSERVER_REGISTRATION = 5008;

    private static final int START_LISTENER = 1;
    @VisibleForTesting static final int USER_TIMEOUT = 2;
    private static final int DISCONNECT_MAP = 3;
    private static final int SHUTDOWN = 4;
    @VisibleForTesting static final int UPDATE_MAS_INSTANCES = 5;

    private static final int RELEASE_WAKE_LOCK_DELAY = 10000;
    private PowerManager.WakeLock mWakeLock = null;

    static final int UPDATE_MAS_INSTANCES_ACCOUNT_ADDED = 0;
    static final int UPDATE_MAS_INSTANCES_ACCOUNT_REMOVED = 1;
    static final int UPDATE_MAS_INSTANCES_ACCOUNT_RENAMED = 2;
    static final int UPDATE_MAS_INSTANCES_ACCOUNT_DISCONNECT = 3;

    private static final int MAS_ID_SMS_MMS = 0;

    private final MapBroadcastReceiver mMapReceiver = new MapBroadcastReceiver();

    private final Handler mSessionStatusHandler;
    private final BluetoothMapAppObserver mAppObserver;
    private final boolean mSmsCapable;

    private BluetoothMnsObexClient mBluetoothMnsObexClient = null;

    // mMasInstances: A list of the active MasInstances using the MasId for the key
    private final SparseArray<BluetoothMapMasInstance> mMasInstances =
            new SparseArray<BluetoothMapMasInstance>(1);
    // mMasInstanceMap: A list of the active MasInstances using the account for the key
    private final HashMap<BluetoothMapAccountItem, BluetoothMapMasInstance> mMasInstanceMap =
            new HashMap<BluetoothMapAccountItem, BluetoothMapMasInstance>(1);

    // The remote connected device - protect access
    private BluetoothDevice mRemoteDevice = null;

    private List<BluetoothMapAccountItem> mEnabledAccounts = null;

    private int mState = BluetoothMap.STATE_DISCONNECTED;
    private final AlarmManager mAlarmManager;

    private boolean mIsWaitingAuthorization = false;
    private boolean mRemoveTimeoutMsg = false;
    private int mPermission = BluetoothDevice.ACCESS_UNKNOWN;
    private boolean mAccountChanged = false;
    private boolean mSdpSearchInitiated = false;
    private SdpMnsRecord mMnsRecord = null;

    private static final ParcelUuid[] MAP_UUIDS = {
        BluetoothUuid.MAP, BluetoothUuid.MNS,
    };

    public static boolean isEnabled() {
        return BluetoothProperties.isProfileMapServerEnabled().orElse(false);
    }

    public BluetoothMapService(AdapterService adapterService) {
        super(BluetoothProfile.MAP, adapterService);
        BluetoothMap.invalidateBluetoothGetConnectionStateCache();

        setComponentAvailable(MAP_FILE_PROVIDER, true);

        HandlerThread thread = new HandlerThread("BluetoothMapHandler");
        thread.start();
        Looper looper = thread.getLooper();
        mSessionStatusHandler = new MapServiceMessageHandler(looper);

        IntentFilter filter = new IntentFilter();
        filter.setPriority(IntentFilter.SYSTEM_HIGH_PRIORITY);
        filter.addAction(BluetoothDevice.ACTION_CONNECTION_ACCESS_REPLY);
        filter.addAction(USER_CONFIRM_TIMEOUT_ACTION);

        // We need two filters, since Type only applies to the ACTION_MESSAGE_SENT
        IntentFilter filterMessageSent = new IntentFilter();
        filterMessageSent.setPriority(IntentFilter.SYSTEM_HIGH_PRIORITY);
        filterMessageSent.addAction(BluetoothMapContentObserver.ACTION_MESSAGE_SENT);
        try {
            filterMessageSent.addDataType("message/*");
        } catch (MalformedMimeTypeException e) {
            Log.e(TAG, "Wrong mime type!!!", e);
        }
        registerReceiver(mMapReceiver, filter);
        registerReceiver(mMapReceiver, filterMessageSent);
        mAppObserver = new BluetoothMapAppObserver(this, this);

        mSmsCapable = requireNonNull(obtainSystemService(TelephonyManager.class)).isSmsCapable();
        mAlarmManager = requireNonNull(obtainSystemService(AlarmManager.class));

        mEnabledAccounts = mAppObserver.getEnabledAccountItems();
        createMasInstances(); // Uses mEnabledAccounts

        sendStartListenerMessage(-1);
    }

    private synchronized void closeService() {
        Log.d(TAG, "closeService() in");
        if (mBluetoothMnsObexClient != null) {
            mBluetoothMnsObexClient.shutdown();
            mBluetoothMnsObexClient = null;
        }
        int numMasInstances = mMasInstances.size();
        for (int i = 0; i < numMasInstances; i++) {
            mMasInstances.valueAt(i).shutdown();
        }
        mMasInstances.clear();

        mIsWaitingAuthorization = false;
        mPermission = BluetoothDevice.ACCESS_UNKNOWN;
        setState(BluetoothMap.STATE_DISCONNECTED);

        if (mWakeLock != null) {
            mWakeLock.release();
            Log.v(TAG, "CloseService(): Release Wake Lock");
            mWakeLock = null;
        }

        mRemoteDevice = null;
        // no need to invalidate cache here because setState did it above

        // Perform cleanup in Handler running on worker Thread
        mSessionStatusHandler.removeCallbacksAndMessages(null);
        Looper looper = mSessionStatusHandler.getLooper();
        if (looper != null) {
            looper.quit();
            Log.v(TAG, "Quit looper");
        }

        Log.v(TAG, "MAP Service closeService out");
    }

    /** Starts the Socket listener threads for each MAS */
    private void startSocketListeners(int masId) {
        if (masId == -1) {
            for (int i = 0, c = mMasInstances.size(); i < c; i++) {
                mMasInstances.valueAt(i).startSocketListeners();
            }
        } else {
            BluetoothMapMasInstance masInst = mMasInstances.get(masId); // returns null for -1
            if (masInst != null) {
                masInst.startSocketListeners();
            } else {
                Log.w(TAG, "startSocketListeners(): Invalid MasId: " + masId);
            }
        }
    }

    /** Start a MAS instance for SMS/MMS and each e-mail account. */
    private void startObexServerSessions() {
        Log.d(TAG, "Map Service START ObexServerSessions()");

        // Acquire the wakeLock before starting Obex transaction thread
        if (mWakeLock == null) {
            PowerManager pm = obtainSystemService(PowerManager.class);
            mWakeLock =
                    pm.newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "StartingObexMapTransaction");
            mWakeLock.setReferenceCounted(false);
            mWakeLock.acquire();
            Log.v(TAG, "startObexSessions(): Acquire Wake Lock");
        }

        if (mBluetoothMnsObexClient == null) {
            mBluetoothMnsObexClient =
                    new BluetoothMnsObexClient(
                            getAdapterService(), mRemoteDevice, mMnsRecord, mSessionStatusHandler);
        }

        boolean connected = false;
        for (int i = 0, c = mMasInstances.size(); i < c; i++) {
            try {
                if (mMasInstances
                        .valueAt(i)
                        .startObexServerSession(this, mBluetoothMnsObexClient)) {
                    connected = true;
                }
            } catch (IOException e) {
                Log.w(
                        TAG,
                        "IOException occurred while starting an obexServerSession restarting"
                                + " the listener",
                        e);
                mMasInstances.valueAt(i).restartObexServerSession();
            } catch (RemoteException e) {
                Log.w(
                        TAG,
                        "RemoteException occurred while starting an obexServerSession restarting"
                                + " the listener",
                        e);
                mMasInstances.valueAt(i).restartObexServerSession();
            }
        }
        if (connected) {
            setState(BluetoothMap.STATE_CONNECTED);
        }

        mSessionStatusHandler.removeMessages(MSG_RELEASE_WAKE_LOCK);
        mSessionStatusHandler.sendMessageDelayed(
                mSessionStatusHandler.obtainMessage(MSG_RELEASE_WAKE_LOCK),
                RELEASE_WAKE_LOCK_DELAY);

        Log.v(TAG, "startObexServerSessions() success!");
    }

    public Handler getHandler() {
        return mSessionStatusHandler;
    }

    /**
     * Restart a MAS instances.
     *
     * @param masId use -1 to stop all instances
     */
    private void stopObexServerSessions(int masId) {
        Log.d(TAG, "MAP Service STOP ObexServerSessions()");

        boolean lastMasInst = true;

        if (masId != -1) {
            for (int i = 0, c = mMasInstances.size(); i < c; i++) {
                BluetoothMapMasInstance masInst = mMasInstances.valueAt(i);
                if (masInst.getMasId() != masId && masInst.isStarted()) {
                    lastMasInst = false;
                }
            }
        } // Else just close down it all

        // Shutdown the MNS client - this must happen before MAS close
        if (mBluetoothMnsObexClient != null && lastMasInst) {
            mBluetoothMnsObexClient.shutdown();
            mBluetoothMnsObexClient = null;
        }

        BluetoothMapMasInstance masInst = mMasInstances.get(masId); // returns null for -1
        if (masInst != null) {
            masInst.restartObexServerSession();
        } else if (masId == -1) {
            for (int i = 0, c = mMasInstances.size(); i < c; i++) {
                mMasInstances.valueAt(i).restartObexServerSession();
            }
        }

        if (lastMasInst) {
            setState(BluetoothMap.STATE_DISCONNECTED);
            mPermission = BluetoothDevice.ACCESS_UNKNOWN;
            mRemoteDevice = null;
            // no need to invalidate cache here because setState did it above
            if (mAccountChanged) {
                updateMasInstances(UPDATE_MAS_INSTANCES_ACCOUNT_DISCONNECT);
            }
        }

        // Release the wake lock at disconnect
        if (mWakeLock != null && lastMasInst) {
            mSessionStatusHandler.removeMessages(MSG_ACQUIRE_WAKE_LOCK);
            mSessionStatusHandler.removeMessages(MSG_RELEASE_WAKE_LOCK);
            mWakeLock.release();
            Log.v(TAG, "stopObexServerSessions(): Release Wake Lock");
        }
    }

    private final class MapServiceMessageHandler extends Handler {
        private MapServiceMessageHandler(Looper looper) {
            super(looper);
        }

        @Override
        public void handleMessage(Message msg) {
            Log.v(TAG, "Handler(): got msg=" + msg.what);

            switch (msg.what) {
                case UPDATE_MAS_INSTANCES -> updateMasInstancesHandler();
                case START_LISTENER -> startSocketListeners(msg.arg1);
                case MSG_MAS_CONNECT -> onConnectHandler(msg.arg1);
                // TODO: We need to handle this by accepting the connection and reject at OBEX
                // level, by using ObexRejectServer - add timeout to handle clients not closing the
                // transport channel.
                case MSG_MAS_CONNECT_CANCEL -> stopObexServerSessions(-1);
                case USER_TIMEOUT -> {
                    if (!mIsWaitingAuthorization) {
                        break;
                    }
                    Intent intent = new Intent(BluetoothDevice.ACTION_CONNECTION_ACCESS_CANCEL);
                    intent.setPackage(
                            SystemProperties.get(
                                    Utils.PAIRING_UI_PROPERTY,
                                    getString(R.string.pairing_ui_package)));
                    intent.putExtra(BluetoothDevice.EXTRA_DEVICE, mRemoteDevice);
                    intent.putExtra(
                            BluetoothDevice.EXTRA_ACCESS_REQUEST_TYPE,
                            BluetoothDevice.REQUEST_TYPE_MESSAGE_ACCESS);
                    BluetoothMapService.this.sendBroadcastAsUser(
                            intent, getUser(), BLUETOOTH_CONNECT, Util.getTempBroadcastBundle());
                    cancelUserTimeoutAlarm();
                    mIsWaitingAuthorization = false;
                    stopObexServerSessions(-1);
                }
                case MSG_SERVERSESSION_CLOSE -> stopObexServerSessions(msg.arg1);
                case MSG_SESSION_ESTABLISHED -> {}
                case MSG_SESSION_DISCONNECTED -> {} // handled elsewhere
                case DISCONNECT_MAP -> {
                    BluetoothDevice device = (BluetoothDevice) msg.obj;
                    disconnectMap(device);
                }
                // Call close from this handler to avoid starting because of pending messages
                case SHUTDOWN -> closeService();
                case MSG_ACQUIRE_WAKE_LOCK -> {
                    Log.v(TAG, "Acquire Wake Lock request message");
                    if (mWakeLock == null) {
                        PowerManager pm = obtainSystemService(PowerManager.class);
                        mWakeLock =
                                pm.newWakeLock(
                                        PowerManager.PARTIAL_WAKE_LOCK,
                                        "StartingObexMapTransaction");
                        mWakeLock.setReferenceCounted(false);
                    }
                    if (!mWakeLock.isHeld()) {
                        mWakeLock.acquire();
                        Log.d(TAG, "  Acquired Wake Lock by message");
                    }
                    mSessionStatusHandler.removeMessages(MSG_RELEASE_WAKE_LOCK);
                    mSessionStatusHandler.sendMessageDelayed(
                            mSessionStatusHandler.obtainMessage(MSG_RELEASE_WAKE_LOCK),
                            RELEASE_WAKE_LOCK_DELAY);
                }
                case MSG_RELEASE_WAKE_LOCK -> {
                    Log.v(TAG, "Release Wake Lock request message");
                    if (mWakeLock != null) {
                        mWakeLock.release();
                        Log.d(TAG, "  Released Wake Lock by message");
                    }
                }
                case MSG_MNS_SDP_SEARCH -> {
                    if (mRemoteDevice != null) {
                        Log.d(TAG, "MNS SDP Initiate Search ..");
                        getAdapterService()
                                .sdpSearch(
                                        mRemoteDevice,
                                        BluetoothMnsObexClient.BLUETOOTH_UUID_OBEX_MNS);
                    } else {
                        Log.w(TAG, "remoteDevice info not available");
                    }
                }
                case MSG_OBSERVER_REGISTRATION -> {
                    Log.d(
                            TAG,
                            "ContentObserver Registration MASID: "
                                    + msg.arg1
                                    + " Enable: "
                                    + msg.arg2);
                    BluetoothMapMasInstance masInst = mMasInstances.get(msg.arg1);
                    if (masInst == null || masInst.mObserver == null) {
                        break;
                    }
                    try {
                        if (msg.arg2 == BluetoothMapAppParams.NOTIFICATION_STATUS_YES) {
                            masInst.mObserver.registerObserver();
                        } else {
                            masInst.mObserver.unregisterObserver();
                        }
                    } catch (RemoteException e) {
                        Log.e(TAG, "ContentObserverRegistration Failed: " + e);
                    }
                }
                default -> {}
            }
        }
    }

    private void onConnectHandler(int masId) {
        if (mIsWaitingAuthorization || mRemoteDevice == null || mSdpSearchInitiated) {
            return;
        }
        BluetoothMapMasInstance masInst = mMasInstances.get(masId);
        // Need to ensure we are still allowed.
        Log.d(TAG, "mPermission = " + mPermission);
        if (mPermission == BluetoothDevice.ACCESS_ALLOWED) {
            try {
                Log.v(
                        TAG,
                        "incoming connection accepted from: "
                                + mRemoteDevice
                                + " automatically as trusted device");
                if (mBluetoothMnsObexClient != null && masInst != null) {
                    masInst.startObexServerSession(this, mBluetoothMnsObexClient);
                } else {
                    startObexServerSessions();
                }
            } catch (IOException ex) {
                Log.e(TAG, "catch IOException starting obex server session", ex);
            } catch (RemoteException ex) {
                Log.e(TAG, "catch RemoteException starting obex server session", ex);
            }
        }
    }

    public int getState() {
        return mState;
    }

    public BluetoothDevice getRemoteDevice() {
        return mRemoteDevice;
    }

    private synchronized void setState(int state) {
        if (state == mState) {
            return;
        }
        Log.d(TAG, "Map state " + mState + " -> " + state);
        int prevState = mState;
        mState = state;
        getAdapterService()
                .updateProfileConnectionAdapterProperties(
                        mRemoteDevice, getProfileId(), mState, prevState);

        BluetoothMap.invalidateBluetoothGetConnectionStateCache();
        Intent intent = new Intent(BluetoothMap.ACTION_CONNECTION_STATE_CHANGED);
        intent.putExtra(BluetoothProfile.EXTRA_PREVIOUS_STATE, prevState);
        intent.putExtra(BluetoothProfile.EXTRA_STATE, mState);
        intent.putExtra(BluetoothDevice.EXTRA_DEVICE, mRemoteDevice);
        sendBroadcast(intent, BLUETOOTH_CONNECT, Util.getTempBroadcastBundle());
    }

    @Override
    public boolean connect(BluetoothDevice device) {
        Log.w(TAG, "connect() was called but not implemented");
        return false;
    }

    @Override
    public boolean disconnect(BluetoothDevice device) {
        mSessionStatusHandler.obtainMessage(DISCONNECT_MAP, 0, 0, device).sendToTarget();
        return true;
    }

    void disconnectMap(BluetoothDevice device) {
        Log.d(TAG, "disconnectMap");
        if (getRemoteDevice() != null
                && getRemoteDevice().equals(device)
                && mState == BluetoothMap.STATE_CONNECTED) {
            // Disconnect all connections and restart all MAS instances
            stopObexServerSessions(-1);
        }
    }

    List<BluetoothDevice> getConnectedDevices() {
        List<BluetoothDevice> devices = new ArrayList<>();
        synchronized (this) {
            if (mState == BluetoothMap.STATE_CONNECTED && mRemoteDevice != null) {
                devices.add(mRemoteDevice);
            }
        }
        return devices;
    }

    List<BluetoothDevice> getDevicesMatchingConnectionStates(int[] states) {
        List<BluetoothDevice> deviceList = new ArrayList<>();
        var bondedDevices = getAdapterService().getBondedDevices();
        synchronized (this) {
            for (BluetoothDevice device : bondedDevices) {
                final ParcelUuid[] featureUuids = getAdapterService().getRemoteUuids(device);
                if (!BluetoothUuid.containsAnyUuid(featureUuids, MAP_UUIDS)) {
                    continue;
                }
                int connectionState = getConnectionState(device);
                for (int state : states) {
                    if (connectionState == state) {
                        deviceList.add(device);
                    }
                }
            }
        }
        return deviceList;
    }

    /**
     * Gets the connection state of MAP with the passed in device.
     *
     * @param device is the device whose connection state we are querying
     * @return {@link BluetoothProfile#STATE_CONNECTED} if MAP is connected to this device, {@link
     *     BluetoothProfile#STATE_DISCONNECTED} otherwise
     */
    @Override
    public int getConnectionState(BluetoothDevice device) {
        synchronized (this) {
            if (getState() == BluetoothMap.STATE_CONNECTED
                    && getRemoteDevice() != null
                    && getRemoteDevice().equals(device)) {
                return STATE_CONNECTED;
            } else {
                return STATE_DISCONNECTED;
            }
        }
    }

    /**
     * Set connection policy of the profile and tries to disconnect it if connectionPolicy is {@link
     * BluetoothProfile#CONNECTION_POLICY_FORBIDDEN}
     *
     * <p>The device should already be paired. Connection policy can be one of: {@link
     * BluetoothProfile#CONNECTION_POLICY_ALLOWED}, {@link
     * BluetoothProfile#CONNECTION_POLICY_FORBIDDEN}, {@link
     * BluetoothProfile#CONNECTION_POLICY_UNKNOWN}
     *
     * @param device Paired bluetooth device
     * @param connectionPolicy is the connection policy to set to for this profile
     * @return true if connectionPolicy is set, false on error
     */
    @Override
    public boolean setConnectionPolicy(BluetoothDevice device, int connectionPolicy) {
        Log.v(TAG, "Saved connectionPolicy " + device + " = " + connectionPolicy);

        getAdapterService().setProfileConnectionPolicy(device, getProfileId(), connectionPolicy);

        if (connectionPolicy == CONNECTION_POLICY_FORBIDDEN) {
            disconnect(device);
        }
        return true;
    }

    @Override
    protected IProfileServiceBinder initBinder() {
        return new BluetoothMapServiceBinder(this);
    }

    /**
     * Call this to trigger an update of the MAS instance list. No changes will be applied unless in
     * disconnected state
     */
    void updateMasInstances(int action) {
        mSessionStatusHandler.obtainMessage(UPDATE_MAS_INSTANCES, action, 0).sendToTarget();
    }

    /**
     * Update the active MAS Instances according the difference between mEnabledDevices and the
     * current list of accounts. Will only make changes if state is disconnected.
     *
     * <p>How it works: 1) Build two lists of accounts newAccountList - all accounts from
     * mAppObserver newAccounts - accounts that have been enabled since mEnabledAccounts was last
     * updated. mEnabledAccounts - The accounts which are left 2) Stop and remove all MasInstances
     * in mEnabledAccounts 3) Add and start MAS instances for accounts on the new list. Called at: -
     * Each change in accounts - Each disconnect - before MasInstances restart.
     */
    private void updateMasInstancesHandler() {
        Log.d(TAG, "updateMasInstancesHandler() state = " + getState());

        if (getState() != BluetoothMap.STATE_DISCONNECTED) {
            mAccountChanged = true;
            return;
        }

        List<BluetoothMapAccountItem> newAccountList = mAppObserver.getEnabledAccountItems();
        List<BluetoothMapAccountItem> newAccounts = new ArrayList<>();

        for (BluetoothMapAccountItem account : newAccountList) {
            if (!mEnabledAccounts.remove(account)) {
                newAccounts.add(account);
            }
        }

        // Remove all disabled/removed accounts
        if (mEnabledAccounts.size() > 0) {
            for (BluetoothMapAccountItem account : mEnabledAccounts) {
                BluetoothMapMasInstance masInst = mMasInstanceMap.remove(account);
                Log.v(TAG, "  Removing account: " + account + " masInst = " + masInst);
                if (masInst != null) {
                    masInst.shutdown();
                    mMasInstances.remove(masInst.getMasId());
                }
            }
        }

        // Add any newly created accounts
        for (BluetoothMapAccountItem account : newAccounts) {
            Log.v(TAG, "  Adding account: " + account);
            int masId = getNextMasId();
            BluetoothMapMasInstance newInst =
                    new BluetoothMapMasInstance(getAdapterService(), this, account, masId, false);
            mMasInstances.append(masId, newInst);
            mMasInstanceMap.put(account, newInst);
            // Start the new instance
            if (getAdapterService().isEnabled()) {
                newInst.startSocketListeners();
            }
        }

        mEnabledAccounts = newAccountList;

        // The following is a large enough debug operation such that we want to guard it with an
        // isLoggable check
        if (Log.isLoggable(TAG, Log.VERBOSE)) {
            Log.v(TAG, "  Enabled accounts:");
            for (BluetoothMapAccountItem account : mEnabledAccounts) {
                Log.v(TAG, "   " + account);
            }
            Log.v(TAG, "  Active MAS instances:");
            for (int i = 0, c = mMasInstances.size(); i < c; i++) {
                BluetoothMapMasInstance masInst = mMasInstances.valueAt(i);
                Log.v(TAG, "   " + masInst);
            }
        }

        mAccountChanged = false;
    }

    /**
     * Return a free key greater than the largest key in use. If the key 255 is in use, the first
     * free masId will be returned.
     *
     * @return a free MasId
     */
    @VisibleForTesting
    int getNextMasId() {
        // Find the largest masId in use
        int largestMasId = 0;
        for (int i = 0, c = mMasInstances.size(); i < c; i++) {
            int masId = mMasInstances.keyAt(i);
            if (masId > largestMasId) {
                largestMasId = masId;
            }
        }
        if (largestMasId < 0xff) {
            return largestMasId + 1;
        }
        // If 0xff is already in use, wrap and choose the first free MasId.
        for (int i = 1; i <= 0xff; i++) {
            if (mMasInstances.get(i) == null) {
                return i;
            }
        }
        return 0xff; // This will never happen, as we only allow 10 e-mail accounts to be enabled
    }

    private void createMasInstances() {
        int masId = MAS_ID_SMS_MMS;

        if (mSmsCapable) {
            // Add the SMS/MMS instance
            BluetoothMapMasInstance smsMmsInst =
                    new BluetoothMapMasInstance(getAdapterService(), this, null, masId, true);
            mMasInstances.append(masId, smsMmsInst);
            mMasInstanceMap.put(null, smsMmsInst);
            masId++;
        }

        // get list of accounts already set to be visible through MAP
        for (BluetoothMapAccountItem account : mEnabledAccounts) {
            BluetoothMapMasInstance newInst =
                    new BluetoothMapMasInstance(getAdapterService(), this, account, masId, false);
            mMasInstances.append(masId, newInst);
            mMasInstanceMap.put(account, newInst);
            masId++;
        }
    }

    @Override
    public void cleanup() {
        Log.i(TAG, "cleanup()");

        unregisterReceiver(mMapReceiver);
        mAppObserver.shutdown();
        sendShutdownMessage();
        setComponentAvailable(MAP_FILE_PROVIDER, false);
    }

    /**
     * Called from each MAS instance when a connection is received.
     *
     * @param remoteDevice The device connecting
     * @param masInst a reference to the calling MAS instance.
     * @return true if the connection was accepted, false otherwise
     */
    public boolean onConnect(BluetoothDevice remoteDevice, BluetoothMapMasInstance masInst) {
        boolean sendIntent = false;
        boolean cancelConnection = false;

        // As this can be called from each MasInstance, we need to lock access to member variables
        synchronized (this) {
            if (mRemoteDevice == null) {
                mRemoteDevice = remoteDevice;
                if (getState() == BluetoothMap.STATE_CONNECTED) {
                    BluetoothMap.invalidateBluetoothGetConnectionStateCache();
                }

                mPermission = getAdapterService().getMessageAccessPermission(mRemoteDevice);
                if (mPermission == BluetoothDevice.ACCESS_UNKNOWN) {
                    sendIntent = true;
                    mIsWaitingAuthorization = true;
                    setUserTimeoutAlarm();
                } else if (mPermission == BluetoothDevice.ACCESS_REJECTED) {
                    cancelConnection = true;
                } else if (mPermission == BluetoothDevice.ACCESS_ALLOWED) {
                    getAdapterService()
                            .sdpSearch(
                                    mRemoteDevice, BluetoothMnsObexClient.BLUETOOTH_UUID_OBEX_MNS);
                    mSdpSearchInitiated = true;
                }
            } else if (!mRemoteDevice.equals(remoteDevice)) {
                Log.w(TAG, "Unexpected connection from a second Remote Device: " + remoteDevice);
                return false;
            } // Else second connection to same device, just continue
        }

        if (sendIntent) {
            // This will trigger Settings app's dialog.
            Intent intent = new Intent(BluetoothDevice.ACTION_CONNECTION_ACCESS_REQUEST);
            intent.setPackage(
                    SystemProperties.get(
                            Utils.PAIRING_UI_PROPERTY, getString(R.string.pairing_ui_package)));
            intent.putExtra(
                    BluetoothDevice.EXTRA_ACCESS_REQUEST_TYPE,
                    BluetoothDevice.REQUEST_TYPE_MESSAGE_ACCESS);
            intent.putExtra(BluetoothDevice.EXTRA_DEVICE, mRemoteDevice);
            sendOrderedBroadcastAsUser(
                    intent,
                    getUser(),
                    BLUETOOTH_CONNECT,
                    android.app.AppOpsManager.OP_NONE,
                    Util.getTempBroadcastBundle(),
                    null,
                    null,
                    Activity.RESULT_OK,
                    null,
                    null);

            Log.v(TAG, "Waiting for authorization for connection from: " + mRemoteDevice);
            // Queue USER_TIMEOUT to disconnect MAP OBEX session. If user doesn't
            // accept or reject authorization request
        } else if (cancelConnection) {
            sendConnectCancelMessage();
        } else if (mPermission == BluetoothDevice.ACCESS_ALLOWED) {
            // Signal to the service that we have a incoming connection.
            sendConnectMessage(masInst.getMasId());
        }
        return true;
    }

    private void setUserTimeoutAlarm() {
        Log.d(TAG, "SetUserTimeOutAlarm()");
        mRemoveTimeoutMsg = true;
        Intent timeoutIntent = new Intent(USER_CONFIRM_TIMEOUT_ACTION);
        PendingIntent pIntent =
                PendingIntent.getBroadcast(this, 0, timeoutIntent, PendingIntent.FLAG_IMMUTABLE);
        mAlarmManager.set(
                AlarmManager.RTC_WAKEUP,
                System.currentTimeMillis() + USER_CONFIRM_TIMEOUT_VALUE,
                pIntent);
    }

    private void cancelUserTimeoutAlarm() {
        Log.d(TAG, "cancelUserTimeOutAlarm()");
        Intent timeoutIntent = new Intent(USER_CONFIRM_TIMEOUT_ACTION);
        PendingIntent pIntent =
                PendingIntent.getBroadcast(this, 0, timeoutIntent, PendingIntent.FLAG_IMMUTABLE);
        pIntent.cancel();

        AlarmManager alarmManager = obtainSystemService(AlarmManager.class);
        alarmManager.cancel(pIntent);
        mRemoveTimeoutMsg = false;
    }

    /**
     * Start the incoming connection listeners for a MAS ID
     *
     * @param masId the MasID to start. Use -1 to start all listeners.
     */
    void sendStartListenerMessage(int masId) {
        if (!mSessionStatusHandler.hasMessages(START_LISTENER)) {
            Message msg = mSessionStatusHandler.obtainMessage(START_LISTENER, masId, 0);
            /* We add a small delay here to ensure the call returns true before this message is
             * handled. It seems wrong to add a delay, but the alternative is to build a lock
             * system to handle synchronization, which isn't nice either... */
            mSessionStatusHandler.sendMessageDelayed(msg, 20);
        } else {
            Log.w(TAG, "mSessionStatusHandler START_LISTENER message already in Queue");
        }
    }

    private void sendConnectMessage(int masId) {
        Message msg = mSessionStatusHandler.obtainMessage(MSG_MAS_CONNECT, masId, 0);
        /* We add a small delay here to ensure onConnect returns true before this message is
         * handled. It seems wrong, but the alternative is to store a reference to the
         * connection in this message, which isn't nice either... */
        mSessionStatusHandler.sendMessageDelayed(msg, 20);
    }

    @VisibleForTesting
    void sendConnectTimeoutMessage() {
        Log.d(TAG, "sendConnectTimeoutMessage()");
        mSessionStatusHandler.obtainMessage(USER_TIMEOUT).sendToTarget();
    }

    @VisibleForTesting
    void sendConnectCancelMessage() {
        mSessionStatusHandler.obtainMessage(MSG_MAS_CONNECT_CANCEL).sendToTarget();
    }

    private void sendShutdownMessage() {
        // We should close the Setting's permission dialog if one is open.
        if (mRemoveTimeoutMsg) {
            sendConnectTimeoutMessage();
        }
        if (mSessionStatusHandler.hasMessages(SHUTDOWN)) {
            Log.w(TAG, "mSessionStatusHandler shutdown message already in Queue");
            return;
        }
        mSessionStatusHandler.removeCallbacksAndMessages(null);
        // Request release of all resources
        Message msg = mSessionStatusHandler.obtainMessage(SHUTDOWN);
        if (!mSessionStatusHandler.sendMessage(msg)) {
            Log.w(TAG, "mSessionStatusHandler shutdown message could not be sent");
        }
    }

    private class MapBroadcastReceiver extends BroadcastReceiver {
        @Override
        public void onReceive(Context context, Intent intent) {
            String action = intent.getAction();
            Log.d(TAG, "onReceive: " + action);
            if (action.equals(USER_CONFIRM_TIMEOUT_ACTION)) {
                Log.d(TAG, "USER_CONFIRM_TIMEOUT ACTION Received.");
                sendConnectTimeoutMessage();
            } else if (action.equals(BluetoothDevice.ACTION_CONNECTION_ACCESS_REPLY)) {
                int requestType =
                        intent.getIntExtra(
                                BluetoothDevice.EXTRA_ACCESS_REQUEST_TYPE,
                                BluetoothDevice.REQUEST_TYPE_PHONEBOOK_ACCESS);

                Log.d(
                        TAG,
                        "Received ACTION_CONNECTION_ACCESS_REPLY:"
                                + requestType
                                + "isWaitingAuthorization:"
                                + mIsWaitingAuthorization);
                if ((!mIsWaitingAuthorization)
                        || (requestType != BluetoothDevice.REQUEST_TYPE_MESSAGE_ACCESS)) {
                    return;
                }
                BluetoothDevice remoteDevice = mRemoteDevice;
                if (remoteDevice == null) {
                    return;
                }

                mIsWaitingAuthorization = false;
                if (mRemoveTimeoutMsg) {
                    mSessionStatusHandler.removeMessages(USER_TIMEOUT);
                    cancelUserTimeoutAlarm();
                    setState(BluetoothMap.STATE_DISCONNECTED);
                }

                if (intent.getIntExtra(
                                BluetoothDevice.EXTRA_CONNECTION_ACCESS_RESULT,
                                BluetoothDevice.CONNECTION_ACCESS_NO)
                        == BluetoothDevice.CONNECTION_ACCESS_YES) {
                    // Bluetooth connection accepted by user
                    mPermission = BluetoothDevice.ACCESS_ALLOWED;
                    if (intent.getBooleanExtra(BluetoothDevice.EXTRA_ALWAYS_ALLOWED, false)) {
                        boolean result =
                                remoteDevice.setMessageAccessPermission(
                                        BluetoothDevice.ACCESS_ALLOWED);
                        Log.d(TAG, "setMessageAccessPermission(ACCESS_ALLOWED) result=" + result);
                    }

                    getAdapterService()
                            .sdpSearch(
                                    remoteDevice, BluetoothMnsObexClient.BLUETOOTH_UUID_OBEX_MNS);
                    mSdpSearchInitiated = true;
                } else {
                    // Auth. declined by user, serverSession should not be running, but
                    // call stop anyway to restart listener.
                    mPermission = BluetoothDevice.ACCESS_REJECTED;
                    if (intent.getBooleanExtra(BluetoothDevice.EXTRA_ALWAYS_ALLOWED, false)) {
                        boolean result =
                                remoteDevice.setMessageAccessPermission(
                                        BluetoothDevice.ACCESS_REJECTED);
                        Log.d(TAG, "setMessageAccessPermission(ACCESS_REJECTED) result=" + result);
                    }
                    sendConnectCancelMessage();
                }
            } else if (action.equals(BluetoothMapContentObserver.ACTION_MESSAGE_SENT)) {
                int result = getResultCode();
                boolean handled = false;
                if (mSmsCapable && mMasInstances != null) {
                    BluetoothMapMasInstance masInst = mMasInstances.get(MAS_ID_SMS_MMS);
                    if (masInst != null) {
                        intent.putExtra(
                                BluetoothMapContentObserver.EXTRA_MESSAGE_SENT_RESULT, result);
                        handled = masInst.handleSmsSendIntent(context, intent);
                    }
                }
                if (!handled) {
                    // Move the SMS to the correct folder.
                    BluetoothMapContentObserver.actionMessageSentDisconnected(
                            context, intent, result);
                }
            }
        }
    }

    public void aclDisconnected(BluetoothDevice device) {
        mSessionStatusHandler.post(() -> handleAclDisconnected(device));
    }

    private void handleAclDisconnected(BluetoothDevice device) {
        if (!mIsWaitingAuthorization) {
            return;
        }
        if (mRemoteDevice == null || device == null) {
            Log.e(TAG, "Unexpected error!");
            return;
        }

        Log.v(TAG, "ACL disconnected for " + device);

        if (mRemoteDevice.equals(device)) {
            // Send any pending timeout now, since ACL got disconnected
            mSessionStatusHandler.removeMessages(USER_TIMEOUT);
            mSessionStatusHandler.obtainMessage(USER_TIMEOUT).sendToTarget();
        }
    }

    public void receiveSdpSearchRecord(int status, Parcelable record, ParcelUuid uuid) {
        mSessionStatusHandler.post(() -> handleSdpSearchRecordReceived(status, record, uuid));
    }

    private void handleSdpSearchRecordReceived(int status, Parcelable record, ParcelUuid uuid) {
        Log.d(TAG, "Received ACTION_SDP_RECORD.");
        Log.v(TAG, "Received UUID: " + uuid.toString());
        Log.v(TAG, "expected UUID: " + BluetoothMnsObexClient.BLUETOOTH_UUID_OBEX_MNS.toString());
        if (uuid.equals(BluetoothMnsObexClient.BLUETOOTH_UUID_OBEX_MNS)) {
            mMnsRecord = (SdpMnsRecord) record;
            Log.v(TAG, " -> MNS Record:" + mMnsRecord);
            Log.v(TAG, " -> status: " + status);
            if (mBluetoothMnsObexClient != null && !mSdpSearchInitiated) {
                mBluetoothMnsObexClient.setMnsRecord(mMnsRecord);
            }
            if (status != -1 && mMnsRecord != null) {
                for (int i = 0, c = mMasInstances.size(); i < c; i++) {
                    mMasInstances
                            .valueAt(i)
                            .setRemoteFeatureMask(mMnsRecord.getSupportedFeatures());
                }
            }
            if (mSdpSearchInitiated) {
                mSdpSearchInitiated = false; // done searching
                sendConnectMessage(-1); // -1 indicates all MAS instances
            }
        }
    }

    @Override
    public void dump(StringBuilder sb) {
        super.dump(sb);
        println(sb, "mRemoteDevice: " + mRemoteDevice);
        println(sb, "mState: " + mState);
        println(sb, "mAppObserver: " + mAppObserver);
        println(sb, "mIsWaitingAuthorization: " + mIsWaitingAuthorization);
        println(sb, "mRemoveTimeoutMsg: " + mRemoveTimeoutMsg);
        println(sb, "mPermission: " + mPermission);
        println(sb, "mAccountChanged: " + mAccountChanged);
        println(sb, "mBluetoothMnsObexClient: " + mBluetoothMnsObexClient);
        println(sb, "mMasInstanceMap:");
        for (BluetoothMapAccountItem key : mMasInstanceMap.keySet()) {
            println(sb, "  " + key + " : " + mMasInstanceMap.get(key));
        }
        println(sb, "mEnabledAccounts:");
        for (BluetoothMapAccountItem account : mEnabledAccounts) {
            println(sb, "  " + account);
        }
    }
}
