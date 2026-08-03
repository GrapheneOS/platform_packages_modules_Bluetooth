/*
 * Copyright (C) 2024 The Android Open Source Project
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

package com.android.bluetooth.pbap;

import static android.Manifest.permission.BLUETOOTH_CONNECT;
import static android.bluetooth.BluetoothDevice.ACCESS_ALLOWED;
import static android.bluetooth.BluetoothDevice.ACCESS_REJECTED;
import static android.bluetooth.BluetoothProfile.CONNECTION_POLICY_ALLOWED;
import static android.bluetooth.BluetoothProfile.CONNECTION_POLICY_FORBIDDEN;
import static android.bluetooth.BluetoothProfile.STATE_DISCONNECTED;

import static com.android.bluetooth.Utils.joinUninterruptibly;

import static java.util.Objects.requireNonNull;

import android.app.Activity;
import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.bluetooth.BluetoothDevice;
import android.bluetooth.BluetoothProfile;
import android.bluetooth.BluetoothSocket;
import android.bluetooth.BluetoothUtils;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.database.ContentObserver;
import android.os.Handler;
import android.os.HandlerThread;
import android.os.Looper;
import android.os.Message;
import android.os.PowerManager;
import android.os.SystemProperties;
import android.os.UserHandle;
import android.os.UserManager;
import android.sysprop.BluetoothProperties;
import android.telephony.TelephonyManager;
import android.util.Log;

import com.android.bluetooth.R;
import com.android.bluetooth.Util;
import com.android.bluetooth.Utils;
import com.android.bluetooth.btservice.AdapterService;
import com.android.bluetooth.btservice.InteropUtil;
import com.android.bluetooth.flags.Flags;
import com.android.bluetooth.obex.IObexConnectionHandler;
import com.android.bluetooth.obex.ObexServerSockets;
import com.android.bluetooth.profile.ConnectableProfile;
import com.android.bluetooth.util.DevicePolicyUtils;
import com.android.internal.annotations.VisibleForTesting;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class BluetoothPbapService extends ConnectableProfile implements IObexConnectionHandler {
    private static final String TAG = BluetoothPbapService.class.getSimpleName();

    /** The component name of the owned BluetoothPbapActivity */
    private static final String PBAP_ACTIVITY = BluetoothPbapActivity.class.getCanonicalName();

    /** Intent indicating incoming obex authentication request which is from PCE(Carkit) */
    static final String AUTH_CHALL_ACTION = "com.android.bluetooth.pbap.authchall";

    /**
     * Intent indicating obex session key input complete by user which is sent from
     * BluetoothPbapActivity
     */
    static final String AUTH_RESPONSE_ACTION = "com.android.bluetooth.pbap.authresponse";

    /**
     * Intent indicating user canceled obex authentication session key input which is sent from
     * BluetoothPbapActivity
     */
    static final String AUTH_CANCELLED_ACTION = "com.android.bluetooth.pbap.authcancelled";

    /** Intent indicating timeout for user confirmation, which is sent to BluetoothPbapActivity */
    static final String USER_CONFIRM_TIMEOUT_ACTION =
            "com.android.bluetooth.pbap.userconfirmtimeout";

    /** Intent Extra name indicating session key which is sent from BluetoothPbapActivity */
    static final String EXTRA_SESSION_KEY = "com.android.bluetooth.pbap.sessionkey";

    static final String EXTRA_DEVICE = "com.android.bluetooth.pbap.device";

    static final int MSG_ACQUIRE_WAKE_LOCK = 5004;
    private static final int MSG_RELEASE_WAKE_LOCK = 5005;
    static final int MSG_STATE_MACHINE_DONE = 5006;

    private static final int START_LISTENER = 1;
    static final int USER_TIMEOUT = 2;
    private static final int SHUTDOWN = 3;
    static final int LOAD_CONTACTS = 4;
    static final int CONTACTS_LOADED = 5;
    private static final int CHECK_SECONDARY_VERSION_COUNTER = 6;
    static final int ROLLOVER_COUNTERS = 7;
    private static final int GET_LOCAL_TELEPHONY_DETAILS = 8;
    private static final int HANDLE_VERSION_UPDATE_NOTIFICATION = 9;
    private static final int HANDLE_ACCEPT_FAILED = 10;

    static final int USER_CONFIRM_TIMEOUT_VALUE = 30000;
    private static final int RELEASE_WAKE_LOCK_DELAY_MS = 10000;

    private static final int SDP_PBAP_SERVER_VERSION_1_2 = 0x0102;
    // PBAP v1.2.3, Sec. 7.1.2: local phonebook and favorites
    private static final int SDP_PBAP_SUPPORTED_REPOSITORIES_WITHOUT_SIM = 0x0009;
    private static final int SDP_PBAP_SUPPORTED_REPOSITORIES_WITH_SIM = 0x000B;
    private static final int SDP_PBAP_SUPPORTED_FEATURES = 0x021F;

    /* PBAP will use Bluetooth notification ID from 1000000 (included) to 2000000 (excluded).
    The notification ID should be unique in Bluetooth package. */
    private static final int PBAP_NOTIFICATION_ID_START = 1000000;
    private static final int PBAP_NOTIFICATION_ID_END = 2000000;
    private static final int VERSION_UPDATE_NOTIFICATION_DELAY_MS = 500;

    // package and class name to which we send intent to check phone book access permission
    private static final String ACCESS_AUTHORITY_PACKAGE = "com.android.settings";
    private static final String ACCESS_AUTHORITY_CLASS =
            "com.android.settings.bluetooth.BluetoothPermissionRequest";

    private static final String PBAP_NOTIFICATION_ID = "pbap_notification";
    private static final String PBAP_NOTIFICATION_NAME = "BT_PBAP_ADVANCE_SUPPORT";
    private static final int PBAP_ADV_VERSION = 0x0102;

    @VisibleForTesting
    final Map<BluetoothDevice, PbapStateMachine> mPbapStateMachineMap = new HashMap<>();

    private final BluetoothPbapContentObserver mContactChangeObserver =
            new BluetoothPbapContentObserver();

    private final NotificationManager mNotificationManager;
    private final PbapHandler mSessionStatusHandler;
    private final HandlerThread mHandlerThread;
    private final Looper mLooper;
    private final boolean mIsPseDynamicVersionUpgradeEnabled;

    private static String sLocalPhoneNum;
    private static String sLocalPhoneName;

    private PowerManager.WakeLock mWakeLock = null;
    private ObexServerSockets mServerSockets = null;
    private int mSdpHandle = -1;
    private int mNextNotificationId = PBAP_NOTIFICATION_ID_START;

    private Thread mThreadLoadContacts;
    private boolean mContactsLoaded = false;

    private Thread mThreadUpdateSecVersionCounter;

    public BluetoothPbapService(
            AdapterService adapterService, NotificationManager notificationManager) {
        this(requireNonNull(adapterService), notificationManager, null);
    }

    @VisibleForTesting
    BluetoothPbapService(
            AdapterService adapterService, NotificationManager notificationManager, Looper looper) {
        super(BluetoothProfile.PBAP, adapterService);
        mNotificationManager = requireNonNull(notificationManager);

        IntentFilter userFilter = new IntentFilter();
        userFilter.setPriority(IntentFilter.SYSTEM_HIGH_PRIORITY);
        userFilter.addAction(Intent.ACTION_USER_SWITCHED);
        userFilter.addAction(Intent.ACTION_USER_UNLOCKED);

        registerReceiver(mUserChangeReceiver, userFilter);

        // Enable owned Activity component
        setComponentAvailable(PBAP_ACTIVITY, true);

        if (looper == null) {
            mHandlerThread = new HandlerThread("PbapHandlerThread");
            mHandlerThread.start();
            mLooper = mHandlerThread.getLooper();
        } else {
            mHandlerThread = null;
            mLooper = looper;
        }
        mSessionStatusHandler = new PbapHandler(mLooper);
        IntentFilter filter = new IntentFilter();
        filter.setPriority(IntentFilter.SYSTEM_HIGH_PRIORITY);
        filter.addAction(BluetoothDevice.ACTION_CONNECTION_ACCESS_REPLY);
        filter.addAction(AUTH_RESPONSE_ACTION);
        filter.addAction(AUTH_CANCELLED_ACTION);
        BluetoothPbapConfig.init(this);
        registerReceiver(mPbapReceiver, filter);
        getAdapterService()
                .getContentResolver()
                .registerContentObserver(
                        DevicePolicyUtils.getEnterprisePhoneUri(getAdapterService()),
                        false,
                        mContactChangeObserver);

        mSessionStatusHandler.sendEmptyMessage(GET_LOCAL_TELEPHONY_DETAILS);
        mSessionStatusHandler.sendEmptyMessage(START_LISTENER);

        mIsPseDynamicVersionUpgradeEnabled =
                getAdapterService().pbapPseDynamicVersionUpgradeIsEnabled();
        Log.d(TAG, "mIsPseDynamicVersionUpgradeEnabled: " + mIsPseDynamicVersionUpgradeEnabled);
    }

    public static boolean isEnabled() {
        return BluetoothProperties.isProfilePbapServerEnabled().orElse(false);
    }

    public static boolean isSimEnabled() {
        return BluetoothProperties.isProfilePbapSimEnabled().orElse(false);
    }

    private class BluetoothPbapContentObserver extends ContentObserver {
        BluetoothPbapContentObserver() {
            super(new Handler());
        }

        @Override
        public void onChange(boolean selfChange) {
            Log.d(TAG, " onChange on contact uri ");
            sendUpdateRequest();
        }
    }

    private void sendUpdateRequest() {
        if (mContactsLoaded) {
            if (!mSessionStatusHandler.hasMessages(CHECK_SECONDARY_VERSION_COUNTER)) {
                mSessionStatusHandler.sendMessage(
                        mSessionStatusHandler.obtainMessage(CHECK_SECONDARY_VERSION_COUNTER));
            }
        }
    }

    private void parseIntent(final Intent intent) {
        String action = intent.getAction();
        Log.d(TAG, "action: " + action);
        if (BluetoothDevice.ACTION_CONNECTION_ACCESS_REPLY.equals(action)) {
            int requestType =
                    intent.getIntExtra(
                            BluetoothDevice.EXTRA_ACCESS_REQUEST_TYPE,
                            BluetoothDevice.REQUEST_TYPE_PHONEBOOK_ACCESS);
            if (requestType != BluetoothDevice.REQUEST_TYPE_PHONEBOOK_ACCESS) {
                return;
            }

            BluetoothDevice device = intent.getParcelableExtra(BluetoothDevice.EXTRA_DEVICE);
            synchronized (mPbapStateMachineMap) {
                PbapStateMachine sm = mPbapStateMachineMap.get(device);
                if (sm == null) {
                    Log.w(TAG, "device not connected! device=" + device);
                    return;
                }
                mSessionStatusHandler.removeMessages(USER_TIMEOUT, sm);
                int access =
                        intent.getIntExtra(
                                BluetoothDevice.EXTRA_CONNECTION_ACCESS_RESULT,
                                BluetoothDevice.CONNECTION_ACCESS_NO);
                boolean savePreference =
                        intent.getBooleanExtra(BluetoothDevice.EXTRA_ALWAYS_ALLOWED, false);

                if (access == BluetoothDevice.CONNECTION_ACCESS_YES) {
                    if (savePreference) {
                        getAdapterService().setPhonebookAccessPermission(device, ACCESS_ALLOWED);
                        Log.v(TAG, "setPhonebookAccessPermission(ACCESS_ALLOWED)");
                    }
                    sm.sendMessage(PbapStateMachine.AUTHORIZED);
                } else {
                    if (savePreference) {
                        getAdapterService().setPhonebookAccessPermission(device, ACCESS_REJECTED);
                        Log.v(TAG, "setPhonebookAccessPermission(ACCESS_REJECTED)");
                    }
                    sm.sendMessage(PbapStateMachine.REJECTED);
                }
            }
        } else if (AUTH_RESPONSE_ACTION.equals(action)) {
            String sessionKey = intent.getStringExtra(EXTRA_SESSION_KEY);
            BluetoothDevice device = intent.getParcelableExtra(EXTRA_DEVICE);
            synchronized (mPbapStateMachineMap) {
                PbapStateMachine sm = mPbapStateMachineMap.get(device);
                if (sm == null) {
                    return;
                }
                sm.sendMessage(sm.obtainMessage(PbapStateMachine.AUTH_KEY_INPUT, sessionKey));
            }
        } else if (AUTH_CANCELLED_ACTION.equals(action)) {
            BluetoothDevice device = intent.getParcelableExtra(EXTRA_DEVICE);
            synchronized (mPbapStateMachineMap) {
                PbapStateMachine sm = mPbapStateMachineMap.get(device);
                if (sm == null) {
                    return;
                }
                sm.sendMessage(PbapStateMachine.AUTH_CANCELLED);
            }
        } else {
            Log.w(TAG, "Unhandled intent action: " + action);
        }
    }

    @Override
    public void handleBondStateChanged(BluetoothDevice device, int fromState, int toState) {
        if (toState == BluetoothDevice.BOND_BONDED && mIsPseDynamicVersionUpgradeEnabled) {
            mSessionStatusHandler.sendMessageDelayed(
                    mSessionStatusHandler.obtainMessage(HANDLE_VERSION_UPDATE_NOTIFICATION, device),
                    VERSION_UPDATE_NOTIFICATION_DELAY_MS);
        }
    }

    private final BroadcastReceiver mUserChangeReceiver =
            new BroadcastReceiver() {
                @Override
                public void onReceive(Context context, Intent intent) {
                    final String action = intent.getAction();
                    // EXTRA_USER_HANDLE is sent for both ACTION_USER_SWITCHED and
                    // ACTION_USER_UNLOCKED (even if the documentation doesn't mention it)
                    final int userId =
                            intent.getIntExtra(
                                    Intent.EXTRA_USER_HANDLE,
                                    BluetoothUtils.USER_HANDLE_NULL.getIdentifier());
                    if (userId == BluetoothUtils.USER_HANDLE_NULL.getIdentifier()) {
                        Log.e(TAG, "userChangeReceiver received an invalid EXTRA_USER_HANDLE");
                        return;
                    }
                    Log.d(TAG, "Got " + action + " to userId " + userId);
                    UserManager userManager = obtainSystemService(UserManager.class);
                    if (userManager.isUserUnlocked(UserHandle.of(userId))) {
                        sendUpdateRequest();
                    }
                }
            };

    @VisibleForTesting
    BroadcastReceiver mPbapReceiver =
            new BroadcastReceiver() {
                @Override
                public void onReceive(Context context, Intent intent) {
                    parseIntent(intent);
                }
            };

    private void closeService() {
        Log.v(TAG, "Pbap Service closeService");

        BluetoothPbapUtils.savePbapParams(this);

        if (mWakeLock != null) {
            mWakeLock.release();
            mWakeLock = null;
        }

        cleanUpServerSocket();

        mSessionStatusHandler.removeCallbacksAndMessages(null);
    }

    private void cleanUpServerSocket() {
        // Step 1, 2: clean up active server session and connection socket
        synchronized (mPbapStateMachineMap) {
            for (PbapStateMachine stateMachine : mPbapStateMachineMap.values()) {
                stateMachine.sendMessage(PbapStateMachine.DISCONNECT);
            }
        }
        // Step 3: clean up SDP record
        cleanUpSdpRecord();
        // Step 4: clean up existing server sockets
        if (mServerSockets != null) {
            mServerSockets.shutdown(false);
            mServerSockets = null;
        }
    }

    private void createSdpRecord() {
        if (mSdpHandle > -1) {
            Log.w(TAG, "createSdpRecord, SDP record already created");
            return;
        }

        int pbapSupportedRepositories =
                isSimEnabled()
                        ? SDP_PBAP_SUPPORTED_REPOSITORIES_WITH_SIM
                        : SDP_PBAP_SUPPORTED_REPOSITORIES_WITHOUT_SIM;

        final var nativeInterface = getAdapterService().getSdpManagerNativeInterface();
        if (nativeInterface.isEmpty()) {
            Log.e(TAG, "SdpManagerNativeInterface is not available");
            return;
        }

        mSdpHandle =
                nativeInterface
                        .get()
                        .createPbapPseRecord(
                                "OBEX Phonebook Access Server",
                                mServerSockets.getRfcommChannel(),
                                mServerSockets.getL2capPsm(),
                                SDP_PBAP_SERVER_VERSION_1_2,
                                pbapSupportedRepositories,
                                SDP_PBAP_SUPPORTED_FEATURES);

        Log.d(TAG, "created Sdp record, mSdpHandle=" + mSdpHandle);
    }

    private void cleanUpSdpRecord() {
        if (mSdpHandle < 0) {
            Log.w(TAG, "cleanUpSdpRecord, SDP record never created");
            return;
        }
        int sdpHandle = mSdpHandle;
        mSdpHandle = -1;
        final var nativeInterface = getAdapterService().getSdpManagerNativeInterface();
        Log.d(TAG, "cleanUpSdpRecord, mSdpHandle=" + sdpHandle);
        if (nativeInterface.isEmpty()) {
            Log.e(TAG, "SdpManagerNativeInterface is not available");
        } else if (!nativeInterface.get().removeSdpRecord(sdpHandle)) {
            Log.w(TAG, "cleanUpSdpRecord, removeSdpRecord failed, sdpHandle=" + sdpHandle);
        }
    }

    /*Creates Notification for PBAP version upgrade */
    protected void createNotification() {
        Log.v(TAG, "Create PBAP Notification for Upgrade");
        // create Notification channel.
        NotificationChannel mChannel =
                new NotificationChannel(
                        PBAP_NOTIFICATION_ID,
                        PBAP_NOTIFICATION_NAME,
                        NotificationManager.IMPORTANCE_DEFAULT);
        mNotificationManager.createNotificationChannel(mChannel);
        // create notification
        String title = getString(R.string.phonebook_advance_feature_support);
        String contentText = getString(R.string.repair_for_adv_phonebook_feature);
        int notificationId = android.R.drawable.stat_sys_data_bluetooth;
        Notification notification =
                new Notification.Builder(this, PBAP_NOTIFICATION_ID)
                        .setContentTitle(title)
                        .setContentText(contentText)
                        .setSmallIcon(notificationId)
                        .setAutoCancel(true)
                        .build();
        mNotificationManager.notify(notificationId, notification);
    }

    /* Checks if notification for Version Upgrade is required */
    protected void handleNotificationTask(BluetoothDevice remoteDevice) {
        int pce_version = getAdapterService().getRemotePbapPceVersion(remoteDevice.getAddress());
        Log.d(TAG, "pce_version: " + pce_version);

        var feature = InteropUtil.InteropFeature.INTEROP_ADV_PBAP_VER_1_2;
        var matched = getAdapterService().interopMatchDevice(feature, remoteDevice);
        Log.d(TAG, "INTEROP_ADV_PBAP_VER_1_2: matched=" + matched);

        if (pce_version == PBAP_ADV_VERSION && !matched) {
            Log.d(TAG, "Remote Supports PBAP 1.2. Notify user");
            createNotification();
        } else {
            Log.d(TAG, "Notification Not Required.");
            mNotificationManager.cancel(android.R.drawable.stat_sys_data_bluetooth);
        }
    }

    private class PbapHandler extends Handler {
        private PbapHandler(Looper looper) {
            super(looper);
        }

        @Override
        public void handleMessage(Message msg) {
            Log.v(TAG, "Handler(): got msg=" + msg.what);

            switch (msg.what) {
                case START_LISTENER -> {
                    mServerSockets =
                            ObexServerSockets.create(
                                    getAdapterService(), BluetoothPbapService.this);
                    if (mServerSockets == null) {
                        Log.w(TAG, "ObexServerSockets.create() returned null");
                        break;
                    }
                    createSdpRecord();
                    // fetch Pbap Params to check if significant change has happened to Database
                    BluetoothPbapUtils.fetchPbapParams(BluetoothPbapService.this);
                }
                case USER_TIMEOUT -> {
                    Intent intent = new Intent(BluetoothDevice.ACTION_CONNECTION_ACCESS_CANCEL);
                    intent.setPackage(
                            SystemProperties.get(
                                    Utils.PAIRING_UI_PROPERTY,
                                    getString(R.string.pairing_ui_package)));
                    PbapStateMachine stateMachine = (PbapStateMachine) msg.obj;
                    intent.putExtra(BluetoothDevice.EXTRA_DEVICE, stateMachine.getRemoteDevice());
                    intent.putExtra(
                            BluetoothDevice.EXTRA_ACCESS_REQUEST_TYPE,
                            BluetoothDevice.REQUEST_TYPE_PHONEBOOK_ACCESS);
                    BluetoothPbapService.this.sendBroadcastAsUser(
                            intent, getUser(), BLUETOOTH_CONNECT, Util.getTempBroadcastBundle());
                    stateMachine.sendMessage(PbapStateMachine.REJECTED);
                }
                case MSG_ACQUIRE_WAKE_LOCK -> {
                    if (mWakeLock == null) {
                        PowerManager pm = obtainSystemService(PowerManager.class);
                        mWakeLock =
                                pm.newWakeLock(
                                        PowerManager.PARTIAL_WAKE_LOCK,
                                        "StartingObexPbapTransaction");
                        mWakeLock.setReferenceCounted(false);
                        mWakeLock.acquire();
                        Log.w(TAG, "Acquire Wake Lock");
                    }
                    mSessionStatusHandler.removeMessages(MSG_RELEASE_WAKE_LOCK);
                    mSessionStatusHandler.sendMessageDelayed(
                            mSessionStatusHandler.obtainMessage(MSG_RELEASE_WAKE_LOCK),
                            RELEASE_WAKE_LOCK_DELAY_MS);
                }
                case MSG_RELEASE_WAKE_LOCK -> {
                    if (mWakeLock != null) {
                        mWakeLock.release();
                        mWakeLock = null;
                    }
                }
                case SHUTDOWN -> closeService();
                case LOAD_CONTACTS -> loadAllContacts();
                case CONTACTS_LOADED -> mContactsLoaded = true;
                case CHECK_SECONDARY_VERSION_COUNTER -> updateSecondaryVersion();
                case ROLLOVER_COUNTERS -> BluetoothPbapUtils.rolloverCounters();
                case MSG_STATE_MACHINE_DONE -> {
                    PbapStateMachine sm = (PbapStateMachine) msg.obj;
                    BluetoothDevice remoteDevice = sm.getRemoteDevice();
                    sm.quitNow();
                    synchronized (mPbapStateMachineMap) {
                        mPbapStateMachineMap.remove(remoteDevice);
                    }
                }
                case GET_LOCAL_TELEPHONY_DETAILS -> getLocalTelephonyDetails();
                case HANDLE_VERSION_UPDATE_NOTIFICATION -> {
                    BluetoothDevice remoteDev = (BluetoothDevice) msg.obj;

                    handleNotificationTask(remoteDev);
                }
                case HANDLE_ACCEPT_FAILED -> handleAcceptFailed();
                default -> {}
            }
        }
    }

    /**
     * Get the current connection state of PBAP with the passed in device
     *
     * @param device is the device whose connection state to PBAP we are trying to get
     * @return current connection state, one of {@link BluetoothProfile#STATE_DISCONNECTED}, {@link
     *     BluetoothProfile#STATE_CONNECTING}, {@link BluetoothProfile#STATE_CONNECTED}, or {@link
     *     BluetoothProfile#STATE_DISCONNECTING}
     */
    @Override
    public int getConnectionState(BluetoothDevice device) {
        synchronized (mPbapStateMachineMap) {
            PbapStateMachine sm = mPbapStateMachineMap.get(device);
            if (sm == null) {
                return STATE_DISCONNECTED;
            }
            return sm.getConnectionState();
        }
    }

    List<BluetoothDevice> getConnectedDevices() {
        synchronized (mPbapStateMachineMap) {
            return new ArrayList<>(mPbapStateMachineMap.keySet());
        }
    }

    List<BluetoothDevice> getDevicesMatchingConnectionStates(int[] states) {
        List<BluetoothDevice> devices = new ArrayList<>();
        if (states == null) {
            return devices;
        }
        synchronized (mPbapStateMachineMap) {
            for (int state : states) {
                for (BluetoothDevice device : mPbapStateMachineMap.keySet()) {
                    if (state == mPbapStateMachineMap.get(device).getConnectionState()) {
                        devices.add(device);
                    }
                }
            }
        }
        return devices;
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
        Log.d(TAG, "Saved connectionPolicy " + device + " = " + connectionPolicy);

        getAdapterService().setProfileConnectionPolicy(device, getProfileId(), connectionPolicy);
        if (connectionPolicy == CONNECTION_POLICY_FORBIDDEN) {
            disconnect(device);
        }
        return true;
    }

    @Override
    public boolean connect(BluetoothDevice device) {
        Log.w(TAG, "connect() was called but not implemented");
        return false;
    }

    @Override
    public boolean disconnect(BluetoothDevice device) {
        synchronized (mPbapStateMachineMap) {
            PbapStateMachine sm = mPbapStateMachineMap.get(device);
            if (sm != null) {
                sm.sendMessage(PbapStateMachine.DISCONNECT);
            }
        }

        return true;
    }

    static String getLocalPhoneNum() {
        return sLocalPhoneNum;
    }

    @VisibleForTesting
    static void setLocalPhoneName(String localPhoneName) {
        sLocalPhoneName = localPhoneName;
    }

    static String getLocalPhoneName() {
        return sLocalPhoneName;
    }

    @Override
    protected IProfileServiceBinder initBinder() {
        return new BluetoothPbapServiceBinder(this);
    }

    @Override
    public void cleanup() {
        Log.i(TAG, "cleanup()");

        mSessionStatusHandler.sendEmptyMessage(SHUTDOWN);
        if (mHandlerThread != null) {
            mHandlerThread.quitSafely();
            joinUninterruptibly(mHandlerThread);
        }
        mContactsLoaded = false;
        unregisterReceiver(mPbapReceiver);
        getAdapterService().getContentResolver().unregisterContentObserver(mContactChangeObserver);
        setComponentAvailable(PBAP_ACTIVITY, false);
        synchronized (mPbapStateMachineMap) {
            mPbapStateMachineMap.clear();
        }
        unregisterReceiver(mUserChangeReceiver);
    }

    @Override
    public boolean onConnect(BluetoothDevice remoteDevice, BluetoothSocket socket) {
        if (remoteDevice == null || socket == null) {
            Log.e(
                    TAG,
                    "onConnect(): Unexpected null. remoteDevice="
                            + remoteDevice
                            + " socket="
                            + socket);
            return false;
        }
        if (Flags.pbapCleanupUseHandler() && !mContactsLoaded) {
            mSessionStatusHandler.sendEmptyMessage(LOAD_CONTACTS);
        }

        PbapStateMachine sm =
                new PbapStateMachine(
                        getAdapterService(),
                        this,
                        mNotificationManager,
                        mLooper,
                        remoteDevice,
                        socket,
                        mSessionStatusHandler,
                        mNextNotificationId);
        mNextNotificationId++;
        if (mNextNotificationId == PBAP_NOTIFICATION_ID_END) {
            mNextNotificationId = PBAP_NOTIFICATION_ID_START;
        }
        synchronized (mPbapStateMachineMap) {
            mPbapStateMachineMap.put(remoteDevice, sm);
        }
        sm.sendMessage(PbapStateMachine.REQUEST_PERMISSION);
        return true;
    }

    /**
     * Get the phonebook access permission for the device; if unknown, ask the user. Send the result
     * to the state machine.
     *
     * @param stateMachine PbapStateMachine which sends the request
     */
    @VisibleForTesting(visibility = VisibleForTesting.Visibility.PACKAGE)
    public void checkOrGetPhonebookPermission(PbapStateMachine stateMachine) {
        BluetoothDevice device = stateMachine.getRemoteDevice();
        int permission = getAdapterService().getPhonebookAccessPermission(device);
        Log.d(TAG, "getPhonebookAccessPermission() = " + permission);

        if (permission == ACCESS_ALLOWED) {
            setConnectionPolicy(device, CONNECTION_POLICY_ALLOWED);
            stateMachine.sendMessage(PbapStateMachine.AUTHORIZED);
        } else if (permission == ACCESS_REJECTED) {
            stateMachine.sendMessage(PbapStateMachine.REJECTED);
        } else { // permission == BluetoothDevice.ACCESS_UNKNOWN
            Intent intent = new Intent(BluetoothDevice.ACTION_CONNECTION_ACCESS_REQUEST);
            intent.setClassName(
                    BluetoothPbapService.ACCESS_AUTHORITY_PACKAGE,
                    BluetoothPbapService.ACCESS_AUTHORITY_CLASS);
            intent.putExtra(
                    BluetoothDevice.EXTRA_ACCESS_REQUEST_TYPE,
                    BluetoothDevice.REQUEST_TYPE_PHONEBOOK_ACCESS);
            intent.putExtra(BluetoothDevice.EXTRA_DEVICE, device);
            intent.putExtra(BluetoothDevice.EXTRA_PACKAGE_NAME, this.getPackageName());
            sendOrderedBroadcastAsUser(
                    intent,
                    getUser(),
                    BLUETOOTH_CONNECT,
                    android.app.AppOpsManager.OP_NONE,
                    Util.getTempBroadcastBundle(),
                    null /* resultReceiver */,
                    null /* scheduler */,
                    Activity.RESULT_OK /* initialCode */,
                    null /* initialData */,
                    null /* initialExtras */);
            Log.v(TAG, "waiting for authorization for connection from: " + device);
            /* In case car kit time out and try to use HFP for phonebook
             * access, while UI still there waiting for user to confirm */
            Message msg =
                    mSessionStatusHandler.obtainMessage(
                            BluetoothPbapService.USER_TIMEOUT, stateMachine);
            mSessionStatusHandler.sendMessageDelayed(msg, USER_CONFIRM_TIMEOUT_VALUE);
            /* We will continue the process when we receive
             * BluetoothDevice.ACTION_CONNECTION_ACCESS_REPLY from Settings app. */
        }
    }

    /**
     * Called when an unrecoverable error occurred in an accept thread. Close down the server
     * socket, and restart.
     */
    @Override
    public synchronized void onAcceptFailed() {
        Log.w(TAG, "PBAP server socket accept thread failed. Restarting the server socket");

        if (Flags.pbapCleanupUseHandler()) {
            mSessionStatusHandler.sendEmptyMessage(HANDLE_ACCEPT_FAILED);
        } else {
            handleAcceptFailed();
        }
    }

    private void handleAcceptFailed() {
        if (mWakeLock != null) {
            mWakeLock.release();
            mWakeLock = null;
        }

        cleanUpServerSocket();

        mSessionStatusHandler.removeCallbacksAndMessages(null);

        synchronized (mPbapStateMachineMap) {
            mPbapStateMachineMap.clear();
        }

        mSessionStatusHandler.sendEmptyMessage(START_LISTENER);
    }

    private void loadAllContacts() {
        if (mThreadLoadContacts == null) {
            mThreadLoadContacts =
                    new Thread(
                            () -> {
                                BluetoothPbapUtils.loadAllContacts(
                                        BluetoothPbapService.this, mSessionStatusHandler);
                                mThreadLoadContacts = null;
                            });
            mThreadLoadContacts.start();
        }
    }

    private void updateSecondaryVersion() {
        if (mThreadUpdateSecVersionCounter == null) {
            mThreadUpdateSecVersionCounter =
                    new Thread(
                            () -> {
                                BluetoothPbapUtils.updateSecondaryVersionCounter(
                                        BluetoothPbapService.this, mSessionStatusHandler);
                                mThreadUpdateSecVersionCounter = null;
                            });
            mThreadUpdateSecVersionCounter.start();
        }
    }

    private void getLocalTelephonyDetails() {
        TelephonyManager tm = obtainSystemService(TelephonyManager.class);
        if (tm != null) {
            sLocalPhoneNum = tm.getLine1Number();
            sLocalPhoneName = this.getString(R.string.localPhoneName);
        }
        Log.v(TAG, "Local Phone Details- Number:" + sLocalPhoneNum + ", Name:" + sLocalPhoneName);
    }
}
