/*
 * Copyright (C) 2012 The Android Open Source Project
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

package com.android.server.bluetooth;

import static android.Manifest.permission.BLUETOOTH_CONNECT;
import static android.bluetooth.BluetoothProtoEnums.ENABLE_DISABLE_REASON_AIRPLANE_MODE;
import static android.bluetooth.BluetoothProtoEnums.ENABLE_DISABLE_REASON_APPLICATION_REQUEST;
import static android.bluetooth.BluetoothProtoEnums.ENABLE_DISABLE_REASON_AUTO_ON;
import static android.bluetooth.BluetoothProtoEnums.ENABLE_DISABLE_REASON_CRASH;
import static android.bluetooth.BluetoothProtoEnums.ENABLE_DISABLE_REASON_DISALLOWED;
import static android.bluetooth.BluetoothProtoEnums.ENABLE_DISABLE_REASON_FACTORY_RESET;
import static android.bluetooth.BluetoothProtoEnums.ENABLE_DISABLE_REASON_RESTARTED;
import static android.bluetooth.BluetoothProtoEnums.ENABLE_DISABLE_REASON_RESTORE_USER_SETTING;
import static android.bluetooth.BluetoothProtoEnums.ENABLE_DISABLE_REASON_SATELLITE_MODE;
import static android.bluetooth.BluetoothProtoEnums.ENABLE_DISABLE_REASON_START_ERROR;
import static android.bluetooth.BluetoothProtoEnums.ENABLE_DISABLE_REASON_SYSTEM_BOOT;
import static android.bluetooth.BluetoothProtoEnums.ENABLE_DISABLE_REASON_USER_SWITCH;
import static android.bluetooth.IBluetoothManager.ACTION_BLE_STATE_CHANGED;
import static android.bluetooth.IBluetoothManager.ACTION_LOCAL_NAME_CHANGED;
import static android.bluetooth.IBluetoothManager.ACTION_STATE_CHANGED;
import static android.bluetooth.IBluetoothManager.EXTRA_LOCAL_NAME;
import static android.bluetooth.IBluetoothManager.EXTRA_PREVIOUS_STATE;
import static android.bluetooth.IBluetoothManager.EXTRA_STATE;
import static android.os.PowerExemptionManager.TEMPORARY_ALLOW_LIST_TYPE_FOREGROUND_SERVICE_ALLOWED;
import static android.provider.Settings.Global.DEVICE_NAME;

import static com.android.bluetooth.util.Text.elapsedString;

import static java.util.Objects.requireNonNull;

import android.annotation.NonNull;
import android.app.BroadcastOptions;
import android.bluetooth.IAdapter;
import android.bluetooth.IBluetoothCallback;
import android.bluetooth.IBluetoothManagerCallback;
import android.bluetooth.State;
import android.content.BroadcastReceiver;
import android.content.ComponentName;
import android.content.ContentResolver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.ServiceConnection;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.os.Bundle;
import android.os.Handler;
import android.os.IBinder;
import android.os.Looper;
import android.os.Message;
import android.os.PowerExemptionManager;
import android.os.RemoteCallbackList;
import android.os.RemoteException;
import android.os.SystemClock;
import android.os.SystemProperties;
import android.os.UserHandle;
import android.provider.Settings;
import android.sysprop.BluetoothProperties;

import com.android.bluetooth.beta.flags.Flags;
import com.android.bluetooth.util.Text;
import com.android.bluetooth.util.TimeProvider;
import com.android.internal.annotations.VisibleForTesting;
import com.android.server.bluetooth.airplane.AirplaneModeController;
import com.android.server.bluetooth.airplane.AirplaneModeListener;
import com.android.server.bluetooth.satellite.SatelliteModeListener;

import kotlin.Unit;
import kotlin.time.TimeSource;

import java.io.FileDescriptor;
import java.io.PrintWriter;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.regex.Pattern;

@VisibleForTesting(visibility = VisibleForTesting.Visibility.PACKAGE) // For Kotlin
public class BluetoothManagerService {
    private static final String TAG = BluetoothManagerService.class.getSimpleName();

    private static final int CRASH_LOG_MAX_SIZE = 100;

    private static final Pattern ADDR_PATTERN = Pattern.compile("^([0-9A-F]{2}:){5}[0-9A-F]{2}$");

    // See android.os.Build.HW_TIMEOUT_MULTIPLIER. This should not be set on real hw
    private static final int HW_MULTIPLIER = SystemProperties.getInt("ro.hw_timeout_multiplier", 1);
    private static final boolean DEGRADED_PERFORMANCE =
            SystemProperties.getBoolean(
                    "bluetooth.hardware.degraded_performance_mode.enabled", false);

    @VisibleForTesting static final Duration TIMEOUT_BIND;
    private static final Duration STATE_TIMEOUT;
    @VisibleForTesting static final Duration SERVICE_RESTART_DELAY = Duration.ofMillis(400);
    private static final Duration ADD_PROXY_DELAY = Duration.ofMillis(100);

    static {
        if (DEGRADED_PERFORMANCE || HW_MULTIPLIER != 1) {
            TIMEOUT_BIND = Duration.ofSeconds(8).multipliedBy(HW_MULTIPLIER);
            STATE_TIMEOUT = Duration.ofSeconds(8).multipliedBy(HW_MULTIPLIER);
        } else {
            TIMEOUT_BIND = Duration.ofSeconds(4);
            STATE_TIMEOUT = Duration.ofSeconds(4);
        }
    }

    @VisibleForTesting static final int MESSAGE_BLUETOOTH_SERVICE_CONNECTED = 40;
    @VisibleForTesting static final int MESSAGE_BLUETOOTH_SERVICE_DISCONNECTED = 41;
    @VisibleForTesting static final int MESSAGE_RESTART_BLUETOOTH_SERVICE = 42;
    @VisibleForTesting static final int MESSAGE_BLUETOOTH_STATE_CHANGE = 60;
    @VisibleForTesting static final int MESSAGE_TIMEOUT_BIND = 100;
    @VisibleForTesting static final int MESSAGE_RESTORE_USER_SETTING_OFF = 501;
    private static final int MESSAGE_RESTORE_USER_SETTING_ON = 502;

    private static final int MAX_ERROR_RESTART_RETRIES = 6;

    // Bluetooth persisted setting is off
    @VisibleForTesting static final int BLUETOOTH_OFF = 0;
    // Bluetooth persisted setting is on
    // and Airplane mode won't affect Bluetooth state at start up
    // This is the default value
    @VisibleForTesting static final int BLUETOOTH_ON_BLUETOOTH = 1;
    // Bluetooth persisted setting is on
    // but Airplane mode will affect Bluetooth state at start up
    // and Airplane mode will have higher priority.
    private static final int BLUETOOTH_ON_AIRPLANE = 2;

    private final BleAppManager mBleAppManager;
    private final ActiveLogs mActiveLogs;
    private final BluetoothComponent mBluetoothComponent;
    private final TimeProvider mTimeProvider;

    private final BluetoothAdapterState mState = new BluetoothAdapterState();
    private final List<Long> mCrashTimestamps = new ArrayList<>();
    private final RemoteCallbackList<IBluetoothManagerCallback> mCallbacks =
            new RemoteCallbackList<>();
    @VisibleForTesting final BluetoothHandler mHandler;
    private final ContentResolver mContentResolver;
    private final Context mContext;
    private final Looper mLooper;

    private final String mHciInstanceName;
    private AutoOn mAutoOn;
    private AirplaneModeController mAirplaneModeController;
    private SharingRestriction mSharingRestriction;

    private String mAddress;
    private String mName;
    private AdapterBinder mAdapter;
    private Context mUserContext;
    private UserHandle mUser;
    private UserHandle mPendingUser; // Non null only when user switch is pending

    // used inside handler thread
    private boolean mQuietEnable = false;
    private boolean mEnable = false;
    private boolean mShutdownInProgress = false;

    private int mCrashes = 0;
    private Instant mLastBindingTime;

    // configuration from external IBinder call which is used to
    // synchronize with broadcast receiver.
    private boolean mQuietEnableExternal = false;
    private boolean mEnableExternal = false;

    private int mRetryCounter = 0;
    private boolean mIsBootCompleted = false;

    // The code in mBluetoothCallback is running on Binder thread.
    // It must be posted on the local looper to prevent concurrent access.
    private final IBluetoothCallback mBluetoothCallback =
            new IBluetoothCallback.Stub() {
                @Override
                public void onBluetoothStateChange(int prevState, int newState) {
                    Log.d(
                            TAG,
                            "IBluetoothCallback.onBluetoothStateChange:"
                                    + (" prevState=" + State.$.toString(prevState))
                                    + (" newState=" + State.$.toString(newState)));
                    sendMessage(MESSAGE_BLUETOOTH_STATE_CHANGE, prevState, newState);
                }

                @Override
                public void onAdapterAddressChange(String address) {
                    requireNonNull(address);
                    if (!ADDR_PATTERN.matcher(address).matches()) {
                        throw new IllegalArgumentException("Invalid address");
                    }
                    Log.d(
                            TAG,
                            "IBluetoothCallback.onAdapterAddressChange: " + Log.address(address));
                    post(() -> storeAddress(address));
                }

                @Override
                public void onMediaProfileConnectionChange(boolean connected) {
                    Log.d(TAG, "IBluetoothCallback.onMediaProfileConnectionChange: " + connected);
                    post(() -> mAirplaneModeController.setIsMediaProfileConnected(connected));
                }

                @Override
                public void onWatchConnectionChange(boolean connected) {
                    Log.d(TAG, "IBluetoothCallback.onWatchConnectionChange: " + connected);
                    post(() -> mAirplaneModeController.setWatchConnectionState(connected));
                }

                @Override
                public void setAdapterServiceBinder(IBinder binder) {
                    Log.d(TAG, "IBluetoothCallback.setAdapterServiceBinder: " + binder);
                    post(
                            () -> {
                                if (mAdapter == null) {
                                    return;
                                }
                                mAdapter.setAdapterServiceBinder(binder);
                                broadcastToAdapters(
                                        "setAdapterServiceBinder",
                                        (item) -> item.onBluetoothServiceUp(binder));
                            });
                }
            };

    private String validateLocalName(String name) {
        if (name == null || name.isEmpty()) {
            name = SystemProperties.get("bluetooth.device.default_name");
        }
        if (name == null || name.isEmpty()) {
            name = Settings.Global.getString(mContentResolver, DEVICE_NAME);
        }
        if (name == null || name.isEmpty()) {
            name = SystemProperties.get("ro.product.model");
        }
        if (name == null || name.isEmpty()) {
            name = "Android";
        }
        // The Bluetooth Device Name can be up to 248 bytes (see [Vol 2] Part C, Section 4.3.5).
        return Text.truncateUtf8String(name, 248);
    }

    private void storeName(String name) {
        if (!Settings.Secure.putString(mContentResolver, Settings.Secure.BLUETOOTH_NAME, name)) {
            Log.e(TAG, "storeName(" + name + "): Failed. Name is still " + mName);
            return;
        }
        mName = name;
        Log.v(TAG, "storeName(" + mName + "): Success");
        Intent intent =
                new Intent(ACTION_LOCAL_NAME_CHANGED)
                        .putExtra(EXTRA_LOCAL_NAME, name)
                        .addFlags(Intent.FLAG_RECEIVER_REGISTERED_ONLY_BEFORE_BOOT);
        var userManager = mUserContext.getSystemService(android.os.UserManager.class);
        for (UserHandle user : userManager.getEnabledProfiles()) {
            mContext.sendBroadcastAsUser(intent, user,
                    BLUETOOTH_CONNECT, getTempAllowlistBroadcastOptions());
        }
    }

    private void storeAddress(String address) {
        if (!Settings.Secure.putString(
                mContentResolver, Settings.Secure.BLUETOOTH_ADDRESS, address)) {
            Log.e(
                    TAG,
                    "storeAddress("
                            + Log.address(address)
                            + "): Failed. Address is still "
                            + Log.address(mAddress));
            return;
        }
        mAddress = address;
        Log.v(TAG, "storeAddress(" + Log.address(mAddress) + "): Success");
    }

    boolean factoryReset(int count) {
        if (mAutoOn != null) {
            mAutoOn.factoryReset();
        }
        mAirplaneModeController.factoryReset();
        try {
            BluetoothProperties.snoop_log_mode(null);
        } catch (RuntimeException e) {
            Log.e(TAG, "factoryReset: Failed to reset snoop log mode", e);
        }

        if (count == 10 || mState.oneOf(State.OFF)) {
            Log.e(TAG, "factoryReset(" + count + "): Set property to retry when Bluetooth start");
            BluetoothProperties.factory_reset(true);
            return false;
        }

        if (!mState.oneOf(State.BLE_ON, State.ON)) {
            // Bluetooth can not be toggled when it is in a transition state
            postDelayed(() -> factoryReset(count + 1), Duration.ofSeconds(1));
            return false;
        }

        Log.d(TAG, "factoryReset: Will perform service restart after setting reset property");
        BluetoothProperties.factory_reset(true);

        mBleAppManager.clearBleApps();
        mActiveLogs.add(ENABLE_DISABLE_REASON_FACTORY_RESET, false);
        if (mState.oneOf(State.BLE_ON)) {
            bleOnToOff();
        } else {
            onToBleOn();
        }
        return true;
    }

    private Duration estimateBusyTime(Object token) {
        if (!mState.oneOf(State.ON, State.OFF, State.BLE_ON, State.BLE_TURNING_ON)) {
            // Bluetooth is in a temporary turning state
            return ADD_PROXY_DELAY;
        } else if (mHandler.hasMessages(MESSAGE_RESTART_BLUETOOTH_SERVICE)
                || isBinding()
                || (token != ON_SWITCH_USER_TOKEN && mPendingUser != null)) {
            Log.d(
                    TAG,
                    "Busy reason:"
                            + " RESTART_BLUETOOTH_SERVICE="
                            + mHandler.hasMessages(MESSAGE_RESTART_BLUETOOTH_SERVICE)
                            + (" isBinding=" + isBinding())
                            + (" mPendingUser=" + mPendingUser));
            // Bluetooth is restarting
            return SERVICE_RESTART_DELAY;
        }
        return Duration.ZERO;
    }

    private void delayModeChangedIfNeeded(Object token, Runnable r, String modeChanged) {
        final Duration delay = estimateBusyTime(token);
        Log.d(
                TAG,
                ("delayModeChangedIfNeeded(" + modeChanged + "):")
                        + (" state=" + mState)
                        + (" Airplane.isOnForUser=" + mAirplaneModeController.isOnForUser())
                        + (" Airplane.isOn=" + AirplaneModeListener.isOn())
                        + (" isSatelliteModeOn()=" + isSatelliteModeOn())
                        + (" delayed=" + delay + "ms"));

        mHandler.removeCallbacksAndMessages(token);

        if (delay.isPositive()) {
            postDelayed(() -> delayModeChangedIfNeeded(token, r, modeChanged), token, delay);
        } else {
            r.run();
        }
    }

    /** Send Intent to the Notification Service in the Bluetooth app */
    Unit sendToggleNotification(String notificationReason) {
        Intent intent =
                new Intent("android.bluetooth.notification.action.SEND_TOGGLE_NOTIFICATION");
        intent.setComponent(
                new ComponentName(
                        mBluetoothComponent.getPackageName(),
                        "com.android.bluetooth.notification.NotificationHelperService"));
        intent.putExtra(
                "android.bluetooth.notification.extra.NOTIFICATION_REASON", notificationReason);
        mUserContext.startService(intent);
        return Unit.INSTANCE;
    }

    private static final Object ON_AIRPLANE_MODE_CHANGED_TOKEN = new Object();
    private static final Object ON_SATELLITE_MODE_CHANGED_TOKEN = new Object();
    private static final Object ON_SWITCH_USER_TOKEN = new Object();

    @VisibleForTesting
    Unit onAirplaneModeChanged(boolean isAirplaneModeOn) {
        delayModeChangedIfNeeded(
                ON_AIRPLANE_MODE_CHANGED_TOKEN,
                () -> handleAirplaneModeChanged(isAirplaneModeOn),
                "onAirplaneModeChanged");
        return Unit.INSTANCE;
    }

    Unit onSatelliteModeChanged(boolean isSatelliteModeOn) {
        delayModeChangedIfNeeded(
                ON_SATELLITE_MODE_CHANGED_TOKEN,
                () -> handleSatelliteModeChanged(isSatelliteModeOn),
                "onSatelliteModeChanged");
        return Unit.INSTANCE;
    }

    void onUserSwitching(UserHandle userHandle) {
        if (Flags.systemServerDirectSwitch()) {
            Log.d(TAG, "onUserSwitching(" + userHandle + ") -- Direct switch");
            handleSwitchUser(userHandle);
            return;
        }
        Log.d(TAG, "onUserSwitching(" + userHandle + ")");
        mPendingUser = userHandle;
        delayModeChangedIfNeeded(
                ON_SWITCH_USER_TOKEN, () -> handleSwitchUser(mPendingUser), "onUserSwitching");
    }

    private void forceToOffFromModeChange(int currentState, int reason) {
        // Clear registered LE apps to force shut-off
        mBleAppManager.clearBleApps();

        if (reason == ENABLE_DISABLE_REASON_SATELLITE_MODE
                || !mAirplaneModeController.hasUserToggledApm()) {
            // AirplaneMode can have a state where it does not impact AutoOn
            if (mAutoOn != null) {
                mAutoOn.pause();
            }
        }

        if (currentState == State.ON) {
            mEnable = false;
            mActiveLogs.add(reason, false);
            onToBleOn();
        } else if (currentState == State.BLE_ON) {
            mEnable = false;
            mEnableExternal = false;
            mActiveLogs.add(reason, false);
            bleOnToOff();
        } else if (currentState == State.BLE_TURNING_ON) {
            mEnable = false;
            mActiveLogs.add(reason, false);
            bleTurningOnToOff();
        }
    }

    private void handleAirplaneModeChanged(boolean isAirplaneModeOn) {
        boolean isPersistStateOn = isBluetoothPersistedStateOn();
        if (isPersistStateOn) {
            if (isAirplaneModeOn) {
                setBluetoothPersistedState(BLUETOOTH_ON_AIRPLANE);
            } else {
                setBluetoothPersistedState(BLUETOOTH_ON_BLUETOOTH);
            }
        }

        int currentState = mState.get();

        Log.d(
                TAG,
                ("handleAirplaneModeChanged(" + isAirplaneModeOn + "):")
                        + (" mEnableExternal=" + mEnableExternal)
                        + (" isPersistStateOn=" + isPersistStateOn)
                        + (" currentState=" + State.$.toString(currentState)));

        if (isAirplaneModeOn) {
            forceToOffFromModeChange(currentState, ENABLE_DISABLE_REASON_AIRPLANE_MODE);
        } else if (mEnableExternal && currentState != State.ON && isPersistStateOn) {
            // isPersistStateOn is checked to prevent race with RESTORE_USER_SETTING
            sendEnableMsg(mQuietEnableExternal, ENABLE_DISABLE_REASON_AIRPLANE_MODE);
        } else if (currentState != State.ON) {
            autoOnSetupTimer();
        }
    }

    private void handleSatelliteModeChanged(boolean isSatelliteModeOn) {
        final int currentState = mState.get();

        boolean shouldBeOn = shouldBluetoothBeOn(isSatelliteModeOn);

        if (shouldBeOn && currentState != State.ON) {
            sendEnableMsg(mQuietEnableExternal, ENABLE_DISABLE_REASON_SATELLITE_MODE);
        } else if (!shouldBeOn && currentState != State.OFF) {
            forceToOffFromModeChange(currentState, ENABLE_DISABLE_REASON_SATELLITE_MODE);
        } else if (!isSatelliteModeOn && !shouldBeOn && currentState != State.ON) {
            autoOnSetupTimer();
        }
    }

    private boolean shouldBluetoothBeOn(boolean isSatelliteModeOn) {
        if (!BluetoothRestriction.isBluetoothAllowed()) {
            Log.d(TAG, "shouldBluetoothBeOn: False - not allowed");
            return false;
        }

        if (!isBluetoothPersistedStateOn()) {
            Log.d(TAG, "shouldBluetoothBeOn: False - user persistent setting");
            return false;
        }

        if (isSatelliteModeOn) {
            Log.d(TAG, "shouldBluetoothBeOn: False - satellite mode");
            return false;
        }

        if (mAirplaneModeController.isOnForUser() && isBluetoothPersistedStateOnAirplane()) {
            Log.d(TAG, "shouldBluetoothBeOn: False - airplane mode");
            return false;
        }

        Log.d(TAG, "shouldBluetoothBeOn: True");
        return true;
    }

    private final BroadcastReceiver mReceiver =
            new BroadcastReceiver() {
                @Override
                public void onReceive(Context context, Intent intent) {
                    String action = intent.getAction();
                    if (Intent.ACTION_SETTING_RESTORED.equals(action)) {
                        final String name = intent.getStringExtra(Intent.EXTRA_SETTING_NAME);
                        if (Settings.Global.BLUETOOTH_ON.equals(name)) {
                            // The Bluetooth On state may be changed during system restore.
                            final String prevValue =
                                    intent.getStringExtra(Intent.EXTRA_SETTING_PREVIOUS_VALUE);
                            final String newValue =
                                    intent.getStringExtra(Intent.EXTRA_SETTING_NEW_VALUE);

                            Log.d(
                                    TAG,
                                    "ACTION_SETTING_RESTORED with BLUETOOTH_ON"
                                            + (" prevValue=" + prevValue)
                                            + (" newValue=" + newValue));

                            if ((newValue == null)
                                    || (prevValue == null)
                                    || prevValue.equals(newValue)) {
                                return;
                            }
                            if (newValue.equals("0")) {
                                sendMessage(MESSAGE_RESTORE_USER_SETTING_OFF);
                            } else {
                                sendMessage(MESSAGE_RESTORE_USER_SETTING_ON);
                            }
                        }
                    } else if (action.equals(Intent.ACTION_SHUTDOWN)) {
                        Log.i(TAG, "Device is shutting down.");
                        mShutdownInProgress = true;
                        mEnable = false;
                        mEnableExternal = false;
                        if (mState.oneOf(State.BLE_ON)) {
                            bleOnToOff();
                        } else if (mState.oneOf(State.ON)) {
                            onToBleOn();
                        }
                    }
                }
            };

    BluetoothManagerService(
            Context context,
            Looper looper,
            String hciInstanceName,
            BluetoothComponent bluetoothComponent,
            TimeProvider timeProvider) {
        mContext = requireNonNull(context);
        mContentResolver = requireNonNull(mContext.getContentResolver());
        mLooper = requireNonNull(looper);
        mHciInstanceName = requireNonNull(hciInstanceName);
        mBluetoothComponent = requireNonNull(bluetoothComponent);
        mTimeProvider = requireNonNull(timeProvider);
        mActiveLogs = new ActiveLogs();

        mHandler = new BluetoothHandler(mLooper);
        mBleAppManager = new BleAppManager(this::post, this::bleOnToOffIfNeeded);

        // Observe BLE scan only mode settings change.
        BleScanSettingListener.initialize(mLooper, mContentResolver, this::onBleScanDisabled);

        IntentFilter filter = new IntentFilter();
        filter.addAction(Intent.ACTION_SETTING_RESTORED);
        filter.addAction(Intent.ACTION_SHUTDOWN);
        filter.setPriority(IntentFilter.SYSTEM_HIGH_PRIORITY);
        mContext.registerReceiver(mReceiver, filter, null, mHandler);

        mName =
                validateLocalName(
                        BluetoothServerProxy.getInstance()
                                .settingsSecureGetString(
                                        mContentResolver, Settings.Secure.BLUETOOTH_NAME));
        mAddress =
                BluetoothServerProxy.getInstance()
                        .settingsSecureGetString(
                                mContentResolver, Settings.Secure.BLUETOOTH_ADDRESS);

        int persistedState = getBluetoothPersistedState();

        mEnableExternal = persistedState != BLUETOOTH_OFF;

        mConfigAllowAutoOn =
                SystemProperties.getBoolean("bluetooth.server.automatic_turn_on", false);

        Log.i(
                TAG,
                "BluetoothManagerService Start with:"
                        + (" Name=" + mName)
                        + (" Address=" + Log.address(mAddress))
                        + (" HciInstance=" + mHciInstanceName)
                        + (" BluetoothAllowed=" + BluetoothRestriction.isBluetoothAllowed())
                        + (" PersistentState=" + persistedState)
                        + (" EnableExternal=" + mEnableExternal)
                        + (" AutoOnEnabled=" + mConfigAllowAutoOn));
    }

    Unit onRestrictionChange() {
        if (mSharingRestriction != null) {
            mSharingRestriction.updateRestriction();
        }
        if (!BluetoothRestriction.isBluetoothAllowed()) {
            autoOnSetupTimer();
            if (mState.oneOf(State.OFF)) {
                return Unit.INSTANCE;
            }

            Log.i(TAG, "onRestrictionChange: Turning Bluetooth off");

            mBleAppManager.clearBleApps();

            mEnable = false;
            mEnableExternal = false;
            mActiveLogs.add(ENABLE_DISABLE_REASON_DISALLOWED, false);

            if (mState.oneOf(State.BLE_ON)) {
                bleOnToOff();
            } else if (mState.oneOf(State.ON)) {
                onToBleOn();
            }
        } else {
            if (!isBluetoothPersistedStateOnBluetooth()) {
                Log.d(TAG, "onRestrictionChange: No need to start Bluetooth");
                autoOnSetupTimer();
            } else {
                Log.i(TAG, "onRestrictionChange: Re-enabling Bluetooth for " + mUser);
                sendEnableMsg(mQuietEnableExternal, ENABLE_DISABLE_REASON_DISALLOWED);
            }
        }
        return Unit.INSTANCE;
    }

    @VisibleForTesting
    Unit onBleScanDisabled() {
        if (mState.oneOf(State.OFF, State.BLE_TURNING_OFF)) {
            Log.d(TAG, "onBleScanDisabled: Nothing to do, Bluetooth is already off");
            return Unit.INSTANCE;
        }
        mBleAppManager.clearBleApps();

        if (mState.oneOf(State.BLE_ON)) {
            Log.i(TAG, "onBleScanDisabled: Shutting down from BLE_ON");
            mEnable = false;
            bleOnToOff();
        } else {
            Log.d(TAG, "onBleScanDisabled: Nothing to do, Bluetooth is not in BLE_ON");
        }
        return Unit.INSTANCE;
    }

    /** Returns true if satellite mode is turned on. */
    private static boolean isSatelliteModeOn() {
        return SatelliteModeListener.isOn();
    }

    /** Returns true if the Bluetooth saved state is "on" */
    private boolean isBluetoothPersistedStateOn() {
        final int state = getBluetoothPersistedState();
        Log.v(TAG, "isBluetoothPersistedStateOn: " + state);
        return state != BLUETOOTH_OFF;
    }

    private boolean isBluetoothPersistedStateOnAirplane() {
        final int state = getBluetoothPersistedState();
        Log.v(TAG, "isBluetoothPersistedStateOnAirplane: " + state);
        return state == BLUETOOTH_ON_AIRPLANE;
    }

    /** Returns true if the Bluetooth saved state is BLUETOOTH_ON_BLUETOOTH */
    private boolean isBluetoothPersistedStateOnBluetooth() {
        final int state = getBluetoothPersistedState();
        Log.v(TAG, "isBluetoothPersistedStateOnBluetooth: " + state);
        return state == BLUETOOTH_ON_BLUETOOTH;
    }

    private int getBluetoothPersistedState() {
        return BluetoothServerProxy.getInstance()
                .getBluetoothPersistedState(mContentResolver, BLUETOOTH_ON_BLUETOOTH);
    }

    private void setBluetoothPersistedState(int state) {
        BluetoothServerProxy.getInstance().setBluetoothPersistedState(mContentResolver, state);
    }

    IBinder registerAdapter(IBluetoothManagerCallback callback) {
        mCallbacks.register(callback);
        if (mAdapter == null) {
            return null;
        }
        return mAdapter.getAdapterServiceBinder();
    }

    void unregisterAdapter(IBluetoothManagerCallback callback) {
        mCallbacks.unregister(callback);
    }

    int getState() {
        return mState.get();
    }

    boolean isBleScanAvailable() {
        if (mUser == null) {
            return false;
        }
        if (!BluetoothRestriction.isBluetoothAllowed()) {
            return false;
        }
        if (AirplaneModeListener.isOn() && !mEnable) {
            return false;
        }
        if (SatelliteModeListener.isOn()) {
            return false;
        }
        return BleScanSettingListener.isScanAllowed();
    }

    Context getUserContext() {
        return mUserContext;
    }

    boolean enableBle(String packageName, IBinder token) {
        Log.i(
                TAG,
                ("enableBle(" + packageName + ", " + token + "):")
                        + (" mAdapter=" + mAdapter)
                        + (" isBinding=" + isBinding())
                        + (" mState=" + mState));

        if (AirplaneModeListener.isOn() && !mEnable) {
            Log.d(TAG, "enableBle: not enabling - airplane mode");
            return false;
        }

        if (isSatelliteModeOn()) {
            Log.d(TAG, "enableBle: not enabling - satellite mode");
            return false;
        }

        if (mUser == null) {
            Log.e(TAG, "enableBle: not enabling - no user");
            return false;
        }

        if (mPendingUser != null) {
            Log.i(TAG, "enableBle: not enabling - pending user switch");
            return false;
        }

        if (!BleScanSettingListener.isScanAllowed()) {
            Log.d(TAG, "enableBle: not enabling - scan mode is not allowed");
            return false;
        }

        if (!mBleAppManager.addBleApp(token, packageName)) {
            Log.w(TAG, "enableBle: not enabling - requesting app is already dead: " + packageName);
            return false;
        }

        if (mState.oneOf(
                State.ON,
                State.BLE_ON,
                State.TURNING_ON,
                State.TURNING_OFF,
                State.BLE_TURNING_ON)) {
            Log.i(TAG, "enableBle: nothing to do - already in state " + mState);
            return true;
        }
        sendEnableMsg(false, ENABLE_DISABLE_REASON_APPLICATION_REQUEST, packageName, true);
        return true;
    }

    boolean disableBle(String packageName, IBinder token) {
        Log.i(
                TAG,
                ("disableBle(" + packageName + ", " + token + "):")
                        + (" mAdapter=" + mAdapter)
                        + (" isBinding=" + isBinding())
                        + (" mState=" + mState));

        mBleAppManager.removeBleApp(ENABLE_DISABLE_REASON_APPLICATION_REQUEST, token, packageName);
        return true;
    }

    private Unit bleOnToOffIfNeeded(int reason, String packageName) {
        if (!mState.oneOf(State.BLE_ON)) {
            Log.d(TAG, "bleOnToOffIfNeeded: nothing to do - current state is: " + mState);
            return Unit.INSTANCE;
        }
        mEnable = false;
        mActiveLogs.add(reason, false, packageName, true);
        bleOnToOff();
        return Unit.INSTANCE;
    }

    /**
     * Will call startBrEdr() if bluetooth classic should be on and will call stopBle if bluetooth
     * BLE should be off
     */
    private void continueFromBleOnState() {
        if (!mState.oneOf(State.BLE_ON)) {
            Log.e(TAG, "continueFromBleOnState: Impossible transition from " + mState);
            return;
        }
        if (!mEnableExternal && !mBleAppManager.isBleAppPresent()) {
            // TODO(b/262605980): this code is unlikely to be trigger and will never be once
            // enableBle & disableBle are executed on the handler
            Log.i(TAG, "continueFromBleOnState: Disabled while enabling BLE, disable BLE now");
            mEnable = false;
            bleOnToOff();
            return;
        }
        if (isBluetoothPersistedStateOnBluetooth() || !mBleAppManager.isBleAppPresent()) {
            Log.i(TAG, "continueFromBleOnState: initiate transition to ON");
            // This triggers transition to State.ON
            bleOnToOn();
            setBluetoothPersistedState(BLUETOOTH_ON_BLUETOOTH);
        } else {
            Log.i(TAG, "continueFromBleOnState: stay in BLE_ON");
        }
    }

    private Unit enableFromAutoOn() {
        if (!BluetoothRestriction.isBluetoothAllowed()) {
            Log.d(TAG, "enableFromAutoOn: not enabling - not allowed");
            return Unit.INSTANCE;
        }
        sendToggleNotification("auto_on_bt_enabled_notification");
        enable(ENABLE_DISABLE_REASON_AUTO_ON, mContext.getPackageName());
        return Unit.INSTANCE;
    }

    AirplaneModeController getAirplaneModeController() {
        return mAirplaneModeController;
    }

    boolean enableNoAutoConnect(String packageName) {
        Log.d(
                TAG,
                ("enableNoAutoConnect(" + packageName + "):")
                        + (" mAdapter=" + mAdapter)
                        + (" isBinding=" + isBinding())
                        + (" mState=" + mState));

        if (isSatelliteModeOn()) {
            Log.d(TAG, "enableNoAutoConnect: not enabling - satellite mode");
            return false;
        }

        if (mUser == null) {
            Log.e(TAG, "enableNoAutoConnect: not enabling - no user");
            return false;
        }

        if (mPendingUser != null) {
            Log.i(TAG, "enableNoAutoConnect: not enabling - pending user switch");
            return false;
        }

        mQuietEnableExternal = true;
        mEnableExternal = true;
        sendEnableMsg(true, ENABLE_DISABLE_REASON_APPLICATION_REQUEST, packageName);
        return true;
    }

    boolean enable(int reason, String packageName) {
        Log.d(
                TAG,
                ("enable(" + packageName + "):")
                        + (" mAdapter=" + mAdapter)
                        + (" isBinding=" + isBinding())
                        + (" mState=" + mState));

        if (isSatelliteModeOn()) {
            Log.d(TAG, "enable: not enabling - satellite mode");
            return false;
        }

        if (mUser == null) {
            Log.e(TAG, "enable: not enabling - no user");
            return false;
        }

        if (mPendingUser != null) {
            Log.i(TAG, "enable: not enabling - pending user switch");
            return false;
        }

        mQuietEnableExternal = false;
        mEnableExternal = true;
        mAirplaneModeController.notifyUserToggledBluetooth(true);
        sendEnableMsg(false, reason, packageName);
        return true;
    }

    boolean disable(String packageName, boolean persist) {
        Log.d(
                TAG,
                ("disable(" + packageName + ", " + persist + "):")
                        + (" mAdapter=" + mAdapter)
                        + (" mEnable=" + mEnable)
                        + (" mBleAppManager=" + mBleAppManager)
                        + (" isBinding=" + isBinding())
                        + (" mState=" + mState));

        mAirplaneModeController.notifyUserToggledBluetooth(false);

        if (persist) {
            setBluetoothPersistedState(BLUETOOTH_OFF);
        }
        mEnableExternal = false;
        sendDisableMsg(ENABLE_DISABLE_REASON_APPLICATION_REQUEST, packageName);
        return true;
    }

    private static CompletableFuture<Void> createDeathNotifier(IBinder binder) {
        CompletableFuture<Void> deathNotifier = new CompletableFuture<>();
        try {
            binder.linkToDeath(
                    () -> {
                        Log.i(TAG, "--- Successfully received Bluetooth death ---");
                        deathNotifier.complete(null);
                    },
                    0);
        } catch (RemoteException e) {
            Log.e(TAG, "createDeathNotifier: Failed to linkToDeath", e);
            deathNotifier.complete(null);
        }
        return deathNotifier;
    }

    private static void killBluetoothProcess(
            AdapterBinder adapter, CompletableFuture<Void> deathNotifier) {
        try {
            // Force kill Bluetooth to make sure its process is not reused.
            // Note: In a perfect world, we should be able to re-init the same process.
            // Unfortunately, this requires an heavy rework of the Bluetooth app
            // TODO: b/339501753 - Properly stop Bluetooth without killing it
            adapter.killBluetoothProcess();

            deathNotifier.get(2_000, TimeUnit.MILLISECONDS);
        } catch (android.os.DeadObjectException e) {
            // Reduce exception to info and skip waiting (Bluetooth is dead as wanted)
            Log.i(TAG, "killBluetoothProcess: nothing to do - already dead 💀");
        } catch (RemoteException e) {
            Log.e(TAG, "killBluetoothProcess: call failed", e);
        } catch (TimeoutException | InterruptedException | ExecutionException e) {
            Log.e(TAG, "killBluetoothProcess: timeout - Bluetooth death not received", e);
        }
    }

    void unbindAndFinish() {
        Log.d(TAG, "unbindAndFinish: mAdapter=" + mAdapter + " isBinding=" + isBinding());

        mHandler.removeMessages(MESSAGE_BLUETOOTH_STATE_CHANGE);
        if (mAdapter == null) {
            // mAdapter can be null when Bluetooth crashed and sent SERVICE_DISCONNECTED
            return;
        }

        try {
            mAdapter.unregisterCallback(mBluetoothCallback);
        } catch (RemoteException e) {
            Log.e(TAG, "unbindAndFinish: fail to unregister callback", e);
        }

        CompletableFuture<Void> deathNotifier =
                createDeathNotifier(mAdapter.getAdapterBinder().asBinder());

        // Unbind first to avoid receiving unwanted "onServiceDisconnected"
        mContext.unbindService(mConnection);

        killBluetoothProcess(mAdapter, deathNotifier);

        // TODO: b/356931756 - Remove sleep
        Log.d(TAG, "unbindAndFinish: Force sleep 100 ms to wait for Bluetooth death propagation");
        SystemClock.sleep(100); // required to let the ActivityManager be notified of BT death

        mAdapter = null; // Don't call resetAdapter as we already call unbindService
        mHandler.removeMessages(MESSAGE_TIMEOUT_BIND);
    }

    void onBootCompleted() {
        mIsBootCompleted = true;
        if (!mHandler.hasMessages(MESSAGE_TIMEOUT_BIND)) {
            return;
        }

        mHandler.removeMessages(MESSAGE_TIMEOUT_BIND);
        sendMessageDelayed(MESSAGE_TIMEOUT_BIND, TIMEOUT_BIND);
    }

    /**
     * Send enable message and set adapter name and address. Called when the boot phase becomes
     * PHASE_SYSTEM_SERVICES_READY.
     */
    void handleOnBootPhase(UserHandle userHandle) {
        mUser = userHandle;
        mUserContext = mContext.createContextAsUser(userHandle, 0);

        mAirplaneModeController =
                new AirplaneModeController(
                        mUserContext,
                        mState,
                        this::onAirplaneModeChanged,
                        this::sendToggleNotification,
                        TimeSource.Monotonic.INSTANCE);

        if (mConfigAllowAutoOn) {
            mAutoOn =
                    new AutoOn(
                            mLooper,
                            mUserContext,
                            mUser,
                            mState,
                            this::enableFromAutoOn,
                            mAirplaneModeController);
        }

        mSharingRestriction =
                new SharingRestriction(mUserContext, mLooper, mBluetoothComponent, mUser);

        if (!BluetoothRestriction.isBluetoothAllowed()) {
            Log.i(TAG, "handleOnBootPhase: not enabling - not allowed");
            return;
        }
        if (mContext.getPackageManager().isSafeMode()) {
            Log.i(TAG, "handleOnBootPhase: not enabling - SafeMode");
            return;
        }
        if (!mEnableExternal || !isBluetoothPersistedStateOnBluetooth()) {
            Log.i(TAG, "handleOnBootPhase: not enabling - user persistent setting");
            autoOnSetupTimer();
            return;
        }
        Log.i(TAG, "handleOnBootPhase: enabling for " + mUser);
        sendEnableMsg(mQuietEnableExternal, ENABLE_DISABLE_REASON_SYSTEM_BOOT);
    }

    /** Called when switching to a different foreground user. */
    @VisibleForTesting
    void handleSwitchUser(UserHandle nextUser) {
        Log.d(TAG, "handleSwitchUser(" + nextUser + ")");
        if (Flags.systemServerDirectSwitch()) {
            if (mUser.equals(nextUser) && mState.oneOf(State.TURNING_ON)) {
                // When shutting down, we must complete the switch in order to restart, else we skip
                Log.d(TAG, "handleSwitchUser: nothing to do - fast switch on " + mUser);
                mPendingUser = null;
                return;
            }
        } else {
            if (mUser.equals(mPendingUser)) {
                Log.d(TAG, "handleSwitchUser: nothing to do - fast switch on " + mUser);
                mPendingUser = null;
                return;
            }
        }

        if (mAutoOn != null) {
            mAutoOn.pause();
            mAutoOn = null;
            Log.d(TAG, "handleSwitchUser: stopping AutoOn for " + mUser);
        }

        mSharingRestriction.stop();

        if (mState.oneOf(State.OFF)) {
            executeUserSwitch(nextUser);
        } else {
            prepareUserSwitch(nextUser);
        }
    }

    @FunctionalInterface
    private interface RemoteExceptionConsumer<T> {
        void accept(T t) throws RemoteException;
    }

    private void broadcastToAdapters(
            String logAction, RemoteExceptionConsumer<IBluetoothManagerCallback> action) {
        final int itemCount = mCallbacks.beginBroadcast();
        Log.v(TAG, "Broadcasting " + logAction + "() to " + itemCount + " receivers");
        for (int i = 0; i < itemCount; i++) {
            try {
                action.accept(mCallbacks.getBroadcastItem(i));
            } catch (RemoteException e) {
                Log.e(TAG, "RemoteException while calling " + logAction + "()#" + i, e);
            }
        }
        mCallbacks.finishBroadcast();
    }

    private void sendBluetoothOnCallback() {
        broadcastToAdapters("sendBluetoothOnCallback", IBluetoothManagerCallback::onBluetoothOn);
    }

    private void sendBluetoothOffCallback() {
        broadcastToAdapters("sendBluetoothOffCallback", IBluetoothManagerCallback::onBluetoothOff);
    }

    private void sendBluetoothServiceDownCallback() {
        if (Flags.systemServerDirectSwitch() && isBinding()) {
            // No need to call onBluetoothServiceDown if the service was never up
            return;
        }
        broadcastToAdapters(
                "sendBluetoothServiceDownCallback",
                IBluetoothManagerCallback::onBluetoothServiceDown);
    }

    String getAddress() {
        return mAddress;
    }

    void setName(String name) {
        name = validateLocalName(name);
        if (Objects.equals(name, mName)) {
            return;
        }
        if (mAdapter != null) {
            try {
                mAdapter.setName(name);
            } catch (RemoteException e) {
                Log.e(TAG, "Unable to change the local name", e);
            }
        }
        storeName(name);
    }

    String getName() {
        return mName;
    }

    @VisibleForTesting
    class BluetoothServiceConnection implements ServiceConnection {
        @Override
        public void onServiceConnected(ComponentName componentName, IBinder service) {
            String name = componentName.getClassName();
            Log.d(TAG, "ServiceConnection.onServiceConnected(" + name + ", " + service + ")");
            if (!name.equals("com.android.bluetooth.btservice.AdapterService")) {
                // Impossible to reach
                Log.e(TAG, "Unknown service connected: " + name);
                return;
            }
            sendMessage(MESSAGE_BLUETOOTH_SERVICE_CONNECTED, service);
        }

        @Override
        public void onServiceDisconnected(ComponentName componentName) {
            // Called if we unexpectedly disconnect.
            String name = componentName.getClassName();
            Log.e(TAG, "ServiceConnection.onServiceDisconnected(" + name + ")");
            if (!name.equals("com.android.bluetooth.btservice.AdapterService")) {
                // Impossible to reach
                Log.e(TAG, "Unknown service disconnected: " + name);
                return;
            }
            sendMessage(MESSAGE_BLUETOOTH_SERVICE_DISCONNECTED);
        }

        @Override
        public void onBindingDied(ComponentName componentName) {
            String name = componentName.getClassName();
            Log.wtf(TAG, "ServiceConnection.onBindingDied(" + name + ")");
        }

        @Override
        public void onNullBinding(ComponentName componentName) {
            String name = componentName.getClassName();
            Log.wtf(TAG, "ServiceConnection.onNullBinding(" + name + ")");
        }
    }

    private final BluetoothServiceConnection mConnection = new BluetoothServiceConnection();

    @VisibleForTesting
    class BluetoothHandler extends Handler {
        BluetoothHandler(Looper looper) {
            super(looper);
        }

        @Override
        public void handleMessage(Message msg) {
            switch (msg.what) {
                case MESSAGE_RESTORE_USER_SETTING_OFF -> {
                    if (!mEnable) {
                        Log.w(TAG, "RESTORE_USER_SETTING_OFF: nothing to do - already disabled");
                        break;
                    }
                    Log.d(TAG, "RESTORE_USER_SETTING_OFF: disabling Bluetooth");
                    setBluetoothPersistedState(BLUETOOTH_OFF);
                    mEnableExternal = false;
                    sendDisableMsg(ENABLE_DISABLE_REASON_RESTORE_USER_SETTING);
                }
                case MESSAGE_RESTORE_USER_SETTING_ON -> {
                    if (mEnable) {
                        Log.w(TAG, "RESTORE_USER_SETTING_ON: nothing to do - already enabled");
                        break;
                    }
                    Log.d(TAG, "RESTORE_USER_SETTING_ON: enabling Bluetooth");
                    mQuietEnableExternal = false;
                    mEnableExternal = true;
                    sendEnableMsg(false, ENABLE_DISABLE_REASON_RESTORE_USER_SETTING);
                }
                case MESSAGE_BLUETOOTH_SERVICE_CONNECTED -> {
                    IBinder service = (IBinder) msg.obj;

                    // Handle case where disable was called before binding complete.
                    if (!isBinding() && !mEnable) {
                        Log.d(TAG, "MESSAGE_BLUETOOTH_SERVICE_CONNECTED: after cancelling binding");
                        AdapterBinder adapter =
                                BluetoothServerProxy.getInstance().createAdapterBinder(service);
                        killBluetoothProcess(adapter, createDeathNotifier(service));
                        break;
                    }
                    Log.d(TAG, "MESSAGE_BLUETOOTH_SERVICE_CONNECTED: service=" + service);

                    // Remove timeout
                    mHandler.removeMessages(MESSAGE_TIMEOUT_BIND);

                    mAdapter = BluetoothServerProxy.getInstance().createAdapterBinder(service);

                    try {
                        mAdapter.registerCallback(mBluetoothCallback);
                    } catch (RemoteException e) {
                        Log.e(TAG, "Unable to register BluetoothCallback", e);
                    }

                    propagateOffToBleOn(mHciInstanceName);
                }
                case MESSAGE_BLUETOOTH_STATE_CHANGE -> {
                    int prevState = msg.arg1;
                    int newState = msg.arg2;
                    Log.d(
                            TAG,
                            "MESSAGE_BLUETOOTH_STATE_CHANGE:"
                                    + (" prevState=" + State.$.toString(prevState))
                                    + (" newState=" + State.$.toString(newState)));
                    if (mAdapter == null) {
                        Log.e(TAG, "State change received after bluetooth has crashed");
                        break;
                    }
                    bluetoothStateChangeHandler(prevState, newState);
                    // handle error state transition case from TURNING_ON to OFF
                    // unbind and rebind bluetooth service and enable bluetooth
                    if ((prevState == State.BLE_TURNING_ON) && (newState == State.OFF) && mEnable) {
                        recoverBluetoothServiceFromError(false);
                    }
                    if ((prevState == State.TURNING_ON) && (newState == State.BLE_ON) && mEnable) {
                        recoverBluetoothServiceFromError(true);
                    }
                    // If we tried to enable BT while BT was in the process of shutting down,
                    // wait for the BT process to fully tear down and then force a restart here.
                    if (prevState == State.BLE_TURNING_OFF && newState == State.OFF) {
                        if (mHandler.hasMessages(0, ON_AIRPLANE_MODE_CHANGED_TOKEN)) {
                            mHandler.removeCallbacksAndMessages(ON_AIRPLANE_MODE_CHANGED_TOKEN);
                            Log.d(TAG, "Handling delayed airplane mode event");
                            handleAirplaneModeChanged(mAirplaneModeController.isOnForUser());
                        }
                        // When performing FactoryReset, we currently depend on this to restart
                        if (mEnable && !isBinding()) {
                            Log.d(TAG, "Entering State.OFF but mEnable is true; restarting.");
                            handleRestartMessage();
                        }
                    }
                    if (newState == State.ON || newState == State.BLE_ON) {
                        // bluetooth is working, reset the counter
                        if (mRetryCounter != 0) {
                            Log.i(TAG, "Bluetooth is recovered from error");
                            mRetryCounter = 0;
                        }
                    }
                }
                case MESSAGE_BLUETOOTH_SERVICE_DISCONNECTED -> {
                    Log.e(TAG, "MESSAGE_BLUETOOTH_SERVICE_DISCONNECTED");
                    disableBluetoothComponents();

                    if (!resetAdapter()) {
                        break;
                    }

                    // log the unexpected crash
                    addCrashLog();
                    mActiveLogs.add(ENABLE_DISABLE_REASON_CRASH, false);
                    if (mEnable) {
                        prepareRestartMessage(false);
                    }

                    sendBluetoothServiceDownCallback();

                    // Send BT state broadcast to update listener correctly (like Bt icon)
                    if (mState.oneOf(State.TURNING_ON, State.ON)) {
                        bluetoothStateChangeHandler(mState.get(), State.TURNING_OFF);
                    }
                    if (mState.oneOf(State.TURNING_OFF, State.BLE_ON)) {
                        bluetoothStateChangeHandler(mState.get(), State.BLE_TURNING_OFF);
                    }
                    if (mState.oneOf(State.BLE_TURNING_ON, State.BLE_TURNING_OFF)) {
                        bluetoothStateChangeHandler(mState.get(), State.OFF);
                    }

                    mHandler.removeMessages(MESSAGE_BLUETOOTH_STATE_CHANGE);
                    mHandler.removeMessages(MESSAGE_BLUETOOTH_SERVICE_CONNECTED);
                }
                case MESSAGE_RESTART_BLUETOOTH_SERVICE -> handleRestartMessage();

                case MESSAGE_TIMEOUT_BIND -> {
                    Log.e(TAG, "TIMEOUT_BIND: Impossible to bind to Bluetooth service");
                    mContext.unbindService(mConnection);
                    bluetoothStateChangeHandler(State.BLE_TURNING_ON, State.OFF);
                    mHandler.removeMessages(MESSAGE_BLUETOOTH_SERVICE_CONNECTED);
                    if (mEnable) {
                        prepareRestartMessage(true);
                    }
                }

                default -> {} // Nothing to do
            }
        }
    }

    private boolean isBinding() {
        return mHandler.hasMessages(MESSAGE_TIMEOUT_BIND);
    }

    private void prepareRestartMessage(boolean recoverFromTimeout) {
        mEnable = false;

        mRetryCounter++;
        if (mRetryCounter > MAX_ERROR_RESTART_RETRIES) {
            resetAdapter();
            Log.e(TAG, "Reached maximum retry to restart Bluetooth!");
            return;
        }

        var delay = SERVICE_RESTART_DELAY.multipliedBy(mRetryCounter);
        if (mRetryCounter > MAX_ERROR_RESTART_RETRIES / 2) {
            // Last attempts should leave way more time
            delay = delay.multipliedBy(10);
        }
        if (recoverFromTimeout) {
            // Leave more time to recover when it come from a timeout, to not add load on an already
            // performance limited device.
            // This should also give enough time to terminate the Bluetooth process and make sure it
            // is not being re-used.
            delay = delay.multipliedBy(10);
        }

        Log.e(TAG, "Recovery #" + mRetryCounter + " scheduled in " + delay.toString().substring(2));
        sendMessageDelayed(MESSAGE_RESTART_BLUETOOTH_SERVICE, delay);
    }

    private void handleRestartMessage() {
        // Enable without persisting the setting as it doesn't change when Bluetooth restarts
        mEnable = true;
        mActiveLogs.add(ENABLE_DISABLE_REASON_RESTARTED, true);
        handleEnable();
    }

    private void prepareUserSwitch(UserHandle nextUser) {
        Log.d(TAG, "prepareUserSwitch(" + nextUser + "): during state:" + mState);

        mBleAppManager.clearBleApps(); // Clear registered LE apps to force shut-off

        mEnable = false;
        mEnableExternal = false;

        mActiveLogs.add(ENABLE_DISABLE_REASON_USER_SWITCH, false);

        if (Flags.systemServerDirectSwitch()) {
            switch (mState.get()) {
                case State.ON -> onToBleOn();
                case State.BLE_ON -> bleOnToOff();
                case State.BLE_TURNING_ON -> {
                    bleTurningOnToOff();
                    executeUserSwitch(nextUser);
                    return;
                }
                default -> {} // Already turning OFF, or handled with mNextUser when reaching ON
            }
            mPendingUser = nextUser;
            return;
        }

        switch (mState.get()) {
            case State.ON -> onToBleOn();
            case State.BLE_ON -> bleOnToOff();
            case State.BLE_TURNING_ON -> bleTurningOnToOff();
            default -> throw new IllegalStateException("From impossible state:" + mState);
        }
    }

    private void executeUserSwitch(UserHandle nextUser) {
        if (Flags.systemServerDirectSwitch()) {
            mUser = nextUser;
            Log.i(TAG, "executeUserSwitch: Active user is " + mUser);
            mQuietEnable = false;
            mQuietEnableExternal = false;
        } else {
            mUser = mPendingUser;
            mPendingUser = null;
        }

        mUserContext = mContext.createContextAsUser(mUser, 0);

        mAirplaneModeController =
                new AirplaneModeController(
                        mUserContext,
                        mState,
                        this::onAirplaneModeChanged,
                        this::sendToggleNotification,
                        TimeSource.Monotonic.INSTANCE);

        if (mConfigAllowAutoOn) {
            mAutoOn =
                    new AutoOn(
                            mLooper,
                            mUserContext,
                            mUser,
                            mState,
                            this::enableFromAutoOn,
                            mAirplaneModeController);
        }

        mSharingRestriction =
                new SharingRestriction(mUserContext, mLooper, mBluetoothComponent, mUser);

        if (!BluetoothRestriction.isBluetoothAllowed()) {
            Log.i(TAG, "executeUserSwitch: not enabling - not allowed");
            return;
        }
        if (mContext.getPackageManager().isSafeMode()) {
            Log.i(TAG, "executeUserSwitch: not enabling - SafeMode");
            return;
        }
        if (!isBluetoothPersistedStateOnBluetooth()) {
            Log.i(TAG, "executeUserSwitch: not enabling - user persistent setting");
            autoOnSetupTimer();
            return;
        }
        Log.i(TAG, "executeUserSwitch: enabling for " + mUser);
        mEnableExternal = true;
        sendEnableMsg(false, ENABLE_DISABLE_REASON_USER_SWITCH);
    }

    private boolean resetAdapter() {
        if (mAdapter == null) {
            return false;
        }
        mAdapter = null;
        mContext.unbindService(mConnection);
        return true;
    }

    private void handleEnable() {
        if (mAdapter != null) {
            Log.w(TAG, "handleEnable: Adapter already created");
            return;
        } else if (isBinding()) {
            Log.w(TAG, "handleEnable: Binding in progress");
            return;
        }

        bluetoothStateChangeHandler(State.OFF, State.BLE_TURNING_ON);
        RolePermissionListener.registerForUser(mLooper, mUserContext, mUser, this::onRoleGranted);
    }

    private Unit onRoleGranted() {
        if (!(mEnableExternal || mBleAppManager.isBleAppPresent())) {
            Log.w(TAG, "onRoleGranted: external=" + mEnableExternal + " ble=" + mBleAppManager);
            bluetoothStateChangeHandler(State.BLE_TURNING_ON, State.OFF);
        } else if (mAdapter != null) {
            Log.w(TAG, "onRoleGranted: Adapter already created");
        } else if (isBinding()) {
            Log.w(TAG, "onRoleGranted: Binding in progress");
        } else {
            bindToAdapter();
        }
        return Unit.INSTANCE;
    }

    private void bindToAdapter() {
        requireNonNull(mUser, "There is no user to start for");
        int flags = Context.BIND_AUTO_CREATE | Context.BIND_IMPORTANT;
        Intent intent = new Intent(IAdapter.class.getName());
        intent.putExtra(EXTRA_LOCAL_NAME, mName);
        intent.setComponent(mBluetoothComponent.getComponentName());

        Log.d(TAG, "Start binding to the Bluetooth service with intent=" + intent);
        mLastBindingTime = Instant.now();
        if (!mContext.bindServiceAsUser(intent, mConnection, flags, mUser)) {
            Log.e(TAG, "Fail to bind intent=" + intent);
            mContext.unbindService(mConnection);
            bluetoothStateChangeHandler(State.BLE_TURNING_ON, State.OFF);
            mBleAppManager.clearBleApps();
            mActiveLogs.add(ENABLE_DISABLE_REASON_START_ERROR, false);
            return;
        }

        // Leave more time to bind to Bluetooth if the boot is not completed
        var delay = mIsBootCompleted ? TIMEOUT_BIND : TIMEOUT_BIND.multipliedBy(20);
        sendMessageDelayed(MESSAGE_TIMEOUT_BIND, delay);
    }

    private void propagateOffToBleOn(String hciInstanceName) {
        if (!mState.oneOf(State.BLE_TURNING_ON)) {
            Log.e(TAG, "propagateOffToBleOn: Impossible transition from " + mState);
            return;
        }
        Log.d(TAG, "propagateOffToBleOn: Sending request hciInstanceName " + hciInstanceName);
        try {
            mAdapter.offToBleOn(mQuietEnable, hciInstanceName);
        } catch (RemoteException e) {
            Log.e(TAG, "Unable to call offToBleOn()", e);
        }
    }

    private void onToBleOn() {
        if (!mState.oneOf(State.ON)) {
            Log.e(TAG, "onToBleOn: Impossible transition from " + mState);
            return;
        }
        Log.d(TAG, "onToBleOn: Sending request");
        try {
            mAdapter.onToBleOn();
        } catch (RemoteException e) {
            Log.e(TAG, "Unable to call onToBleOn()", e);
        }
        bluetoothStateChangeHandler(State.ON, State.TURNING_OFF);
    }

    private void bleOnToOn() {
        if (!mState.oneOf(State.BLE_ON)) {
            Log.e(TAG, "bleOnToOn: Impossible transition from " + mState);
            return;
        }
        Log.d(TAG, "bleOnToOn: sending request");
        try {
            mAdapter.bleOnToOn();
        } catch (RemoteException e) {
            Log.e(TAG, "Unable to call bleOnToOn()", e);
        }
        bluetoothStateChangeHandler(State.BLE_ON, State.TURNING_ON);
    }

    private void bleOnToOff() {
        if (!mState.oneOf(State.BLE_ON)) {
            Log.e(TAG, "bleOnToOff: Impossible transition from " + mState);
            return;
        }
        Log.d(TAG, "bleOnToOff: Sending request");
        try {
            mAdapter.bleOnToOff();
        } catch (RemoteException e) {
            Log.e(TAG, "Unable to call bleOnToOff()", e);
        }
        bluetoothStateChangeHandler(State.BLE_ON, State.BLE_TURNING_OFF);
    }

    private void bleTurningOnToOff() {
        if (!mState.oneOf(State.BLE_TURNING_ON)) {
            throw new IllegalStateException("bleTurningOnToOff: Impossible from " + mState);
        }
        Log.d(TAG, "bleTurningOnToOff: Sending request");
        if (mAdapter == null) {
            // When Bluetooth was not yet bound, prevent binding to complete
            Log.d(TAG, "bleTurningOnToOff: Cancel binding");
            mContext.unbindService(mConnection);
            if (!Flags.systemServerDirectSwitch()) {
                mHandler.removeMessages(MESSAGE_BLUETOOTH_SERVICE_CONNECTED);
            }
        }
        if (!Flags.systemServerDirectSwitch()) {
            mHandler.removeMessages(MESSAGE_BLUETOOTH_STATE_CHANGE);
        }
        bluetoothStateChangeHandler(State.BLE_TURNING_ON, State.OFF);
        if (Flags.systemServerDirectSwitch()) {
            mHandler.removeMessages(MESSAGE_TIMEOUT_BIND);
            mHandler.removeMessages(MESSAGE_BLUETOOTH_STATE_CHANGE);
            mHandler.removeMessages(MESSAGE_BLUETOOTH_SERVICE_CONNECTED);
        }
    }

    private void broadcastIntentStateChange(String action, int prevState, int newState) {
        Log.d(
                TAG,
                "broadcastIntentStateChange:"
                        + (" action=" + action.substring(action.lastIndexOf('.') + 1))
                        + (" prevState=" + State.$.toString(prevState))
                        + (" newState=" + State.$.toString(newState)));
        // Send broadcast message to everyone else
        Intent intent =
                new Intent(action)
                        .putExtra(EXTRA_PREVIOUS_STATE, prevState)
                        .putExtra(EXTRA_STATE, newState)
                        .addFlags(Intent.FLAG_RECEIVER_REGISTERED_ONLY_BEFORE_BOOT);
        var userManager = mUserContext.getSystemService(android.os.UserManager.class);
        for (UserHandle user : userManager.getEnabledProfiles()) {
            mContext.sendBroadcastAsUser(intent, user, null,
                    getTempAllowlistBroadcastOptions());
        }
    }

    private static boolean isBleState(int state) {
        return switch (state) {
            case State.BLE_ON, State.BLE_TURNING_ON, State.BLE_TURNING_OFF -> true;
            default -> false;
        };
    }

    private void bluetoothStateChangeHandler(int prevState, int newState) {
        String header =
                "bluetoothStateChangeHandler("
                        + State.$.toString(prevState)
                        + ", "
                        + State.$.toString(newState)
                        + "): ";
        if (mState.oneOf(newState)) {
            // Unreachable. We should be able to delete the if entirely
            Log.e(TAG, header + "Already in state " + mState);
            return;
        }

        if (newState == State.OFF) {
            // If Bluetooth is off, send service down event to proxy objects, and unbind
            sendBluetoothServiceDownCallback();
            unbindAndFinish();
        }

        mState.set(newState);

        broadcastIntentStateChange(ACTION_BLE_STATE_CHANGED, prevState, newState);

        // BLE state are shown as State.OFF for BrEdr users
        final int prevBrEdrState = isBleState(prevState) ? State.OFF : prevState;
        final int newBrEdrState = isBleState(newState) ? State.OFF : newState;

        if (prevBrEdrState != newBrEdrState) { // Only broadcast when there is a BrEdr state change.
            broadcastIntentStateChange(ACTION_STATE_CHANGED, prevBrEdrState, newBrEdrState);
            if (newBrEdrState == State.OFF) {
                sendBluetoothOffCallback();
            }
        }

        if (prevState == State.ON) {
            autoOnSetupTimer();
            mAirplaneModeController.setIsMediaProfileConnected(false);
            mAirplaneModeController.setWatchConnectionState(false);
        }

        if (newState == State.ON) {
            actionWhenBluetoothReachStateOn();
        } else if (newState == State.BLE_ON && prevState == State.BLE_TURNING_ON) {
            continueFromBleOnState();
        } else if (newState == State.OFF) {
            actionWhenBluetoothReachStateOff(prevState);
        }
    }

    private void actionWhenBluetoothReachStateOn() {
        String header = "actionWhenBluetoothReachStateOn(): ";
        if (mAutoOn != null) {
            mAutoOn.notifyBluetoothOn();
        }

        if (!mEnable) {
            Log.d(TAG, header + "mEnable is false. Turning off");
            onToBleOn();
            return;
        }

        if (mPendingUser != null) {
            if (!Flags.systemServerDirectSwitch()) {
                mHandler.removeCallbacksAndMessages(ON_SWITCH_USER_TOKEN);
            }
            if (!mPendingUser.equals(mUser)) {
                Log.d(TAG, header + "Resume user switch to " + mPendingUser);
                if (Flags.systemServerDirectSwitch()) {
                    onToBleOn();
                } else {
                    prepareUserSwitch(mPendingUser);
                }
                return;
            }
            Log.d(TAG, header + "Already on correct user. Discard user switch");
            mPendingUser = null;
        }

        sendBluetoothOnCallback();
    }

    private void actionWhenBluetoothReachStateOff(int prevState) {
        String header = "actionWhenBluetoothReachStateOff(): ";

        if (mPendingUser != null && Flags.systemServerDirectSwitch()) {
            Log.d(TAG, header + "Resume user switch to " + mPendingUser);
            UserHandle nextUser = mPendingUser;
            mPendingUser = null;
            executeUserSwitch(nextUser);
            return;
        }
        if (mPendingUser != null && !Flags.systemServerDirectSwitch()) {
            Log.d(TAG, header + "Resume user switch to " + mPendingUser);
            mHandler.removeCallbacksAndMessages(ON_SWITCH_USER_TOKEN);
            // Once everything is done finish the user switch if present
            executeUserSwitch(mPendingUser);
            return;
        }

        if (prevState != State.BLE_TURNING_OFF) {
            Log.d(TAG, header + "Invalid previous state: " + State.$.toString(prevState));
            return;
        }
        if (mHandler.hasMessages(MESSAGE_RESTART_BLUETOOTH_SERVICE)) {
            Log.d(TAG, header + "Skipped since a restart is already scheduled");
            return;
        }
        if (!mBleAppManager.isBleAppPresent()) {
            Log.d(TAG, header + "There is no BLE app registered, staying OFF");
            return;
        }
        if (AirplaneModeListener.isOn()) {
            Log.d(TAG, header + "Airplane mode forces Bluetooth to stay OFF. Clearing BLE apps");
            mBleAppManager.clearBleApps();
            return;
        }
        Log.d(TAG, header + "Restarting to BLE_ON due to " + mBleAppManager);
        sendEnableMsg(
                false, ENABLE_DISABLE_REASON_APPLICATION_REQUEST, mContext.getPackageName(), true);
    }

    boolean waitForState(int... states) {
        Log.v(TAG, "Waiting " + STATE_TIMEOUT + " for state: " + Arrays.toString(states));
        return mState.waitForState(STATE_TIMEOUT, states);
    }

    private void sendDisableMsg(int reason) {
        sendDisableMsg(reason, mContext.getPackageName());
    }

    private void sendDisableMsg(int reason, String packageName) {
        mActiveLogs.add(reason, false, packageName, false);
        mHandler.removeMessages(MESSAGE_RESTART_BLUETOOTH_SERVICE);

        mEnable = false;

        if (mState.oneOf(State.ON)) {
            Log.d(TAG, "Disable - Initiate shutdown");
            onToBleOn();
        } else if (!mBleAppManager.isBleAppPresent() && isBinding()) {
            Log.d(TAG, "Disable - Cancel binding");
            mContext.unbindService(mConnection);
            mHandler.removeMessages(MESSAGE_TIMEOUT_BIND);
            bluetoothStateChangeHandler(State.BLE_TURNING_ON, State.OFF);
            mHandler.removeMessages(MESSAGE_BLUETOOTH_SERVICE_CONNECTED);
        } else if (!mBleAppManager.isBleAppPresent() && mState.oneOf(State.BLE_TURNING_ON)) {
            Log.d(TAG, "Disable - Cancel BLE_TURNING_ON");
            bluetoothStateChangeHandler(State.BLE_TURNING_ON, State.OFF);
        } else {
            Log.d(TAG, "Disable - Nothing to do. `mEnable` set to false. mState=" + mState);
        }
    }

    private void sendEnableMsg(boolean quietMode, int reason) {
        sendEnableMsg(quietMode, reason, mContext.getPackageName());
    }

    private void sendEnableMsg(boolean quietMode, int reason, String packageName) {
        sendEnableMsg(quietMode, reason, packageName, false);
    }

    private void sendEnableMsg(boolean quietEnable, int reason, String packageName, boolean isBle) {
        mActiveLogs.add(reason, true, packageName, isBle);
        String logHeader = "sendEnableMsg(" + quietEnable + ", " + isBle + "): ";
        if (mShutdownInProgress) {
            Log.d(TAG, logHeader + "Skip Bluetooth Enable in device shutdown process");
            return;
        }

        mHandler.removeMessages(MESSAGE_RESTART_BLUETOOTH_SERVICE);
        mEnable = true;

        if (!isBle) {
            setBluetoothPersistedState(BLUETOOTH_ON_BLUETOOTH);
        }

        if (mState.oneOf(State.BLE_TURNING_ON, State.TURNING_ON, State.ON)) {
            Log.i(TAG, logHeader + "Already enabled. Current state=" + mState);
            return;
        }

        if (mState.oneOf(State.BLE_ON) && isBle) {
            Log.i(TAG, logHeader + "Already in BLE_ON while being requested to go to BLE_ON");
            return;
        }

        if (mState.oneOf(State.BLE_ON)) {
            Log.i(TAG, logHeader + "Initiate transition from State.BLE_ON to State.ON");
            bleOnToOn();
            return;
        }

        mQuietEnable = quietEnable;
        handleEnable();
    }

    private void addCrashLog() {
        synchronized (mCrashTimestamps) {
            if (mCrashTimestamps.size() == CRASH_LOG_MAX_SIZE) {
                mCrashTimestamps.remove(0);
            }
            mCrashTimestamps.add(System.currentTimeMillis());
            mCrashes++;
        }
    }

    private void recoverBluetoothServiceFromError(boolean clearBle) {
        Log.e(TAG, "recoverBluetoothServiceFromError");
        boolean repeatAirplaneRunnable = false;

        // 0 means we are matching unset `what` since we are using a token instead
        if (mHandler.hasMessages(0, ON_AIRPLANE_MODE_CHANGED_TOKEN)) {
            mHandler.removeCallbacksAndMessages(ON_AIRPLANE_MODE_CHANGED_TOKEN);
            repeatAirplaneRunnable = true;
        }

        if (mAdapter != null) {
            try {
                mAdapter.unregisterCallback(mBluetoothCallback);
            } catch (RemoteException e) {
                Log.e(TAG, "Unable to unregister", e);
            }
        }

        Log.d(TAG, "Force sleep 500 ms for recovering from error");
        SystemClock.sleep(500);

        // disable
        mActiveLogs.add(ENABLE_DISABLE_REASON_START_ERROR, false);
        onToBleOn();

        waitForState(State.OFF);

        sendBluetoothServiceDownCallback();

        resetAdapter();

        mHandler.removeMessages(MESSAGE_BLUETOOTH_STATE_CHANGE);
        mState.set(State.OFF);

        if (clearBle) {
            mBleAppManager.clearBleApps();
        }

        prepareRestartMessage(false);

        if (repeatAirplaneRunnable) {
            onAirplaneModeChanged(mAirplaneModeController.isOnForUser());
        }
    }

    void dump(FileDescriptor fd, PrintWriter writer, String[] args) {
        String errorMsg = null;

        writer.println("Bluetooth Status:");
        writer.println("  State:         " + mState);
        writer.println("  Address:       " + Log.address(mAddress));
        writer.println("  Name:          " + mName);
        writer.println("  Inner app:     " + mBluetoothComponent.getPackageName());
        if (!mState.oneOf(State.OFF)) {
            writer.println("  Uptime:        " + elapsedString(mLastBindingTime, Instant.now()));
        }

        writer.println("");
        mActiveLogs.dump(writer);

        writer.println("");

        writer.println("Bluetooth crashed " + mCrashes + " time" + (mCrashes == 1 ? "" : "s"));
        if (mCrashes == CRASH_LOG_MAX_SIZE) {
            writer.println("(last " + CRASH_LOG_MAX_SIZE + ")");
        }
        for (Long time : mCrashTimestamps) {
            writer.println("  " + Log.timeToStringWithZone(time));
        }

        writer.println("");
        writer.println("Ble app registered: " + mBleAppManager);

        writer.println("");
        writer.println("BluetoothManagerService:");
        writer.println("  mEnable:" + mEnable);
        writer.println("  mQuietEnable:" + mQuietEnable);
        writer.println("  mEnableExternal:" + mEnableExternal);
        writer.println("  mQuietEnableExternal:" + mQuietEnableExternal);

        writer.println("");

        writer.flush();

        if (mAdapter == null) {
            errorMsg = "Bluetooth Service not connected";
        } else {
            if (args.length == 0) {
                // Add arg to produce output
                args = new String[1];
                args[0] = "--print";
            }

            try {
                mAdapter.getAdapterBinder().asBinder().dumpAsync(fd, args);
            } catch (RemoteException re) {
                errorMsg = "RemoteException while dumping Bluetooth Service";
            }
        }
        if (errorMsg != null) {
            writer.println(errorMsg);
        }
    }

    static @NonNull Bundle getTempAllowlistBroadcastOptions() {
        final long duration = 10_000;
        final BroadcastOptions bOptions = BroadcastOptions.makeBasic();
        bOptions.setTemporaryAppAllowlist(
                duration,
                TEMPORARY_ALLOW_LIST_TYPE_FOREGROUND_SERVICE_ALLOWED,
                PowerExemptionManager.REASON_BLUETOOTH_BROADCAST,
                "");
        return bOptions.toBundle();
    }

    private final boolean mConfigAllowAutoOn;

    private void autoOnSetupTimer() {
        if (mAutoOn == null) {
            Log.v(TAG, "AutoOn is not supported in current config. Nothing to do");
            return;
        }
        mAutoOn.resetAutoOnTimer();
    }

    boolean isAutoOnSupported() {
        return mAutoOn != null && mAutoOn.isSupported();
    }

    boolean isAutoOnEnabled() {
        if (mAutoOn == null) {
            throw new IllegalStateException("AutoOn is not supported in current config");
        }
        return mAutoOn.isEnabled();
    }

    void setAutoOnEnabled(boolean status) {
        if (mAutoOn == null) {
            throw new IllegalStateException("AutoOn is not supported in current config");
        }
        mAutoOn.setEnabled(status);
    }

    /**
     * In case of a Bluetooth crash, mark it's enabled components as non longer available to trigger
     * the PACKAGE_CHANGED intent. This should not be needed in a normal shutdown as the Bluetooth
     * clean its components on its own
     */
    private void disableBluetoothComponents() {
        String packageName = mBluetoothComponent.getPackageName();
        PackageManager pm = mContext.getPackageManager();
        PackageInfo packageInfo;

        try {
            packageInfo =
                    pm.getPackageInfo(
                            packageName,
                            PackageManager.GET_SERVICES
                                    | PackageManager.GET_ACTIVITIES
                                    | PackageManager.GET_RECEIVERS
                                    | PackageManager.GET_PROVIDERS);
        } catch (PackageManager.NameNotFoundException e) {
            Log.e(TAG, "Package not found: " + packageName, e);
            return;
        }

        disableComponents(
                pm, packageInfo.activities, packageName, SharingRestriction.getOppActivities());
        disableComponents(pm, packageInfo.services, packageName, Collections.emptySet());
        disableComponents(pm, packageInfo.receivers, packageName, Collections.emptySet());
        disableComponents(pm, packageInfo.providers, packageName, Collections.emptySet());
    }

    private static <T extends android.content.pm.ComponentInfo> void disableComponents(
            PackageManager pm, T[] components, String packageName, Set<String> componentsToKeep) {
        if (components == null) {
            return;
        }

        Arrays.stream(components)
                // Only disable components that are supposed to be disabled in the Manifest.
                .filter(componentInfo -> !componentInfo.enabled)
                .filter(componentInfo -> !componentsToKeep.contains(componentInfo.name))
                .map(componentInfo -> new ComponentName(packageName, componentInfo.name))
                .forEach(
                        componentName -> {
                            pm.setComponentEnabledSetting(
                                    componentName,
                                    PackageManager.COMPONENT_ENABLED_STATE_DISABLED,
                                    PackageManager.DONT_KILL_APP);
                            Log.i(TAG, "Disabled component: " + componentName.flattenToString());
                        });
    }

    private Unit post(Runnable r) {
        sendMessage(Message.obtain(mHandler, r));
        return Unit.INSTANCE;
    }

    private void postDelayed(Runnable r, Duration delay) {
        sendMessageDelayed(Message.obtain(mHandler, r), delay);
    }

    private void postDelayed(Runnable r, Object token, Duration delay) {
        Message msg = Message.obtain(mHandler, r);
        msg.obj = token;
        sendMessageDelayed(msg, delay);
    }

    private void sendMessage(int what) {
        sendMessage(mHandler.obtainMessage(what));
    }

    private void sendMessage(int what, Object obj) {
        sendMessage(mHandler.obtainMessage(what, obj));
    }

    private void sendMessage(int what, int arg1, int arg2) {
        sendMessage(mHandler.obtainMessage(what, arg1, arg2));
    }

    private void sendMessageDelayed(int what, Duration delay) {
        sendMessageDelayed(mHandler.obtainMessage(what), delay);
    }

    private void sendMessage(Message msg) {
        sendMessageDelayed(msg, Duration.ZERO);
    }

    private void sendMessageDelayed(Message msg, Duration delay) {
        mHandler.sendMessageAtTime(msg, mTimeProvider.uptimeMillis() + delay.toMillis());
    }
}
