/*
 * Copyright (C) 2012 The Android Open Source Project
 * Copyright (C) 2016-2017 The Linux Foundation
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

package com.android.bluetooth.btservice;

import static android.Manifest.permission.BLUETOOTH_CONNECT;
import static android.Manifest.permission.BLUETOOTH_PRIVILEGED;
import static android.Manifest.permission.BLUETOOTH_SCAN;
import static android.bluetooth.BluetoothAdapter.SCAN_MODE_CONNECTABLE;
import static android.bluetooth.BluetoothAdapter.SCAN_MODE_CONNECTABLE_DISCOVERABLE;
import static android.bluetooth.BluetoothAdapter.SCAN_MODE_NONE;
import static android.bluetooth.BluetoothAdapter.nameForState;
import static android.bluetooth.BluetoothDevice.BATTERY_LEVEL_UNKNOWN;
import static android.bluetooth.BluetoothDevice.BOND_BONDED;
import static android.bluetooth.BluetoothDevice.BOND_BONDING;
import static android.bluetooth.BluetoothDevice.TRANSPORT_AUTO;
import static android.bluetooth.BluetoothDevice.TRANSPORT_LE;
import static android.bluetooth.BluetoothProfile.CONNECTION_POLICY_ALLOWED;
import static android.bluetooth.BluetoothProfile.CONNECTION_POLICY_FORBIDDEN;
import static android.bluetooth.BluetoothProfile.CONNECTION_POLICY_UNKNOWN;
import static android.bluetooth.BluetoothProfile.STATE_CONNECTED;
import static android.bluetooth.BluetoothProfile.STATE_CONNECTING;
import static android.bluetooth.BluetoothProfile.getProfileName;
import static android.bluetooth.BluetoothUtils.RemoteExceptionIgnoringConsumer;
import static android.bluetooth.BluetoothUtils.logRemoteException;
import static android.bluetooth.IBluetoothLeAudio.LE_AUDIO_GROUP_ID_INVALID;

import static com.android.bluetooth.Util.isPackageNameAccurate;
import static com.android.bluetooth.Utils.callbackToApp;
import static com.android.bluetooth.Utils.isDualModeAudioEnabled;

import static java.util.Objects.requireNonNull;
import static java.util.Objects.requireNonNullElse;
import static java.util.Objects.requireNonNullElseGet;

import android.annotation.NonNull;
import android.annotation.Nullable;
import android.annotation.RequiresPermission;
import android.app.Activity;
import android.app.AppOpsManager;
import android.app.BroadcastOptions;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.app.Service;
import android.app.admin.DevicePolicyManager;
import android.bluetooth.BluetoothA2dp;
import android.bluetooth.BluetoothActivityEnergyInfo;
import android.bluetooth.BluetoothAdapter;
import android.bluetooth.BluetoothAdapter.ActiveDeviceProfile;
import android.bluetooth.BluetoothAdapter.ActiveDeviceUse;
import android.bluetooth.BluetoothClass;
import android.bluetooth.BluetoothDevice;
import android.bluetooth.BluetoothDevice.BluetoothAddress;
import android.bluetooth.BluetoothFrameworkInitializer;
import android.bluetooth.BluetoothLeAudio;
import android.bluetooth.BluetoothManager;
import android.bluetooth.BluetoothMap;
import android.bluetooth.BluetoothProfile;
import android.bluetooth.BluetoothProtoEnums;
import android.bluetooth.BluetoothQualityReport;
import android.bluetooth.BluetoothSap;
import android.bluetooth.BluetoothServerSocket;
import android.bluetooth.BluetoothSinkAudioPolicy;
import android.bluetooth.BluetoothSocket;
import android.bluetooth.BluetoothStatusCodes;
import android.bluetooth.BluetoothUtils;
import android.bluetooth.BluetoothUuid;
import android.bluetooth.BondStatus;
import android.bluetooth.BufferConstraints;
import android.bluetooth.EncryptionStatus;
import android.bluetooth.GattOffloadCapabilities;
import android.bluetooth.IBluetoothCallback;
import android.bluetooth.IBluetoothConnectionCallback;
import android.bluetooth.IBluetoothMetadataListener;
import android.bluetooth.IBluetoothOobDataCallback;
import android.bluetooth.IBluetoothPreferredAudioProfilesCallback;
import android.bluetooth.IBluetoothProfileCallback;
import android.bluetooth.IBluetoothQualityReportReadyCallback;
import android.bluetooth.IncomingRfcommSocketInfo;
import android.bluetooth.OobData;
import android.bluetooth.State;
import android.bluetooth.UidTraffic;
import android.companion.CompanionDeviceManager;
import android.content.AttributionSource;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.hardware.devicestate.DeviceStateManager;
import android.net.MacAddress;
import android.os.AsyncTask;
import android.os.BatteryStatsManager;
import android.os.Binder;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.IBinder;
import android.os.Looper;
import android.os.Message;
import android.os.ParcelUuid;
import android.os.Parcelable;
import android.os.PowerManager;
import android.os.RemoteCallbackList;
import android.os.RemoteException;
import android.os.SystemClock;
import android.os.SystemProperties;
import android.os.UserHandle;
import android.os.UserManager;
import android.provider.DeviceConfig;
import android.sysprop.BluetoothProperties;
import android.text.TextUtils;
import android.util.Log;
import android.util.Pair;
import android.util.SparseArray;

import com.android.bluetooth.BluetoothEventLogger;
import com.android.bluetooth.BluetoothStatsLog;
import com.android.bluetooth.R;
import com.android.bluetooth.Util;
import com.android.bluetooth.Utils;
import com.android.bluetooth.a2dp.A2dpService;
import com.android.bluetooth.a2dpsink.A2dpSinkService;
import com.android.bluetooth.avrcp.AvrcpTargetService;
import com.android.bluetooth.avrcpcontroller.AvrcpControllerService;
import com.android.bluetooth.bas.BatteryService;
import com.android.bluetooth.bass_client.BassClientService;
import com.android.bluetooth.btservice.InteropUtil.InteropFeature;
import com.android.bluetooth.btservice.RemoteDevices.DeviceProperties;
import com.android.bluetooth.btservice.bluetoothkeystore.BluetoothKeystoreNativeInterface;
import com.android.bluetooth.btservice.bluetoothkeystore.BluetoothKeystoreService;
import com.android.bluetooth.csip.CsipSetCoordinatorService;
import com.android.bluetooth.flags.Flags;
import com.android.bluetooth.gatt.AdvertiseManagerNativeInterface;
import com.android.bluetooth.gatt.DistanceMeasurementNativeInterface;
import com.android.bluetooth.gatt.GattNativeInterface;
import com.android.bluetooth.gatt.GattService;
import com.android.bluetooth.hap.HapClientService;
import com.android.bluetooth.hearingaid.HearingAidService;
import com.android.bluetooth.hfp.HeadsetService;
import com.android.bluetooth.hfpclient.HeadsetClientService;
import com.android.bluetooth.hid.HidDeviceService;
import com.android.bluetooth.hid.HidHostService;
import com.android.bluetooth.le_audio.LeAudioBroadcast;
import com.android.bluetooth.le_audio.LeAudioPeripheralService;
import com.android.bluetooth.le_audio.LeAudioService;
import com.android.bluetooth.le_audio.LeAudioTmapService;
import com.android.bluetooth.le_scan.PeriodicScanNativeInterface;
import com.android.bluetooth.le_scan.ScanController;
import com.android.bluetooth.le_scan.ScanNativeInterface;
import com.android.bluetooth.le_scan.ScanUtil;
import com.android.bluetooth.map.BluetoothMapService;
import com.android.bluetooth.mapclient.MapClientService;
import com.android.bluetooth.mcp.McpClientService;
import com.android.bluetooth.mcp.McpService;
import com.android.bluetooth.media_audio.sink.MediaAudioServer;
import com.android.bluetooth.metrics.MetricsLogger;
import com.android.bluetooth.notification.NotificationHelperService;
import com.android.bluetooth.opp.BluetoothOppService;
import com.android.bluetooth.pan.PanService;
import com.android.bluetooth.pbap.BluetoothPbapService;
import com.android.bluetooth.pbapclient.PbapClientService;
import com.android.bluetooth.profile.ConnectableProfile;
import com.android.bluetooth.profile.ProfileService;
import com.android.bluetooth.sap.SapService;
import com.android.bluetooth.sdp.SdpManager;
import com.android.bluetooth.sdp.SdpManagerNativeInterface;
import com.android.bluetooth.storage.BluetoothStorageManager;
import com.android.bluetooth.tbs.TbsService;
import com.android.bluetooth.telephony.BluetoothInCallService;
import com.android.bluetooth.util.DeviceConfigUtils;
import com.android.bluetooth.util.Text;
import com.android.bluetooth.vap.VapServerService;
import com.android.bluetooth.vc.VolumeControlService;
import com.android.bluetooth.vcp.VcpRendererService;
import com.android.internal.annotations.GuardedBy;
import com.android.internal.annotations.VisibleForTesting;
import com.android.modules.utils.BackgroundThread;
import com.android.modules.utils.BytesMatcher;

import libcore.util.SneakyThrow;

import java.io.File;
import java.io.FileDescriptor;
import java.io.IOException;
import java.io.PrintWriter;
import java.nio.file.Paths;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Executor;
import java.util.concurrent.FutureTask;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.function.Predicate;
import java.util.function.Supplier;
import java.util.regex.Pattern;
import java.util.stream.Stream;

public class AdapterService extends Service {
    private static final String TAG = Util.BT_PREFIX + AdapterService.class.getSimpleName();

    private static final int MESSAGE_PROFILE_SERVICE_STATE_CHANGED = 1;
    private static final int MESSAGE_PROFILE_SERVICE_REGISTERED = 2;
    private static final int MESSAGE_PROFILE_SERVICE_UNREGISTERED = 3;
    private static final int MESSAGE_PREFERRED_AUDIO_PROFILES_AUDIO_FRAMEWORK_TIMEOUT = 4;

    private static final int CONTROLLER_ENERGY_UPDATE_TIMEOUT_MILLIS = 100;

    private static final Duration PENDING_SOCKET_HANDOFF_TIMEOUT = Duration.ofMinutes(1);
    private static final Duration GENERATE_LOCAL_OOB_DATA_TIMEOUT = Duration.ofSeconds(2);
    private static final Duration PREFERRED_AUDIO_PROFILE_CHANGE_TIMEOUT = Duration.ofSeconds(10);

    static final String PHONEBOOK_ACCESS_PERMISSION_PREFERENCE_FILE = "phonebook_access_permission";
    static final String MESSAGE_ACCESS_PERMISSION_PREFERENCE_FILE = "message_access_permission";
    static final String SIM_ACCESS_PERMISSION_PREFERENCE_FILE = "sim_access_permission";

    static final String LE_AUDIO_ALLOW_LIST_EXTEND = "persist.bluetooth.leaudio.allow_list_extend";

    // The Bluetooth Device Name can be up to 248 bytes (see [Vol 2] Part C, Section 4.3.5).
    static final int BLUETOOTH_NAME_MAX_LENGTH_BYTES = 248;

    private static AdapterService sAdapterService;

    private final Object mEnergyInfoLock = new Object();
    private final SparseArray<UidTraffic> mUidTraffic = new SparseArray<>();

    private final Map<Integer, ProfileService> mStartedProfiles = new HashMap<>();
    private final List<ProfileService> mRegisteredProfiles = new ArrayList<>();
    private final List<ProfileService> mRunningProfiles = new ArrayList<>();

    private final Map<CallingPackage, DiscoveringPackageInfo> mDiscoveringPackages = new HashMap<>();

    // Used to broadcast discovered devices to new packages starting discovery.
    @GuardedBy("mDiscoveringPackages")
    private final Set<BluetoothDevice> mDiscoveredDevices = new HashSet<>();

    private final Map<BluetoothDevice, RemoteCallbackList<IBluetoothMetadataListener>>
            mMetadataListeners = new HashMap<>();

    // Map<groupId, PendingAudioProfilePreferenceRequest>
    @GuardedBy("mCsipGroupsPendingAudioProfileChanges")
    private final Map<Integer, PendingAudioProfilePreferenceRequest>
            mCsipGroupsPendingAudioProfileChanges = new HashMap<>();

    private final Map<BluetoothStateCallback, Executor> mLocalCallbacks = new ConcurrentHashMap<>();
    private final Map<UUID, RfcommListenerData> mBluetoothServerSockets = new ConcurrentHashMap<>();
    private final ArrayDeque<IBluetoothOobDataCallback> mOobDataCallbackQueue = new ArrayDeque<>();

    private final RemoteCallbackList<IBluetoothPreferredAudioProfilesCallback>
            mPreferredAudioProfilesCallbacks = new RemoteCallbackList<>();
    private final RemoteCallbackList<IBluetoothQualityReportReadyCallback>
            mBluetoothQualityReportReadyCallbacks = new RemoteCallbackList<>();
    private final RemoteCallbackList<IBluetoothCallback> mSystemServerCallbacks =
            new RemoteCallbackList<>();
    private final RemoteCallbackList<IBluetoothConnectionCallback> mBluetoothConnectionCallbacks =
            new RemoteCallbackList<>();

    private final BluetoothEventLogger mScanModeChanges =
            new BluetoothEventLogger(10, "Scan Mode Changes");

    private final DeviceConfigListener mDeviceConfigListener = new DeviceConfigListener();

    private final BluetoothHciVendorSpecificDispatcher mBluetoothHciVendorSpecificDispatcher =
            new BluetoothHciVendorSpecificDispatcher();

    private final PowerManager.WakeLockStateListener mWakeLockListener =
            new PowerManager.WakeLockStateListener() {
                @Override
                public void onStateChanged(boolean enabled) {
                    // Skip isPresent as the listener is only registered when AdapterSuspend exist
                    mAdapterSuspend.get().updateWakeLockState(enabled);
                }
            };

    private final Looper mLooper;
    private final AdapterState mAdapterState;
    private final AdapterServiceHandler mHandler;
    private final AdapterNativeInterface mNativeInterface;
    private final BluetoothKeystoreService mBluetoothKeystoreService;
    private final BluetoothQualityReportNativeInterface mBluetoothQualityReportNativeInterface;
    private final BluetoothHciVendorSpecificNativeInterface
            mBluetoothHciVendorSpecificNativeInterface;
    private final ScanNativeInterface mScanNativeInterface;
    private final PeriodicScanNativeInterface mPeriodicScanNativeInterface;
    private final GattNativeInterface mGattNativeInterface;
    private final AdvertiseManagerNativeInterface mAdvertiseManagerNativeInterface;
    private final DistanceMeasurementNativeInterface mDistanceMeasurementNativeInterface;
    private final SdpManagerNativeInterface mSdpManagerNativeInterface;
    private final SilenceDeviceManager mSilenceDeviceManager;
    private final BluetoothStorageManager mStorage;

    /**
     * Predicate that tests if the given {@link BluetoothDevice} is well-known to be used for
     * physical location.
     */
    private final Predicate<BluetoothDevice> mLocationDenylistPredicate;

    // Only available on devices that have any of the various media or audio sink profile roles
    private Optional<MediaAudioServer> mMediaAudioServer = Optional.empty();

    private boolean mIsMediaProfileConnected;

    @GuardedBy("mEnergyInfoLock")
    private Instant mLastActivityReport = Instant.now();

    @GuardedBy("mEnergyInfoLock")
    private int mStackReportedState;

    @GuardedBy("mEnergyInfoLock")
    private long mTxTimeTotalMs;

    @GuardedBy("mEnergyInfoLock")
    private long mRxTimeTotalMs;

    @GuardedBy("mEnergyInfoLock")
    private long mIdleTimeTotalMs;

    @GuardedBy("mEnergyInfoLock")
    private long mEnergyUsedTotalVoltAmpSecMicro;

    private final Set<String> mLeAudioAllowDevices = ConcurrentHashMap.newKeySet();

    /* List of pairs of gatt clients which controls AutoActiveMode on the device.*/
    @VisibleForTesting
    final List<Pair<Integer, BluetoothDevice>> mLeGattClientsControllingAutoActiveMode =
            new ArrayList<>();

    private BluetoothAdapter mAdapter;
    private AdapterProperties mAdapterProperties;
    private BondStateMachine mBondStateMachine;
    private RemoteDevices mRemoteDevices;
    private Optional<AdapterSuspend> mAdapterSuspend = Optional.empty();
    private DisplayListener mDisplayListener;

    /* TODO: Consider to remove the search API from this class, if changed to use call-back */
    private Optional<SdpManager> mSdpManager = Optional.empty();

    private boolean mNativeAvailable;
    private boolean mCleaningUp;
    private boolean mQuietMode = false;
    private final Map<String, CallerInfo> mBondAttemptCallerInfo = new ConcurrentHashMap<>();

    private BatteryStatsManager mBatteryStatsManager;
    private PowerManager mPowerManager;
    private PowerManager.WakeLock mWakeLock;
    private UserManager mUserManager;
    private CompanionDeviceManager mCompanionDeviceManager;

    // Phone Policy is not used on all devices and can be empty
    private Optional<PhonePolicy> mPhonePolicy = Optional.empty();

    private ActiveDeviceManager mActiveDeviceManager;
    private CompanionManager mCompanionManager;
    private AppOpsManager mAppOps;

    private BluetoothSocketManagerBinder mBluetoothSocketManagerBinder;

    private GattService mGattService;
    private ScanController mScanController;

    private volatile boolean mTestModeEnabled = false;

    /** Handlers for incoming service calls */
    private final AdapterServiceBinder mAdapterServiceBinder = new AdapterServiceBinder(this);

    private final AdapterBinder mAdapterBinder = new AdapterBinder(this);

    private volatile int mScanMode;

    private boolean mSuspend = false;
    private boolean mScanModeChangedDuringSuspend;
    private String mLocalName; // Set when SystemServer bind to the AdapterService
    private String mScanModeChangedDuringSuspendFrom;
    private int mScanModeAfterSuspend;

    private final Map<BluetoothDevice, Integer> mDisconnectReasons = new ConcurrentHashMap<>();

    // Report ID definition
    public enum BqrQualityReportId {
        QUALITY_REPORT_ID_MONITOR_MODE(0x01),
        QUALITY_REPORT_ID_APPROACH_LSTO(0x02),
        QUALITY_REPORT_ID_A2DP_AUDIO_CHOPPY(0x03),
        QUALITY_REPORT_ID_SCO_VOICE_CHOPPY(0x04),
        QUALITY_REPORT_ID_ROOT_INFLAMMATION(0x05),
        QUALITY_REPORT_ID_CONNECT_FAIL(0x08),
        QUALITY_REPORT_ID_LMP_LL_MESSAGE_TRACE(0x11),
        QUALITY_REPORT_ID_BT_SCHEDULING_TRACE(0x12),
        QUALITY_REPORT_ID_CONTROLLER_DBG_INFO(0x13);

        private final int mValue;

        BqrQualityReportId(int value) {
            mValue = value;
        }

        public int getValue() {
            return mValue;
        }
    }

    // Keep a constructor for ActivityThread.handleCreateService
    AdapterService() {
        this(
                Looper.getMainLooper(),
                new AdapterNativeInterface(),
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                null);
    }

    @VisibleForTesting
    AdapterService(
            Looper looper,
            Context ctx,
            AdapterNativeInterface nativeInterface,
            BluetoothKeystoreNativeInterface bluetoothKeystoreNativeInterface,
            BluetoothQualityReportNativeInterface bluetoothQualityReportNativeInterface,
            BluetoothHciVendorSpecificNativeInterface bluetoothHciVendorSpecificNativeInterface,
            ScanNativeInterface scanNativeInterface,
            PeriodicScanNativeInterface periodicScanNativeInterface,
            GattNativeInterface gattNativeInterface,
            AdvertiseManagerNativeInterface advertiseManagerNativeInterface,
            DistanceMeasurementNativeInterface distanceMeasurementNativeInterface,
            SdpManagerNativeInterface sdpManagerNativeInterface) {
        this(
                looper,
                nativeInterface,
                bluetoothKeystoreNativeInterface,
                bluetoothQualityReportNativeInterface,
                bluetoothHciVendorSpecificNativeInterface,
                scanNativeInterface,
                periodicScanNativeInterface,
                gattNativeInterface,
                advertiseManagerNativeInterface,
                distanceMeasurementNativeInterface,
                sdpManagerNativeInterface);
        attachBaseContext(ctx);
    }

    private AdapterService(
            Looper looper,
            AdapterNativeInterface nativeInterface,
            BluetoothKeystoreNativeInterface bluetoothKeystoreNativeInterface,
            BluetoothQualityReportNativeInterface bluetoothQualityReportNativeInterface,
            BluetoothHciVendorSpecificNativeInterface bluetoothHciVendorSpecificNativeInterface,
            ScanNativeInterface scanNativeInterface,
            PeriodicScanNativeInterface periodicScanNativeInterface,
            GattNativeInterface gattNativeInterface,
            AdvertiseManagerNativeInterface advertiseManagerNativeInterface,
            DistanceMeasurementNativeInterface distanceMeasurementNativeInterface,
            SdpManagerNativeInterface sdpManagerNativeInterface) {
        mLooper = requireNonNull(looper);
        mHandler = new AdapterServiceHandler(mLooper);
        mAdapterState = new AdapterState(this, mLooper);
        mNativeInterface = requireNonNull(nativeInterface);
        mBluetoothKeystoreService = new BluetoothKeystoreService(bluetoothKeystoreNativeInterface);
        var bQRnativeCallback = new BluetoothQualityReportNativeCallback(this);
        mBluetoothQualityReportNativeInterface =
                requireNonNullElseGet(
                        bluetoothQualityReportNativeInterface,
                        () -> new BluetoothQualityReportNativeInterface(bQRnativeCallback));
        mBluetoothHciVendorSpecificNativeInterface =
                requireNonNullElseGet(
                        bluetoothHciVendorSpecificNativeInterface,
                        () ->
                                new BluetoothHciVendorSpecificNativeInterface(
                                        mBluetoothHciVendorSpecificDispatcher));
        mScanNativeInterface = scanNativeInterface;
        mPeriodicScanNativeInterface = periodicScanNativeInterface;
        mGattNativeInterface = gattNativeInterface;
        mAdvertiseManagerNativeInterface = advertiseManagerNativeInterface;
        mDistanceMeasurementNativeInterface = distanceMeasurementNativeInterface;
        mSdpManagerNativeInterface = sdpManagerNativeInterface;
        mSilenceDeviceManager = new SilenceDeviceManager(this, mLooper);
        mStorage = new BluetoothStorageManager(this);
        mLocationDenylistPredicate =
                (device) -> {
                    final MacAddress parsedAddress = MacAddress.fromString(device.getAddress());
                    if (getLocationDenylistMac().test(parsedAddress.toByteArray())) {
                        Log.v(TAG, "Skipping device matching denylist: " + device);
                        return true;
                    }
                    final String name = getRemoteName(device);
                    if (getLocationDenylistName().test(name)) {
                        Log.v(TAG, "Skipping name matching denylist: " + name);
                        return true;
                    }
                    return false;
                };
    }

    <T> T syncPost(Supplier<T> supplier, T defaultValue) {
        Utils.enforceMainLooperIsNotUsed();

        final FutureTask<T> task =
                new FutureTask<>(
                        () -> {
                            if (!isAvailable()) {
                                return defaultValue;
                            }
                            return supplier.get();
                        });
        if (!mHandler.post(task)) {
            Log.w(TAG, "Failed to post task\n" + Log.getStackTraceString(new Throwable()));
            return defaultValue;
        }
        try {
            // Timeout is longer than ANR, to help debugging in case of unusual slowness.
            // Most likely, any method calling syncPost should be done in under 1 seconds
            return task.get(10, TimeUnit.SECONDS);
        } catch (TimeoutException | InterruptedException e) {
            SneakyThrow.sneakyThrow(e);
        } catch (ExecutionException e) {
            SneakyThrow.sneakyThrow(e.getCause());
        }
        return defaultValue;
    }

    @Deprecated // Do not expand this method usage and use injection pattern when needed.
    public static synchronized AdapterService deprecatedGetAdapterService() {
        return sAdapterService;
    }

    private static synchronized void setAdapterService(AdapterService instance) {
        if (instance == null) {
            Log.e(TAG, "setAdapterService(): Instance is null");
            return;
        }
        Log.d(TAG, "setAdapterService(): Set service to " + instance);
        sAdapterService = instance;
    }

    private static synchronized void clearAdapterService(AdapterService instance) {
        if (sAdapterService == instance) {
            Log.d(TAG, "clearAdapterService(): This adapter was cleared " + instance);
            sAdapterService = null;
        } else {
            Log.d(
                    TAG,
                    "clearAdapterService(): Incorrect cleared adapter."
                            + (" Instance=" + instance)
                            + (" vs sAdapterService=" + sAdapterService));
        }
    }

    class AdapterServiceHandler extends Handler {
        AdapterServiceHandler(Looper looper) {
            super(looper);
        }

        @Override
        public void handleMessage(Message msg) {
            var header = "handleMessage(): ";
            switch (msg.what) {
                case MESSAGE_PROFILE_SERVICE_STATE_CHANGED -> {
                    var profile = (ProfileService) msg.obj;
                    Log.v(TAG, header + "MESSAGE_PROFILE_SERVICE_STATE_CHANGED for " + profile);
                    processProfileServiceStateChanged(profile, msg.arg1);
                }
                case MESSAGE_PROFILE_SERVICE_REGISTERED -> {
                    var profile = (ProfileService) msg.obj;
                    Log.v(TAG, header + "MESSAGE_PROFILE_SERVICE_REGISTERED for " + profile);
                    registerProfileService(profile);
                }
                case MESSAGE_PROFILE_SERVICE_UNREGISTERED -> {
                    var profile = (ProfileService) msg.obj;
                    Log.v(TAG, header + "MESSAGE_PROFILE_SERVICE_UNREGISTERED for " + profile);
                    unregisterProfileService(profile);
                }
                case MESSAGE_PREFERRED_AUDIO_PROFILES_AUDIO_FRAMEWORK_TIMEOUT -> {
                    Log.e(TAG, header + "MESSAGE_PREFERRED_PROFILE_CHANGE_AUDIO_FRAMEWORK_TIMEOUT");
                    int groupId = (int) msg.obj;

                    synchronized (mCsipGroupsPendingAudioProfileChanges) {
                        removeFromPendingAudioProfileChanges(groupId);
                        PendingAudioProfilePreferenceRequest request =
                                mCsipGroupsPendingAudioProfileChanges.remove(groupId);
                        Log.e(
                                TAG,
                                "Preferred audio profiles change audio framework timeout for "
                                        + ("device " + request.device));
                        sendPreferredAudioProfilesCallbackToApps(
                                request.device,
                                request.preferences,
                                BluetoothStatusCodes.ERROR_TIMEOUT);
                    }
                }
                default -> Log.e(TAG, header + "Unknown message: " + msg.what);
            }
        }

        private void registerProfileService(ProfileService profile) {
            if (mRegisteredProfiles.contains(profile)) {
                Log.e(TAG, profile + " already registered.");
                return;
            }
            mRegisteredProfiles.add(profile);
        }

        private void unregisterProfileService(ProfileService profile) {
            if (!mRegisteredProfiles.contains(profile)) {
                Log.e(TAG, profile + " not registered (UNREGISTER).");
                return;
            }
            mRegisteredProfiles.remove(profile);
        }

        private void processProfileServiceStateChanged(ProfileService profile, int state) {
            switch (state) {
                case State.ON -> {
                    if (!mRegisteredProfiles.contains(profile)) {
                        Log.e(TAG, profile + " not registered (STATE_ON).");
                        return;
                    }
                    if (mRunningProfiles.contains(profile)) {
                        Log.e(TAG, profile + " already running.");
                        return;
                    }
                    mRunningProfiles.add(profile);
                    // TODO(b/228875190): GATT is assumed supported. GATT starting triggers hardware
                    // initialization. Configuring a device without GATT causes start up failures.
                    if (!(profile.getProfileId() == BluetoothProfile.GATT
                                    && !Flags.onlyStartScanDuringBleOn())
                            && mRegisteredProfiles.size() == Config.getSupportedProfiles().length
                            && mRegisteredProfiles.size() == mRunningProfiles.size()) {
                        setScanMode(SCAN_MODE_CONNECTABLE, "processProfileServiceStateChanged");
                        refreshBondedDeviceUuids();
                        mNativeInterface.getAdapterProperty(
                                AbstractionLayer.BT_PROPERTY_DYNAMIC_AUDIO_BUFFER);
                        mAdapterState.sendMessage(AdapterState.BREDR_STARTED);
                        mCompanionManager.loadCompanionInfo();
                    }
                }
                case State.OFF -> {
                    if (!mRegisteredProfiles.contains(profile)) {
                        Log.e(TAG, profile + " not registered (STATE_OFF).");
                        return;
                    }
                    if (!mRunningProfiles.contains(profile)) {
                        Log.e(TAG, profile + " not running.");
                        return;
                    }
                    mRunningProfiles.remove(profile);

                    if (Flags.onlyStartScanDuringBleOn()) {
                        if (mRunningProfiles.size() == 0) {
                            mAdapterState.sendMessage(AdapterState.BREDR_STOPPED);
                        }
                    } else {
                        // TODO(b/228875190): GATT is assumed supported. GATT is expected to be the
                        // only profile available in the "BLE ON" state. If only GATT is left, send
                        // BREDR_STOPPED. If GATT is stopped, deinitialize the hardware.
                        if (mRunningProfiles.size() == 1
                                && mRunningProfiles.get(0).getProfileId()
                                        == BluetoothProfile.GATT) {
                            mAdapterState.sendMessage(AdapterState.BREDR_STOPPED);
                        }
                    }
                }
                default -> Log.e(TAG, "Unhandled profile state: " + state);
            }
        }
    }

    /**
     * Stores information about requests made to the audio framework arising from calls to {@link
     * BluetoothAdapter#setPreferredAudioProfiles(BluetoothDevice, Bundle)}.
     */
    private record PendingAudioProfilePreferenceRequest(
            // The newly requested preferences
            Bundle preferences,
            // Reference counter for how many calls are pending completion in the audio framework
            int numberOfRemainingRequestsToAudioFramework,
            // The device with which the request was made. Used for sending the callback.
            BluetoothDevice device) {}

    @Override
    public void onCreate() {
        super.onCreate();
        Log.d(TAG, "onCreate()");
        // OnCreate must perform the minimum of infallible and mandatory initialization
        // This is the first method call with a context attached
        mUserManager = requireNonNull(getSystemService(UserManager.class));
        mAppOps = requireNonNull(getSystemService(AppOpsManager.class));
        mPowerManager = requireNonNull(getSystemService(PowerManager.class));
        mBatteryStatsManager = requireNonNull(getSystemService(BatteryStatsManager.class));
        mCompanionDeviceManager = requireNonNull(getSystemService(CompanionDeviceManager.class));

        mRemoteDevices = new RemoteDevices(this, mLooper);
        mAdapterProperties = new AdapterProperties(this, mRemoteDevices, mLooper);

        // Media Audio Server is enabled when any of the various sink media or audio profiles are
        // enabled. It allows protocols to register and contribute to our outward MediaSession,
        // which in turn allows Media clients to interact with Bluetooth media as if it was any
        // other media application
        if (Flags.mediaAudioServer() && MediaAudioServer.isEnabled()) {
            mMediaAudioServer = Optional.of(new MediaAudioServer(this));
        }

        setAdapterService(this);
    }

    @Override
    public IBinder onBind(Intent intent) {
        Log.d(TAG, "onBind()");
        mLocalName = intent.getStringExtra(BluetoothAdapter.EXTRA_LOCAL_NAME);
        return mAdapterBinder;
    }

    @Override
    public boolean onUnbind(Intent intent) {
        Log.d(TAG, "onUnbind()");
        return super.onUnbind(intent);
    }

    @Override
    public void onDestroy() {
        Log.d(TAG, "onDestroy()");
    }

    public RemoteDevices getRemoteDevices() {
        return mRemoteDevices;
    }

    public Optional<SdpManagerNativeInterface> getSdpManagerNativeInterface() {
        return mSdpManager.map(SdpManager::getNativeInterface);
    }

    public SilenceDeviceManager getSilenceDeviceManager() {
        return mSilenceDeviceManager;
    }

    AdapterNativeInterface getNative() {
        return mNativeInterface;
    }

    AdapterServiceHandler getHandler() {
        return mHandler;
    }

    List<BluetoothDevice> getMostRecentlyConnectedDevices() {
        return mStorage.getMostRecentlyConnectedDevices();
    }

    void setActiveAudioPolicy(BluetoothDevice device, int policy) {
        mStorage.setActiveAudioPolicy(device, policy);
    }

    int getActiveAudioPolicy(BluetoothDevice device) {
        return mStorage.getActiveAudioPolicy(device);
    }

    void setMicrophonePreferredForCalls(BluetoothDevice device, boolean enabled) {
        mStorage.setMicrophonePreferredForCalls(device, enabled);
    }

    boolean isMicrophonePreferredForCalls(BluetoothDevice device) {
        return mStorage.isMicrophonePreferredForCalls(device);
    }

    public AdapterProperties getAdapterProperties() {
        return mAdapterProperties;
    }

    Map<BluetoothDevice, RemoteCallbackList<IBluetoothMetadataListener>> getMetadataListeners() {
        return mMetadataListeners;
    }

    public Optional<MediaAudioServer> getMediaAudioServer() {
        return mMediaAudioServer;
    }

    Optional<PhonePolicy> getPhonePolicy() {
        return mPhonePolicy;
    }

    BondStateMachine getBondStateMachine() {
        return mBondStateMachine;
    }

    CompanionDeviceManager getCompanionDeviceManager() {
        return mCompanionDeviceManager;
    }

    BluetoothSocketManagerBinder getBluetoothSocketManagerBinder() {
        return mBluetoothSocketManagerBinder;
    }

    RemoteCallbackList<IBluetoothConnectionCallback> getBluetoothConnectionCallbacks() {
        return mBluetoothConnectionCallbacks;
    }

    RemoteCallbackList<IBluetoothPreferredAudioProfilesCallback>
            getPreferredAudioProfilesCallbacks() {
        return mPreferredAudioProfilesCallbacks;
    }

    RemoteCallbackList<IBluetoothQualityReportReadyCallback>
            getBluetoothQualityReportReadyCallbacks() {
        return mBluetoothQualityReportReadyCallbacks;
    }

    BluetoothHciVendorSpecificDispatcher getBluetoothHciVendorSpecificDispatcher() {
        return mBluetoothHciVendorSpecificDispatcher;
    }

    BluetoothHciVendorSpecificNativeInterface getBluetoothHciVendorSpecificNativeInterface() {
        return mBluetoothHciVendorSpecificNativeInterface;
    }

    public Optional<AdapterSuspend> getAdapterSuspend() {
        return mAdapterSuspend;
    }

    public DisplayListener getDisplayListener() {
        return mDisplayListener;
    }

    public Optional<A2dpService> getA2dpService() {
        return getStartedProfile(BluetoothProfile.A2DP, A2dpService.class);
    }

    public Optional<A2dpSinkService> getA2dpSinkService() {
        return getStartedProfile(BluetoothProfile.A2DP_SINK, A2dpSinkService.class);
    }

    public Optional<AvrcpTargetService> getAvrcpTargetService() {
        return getStartedProfile(BluetoothProfile.AVRCP, AvrcpTargetService.class);
    }

    public Optional<AvrcpControllerService> getAvrcpControllerService() {
        return getStartedProfile(BluetoothProfile.AVRCP_CONTROLLER, AvrcpControllerService.class);
    }

    public Optional<BassClientService> getBassClientService() {
        return getStartedProfile(
                BluetoothProfile.LE_AUDIO_BROADCAST_ASSISTANT, BassClientService.class);
    }

    public Optional<BatteryService> getBatteryService() {
        return getStartedProfile(BluetoothProfile.BATTERY, BatteryService.class);
    }

    public Optional<CsipSetCoordinatorService> getCsipSetCoordinatorService() {
        return getStartedProfile(
                BluetoothProfile.CSIP_SET_COORDINATOR, CsipSetCoordinatorService.class);
    }

    public Optional<HapClientService> getHapClientService() {
        return getStartedProfile(BluetoothProfile.HAP_CLIENT, HapClientService.class);
    }

    public Optional<HeadsetService> getHeadsetService() {
        return getStartedProfile(BluetoothProfile.HEADSET, HeadsetService.class);
    }

    public Optional<HeadsetClientService> getHeadsetClientService() {
        return getStartedProfile(BluetoothProfile.HEADSET_CLIENT, HeadsetClientService.class);
    }

    public Optional<HearingAidService> getHearingAidService() {
        return getStartedProfile(BluetoothProfile.HEARING_AID, HearingAidService.class);
    }

    public Optional<HidDeviceService> getHidDeviceService() {
        return getStartedProfile(BluetoothProfile.HID_DEVICE, HidDeviceService.class);
    }

    public Optional<HidHostService> getHidHostService() {
        return getStartedProfile(BluetoothProfile.HID_HOST, HidHostService.class);
    }

    public Optional<GattService> getGattService() {
        return getStartedProfile(BluetoothProfile.GATT, GattService.class);
    }

    public Optional<LeAudioService> getLeAudioService() {
        return getStartedProfile(BluetoothProfile.LE_AUDIO, LeAudioService.class);
    }

    public Optional<TbsService> getTbsService() {
        return getStartedProfile(BluetoothProfile.LE_CALL_CONTROL, TbsService.class);
    }

    public Optional<BluetoothMapService> getMapService() {
        return getStartedProfile(BluetoothProfile.MAP, BluetoothMapService.class)
                .filter(ProfileService::isAvailable);
    }

    public Optional<MapClientService> getMapClientService() {
        return getStartedProfile(BluetoothProfile.MAP_CLIENT, MapClientService.class)
                .filter(ProfileService::isAvailable);
    }

    public Optional<McpService> getMcpService() {
        return getStartedProfile(BluetoothProfile.MCP_SERVER, McpService.class);
    }

    public Optional<BluetoothOppService> getOppService() {
        return getStartedProfile(BluetoothProfile.OPP, BluetoothOppService.class);
    }

    public Optional<PanService> getPanService() {
        return getStartedProfile(BluetoothProfile.PAN, PanService.class);
    }

    public Optional<BluetoothPbapService> getPbapService() {
        return getStartedProfile(BluetoothProfile.PBAP, BluetoothPbapService.class);
    }

    public Optional<PbapClientService> getPbapClientService() {
        return getStartedProfile(BluetoothProfile.PBAP_CLIENT, PbapClientService.class)
                .filter(ProfileService::isAvailable);
    }

    public Optional<SapService> getSapService() {
        return getStartedProfile(BluetoothProfile.SAP, SapService.class)
                .filter(ProfileService::isAvailable);
    }

    public Optional<VolumeControlService> getVolumeControlService() {
        return getStartedProfile(BluetoothProfile.VOLUME_CONTROL, VolumeControlService.class);
    }

    public Optional<VapServerService> getVapServerService() {
        return getStartedProfile(BluetoothProfile.VAP_SERVER, VapServerService.class);
    }

    public Optional<LeAudioPeripheralService> getLeAudioPeripheralService() {
        return getStartedProfile(
                BluetoothProfile.LE_AUDIO_PERIPHERAL, LeAudioPeripheralService.class);
    }

    public Optional<McpClientService> getMcpClientService() {
        return getStartedProfile(BluetoothProfile.MCP_CLIENT, McpClientService.class);
    }

    public Optional<VcpRendererService> getVcpRendererService() {
        return getStartedProfile(BluetoothProfile.VCP_RENDERER, VcpRendererService.class);
    }

    public Optional<ConnectableProfile> getStartedConnectableProfile(int id) {
        return getStartedProfile(id, ConnectableProfile.class);
    }

    private Stream<ConnectableProfile> getStartedConnectableProfiles() {
        return mStartedProfiles.values().stream()
                .filter(ConnectableProfile.class::isInstance)
                .map(ConnectableProfile.class::cast);
    }

    private <T extends ProfileService> Optional<T> getStartedProfile(int id, Class<T> profile) {
        return getStartedProfile(id).filter(profile::isInstance).map(profile::cast);
    }

    private Optional<ProfileService> getStartedProfile(int id) {
        return Optional.ofNullable(mStartedProfiles.get(id));
    }

    Optional<String> getCallingPackageName(String address) {
        CallerInfo info = mBondAttemptCallerInfo.get(address);
        if (info == null) {
            return Optional.empty();
        }
        return Optional.of(info.callerPackageName());
    }

    /**
     * Initialize AdapterService with necessary configuration parameters and progress AdapterService
     * state from OFF to BLE ON.
     *
     * @param quietMode Enables or disables quiet mode
     * @param hciInstanceName The hci instance name used to bind to the hardware
     */
    synchronized void offToBleOn(boolean quietMode, String hciInstanceName) {
        // Enforce the user restriction for disallowing Bluetooth if it was set.
        if (mUserManager.hasUserRestrictionForUser(
                UserManager.DISALLOW_BLUETOOTH, UserHandle.SYSTEM)) {
            Log.d(TAG, "offToBleOn(): Called when Bluetooth was disallowed");
            return;
        }
        mQuietMode = quietMode;
        // The call to init must be done on the main thread
        mHandler.post(() -> init(hciInstanceName));
        Log.i(TAG, "offToBleOn(quietMode=" + quietMode + ", instance=" + hciInstanceName + ")");

        mAdapterState.sendMessage(AdapterState.BLE_TURN_ON);
    }

    void onToBleOn() {
        Log.d(TAG, "onToBleOn(): Called with mRunningProfiles.size()=" + mRunningProfiles.size());
        mAdapterState.sendMessage(AdapterState.USER_TURN_OFF);
    }

    @VisibleForTesting
    void init(String hciInstanceName) {
        Log.d(TAG, "init(instance=" + hciInstanceName + ")");

        factoryResetIfNeeded();
        mStorage.initialize();

        Config.init(this);
        mDeviceConfigListener.start();

        MetricsLogger.getInstance().init(this, mRemoteDevices);

        clearDiscoveryData();
        mAdapter = requireNonNull(getSystemService(BluetoothManager.class).getAdapter());
        boolean isCommonCriteriaMode =
                requireNonNull(getSystemService(DevicePolicyManager.class))
                        .isCommonCriteriaModeEnabled(null);
        mBluetoothKeystoreService.init(isCommonCriteriaMode);
        mBluetoothKeystoreService.start();
        int configCompareResult = mBluetoothKeystoreService.getCompareResult();

        // Start tracking Binder latency for the bluetooth process.
        BluetoothFrameworkInitializer.initializeBinderCallsStats(getApplicationContext());

        // Android TV doesn't show consent dialogs for just works and encryption only le pairing
        boolean isAtvDevice =
                getApplicationContext()
                        .getPackageManager()
                        .hasSystemFeature(PackageManager.FEATURE_LEANBACK_ONLY);
        if (Util.isInstrumentationTestMode()) {
            Log.w(TAG, "This Bluetooth App is instrumented. ** Skip loading the native **");
        } else {
            Log.d(TAG, "Loading JNI Library");
            System.loadLibrary("bluetooth_jni");
        }
        mNativeInterface.init(
                this,
                mAdapterProperties,
                mUserManager.isGuestUser(),
                isCommonCriteriaMode,
                configCompareResult,
                isAtvDevice,
                hciInstanceName);
        mNativeAvailable = true;
        // Load the name and address
        mNativeInterface.getAdapterProperty(AbstractionLayer.BT_PROPERTY_BDADDR);
        mNativeInterface.getAdapterProperty(AbstractionLayer.BT_PROPERTY_CLASS_OF_DEVICE);

        mBluetoothKeystoreService.initJni();

        mBluetoothQualityReportNativeInterface.init();

        mBluetoothHciVendorSpecificNativeInterface.init();

        mSdpManager = Optional.of(new SdpManager(this, mSdpManagerNativeInterface, mLooper));

        var isAutomotiveDevice = Util.isAutomotive(getApplicationContext());

        /*
         * Phone policy is specific to phone implementations and hence if a device wants to exclude
         * it out then it can be disabled by using the flag below. Phone policy is never used on
         * Android Automotive OS builds, in favor of a policy currently located in
         * CarBluetoothService.
         */
        if (!isAutomotiveDevice && getResources().getBoolean(R.bool.enable_phone_policy)) {
            Log.i(TAG, "Phone policy enabled");
            mPhonePolicy = Optional.of(new PhonePolicy(this, mLooper, mStorage));
        } else {
            Log.i(TAG, "Phone policy disabled");
        }

        mActiveDeviceManager = new ActiveDeviceManager(this, mStorage);
        mActiveDeviceManager.start();

        mCompanionManager = new CompanionManager(this);

        mBluetoothSocketManagerBinder = new BluetoothSocketManagerBinder(this);

        if (Flags.adapterSuspendMgmt()) {
            var disconnectAcl =
                    SystemProperties.getBoolean(
                            AdapterSuspend.BLUETOOTH_SUSPEND_DISCONNECT_ACL, false);
            var scanModeNone =
                    SystemProperties.getBoolean(
                            AdapterSuspend.BLUETOOTH_SUSPEND_SCAN_MODE_NONE, false);
            var stopLeScan =
                    SystemProperties.getBoolean(
                            AdapterSuspend.BLUETOOTH_SUSPEND_STOP_LE_SCAN, false);
            var pauseAdvertisement =
                    SystemProperties.getBoolean(
                            AdapterSuspend.BLUETOOTH_SUSPEND_PAUSE_ADVERTISEMENT, false);
            if (disconnectAcl || scanModeNone || stopLeScan || pauseAdvertisement) {
                mAdapterSuspend =
                        Optional.of(
                                new AdapterSuspend(
                                        this,
                                        mLooper,
                                        getSystemService(DeviceStateManager.class),
                                        disconnectAcl,
                                        scanModeNone,
                                        stopLeScan,
                                        pauseAdvertisement));
            }
        }

        invalidateBluetoothCaches();
        if (Flags.leaudioAllowlistRefactor()) {
            cacheLeAudioAllowlistDevicesFromProp();
        }

        // First call to getSharedPreferences will result in a file read into
        // memory cache. Call it here asynchronously to avoid potential ANR
        // in the future
        new AsyncTask<Void, Void, Void>() {
            @Override
            protected Void doInBackground(Void... params) {
                getSharedPreferences(
                        PHONEBOOK_ACCESS_PERMISSION_PREFERENCE_FILE, Context.MODE_PRIVATE);
                getSharedPreferences(
                        MESSAGE_ACCESS_PERMISSION_PREFERENCE_FILE, Context.MODE_PRIVATE);
                getSharedPreferences(SIM_ACCESS_PERMISSION_PREFERENCE_FILE, Context.MODE_PRIVATE);
                return null;
            }
        }.execute();

        try {
            int systemUiUid =
                    getApplicationContext()
                            .createContextAsUser(UserHandle.SYSTEM, /* flags= */ 0)
                            .getPackageManager()
                            .getPackageUid(
                                    "com.android.systemui", PackageManager.MATCH_SYSTEM_ONLY);

            Utils.setSystemUiUid(systemUiUid);
        } catch (PackageManager.NameNotFoundException e) {
            // Some platforms, such as wearables do not have a system ui.
            Log.w(TAG, "Unable to resolve SystemUI's UID.", e);
        }
        mDisplayListener = new DisplayListener(this, mLooper, mPowerManager);
    }

    private void factoryResetIfNeeded() {
        if (!BluetoothProperties.factory_reset().orElse(false)) {
            return;
        }
        Log.i(TAG, "factoryResetIfNeeded(): Starting");
        BluetoothProperties.factory_reset(false);
        recursivelyDeleteDirectory(getDataDir(), false);
        recursivelyDeleteDirectory(Paths.get("/data/misc/bluedroid/").toFile(), false);
        recursivelyDeleteDirectory(Paths.get("/data/misc/bluetooth/").toFile(), false);
        NotificationHelperService.factoryReset(getContentResolver());
        Log.i(TAG, "factoryResetIfNeeded(): Completed");
    }

    // Clears both the discovery packages and discovered devices list.
    void clearDiscoveryData() {
        synchronized (mDiscoveringPackages) {
            mDiscoveringPackages.clear();

            if (Flags.sendDiscoveredDevToNewPkgs()) {
                mDiscoveredDevices.clear();
            }
        }
    }

    /**
     * Returns true if device discovery is in progress.
     *
     * <p>This is true if either of the following conditions is met:
     *
     * <ul>
     *   <li>The Java layer has initiated discovery (mDiscoveringPackages is not empty).
     *   <li>The native layer has initiated discovery (isNativeDiscovering() is true).
     * </ul>
     *
     * @return true if discovery is in progress, false otherwise.
     */
    boolean isDiscovering() {
        boolean isNativeDiscovering = mAdapterProperties.isNativeDiscovering();
        if (!Flags.ignoreRedundantDiscoveryIfSameState()) {
            return isNativeDiscovering;
        }

        synchronized (mDiscoveringPackages) {
            return isNativeDiscovering || !mDiscoveringPackages.isEmpty();
        }
    }

    private static void invalidateBluetoothCaches() {
        BluetoothAdapter.invalidateGetProfileConnectionStateCache();
        BluetoothAdapter.invalidateIsOffloadedFilteringSupportedCache();
        BluetoothDevice.invalidateBluetoothGetBondStateCache();
        BluetoothAdapter.invalidateGetAdapterConnectionStateCache();
        BluetoothMap.invalidateBluetoothGetConnectionStateCache();
        BluetoothSap.invalidateBluetoothGetConnectionStateCache();
    }

    void cacheLeAudioAllowlistDevicesFromProp() {
        Set<String> newDevices = ConcurrentHashMap.newKeySet();

        List<String> leAudioAllowlistProp = BluetoothProperties.le_audio_allow_list();
        if (leAudioAllowlistProp != null && !leAudioAllowlistProp.isEmpty()) {
            newDevices.addAll(leAudioAllowlistProp);
        }

        String allowlistExtend = SystemProperties.get(LE_AUDIO_ALLOW_LIST_EXTEND, "");
        if (!allowlistExtend.isEmpty()) {
            newDevices.addAll(Arrays.asList(allowlistExtend.split(",")));
        }

        Log.d(TAG, "Le Audio allowlist from sysprop: " + newDevices);

        mLeAudioAllowDevices.clear();
        mLeAudioAllowDevices.addAll(newDevices);
    }

    void bringUpBle() {
        Log.d(TAG, "bleOnProcessStart()");

        if (getResources()
                .getBoolean(R.bool.config_bluetooth_reload_supported_profiles_when_enabled)) {
            Config.init(getApplicationContext());
        }

        // Reset |mRemoteDevices| whenever BLE is turned off then on
        // This is to replace the fact that |mRemoteDevices| was
        // reinitialized in previous code.
        //
        // TODO(apanicke): The reason is unclear but
        // I believe it is to clear the variable every time BLE was
        // turned off then on. The same effect can be achieved by
        // calling cleanup but this may not be necessary at all
        // We should figure out why this is needed later
        mRemoteDevices.reset();
        mAdapterProperties.init();

        Log.d(TAG, "bleOnProcessStart(): Make Bond State Machine");
        mBondStateMachine = new BondStateMachine(this, mLooper, mAdapterProperties, mRemoteDevices);

        mNativeInterface.getCallbacks().init(mBondStateMachine, mRemoteDevices);

        mBatteryStatsManager.reportBleScanReset();
        BluetoothStatsLog.write_non_chained(
                BluetoothStatsLog.BLE_SCAN_STATE_CHANGED,
                -1,
                null,
                BluetoothStatsLog.BLE_SCAN_STATE_CHANGED__STATE__RESET,
                false,
                false,
                false);

        startScanController();

        if (!Flags.onlyStartScanDuringBleOn()) {
            // Note: This segment can be deleted on `Flags.onlyStartScanDuringBleOn()` cleanup
            // TODO(b/228875190): GATT is assumed supported. As a result, we don't respect the
            // configuration sysprop. Configuring a device without GATT, although rare, will cause
            // stack start up errors yielding init loops.
            if (!GattService.isEnabled()) {
                Log.w(TAG, "GATT is not enabled but stack requires it to be. Starting GATT");
            }
            startGattProfileService();
        }
    }

    private void startScanController() {
        Instant start = Instant.now();
        var header = "startScanController(): ";
        Log.i(TAG, header + "Starting…");
        mScanController =
                new ScanController(
                        this,
                        mScanNativeInterface,
                        mPeriodicScanNativeInterface,
                        mBatteryStatsManager,
                        mCompanionDeviceManager);
        mNativeInterface.enable(mLocalName);
        Instant end = Instant.now();
        Log.i(TAG, header + "Completed in " + Duration.between(start, end).toMillis() + "ms");
    }

    private void startGattProfileService() {
        Instant start = Instant.now();
        var header = "startGattProfileService(): ";
        Log.i(TAG, header + "Starting…");
        constructProfile(BluetoothProfile.GATT);
        mStartedProfiles.put(BluetoothProfile.GATT, mGattService);
        addProfile(mGattService);
        mGattService.setAvailable(true);
        onProfileServiceStateChanged(mGattService, State.ON);
        Instant end = Instant.now();
        Log.i(TAG, header + "Completed in " + Duration.between(start, end).toMillis() + "ms");
    }

    void startProfileServices() {
        Log.d(TAG, "startProfileServices()");
        mAdapterProperties.onBluetoothReady();
        final int[] supportedProfiles = Config.getSupportedProfiles();
        if (Flags.onlyStartScanDuringBleOn()) {
            // Scanning is always supported, started separately, and is not a profile service.
            // This will check other profile services.
            if (supportedProfiles.length == 0) {
                setScanMode(SCAN_MODE_CONNECTABLE, "startProfileServices");
                refreshBondedDeviceUuids();
                mAdapterState.sendMessage(AdapterState.BREDR_STARTED);
            } else {
                setAllProfileServiceStates(supportedProfiles, State.ON);
            }
        } else {
            // TODO(b/228875190): GATT is assumed supported. If we support no other profiles then
            // just move on to BREDR_STARTED. Note that configuring GATT to NOT supported will cause
            // adapter initialization failures
            if (supportedProfiles.length == 1 && supportedProfiles[0] == BluetoothProfile.GATT) {
                setScanMode(SCAN_MODE_CONNECTABLE, "startProfileServices");
                refreshBondedDeviceUuids();
                mAdapterState.sendMessage(AdapterState.BREDR_STARTED);
            } else {
                setAllProfileServiceStates(supportedProfiles, State.ON);
            }
        }
    }

    private void setAllProfileServiceStates(int[] profileIds, int state) {
        for (int profileId : profileIds) {
            if (!Flags.onlyStartScanDuringBleOn()) {
                // TODO(b/228875190): GATT is assumed supported and treated differently as part of
                //  the "BLE ON" state, despite GATT not being BLE specific.
                if (profileId == BluetoothProfile.GATT) {
                    continue;
                }
            }
            setProfileServiceState(profileId, state);
        }
    }

    /**
     * Constructs a {@link ProfileService} instance for the given profile ID.
     *
     * <p><b>Note:</b> This method assumes that any dependencies required by the profile being
     * constructed have already been initialized. This relies on the strict startup order defined in
     * {@code Config.PROFILE_SERVICES_AND_FLAGS}.
     */
    private ProfileService constructProfile(int id) {
        return switch (id) {
            case BluetoothProfile.GATT -> {
                mGattService =
                        new GattService(
                                this,
                                mGattNativeInterface,
                                mAdvertiseManagerNativeInterface,
                                mDistanceMeasurementNativeInterface,
                                mCompanionDeviceManager);
                yield mGattService;
            }
            case BluetoothProfile.A2DP ->
                    new A2dpService(this, mStorage, mActiveDeviceManager, mCompanionDeviceManager);
            case BluetoothProfile.A2DP_SINK -> new A2dpSinkService(this);
            case BluetoothProfile.AVRCP_CONTROLLER -> new AvrcpControllerService(this);
            case BluetoothProfile.AVRCP -> new AvrcpTargetService(this, mStorage, mUserManager);
            case BluetoothProfile.BATTERY -> new BatteryService(this);
            case BluetoothProfile.CSIP_SET_COORDINATOR -> new CsipSetCoordinatorService(this);
            case BluetoothProfile.HAP_CLIENT -> new HapClientService(this, mActiveDeviceManager);
            case BluetoothProfile.HEADSET_CLIENT -> new HeadsetClientService(this);
            case BluetoothProfile.HEADSET ->
                    new HeadsetService(this, mStorage, mActiveDeviceManager);
            case BluetoothProfile.HEARING_AID -> new HearingAidService(this, mActiveDeviceManager);
            case BluetoothProfile.HID_DEVICE -> new HidDeviceService(this);
            case BluetoothProfile.HID_HOST -> new HidHostService(this);
            case BluetoothProfile.LE_AUDIO_BROADCAST_ASSISTANT ->
                    new BassClientService(this, mScanController);
            case BluetoothProfile.LE_AUDIO_BROADCAST -> new LeAudioBroadcast(this);
            case BluetoothProfile.LE_AUDIO ->
                    new LeAudioService(this, mStorage, mActiveDeviceManager, mScanController);
            case BluetoothProfile.LE_CALL_CONTROL -> new TbsService(this, mGattService);
            case BluetoothProfile.MAP_CLIENT -> new MapClientService(this);
            case BluetoothProfile.MAP -> new BluetoothMapService(this);
            case BluetoothProfile.MCP_SERVER -> new McpService(this);
            case BluetoothProfile.OPP -> new BluetoothOppService(this);
            case BluetoothProfile.PAN -> new PanService(this, mUserManager);
            case BluetoothProfile.PBAP_CLIENT -> new PbapClientService(this);
            case BluetoothProfile.PBAP ->
                    new BluetoothPbapService(this, getSystemService(NotificationManager.class));
            case BluetoothProfile.SAP -> new SapService(this);
            case BluetoothProfile.VAP_SERVER -> new VapServerService(this);
            case BluetoothProfile.VOLUME_CONTROL -> new VolumeControlService(this);
            case BluetoothProfile.LE_AUDIO_PERIPHERAL -> new LeAudioPeripheralService(this);
            case BluetoothProfile.TMAP_SERVER -> new LeAudioTmapService(this);
            case BluetoothProfile.MCP_CLIENT -> new McpClientService(this);
            case BluetoothProfile.VCP_RENDERER -> new VcpRendererService(this);
            default -> throw new IllegalArgumentException(getProfileName(id));
        };
    }

    @VisibleForTesting
    void setProfileServiceState(int profileId, int state) {
        Instant start = Instant.now();
        var profile = getProfileName(profileId);
        var header = "setProfileServiceState(" + profile + ", " + nameForState(state) + "): ";

        if (state == State.ON) {
            if (mStartedProfiles.containsKey(profileId)) {
                Log.wtf(TAG, header + "Profile is already started");
                return;
            }
            Log.i(TAG, header + "Starting profile…");
            final var profileService = constructProfile(profileId);
            mStartedProfiles.put(profileId, profileService);
            addProfile(profileService);
            profileService.setAvailable(true);
            onProfileServiceStateChanged(profileService, State.ON);
        } else if (state == State.OFF) {
            ProfileService profileService = mStartedProfiles.remove(profileId);
            if (profileService == null) {
                Log.wtf(TAG, header + "Profile is already stopped");
                return;
            }
            Log.i(TAG, header + "Stopping profile…");
            profileService.setAvailable(false);
            onProfileServiceStateChanged(profileService, State.OFF);
            removeProfile(profileService);
            profileService.cleanup();
            profileService.getBinder().ifPresent(ProfileService.IProfileServiceBinder::cleanup);
        }
        Instant end = Instant.now();
        Log.i(TAG, header + "Completed in " + Duration.between(start, end).toMillis() + "ms");
    }

    /**
     * Register a {@link ProfileService} with AdapterService.
     *
     * @param profile the service being added.
     */
    @VisibleForTesting
    void addProfile(ProfileService profile) {
        mHandler.obtainMessage(MESSAGE_PROFILE_SERVICE_REGISTERED, profile).sendToTarget();
    }

    /**
     * Unregister a ProfileService with AdapterService.
     *
     * @param profile the service being removed.
     */
    private void removeProfile(ProfileService profile) {
        mHandler.obtainMessage(MESSAGE_PROFILE_SERVICE_UNREGISTERED, profile).sendToTarget();
    }

    /**
     * Notify AdapterService that a ProfileService has started or stopped.
     *
     * @param profile the service being removed.
     * @param state {@link State#ON} or {@link State#OFF}
     */
    @VisibleForTesting
    void onProfileServiceStateChanged(ProfileService profile, int state) {
        if (state != State.ON && state != State.OFF) {
            throw new IllegalArgumentException(nameForState(state));
        }
        Message m = mHandler.obtainMessage(MESSAGE_PROFILE_SERVICE_STATE_CHANGED);
        m.obj = profile;
        m.arg1 = state;
        mHandler.sendMessage(m);
    }

    void bringDownBle() {
        if (!Flags.onlyStartScanDuringBleOn()) {
            stopGattProfileService();
        }
        stopScanController();
    }

    private void stopScanController() {
        Instant start = Instant.now();
        var header = "stopScanController(): ";
        Log.i(TAG, header + "Stopping…");
        setScanMode(SCAN_MODE_NONE, "stopScanController");
        final var scanController = getBluetoothScanController();
        if (scanController != null) {
            mScanController = null;
            scanController.cleanup();
        }
        mNativeInterface.disable();
        Instant end = Instant.now();
        Log.i(TAG, header + "Completed in " + Duration.between(start, end).toMillis() + "ms");
    }

    private void stopGattProfileService() {
        Instant start = Instant.now();
        var header = "stopGattProfileService(): ";
        Log.i(TAG, header + "Stopping…");
        setScanMode(SCAN_MODE_NONE, "stopGattProfileService");

        mStartedProfiles.remove(BluetoothProfile.GATT);
        final var gattService = mGattService;
        if (gattService != null) {
            mGattService = null;
            gattService.setAvailable(false);
            onProfileServiceStateChanged(gattService, State.OFF);
            removeProfile(gattService);
            gattService.cleanup();
            gattService.getBinder().ifPresent(ProfileService.IProfileServiceBinder::cleanup);
        }
        Instant end = Instant.now();
        Log.i(TAG, header + "Completed in " + Duration.between(start, end).toMillis() + "ms");
    }

    void stopProfileServices() {
        // Make sure to stop classic background tasks now
        mNativeInterface.cancelDiscovery();
        setScanMode(SCAN_MODE_NONE, "StopProfileServices");

        final int[] supportedProfiles = Config.getSupportedProfiles();
        if (Flags.onlyStartScanDuringBleOn()) {
            // Scanning is always supported, started separately, and is not a profile service.
            // This will check other profile services.
            if (supportedProfiles.length == 0) {
                mAdapterState.sendMessage(AdapterState.BREDR_STOPPED);
            } else {
                setAllProfileServiceStates(supportedProfiles, State.OFF);
            }
        } else {
            // TODO(b/228875190): GATT is assumed supported. If we support no profiles then just
            // move on to BREDR_STOPPED
            if (supportedProfiles.length == 1
                    && mRunningProfiles.size() == 1
                    && mRunningProfiles.get(0).getProfileId() == BluetoothProfile.GATT) {
                Log.d(
                        TAG,
                        "stopProfileServices(): No profiles services to stop or already stopped.");
                mAdapterState.sendMessage(AdapterState.BREDR_STOPPED);
            } else {
                setAllProfileServiceStates(supportedProfiles, State.OFF);
            }
        }
        mIsMediaProfileConnected = false;
    }

    void cleanup() {
        Log.i(TAG, "cleanup()");
        if (mCleaningUp) {
            Log.e(TAG, "cleanup(): Service already starting to cleanup, ignoring request…");
            return;
        }

        MetricsLogger.getInstance().close();

        clearAdapterService(this);

        mCleaningUp = true;
        invalidateBluetoothCaches();

        stopRfcommServerSockets();

        // This wake lock release may also be called concurrently by
        // {@link #releaseWakeLock(String lockName)}, so a synchronization is needed here.
        synchronized (this) {
            if (mWakeLock != null) {
                if (mWakeLock.isHeld()) {
                    mWakeLock.release();
                }
                mWakeLock = null;
            }
        }

        mStorage.cleanup();

        mMediaAudioServer.ifPresent(MediaAudioServer::cleanup);
        mMediaAudioServer = Optional.empty();

        mAdapterState.doQuit();

        if (mBondStateMachine != null) {
            mBondStateMachine.doQuit();
        }

        if (mRemoteDevices != null) {
            mRemoteDevices.reset();
        }

        mSdpManager.ifPresent(SdpManager::cleanup);
        mSdpManager = Optional.empty();

        if (mNativeAvailable) {
            Log.d(TAG, "cleanup(): Cleaning up adapter native");
            mNativeInterface.cleanup();
            mNativeAvailable = false;
        }

        if (mAdapterProperties != null) {
            mAdapterProperties.cleanup();
        }

        if (mNativeInterface.getCallbacks() != null) {
            mNativeInterface.getCallbacks().cleanup();
        }

        mBluetoothQualityReportNativeInterface.cleanup();

        if (mBluetoothKeystoreService != null) {
            Log.d(TAG, "cleanup(): mBluetoothKeystoreService.cleanup()");
            mBluetoothKeystoreService.cleanup();
        }

        mPhonePolicy.ifPresent(PhonePolicy::cleanup);

        mSilenceDeviceManager.cleanup();

        if (mActiveDeviceManager != null) {
            mActiveDeviceManager.cleanup();
        }

        if (mBluetoothSocketManagerBinder != null) {
            mBluetoothSocketManagerBinder.cleanUp();
            mBluetoothSocketManagerBinder = null;
        }

        mAdapterSuspend.ifPresent(AdapterSuspend::cleanup);

        mDisplayListener.close();

        mPreferredAudioProfilesCallbacks.kill();

        mBluetoothQualityReportReadyCallbacks.kill();

        mBluetoothConnectionCallbacks.kill();

        mSystemServerCallbacks.kill();

        mMetadataListeners.values().forEach(RemoteCallbackList::kill);
    }

    private void stopRfcommServerSockets() {
        Iterator<Map.Entry<UUID, RfcommListenerData>> socketsIterator =
                mBluetoothServerSockets.entrySet().iterator();
        while (socketsIterator.hasNext()) {
            socketsIterator.next().getValue().closeServerAndPendingSockets(mHandler);
            socketsIterator.remove();
        }
    }

    /**
     * Log L2CAP CoC Server Connection Metrics
     *
     * @param port port of socket
     * @param isSecured if secured API is called
     * @param result transaction result of the connection
     * @param socketCreationLatencyMillis latency of the connection
     * @param timeoutMillis timeout set by the app
     */
    public void logL2capcocServerConnection(
            @Nullable BluetoothDevice device,
            int port,
            boolean isSecured,
            int result,
            long socketCreationTimeMillis,
            long socketCreationLatencyMillis,
            long socketConnectionTimeMillis,
            long timeoutMillis,
            int appUid) {

        int metricId = 0;
        if (device != null) {
            metricId = getMetricId(device);
        }
        long currentTime = System.currentTimeMillis();
        long endToEndLatencyMillis = currentTime - socketCreationTimeMillis;
        long socketAcceptanceLatencyMillis = currentTime - socketConnectionTimeMillis;
        Log.i(
                TAG,
                ("Statslog L2capcoc server connection. metricId " + metricId + ", port " + port)
                        + (", isSecured " + isSecured + ", result " + result)
                        + (", endToEndLatencyMillis " + endToEndLatencyMillis)
                        + (", socketCreationLatencyMillis " + socketCreationLatencyMillis)
                        + (", socketAcceptanceLatencyMillis " + socketAcceptanceLatencyMillis)
                        + (", timeout set by app " + timeoutMillis + ", appUid " + appUid));
        BluetoothStatsLog.write(
                BluetoothStatsLog.BLUETOOTH_L2CAP_COC_SERVER_CONNECTION,
                metricId,
                port,
                isSecured,
                result,
                endToEndLatencyMillis,
                timeoutMillis,
                appUid,
                socketCreationLatencyMillis,
                socketAcceptanceLatencyMillis);
    }

    /**
     * Log L2CAP CoC Client Connection Metrics
     *
     * @param device Bluetooth device
     * @param port port of socket
     * @param isSecured if secured API is called
     * @param result transaction result of the connection
     * @param socketCreationLatencyNanos latency of the connection
     */
    public void logL2capcocClientConnection(
            BluetoothDevice device,
            int port,
            boolean isSecured,
            int result,
            long socketCreationTimeNanos,
            long socketCreationLatencyNanos,
            long socketConnectionTimeNanos,
            int appUid) {

        int metricId = getMetricId(device);
        long currentTime = System.nanoTime();
        long endToEndLatencyMillis = (currentTime - socketCreationTimeNanos) / 1000000;
        long socketCreationLatencyMillis = socketCreationLatencyNanos / 1000000;
        long socketConnectionLatencyMillis = (currentTime - socketConnectionTimeNanos) / 1000000;
        Log.i(
                TAG,
                ("Statslog L2capcoc client connection. metricId " + metricId + ", port " + port)
                        + (", isSecured " + isSecured + ", result " + result)
                        + (", endToEndLatencyMillis " + endToEndLatencyMillis)
                        + (", socketCreationLatencyMillis " + socketCreationLatencyMillis)
                        + (", socketConnectionLatencyMillis " + socketConnectionLatencyMillis)
                        + (", appUid " + appUid));
        BluetoothStatsLog.write(
                BluetoothStatsLog.BLUETOOTH_L2CAP_COC_CLIENT_CONNECTION,
                metricId,
                port,
                isSecured,
                result,
                endToEndLatencyMillis,
                appUid,
                socketCreationLatencyMillis,
                socketConnectionLatencyMillis);
    }

    public boolean sdpSearch(BluetoothDevice device, ParcelUuid uuid) {
        mSdpManager.ifPresent(sdpManager -> sdpManager.sdpSearch(device, uuid));
        return mSdpManager.isPresent();
    }

    void stateChangeCallback(int status) {
        if (status == AbstractionLayer.BT_STATE_OFF) {
            Log.d(TAG, "stateChangeCallback: disableNative() completed");
            mAdapterState.sendMessage(AdapterState.BLE_STOPPED);
        } else if (status == AbstractionLayer.BT_STATE_ON) {
            mAdapterState.sendMessage(AdapterState.BLE_STARTED);
        } else {
            Log.e(TAG, "Incorrect status " + status + " in stateChangeCallback");
        }
    }

    void updateLeAudioProfileServiceState() {
        Set<Integer> nonSupportedProfiles = new HashSet<>();

        if (!isLeConnectedIsochronousStreamCentralSupported()) {
            for (int profileId : Config.getLeAudioUnicastProfiles()) {
                nonSupportedProfiles.add(profileId);
            }
        }

        if (!isLeConnectedIsochronousStreamPeripheralSupported()) {
            for (int profileId : Config.getLeAudioUnicastPeripheralProfiles()) {
                nonSupportedProfiles.add(profileId);
            }
        }

        if (!isLeAudioBroadcastAssistantSupported()) {
            nonSupportedProfiles.add(BluetoothProfile.LE_AUDIO_BROADCAST_ASSISTANT);
        }

        if (!isLeAudioBroadcastSourceSupported()) {
            Config.setProfileEnabled(BluetoothProfile.LE_AUDIO_BROADCAST, false);
        }

        // Disable the non-supported profiles service
        for (int profileId : nonSupportedProfiles) {
            Config.setProfileEnabled(profileId, false);
            if (mStartedProfiles.containsKey(profileId)) {
                setProfileServiceState(profileId, State.OFF);
            }
        }
    }

    private void broadcastToSystemServerCallbacks(
            String logAction, RemoteExceptionIgnoringConsumer<IBluetoothCallback> action) {
        final int itemCount = mSystemServerCallbacks.beginBroadcast();
        Log.d(TAG, "Broadcasting [" + logAction + "] to " + itemCount + " receivers");
        for (int i = 0; i < itemCount; i++) {
            action.accept(mSystemServerCallbacks.getBroadcastItem(i));
        }
        mSystemServerCallbacks.finishBroadcast();
    }

    void updateWatchConnection(boolean connected) {
        broadcastToSystemServerCallbacks(
                "updateWatchConnection", (c) -> c.onWatchConnectionChange(connected));
    }

    void updateAdapterAddress(String address) {
        broadcastToSystemServerCallbacks(
                "updateAdapterAddress(" + BluetoothUtils.toAnonymizedAddress(address) + ")",
                (c) -> c.onAdapterAddressChange(address));
    }

    void updateAdapterState(int from, int to) {
        broadcastToSystemServerCallbacks(
                "updateAdapterState(" + nameForState(from) + ", " + nameForState(to) + ")",
                (c) -> c.onBluetoothStateChange(from, to));

        for (Map.Entry<BluetoothStateCallback, Executor> e : mLocalCallbacks.entrySet()) {
            e.getValue().execute(() -> e.getKey().onBluetoothStateChange(from, to));
        }
    }

    void linkQualityReportCallback(
            long timestamp,
            int reportId,
            int rssi,
            int snr,
            int retransmissionCount,
            int packetsNotReceiveCount,
            int negativeAcknowledgementCount) {
        BluetoothInCallService bluetoothInCallService = BluetoothInCallService.getInstance();

        if (reportId == BqrQualityReportId.QUALITY_REPORT_ID_SCO_VOICE_CHOPPY.getValue()) {
            if (bluetoothInCallService == null) {
                Log.w(
                        TAG,
                        "No BluetoothInCallService while trying to send BQR."
                                + (" timestamp: " + timestamp)
                                + (", reportId: " + reportId + ", rssi: " + rssi)
                                + (", snr: " + snr)
                                + (", retransmissionCount: " + retransmissionCount)
                                + (", packetsNotReceiveCount: " + packetsNotReceiveCount)
                                + (", negativeAcknowledgementCount: "
                                        + negativeAcknowledgementCount));
                return;
            }
            bluetoothInCallService.sendBluetoothCallQualityReport(
                    timestamp,
                    rssi,
                    snr,
                    retransmissionCount,
                    packetsNotReceiveCount,
                    negativeAcknowledgementCount);
        }
    }

    /**
     * Callback from Bluetooth Quality Report Native Interface to inform the listeners about
     * Bluetooth Quality.
     *
     * @param device is the BluetoothDevice which connection quality is being reported
     * @param bluetoothQualityReport a Parcel that contains information about Bluetooth Quality
     * @return whether the Bluetooth stack acknowledged the change successfully
     */
    public int bluetoothQualityReportReadyCallback(
            BluetoothDevice device, BluetoothQualityReport bluetoothQualityReport) {
        synchronized (mBluetoothQualityReportReadyCallbacks) {
            int n = mBluetoothQualityReportReadyCallbacks.beginBroadcast();
            Log.d(
                    TAG,
                    "bluetoothQualityReportReadyCallback(): "
                            + ("Broadcasting Bluetooth Quality Report to " + n + " receivers."));
            for (int i = 0; i < n; i++) {
                try {
                    mBluetoothQualityReportReadyCallbacks
                            .getBroadcastItem(i)
                            .onBluetoothQualityReportReady(
                                    device, bluetoothQualityReport, BluetoothStatusCodes.SUCCESS);
                } catch (RemoteException e) {
                    Log.d(
                            TAG,
                            "bluetoothQualityReportReadyCallback(): "
                                    + ("Callback #" + i + " failed (" + e + ")"));
                }
            }
            mBluetoothQualityReportReadyCallbacks.finishBroadcast();
        }

        return BluetoothStatusCodes.SUCCESS;
    }

    void switchBufferSizeCallback(boolean isLowLatencyBufferSize) {
        List<BluetoothDevice> activeDevices = getActiveDevices(BluetoothProfile.A2DP);
        int size = activeDevices.size();
        if (size != 1) {
            Log.e(TAG, "Cannot switch buffer size. The number of A2DP active devices is " + size);
            return;
        }

        // Send intent to fastpair
        Intent switchBufferSizeIntent = new Intent(BluetoothDevice.ACTION_SWITCH_BUFFER_SIZE);
        switchBufferSizeIntent.setClassName(
                getString(com.android.bluetooth.R.string.peripheral_link_package),
                getString(com.android.bluetooth.R.string.peripheral_link_package)
                        + getString(com.android.bluetooth.R.string.peripheral_link_service));
        switchBufferSizeIntent.putExtra(BluetoothDevice.EXTRA_DEVICE, activeDevices.get(0));
        switchBufferSizeIntent.putExtra(
                BluetoothDevice.EXTRA_LOW_LATENCY_BUFFER_SIZE, isLowLatencyBufferSize);
        sendBroadcastMultiplePermissions(
                switchBufferSizeIntent,
                new String[] {BLUETOOTH_CONNECT, BLUETOOTH_PRIVILEGED},
                null);
    }

    void switchCodecCallback(boolean isLowLatencyBufferSize) {
        if (Flags.a2dpHandleSaReconfigInNative()) {
            throw new IllegalStateException("Reconfig is in native");
        }
        List<BluetoothDevice> activeDevices = getActiveDevices(BluetoothProfile.A2DP);
        int size = activeDevices.size();
        if (size != 1) {
            Log.e(TAG, "Cannot switch buffer size. The number of A2DP active devices is " + size);
            return;
        }
        getA2dpService()
                .ifPresent(
                        a2dp ->
                                a2dp.switchCodecByBufferSize(
                                        activeDevices.get(0), isLowLatencyBufferSize));
    }

    /**
     * Checks whether the remote device is a dual mode audio sink device (supports both classic and
     * LE Audio sink roles.
     *
     * @param device the remote device
     * @return {@code true} if it's a dual mode audio device, {@code false} otherwise
     */
    public boolean isDualModeAudioSinkDevice(BluetoothDevice device) {
        final var leAudio = getLeAudioService();
        if (leAudio.isEmpty() || leAudio.get().getGroupId(device) == LE_AUDIO_GROUP_ID_INVALID) {
            return false;
        }

        // Check if any device in the CSIP group is a dual mode audio sink device
        for (BluetoothDevice groupDevice :
                leAudio.get().getGroupDevices(leAudio.get().getGroupId(device))) {
            if (isProfileSupported(groupDevice, BluetoothProfile.LE_AUDIO)
                    && (isProfileSupported(groupDevice, BluetoothProfile.HEADSET)
                            || isProfileSupported(groupDevice, BluetoothProfile.A2DP))) {
                return true;
            }
        }
        return false;
    }

    /**
     * Checks whether the local and remote device support a connection for duplex audio (input and
     * output) over HFP or LE Audio.
     *
     * @param leAudio the instance of LeAudioService
     * @param groupDevices the devices in the CSIP group
     * @return {@code true} if duplex is supported on the remote device, {@code false} otherwise
     */
    private boolean isDuplexAudioSupported(
            LeAudioService leAudio, List<BluetoothDevice> groupDevices) {
        for (BluetoothDevice device : groupDevices) {
            if (isProfileSupported(device, BluetoothProfile.HEADSET)
                    || (isProfileSupported(device, BluetoothProfile.LE_AUDIO)
                            && leAudio.isLeAudioDuplexSupported(device))) {
                return true;
            }
        }
        return false;
    }

    /**
     * Checks whether the local and remote device support a connection for output only audio over
     * A2DP or LE Audio.
     *
     * @param leAudio the instance of LeAudioService
     * @param groupDevices the devices in the CSIP group
     * @return {@code true} if output only is supported, {@code false} otherwise
     */
    private boolean isOutputOnlyAudioSupported(
            LeAudioService leAudio, List<BluetoothDevice> groupDevices) {
        for (BluetoothDevice device : groupDevices) {
            if (isProfileSupported(device, BluetoothProfile.A2DP)
                    || (isProfileSupported(device, BluetoothProfile.LE_AUDIO)
                            && leAudio.isLeAudioOutputSupported(device))) {
                return true;
            }
        }
        return false;
    }

    /**
     * Verifies whether the profile is supported by the local bluetooth adapter by checking a
     * bitmask of its supported profiles
     *
     * @param device is the remote device we wish to connect to
     * @param id is the profile id we are checking for support
     * @return true if the profile is supported by both the local and remote device, false otherwise
     */
    boolean isProfileSupported(BluetoothDevice device, int id) {
        return ConnectableProfile.isSupported(this, device, id);
    }

    /**
     * Checks if the connection policy of all profiles are unknown for the given device
     *
     * @param device is the device for which we are checking if the connection policy of all
     *     profiles are unknown
     * @return false if one of profile is enabled or disabled, true otherwise
     */
    boolean isAllProfilesUnknown(BluetoothDevice device) {
        return !getStartedConnectableProfiles()
                .anyMatch(p -> p.getConnectionPolicy(device) != CONNECTION_POLICY_UNKNOWN);
    }

    /**
     * Connects only available profiles (those with {@link
     * BluetoothProfile#CONNECTION_POLICY_ALLOWED})
     *
     * @param device is the device with which we are connecting the profiles
     * @return {@link BluetoothStatusCodes#SUCCESS}
     */
    private int connectEnabledProfiles(BluetoothDevice device) {
        connectEnabledProfile(BluetoothProfile.CSIP_SET_COORDINATOR, device);
        // Order matters, some devices do not accept A2DP connection before HFP connection
        connectEnabledProfile(BluetoothProfile.HEADSET, device);
        connectEnabledProfile(BluetoothProfile.HEADSET_CLIENT, device);
        connectEnabledProfile(BluetoothProfile.A2DP, device);
        connectEnabledProfile(BluetoothProfile.A2DP_SINK, device);
        connectEnabledProfile(BluetoothProfile.MAP_CLIENT, device);
        connectEnabledProfile(BluetoothProfile.HID_HOST, device);
        connectEnabledProfile(BluetoothProfile.PAN, device);
        connectEnabledProfile(BluetoothProfile.PBAP_CLIENT, device);
        connectEnabledProfile(BluetoothProfile.HEARING_AID, device);
        connectEnabledProfile(BluetoothProfile.HAP_CLIENT, device);
        connectEnabledProfile(BluetoothProfile.VOLUME_CONTROL, device);
        connectEnabledProfile(BluetoothProfile.LE_AUDIO, device);
        connectEnabledProfile(BluetoothProfile.LE_AUDIO_BROADCAST_ASSISTANT, device);
        connectEnabledProfile(BluetoothProfile.BATTERY, device);
        connectEnabledProfile(BluetoothProfile.MCP_CLIENT, device);
        return BluetoothStatusCodes.SUCCESS;
    }

    private void connectEnabledProfile(int id, BluetoothDevice device) {
        getStartedConnectableProfile(id)
                .filter(profile -> isProfileSupported(device, id))
                .filter(prof -> prof.getConnectionPolicy(device) > CONNECTION_POLICY_FORBIDDEN)
                .ifPresent(
                        profile -> {
                            Log.i(TAG, "connectEnabledProfile(" + profile + ")");
                            profile.connect(device);
                        });
    }

    /**
     * Verifies that all bluetooth profile services are running
     *
     * @return true if all bluetooth profile services running, false otherwise
     */
    private boolean profileServicesRunning() {
        if (mRegisteredProfiles.size() == Config.getSupportedProfiles().length
                && mRegisteredProfiles.size() == mRunningProfiles.size()) {
            return true;
        }

        Log.e(TAG, "profileServicesRunning(): One or more supported services not running");
        return false;
    }

    @BluetoothAdapter.RfcommListenerResult
    @RequiresPermission(BLUETOOTH_CONNECT)
    int startRfcommListener(
            String name, ParcelUuid uuid, PendingIntent pendingIntent, AttributionSource source) {
        if (mBluetoothServerSockets.containsKey(uuid.getUuid())) {
            Log.d(TAG, "Cannot start RFCOMM listener: UUID " + uuid.getUuid() + "already in use.");
            return BluetoothStatusCodes.RFCOMM_LISTENER_START_FAILED_UUID_IN_USE;
        }

        try {
            startRfcommListenerInternal(name, uuid.getUuid(), pendingIntent, source);
        } catch (IOException e) {
            return BluetoothStatusCodes.RFCOMM_LISTENER_FAILED_TO_CREATE_SERVER_SOCKET;
        }

        return BluetoothStatusCodes.SUCCESS;
    }

    @BluetoothAdapter.RfcommListenerResult
    int stopRfcommListener(ParcelUuid uuid, AttributionSource source) {
        RfcommListenerData listenerData = mBluetoothServerSockets.get(uuid.getUuid());

        if (listenerData == null) {
            Log.d(TAG, "Cannot stop RFCOMM listener: UUID " + uuid.getUuid() + "is not registered");
            return BluetoothStatusCodes.RFCOMM_LISTENER_OPERATION_FAILED_NO_MATCHING_SERVICE_RECORD;
        }

        if (source.getUid() != listenerData.source.getUid()) {
            return BluetoothStatusCodes.RFCOMM_LISTENER_OPERATION_FAILED_DIFFERENT_APP;
        }

        // Remove the entry so that it does not try and restart the server socket.
        mBluetoothServerSockets.remove(uuid.getUuid());

        return listenerData.closeServerAndPendingSockets(mHandler);
    }

    IncomingRfcommSocketInfo retrievePendingSocketForServiceRecord(
            ParcelUuid uuid, AttributionSource source) {
        IncomingRfcommSocketInfo socketInfo = new IncomingRfcommSocketInfo();

        RfcommListenerData listenerData = mBluetoothServerSockets.get(uuid.getUuid());

        if (listenerData == null) {
            socketInfo.status =
                    BluetoothStatusCodes
                            .RFCOMM_LISTENER_OPERATION_FAILED_NO_MATCHING_SERVICE_RECORD;
            return socketInfo;
        }

        if (source.getUid() != listenerData.source.getUid()) {
            socketInfo.status = BluetoothStatusCodes.RFCOMM_LISTENER_OPERATION_FAILED_DIFFERENT_APP;
            return socketInfo;
        }

        BluetoothSocket socket = listenerData.pendingSockets.poll();

        if (socket == null) {
            socketInfo.status = BluetoothStatusCodes.RFCOMM_LISTENER_NO_SOCKET_AVAILABLE;
            return socketInfo;
        }

        mHandler.removeCallbacksAndMessages(socket);

        socketInfo.bluetoothDevice = socket.getRemoteDevice();
        socketInfo.pfd = socket.getParcelFileDescriptor();
        socketInfo.status = BluetoothStatusCodes.SUCCESS;

        return socketInfo;
    }

    @RequiresPermission(BLUETOOTH_CONNECT)
    private void handleIncomingRfcommConnections(UUID uuid) {
        RfcommListenerData listenerData = mBluetoothServerSockets.get(uuid);
        while (true) {
            BluetoothSocket socket;
            try {
                socket = listenerData.serverSocket.accept();
            } catch (IOException e) {
                if (mBluetoothServerSockets.containsKey(uuid)) {
                    // The uuid still being in the map indicates that the accept failure is
                    // unexpected. Try and restart the listener.
                    Log.e(TAG, "Failed to accept socket on " + listenerData.serverSocket, e);
                    restartRfcommListener(listenerData, uuid);
                }
                return;
            }

            MetricsLogger.getInstance()
                    .logBluetoothEvent(
                            socket.getRemoteDevice(),
                            BluetoothStatsLog
                                    .BLUETOOTH_CROSS_LAYER_EVENT_REPORTED__EVENT_TYPE__RFCOMM_SOCKET_JAVA_CONNECTION,
                            BluetoothStatsLog
                                    .BLUETOOTH_CROSS_LAYER_EVENT_REPORTED__STATE__SUCCESS_ACCEPT,
                            Binder.getCallingUid());

            listenerData.pendingSockets.add(socket);
            try {
                listenerData.pendingIntent.send();
            } catch (PendingIntent.CanceledException e) {
                Log.e(TAG, "PendingIntent for RFCOMM socket notifications cancelled.", e);
                // The pending intent was cancelled, close the server as there is no longer any way
                // to notify the app that registered the listener.
                listenerData.closeServerAndPendingSockets(mHandler);
                mBluetoothServerSockets.remove(uuid);
                return;
            }
            mHandler.postDelayed(
                    () -> pendingSocketTimeoutRunnable(listenerData, socket),
                    socket,
                    PENDING_SOCKET_HANDOFF_TIMEOUT.toMillis());
        }
    }

    // Tries to restart the rfcomm listener for the given UUID
    @RequiresPermission(BLUETOOTH_CONNECT)
    private void restartRfcommListener(RfcommListenerData listenerData, UUID uuid) {
        listenerData.closeServerAndPendingSockets(mHandler);
        try {
            startRfcommListenerInternal(
                    listenerData.name, uuid, listenerData.pendingIntent, listenerData.source);
        } catch (IOException e) {
            Log.e(TAG, "Failed to recreate rfcomm server socket", e);

            mBluetoothServerSockets.remove(uuid);
        }
    }

    private static void pendingSocketTimeoutRunnable(
            RfcommListenerData listenerData, BluetoothSocket socket) {
        boolean socketFound = listenerData.pendingSockets.remove(socket);
        if (socketFound) {
            try {
                socket.close();
            } catch (IOException e) {
                Log.e(TAG, "Failed to close bt socket", e);
                // We don't care if closing the socket failed, just continue on.
            }
        }
    }

    @RequiresPermission(BLUETOOTH_CONNECT)
    private void startRfcommListenerInternal(
            String name, UUID uuid, PendingIntent intent, AttributionSource source)
            throws IOException {
        BluetoothServerSocket bluetoothServerSocket =
                mAdapter.listenUsingRfcommWithServiceRecord(name, uuid);

        RfcommListenerData listenerData =
                new RfcommListenerData(
                        bluetoothServerSocket, name, intent, source, new ConcurrentLinkedQueue<>());

        mBluetoothServerSockets.put(uuid, listenerData);

        new Thread(() -> handleIncomingRfcommConnections(uuid)).start();
    }

    private record RfcommListenerData(
            BluetoothServerSocket serverSocket,
            // Service record name
            String name,
            // Contains the Service info to which the incoming socket connections are handed off to
            PendingIntent pendingIntent,
            // AttributionSource for the requester of the RFCOMM listener
            AttributionSource source,
            // Contains the connected sockets which are pending transfer to the app which requested
            // the listener.
            ConcurrentLinkedQueue<BluetoothSocket> pendingSockets) {

        int closeServerAndPendingSockets(Handler handler) {
            int result = BluetoothStatusCodes.SUCCESS;
            try {
                serverSocket.close();
            } catch (IOException e) {
                Log.e(TAG, "Failed to call close on rfcomm server socket", e);
                result = BluetoothStatusCodes.RFCOMM_LISTENER_FAILED_TO_CLOSE_SERVER_SOCKET;
            }
            pendingSockets.forEach(
                    pendingSocket -> {
                        handler.removeCallbacksAndMessages(pendingSocket);
                        try {
                            pendingSocket.close();
                        } catch (IOException e) {
                            Log.e(TAG, "Failed to close socket", e);
                        }
                    });
            pendingSockets.clear();
            return result;
        }
    }

    boolean isAvailable() {
        return !mCleaningUp;
    }

    public void setProfileConnectionPolicy(BluetoothDevice device, int profile, int policy) {
        mStorage.setProfileConnectionPolicy(device, profile, policy);
    }

    public int getProfileConnectionPolicy(BluetoothDevice device, int profile) {
        return mStorage.getProfileConnectionPolicy(device, profile);
    }

    public int getKeyMissingCount(BluetoothDevice device) {
        return mStorage.getKeyMissingCount(device);
    }

    /**
     * Wrapper to provide the bond loss status directly through {@link
     * AdapterService#getKeyMissingCount}
     *
     * @param device is the remote device whose bond state we want to check
     * @return true if the bond loss is already detected on the device, false otherwise
     */
    public boolean isBondLost(BluetoothDevice device) {
        return getKeyMissingCount(device) > 0;
    }

    public void updateKeyMissingCount(BluetoothDevice device, boolean isKeyMissingDetected) {
        mStorage.updateKeyMissingCount(device, isKeyMissingDetected);
    }

    /**
     * Set metadata value for the given device and key
     *
     * @return true if metadata is set successfully
     */
    public boolean setMetadata(BluetoothDevice device, int key, byte[] value) {
        if (value == null || value.length > BluetoothDevice.METADATA_MAX_LENGTH) {
            return false;
        }
        logManufacturerInfo(device, key, value);
        boolean status = mStorage.setCustomMetadata(device, key, value);
        if (key == BluetoothDevice.METADATA_SOFTWARE_VERSION
                && getBondState(device) == BOND_BONDED) {
            mCompanionManager.setCompanionDevice(device, value);
        }
        return status;
    }

    private void logManufacturerInfo(BluetoothDevice device, int key, byte[] bytesValue) {
        String callingApp = getPackageManager().getNameForUid(Binder.getCallingUid());
        String manufacturerName = "";
        String modelName = "";
        String hardwareVersion = "";
        String softwareVersion = "";
        switch (key) {
            case BluetoothDevice.METADATA_MANUFACTURER_NAME ->
                    manufacturerName = Utils.byteArrayToUtf8String(bytesValue);
            case BluetoothDevice.METADATA_MODEL_NAME ->
                    modelName = Utils.byteArrayToUtf8String(bytesValue);
            case BluetoothDevice.METADATA_HARDWARE_VERSION ->
                    hardwareVersion = Utils.byteArrayToUtf8String(bytesValue);
            case BluetoothDevice.METADATA_SOFTWARE_VERSION ->
                    softwareVersion = Utils.byteArrayToUtf8String(bytesValue);
            default -> {
                // Do not log anything if metadata doesn't fall into above categories
                return;
            }
        }
        String[] macAddress = device.getAddress().split(":");
        BluetoothStatsLog.write(
                BluetoothStatsLog.BLUETOOTH_DEVICE_INFO_REPORTED,
                obfuscateAddress(device),
                BluetoothProtoEnums.DEVICE_INFO_EXTERNAL,
                callingApp,
                manufacturerName,
                modelName,
                hardwareVersion,
                softwareVersion,
                getMetricId(device),
                device.getAddressType(),
                Integer.parseInt(macAddress[0], 16),
                Integer.parseInt(macAddress[1], 16),
                Integer.parseInt(macAddress[2], 16));
    }

    /**
     * Get metadata of given device and key
     *
     * @return value of given device and key combination
     */
    public byte[] getMetadata(BluetoothDevice device, int key) {
        return mStorage.getCustomMetadata(device, key);
    }

    /** Update Adapter Properties when BT profiles connection state changes. */
    public void updateProfileConnectionAdapterProperties(
            BluetoothDevice device, int profile, int state, int prevState) {
        mHandler.post(
                () ->
                        mAdapterProperties.updateOnProfileConnectionChanged(
                                device, profile, state, prevState));
        if (Flags.leHidConnectionPolicySuspend()) {
            mAdapterSuspend.ifPresent(
                    adapterSuspend ->
                            adapterSuspend.profileConnectionStateChanged(
                                    profile, device, prevState, state));
        }
    }

    /**
     * Gets the preferred audio profiles for the device. See {@link
     * BluetoothAdapter#getPreferredAudioProfiles(BluetoothDevice)} for more details.
     *
     * @param device is the remote device whose preferences we want to fetch
     * @return a Bundle containing the preferred audio profiles for the device
     */
    public Bundle getPreferredAudioProfiles(BluetoothDevice device) {
        final var leAudio = getLeAudioService();
        if (!isDualModeAudioEnabled() || leAudio.isEmpty() || !isDualModeAudioSinkDevice(device)) {
            return Bundle.EMPTY;
        }
        // Checks if the device is part of an LE Audio group
        final List<BluetoothDevice> groupDevices = leAudio.get().getGroupDevices(device);
        if (groupDevices.isEmpty()) {
            return Bundle.EMPTY;
        }

        // If there are no preferences stored, return the defaults
        Bundle storedBundle = Bundle.EMPTY;
        for (BluetoothDevice groupDevice : groupDevices) {
            Bundle groupDevicePreferences = mStorage.getPreferredAudioProfiles(groupDevice);
            if (!groupDevicePreferences.isEmpty()) {
                storedBundle = groupDevicePreferences;
                break;
            }
        }

        if (storedBundle.isEmpty()) {
            Bundle defaultPreferencesBundle = new Bundle();
            boolean useDefaultPreferences = false;
            if (isOutputOnlyAudioSupported(leAudio.get(), groupDevices)) {
                // Gets the default output only audio profile or defaults to LE_AUDIO if not present
                int outputOnlyDefault =
                        BluetoothProperties.getDefaultOutputOnlyAudioProfile()
                                .orElse(BluetoothProfile.LE_AUDIO);
                if (outputOnlyDefault != BluetoothProfile.A2DP
                        && outputOnlyDefault != BluetoothProfile.LE_AUDIO) {
                    outputOnlyDefault = BluetoothProfile.LE_AUDIO;
                }
                defaultPreferencesBundle.putInt(
                        BluetoothAdapter.AUDIO_MODE_OUTPUT_ONLY, outputOnlyDefault);
                useDefaultPreferences = true;
            }
            if (isDuplexAudioSupported(leAudio.get(), groupDevices)) {
                // Gets the default duplex audio profile or defaults to LE_AUDIO if not present
                int duplexDefault =
                        BluetoothProperties.getDefaultDuplexAudioProfile()
                                .orElse(BluetoothProfile.LE_AUDIO);
                if (duplexDefault != BluetoothProfile.HEADSET
                        && duplexDefault != BluetoothProfile.LE_AUDIO) {
                    duplexDefault = BluetoothProfile.LE_AUDIO;
                }
                defaultPreferencesBundle.putInt(BluetoothAdapter.AUDIO_MODE_DUPLEX, duplexDefault);
                useDefaultPreferences = true;
            }

            if (useDefaultPreferences) {
                return defaultPreferencesBundle;
            }
        }
        return storedBundle;
    }

    /**
     * Sets the preferred audio profiles for the device. See {@link
     * BluetoothAdapter#setPreferredAudioProfiles(BluetoothDevice, Bundle)} for more details.
     *
     * @param device is the remote device whose preferences we want to fetch
     * @param modeToProfileBundle is the preferences we want to set for the device
     * @return whether the preferences were successfully requested
     */
    int setPreferredAudioProfiles(BluetoothDevice device, Bundle modeToProfileBundle) {
        Log.i(TAG, "setPreferredAudioProfiles for device=" + device);
        if (!isDualModeAudioEnabled()) {
            Log.e(TAG, "setPreferredAudioProfiles called while sysprop is disabled");
            return BluetoothStatusCodes.FEATURE_NOT_SUPPORTED;
        }
        final var leAudio = getLeAudioService();
        if (leAudio.isEmpty()) {
            Log.e(TAG, "setPreferredAudioProfiles: LEA service is not up");
            return BluetoothStatusCodes.ERROR_PROFILE_NOT_CONNECTED;
        }
        if (!isDualModeAudioSinkDevice(device)) {
            Log.e(TAG, "setPreferredAudioProfiles: Not a dual mode audio device");
            return BluetoothStatusCodes.ERROR_NOT_DUAL_MODE_AUDIO_DEVICE;
        }
        // Checks if the device is part of an LE Audio group
        int groupId = leAudio.get().getGroupId(device);
        final List<BluetoothDevice> groupDevices = leAudio.get().getGroupDevices(groupId);
        if (groupDevices.isEmpty()) {
            return BluetoothStatusCodes.ERROR_DEVICE_NOT_BONDED;
        }

        // Copies relevant keys & values from modeToProfile bundle
        Bundle strippedPreferences = new Bundle();
        if (modeToProfileBundle.containsKey(BluetoothAdapter.AUDIO_MODE_OUTPUT_ONLY)
                && isOutputOnlyAudioSupported(leAudio.get(), groupDevices)) {
            int outputOnlyProfile =
                    modeToProfileBundle.getInt(BluetoothAdapter.AUDIO_MODE_OUTPUT_ONLY);
            if (outputOnlyProfile != BluetoothProfile.A2DP
                    && outputOnlyProfile != BluetoothProfile.LE_AUDIO) {
                throw new IllegalArgumentException(
                        "AUDIO_MODE_OUTPUT_ONLY has invalid value: " + outputOnlyProfile);
            }
            strippedPreferences.putInt(BluetoothAdapter.AUDIO_MODE_OUTPUT_ONLY, outputOnlyProfile);
        }
        if (modeToProfileBundle.containsKey(BluetoothAdapter.AUDIO_MODE_DUPLEX)
                && isDuplexAudioSupported(leAudio.get(), groupDevices)) {
            int duplexProfile = modeToProfileBundle.getInt(BluetoothAdapter.AUDIO_MODE_DUPLEX);
            if (duplexProfile != BluetoothProfile.HEADSET
                    && duplexProfile != BluetoothProfile.LE_AUDIO) {
                throw new IllegalArgumentException(
                        "AUDIO_MODE_DUPLEX has invalid value: " + duplexProfile);
            }
            strippedPreferences.putInt(BluetoothAdapter.AUDIO_MODE_DUPLEX, duplexProfile);
        }

        synchronized (mCsipGroupsPendingAudioProfileChanges) {
            if (mCsipGroupsPendingAudioProfileChanges.containsKey(groupId)) {
                return BluetoothStatusCodes.ERROR_ANOTHER_ACTIVE_REQUEST;
            }

            Bundle previousPreferences = getPreferredAudioProfiles(device);

            mStorage.setPreferredAudioProfiles(groupDevices, strippedPreferences);

            int outputOnlyPreference =
                    strippedPreferences.getInt(BluetoothAdapter.AUDIO_MODE_OUTPUT_ONLY);
            if (outputOnlyPreference == 0) {
                outputOnlyPreference =
                        previousPreferences.getInt(BluetoothAdapter.AUDIO_MODE_OUTPUT_ONLY);
            }
            int duplexPreference = strippedPreferences.getInt(BluetoothAdapter.AUDIO_MODE_DUPLEX);
            if (duplexPreference == 0) {
                duplexPreference = previousPreferences.getInt(BluetoothAdapter.AUDIO_MODE_DUPLEX);
            }

            leAudio.get()
                    .sendAudioProfilePreferencesToNative(
                            groupId,
                            outputOnlyPreference == BluetoothProfile.LE_AUDIO,
                            duplexPreference == BluetoothProfile.LE_AUDIO);

            /* Populates the HashMap to hold requests on the groupId. We will update
            numRequestsToAudioFramework after we make requests to the audio framework */
            PendingAudioProfilePreferenceRequest holdRequest =
                    new PendingAudioProfilePreferenceRequest(strippedPreferences, 0, device);
            mCsipGroupsPendingAudioProfileChanges.put(groupId, holdRequest);

            // Notifies audio framework via the handler thread to avoid this blocking calls
            mHandler.post(
                    () ->
                            sendPreferredAudioProfileChangeToAudioFramework(
                                    device, strippedPreferences, previousPreferences));
            return BluetoothStatusCodes.SUCCESS;
        }
    }

    /**
     * Sends the updated preferred audio profiles to the audio framework.
     *
     * @param device is the device with updated audio preferences
     * @param strippedPreferences is a {@link Bundle} containing the preferences
     */
    private void sendPreferredAudioProfileChangeToAudioFramework(
            BluetoothDevice device, Bundle strippedPreferences, Bundle previousPreferences) {
        int newOutput = strippedPreferences.getInt(BluetoothAdapter.AUDIO_MODE_OUTPUT_ONLY);
        int newDuplex = strippedPreferences.getInt(BluetoothAdapter.AUDIO_MODE_DUPLEX);
        int previousOutput = previousPreferences.getInt(BluetoothAdapter.AUDIO_MODE_OUTPUT_ONLY);
        int previousDuplex = previousPreferences.getInt(BluetoothAdapter.AUDIO_MODE_DUPLEX);

        Log.i(
                TAG,
                "sendPreferredAudioProfileChangeToAudioFramework: changing output from "
                        + BluetoothProfile.getProfileName(previousOutput)
                        + " to "
                        + BluetoothProfile.getProfileName(newOutput)
                        + " and duplex from "
                        + BluetoothProfile.getProfileName(previousDuplex)
                        + " to "
                        + BluetoothProfile.getProfileName(newDuplex));

        // If no change from existing preferences, do not inform audio framework
        if (previousOutput == newOutput && previousDuplex == newDuplex) {
            Log.i(TAG, "No change to preferred audio profiles, no requests to Audio FW");
            sendPreferredAudioProfilesCallbackToApps(
                    device, strippedPreferences, BluetoothStatusCodes.SUCCESS);
            return;
        }

        int numRequestsToAudioFw = 0;

        final var leAudio = getLeAudioService();
        if (leAudio.isEmpty()) {
            return;
        }

        // Checks if the device is part of an LE Audio group
        int groupId = leAudio.get().getGroupId(device);
        final List<BluetoothDevice> groupDevices = leAudio.get().getGroupDevices(groupId);
        if (groupDevices.isEmpty()) {
            Log.i(
                    TAG,
                    "sendPreferredAudioProfileChangeToAudioFramework: Empty LEA group for "
                            + "device - "
                            + device);
            sendPreferredAudioProfilesCallbackToApps(
                    device, strippedPreferences, BluetoothStatusCodes.ERROR_DEVICE_NOT_BONDED);
            return;
        }

        synchronized (mCsipGroupsPendingAudioProfileChanges) {
            final var a2dp = getA2dpService();
            if (previousOutput != newOutput) {
                if (newOutput == BluetoothProfile.A2DP
                        && a2dp.isPresent()
                        && a2dp.get().getActiveDevice() != null
                        && groupDevices.contains(a2dp.get().getActiveDevice())) {
                    Log.i(TAG, "Sent change for AUDIO_MODE_OUTPUT_ONLY to A2DP to Audio FW");
                    numRequestsToAudioFw +=
                            a2dp.get().sendPreferredAudioProfileChangeToAudioFramework();
                } else if (newOutput == BluetoothProfile.LE_AUDIO
                        && leAudio.get().getActiveGroupId() == groupId) {
                    Log.i(TAG, "Sent change for AUDIO_MODE_OUTPUT_ONLY to LE_AUDIO to Audio FW");
                    numRequestsToAudioFw +=
                            leAudio.get().sendPreferredAudioProfileChangeToAudioFramework();
                }
            }

            if (previousDuplex != newDuplex) {
                final var headset = getHeadsetService();
                if (newDuplex == BluetoothProfile.HEADSET
                        && headset.isPresent()
                        && headset.get().getActiveDevice() != null
                        && groupDevices.contains(headset.get().getActiveDevice())) {
                    Log.i(TAG, "Sent change for AUDIO_MODE_DUPLEX to HFP to Audio FW");
                    // TODO(b/275426145): Add similar HFP method in BluetoothProfileConnectionInfo
                    if (a2dp.isPresent()) {
                        numRequestsToAudioFw +=
                                a2dp.get().sendPreferredAudioProfileChangeToAudioFramework();
                    }
                } else if (newDuplex == BluetoothProfile.LE_AUDIO
                        && leAudio.get().getActiveGroupId() == groupId) {
                    Log.i(TAG, "Sent change for AUDIO_MODE_DUPLEX to LE_AUDIO to Audio FW");
                    numRequestsToAudioFw +=
                            leAudio.get().sendPreferredAudioProfileChangeToAudioFramework();
                }
            }

            Log.i(
                    TAG,
                    "sendPreferredAudioProfileChangeToAudioFramework: sent "
                            + numRequestsToAudioFw
                            + " request(s) to the Audio Framework for device: "
                            + device);

            if (numRequestsToAudioFw > 0) {
                mCsipGroupsPendingAudioProfileChanges.put(
                        groupId,
                        new PendingAudioProfilePreferenceRequest(
                                strippedPreferences, numRequestsToAudioFw, device));

                Message m =
                        mHandler.obtainMessage(
                                MESSAGE_PREFERRED_AUDIO_PROFILES_AUDIO_FRAMEWORK_TIMEOUT);
                m.obj = groupId;
                mHandler.sendMessageDelayed(m, PREFERRED_AUDIO_PROFILE_CHANGE_TIMEOUT.toMillis());
                return;
            }
        }
        sendPreferredAudioProfilesCallbackToApps(
                device, strippedPreferences, BluetoothStatusCodes.SUCCESS);
    }

    private void removeFromPendingAudioProfileChanges(int groupId) {
        synchronized (mCsipGroupsPendingAudioProfileChanges) {
            Log.i(
                    TAG,
                    "removeFromPendingAudioProfileChanges: Timeout on change for groupId="
                            + groupId);
            if (!mCsipGroupsPendingAudioProfileChanges.containsKey(groupId)) {
                Log.e(
                        TAG,
                        "removeFromPendingAudioProfileChanges( "
                                + groupId
                                + ", "
                                + groupId
                                + ") is not pending");
            }
        }
    }

    /**
     * Notification from the audio framework that an active device change has taken effect. See
     * {@link BluetoothAdapter#notifyActiveDeviceChangeApplied(BluetoothDevice)} for more details.
     *
     * @param device the remote device whose preferred audio profiles have been changed
     * @return whether the Bluetooth stack acknowledged the change successfully
     */
    int notifyActiveDeviceChangeApplied(BluetoothDevice device) {
        final var leAudio = getLeAudioService();
        if (leAudio.isEmpty()) {
            Log.e(TAG, "LE Audio profile not enabled");
            return BluetoothStatusCodes.ERROR_PROFILE_NOT_CONNECTED;
        }

        int groupId = leAudio.get().getGroupId(device);
        if (groupId == LE_AUDIO_GROUP_ID_INVALID) {
            return BluetoothStatusCodes.ERROR_DEVICE_NOT_BONDED;
        }

        synchronized (mCsipGroupsPendingAudioProfileChanges) {
            if (!mCsipGroupsPendingAudioProfileChanges.containsKey(groupId)) {
                Log.e(
                        TAG,
                        "notifyActiveDeviceChangeApplied, but no pending request for "
                                + "groupId: "
                                + groupId);
                return BluetoothStatusCodes.ERROR_UNKNOWN;
            }

            PendingAudioProfilePreferenceRequest pendingRequest =
                    mCsipGroupsPendingAudioProfileChanges.get(groupId);

            // If this is the final audio framework request, send callback to apps
            if (pendingRequest.numberOfRemainingRequestsToAudioFramework == 1) {
                Log.i(
                        TAG,
                        "notifyActiveDeviceChangeApplied: Complete for device "
                                + pendingRequest.device);
                sendPreferredAudioProfilesCallbackToApps(
                        pendingRequest.device,
                        pendingRequest.preferences,
                        BluetoothStatusCodes.SUCCESS);
                // Removes the timeout from the handler
                mHandler.removeMessages(
                        MESSAGE_PREFERRED_AUDIO_PROFILES_AUDIO_FRAMEWORK_TIMEOUT, groupId);
            } else if (pendingRequest.numberOfRemainingRequestsToAudioFramework > 1) {
                PendingAudioProfilePreferenceRequest updatedPendingRequest =
                        new PendingAudioProfilePreferenceRequest(
                                pendingRequest.preferences,
                                pendingRequest.numberOfRemainingRequestsToAudioFramework - 1,
                                pendingRequest.device);
                Log.i(
                        TAG,
                        "notifyActiveDeviceChangeApplied: Updating device "
                                + updatedPendingRequest.device
                                + " with new remaining requests count="
                                + updatedPendingRequest.numberOfRemainingRequestsToAudioFramework);
                mCsipGroupsPendingAudioProfileChanges.put(groupId, updatedPendingRequest);
            } else {
                Log.i(
                        TAG,
                        "notifyActiveDeviceChangeApplied: "
                                + pendingRequest.device
                                + " has no remaining requests to audio framework, but is still"
                                + " present in mCsipGroupsPendingAudioProfileChanges");
            }
        }

        return BluetoothStatusCodes.SUCCESS;
    }

    private void sendPreferredAudioProfilesCallbackToApps(
            BluetoothDevice device, Bundle preferredAudioProfiles, int status) {
        int n = mPreferredAudioProfilesCallbacks.beginBroadcast();
        Log.d(
                TAG,
                "sendPreferredAudioProfilesCallbackToApps(): Broadcasting audio profile "
                        + ("change callback to device: " + device)
                        + (" and status=" + status)
                        + (" to " + n + " receivers."));
        for (int i = 0; i < n; i++) {
            try {
                mPreferredAudioProfilesCallbacks
                        .getBroadcastItem(i)
                        .onPreferredAudioProfilesChanged(device, preferredAudioProfiles, status);
            } catch (RemoteException e) {
                Log.d(
                        TAG,
                        ("sendPreferredAudioProfilesCallbackToApps(): Callback #" + i)
                                + (" failed (" + e + ")"));
            }
        }
        mPreferredAudioProfilesCallbacks.finishBroadcast();
    }

    // ----API Methods--------

    public boolean isEnabled() {
        return getState() == State.ON;
    }

    public int getState() {
        return mAdapterState.getState();
    }

    void disconnectAllAcls() {
        Log.d(TAG, "disconnectAllAcls()");
        mNativeInterface.disconnectAllAcls();
    }

    void setName(String name) {
        String newName = Text.truncateUtf8String(name, BLUETOOTH_NAME_MAX_LENGTH_BYTES);
        if (newName.equals(mLocalName)) {
            return;
        }
        mLocalName = newName;
        mNativeInterface.setLocalName(newName);
    }

    public String getName() {
        return mLocalName;
    }

    public int getNameLengthForAdvertise() {
        return mLocalName.length();
    }

    record CallingPackage(String packageName, UserHandle user) {}

    boolean startDiscovery(AttributionSource source) {
        UserHandle callingUser = Binder.getCallingUserHandle();
        Log.d(TAG, "startDiscovery");
        var callingPackage = new CallingPackage(source.getPackageName(), callingUser);
        mAppOps.checkPackage(Binder.getCallingUid(), callingPackage.packageName);
        boolean isQApp = Util.checkCallerTargetSdk(this, source, Build.VERSION_CODES.Q);
        boolean hasDisavowedLocation =
                Util.hasDisavowedLocationForScan(this, source, mTestModeEnabled);
        String permission = null;
        if (getState() != State.ON) {
            return false;
        }
        if (Util.checkCallerHasNetworkSettingsPermission(this)) {
            permission = android.Manifest.permission.NETWORK_SETTINGS;
        } else if (Util.checkCallerHasNetworkSetupWizardPermission(this)) {
            permission = android.Manifest.permission.NETWORK_SETUP_WIZARD;
        } else if (!hasDisavowedLocation) {
            if (isQApp) {
                if (!Util.checkCallerHasFineLocation(this, source, callingUser)) {
                    return false;
                }
                permission = android.Manifest.permission.ACCESS_FINE_LOCATION;
            } else {
                if (!Util.checkCallerHasCoarseLocation(this, source, callingUser)) {
                    return false;
                }
                permission = android.Manifest.permission.ACCESS_COARSE_LOCATION;
            }
        }

        synchronized (mDiscoveringPackages) {
            boolean discovering = isDiscovering();
            DiscoveringPackageInfo pkgInfo =
                    new DiscoveringPackageInfo(permission, hasDisavowedLocation);
            DiscoveringPackageInfo oldPkgInfo = mDiscoveringPackages.put(callingPackage, pkgInfo);

            if (Flags.ignoreRedundantDiscoveryIfSameState() && discovering) {
                // If discovery is already running, broadcast the ACTION_DISCOVERY_STARTED intent.
                Log.d(TAG, "startDiscovery: discovery is already running");
                if (oldPkgInfo != null) {
                    Log.e(TAG, "startDiscovery: discovery already started by the same package");
                    return false;
                }

                Intent intent = new Intent(BluetoothAdapter.ACTION_DISCOVERY_STARTED);
                intent.setPackage(callingPackage.packageName);
                sendBroadcastAsUser(intent, callingUser, BLUETOOTH_SCAN, Util.getTempBroadcastBundle());

                // Now start sending all the discovered devices to the new discovering package.
                if (Flags.sendDiscoveredDevToNewPkgs()) {
                    for (BluetoothDevice device : mDiscoveredDevices) {
                        DeviceProperties deviceProp = mRemoteDevices.getDeviceProperties(device);
                        if (deviceProp == null) {
                            continue;
                        }
                        Intent discoveryResIntent = prepareDiscoveryResultIntent(deviceProp);
                        sendDiscoveryResult(callingPackage, pkgInfo, device, discoveryResIntent);
                    }
                }
                return true;
            }
        }

        return mNativeInterface.startDiscovery();
    }

    public boolean cancelDiscovery(AttributionSource source, UserHandle user) {
        CallingPackage callingPackage = new CallingPackage(source.getPackageName(), user);
        if (getState() != State.ON) {
            return false;
        }

        if (Flags.ignoreRedundantDiscoveryIfSameState()) {
            synchronized (mDiscoveringPackages) {
                // If there are no discovering packages, we can't cancel discovery.
                if (mDiscoveringPackages.isEmpty()) {
                    return false;
                }

                // Remove the package from the list of discovering packages, if it was there.
                if (mDiscoveringPackages.remove(callingPackage) == null) {
                    return false;
                }

                // If there are still discovering packages, we can't cancel discovery.
                if (!mDiscoveringPackages.isEmpty()) {
                    return true;
                }
            }
        }

        return mNativeInterface.cancelDiscovery();
    }

    /**
     * @return set of bonded {@link BluetoothDevice}
     */
    public @NonNull Set<BluetoothDevice> getBondedDevices() {
        return mAdapterProperties.getBondedDevices();
    }

    public byte[] getByteIdentityAddress(BluetoothDevice device) {
        DeviceProperties deviceProp = mRemoteDevices.getDeviceProperties(device);
        if (deviceProp != null && deviceProp.getIdentityAddress().getAddress() != null) {
            return Util.getBytesFromAddress(deviceProp.getIdentityAddress().getAddress());
        }

        // Return null if identity address unknown
        return null;
    }

    public BluetoothDevice getRemoteDevice(String address) {
        return getRemoteDevice(address, BluetoothDevice.ADDRESS_TYPE_PUBLIC);
    }

    public BluetoothDevice getRemoteDevice(String address, int addressType) {
        if (!BluetoothAdapter.checkBluetoothAddress(address)) {
            throw new IllegalArgumentException(address + " is not a valid Bluetooth address");
        }

        // Reuse the existing BluetoothDevice object if it exists
        BluetoothDevice device =
                Flags.retainAddressType() ? mRemoteDevices.getDevice(address) : null;
        if (device == null) {
            // BluetoothAdapter.getRemoteLeDevice() is same as BluetoothAdapter.getRemoteDevice()
            // with the specific address type.
            device = mAdapter.getRemoteLeDevice(address, addressType);
        }
        return device;
    }

    public BluetoothDevice getDeviceFromByte(byte[] address) {
        BluetoothDevice device = mRemoteDevices.getDevice(address);
        if (device == null) {
            device = mAdapter.getRemoteDevice(address);
        }
        return device;
    }

    /** {@link #getBrEdrAddress(String)} */
    public String getBrEdrAddress(BluetoothDevice device) {
        return getBrEdrAddress(device.getAddress());
    }

    /**
     * Returns the correct device address to be used for connections over BR/EDR transport.
     *
     * @param address the device address for which to obtain the connection address
     * @return either identity address or device address in String format
     */
    public String getBrEdrAddress(String address) {
        String identity = getIdentityAddress(address);
        return identity != null ? identity : address;
    }

    /**
     * Returns the correct device address to be used for connections over BR/EDR transport.
     *
     * @param device the device for which to obtain the connection address
     * @return either identity address or device address as a byte array
     */
    public byte[] getByteBrEdrAddress(BluetoothDevice device) {
        // If dual mode device bonded over BLE first, BR/EDR address will be identity address
        // Otherwise, BR/EDR address will be same address as in BluetoothDevice#getAddress
        byte[] address = getByteIdentityAddress(device);
        if (address == null) {
            address = Util.getByteAddress(device);
        }
        return address;
    }

    public String getIdentityAddress(String address) {
        return getIdentityAddressWithType(address).getAddress();
    }

    /**
     * Returns the identity address and identity address type.
     *
     * @param address of remote device
     * @return a {@link BluetoothDevice.BluetoothAddress} containing identity address and identity
     *     address type
     */
    @NonNull
    public BluetoothAddress getIdentityAddressWithType(@NonNull String address) {
        BluetoothDevice device = getRemoteDevice(address.toUpperCase(Locale.ROOT));
        DeviceProperties deviceProp = mRemoteDevices.getDeviceProperties(device);
        return deviceProp != null
                ? deviceProp.getIdentityAddress()
                : DeviceProperties.UNKNOWN_ADDRESS;
    }

    public boolean addAssociatedPackage(BluetoothDevice device, String packageName) {
        if (packageName == null) {
            return false;
        }
        DeviceProperties deviceProp = mRemoteDevices.getDeviceProperties(device);
        if (deviceProp == null) {
            return false;
        }
        deviceProp.addPackage(packageName);
        return true;
    }

    private record CallerInfo(String callerPackageName, UserHandle user) {}

    boolean createBond(
            BluetoothDevice device,
            int transport,
            OobData remoteP192Data,
            OobData remoteP256Data,
            String callingPackage) {
        DeviceProperties deviceProp = mRemoteDevices.getDeviceProperties(device);
        int bondState = deviceProp != null ? deviceProp.getBondState() : BluetoothDevice.BOND_NONE;

        if (!Flags.nonCtkdDualModePairing() && bondState != BluetoothDevice.BOND_NONE) {
            return bondState == BluetoothDevice.BOND_BONDING; // true for BONDING, false for BONDED
        }

        if (bondState == BluetoothDevice.BOND_BONDING) {
            Log.e(TAG, "Already bonding " + device);
            return true;
        }

        if (bondState == BluetoothDevice.BOND_BONDED
                && deviceProp.getDeviceType() == BluetoothDevice.DEVICE_TYPE_DUAL) {
            boolean leBonded = deviceProp.getBondStatus(BluetoothDevice.TRANSPORT_LE) != null;
            boolean bredrBonded = deviceProp.getBondStatus(BluetoothDevice.TRANSPORT_BREDR) != null;

            if (bredrBonded && leBonded) {
                Log.e(TAG, "Already bonded over both BR/EDR and LE " + device);
                return false;
            }

            if (transport == BluetoothDevice.TRANSPORT_BREDR && bredrBonded) {
                Log.e(TAG, "Already bonded over BR/EDR " + device);
                return false;
            }

            if (transport == BluetoothDevice.TRANSPORT_LE && leBonded) {
                Log.e(TAG, "Already bonded over LE " + device);
                return false;
            }

            if (!bredrBonded) {
                Log.d(TAG, "Bonding over BR/EDR " + device);
                // Make sure to bond over BR/EDR transport in case app didn't specify transport
                transport = BluetoothDevice.TRANSPORT_BREDR;
            } else if (!leBonded) {
                Log.d(TAG, "Bonding over LE " + device);
                // Make sure to bond over LE transport in case app didn't specify transport
                transport = BluetoothDevice.TRANSPORT_LE;
            }
        }

        if (!isEnabled()) {
            Log.e(TAG, "Impossible to call createBond when Bluetooth is not enabled");
            return false;
        }

        if (!isPackageNameAccurate(this, callingPackage, Binder.getCallingUid())) {
            return false;
        }

        CallerInfo createBondCaller = new CallerInfo(callingPackage, Binder.getCallingUserHandle());
        mBondAttemptCallerInfo.put(device.getAddress(), createBondCaller);

        mRemoteDevices.setBondingInitiatedLocally(device);
        addAssociatedPackage(device, callingPackage);

        // Pairing is unreliable while scanning, so cancel discovery
        // Note, remove this when native stack improves
        mNativeInterface.cancelDiscovery();
        sendCreateBondMessage(device, transport, remoteP192Data, remoteP256Data);
        return true;
    }

    void sendCreateBondMessage(
            BluetoothDevice device, int transport, OobData remoteP192Data, OobData remoteP256Data) {
        Message msg = mBondStateMachine.obtainMessage(BondStateMachine.MESSAGE_CREATE_BOND);
        msg.obj = device;
        msg.arg1 = transport;

        Bundle remoteOobDatasBundle = new Bundle();
        boolean setData = false;
        if (remoteP192Data != null) {
            remoteOobDatasBundle.putParcelable(BondStateMachine.KEY_OOBDATAP192, remoteP192Data);
            setData = true;
        }
        if (remoteP256Data != null) {
            remoteOobDatasBundle.putParcelable(BondStateMachine.KEY_OOBDATAP256, remoteP256Data);
            setData = true;
        }
        if (setData) {
            msg.setData(remoteOobDatasBundle);
        } else {
            MetricsLogger.getInstance()
                    .logBluetoothEvent(
                            device,
                            BluetoothStatsLog
                                    .BLUETOOTH_CROSS_LAYER_EVENT_REPORTED__EVENT_TYPE__BONDING,
                            BluetoothStatsLog.BLUETOOTH_CROSS_LAYER_EVENT_REPORTED__STATE__START,
                            Binder.getCallingUid());
        }
        mBondStateMachine.sendMessage(msg);
    }

    boolean removeBond(BluetoothDevice device) {
        String header = "removeBond(" + device + "): ";
        DeviceProperties deviceProp = mRemoteDevices.getDeviceProperties(device);
        if (deviceProp == null) {
            Log.w(TAG, header + "FAIL. No properties for this device");
            return false;
        }
        final int bondState = deviceProp.getBondState();
        if (bondState == BluetoothDevice.BOND_NONE
                || (bondState == BluetoothDevice.BOND_BONDING
                        && !Flags.cancelPairingWhileRemoveBond())) {
            Log.w(TAG, header + "FAIL. Device bond state is " + bondState);
            return false;
        }
        deviceProp.setBondingInitiatedLocally(false);

        Set<BluetoothDevice> devices = new HashSet<BluetoothDevice>(List.of(device));
        Optional<CsipSetCoordinatorService> csipSetCoordinatorService =
                getCsipSetCoordinatorService();
        if (csipSetCoordinatorService.isPresent()) {
            List<BluetoothDevice> groupDevices =
                    csipSetCoordinatorService
                            .get()
                            .getGroupDevicesOrdered(device, BluetoothUuid.CAP);
            if (!groupDevices.isEmpty()) {
                Log.i(TAG, header + "Group devices found: " + groupDevices);
                devices.addAll(groupDevices);
            }
        }

        for (BluetoothDevice dev : devices) {
            mBondAttemptCallerInfo.remove(dev.getAddress());
            getStartedConnectableProfiles()
                    .filter(p -> p.getConnectionPolicy(dev) == CONNECTION_POLICY_ALLOWED)
                    .forEach(
                            p -> {
                                Log.d(TAG, "removeBond: " + dev + " Manually disable " + p);
                                setProfileConnectionPolicy(
                                        dev, p.getProfileId(), CONNECTION_POLICY_FORBIDDEN);
                            });

            mBondStateMachine.dispatchMessage(BondStateMachine.MESSAGE_REMOVE_BOND, dev);
        }
        return true;
    }

    /**
     * Fetches the local OOB data to give out to remote.
     *
     * @param transport - specify data transport.
     * @param callback - callback used to receive the requested {@link OobData}; null will be
     *     ignored silently.
     */
    public synchronized void generateLocalOobData(
            int transport, IBluetoothOobDataCallback callback) {
        if (callback == null) {
            Log.e(TAG, "'callback' argument must not be null!");
            return;
        }
        if (mOobDataCallbackQueue.peek() != null) {
            try {
                callback.onError(BluetoothStatusCodes.ERROR_ANOTHER_ACTIVE_OOB_REQUEST);
            } catch (RemoteException e) {
                Log.e(TAG, "Failed to make callback", e);
            }
            return;
        }
        mOobDataCallbackQueue.offer(callback);
        mHandler.postDelayed(
                () -> removeFromOobDataCallbackQueue(callback),
                GENERATE_LOCAL_OOB_DATA_TIMEOUT.toMillis());
        mNativeInterface.generateLocalOobData(transport);
    }

    private synchronized void removeFromOobDataCallbackQueue(IBluetoothOobDataCallback callback) {
        if (callback == null) {
            return;
        }

        if (mOobDataCallbackQueue.peek() == callback) {
            try {
                mOobDataCallbackQueue.poll().onError(BluetoothStatusCodes.ERROR_UNKNOWN);
            } catch (RemoteException e) {
                Log.e(TAG, "Failed to make OobDataCallback to remove callback from queue", e);
            }
        }
    }

    /* package */ synchronized void notifyOobDataCallback(int transport, OobData oobData) {
        if (mOobDataCallbackQueue.peek() == null) {
            Log.e(TAG, "Failed to make callback, no callback exists");
            return;
        }
        if (oobData == null) {
            try {
                mOobDataCallbackQueue.poll().onError(BluetoothStatusCodes.ERROR_UNKNOWN);
            } catch (RemoteException e) {
                Log.e(TAG, "Failed to make callback", e);
            }
        } else {
            try {
                mOobDataCallbackQueue.poll().onOobData(transport, oobData);
            } catch (RemoteException e) {
                Log.e(TAG, "Failed to make callback", e);
            }
        }
    }

    public boolean isQuietModeEnabled() {
        Log.d(TAG, "isQuietModeEnabled(): Enabled = " + mQuietMode);
        return mQuietMode;
    }

    private void refreshBondedDeviceUuids() {
        Log.d(TAG, "refreshBondedDeviceUuids() - Retrieving UUIDs for bonded devices");
        for (BluetoothDevice device : getBondedDevices()) {
            mRemoteDevices.triggerUuidNotification(device);
        }
    }

    // TODO (b/462533972): Make it private once flag broadcast_uuids_from_main_looper is shipped.
    public void serviceDiscoveryNotificationToBondStateMachine(BluetoothDevice device) {
        if (Flags.broadcastUuidsFromMainLooper()) {
            mBondStateMachine.dispatchMessage(BondStateMachine.MESSAGE_UUID_UPDATE, device);
        } else {
            Message msg =
                    mBondStateMachine.obtainMessage(BondStateMachine.MESSAGE_UUID_UPDATE, device);
            mBondStateMachine.sendMessage(msg);
        }
    }

    /**
     * Relays updated UUIDs to {@link BondStateMachine} and other internal modules. Also sends an
     * ACTION_UUID intent if the adapter is ON.
     *
     * @param device remote device of interest
     * @param uuids UUIDs of the device
     * @param success whether the UUID update was successful
     */
    public void deviceUuidsUpdated(BluetoothDevice device, ParcelUuid[] uuids, boolean success) {
        int state = getState();
        if (state != State.ON
                && state != State.BLE_ON
                && state != State.TURNING_ON
                && state != State.BLE_TURNING_ON) {
            // Silently dropping UUIDs and with no intent
            MetricsLogger.getInstance().cacheCount(BluetoothProtoEnums.SDP_DROP_UUID, 1);
            Log.e(
                    TAG,
                    "deviceUuidsUpdated: Ignoring UUID update in adapter state: "
                            + nameForState(state));
            return;
        }

        if (success) {
            // Notify BondStateMachine
            serviceDiscoveryNotificationToBondStateMachine(device);

            // Notify all other internal modules
            sendUuidsInternal(device, uuids);
        }

        if (state != State.ON) {
            MetricsLogger.getInstance()
                    .cacheCount(BluetoothProtoEnums.SDP_ADD_UUID_WITH_NO_INTENT, 1);
            Log.w(
                    TAG,
                    "deviceUuidsUpdated: Not broadcasting ACTION_UUID in adapter state: "
                            + nameForState(state));
            return;
        }

        MetricsLogger.getInstance()
                .cacheCount(
                        success
                                ? BluetoothProtoEnums.SDP_ADD_UUID_WITH_INTENT
                                : BluetoothProtoEnums.SDP_SENDING_DELAYED_UUID,
                        1);
        MetricsLogger.getInstance().cacheCount(BluetoothProtoEnums.SDP_SENT_UUID, 1);

        Log.i(
                TAG,
                "deviceUuidsUpdated: ACTION_UUID Intent: device: "
                        + device
                        + " count: "
                        + (uuids != null ? uuids.length : 0));

        Intent intent = new Intent(BluetoothDevice.ACTION_UUID);
        intent.putExtra(BluetoothDevice.EXTRA_DEVICE, device);
        intent.putExtra(BluetoothDevice.EXTRA_UUID, uuids);
        sendBroadcast(intent, BLUETOOTH_CONNECT, Util.getTempBroadcastBundle());
    }

    /**
     * Get the bond state of a particular {@link BluetoothDevice}
     *
     * @param device remote device of interest
     * @return bond state
     *     <p>Possible values are {@link BluetoothDevice#BOND_NONE}, {@link
     *     BluetoothDevice#BOND_BONDING}, {@link BluetoothDevice#BOND_BONDED}.
     */
    public int getBondState(BluetoothDevice device) {
        return mRemoteDevices.getBondState(device);
    }

    public boolean isConnected(BluetoothDevice device) {
        return getConnectionState(device) != BluetoothDevice.CONNECTION_STATE_DISCONNECTED;
    }

    void setDeviceDisconnectReason(BluetoothDevice device, int reason) {
        mDisconnectReasons.put(device, reason);
    }

    /**
     * Get and clear the disconnect reason for a remote device
     *
     * @param device Remote device
     * @return disconnect reason for the device, or {@link
     *     BluetoothStatusCodes#ERROR_DISCONNECT_REASON_LOCAL_REQUEST} if not found
     */
    int popDeviceDisconnectReason(BluetoothDevice device) {
        var reason = mDisconnectReasons.remove(device);
        return reason != null ? reason : BluetoothStatusCodes.ERROR_DISCONNECT_REASON_LOCAL_REQUEST;
    }

    private void addGattClientToControlAutoActiveMode(
            LeAudioService leAudio, int clientIf, BluetoothDevice device) {
        /* When GATT client is connecting to LeAudio device, stack should not assume that
         * LeAudio device should be automatically connected to Audio Framework.
         * e.g. given LeAudio device might be busy with audio streaming from another device.
         * LeAudio shall be automatically connected to Audio Framework when
         * 1. Remote device expects that - Targeted Announcements are used
         * 2. User is connecting device from Settings application.
         * 3. Device has been just bonded.
         *
         * Above conditions are tracked by LeAudioService. In here, there is need to notify
         * LeAudioService that connection is made for GATT purposes, so LeAudioService can
         * disable AutoActiveMode and make sure to not make device Active just after connection
         * is created.
         *
         * Note: AutoActiveMode is by default set to true and it means that LeAudio device is ready
         * to streaming just after connection is created. That implies that device will be connected
         * to Audio Framework (is made Active) when connection is created.
         */

        int groupId = leAudio.getGroupId(device);
        if (groupId == BluetoothLeAudio.GROUP_ID_INVALID) {
            /* If this is not a LeAudio device, there is nothing to do here. */
            return;
        }

        if (leAudio.getConnectionPolicy(device) != CONNECTION_POLICY_ALLOWED) {
            Log.d(
                    TAG,
                    "addGattClientToControlAutoActiveMode: "
                            + device
                            + " LeAudio connection policy is not allowed");
            return;
        }

        Log.i(
                TAG,
                "addGattClientToControlAutoActiveMode: clientIf: "
                        + clientIf
                        + ", "
                        + device
                        + ", groupId: "
                        + groupId);

        synchronized (mLeGattClientsControllingAutoActiveMode) {
            Pair<Integer, BluetoothDevice> newPair = new Pair<>(clientIf, device);
            if (mLeGattClientsControllingAutoActiveMode.contains(newPair)) {
                return;
            }

            for (Pair<Integer, BluetoothDevice> pair : mLeGattClientsControllingAutoActiveMode) {
                if (pair.second.equals(device) || groupId == leAudio.getGroupId(pair.second)) {
                    Log.i(TAG, "addGattClientToControlAutoActiveMode: adding new client");
                    mLeGattClientsControllingAutoActiveMode.add(newPair);
                    return;
                }
            }

            if (leAudio.setAutoActiveModeState(leAudio.getGroupId(device), false)) {
                Log.i(
                        TAG,
                        "addGattClientToControlAutoActiveMode: adding new client and notifying"
                                + " leAudioService");
                mLeGattClientsControllingAutoActiveMode.add(newPair);
            }
        }
    }

    /**
     * When this is called, AdapterService is aware of user doing GATT connection over LE. Adapter
     * service will use this information to manage internal GATT services if needed. For now,
     * AdapterService is using this information to control Auto Active Mode for LeAudio devices.
     *
     * @param clientIf clientIf ClientIf which was doing GATT connection attempt
     * @param device device Remote device to connect
     */
    public void notifyDirectLeGattClientConnect(int clientIf, BluetoothDevice device) {
        getLeAudioService()
                .ifPresent(
                        leAudio -> addGattClientToControlAutoActiveMode(leAudio, clientIf, device));
    }

    private void removeGattClientFromControlAutoActiveMode(
            LeAudioService leAudio, int clientIf, BluetoothDevice device) {
        if (mLeGattClientsControllingAutoActiveMode.isEmpty()) {
            return;
        }

        int groupId = leAudio.getGroupId(device);
        if (groupId == BluetoothLeAudio.GROUP_ID_INVALID) {
            /* If this is not a LeAudio device, there is nothing to do here. */
            return;
        }

        /* Remember if auto active mode is still disabled.
         * If it is disabled, it means, that either User or remote device did not make an
         * action to make LeAudio device Active.
         * That means, AdapterService should disconnect ACL when all the clients are disconnected
         * from the group to which the device belongs.
         */
        boolean isAutoActiveModeDisabled = !leAudio.isAutoActiveModeEnabled(groupId);

        synchronized (mLeGattClientsControllingAutoActiveMode) {
            Log.d(
                    TAG,
                    "removeGattClientFromControlAutoActiveMode: removing "
                            + ("clientIf:" + clientIf)
                            + ("device:" + device)
                            + ("groupId:" + groupId));

            mLeGattClientsControllingAutoActiveMode.remove(new Pair<>(clientIf, device));

            if (!mLeGattClientsControllingAutoActiveMode.isEmpty()) {
                for (Pair<Integer, BluetoothDevice> pair :
                        mLeGattClientsControllingAutoActiveMode) {
                    if (pair.second.equals(device) || groupId == leAudio.getGroupId(pair.second)) {
                        Log.d(
                                TAG,
                                "removeGattClientFromControlAutoActiveMode:"
                                        + device
                                        + " or groupId: "
                                        + groupId
                                        + " is still in use by clientif: "
                                        + pair.first);
                        return;
                    }
                }
            }

            /* Back auto active mode to default. */
            leAudio.setAutoActiveModeState(groupId, true);
        }

        int leConnectedState =
                BluetoothDevice.CONNECTION_STATE_ENCRYPTED_LE
                        | BluetoothDevice.CONNECTION_STATE_CONNECTED;

        /* If auto active mode was disabled for the given group and is still connected
         * make sure to disconnected all the devices from the group
         */
        if (isAutoActiveModeDisabled && ((getConnectionState(device) & leConnectedState) != 0)) {
            for (BluetoothDevice dev : leAudio.getGroupDevices(groupId)) {
                /* Need to disconnect all the devices from the group as those might be connected
                 * as well especially those which might keep the connection
                 */
                if ((getConnectionState(dev) & leConnectedState) != 0) {
                    mNativeInterface.disconnectAcl(dev, TRANSPORT_LE);
                }
            }
        }
    }

    /**
     * Notify AdapterService about failed GATT connection attempt.
     *
     * @param clientIf ClientIf which was doing GATT connection attempt
     * @param device Remote device to which connection attempt failed
     */
    public void notifyGattClientConnectFailed(int clientIf, BluetoothDevice device) {
        getLeAudioService()
                .ifPresent(
                        leAudio ->
                                removeGattClientFromControlAutoActiveMode(
                                        leAudio, clientIf, device));
    }

    /**
     * Notify AdapterService about GATT connection being disconnecting or disconnected.
     *
     * @param clientIf ClientIf which is disconnecting or is already disconnected
     * @param device Remote device which is disconnecting or is disconnected
     */
    public void notifyGattClientDisconnect(int clientIf, BluetoothDevice device) {
        getLeAudioService()
                .ifPresent(
                        leAudio ->
                                removeGattClientFromControlAutoActiveMode(
                                        leAudio, clientIf, device));
    }

    public int getConnectionState(BluetoothDevice device) {
        DeviceProperties deviceProp = mRemoteDevices.getDeviceProperties(device);
        if (deviceProp == null) {
            return BluetoothDevice.CONNECTION_STATE_DISCONNECTED;
        }

        int connectionState = 0;
        DeviceProperties.LinkState leLinkState =
                deviceProp.getLinkState(BluetoothDevice.TRANSPORT_LE);
        if (leLinkState != null) {
            connectionState |= BluetoothDevice.CONNECTION_STATE_CONNECTED;
            if (leLinkState.getEncryptionStatus() != null) {
                connectionState |= BluetoothDevice.CONNECTION_STATE_ENCRYPTED_LE;
            }
        }

        DeviceProperties.LinkState bredrLinkState =
                deviceProp.getLinkState(BluetoothDevice.TRANSPORT_BREDR);
        if (bredrLinkState != null) {
            connectionState |= BluetoothDevice.CONNECTION_STATE_CONNECTED;
            if (bredrLinkState.getEncryptionStatus() != null) {
                connectionState |= BluetoothDevice.CONNECTION_STATE_ENCRYPTED_BREDR;
            }
        }

        return connectionState;
    }

    int getConnectionHandle(BluetoothDevice device, int transport) {
        DeviceProperties deviceProp = mRemoteDevices.getDeviceProperties(device);
        if (deviceProp == null) {
            return BluetoothDevice.ERROR;
        }
        return deviceProp.getConnectionHandle(transport);
    }

    /**
     * Get ASHA Capability
     *
     * @param device discovered bluetooth device
     * @return ASHA capability
     */
    public int getAshaCapability(BluetoothDevice device) {
        DeviceProperties deviceProp = mRemoteDevices.getDeviceProperties(device);
        if (deviceProp == null) {
            return BluetoothDevice.ERROR;
        }
        return deviceProp.getAshaCapability();
    }

    /**
     * Get ASHA truncated HiSyncId
     *
     * @param device discovered bluetooth device
     * @return ASHA truncated HiSyncId
     */
    public int getAshaTruncatedHiSyncId(BluetoothDevice device) {
        DeviceProperties deviceProp = mRemoteDevices.getDeviceProperties(device);
        if (deviceProp == null) {
            return BluetoothDevice.ERROR;
        }
        return deviceProp.getAshaTruncatedHiSyncId();
    }

    /**
     * Checks whether the device was recently associated with the companion app that called {@link
     * BluetoothDevice#createBond}. This allows these devices to skip the pairing dialog if their
     * pairing variant is {@link BluetoothDevice#PAIRING_VARIANT_CONSENT}.
     *
     * @param device the bluetooth device that is being bonded
     * @return true if it was recently associated and we can bypass the dialog, false otherwise
     */
    public boolean canBondWithoutDialog(BluetoothDevice device) {
        CallerInfo info = mBondAttemptCallerInfo.get(device.getAddress());
        if (info == null) {
            return false;
        }
        return mCompanionDeviceManager.canPairWithoutPrompt(
                info.callerPackageName(), device.getAddress(), info.user());
    }

    /**
     * Returns the package name of the most recent caller that called {@link
     * BluetoothDevice#createBond} on the given device.
     */
    @Nullable
    public String getPackageNameOfBondingApplication(BluetoothDevice device) {
        CallerInfo info = mBondAttemptCallerInfo.get(device.getAddress());
        if (info == null) {
            return null;
        }
        return info.callerPackageName();
    }

    /**
     * Sets device as the active devices for the profiles passed into the function.
     *
     * @param device is the remote bluetooth device
     * @param profiles is a constant that references for which profiles we'll be setting the remote
     *     device as our active device. One of the following: {@link
     *     BluetoothAdapter#ACTIVE_DEVICE_AUDIO}, {@link BluetoothAdapter#ACTIVE_DEVICE_PHONE_CALL}
     *     {@link BluetoothAdapter#ACTIVE_DEVICE_ALL}
     * @return false if profiles value is not one of the constants we accept, true otherwise
     */
    public boolean setActiveDevice(BluetoothDevice device, @ActiveDeviceUse int profiles) {
        if (getState() != State.ON) {
            Log.e(TAG, "setActiveDevice: Bluetooth is not enabled");
            return false;
        }

        return mActiveDeviceManager.setActiveDevice(device, profiles);
    }

    /**
     * Checks if all supported classic audio profiles are active on this LE Audio device.
     *
     * @param leAudioDevice the remote device
     * @return {@code true} if all supported classic audio profiles are active on this device,
     *     {@code false} otherwise
     */
    public boolean isAllSupportedClassicAudioProfilesActive(BluetoothDevice leAudioDevice) {
        final var leAudio = getLeAudioService();
        if (leAudio.isEmpty()) {
            return false;
        }
        boolean hfpSupported = isProfileSupported(leAudioDevice, BluetoothProfile.HEADSET);
        boolean a2dpSupported = isProfileSupported(leAudioDevice, BluetoothProfile.A2DP);

        final List<BluetoothDevice> groupDevices = leAudio.get().getGroupDevices(leAudioDevice);
        final var headset = getHeadsetService();
        if (hfpSupported && headset.isPresent()) {
            BluetoothDevice activeHfpDevice = headset.get().getActiveDevice();
            if (activeHfpDevice == null || !groupDevices.contains(activeHfpDevice)) {
                return false;
            }
        }
        final var a2dp = getA2dpService();
        if (a2dpSupported && a2dp.isPresent()) {
            BluetoothDevice activeA2dpDevice = a2dp.get().getActiveDevice();
            if (activeA2dpDevice == null || !groupDevices.contains(activeA2dpDevice)) {
                return false;
            }
        }
        return true;
    }

    /**
     * Get the active devices for the BluetoothProfile specified
     *
     * @param profile is the profile from which we want the active devices. Possible values are:
     *     {@link BluetoothProfile#HEADSET}, {@link BluetoothProfile#A2DP}, {@link
     *     BluetoothProfile#HEARING_AID} {@link BluetoothProfile#LE_AUDIO}
     * @return A list of active bluetooth devices
     */
    public List<BluetoothDevice> getActiveDevices(@ActiveDeviceProfile int profile) {
        List<BluetoothDevice> activeDevices = new ArrayList<>();

        switch (profile) {
            case BluetoothProfile.HEADSET -> {
                final var headset = getHeadsetService();
                if (!headset.isPresent()) {
                    Log.e(TAG, "getActiveDevices: HeadsetService is null");
                    break;
                }
                BluetoothDevice device = headset.get().getActiveDevice();
                if (device != null) {
                    activeDevices.add(device);
                }
                Log.i(TAG, "getActiveDevices: Headset device: " + device);
            }
            case BluetoothProfile.A2DP -> {
                final var a2dp = getA2dpService();
                if (!a2dp.isPresent()) {
                    Log.e(TAG, "getActiveDevices: A2dpService is null");
                    break;
                }
                BluetoothDevice device = a2dp.get().getActiveDevice();
                if (device != null) {
                    activeDevices.add(device);
                }
                Log.i(TAG, "getActiveDevices: A2dp device: " + device);
            }
            case BluetoothProfile.HEARING_AID -> {
                final var hearingAid = getHearingAidService();
                if (!hearingAid.isPresent()) {
                    Log.e(TAG, "getActiveDevices: HearingAidService is null");
                    break;
                }
                activeDevices = hearingAid.get().getActiveDevices();
                Log.i(
                        TAG,
                        "getActiveDevices: Hearing Aid devices:"
                                + (" Left[" + activeDevices.get(0) + "] -")
                                + (" Right[" + activeDevices.get(1) + "]"));
            }
            case BluetoothProfile.LE_AUDIO -> {
                final var leAudio = getLeAudioService();
                if (!leAudio.isPresent()) {
                    Log.e(TAG, "getActiveDevices: LeAudioService is null");
                    break;
                }
                activeDevices = leAudio.get().getActiveDevices();
                Log.i(
                        TAG,
                        "getActiveDevices: LeAudio devices:"
                                + (" Lead[" + activeDevices.get(0) + "] -")
                                + (" member_1[" + activeDevices.get(1) + "]"));
            }
            case BluetoothProfile.LE_AUDIO_PERIPHERAL -> {
                final var leAudioPeripheral = getLeAudioPeripheralService();
                if (!leAudioPeripheral.isPresent()) {
                    Log.e(TAG, "getActiveDevices: LeAudioPeripheralService is null");
                    break;
                }

                activeDevices = leAudioPeripheral.get().getActiveDevices();
                Log.i(TAG, "getActiveDevices: LeAudioPeripheral: " + activeDevices);
            }
            default -> Log.e(TAG, "getActiveDevices: profile value is not valid");
        }
        return activeDevices;
    }

    /**
     * Attempts connection to all enabled and supported bluetooth profiles between the local and
     * remote device
     *
     * @param device is the remote device with which to connect these profiles
     * @return {@link BluetoothStatusCodes#SUCCESS} if all profiles connections are attempted, false
     *     if an error occurred
     */
    public int connectAllEnabledProfiles(BluetoothDevice device) {
        if (!profileServicesRunning()) {
            Log.e(TAG, "connectAllEnabledProfiles: Not all profile services running");
            return BluetoothStatusCodes.ERROR_BLUETOOTH_NOT_ENABLED;
        }

        device = requireNonNullElse(mRemoteDevices.getDevice(device.getAddress()), device);

        // Checks if any profiles are enabled or disabled and if so, only connect enabled profiles
        if (!isAllProfilesUnknown(device)) {
            return connectEnabledProfiles(device);
        }

        connectAllSupportedProfiles(device);

        return BluetoothStatusCodes.SUCCESS;
    }

    /** All profile toggles are disabled, so connects all supported profiles */
    private void connectAllSupportedProfiles(BluetoothDevice device) {
        int numProfilesConnected = 0;

        // Order matters, some devices do not accept A2DP connection before HFP connection
        if (connectIfProfileSupported(BluetoothProfile.HEADSET, device)) {
            numProfilesConnected++;
        }
        if (connectIfProfileSupported(BluetoothProfile.HEADSET_CLIENT, device)) {
            numProfilesConnected++;
        }
        if (connectIfProfileSupported(BluetoothProfile.A2DP, device)) {
            numProfilesConnected++;
        }
        if (connectIfProfileSupported(BluetoothProfile.A2DP_SINK, device)) {
            numProfilesConnected++;
        }
        if (connectIfProfileSupported(BluetoothProfile.MAP_CLIENT, device)) {
            numProfilesConnected++;
        }
        if (connectIfProfileSupported(BluetoothProfile.HID_HOST, device)) {
            numProfilesConnected++;
        }
        if (connectIfProfileSupported(BluetoothProfile.PAN, device)) {
            numProfilesConnected++;
        }
        if (connectIfProfileSupported(BluetoothProfile.PBAP_CLIENT, device)) {
            numProfilesConnected++;
        }
        if (connectIfProfileSupported(BluetoothProfile.HAP_CLIENT, device)) {
            numProfilesConnected++;
        } else if (connectIfProfileSupported(BluetoothProfile.HEARING_AID, device)) {
            numProfilesConnected++;
        }
        if (connectIfProfileSupported(BluetoothProfile.VOLUME_CONTROL, device)) {
            numProfilesConnected++;
        }
        if (connectIfProfileSupported(BluetoothProfile.CSIP_SET_COORDINATOR, device)) {
            numProfilesConnected++;
        }
        if (connectIfProfileSupported(BluetoothProfile.LE_AUDIO, device)) {
            numProfilesConnected++;
        }
        if (connectIfProfileSupported(BluetoothProfile.BATTERY, device)) {
            numProfilesConnected++;
        }
        if (connectIfProfileSupported(BluetoothProfile.MCP_CLIENT, device)) {
            numProfilesConnected++;
        }

        Log.i(TAG, "connectAllSupportedProfiles: # of Profiles Connected: " + numProfilesConnected);
    }

    private boolean connectIfProfileSupported(int id, BluetoothDevice device) {
        return getStartedConnectableProfile(id)
                .filter(profile -> isProfileSupported(device, id))
                .map(
                        profile -> {
                            Log.i(TAG, "connectIfProfileSupported: Connecting " + profile);
                            profile.setConnectionPolicy(device, CONNECTION_POLICY_ALLOWED);
                            return true;
                        })
                .orElse(false);
    }

    /**
     * Disconnects all enabled and supported bluetooth profiles between the local and remote device
     *
     * @param device is the remote device with which to disconnect these profiles
     * @return true if all profiles successfully disconnected, false if an error occurred
     */
    public int disconnectAllEnabledProfiles(BluetoothDevice device, int reason) {
        if (reason != BluetoothStatusCodes.SUCCESS) {
            setDeviceDisconnectReason(device, reason);
        }

        if (Util.isTv(this)) {
            mNativeInterface.disconnectAllAcls(device);
            return BluetoothStatusCodes.SUCCESS;
        }

        if (!profileServicesRunning()) {
            Log.e(TAG, "disconnectAllEnabledProfiles: Not all profile services bound");
            return BluetoothStatusCodes.ERROR_BLUETOOTH_NOT_ENABLED;
        }
        disconnectEnabledProfile(BluetoothProfile.HEADSET, device);
        disconnectEnabledProfile(BluetoothProfile.HEADSET_CLIENT, device);
        disconnectEnabledA2dpProfile(device);
        disconnectEnabledProfile(BluetoothProfile.A2DP_SINK, device);
        disconnectEnabledProfile(BluetoothProfile.MAP_CLIENT, device);
        disconnectEnabledProfile(BluetoothProfile.MAP, device);
        disconnectHidDevice(device);
        disconnectEnabledProfile(BluetoothProfile.HID_HOST, device);
        disconnectEnabledProfile(BluetoothProfile.PAN, device);
        disconnectEnabledProfile(BluetoothProfile.PBAP_CLIENT, device);
        disconnectEnabledProfile(BluetoothProfile.PBAP, device);
        disconnectEnabledProfile(BluetoothProfile.HEARING_AID, device);
        disconnectEnabledProfile(BluetoothProfile.HAP_CLIENT, device);
        disconnectEnabledProfile(BluetoothProfile.VOLUME_CONTROL, device);
        disconnectEnabledProfile(BluetoothProfile.SAP, device);
        disconnectEnabledProfile(BluetoothProfile.CSIP_SET_COORDINATOR, device);
        disconnectEnabledProfile(BluetoothProfile.LE_AUDIO, device);
        disconnectEnabledProfile(BluetoothProfile.LE_AUDIO_BROADCAST_ASSISTANT, device);
        disconnectEnabledProfile(BluetoothProfile.BATTERY, device);
        disconnectEnabledProfile(BluetoothProfile.MCP_CLIENT, device);
        return BluetoothStatusCodes.SUCCESS;
    }

    /**
     * Disconnects all ACL connections between the local and remote device
     *
     * @param device is the remote device with which to disconnect
     * @param reason is the reason for the disconnection
     * @return SUCCESS if successful, ERROR_UNKNOWN otherwise
     */
    public int disconnectAllAcl(BluetoothDevice device, int reason) {
        if (reason != BluetoothStatusCodes.SUCCESS) {
            setDeviceDisconnectReason(device, reason);
        }
        return mNativeInterface.disconnectAcl(device, TRANSPORT_AUTO)
                ? BluetoothStatusCodes.SUCCESS
                : BluetoothStatusCodes.ERROR_UNKNOWN;
    }

    private void disconnectEnabledProfile(int id, BluetoothDevice device) {
        getStartedConnectableProfile(id)
                .filter(
                        profile -> {
                            final int state = profile.getConnectionState(device);
                            return state == STATE_CONNECTED || state == STATE_CONNECTING;
                        })
                .ifPresent(
                        profile -> {
                            Log.i(TAG, "Disconnecting " + profile);
                            profile.disconnect(device);
                        });
    }

    // HidDevice as a weird situation of being 'connectable' without implementing the whole feature
    // of other connectable profiles such as connectionPolicy.
    private void disconnectHidDevice(BluetoothDevice device) {
        getHidDeviceService()
                .filter(
                        profile -> {
                            final int state = profile.getConnectionState(device);
                            return state == STATE_CONNECTED || state == STATE_CONNECTING;
                        })
                .ifPresent(
                        profile -> {
                            Log.i(TAG, "Disconnecting " + profile);
                            profile.disconnect(device);
                        });
    }

    /**
     * Disconnect enabled A2DP profile.
     *
     * <p>This function takes into account interop checks.
     *
     * @param device is the remote device with which to disconnect this profile
     */
    private void disconnectEnabledA2dpProfile(BluetoothDevice device) {
        getStartedConnectableProfile(BluetoothProfile.A2DP)
                .filter(
                        profile -> {
                            final int state = profile.getConnectionState(device);
                            return state == STATE_CONNECTED || state == STATE_CONNECTING;
                        })
                .ifPresent(
                        profile -> {
                            if (shouldDelayA2dpDisconnection(device)) {
                                final var headset = getHeadsetService();
                                if (headset.isPresent()
                                        && (headset.get().isInCall()
                                                || headset.get().isRinging())) {
                                    Log.i(TAG, "Post a delayed message to disconnect A2DP profile");
                                    mHandler.postDelayed(
                                            () -> {
                                                Log.i(TAG, "Disconnecting " + profile);
                                                profile.disconnect(device);
                                            },
                                            400);
                                    return;
                                }
                            }
                            Log.i(TAG, "Disconnecting " + profile);
                            profile.disconnect(device);
                        });
    }

    /** Check if A2DP disconnection should be delayed for interop device. */
    private boolean shouldDelayA2dpDisconnection(BluetoothDevice device) {
        Objects.requireNonNull(device, "device must not be null");
        boolean matched =
                interopMatchDevice(
                        InteropUtil.InteropFeature.INTEROP_A2DP_DELAY_DISCONNECT, device);
        return matched;
    }

    /**
     * Same as API method {@link BluetoothDevice#getName()}
     *
     * @param device remote device of interest
     * @return remote device name
     */
    public String getRemoteName(BluetoothDevice device) {
        return mRemoteDevices.getName(device);
    }

    public int getRemoteClass(BluetoothDevice device) {
        return mRemoteDevices.getBluetoothClass(device);
    }

    /**
     * Get UUIDs for service supported by a remote device
     *
     * @param device the remote device that we want to get UUIDs from
     * @return the uuids of the remote device
     */
    public ParcelUuid[] getRemoteUuids(BluetoothDevice device) {
        return mRemoteDevices.getUuids(device);
    }

    void aclStateChangeBroadcastCallback(
            RemoteExceptionIgnoringConsumer<IBluetoothConnectionCallback> cb) {
        int n = mBluetoothConnectionCallbacks.beginBroadcast();
        Log.d(TAG, "aclStateChangeBroadcastCallback(): Broadcasting to " + n + " receivers");
        for (int i = 0; i < n; i++) {
            cb.accept(mBluetoothConnectionCallbacks.getBroadcastItem(i));
        }
        mBluetoothConnectionCallbacks.finishBroadcast();
    }

    void logUserBondResponse(BluetoothDevice device, boolean accepted, AttributionSource source) {
        final long token = Binder.clearCallingIdentity();
        try {
            MetricsLogger.getInstance()
                    .logBluetoothEvent(
                            device,
                            BluetoothStatsLog
                                    .BLUETOOTH_CROSS_LAYER_EVENT_REPORTED__EVENT_TYPE__USER_CONF_REQUEST,
                            accepted
                                    ? BluetoothStatsLog
                                            .BLUETOOTH_CROSS_LAYER_EVENT_REPORTED__STATE__SUCCESS
                                    : BluetoothStatsLog
                                            .BLUETOOTH_CROSS_LAYER_EVENT_REPORTED__STATE__FAIL,
                            source.getUid());

            if (Utils.isAutonomousRepairingSupported()
                    && getBondState(device) == BluetoothDevice.BOND_BONDING
                    && isBondLost(device)
                    && !accepted) {
                MetricsLogger.getInstance().count(BluetoothProtoEnums.BOND_REPAIR_LOCAL_CANCEL, 1);
            }
        } finally {
            Binder.restoreCallingIdentity(token);
        }
    }

    public int getPhonebookAccessPermission(BluetoothDevice device) {
        return mStorage.getPhonebookAccessPermission(device);
    }

    public int getMessageAccessPermission(BluetoothDevice device) {
        return mStorage.getMessageAccessPermission(device);
    }

    public int getSimAccessPermission(BluetoothDevice device) {
        return mStorage.getSimAccessPermission(device);
    }

    public void setPhonebookAccessPermission(BluetoothDevice device, int value) {
        mStorage.setPhonebookAccessPermission(device, value);
    }

    public void setMessageAccessPermission(BluetoothDevice device, int value) {
        mStorage.setMessageAccessPermission(device, value);
    }

    public void setSimAccessPermission(BluetoothDevice device, int value) {
        mStorage.setSimAccessPermission(device, value);
    }

    public int getNumOfOffloadedScanFilterSupported() {
        return mAdapterProperties.getNumOfOffloadedScanFilterSupported();
    }

    public int getOffloadedScanResultStorage() {
        return mAdapterProperties.getOffloadedScanResultStorage();
    }

    public boolean isLe2MPhySupported() {
        return mAdapterProperties.isLe2MPhySupported();
    }

    public boolean isLeCodedPhySupported() {
        return mAdapterProperties.isLeCodedPhySupported();
    }

    /**
     * Check if the LE high data throughput phy feature is supported.
     *
     * @return true, if the LE high data throughput phy feature is supported
     */
    public boolean isLeHighDataThroughputPhySupported() {
        if (!Flags.leaudioOverHdtPhyApi()) {
            return false;
        }
        return mAdapterProperties.isLeHighDataThroughputPhySupported();
    }

    public boolean isLeExtendedAdvertisingSupported() {
        return mAdapterProperties.isLeExtendedAdvertisingSupported();
    }

    public boolean isLePeriodicAdvertisingSupported() {
        return mAdapterProperties.isLePeriodicAdvertisingSupported();
    }

    /**
     * Check if the LE audio broadcast source feature is supported.
     *
     * @return true, if the LE audio broadcast source is supported
     */
    public boolean isLeAudioBroadcastSourceSupported() {
        return mAdapterProperties.isLePeriodicAdvertisingSupported()
                && mAdapterProperties.isLeExtendedAdvertisingSupported()
                && mAdapterProperties.isLeIsochronousBroadcasterSupported();
    }

    /**
     * Check if the LE audio broadcast assistant feature is supported.
     *
     * @return true, if the LE audio broadcast assistant is supported
     */
    public boolean isLeAudioBroadcastAssistantSupported() {
        return mAdapterProperties.isLePeriodicAdvertisingSupported()
                && mAdapterProperties.isLeExtendedAdvertisingSupported()
                && (mAdapterProperties.isLePeriodicAdvertisingSyncTransferSenderSupported()
                        || mAdapterProperties
                                .isLePeriodicAdvertisingSyncTransferRecipientSupported());
    }

    /**
     * Check if the LE channel sounding feature is supported.
     *
     * @return true, if the LE channel sounding is supported
     */
    public boolean isLeChannelSoundingSupported() {
        return mAdapterProperties.isLeChannelSoundingSupported();
    }

    /**
     * Check if the LE audio CIS central feature is supported.
     *
     * @return true, if the LE audio CIS central is supported
     */
    public boolean isLeConnectedIsochronousStreamCentralSupported() {
        return mAdapterProperties.isLeConnectedIsochronousStreamCentralSupported();
    }

    /**
     * Check if the LE audio CIS peripheral feature is supported.
     *
     * @return true, if the LE audio CIS peripheral is supported
     */
    public boolean isLeConnectedIsochronousStreamPeripheralSupported() {
        return mAdapterProperties.isLeConnectedIsochronousStreamPeripheralSupported();
    }

    /**
     * Check if the LE BIG Channel Classification feature is supported.
     *
     * @return true, if the LE BIG Channel Classification is supported
     */
    public boolean isLeBigSetChannelClassificationSupported() {
        return mAdapterProperties.isLeBigSetChannelClassificationSupported();
    }

    public int getLeMaximumAdvertisingDataLength() {
        return mAdapterProperties.getLeMaximumAdvertisingDataLength();
    }

    /**
     * Get the maximum number of connected audio devices.
     *
     * @return the maximum number of connected audio devices
     */
    public int getMaxConnectedAudioDevices() {
        return mAdapterProperties.getMaxConnectedAudioDevices();
    }

    /**
     * Check whether A2DP offload is enabled.
     *
     * @return true if A2DP offload is enabled
     */
    public boolean isA2dpOffloadEnabled() {
        return mAdapterProperties.isA2dpOffloadEnabled();
    }

    /** Register a bluetooth state callback */
    public void registerBluetoothStateCallback(Executor executor, BluetoothStateCallback callback) {
        mLocalCallbacks.put(callback, executor);
    }

    /** Unregister a bluetooth state callback */
    public void unregisterBluetoothStateCallback(BluetoothStateCallback callback) {
        mLocalCallbacks.remove(callback);
    }

    void registerRemoteCallback(IBluetoothCallback callback) {
        mSystemServerCallbacks.register(callback);
        try {
            callback.setAdapterServiceBinder(mAdapterServiceBinder);
        } catch (RemoteException e) {
            logRemoteException(TAG, e);
        }
    }

    void unregisterRemoteCallback(IBluetoothCallback callback) {
        mSystemServerCallbacks.unregister(callback);
    }

    void bleOnToOn() {
        mAdapterState.sendMessage(AdapterState.USER_TURN_ON);
    }

    void bleOnToOff() {
        mAdapterState.sendMessage(AdapterState.BLE_TURN_OFF);
    }

    private static void recursivelyDeleteDirectory(File file, boolean deleteDirectory) {
        if (!file.isDirectory()) {
            Log.i(TAG, "Deleting file: " + file.getPath());
            file.delete();
            return;
        }

        Log.i(TAG, "Deleting directory content: " + file.getPath());
        for (File innerFile : file.listFiles()) {
            recursivelyDeleteDirectory(innerFile, true);
        }

        if (deleteDirectory) {
            Log.i(TAG, "Deleting empty directory: " + file.getPath());
            file.delete();
        }
    }

    int getScanMode() {
        return mScanMode;
    }

    boolean setScanMode(int mode, String from) {
        if (mSuspend) {
            Log.d(TAG, "Suspending. Don't broadcast scan mode and return early.");
            mScanModeChangedDuringSuspend = true;
            mScanModeChangedDuringSuspendFrom = from;
            mScanModeAfterSuspend = mode;
            return true;
        }

        if (!logAndSetScanModeNative(mode, from)) {
            return false;
        }

        updateScanModeAndBroadcast(mode);
        return true;
    }

    private boolean logAndSetScanModeNative(int mode, String from) {
        mScanModeChanges.add(from + ": " + scanModeName(mode));
        return mNativeInterface.setScanMode(convertScanModeToHal(mode));
    }

    private void updateScanModeAndBroadcast(int mode) {
        mScanMode = mode;
        Intent intent =
                new Intent(BluetoothAdapter.ACTION_SCAN_MODE_CHANGED)
                        .putExtra(BluetoothAdapter.EXTRA_SCAN_MODE, mScanMode)
                        .addFlags(Intent.FLAG_RECEIVER_REGISTERED_ONLY_BEFORE_BOOT);
        sendBroadcast(intent, BLUETOOTH_SCAN, Util.getTempBroadcastBundle());
    }

    @GuardedBy("mEnergyInfoLock")
    private BluetoothActivityEnergyInfo returnCurrentActivityInfo() {
        final BluetoothActivityEnergyInfo info =
                new BluetoothActivityEnergyInfo(
                        SystemClock.elapsedRealtime(),
                        mStackReportedState,
                        mTxTimeTotalMs,
                        mRxTimeTotalMs,
                        mIdleTimeTotalMs,
                        mEnergyUsedTotalVoltAmpSecMicro);

        // Copy the traffic objects whose byte counts are > 0
        final List<UidTraffic> result = new ArrayList<>();
        for (int i = 0; i < mUidTraffic.size(); i++) {
            final UidTraffic traffic = mUidTraffic.valueAt(i);
            if (traffic.getTxBytes() != 0 || traffic.getRxBytes() != 0) {
                result.add(traffic.clone());
            }
        }

        info.setUidTraffic(result);

        return info;
    }

    BluetoothActivityEnergyInfo requestActivityInfo() {
        if (getState() != State.ON || !mAdapterProperties.isActivityAndEnergyReportingSupported()) {
            return null;
        }

        var now = Instant.now();
        var staleThreshold = now.minusMillis(CONTROLLER_ENERGY_UPDATE_TIMEOUT_MILLIS);
        var waitDeadline = now.plusMillis(CONTROLLER_ENERGY_UPDATE_TIMEOUT_MILLIS);

        synchronized (mEnergyInfoLock) {
            // If activity info has just been requested, return the already saved data directly
            if (mLastActivityReport.isAfter(staleThreshold)) {
                return returnCurrentActivityInfo();
            }
            // Pull the live data. The callback will notify mEnergyInfoLock.
            mNativeInterface.readEnergyInfo();
            while (now.isBefore(waitDeadline)) {
                try {
                    mEnergyInfoLock.wait(Duration.between(now, waitDeadline).toMillis());
                    break;
                } catch (InterruptedException e) {
                    now = Instant.now();
                }
            }
            return returnCurrentActivityInfo();
        }
    }

    public int getTotalNumOfTrackableAdvertisements() {
        return mAdapterProperties.getTotalNumOfTrackableAdvertisements();
    }

    /**
     * Return if offloaded TDS filter is supported.
     *
     * @return {@code BluetoothStatusCodes.FEATURE_SUPPORTED} if supported
     */
    public int getOffloadedTransportDiscoveryDataScanSupported() {
        if (mAdapterProperties.isOffloadedTransportDiscoveryDataScanSupported()) {
            return BluetoothStatusCodes.FEATURE_SUPPORTED;
        }
        return BluetoothStatusCodes.FEATURE_NOT_SUPPORTED;
    }

    IBinder getBluetoothGatt() {
        final var gattService = mGattService;
        return gattService == null ? null : gattService.getBinder().orElse(null);
    }

    IBinder getBluetoothScan() {
        final var scanController = getBluetoothScanController();
        return scanController == null ? null : scanController.getBinder();
    }

    @Nullable
    public ScanController getBluetoothScanController() {
        return mScanController;
    }

    @Nullable
    IBinder getBluetoothAdvertise() {
        return mGattService == null ? null : mGattService.getBluetoothAdvertise();
    }

    @Nullable
    IBinder getDistanceMeasurement() {
        return mGattService == null ? null : mGattService.getDistanceMeasurement();
    }

    void getProfile(int id, IBluetoothProfileCallback callback) {
        if (getState() == State.TURNING_ON) {
            return;
        }

        // LE_AUDIO_BROADCAST is not associated with a service and use LE_AUDIO's Binder
        if (id == BluetoothProfile.LE_AUDIO_BROADCAST) {
            id = BluetoothProfile.LE_AUDIO;
        }

        getStartedProfile(id)
                .flatMap(ProfileService::getBinder)
                .ifPresent(binder -> callbackToApp(() -> callback.getProfileReply(binder)));
    }

    private boolean isMediaProfileConnected() {
        if (getA2dpService().map(a2dp -> a2dp.getConnectedDevices().size() > 0).orElse(false)) {
            Log.d(TAG, "isMediaProfileConnected. A2dp is connected");
            return true;
        }
        if (getHearingAidService()
                .map(hearingAid -> hearingAid.getConnectedDevices().size() > 0)
                .orElse(false)) {
            Log.d(TAG, "isMediaProfileConnected. HearingAid is connected");
            return true;
        }
        if (getLeAudioService()
                .map(leAudio -> leAudio.getConnectedDevices().size() > 0)
                .orElse(false)) {
            Log.d(TAG, "isMediaProfileConnected. LeAudio is connected");
            return true;
        }
        Log.d(
                TAG,
                "isMediaProfileConnected: no Media connected."
                        + (" A2dp=" + getA2dpService())
                        + (" HearingAid=" + getHearingAidService())
                        + (" LeAudio=" + getLeAudioService()));
        return false;
    }

    List<BluetoothDevice> getConnectedDevicesForProfile(int profile) {
        List<BluetoothDevice> connectedDevices = new ArrayList<>();
        switch (profile) {
            case BluetoothProfile.A2DP -> {
                final var a2dp = getA2dpService();
                if (a2dp.isPresent()) {
                    connectedDevices = a2dp.get().getConnectedDevices();
                }
            }
            case BluetoothProfile.HEARING_AID -> {
                final var hearingAid = getHearingAidService();
                if (hearingAid.isPresent()) {
                    connectedDevices = hearingAid.get().getConnectedDevices();
                }
            }
            case BluetoothProfile.LE_AUDIO -> {
                final var leAudio = getLeAudioService();
                if (leAudio.isPresent()) {
                    connectedDevices = leAudio.get().getConnectedDevices();
                }
            }
            case BluetoothProfile.HID_HOST -> {
                final var hh = getHidHostService();
                if (hh.isPresent()) {
                    connectedDevices = hh.get().getConnectedDevices();
                }
            }
            default -> Log.e(TAG, "getConnectedDevicesForProfile: profile value is not valid");
        }
        return connectedDevices;
    }

    /**
     * Notify {@link BluetoothProfile} when ACL connection disconnects from {@link BluetoothDevice}
     * for a given {@code transport}.
     */
    public void notifyAclDisconnected(BluetoothDevice device, int transport) {
        if (Flags.leHidConnectionPolicySuspend()) {
            mAdapterSuspend.ifPresent(
                    adapterSuspend -> adapterSuspend.aclDisconnected(device, transport));
        }
        getMapService().ifPresent(profile -> profile.aclDisconnected(device));
        getMapClientService().ifPresent(profile -> profile.aclDisconnected(device, transport));
        getSapService().ifPresent(profile -> profile.aclDisconnected(device));
        getPbapClientService().ifPresent(profile -> profile.aclDisconnected(device, transport));
    }

    /**
     * Notify scan module of a Bluetooth profile's connection state change for a given {@link
     * BluetoothProfile}.
     */
    public void notifyProfileConnectionStateChangeToScan(int profile, int fromState, int toState) {
        final var scanController = getBluetoothScanController();
        if (scanController == null) return;
        scanController.doOnScanThread(
                () ->
                        scanController.notifyProfileConnectionStateChange(
                                profile, fromState, toState));
    }

    /**
     * Handle Bluetooth app state when connection state changes for a given {@code profile}.
     *
     * <p>Currently this function is limited to handling Phone policy but the eventual goal is to
     * move all connection logic here.
     */
    public void handleProfileConnectionStateChange(
            int profile, BluetoothDevice device, int fromState, int toState) {
        mPhonePolicy.ifPresent(
                policy ->
                        policy.profileConnectionStateChanged(profile, device, fromState, toState));
        if (!Flags.leHidConnectionPolicySuspend()) {
            // When leHidConnectionPolicySuspend is true, the function call below is done by
            // updateProfileConnectionAdapterProperties, so it can be safely removed.
            mAdapterSuspend.ifPresent(
                    adapterSuspend ->
                            adapterSuspend.profileConnectionStateChanged(
                                    profile, device, fromState, toState));
        }
        boolean mediaConnected = isMediaProfileConnected();
        if (mIsMediaProfileConnected != mediaConnected) {
            mIsMediaProfileConnected = mediaConnected;
            mHandler.post(
                    () ->
                            broadcastToSystemServerCallbacks(
                                    "mediaConnected",
                                    (c) -> c.onMediaProfileConnectionChange(mediaConnected)));
        }
    }

    /** Handle Bluetooth app state when active device changes for a given {@code profile}. */
    public void handleActiveDeviceChange(int profile, BluetoothDevice device) {
        if (!Flags.admCentralizeActiveDeviceHandling()) {
            mActiveDeviceManager.profileActiveDeviceChanged(profile, device);
        }
        mSilenceDeviceManager.profileActiveDeviceChanged(profile, device);
        mPhonePolicy.ifPresent(policy -> policy.profileActiveDeviceChanged(profile, device));
    }

    /** Notify MAP and Pbap when a new sdp search record is found. */
    public void sendSdpSearchRecord(
            BluetoothDevice device, int status, Parcelable record, ParcelUuid uuid) {
        getMapService().ifPresent(profile -> profile.receiveSdpSearchRecord(status, record, uuid));
        getMapClientService()
                .ifPresent(profile -> profile.receiveSdpSearchRecord(device, status, record, uuid));
        getPbapClientService()
                .ifPresent(profile -> profile.receiveSdpSearchRecord(device, status, record, uuid));
    }

    /** Handle Bluetooth profiles when bond state changes with a {@link BluetoothDevice} */
    public void handleBondStateChanged(BluetoothDevice device, int fromState, int toState) {
        handleBondStateChange(BluetoothProfile.HEADSET, device, fromState, toState);
        handleBondStateChange(BluetoothProfile.A2DP, device, fromState, toState);
        handleBondStateChange(BluetoothProfile.LE_AUDIO, device, fromState, toState);
        handleBondStateChange(BluetoothProfile.HEARING_AID, device, fromState, toState);
        handleBondStateChange(BluetoothProfile.HAP_CLIENT, device, fromState, toState);
        handleBondStateChange(
                BluetoothProfile.LE_AUDIO_BROADCAST_ASSISTANT, device, fromState, toState);
        handleBondStateChange(BluetoothProfile.BATTERY, device, fromState, toState);
        handleBondStateChange(BluetoothProfile.VOLUME_CONTROL, device, fromState, toState);
        handleBondStateChange(BluetoothProfile.PBAP, device, fromState, toState);
        handleBondStateChange(BluetoothProfile.CSIP_SET_COORDINATOR, device, fromState, toState);
        handleBondStateChange(BluetoothProfile.MCP_CLIENT, device, fromState, toState);

        mStorage.onBondStateChanged(device, fromState, toState);

        // Remove the bond caller info when bonding is concluded
        if (Flags.removeBondCallerInfo() && toState != BOND_BONDING) {
            CallerInfo callerInfo = mBondAttemptCallerInfo.remove(device.getAddress());
            if (callerInfo != null) {
                Log.d(TAG, "Removed bond caller info for device: " + device);
            }
        }
    }

    private void handleBondStateChange(int id, BluetoothDevice device, int fromState, int toState) {
        getStartedConnectableProfile(id)
                .filter(ConnectableProfile::isAvailable)
                .ifPresent(profile -> profile.handleBondStateChanged(device, fromState, toState));
    }

    static int convertScanModeToHal(int mode) {
        return switch (mode) {
            case SCAN_MODE_NONE -> AbstractionLayer.BT_SCAN_MODE_NONE;
            case SCAN_MODE_CONNECTABLE -> AbstractionLayer.BT_SCAN_MODE_CONNECTABLE;
            case SCAN_MODE_CONNECTABLE_DISCOVERABLE ->
                    AbstractionLayer.BT_SCAN_MODE_CONNECTABLE_DISCOVERABLE;
            default -> -1;
        };
    }

    // This function is called from JNI. It allows native code to acquire a single wake lock.
    // If the wake lock is already held, this function returns success. Although this function
    // only supports acquiring a single wake lock at a time right now, it will eventually be
    // extended to allow acquiring an arbitrary number of wake locks. The current interface
    // takes |lockName| as a parameter in anticipation of that implementation.
    boolean acquireWakeLock(String lockName) {
        synchronized (this) {
            if (mWakeLock == null) {
                mWakeLock = mPowerManager.newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, lockName);
                if (mAdapterSuspend.isPresent()) {
                    mWakeLock.setStateListener(mHandler::post, mWakeLockListener);
                }
            }

            mWakeLock.acquire();
        }
        return true;
    }

    // This function is called from JNI. It allows native code to release a wake lock acquired
    // by |acquireWakeLock|. If the wake lock is not held, this function returns failure.
    // Note that the release() call is also invoked by {@link #cleanup()} so a synchronization is
    // needed here. See the comment for |acquireWakeLock| for an explanation of the interface.
    boolean releaseWakeLock(String lockName) {
        synchronized (this) {
            if (mWakeLock == null) {
                Log.e(TAG, "Repeated wake lock release; aborting release: " + lockName);
                return false;
            }

            mWakeLock.release();
        }
        return true;
    }

    void energyInfoCallbackInternal(
            int status,
            int ctrlState,
            long txTime,
            long rxTime,
            long idleTime,
            long energyUsed,
            UidTraffic[] data) {
        // Energy is product of mA, V and ms. If the chipset doesn't
        // report it, we have to compute it from time
        if (energyUsed == 0) {
            try {
                final long txMah = Math.multiplyExact(txTime, getTxCurrentMa());
                final long rxMah = Math.multiplyExact(rxTime, getRxCurrentMa());
                final long idleMah = Math.multiplyExact(idleTime, getIdleCurrentMa());
                energyUsed =
                        (long)
                                (Math.addExact(Math.addExact(txMah, rxMah), idleMah)
                                        * getOperatingVolt());
            } catch (ArithmeticException e) {
                Log.wtf(TAG, "overflow in bluetooth energy callback", e);
                // Energy is already 0 if the exception was thrown.
            }
        }

        synchronized (mEnergyInfoLock) {
            mStackReportedState = ctrlState;
            long totalTxTimeMs;
            long totalRxTimeMs;
            long totalIdleTimeMs;
            long totalEnergy;
            try {
                totalTxTimeMs = Math.addExact(mTxTimeTotalMs, txTime);
                totalRxTimeMs = Math.addExact(mRxTimeTotalMs, rxTime);
                totalIdleTimeMs = Math.addExact(mIdleTimeTotalMs, idleTime);
                totalEnergy = Math.addExact(mEnergyUsedTotalVoltAmpSecMicro, energyUsed);
            } catch (ArithmeticException e) {
                // This could be because we accumulated a lot of time, or we got a very strange
                // value from the controller (more likely). Discard this data.
                Log.wtf(TAG, "overflow in bluetooth energy callback", e);
                totalTxTimeMs = mTxTimeTotalMs;
                totalRxTimeMs = mRxTimeTotalMs;
                totalIdleTimeMs = mIdleTimeTotalMs;
                totalEnergy = mEnergyUsedTotalVoltAmpSecMicro;
            }

            mTxTimeTotalMs = totalTxTimeMs;
            mRxTimeTotalMs = totalRxTimeMs;
            mIdleTimeTotalMs = totalIdleTimeMs;
            mEnergyUsedTotalVoltAmpSecMicro = totalEnergy;

            for (UidTraffic traffic : data) {
                UidTraffic existingTraffic = mUidTraffic.get(traffic.getUid());
                if (existingTraffic == null) {
                    mUidTraffic.put(traffic.getUid(), traffic);
                } else {
                    existingTraffic.addRxBytes(traffic.getRxBytes());
                    existingTraffic.addTxBytes(traffic.getTxBytes());
                }
            }
            mLastActivityReport = Instant.now();
            mEnergyInfoLock.notifyAll();
        }
    }

    void energyInfoCallback(
            int status,
            int ctrlState,
            long txTime,
            long rxTime,
            long idleTime,
            long energyUsed,
            UidTraffic[] data) {
        energyInfoCallbackInternal(status, ctrlState, txTime, rxTime, idleTime, energyUsed, data);
        Log.v(
                TAG,
                "energyInfoCallback()"
                        + (" status = " + status)
                        + (" txTime = " + txTime)
                        + (" rxTime = " + rxTime)
                        + (" idleTime = " + idleTime)
                        + (" energyUsed = " + energyUsed)
                        + (" ctrlState = " + Utils.formatSimple("0x%08x", ctrlState))
                        + (" traffic = " + Arrays.toString(data)));
    }

    /** Update metadata change to registered listeners */
    public void onMetadataChanged(BluetoothDevice device, int key, byte[] value) {
        mHandler.post(() -> onMetadataChangedInternal(device, key, value));
    }

    private void onMetadataChangedInternal(BluetoothDevice device, int key, byte[] value) {
        String info = "onMetadataChangedInternal(" + device + ", " + key + ")";

        // pass just interesting metadata to native, to reduce spam
        if (key == BluetoothDevice.METADATA_LE_AUDIO) {
            mNativeInterface.metadataChanged(device, key, value);
        }

        RemoteCallbackList<IBluetoothMetadataListener> list = mMetadataListeners.get(device);
        if (list == null) {
            Log.d(TAG, info + ": No registered listener");
            return;
        }
        int n = list.beginBroadcast();
        Log.d(TAG, info + ": Broadcast to " + n + " receivers");
        for (int i = 0; i < n; i++) {
            try {
                list.getBroadcastItem(i).onMetadataChanged(device, key, value);
            } catch (RemoteException e) {
                Log.d(TAG, info + ": Callback #" + i + " failed (" + e + ")");
            }
        }
        list.finishBroadcast();
    }

    private static int getIdleCurrentMa() {
        return BluetoothProperties.getHardwareIdleCurrentMa().orElse(0);
    }

    private static int getTxCurrentMa() {
        return BluetoothProperties.getHardwareTxCurrentMa().orElse(0);
    }

    private static int getRxCurrentMa() {
        return BluetoothProperties.getHardwareRxCurrentMa().orElse(0);
    }

    private static double getOperatingVolt() {
        return BluetoothProperties.getHardwareOperatingVoltageMv().orElse(0) / 1000.0;
    }

    private static String scanModeName(int scanMode) {
        return switch (scanMode) {
            case SCAN_MODE_NONE -> "SCAN_MODE_NONE";
            case SCAN_MODE_CONNECTABLE -> "SCAN_MODE_CONNECTABLE";
            case SCAN_MODE_CONNECTABLE_DISCOVERABLE -> "SCAN_MODE_CONNECTABLE_DISCOVERABLE";
            default -> "Unknown Scan Mode " + scanMode;
        };
    }

    @Override
    protected void dump(FileDescriptor fd, PrintWriter writer, String[] args) {
        if (args.length == 0) {
            writer.println("Skipping dump in APP SERVICES, see bluetooth_manager section.");
            writer.println("Use --print argument for dumpsys direct from AdapterService.");
            return;
        }

        if ("set-test-mode".equals(args[0])) {
            final var testModeEnabled = "enabled".equalsIgnoreCase(args[1]);
            final var scanController = getBluetoothScanController();
            if (scanController != null) {
                scanController.setTestModeEnabled(testModeEnabled);
            }
            mTestModeEnabled = testModeEnabled;
            return;
        }

        mAdapterSuspend.ifPresent(adapterSuspend -> adapterSuspend.dump(fd, writer, args));

        writer.println();

        mAdapterProperties.dump(writer);

        mRemoteDevices.dump(writer);

        if (mActiveDeviceManager != null) {
            mActiveDeviceManager.dump(writer);
        }

        writer.println("ScanMode: " + scanModeName(getScanMode()));
        StringBuilder sb = new StringBuilder();
        mScanModeChanges.dump(sb);
        writer.println(sb);

        writer.println("Enabled Profile Services:");
        for (int profileId : Config.getSupportedProfiles()) {
            writer.println("  " + BluetoothProfile.getProfileName(profileId));
        }
        writer.println();

        writer.println("LE Gatt clients controlling AutoActiveMode:");
        for (Pair<Integer, BluetoothDevice> pair : mLeGattClientsControllingAutoActiveMode) {
            writer.println("   clientIf:" + pair.first + " " + pair.second);
        }
        writer.println();

        mAdapterState.dump(fd, writer, args);
        writer.println();

        final var stringBuilder = new StringBuilder();
        mSilenceDeviceManager.dump(stringBuilder);

        stringBuilder.append("\n");
        mStorage.dump(stringBuilder);
        stringBuilder.append("\n");

        for (ProfileService profile : mRegisteredProfiles) {
            profile.dump(stringBuilder);
            stringBuilder.append("\n");
        }

        if (Flags.mediaAudioServer()) {
            if (mMediaAudioServer.isPresent()) {
                mMediaAudioServer.get().dump(stringBuilder);
                stringBuilder.append("\n");
            } else {
                stringBuilder.append("\nMediaAudioServer:\n    Disabled\n\n");
            }
        }

        final var scanController = getBluetoothScanController();
        if (scanController != null) {
            scanController.forceRunSyncOnScanThread(() -> scanController.dump(stringBuilder));
        }

        writer.write(stringBuilder.toString());

        final int currentState = mAdapterState.getState();
        if (currentState == State.OFF
                || currentState == State.BLE_TURNING_ON
                || currentState == State.TURNING_OFF
                || currentState == State.BLE_TURNING_OFF) {
            writer.println();
            writer.println("Impossible to dump native stack. state=" + nameForState(currentState));
            writer.println();
            writer.flush();
        } else {
            writer.flush();
            mNativeInterface.dump(fd, args);
        }
    }

    private final Object mDeviceConfigLock = new Object();

    /**
     * Predicate that can be applied to names to determine if a device is well-known to be used for
     * physical location.
     */
    @GuardedBy("mDeviceConfigLock")
    private Predicate<String> mLocationDenylistName = (v) -> false;

    /**
     * Predicate that can be applied to MAC addresses to determine if a device is well-known to be
     * used for physical location.
     */
    @GuardedBy("mDeviceConfigLock")
    private Predicate<byte[]> mLocationDenylistMac = (v) -> false;

    /**
     * Predicate that can be applied to Advertising Data payloads to determine if a device is
     * well-known to be used for physical location.
     */
    @GuardedBy("mDeviceConfigLock")
    private Predicate<byte[]> mLocationDenylistAdvertisingData = (v) -> false;

    @GuardedBy("mDeviceConfigLock")
    private int mScanQuotaCount = ScanUtil.DEFAULT_SCAN_QUOTA_COUNT;

    @GuardedBy("mDeviceConfigLock")
    private Duration mScanQuotaWindow = ScanUtil.DEFAULT_SCAN_QUOTA_WINDOW;

    @GuardedBy("mDeviceConfigLock")
    private Duration mScanTimeout = ScanUtil.DEFAULT_SCAN_TIMEOUT;

    @GuardedBy("mDeviceConfigLock")
    private Duration mScanUpgradeDuration = ScanUtil.DEFAULT_SCAN_UPGRADE_DURATION;

    @GuardedBy("mDeviceConfigLock")
    private Duration mScanDowngradeDuration =
            ScanUtil.DEFAULT_SCAN_DOWNGRADE_DURATION_BT_CONNECTING;

    @GuardedBy("mDeviceConfigLock")
    private Duration mScreenOffLowPowerWindow = ScanUtil.SCAN_MODE_SCREEN_OFF_LOW_POWER_WINDOW;

    @GuardedBy("mDeviceConfigLock")
    private Duration mScreenOffLowPowerInterval = ScanUtil.SCAN_MODE_SCREEN_OFF_LOW_POWER_INTERVAL;

    @GuardedBy("mDeviceConfigLock")
    private Duration mScreenOffBalancedWindow = ScanUtil.SCAN_MODE_SCREEN_OFF_BALANCED_WINDOW;

    @GuardedBy("mDeviceConfigLock")
    private Duration mScreenOffBalancedInterval = ScanUtil.SCAN_MODE_SCREEN_OFF_BALANCED_INTERVAL;

    @GuardedBy("mDeviceConfigLock")
    private String mLeAudioAllowList;

    public @NonNull Predicate<String> getLocationDenylistName() {
        synchronized (mDeviceConfigLock) {
            return mLocationDenylistName;
        }
    }

    public @NonNull Predicate<byte[]> getLocationDenylistMac() {
        synchronized (mDeviceConfigLock) {
            return mLocationDenylistMac;
        }
    }

    public @NonNull Predicate<byte[]> getLocationDenylistAdvertisingData() {
        synchronized (mDeviceConfigLock) {
            return mLocationDenylistAdvertisingData;
        }
    }

    /** Returns scan quota count. */
    public int getScanQuotaCount() {
        synchronized (mDeviceConfigLock) {
            return mScanQuotaCount;
        }
    }

    /** Returns scan quota window. */
    public Duration getScanQuotaWindow() {
        synchronized (mDeviceConfigLock) {
            return mScanQuotaWindow;
        }
    }

    /** Returns scan timeout. */
    public Duration getScanTimeout() {
        synchronized (mDeviceConfigLock) {
            return mScanTimeout;
        }
    }

    /** Returns scan upgrade duration. */
    public Duration getScanUpgradeDuration() {
        synchronized (mDeviceConfigLock) {
            return mScanUpgradeDuration;
        }
    }

    /** Returns scan downgrade duration. */
    public Duration getScanDowngradeDuration() {
        synchronized (mDeviceConfigLock) {
            return mScanDowngradeDuration;
        }
    }

    /** Returns SCREEN_OFF low power scan window. */
    public Duration getScreenOffLowPowerWindow() {
        synchronized (mDeviceConfigLock) {
            return mScreenOffLowPowerWindow;
        }
    }

    /** Returns SCREEN_OFF low power scan interval. */
    public Duration getScreenOffLowPowerInterval() {
        synchronized (mDeviceConfigLock) {
            return mScreenOffLowPowerInterval;
        }
    }

    /** Returns SCREEN_OFF_BALANCED scan window. */
    public Duration getScreenOffBalancedWindow() {
        synchronized (mDeviceConfigLock) {
            return mScreenOffBalancedWindow;
        }
    }

    /** Returns SCREEN_OFF_BALANCED scan interval. */
    public Duration getScreenOffBalancedInterval() {
        synchronized (mDeviceConfigLock) {
            return mScreenOffBalancedInterval;
        }
    }

    @VisibleForTesting
    public class DeviceConfigListener implements DeviceConfig.OnPropertiesChangedListener {
        private static final String LOCATION_DENYLIST_NAME = "location_denylist_name";
        private static final String LOCATION_DENYLIST_MAC = "location_denylist_mac";
        private static final String LOCATION_DENYLIST_ADVERTISING_DATA =
                "location_denylist_advertising_data";
        private static final String SCAN_QUOTA_COUNT = "scan_quota_count";
        private static final String SCAN_QUOTA_WINDOW_MILLIS = "scan_quota_window_millis";
        private static final String SCAN_TIMEOUT_MILLIS = "scan_timeout_millis";
        private static final String SCAN_UPGRADE_DURATION_MILLIS = "scan_upgrade_duration_millis";
        private static final String SCAN_DOWNGRADE_DURATION_MILLIS =
                "scan_downgrade_duration_millis";
        private static final String SCREEN_OFF_LOW_POWER_WINDOW_MILLIS =
                "screen_off_low_power_window_millis";
        private static final String SCREEN_OFF_LOW_POWER_INTERVAL_MILLIS =
                "screen_off_low_power_interval_millis";
        private static final String SCREEN_OFF_BALANCED_WINDOW_MILLIS =
                "screen_off_balanced_window_millis";
        private static final String SCREEN_OFF_BALANCED_INTERVAL_MILLIS =
                "screen_off_balanced_interval_millis";
        private static final String LE_AUDIO_ALLOW_LIST = "le_audio_allow_list";

        /**
         * Default denylist which matches Eddystone (except for Eddystone-E2EE-EID) and iBeacon
         * payloads.
         */
        private static final String DEFAULT_LOCATION_DENYLIST_ADVERTISING_DATA =
                "⊈0016AAFE40/00FFFFFFF0,⊆0016AAFE/00FFFFFF,⊆00FF4C0002/00FFFFFFFF";

        public void start() {
            DeviceConfig.addOnPropertiesChangedListener(
                    DeviceConfig.NAMESPACE_BLUETOOTH, BackgroundThread.getExecutor(), this);
            onPropertiesChanged(DeviceConfig.getProperties(DeviceConfig.NAMESPACE_BLUETOOTH));
        }

        @Override
        public void onPropertiesChanged(DeviceConfig.Properties properties) {
            synchronized (mDeviceConfigLock) {
                final String name = properties.getString(LOCATION_DENYLIST_NAME, null);
                mLocationDenylistName =
                        !TextUtils.isEmpty(name)
                                ? Pattern.compile(name).asPredicate()
                                : (v) -> false;
                mLocationDenylistMac =
                        BytesMatcher.decode(properties.getString(LOCATION_DENYLIST_MAC, null));
                mLocationDenylistAdvertisingData =
                        BytesMatcher.decode(
                                properties.getString(
                                        LOCATION_DENYLIST_ADVERTISING_DATA,
                                        DEFAULT_LOCATION_DENYLIST_ADVERTISING_DATA));
                mScanQuotaCount =
                        properties.getInt(SCAN_QUOTA_COUNT, ScanUtil.DEFAULT_SCAN_QUOTA_COUNT);
                mScanQuotaWindow =
                        DeviceConfigUtils.getDuration(
                                properties,
                                SCAN_QUOTA_WINDOW_MILLIS,
                                ScanUtil.DEFAULT_SCAN_QUOTA_WINDOW);
                mScanTimeout =
                        DeviceConfigUtils.getDuration(
                                properties, SCAN_TIMEOUT_MILLIS, ScanUtil.DEFAULT_SCAN_TIMEOUT);
                mScanUpgradeDuration =
                        DeviceConfigUtils.getDuration(
                                properties,
                                SCAN_UPGRADE_DURATION_MILLIS,
                                ScanUtil.DEFAULT_SCAN_UPGRADE_DURATION);
                mScanDowngradeDuration =
                        DeviceConfigUtils.getDuration(
                                properties,
                                SCAN_DOWNGRADE_DURATION_MILLIS,
                                ScanUtil.DEFAULT_SCAN_DOWNGRADE_DURATION_BT_CONNECTING);
                mScreenOffLowPowerWindow =
                        DeviceConfigUtils.getDuration(
                                properties,
                                SCREEN_OFF_LOW_POWER_WINDOW_MILLIS,
                                ScanUtil.SCAN_MODE_SCREEN_OFF_LOW_POWER_WINDOW);
                mScreenOffLowPowerInterval =
                        DeviceConfigUtils.getDuration(
                                properties,
                                SCREEN_OFF_LOW_POWER_INTERVAL_MILLIS,
                                ScanUtil.SCAN_MODE_SCREEN_OFF_LOW_POWER_INTERVAL);
                mScreenOffBalancedWindow =
                        DeviceConfigUtils.getDuration(
                                properties,
                                SCREEN_OFF_BALANCED_WINDOW_MILLIS,
                                ScanUtil.SCAN_MODE_SCREEN_OFF_BALANCED_WINDOW);
                mScreenOffBalancedInterval =
                        DeviceConfigUtils.getDuration(
                                properties,
                                SCREEN_OFF_BALANCED_INTERVAL_MILLIS,
                                ScanUtil.SCAN_MODE_SCREEN_OFF_BALANCED_INTERVAL);
                mLeAudioAllowList = properties.getString(LE_AUDIO_ALLOW_LIST, "");

                if (!mLeAudioAllowList.isEmpty()) {
                    List<String> leAudioAllowlistFromDeviceConfig =
                            Arrays.asList(mLeAudioAllowList.split(","));
                    BluetoothProperties.le_audio_allow_list(leAudioAllowlistFromDeviceConfig);
                }

                if (Flags.leaudioAllowlistRefactor()) {
                    cacheLeAudioAllowlistDevicesFromProp();
                } else {
                    List<String> leAudioAllowlistProp = BluetoothProperties.le_audio_allow_list();
                    if (leAudioAllowlistProp != null && !leAudioAllowlistProp.isEmpty()) {
                        mLeAudioAllowDevices.clear();
                        mLeAudioAllowDevices.addAll(leAudioAllowlistProp);
                    }
                }
            }
        }
    }

    /** A callback that will be called when AdapterState is changed */
    public interface BluetoothStateCallback {
        /**
         * Called when the status of bluetooth adapter is changing. {@code prevState} and {@code
         * newState} takes one of following values defined in BluetoothAdapter.java: STATE_OFF,
         * STATE_TURNING_ON, STATE_ON, STATE_TURNING_OFF, STATE_BLE_TURNING_ON, STATE_BLE_ON,
         * STATE_BLE_TURNING_OFF
         *
         * @param prevState the previous Bluetooth state.
         * @param newState the new Bluetooth state.
         */
        void onBluetoothStateChange(int prevState, int newState);
    }

    /**
     * Obfuscate Bluetooth MAC address into a PII free ID string
     *
     * @param device Bluetooth device whose MAC address will be obfuscated
     * @return a byte array that is unique to this MAC address on this device, or empty byte array
     *     when either device is null or obfuscateAddressNative fails
     */
    public byte[] obfuscateAddress(BluetoothDevice device) {
        if (device == null) {
            return new byte[0];
        }
        return mNativeInterface.obfuscateAddress(Util.getByteAddress(device));
    }

    /**
     * Get dynamic audio buffer size supported type
     *
     * @return support
     *     <p>Possible values are {@link BluetoothA2dp#DYNAMIC_BUFFER_SUPPORT_NONE}, {@link
     *     BluetoothA2dp#DYNAMIC_BUFFER_SUPPORT_A2DP_OFFLOAD}, {@link
     *     BluetoothA2dp#DYNAMIC_BUFFER_SUPPORT_A2DP_SOFTWARE_ENCODING}.
     */
    public int getDynamicBufferSupport() {
        return mAdapterProperties.getDynamicBufferSupport();
    }

    /**
     * Get dynamic audio buffer size
     *
     * @return BufferConstraints
     */
    public BufferConstraints getBufferConstraints() {
        return mAdapterProperties.getBufferConstraints();
    }

    /**
     * Set dynamic audio buffer size
     *
     * @param codec Audio codec
     * @param value buffer millis
     * @return true if the settings is successful, false otherwise
     */
    public boolean setBufferLengthMillis(int codec, int value) {
        return mAdapterProperties.setBufferLengthMillis(codec, value);
    }

    /**
     * Get an incremental id of Bluetooth metrics and log
     *
     * @param device Bluetooth device
     * @return int of id for Bluetooth metrics and logging, 0 if the device is invalid
     */
    public int getMetricId(BluetoothDevice device) {
        if (device == null) {
            return 0;
        }
        return mNativeInterface.getMetricId(Util.getByteAddress(device));
    }

    public CompanionManager getCompanionManager() {
        return mCompanionManager;
    }

    /**
     * Get audio policy feature support status
     *
     * @param device Bluetooth device to be checked for audio policy support
     * @return int status of the remote support for audio policy feature
     */
    int isRequestAudioPolicyAsSinkSupported(BluetoothDevice device) {
        var headsetClient = getHeadsetClientService();
        if (headsetClient.isEmpty()) {
            Log.e(TAG, "No audio transport connected");
            return BluetoothStatusCodes.FEATURE_NOT_CONFIGURED;
        } else {
            return headsetClient.get().getAudioPolicyRemoteSupported(device);
        }
    }

    /**
     * Set audio policy for remote device
     *
     * @param device Bluetooth device to be set policy for
     * @return int result status for requestAudioPolicyAsSink API
     */
    int requestAudioPolicyAsSink(BluetoothDevice device, BluetoothSinkAudioPolicy policies) {
        DeviceProperties deviceProp = mRemoteDevices.getDeviceProperties(device);
        if (deviceProp == null) {
            return BluetoothStatusCodes.ERROR_DEVICE_NOT_BONDED;
        }

        var headsetClient = getHeadsetClientService();
        if (headsetClient.isEmpty()) {
            Log.e(TAG, "HeadsetClient not connected");
            return BluetoothStatusCodes.ERROR_PROFILE_NOT_CONNECTED;
        } else {
            if (isRequestAudioPolicyAsSinkSupported(device)
                    != BluetoothStatusCodes.FEATURE_SUPPORTED) {
                throw new UnsupportedOperationException(
                        "Request Audio Policy As Sink not supported");
            }
            deviceProp.setHfAudioPolicyForRemoteAg(policies);
            headsetClient.get().setAudioPolicy(device, policies);
            return BluetoothStatusCodes.SUCCESS;
        }
    }

    /**
     * Get audio policy for remote device
     *
     * @param device Bluetooth device to be set policy for
     * @return {@link BluetoothSinkAudioPolicy} policy stored for the device
     */
    public BluetoothSinkAudioPolicy getRequestedAudioPolicyAsSink(BluetoothDevice device) {
        DeviceProperties deviceProp = mRemoteDevices.getDeviceProperties(device);
        if (deviceProp == null) {
            return null;
        }

        if (getHeadsetClientService().isEmpty()) {
            Log.e(TAG, "HeadsetClient not connected");
            return null;
        } else {
            return deviceProp.getHfAudioPolicyForRemoteAg();
        }
    }

    /**
     * Allow audio low latency
     *
     * @param allowed true if audio low latency is being allowed
     * @param device device whose audio low latency will be allowed or disallowed
     * @return boolean true if audio low latency is successfully allowed or disallowed
     */
    public boolean allowLowLatencyAudio(boolean allowed, BluetoothDevice device) {
        return mNativeInterface.allowLowLatencyAudio(allowed, Util.getByteAddress(device));
    }

    /**
     * get remote PBAP PCE version.
     *
     * @param address of remote device
     * @return int value other than 0 if remote PBAP PCE version is found
     */
    public int getRemotePbapPceVersion(String address) {
        return mNativeInterface.getRemotePbapPceVersion(address);
    }

    /**
     * check, if PBAP PSE dynamic version upgrade is enabled.
     *
     * @return true/false.
     */
    public boolean pbapPseDynamicVersionUpgradeIsEnabled() {
        return mNativeInterface.pbapPseDynamicVersionUpgradeIsEnabled();
    }

    /** Sets the battery level of the remote device */
    public void setBatteryLevel(BluetoothDevice device, int batteryLevel, boolean isBas) {
        if (batteryLevel == BATTERY_LEVEL_UNKNOWN) {
            mRemoteDevices.resetBatteryLevel(device, isBas);
        } else {
            mRemoteDevices.updateBatteryLevel(device, batteryLevel, isBas);
        }
    }

    /**
     * Check if a given device's address or remote device name matches a known interoperability
     * workaround identified by the interop feature. remote device name will be fetched internally
     * based on the given address at stack layer.
     *
     * @param feature a given interop feature defined in {@link InteropFeature}.
     * @param device the remote device to be matched.
     * @return {@code true} if matched, {@code false} otherwise
     */
    public boolean interopMatchDevice(InteropFeature feature, BluetoothDevice device) {
        return mNativeInterface.interopMatchAddrOrName(feature.name(), device.getAddress());
    }

    /**
     * Checks the remote device is in the LE Audio allow list or not.
     *
     * @param device the device to check
     * @return boolean true if the device is in the allow list, false otherwise.
     */
    public boolean isLeAudioAllowed(BluetoothDevice device) {
        DeviceProperties deviceProp = mRemoteDevices.getDeviceProperties(device);

        if (deviceProp == null
                || deviceProp.getModelName() == null
                || !mLeAudioAllowDevices.contains(deviceProp.getModelName())) {

            return false;
        }

        return true;
    }

    /**
     * Get type of the remote device
     *
     * @param device the device to check
     * @return int device type
     */
    public int getRemoteType(BluetoothDevice device) {
        return mRemoteDevices.getType(device);
    }

    /**
     * Sends service discovery UUIDs internally within the stack. This is meant to remove internal
     * dependencies on the broadcast {@link BluetoothDevice#ACTION_UUID}.
     *
     * @param device is the remote device whose UUIDs have been discovered
     * @param uuids are the services supported on the remote device
     */
    void sendUuidsInternal(BluetoothDevice device, ParcelUuid[] uuids) {
        if (device == null) {
            Log.w(TAG, "sendUuidsInternal: null device");
            return;
        }
        if (uuids == null) {
            Log.w(TAG, "sendUuidsInternal: uuids is null");
            return;
        }
        Log.i(TAG, "sendUuidsInternal: Received service discovery UUIDs for device " + device);
        for (int i = 0; i < uuids.length; i++) {
            Log.d(TAG, "sendUuidsInternal: index=" + i + " uuid=" + uuids[i]);
        }
        mPhonePolicy.ifPresent(policy -> policy.onUuidsDiscovered(device, uuids));
    }

    /** Get the number of the supported offloaded LE COC sockets. */
    public int getNumberOfSupportedOffloadedLeCocSockets() {
        return mAdapterProperties.getNumberOfSupportedOffloadedLeCocSockets();
    }

    /** Check if the offloaded LE COC socket is supported. */
    public boolean isLeCocSocketOffloadSupported() {
        int val = getNumberOfSupportedOffloadedLeCocSockets();
        return val > 0;
    }

    /** Get the number of the supported offloaded RFCOMM sockets. */
    public int getNumberOfSupportedOffloadedRfcommSockets() {
        return mAdapterProperties.getNumberOfSupportedOffloadedRfcommSockets();
    }

    /** Check if the offloaded RFCOMM socket is supported. */
    public boolean isRfcommSocketOffloadSupported() {
        int val = getNumberOfSupportedOffloadedRfcommSockets();
        return val > 0;
    }

    /**
     * Get the link status of the given transport.
     *
     * <p>It will extract the remote device properties, and use the link details to construct the
     * link status.
     *
     * @param transport the transport to get the link status for
     * @return the link status of the given transport
     */
    public EncryptionStatus getEncryptionStatus(BluetoothDevice device, int transport) {
        DeviceProperties deviceProp = mRemoteDevices.getDeviceProperties(device);
        if (deviceProp == null) {
            return null;
        }
        return deviceProp.getEncryptionStatus(transport);
    }

    /**
     * Checks if the device is connected on the given transport.
     *
     * <p>It will extract the remote device properties, and use the connection handle to check if
     * the device is connected.
     *
     * @param transport the transport to check the connection for
     * @return true if the device is connected to the given transport, false otherwise
     */
    boolean isConnected(BluetoothDevice device, int transport) {
        DeviceProperties deviceProp = mRemoteDevices.getDeviceProperties(device);
        return (deviceProp != null)
                && (deviceProp.getConnectionHandle(transport) != BluetoothDevice.ERROR);
    }

    void setSuspendState(boolean suspend) {
        if (mSuspend == suspend) {
            return;
        }

        mSuspend = suspend;
        if (suspend) {
            // When suspending set scan to NONE to minimize power usage. Don't broadcast this
            // event change to minimize disturbance to other apps. It will be recovered on resume.
            mScanModeChangedDuringSuspend = false;
            mScanModeChangedDuringSuspendFrom = "";
            mScanModeAfterSuspend = mScanMode;
            logAndSetScanModeNative(SCAN_MODE_NONE, "handleSuspend");
        } else {
            // When resuming, always call setScanMode since the actual mode might be updated
            // in the native layer and not propagated up. However only broadcast when
            // someone demands a change when we're suspending.
            if (logAndSetScanModeNative(
                    mScanModeAfterSuspend, "handleResume " + mScanModeChangedDuringSuspendFrom)) {
                if (mScanModeChangedDuringSuspend) {
                    updateScanModeAndBroadcast(mScanModeAfterSuspend);
                }
            }
        }
    }

    /** Check if the offloaded GATT client is supported. */
    public boolean isGattClientOffloadSupported() {
        int val = mAdapterProperties.getSupportedOffloadedGattClientProperties();
        return val != 0;
    }

    /** Check if the offloaded GATT server is supported. */
    public boolean isGattServerOffloadSupported() {
        int val = mAdapterProperties.getSupportedOffloadedGattServerProperties();
        return val != 0;
    }

    /** Get the supported GATT offload capabilities. */
    public GattOffloadCapabilities.InnerParcel getSupportedGattOffloadCapabilities() {
        return new GattOffloadCapabilities.InnerParcel(
                mAdapterProperties.getSupportedOffloadedGattClientProperties(),
                mAdapterProperties.getSupportedOffloadedGattServerProperties());
    }

    /**
     * Populate the (ACTION_FOUND) intent with the discovering packages and send the broadcast.
     *
     * @param deviceProp the device properties
     */
    public void discoveryResultHandler(DeviceProperties deviceProp) {
        if (deviceProp == null) {
            Log.e(TAG, "discoveryResultHandler: Invalid arguments");
            return;
        }

        synchronized (mDiscoveringPackages) {
            if (mDiscoveringPackages.isEmpty()) {
                Log.e(
                        TAG,
                        "discoveryResultHandler: deviceFoundCallback was triggered, but no"
                                + " discovering packages found!");
                return;
            }
        }

        BluetoothDevice device = deviceProp.getDevice();
        Intent intent = prepareDiscoveryResultIntent(deviceProp);

        synchronized (mDiscoveringPackages) {
            // Populate the intent with the discovering packages and send the broadcast.
            for (Map.Entry<CallingPackage, DiscoveringPackageInfo> pkgEntry :
                    mDiscoveringPackages.entrySet()) {
                sendDiscoveryResult(pkgEntry.getKey(), pkgEntry.getValue(), device, intent);
            }

            if (Flags.sendDiscoveredDevToNewPkgs()) {
                // Cache the new discovered device to the discovered device list.
                mDiscoveredDevices.add(device);
            }
        }
    }

    public BondStatus getBondStatus(BluetoothDevice device, int transport) {
        DeviceProperties deviceProp = mRemoteDevices.getDeviceProperties(device);
        if (deviceProp == null) {
            return null;
        }

        return deviceProp.getBondStatus(transport);
    }

    /**
     * Prepare the ACTION_FOUND intent to be sent to required packages.
     *
     * @param deviceProp the discovered device properties to be used in the intent
     * @return the prepared intent
     */
    private static Intent prepareDiscoveryResultIntent(@NonNull DeviceProperties deviceProp) {
        BluetoothDevice device = deviceProp.getDevice();

        Intent intent = new Intent(BluetoothDevice.ACTION_FOUND);
        intent.putExtra(BluetoothDevice.EXTRA_DEVICE, device);
        intent.putExtra(
                BluetoothDevice.EXTRA_CLASS, new BluetoothClass(deviceProp.getBluetoothClass()));
        intent.putExtra(BluetoothDevice.EXTRA_RSSI, deviceProp.getRssi());
        intent.putExtra(BluetoothDevice.EXTRA_NAME, deviceProp.getName());
        intent.putExtra(
                BluetoothDevice.EXTRA_IS_COORDINATED_SET_MEMBER,
                deviceProp.isCoordinatedSetMember());

        int discoveryResultType = deviceProp.getDiscoveryResultType();
        if (discoveryResultType != BluetoothDevice.DEVICE_TYPE_UNKNOWN) {
            intent.putExtra(BluetoothDevice.EXTRA_DISCOVERY_RESULT_TYPE, discoveryResultType);

            if ((discoveryResultType & BluetoothDevice.DEVICE_TYPE_CLASSIC) != 0) {
                ParcelUuid[] uuids = deviceProp.getUuidsFromExtendedInquiryResponse();
                intent.putExtra(BluetoothDevice.EXTRA_UUID, uuids);
            }

            if ((discoveryResultType & BluetoothDevice.DEVICE_TYPE_LE) != 0) {
                ParcelUuid[] uuids = deviceProp.getUuidsFromLeAdvertisingData();
                intent.putExtra(BluetoothDevice.EXTRA_UUID_LE, uuids);
            }
        }

        return intent;
    }

    /**
     * Send the discovery result intent to the specific package.
     *
     * @param callingPackage the discovering package
     * @param pkgInfo the package information of the discovering package
     * @param discoveredDevice the discovered device to be sent in the intent
     * @param intent the intent to be sent
     */
    private void sendDiscoveryResult(
            @NonNull CallingPackage callingPackage,
            @NonNull DiscoveringPackageInfo pkgInfo,
            @NonNull BluetoothDevice discoveredDevice,
            @NonNull Intent intent) {
        if (pkgInfo.getHasDisavowedLocation()) {
            if (mLocationDenylistPredicate.test(discoveredDevice)) {
                return;
            }
        }

        intent.setPackage(callingPackage.packageName);
        intent.setAction(BluetoothDevice.ACTION_FOUND);
        if (pkgInfo.getPermission() != null) {
            sendBroadcastAsUserMultiplePermissions(
                    intent, callingPackage.user,
                    new String[] {BLUETOOTH_SCAN, pkgInfo.getPermission()},
                    Util.getTempBroadcastOptions());
        } else {
            sendBroadcastAsUser(intent, callingPackage.user, BLUETOOTH_SCAN, Util.getTempBroadcastBundle());
        }
    }

    @Override
    public void sendBroadcast(Intent intent, @Nullable String receiverPermission) {
        for (UserHandle user : mUserManager.getEnabledProfiles()) {
            sendBroadcastAsUser(intent, user, receiverPermission);
        }
    }

    @Override
    public void sendBroadcastMultiplePermissions(@NonNull Intent intent, @NonNull String[] receiverPermissions, @Nullable BroadcastOptions options) {
        for (UserHandle user : mUserManager.getEnabledProfiles()) {
            sendBroadcastAsUserMultiplePermissions(intent, user, receiverPermissions, options);
        }
    }

    @Override
    public void sendBroadcast(@NonNull Intent intent, @Nullable String receiverPermission, @Nullable Bundle options) {
        for (UserHandle user : mUserManager.getEnabledProfiles()) {
            sendBroadcastAsUser(intent, user, receiverPermission, options);
        }
    }

    @Override
    public void sendOrderedBroadcast(Intent intent, @Nullable String receiverPermission) {
        for (UserHandle user : mUserManager.getEnabledProfiles()) {
            sendOrderedBroadcastAsUser(intent, user, receiverPermission, AppOpsManager.OP_NONE, null, null, null, Activity.RESULT_OK, null, null);
        }
    }

    @Override
    public void sendOrderedBroadcast(@NonNull Intent intent, @Nullable String receiverPermission, @Nullable Bundle options) {
        for (UserHandle user : mUserManager.getEnabledProfiles()) {
            sendOrderedBroadcastAsUser(intent, user, receiverPermission, AppOpsManager.OP_NONE, options, null, null, Activity.RESULT_OK, null, null);
        }
    }

    @Override
    public void sendOrderedBroadcast(Intent intent, @Nullable String receiverPermission, @Nullable BroadcastReceiver resultReceiver, @Nullable Handler scheduler, int initialCode, @Nullable String initialData, @Nullable Bundle initialExtras) {
        for (UserHandle user : mUserManager.getEnabledProfiles()) {
            sendOrderedBroadcastAsUser(intent, user, receiverPermission, AppOpsManager.OP_NONE, null, resultReceiver, scheduler,
                    initialCode, initialData, initialExtras);
        }
    }

    @Override
    public void sendOrderedBroadcast(@NonNull Intent intent, @Nullable String receiverPermission, @Nullable Bundle options, @Nullable BroadcastReceiver resultReceiver, @Nullable Handler scheduler, int initialCode, @Nullable String initialData, @Nullable Bundle initialExtras) {
        for (UserHandle user : mUserManager.getEnabledProfiles()) {
            sendOrderedBroadcastAsUser(intent, user, receiverPermission, AppOpsManager.OP_NONE, options,
                    resultReceiver, scheduler, initialCode, initialData, initialExtras);
        }
    }
}
