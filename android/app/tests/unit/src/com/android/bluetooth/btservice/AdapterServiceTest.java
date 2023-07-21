/*
 * Copyright 2017 The Android Open Source Project
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

import static android.Manifest.permission.BLUETOOTH_SCAN;

import static com.google.common.truth.Truth.assertThat;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

import android.app.AlarmManager;
import android.app.AppOpsManager;
import android.app.admin.DevicePolicyManager;
import android.bluetooth.BluetoothAdapter;
import android.bluetooth.BluetoothDevice;
import android.bluetooth.BluetoothManager;
import android.bluetooth.IBluetoothCallback;
import android.companion.CompanionDeviceManager;
import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import android.content.pm.PermissionInfo;
import android.content.res.Resources;
import android.media.AudioManager;
import android.os.AsyncTask;
import android.os.BatteryStatsManager;
import android.os.Binder;
import android.os.Bundle;
import android.os.Looper;
import android.os.PowerManager;
import android.os.Process;
import android.os.RemoteException;
import android.os.UserHandle;
import android.os.UserManager;
import android.permission.PermissionCheckerManager;
import android.permission.PermissionManager;
import android.provider.Settings;
import android.sysprop.BluetoothProperties;
import android.test.mock.MockContentProvider;
import android.test.mock.MockContentResolver;
import android.util.Log;

import androidx.test.InstrumentationRegistry;
import androidx.test.filters.MediumTest;
import androidx.test.runner.AndroidJUnit4;

import com.android.bluetooth.TestUtils;
import com.android.bluetooth.Utils;
import com.android.bluetooth.a2dp.A2dpService;
import com.android.bluetooth.a2dpsink.A2dpSinkService;
import com.android.bluetooth.avrcp.AvrcpTargetService;
import com.android.bluetooth.avrcpcontroller.AvrcpControllerService;
import com.android.bluetooth.bas.BatteryService;
import com.android.bluetooth.bass_client.BassClientService;
import com.android.bluetooth.csip.CsipSetCoordinatorService;
import com.android.bluetooth.gatt.GattService;
import com.android.bluetooth.hap.HapClientService;
import com.android.bluetooth.hearingaid.HearingAidService;
import com.android.bluetooth.hfp.HeadsetService;
import com.android.bluetooth.hfpclient.HeadsetClientService;
import com.android.bluetooth.hid.HidDeviceService;
import com.android.bluetooth.hid.HidHostService;
import com.android.bluetooth.le_audio.LeAudioService;
import com.android.bluetooth.map.BluetoothMapService;
import com.android.bluetooth.mapclient.MapClientService;
import com.android.bluetooth.mcp.McpService;
import com.android.bluetooth.opp.BluetoothOppService;
import com.android.bluetooth.pan.PanService;
import com.android.bluetooth.pbap.BluetoothPbapService;
import com.android.bluetooth.pbapclient.PbapClientService;
import com.android.bluetooth.sap.SapService;
import com.android.bluetooth.tbs.TbsService;
import com.android.bluetooth.vc.VolumeControlService;
import com.android.internal.app.IBatteryStats;

import libcore.util.HexEncoding;

import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import java.io.FileDescriptor;
import java.io.PrintWriter;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.List;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

@MediumTest
@RunWith(AndroidJUnit4.class)
public class AdapterServiceTest {
    private static final String TAG = AdapterServiceTest.class.getSimpleName();
    private static final String TEST_BT_ADDR_1 = "00:11:22:33:44:55";
    private static final String TEST_BT_ADDR_2 = "00:11:22:33:44:66";

    private AdapterService mAdapterService;

    private @Mock Context mMockContext;
    private @Mock ApplicationInfo mMockApplicationInfo;
    private @Mock Resources mMockResources;
    private @Mock ProfileService mMockGattService;
    private @Mock ProfileService mMockService;
    private @Mock ProfileService mMockService2;
    private @Mock IBluetoothCallback mIBluetoothCallback;
    private @Mock Binder mBinder;
    private @Mock android.app.Application mApplication;
    private @Mock MetricsLogger mMockMetricsLogger;

    // Mocked SystemService
    private @Mock AlarmManager mMockAlarmManager;
    private @Mock AppOpsManager mMockAppOpsManager;
    private @Mock AudioManager mMockAudioManager;
    private @Mock DevicePolicyManager mMockDevicePolicyManager;
    private @Mock UserManager mMockUserManager;

    // SystemService that are not mocked
    private BluetoothManager mBluetoothManager;
    private CompanionDeviceManager mCompanionDeviceManager;
    private PowerManager mPowerManager;
    private PermissionCheckerManager mPermissionCheckerManager;
    private PermissionManager mPermissionManager;
    // BatteryStatsManager is final and cannot be mocked with regular mockito, so just mock the
    // underlying binder calls.
    final BatteryStatsManager mBatteryStatsManager =
            new BatteryStatsManager(mock(IBatteryStats.class));

    private static final int CONTEXT_SWITCH_MS = 100;
    private static final int PROFILE_SERVICE_TOGGLE_TIME_MS = 200;
    private static final int GATT_START_TIME_MS = 1000;
    private static final int ONE_SECOND_MS = 1000;
    private static final int NATIVE_INIT_MS = 8000;
    private static final int NATIVE_DISABLE_MS = 8000;


    private PackageManager mMockPackageManager;
    private MockContentResolver mMockContentResolver;
    private HashMap<String, HashMap<String, String>> mAdapterConfig;
    private int mForegroundUserId;

    static void configureEnabledProfiles() {
        Log.e(TAG, "configureEnabledProfiles");
        Config.setProfileEnabled(PanService.class, true);
        Config.setProfileEnabled(BluetoothPbapService.class, true);
        Config.setProfileEnabled(GattService.class, true);

        Config.setProfileEnabled(A2dpService.class, false);
        Config.setProfileEnabled(A2dpSinkService.class, false);
        Config.setProfileEnabled(AvrcpTargetService.class, false);
        Config.setProfileEnabled(AvrcpControllerService.class, false);
        Config.setProfileEnabled(BassClientService.class, false);
        Config.setProfileEnabled(BatteryService.class, false);
        Config.setProfileEnabled(CsipSetCoordinatorService.class, false);
        Config.setProfileEnabled(HapClientService.class, false);
        Config.setProfileEnabled(HeadsetService.class, false);
        Config.setProfileEnabled(HeadsetClientService.class, false);
        Config.setProfileEnabled(HearingAidService.class, false);
        Config.setProfileEnabled(HidDeviceService.class, false);
        Config.setProfileEnabled(HidHostService.class, false);
        Config.setProfileEnabled(LeAudioService.class, false);
        Config.setProfileEnabled(TbsService.class, false);
        Config.setProfileEnabled(BluetoothMapService.class, false);
        Config.setProfileEnabled(MapClientService.class, false);
        Config.setProfileEnabled(McpService.class, false);
        Config.setProfileEnabled(BluetoothOppService.class, false);
        Config.setProfileEnabled(PbapClientService.class, false);
        Config.setProfileEnabled(SapService.class, false);
        Config.setProfileEnabled(VolumeControlService.class, false);
    }

    @BeforeClass
    public static void setupClass() {
        Log.e(TAG, "setupClass");
        // Bring native layer up and down to make sure config files are properly loaded
        if (Looper.myLooper() == null) {
            Looper.prepare();
        }
        assertThat(Looper.myLooper()).isNotNull();
        AdapterService adapterService = new AdapterService();
        adapterService.initNative(false /* is_restricted */, false /* is_common_criteria_mode */,
                0 /* config_compare_result */, new String[0], false, "");
        adapterService.cleanupNative();
        HashMap<String, HashMap<String, String>> adapterConfig = TestUtils.readAdapterConfig();
        assertThat(adapterConfig).isNotNull();
        assertThat(getMetricsSalt(adapterConfig)).isNotNull();
    }

    <T> void mockGetSystemService(String serviceName, Class<T> serviceClass, T mockService) {
        when(mMockContext.getSystemService(eq(serviceName))).thenReturn(mockService);
        when(mMockContext.getSystemServiceName(eq(serviceClass))).thenReturn(serviceName);
    }

    @Before
    public void setUp() throws PackageManager.NameNotFoundException {
        Log.e(TAG, "setUp()");
        MockitoAnnotations.initMocks(this);
        if (Looper.myLooper() == null) {
            Looper.prepare();
        }
        assertThat(Looper.myLooper()).isNotNull();

        // Dispatch all async work through instrumentation so we can wait until
        // it's drained below
        AsyncTask.setDefaultExecutor((r) -> {
            InstrumentationRegistry.getInstrumentation().runOnMainSync(r);
        });
        InstrumentationRegistry.getInstrumentation().getUiAutomation()
                .adoptShellPermissionIdentity();

        InstrumentationRegistry.getInstrumentation().runOnMainSync(
                () -> mAdapterService = new AdapterService());
        mMockPackageManager = mock(PackageManager.class);
        when(mMockPackageManager.getPermissionInfo(any(), anyInt()))
                .thenReturn(new PermissionInfo());

        mMockContentResolver = new MockContentResolver(InstrumentationRegistry.getTargetContext());
        mMockContentResolver.addProvider(Settings.AUTHORITY, new MockContentProvider() {
            @Override
            public Bundle call(String method, String request, Bundle args) {
                return Bundle.EMPTY;
            }
        });

        mPowerManager = InstrumentationRegistry.getTargetContext()
                .getSystemService(PowerManager.class);
        mPermissionCheckerManager = InstrumentationRegistry.getTargetContext()
                .getSystemService(PermissionCheckerManager.class);

        mPermissionManager = InstrumentationRegistry.getTargetContext()
                .getSystemService(PermissionManager.class);

        mBluetoothManager = InstrumentationRegistry.getTargetContext()
                .getSystemService(BluetoothManager.class);

        mCompanionDeviceManager =
                InstrumentationRegistry.getTargetContext()
                        .getSystemService(CompanionDeviceManager.class);

        when(mMockContext.getCacheDir()).thenReturn(InstrumentationRegistry.getTargetContext()
                .getCacheDir());
        when(mMockContext.getApplicationInfo()).thenReturn(mMockApplicationInfo);
        when(mMockContext.getContentResolver()).thenReturn(mMockContentResolver);
        when(mMockContext.getApplicationContext()).thenReturn(mMockContext);
        when(mMockContext.createContextAsUser(UserHandle.SYSTEM, /* flags= */ 0)).thenReturn(
                mMockContext);
        when(mMockContext.getResources()).thenReturn(mMockResources);
        when(mMockContext.getUserId()).thenReturn(Process.BLUETOOTH_UID);
        when(mMockContext.getPackageManager()).thenReturn(mMockPackageManager);

        mockGetSystemService(Context.ALARM_SERVICE, AlarmManager.class, mMockAlarmManager);
        mockGetSystemService(Context.APP_OPS_SERVICE, AppOpsManager.class, mMockAppOpsManager);
        mockGetSystemService(Context.AUDIO_SERVICE, AudioManager.class, mMockAudioManager);
        mockGetSystemService(
                Context.DEVICE_POLICY_SERVICE, DevicePolicyManager.class, mMockDevicePolicyManager);
        mockGetSystemService(Context.USER_SERVICE, UserManager.class, mMockUserManager);

        mockGetSystemService(
                Context.BATTERY_STATS_SERVICE, BatteryStatsManager.class, mBatteryStatsManager);
        mockGetSystemService(Context.BLUETOOTH_SERVICE, BluetoothManager.class, mBluetoothManager);
        mockGetSystemService(
                Context.COMPANION_DEVICE_SERVICE,
                CompanionDeviceManager.class,
                mCompanionDeviceManager);
        mockGetSystemService(
                Context.PERMISSION_CHECKER_SERVICE,
                PermissionCheckerManager.class,
                mPermissionCheckerManager);
        mockGetSystemService(
                Context.PERMISSION_SERVICE, PermissionManager.class, mPermissionManager);
        mockGetSystemService(Context.POWER_SERVICE, PowerManager.class, mPowerManager);

        when(mMockContext.getSharedPreferences(anyString(), anyInt()))
                .thenReturn(InstrumentationRegistry.getTargetContext()
                        .getSharedPreferences("AdapterServiceTestPrefs", Context.MODE_PRIVATE));

        doReturn(true).when(mMockContext).bindServiceAsUser(any(), any(), anyInt(), any());

        doAnswer(invocation -> {
            Object[] args = invocation.getArguments();
            return InstrumentationRegistry.getTargetContext().getDatabasePath((String) args[0]);
        }).when(mMockContext).getDatabasePath(anyString());

        // Sets the foreground user id to match that of the tests (restored in tearDown)
        mForegroundUserId = Utils.getForegroundUserId();
        int callingUid = Binder.getCallingUid();
        UserHandle callingUser = UserHandle.getUserHandleForUid(callingUid);
        Utils.setForegroundUserId(callingUser.getIdentifier());

        when(mMockDevicePolicyManager.isCommonCriteriaModeEnabled(any())).thenReturn(false);

        when(mIBluetoothCallback.asBinder()).thenReturn(mBinder);

        doReturn(Process.BLUETOOTH_UID).when(mMockPackageManager)
                .getPackageUidAsUser(any(), anyInt(), anyInt());

        when(mMockGattService.getName()).thenReturn("GattService");
        when(mMockService.getName()).thenReturn("Service1");
        when(mMockService2.getName()).thenReturn("Service2");

        when(mMockMetricsLogger.init(any())).thenReturn(true);
        when(mMockMetricsLogger.close()).thenReturn(true);

        configureEnabledProfiles();
        Config.init(mMockContext);

        mAdapterService.setMetricsLogger(mMockMetricsLogger);

        // Attach a context to the service for permission checks.
        mAdapterService.attach(mMockContext, null, null, null, mApplication, null);
        mAdapterService.onCreate();

        // Wait for any async events to drain
        InstrumentationRegistry.getInstrumentation().waitForIdleSync();

        mAdapterService.registerCallback(mIBluetoothCallback);

        mAdapterConfig = TestUtils.readAdapterConfig();
        assertThat(mAdapterConfig).isNotNull();
    }

    @After
    public void tearDown() {
        Log.e(TAG, "tearDown()");

        // Restores the foregroundUserId to the ID prior to the test setup
        Utils.setForegroundUserId(mForegroundUserId);

        mAdapterService.cleanup();
        mAdapterService.unregisterCallback(mIBluetoothCallback);
    }

    @AfterClass
    public static void tearDownOnce() {
        AsyncTask.setDefaultExecutor(AsyncTask.SERIAL_EXECUTOR);
    }

    private void verifyStateChange(int prevState, int currState, int callNumber, int timeoutMs) {
        try {
            verify(mIBluetoothCallback, timeout(timeoutMs).times(callNumber))
                    .onBluetoothStateChange(prevState, currState);
        } catch (RemoteException e) {
            // the mocked onBluetoothStateChange doesn't throw RemoteException
        }
    }

    private static void verifyStateChange(
            IBluetoothCallback cb, int prevState, int currState, int timeoutMs) {
        try {
            verify(cb, timeout(timeoutMs)).onBluetoothStateChange(prevState, currState);
        } catch (RemoteException e) {
            // the mocked onBluetoothStateChange doesn't throw RemoteException
        }
    }

    void doEnable(boolean onlyGatt) {
        doEnable(
                mMockGattService,
                mAdapterService,
                mMockContext,
                1,
                onlyGatt,
                List.of(mMockService, mMockService2));
    }
    // Method is re-used in other AdapterService*Test
    static void doEnable(
            ProfileService gattService,
            AdapterService adapter,
            Context ctx,
            int invocationNumber,
            boolean onlyGatt,
            List<ProfileService> services) {
        Log.e(TAG, "doEnable() start");

        IBluetoothCallback callback = mock(IBluetoothCallback.class);
        Binder binder = mock(Binder.class);
        doReturn(binder).when(callback).asBinder();
        adapter.registerCallback(callback);

        assertThat(adapter.getState()).isEqualTo(BluetoothAdapter.STATE_OFF);

        adapter.enable(false);

        verifyStateChange(
                callback,
                BluetoothAdapter.STATE_OFF,
                BluetoothAdapter.STATE_BLE_TURNING_ON,
                CONTEXT_SWITCH_MS);

        // Start GATT
        verify(ctx, timeout(GATT_START_TIME_MS).times(invocationNumber))
                .bindServiceAsUser(any(), any(), anyInt(), any());
        adapter.addProfile(gattService);
        adapter.onProfileServiceStateChanged(gattService, BluetoothAdapter.STATE_ON);

        verifyStateChange(
                callback,
                BluetoothAdapter.STATE_BLE_TURNING_ON,
                BluetoothAdapter.STATE_BLE_ON,
                NATIVE_INIT_MS);

        adapter.startBrEdr();

        verifyStateChange(
                callback,
                BluetoothAdapter.STATE_BLE_ON,
                BluetoothAdapter.STATE_TURNING_ON,
                CONTEXT_SWITCH_MS);

        if (!onlyGatt) {
            // Start Mock PBAP and PAN services
            verify(ctx, timeout(ONE_SECOND_MS).times(4 * invocationNumber - 2)).startService(any());

            for (ProfileService service : services) {
                adapter.addProfile(service);
            }
            // Keep in 2 separate loop to first add the services and then eventually trigger the
            // ON transition during the callback
            for (ProfileService service : services) {
                adapter.onProfileServiceStateChanged(service, BluetoothAdapter.STATE_ON);
            }
        }

        verifyStateChange(
                callback,
                BluetoothAdapter.STATE_TURNING_ON,
                BluetoothAdapter.STATE_ON,
                PROFILE_SERVICE_TOGGLE_TIME_MS);

        verify(ctx, timeout(CONTEXT_SWITCH_MS).times(2 * invocationNumber))
                .sendBroadcast(any(), eq(BLUETOOTH_SCAN), any(Bundle.class));
        assertThat(adapter.getState()).isEqualTo(BluetoothAdapter.STATE_ON);
        adapter.unregisterCallback(callback);
        Log.e(TAG, "doEnable() complete success");
    }

    void doDisable(boolean onlyGatt) {
        doDisable(
                mMockGattService,
                mAdapterService,
                mMockContext,
                1,
                onlyGatt,
                List.of(mMockService, mMockService2));
    }

    private static void doDisable(
            ProfileService gattService,
            AdapterService adapter,
            Context ctx,
            int invocationNumber,
            boolean onlyGatt,
            List<ProfileService> services) {
        Log.e(TAG, "doDisable() start");
        IBluetoothCallback callback = mock(IBluetoothCallback.class);
        Binder binder = mock(Binder.class);
        doReturn(binder).when(callback).asBinder();
        adapter.registerCallback(callback);

        assertThat(adapter.getState()).isEqualTo(BluetoothAdapter.STATE_ON);

        adapter.disable();

        verifyStateChange(
                callback,
                BluetoothAdapter.STATE_ON,
                BluetoothAdapter.STATE_TURNING_OFF,
                CONTEXT_SWITCH_MS);

        if (!onlyGatt) {
            // Stop PBAP and PAN services
            verify(ctx, timeout(ONE_SECOND_MS).times(4 * invocationNumber)).startService(any());

            for (ProfileService service : services) {
                adapter.onProfileServiceStateChanged(service, BluetoothAdapter.STATE_OFF);
            }
        }

        verifyStateChange(
                callback,
                BluetoothAdapter.STATE_TURNING_OFF,
                BluetoothAdapter.STATE_BLE_ON,
                PROFILE_SERVICE_TOGGLE_TIME_MS);

        adapter.stopBle();

        verifyStateChange(
                callback,
                BluetoothAdapter.STATE_BLE_ON,
                BluetoothAdapter.STATE_BLE_TURNING_OFF,
                CONTEXT_SWITCH_MS);

        // Stop GATT
        verify(ctx, timeout(ONE_SECOND_MS).times(invocationNumber)).unbindService(any());
        adapter.onProfileServiceStateChanged(gattService, BluetoothAdapter.STATE_OFF);

        verifyStateChange(
                callback,
                BluetoothAdapter.STATE_BLE_TURNING_OFF,
                BluetoothAdapter.STATE_OFF,
                NATIVE_DISABLE_MS);

        assertThat(adapter.getState()).isEqualTo(BluetoothAdapter.STATE_OFF);
        adapter.unregisterCallback(callback);
        Log.e(TAG, "doDisable() complete success");
    }

    /**
     * Test: Turn Bluetooth on.
     * Check whether the AdapterService gets started.
     */
    @Test
    public void testEnable() {
        doEnable(false);
    }

    @Test
    public void enable_isCorrectScanMode() {
        doEnable(false);
        final int scanMode = mAdapterService.getScanMode();
        assertThat(scanMode)
                .isAnyOf(
                        BluetoothAdapter.SCAN_MODE_CONNECTABLE,
                        BluetoothAdapter.SCAN_MODE_CONNECTABLE_DISCOVERABLE);
    }

    /**
     * Test: Turn Bluetooth on/off.
     * Check whether the AdapterService gets started and stopped.
     */
    @Test
    public void testEnableDisable() {
        doEnable(false);
        doDisable(false);
    }

    /**
     * Test: Turn Bluetooth on/off with only GATT supported.
     * Check whether the AdapterService gets started and stopped.
     */
    @Test
    public void testEnableDisableOnlyGatt() {
        Context mockContext = mock(Context.class);
        Resources mockResources = mock(Resources.class);

        when(mockContext.getApplicationInfo()).thenReturn(mMockApplicationInfo);
        when(mockContext.getContentResolver()).thenReturn(mMockContentResolver);
        when(mockContext.getApplicationContext()).thenReturn(mockContext);
        when(mockContext.getResources()).thenReturn(mockResources);
        when(mockContext.getUserId()).thenReturn(Process.BLUETOOTH_UID);
        when(mockContext.getPackageManager()).thenReturn(mMockPackageManager);

        // Config is set to PBAP, PAN and GATT by default. Turn off PAN and PBAP.
        Config.setProfileEnabled(PanService.class, false);
        Config.setProfileEnabled(BluetoothPbapService.class, false);

        Config.init(mockContext);
        doEnable(true);
        doDisable(true);
    }

    /**
     * Test: Don't start GATT
     * Check whether the AdapterService quits gracefully
     */
    @Test
    public void testGattStartTimeout() {
        assertThat(mAdapterService.getState()).isEqualTo(BluetoothAdapter.STATE_OFF);

        mAdapterService.enable(false);

        verifyStateChange(BluetoothAdapter.STATE_OFF, BluetoothAdapter.STATE_BLE_TURNING_ON, 1,
                CONTEXT_SWITCH_MS);

        // Start GATT
        verify(mMockContext, timeout(GATT_START_TIME_MS))
                .bindServiceAsUser(any(), any(), anyInt(), any());
        mAdapterService.addProfile(mMockGattService);

        verifyStateChange(BluetoothAdapter.STATE_BLE_TURNING_ON,
                BluetoothAdapter.STATE_BLE_TURNING_OFF, 1,
                AdapterState.BLE_START_TIMEOUT_DELAY + CONTEXT_SWITCH_MS);

        // Stop GATT
        verify(mMockContext, timeout(AdapterState.BLE_STOP_TIMEOUT_DELAY + CONTEXT_SWITCH_MS))
                .unbindService(any());

        verifyStateChange(BluetoothAdapter.STATE_BLE_TURNING_OFF, BluetoothAdapter.STATE_OFF, 1,
                NATIVE_DISABLE_MS);

        assertThat(mAdapterService.getState()).isEqualTo(BluetoothAdapter.STATE_OFF);
    }

    /**
     * Test: Don't stop GATT
     * Check whether the AdapterService quits gracefully
     */
    @Test
    public void testGattStopTimeout() {
        doEnable(false);
        assertThat(mAdapterService.getState()).isEqualTo(BluetoothAdapter.STATE_ON);

        mAdapterService.disable();

        verifyStateChange(BluetoothAdapter.STATE_ON, BluetoothAdapter.STATE_TURNING_OFF, 1,
                CONTEXT_SWITCH_MS);

        // Stop PBAP and PAN services
        verify(mMockContext, timeout(ONE_SECOND_MS).times(4)).startService(any());
        mAdapterService.onProfileServiceStateChanged(mMockService, BluetoothAdapter.STATE_OFF);
        mAdapterService.onProfileServiceStateChanged(mMockService2, BluetoothAdapter.STATE_OFF);

        verifyStateChange(BluetoothAdapter.STATE_TURNING_OFF, BluetoothAdapter.STATE_BLE_ON, 1,
                CONTEXT_SWITCH_MS);

        mAdapterService.stopBle();

        verifyStateChange(BluetoothAdapter.STATE_BLE_ON, BluetoothAdapter.STATE_BLE_TURNING_OFF, 1,
                CONTEXT_SWITCH_MS);

        // Stop GATT
        verify(mMockContext, timeout(AdapterState.BLE_STOP_TIMEOUT_DELAY + CONTEXT_SWITCH_MS))
                .unbindService(any());

        verifyStateChange(BluetoothAdapter.STATE_BLE_TURNING_OFF, BluetoothAdapter.STATE_OFF, 1,
                AdapterState.BLE_STOP_TIMEOUT_DELAY + NATIVE_DISABLE_MS);

        assertThat(mAdapterService.getState()).isEqualTo(BluetoothAdapter.STATE_OFF);
    }

    /**
     * Test: Don't start a classic profile
     * Check whether the AdapterService quits gracefully
     */
    @Test
    public void testProfileStartTimeout() {
        assertThat(mAdapterService.getState()).isEqualTo(BluetoothAdapter.STATE_OFF);

        mAdapterService.enable(false);

        verifyStateChange(BluetoothAdapter.STATE_OFF, BluetoothAdapter.STATE_BLE_TURNING_ON, 1,
                CONTEXT_SWITCH_MS);

        // Start GATT
        verify(mMockContext, timeout(GATT_START_TIME_MS))
                .bindServiceAsUser(any(), any(), anyInt(), any());
        mAdapterService.addProfile(mMockGattService);
        mAdapterService.onProfileServiceStateChanged(mMockGattService, BluetoothAdapter.STATE_ON);

        verifyStateChange(BluetoothAdapter.STATE_BLE_TURNING_ON, BluetoothAdapter.STATE_BLE_ON, 1,
                NATIVE_INIT_MS);

        mAdapterService.startBrEdr();

        verifyStateChange(BluetoothAdapter.STATE_BLE_ON, BluetoothAdapter.STATE_TURNING_ON, 1,
                CONTEXT_SWITCH_MS);

        // Register Mock PBAP and PAN services
        verify(mMockContext, timeout(ONE_SECOND_MS).times(2)).startService(any());
        mAdapterService.addProfile(mMockService);
        mAdapterService.addProfile(mMockService2);
        mAdapterService.onProfileServiceStateChanged(mMockService, BluetoothAdapter.STATE_ON);

        verifyStateChange(BluetoothAdapter.STATE_TURNING_ON, BluetoothAdapter.STATE_TURNING_OFF, 1,
                AdapterState.BREDR_START_TIMEOUT_DELAY + CONTEXT_SWITCH_MS);

        // Stop PBAP and PAN services
        verify(mMockContext, timeout(ONE_SECOND_MS).times(4)).startService(any());
        mAdapterService.onProfileServiceStateChanged(mMockService, BluetoothAdapter.STATE_OFF);

        verifyStateChange(BluetoothAdapter.STATE_TURNING_OFF, BluetoothAdapter.STATE_BLE_ON, 1,
                CONTEXT_SWITCH_MS);

        // Ensure GATT is still running
        verify(mMockContext, times(0)).unbindService(any());
    }

    /**
     * Test: Don't stop a classic profile
     * Check whether the AdapterService quits gracefully
     */
    @Test
    public void testProfileStopTimeout() {
        doEnable(false);

        assertThat(mAdapterService.getState()).isEqualTo(BluetoothAdapter.STATE_ON);

        mAdapterService.disable();

        verifyStateChange(BluetoothAdapter.STATE_ON, BluetoothAdapter.STATE_TURNING_OFF, 1,
                CONTEXT_SWITCH_MS);

        // Stop PBAP and PAN services
        verify(mMockContext, timeout(ONE_SECOND_MS).times(4)).startService(any());
        mAdapterService.onProfileServiceStateChanged(mMockService, BluetoothAdapter.STATE_OFF);

        verifyStateChange(BluetoothAdapter.STATE_TURNING_OFF,
                BluetoothAdapter.STATE_BLE_TURNING_OFF, 1,
                AdapterState.BREDR_STOP_TIMEOUT_DELAY + CONTEXT_SWITCH_MS);

        // Stop GATT
        verify(mMockContext, timeout(AdapterState.BLE_STOP_TIMEOUT_DELAY + CONTEXT_SWITCH_MS))
                .unbindService(any());
        mAdapterService.onProfileServiceStateChanged(mMockGattService, BluetoothAdapter.STATE_OFF);

        verifyStateChange(BluetoothAdapter.STATE_BLE_TURNING_OFF, BluetoothAdapter.STATE_OFF, 1,
                AdapterState.BLE_STOP_TIMEOUT_DELAY + NATIVE_DISABLE_MS);

        assertThat(mAdapterService.getState()).isEqualTo(BluetoothAdapter.STATE_OFF);
    }

    /**
     * Test: Toggle snoop logging setting
     * Check whether the AdapterService restarts fully
     */
    @Test
    public void testSnoopLoggingChange() {
        BluetoothProperties.snoop_log_mode_values snoopSetting =
                BluetoothProperties.snoop_log_mode()
                .orElse(BluetoothProperties.snoop_log_mode_values.EMPTY);
        BluetoothProperties.snoop_log_mode(BluetoothProperties.snoop_log_mode_values.DISABLED);
        doEnable(false);

        assertThat(mAdapterService.getState()).isEqualTo(BluetoothAdapter.STATE_ON);

        assertThat(
                        BluetoothProperties.snoop_log_mode()
                                .orElse(BluetoothProperties.snoop_log_mode_values.EMPTY))
                .isNotEqualTo(BluetoothProperties.snoop_log_mode_values.FULL);

        BluetoothProperties.snoop_log_mode(BluetoothProperties.snoop_log_mode_values.FULL);

        mAdapterService.disable();

        verifyStateChange(BluetoothAdapter.STATE_ON, BluetoothAdapter.STATE_TURNING_OFF, 1,
                CONTEXT_SWITCH_MS);

        // Stop PBAP and PAN services
        verify(mMockContext, timeout(ONE_SECOND_MS).times(4)).startService(any());
        mAdapterService.onProfileServiceStateChanged(mMockService, BluetoothAdapter.STATE_OFF);
        mAdapterService.onProfileServiceStateChanged(mMockService2, BluetoothAdapter.STATE_OFF);

        verifyStateChange(BluetoothAdapter.STATE_TURNING_OFF, BluetoothAdapter.STATE_BLE_ON, 1,
                CONTEXT_SWITCH_MS);

        // Don't call stopBle().  The Adapter should turn itself off.

        verifyStateChange(
                BluetoothAdapter.STATE_BLE_ON,
                BluetoothAdapter.STATE_BLE_TURNING_OFF,
                1,
                CONTEXT_SWITCH_MS);

        // Stop GATT
        verify(mMockContext, timeout(AdapterState.BLE_STOP_TIMEOUT_DELAY + CONTEXT_SWITCH_MS))
                .unbindService(any());

        mAdapterService.onProfileServiceStateChanged(mMockGattService, BluetoothAdapter.STATE_OFF);

        verifyStateChange(BluetoothAdapter.STATE_BLE_TURNING_OFF, BluetoothAdapter.STATE_OFF, 1,
                NATIVE_DISABLE_MS);

        assertThat(mAdapterService.getState()).isEqualTo(BluetoothAdapter.STATE_OFF);

        // Restore earlier setting
        BluetoothProperties.snoop_log_mode(snoopSetting);
    }


    /**
     * Test: Obfuscate a null Bluetooth
     * Check if returned value from {@link AdapterService#obfuscateAddress(BluetoothDevice)} is
     * an empty array when device address is null
     */
    @Test
    public void testObfuscateBluetoothAddress_NullAddress() {
        assertThat(mAdapterService.obfuscateAddress(null)).isEmpty();
    }

    /**
     * Test: Obfuscate Bluetooth address when Bluetooth is disabled
     * Check whether the returned value meets expectation
     */
    @Test
    public void testObfuscateBluetoothAddress_BluetoothDisabled() {
        assertThat(mAdapterService.getState()).isEqualTo(BluetoothAdapter.STATE_OFF);
        byte[] metricsSalt = getMetricsSalt(mAdapterConfig);
        assertThat(metricsSalt).isNotNull();
        BluetoothDevice device = TestUtils.getTestDevice(BluetoothAdapter.getDefaultAdapter(), 0);
        byte[] obfuscatedAddress = mAdapterService.obfuscateAddress(device);
        assertThat(obfuscatedAddress).isNotEmpty();
        assertThat(isByteArrayAllZero(obfuscatedAddress)).isFalse();
        assertThat(obfuscateInJava(metricsSalt, device)).isEqualTo(obfuscatedAddress);
    }

    /**
     * Test: Obfuscate Bluetooth address when Bluetooth is enabled
     * Check whether the returned value meets expectation
     */
    @Test
    public void testObfuscateBluetoothAddress_BluetoothEnabled() {
        assertThat(mAdapterService.getState()).isEqualTo(BluetoothAdapter.STATE_OFF);
        doEnable(false);
        assertThat(mAdapterService.getState()).isEqualTo(BluetoothAdapter.STATE_ON);
        byte[] metricsSalt = getMetricsSalt(mAdapterConfig);
        assertThat(metricsSalt).isNotNull();
        BluetoothDevice device = TestUtils.getTestDevice(BluetoothAdapter.getDefaultAdapter(), 0);
        byte[] obfuscatedAddress = mAdapterService.obfuscateAddress(device);
        assertThat(obfuscatedAddress).isNotEmpty();
        assertThat(isByteArrayAllZero(obfuscatedAddress)).isFalse();
        assertThat(obfuscateInJava(metricsSalt, device)).isEqualTo(obfuscatedAddress);
    }

    /**
     * Test: Check if obfuscated Bluetooth address stays the same after toggling Bluetooth
     */
    @Test
    public void testObfuscateBluetoothAddress_PersistentBetweenToggle() {
        assertThat(mAdapterService.getState()).isEqualTo(BluetoothAdapter.STATE_OFF);
        byte[] metricsSalt = getMetricsSalt(mAdapterConfig);
        assertThat(metricsSalt).isNotNull();
        BluetoothDevice device = TestUtils.getTestDevice(BluetoothAdapter.getDefaultAdapter(), 0);
        byte[] obfuscatedAddress1 = mAdapterService.obfuscateAddress(device);
        assertThat(obfuscatedAddress1).isNotEmpty();
        assertThat(isByteArrayAllZero(obfuscatedAddress1)).isFalse();
        assertThat(obfuscateInJava(metricsSalt, device)).isEqualTo(obfuscatedAddress1);
        // Enable
        doEnable(false);
        assertThat(mAdapterService.getState()).isEqualTo(BluetoothAdapter.STATE_ON);
        byte[] obfuscatedAddress3 = mAdapterService.obfuscateAddress(device);
        assertThat(obfuscatedAddress3).isNotEmpty();
        assertThat(isByteArrayAllZero(obfuscatedAddress3)).isFalse();
        assertThat(obfuscatedAddress3).isEqualTo(obfuscatedAddress1);
        // Disable
        doDisable(false);
        assertThat(mAdapterService.getState()).isEqualTo(BluetoothAdapter.STATE_OFF);
        byte[] obfuscatedAddress4 = mAdapterService.obfuscateAddress(device);
        assertThat(obfuscatedAddress4).isNotEmpty();
        assertThat(isByteArrayAllZero(obfuscatedAddress4)).isFalse();
        assertThat(obfuscatedAddress4).isEqualTo(obfuscatedAddress1);
    }

    @Test
    public void testAddressConsolidation() {
        // Create device properties
        RemoteDevices remoteDevices = mAdapterService.getRemoteDevices();
        remoteDevices.addDeviceProperties(Utils.getBytesFromAddress((TEST_BT_ADDR_1)));
        String identityAddress = mAdapterService.getIdentityAddress(TEST_BT_ADDR_1);
        assertThat(identityAddress).isEqualTo(TEST_BT_ADDR_1);

        // Trigger address consolidate callback
        remoteDevices.addressConsolidateCallback(Utils.getBytesFromAddress(TEST_BT_ADDR_1),
                Utils.getBytesFromAddress(TEST_BT_ADDR_2));

        // Verify we can get correct identity address
        identityAddress = mAdapterService.getIdentityAddress(TEST_BT_ADDR_1);
        assertThat(identityAddress).isEqualTo(TEST_BT_ADDR_2);
    }

    public static byte[] getMetricsSalt(HashMap<String, HashMap<String, String>> adapterConfig) {
        HashMap<String, String> metricsSection = adapterConfig.get("Metrics");
        if (metricsSection == null) {
            Log.e(TAG, "Metrics section is null: " + adapterConfig.toString());
            return null;
        }
        String saltString = metricsSection.get("Salt256Bit");
        if (saltString == null) {
            Log.e(TAG, "Salt256Bit is null: " + metricsSection.toString());
            return null;
        }
        byte[] metricsSalt = HexEncoding.decode(saltString, false /* allowSingleChar */);
        if (metricsSalt.length != 32) {
            Log.e(TAG, "Salt length is not 32 bit, but is " + metricsSalt.length);
            return null;
        }
        return metricsSalt;
    }

    public static byte[] obfuscateInJava(byte[] key, BluetoothDevice device) {
        String algorithm = "HmacSHA256";
        try {
            Mac hmac256 = Mac.getInstance(algorithm);
            hmac256.init(new SecretKeySpec(key, algorithm));
            return hmac256.doFinal(Utils.getByteAddress(device));
        } catch (NoSuchAlgorithmException | IllegalStateException | InvalidKeyException exp) {
            exp.printStackTrace();
            return null;
        }
    }

    public static boolean isByteArrayAllZero(byte[] byteArray) {
        for (byte i : byteArray) {
            if (i != 0) {
                return false;
            }
        }
        return true;
    }

    /**
     * Test: Get id for null address
     * Check if returned value from {@link AdapterService#getMetricId(BluetoothDevice)} is
     * 0 when device address is null
     */
    @Test
    public void testGetMetricId_NullAddress() {
        assertThat(mAdapterService.getMetricId(null)).isEqualTo(0);
    }

    /**
     * Test: Get id when Bluetooth is disabled
     * Check whether the returned value meets expectation
     */
    @Test
    public void testGetMetricId_BluetoothDisabled() {
        assertThat(mAdapterService.getState()).isEqualTo(BluetoothAdapter.STATE_OFF);
        BluetoothDevice device = TestUtils.getTestDevice(BluetoothAdapter.getDefaultAdapter(), 0);
        assertThat(mAdapterService.getMetricId(device)).isGreaterThan(0);
    }

    /**
     * Test: Get id when Bluetooth is enabled
     * Check whether the returned value meets expectation
     */
    @Test
    public void testGetMetricId_BluetoothEnabled() {
        assertThat(mAdapterService.getState()).isEqualTo(BluetoothAdapter.STATE_OFF);
        doEnable(false);
        assertThat(mAdapterService.getState()).isEqualTo(BluetoothAdapter.STATE_ON);
        BluetoothDevice device = TestUtils.getTestDevice(BluetoothAdapter.getDefaultAdapter(), 0);
        assertThat(mAdapterService.getMetricId(device)).isGreaterThan(0);
    }

    /**
     * Test: Check if id gotten stays the same after toggling Bluetooth
     */
    @Test
    public void testGetMetricId_PersistentBetweenToggle() {
        assertThat(mAdapterService.getState()).isEqualTo(BluetoothAdapter.STATE_OFF);
        BluetoothDevice device = TestUtils.getTestDevice(BluetoothAdapter.getDefaultAdapter(), 0);
        final int initialMetricId = mAdapterService.getMetricId(device);
        assertThat(initialMetricId).isGreaterThan(0);

        // Enable
        doEnable(false);
        assertThat(mAdapterService.getState()).isEqualTo(BluetoothAdapter.STATE_ON);
        assertThat(mAdapterService.getMetricId(device)).isEqualTo(initialMetricId);

        // Disable
        doDisable(false);
        assertThat(mAdapterService.getState()).isEqualTo(BluetoothAdapter.STATE_OFF);
        assertThat(mAdapterService.getMetricId(device)).isEqualTo(initialMetricId);
    }

    @Test
    public void testDump_doesNotCrash() {
        FileDescriptor fd = new FileDescriptor();
        PrintWriter writer = mock(PrintWriter.class);

        mAdapterService.dump(fd, writer, new String[]{});
        mAdapterService.dump(fd, writer, new String[]{"set-test-mode", "enabled"});
        mAdapterService.dump(fd, writer, new String[]{"--proto-bin"});
        mAdapterService.dump(fd, writer, new String[]{"random", "arguments"});
    }
}
