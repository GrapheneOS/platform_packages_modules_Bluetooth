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
import android.content.AttributionSource;
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
import android.os.UserHandle;
import android.os.UserManager;
import android.permission.PermissionCheckerManager;
import android.permission.PermissionManager;
import android.provider.Settings;
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

import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import java.util.HashMap;

@MediumTest
@RunWith(AndroidJUnit4.class)
public class AdapterServiceRestartTest {
    private static final String TAG = AdapterServiceTest.class.getSimpleName();

    private AdapterService mAdapterService;
    private AdapterService.AdapterServiceBinder mServiceBinder;

    private @Mock Context mMockContext;
    private @Mock ApplicationInfo mMockApplicationInfo;
    private @Mock Resources mMockResources;
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

    private final AttributionSource mAttributionSource = new AttributionSource.Builder(
            Process.myUid()).build();

    private PackageManager mMockPackageManager;
    private MockContentResolver mMockContentResolver;
    private HashMap<String, HashMap<String, String>> mAdapterConfig;
    private int mForegroundUserId;

    private void configureEnabledProfiles() {
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
        assertThat(AdapterServiceTest.getMetricsSalt(adapterConfig)).isNotNull();
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
            androidx.test.platform.app.InstrumentationRegistry.getInstrumentation()
                    .runOnMainSync(r);
        });
        androidx.test.platform.app.InstrumentationRegistry.getInstrumentation().getUiAutomation()
                .adoptShellPermissionIdentity();

        androidx.test.platform.app.InstrumentationRegistry.getInstrumentation().runOnMainSync(
                () -> mAdapterService = new AdapterService());
        mServiceBinder = new AdapterService.AdapterServiceBinder(mAdapterService);
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

        when(mMockContext.getAttributionSource()).thenReturn(mAttributionSource);
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

        when(mMockMetricsLogger.init(any())).thenReturn(true);
        when(mMockMetricsLogger.close()).thenReturn(true);

        configureEnabledProfiles();
        Config.init(mMockContext);

        mAdapterService.setMetricsLogger(mMockMetricsLogger);

        // Attach a context to the service for permission checks.
        mAdapterService.attach(mMockContext, null, null, null, mApplication, null);
        mAdapterService.onCreate();

        // Wait for any async events to drain
        androidx.test.platform.app.InstrumentationRegistry.getInstrumentation().waitForIdleSync();

        mServiceBinder.registerCallback(mIBluetoothCallback, mAttributionSource);

        mAdapterConfig = TestUtils.readAdapterConfig();
        assertThat(mAdapterConfig).isNotNull();
    }

    @After
    public void tearDown() {
        Log.e(TAG, "tearDown()");

        // Restores the foregroundUserId to the ID prior to the test setup
        Utils.setForegroundUserId(mForegroundUserId);

        mServiceBinder.unregisterCallback(mIBluetoothCallback, mAttributionSource);
        mAdapterService.cleanup();
    }

    @AfterClass
    public static void tearDownOnce() {
        AsyncTask.setDefaultExecutor(AsyncTask.SERIAL_EXECUTOR);
    }

    /**
     * Test: Check if obfuscated Bluetooth address stays the same after re-initializing
     *       {@link AdapterService}
     */
    @Test
    public void testObfuscateBluetoothAddress_PersistentBetweenAdapterServiceInitialization() throws
            PackageManager.NameNotFoundException {
        // Sleep needed to ensure the metrics are valid in both native and java (b/267528843)
        try {
            Thread.sleep(1_000);
        } catch (InterruptedException e) {
            Log.e("AdapterServiceTest", "Sleep interrupted: " + e);
        }
        byte[] metricsSalt = AdapterServiceTest.getMetricsSalt(mAdapterConfig);
        assertThat(metricsSalt).isNotNull();
        assertThat(mAdapterService.getState()).isEqualTo(BluetoothAdapter.STATE_OFF);
        BluetoothDevice device = TestUtils.getTestDevice(BluetoothAdapter.getDefaultAdapter(), 0);
        byte[] obfuscatedAddress1 = mAdapterService.obfuscateAddress(device);
        assertThat(obfuscatedAddress1).isNotEmpty();
        assertThat(AdapterServiceTest.isByteArrayAllZero(obfuscatedAddress1)).isFalse();
        assertThat(AdapterServiceTest.obfuscateInJava(metricsSalt, device))
                .isEqualTo(obfuscatedAddress1);
        tearDown();
        setUp();

        byte[] metricsSalt2 = AdapterServiceTest.getMetricsSalt(mAdapterConfig);
        assertThat(metricsSalt2).isNotNull();
        assertThat(metricsSalt).isEqualTo(metricsSalt2);

        assertThat(mAdapterService.getState()).isEqualTo(BluetoothAdapter.STATE_OFF);
        byte[] obfuscatedAddress2 = mAdapterService.obfuscateAddress(device);
        assertThat(obfuscatedAddress2).isNotEmpty();
        assertThat(AdapterServiceTest.isByteArrayAllZero(obfuscatedAddress2)).isFalse();
        assertThat(obfuscatedAddress2).isEqualTo(obfuscatedAddress1);
    }

    /**
     * Test: Check if id gotten stays the same after re-initializing
     *       {@link AdapterService}
     */
    @Test
    public void testgetMetricId_PersistentBetweenAdapterServiceInitialization() throws
            PackageManager.NameNotFoundException {
        assertThat(mAdapterService.getState()).isEqualTo(BluetoothAdapter.STATE_OFF);
        BluetoothDevice device = TestUtils.getTestDevice(BluetoothAdapter.getDefaultAdapter(), 0);
        int initialMetricId = mAdapterService.getMetricId(device);
        assertThat(initialMetricId).isGreaterThan(0);
        tearDown();
        setUp();
        assertThat(mAdapterService.getState()).isEqualTo(BluetoothAdapter.STATE_OFF);
        assertThat(mAdapterService.getMetricId(device)).isEqualTo(initialMetricId);
    }
}
