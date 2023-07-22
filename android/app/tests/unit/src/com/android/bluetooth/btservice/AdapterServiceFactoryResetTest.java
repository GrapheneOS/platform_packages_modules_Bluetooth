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

import static android.bluetooth.BluetoothAdapter.STATE_OFF;

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
import android.os.BatteryStatsManager;
import android.os.Binder;
import android.os.Bundle;
import android.os.Handler;
import android.os.PowerManager;
import android.os.Process;
import android.os.UserHandle;
import android.os.UserManager;
import android.os.test.TestLooper;
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
import com.android.internal.app.IBatteryStats;

import org.junit.After;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Ignore;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import java.util.HashMap;
import java.util.List;

@MediumTest
@RunWith(AndroidJUnit4.class)
public class AdapterServiceFactoryResetTest {
    private static final String TAG = AdapterServiceFactoryResetTest.class.getSimpleName();

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

    private PackageManager mMockPackageManager;
    private MockContentResolver mMockContentResolver;
    private HashMap<String, HashMap<String, String>> mAdapterConfig;
    private int mForegroundUserId;
    private TestLooper mLooper;

    @BeforeClass
    public static void setupClass() {
        AdapterServiceTest.setupClass();
    }

    <T> void mockGetSystemService(String serviceName, Class<T> serviceClass, T mockService) {
        when(mMockContext.getSystemService(eq(serviceName))).thenReturn(mockService);
        when(mMockContext.getSystemServiceName(eq(serviceClass))).thenReturn(serviceName);
    }

    @Before
    public void setUp() throws PackageManager.NameNotFoundException {
        Log.e(TAG, "setUp()");
        MockitoAnnotations.initMocks(this);

        mLooper = new TestLooper();
        Handler handler = new Handler(mLooper.getLooper());

        // Post the creation of AdapterService since it rely on Looper.myLooper()
        handler.post(() -> mAdapterService = new AdapterService(mLooper.getLooper()));
        assertThat(mLooper.dispatchAll()).isEqualTo(1);
        assertThat(mAdapterService).isNotNull();

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

        when(mMockContext.getCacheDir())
                .thenReturn(InstrumentationRegistry.getTargetContext().getCacheDir());
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
                .thenReturn(
                        InstrumentationRegistry.getTargetContext()
                                .getSharedPreferences(
                                        "AdapterServiceTestPrefs", Context.MODE_PRIVATE));

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

        AdapterServiceTest.configureEnabledProfiles();
        Config.init(mMockContext);

        mAdapterService.setMetricsLogger(mMockMetricsLogger);

        // Attach a context to the service for permission checks.
        mAdapterService.attach(mMockContext, null, null, null, mApplication, null);
        mAdapterService.onCreate();

        mLooper.dispatchAll();

        mAdapterConfig = TestUtils.readAdapterConfig();
        assertThat(mAdapterConfig).isNotNull();
    }

    @After
    public void tearDown() {
        Log.e(TAG, "tearDown()");

        // Enable the stack to re-create the config. Next tests rely on it.
        doEnable();

        // Restores the foregroundUserId to the ID prior to the test setup
        Utils.setForegroundUserId(mForegroundUserId);

        mAdapterService.cleanup();
    }

    void doEnable() {
        AdapterServiceTest.doEnable(
                mLooper,
                mMockGattService,
                mAdapterService,
                mMockContext,
                false,
                List.of(mMockService, mMockService2));
    }

    /**
     * Test: Verify that obfuscated Bluetooth address changes after factory reset
     *
     * There are 4 types of factory reset that we are talking about:
     * 1. Factory reset all user data from Settings -> Will restart phone
     * 2. Factory reset WiFi and Bluetooth from Settings -> Will only restart WiFi and BT
     * 3. Call BluetoothAdapter.factoryReset() -> Will disable Bluetooth and reset config in
     * memory and disk
     * 4. Call AdapterService.factoryReset() -> Will only reset config in memory
     *
     * We can only use No. 4 here
     */
    @Ignore("AdapterService.factoryReset() does not reload config into memory and hence old salt"
            + " is still used until next time Bluetooth library is initialized. However Bluetooth"
            + " cannot be used until Bluetooth process restart any way. Thus it is almost"
            + " guaranteed that user has to re-enable Bluetooth and hence re-generate new salt"
            + " after factory reset")
    @Test
    public void testObfuscateBluetoothAddress_FactoryReset() {
        assertThat(mAdapterService.getState()).isEqualTo(STATE_OFF);
        BluetoothDevice device = TestUtils.getTestDevice(BluetoothAdapter.getDefaultAdapter(), 0);
        byte[] obfuscatedAddress1 = mAdapterService.obfuscateAddress(device);
        assertThat(obfuscatedAddress1).isNotEmpty();
        assertThat(AdapterServiceTest.isByteArrayAllZero(obfuscatedAddress1)).isFalse();
        mAdapterService.factoryReset();
        byte[] obfuscatedAddress2 = mAdapterService.obfuscateAddress(device);
        assertThat(obfuscatedAddress2).isNotEmpty();
        assertThat(AdapterServiceTest.isByteArrayAllZero(obfuscatedAddress2)).isFalse();
        assertThat(obfuscatedAddress2).isNotEqualTo(obfuscatedAddress1);
        doEnable();
        byte[] obfuscatedAddress3 = mAdapterService.obfuscateAddress(device);
        assertThat(obfuscatedAddress3).isNotEmpty();
        assertThat(AdapterServiceTest.isByteArrayAllZero(obfuscatedAddress3)).isFalse();
        assertThat(obfuscatedAddress3).isEqualTo(obfuscatedAddress2);
        mAdapterService.factoryReset();
        byte[] obfuscatedAddress4 = mAdapterService.obfuscateAddress(device);
        assertThat(obfuscatedAddress4).isNotEmpty();
        assertThat(AdapterServiceTest.isByteArrayAllZero(obfuscatedAddress4)).isFalse();
        assertThat(obfuscatedAddress4).isNotEqualTo(obfuscatedAddress3);
    }

    /**
     * Test: Verify that obfuscated Bluetooth address changes after factory reset and reloading
     * native layer
     */
    @Test
    public void testObfuscateBluetoothAddress_FactoryResetAndReloadNativeLayer()
            throws PackageManager.NameNotFoundException {
        byte[] metricsSalt1 = AdapterServiceTest.getMetricsSalt(mAdapterConfig);
        assertThat(metricsSalt1).isNotNull();
        assertThat(mAdapterService.getState()).isEqualTo(STATE_OFF);
        BluetoothDevice device = TestUtils.getTestDevice(BluetoothAdapter.getDefaultAdapter(), 0);
        byte[] obfuscatedAddress1 = mAdapterService.obfuscateAddress(device);
        assertThat(obfuscatedAddress1).isNotEmpty();
        assertThat(AdapterServiceTest.isByteArrayAllZero(obfuscatedAddress1)).isFalse();
        assertThat(AdapterServiceTest.obfuscateInJava(metricsSalt1, device))
                .isEqualTo(obfuscatedAddress1);
        mAdapterService.factoryReset();
        tearDown();
        setUp();
        // Cannot verify metrics salt since it is not written to disk until native cleanup
        byte[] obfuscatedAddress2 = mAdapterService.obfuscateAddress(device);
        assertThat(obfuscatedAddress2).isNotEmpty();
        assertThat(AdapterServiceTest.isByteArrayAllZero(obfuscatedAddress2)).isFalse();
        assertThat(obfuscatedAddress2).isNotEqualTo(obfuscatedAddress1);
    }
}
